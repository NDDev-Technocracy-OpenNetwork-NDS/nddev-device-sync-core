//! First-alpha application candidate eligibility. No download or activation I/O.
//!
//! The root owns `contracts/app-release.schema.json`. Consumers deserialize this
//! one model, authenticate the entire document, then apply these pure rules.
//! Exact format equality permits staging only; it grants no migration/activation.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_ARTIFACT_BYTES: u64 = 1_073_741_824;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DataVersions {
    pub vault_journal: u32,
    pub sync_wire: u32,
    pub accounts_fence: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub role: String,
    pub repository: String,
    pub commit: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub url: String,
    pub bytes: u64,
    pub sha256: String,
    pub app_source: String,
    pub native_source: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub schema: u32,
    pub application: String,
    pub version: String,
    pub platform: String,
    pub architecture: String,
    pub channel: String,
    pub sources: Vec<Source>,
    pub data: DataVersions,
    pub artifact: Artifact,
}

/// Facts from trusted assembly/owning code, never the candidate itself.
pub struct Installed<'a> {
    pub version: &'a str,
    pub architecture: &'a str,
    pub data: Option<DataVersions>,
    pub approved_sources: &'a [Source],
    pub application_repository: &'a str,
}

/// Only supplied after certificate, identity and transparency verification.
pub struct PublisherSource<'a> {
    pub repository: &'a str,
    pub commit: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("invalid application release manifest")]
    Invalid,
    #[error("unsupported application platform or architecture")]
    Platform,
    #[error("unsupported release channel")]
    Channel,
    #[error("application source graph does not match its verified publisher")]
    Source,
    #[error("application data compatibility is unknown or unsupported")]
    Compatibility,
    #[error("application candidate is not newer than the installed version")]
    NotNewer,
}

pub fn candidate(version: &str) -> Result<u32, Error> {
    let number = version.strip_prefix("1.0.0-alpha.").ok_or(Error::Invalid)?;
    if number.is_empty() || number.starts_with('0') || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Invalid);
    }
    number.parse().map_err(|_| Error::Invalid)
}

pub fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn repository(value: &str) -> bool {
    let Some(path) = value.strip_prefix("https://github.com/") else {
        return false;
    };
    let mut parts = path.split('/');
    let valid = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    matches!((parts.next(), parts.next(), parts.next()), (Some(owner), Some(name), None) if valid(owner) && valid(name))
}

impl Release {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema != 1
            || self.application != "nds"
            || candidate(&self.version).is_err()
            || self.sources.is_empty()
            || self.sources.len() > 64
            || self.artifact.bytes == 0
            || self.artifact.bytes > MAX_ARTIFACT_BYTES
            || !hex(&self.artifact.sha256, 64)
            || !hex(&self.artifact.app_source, 40)
            || !hex(&self.artifact.native_source, 40)
            || self.artifact.url.len() > 2048
            || !(self.artifact.url.starts_with("https://")
                || self.artifact.url.starts_with("http://"))
            || self.artifact.url.bytes().any(|b| b.is_ascii_control())
            || self.data.vault_journal == 0
            || self.data.sync_wire == 0
            || self.data.accounts_fence == 0
        {
            return Err(Error::Invalid);
        }
        if self.platform != "linux" || !matches!(self.architecture.as_str(), "x86_64" | "aarch64") {
            return Err(Error::Platform);
        }
        if self.channel != "alpha" {
            return Err(Error::Channel);
        }
        let mut seen = BTreeSet::new();
        for source in &self.sources {
            if !repository(&source.repository)
                || !hex(&source.commit, 40)
                || source.role.is_empty()
                || source.role.len() > 64
                || !source.role.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
                })
                || !seen.insert(&source.role)
            {
                return Err(Error::Source);
            }
        }
        Ok(())
    }

    pub fn eligible(
        &self,
        installed: &Installed<'_>,
        publisher: &PublisherSource<'_>,
    ) -> Result<(), Error> {
        self.validate()?;
        if self.architecture != installed.architecture {
            return Err(Error::Platform);
        }
        if installed.data != Some(self.data) {
            return Err(Error::Compatibility);
        }
        if candidate(&self.version)? <= candidate(installed.version)? {
            return Err(Error::NotNewer);
        }
        let expected: BTreeSet<_> = installed
            .approved_sources
            .iter()
            .map(|s| (&s.role, &s.repository, &s.commit))
            .collect();
        let actual: BTreeSet<_> = self
            .sources
            .iter()
            .map(|s| (&s.role, &s.repository, &s.commit))
            .collect();
        if expected.len() != installed.approved_sources.len() || actual != expected {
            return Err(Error::Source);
        }
        let app = self.sources.iter().find(|s| s.role == "desktop");
        if !app.is_some_and(|s| s.repository == installed.application_repository
            && s.repository == publisher.repository && s.commit == publisher.commit
            && s.commit == self.artifact.app_source)
            // Desktop's app and shared native library have the same source owner.
            || self.artifact.native_source != self.artifact.app_source
        {
            return Err(Error::Source);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn release() -> Release {
        Release {
            schema: 1,
            application: "nds".into(),
            version: "1.0.0-alpha.2".into(),
            platform: "linux".into(),
            architecture: "x86_64".into(),
            channel: "alpha".into(),
            sources: vec![Source {
                role: "desktop".into(),
                repository: "https://github.com/example/desktop".into(),
                commit: "a".repeat(40),
            }],
            data: DataVersions {
                vault_journal: 8,
                sync_wire: 3,
                accounts_fence: 1,
            },
            artifact: Artifact {
                url: "https://example.invalid/app.bin".into(),
                bytes: 17,
                sha256: "b".repeat(64),
                app_source: "a".repeat(40),
                native_source: "a".repeat(40),
            },
        }
    }
    fn eligibility(r: &Release, data: Option<DataVersions>) -> Result<(), Error> {
        r.eligible(
            &Installed {
                version: "1.0.0-alpha.1",
                architecture: "x86_64",
                data,
                approved_sources: &release().sources,
                application_repository: "https://github.com/example/desktop",
            },
            &PublisherSource {
                repository: "https://github.com/example/desktop",
                commit: &"a".repeat(40),
            },
        )
    }
    #[test]
    fn each_format_is_independent_and_unknown_or_unsupported_data_refuses() {
        let r = release();
        assert_eq!(eligibility(&r, Some(r.data)), Ok(()));
        assert_eq!(eligibility(&r, None), Err(Error::Compatibility));
        for data in [
            DataVersions {
                vault_journal: 7,
                ..r.data
            },
            DataVersions {
                sync_wire: 2,
                ..r.data
            },
            DataVersions {
                accounts_fence: 2,
                ..r.data
            },
        ] {
            assert_eq!(eligibility(&r, Some(data)), Err(Error::Compatibility));
        }
    }
    #[test]
    fn signed_source_facts_cannot_rebind_publisher_or_native_artifact() {
        let r = release();
        for changed in 0..4 {
            let mut c = r.clone();
            match changed {
                0 => c.sources[0].commit = "c".repeat(40),
                1 => c.artifact.native_source = "c".repeat(40),
                2 => c.sources.push(c.sources[0].clone()),
                _ => c.sources[0].repository = "https://github.com/example/other".into(),
            }
            assert_eq!(eligibility(&c, Some(r.data)), Err(Error::Source));
        }
    }
    #[test]
    fn same_repository_can_have_distinct_exact_package_roles() {
        let mut r = release();
        r.sources.push(Source {
            role: "adapter-io".into(),
            repository: r.sources[0].repository.clone(),
            commit: "d".repeat(40),
        });
        let approved = r.sources.clone();
        let installed = Installed {
            version: "1.0.0-alpha.1",
            architecture: "x86_64",
            data: Some(r.data),
            approved_sources: &approved,
            application_repository: "https://github.com/example/desktop",
        };
        let publisher = PublisherSource {
            repository: "https://github.com/example/desktop",
            commit: &"a".repeat(40),
        };
        assert_eq!(r.eligible(&installed, &publisher), Ok(()));
        r.sources[1].commit = "e".repeat(40);
        assert_eq!(r.eligible(&installed, &publisher), Err(Error::Source));
    }
    #[test]
    fn publisher_cannot_bind_a_different_role_at_the_desktop_repository() {
        let mut r = release();
        r.sources.push(Source {
            role: "other-package".into(),
            repository: r.sources[0].repository.clone(),
            commit: "b".repeat(40),
        });
        let approved = r.sources.clone();
        let installed = Installed {
            version: "1.0.0-alpha.1",
            architecture: "x86_64",
            data: Some(r.data),
            approved_sources: &approved,
            application_repository: "https://github.com/example/desktop",
        };
        let publisher = PublisherSource {
            repository: "https://github.com/example/desktop",
            commit: &"b".repeat(40),
        };
        assert_eq!(r.eligible(&installed, &publisher), Err(Error::Source));
    }
    #[test]
    fn product_candidate_is_bounded_and_no_downgrade_is_staged() {
        for bad in [
            "1.0.0",
            "1.0.0-alpha.0",
            "1.0.0-alpha.01",
            "1.0.0-alpha.2+build",
            "1.0.0-alpha.4294967296",
        ] {
            assert_eq!(candidate(bad), Err(Error::Invalid));
        }
        let mut r = release();
        r.version = "1.0.0-alpha.1".into();
        assert_eq!(eligibility(&r, Some(r.data)), Err(Error::NotNewer));
    }
    #[test]
    fn platform_channel_bounds_and_closed_json_are_enforced() {
        let r = release();
        let mut c = r.clone();
        c.platform = "windows".into();
        assert_eq!(c.validate(), Err(Error::Platform));
        let mut c = r.clone();
        c.channel = "release".into();
        assert_eq!(c.validate(), Err(Error::Channel));
        let mut c = r.clone();
        c.artifact.bytes = MAX_ARTIFACT_BYTES + 1;
        assert_eq!(c.validate(), Err(Error::Invalid));
        let mut value = serde_json::to_value(r).unwrap();
        value["data"]["schema"] = 3.into();
        assert!(serde_json::from_value::<Release>(value).is_err());
    }
}
