//! Portable encrypted observations and explicit owner/device intent. Stored
//! facts and preferences never grant authority to mutate a provider's state.
use crate::{
    DeviceId, ModuleId, Platform,
    devices::DeviceName,
    sync::{EntityKind, MAX_REVISION, SyncError},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u16,
    pub observed_at_ms: u64,
    pub data: State,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum State {
    /// Owner-wide catalog choice only. Device-local module consent and a fresh
    /// protected-record check remain required before every provider operation.
    GithubSource {
        selection: Option<crate::repositories::catalog::CredentialSelection>,
    },
    Repository {
        observation: crate::repositories::catalog::observations::RepositoryObservation,
    },
    Device {
        display_name: String,
        platform: String,
        client_version: String,
    },
    Module {
        module_id: String,
        version: String,
        configured: bool,
        reachability: Reachability,
        checked_at_ms: Option<u64>,
        error_class: Option<String>,
    },
    /// Desired state is its own entity. Automatic observation publication may
    /// never replace consent or re-enable a locally disabled module.
    ModuleConfiguration {
        module_id: String,
        configuration: crate::modules::control::Configuration,
    },
    Account {
        auth_method: String,
        checked_at_ms: u64,
        expires_at_ms: u64,
    },
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    NotChecked,
    Reachable,
    Unavailable,
    Failed,
}

fn version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}
impl Snapshot {
    /// Match the encrypted payload to its signed writer/kind/entity and reject
    /// impossible freshness or health claims before displaying remote state.
    pub fn validate(
        &self,
        writer: &DeviceId,
        kind: EntityKind,
        entity: &str,
    ) -> Result<(), SyncError> {
        let valid_entity = if kind == EntityKind::RepositoryState {
            crate::sync::long_id(entity)
        } else {
            crate::valid_identifier(entity)
        };
        if !valid_entity
            || self.schema_version
                != match (&self.data, kind) {
                    (
                        State::Repository { .. } | State::GithubSource { .. },
                        EntityKind::RepositoryState,
                    )
                    | (State::ModuleConfiguration { .. }, EntityKind::ModuleState) => 2,
                    _ => 1,
                }
            || self.observed_at_ms == 0
            || self.observed_at_ms > MAX_REVISION
        {
            return Err(SyncError::Invalid);
        }
        let valid = match (&self.data, kind) {
            (State::GithubSource { selection }, EntityKind::RepositoryState) => {
                entity == crate::repositories::catalog::SOURCE_ENTITY_ID
                    && selection
                        .as_ref()
                        .is_none_or(|value| value.validate().is_ok())
            }
            (
                State::Device {
                    display_name,
                    platform,
                    client_version,
                },
                EntityKind::DeviceState,
            ) => {
                entity == writer.as_str()
                    && DeviceName::new(display_name.clone()).is_ok()
                    && Platform::deserialize(serde::de::value::StrDeserializer::<
                        serde::de::value::Error,
                    >::new(platform))
                    .is_ok()
                    && (client_version.is_empty() || version(client_version))
            }
            (
                State::Module {
                    module_id,
                    version: release,
                    configured,
                    reachability,
                    checked_at_ms,
                    error_class,
                },
                EntityKind::ModuleState,
            ) => {
                ModuleId::new(module_id.clone()).is_ok()
                    && !module_id.ends_with(":configuration")
                    && version(release)
                    && entity == format!("{}:{module_id}", writer.as_str())
                    && checked_at_ms.is_none_or(|time| time > 0 && time <= self.observed_at_ms)
                    && error_class.as_ref().is_none_or(|error| {
                        matches!(
                            error.as_str(),
                            "provider_unavailable"
                                | "provider_failed"
                                | "operation_timeout"
                                | "invalid_response"
                        )
                    })
                    && match reachability {
                        Reachability::NotChecked => {
                            checked_at_ms.is_none() && error_class.is_none()
                        }
                        Reachability::Reachable => {
                            *configured && checked_at_ms.is_some() && error_class.is_none()
                        }
                        Reachability::Unavailable | Reachability::Failed => {
                            *configured && checked_at_ms.is_some() && error_class.is_some()
                        }
                    }
            }
            (State::ModuleConfiguration { module_id, .. }, EntityKind::ModuleState) => {
                ModuleId::new(module_id.clone()).is_ok()
                    && !module_id.contains(':')
                    && entity == format!("{}:{module_id}:configuration", writer.as_str())
            }
            (
                State::Account {
                    auth_method,
                    checked_at_ms,
                    expires_at_ms,
                },
                EntityKind::AccountState,
            ) => {
                entity == format!("{}:nds", writer.as_str())
                    && matches!(auth_method.as_str(), "email_otp" | "github" | "passkey")
                    && *checked_at_ms > 0
                    && *checked_at_ms <= self.observed_at_ms
                    && *expires_at_ms > *checked_at_ms
                    && *expires_at_ms <= MAX_REVISION
            }
            (State::Repository { observation }, EntityKind::RepositoryState) => {
                observation.validate().is_ok() && observation.key().entity_id() == entity
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(SyncError::Invalid)
        }
    }
}

impl Snapshot {
    /// Material equality excludes observation time and scan markers. Scope
    /// summaries still bind their evidence to the selected credential version.
    /// It does not authorize settlement or conflict retirement.
    pub fn material_eq(&self, other: &Self) -> bool {
        match (&self.data, &other.data) {
            (State::Repository { observation: a }, State::Repository { observation: b }) => {
                a.material_eq(b)
            }
            _ => self.data == other.data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_choice_is_owner_wide_and_never_a_device_grant_or_observation() {
        use crate::repositories::catalog::{CredentialSelection, SOURCE_ENTITY_ID};
        let writer = DeviceId::new("device").unwrap();
        let mut snapshot = Snapshot {
            schema_version: 2,
            observed_at_ms: 100,
            data: State::GithubSource {
                selection: Some(CredentialSelection::new("credential".into(), 7, None).unwrap()),
            },
        };
        for device in [writer.clone(), DeviceId::new("other-device").unwrap()] {
            assert!(
                snapshot
                    .validate(&device, EntityKind::RepositoryState, SOURCE_ENTITY_ID)
                    .is_ok()
            );
        }
        for (kind, id) in [
            (EntityKind::ModuleState, "device:gds:configuration"),
            (EntityKind::RepositoryState, "github:repo:1"),
            (EntityKind::VaultRecord, SOURCE_ENTITY_ID),
        ] {
            assert!(snapshot.validate(&writer, kind, id).is_err());
        }
        snapshot.data = State::GithubSource { selection: None };
        assert!(
            snapshot
                .validate(&writer, EntityKind::RepositoryState, SOURCE_ENTITY_ID)
                .is_ok()
        );
        snapshot.schema_version = 1;
        assert!(
            snapshot
                .validate(&writer, EntityKind::RepositoryState, SOURCE_ENTITY_ID)
                .is_err()
        );
        snapshot.schema_version = 2;
        snapshot.data = State::GithubSource {
            selection: Some(
                serde_json::from_str(r#"{"record_ref":"","revision":0,"pending_id":null}"#)
                    .unwrap(),
            ),
        };
        assert!(
            snapshot
                .validate(&writer, EntityKind::RepositoryState, SOURCE_ENTITY_ID)
                .is_err()
        );
    }
    #[test]
    fn module_configuration_is_writer_scoped_and_separate_from_observations() {
        let writer = DeviceId::new("device").unwrap();
        let mut value = Snapshot {
            schema_version: 2,
            observed_at_ms: 100,
            data: State::ModuleConfiguration {
                module_id: "gds".into(),
                configuration: Default::default(),
            },
        };
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "device:gds:configuration")
                .is_ok()
        );
        for id in [
            "device:gds",
            "other:gds:configuration",
            "device:rds:configuration",
        ] {
            assert!(
                value
                    .validate(&writer, EntityKind::ModuleState, id)
                    .is_err()
            );
        }
        value.schema_version = 1;
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "device:gds:configuration")
                .is_err()
        );
        let legacy: Snapshot = serde_json::from_str(
            r#"{"schema_version":1,"observed_at_ms":100,"data":{"kind":"module","module_id":"gds","version":"1","configured":false,"reachability":"not_checked","checked_at_ms":null,"error_class":null}}"#,
        )
        .unwrap();
        assert!(
            legacy
                .validate(&writer, EntityKind::ModuleState, "device:gds")
                .is_ok()
        );
    }

    #[test]
    fn device_observations_accept_every_supported_platform_and_reject_unknowns() {
        let writer = DeviceId::new("device").unwrap();
        for platform in [
            "linux", "macos", "windows", "android", "ios", "web", "unknown",
        ] {
            let snapshot = Snapshot {
                schema_version: 1,
                observed_at_ms: 100,
                data: State::Device {
                    display_name: "NDS device".into(),
                    platform: platform.into(),
                    client_version: "0.0.1-alpha.19".into(),
                },
            };
            assert_eq!(
                snapshot
                    .validate(&writer, EntityKind::DeviceState, "device")
                    .is_ok(),
                platform != "unknown"
            );
            assert!(
                snapshot
                    .validate(&writer, EntityKind::DeviceState, "other")
                    .is_err()
            );
        }
    }
    #[test]
    fn remote_state_cannot_claim_another_writer_or_unobserved_provider_success() {
        let writer = DeviceId::new("device").unwrap();
        let mut value = Snapshot {
            schema_version: 1,
            observed_at_ms: 100,
            data: State::Module {
                module_id: "gds".into(),
                version: "0.0.1-alpha.1".into(),
                configured: false,
                reachability: Reachability::NotChecked,
                checked_at_ms: None,
                error_class: None,
            },
        };
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "device:gds")
                .is_ok()
        );
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "other:gds")
                .is_err()
        );
        assert!(
            value
                .validate(&writer, EntityKind::DeviceState, "device")
                .is_err()
        );
        if let State::Module { reachability, .. } = &mut value.data {
            *reachability = Reachability::Reachable;
        }
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "device:gds")
                .is_err()
        );
        if let State::Module {
            configured,
            checked_at_ms,
            ..
        } = &mut value.data
        {
            *configured = true;
            *checked_at_ms = Some(101);
        }
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "device:gds")
                .is_err()
        );
        if let State::Module { checked_at_ms, .. } = &mut value.data {
            *checked_at_ms = Some(99);
        }
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "device:gds")
                .is_ok()
        );
    }
}
