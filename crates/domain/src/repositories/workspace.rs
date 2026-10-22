//! Canonical checkout identity and existing-commit policy for the GDS adapter.
//! Paths are relative to the installation's authorized Developer/nddev root.
//! These observations never grant filesystem, credential or Git authority.
use super::{BranchComparison, Changes, HeadKind, LocalGitStatus, catalog::*};
use crate::{Permission, modules::ModuleError};
use serde::{Deserialize, Serialize};

/// Stable provider identity is distinct from a mutable, portable locator.
/// No absolute device paths, token or remote-controlled URL is retained here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutLocation {
    pub repository_id: RepositoryId,
    pub owner_id: GithubAccountId,
    owner: String,
    repository: String,
}
impl CheckoutLocation {
    pub fn from_repository(repository: &RepositorySummary) -> Result<Self, ModuleError> {
        Self::new(
            repository.id,
            repository.owner.id,
            repository.owner.login.clone(),
            repository.name.clone(),
        )
    }
    pub fn new(
        repository_id: RepositoryId,
        owner_id: GithubAccountId,
        owner: String,
        repository: String,
    ) -> Result<Self, ModuleError> {
        let location = Self {
            repository_id,
            owner_id,
            owner,
            repository,
        };
        location.validate()?;
        Ok(location)
    }
    pub fn validate(&self) -> Result<(), ModuleError> {
        if !portable_component(&self.owner) || !portable_component(&self.repository) {
            return Err(ModuleError::InvalidInput);
        }
        Ok(())
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn repository(&self) -> &str {
        &self.repository
    }
    pub fn relative_path(&self) -> String {
        format!("{}/{}", self.owner, self.repository)
    }
    /// GitHub's owner/repository namespace is case insensitive. A portable
    /// collision key prevents different IDs sharing a path on any device.
    pub fn collision_key(&self) -> String {
        self.relative_path().to_ascii_lowercase()
    }
    pub fn connection_entity_id(&self) -> String {
        connection_entity_id(self.repository_id)
    }
    pub fn https_url(&self) -> String {
        format!("https://github.com/{}/{}.git", self.owner, self.repository)
    }
    /// Recognize only explicit GitHub origins. This does not resolve SSH
    /// aliases/configuration or authorize that transport: I/O always uses the
    /// fixed HTTPS endpoint with its own protected credential.
    pub fn matches_origin(&self, origin: &str) -> bool {
        let path = origin
            .strip_prefix("https://github.com/")
            .or_else(|| origin.strip_prefix("git@github.com:"))
            .or_else(|| origin.strip_prefix("ssh://git@github.com/"))
            .or_else(|| origin.strip_prefix("ssh://git@github.com:22/"));
        path.is_some_and(|path| {
            path.eq_ignore_ascii_case(&self.relative_path())
                || path.eq_ignore_ascii_case(&format!("{}.git", self.relative_path()))
        })
    }
}

pub fn connection_entity_id(repository: RepositoryId) -> String {
    format!("nds:connection:{}", repository.value())
}

/// A local witness, not an authorization capability. The adapter derives this
/// from its original authenticated NDS scope; it never accepts it from a UI.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspacePrincipal {
    pub origin: String,
    pub tenant: String,
    pub user: String,
    pub device: String,
}
impl WorkspacePrincipal {
    pub fn validate(&self) -> Result<(), ModuleError> {
        if self.origin.is_empty()
            || self.origin.len() > 2048
            || !self.origin.bytes().all(|b| b.is_ascii_graphic())
            || [&self.tenant, &self.user, &self.device]
                .into_iter()
                .any(|id| !crate::valid_identifier(id))
        {
            Err(ModuleError::InvalidInput)
        } else {
            Ok(())
        }
    }
}

/// Device-local Git witness over the canonical connection location. NDS keeps
/// owner-wide connection intent, not one replicated marker per device. No
/// absolute path, credential or provider success is stored in this witness.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutBinding {
    pub id: String,
    pub principal: WorkspacePrincipal,
    pub location: CheckoutLocation,
}
impl CheckoutBinding {
    pub fn validate(&self) -> Result<(), ModuleError> {
        self.principal.validate()?;
        self.location.validate()?;
        if uuid::Uuid::parse_str(&self.id).is_ok_and(|id| !id.is_nil() && id.to_string() == self.id)
        {
            Ok(())
        } else {
            Err(ModuleError::InvalidInput)
        }
    }
}

/// Dedicated bounded Git authority; catalog/observation consent remains smaller.
pub fn write_permissions() -> std::collections::BTreeSet<Permission> {
    std::collections::BTreeSet::from([
        Permission::ReadOnly,
        Permission::CredentialStore,
        Permission::LocalNetwork,
        Permission::GitWrite,
    ])
}

pub enum CheckoutPresence {
    Missing,
    Occupied,
    Repository {
        origin: String,
        active_writer: bool,
        binding: Option<Box<CheckoutBinding>>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionBlock {
    PathOccupied,
    WrongRemote,
    ActiveWriter,
    DifferentAccount,
    DifferentRepository,
    RelocationRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionDecision {
    Clone,
    Adopt,
    AlreadyConnected,
    Blocked(ConnectionBlock),
}
pub fn connection_decision(
    principal: &WorkspacePrincipal,
    location: &CheckoutLocation,
    presence: &CheckoutPresence,
) -> Result<ConnectionDecision, ModuleError> {
    use ConnectionDecision::*;
    principal.validate()?;
    location.validate()?;
    let CheckoutPresence::Repository {
        origin,
        active_writer,
        binding,
    } = presence
    else {
        return Ok(if matches!(presence, CheckoutPresence::Missing) {
            Clone
        } else {
            Blocked(ConnectionBlock::PathOccupied)
        });
    };
    if *active_writer {
        return Ok(Blocked(ConnectionBlock::ActiveWriter));
    }
    if !location.matches_origin(origin) {
        return Ok(Blocked(ConnectionBlock::WrongRemote));
    }
    let Some(binding) = binding else {
        return Ok(Adopt);
    };
    binding.validate()?;
    Ok(if binding.principal != *principal {
        Blocked(ConnectionBlock::DifferentAccount)
    } else if binding.location.repository_id != location.repository_id {
        Blocked(ConnectionBlock::DifferentRepository)
    } else if binding.location != *location {
        Blocked(ConnectionBlock::RelocationRequired)
    } else {
        AlreadyConnected
    })
}

fn portable_component(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 100
        || value.starts_with('-')
        || value.ends_with('.')
        || matches!(value, "." | "..")
        || value.eq_ignore_ascii_case(".git")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return false;
    }
    let stem = value.split('.').next().unwrap_or("").to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && (b'1'..=b'9').contains(&stem.as_bytes()[3]))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncBlock {
    Archived,
    ActiveWriter,
    Incomplete,
    Conflicted,
    Dirty,
    Detached,
    Unborn,
    NoUpstream,
    WrongRemote,
    Diverged,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitDecision {
    Fetch,
    UpToDate,
    Push,
    FastForward,
    Blocked(SyncBlock),
}

/// Freshness applies to this exact branch comparison after this operation's
/// fetch, never to cached refs from another scan or a catalog observation.
#[derive(Clone, Copy)]
pub enum ComparisonFreshness {
    Cached,
    Fetched,
}

pub fn commit_decision(
    status: &LocalGitStatus,
    freshness: ComparisonFreshness,
    archived: bool,
    active_writer: bool,
    upstream_matches: bool,
) -> CommitDecision {
    use CommitDecision::*;
    let block = if active_writer {
        Some(SyncBlock::ActiveWriter)
    } else if !status.partial_reasons.is_empty() || status.comparison == BranchComparison::Partial {
        Some(SyncBlock::Incomplete)
    } else if status.changes.conflicted != 0 {
        Some(SyncBlock::Conflicted)
    } else if status.changes != Changes::default() {
        Some(SyncBlock::Dirty)
    } else if status.head_kind == HeadKind::Detached {
        Some(SyncBlock::Detached)
    } else if status.head_kind == HeadKind::Unborn {
        Some(SyncBlock::Unborn)
    } else if status.branch.is_none() || status.upstream.is_none() {
        Some(SyncBlock::NoUpstream)
    } else if !upstream_matches {
        Some(SyncBlock::WrongRemote)
    } else {
        None
    };
    if let Some(reason) = block {
        return Blocked(reason);
    }
    if matches!(freshness, ComparisonFreshness::Cached) {
        return Fetch;
    }
    match status.comparison {
        BranchComparison::Available {
            ahead: 0,
            behind: 0,
        } => UpToDate,
        BranchComparison::Available {
            ahead: _,
            behind: 0,
        } if archived => Blocked(SyncBlock::Archived),
        BranchComparison::Available {
            ahead: _,
            behind: 0,
        } => Push,
        BranchComparison::Available {
            ahead: 0,
            behind: _,
        } => FastForward,
        BranchComparison::Available { .. } => Blocked(SyncBlock::Diverged),
        _ => Blocked(SyncBlock::Incomplete),
    }
}
