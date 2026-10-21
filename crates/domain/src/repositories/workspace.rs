//! Canonical checkout identity and existing-commit policy for the GDS adapter.
//! Paths are relative to the installation's authorized Developer/nddev root.
//! These observations never grant filesystem, credential or Git authority.
use super::{BranchComparison, Changes, HeadKind, LocalGitStatus, catalog::*};
use crate::modules::ModuleError;
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
        let location = Self {
            repository_id: repository.id,
            owner_id: repository.owner.id,
            owner: repository.owner.login.clone(),
            repository: repository.name.clone(),
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
    pub fn https_url(&self) -> String {
        format!("https://github.com/{}/{}.git", self.owner, self.repository)
    }
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
    let block = if archived {
        Some(SyncBlock::Archived)
    } else if active_writer {
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
        } => Push,
        BranchComparison::Available {
            ahead: 0,
            behind: _,
        } => FastForward,
        BranchComparison::Available { .. } => Blocked(SyncBlock::Diverged),
        _ => Blocked(SyncBlock::Incomplete),
    }
}
