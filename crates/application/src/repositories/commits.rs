//! One existing-commit cycle for the GitHub module native adapter. The port retains the
//! checkout lock, credential/fence, cancellation and exact Git snapshot witness.
use nddev_device_sync_domain::{modules::ModuleError, repositories::workspace::*};
use std::future::Future;

pub struct Inspection<W> {
    pub status: nddev_device_sync_domain::repositories::LocalGitStatus,
    pub witness: W,
    pub archived: bool,
    pub active_writer: bool,
    pub upstream_matches: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    UpToDate,
    Published,
    FastForwarded,
    Blocked(SyncBlock),
}
pub trait SynchronizeCommits {
    type Witness;
    fn inspect(&mut self) -> impl Future<Output = Result<Inspection<Self::Witness>, ModuleError>>;
    fn fetch(&mut self, expected: &Self::Witness) -> impl Future<Output = Result<(), ModuleError>>;
    /// A normal push, bound to the exact observed commit; never a force, tag,
    /// mirror, wildcard, deletion or inferred pull-request approval.
    fn push(&mut self, expected: &Self::Witness) -> impl Future<Output = Result<(), ModuleError>>;
    /// Update only the observed clean checkout, with Git's fast-forward guard.
    fn fast_forward(
        &mut self,
        expected: &Self::Witness,
    ) -> impl Future<Output = Result<(), ModuleError>>;
}

pub async fn synchronize<P: SynchronizeCommits>(
    port: &mut P,
) -> Result<CommitOutcome, ModuleError> {
    let before = port.inspect().await?;
    match decide(&before, ComparisonFreshness::Cached) {
        CommitDecision::Blocked(reason) => return Ok(CommitOutcome::Blocked(reason)),
        CommitDecision::Fetch => port.fetch(&before.witness).await?,
        _ => return Err(ModuleError::InvalidContract),
    }
    let current = port.inspect().await?;
    let outcome = match decide(&current, ComparisonFreshness::Fetched) {
        CommitDecision::Blocked(reason) => return Ok(CommitOutcome::Blocked(reason)),
        CommitDecision::UpToDate => return Ok(CommitOutcome::UpToDate),
        CommitDecision::Push => {
            port.push(&current.witness).await?;
            CommitOutcome::Published
        }
        CommitDecision::FastForward => {
            port.fast_forward(&current.witness).await?;
            CommitOutcome::FastForwarded
        }
        CommitDecision::Fetch => return Err(ModuleError::InvalidContract),
    };
    // The adapter rechecks exact witness/fence at mutation and verifies the
    // result. A new concurrent writer cannot be reported as a clean result.
    let after = port.inspect().await?;
    match decide(&after, ComparisonFreshness::Fetched) {
        CommitDecision::UpToDate => Ok(outcome),
        CommitDecision::Blocked(reason) => Ok(CommitOutcome::Blocked(reason)),
        _ => Err(ModuleError::Busy),
    }
}
fn decide<W>(inspection: &Inspection<W>, freshness: ComparisonFreshness) -> CommitDecision {
    commit_decision(
        &inspection.status,
        freshness,
        inspection.archived,
        inspection.active_writer,
        inspection.upstream_matches,
    )
}
