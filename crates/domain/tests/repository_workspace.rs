use nddev_device_sync_domain::{
    modules::ModuleError,
    repositories::{catalog::*, workspace::*, *},
};

fn repository(owner: &str, name: &str) -> RepositorySummary {
    RepositorySummary {
        id: RepositoryId::new(19).unwrap(),
        owner: GithubOwner {
            id: GithubAccountId::new(7).unwrap(),
            kind: GithubOwnerKind::Organization,
            login: owner.into(),
        },
        name: name.into(),
        visibility: RepositoryVisibility::Private,
        archived: false,
        default_branch: Some("main".into()),
    }
}
fn clean(ahead: u32, behind: u32) -> LocalGitStatus {
    LocalGitStatus {
        head_kind: HeadKind::Branch,
        branch: Some("main".into()),
        upstream: Some("origin/main".into()),
        comparison: BranchComparison::Available { ahead, behind },
        changes: Changes::default(),
        partial_reasons: vec![],
    }
}
#[test]
fn portable_paths_keep_identity_across_rename_and_transfer() {
    let old = CheckoutLocation::from_repository(&repository("personal", "source")).unwrap();
    let new = CheckoutLocation::from_repository(&repository("company", "renamed")).unwrap();
    assert_eq!(old.repository_id, new.repository_id);
    assert_eq!(new.relative_path(), "company/renamed");
    assert_eq!(new.https_url(), "https://github.com/company/renamed.git");
    let case = CheckoutLocation::from_repository(&repository("Company", "Renamed")).unwrap();
    assert_eq!(case.collision_key(), new.collision_key());
    for component in [
        "",
        ".",
        "..",
        "../outside",
        "owner/repo",
        "C:drive",
        "back\\slash",
        "name.",
        "NUL",
        "Con.txt",
        "LPT1",
        "com9.log",
        ".GIT",
        "repo\n",
        "-option",
        "space name",
        "🚀",
    ] {
        assert!(
            matches!(
                CheckoutLocation::from_repository(&repository("owner", component)),
                Err(ModuleError::InvalidInput)
            ),
            "{component}"
        );
        assert!(CheckoutLocation::from_repository(&repository(component, "repo")).is_err());
    }
    assert!(CheckoutLocation::from_repository(&repository("owner", &"x".repeat(101))).is_err());
}
#[test]
fn cached_comparisons_never_authorize_a_push_or_worktree_change() {
    for (ahead, behind) in [(0, 0), (3, 0), (0, 4), (5, 6)] {
        assert_eq!(
            commit_decision(
                &clean(ahead, behind),
                ComparisonFreshness::Cached,
                false,
                false,
                true
            ),
            CommitDecision::Fetch
        );
    }
    for ((ahead, behind), expected) in [
        ((0, 0), CommitDecision::UpToDate),
        ((3, 0), CommitDecision::Push),
        ((0, 4), CommitDecision::FastForward),
        ((5, 6), CommitDecision::Blocked(SyncBlock::Diverged)),
    ] {
        assert_eq!(
            commit_decision(
                &clean(ahead, behind),
                ComparisonFreshness::Fetched,
                false,
                false,
                true
            ),
            expected
        );
    }
}
#[test]
fn local_edits_locks_and_partial_reads_block_before_network() {
    for changes in [
        Changes {
            staged: 1,
            ..Default::default()
        },
        Changes {
            unstaged: 1,
            ..Default::default()
        },
        Changes {
            untracked: 1,
            ..Default::default()
        },
        Changes {
            submodule_changes: 1,
            ..Default::default()
        },
    ] {
        let mut status = clean(1, 0);
        status.changes = changes;
        assert_eq!(
            commit_decision(&status, ComparisonFreshness::Cached, false, false, true),
            CommitDecision::Blocked(SyncBlock::Dirty)
        );
    }
    let status = clean(1, 0);
    assert_eq!(
        commit_decision(&status, ComparisonFreshness::Cached, false, true, true),
        CommitDecision::Blocked(SyncBlock::ActiveWriter)
    );
    assert_eq!(
        commit_decision(&status, ComparisonFreshness::Cached, true, false, true),
        CommitDecision::Fetch
    );
    assert_eq!(
        commit_decision(&status, ComparisonFreshness::Fetched, true, false, true),
        CommitDecision::Blocked(SyncBlock::Archived)
    );
    assert_eq!(
        commit_decision(
            &clean(0, 1),
            ComparisonFreshness::Fetched,
            true,
            false,
            true
        ),
        CommitDecision::FastForward
    );
    assert_eq!(
        commit_decision(&status, ComparisonFreshness::Cached, false, false, false),
        CommitDecision::Blocked(SyncBlock::WrongRemote)
    );
    let mut partial = clean(1, 0);
    partial.partial_reasons.push(PartialReason::HistoryBudget);
    assert_eq!(
        commit_decision(&partial, ComparisonFreshness::Fetched, false, false, true),
        CommitDecision::Blocked(SyncBlock::Incomplete)
    );
}
