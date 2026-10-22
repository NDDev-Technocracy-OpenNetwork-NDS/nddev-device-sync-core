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
fn principal() -> WorkspacePrincipal {
    WorkspacePrincipal {
        origin: "https://nds.example.invalid".into(),
        tenant: "company".into(),
        user: "owner".into(),
        device: "device".into(),
    }
}
fn binding() -> CheckoutBinding {
    CheckoutBinding {
        id: "10000000-0000-4000-8000-000000000001".into(),
        principal: principal(),
        location: CheckoutLocation::from_repository(&repository("owner", "source")).unwrap(),
    }
}
#[test]
fn only_explicit_github_origins_match_without_consulting_ambient_ssh_config() {
    let location = binding().location;
    for origin in [
        "https://github.com/owner/source.git",
        "https://github.com/Owner/Source",
        "git@github.com:owner/source.git",
        "ssh://git@github.com/owner/source.git",
        "ssh://git@github.com:22/owner/source",
    ] {
        assert!(location.matches_origin(origin), "{origin}");
    }
    for origin in [
        "https://github.com.evil.invalid/owner/source.git",
        "https://github.com@evil.invalid/owner/source.git",
        "https://token@github.com/owner/source.git",
        "https://github.com/owner/source.git?redirect=1",
        "https://github.com/owner/../source.git",
        "git@github-alias:owner/source.git",
        "ssh://git@github.com:2222/owner/source.git",
        "file:///owner/source",
        "https://github.com/owner/source.git\n",
        "https://github.com/other/source.git",
    ] {
        assert!(!location.matches_origin(origin), "{origin}");
    }
}
#[test]
fn catalog_and_process_permissions_never_implicitly_grant_git_changes() {
    use nddev_device_sync_domain::{
        Permission,
        modules::control::{Configuration, Readiness},
    };
    let mut permissions = write_permissions();
    permissions.remove(&Permission::GitWrite);
    permissions.insert(Permission::ProcessExecution);
    let mut setting = Configuration {
        enabled: true,
        permissions,
    };
    assert_eq!(
        setting.admit(true, true, &write_permissions()),
        Err(Readiness::PermissionRequired)
    );
    setting.permissions.insert(Permission::GitWrite);
    assert_eq!(setting.admit(true, true, &write_permissions()), Ok(()));
    setting.enabled = false;
    assert_eq!(
        setting.admit(true, true, &write_permissions()),
        Err(Readiness::Disabled)
    );
}
#[test]
fn connection_preserves_account_identity_repository_identity_and_existing_paths() {
    let expected = binding();
    let presence = |binding| CheckoutPresence::Repository {
        origin: "git@github.com:owner/source.git".into(),
        active_writer: false,
        binding,
    };
    let decide =
        |presence| connection_decision(&expected.principal, &expected.location, &presence).unwrap();
    assert_eq!(decide(CheckoutPresence::Missing), ConnectionDecision::Clone);
    assert_eq!(
        decide(CheckoutPresence::Occupied),
        ConnectionDecision::Blocked(ConnectionBlock::PathOccupied)
    );
    assert_eq!(decide(presence(None)), ConnectionDecision::Adopt);
    assert_eq!(
        decide(presence(Some(Box::new(expected.clone())))),
        ConnectionDecision::AlreadyConnected
    );
    for field in ["origin", "tenant", "user", "device"] {
        let mut other = expected.clone();
        match field {
            "origin" => other.principal.origin = "https://other.example.invalid".into(),
            "tenant" => other.principal.tenant = "other-company".into(),
            "user" => other.principal.user = "other-owner".into(),
            _ => other.principal.device = "other-device".into(),
        }
        assert_eq!(
            decide(presence(Some(Box::new(other)))),
            ConnectionDecision::Blocked(ConnectionBlock::DifferentAccount)
        );
    }
    let mut other = expected.clone();
    other.location.repository_id = RepositoryId::new(20).unwrap();
    assert_eq!(
        decide(presence(Some(Box::new(other)))),
        ConnectionDecision::Blocked(ConnectionBlock::DifferentRepository)
    );
    let mut other = expected.clone();
    other.location.owner_id = GithubAccountId::new(8).unwrap();
    assert_eq!(
        decide(presence(Some(Box::new(other)))),
        ConnectionDecision::Blocked(ConnectionBlock::RelocationRequired)
    );
    assert_eq!(
        decide(CheckoutPresence::Repository {
            origin: expected.location.https_url(),
            active_writer: true,
            binding: None
        }),
        ConnectionDecision::Blocked(ConnectionBlock::ActiveWriter)
    );
}
#[test]
fn connection_intent_is_owner_wide_and_bounded_at_1024_repositories_on_32_devices() {
    use nddev_device_sync_domain::{
        DeviceId,
        state::{Snapshot, State},
        sync::EntityKind,
    };
    let mut ids = std::collections::BTreeSet::new();
    for repository_id in 1..=1024 {
        let mut location = binding().location;
        location.repository_id = RepositoryId::new(repository_id).unwrap();
        let entity = location.connection_entity_id();
        let state = Snapshot {
            schema_version: 2,
            observed_at_ms: 100,
            data: State::RepositoryConnection { location },
        };
        for device in 1..=32 {
            assert!(
                state
                    .validate(
                        &DeviceId::new(format!("device-{device}")).unwrap(),
                        EntityKind::RepositoryState,
                        &entity
                    )
                    .is_ok()
            );
            ids.insert(entity.clone());
        }
        assert!(
            state
                .validate(
                    &DeviceId::new("device").unwrap(),
                    EntityKind::RepositoryState,
                    "github:repo:19"
                )
                .is_err()
        );
    }
    assert_eq!(ids.len(), 1024);
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
