# nddev-device-sync-domain

Pure domain model for nddev-device-sync: entities, identity rules, sync
invariants and typed errors with no filesystem, process, network, UI or
credential-store code. The crate stays portable across every supported
operating system so domain rules remain testable in isolation.

Consumers pin this crate by immutable Git revision through the workspace
lockfile; see the root README for the release journal.
