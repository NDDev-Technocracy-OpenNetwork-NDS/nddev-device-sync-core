---
status: accepted
date: '2026-10-22'
adaptation:
  standard:
    id: std-0001
  rules:
  - R-0018
  paths:
  - .config
  - module.yaml
  - standarts.lock
  reason: NDS system ADR 0013 (accepted owner direction, 2026-10-22) keeps NDS contract material at fixed top-level locations in every member repository.
  result: module.yaml is the NDS module descriptor, standarts.lock pins the NDS standards source and .config holds the repository's pinned nextest CI profile; each stays at the repository root under its owner.
  verification: Review against the NDS root ADR 0013; the root catalog check validates module.yaml and standarts.lock, and the nextest CI profile is exercised by the repository's own CI.
---
# NDS contract locations

The owner accepted NDS system [ADR 0013](https://github.com/NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync/blob/main/standarts/decisions/0013-estate-hygiene-and-standards-adoption.md)
on 2026-10-22. It keeps NDS-owned contract material at deliberate top-level
locations in every member repository. This record scopes that decision to this
repository under std-0001 R-0037. It replaces the earlier manifest variations
without changing the decision.
