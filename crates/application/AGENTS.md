# Application crate working contract

Use cases depend on `nddev-device-sync-domain` types and on ports declared
here; concrete I/O stays in consuming adapters. Keep every use case bounded,
cancellable and telemetry-aware through the domain event vocabulary. Add
focused unit tests next to the use case. Run the workspace `just check`
before review.
