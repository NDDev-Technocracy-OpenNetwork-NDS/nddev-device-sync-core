set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

fmt-check:
    cargo fmt --all -- --check

# Execution host or runner only.
test: clippy build audit
    cargo nextest run --locked --workspace --jobs 4 --profile ci
    cargo test --locked --workspace --doc --jobs 4

clippy:
    cargo clippy --locked --workspace --all-targets --jobs 4 -- -D warnings

dependencies-check:
    cargo deny --locked check licenses sources
    cargo shear --locked --deny-warnings

audit:
    cargo audit --deny warnings

check: fmt-check dependencies-check
    just --fmt --check

# Execution host or runner only.
build:
    cargo build --locked --workspace --release --jobs 4

verify: check test audit build

# Fetch locked source dependencies without compiling.
setup:
    cargo fetch --locked
