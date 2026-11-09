set shell := ["bash", "-euo", "pipefail", "-c"]

export CARGO_PROFILE_DEV_DEBUG := "0"
export CARGO_PROFILE_TEST_DEBUG := "0"

default:
    @just --list

setup:
    cargo fetch --locked

fmt-check:
    cargo fmt --all -- --check

# Execution host or runner only.
test: clippy
    cargo nextest run --locked --workspace --jobs 4 --profile ci
    cargo test --locked --workspace --doc --jobs 4

clippy:
    cargo clippy --locked --workspace --all-targets --jobs 4 -- -D warnings

dependencies-check:
    cargo deny --frozen check licenses sources
    cargo shear --locked --deny-warnings

audit:
    cargo audit --deny warnings

check: fmt-check dependencies-check

# Execution host or runner only.
build:
    cargo build --locked --workspace --release --jobs 4

verify: check test audit build
