#!/bin/bash
# 17 — Rust HTTP integration tests (tests/http.rs).
# Drives the axum Router via tower::ServiceExt::oneshot — no socket,
# no port allocation, no Tokio runtime races.
#
# Single-threaded because AppState::for_test mutates the process-global
# TRAFFIC_CYPHER_VAULT_PATH env var. Same constraint as 10_rust_unit_tests.sh.
set -e
source "$(dirname "$0")/lib/common.sh"

require_cmd cargo

cd "$REPO_ROOT/traffic_cypher_in_Rust"
info "cargo test --release --test http -- --test-threads=1"
cargo test --release --test http -- --test-threads=1 2>&1 | tail -25
pass "All Rust HTTP integration tests pass (serial)"
