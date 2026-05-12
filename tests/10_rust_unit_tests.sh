#!/bin/bash
# 10 — Rust unit tests.
# Single-threaded because vault.rs::with_test_vault uses env::set_var,
# which is racy. Pre-existing baseline issue; tracked for the Week 3
# tests/http.rs refactor that introduces AppState::for_test(path).
set -e
source "$(dirname "$0")/lib/common.sh"

require_cmd cargo

cd "$REPO_ROOT/traffic_cypher_in_Rust"
info "cargo test --release -- --test-threads=1"
cargo test --release -- --test-threads=1 2>&1 | tail -15
pass "All Rust unit tests pass (serial)"
