#!/bin/bash
# 00 — Rust release build must succeed. Required by later tests.
set -e
source "$(dirname "$0")/lib/common.sh"

require_cmd cargo

cd "$REPO_ROOT/traffic_cypher_in_Rust"
info "cargo build --release --bins"
cargo build --release --bins 2>&1 | tail -5
[ -x ./target/release/traffic_cypher ] || fail "Rust CLI binary not produced"
[ -x ./target/release/pm ] || fail "Rust PM binary not produced"
pass "Rust release build clean; CLI + PM binaries present"
