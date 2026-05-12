#!/bin/bash
# 19 — Pin the clippy gate: `cargo clippy --all-targets -- -D warnings` must
# exit 0. This is the structural counterpart to the CI clippy step; running it
# locally before pushing catches regressions cheaply.
#
# Slow: clippy can take ~30 s on a cold target/ directory.
set -e
source "$(dirname "$0")/lib/common.sh"

require_cmd cargo

cd "$REPO_ROOT/traffic_cypher_in_Rust"
info "cargo clippy --all-targets --locked -- -D warnings (may take ~30s)"
cargo clippy --all-targets --locked -- -D warnings 2>&1 | tail -20
pass "clippy is clean under -D warnings"
