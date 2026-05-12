#!/bin/bash
# 60 — Cross-implementation parity smoke. Runs parity/parity_test.py
# against the first --max-cases cases and asserts both PMs agree (or are
# flagged expected_diff).
#
# See parity/README.md for the harness design.
set -u
source "$(dirname "$0")/lib/common.sh"

require_cmd python3
require_cmd curl  # sanity only; the harness itself uses urllib

C_PM="$REPO_ROOT/traffic_cypher_in_C/traffic-cypher-pm"
RUST_PM="$REPO_ROOT/traffic_cypher_in_Rust/target/release/pm"

[ -x "$C_PM" ]    || fail "C PM not built: $C_PM (run tests/01_build_c.sh)"
[ -x "$RUST_PM" ] || fail "Rust PM not built: $RUST_PM (run tests/00_build_rust.sh)"

if curl -s -m 1 "http://127.0.0.1:9876/api/auth/status" >/dev/null 2>&1; then
    fail "Port 9876 is already in use; aborting"
fi

# Limit to 4 anchor cases so smoke stays under 30 s wall time on a 2024
# laptop. Per-case wall time is dominated by 2× PM boot + 1 s port drain
# per impl (~3-4 s/case).
if ! python3 "$REPO_ROOT/parity/parity_test.py" --max-cases 4; then
    fail "parity harness reported failures"
fi
pass "parity harness: 4 anchor cases agree (or are expected_diff)"
