#!/bin/bash
# 60 — Cross-implementation parity smoke. Runs parity/parity_test.py
# against the first --max-cases cases and asserts both PMs agree (or are
# flagged expected_diff).
#
# BUILD_VARIANT axis (read transparently by parity_test.py via env):
#   default          (or unset) — run the prebuilt C binary; per-case
#                                 expected_diff resolves to its "default"
#                                 value. This is what tests/run.sh
#                                 invokes, so the smoke stays cheap.
#   traffic_entropy            — rebuild the C tree with
#                                 ENABLE_TRAFFIC_ENTROPY=1 into a tmpdir
#                                 and run that binary; per-case
#                                 expected_diff resolves to its
#                                 "traffic_entropy" value. Exposed for a
#                                 separate CI job; this script does NOT
#                                 invoke it on its own.
#
# See parity/README.md for the harness design.
set -u
source "$(dirname "$0")/lib/common.sh"

require_cmd python3
require_cmd curl  # sanity only; the harness itself uses urllib

BUILD_VARIANT="${BUILD_VARIANT:-default}"
export BUILD_VARIANT

C_PM="$REPO_ROOT/traffic_cypher_in_C/traffic-cypher-pm"
RUST_PM="$REPO_ROOT/traffic_cypher_in_Rust/target/release/pm"

# For the `default` variant we run the prebuilt C binary directly. For
# any other variant the parity harness rebuilds C into a tmpdir, so we
# don't gate on $C_PM here — but we still need a default binary on disk
# because variant builds rsync from $C/ (and `make` itself doesn't care
# whether $C/traffic-cypher-pm exists). Either way, requiring it keeps
# the diagnostic on missing-C-build crisp.
[ -x "$C_PM" ]    || fail "C PM not built: $C_PM (run tests/01_build_c.sh)"
[ -x "$RUST_PM" ] || fail "Rust PM not built: $RUST_PM (run tests/00_build_rust.sh)"

if curl -s -m 1 "http://127.0.0.1:9876/api/auth/status" >/dev/null 2>&1; then
    fail "Port 9876 is already in use; aborting"
fi

# Limit to 5 anchor cases so smoke stays under 30 s wall time on a 2024
# laptop. Per-case wall time is dominated by 2× PM boot + 1 s port drain
# per impl (~3-4 s/case). traffic_entropy variant adds ~10-20 s for the
# tmp `make` invocation up front.
if ! python3 "$REPO_ROOT/parity/parity_test.py" --max-cases 5; then
    fail "parity harness reported failures (BUILD_VARIANT=$BUILD_VARIANT)"
fi
pass "parity harness: 5 anchor cases agree (or are expected_diff) [BUILD_VARIANT=$BUILD_VARIANT]"
