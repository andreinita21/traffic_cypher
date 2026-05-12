#!/bin/bash
# 14 — #5b regression: frontend is single-source-of-truth at repo root.
#
# After de-duplication (REMEDIATION_PLAN.md #5b):
#   - canonical frontend lives at  $REPO_ROOT/frontend/
#   - Rust embeds via include_str! at compile time
#   - C copies into traffic_cypher_in_C/frontend/ at `make` time (build artifact)
#
# This test guards three invariants:
#   1. canonical files exist
#   2. the old Rust-side path is gone (no zombie copy reappearing)
#   3. if the C build ran, its copy matches canonical byte-for-byte
set -e
source "$(dirname "$0")/lib/common.sh"

# 1. Canonical files exist at repo root.
for f in index.html app.js style.css; do
    [ -f "$REPO_ROOT/frontend/$f" ] \
        || fail "canonical frontend/$f missing at repo root"
done
pass "canonical frontend/{index.html,app.js,style.css} present at repo root"

# 2. The pre-dedup Rust-side directory must not exist (it moved via git mv).
if [ -d "$REPO_ROOT/traffic_cypher_in_Rust/src/frontend" ]; then
    fail "traffic_cypher_in_Rust/src/frontend/ still exists — should have moved to repo root"
fi
pass "old traffic_cypher_in_Rust/src/frontend/ is gone"

# 3. If the C build has run, its frontend/ must match canonical byte-for-byte.
#    Fresh checkout before any `make` — skip with a guard.
#    In the normal test suite, 01_build_c.sh runs first and populates this.
C_FRONTEND="$REPO_ROOT/traffic_cypher_in_C/frontend"
if [ -d "$C_FRONTEND" ]; then
    if ! diff -q -r "$REPO_ROOT/frontend/" "$C_FRONTEND/" >/dev/null; then
        diff -q -r "$REPO_ROOT/frontend/" "$C_FRONTEND/" || true
        fail "C-side frontend has drifted from canonical (Makefile copy out of sync?)"
    fi
    pass "traffic_cypher_in_C/frontend/ matches canonical (no drift)"
else
    info "traffic_cypher_in_C/frontend/ not present — skipping drift check (no C build yet)"
fi
