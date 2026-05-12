#!/bin/bash
# 20 — #5a regression: esc() must encode quotes.
#
# After #5b de-duplication (REMEDIATION_PLAN.md), the frontend has a single
# canonical source at $REPO_ROOT/frontend/. Rust embeds it via include_str!;
# C copies it into traffic_cypher_in_C/frontend/ at `make` time. We assert
# on the canonical path, and (if the C build already ran) verify the copy
# has not drifted — this is what proves the build-time copy machinery works.
set -e
source "$(dirname "$0")/lib/common.sh"

CANON_APP="$REPO_ROOT/frontend/app.js"
C_APP="$REPO_ROOT/traffic_cypher_in_C/frontend/app.js"

[ -f "$CANON_APP" ] || fail "canonical app.js missing at $CANON_APP"

# 1. If the C build already produced its frontend copy, it must be byte-identical
#    to canonical (otherwise the Makefile `frontend` target has drifted).
if [ -f "$C_APP" ]; then
    diff -q "$CANON_APP" "$C_APP" >/dev/null \
        || fail "C-side app.js copy has drifted from canonical frontend/app.js"
    pass "C-side app.js matches canonical (build-time copy in sync)"
else
    info "C-side app.js not present (no make yet) — skipping copy-drift check"
fi

# 2. esc() contains the expected encoders — every replacement and the new
#    null-only guard (instead of the unsafe `!str`).
grep -q "if (str == null)" "$CANON_APP" \
    || fail "esc() missing 'if (str == null)' guard (falsy strings would be lost)"
grep -q "replace(/&/g, '&amp;')" "$CANON_APP" \
    || fail "esc() missing & → &amp; replacement"
grep -q "replace(/</g, '&lt;')" "$CANON_APP" \
    || fail "esc() missing < → &lt; replacement"
grep -q "replace(/>/g, '&gt;')" "$CANON_APP" \
    || fail "esc() missing > → &gt; replacement"
grep -q "replace(/\"/g, '&quot;')" "$CANON_APP" \
    || fail "esc() missing \" → &quot; replacement (THE XSS FIX)"
grep -q "replace(/'/g, '&#39;')" "$CANON_APP" \
    || fail "esc() missing ' → &#39; replacement (THE XSS FIX)"
pass "esc() body contains all five expected encoders + null-only guard"

# 3. Behavioural spec test in Node (if available).
if command -v node >/dev/null 2>&1; then
    info "running tests/lib/esc_unit_test.js"
    node "$(dirname "$0")/lib/esc_unit_test.js" \
        || fail "esc() behavioural spec test failed"
    pass "esc() behavioural spec test (13 assertions) passes"
else
    info "node not installed; behavioural test skipped"
fi
