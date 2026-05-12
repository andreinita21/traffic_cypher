#!/bin/bash
# 20 — #5a regression: esc() must encode quotes; both app.js copies must agree.
set -e
source "$(dirname "$0")/lib/common.sh"

RUST_APP="$REPO_ROOT/traffic_cypher_in_Rust/src/frontend/app.js"
C_APP="$REPO_ROOT/traffic_cypher_in_C/frontend/app.js"

[ -f "$RUST_APP" ] || fail "Rust app.js missing at $RUST_APP"
[ -f "$C_APP" ] || fail "C app.js missing at $C_APP"

# 1. Both copies byte-identical (drift would mean a fix landed in only one).
diff -q "$RUST_APP" "$C_APP" >/dev/null \
    || fail "Rust and C app.js have diverged"
pass "Both app.js copies byte-identical"

# 2. esc() contains the expected encoders — every replacement and the new
#    null-only guard (instead of the unsafe `!str`).
grep -q "if (str == null)" "$RUST_APP" \
    || fail "esc() missing 'if (str == null)' guard (falsy strings would be lost)"
grep -q "replace(/&/g, '&amp;')" "$RUST_APP" \
    || fail "esc() missing & → &amp; replacement"
grep -q "replace(/</g, '&lt;')" "$RUST_APP" \
    || fail "esc() missing < → &lt; replacement"
grep -q "replace(/>/g, '&gt;')" "$RUST_APP" \
    || fail "esc() missing > → &gt; replacement"
grep -q "replace(/\"/g, '&quot;')" "$RUST_APP" \
    || fail "esc() missing \" → &quot; replacement (THE XSS FIX)"
grep -q "replace(/'/g, '&#39;')" "$RUST_APP" \
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
