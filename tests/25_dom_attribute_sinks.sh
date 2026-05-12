#!/bin/bash
# 25 — #5c DOM-construction pass: the 9 high-risk attribute interpolation
# sites called out by REMEDIATION_PLAN.md (Week 4+) must be gone.
#
# Original sites (esc() interpolated into an HTML attribute value):
#   358 — data-copy="${esc(c.username)}"
#   475, 479, 483, 487, 512, 516 — <input value="${esc(...)}">
#   1084, 1088 — <input value="${esc(stream.label/url)}">
#
# Replaced by `.value =` / event-handler binding after `appendChild`. The DOM
# setter writes the attribute verbatim; HTML parsing is not re-invoked, so an
# `esc()` regression cannot escape the attribute. Text-content `${esc(...)}`
# sites (outside attributes) remain — those are still safe.
set -e
source "$(dirname "$0")/lib/common.sh"

CANON_APP="$REPO_ROOT/frontend/app.js"
[ -f "$CANON_APP" ] || fail "canonical app.js missing at $CANON_APP"

# 1. No `value="${esc(...)}"` anywhere — that was the high-risk attribute sink
#    on the 7 form inputs / 1 textarea.
if grep -nE 'value="\$\{esc' "$CANON_APP" >/dev/null; then
    grep -nE 'value="\$\{esc' "$CANON_APP"
    fail "app.js still has value=\"\${esc(...)}\" attribute interpolation"
fi
pass "no value=\"\${esc(...)}\" attribute interpolation remains"

# 2. No `data-copy="${esc(...)}"` — that was the dispatched copy button.
#    The replacement is a closure-based handler on an id'd button. Restrict
#    the search to code lines (skip the comment in the binding block).
if grep -nE 'data-copy="\$\{esc' "$CANON_APP" | grep -vE '^\s*[0-9]+:\s*//' >/dev/null; then
    grep -nE 'data-copy="\$\{esc' "$CANON_APP"
    fail "app.js still has data-copy=\"\${esc(...)}\" attribute interpolation"
fi
pass "no data-copy=\"\${esc(...)}\" attribute interpolation remains"

# 3. Sanity: the replacement setters must be present so we're sure we actually
#    re-wired the form (not just deleted the value=... and left fields empty).
for id in f-label f-website f-username f-password f-totp f-tags f-notes \
          es-label es-url; do
    grep -qE "#$id'.*\.value\s*=" "$CANON_APP" \
        || fail "missing #$id .value = ... setter (DOM-construction pass)"
done
pass "all 9 expected form fields are populated via .value setters"

# 4. The username copy button is bound via a real listener with c.username
#    captured in the closure (not via dataset). This is the surviving
#    'data-*' replacement.
grep -q "copy-username-btn" "$CANON_APP" \
    || fail "missing #copy-username-btn (data-copy attribute replacement)"
pass "username copy button replaced with id + closure handler"

# 5. JS still parses (node syntax-check).
if command -v node >/dev/null 2>&1; then
    node --check "$CANON_APP" 2>&1 \
        || fail "app.js fails node --check"
    pass "app.js passes node --check"
else
    info "node not installed; --check skipped"
fi

# 6. C-side copy is in sync if `make` has already run.
C_APP="$REPO_ROOT/traffic_cypher_in_C/frontend/app.js"
if [ -f "$C_APP" ]; then
    diff -q "$CANON_APP" "$C_APP" >/dev/null \
        || fail "C-side app.js has drifted from canonical (rerun make)"
    pass "C-side app.js matches canonical"
fi
