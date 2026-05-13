#!/usr/bin/env bash
# 35 — #1a stage 4d: frontend renderer recognises all four live stream states
# produced by the ENABLE_TRAFFIC_ENTROPY=1 C build (and always by Rust):
# Connecting / Active / Failed / Stopped. Plus the legacy `Disabled` banner
# path from the default C build must keep working.
#
# The renderer must NOT introduce new attribute-string interpolation sinks
# of the form  value="${esc(...)}"  or  data-X="${esc(...)}"  — the full pin
# lives in tests/25_dom_attribute_sinks.sh; this test only spot-checks the
# stream-list renderer.
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

CANON_APP="$REPO_ROOT/frontend/app.js"
[ -f "$CANON_APP" ] || fail "canonical app.js missing at $CANON_APP"

# ---------------------------------------------------------------------------
# 1. Whitelist pin — each live state name must appear as a quoted string in
#    the renderer's status mapping (the STATUS_CLASS table). The whitelist
#    pattern is what prevents an untrusted server from injecting arbitrary
#    class names into the status-dot.
# ---------------------------------------------------------------------------
for state in 'Connecting' 'Active' 'Failed' 'Stopped' 'Disabled'; do
    grep -qF "'${state}'" "$CANON_APP" \
        || fail "renderer missing '${state}' literal (stage 4d whitelist)"
done
pass "renderer recognises Connecting / Active / Failed / Stopped / Disabled"

# Sanity: the status-dot CSS classes for the four live states already exist.
# (They predate stage 4d — pin them so a future CSS refactor doesn't drop
# the visual distinction.)
CSS="$REPO_ROOT/frontend/style.css"
[ -f "$CSS" ] || fail "style.css missing at $CSS"
for cls in 'status-dot.active' 'status-dot.connecting' 'status-dot.failed' 'status-dot.stopped'; do
    grep -qF "$cls" "$CSS" \
        || fail "style.css missing .${cls} rule"
done
pass "style.css has status-dot rules for active/connecting/failed/stopped"

# ---------------------------------------------------------------------------
# 2. frames_captured must be rendered somewhere on each stream row. We pin
#    that the renderer references the field by name. The "—" / count fallback
#    is implementation detail; just confirm the field is consumed.
# ---------------------------------------------------------------------------
grep -qF 'frames_captured' "$CANON_APP" \
    || fail "renderer no longer references frames_captured"
pass "renderer consumes frames_captured"

# ---------------------------------------------------------------------------
# 3. Spot-check for new attribute-string interpolation sinks IN THE STREAM
#    RENDERER specifically. The full pin lives in tests/25_dom_attribute_sinks.sh.
#    Here we just confirm the renderer block hasn't grown a `value="${esc(...)}"`
#    or `data-X="${esc(...)}"` since stage 4d landed.
# ---------------------------------------------------------------------------
# Extract the loadStreams renderer block (innerHTML = streams.map(...)).
# Use awk to pull from `listEl.innerHTML = streams.map` to the matching
# `).join('')` — roughly 25 lines.
renderer_block=$(awk '
    /listEl\.innerHTML = streams\.map/  { capture=1 }
    capture                              { print }
    capture && /\)\.join\(/              { exit }
' "$CANON_APP")

if [ -z "$renderer_block" ]; then
    fail "could not locate stream-list renderer block in app.js"
fi

if printf '%s\n' "$renderer_block" | grep -qE 'value="\$\{esc'; then
    printf '%s\n' "$renderer_block" | grep -nE 'value="\$\{esc' >&2
    fail "stream renderer introduced a value=\"\${esc(...)}\" sink"
fi
if printf '%s\n' "$renderer_block" | grep -qE 'data-[A-Za-z-]+="\$\{esc'; then
    printf '%s\n' "$renderer_block" | grep -nE 'data-[A-Za-z-]+="\$\{esc' >&2
    fail "stream renderer introduced a data-X=\"\${esc(...)}\" sink"
fi
pass "stream renderer has no value=/data-* \${esc(...)} attribute sinks"

# ---------------------------------------------------------------------------
# 4. node --check on the canonical app.js.
# ---------------------------------------------------------------------------
if command -v node >/dev/null 2>&1; then
    node --check "$CANON_APP" 2>&1 \
        || fail "app.js fails node --check"
    pass "app.js passes node --check"
else
    info "node not installed; --check skipped"
fi

# ---------------------------------------------------------------------------
# 5. C-side mirror is in sync. The Makefile's `frontend` phony copies the
#    canonical tree into ./frontend/. Run it and diff -r to confirm.
# ---------------------------------------------------------------------------
C_DIR="$REPO_ROOT/traffic_cypher_in_C"
if [ ! -d "$C_DIR" ]; then
    info "C tree absent; skipping mirror check"
else
    if ! command -v make >/dev/null 2>&1; then
        skip "make not installed; cannot verify C-side frontend mirror"
    fi
    ( cd "$C_DIR" && make frontend >/dev/null 2>&1 ) \
        || fail "make -C traffic_cypher_in_C frontend failed"
    diff -r "$REPO_ROOT/frontend/" "$C_DIR/frontend/" >/dev/null \
        || fail "C-side frontend mirror diverges from canonical after make frontend"
    pass "C-side frontend mirror matches canonical"
fi
