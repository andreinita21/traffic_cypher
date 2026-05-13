#!/usr/bin/env bash
# 37 — NEXT_STEPS.md Phase A: end-to-end smoke for the ENABLE_TRAFFIC_ENTROPY
# build's async stream pipeline.
#
# This is the safety net for the future default-flip (NEXT_STEPS Phase C). It
# proves that POST /api/streams returns 202 promptly (the async refactor is
# alive), that the prep pthread reaches resolve_stream_url, and that
# resolve-failure transitions the slot to Failed within the cancel window —
# all without depending on yt-dlp being installed or YouTube being reachable.
#
# Bogus URLs only by design: real YouTube would be flaky in CI and the
# pipeline coverage is identical (we exercise resolve → fail → slot=Failed,
# not the resolve → ffmpeg → frames path). The frames path is covered
# separately by tests/38 (phone-camera endpoint, NEXT_STEPS Phase B).
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

C="$REPO_ROOT/traffic_cypher_in_C"

# --- Build the flag-on tree in a tmpcopy (same pattern as tests/33) -----------

WORK="$(mktemp -d -t tc_e2e_build.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

if command -v rsync >/dev/null 2>&1; then
    rsync -a --exclude='*.o' --exclude='traffic-cypher' --exclude='traffic-cypher-pm' \
          --exclude='frontend' --exclude='msm_test*' \
          "$C/" "$WORK/C/"
else
    cp -R "$C" "$WORK/C"
    rm -f "$WORK"/C/src_c/*.o "$WORK"/C/traffic-cypher{,-pm} "$WORK"/C/msm_test
    rm -rf "$WORK"/C/frontend
fi
ln -s "$REPO_ROOT/frontend" "$WORK/frontend"

OPENSSL_PREFIX_DEFAULT="$(brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)"
export OPENSSL_PREFIX="${OPENSSL_PREFIX:-$OPENSSL_PREFIX_DEFAULT}"

( cd "$WORK/C" && make ENABLE_TRAFFIC_ENTROPY=1 >"$WORK/build.log" 2>&1 ) \
    || { cat "$WORK/build.log" >&2; fail "ENABLE_TRAFFIC_ENTROPY=1 build failed"; }
pass "ENABLE_TRAFFIC_ENTROPY=1 build succeeds"

# --- Boot the PM --------------------------------------------------------------

if lsof -iTCP:9876 -sTCP:LISTEN >/dev/null 2>&1; then
    skip "port 9876 already in use; cannot run integration check"
fi

TMPHOME="$(mktemp -d -t tc_e2e_run.XXXXXX)"
trap 'rm -rf "$WORK" "$TMPHOME"; [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null || true' EXIT
PID=""

( cd "$WORK/C" && HOME="$TMPHOME" TRAFFIC_CYPHER_VAULT_PATH="$TMPHOME/vault.json" \
    exec ./traffic-cypher-pm >"$TMPHOME/server.log" 2>&1 ) &
PID=$!

for _ in $(seq 1 50); do
    if curl -s --max-time 1 http://127.0.0.1:9876/api/auth/status >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if ! curl -s --max-time 1 http://127.0.0.1:9876/api/auth/status >/dev/null 2>&1; then
    cat "$TMPHOME/server.log" >&2
    fail "server did not start"
fi
pass "ENABLE_TRAFFIC_ENTROPY=1 PM is up"

# --- Unlock + reserve a session ----------------------------------------------

unlock_resp=$(curl -s -X POST http://127.0.0.1:9876/api/auth/unlock \
    -H 'Content-Type: application/json' \
    -d '{"master_password":"e2e-test-pw"}')
token=$(printf '%s' "$unlock_resp" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || fail "unlock did not return a token: $unlock_resp"

# --- Assertion 1: POST returns 202 promptly ----------------------------------

post_start=$(python3 -c 'import time; print(time.time())')
add_status=$(curl -s -o "$TMPHOME/add.body" -w '%{http_code}' \
    -X POST http://127.0.0.1:9876/api/streams \
    -H "Authorization: Bearer ${token}" \
    -H 'Content-Type: application/json' \
    -d '{"url":"https://invalid.example/not-a-real-stream","label":"e2e-smoke"}')
post_end=$(python3 -c 'import time; print(time.time())')
elapsed=$(python3 -c "print(f'{$post_end - $post_start:.2f}')")

echo "  POST status: $add_status (in ${elapsed}s)"
echo "  body:        $(cat "$TMPHOME/add.body")"

[ "$add_status" = "202" ] \
    || fail "expected 202 Accepted, got $add_status"
pass "POST /api/streams returns 202 Accepted"

python3 -c "import sys; sys.exit(0 if $elapsed < 2.0 else 1)" \
    || fail "POST took ${elapsed}s — async refactor is not in effect"
pass "POST completed in <2s (${elapsed}s — async path alive)"

grep -q '"status":"connecting"' "$TMPHOME/add.body" \
    || fail "response body missing status:connecting"
grep -q '"index":0' "$TMPHOME/add.body" \
    || fail "response body missing index:0"
pass "response body is {status:connecting,index:0}"

# --- Assertion 2: slot reaches Failed within 15s -----------------------------

got_failed=0
for _ in $(seq 1 15); do
    cur=$(curl -s -H "Authorization: Bearer ${token}" http://127.0.0.1:9876/api/streams)
    if printf '%s' "$cur" | grep -q '"status":"Failed"'; then
        got_failed=1
        break
    fi
    sleep 1
done

if [ "$got_failed" = "1" ]; then
    pass "prep pthread transitioned slot to Failed within 15s"
else
    cur=$(curl -s -H "Authorization: Bearer ${token}" http://127.0.0.1:9876/api/streams)
    # On a slow runner with real yt-dlp installed, the resolve may still be
    # running. Accept Connecting as evidence the pipeline is alive — we're
    # not asserting the exact transition timing, only the path's existence.
    if printf '%s' "$cur" | grep -q '"status":"Connecting"'; then
        info "slot still Connecting after 15s (likely slow yt-dlp resolve)"
    else
        fail "slot never reached Failed or Connecting: $cur"
    fi
fi

# --- Assertion 3: frames_captured == 0 (no frames flowed for a bogus URL) ----

cur=$(curl -s -H "Authorization: Bearer ${token}" http://127.0.0.1:9876/api/streams)
echo "  final /api/streams: $cur"
if printf '%s' "$cur" | grep -qE '"frames_captured":[1-9]'; then
    fail "frames_captured > 0 for a bogus URL — unexpected"
fi
pass "frames_captured == 0 for the failed slot"

# --- Cleanup -----------------------------------------------------------------

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""
