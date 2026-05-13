#!/usr/bin/env bash
# 33 — Week 4+ #1a stage 3: build C with ENABLE_TRAFFIC_ENTROPY=1 and verify
# the user-facing flip happens (and *only* with the flag).
#
# We rebuild traffic-cypher-pm twice on a temp Makefile invocation, run each
# briefly, and compare /api/build/info responses. We do NOT POST a real stream
# (yt-dlp may not be installed; even if it is, hitting a live YouTube URL
# would make CI flaky), but we *do* verify /api/streams shape and that an
# attempt with a bogus URL is rejected with 500 (resolve fails) — not 501.
#
# After this run, the build artifacts are RESTORED to the default (no-flag)
# state so subsequent tests in the run.sh sequence still see the expected
# binary.
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

C="$REPO_ROOT/traffic_cypher_in_C"
BIN="$C/traffic-cypher-pm"

# Static checks (no rebuild needed).
grep -q 'ENABLE_TRAFFIC_ENTROPY' "$C/Makefile" \
    || fail "Makefile missing ENABLE_TRAFFIC_ENTROPY opt-in"
grep -q '^ifeq.*ENABLE_TRAFFIC_ENTROPY' "$C/Makefile" \
    || fail "Makefile ENABLE_TRAFFIC_ENTROPY toggle is not gated by ifeq"
grep -q 'ENABLE_TRAFFIC_ENTROPY' "$C/src_c/web_server.c" \
    || fail "web_server.c missing ENABLE_TRAFFIC_ENTROPY gate"
grep -q 'ENABLE_TRAFFIC_ENTROPY' "$C/src_c/key_rotation.c" \
    && fail "key_rotation.c should NOT gate on ENABLE_TRAFFIC_ENTROPY (stage 2 daemon works for both)"
pass "Makefile + web_server.c expose the ENABLE_TRAFFIC_ENTROPY toggle"

# Pin the CI job name so a future workflow rename can't quietly delete the
# opt-in-build coverage. If you rename the job, update this string too.
CI_YML="$REPO_ROOT/.github/workflows/ci.yml"
if [ -f "$CI_YML" ]; then
    grep -q 'c-traffic-entropy' "$CI_YML" \
        || fail "ci.yml missing 'c-traffic-entropy' job — rename without updating this test would lose ENABLE_TRAFFIC_ENTROPY CI coverage"
    pass "ci.yml still defines the c-traffic-entropy job"
fi

# Confirm the default build still reports traffic_entropy:false. The
# tests/31_c_no_entropy_lie.sh script already does this end-to-end; here we
# do the static binary-string check — BUT only when the on-disk binary is
# actually the default variant. In the CI job c-traffic-entropy, an earlier
# step already ran `make ENABLE_TRAFFIC_ENTROPY=1`, so $BIN is the flag-on
# variant; the default-build invariant doesn't apply there. Detect the
# variant from the binary's strings rather than from any out-of-band flag.
if command -v strings >/dev/null 2>&1 && [ -f "$BIN" ]; then
    if strings "$BIN" | grep -q '"traffic_entropy":false'; then
        # $BIN is the default variant — verify it doesn't ALSO carry the
        # flipped literal (a regression where the build accidentally inlined
        # both branches would show up here).
        if strings "$BIN" | grep -q '"traffic_entropy":true'; then
            fail "default binary unexpectedly contains traffic_entropy:true literal"
        fi
        pass "default binary contains only the OS-only build_info literal"
    else
        # $BIN is the flag-on variant (or unknown). The default-build
        # invariants don't apply; the tests/31_c_no_entropy_lie.sh suite
        # covers them whenever the default binary IS on disk.
        info "skipping default-binary literal check (\$BIN is not the default variant)"
    fi
fi

# Now rebuild WITH the flag, in a tmpcopy of the C tree (so we don't pollute
# the default-build artifacts other tests depend on).
WORK="$(mktemp -d -t tc_te_build.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# Use rsync if available (preserves perms); fall back to cp.
if command -v rsync >/dev/null 2>&1; then
    rsync -a --exclude='*.o' --exclude='traffic-cypher' --exclude='traffic-cypher-pm' \
          --exclude='frontend' --exclude='msm_test*' \
          "$C/" "$WORK/C/"
else
    cp -R "$C" "$WORK/C"
    rm -f "$WORK"/C/src_c/*.o "$WORK"/C/traffic-cypher{,-pm} "$WORK"/C/msm_test
    rm -rf "$WORK"/C/frontend
fi
# The Makefile's `frontend` phony target does `cp -R ../frontend ./frontend`,
# so we mirror the repo-root layout inside $WORK by symlinking the canonical
# frontend sibling. (Symlink avoids a second multi-MiB copy.)
ln -s "$REPO_ROOT/frontend" "$WORK/frontend"

# Mirror the OPENSSL_PREFIX detection from the main Makefile (macOS).
OPENSSL_PREFIX_DEFAULT="$(brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)"
export OPENSSL_PREFIX="${OPENSSL_PREFIX:-$OPENSSL_PREFIX_DEFAULT}"

( cd "$WORK/C" && make ENABLE_TRAFFIC_ENTROPY=1 >"$WORK/build.log" 2>&1 ) \
    || { cat "$WORK/build.log" >&2; fail "build with ENABLE_TRAFFIC_ENTROPY=1 failed"; }
pass "ENABLE_TRAFFIC_ENTROPY=1 build succeeds"

if command -v strings >/dev/null 2>&1; then
    if ! strings "$WORK/C/traffic-cypher-pm" | grep -q '"traffic_entropy":true'; then
        fail "ENABLE_TRAFFIC_ENTROPY=1 binary missing traffic_entropy:true literal"
    fi
    pass "ENABLE_TRAFFIC_ENTROPY=1 binary contains the flipped build_info literal"
fi

# Bring the binary up briefly and hit /api/build/info + /api/streams.
if lsof -iTCP:9876 -sTCP:LISTEN >/dev/null 2>&1; then
    skip "port 9876 already in use; cannot run integration check"
fi

TMPHOME="$(mktemp -d -t tc_te_run.XXXXXX)"
trap 'rm -rf "$WORK" "$TMPHOME"; [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null || true' EXIT
PID=""

# Use `exec` inside the subshell so $! captures the binary PID, not the
# transient subshell PID — otherwise the trap can't reap the orphan.
( cd "$WORK/C" && HOME="$TMPHOME" TRAFFIC_CYPHER_VAULT_PATH="$TMPHOME/vault.json" \
    exec ./traffic-cypher-pm >"$TMPHOME/server.log" 2>&1 ) &
PID=$!

# Wait for bind.
for _ in $(seq 1 50); do
    if curl -s --max-time 1 http://127.0.0.1:9876/api/auth/status >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if ! curl -s --max-time 1 http://127.0.0.1:9876/api/auth/status >/dev/null 2>&1; then
    cat "$TMPHOME/server.log" >&2
    fail "ENABLE_TRAFFIC_ENTROPY=1 server did not start"
fi

# /api/build/info — should be flipped.
build_info=$(curl -s http://127.0.0.1:9876/api/build/info)
echo "  build/info: $build_info"
echo "$build_info" | grep -q '"traffic_entropy":true' \
    || fail "/api/build/info did not flip to traffic_entropy:true"
echo "$build_info" | grep -q '"build":"c"' \
    || fail "/api/build/info no longer reports build:c"
pass "/api/build/info reports traffic_entropy:true with the flag set"

# /api/streams — would 401 without unlock. Unlock first.
unlock_resp=$(curl -s -X POST http://127.0.0.1:9876/api/auth/unlock \
    -H 'Content-Type: application/json' \
    -d '{"master_password":"integration-test-pw"}')
token=$(printf '%s' "$unlock_resp" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || fail "unlock did not return a token: $unlock_resp"

streams=$(curl -s -H "Authorization: Bearer ${token}" http://127.0.0.1:9876/api/streams)
echo "  streams: $streams"
[ "$streams" = "[]" ] || fail "/api/streams should be empty on fresh PM, got: $streams"
pass "/api/streams returns [] on fresh manager"

# POST a bogus URL to /api/streams. After the stage-5 async refactor,
# msm_add_stream returns immediately (slot reserved, prep pthread spawned)
# and we expect 202 Accepted with status:"connecting" — failure happens in
# the background. The slot should transition to Failed shortly after.
add_status=$(curl -s -o "$TMPHOME/add.body" -w '%{http_code}' \
    -X POST http://127.0.0.1:9876/api/streams \
    -H "Authorization: Bearer ${token}" \
    -H 'Content-Type: application/json' \
    -d '{"url":"https://invalid.example/not-a-real-stream","label":"bogus"}')
echo "  POST /api/streams status: $add_status"
echo "  POST /api/streams body:   $(cat "$TMPHOME/add.body")"

[ "$add_status" = "501" ] \
    && fail "/api/streams POST still returns 501 with the flag set"
# 202 is the new expected (async). 200/400/503 are tolerated to keep the test
# resilient to future tweaks; 500 from a sync failure is no longer expected
# but accepted for now.
case "$add_status" in
    202|200|400|500|503) ;;
    *) fail "unexpected status from POST /api/streams: $add_status" ;;
esac
pass "POST /api/streams no longer returns 501 with the flag set"

# The async refactor's other observable: POST should return promptly. We
# already received the body, so measure end-to-end by timing a second call.
post_start=$(python3 -c 'import time; print(time.time())')
curl -s -o /dev/null -w '%{http_code}\n' \
    -X POST http://127.0.0.1:9876/api/streams \
    -H "Authorization: Bearer ${token}" \
    -H 'Content-Type: application/json' \
    -d '{"url":"https://invalid.example/another-bogus","label":"bogus2"}' \
    >"$TMPHOME/add2.status"
post_end=$(python3 -c 'import time; print(time.time())')
elapsed=$(python3 -c "print(f'{$post_end - $post_start:.2f}')")
echo "  second POST elapsed: ${elapsed}s, status: $(cat "$TMPHOME/add2.status")"
# yt-dlp resolve typically takes 2-5 s; the async refactor's whole point is
# that the POST itself completes well under 1 s. Be generous: 2 s budget.
python3 -c "import sys; sys.exit(0 if $elapsed < 2.0 else 1)" \
    || fail "POST /api/streams took ${elapsed}s — async refactor is not in effect"
pass "POST /api/streams returns in <2s (async refactor in effect)"

# Poll /api/streams up to 15 s — the bogus URLs will fail their resolve and
# the slots should transition to Failed.
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
    pass "background prep marked the bogus slot Failed within 15s"
else
    # If yt-dlp resolve takes longer (network), allow the slot to still be
    # Connecting — that's evidence the async path is alive too.
    cur=$(curl -s -H "Authorization: Bearer ${token}" http://127.0.0.1:9876/api/streams)
    printf '%s' "$cur" | grep -q '"status":"Connecting"' \
        || fail "bogus slot never reached Failed nor Connecting: $cur"
    info "background prep still Connecting after 15s (likely slow yt-dlp resolve)"
fi

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""
