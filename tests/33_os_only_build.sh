#!/usr/bin/env bash
# 33 — NEXT_STEPS.md Phase C: opt-out OS-entropy-only build regression.
#
# After the default-flip, `make` produces the flag-on C build (full traffic
# entropy via MSM + phone endpoints). `make ENABLE_TRAFFIC_ENTROPY=0` is the
# opt-out path that restores the pre-#1a behaviour: handle_add_stream returns
# 501, /api/build/info reports traffic_entropy:false, the OS-only banner
# fires in the frontend.
#
# This test rebuilds the C tree out-of-tree with the opt-out flag and
# verifies:
#   - the binary carries the "traffic_entropy":false build_info literal
#     (and NOT the :true literal)
#   - `make ENABLE_TRAFFIC_ENTROPY=0` is honoured by the Makefile gate
#   - POST /api/streams returns 501 (the legacy "Not Implemented" path)
#   - POST /api/streams/phone is unreachable (404 — route is #ifdef-gated)
#   - GET /api/build/info returns the OS-only descriptor
#
# Mirrors the structure of tests/37_msm_e2e_smoke.sh and tests/38 — out-of-
# tree build, port-9876 boot, curl assertions.
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

C="$REPO_ROOT/traffic_cypher_in_C"

# Static checks (no rebuild needed).
grep -q 'ENABLE_TRAFFIC_ENTROPY' "$C/Makefile" \
    || fail "Makefile missing ENABLE_TRAFFIC_ENTROPY gate"
grep -q '^ifneq.*ENABLE_TRAFFIC_ENTROPY' "$C/Makefile" \
    || fail "Makefile ENABLE_TRAFFIC_ENTROPY gate is no longer the default-on (post-flip) shape"
grep -q 'ENABLE_TRAFFIC_ENTROPY' "$C/src_c/web_server.c" \
    || fail "web_server.c missing ENABLE_TRAFFIC_ENTROPY gate"
grep -q 'ENABLE_TRAFFIC_ENTROPY' "$C/src_c/key_rotation.c" \
    && fail "key_rotation.c should NOT gate on ENABLE_TRAFFIC_ENTROPY (daemon works in both modes)"
pass "Makefile + web_server.c expose the ENABLE_TRAFFIC_ENTROPY gate"

# Pin the CI job name so a future workflow rename can't quietly drop opt-out
# coverage. Renamed c-traffic-entropy → c-os-only post-flip.
CI_YML="$REPO_ROOT/.github/workflows/ci.yml"
if [ -f "$CI_YML" ]; then
    grep -q 'c-os-only' "$CI_YML" \
        || fail "ci.yml missing 'c-os-only' job — rename without updating this test would lose ENABLE_TRAFFIC_ENTROPY=0 coverage"
    pass "ci.yml still defines the c-os-only job"
fi

# Confirm the *default* on-disk binary carries the post-flip literal. If the
# on-disk binary is the opt-out variant (e.g. because the c-os-only CI job
# already ran make ENABLE_TRAFFIC_ENTROPY=0 in this checkout), skip this
# inverse check — the rest of the test rebuilds out-of-tree anyway.
BIN="$C/traffic-cypher-pm"
if command -v strings >/dev/null 2>&1 && [ -f "$BIN" ]; then
    if strings "$BIN" | grep -q '"traffic_entropy":true'; then
        # Default variant on disk — must NOT also carry the opt-out literal.
        if strings "$BIN" | grep -q '"traffic_entropy":false'; then
            fail "default binary unexpectedly contains BOTH literals"
        fi
        pass "default on-disk binary has the post-flip traffic_entropy:true literal"
    else
        info "skipping default-binary literal check (\$BIN is not the post-flip default)"
    fi
fi

# Rebuild WITH the opt-out, in a tmpcopy so we don't clobber the default
# artefacts that subsequent tests in run.sh depend on.
WORK="$(mktemp -d -t tc_os_only_build.XXXXXX)"
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
# Mirror the canonical frontend layout for the Makefile's `frontend` phony
# (`cp -R ../frontend ./frontend`). Symlink avoids a multi-MiB copy.
ln -s "$REPO_ROOT/frontend" "$WORK/frontend"

OPENSSL_PREFIX_DEFAULT="$(brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)"
export OPENSSL_PREFIX="${OPENSSL_PREFIX:-$OPENSSL_PREFIX_DEFAULT}"

( cd "$WORK/C" && make ENABLE_TRAFFIC_ENTROPY=0 >"$WORK/build.log" 2>&1 ) \
    || { cat "$WORK/build.log" >&2; fail "ENABLE_TRAFFIC_ENTROPY=0 build failed"; }
pass "ENABLE_TRAFFIC_ENTROPY=0 build succeeds"

if command -v strings >/dev/null 2>&1; then
    if ! strings "$WORK/C/traffic-cypher-pm" | grep -q '"traffic_entropy":false'; then
        fail "opt-out binary missing the OS-only build_info literal"
    fi
    if strings "$WORK/C/traffic-cypher-pm" | grep -q '"traffic_entropy":true'; then
        fail "opt-out binary unexpectedly contains the flag-on literal"
    fi
    pass "opt-out binary carries only the OS-only build_info literal"
fi

# Boot the opt-out PM briefly and hit /api/build/info + /api/streams.
if lsof -iTCP:9876 -sTCP:LISTEN >/dev/null 2>&1; then
    skip "port 9876 already in use; cannot run integration check"
fi

TMPHOME="$(mktemp -d -t tc_os_only_run.XXXXXX)"
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
    fail "opt-out server did not start"
fi

# /api/build/info — should be the OS-only descriptor.
build_info=$(curl -s http://127.0.0.1:9876/api/build/info)
echo "  build/info: $build_info"
echo "$build_info" | grep -q '"traffic_entropy":false' \
    || fail "/api/build/info did not report traffic_entropy:false"
echo "$build_info" | grep -q '"note"' \
    || fail "/api/build/info missing OS-only note field"
pass "/api/build/info reports the OS-only descriptor with the opt-out flag"

# Unlock to test the /api/streams paths.
unlock_resp=$(curl -s -X POST http://127.0.0.1:9876/api/auth/unlock \
    -H 'Content-Type: application/json' \
    -d '{"master_password":"os-only-test-pw"}')
token=$(printf '%s' "$unlock_resp" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || fail "unlock did not return a token: $unlock_resp"

# POST /api/streams must return 501 (the legacy "Not Implemented" path).
add_status=$(curl -s -o "$TMPHOME/add.body" -w '%{http_code}' \
    -X POST http://127.0.0.1:9876/api/streams \
    -H "Authorization: Bearer ${token}" \
    -H 'Content-Type: application/json' \
    -d '{"url":"https://example.com/anything","label":"opt-out-test"}')
echo "  POST /api/streams: $add_status — $(cat "$TMPHOME/add.body")"
[ "$add_status" = "501" ] \
    || fail "expected 501 from opt-out POST /api/streams, got $add_status"
pass "POST /api/streams returns 501 in the opt-out build"

# POST /api/streams/phone must be unreachable. With the route registered
# (flag-on build) it would 202 even without Bearer auth (the upload-token
# is the boundary). With the route NOT registered (opt-out build), the
# generic /api/* auth gate fires first → 401, or if we add Bearer → 404.
# Either non-202 response proves the route isn't actually serving.
phone_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:9876/api/streams/phone \
    -H 'Content-Type: application/json' \
    -d '{"label":"opt-out-phone"}')
echo "  POST /api/streams/phone (no auth): $phone_status"
case "$phone_status" in
    401|404) ;;
    202)
        fail "phone endpoint registered in opt-out build (got $phone_status — flag-gating broken)" ;;
    *)
        fail "unexpected status from opt-out POST /api/streams/phone: $phone_status" ;;
esac

# Confirm with Bearer auth — should be 404 (route doesn't exist), not 202.
phone_status2=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:9876/api/streams/phone \
    -H "Authorization: Bearer ${token}" \
    -H 'Content-Type: application/json' \
    -d '{"label":"opt-out-phone-auth"}')
echo "  POST /api/streams/phone (with Bearer): $phone_status2"
[ "$phone_status2" = "404" ] \
    || fail "opt-out phone endpoint should 404 with valid Bearer, got $phone_status2"
pass "POST /api/streams/phone unreachable in opt-out build (no-auth: $phone_status, bearer: 404)"

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""
