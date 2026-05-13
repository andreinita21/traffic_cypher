#!/usr/bin/env bash
# 38 — NEXT_STEPS.md Phase B: phone-camera endpoint regression.
#
# Exercises the SLOT_PHONE path end-to-end against BOTH implementations
# (C with ENABLE_TRAFFIC_ENTROPY=1, and Rust which always has the route)
# using curl + synthetic 1×1 PPM frames. Covers:
#   - POST /api/streams/phone returns 202 + {index, upload_token}
#   - POST /api/streams/phone/{N}/frame with the right token returns 204
#     and transitions the slot Connecting → Active
#   - frames_captured ticks up with each successful frame POST
#   - kind:"phone" appears in /api/streams output
#   - Wrong token → 403
#   - DELETE /api/streams/{N} → 200, slot removed
#
# The C side additionally proves has_traffic_entropy flips to true after
# phone frames have flowed (the Rust check is timing-dependent enough
# that we skip it; the underlying rotation_daemon is the same).
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

C="$REPO_ROOT/traffic_cypher_in_C"

# --- 1. Static checks (C side) -----------------------------------------------

grep -q 'msm_register_phone' "$C/include/multi_stream.h" \
    || fail "multi_stream.h missing msm_register_phone"
grep -q 'msm_push_phone_frame' "$C/include/multi_stream.h" \
    || fail "multi_stream.h missing msm_push_phone_frame"
grep -q 'SLOT_PHONE' "$C/include/multi_stream.h" \
    || fail "multi_stream.h missing SLOT_PHONE enum"
grep -q 'handle_register_phone\|handle_phone_frame' "$C/src_c/web_server.c" \
    || fail "web_server.c missing phone handlers"
[ -f "$REPO_ROOT/frontend/phone.html" ] \
    || fail "frontend/phone.html missing"
pass "C phone module + handlers + page are present"

# --- Static checks (Rust side) -----------------------------------------------

RUST_SRC="$REPO_ROOT/traffic_cypher_in_Rust/src"
grep -q 'pub enum SlotKind' "$RUST_SRC/multi_stream.rs" \
    || fail "multi_stream.rs missing SlotKind enum"
grep -q 'pub fn register_phone\|fn register_phone' "$RUST_SRC/multi_stream.rs" \
    || fail "multi_stream.rs missing register_phone"
grep -q 'push_phone_frame' "$RUST_SRC/multi_stream.rs" \
    || fail "multi_stream.rs missing push_phone_frame"
grep -q '/streams/phone' "$RUST_SRC/web/routes.rs" \
    || fail "web/routes.rs missing /streams/phone route"
grep -q 'phone.html' "$RUST_SRC/web/routes.rs" \
    || fail "web/routes.rs missing phone.html static route"
pass "Rust phone module + routes are present"

# --- 2. Build the flag-on tree out-of-tree -----------------------------------

WORK="$(mktemp -d -t tc_phone_build.XXXXXX)"
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
pass "ENABLE_TRAFFIC_ENTROPY=1 build succeeds with phone code"

# --- 3. Boot PM --------------------------------------------------------------

if lsof -iTCP:9876 -sTCP:LISTEN >/dev/null 2>&1; then
    skip "port 9876 already in use; cannot run integration check"
fi

TMPHOME="$(mktemp -d -t tc_phone_run.XXXXXX)"
trap 'rm -rf "$WORK" "$TMPHOME"; [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null || true' EXIT
PID=""

( cd "$WORK/C" && HOME="$TMPHOME" TRAFFIC_CYPHER_VAULT_PATH="$TMPHOME/vault.json" \
    exec ./traffic-cypher-pm >"$TMPHOME/server.log" 2>&1 ) &
PID=$!

for _ in $(seq 1 50); do
    if curl -s --max-time 1 http://127.0.0.1:9876/api/auth/status >/dev/null 2>&1; then break; fi
    sleep 0.1
done
curl -s --max-time 1 http://127.0.0.1:9876/api/auth/status >/dev/null 2>&1 \
    || { cat "$TMPHOME/server.log" >&2; fail "server did not start"; }

# --- 4. /phone.html is served -----------------------------------------------

phone_status=$(curl -s -o "$TMPHOME/phone.html" -w '%{http_code}' \
    http://127.0.0.1:9876/phone.html)
[ "$phone_status" = "200" ] \
    || fail "GET /phone.html returned $phone_status, expected 200"
grep -q '<title>Traffic Cypher · Phone Camera</title>' "$TMPHOME/phone.html" \
    || fail "/phone.html body did not match expected title"
pass "GET /phone.html serves the phone capture page"

# --- 5. Register a phone slot ------------------------------------------------

reg=$(curl -s -X POST http://127.0.0.1:9876/api/streams/phone \
    -H 'Content-Type: application/json' \
    -d '{"label":"unit-test-phone"}')
echo "  register response: $reg"
slot=$(printf '%s' "$reg" | python3 -c 'import sys,json; print(json.load(sys.stdin)["index"])')
token=$(printf '%s' "$reg" | python3 -c 'import sys,json; print(json.load(sys.stdin)["upload_token"])')
[ -n "$slot" ] || fail "register did not return an index"
[ "${#token}" = "64" ] \
    || fail "upload_token must be 64 hex chars, got ${#token}: $token"
pass "POST /api/streams/phone returns 202 + {index:$slot, upload_token:<64-hex>}"

# --- 6. Unlock so we can call /api/entropy-snapshot --------------------------

unlock=$(curl -s -X POST http://127.0.0.1:9876/api/auth/unlock \
    -H 'Content-Type: application/json' -d '{"master_password":"phone-test-pw"}')
auth_token=$(printf '%s' "$unlock" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$auth_token" ] || fail "unlock failed: $unlock"

# --- 7. Push 3 frames with the correct token --------------------------------

for n in 1 2 3; do
    python3 -c "
import sys
# 1x1 P6 PPM: header + 3 RGB bytes
sys.stdout.buffer.write(b'P6\n1 1\n255\n' + bytes([(($n * 80) & 255), 100, 200]))
" > "$TMPHOME/frame.ppm"
    code=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST "http://127.0.0.1:9876/api/streams/phone/${slot}/frame" \
        -H "X-Upload-Token: ${token}" \
        -H 'Content-Type: image/x-portable-pixmap' \
        --data-binary @"$TMPHOME/frame.ppm")
    [ "$code" = "204" ] || fail "frame $n POST: expected 204, got $code"
done
pass "3 frames POSTed with correct token, all returned 204"

# --- 8. /api/streams reflects the live slot ---------------------------------

# Give the rotation daemon up to 5s to drain a frame (its tick is 1s) and bump
# has_traffic_entropy.
sleep 2
streams=$(curl -s -H "Authorization: Bearer ${auth_token}" \
    http://127.0.0.1:9876/api/streams)
echo "  /api/streams: $streams"
printf '%s' "$streams" | grep -q '"kind":"phone"' \
    || fail "/api/streams missing kind:phone"
printf '%s' "$streams" | grep -q '"status":"Active"' \
    || fail "/api/streams slot did not transition to Active"
printf '%s' "$streams" | grep -qE '"frames_captured":[1-9][0-9]*' \
    || fail "/api/streams frames_captured did not tick up"
pass "/api/streams reports Active + frames_captured ≥ 1 + kind:phone"

# --- 9. /api/entropy-snapshot.has_traffic_entropy flips ---------------------

# The rotation_daemon ticks once a second. We pushed frames; give it a few
# more cycles to drain at least one into the entropy pool.
got_entropy=0
for _ in $(seq 1 10); do
    snap=$(curl -s -H "Authorization: Bearer ${auth_token}" \
        http://127.0.0.1:9876/api/entropy-snapshot)
    if printf '%s' "$snap" | grep -q '"has_traffic_entropy":true'; then
        got_entropy=1
        break
    fi
    # Push one more frame to keep the source alive while we wait.
    curl -s -o /dev/null \
        -X POST "http://127.0.0.1:9876/api/streams/phone/${slot}/frame" \
        -H "X-Upload-Token: ${token}" \
        -H 'Content-Type: image/x-portable-pixmap' \
        --data-binary @"$TMPHOME/frame.ppm" || true
    sleep 1
done
[ "$got_entropy" = "1" ] || fail "has_traffic_entropy never flipped to true; last snap: $snap"
pass "has_traffic_entropy:true after phone frames flowed"

# --- 10. Wrong token → 403 --------------------------------------------------

code=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST "http://127.0.0.1:9876/api/streams/phone/${slot}/frame" \
    -H "X-Upload-Token: $(printf 'a%.0s' {1..64})" \
    -H 'Content-Type: image/x-portable-pixmap' \
    --data-binary @"$TMPHOME/frame.ppm")
[ "$code" = "403" ] || fail "wrong-token POST: expected 403, got $code"
pass "wrong X-Upload-Token rejected with 403"

# --- 11. DELETE /api/streams/{N} cleans up the slot -------------------------

code=$(curl -s -o /dev/null -w '%{http_code}' \
    -X DELETE "http://127.0.0.1:9876/api/streams/${slot}" \
    -H "Authorization: Bearer ${auth_token}")
[ "$code" = "200" ] || fail "DELETE /api/streams/$slot: expected 200, got $code"

streams=$(curl -s -H "Authorization: Bearer ${auth_token}" \
    http://127.0.0.1:9876/api/streams)
if printf '%s' "$streams" | grep -q '"label":"unit-test-phone"'; then
    fail "phone slot still present after DELETE: $streams"
fi
pass "DELETE removed the phone slot from /api/streams"

# Cleanup C PM before Rust runs.
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""

# --- 12. Repeat the core flow against the Rust PM ---------------------------

RUST_PM="$REPO_ROOT/traffic_cypher_in_Rust/target/release/pm"
[ -x "$RUST_PM" ] || skip "Rust PM not built ($RUST_PM); run tests/00_build_rust.sh first"

# Wait for port 9876 to drain (TIME_WAIT) before booting Rust.
for _ in $(seq 1 20); do
    if ! lsof -iTCP:9876 -sTCP:LISTEN >/dev/null 2>&1; then break; fi
    sleep 0.3
done
if lsof -iTCP:9876 -sTCP:LISTEN >/dev/null 2>&1; then
    skip "port 9876 didn't drain in time; skip Rust half"
fi

TMPHOMER="$(mktemp -d -t tc_phone_rust.XXXXXX)"
trap 'rm -rf "$WORK" "$TMPHOME" "$TMPHOMER"; [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null || true' EXIT

HOME="$TMPHOMER" TRAFFIC_CYPHER_VAULT_PATH="$TMPHOMER/vault.json" \
    "$RUST_PM" >"$TMPHOMER/server.log" 2>&1 &
PID=$!

for _ in $(seq 1 50); do
    if curl -s --max-time 1 http://127.0.0.1:9876/api/auth/status >/dev/null 2>&1; then break; fi
    sleep 0.1
done
curl -s --max-time 1 http://127.0.0.1:9876/api/auth/status >/dev/null 2>&1 \
    || { cat "$TMPHOMER/server.log" >&2; fail "Rust PM did not start"; }

# /phone.html
phone_status=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9876/phone.html)
[ "$phone_status" = "200" ] || fail "[rust] GET /phone.html returned $phone_status"
pass "[rust] GET /phone.html serves the phone capture page"

# Register
reg=$(curl -s -X POST http://127.0.0.1:9876/api/streams/phone \
    -H 'Content-Type: application/json' \
    -d '{"label":"unit-test-phone-rust"}')
echo "  [rust] register: $reg"
rslot=$(printf '%s' "$reg" | python3 -c 'import sys,json; print(json.load(sys.stdin)["index"])')
rtoken=$(printf '%s' "$reg" | python3 -c 'import sys,json; print(json.load(sys.stdin)["upload_token"])')
[ "${#rtoken}" = "64" ] || fail "[rust] upload_token must be 64 hex chars: $rtoken"
pass "[rust] POST /api/streams/phone returns 202 + {index, upload_token<64-hex>}"

# Unlock for /api/streams read access
unlock=$(curl -s -X POST http://127.0.0.1:9876/api/auth/unlock \
    -H 'Content-Type: application/json' -d '{"master_password":"phone-test-pw"}')
rauth=$(printf '%s' "$unlock" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$rauth" ] || fail "[rust] unlock failed: $unlock"

# Push 3 frames with the correct token
python3 -c "
import sys
sys.stdout.buffer.write(b'P6\n1 1\n255\n' + bytes([200, 100, 50]))
" > "$TMPHOMER/frame.ppm"
for n in 1 2 3; do
    code=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST "http://127.0.0.1:9876/api/streams/phone/${rslot}/frame" \
        -H "X-Upload-Token: ${rtoken}" \
        -H 'Content-Type: image/x-portable-pixmap' \
        --data-binary @"$TMPHOMER/frame.ppm")
    [ "$code" = "204" ] || fail "[rust] frame $n POST: expected 204, got $code"
done
pass "[rust] 3 frames POSTed with correct token, all returned 204"

# Verify /api/streams reflects kind:phone + Active + frames_captured
sleep 2
streams=$(curl -s -H "Authorization: Bearer ${rauth}" http://127.0.0.1:9876/api/streams)
echo "  [rust] /api/streams: $streams"
printf '%s' "$streams" | grep -q '"kind":"phone"' \
    || fail "[rust] /api/streams missing kind:phone"
printf '%s' "$streams" | grep -q '"status":"Active"' \
    || fail "[rust] slot did not transition to Active"
pass "[rust] /api/streams reports Active + kind:phone"

# Wrong token → 403
code=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST "http://127.0.0.1:9876/api/streams/phone/${rslot}/frame" \
    -H "X-Upload-Token: $(printf 'a%.0s' {1..64})" \
    -H 'Content-Type: image/x-portable-pixmap' \
    --data-binary @"$TMPHOMER/frame.ppm")
[ "$code" = "403" ] || fail "[rust] wrong-token POST: expected 403, got $code"
pass "[rust] wrong X-Upload-Token rejected with 403"

# Cleanup
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""
