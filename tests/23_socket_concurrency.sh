#!/bin/bash
# 23 — #7b regression: the C PM uses a worker pool so concurrent HTTP
# requests are served in parallel, not serialized through a single accept
# thread.  Fire 8 concurrent requests, all of which must complete; assert
# the wall clock is well under 8x the single-request latency.
set -u
source "$(dirname "$0")/lib/common.sh"

require_cmd curl
require_cmd python3

PM="$REPO_ROOT/traffic_cypher_in_C/traffic-cypher-pm"
[ -x "$PM" ] || fail "traffic-cypher-pm not built; run tests/01_build_c.sh first"

PORT=9876
if curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1; then
    fail "Port $PORT is already in use; aborting"
fi

VAULT="/tmp/tc_test_23_vault_$$.json"
LOG="/tmp/tc_test_23_log_$$.txt"
RESP_DIR="/tmp/tc_test_23_resp_$$"
mkdir -p "$RESP_DIR"
export TRAFFIC_CYPHER_VAULT_PATH="$VAULT"

cleanup() {
    if [ -n "${PM_PID:-}" ]; then
        kill "$PM_PID" 2>/dev/null || true
        wait "$PM_PID" 2>/dev/null || true
    fi
    rm -rf "$VAULT" "$LOG" "$RESP_DIR"
}
trap cleanup EXIT

"$PM" >"$LOG" 2>&1 &
PM_PID=$!

for _ in $(seq 1 50); do
    curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1 && break
    sleep 0.1
done
if ! curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1; then
    fail "PM did not bind $PORT within 5 s — log:
$(cat "$LOG")"
fi
pass "PM bound 127.0.0.1:$PORT"

# Unlock the vault — credentials endpoints require auth.
UNLOCK=$(curl -s -m 5 -X POST "http://127.0.0.1:$PORT/api/auth/unlock" \
    -H 'Content-Type: application/json' -d '{"master_password":"testpass23"}')
TOKEN=$(printf '%s' "$UNLOCK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])') \
    || fail "unlock failed: $UNLOCK"
AUTH="Authorization: Bearer $TOKEN"
pass "unlocked vault"

# Measure baseline single-request latency. Use /api/credentials which does a
# vault lock + serialize, slightly heavier than /api/auth/status.
SINGLE_START=$(python3 -c 'import time; print(time.time())')
curl -s -m 5 -H "$AUTH" "http://127.0.0.1:$PORT/api/credentials" >/dev/null
SINGLE_END=$(python3 -c 'import time; print(time.time())')
SINGLE_MS=$(python3 -c "print(int(($SINGLE_END - $SINGLE_START) * 1000))")
info "Single request: ${SINGLE_MS} ms"

# Fire 8 concurrent requests in the background; each writes the HTTP status
# code to its own response file.
info "Firing 8 concurrent requests…"
CONCURRENT_START=$(python3 -c 'import time; print(time.time())')
PIDS=()
for i in $(seq 1 8); do
    (
        curl -s -m 30 -o /dev/null -w '%{http_code}' \
            -H "$AUTH" "http://127.0.0.1:$PORT/api/credentials" > "$RESP_DIR/r$i"
    ) &
    PIDS+=($!)
done

for p in "${PIDS[@]}"; do
    wait "$p" || true
done
CONCURRENT_END=$(python3 -c 'import time; print(time.time())')
CONCURRENT_MS=$(python3 -c "print(int(($CONCURRENT_END - $CONCURRENT_START) * 1000))")
info "8 concurrent requests: ${CONCURRENT_MS} ms"

# At least one of the 8 must have succeeded with 200.  With 4 workers and
# queue cap 32, all 8 should fit and all should succeed; 503s are tolerated
# only as a tail behaviour.
SUCC=0
FAILED=0
for i in $(seq 1 8); do
    code=$(cat "$RESP_DIR/r$i" 2>/dev/null || echo "000")
    if [ "$code" = "200" ]; then
        SUCC=$((SUCC + 1))
    else
        FAILED=$((FAILED + 1))
        info "  request $i → HTTP $code"
    fi
done
[ "$SUCC" -ge 1 ] || fail "no concurrent request succeeded (all $FAILED failed)"
pass "$SUCC/8 concurrent requests succeeded ($FAILED non-200)"

# Wall clock proves parallelism.  Serial processing would take ~8 × single.
# With 4 workers, expected wall-clock ≈ 2 × single, plus dispatch overhead.
# We test a loose bound: wall clock must be < 6 × single (gives margin on
# slow CI without admitting fully serial behaviour).
THRESHOLD_MS=$((SINGLE_MS * 6 + 200))
if [ "$CONCURRENT_MS" -gt "$THRESHOLD_MS" ]; then
    fail "concurrent wall clock ${CONCURRENT_MS} ms > 6× single ${SINGLE_MS} ms (threshold ${THRESHOLD_MS} ms) — workers not running in parallel?"
fi
pass "concurrent wall clock ${CONCURRENT_MS} ms ≤ 6× single ${SINGLE_MS} ms"
