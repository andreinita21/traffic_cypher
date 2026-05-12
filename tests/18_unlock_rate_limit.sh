#!/bin/bash
# 18 — REMEDIATION_PLAN.md §8: rate-limit /api/auth/unlock.
#
# After 5 failed unlocks within 60 s the 6th attempt (right OR wrong password)
# must return HTTP 429 with a Retry-After header until the lockout elapses. A
# successful unlock resets the failure counter.
#
# Slowness: this test would naturally need a ≥31 s sleep for the cooldown to
# expire. To keep the suite snappy, both PMs honour the TC_UNLOCK_LOCKOUT_S
# env var to override the 30 s default; the test sets it to 2 s. End-to-end
# the test sleeps ~3 s of wall time instead of ~31 s. The hook is documented
# in `src/web/routes.rs::unlock_lockout_secs` (Rust) and `web_server.c::
# unlock_lockout_secs` (C).
set -u
source "$(dirname "$0")/lib/common.sh"

require_cmd curl

C_PM="$REPO_ROOT/traffic_cypher_in_C/traffic-cypher-pm"
RUST_PM="$REPO_ROOT/traffic_cypher_in_Rust/target/release/pm"

[ -x "$C_PM" ]    || fail "C PM not built (run tests/01_build_c.sh)"
[ -x "$RUST_PM" ] || fail "Rust PM not built (run tests/00_build_rust.sh)"

PORT=9876
LOCKOUT_S=2          # short cooldown for the test
CORRECT_PW='correct horse battery staple'
WRONG_PW='wrong-${RANDOM}'

PM_PID=""
VAULT=""
LOG=""

cleanup() {
    if [ -n "$PM_PID" ]; then
        kill "$PM_PID" 2>/dev/null || true
        wait "$PM_PID" 2>/dev/null || true
    fi
    rm -f "$VAULT" "$LOG"
    PM_PID=""
}
trap cleanup EXIT

# --- helpers --------------------------------------------------------------

# POST /api/auth/unlock with the given password. Echoes
#   "<status_code>|<retry_after_or_empty>"
unlock_attempt() {
    local pw="$1"
    local resp
    resp=$(curl -s -m 5 -o /dev/null \
                -D - \
                -X POST \
                -H 'Content-Type: application/json' \
                --data "{\"master_password\":\"$pw\"}" \
                "http://127.0.0.1:$PORT/api/auth/unlock")
    local code retry
    code=$(printf '%s' "$resp" | awk 'NR==1 {print $2}')
    # Header name matching must be case-insensitive — axum emits lowercase
    # ("retry-after") while the C build emits canonical "Retry-After".
    retry=$(printf '%s' "$resp" \
        | tr -d '\r' \
        | grep -i '^retry-after:' \
        | head -1 \
        | awk -F': *' '{print $2}')
    printf '%s|%s' "$code" "$retry"
}

# Wait for the PM listener to bind. Fails the test if it never does.
wait_for_listener() {
    local label="$1"
    for _ in $(seq 1 60); do
        if curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    fail "$label PM did not bind $PORT — log:
$(cat "$LOG")"
}

# Bootstrap a real vault file under the configured TRAFFIC_CYPHER_VAULT_PATH.
# Without this, load_vault() short-circuits on a missing file and accepts ANY
# password, so the 'wrong password' path can't be exercised.
bootstrap_vault() {
    local r
    r=$(curl -s -m 5 \
             -X POST -H 'Content-Type: application/json' \
             --data "{\"master_password\":\"$CORRECT_PW\"}" \
             "http://127.0.0.1:$PORT/api/auth/unlock")
    local tok
    tok=$(printf '%s' "$r" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    [ -n "$tok" ] || fail "bootstrap unlock failed: $r"

    curl -s -m 5 -o /dev/null \
         -X POST -H 'Content-Type: application/json' \
         -H "Authorization: Bearer $tok" \
         --data '{"label":"seed"}' \
         "http://127.0.0.1:$PORT/api/credentials"

    curl -s -m 5 -o /dev/null \
         -X POST \
         -H "Authorization: Bearer $tok" \
         "http://127.0.0.1:$PORT/api/auth/lock"
}

# --- per-PM scenario ------------------------------------------------------

run_scenario() {
    local label="$1" pm_bin="$2"

    info "[$label] starting PM with TC_UNLOCK_LOCKOUT_S=$LOCKOUT_S"
    VAULT="/tmp/tc_test_18_${label}_vault_$$.json"
    LOG="/tmp/tc_test_18_${label}_log_$$.txt"
    rm -f "$VAULT"

    if curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1; then
        fail "[$label] port $PORT already in use"
    fi

    TRAFFIC_CYPHER_VAULT_PATH="$VAULT" \
    TC_UNLOCK_LOCKOUT_S="$LOCKOUT_S" \
        "$pm_bin" >"$LOG" 2>&1 &
    PM_PID=$!
    wait_for_listener "$label"

    bootstrap_vault
    info "[$label] vault bootstrapped at $VAULT"

    # --- Case A: 5 wrong → 6th locks; cooldown clears; correct=200 -------
    for i in 1 2 3 4 5; do
        local r; r=$(unlock_attempt "$WRONG_PW")
        local code="${r%%|*}"
        if [ "$code" != "401" ]; then
            fail "[$label] wrong-password attempt #$i expected 401 got '$code'"
        fi
    done
    pass "[$label] 5 wrong-password attempts returned 401"

    local r6; r6=$(unlock_attempt "$WRONG_PW")
    local code6="${r6%%|*}" retry6="${r6##*|}"
    if [ "$code6" != "429" ]; then
        fail "[$label] 6th attempt expected 429 got '$code6' (retry='$retry6')"
    fi
    if [ -z "$retry6" ]; then
        fail "[$label] 6th attempt returned 429 but no Retry-After header"
    fi
    pass "[$label] 6th attempt returned 429 with Retry-After: $retry6"

    # During lockout, even the CORRECT password is refused.
    local rc; rc=$(unlock_attempt "$CORRECT_PW")
    if [ "${rc%%|*}" != "429" ]; then
        fail "[$label] correct password during lockout expected 429 got '${rc%%|*}'"
    fi
    pass "[$label] correct password during lockout also returned 429"

    info "[$label] sleeping $((LOCKOUT_S + 1))s for cooldown …"
    sleep "$((LOCKOUT_S + 1))"

    # After cooldown, a WRONG password must return 401 (lockout cleared), not 429.
    local rw; rw=$(unlock_attempt "$WRONG_PW")
    if [ "${rw%%|*}" != "401" ]; then
        fail "[$label] post-cooldown wrong-password expected 401 got '${rw%%|*}'"
    fi
    pass "[$label] post-cooldown wrong password returned 401"

    # Finally, the correct password should succeed (200).
    local rok; rok=$(unlock_attempt "$CORRECT_PW")
    if [ "${rok%%|*}" != "200" ]; then
        fail "[$label] post-cooldown correct password expected 200 got '${rok%%|*}'"
    fi
    pass "[$label] post-cooldown correct password returned 200"

    # --- Case B: success resets the counter ------------------------------
    # PM is now unlocked. Lock it back (it's already 'unlocked' from above),
    # then verify the counter reset by doing 3 wrong + 1 correct + 5 wrong.
    # The state is already reset (unlock just succeeded), so we don't need
    # an explicit /api/auth/lock here — we just want to count failures.

    # Wait out any leftover window safety (the sliding window doesn't carry
    # over after success but extra safety doesn't hurt and is cheap).

    for i in 1 2 3; do
        local r; r=$(unlock_attempt "$WRONG_PW")
        if [ "${r%%|*}" != "401" ]; then
            fail "[$label] reset-case wrong #$i expected 401 got '${r%%|*}'"
        fi
    done

    local rs; rs=$(unlock_attempt "$CORRECT_PW")
    if [ "${rs%%|*}" != "200" ]; then
        fail "[$label] reset-case correct expected 200 got '${rs%%|*}'"
    fi
    pass "[$label] success after 3 wrong returned 200 (reset path engaged)"

    # Now 5 more wrong should each be 401, then a 6th = 429. Confirms the
    # earlier 3 failures did not 'carry over' past the success.
    for i in 1 2 3 4 5; do
        local r; r=$(unlock_attempt "$WRONG_PW")
        if [ "${r%%|*}" != "401" ]; then
            fail "[$label] reset-case post-success wrong #$i expected 401 got '${r%%|*}' (counter did not reset!)"
        fi
    done
    local rlock; rlock=$(unlock_attempt "$WRONG_PW")
    if [ "${rlock%%|*}" != "429" ]; then
        fail "[$label] reset-case 6th-after-success expected 429 got '${rlock%%|*}'"
    fi
    pass "[$label] counter reset confirmed (3 wrong → success → 5 wrong → 6th=429)"

    cleanup
    sleep 1  # let kernel release listening socket
}

run_scenario rust "$RUST_PM"
run_scenario c    "$C_PM"
