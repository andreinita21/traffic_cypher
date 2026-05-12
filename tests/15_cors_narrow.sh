#!/bin/bash
# 15 — CORS is narrowed to http://127.0.0.1:9876 only; Allow-Headers drops Authorization.
# Runs both PMs sequentially because they share port 9876.
set -u
source "$(dirname "$0")/lib/common.sh"

require_cmd curl

C_PM="$REPO_ROOT/traffic_cypher_in_C/traffic-cypher-pm"
RUST_PM="$REPO_ROOT/traffic_cypher_in_Rust/target/release/pm"

for b in "$C_PM" "$RUST_PM"; do
    [ -x "$b" ] || fail "binary not built: $b"
done

if curl -s -m 1 "http://127.0.0.1:9876/api/auth/status" >/dev/null 2>&1; then
    fail "Port 9876 is already in use; aborting"
fi

EXPECTED_ORIGIN="http://127.0.0.1:9876"
EVIL_ORIGIN="https://evil.example"

# Extract the value of a header from `curl -i` output, lowercased, trimmed of \r.
# Robust against arbitrary case in the header name.
extract_header_value() {
    local headers="$1"
    local name_lower="$2"
    printf '%s\n' "$headers" \
        | awk -v want="$name_lower" '
            {
                # Split on the first colon.
                idx = index($0, ":")
                if (idx == 0) next
                name = substr($0, 1, idx - 1)
                val  = substr($0, idx + 1)
                # Lowercase the name for case-insensitive match.
                lname = tolower(name)
                if (lname == want) {
                    # Strip leading/trailing whitespace and CR.
                    gsub(/^[ \t]+|[ \t\r]+$/, "", val)
                    print val
                    exit
                }
            }
        '
}

wait_for_pm() {
    local name="$1"
    for _ in $(seq 1 50); do
        if curl -s -m 1 http://127.0.0.1:9876/api/auth/status | grep -q unlocked; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

check_cors() {
    local label="$1"
    local raw
    raw="$(curl -s -i -X OPTIONS \
        -H "Origin: ${EVIL_ORIGIN}" \
        -H "Access-Control-Request-Method: GET" \
        -H "Access-Control-Request-Headers: Authorization, Content-Type" \
        http://127.0.0.1:9876/api/auth/status)"

    # Keep only the header block (everything before the first blank line).
    local headers
    headers="$(printf '%s\n' "$raw" | awk 'BEGIN{RS=""} NR==1{print; exit}')"

    local origin
    origin="$(extract_header_value "$headers" "access-control-allow-origin")"
    if [ -z "$origin" ]; then
        fail "$label: no Access-Control-Allow-Origin header in response"
    fi
    if [ "$origin" = "*" ]; then
        fail "$label: Access-Control-Allow-Origin is wildcard '*'"
    fi
    if [ "$origin" = "$EVIL_ORIGIN" ]; then
        fail "$label: Access-Control-Allow-Origin echoes attacker origin ($origin)"
    fi
    if [ "$origin" != "$EXPECTED_ORIGIN" ]; then
        fail "$label: Access-Control-Allow-Origin is '$origin', expected '$EXPECTED_ORIGIN'"
    fi
    pass "$label: Allow-Origin is $EXPECTED_ORIGIN (not '*', not echoed)"

    local allow_hdrs
    allow_hdrs="$(extract_header_value "$headers" "access-control-allow-headers")"
    # Lowercase the value for case-insensitive substring check.
    local allow_hdrs_lc
    allow_hdrs_lc="$(printf '%s' "$allow_hdrs" | tr '[:upper:]' '[:lower:]')"
    if [ -n "$allow_hdrs_lc" ] && printf '%s' "$allow_hdrs_lc" | grep -q 'authorization'; then
        fail "$label: Access-Control-Allow-Headers still contains Authorization: '$allow_hdrs'"
    fi
    pass "$label: Allow-Headers does not contain Authorization (value='$allow_hdrs')"
}

# --- C PM ---
VAULT_C="/tmp/tc_test_15_c_vault_$$.json"
LOG_C="/tmp/tc_test_15_c_log_$$.txt"
export TRAFFIC_CYPHER_VAULT_PATH="$VAULT_C"

"$C_PM" >"$LOG_C" 2>&1 &
PID=$!
if wait_for_pm "C PM"; then
    check_cors "C PM"
else
    kill $PID 2>/dev/null || true
    fail "C PM did not start — log:
$(cat "$LOG_C")"
fi
kill $PID 2>/dev/null || true
wait $PID 2>/dev/null || true
rm -f "$VAULT_C" "$LOG_C"

# Let the kernel release the listening socket before reusing the port.
sleep 1

# --- Rust PM ---
VAULT_R="/tmp/tc_test_15_rust_vault_$$.json"
LOG_R="/tmp/tc_test_15_rust_log_$$.txt"
export TRAFFIC_CYPHER_VAULT_PATH="$VAULT_R"

"$RUST_PM" >"$LOG_R" 2>&1 &
PID=$!
if wait_for_pm "Rust PM"; then
    check_cors "Rust PM"
else
    kill $PID 2>/dev/null || true
    fail "Rust PM did not start — log:
$(cat "$LOG_R")"
fi
kill $PID 2>/dev/null || true
wait $PID 2>/dev/null || true
rm -f "$VAULT_R" "$LOG_R"
