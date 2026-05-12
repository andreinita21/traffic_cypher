#!/bin/bash
# 99 — End-to-end smoke: both PMs and both CLIs are runnable.
# Runs sequentially because both PMs bind port 9876.
set -u
source "$(dirname "$0")/lib/common.sh"

require_cmd curl

C_CLI="$REPO_ROOT/traffic_cypher_in_C/traffic-cypher"
C_PM="$REPO_ROOT/traffic_cypher_in_C/traffic-cypher-pm"
RUST_CLI="$REPO_ROOT/traffic_cypher_in_Rust/target/release/traffic_cypher"
RUST_PM="$REPO_ROOT/traffic_cypher_in_Rust/target/release/pm"

for b in "$C_CLI" "$C_PM" "$RUST_CLI" "$RUST_PM"; do
    [ -x "$b" ] || fail "binary not built: $b"
done

if curl -s -m 1 "http://127.0.0.1:9876/api/auth/status" >/dev/null 2>&1; then
    fail "Port 9876 is already in use; aborting"
fi

# --- CLI --help on both ---
"$C_CLI" --help 2>&1 | grep -qi usage || fail "C CLI --help broken"
pass "C CLI --help works"

"$RUST_CLI" --help 2>&1 | grep -qi usage || fail "Rust CLI --help broken"
pass "Rust CLI --help works"

# --- C PM boots and serves ---
VAULT_C="/tmp/tc_test_99_c_vault_$$.json"
LOG_C="/tmp/tc_test_99_c_log_$$.txt"
export TRAFFIC_CYPHER_VAULT_PATH="$VAULT_C"

"$C_PM" >"$LOG_C" 2>&1 &
PID=$!
for _ in $(seq 1 50); do
    if curl -s -m 1 http://127.0.0.1:9876/api/auth/status | grep -q unlocked; then
        break
    fi
    sleep 0.1
done
if curl -s -m 2 http://127.0.0.1:9876/api/auth/status | grep -q unlocked; then
    pass "C PM serves /api/auth/status on 127.0.0.1:9876"
else
    kill $PID 2>/dev/null || true
    fail "C PM did not serve — log:
$(cat "$LOG_C")"
fi
kill $PID 2>/dev/null || true
wait $PID 2>/dev/null || true
rm -f "$VAULT_C" "$LOG_C"

# Let the kernel release the listening socket before reusing the port.
sleep 1

# --- Rust PM boots and serves ---
VAULT_R="/tmp/tc_test_99_rust_vault_$$.json"
LOG_R="/tmp/tc_test_99_rust_log_$$.txt"
export TRAFFIC_CYPHER_VAULT_PATH="$VAULT_R"

"$RUST_PM" >"$LOG_R" 2>&1 &
PID=$!
for _ in $(seq 1 50); do
    if curl -s -m 1 http://127.0.0.1:9876/api/auth/status | grep -q unlocked; then
        break
    fi
    sleep 0.1
done
if curl -s -m 2 http://127.0.0.1:9876/api/auth/status | grep -q unlocked; then
    pass "Rust PM serves /api/auth/status on 127.0.0.1:9876"
else
    kill $PID 2>/dev/null || true
    fail "Rust PM did not serve — log:
$(cat "$LOG_R")"
fi
kill $PID 2>/dev/null || true
wait $PID 2>/dev/null || true
rm -f "$VAULT_R" "$LOG_R"
