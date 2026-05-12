#!/bin/bash
# 22 — #7a regression: a silent TCP client cannot freeze the server forever.
# With SO_RCVTIMEO=15s, a client that opens a connection and never writes
# must be dropped by the server within ~16s.
#
# Implementation note: we use python3 to hold a socket open without writing.
# `nc < /dev/null` closes its end immediately on EOF, which would mask the
# server-side timeout. python3 is available on every supported dev box.
#
# Slow: this test sleeps ~15-17 s by design.
set -u
source "$(dirname "$0")/lib/common.sh"

require_cmd curl
require_cmd python3

PM="$REPO_ROOT/traffic_cypher_in_C/traffic-cypher-pm"
[ -x "$PM" ] || fail "traffic-cypher-pm not built; run tests/01_build_c.sh first"

PORT=9876
if curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1; then
    fail "Port $PORT is already in use; aborting to avoid contaminating an existing PM session"
fi

VAULT="/tmp/tc_test_22_vault_$$.json"
LOG="/tmp/tc_test_22_log_$$.txt"
export TRAFFIC_CYPHER_VAULT_PATH="$VAULT"

cleanup() {
    if [ -n "${PM_PID:-}" ]; then
        kill "$PM_PID" 2>/dev/null || true
        wait "$PM_PID" 2>/dev/null || true
    fi
    rm -f "$VAULT" "$LOG"
}
trap cleanup EXIT

"$PM" >"$LOG" 2>&1 &
PM_PID=$!

# Wait up to 5 s for the listener to come up.
for _ in $(seq 1 50); do
    if curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if ! curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1; then
    fail "PM did not bind $PORT within 5 s — server log:
$(cat "$LOG")"
fi
pass "PM bound 127.0.0.1:$PORT"

# Open a TCP connection, send no bytes, and time how long until the
# server closes us. Expected: ~15 s (the SO_RCVTIMEO).
info "Opening silent TCP connection (expect server-side close in ~15 s) …"
START_TS=$(date +%s)
python3 - "$PORT" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])
s = socket.socket()
s.settimeout(30)  # Client-side bail — well above the 15 s server timeout.
s.connect(("127.0.0.1", port))
# Send nothing. Wait for the server to close from its end (recv returns b'')
# or for our own settimeout to bail.
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break  # Server closed us — good
except (socket.timeout, ConnectionResetError, OSError):
    pass
s.close()
PYEOF
END_TS=$(date +%s)
ELAPSED=$(( END_TS - START_TS ))

if [ "$ELAPSED" -lt 10 ]; then
    fail "Silent connection closed in ${ELAPSED}s — too fast (expected ~15 s); server timeout may not be wired correctly"
fi
if [ "$ELAPSED" -gt 22 ]; then
    fail "Silent connection lasted ${ELAPSED}s — server-side timeout did not fire within 22 s (regression of #7a)"
fi
pass "Silent connection closed by server in ${ELAPSED}s (expected ≈15 s)"

# After the timeout fired, the server must accept new requests again.
info "Verifying server is still responsive after the timeout cycle …"
if curl -s -m 5 "http://127.0.0.1:$PORT/api/auth/status" | grep -q unlocked; then
    pass "Server still serves /api/auth/status after silent-client timeout"
else
    fail "Server is unresponsive after silent-client timeout — log:
$(cat "$LOG")"
fi
