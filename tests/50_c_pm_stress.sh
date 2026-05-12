#!/usr/bin/env bash
# 50_c_pm_stress.sh
#
# Stress test exercising the post-#3 str_buf migration in web_server.c +
# vault.c. Pre-migration this would have blown past the fixed-size strcat
# buffers in handle_list_credentials / vault_entry_to_json / vault_to_json
# and either crashed (FORTIFY abort) or silently produced truncated JSON.
#
# Behaviour asserted:
#   1. Create 20 credentials, each with 10 password updates (= 10 history
#      entries each).
#   2. GET /api/credentials returns a body that
#        - parses as JSON
#        - is a list of length 20
#        - every entry carries its 10-entry password_history array
#
# If any of the strcat-into-fixed-buffer sites still existed, the response
# would either be truncated (json.load raises) or missing entries.

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

TMPDIR="$(mktemp -d -t tc_stress_XXXXXX)"
VAULT="$TMPDIR/vault.json"
LOG="$TMPDIR/pm.log"
export TRAFFIC_CYPHER_VAULT_PATH="$VAULT"
export HOME="$TMPDIR"

cleanup() {
    if [ -n "${PM_PID:-}" ]; then
        kill "$PM_PID" 2>/dev/null || true
        wait "$PM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

# Run from the frontend directory so the PM finds frontend/index.html.
cd "$REPO_ROOT/traffic_cypher_in_C"
"$PM" >"$LOG" 2>&1 &
PM_PID=$!

# Wait for server to bind.
for _ in $(seq 1 50); do
    curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1 && break
    sleep 0.1
done
curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1 \
    || fail "PM did not bind $PORT — log: $(cat "$LOG")"

UNLOCK=$(curl -s -m 5 -X POST "http://127.0.0.1:$PORT/api/auth/unlock" \
    -H 'Content-Type: application/json' -d '{"master_password":"stresspass"}')
TOKEN=$(printf '%s' "$UNLOCK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])') \
    || fail "unlock failed: $UNLOCK"
AUTH="Authorization: Bearer $TOKEN"
pass "unlocked vault"

# Create 20 credentials, each padded with bytes that are guaranteed to break
# the old fixed 16384/8192/4096 buffers when concatenated. We use long notes
# fields (~1 KiB) plus a long label, then 10 password updates per entry to
# build up the password_history array.
NOTES_PAYLOAD=$(python3 -c 'print("n" * 1024)')

for i in $(seq 1 20); do
    CREATE_RESP=$(curl -s -m 10 -X POST "http://127.0.0.1:$PORT/api/credentials" \
        -H "$AUTH" -H 'Content-Type: application/json' \
        -d "$(python3 -c "
import json, sys
print(json.dumps({
    'label': 'stress-cred-' + str($i),
    'website': 'example' + str($i) + '.com',
    'username': 'user' + str($i),
    'password': 'initial-p$i',
    'notes': '$NOTES_PAYLOAD',
    'tags': ['stress', 'batch-' + str($i)],
}))")")
    ID=$(printf '%s' "$CREATE_RESP" \
         | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])') \
        || fail "create $i failed: $CREATE_RESP"

    # 10 password updates → 10 history entries
    for j in $(seq 1 10); do
        curl -s -m 10 -X PUT "http://127.0.0.1:$PORT/api/credentials/$ID" \
            -H "$AUTH" -H 'Content-Type: application/json' \
            -d "{\"password\":\"rot-${i}-${j}-xxxxxxxxxxxxxxxx\"}" >/dev/null \
            || fail "update $i.$j failed"
    done
done
pass "created 20 credentials with 10 history entries each"

# GET the list and verify it parses + has all 20 entries with full history.
LIST=$(curl -s -m 30 -H "$AUTH" "http://127.0.0.1:$PORT/api/credentials")

# The old code would either truncate this response or crash mid-write under
# FORTIFY_SOURCE. We assert it parses as JSON, has 20 entries, and that the
# history array survived the round-trip.
printf '%s' "$LIST" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert isinstance(data, list), f"expected list, got {type(data).__name__}"
assert len(data) == 20, f"expected 20 entries, got {len(data)}"
# Each entry must keep its 10 history rows. The vault add path keeps the
# latest password current and pushes the previous ones into history, so we
# expect history_count == 10 (initial + 9 rotations) or 10 (capped at
# VAULT_MAX_HISTORY=10).
for i, e in enumerate(data):
    h = e.get("password_history", [])
    assert isinstance(h, list), f"entry {i}: history not a list"
    assert len(h) == 10, f"entry {i}: expected 10 history rows, got {len(h)}"
    assert all("password" in r and "changed_at" in r for r in h), \
        f"entry {i}: malformed history row"
print("OK: 20 entries, 200 history rows total, JSON well-formed")
' || fail "list response failed JSON / shape check (len=$(printf '%s' "$LIST" | wc -c) bytes)"

pass "GET /api/credentials parses and contains all 20 entries with full history"
