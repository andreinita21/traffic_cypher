#!/bin/bash
# 30 — #8 regression: the C password manager must persist the `tags` array
# on credential create and update, with PATCH semantics on update (absent
# `tags` key means keep existing) and a hard cap at VAULT_MAX_TAGS (16).
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

VAULT="/tmp/tc_test_30_vault_$$.json"
LOG="/tmp/tc_test_30_log_$$.txt"
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
for _ in $(seq 1 50); do
    curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1 && break
    sleep 0.1
done
curl -s -m 1 "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1 \
    || fail "PM did not bind $PORT — log: $(cat "$LOG")"

UNLOCK=$(curl -s -m 5 -X POST "http://127.0.0.1:$PORT/api/auth/unlock" \
    -H 'Content-Type: application/json' -d '{"master_password":"testpass"}')
TOKEN=$(printf '%s' "$UNLOCK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])') \
    || fail "unlock failed: $UNLOCK"
AUTH="Authorization: Bearer $TOKEN"
pass "unlocked vault"

CREATE=$(curl -s -m 5 -X POST "http://127.0.0.1:$PORT/api/credentials" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d '{"label":"t","password":"p","tags":["work","social"]}')
ID=$(printf '%s' "$CREATE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])') \
    || fail "create failed: $CREATE"

GET=$(curl -s -m 5 -H "$AUTH" "http://127.0.0.1:$PORT/api/credentials/$ID")
printf '%s' "$GET" | grep -q '"work"'   || fail "tag 'work' missing on create: $GET"
printf '%s' "$GET" | grep -q '"social"' || fail "tag 'social' missing on create: $GET"
pass "create persists tags=[work,social]"

curl -s -m 5 -X PUT "http://127.0.0.1:$PORT/api/credentials/$ID" \
    -H "$AUTH" -H 'Content-Type: application/json' -d '{"tags":["only"]}' >/dev/null
GET=$(curl -s -m 5 -H "$AUTH" "http://127.0.0.1:$PORT/api/credentials/$ID")
printf '%s' "$GET" | grep -q '"only"'   || fail "tag 'only' missing after replace: $GET"
printf '%s' "$GET" | grep -q '"work"'   && fail "tag 'work' should have been replaced: $GET"
printf '%s' "$GET" | grep -q '"social"' && fail "tag 'social' should have been replaced: $GET"
pass "update with explicit tags replaces"

curl -s -m 5 -X PUT "http://127.0.0.1:$PORT/api/credentials/$ID" \
    -H "$AUTH" -H 'Content-Type: application/json' -d '{"label":"renamed"}' >/dev/null
GET=$(curl -s -m 5 -H "$AUTH" "http://127.0.0.1:$PORT/api/credentials/$ID")
printf '%s' "$GET" | grep -q '"only"' || fail "PATCH semantic broken — tags wiped when key absent: $GET"
pass "update without tags key keeps existing"

BIG=$(python3 -c 'import json; print(json.dumps({"tags":["t"+str(i) for i in range(100)]}))')
STATUS=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -X PUT \
    "http://127.0.0.1:$PORT/api/credentials/$ID" \
    -H "$AUTH" -H 'Content-Type: application/json' -d "$BIG")
[ "$STATUS" = "400" ] || fail "100 tags expected 400, got $STATUS"
pass "100 tags rejected with 400"
