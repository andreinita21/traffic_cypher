#!/bin/bash
# 13 — #7b regression: the C PM must use a worker pool, must use a
# constant-time session token compare, and must NOT use the original
# strcmp(token, ...) sink that leaked timing.
set -e
source "$(dirname "$0")/lib/common.sh"

WS="$REPO_ROOT/traffic_cypher_in_C/src_c/web_server.c"
[ -r "$WS" ] || fail "web_server.c not found at $WS"

# Worker pool spawned with pthread_create.
grep -q "pthread_create" "$WS" \
    || fail "web_server.c missing pthread_create (worker pool not spawned)"
pass "web_server.c spawns worker threads (pthread_create)"

# Some marker of constant-time comparison must be present.
if grep -qE "ct_eq|constant.time|crypto_verify" "$WS"; then
    pass "web_server.c uses a constant-time token compare (ct_eq/constant-time/crypto_verify)"
else
    fail "web_server.c missing constant-time compare marker (ct_eq/constant.time/crypto_verify)"
fi

# The original strcmp(token, ...) sink must be gone.
if grep -nE "strcmp\s*\(\s*token\s*," "$WS" >/dev/null; then
    grep -nE "strcmp\s*\(\s*token\s*," "$WS"
    fail "web_server.c still uses strcmp(token, ...) — timing side-channel"
fi
pass "web_server.c no longer uses strcmp(token, ...)"
