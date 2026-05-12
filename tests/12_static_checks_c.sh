#!/bin/bash
# 12 — Static grep guards for #2 (command injection) and #7a (socket timeouts).
set -e
source "$(dirname "$0")/lib/common.sh"

C="$REPO_ROOT/traffic_cypher_in_C"

# --- #2: command injection fix ---

# popen() must be gone — it's the original sink.
if grep -nE '\bpopen\s*\(' "$C/src_c/stream_ingestion.c" >/dev/null; then
    grep -nE '\bpopen\s*\(' "$C/src_c/stream_ingestion.c"
    fail "stream_ingestion.c still calls popen()"
fi
pass "stream_ingestion.c no longer uses popen"

grep -q "execvp" "$C/src_c/stream_ingestion.c" \
    || fail "stream_ingestion.c does not call execvp"
pass "stream_ingestion.c uses execvp (no shell)"

# argv must include the -- sentinel so leading '-' in a URL isn't read as a flag.
grep -q '"--"' "$C/src_c/stream_ingestion.c" \
    || fail "stream_ingestion.c argv missing -- sentinel"
pass "argv includes -- sentinel"

# Validation must reject non-http(s) prefixes.
grep -qE "(https?://|http://)" "$C/src_c/stream_ingestion.c" \
    || fail "stream_ingestion.c does not check http(s):// prefix"
pass "stream_ingestion.c validates http(s):// prefix"

# --- #7a: socket timeouts ---

grep -q "SO_RCVTIMEO" "$C/src_c/web_server.c" \
    || fail "web_server.c missing SO_RCVTIMEO"
grep -q "SO_SNDTIMEO" "$C/src_c/web_server.c" \
    || fail "web_server.c missing SO_SNDTIMEO"
pass "web_server.c sets receive + send timeouts on accepted sockets"
