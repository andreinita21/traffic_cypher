#!/usr/bin/env bash
# 34 — Week 4+ #1a stage 4 part A: auto-replay persisted stream_config on unlock.
#
# When the C PM is built with ENABLE_TRAFFIC_ENTROPY=1, handle_unlock should
# snapshot state->stream_config and hand it off to a detached pthread that
# calls msm_add_stream() for each persisted entry. This avoids stalling the
# unlock HTTP response while yt-dlp resolves each URL.
#
# This test:
#   1. Statically checks web_server.c has the replay function and it is
#      #ifdef ENABLE_TRAFFIC_ENTROPY-gated.
#   2. Rebuilds the C tree in a tmpcopy with ENABLE_TRAFFIC_ENTROPY=1 to
#      confirm the flagged build is clean.
#   3. If yt-dlp is available, runs the integration check: write a bogus
#      stream_config.json by hand, unlock, then verify /api/streams reflects
#      the entry as "Failed" after a few seconds.
#      If yt-dlp is missing, that step is skipped (the replay thread can
#      still run — msm_add_stream just immediately marks the slot FAILED —
#      but we keep the skip path so this test stays cheap on CI without
#      yt-dlp installed).
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

C="$REPO_ROOT/traffic_cypher_in_C"

# --- 1. Static checks ---------------------------------------------------------

grep -q 'spawn_stream_replay_locked\|stream_replay_main' "$C/src_c/web_server.c" \
    || fail "web_server.c missing the stream-replay function"
pass "web_server.c defines the stream-replay function"

# The replay function block must be inside an ENABLE_TRAFFIC_ENTROPY ifdef.
# Grep for the function definition and confirm it sits below an ifdef line
# that has not yet been closed. We do this by checking that the file has
# a corresponding ifdef ENABLE_TRAFFIC_ENTROPY before the function.
python3 - "$C/src_c/web_server.c" <<'PY' || fail "stream_replay_main not gated by ENABLE_TRAFFIC_ENTROPY"
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r'\bstream_replay_main\s*\(', src)
if not m:
    sys.exit("no stream_replay_main definition")
prefix = src[:m.start()]
# Find the *last* #ifdef / #ifndef / #endif before the function.
last = None
for tok in re.finditer(r'^\s*#\s*(ifdef|ifndef|if|else|elif|endif)\b[^\n]*', prefix, re.M):
    last = tok
if last is None:
    sys.exit("no preceding preprocessor directive")
line = last.group(0).strip()
if 'ENABLE_TRAFFIC_ENTROPY' not in line or 'endif' in line:
    sys.exit(f"replay function not gated by ENABLE_TRAFFIC_ENTROPY (preceding directive: {line!r})")
PY
pass "stream_replay_main is gated by #ifdef ENABLE_TRAFFIC_ENTROPY"

# Confirm the call site sits inside handle_unlock between load_stream_config
# and the rotation_daemon spawn.
python3 - "$C/src_c/web_server.c" <<'PY' || fail "handle_unlock does not invoke the replay between load_stream_config and pthread_create rotation_daemon"
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r'static\s+void\s+handle_unlock\b.*?\n\}', src, re.S)
if not m:
    sys.exit("could not locate handle_unlock")
body = m.group(0)
i_load = body.find('load_stream_config')
i_call = body.find('spawn_stream_replay_locked')
i_rot  = re.search(r'pthread_create\s*\([^,]*,\s*[^,]*,\s*rotation_daemon', body)
if i_load < 0 or i_call < 0 or i_rot is None:
    sys.exit(f"missing one of the three anchors: load={i_load}, call={i_call}, rot={i_rot}")
if not (i_load < i_call < i_rot.start()):
    sys.exit(f"ordering wrong: load={i_load}, call={i_call}, rot={i_rot.start()}")
PY
pass "handle_unlock invokes replay between load_stream_config and rotation_daemon"

# --- 2. Build the flagged tree in a tmpcopy -----------------------------------

WORK="$(mktemp -d -t tc_replay_build.XXXXXX)"
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
    || { cat "$WORK/build.log" >&2; fail "build with ENABLE_TRAFFIC_ENTROPY=1 failed"; }
pass "ENABLE_TRAFFIC_ENTROPY=1 build succeeds with replay code"

# --- 3. Integration: persisted streams must be replayed on unlock -------------

if ! command -v yt-dlp >/dev/null 2>&1; then
    skip "yt-dlp not installed; replay-thread integration check requires it"
fi

if lsof -iTCP:9876 -sTCP:LISTEN >/dev/null 2>&1; then
    skip "port 9876 already in use; cannot run integration check"
fi

TMPHOME="$(mktemp -d -t tc_replay_run.XXXXXX)"
trap 'rm -rf "$WORK" "$TMPHOME"; [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null || true' EXIT
PID=""

# Pre-write a stream_config.json with a bogus URL. The C PM loads this on
# unlock and (with the flag set) should fan the entry through msm_add_stream.
# Because the URL is bogus, resolve_stream_url fails -> the slot becomes
# STREAM_FAILED. Path matches stream_config_path() in vault.c.
cat >"$TMPHOME/.traffic_cypher_streams.json" <<'JSON'
{
  "streams": [
    {"url": "https://invalid.example/not-a-real-stream", "label": "bogus-replay", "enabled": true}
  ],
  "default_stream": "https://www.youtube.com/watch?v=rs2be3mqryo",
  "auto_lock_minutes": 5
}
JSON

( cd "$WORK/C" && HOME="$TMPHOME" TRAFFIC_CYPHER_VAULT_PATH="$TMPHOME/vault.json" \
    exec ./traffic-cypher-pm >"$TMPHOME/server.log" 2>&1 ) &
PID=$!

for _ in $(seq 1 50); do
    if curl -s --max-time 1 http://127.0.0.1:9876/api/auth/status >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if ! curl -s --max-time 1 http://127.0.0.1:9876/api/auth/status >/dev/null 2>&1; then
    cat "$TMPHOME/server.log" >&2
    fail "ENABLE_TRAFFIC_ENTROPY=1 server did not start"
fi

# Unlock — first launch creates a fresh vault, so any password works.
unlock_resp=$(curl -s -X POST http://127.0.0.1:9876/api/auth/unlock \
    -H 'Content-Type: application/json' \
    -d '{"master_password":"replay-test-pw"}')
token=$(printf '%s' "$unlock_resp" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || fail "unlock did not return a token: $unlock_resp"
pass "unlock returned a session token (handler did not block on replay)"

# Poll /api/streams up to 30 seconds — yt-dlp resolution typically completes
# (with a failure) in well under 10 s, but give the OS some slack.
streams=""
for _ in $(seq 1 30); do
    streams=$(curl -s -H "Authorization: Bearer ${token}" http://127.0.0.1:9876/api/streams)
    if printf '%s' "$streams" | grep -q '"bogus-replay"'; then
        break
    fi
    sleep 1
done

echo "  /api/streams after replay: $streams"
printf '%s' "$streams" | grep -q '"bogus-replay"' \
    || fail "/api/streams never reflected the replayed entry: $streams"
pass "/api/streams reflects the auto-replayed persisted entry"

# It should be marked Failed (bogus URL) — never Disabled (that's the
# pre-#1a no-op path).
printf '%s' "$streams" | grep -q '"status":"Failed"' \
    || fail "replayed bogus entry not marked Failed; got: $streams"
pass "replayed bogus entry is marked Failed (resolve correctly rejected)"

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""
