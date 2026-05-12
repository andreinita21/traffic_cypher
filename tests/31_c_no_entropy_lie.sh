#!/usr/bin/env bash
# Regression: the C password manager must NOT claim traffic entropy.
#
# - GET /api/build/info returns build=c, traffic_entropy=false (no auth)
# - After unlock, GET /api/entropy-snapshot returns has_traffic_entropy=false,
#   even after the rotation daemon has been running for a couple of seconds.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
binary="$repo_root/traffic_cypher_in_C/traffic-cypher-pm"
frontend_dir="$repo_root/traffic_cypher_in_C"

if [[ ! -x "$binary" ]]; then
    echo "SKIP: $binary not built. Run 'make -C traffic_cypher_in_C' first." >&2
    exit 1
fi

PORT=$((20000 + RANDOM % 20000))
TMPHOME="$(mktemp -d)"
trap 'cleanup' EXIT
PID=""
cleanup() {
    if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$TMPHOME"
}

# The C PM hardcodes port 9876 inside pm_main.c. To avoid colliding with a
# real daemon already running, fall back to port-hop only if 9876 is busy.
# Easier: just refuse to run if 9876 is in use.
if lsof -iTCP:9876 -sTCP:LISTEN >/dev/null 2>&1; then
    echo "FAIL: port 9876 is already in use; stop the running daemon first." >&2
    exit 1
fi
PORT=9876
BASE="http://127.0.0.1:${PORT}"

# Launch C PM with isolated HOME and vault path. Run from a working directory
# that contains the frontend/ dir the server expects to load at runtime.
cd "$frontend_dir"
HOME="$TMPHOME" TRAFFIC_CYPHER_VAULT_PATH="$TMPHOME/vault.json" \
    "$binary" >"$TMPHOME/server.log" 2>&1 &
PID=$!

# Wait for server to bind.
for _ in $(seq 1 50); do
    if curl -s --max-time 1 "${BASE}/api/auth/status" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if ! curl -s --max-time 1 "${BASE}/api/auth/status" >/dev/null 2>&1; then
    echo "FAIL: server did not start. Log:" >&2
    cat "$TMPHOME/server.log" >&2
    exit 1
fi

# --- Check /api/build/info (no auth required) ---
build_info=$(curl -s "${BASE}/api/build/info")
echo "build/info: $build_info"
if ! echo "$build_info" | grep -q '"build":"c"'; then
    echo "FAIL: build/info should report build=c. Got: $build_info" >&2
    exit 1
fi
if ! echo "$build_info" | grep -q '"traffic_entropy":false'; then
    echo "FAIL: build/info should report traffic_entropy=false. Got: $build_info" >&2
    exit 1
fi

# --- Unlock vault (first launch creates a fresh one) ---
unlock_resp=$(curl -s -X POST "${BASE}/api/auth/unlock" \
    -H 'Content-Type: application/json' \
    -d '{"master_password":"integration-test-pw"}')
token=$(printf '%s' "$unlock_resp" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$token" ]]; then
    echo "FAIL: unlock did not return a token. Response: $unlock_resp" >&2
    exit 1
fi

# Give the rotation daemon a couple of cycles to run. If the C build were
# still lying, it would have flipped has_traffic_entropy to true by now.
sleep 3

snap=$(curl -s -H "Authorization: Bearer ${token}" "${BASE}/api/entropy-snapshot")
echo "entropy-snapshot: $snap"
if ! echo "$snap" | grep -q '"has_traffic_entropy":false'; then
    echo "FAIL: /api/entropy-snapshot must report has_traffic_entropy=false in the C build." >&2
    echo "Got: $snap" >&2
    exit 1
fi

echo "OK: C build honestly reports OS-only entropy."
