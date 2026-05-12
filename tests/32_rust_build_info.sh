#!/usr/bin/env bash
# Regression: the Rust password manager exposes /api/build/info with
# {"build":"rust","traffic_entropy":true} and the route does NOT require auth.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
binary="$repo_root/traffic_cypher_in_Rust/target/release/pm"

if [[ ! -x "$binary" ]]; then
    echo "SKIP: $binary not built. Run 'cargo build --release --bins' in traffic_cypher_in_Rust first." >&2
    exit 1
fi

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

if lsof -iTCP:9876 -sTCP:LISTEN >/dev/null 2>&1; then
    echo "FAIL: port 9876 is already in use; stop the running daemon first." >&2
    exit 1
fi
PORT=9876
BASE="http://127.0.0.1:${PORT}"

HOME="$TMPHOME" TRAFFIC_CYPHER_VAULT_PATH="$TMPHOME/vault.json" \
    "$binary" >"$TMPHOME/server.log" 2>&1 &
PID=$!

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

# /api/build/info must be reachable without an Authorization header.
build_info=$(curl -s "${BASE}/api/build/info")
echo "build/info: $build_info"
if ! echo "$build_info" | grep -q '"build":"rust"'; then
    echo "FAIL: build/info should report build=rust. Got: $build_info" >&2
    exit 1
fi
if ! echo "$build_info" | grep -q '"traffic_entropy":true'; then
    echo "FAIL: build/info should report traffic_entropy=true. Got: $build_info" >&2
    exit 1
fi

echo "OK: Rust build advertises traffic_entropy=true."
