#!/usr/bin/env bash
# 41_atomic_vault_writes.sh
#
# Regression test for the atomic-vault-write fix.
#
# Both the C and Rust password managers used to write the vault in place
# (fopen("w")+fputs / std::fs::write). A crash mid-write would leave the
# vault half-written and permanently undecryptable. The fix is the
# write-tmp + fsync + rename pattern.
#
# This test verifies:
#   1. After a credential write, the vault file exists and parses as JSON.
#   2. No "<vault>.tmp" sidecar is left behind on the happy path.
#
# Both impls listen on the same port (9876), so we sequence them.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d -t tc_atomic_XXXXXX)"
VAULT_PATH="$TMPDIR/vault.json"
PORT=9876
PM_PID=""

cleanup() {
    if [[ -n "$PM_PID" ]]; then
        kill "$PM_PID" 2>/dev/null || true
        wait "$PM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

fail() {
    echo "  FAIL: $*" >&2
    exit 1
}

pass() {
    echo "  ok: $*"
}

wait_for_port() {
    local port="$1"
    local tries=50
    while (( tries-- > 0 )); do
        if curl -sf "http://127.0.0.1:${port}/api/auth/status" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_for_port_free() {
    local port="$1"
    local tries=50
    while (( tries-- > 0 )); do
        if ! curl -sf "http://127.0.0.1:${port}/api/auth/status" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

extract_token() {
    # Crude but dependency-free: pull "token":"..." from JSON.
    python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["token"])'
}

run_impl() {
    local label="$1"
    local binary="$2"
    echo "[$label] starting $binary with vault=$VAULT_PATH"

    # Fresh vault dir for each impl.
    rm -f "$VAULT_PATH" "${VAULT_PATH}.tmp"

    # HOME is redirected so stream-config writes also land in the tmp dir
    # (the .traffic_cypher_streams.json file goes under $HOME).
    TRAFFIC_CYPHER_VAULT_PATH="$VAULT_PATH" HOME="$TMPDIR" \
        "$binary" >"$TMPDIR/${label}.log" 2>&1 &
    PM_PID=$!

    if ! wait_for_port "$PORT"; then
        cat "$TMPDIR/${label}.log" >&2 || true
        fail "[$label] server did not come up on :$PORT"
    fi

    # 1. unlock
    local unlock_resp
    unlock_resp=$(curl -sf -X POST -H "Content-Type: application/json" \
        -d '{"master_password":"testpass"}' \
        "http://127.0.0.1:${PORT}/api/auth/unlock") \
        || fail "[$label] /api/auth/unlock failed"
    local token
    token=$(printf '%s' "$unlock_resp" | extract_token) \
        || fail "[$label] could not extract token from $unlock_resp"

    # 2. create a credential — forces a vault write
    curl -sf -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $token" \
        -d '{"label":"atomic-write-test","website":"example.com","username":"u","password":"p"}' \
        "http://127.0.0.1:${PORT}/api/credentials" >/dev/null \
        || fail "[$label] POST /api/credentials failed"

    # The handler writes to disk before responding, so by the time curl
    # returns the file should be on disk. Give it a moment regardless.
    sleep 0.2

    # 3. vault file exists and parses as JSON
    [[ -f "$VAULT_PATH" ]] || fail "[$label] vault file not created at $VAULT_PATH"
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$VAULT_PATH" \
        || fail "[$label] vault file is not valid JSON"
    pass "[$label] vault file exists and parses as JSON"

    # 4. no leftover .tmp sidecar
    if ls "${VAULT_PATH}.tmp" >/dev/null 2>&1; then
        fail "[$label] orphan ${VAULT_PATH}.tmp left behind"
    fi
    # Same check for the streams config (under HOME=$TMPDIR).
    if ls "$TMPDIR/.traffic_cypher_streams.json.tmp" >/dev/null 2>&1; then
        fail "[$label] orphan streams .tmp left behind"
    fi
    pass "[$label] no orphan .tmp files"

    # 5. shut the server down and wait until the port is free again.
    kill "$PM_PID" 2>/dev/null || true
    wait "$PM_PID" 2>/dev/null || true
    PM_PID=""
    wait_for_port_free "$PORT" \
        || fail "[$label] port :$PORT did not free after kill"
}

# ---------- C impl ----------
C_BIN="$REPO_ROOT/traffic_cypher_in_C/traffic-cypher-pm"
if [[ ! -x "$C_BIN" ]]; then
    echo "[c] building..."
    make -C "$REPO_ROOT/traffic_cypher_in_C" >/dev/null \
        || fail "C build failed"
fi
run_impl "c" "$C_BIN"

# ---------- Rust impl ----------
RUST_BIN="$REPO_ROOT/traffic_cypher_in_Rust/target/release/pm"
if [[ ! -x "$RUST_BIN" ]]; then
    echo "[rust] building..."
    (cd "$REPO_ROOT/traffic_cypher_in_Rust" && cargo build --release --bin pm) >/dev/null 2>&1 \
        || fail "Rust build failed"
fi
run_impl "rust" "$RUST_BIN"

echo "PASS: atomic vault writes"
