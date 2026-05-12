#!/usr/bin/env bash
# 70_argon2id_v3.sh
#
# Regression test for REMEDIATION_PLAN.md #4 — Argon2id v3 vault format.
#
# Asserts:
#   1. Rust `pm` writes vault files in the v3 schema (version=3,
#      kdf="argon2id", kdf_m_cost=65536).
#   2. The C `traffic-cypher-pm` can unlock and read a v3 vault produced
#      by Rust — proves cross-impl Argon2id derivation.
#
# Both impls listen on the same port (9876), so we sequence them.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d -t tc_argon2id_v3_XXXXXX)"
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

fail()  { echo "  FAIL: $*" >&2; exit 1; }
pass()  { echo "  ok: $*"; }

wait_for_port() {
    local port="$1"
    local tries=80   # Argon2id unlock adds ~300 ms, so allow extra time.
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
    local tries=150  # Rust pm tears down streams; can take several seconds.
    while (( tries-- > 0 )); do
        if ! curl -sf "http://127.0.0.1:${port}/api/auth/status" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

extract_token() {
    python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["token"])'
}

# ---------- Build both ----------
C_BIN="$REPO_ROOT/traffic_cypher_in_C/traffic-cypher-pm"
RUST_BIN="$REPO_ROOT/traffic_cypher_in_Rust/target/release/pm"

if [[ ! -x "$C_BIN" ]]; then
    echo "[build] C..."
    make -C "$REPO_ROOT/traffic_cypher_in_C" >/dev/null \
        || fail "C build failed"
fi
if [[ ! -x "$RUST_BIN" ]]; then
    echo "[build] Rust..."
    (cd "$REPO_ROOT/traffic_cypher_in_Rust" && cargo build --release --bin pm) >/dev/null 2>&1 \
        || fail "Rust build failed"
fi

# ---------- Phase 1: Rust writes v3 ----------
echo "[rust] writing v3 vault to $VAULT_PATH"
rm -f "$VAULT_PATH" "${VAULT_PATH}.tmp"

TRAFFIC_CYPHER_VAULT_PATH="$VAULT_PATH" HOME="$TMPDIR" \
    "$RUST_BIN" >"$TMPDIR/rust.log" 2>&1 &
PM_PID=$!

if ! wait_for_port "$PORT"; then
    cat "$TMPDIR/rust.log" >&2 || true
    fail "[rust] server did not come up on :$PORT"
fi

# Unlock (creates the vault file). Argon2id can need extra time on first
# call, so a single retry is added before declaring failure.
unlock_resp=""
for try in 1 2 3; do
    if unlock_resp=$(curl -s -X POST -H "Content-Type: application/json" \
        -d '{"master_password":"testpass"}' \
        --max-time 15 \
        "http://127.0.0.1:${PORT}/api/auth/unlock"); then
        if printf '%s' "$unlock_resp" | grep -q '"token"'; then
            break
        fi
    fi
    sleep 0.5
done
if ! printf '%s' "$unlock_resp" | grep -q '"token"'; then
    echo "[rust] last unlock response: $unlock_resp" >&2
    cat "$TMPDIR/rust.log" >&2 || true
    fail "[rust] /api/auth/unlock failed"
fi
token=$(printf '%s' "$unlock_resp" | extract_token) \
    || fail "[rust] could not extract token from $unlock_resp"

# Create one credential to force a vault write.
http_code=$(curl -s -o "$TMPDIR/create.json" -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $token" \
    -d '{"label":"argon2id-test","website":"example.com","username":"alice","password":"shared-secret-xyz"}' \
    --max-time 15 \
    "http://127.0.0.1:${PORT}/api/credentials")
if [[ "$http_code" != "201" && "$http_code" != "200" ]]; then
    echo "[rust] POST response:" >&2
    cat "$TMPDIR/create.json" >&2 || true
    cat "$TMPDIR/rust.log" >&2 || true
    fail "[rust] POST /api/credentials returned $http_code"
fi

sleep 0.5

# Stop Rust server. The Rust pm spawns background tasks; SIGTERM alone
# can take seconds. Send SIGKILL as a fallback.
kill "$PM_PID" 2>/dev/null || true
sleep 0.5
kill -9 "$PM_PID" 2>/dev/null || true
wait "$PM_PID" 2>/dev/null || true
PM_PID=""
wait_for_port_free "$PORT" || fail "[rust] port :$PORT did not free"

# Assert schema.
[[ -f "$VAULT_PATH" ]] || fail "vault file not created"
python3 - "$VAULT_PATH" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    vf = json.load(f)
assert vf["version"] == 3, f"expected version=3, got {vf['version']}"
assert vf["kdf"] == "argon2id", f"expected kdf=argon2id, got {vf['kdf']!r}"
assert vf["kdf_m_cost"] == 65536, f"expected m_cost=65536, got {vf['kdf_m_cost']}"
assert vf["kdf_t_cost"] == 3, f"expected t_cost=3, got {vf['kdf_t_cost']}"
assert vf["kdf_p_cost"] == 1, f"expected p_cost=1, got {vf['kdf_p_cost']}"
print("  ok: schema is v3 with argon2id params")
PY
[[ $? -eq 0 ]] || fail "[rust] schema check failed"

# ---------- Phase 2: C reads Rust's v3 vault ----------
echo "[c] unlocking Rust-written v3 vault"

TRAFFIC_CYPHER_VAULT_PATH="$VAULT_PATH" HOME="$TMPDIR" \
    "$C_BIN" >"$TMPDIR/c.log" 2>&1 &
PM_PID=$!

if ! wait_for_port "$PORT"; then
    cat "$TMPDIR/c.log" >&2 || true
    fail "[c] server did not come up on :$PORT"
fi

unlock_resp=$(curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"master_password":"testpass"}' \
    "http://127.0.0.1:${PORT}/api/auth/unlock") \
    || fail "[c] /api/auth/unlock failed — Argon2id KEK derivation diverged"
c_token=$(printf '%s' "$unlock_resp" | extract_token) \
    || fail "[c] could not extract token from $unlock_resp"
pass "[c] unlocked Rust-written v3 vault"

# List credentials and assert the Rust-written one is present. Use two
# separate curl calls to avoid fragile body/code splitting on a response
# whose body lacks a trailing newline.
http_code=$(curl -s -o "$TMPDIR/list.json" -w "%{http_code}" \
    -H "Authorization: Bearer $c_token" \
    --max-time 10 \
    "http://127.0.0.1:${PORT}/api/credentials")
if [[ "$http_code" != "200" ]]; then
    echo "[c] GET /api/credentials returned $http_code" >&2
    cat "$TMPDIR/list.json" >&2 || true
    cat "$TMPDIR/c.log" >&2 || true
    fail "[c] GET /api/credentials failed (HTTP $http_code)"
fi
list_resp=$(cat "$TMPDIR/list.json")

python3 -c '
import json, sys
raw = open(sys.argv[1]).read().strip()
if not raw:
    raise SystemExit("empty response body from /api/credentials")
data = json.loads(raw)
if isinstance(data, dict):
    data = data.get("credentials") or data.get("entries") or []
labels = [e.get("label") for e in data]
assert "argon2id-test" in labels, f"missing argon2id-test in {labels}"
print("  ok: C sees Rust-written credential argon2id-test")
' "$TMPDIR/list.json" \
    || fail "[c] credential list mismatch"

# Stop C server.
kill "$PM_PID" 2>/dev/null || true
sleep 0.5
kill -9 "$PM_PID" 2>/dev/null || true
wait "$PM_PID" 2>/dev/null || true
PM_PID=""
wait_for_port_free "$PORT" || fail "[c] port :$PORT did not free"

echo "PASS: argon2id v3 cross-impl"
