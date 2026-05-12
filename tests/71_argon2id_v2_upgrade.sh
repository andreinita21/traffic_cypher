#!/usr/bin/env bash
# 71_argon2id_v2_upgrade.sh
#
# Regression test for the v2 -> v3 auto-upgrade path of REMEDIATION_PLAN.md #4.
#
# Drops the pinned test_fixtures/sample_vault_v2.json (a real v2 / HKDF-KEK
# vault) into the Rust pm's data directory and asserts:
#   1. Rust unlocks it (proves the v2 read path still works).
#   2. The pre-loaded credential is present.
#   3. After any write (we create one extra credential), the vault on disk
#      has been silently rewritten as v3 (version=3, kdf="argon2id").
#   4. Re-unlocking from a clean process still works on the new v3 file.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="$REPO_ROOT/test_fixtures/sample_vault_v2.json"
TMPDIR="$(mktemp -d -t tc_v2_upgrade_XXXXXX)"
VAULT_PATH="$TMPDIR/vault.json"
PORT=9876
PM_PID=""

# Master password / payload that the fixture was generated with — see
# traffic_cypher_in_Rust/examples/make_v2_vault.rs.
FIXTURE_PW="upgrade-fixture-pw"
FIXTURE_LABEL="v2-upgrade-test"
FIXTURE_PASSWORD="v2-secret-do-not-lose"

cleanup() {
    if [[ -n "$PM_PID" ]]; then
        kill "$PM_PID" 2>/dev/null || true
        wait "$PM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

fail() { echo "  FAIL: $*" >&2; exit 1; }
pass() { echo "  ok: $*"; }

wait_for_port() {
    local port="$1"; local tries=80
    while (( tries-- > 0 )); do
        if curl -sf "http://127.0.0.1:${port}/api/auth/status" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_for_port_free() {
    local port="$1"; local tries=150  # Rust pm shutdown is slow.
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

[[ -f "$FIXTURE" ]] || fail "missing fixture $FIXTURE"

# Sanity: confirm the fixture is genuinely v2 before we begin — otherwise
# the test isn't actually exercising the v2 path.
python3 - "$FIXTURE" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["version"] == 2, f"fixture is not v2 (got {v['version']})"
assert "kdf" not in v, "v2 fixture must not carry a `kdf` field"
print("  ok: fixture is v2 / no kdf field")
PY
[[ $? -eq 0 ]] || fail "fixture is not v2"

RUST_BIN="$REPO_ROOT/traffic_cypher_in_Rust/target/release/pm"
if [[ ! -x "$RUST_BIN" ]]; then
    echo "[build] Rust..."
    (cd "$REPO_ROOT/traffic_cypher_in_Rust" && cargo build --release --bin pm) >/dev/null 2>&1 \
        || fail "Rust build failed"
fi

# Stage 1: seed the v2 fixture and unlock it.
cp "$FIXTURE" "$VAULT_PATH"
TRAFFIC_CYPHER_VAULT_PATH="$VAULT_PATH" HOME="$TMPDIR" \
    "$RUST_BIN" >"$TMPDIR/rust1.log" 2>&1 &
PM_PID=$!
wait_for_port "$PORT" || { cat "$TMPDIR/rust1.log" >&2; fail "rust did not boot"; }

http_code=$(curl -s -o "$TMPDIR/unlock1.json" -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"master_password\":\"${FIXTURE_PW}\"}" \
    --max-time 15 \
    "http://127.0.0.1:${PORT}/api/auth/unlock")
if [[ "$http_code" != "200" ]]; then
    cat "$TMPDIR/unlock1.json" >&2 || true
    cat "$TMPDIR/rust1.log" >&2 || true
    fail "unlock of v2 fixture failed (HTTP $http_code)"
fi
token=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token"])' "$TMPDIR/unlock1.json")
pass "Rust unlocked v2 fixture"

# Assert the bundled credential is present.
http_code=$(curl -s -o "$TMPDIR/list1.json" -w "%{http_code}" \
    -H "Authorization: Bearer $token" \
    --max-time 10 \
    "http://127.0.0.1:${PORT}/api/credentials")
[[ "$http_code" == "200" ]] || fail "list credentials failed (HTTP $http_code)"

cat > "$TMPDIR/check_v2.py" <<'PY'
import json, os, sys
data = json.load(open(sys.argv[1]))
if isinstance(data, dict):
    data = data.get("credentials") or data.get("entries") or []
labels = [e.get("label") for e in data]
label = os.environ["FIXTURE_LABEL"]
pwd   = os.environ["FIXTURE_PASSWORD"]
assert label in labels, f"missing {label!r} in {labels}"
entry = next(e for e in data if e.get("label") == label)
got = entry.get("password")
assert got == pwd, f"password mismatch: got {got!r}, want {pwd!r}"
print("  ok: v2 entry preserved with correct plaintext")
PY
FIXTURE_LABEL="$FIXTURE_LABEL" FIXTURE_PASSWORD="$FIXTURE_PASSWORD" \
    python3 "$TMPDIR/check_v2.py" "$TMPDIR/list1.json" \
    || fail "v2 entry not preserved"

# Stage 2: force a save by creating a new credential. This should rewrite
# the vault as v3.
http_code=$(curl -s -o "$TMPDIR/create.json" -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -H "Authorization: Bearer $token" \
    -d '{"label":"post-upgrade","website":"x","username":"x","password":"x"}' \
    --max-time 15 \
    "http://127.0.0.1:${PORT}/api/credentials")
if [[ "$http_code" != "201" && "$http_code" != "200" ]]; then
    cat "$TMPDIR/create.json" >&2 || true
    fail "POST /api/credentials returned $http_code"
fi
sleep 0.5

# Stop the server so we can re-test from a fresh process.
kill "$PM_PID" 2>/dev/null || true
sleep 0.5
kill -9 "$PM_PID" 2>/dev/null || true
wait "$PM_PID" 2>/dev/null || true
PM_PID=""
wait_for_port_free "$PORT" || fail "port did not free"

# Stage 3: file on disk is now v3.
python3 - "$VAULT_PATH" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["version"] == 3, f"file did not auto-upgrade to v3 (got {v['version']})"
assert v["kdf"] == "argon2id", f"missing/wrong kdf: {v.get('kdf')!r}"
assert v["kdf_m_cost"] == 65536
assert v["kdf_t_cost"] == 3
assert v["kdf_p_cost"] == 1
print("  ok: vault is now v3 (argon2id)")
PY
[[ $? -eq 0 ]] || fail "v2 -> v3 upgrade did not happen"

# Stage 4: a fresh process can still unlock the upgraded vault.
TRAFFIC_CYPHER_VAULT_PATH="$VAULT_PATH" HOME="$TMPDIR" \
    "$RUST_BIN" >"$TMPDIR/rust2.log" 2>&1 &
PM_PID=$!
wait_for_port "$PORT" || { cat "$TMPDIR/rust2.log" >&2; fail "rust did not reboot"; }

http_code=$(curl -s -o "$TMPDIR/unlock2.json" -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"master_password\":\"${FIXTURE_PW}\"}" \
    --max-time 15 \
    "http://127.0.0.1:${PORT}/api/auth/unlock")
if [[ "$http_code" != "200" ]]; then
    cat "$TMPDIR/unlock2.json" >&2 || true
    cat "$TMPDIR/rust2.log" >&2 || true
    fail "unlock of upgraded v3 vault failed (HTTP $http_code)"
fi
token=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token"])' "$TMPDIR/unlock2.json")

http_code=$(curl -s -o "$TMPDIR/list2.json" -w "%{http_code}" \
    -H "Authorization: Bearer $token" \
    --max-time 10 \
    "http://127.0.0.1:${PORT}/api/credentials")
[[ "$http_code" == "200" ]] || fail "list credentials failed (HTTP $http_code)"

cat > "$TMPDIR/check_v3.py" <<'PY'
import json, os, sys
data = json.load(open(sys.argv[1]))
if isinstance(data, dict):
    data = data.get("credentials") or data.get("entries") or []
labels = sorted(e.get("label") for e in data)
target = os.environ["FIXTURE_LABEL"]
pwd = os.environ["FIXTURE_PASSWORD"]
assert target in labels, f"missing {target!r} in {labels}"
assert "post-upgrade" in labels, f"missing post-upgrade in {labels}"
entry = next(e for e in data if e.get("label") == target)
got = entry.get("password")
assert got == pwd, f"original password lost: got {got!r}"
print(f"  ok: post-upgrade vault has both entries: {labels}")
PY
FIXTURE_LABEL="$FIXTURE_LABEL" FIXTURE_PASSWORD="$FIXTURE_PASSWORD" \
    python3 "$TMPDIR/check_v3.py" "$TMPDIR/list2.json" \
    || fail "content not preserved across upgrade"

echo "PASS: v2 -> v3 auto-upgrade"
