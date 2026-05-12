#!/bin/bash
# 16 — Static guards that the Rust in-memory secrets (DEK, KEK, master
# password, decrypted vault plaintext) are wrapped in `zeroize::Zeroizing`
# so their backing buffers are overwritten on drop. Actual zeroization is
# invisible to userspace; this test pins the dependency + the type-level
# wiring in place so it can't silently regress.
set -e
source "$(dirname "$0")/lib/common.sh"

RUST="$REPO_ROOT/traffic_cypher_in_Rust"
CARGO="$RUST/Cargo.toml"

grep -Eq '^zeroize\s*=' "$CARGO" \
    || fail "Cargo.toml missing direct 'zeroize' dependency"
pass "Cargo.toml declares zeroize as a direct dependency"

grep -q 'use zeroize' "$RUST/src/vault.rs" \
    || fail "vault.rs does not import zeroize"
pass "vault.rs imports zeroize"

grep -q 'Zeroizing' "$RUST/src/vault.rs" \
    || fail "vault.rs does not reference Zeroizing"
pass "vault.rs wraps secrets in Zeroizing"

grep -q 'Zeroizing' "$RUST/src/web/state.rs" \
    || fail "web/state.rs does not reference Zeroizing (master_password / current_dek not wrapped)"
pass "web/state.rs wraps master_password / current_dek in Zeroizing"

grep -q 'Zeroizing' "$RUST/src/web/routes.rs" \
    || fail "web/routes.rs does not reference Zeroizing (unlock/lock write sites unwrapped)"
pass "web/routes.rs wraps secrets at the unlock/lock write sites"
