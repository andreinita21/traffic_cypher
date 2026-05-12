#!/bin/bash
# 26 — Week 4+ #10d cargo-fuzz scaffolding regression.
#
# We don't run libFuzzer here (it needs nightly Rust + libfuzzer-sys), but
# we do enforce that the scaffolding is wired correctly so a future refactor
# can't quietly delete the targets or break the public fuzz_* helpers in
# vault.rs.
set -e
source "$(dirname "$0")/lib/common.sh"

RUST="$REPO_ROOT/traffic_cypher_in_Rust"

# 1. Sub-crate manifest + targets.
[ -f "$RUST/fuzz/Cargo.toml" ] || fail "fuzz/Cargo.toml missing"
[ -f "$RUST/fuzz/fuzz_targets/vault_version_probe.rs" ] \
    || fail "vault_version_probe.rs target missing"
[ -f "$RUST/fuzz/fuzz_targets/vault_v3_envelope.rs" ] \
    || fail "vault_v3_envelope.rs target missing"
pass "fuzz/ scaffolding files present"

# 2. Fuzz crate must depend on libfuzzer-sys and the parent crate via path.
grep -q 'libfuzzer-sys' "$RUST/fuzz/Cargo.toml" \
    || fail "fuzz/Cargo.toml missing libfuzzer-sys dependency"
grep -qE 'traffic_cypher\s*\]|traffic_cypher.*path\s*=' "$RUST/fuzz/Cargo.toml" \
    || fail "fuzz/Cargo.toml does not pull in the parent crate by path"
pass "fuzz/Cargo.toml dependencies correct"

# 3. Targets must drive the public-but-doc-hidden fuzz_parse_* helpers.
grep -q 'fuzz_parse_vault_version' "$RUST/fuzz/fuzz_targets/vault_version_probe.rs" \
    || fail "vault_version_probe target does not call fuzz_parse_vault_version"
grep -q 'fuzz_parse_vault_v3_envelope' "$RUST/fuzz/fuzz_targets/vault_v3_envelope.rs" \
    || fail "vault_v3_envelope target does not call fuzz_parse_vault_v3_envelope"
pass "fuzz targets drive the expected sinks"

# 4. The helpers must still be exposed publicly from vault.rs (without the
#    pub front-end, the fuzz sub-crate can't reach them).
grep -q 'pub fn fuzz_parse_vault_version' "$RUST/src/vault.rs" \
    || fail "vault.rs: pub fn fuzz_parse_vault_version disappeared"
grep -q 'pub fn fuzz_parse_vault_v3_envelope' "$RUST/src/vault.rs" \
    || fail "vault.rs: pub fn fuzz_parse_vault_v3_envelope disappeared"
pass "vault.rs still exports the two fuzz entry points"

# 5. Seed corpora present.
[ -d "$RUST/fuzz/corpus/vault_version_probe" ] \
    || fail "vault_version_probe corpus dir missing"
[ -d "$RUST/fuzz/corpus/vault_v3_envelope" ] \
    || fail "vault_v3_envelope corpus dir missing"
[ "$(find "$RUST/fuzz/corpus/vault_version_probe" -type f | wc -l)" -ge 1 ] \
    || fail "vault_version_probe has no seed inputs"
[ "$(find "$RUST/fuzz/corpus/vault_v3_envelope" -type f | wc -l)" -ge 1 ] \
    || fail "vault_v3_envelope has no seed inputs"
pass "seed corpora populated"

# 6. fuzz/ must NOT be in the parent workspace — otherwise `cargo build`
#    from the parent would try to pull libfuzzer-sys on every CI run.
if grep -q '^\[workspace\]' "$RUST/Cargo.toml"; then
    grep -q 'fuzz' "$RUST/Cargo.toml" && fail \
        "parent Cargo.toml lists fuzz as a workspace member (would break stable CI)"
fi
pass "fuzz/ correctly isolated from the parent build"
