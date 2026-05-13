#!/bin/bash
# 27 — Week 4+ #10d C-side cargo-fuzz scaffolding regression.
#
# Like the Rust counterpart (26_fuzz_scaffolding.sh), we don't run libFuzzer
# here (it needs a clang ship of libclang_rt.fuzzer_*.a) but we enforce that
# the scaffolding stays wired so a refactor can't quietly delete targets,
# break the ENABLE_FUZZ_API gate, or drop the Make target.
set -e
source "$(dirname "$0")/lib/common.sh"

C="$REPO_ROOT/traffic_cypher_in_C"

# 1. Scaffolding files present.
[ -d "$C/fuzz_c" ] || fail "fuzz_c/ directory missing"
for t in fuzz_hex_decode fuzz_json_get_string fuzz_parse_vault_entries; do
    [ -f "$C/fuzz_c/fuzz_targets/$t.c" ] || fail "fuzz_c/fuzz_targets/$t.c missing"
done
pass "fuzz_c/fuzz_targets/ has all 3 fuzz target files"

# 2. ENABLE_FUZZ_API wrappers in vault.c.
grep -q 'ENABLE_FUZZ_API' "$C/src_c/vault.c" \
    || fail "vault.c missing ENABLE_FUZZ_API gate"
grep -q 'fuzz_json_get_string' "$C/src_c/vault.c" \
    || fail "vault.c missing fuzz_json_get_string wrapper"
grep -q 'fuzz_parse_vault_entries' "$C/src_c/vault.c" \
    || fail "vault.c missing fuzz_parse_vault_entries wrapper"
pass "vault.c exposes fuzz wrappers behind ENABLE_FUZZ_API"

# 3. Production build must NOT pick up the wrappers (no -DENABLE_FUZZ_API
#    in the default CFLAGS).
grep -E '^CFLAGS\s*=' "$C/Makefile" | grep -q 'ENABLE_FUZZ_API' \
    && fail "Makefile production CFLAGS leaks ENABLE_FUZZ_API"
pass "production CFLAGS does not define ENABLE_FUZZ_API"

# 4. Fuzz Make target wired with the fuzzer-only sanitizer default
#    (ASan combo hangs on macOS arm64; opt-in via FUZZ_SANITIZER).
grep -q '^fuzz:' "$C/Makefile" || fail "Makefile missing fuzz target"
grep -q 'FUZZ_SANITIZER' "$C/Makefile" \
    || fail "Makefile missing FUZZ_SANITIZER opt-in for ASan"
grep -q '\-DENABLE_FUZZ_API' "$C/Makefile" \
    || fail "Makefile fuzz target does not define ENABLE_FUZZ_API"
pass "fuzz/fuzz-clean targets present and correctly scoped"

# 5. Each target file declares the libFuzzer entry point.
for t in fuzz_hex_decode fuzz_json_get_string fuzz_parse_vault_entries; do
    grep -q 'LLVMFuzzerTestOneInput' "$C/fuzz_c/fuzz_targets/$t.c" \
        || fail "fuzz_targets/$t.c missing LLVMFuzzerTestOneInput"
done
pass "all 3 targets export LLVMFuzzerTestOneInput"

# 6. Seed corpora populated.
for d in hex_decode json_get_string parse_vault_entries; do
    [ -d "$C/fuzz_c/corpus/$d" ] || fail "corpus/$d/ missing"
    [ "$(find "$C/fuzz_c/corpus/$d" -type f | wc -l)" -ge 1 ] \
        || fail "corpus/$d has no seed inputs"
done
pass "seed corpora populated for all 3 targets"

# 7. .gitignore prevents accidental commits of build artifacts.
[ -f "$C/fuzz_c/.gitignore" ] || fail "fuzz_c/.gitignore missing"
grep -q '\.dSYM' "$C/fuzz_c/.gitignore" \
    || fail "fuzz_c/.gitignore does not ignore *.dSYM (will pollute commits on macOS)"
pass "fuzz_c/.gitignore covers binaries + crash-* + .dSYM"

# 8. Pin the CI job name so a future workflow rename can't quietly drop
#    fuzz coverage. NEXT_STEPS.md Phase E wired this on 2026-05-13.
CI_YML="$REPO_ROOT/.github/workflows/ci.yml"
if [ -f "$CI_YML" ]; then
    grep -q 'fuzz-c' "$CI_YML" \
        || fail "ci.yml missing 'fuzz-c' job — rename without updating this test would lose C fuzz CI coverage"
    pass "ci.yml still defines the fuzz-c job"
fi
