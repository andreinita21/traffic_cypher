#!/bin/bash
# 24 — Pin the compile-time hardening flags from the
# "What does not fit in this plan" backlog of REMEDIATION_PLAN.md so they
# don't quietly disappear in a future Makefile/Cargo.toml refactor.
set -e
source "$(dirname "$0")/lib/common.sh"

C_MK="$REPO_ROOT/traffic_cypher_in_C/Makefile"
RUST_TOML="$REPO_ROOT/traffic_cypher_in_Rust/Cargo.toml"
RUST_TOOLCHAIN="$REPO_ROOT/traffic_cypher_in_Rust/rust-toolchain.toml"

# --- C: hardening flags in CFLAGS / LDFLAGS ---

grep -q -- '-fstack-protector-strong' "$C_MK" \
    || fail "Makefile missing -fstack-protector-strong"
pass "Makefile sets -fstack-protector-strong"

grep -q -- '-fPIE' "$C_MK" \
    || fail "Makefile missing -fPIE compile flag"
pass "Makefile sets -fPIE"

grep -q -- '-D_FORTIFY_SOURCE=2' "$C_MK" \
    || fail "Makefile missing -D_FORTIFY_SOURCE=2"
pass "Makefile sets _FORTIFY_SOURCE=2"

# Linux-only linker hardening. The whole block lives under `ifeq ($(UNAME_S),Linux)`.
grep -q -- '-Wl,-z,relro' "$C_MK" \
    || fail "Makefile missing Linux -Wl,-z,relro"
grep -q -- '-Wl,-z,now' "$C_MK" \
    || fail "Makefile missing Linux -Wl,-z,now"
grep -q -- '-Wl,-z,noexecstack' "$C_MK" \
    || fail "Makefile missing Linux -Wl,-z,noexecstack"
pass "Makefile sets Linux linker hardening (relro+now+noexecstack)"

# --- Rust: MSRV, profile.release LTO + strip, toolchain pin ---

grep -Eq '^rust-version *= *"[0-9]+\.[0-9]+"' "$RUST_TOML" \
    || fail "Cargo.toml missing rust-version (MSRV) pin"
pass "Cargo.toml pins rust-version (MSRV)"

grep -q '^\[profile\.release\]' "$RUST_TOML" \
    || fail "Cargo.toml missing [profile.release] section"
grep -Eq '^lto *= *"thin"' "$RUST_TOML" \
    || fail "Cargo.toml profile.release missing lto = \"thin\""
grep -Eq '^strip *= *"symbols"' "$RUST_TOML" \
    || fail "Cargo.toml profile.release missing strip = \"symbols\""
pass "Cargo.toml [profile.release] has lto = \"thin\" + strip = \"symbols\""

[ -f "$RUST_TOOLCHAIN" ] \
    || fail "rust-toolchain.toml missing — toolchain not pinned"
grep -q '^channel *=' "$RUST_TOOLCHAIN" \
    || fail "rust-toolchain.toml missing channel"
grep -q 'rustfmt' "$RUST_TOOLCHAIN" \
    || fail "rust-toolchain.toml does not request rustfmt"
grep -q 'clippy' "$RUST_TOOLCHAIN" \
    || fail "rust-toolchain.toml does not request clippy"
pass "rust-toolchain.toml pins channel + requests rustfmt + clippy"
