# Remediation Progress

This file tracks step-by-step status of the items defined in `REMEDIATION_PLAN.md`. It is updated by the remediation routine.

---

## Environment check (2026-05-13)

| Check | Result |
|------|--------|
| OS | macOS, Darwin 25.4.0, arm64 (Apple Silicon) |
| `git` | installed (/usr/bin/git) |
| `make` | installed (/usr/bin/make) |
| C compiler | clang + gcc installed |
| `cargo` / `rustc` | 1.95.0 stable |
| `rustfmt` / `clippy` | installed during this run (`rustup component add`) |
| OpenSSL | 3.6.1 (Homebrew) — well above Argon2id 3.2 floor |
| Python 3 | /opt/homebrew/bin/python3 |
| `curl`, `jq`, `ffmpeg` | installed |
| `yt-dlp` | **missing** — not installed by routine (Python pip install is user-scoped; stream tests not part of regression harness) |
| `actionlint` | not installed; YAML validated by inspection |

**Cargo fetch**: `cargo fetch --locked` succeeds; `Cargo.lock` valid.

**OpenSSL paths for C build**: `-I/opt/homebrew/opt/openssl@3/include` / `-L/opt/homebrew/opt/openssl@3/lib` discovered by Makefile.

**Limitations**: `yt-dlp` absent — stream-ingestion smoke tests cannot be exercised end-to-end here, but neither the parity harness nor `tests/run.sh` require it.

No system upgrades, no global package installs, no destructive commands run during setup.

---

## Resume state (2026-05-13)

| Source | Last completed week |
|--------|---------------------|
| `REMEDIATION_PROGRESS.md` | — (file did not exist; routine bootstrapped it this run) |
| Git history | Week 3 + most backlog (commits through `f24ca25`) |
| Code state | Week 0–3 verified present, plus 5/9 backlog items |

**No mismatch between Git history and code state.** Specifically verified:

- Week 0: esc() quote-encoding (`e09cdc4`), unused Cargo deps dropped (`985ea19`), `kill_on_drop` (`f532c84`), C `fork+execvp` (`4cfa479`), C socket timeouts (`0d0e95c`).
- Week 1: CI scaffold (`ce40878`), C `tags` parse + regression test (`9061178`), `str_buf` API (`24a4ecb`), honest C relabel + `/api/build/info` (`f4e3836`).
- Week 2: `str_buf` migration + body cap + FORTIFY_SOURCE (`a74afcb`), C 4-thread worker pool + `validate_session` locking + constant-time token compare (`3183b27`), frontend dedup (`37aead3`).
- Week 3: Rust HTTP integration tests (`4d1ebac`), parity harness (`0a8b127`), Argon2id v3 vault + KAT + v2→v3 auto-upgrade (`d00f8fa`).
- Backlog completed: atomic vault writes (`df19525`), CORS narrowing (`fdb0eb2`), `zeroize` (`834c407`), constant-time session token (`3183b27`), per-IP unlock rate limit (`c3d07c9`).
- Stability: 12 pre-existing clippy lints fixed and CI promoted to `-D warnings` (`d8f7c5e`); CI OpenSSL 3.3 build cache for Argon2id on Ubuntu (`f24ca25`).

**Baseline checks (pre-change, this run):**
- `cargo build --release --bins --locked` — OK
- `cargo test --locked -- --test-threads=1` — OK (all suites pass)
- `cargo clippy --all-targets --locked -- -D warnings` — OK
- `make -C traffic_cypher_in_C clean && make` — OK
- `bash tests/run.sh` — 26/26 PASS

**Chosen resume point**: the remaining backlog items from `REMEDIATION_PLAN.md` "What does not fit in this plan" section, plus the Week 4+ #5c DOM hardening and #10d fuzzing targets. Items are ordered by safety / blast radius (smallest first).

---

## Remaining backlog plan

| Item | Status | Notes |
|------|--------|-------|
| Constant-time session-token compare | done | `3183b27` |
| Per-IP unlock rate-limit | done | `c3d07c9` |
| zeroize for in-memory secrets | done | `834c407` |
| Atomic vault writes | done | `df19525` |
| CORS narrowing | done | `fdb0eb2` |
| Pin Rust MSRV via `rust-toolchain.toml` | done | this run — `rust-version = "1.82"` in `Cargo.toml`, `rust-toolchain.toml` pins channel + components |
| `[profile.release]` LTO + strip | done | this run — `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"` |
| More C compile-time hardening flags | done | this run — `-fstack-protector-strong -fPIE` always; Linux: `-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack`; GCC: `-Wstringop-overflow=4` |
| Move report binaries out of `main` | deferred | requires user policy decision (use Releases / Git LFS / branch) — out of scope for an unattended routine |
| Week 4+ #5c DOM construction pass | pending | this run |
| Week 4+ #10d fuzzing targets | pending | this run (Rust `cargo-fuzz` stubs) |
| Week 4+ #1a Full C MultiStreamManager port | deferred | plan calls this "~2 weeks of focused C work"; outside one-routine scope |

---

## Change log

### 2026-05-13 — Backlog batch 1: build hardening (Rust + C)

**Rust**
- `traffic_cypher_in_Rust/Cargo.toml`: added `rust-version = "1.82"` (MSRV), `publish = false` (intent), `[profile.release]` with `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`.
- `traffic_cypher_in_Rust/rust-toolchain.toml` (new): pin `channel = "stable"`, install `rustfmt` + `clippy` automatically for any rustup-using contributor.

**C**
- `traffic_cypher_in_C/Makefile`:
  - CFLAGS: added `-fstack-protector-strong -fPIE` unconditionally; `-Wstringop-overflow=4` under GCC (with `-Wstringop-truncation` already there).
  - Linux LDFLAGS: added `-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack`.
  - macOS untouched (clang already produces PIE by default; ld64 rejects the GNU-ld `-z` flags).

**Tests**
- `tests/24_hardening_flags.sh` (new): static greps that pin the new flags + the MSRV + the profile.release knobs in CI.

**Verification**
- `cargo build --release --bins --locked` — OK (release binary `target/release/traffic_cypher` = 1.7 MiB after LTO+strip).
- `cargo clippy --all-targets --locked -- -D warnings` — OK.
- `cargo test --locked -- --test-threads=1` — OK.
- `make -C traffic_cypher_in_C clean && make` — OK on Apple Silicon macOS.
- `bash tests/run.sh` — 27/27 PASS (was 26; +1 new hardening test).

**Risks**
- `-Wconversion` deliberately not added: it produces hundreds of expected-truthy warnings under `-Wall -Wextra` baseline (size_t↔int, ssize_t→size_t) that would need a separate audit pass. Documented here for the next batch.
- Moving report binaries (`.docx`/`.pdf`) out of `main` is deferred: a fully reversible policy decision (Releases vs. LFS vs. branch) — out of scope for an unattended routine.

---
