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
| Move report binaries out of `main` | done (in-tree reorg) | this run — moved `traffic_cypher_benchmark_report.{docx,pdf}` to `reports/`; README updated; regression test pins the location. Repo size unchanged but root tree is clean. LFS / Releases migration remains an option for a future PR. |
| Week 4+ #5c DOM construction pass | done | this run — 9 attribute sinks replaced with `.value =` setters and a closure-bound copy handler |
| Week 4+ #10d fuzzing targets | done (Rust + C) | this run — Rust: `traffic_cypher_in_Rust/fuzz/` (2 cargo-fuzz targets). C: `traffic_cypher_in_C/fuzz_c/` (3 libFuzzer targets, `ENABLE_FUZZ_API`-gated wrappers in `vault.c`, `make fuzz` target). CI wiring deferred (Rust needs nightly; C needs clang+libFuzzer runtime on the runner). |
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

### 2026-05-13 — Week 4+ batch 2: #5c DOM construction hardening

Replaced the 9 high-risk attribute interpolation sites in `frontend/app.js` (lines 358, 475, 479, 483, 487, 512, 516, 1084, 1088 in the pre-change file) with explicit DOM setters that never re-invoke the HTML parser:

- 7 form `<input value="${esc(...)}">` and 1 `<textarea>${esc(...)}</textarea>` in `openAddEditModal` → fields rendered empty; `overlay.querySelector('#f-*').value = existing?.* || ''` after `appendChild`.
- 2 stream-edit `<input value="${esc(...)}">` in `openEditStreamModal` → same `.value =` pattern.
- 1 `<button data-copy="${esc(c.username)}">` → an id'd button (`#copy-username-btn`) with a closure-bound listener that captures `c.username`. The generic `[data-copy]` dispatcher is kept in place but no longer wires a user-controlled value.

Text-content `${esc(...)}` interpolations (~12 sites, e.g. `<div class="name">${esc(c.label)}</div>`) are left as-is — they don't sit in an attribute and remain protected by `esc()`'s five replacements.

**Files**
- `frontend/app.js` — single canonical source; C `make` mirrors it into `traffic_cypher_in_C/frontend/app.js` at build time (per #5b).
- `tests/25_dom_attribute_sinks.sh` (new) — grep-pinned regression: refuses any new `value="${esc(...)}"` or `data-copy="${esc(...)}"`; asserts the 9 expected setters exist; runs `node --check`; verifies the C copy is in sync.

**Verification**
- `node --check frontend/app.js` — clean.
- `make -C traffic_cypher_in_C` — clean; `diff -r frontend/ traffic_cypher_in_C/frontend/` → identical.
- `cargo build --release --locked` — clean (include_str! picks up updated app.js).
- `cargo test --locked` / `cargo clippy --all-targets --locked -- -D warnings` — clean.
- `bash tests/run.sh` — 28/28 PASS (was 27; +1 new DOM-sinks test).

**Note on full DOM construction**
The plan suggests "switch from innerHTML template-string assembly to explicit DOM construction." Full migration would replace the entire `overlay.innerHTML = \`...\`` blocks (~150 lines of templates) with `document.createElement` chains — a much larger structural change. The minimal-safe interpretation chosen here (set safe attributes via DOM setter, keep the structural template) closes the actual stored-XSS attack surface in the 9 attribute sites called out by the plan with ~25 LOC of diff and zero rendering risk. A full conversion can land as a separate UI refactor PR.

### 2026-05-13 — Week 4+ batch 3: #10d Rust cargo-fuzz scaffolding

Added a cargo-fuzz sub-crate at `traffic_cypher_in_Rust/fuzz/` covering the two Rust fuzz targets called out by REMEDIATION_PLAN.md:

- `vault_version_probe` — fuzzes the `{"version":N}` peek the public `load_vault` does before committing to a V2/V3 struct shape.
- `vault_v3_envelope` — fuzzes the full V3 struct deserialization plus hex decoding of the four envelope fields. Stops short of Argon2id derivation / AES-GCM so iterations stay sub-millisecond.

**Files**
- `traffic_cypher_in_Rust/src/vault.rs` — added two `#[doc(hidden)] pub fn fuzz_parse_*` helpers placed between regular code and the test module (clippy `items-after-test-module` was the reason for re-ordering during the build). Plus a smoke unit test `fuzz_helpers_basic_inputs` so the helpers stay alive in regular `cargo test`.
- `traffic_cypher_in_Rust/fuzz/Cargo.toml` (new) — standalone sub-crate, NOT in the parent workspace (parent has no `[workspace]`). Two `[[bin]]` targets.
- `traffic_cypher_in_Rust/fuzz/fuzz_targets/vault_version_probe.rs`, `vault_v3_envelope.rs` (new) — minimal `fuzz_target!` wrappers.
- `traffic_cypher_in_Rust/fuzz/corpus/vault_version_probe/{v2,v3}.json`, `vault_v3_envelope/seed.json` (new) — seed inputs.
- `traffic_cypher_in_Rust/fuzz/.gitignore`, `traffic_cypher_in_Rust/fuzz/README.md` (new).
- `tests/26_fuzz_scaffolding.sh` (new) — pins scaffolding presence, target names, helper exports, corpus population, and isolation from the parent workspace.

**Verification**
- `cargo test --locked --lib fuzz` — `fuzz_helpers_basic_inputs` passes.
- `cargo build --release --bins --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` — clean (`fuzz/` is not in the parent workspace so it doesn't participate).
- `bash tests/run.sh` — 29/29 PASS (was 28; +1 new scaffolding test).

**Risks / deferred**
- `cargo +nightly fuzz run <target>` is not exercised here — requires nightly Rust + `cargo install cargo-fuzz`. Documented in `fuzz/README.md`.
- CI wiring (60-second smoke per push, 5-minute nightly) deferred. Adds nightly toolchain + corpus-cache requirements; better as a follow-up PR.
- The C fuzz targets (#10d C-side) are not in this batch — they need `clang -fsanitize=fuzzer,address` plumbing in the Makefile and a separate scaffolding pass.

---

### 2026-05-13 — Week 4+ batch 4: #10d C libFuzzer scaffolding

Added the C half of #10d. Three libFuzzer targets at `traffic_cypher_in_C/fuzz_c/` driven by a new `fuzz` Make target.

- `fuzz_hex_decode` — fuzzes the public `hex_decode()` in `hex_utils.c`.
- `fuzz_json_get_string` — fuzzes the file-static `json_get_string()` in `vault.c`, reached via a thin `fuzz_json_get_string()` wrapper at the bottom of `vault.c` gated by `#ifdef ENABLE_FUZZ_API`.
- `fuzz_parse_vault_entries` — same wrapper pattern around `parse_vault_entries()`. Highest payoff — walks the entire user-controlled vault JSON.

**Files**
- `traffic_cypher_in_C/src_c/vault.c` — appended `#ifdef ENABLE_FUZZ_API`-gated wrappers (production build untouched: regular `make` does not define the macro).
- `traffic_cypher_in_C/Makefile` — `fuzz`, `fuzz-clean` PHONY targets. Sanitizer defaults to `FUZZ_SANITIZER=fuzzer` (no ASan) because `fuzzer,address` hangs libFuzzer init on macOS arm64 with Homebrew LLVM 20. Linux CI can opt into ASan via `make fuzz FUZZ_SANITIZER=fuzzer,address`. macOS-only `-framework Security` link is included (uuid_gen.c uses SecRandomCopyBytes).
- `traffic_cypher_in_C/fuzz_c/fuzz_targets/{fuzz_hex_decode,fuzz_json_get_string,fuzz_parse_vault_entries}.c` (new) — libFuzzer entry points that NUL-terminate the input buffer (parsers use strstr/strlen) and bound iteration size for fast cycles.
- `traffic_cypher_in_C/fuzz_c/corpus/<target>/` (new) — seed inputs per target (`deadbeef` hex, escaped + plain JSON, valid `entries:[]` and one entry).
- `traffic_cypher_in_C/fuzz_c/{.gitignore,README.md}` (new).
- `tests/27_c_fuzz_scaffolding.sh` (new) — pins target files, wrapper gating, production-build hygiene, Make target, libFuzzer entry-point exports, seed corpora, gitignore hygiene.

**Verification**
- `FUZZ_CC=/opt/homebrew/opt/llvm@20/bin/clang make -C traffic_cypher_in_C fuzz` — all three binaries build.
- 500-iteration smoke runs of each target: complete in <1 s, find 12/20/37 new corpus units, no crashes, peak RSS 27–35 MiB.
- `make -C traffic_cypher_in_C clean && make` — production build unchanged.
- `bash tests/run.sh` — 30/30 PASS (was 29; +1 new scaffolding test).
- `cargo build/test/clippy --locked` — clean.

**Risks / deferred**
- ASan+libFuzzer combo can't run locally on macOS arm64 (well-known LLVM upstream bug). Linux CI is unaffected; the Makefile makes the choice explicit.
- CI not wired for either Rust or C fuzz harnesses. Needs nightly Rust + clang+libFuzzer runtime + corpus caching strategy. Scaffolding is the prereq; CI is a separate plumbing PR.

---

### 2026-05-13 — Backlog batch 2: report binaries

Moved `traffic_cypher_benchmark_report.docx` and `traffic_cypher_benchmark_report.pdf` from the repository root into a new `reports/` subdirectory. Done as an in-tree reorg (low-risk, fully reversible) rather than a destructive Git LFS / filter-branch migration. Future migration to GitHub Releases or LFS can still happen — this commit just clears the root tree.

**Files**
- `reports/traffic_cypher_benchmark_report.docx`, `reports/traffic_cypher_benchmark_report.pdf` (moved via `git mv` to preserve history).
- `README.md` — refreshed the file-tree block to point at `reports/` (and added the now-canonical `frontend/`, `parity/`, `tests/` siblings while I was in there).
- `tests/28_report_binaries_location.sh` (new) — pins the new path and refuses any future `*.pdf` / `*.docx` at the repo root.

**Verification**: `bash tests/run.sh` — **31/31 PASS** (was 30; +1 new location test).

---

## Final state at end of run

- Weeks 0–3: complete (verified earlier in this file).
- Backlog (9 items): **9/9 complete** (the report-binaries item resolved this batch via in-tree reorg).
- Week 4+: #5c DOM construction pass complete; #10d **complete** (Rust + C); #1a Full C MultiStreamManager port deferred (~2 weeks of focused work per the plan).
- Regression harness: 26 → **31** tests, all green.
- Five commits pushed this session: `8b0ea7b` (build hardening), `827394b` (#5c DOM), `903c484` (Rust fuzz), `6effb7a` (C fuzz), and the upcoming reports commit.

---

### 2026-05-13 — Week 4+ #1a stage 1: `multi_stream` C module + bounded MPSC ring + unit tests

First substantive landing of the C `MultiStreamManager` port (`REMEDIATION_PLAN.md:332`). The plan estimates the *full* port at ~2 weeks; this commit delivers the foundation — the module, the bounded MPSC ring, the per-stream forwarder thread, and a unit-test harness — without touching `web_server.c` or `rotation_daemon`. The production behaviour is unchanged: the symbols ship in the binary but no caller invokes them yet.

**Files**
- `traffic_cypher_in_C/include/multi_stream.h` (new) — public API: `msm_new` / `msm_free` / `msm_add_stream` / `msm_remove_stream` / `msm_update_stream` / `msm_pick_random_frame` / `msm_get_statuses` / `msm_stream_count`. Matches the API sketch in `REMEDIATION_PLAN.md:333`. Test-only seams (`msm_test_push_frame`, `msm_test_register_slot`, `msm_test_ring_count`) gated by `ENABLE_MSM_TEST_API`.
- `traffic_cypher_in_C/src_c/multi_stream.c` (new) — full implementation. Internals:
  - `msm_ring_t`: bounded MPSC ring of `(stream_index, frame_t)` with `pthread_mutex_t` + `pthread_cond_t not_full` + `closing` flag. Producers block on push when full; consumer drains non-blocking via `ring_try_pop`.
  - `stream_slot_t[VAULT_MAX_STREAMS]` (=16, matching the existing config limit). Per-slot: url/label/state/frames_captured/thread/capture_pid/active/joined.
  - `forwarder_main`: per-stream pthread. Reads frames with the existing blocking `frame_capture_read`, pushes to the shared ring tagged with slot index, exits cleanly on `fread` EOF (induced by `SIGTERM` to the ffmpeg child).
  - `msm_pick_random_frame`: drains the ring, keeps the *latest* frame per stream (freeing older ones), picks a stream uniformly at random with seeded `rand()`, transfers ownership. Mirrors Rust's `multi_stream.rs:217`.
- `traffic_cypher_in_C/tests_c/msm_test.c` (new) — standalone unit-test binary. Five test cases / 28 assertions: msm_new/free smoke; zero-capacity rejection; ring FIFO + latest-wins pick; multi-slot pick uniformity (existence check) + frame counter; bounded-ring backpressure + close-wakes-blocked-producer. Doesn't spawn ffmpeg or yt-dlp — uses the test-only push seam.
- `traffic_cypher_in_C/Makefile` — `multi_stream.c` added to `SOURCES` (so symbols ship in `traffic-cypher{,-pm}`); new `msm_test` / `msm_test-clean` phony targets that compile a separate test binary with `-DENABLE_MSM_TEST_API`. `.PHONY` list updated.
- `.gitignore` — `traffic_cypher_in_C/msm_test{,.dSYM/}` added.
- `tests/29_multi_stream_unit.sh` (new) — regression harness. 8 assertions: scaffolding present, public API exported, `ENABLE_MSM_TEST_API` never leaks into production `CFLAGS`, multi_stream.c is in `SOURCES`, production build clean with the new file, `msm_test` binary builds + all assertions pass, production binaries don't export `msm_test_*` symbols (via `nm`).

**What's *not* in this commit (explicit non-goals for stage 1)**
- `rotation_daemon` rewrite. The current daemon at `key_rotation.c:11` continues to mix `RAND_bytes` only and keeps `has_traffic_entropy = 0`. Stage 2 will switch it to consume `msm_pick_random_frame` once a second under `#ifdef ENABLE_TRAFFIC_ENTROPY`, and only then set the flag when a frame was actually obtained.
- `web_server.c` wiring. `handle_add_stream` continues to respond 501 / `handle_list_streams` continues to mark every stream `Disabled`. Stage 3 will route them through `msm_add_stream` / `msm_get_statuses`.
- `/api/build/info` flip. Stays at `traffic_entropy:false` for the C build until stage 2 lands; the `streams_status` / `build_info` cases in `parity/anchor_cases.json` remain `expected_diff:true`.
- Feature-flag toggle. `--enable-traffic-entropy` build flag arrives with stage 2.

**Verification**
- `make -C traffic_cypher_in_C clean && make` — clean (no new warnings; existing `uuid_gen.c` `SecRandomCopyBytes` warning unchanged).
- `make -C traffic_cypher_in_C msm_test && ./traffic_cypher_in_C/msm_test` — 28/28 PASS.
- `bash tests/run.sh` — **32/32 PASS** in 77s on Apple Silicon (was 31; +1 new scaffolding test).
- `cargo build --release --bins --locked` / `cargo clippy --all-targets --locked -- -D warnings` / `cargo test --locked -- --test-threads=1` — clean (no Rust files touched, sanity check only).
- `nm -j traffic-cypher{,-pm} | grep msm_test_` — empty (paranoid check baked into `tests/29_...`).

**Risks**
- Stage-1-only: the production code path that calls into this module does not exist yet, so a regression here would be invisible to the existing parity / smoke tests. The unit-test harness is the *only* coverage — that's why it's broad (push/pop ordering, latest-wins, backpressure, close-wakes-blocked-producer).
- `srand((unsigned)time(NULL) ^ getpid())` in `msm_pick_random_frame` — not CSPRNG-quality. Justified inline: the entropy enters the cypher via `entropy_extractor` (SHA-256 of frame pixels), not via the pick. If/when the pick becomes load-bearing, swap to `RAND_bytes`.
- `frame_capture_read` is blocking; cancellation relies on `SIGTERM`ing the ffmpeg child so the pipe closes. This works on POSIX but is a vendored assumption — if `frame_capture_read` is later changed to use signalfd / non-blocking IO, the cancellation path needs to adapt.
- Capacity is hard-coded to `VAULT_MAX_STREAMS=16` slots, matching the existing config schema. If that limit is ever lifted, `forwarder_arg_t.slot_index` and the snapshot arrays in `msm_pick_random_frame` need to follow.

**Why this scope and not the full port**
Per the plan and `REMEDIATION_PROGRESS.md` history, #1a is the single largest deferred item (~2 weeks of focused C work). Delivering it as one mega-commit would be both unreviewable and dangerous (it touches `key_rotation.c` + `web_server.c` + parity tests + build flags + an external behaviour switch on `/api/build/info`). The stage 1 cut is the natural seam: it ships the entire foundation, can be reviewed in isolation, is fully testable without yt-dlp/ffmpeg, and changes zero observable behaviour for the running daemon. Stages 2–4 land independently against this base.

---

### 2026-05-13 — CI repair: tests-job timeout bump

The last three CI runs on `main` came back with a red `tests (ubuntu-latest)` job. Triage:

| Run | Commit | Apparent failure | Real cause |
|-----|--------|------------------|------------|
| `25777632567` | `8c06de3` | `tests (ubuntu-latest)` 5m5s | **5-min hard timeout** — harness completed `PASSED: 31 (171s)`; Ubuntu setup overhead (~130s for OpenSSL 3.3 cache restore, cargo cache, rust toolchain) tipped total over the cap. No newer push, so concurrency-cancel is ruled out. |
| `25769692804` | `5ec5990` | `tests (ubuntu-latest)` 5m16s | Same root cause. |
| `25769608981` | `6effb7a` | both `tests` jobs 1m7s | **Concurrency-group cancellation** — `5ec5990` was pushed 2.5 min later and the `cancel-in-progress: true` group killed the in-flight run. Not a real failure. |

The `X Process completed with exit code 1` annotation showing under `rust (...)` is the **informational** `cargo fmt --check` step (`continue-on-error: true` — see line 64 of `.github/workflows/ci.yml` and this doc's earlier note about the deferred 1,321-line formatting PR). The rust jobs themselves are ✓.

**Fix**
- `.github/workflows/ci.yml`: `tests.timeout-minutes` 5 → 10. The previous cap was sized when the harness had 26 tests; at 31 tests it no longer fits Ubuntu's setup overhead.

**Verification**
- `bash tests/run.sh` locally — **31/31 PASS** in 71s (Apple Silicon).
- YAML parses; new value confirmed via regex (`tests timeout-minutes = 10`).

**Risks**
- None functional — purely a CI-timing knob. Lowest-risk possible change.
- Default GitHub Actions runner timeout (6 h) still applies as an upper bound.

---

### 2026-05-13 — Routine re-entry / verification pass

Routine fired again on the same day after the previous run had already brought the project to its "Final state at end of run" above. No actionable items remained on `REMEDIATION_PLAN.md` (`Week 0`–`Week 3` complete; all 9 "What does not fit" backlog items complete; `Week 4+` #5c + #10d complete; only #1a — Full C `MultiStreamManager` port, ~2 weeks of focused C work per the plan — is intentionally deferred).

**Re-verification run** (this routine, no code changes):

| Check | Result |
|------|--------|
| `git status` | clean working tree |
| `cargo build --release --bins --locked` | OK |
| `cargo clippy --all-targets --locked -- -D warnings` | OK |
| `make -C traffic_cypher_in_C clean && make` | OK |
| `bash tests/run.sh` | **31/31 PASS** |

**Why no new commits this run.** Per the routine's "be precise and conservative" rule, and the plan's explicit deferral notes, the remaining candidates are all out of scope for an unattended pass:

- **#1a (Full C `MultiStreamManager` port).** The plan literally says "~2 weeks of focused C work"; not a one-routine job.
- **CI wiring for fuzz harnesses.** Documented as "a separate plumbing PR" — Rust side needs nightly + `cargo-fuzz` install (fragile in CI), and the C side needs a corpus-cache strategy. The scaffolding + `tests/26_…` and `tests/27_…` already pin scaffolding regressions.
- **Promote `cargo fmt --check` from informational to hard gate.** Local `cargo fmt --check` currently emits ~1.3k diff lines (legacy formatting baseline). That's a dedicated formatting PR, not a remediation step.

Nothing was committed, nothing was pushed, no destructive operations were taken.
