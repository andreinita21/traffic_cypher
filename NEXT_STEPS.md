# Next Steps — getting Traffic Cypher to its "functional state"

Forward-looking plan, written 2026-05-13 after [`#1a` stages 1–5](./REMEDIATION_PROGRESS.md) landed. `REMEDIATION_PLAN.md` (the original roadmap) is effectively complete; this document tracks the five phases left before the project is functionally complete by the maintainer's definition (traffic entropy works by default, with at least two real entropy sources).

Read this together with `REMEDIATION_PROGRESS.md` for the history of what shipped and `REMEDIATION_PLAN.md` for the original design.

## Status snapshot

| | |
|---|---|
| Branch | `main` |
| Last commit when this was written | `f68886a` (#1a stage 5 — async `msm_add_stream`) |
| Local tests | `bash tests/run.sh` — **35 PASS + 1 SKIP** in ~76 s (Apple Silicon). SKIP is `tests/34_c_auto_replay.sh`'s integration step (requires `yt-dlp`). |
| CI | All 8 jobs green: `rust × 2`, `c × 2`, `c-traffic-entropy × 2`, `tests × 2`. |
| Default build behaviour | `make` still ships the OS-only-entropy daemon (`/api/build/info` → `traffic_entropy:false`). `make ENABLE_TRAFFIC_ENTROPY=1` enables the full Rust-parity C build. |
| Plan items remaining | 4 originally requested + 1 new feature requested mid-plan (phone-camera entropy source). |

## Decisions already made

These came out of the planning conversation. **Do not relitigate** unless requirements change — they're the constraints the phases below are designed against.

1. **OS-only path stays as an opt-out after the default-flip.** `make ENABLE_TRAFFIC_ENTROPY=0` will be the new opt-out for one release cycle. Lets users roll back to legacy behaviour if the flag-on path has a field issue. Removable in a follow-up.
2. **CI integration tests use bogus URLs only, never real YouTube.** YouTube is rate-limited and livestreams go offline — flaky and slow. The async pipeline is exercised end-to-end by POSTing a deliberately-invalid URL and asserting the slot transitions to `Failed` via the prep pthread path. The new phone-camera feature's curl-driven mock-frame test (Phase B) covers the actually-flowing-frames case.
3. **`cargo fmt` lands as a separate single commit.** ~1,321-line auto-generated diff. Bundling into Phase C (default-flip) would create a noisy review.
4. **Fuzz CI = 60s push-time smoke only.** No nightly cron for now. Push-time runs catch regressions; long nightly runs can be added in a follow-up if push-time finds anything interesting.
5. **Phone-camera entropy is a real product feature, not a CI device.** Designed to coexist with YouTube streams in the same MSM; OS fallback still kicks in when no source is active. Anyone can POST frames from anywhere (curl, mobile app, custom client). The "webpage from phone" is one specific client; the backend supports it but isn't responsible for solving the HTTPS problem.

---

# Phase A — Parity-variant in CI

**Why first**: this is the safety net for everything else. Once `ENABLE_TRAFFIC_ENTROPY` is the default (Phase C), you can't undo a regression with "just run the unit tests" — you need CI exercising the full pipeline against the Rust reference.

## Tasks

- [ ] **A.1** Install `yt-dlp` + `ffmpeg` on the `c-traffic-entropy` runner.
    - Ubuntu: `sudo apt-get install -y ffmpeg && pip install yt-dlp`
    - macOS: `brew install ffmpeg yt-dlp`
    - Cache the python pip install if `pip install yt-dlp` is slow.
- [ ] **A.2** Extend the `c-traffic-entropy` job with a step running `BUILD_VARIANT=traffic_entropy bash tests/60_parity_smoke.sh`. The 4 anchor cases already agree in this mode locally (verified at commit `aa33297`), so CI should be green out of the gate.
- [ ] **A.3** Add `tests/37_msm_e2e_smoke.sh` regression. Starts the flag-on PM (out-of-tree rebuild, same pattern as `tests/33`), POSTs `{"url":"https://invalid.example/not-a-real-stream","label":"smoke"}` to `/api/streams`, asserts:
    - Response is `202 Accepted` with `status:"connecting"` (the async path is alive)
    - Within 15s, `/api/streams` shows the slot as `Failed` (the prep pthread + cancel path are alive)
    - `frames_captured == 0` (no real frames flowed; OS fallback handles entropy)
- [ ] **A.4** Wire `tests/37` into the `c-traffic-entropy` CI job and into `tests/run.sh`.

## Verification

```bash
bash tests/run.sh       # expect 36 PASS + 1 SKIP locally (was 35)
gh run watch <latest>   # expect all jobs green; c-traffic-entropy now includes parity-variant + e2e smoke
```

## Files touched

- `.github/workflows/ci.yml` (extend `c-traffic-entropy` job)
- `tests/37_msm_e2e_smoke.sh` (new)
- `REMEDIATION_PROGRESS.md` (entry)

---

# Phase B — Phone-camera entropy source (NEW feature)

**Why this matters**: the user calls traffic entropy a must, and YouTube alone is fragile (rate-limited, copyrighted content). Phone camera is a self-sufficient entropy source any operator can stand up.

## Design

### Backend (Rust + C, behind `ENABLE_TRAFFIC_ENTROPY`)

Three new HTTP endpoints (Rust adds them too — keep the implementations at parity).

| Method | Path | Body | Headers | Response |
|---|---|---|---|---|
| POST | `/api/streams/phone` | `{"label":"phone-1"}` | `Authorization: Bearer <session>` | `202 {"index":N,"upload_token":"<32-byte-hex>"}` |
| POST | `/api/streams/phone/{N}/frame` | raw PPM body (320×240, ~230 KiB) | `X-Upload-Token: <token>` + `Content-Type: image/x-portable-pixmap` | `204 No Content` |
| DELETE | `/api/streams/phone/{N}` | — | `Authorization: Bearer <session>` | `200 {"status":"removed"}` |

PPM is chosen because the existing `frame_capture_read` produces PPM frames; ingesting PPM directly means the entropy pipeline (`extract_entropy` in `entropy_extractor.c`) doesn't need a new decoder. The frontend produces PPM via `<canvas>.getImageData()` and a small header-write loop.

### MSM extension

Add a `slot_kind` enum to `stream_slot_t` in `traffic_cypher_in_C/src_c/multi_stream.c`:

```c
typedef enum { SLOT_FFMPEG = 0, SLOT_PHONE = 1 } slot_kind_t;
```

- `SLOT_FFMPEG` = current default. Has a prep + forwarder pthread. No code path changes.
- `SLOT_PHONE` = no pthreads at all. Frame ingestion happens directly in the HTTP handler that calls `msm_push_phone_frame(msm, idx, frame, token)`.

New public C function `msm_register_phone(msm, label, out_token[32])` allocates a slot, generates a 32-byte random token (via `RAND_bytes`), stores it in the slot, marks `slot_kind = SLOT_PHONE`, `status = STREAM_CONNECTING`. Returns the slot index.

New public C function `msm_push_phone_frame(msm, idx, frame, token)` validates the slot index, slot kind, and token (constant-time compare), then ring-pushes the frame. First successful push transitions `status` from `CONNECTING` → `ACTIVE`.

`msm_remove_stream` already works for `SLOT_PHONE` — it just skips the prep/forwarder join since both are zero for phone slots. Add an explicit `if (slot->kind == SLOT_PHONE) skip_pthread_joins;` early-out.

`msm_get_statuses` is slot-kind-agnostic; no change.

### Frontend

- New file `frontend/phone.html` (loaded standalone, not part of the SPA).
- Asks for camera permission via `navigator.mediaDevices.getUserMedia({video: {width: 320, height: 240}})`.
- Draws to a hidden 320×240 `<canvas>` at 1 FPS via `setInterval` + `drawImage`.
- Exports each frame as PPM by reading `canvas.getContext('2d').getImageData()` and prepending a `P6\n320 240\n255\n` header.
- POSTs the PPM body to `upload_url` with the `X-Upload-Token` header.
- Shows a three-line status panel: `state`, `frames sent`, `last error`.

- Dashboard (`frontend/app.js`): add a "Pair phone" button that:
    - Calls `POST /api/streams/phone` to reserve a slot, gets back `index + upload_token`.
    - Displays the URL `http://<location.host>/phone.html?slot=N&token=<token>` plus a QR code (use a small dep-free QR lib, or just text). QR is optional in v1.
    - Shows the slot in the existing stream list using `frames_captured` from `/api/streams` polling that's already in place.

### HTTPS caveat

`getUserMedia` requires HTTPS or `localhost`. Phone → laptop-IP over HTTP is denied by Chrome/Safari/Firefox. Document the dev mitigation in `README.md`:

> To pair a phone in dev: either (a) run Chrome on the phone with `chrome://flags/#unsafely-treat-insecure-origin-as-secure` set to `http://<laptop-ip>:9876`, or (b) put `mkcert`-issued certificates in front of the daemon and connect via `https://`. TLS termination is not handled by Traffic Cypher itself.

## Tasks

- [ ] **B.1 Backend (C)** — Extend `multi_stream.{h,c}` with `slot_kind_t`, `msm_register_phone`, `msm_push_phone_frame`. Update `msm_remove_stream` + `msm_free` to handle `SLOT_PHONE` cleanly (no pthread joins). Behind `#ifdef ENABLE_TRAFFIC_ENTROPY`.
- [ ] **B.2 Backend (C)** — `web_server.c`: route `POST /api/streams/phone`, `POST /api/streams/phone/{N}/frame`, `DELETE /api/streams/phone/{N}` to the new MSM functions. Auth: `Authorization: Bearer` for the reserve/delete endpoints; `X-Upload-Token` (constant-time) for the frame endpoint. Token validation under the manager lock.
- [ ] **B.3 Backend (Rust)** — Mirror the three endpoints in `traffic_cypher_in_Rust/src/web/routes.rs` so parity holds. The Rust `MultiStreamManager` needs equivalent `register_phone` + `push_phone_frame` methods.
- [ ] **B.4 Frontend** — `frontend/phone.html` (standalone capture page) + dashboard `Pair phone` button. Single canonical source; C `make frontend` mirrors. No new attribute-string interpolation sinks (per `tests/25`).
- [ ] **B.5 Tests** — `tests/38_phone_camera_endpoint.sh`: builds flag-on, starts PM, unlocks, POSTs `/api/streams/phone` (asserts 202 + token), POSTs 3 synthetic PPMs (1×1 pixel for speed), polls `/api/streams` until `frames_captured >= 3` and `status == "Active"`, confirms `/api/entropy-snapshot.has_traffic_entropy == true`. Token-mismatch case asserts 403.
- [ ] **B.6 Parity test** — Add a `phone_streams_status` case to `parity/cases.json` that reserves a phone slot on both implementations and compares the status shape (no `expected_diff` — they should match exactly).

## Verification

```bash
make -C traffic_cypher_in_C ENABLE_TRAFFIC_ENTROPY=1   # both binaries clean
cargo build --release --bins --locked                  # rust side clean
bash tests/run.sh                                      # expect 37 PASS (was 36 after Phase A)
BUILD_VARIANT=traffic_entropy bash tests/60_parity_smoke.sh  # all cases including phone_streams_status agree
```

## Files touched

- `traffic_cypher_in_C/include/multi_stream.h`, `traffic_cypher_in_C/src_c/multi_stream.c`
- `traffic_cypher_in_C/src_c/web_server.c`
- `traffic_cypher_in_Rust/src/multi_stream.rs`, `traffic_cypher_in_Rust/src/web/routes.rs`
- `frontend/app.js`, `frontend/phone.html` (new), `frontend/style.css`
- `parity/cases.json` (new `phone_streams_status` case)
- `tests/38_phone_camera_endpoint.sh` (new)
- `README.md` (HTTPS caveat note)
- `REMEDIATION_PROGRESS.md` (entry — call this `#1a stage 6 — phone-camera entropy source`)

## Open questions

- **Token storage durability**: tokens are in-memory only — process restart loses them, breaking the phone client. Acceptable for v1 since `/api/streams/phone` re-reservation gets a fresh token; phone client must re-pair after server restart.
- **Frame rate cap**: 1 FPS matches ffmpeg's `fps=1`. Higher rates would saturate the entropy pipeline. Enforce server-side rate limit (drop frames if more than 2/sec)?
- **JPEG decode**: if a future phone client sends JPEG instead of PPM for bandwidth, we'd need a decoder. Out of scope for v1; rejection with `415 Unsupported Media Type` is fine.

---

# Phase C — Default-flip of `ENABLE_TRAFFIC_ENTROPY`

**Why third**: only flip after A + B prove the flag-on build is CI-stable and the phone-camera source works as an alternative to YouTube.

## Tasks

- [ ] **C.1 Makefile** — invert the gate. New semantics: `make` defines `-DENABLE_TRAFFIC_ENTROPY` by default; `make ENABLE_TRAFFIC_ENTROPY=0` is the opt-out for the OS-only legacy path. Document the inversion in a comment block.
- [ ] **C.2 `tests/31_c_no_entropy_lie.sh` rewrite** — rename to `tests/31_c_entropy_runtime_honesty.sh`. New invariant: "C build's runtime `traffic_entropy` flag accurately reflects whether frames have flowed". Cases: fresh PM with no streams → `false`; after `tests/38`-style synthetic frame POST → `true`.
- [ ] **C.3 `tests/33_traffic_entropy_build.sh` rename** to `tests/33_os_only_build.sh`. Invert: now tests the `ENABLE_TRAFFIC_ENTROPY=0` opt-out path. Verifies the opt-out binary returns `traffic_entropy:false` from `/api/build/info` and POST `/api/streams` returns 501.
- [ ] **C.4 `parity/cases.json`** — flip default `expected_diff` values for `streams_status` + `build_info`. Variant key renames: `default` → `traffic_entropy` (now the default mode), `traffic_entropy` → unused. Or, equivalently, rename to `os_only` for clarity.
- [ ] **C.5 `.github/workflows/ci.yml`** — rename `c-traffic-entropy` → `c-os-only`. Its job becomes: build with `ENABLE_TRAFFIC_ENTROPY=0`, run `tests/33_os_only_build.sh`. (The regular `c` job now covers the flag-on path implicitly.)
- [ ] **C.6 `README.md`** — flip the parity table cell to `C: Yes (default)` / `OS-only opt-out: ENABLE_TRAFFIC_ENTROPY=0`. Update the "Scope of the C implementation" section to describe the new default + the opt-out.
- [ ] **C.7 `REMEDIATION_PROGRESS.md`** — entry documenting the flip + the resolution of the original #1b "honest relabel" item (it's now genuinely accurate without qualification).

## Verification

```bash
make -C traffic_cypher_in_C            # now produces the flag-on binary
make -C traffic_cypher_in_C ENABLE_TRAFFIC_ENTROPY=0   # produces the opt-out binary
bash tests/run.sh                      # expect 37 PASS (same count; test renamings, no additions)
gh run watch <latest>                  # all jobs green; c-os-only covers the opt-out
```

## Files touched

- `traffic_cypher_in_C/Makefile`
- `tests/31_*.sh` (rename + rewrite), `tests/33_*.sh` (rename + invert)
- `parity/cases.json`
- `.github/workflows/ci.yml`
- `README.md`
- `REMEDIATION_PROGRESS.md`

---

# Phase D — `cargo fmt --check` hard gate

Single mechanical commit.

## Tasks

- [ ] **D.1** `cd traffic_cypher_in_Rust && cargo fmt --all`. Expect ~1,321 lines of auto-generated diff.
- [ ] **D.2** Verify the formatted source still passes `cargo build --release --bins --locked` + `cargo test --locked -- --test-threads=1` + `cargo clippy --all-targets --locked -- -D warnings`.
- [ ] **D.3** `.github/workflows/ci.yml`: remove `continue-on-error: true` from the `cargo fmt --check` step (line ~65), rename the step from "informational" to "(gate)".
- [ ] **D.4** Verify `bash tests/run.sh` still passes (no test changes expected).

Single commit titled `style: cargo fmt across all Rust sources + flip CI gate`.

## Verification

```bash
cd traffic_cypher_in_Rust
cargo fmt --check    # exit 0 — no diff remains
cargo build --release --bins --locked
cargo test --locked -- --test-threads=1
cargo clippy --all-targets --locked -- -D warnings
cd ..
bash tests/run.sh    # unchanged count
```

## Files touched

- Every `.rs` file under `traffic_cypher_in_Rust/src/`, `tests/`, `examples/`, `fuzz/`
- `.github/workflows/ci.yml`

---

# Phase E — Fuzz CI wiring

Two new jobs, both Ubuntu-only (Rust nightly + C clang+libFuzzer).

## Tasks

- [ ] **E.1 `fuzz-rust` job** in `.github/workflows/ci.yml`:
    - Matrix: `ubuntu-latest` only
    - `needs:` nothing (parallel with everything else)
    - Steps:
        1. Install nightly Rust via `dtolnay/rust-toolchain@nightly` with `components: rustfmt`
        2. `cargo install cargo-fuzz` (cached via `Swatinem/rust-cache` or a custom `actions/cache` keyed on the cargo-fuzz version)
        3. For each target in `traffic_cypher_in_Rust/fuzz/fuzz_targets/*.rs`: `cargo +nightly fuzz run <target> -- -max_total_time=60`
        4. Upload any `crash-*` artifacts on failure
    - `timeout-minutes: 10` (60s × 2 targets + nightly install + cargo-fuzz install + corpus restore)
- [ ] **E.2 `fuzz-c` job** in `.github/workflows/ci.yml`:
    - Matrix: `ubuntu-latest` only (macOS ASan + libFuzzer combo is documented-broken in `Makefile`)
    - Steps:
        1. Install OpenSSL 3.3 (reuse the `c` job's cache)
        2. `make -C traffic_cypher_in_C fuzz FUZZ_SANITIZER=fuzzer,address` (Linux can take the ASan combo)
        3. For each binary in `traffic_cypher_in_C/fuzz_c/`: run with `-max_total_time=60 -error_exitcode=1`
        4. Upload any `crash-*` artifacts on failure
- [ ] **E.3 Corpus persistence** via `actions/cache@v4`:
    - Path: `traffic_cypher_in_Rust/fuzz/corpus/`, `traffic_cypher_in_C/fuzz_c/corpus/`
    - Key: `${{ runner.os }}-fuzzcorpus-${{ hashFiles('.github/workflows/ci.yml') }}` (bumps when the workflow changes; otherwise the corpus compounds across runs)
- [ ] **E.4 Self-pin** — `tests/27_c_fuzz_scaffolding.sh` and `tests/26_fuzz_scaffolding.sh` already exist as regression. Add a small CI-job-name pin to one of them (`grep 'fuzz-c' ci.yml`, `grep 'fuzz-rust' ci.yml`) so a future workflow rename can't silently drop coverage.

## Verification

```bash
# Locally — confirm the targets still run before relying on CI
( cd traffic_cypher_in_Rust && cargo +nightly fuzz run vault_version_probe -- -max_total_time=10 )
make -C traffic_cypher_in_C fuzz
./traffic_cypher_in_C/fuzz_c/fuzz_hex_decode -max_total_time=10

# Push and watch
gh run watch <latest>   # fuzz-rust + fuzz-c both green
```

## Files touched

- `.github/workflows/ci.yml`
- `tests/26_fuzz_scaffolding.sh` and/or `tests/27_c_fuzz_scaffolding.sh` (small pin addition)
- `REMEDIATION_PROGRESS.md` (entry)

---

# Cross-cutting reminders

These apply to every phase. Captured here so future-you doesn't have to re-derive them.

- **Always run `bash tests/run.sh` before committing.** Numbers in the verification sections above are *expected* counts assuming earlier phases landed; adjust if you reorder.
- **No `git push --force` on `main`.** Each phase is one or more commits; if CI fails, push a fix-up commit, don't rewrite.
- **Update `REMEDIATION_PROGRESS.md` per phase.** Pattern: heading dated `2026-MM-DD — #1a stage N — <short title>`, followed by "Files", "Verification", "Risks" subsections. Match the style of the existing stage 1-5 entries.
- **Watch CI after every push.** `gh run watch <id> --interval 30 --exit-status` is the idiom. Tests-job timeout is now 10 min; everything else has lower caps.
- **Worktrees**: if you parallelise with subagents again, remember the `tests/34_*.sh` collision from stage 4 and assign distinct test numbers up front.

# When to consider Phase F+ (future)

Out of scope for the "functional state" definition but worth tracking:

- **TLS termination** — needed for non-localhost phone pairing without Chrome flag workarounds. `rustls` + a `mkcert` cert bundle would be a contained addition on the Rust side; the C side would need OpenSSL TLS wiring (~1 day).
- **MJPEG support on phone endpoint** — bandwidth optimisation over PPM. Needs a JPEG decoder in C (libjpeg-turbo) and a parallel implementation in Rust (the `image` crate handles it).
- **Real YouTube CI test** — if YouTube rate-limiting becomes manageable (auth via a service account?), add a single canary livestream URL to the parity smoke. Currently deferred per "decisions already made" #2.
- **Fuzz nightly cron** — 5-min-per-target runs on a `schedule:` trigger. Defer until push-time fuzz surfaces interesting findings.
- **Frontend de-dup pass 2** — `phone.html` adds a second canonical-source file; ensure C `Makefile`'s `frontend` target mirrors it and `tests/14_static_frontend_dedup.sh` covers the new file.
