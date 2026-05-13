# Remediation Progress

This file tracks step-by-step status of the items defined in `REMEDIATION_PLAN.md`. It is updated by the remediation routine.

---

### 2026-05-13 — Phase B.3 (NEXT_STEPS.md): Rust mirror of phone endpoints + parity case

The C-side phone-camera path landed in commit `a7975cd`; this commit brings the Rust side to the same surface so the operator gets identical behaviour from both binaries, and adds a parity test that pins the two impls together going forward.

**Rust mirror — `traffic_cypher_in_Rust/src/multi_stream.rs`**

- New `SlotKind` enum (`Ffmpeg` / `Phone`); `kind` field added to `StreamStatus` (serialised lowercase: `"ffmpeg"` / `"phone"` — matches the C build's JSON shape).
- `StreamHandle` gains `kind` + `upload_token: Option<[u8; 32]>`. The existing `cancel_tx` and `child` fields stay `None` for phone slots, which is why `remove_stream` Just Works for them with zero changes — the existing `if let Some(...)` branches no-op.
- `register_phone(label) -> (usize, String)` generates 32 random bytes via `rand::thread_rng().fill_bytes()`, hex-encodes them, pushes a Connecting/Phone handle, returns the slot index and the hex token.
- `push_phone_frame(index, token_hex, frame) -> Result<(), PhoneFrameError>` validates slot bounds, slot kind, then constant-time-compares the supplied hex against the slot's hex-encoded token via a private `ct_eq_hex64()` helper (a straight-line XOR-accumulator loop, mirroring the C side). On match: transitions Connecting → Active, then `try_send` (non-blocking — avoids deadlock holding the manager mutex over an `await` if the bounded ring is full).
- New `PhoneFrameError` enum (`NotFound`/`TokenMismatch`/`RingFull`) implements `std::error::Error` so handlers can map it to the right HTTP status.

**Rust HTTP layer — `traffic_cypher_in_Rust/src/web/routes.rs`**

- `PHONE_HTML = include_str!("../../../frontend/phone.html")` mirrors the existing `INDEX_HTML` / `APP_JS` / `STYLE_CSS` pattern; `serve_phone` route under `static_routes()`.
- New api routes: `POST /api/streams/phone` → `register_phone` (no Bearer auth — the upload token returned here is the auth boundary on subsequent frame POSTs), `POST /api/streams/phone/{index}/frame` → `push_phone_frame`.
- `parse_ppm_header(&[u8])` ported from the C version, including the comment-skip + 65535 dimension cap. Returns `(width, height, pixel_offset)`. `clippy::needless_range_loop` resolved via `for tok in &mut tokens` instead of indexed `for t in 0..3`.
- HTTP handlers map `PhoneFrameError::TokenMismatch` → 403, `RingFull` → 503, `NotFound` → 400, success → 204. PPM header errors → 415; size mismatch → 400. Empty body → 400.

**Parity — `parity/cases.json`**

- New `phone_register_and_status` case: POSTs `/api/streams/phone`, unlocks, GETs `/api/streams`, asserts both impls return the same shape. `normalize_drop` strips the random `upload_token` plus the usual session-token / entry_count / entropy_source fields.
- New schema field `variants` (optional, array of variant names). When present, the case only runs under the matching `BUILD_VARIANT`. Cases without `variants` run in all variants (back-compat). The phone case uses `["traffic_entropy"]` because the default C build has no route — running it in `default` mode would 404 on the register POST and the harness's `expect_status: 202` would fail the case before the diff-with-Rust comparison.
- `parity/parity_test.py` filters by `variants` after the case-name filter, before `max_cases` truncation.
- `tests/60_parity_smoke.sh` bumps `--max-cases 4` → `5` so the new case actually runs under `BUILD_VARIANT=traffic_entropy`.

**Tests — `tests/38_phone_camera_endpoint.sh`**

Existing C-side block (11 assertions) unchanged. Appended a Rust-side block (8 assertions) at the bottom: drains port 9876 between binaries, boots `target/release/pm`, exercises `/phone.html`, register, 3 synthetic frame POSTs, `kind:"phone"` + Active in `/api/streams`, wrong-token → 403. Skip path if the Rust binary isn't built yet (`tests/00_build_rust.sh` produces it).

**Verification**

- `cd traffic_cypher_in_Rust && cargo build --release --bins --locked` — clean.
- `cargo clippy --all-targets --locked -- -D warnings` — clean (1 lint fix: see above).
- `cargo test --locked -- --test-threads=1` — **8/8 PASS**.
- `bash tests/38_phone_camera_endpoint.sh` — **19/19 PASS** (was 11 — added 8 Rust assertions).
- `bash tests/run.sh` — **37 PASS + 1 SKIP** in 119 s (test count unchanged; tests/38 grew internally).
- `bash tests/60_parity_smoke.sh` (default mode) — 4 cases run (phone case filtered out by variant), 3 PASS + 1 KNOWN-DIVERGENT (the pre-existing `build_info`).
- `BUILD_VARIANT=traffic_entropy bash tests/60_parity_smoke.sh` — **5/5 PASS, 0 KNOWN-DIVERGENT, 0 FAIL** in 5.7 s. Phone register + status match exactly between C and Rust.

**Why `try_send` not `send().await` for phone frames**

The phone frame handler in Rust holds the tokio manager mutex while calling `push_phone_frame`. If the bounded channel were full, `send().await` would suspend while still holding the lock — blocking every other operation on the manager (list_streams, add_stream, remove_stream) until a consumer drained an item. `try_send` returns `Err(RingFull)` immediately on saturation; the handler maps that to 503 and the phone client retries on its next 1-second tick. The bounded channel's whole purpose (backpressure) is preserved without the deadlock surface.

---

### 2026-05-13 — Phase B (NEXT_STEPS.md): phone-camera entropy source (C side)

Second slice of `NEXT_STEPS.md`. Introduces a brand-new entropy source — the phone's own camera, accessed via a standalone capture page served by the daemon — alongside the existing YouTube/yt-dlp path. Both kinds of slots coexist in the same MSM; OS fallback still kicks in when neither is active. Behind `ENABLE_TRAFFIC_ENTROPY` like the rest of stage 3+.

**User flow**
1. Operator opens the dashboard, sees a new "Pair a phone camera" affordance under Live Streams that prints `http://<host>:9876/phone.html`.
2. Phone visits the URL → page asks for a camera name + a Start Streaming click.
3. On click: page POSTs to `/api/streams/phone` (no auth) → server returns `{index, upload_token}`; page calls `getUserMedia`; begins 1-FPS capture loop POSTing PPM frames to `/api/streams/phone/{N}/frame` with `X-Upload-Token`.
4. Dashboard's `/api/streams` polling shows the slot as `Active` with `kind:"phone"` and a live `frames_captured` counter.

**Wire-up**

- `traffic_cypher_in_C/include/multi_stream.h`: new `slot_kind_t` enum (`SLOT_FFMPEG`/`SLOT_PHONE`); `kind` field added to `stream_status_t`; two new public functions `msm_register_phone` (allocates slot, generates 32-byte random token via `RAND_bytes`, writes 64-char lowercase hex to caller buffer) and `msm_push_phone_frame` (validates slot kind + constant-time-checks the token, ring-pushes the frame, transitions `CONNECTING` → `ACTIVE` on first success).
- `traffic_cypher_in_C/src_c/multi_stream.c`:
  - `stream_slot_t` gains `kind` + `upload_token[32]`.
  - `msm_register_phone` / `msm_push_phone_frame` implemented; private `ct_eq_hex64()` constant-time 64-char hex comparator (volatile-accumulator pattern to defeat the compiler re-introducing early exit).
  - `msm_get_statuses` now reports the slot kind.
  - `msm_remove_stream` / `msm_free`: skip pthread joins for `SLOT_PHONE` (those slots have no prep or forwarder threads; phone removal is a synchronous slot-clear + token wipe).
- `traffic_cypher_in_C/src_c/web_server.c`:
  - `http_request_t` gets an `x_upload_token[128]` field; `parse_request` extracts the `X-Upload-Token` header (same pattern as the existing `Authorization` extraction).
  - New handlers `handle_register_phone`, `handle_phone_frame` (both behind `ENABLE_TRAFFIC_ENTROPY`).
  - Routes added BEFORE the generic `/api/*` auth gate: `POST /api/streams/phone` (public) and `POST /api/streams/phone/{N}/frame` (X-Upload-Token auth, no Bearer). Generic `/api/streams/{N}` DELETE still serves both kinds because `msm_remove_stream` is kind-aware. Phone slots don't touch `stream_config`, so the config-shift step is conditional.
  - New static route `GET /phone.html` serves the capture page (loaded at startup via the existing `load_frontend_file` pattern). `frontend_phone` static + `frontend_phone_len` added.
  - `handle_list_streams` (flag-on branch) now emits `"kind":"phone"` or `"kind":"ffmpeg"` per slot.
  - Inline `parse_ppm_header()`: small P6 parser that extracts width/height/pixel-offset from a memory buffer. Doesn't reuse `frame_capture_read`'s parser (that one is `FILE*`-based). Rejects malformed input + caps dimensions at 65535.
- `traffic_cypher_in_C/Makefile`: `msm_test` target now links OpenSSL + hex_utils.c (multi_stream.c uses `RAND_bytes` + `hex_encode`).
- `frontend/phone.html` (new, 220 LOC including inline CSS/JS): self-contained capture page. Camera-name input + Start button → registers + opens camera + captures to canvas at 1 FPS → encodes PPM via `getImageData` → POSTs with the upload token. Stop button tears it down. No external deps.
- `frontend/app.js`: Live Streams panel copy updated ("YouTube livestreams **and** phone cameras feed the same pipeline"). New "Pair a phone camera" row with an absolute URL pointing at the daemon's own host. Stream-list renderer extended with a `KIND_BADGE` whitelist (mirrors the `STATUS_CLASS` whitelist from #1a stage 4d) — `phone`/`ffmpeg` only; anything else collapses to empty string, defeating class-name injection if the server ever lied.
- `tests/38_phone_camera_endpoint.sh` (new, 11 assertions): out-of-tree flag-on build, boots PM, serves /phone.html, registers a slot, pushes 3 synthetic 1×1 PPM frames, checks slot transitions to Active + `kind:"phone"` + `frames_captured ≥ 1`, polls `/api/entropy-snapshot` until `has_traffic_entropy:true`, asserts wrong-token POST → 403, asserts DELETE removes the slot. All curl + python3 — no real phone needed.

**Verification**

- `make -C traffic_cypher_in_C clean && make` — clean (default build, no phone code reachable).
- `make -C traffic_cypher_in_C clean && make ENABLE_TRAFFIC_ENTROPY=1` — clean.
- `./traffic_cypher_in_C/msm_test` — 28/28 PASS (test seam unchanged).
- `bash tests/38_phone_camera_endpoint.sh` — 11/11 PASS. Slot transitions to Active after the first frame; `has_traffic_entropy:true` after ~3-5 s of frame flow.
- `bash tests/run.sh` — **37 PASS + 1 SKIP** in 117 s on Apple Silicon (was 36; +1 new test). The 40 s delta vs. Phase A's 78 s comes from tests/37 + tests/38 each doing their own out-of-tree flag-on rebuild.
- `BUILD_VARIANT=traffic_entropy bash tests/60_parity_smoke.sh` — 4/4 agree. Phone slots don't change the existing 4 anchor cases.

**What's NOT in this commit (Rust mirror + parity case)**

Per NEXT_STEPS.md Phase B's task list, B.3 (Rust mirror of `/api/streams/phone[/...]/frame`) and B.6 (parity `phone_streams_status` case) are deferred. The C side is what makes "traffic entropy works" land for the user; Rust parity for this specific endpoint can follow in a separate commit. The current state remains parity-clean because the new endpoints are net-new — neither implementation has them in the comparison suite yet.

**Risks**

- **HTTPS for phone camera**. `navigator.mediaDevices.getUserMedia` requires HTTPS or localhost. Phone connecting to `http://<laptop-ip>:9876` over HTTP will be refused by the browser. Documented in `NEXT_STEPS.md`'s "HTTPS caveat" section. Dev mitigation: Chrome flag `chrome://flags/#unsafely-treat-insecure-origin-as-secure` set to the daemon's URL, or run TLS termination in front of the daemon. TLS in the daemon itself is out of scope for v1.
- **Slot exhaustion DoS**. A network actor can hammer `POST /api/streams/phone` to fill all 16 slots with `CONNECTING` phantoms. They can't push frames (no token), so the slots stay idle. Operator clears them via DELETE; auto-prune of idle phone slots is a future enhancement.
- **Token lifetime**. Tokens are in-memory only — process restart loses them and the phone must re-pair. Acceptable per the v1 trust model (anyone who can access the daemon URL on the LAN can re-pair via the dashboard's pair-link).
- **Frame size**. 320×240 PPM is ~230 KiB; well under the 8 MiB body cap. Higher resolutions would still fit, but the entropy pipeline scales O(width×height), so 320×240 stays the recommended default.

---

### 2026-05-13 — Phase A (NEXT_STEPS.md): parity-variant in CI

First slice of the `NEXT_STEPS.md` plan. Lands the CI safety net for the future default-flip: `c-traffic-entropy` now runs the parity smoke against the flag-on C build on every push, on both runners.

**Wire-up**

- `.github/workflows/ci.yml` — `c-traffic-entropy` job extended:
  - Adds Rust toolchain install + `Swatinem/rust-cache` + `cargo build --release --bins --locked` (parity needs the Rust PM).
  - Adds yt-dlp + ffmpeg install steps (apt-get + pip on Ubuntu, brew on macOS). `python3 -m pip install --user yt-dlp` is preferred over apt since apt's yt-dlp is typically months behind YouTube; `$HOME/.local/bin` is added to `GITHUB_PATH`.
  - After the existing `tests/33` build-only smoke, runs:
    - `tests/37_msm_e2e_smoke.sh` — end-to-end POST/poll loop.
    - `make clean && make` to restore the *default* C binary (parity's variant mode rebuilds the C side itself; the default binary on disk must NOT be the flag-on one or parity_test.py's variant detection gets confused).
    - `BUILD_VARIANT=traffic_entropy bash tests/60_parity_smoke.sh` — all 4 anchor cases must agree under the flag.
  - `timeout-minutes` bumped 8 → 12 (Rust cold-build + yt-dlp/ffmpeg install + parity smoke + tests/33 + tests/37 fit comfortably in 12).
- `tests/37_msm_e2e_smoke.sh` (new) — out-of-tree `make ENABLE_TRAFFIC_ENTROPY=1` build, boots PM, unlocks, POSTs `https://invalid.example/not-a-real-stream`, asserts 202 within 2s, polls `/api/streams` up to 15s for `Failed`, confirms `frames_captured == 0`. 7 assertions. Bogus URL on purpose — proves the prep-pthread → resolve → fail → cancel-window-honoured path is alive without needing real YouTube reachability.

**Verification**

- `bash tests/37_msm_e2e_smoke.sh` — POST elapsed `0.02s`, slot reaches Failed in ~1s. 7/7 PASS.
- `bash tests/run.sh` — **36 PASS + 1 SKIP** in 78s on Apple Silicon (was 35; +1 new test). The SKIP is `tests/34_c_auto_replay.sh`'s yt-dlp-dependent integration step.
- `BUILD_VARIANT=traffic_entropy bash tests/60_parity_smoke.sh` — `PASS: 4   KNOWN-DIVERGENT: 0   FAIL: 0` in 4.4s.

**Risks**

- yt-dlp pip install adds ~30s to the CI job; cached in pip's user-site cache by default but `actions/cache` would compound across runs. Not optimised here — push-time tradeoff is acceptable.
- The "make clean && make" restore step exists because `parity_test.py`'s `BUILD_VARIANT=traffic_entropy` mode rebuilds the C side in a temp dir but the Rust side reads `traffic_cypher_in_C/traffic-cypher-pm` for the default-mode comparison check (if any). Without the restore, residual flag-on artifacts on disk could confuse the default-variant lookup. Defensive; cheap; harmless.
- `tests/37` adds ~25s to local `bash tests/run.sh` (out-of-tree rebuild). Acceptable but watch this as the suite grows.

---

### 2026-05-13 — Week 4+ #1a stage 5: async `msm_add_stream` (prep pthread)

Removes the multi-second blocking caveat documented in the stage 3 entry. `msm_add_stream` no longer calls `resolve_stream_url` (yt-dlp) or `frame_capture_start` (ffmpeg) on the caller's thread — those run in a per-slot prep pthread spawned by `msm_add_stream` and joined by `msm_remove_stream` / `msm_free`.

**Why this matters**

- `handle_add_stream` (under `ENABLE_TRAFFIC_ENTROPY`) was the slowest HTTP path in the system: a single POST to `/api/streams` held one worker thread for ~2–5 s of yt-dlp resolve. With a 4-thread worker pool, four concurrent stream adds DoSed the daemon.
- Stage 4a's auto-replay-on-unlock fanned `state->stream_config` through `msm_add_stream` serially in a single detached pthread. For a 16-stream config that's a 30+ s wall-clock delay before all streams come online. After this refactor the 16 prep pthreads run in parallel — wall time drops to the slowest single resolve (~5 s).

**Wire-up**

- `traffic_cypher_in_C/src_c/multi_stream.c`:
  - `stream_slot_t` gains `cancel_requested`, `prep_thread`, `forwarder_thread`, `prep_joined`, `forwarder_joined`. The old single `thread` / `joined` fields are gone.
  - New `prep_main` pthread does the three previously-synchronous phases (resolve, capture-start, forwarder-spawn). Between each phase it checks `cancel_requested` so a remove issued during yt-dlp's runtime bails out before the next external call. Failure / cancel marks `STREAM_FAILED`; success transitions ownership of the resolved URL + capture handle into the forwarder thread.
  - `msm_add_stream` is now non-blocking: reserves a slot, snapshots url + label into a heap-owned `prep_arg_t`, `pthread_create`s the prep thread (joinable), and returns the slot index. Microsecond latency.
  - `msm_remove_stream` joins prep first (it may still be inside yt-dlp), then reads `forwarder_thread` from the now-quiesced slot, then joins the forwarder if any. The two joins are sequenced because prep is the writer of `forwarder_thread`.
  - `msm_free` does the same two-pass join over all active slots.
  - `forwarder_main` no longer publishes `capture_pid` — prep does, atomically with `forwarder_thread`, so a remove that fires right when the forwarder starts sees a coherent (pid, tid) pair.
  - Test seam (`msm_test_register_slot`) sets both `prep_joined` and `forwarder_joined` to 1 (no real threads in test mode).
- `traffic_cypher_in_C/src_c/web_server.c` — `handle_add_stream` response under the flag is now `202 Accepted` with body `{"status":"connecting","index":N}`. The previous `500` on resolve/capture failure goes away (failure is observed asynchronously via GET `/api/streams`); the only synchronous failure is `503 Service Unavailable` when the manager is NULL or all 16 slots are taken.
- `tests/33_traffic_entropy_build.sh` — tolerates 202 status, asserts the POST returns in <2 s (the async refactor's whole observable), polls `/api/streams` up to 15 s for the bogus slot to transition to `Failed`, falls back to accepting `Connecting` if yt-dlp resolve is slow.

**Verification**

- `make -C traffic_cypher_in_C clean && make` — clean. Default build untouched.
- `make -C traffic_cypher_in_C clean && make ENABLE_TRAFFIC_ENTROPY=1` — clean.
- `make -C traffic_cypher_in_C msm_test && ./traffic_cypher_in_C/msm_test` — 28/28 PASS (test seam updated for dual joined flags).
- `bash tests/33_traffic_entropy_build.sh` — POST elapsed reported as `0.02s` (was multi-second pre-refactor); slot reaches `Failed` within ~1 s of the bogus URL POST.
- `bash tests/run.sh` — **35 PASS + 1 SKIP** in 76 s on Apple Silicon (matches stage 4 baseline).
- `cargo clippy --all-targets --locked -- -D warnings` — clean.

**Risks**

- `msm_remove_stream` can still take up to a yt-dlp-resolve worth of seconds in the worst case: prep is inside `resolve_stream_url` and we have no way to interrupt the external child without killing the yt-dlp PID (which `stream_ingestion.c` doesn't expose). Bounded by yt-dlp's `--socket-timeout`; in practice <10 s. Operator-facing remove is rare, so accepted.
- Two heap allocations per add now: `prep_arg_t` (~1 KiB) is alive only during the prep thread's lifetime; `forwarder_arg_t` is alive for the forwarder's lifetime. Both freed on their thread's exit paths.
- The `cancel_requested` check between phases is racy with the prep thread already having started the next external call — but `frame_capture_start` is fork+exec which completes in <1 s, so the worst-case wait is short. Cleaner cancellation would require teaching `frame_capture_start` to consult a cancel flag.

---

### 2026-05-13 — Week 4+ #1a stage 4: five-agent fan-out (CI / docs / replay / frontend / parity)

Stage 4 of #1a was scoped as five independent slices and dispatched to five worktree-isolated agents running in parallel. Each landed as its own commit on `main` after a local merge + regression-suite verification.

| Slice | Commit | What |
|---|---|---|
| 4b (CI matrix) | `4507973` | New `c-traffic-entropy` job (matrix: ubuntu + macOS) builds with `ENABLE_TRAFFIC_ENTROPY=1`, asserts the binary string flip, runs `tests/33`. Reuses the `c` job's OpenSSL 3.3 cache; runs in parallel with `c`/`rust`. `tests/33` pins the CI job name. |
| 4e (docs) | `abe0d0e` | README "Scope of the C implementation" split per build variant; new "Build variants" subsection. `tests/36_readme_traffic_entropy_pinning.sh` pins the documented qualifier. |
| 4a (replay) | `a1cf483` | `handle_unlock` snapshots `state->stream_config` under the lock, hands the heap-owned copy to a detached pthread that calls `msm_add_stream` per entry. All inside `#ifdef ENABLE_TRAFFIC_ENTROPY`; default build untouched. `tests/34_c_auto_replay.sh` static-checks the gate + call-site ordering, then rebuilds with the flag; integration SKIPs without yt-dlp. |
| 4d (frontend) | `f8c2696` | `frontend/app.js` whitelist for the five recognised statuses (Connecting/Active/Failed/Stopped/Disabled) replaces the previous `${s.status.toLowerCase()}` class injection; `frames_captured` shown next to each entry with type-guarded rendering. `tests/35_frontend_stream_states.sh` pins the renderer. |
| 4c (parity variant) | `aa33297` | `parity/parity_test.py` accepts `BUILD_VARIANT=default|traffic_entropy` via env var + `--variant` CLI flag; `parity/cases.json`'s `expected_diff` becomes `{variant: bool}` (scalar still supported for back-compat). `build_info.normalize_drop` widened to include `"build"` so the per-impl tag drops out of compare. Under the variant `streams_status` + `build_info` cases now both PASS (no longer KNOWN-DIVERGENT). |

**Test count progression** (default `bash tests/run.sh`): 33 → 34 (E added `tests/36`) → 34 (A added `tests/34`, replaced the slot before D's rename to `tests/35`) → 35 (D's `tests/35` after rename) → 35 (C did not add a test script). Final state: **35 PASS + 1 SKIP** locally (the SKIP is `tests/34_c_auto_replay.sh`'s integration step, which requires yt-dlp; static + flagged-build checks all pass).

**Collisions handled at merge**

- Two agents (A, D) independently claimed `tests/34_*.sh` despite the brief explicitly steering D to `tests/35` on conflict. D's file was renamed in-place during merge; the script's own `# 34 — …` header line was bumped to `# 35 — …` for consistency.
- Agent C's diff against the freshly-committed B/E/A/D state appeared as a large negative delta on those files (it was branched from the pre-stage-4 main). Resolved by checking out only C's actual additions (`parity/*`, `tests/60_parity_smoke.sh`) rather than the full branch diff.
- This summary entry is being written *after* all five commits to avoid serialising the agents on a shared file (`REMEDIATION_PROGRESS.md`); each agent's per-slice notes can be reconstructed from the commit message.

**What's still pending** (post-stage-4)

- Default-flip: promoting `ENABLE_TRAFFIC_ENTROPY` from opt-in to default. Blocked on real-world soak of the flag-on build (no local yt-dlp install available); CI matrix in 4b will surface compile-time regressions in the meantime.
- Async `msm_add_stream`: today's path blocks a worker thread for ~2–5 s per stream while yt-dlp resolves. A future enhancement would split into "reserve slot synchronously + spawn pthread for resolve + start" so POST responds immediately with `CONNECTING`. Documented in the stage 3 entry; not pulled into stage 4 to keep scope bounded.
- Parity-variant CI: the new BUILD_VARIANT axis works locally but isn't wired into a CI job. Adding it requires deciding whether to extend the existing `c-traffic-entropy` job with a parity step, or split into a separate `parity-traffic-entropy` job.

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

### 2026-05-13 — Week 4+ #1a stage 3: `web_server` handlers + `/api/build/info` flip behind `ENABLE_TRAFFIC_ENTROPY`

Third slice of the C `MultiStreamManager` port. Wires the producer side of the pipeline (stream HTTP handlers) into the manager and flips the build descriptor — gated behind the build-time flag the plan calls for at `REMEDIATION_PLAN.md:349`. Default `make` build is untouched: tests/run.sh stays at 32 → **33** PASS with no regression in any existing test.

**Files**
- `traffic_cypher_in_C/Makefile` — `ENABLE_TRAFFIC_ENTROPY=1` toggle adds `-DENABLE_TRAFFIC_ENTROPY` to `CFLAGS`. Default off.
- `traffic_cypher_in_C/src_c/web_server.c`:
  - `handle_add_stream` — under the flag, routes the request through `msm_add_stream` (which resolves URL via yt-dlp + spawns ffmpeg + the per-stream forwarder pthread). On success responds `200 {"status":"added","index":N}`. On any failure (resolve / capture / OOM) responds `500` with a diagnostic message. The configuration is still persisted alongside the MSM registration so a restart with the flag set still remembers the operator's stream list. Without the flag the body is the original 501 reply verbatim.
  - `handle_list_streams` — under the flag, reads live `msm_get_statuses()` and serialises `{url,label,status,frames_captured}` for each active slot. New helper `stream_state_str()` (also gated) maps the enum to the four Rust-parity strings (`"Connecting"`, `"Active"`, `"Failed"`, `"Stopped"`). Without the flag the body is the original "Disabled / OS entropy only in C build" list verbatim.
  - `handle_remove_stream` — under the flag, calls `msm_remove_stream` *before* the existing config-shift logic (so the forwarder pthread + ffmpeg child are torn down before the operator loses sight of which index they removed).
  - `handle_build_info` — under the flag returns `{"build":"c","traffic_entropy":true}` (no banner note); without the flag stays at the existing `{"build":"c","traffic_entropy":false,"note":"OS entropy only; see README"}`.
- `tests/33_traffic_entropy_build.sh` (new) — regression for the toggle. Static checks (Makefile + web_server.c have the gate; key_rotation.c does NOT — stage 2 daemon works in both modes), default-binary literal check, then an out-of-tree rebuild with the flag set, followed by an integration check against the rebuilt binary: `/api/build/info` returns `traffic_entropy:true`, `/api/streams` returns `[]` on a fresh manager, and POST `/api/streams` with a bogus URL returns 500 (resolve failed) instead of the old 501 ("Not Implemented"). Out-of-tree build lives under a `mktemp` workdir + `$WORK/frontend` symlink so the original `$C` build artifacts are untouched.

**Build behaviour matrix**

| Endpoint | Default build | `ENABLE_TRAFFIC_ENTROPY=1` build |
|---|---|---|
| `GET /api/build/info` | `{"build":"c","traffic_entropy":false,"note":"OS entropy only; see README"}` | `{"build":"c","traffic_entropy":true}` |
| `GET /api/streams` (no streams added) | `[]` | `[]` |
| `POST /api/streams` | `501 Not Implemented` (config persisted) | `200 {"status":"added","index":N}` on success, `500` on resolve/capture failure |
| `DELETE /api/streams/{i}` | clears config only | calls `msm_remove_stream` then clears config |

**Verification**
- `make -C traffic_cypher_in_C clean && make` — clean. Default binary unchanged.
- `make -C traffic_cypher_in_C clean && make ENABLE_TRAFFIC_ENTROPY=1` — clean. `strings traffic-cypher-pm | grep traffic_entropy` shows only the `true` literal (and no `false`).
- `bash tests/run.sh` — **33/33 PASS** in 74s on Apple Silicon (was 32; +1 new opt-in build test).
  - `tests/31_c_no_entropy_lie.sh` (3-second daemon soak on the default binary) — still passes; the default build path is unchanged.
  - `tests/33_traffic_entropy_build.sh` (out-of-tree rebuild + integration) — passes 7/7 assertions including `traffic_entropy:true` flip, `[]` initial list, and the no-longer-501 POST.
  - `tests/60_parity_smoke.sh` — `expected_diff` flags on `streams_status` + `build_info` still report `true` (correct: this commit doesn't yet land the parity flip; that's stage 4).
- `cargo clippy --all-targets --locked -- -D warnings` — clean (no Rust files touched).

**Caveat: `msm_add_stream` is synchronous and can block a worker for seconds**

`resolve_stream_url` (yt-dlp) typically takes ~2-5 s on a real YouTube livestream; `frame_capture_start` adds another second for ffmpeg's first frame. With the 4-thread worker pool (`#7b`) added in `3183b27`, this means a single add-stream request can saturate ~25% of capacity until it completes. Acceptable for a single-user admin endpoint, but a future enhancement could split add_stream into a synchronous "reserve slot" + asynchronous "resolve + start" pthread so the HTTP response returns immediately with a `CONNECTING` status the operator can poll. Not done here to keep the diff focused.

**What stage 4 still owes**
- Flip `parity/anchor_cases.json` `expected_diff:false` for `streams_status` and `build_info` *only* when the parity harness exercises the `ENABLE_TRAFFIC_ENTROPY=1` C build. The current harness runs the default-build binary, so flipping unconditionally would break it — needs a `BUILD_VARIANT` axis in the parity runner.
- Rewrite `tests/31_c_no_entropy_lie.sh` once the flag flips from "opt-in" to "default" — the test's "the C build lies about entropy" invariant becomes "the C build accurately reports `has_traffic_entropy` based on whether frames actually flowed".
- Auto-replay persisted stream config on unlock so the user's saved streams come back on PM restart. Currently each PM start needs the user to re-POST every stream.
- CI wiring: a separate job that runs `make ENABLE_TRAFFIC_ENTROPY=1 && bash tests/run.sh` (or just `tests/33_…`) to keep the flag-on build green. Held back because the existing C job already builds OpenSSL 3.3 from source on Ubuntu (~2 min) and the duplicated build would push tests well past the 10-min cap we just set.

---

### 2026-05-13 — Week 4+ #1a stage 2: `rotation_daemon` rewrite (consumer side)

Second slice of the C `MultiStreamManager` port. Rewires `rotation_daemon` in `traffic_cypher_in_C/src_c/key_rotation.c` so that, once a second, it first attempts `msm_pick_random_frame(state->msm, ...)`. On hit it runs the full Rust-parity pipeline — `extract_entropy` (full-frame SHA-256 + delta-from-previous + 8×8 block hashes) → `entropy_pool_push` → `entropy_pool_digest` → `mix_entropy` → `derive_key` — and sets `state->has_traffic_entropy = 1` (monotonic, matching `key_rotation.rs:138`). On miss it falls back to the pre-#1a `RAND_bytes`-only path verbatim.

**Why no build flag is needed.** Stage 1 shipped the MSM symbols but no producer side (`web_server.c::handle_add_stream` still returns 501). Until stage 3 lands the producer wiring, `msm_pick_random_frame` always returns -1 → the daemon takes the OS-only path every tick → behaviour is observationally identical to before. The new code path is reachable but inert; no `ENABLE_TRAFFIC_ENTROPY` macro is required.

**Files**
- `traffic_cypher_in_C/include/web_server.h` — added `#include "multi_stream.h"` and `multi_stream_manager_t *msm;` field on `app_state_t` with a docstring describing the staged wire-up.
- `traffic_cypher_in_C/src_c/web_server.c`:
  - `app_state_init()` — calls `msm_new(256)` (matches Rust's `tokio::mpsc::channel(256)` at `multi_stream.rs:51`); NULL tolerated with a stderr warning.
  - `web_server_start()` end-of-function cleanup — `msm_free(state->msm)` after the rotation daemon has joined.
- `traffic_cypher_in_C/src_c/key_rotation.c` — full rewrite of `rotation_daemon`. Adds `<entropy_extractor.h>`, `<multi_stream.h>`, `<frame_sampler.h>`, `<stdlib.h>`. Caches `msm` at daemon start under the lock and treats NULL as "no streams". Manages `previous_frame_data` ownership across iterations.

**Behaviour matrix**

| State | Stage 1 | Stage 2 (this commit) |
|---|---|---|
| C PM with no streams added (current real-world state) | OS-only path; `has_traffic_entropy=0` | OS-only path; `has_traffic_entropy=0` |
| C PM with streams added (future stage 3) | n/a — `handle_add_stream` returns 501 | Frame path; `has_traffic_entropy=1` once a frame flows |
| C PM `rotation_running` snapshot | ✓ | ✓ |
| C PM `key_epoch` ticks every second | ✓ | ✓ |
| C PM `pool_depth` grows | ✓ (capped at pool capacity 8) | ✓ (same) |
| C PM `frames_processed` | unchanged from pre-#1a (stays 0) | increments on each frame hit (currently 0 because none flow) |

**Verification**
- `make -C traffic_cypher_in_C clean && make` — clean.
- `make -C traffic_cypher_in_C msm_test && ./traffic_cypher_in_C/msm_test` — 28/28 PASS (unchanged from stage 1; daemon doesn't drive the test).
- `bash tests/run.sh` — **32/32 PASS** in 73s on Apple Silicon. The critical regressions here:
  - `tests/31_c_no_entropy_lie.sh` (3-second daemon soak): C PM still reports `has_traffic_entropy:false`. Confirms the daemon takes the OS-only path when no streams are added.
  - `tests/50_c_pm_stress.sh`: 20-entry × 10-history-each stress under the new daemon — passes within budget.
  - `tests/60_parity_smoke.sh`: `expected_diff` flags on `streams_status` and `build_info` are still `true` (correct — stage 3 will flip them).
- `cargo build --release` / `cargo clippy --all-targets -- -D warnings` / `cargo test` — clean (no Rust files touched).

**Risks**
- `pool_chain` allocation can fail under memory pressure; silently dropped (chain still works because `new_key` lives in `previous_key`). Previously the same allocation existed without a NULL guard — the new code adds one because the daemon now uses more memory per tick when frames flow.
- A frame's pixel buffer may be up to `1280×720×3 ≈ 2.6 MiB` (ffmpeg `scale=320:240` in `frame_sampler.c:51` caps it at 230 KiB in practice). The daemon keeps one `previous_frame_data` plus the just-picked frame across iterations — 2 × 230 KiB peak. Acceptable.
- `state->msm` reads in the daemon are racy with `app_state_init` only if the daemon could start before init — it can't (daemon is started by `handle_unlock` after init completes), so the snapshot read at daemon start is safe without a lock.

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
