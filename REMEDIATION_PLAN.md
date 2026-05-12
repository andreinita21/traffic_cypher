# Remediation Plan

Consolidated output of a 10-agent analysis pass against the top findings in `PROJECT_REVIEW.md`. Each finding has a chosen fix, identified prerequisites, and an effort band. The end of the document maps everything onto a 4-week sequencing.

---

## Dependency map

```
            ┌──────────────────────────────────────────────────────┐
   Week 0   │ #9 Cargo deps    #6 kill_on_drop    #2 fork+execvp  │  (trivial,
            │ #7a sock_timeouts          #5 esc() hotfix          │   1 LOC–1 file each)
            └──────────┬───────────────────────────┬───────────────┘
                       │                           │
   Week 1   ┌──────────▼───────────┐   ┌───────────▼──────────────┐
            │ #10a CI scaffold     │   │ #1b "honest relabel"     │
            │ #8 C tags drop       │   │ #3-pre str_buf API       │
            └──────────┬───────────┘   └───────────┬──────────────┘
                       │                           │
   Week 2   ┌──────────▼───────────────────────────▼──────────────┐
            │ #3 str_buf migration    #7b worker pool             │
            │ #5b frontend de-dup                                  │
            └──────────┬───────────────────────────────────────────┘
                       │
   Week 3   ┌──────────▼───────────┐   ┌───────────────────────────┐
            │ #10b Rust HTTP tests │   │ #4 Argon2id v3 vault      │
            │ #10c Parity harness  │◀──┤   (KAT fixture feeds      │
            └──────────────────────┘   │    parity harness)        │
                                       └───────────────────────────┘

   Week 4+  ┌──────────────────────┐   ┌───────────────────────────┐
            │ #1a C multi_stream   │   │ #10d Fuzzing, #5c DOM     │
            │      port            │   │      construction pass     │
            └──────────────────────┘   └───────────────────────────┘
```

Sequencing rationale: small isolated PRs first (de-risk the queue), then C `str_buf` (unblocks both buffer-overflow and worker-pool work), then the test scaffolding that future PRs ride on, then the heavier crypto + porting work last.

---

## Week 0 — single-file fixes

These are independent, reviewable in <30 minutes each, and remove the highest-CVSS bugs.

### #9 Drop unused Cargo dependencies
**Root cause.** `traffic_cypher_in_Rust/Cargo.toml` lists `image`, `rpassword`, `hmac` — none are imported in `src/`. `hmac` is still in the resolution graph transitively via `hkdf 0.12 → hmac 0.12.1` (`Cargo.lock:480`).

**Fix.** Remove the three lines; narrow `tokio` features from `"full"` to `["macros", "rt-multi-thread", "sync", "time", "io-util", "fs", "process", "signal", "net"]` (the set actually `use`-ed in `src/`). Run `cargo build --release --bins`, `cargo test`, `cargo clippy --all-targets -- -D warnings`, commit the regenerated `Cargo.lock` in the same PR. Add `--locked` to CI cargo invocations going forward.

**While here.** `Cargo.toml` is missing `license`, `repository`, `readme`, `rust-version`. Either add them or set `publish = false` to make intent explicit.

**Files.** `Cargo.toml`, `Cargo.lock`. **Effort.** ~30 minutes.

---

### #6 Orphaned ffmpeg processes (Rust)
**Root cause.** `traffic_cypher_in_Rust/src/multi_stream.rs:89` binds the `tokio::process::Child` to `_child` which drops at end of scope. `tokio::process::Child` does **not** kill the process on drop unless the `Command` had `.kill_on_drop(true)`.

**Fix.** Two-step:
1. Add `.kill_on_drop(true)` to `Command` in `frame_sampler.rs:25` — single line, fixes both the PM path and a panic-path leak in `main.rs:46-144` where the explicit `kill().await` at line 144 only runs on the happy `break` branch.
2. Promote the `Child` into `StreamHandle` (`multi_stream.rs:32-38`) alongside `cancel_tx`. Make `remove_stream` `async` and do `child.kill().await; child.wait().await` for deterministic SIGCHLD reaping. In the `lock` handler (`routes.rs:301`) iterate `mgr.remove_stream(0).await` so vault-lock also stops all streams.

**Tests.** Hidden `--smoke-add-remove-stream` flag on `pm` that adds/removes against a local `python3 -m http.server` fake HLS; CI script asserts `pgrep ffmpeg` count returns to baseline within 2 s. Add a panic-path `#[tokio::test]` that `std::panic::catch_unwind`s an `add_stream`+panic and asserts the PID disappears.

**Files.** `frame_sampler.rs`, `multi_stream.rs`, `main.rs`, `web/routes.rs`. **Effort.** ~3 h.

---

### #2 Command injection in C stream resolver
**Root cause.** `traffic_cypher_in_C/src_c/stream_ingestion.c:23` builds a shell command with the URL inside single quotes and runs it through `popen`. Reached from CLI `--url` (`main.c:122`) and PM `add_stream` (`web_server.c:722`).

**Fix.** Replace `popen` with `pipe`+`fork`+`execvp(yt_dlp, argv)` — argv is `{yt_dlp, "-g", "-f", "best", "--no-warnings", "--", youtube_url, NULL}`. The `"--"` neutralises argument confusion if a URL begins with `-`. Capture stderr into a separate pipe (8 KiB cap) so the `[ERROR]` log surfaces yt-dlp's diagnostic. Use `waitpid` with `EINTR` retry; check `WIFEXITED`/`WEXITSTATUS`. Pre-validate: reject URLs containing control bytes (`< 0x20`) or NULs; require `http://`/`https://` prefix. Note this is defense-in-depth — with execvp+argv, shell injection is structurally impossible.

**Refactor opportunity.** `frame_sampler.c:33-61` uses the same fork+exec pattern. Extract a shared `spawn_capture_child(argv, out_fd, err_fd, pid)` helper used by both files. Not required for the security fix; useful follow-up.

**Files.** `stream_ingestion.c`. **Effort.** ~2 h.

---

### #7a Socket timeouts on C HTTP accept
**Root cause.** `traffic_cypher_in_C/src_c/web_server.c::web_server_start` `accept`s a connection and immediately calls `parse_request`'s blocking `read()` with no timeout. Any local process that opens a TCP connection without writing freezes the server indefinitely — `rotation_daemon` keeps running but auto-lock checks (which only fire on incoming HTTP requests) stop.

**Fix (this PR).** After `accept` returns `client_fd`, `setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, {15,0})` and `SO_SNDTIMEO`. `parse_request` already treats `n <= 0` as terminal, so it drops out gracefully.

**Defer to #7b.** The full worker-pool design needs `validate_session` to take `state->lock` first (currently it doesn't — safe only by single-threadedness accident). Ship the timeout patch alone; the pool comes Week 2 paired with the locking fix.

**Files.** `web_server.c` (one block after line 1004). **Effort.** ~30 minutes.

---

### #5a XSS hot-fix in `esc()`
**Root cause.** `app.js:1337-1342` `esc()` does `div.textContent = str; return div.innerHTML;` — encodes `<`/`>`/`&` but not `"` or `'`. Output is interpolated into HTML attributes at nine sites (lines 358, 475, 479, 483, 487, 512, 516, 1084, 1088).

**Fix (this PR).**
```js
function esc(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
```
`&` first to avoid double-encoding. Guard becomes `== null` so `"0"` survives. Confirmed no `<script>` or `javascript:` sinks in `app.js` (`grep`'d), so attribute encoding is sufficient for current sinks.

**Apply twice** until #5b lands: `traffic_cypher_in_Rust/src/frontend/app.js` and `traffic_cypher_in_C/frontend/app.js` (currently byte-identical copies).

**Realism note.** The attacker needs to plant a malicious credential. Two realistic paths: (1) any future vault-import feature, (2) `password_history` is a stored-string corpus — once an attacker briefly controls the UI they can poison history entries that re-trigger on view.

**Files.** Both `app.js` copies. **Effort.** ~15 minutes.

---

## Week 1 — scaffolding and small functional fixes

### #10a CI scaffold
**Fix.** `.github/workflows/ci.yml` matrix `[ubuntu-latest, macos-latest]`. Three jobs initially:
- `rust`: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --release --locked`. Use `Swatinem/rust-cache@v2`.
- `c`: install openssl (`brew install openssl@3` / `apt-get install libssl-dev`), `make`, `make test` (empty target stubbed for now).
- Cache key for C build: `${{ runner.os }}-c-${{ hashFiles('traffic_cypher_in_C/Makefile', 'traffic_cypher_in_C/src_c/**', 'traffic_cypher_in_C/include/**') }}`.

Adds `parity` and `fuzz-smoke` jobs in Week 3. Expected ~4.5 m per push on Ubuntu, ~7.5 m on macOS (warm caches).

**Files.** `.github/workflows/ci.yml` (new). **Effort.** ~2 h.

---

### #8 C `tags` drop fix
**Root cause.** `web_server.c::handle_create_credential` (`:447-487`) and `handle_update_credential` (`:489-540`) never parse the `tags` array from the request body. Stored entry has `tag_count = 0`.

**Fix.**
1. Add `static int json_body_get_string_array(const char *body, const char *key, char out[][VAULT_LABEL_MAX], int max_entries)` near `json_body_get_string` (`web_server.c:221`). Models the on-disk tag loop (`vault.c:334-354`). Returns `-1` on cap-exceeded so the handler can respond `400`.
2. In `handle_create_credential`, set `entry.tags`/`entry.tag_count` *after* `vault_entry_new` at line 474, *before* `vault_add_or_update` at line 477 (which copies by value). Don't grow `vault_entry_new`'s signature — keeps the CLI path stable.
3. In `handle_update_credential`, gate replacement on `strstr(req->body, "\"tags\":")` to distinguish "absent → keep existing" from "explicit empty → clear" — matches Rust's `Option<Vec<String>>` semantic at `routes.rs:441`.

**Bound behaviour.** 100 tags → `400 Bad Request` (rejecting > truncating; users editing tags should not silently lose data). Single 10 KB tag → truncate to 255 chars inline (consistent with `strncpy` style on every other field).

**Smoke test.** `benchmark/test_tags.sh` curls a fresh PM, creates a credential with two tags, asserts `GET /api/credentials/{id}` returns `tags.length == 2`, then PUTs a 100-tag body and asserts `400`. Invoke from a `test-tags` Make target.

**Sequencing note.** Land this *without* waiting on cJSON migration. The new helper reuses the same hand-rolled idiom already used by `parse_vault_entries`, so we're not increasing the fragility class. When cJSON lands, this helper collapses to 5 lines.

**Files.** `web_server.c`, `Makefile`, new `benchmark/test_tags.sh`. **Effort.** ~3 h.

---

### #1b C "honest relabel" (interim)
**Root cause.** `traffic_cypher_in_C/src_c/key_rotation.c:11-66` mixes only OS entropy but sets `state->has_traffic_entropy = 1`. The C PM has no `MultiStreamManager`-equivalent. `handle_list_streams` returns hardcoded `"status":"Active","frames_captured":0`.

**Fix (now).** Stop the lie before the port lands:
- Remove `state->has_traffic_entropy = 1` from `key_rotation.c:64`; rename the field to `has_entropy` and the daemon to `os_entropy_daemon` to remove the false claim from the type system.
- `handle_list_streams` returns real config but with `"status":"Disabled","note":"OS entropy only in C build"`.
- `handle_add_stream`/`handle_remove_stream` return `HTTP 501 {"error":"stream ingestion not implemented in C build"}` — UI accepts the list for parity with Rust's schema but the streams are inert.
- New `/api/build/info` returns `{"build":"c","traffic_entropy":false}`. Frontend reads it and surfaces a banner "C build derives DEKs from OS CSPRNG only" plus hides the Add-Stream panel.
- README: add "Scope of the C implementation" section. Top-level README comparison table: "Traffic entropy in PM mode" → C: No, Rust: Yes.

**Note.** `main.c` (CLI) *does* wire frame entropy correctly — leave it untouched.

**Files.** `key_rotation.c`, `web_server.c`, `web_server.h`, `README.md`, `traffic_cypher_in_C/README.md` (or section in repo README), both `app.js` copies.
**Effort.** ~4 h.

---

### #3-pre `str_buf` API (no behaviour change)
**Why first.** Buffer-overflow fix (#3 full), tags-JSON escape (#8 follow-up), worker-pool 503 response (#7b), and any future cJSON migration all want the same growing-string builder. Land the API alone first — zero behaviour change, easy to review, unblocks everything else.

**Sketch.** New `include/str_buf.h` + `src_c/str_buf.c`:
```c
typedef struct { char *data; size_t len, cap; int err; } str_buf;
void  sb_init(str_buf *, size_t initial_cap);
int   sb_append(str_buf *, const char *);
int   sb_append_n(str_buf *, const char *, size_t);
int   sb_appendf(str_buf *, const char *fmt, ...) __attribute__((format(printf,2,3)));
int   sb_append_json_escaped(str_buf *, const char *raw);  // subsumes json_escape_str
char *sb_release(str_buf *, size_t *out_len);              // caller frees
void  sb_free(str_buf *);
```
Doubling growth (`cap = max(cap*2, len + need + 1)`, min 64). Sticky `err` flag lets callers chain appends and check once at end — avoids threading return codes through every site. `sb_appendf` uses a 256-byte stack scratch for `vsnprintf`; falls through to direct write on overflow. ~80 LOC.

**Files.** New `include/str_buf.h`, new `src_c/str_buf.c`, `Makefile` (add to `SOURCES`). No callers yet. **Effort.** ~2 h.

---

## Week 2 — buffer hardening and concurrency

### #3 C HTTP/vault `str_buf` migration
**Sites to migrate (exhaustive).**

Must change (overflow / truncation hazards):
- `web_server.c:377-430` `handle_list_credentials` — heap buffer + `strcat`.
- `web_server.c:684-706` `handle_get_settings` — stack `buf[4096]`.
- `web_server.c:765-780` `handle_list_streams` — stack `buf[8192]`, 16×2 KB easily overflows.
- `vault.c:147-202` `vault_entry_to_json` — fixed 16384 + child buffers (`tags_buf[4096]`, `hist_buf[8192]`) both overflowable.
- `vault.c:205-219` `vault_to_json` — fixed estimate × `entry_count`; truncated children cascade.
- `vault.c:808-841` `save_stream_config` — malloc + `strcat` chain.

Leave alone (provably bounded): `send_error` (line 209), short status responses with literal formats, response headers. Verify `entropy_hex` length before keeping `web_server.c:638-639` and `:667-668`.

**API decision.** Refactor `vault_entry_to_json` into internal `vault_entry_append_json(const vault_entry_t *e, str_buf *sb)` plus a thin wrapper for callers that genuinely want a heap string (`handle_get_credential` at `:432-445`). This drops N+1 large allocations in `handle_list_credentials` and `vault_to_json` to a single growing buffer.

**Body parser.** `parse_request` (`web_server.c:108-178`) currently caps at 64 KiB and silently truncates. Add: parse `Content-Length` with `strtoll`, reject negative/missing, cap at 8 MiB, respond `413 Payload Too Large` on overflow. Stream body directly into a `str_buf` using a new `sb_reserve`+`sb_advance` pair.

**Compile hardening.** Turn on in `Makefile:5`:
```
CFLAGS += -D_FORTIFY_SOURCE=2 -Wformat-security -Wstringop-overflow=4 \
          -Wstringop-truncation
```
`_FORTIFY_SOURCE` aborts on `strcat` overflow at runtime under glibc — useful belt-and-braces while migrating. `-Wstringop-overflow` will surface remaining `strcat`-into-`buf[N]` sites under Linux CI.

**Files.** `web_server.c`, `vault.c`, `Makefile`. **Effort.** ~2 days.

---

### #7b C HTTP worker pool
**Design.** Fixed pool of 4 workers + bounded fd queue (cap 32, matches existing `listen` backlog at `web_server.c:993`). Mutex + two condvars (`qnot_empty`/`qnot_full`). `accept` loop pushes `client_fd`; workers pop, set `SO_RCVTIMEO`/`SO_SNDTIMEO`, call `parse_request`+`handle_request`+`close`. ~80 LOC.

**Backpressure.** When queue is full, do **not** block accept — write a canned `503 Service Unavailable\r\nConnection: close\r\n\r\n` and `close(fd)`. Blocking accept would reproduce the original DoS through a different door.

**Locking fix (required).** `validate_session` (`web_server.c:67-86`) reads/writes `state->has_session`, `session_token`, `last_activity` *without* holding `state->lock`. Safe today only by single-threadedness. Wrap the function body in `pthread_mutex_lock/unlock(&state->lock)`. Same for `app_state_touch` at `:57-59`. This is the only structural correctness change required in handler code — every other handler already takes `state->lock` (verified by spot-check of all handlers).

**Graceful shutdown.** Install SIGINT/SIGTERM handler that sets `server_running = 0` and `shutdown(server_fd, SHUT_RDWR)` to wake `accept`. Then `pthread_cond_broadcast(&qnot_empty)` to wake idle workers, `pthread_join` all workers, then `state->rotation_stop = 1` and join `rotation_thread` last (the daemon already polls `rotation_stop` at `key_rotation.c:31`).

**Files.** `web_server.c`. **Effort.** ~1 day.

---

### #5b Frontend de-duplication
**Goal.** Eliminate the byte-identical copies in `traffic_cypher_Rust/src/frontend/` and `traffic_cypher_in_C/frontend/`. A future bug fix to the XSS escaping or any UI feature must currently be applied twice — drift is inevitable.

**Plan.**
- Move canonical source to repo root `/Users/andrei/Desktop/traffic_cypher/frontend/`.
- Rust: change `include_str!("../frontend/...")` in `src/web/routes.rs:21-23` to `include_str!("../../../frontend/...")`. Drop `src/frontend/` entirely.
- C: add a phony `frontend` Make target that runs `cp -R ../frontend/ ./frontend/`; make `all` depend on it. Frontend stays at `traffic_cypher_in_C/frontend/` at runtime so `web_server.c:962-964` doesn't change.
- CI guard: `diff -r frontend/ traffic_cypher_in_C/frontend/` fails the build on drift.

Symlinks are an alternative but break on Windows checkouts — build-time copy is portable.

**Files.** New `frontend/` at root; both old copies deleted; `Makefile`; `routes.rs`. **Effort.** ~1 h plus CI integration.

---

## Week 3 — tests and crypto

### #10b Rust HTTP integration tests
**Location.** `traffic_cypher_in_Rust/tests/http.rs` (Cargo picks up automatically).
**Tooling.** `tower = { version = "0.5", features = ["util"] }` and `http-body-util = "0.1"` under `[dev-dependencies]`. Use `tower::ServiceExt::oneshot` against `web::create_router`.

**Test surface.** ~25 tests targeting the 844 lines of `web/routes.rs`. Each test gets a fresh `TempDir` and passes the path via an `AppState::for_test(path)` constructor (avoid `env::set_var` so tests are parallel-safe).

**Must-have flows.**
1. Full credential lifecycle: unlock → create (with tags!) → list → get → delete → list-empty. The tags assertion catches any regression of #8.
2. Locked vault → 401 on every protected route.
3. Malformed JSON → 400.
4. Unknown id → 404; double-delete → 404.
5. Auto-lock: warp `last_activity` backwards, assert next request returns 401.
6. Rate-of-unlock guard (if added per `PROJECT_REVIEW.md §8`): rapid 5 wrong passwords get progressively delayed responses.

**Files.** `tests/http.rs` (new), `web/state.rs` (add `AppState::for_test`). **Effort.** ~2 days.

---

### #10c Cross-implementation parity harness
**Location.** New `/Users/andrei/Desktop/traffic_cypher/parity/` with `parity_test.py` + `cases.yaml`. Pure-stdlib Python (no `requests`, no `pytest-deps` overhead — just `subprocess`, `urllib.request`, `json`, `tempfile`, `pathlib`).

**Flow per case.**
1. Build both binaries (CI reuses build caches from rust/c jobs via `actions/cache@v4`).
2. Use a fresh `TRAFFIC_CYPHER_VAULT_PATH = tmp/vault.json`.
3. For each binary, spawn it as a subprocess (`Popen`), wait for `GET /api/health` (add this trivial endpoint to both), replay the case's HTTP requests, record responses, kill.
4. `normalize(resp)` strips: `id`, `created_at`, `updated_at`, `session_token`, any `*_nonce`, `Server` header.
5. `assert normalize(c_resp) == normalize(rust_resp)`, diff on mismatch.

**Anchor cases.**
- `create_with_tags` — POST credential with `"tags":["a","b"]`, GET list, assert tags present in both. Would have caught #8 immediately.
- `streams_status` — GET `/api/streams` on a fresh vault. Catches the streams-status mismatch from #1.
- `unlock_wrong_password` — both must return identical 401 shape.
- `large_note` — POST credential with 1 MiB notes field. Stresses #3 + body-cap logic.

**Files.** `parity/` directory (new). **Effort.** ~2 days.

---

### #4 Argon2id vault format v3
**Parameters.** `m_cost = 65536` (64 MiB), `t_cost = 3`, `p_cost = 1`. OWASP 2024 second-tier; ~250–400 ms on a 2024 laptop. The three integers are persisted in the vault file so future parameter bumps don't brick existing vaults.

**Schema diff vs. v2** (`vault.rs:143-160`):
```jsonc
{
  "version": 3,                          // was 2
  "kdf": "argon2id",                     // NEW
  "kdf_m_cost": 65536,                   // NEW
  "kdf_t_cost": 3,                       // NEW
  "kdf_p_cost": 1,                       // NEW
  "kek_salt": "<hex 32 bytes>",          // REUSED (still random 32 B, fed as Argon2 salt)
  "wrapped_dek_nonce": "<hex 12>",       // unchanged
  "wrapped_dek": "<hex>",                // unchanged
  "vault_nonce": "<hex 12>",             // unchanged
  "vault_ciphertext": "<hex>",           // unchanged
  "entropy_source": "os|traffic",        // unchanged
  "updated_at": 1715520000               // unchanged
}
```

**Backward compatibility.** `load_vault` branches on `version`:
- `v2` → existing HKDF derivation, set `needs_upgrade` flag in the unlocked struct. Auto-upgrade is implicit: next `save_vault` writes v3.
- `v3` → read params, call `derive_kek_argon2id`.
- Unknown → hard error.

**Dependencies.**
- **Rust:** `argon2` crate (RustCrypto, same ecosystem as `hkdf`/`sha2`/`aes-gcm`). One line in `Cargo.toml`.
- **C:** OpenSSL 3.2+ `EVP_KDF_fetch("ARGON2ID")` + `OSSL_PARAM_construct_*`. Zero new system deps — `-lcrypto` is already linked. Build-time check `OPENSSL_VERSION_NUMBER >= 0x30200000L`; fall back to libargon2 only behind `#ifdef`. **Reject libsodium** — too heavy for one function.

**Cross-impl KAT.** New `/Users/andrei/Desktop/traffic_cypher/test_fixtures/argon2id_kek_kat.json`:
```json
{
  "password": "x",
  "salt_hex": "00...00",   // 32 zero bytes
  "m_cost": 65536, "t_cost": 3, "p_cost": 1, "out_len": 32,
  "expected_kek_hex": "<pinned once with reference impl>"
}
```
Both `cargo test` (via `include_str!`) and the C test suite (`fopen`+parse) consume the same file. Catches endianness/encoding drift between the two libraries (a known Argon2 risk).

**UX.** Print `"Deriving key..."` after password entry, clear on success. Don't re-derive KEK on every `save_vault` — cache the derived KEK on `UnlockedVault` and re-derive only on lock/unlock. With traffic-entropy rotations that re-save frequently, this is the difference between 300 ms hangs every few seconds and a single 300 ms unlock pause.

**Sequencing.** Lands after #10c parity harness so the v2→v3 migration is regression-tested across both implementations on every push.

**Files.** `vault.rs`, `vault.c`, `Cargo.toml`, `Makefile`, new `test_fixtures/argon2id_kek_kat.json`. **Effort.** ~1 week.

---

## Week 4+ — heavier items

### #1a Full C `MultiStreamManager` port
**Header** `traffic_cypher_in_C/include/multi_stream.h`:
```c
typedef enum { STREAM_CONNECTING, STREAM_ACTIVE, STREAM_FAILED, STREAM_STOPPED } stream_state_t;
typedef struct multi_stream_manager multi_stream_manager_t;
multi_stream_manager_t *msm_new(size_t ring_capacity);
int  msm_add_stream(multi_stream_manager_t *, const char *url, const char *label);
int  msm_remove_stream(multi_stream_manager_t *, int index);
int  msm_pick_random_frame(multi_stream_manager_t *, frame_t *out);
int  msm_get_statuses(multi_stream_manager_t *, stream_status_t *out, int max);
void msm_free(multi_stream_manager_t *);
```

**Internals.** Fixed `stream_slot_t slots[VAULT_MAX_STREAMS]` (matches existing `VAULT_MAX_STREAMS=16`). Shared MPSC ring of `(stream_index, frame_t)` protected by `pthread_mutex_t` + `pthread_cond_t not_empty`, capacity 256 (matches Rust's `tokio::mpsc(256)` at `multi_stream.rs:44`). One forwarder pthread per stream calling the existing blocking `frame_capture_read` (`frame_sampler.c:93`); no separate consumer — `rotation_daemon` becomes the consumer.

**`rotation_daemon` rewrite** (`key_rotation.c:11-66`): genuine frame consumption (which the current code lacks — it pushes `new_key` into the pool instead of frame entropy, a real bug at line 56). Fall back to `RAND_bytes` when no frame available, but **do not** set `has_traffic_entropy = 1` in that branch.

**Behind a feature flag.** Ship behind `--enable-traffic-entropy` (build-time `-DENABLE_TRAFFIC_ENTROPY`). Default off until proven stable. Once on by default, the #1b "honest relabel" reverts.

**Effort.** ~2 weeks of focused C work. The interesting design question for the project's academic story is *how much harder* this is than `tokio::select!` + `Drop` — keep the comparison artefacts.

---

### #10d Fuzzing + #5c DOM construction pass

**Rust fuzz targets** (`cargo fuzz`):
- `vault_deserialize.rs` → `serde_json::from_slice::<VaultFile>(data)`. Corpus: a valid vault from the unit tests. Catches panics on planted/malformed vault files.
- `ppm_header.rs` → `frame_sampler::read_ppm_header` against arbitrary bytes. Corpus: smallest valid 1×1 PPM. Catches integer-overflow/dimensions DoS.

**C fuzz targets** (`clang -fsanitize=fuzzer,address`):
- `fuzz_json_get_string.c` → `vault.c:224`. Seed: `{"k":"v"}`.
- `fuzz_hex_decode.c` → `hex_utils.c`. Seed: `"deadbeef"`.
- `fuzz_parse_vault_entries.c` → `vault.c:283`. Highest payoff: walks the whole user-controlled file.

CI: 60-second smoke run per target on every push to `main`; full nightly run with 5-minute budget per target, corpus committed to `fuzz/corpus/<target>/`.

**#5c DOM construction.** Switch the nine high-risk attribute sites in `app.js` (line 358 et al.) from `innerHTML` template-string assembly to explicit DOM construction: `el.value = ...` for `<input value="...">` and `el.dataset.copy = ...` for `data-*`. The setter writes the attribute verbatim — cannot be escaped out of, even if a future change regresses `esc()`. ~50 LOC change, ~2 h work.

---

## Risk matrix

| Item | CVSS-ish | Reach | Effort | Land |
|------|---------|-------|--------|------|
| #2 Cmd injection | 7.8 H | Local RCE for authenticated PM user | 2 h | Week 0 |
| #3 C HTTP buffer overflow | 7.5 H | Local heap/stack corruption | 2 d | Week 2 |
| #4 Weak KEK | 7.5 H | Offline password brute-force on file theft | 1 w | Week 3 |
| #5 Stored XSS | 6.1 M | Credential exfil via injected handler | 15 min + 2 h | W0+W4 |
| #6 Orphaned ffmpeg | 4.0 L | Resource leak, CPU/network | 3 h | Week 0 |
| #7 C HTTP DoS | 5.3 M | Local DoS, auto-lock stalls | 30 min + 1 d | W0+W2 |
| #8 Tags drop | 4.3 L | User-visible data loss | 3 h | Week 1 |
| #9 Unused deps | — | Bloat, attack surface | 30 min | Week 0 |
| #1 C entropy lie | — | Correctness / honesty | 4 h + 2 w | W1 (b) + W4 (a) |
| #10 No tests/CI | — | Regression blind spot | scaffolding 2 h, full ~1 w | W1 onwards |

---

## Cross-cutting decisions

1. **Hand-rolled C JSON stays for now.** The cJSON migration is a separate, larger PR (see `PROJECT_REVIEW.md §12 step 2`). Don't block the user-visible data fix (#8) on it. The new `tags` helper reuses the existing idiom — no new fragility class.

2. **`str_buf` lands before behaviour changes that need it.** Buffer-overflow remediation (#3), worker-pool 503 responses (#7b), tags JSON escaping (#8 follow-up), and any future cJSON migration all benefit. Ship the API alone first; migrate callers in a separate PR per file.

3. **CI scaffold lands early so every subsequent PR rides it from green.** Otherwise we accumulate untested PRs and CI integration becomes its own retrofit project.

4. **Parity harness is the highest-leverage test.** It catches both bugs covered by other fixes (#1, #8) *and* unknown future drift across the two implementations. Land it in Week 3 as the canonical regression net.

5. **Argon2id needs the parity harness to land first.** A cross-impl crypto migration without parity tests is a recipe for one side producing different ciphertext than the other. KAT fixture is the second safety net.

6. **C `MultiStreamManager` port is academic-value high but security-priority low.** Path (b) "honest relabel" eliminates the existing misrepresentation in 4 h; path (a) full port is a multi-week investment that depends on whether the project's thesis is "concurrent stream ingestion ergonomics" (port it) or "crypto-primitive comparison" (don't — just document the gap).

7. **Frontend de-dup unblocks future UI work.** The XSS hot-fix (#5a) must currently be applied twice; the DOM-construction strengthening pass (#5c) would have to be too. Land the canonical-source layout (#5b) before that work.

---

## What does *not* fit in this plan

These appeared in `PROJECT_REVIEW.md` but were not assigned to an agent and remain open:

- Constant-time session-token comparison (currently `strcmp` / `==`).
- Per-IP / per-session rate limiting on `/api/auth/unlock`.
- `zeroize` for in-memory secrets (DEK, KEK, master password, decrypted vault bytes).
- Atomic vault writes (`write tmp + rename`).
- CORS narrowing from `Any` to `http://127.0.0.1:9876`.
- Move report binaries (`*.docx`, `*.pdf`) out of `main`.
- Pin Rust MSRV via `rust-toolchain.toml`; `[profile.release]` LTO + strip.
- Compile-time hardening flags for the C build (`-fstack-protector-strong`, `-Wconversion`) — partial coverage already proposed under #3.

Treat these as the next batch once the 10 critical items are merged.
