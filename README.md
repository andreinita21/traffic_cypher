# Traffic Cypher

Derive rotating cryptographic keys and high-entropy passwords from live city traffic — by sampling the visual entropy of public YouTube livestreams.

This repository contains **two functionally equivalent implementations** (C and Rust) of the same system, plus a **side-by-side benchmark suite** that compares their performance, code metrics, and security properties.

```
TrafficCypher/
├── traffic_cypher_in_C/      # C implementation (CLI + web password manager)
├── traffic_cypher_in_Rust/   # Rust implementation (CLI + web password manager)
├── benchmark/                # Cross-implementation benchmark suite
├── frontend/                 # Shared web UI (deduped; C build mirrors it)
├── parity/                   # Cross-implementation HTTP parity harness
├── tests/                    # Regression test runner (bash tests/run.sh)
└── reports/                  # Pre-built benchmark reports (.pdf, .docx)
```

---

## What it does

1. Pulls frames from a public YouTube livestream (e.g. a city traffic camera).
2. Extracts entropy from frame deltas — pixel motion that no attacker can predict.
3. Mixes that with OS entropy through HKDF + HMAC-SHA-256.
4. Outputs:
   - **CLI tool** — rotating cryptographic keys (hex or base64).
   - **Password manager** — local web UI on `http://127.0.0.1:9876` with vault, TOTP, and password generation.

Both implementations expose the same HTTP API and produce keys with the same construction, so they are directly comparable.

> **Scope of the C implementation.** The C **CLI binary** (`traffic-cypher`, `src_c/main.c`) wires traffic-frame entropy correctly. The C **password manager daemon** (`traffic-cypher-pm`) has two build variants:
>
> - **Default build (`make`)** — runs an OS-entropy-only rotation loop and does not open or read any stream. Streams added through its UI are persisted to config (so the Rust build on the same machine still benefits) but are reported as `Disabled` and `frames_captured: 0`, and `POST /api/streams` responds `501 Not Implemented`. `GET /api/build/info` reports `{"build":"c","traffic_entropy":false}` and the shared frontend shows a top-of-screen banner.
> - **`make ENABLE_TRAFFIC_ENTROPY=1`** — compiles the full C `MultiStreamManager` port (remediation #1a, stages 1–3 landed 2026-05-13; see `REMEDIATION_PROGRESS.md`). `POST /api/streams` resolves the URL via `yt-dlp`, spawns ffmpeg, and feeds frames into the rotation daemon's entropy pool. `GET /api/build/info` flips to `{"build":"c","traffic_entropy":true}`. The Rust build always reports `{"build":"rust","traffic_entropy":true}`.
>
> The default is **off** until the parity harness exercises the flag-on build (per `REMEDIATION_PLAN.md` #1a). Local regression coverage for the flag-on path lives in `tests/33_traffic_entropy_build.sh`.

---

## Quick start

Each subproject ships with a one-shot launcher.

| Component | Unix / macOS | Windows |
|---|---|---|
| C implementation | `cd traffic_cypher_in_C && ./run.sh` | `cd traffic_cypher_in_C && run.bat` |
| Rust implementation | `cd traffic_cypher_in_Rust && ./run.sh` | `cd traffic_cypher_in_Rust && run.bat` |
| Benchmark suite | `cd benchmark && ./run.sh` | `cd benchmark && run.bat` |

The Unix scripts auto-install missing dependencies (Homebrew on macOS, apt/dnf/pacman on Linux). The Windows scripts check for required tools and tell you what to install if anything is missing.

---

## Requirements

### Common (both implementations)
- `ffmpeg` — frame decoding
- `yt-dlp` — pulls the live HLS manifest from YouTube
- A working network connection to YouTube

### C implementation
- C11 compiler (`cc`, `gcc`, or `clang`)
- `make`
- `OpenSSL` (1.1+ or 3.x)
- POSIX threads — Linux, macOS, or WSL on Windows

### Rust implementation
- Rust 1.75+ (`rustup` recommended — installs via `https://rustup.rs`)
- Cargo (bundled with Rust)
- Builds natively on Linux, macOS, and Windows

### Benchmark suite
- Both implementations buildable
- Python 3.8+ (used for timing math and JSON parsing)
- `curl` (for the HTTP latency tests)

---

## Running on Windows

The Rust version runs natively on Windows. The C version is POSIX-centric (uses `pthread`, raw sockets, and the macOS `Security.framework`) and is best run under **WSL 2**.

The provided `run.bat` files detect WSL automatically and forward to the matching Unix script when needed. If you don't have WSL, install it once with:

```powershell
wsl --install
```

Then re-run the `.bat` file.

---

## What's in each part

### `traffic_cypher_in_C/`

A from-scratch C implementation. Two binaries:
- `traffic-cypher` — CLI key generator. Streams a YouTube livestream, derives a rotating 256-bit key.
- `traffic-cypher-pm` — local password manager with web UI, JSON vault, TOTP, and password strength scoring.

Builds via `make`. No package manager — dependencies (`OpenSSL`, `pthread`, `libm`) are linked at the system level.

#### Build variants

The C tree exposes a build-time toggle for the password-manager traffic-entropy pipeline:

| Variant | Command | Traffic entropy in PM mode | `traffic-cypher-pm` behaviour |
|---|---|---|---|
| Default | `make` | default build: No | OS-entropy-only rotation; `POST /api/streams` returns `501`; `/api/build/info` reports `traffic_entropy:false`. |
| Opt-in | `make ENABLE_TRAFFIC_ENTROPY=1` | `ENABLE_TRAFFIC_ENTROPY=1`: Yes | Full C `MultiStreamManager` port; `POST /api/streams` resolves and ingests; `/api/build/info` reports `traffic_entropy:true`. |

The default is **off** until the parity harness exercises the flag-on build (per `REMEDIATION_PLAN.md` #1a). The flag-on path is exercised locally by `tests/33_traffic_entropy_build.sh`. Stages 1–3 of #1a landed 2026-05-13; the path-(a) full port is now reachable via the build flag. See `REMEDIATION_PROGRESS.md` for the 2026-05-13 stage entries.

### `traffic_cypher_in_Rust/`

The same system rebuilt in Rust. Three binaries:
- `traffic_cypher` — CLI (analogous to the C `traffic-cypher`)
- `pm` — password manager web UI (analogous to `traffic-cypher-pm`)
- `bench` — Rust benchmark harness used by the cross-implementation suite

Built via Cargo (`cargo build --release`). Uses `axum`, `tokio`, `serde`, `aes-gcm`, and the RustCrypto stack.

### `benchmark/`

Runs both implementations head-to-head and produces JSON results plus a comparison table. Measures:

1. Build time (clean rebuild)
2. Binary size
3. Source LOC and dependency count
4. Startup latency (20-run mean)
5. 17 micro-benchmarks per implementation (HKDF, entropy pipeline, vault ops, crypto, password generation, TOTP)
6. HTTP API latency for 6 endpoints (50 requests each)
7. Resident-set memory under load

Results land in `benchmark/results/` as `c_results.json` and `rust_results.json`. The pre-rendered PDF / DOCX reports at the top of this repo are the output of an earlier run.

---

## Notes on entropy

The system treats a YouTube livestream as a wide-bandwidth source of **uncontrollable physical motion** (pedestrians, cars, weather). Entropy is conditioned through:

1. Frame difference extraction (rejects static pixels)
2. Pool-based mixing via SHA-256
3. Combination with OS entropy (`getrandom` / `/dev/urandom`) via HKDF

OS entropy is always mixed in, so even a degraded or replayed stream cannot reduce key strength below the OS baseline. The traffic stream is an additive entropy source, not the only one.

---

## License

This repository is part of an academic comparison study. See the benchmark report for methodology. No production-grade hardening claim is made by either implementation; in particular, neither one zeroes secret memory on drop. Use at your own risk.
