# Traffic Cypher

Derive rotating cryptographic keys and high-entropy passwords from live city traffic — by sampling the visual entropy of public YouTube livestreams.

This repository contains **two functionally equivalent implementations** (C and Rust) of the same system, plus a **side-by-side benchmark suite** that compares their performance, code metrics, and security properties.

```
TrafficCypher/
├── traffic_cypher_in_C/      # C implementation (CLI + web password manager)
├── traffic_cypher_in_Rust/   # Rust implementation (CLI + web password manager)
├── benchmark/                # Cross-implementation benchmark suite
├── traffic_cypher_benchmark_report.pdf
└── traffic_cypher_benchmark_report.docx
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

> **Scope of the C implementation (current build).** The C **CLI binary** (`traffic-cypher`, `src_c/main.c`) wires traffic-frame entropy correctly. The C **password manager daemon** (`traffic-cypher-pm`) does *not* — it currently runs an OS-entropy-only rotation loop and does not open or read any stream. Streams added through its UI are persisted to config (so the Rust build on the same machine still benefits) but are reported as `Disabled` and `frames_captured: 0`, and `POST /api/streams` responds `501 Not Implemented`. Every build exposes a no-auth `GET /api/build/info` endpoint that reports `{"build":"c","traffic_entropy":false}` (C) or `{"build":"rust","traffic_entropy":true}` (Rust), and the shared frontend shows a top-of-screen banner whenever `traffic_entropy` is false. The full C `MultiStreamManager` port is tracked as remediation item #1a (Week 4+).

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
