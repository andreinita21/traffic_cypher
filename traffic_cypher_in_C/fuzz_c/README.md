# C fuzz harness

libFuzzer scaffolding for the C build. Closes the C half of
[REMEDIATION_PLAN.md](../../REMEDIATION_PLAN.md) Week 4+ #10d. The Rust
half lives at [`traffic_cypher_in_Rust/fuzz/`](../../traffic_cypher_in_Rust/fuzz/).

## Targets

| Target | Sink | Notes |
|--------|------|-------|
| `fuzz_hex_decode` | `hex_utils.c::hex_decode` | Public API, fuzzed directly. |
| `fuzz_json_get_string` | `vault.c::json_get_string` (static) | Reached via `fuzz_json_get_string` wrapper compiled in only with `-DENABLE_FUZZ_API`. |
| `fuzz_parse_vault_entries` | `vault.c::parse_vault_entries` (static) | Same wrapper pattern. Highest payoff — walks the entire user-controlled vault JSON. |

The wrappers live at the bottom of `src_c/vault.c`, gated by
`#ifdef ENABLE_FUZZ_API` so the production binary is unchanged.

## Building

Requires a `clang` that ships libFuzzer's runtime
(`libclang_rt.fuzzer_*.a`). On macOS, install via Homebrew and point the
Makefile at it:

```sh
brew install llvm@20
FUZZ_CC=/opt/homebrew/opt/llvm@20/bin/clang make -C traffic_cypher_in_C fuzz
```

On Linux, the distro clang typically works:

```sh
make -C traffic_cypher_in_C fuzz                   # fuzzer only (default)
make -C traffic_cypher_in_C fuzz FUZZ_SANITIZER=fuzzer,address  # opt-in ASan
```

ASan + libFuzzer is the default-off because the combo hangs libFuzzer's
`main` on macOS arm64 with Homebrew LLVM 20 (ASan dyld stall). The
fuzzer-only build still gets coverage-guided exploration and crash
detection; ASan can be enabled on Linux CI where the bug isn't present.

## Running

Each binary takes any libFuzzer flag plus an optional corpus directory:

```sh
./fuzz_c/fuzz_hex_decode             fuzz_c/corpus/hex_decode             -max_total_time=60
./fuzz_c/fuzz_json_get_string        fuzz_c/corpus/json_get_string        -max_total_time=60
./fuzz_c/fuzz_parse_vault_entries    fuzz_c/corpus/parse_vault_entries    -max_total_time=60
```

500-iteration smoke runs of each target finish in <1 s on a 2024 M-series
mac with peak RSS of 27–35 MiB.

## CI not wired

REMEDIATION_PLAN.md schedules 60-second per-target smoke runs on every
push and a 5-minute nightly. Wiring that requires clang on the runner,
corpus caching, and a triage path for new finds — out of scope for the
scaffolding commit. Add a follow-up CI job once the targets are stable.
