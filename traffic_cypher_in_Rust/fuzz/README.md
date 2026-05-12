# Fuzz harness

Cargo-fuzz scaffolding for the Rust crate. Closes the Rust half of
[REMEDIATION_PLAN.md](../../REMEDIATION_PLAN.md) Week 4+ #10d.

## Prerequisites

Install `cargo-fuzz` and a nightly toolchain (libFuzzer hooks aren't on
stable yet):

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

| Target | Sink | What it shakes loose |
|--------|------|----------------------|
| `vault_version_probe` | `vault::fuzz_parse_vault_version` | Panics in the `{"version":N}` peek path used by `load_vault` before it commits to V2/V3. |
| `vault_v3_envelope`   | `vault::fuzz_parse_vault_v3_envelope` | V3 struct deserialization + hex decoding of the four envelope fields. Stops short of Argon2id derivation so fuzz cycles stay fast. |

Both targets exercise public-but-`#[doc(hidden)]` helpers in `vault.rs`;
the harness never touches the filesystem so each iteration is sub-millisecond.

## Running

```sh
cd traffic_cypher_in_Rust/fuzz
cargo +nightly fuzz run vault_version_probe -- -max_total_time=60
cargo +nightly fuzz run vault_v3_envelope  -- -max_total_time=60
```

Initial seed corpora live in `corpus/<target>/`. New findings (crashes,
slow inputs) accumulate under `corpus/<target>/` and `artifacts/<target>/`;
both directories are gitignored except for the seeds.

## Why this is outside the parent workspace

The parent crate (`traffic_cypher_in_Rust`) doesn't declare `[workspace]`,
so `cargo build` / `cargo test` / `cargo clippy` invoked from the parent
ignore this directory. That keeps stable CI green while still allowing
local nightly fuzzing.

## Not run in CI (yet)

REMEDIATION_PLAN.md schedules a 60-second smoke run per target on `main`
plus a 5-minute nightly. Wiring that into `.github/workflows/ci.yml`
requires a nightly toolchain on the runner and a corpus-cache strategy
(committed seed + actions/cache for accumulated findings) — out of scope
for the scaffolding commit. Add the nightly job in a follow-up.
