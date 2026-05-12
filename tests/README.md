# Test suite

A pragmatic regression harness for Traffic Cypher. Each test is an executable
shell script (or invoked by one) that exits `0` on pass, non-zero on fail, and
`77` to skip. Tests are discovered by `run.sh` in numeric order.

```
tests/
├── run.sh                       # entrypoint — runs every NN_*.sh in order
├── lib/
│   ├── common.sh                # pass/fail/skip helpers, color
│   └── esc_unit_test.js         # Node spec test for the esc() helper
├── 00_build_rust.sh             # cargo build --release --bins
├── 01_build_c.sh                # make in traffic_cypher_in_C
├── 10_rust_unit_tests.sh        # cargo test --release -- --test-threads=1
├── 11_static_checks_rust.sh     # grep guards for #6 / #9 invariants
├── 12_static_checks_c.sh        # grep guards for #2 / #7a invariants
├── 20_esc_function.sh           # #5a XSS regression
├── 21_command_injection.sh      # #2 cmd-injection regression
├── 22_socket_timeout.sh         # #7a slow-client DoS regression (slow, ~16s)
└── 99_servers_boot.sh           # both PM servers boot and serve /api/auth/status
```

Run everything:

```
./tests/run.sh
```

Run a single case:

```
bash tests/22_socket_timeout.sh
```

## Adding tests

Drop a new `NN_short_name.sh` script in `tests/`. Pick a prefix bucket:

| Prefix | Bucket                                                    |
|--------|-----------------------------------------------------------|
| `00–09`| Build steps. Must succeed before anything else runs.      |
| `10–19`| Language-native unit tests (`cargo test`, future C unit). |
| `11–19`| Static grep guards for invariants worth pinning.          |
| `20–29`| Targeted regression tests for individual fixes.           |
| `30–89`| Future buckets (integration, parity, fuzz smoke, …).      |
| `99_*` | End-to-end smoke that needs both binaries built.          |

A test should:
- `source "$(dirname "$0")/lib/common.sh"`.
- Use `pass`, `fail`, `skip`, `require_cmd` helpers.
- Clean up its own temp files / processes via `trap`.
- Be idempotent — running it twice in a row should still pass.

## Conventions

- Tests assume macOS or Linux. Anything that depends on a platform-specific
  flag should `require_cmd` or `uname`-guard.
- Tests must not write outside `/tmp` or the repo. Vault paths use
  `TRAFFIC_CYPHER_VAULT_PATH=/tmp/tc_test_*_$$.json` and clean up on exit.
- Tests must not require network. If a feature genuinely needs the internet
  (e.g. live YouTube resolve), gate it behind `TRAFFIC_CYPHER_TEST_ONLINE=1`
  and `skip` otherwise.
- Slow tests (>5 s) note this in their header comment.

## CI

The Week 1 `.github/workflows/ci.yml` will call `tests/run.sh` after the
language-specific jobs. Until then, run locally before merging.
