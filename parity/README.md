# Cross-implementation parity harness

Boots each Traffic Cypher PM in turn (C and Rust) against an isolated
vault file, replays the same HTTP request sequence, normalises the
responses, and asserts the two implementations agree.

This is item **#10c** of `REMEDIATION_PLAN.md`. It catches both bugs
that have been fixed (#8 C-side `tags` drop) and unknown future drift
between the two implementations — see "Why it exists" below.

## Quickstart

```bash
# Build both PMs (smoke wrapper does this in CI):
tests/00_build_rust.sh
tests/01_build_c.sh

# Run every case:
python3 parity/parity_test.py

# Run only the 4 anchor cases (used by tests/60_parity_smoke.sh):
python3 parity/parity_test.py --max-cases 4

# Run a single case by name, with per-request logging:
python3 parity/parity_test.py --case create_with_tags --verbose

# Run against the ENABLE_TRAFFIC_ENTROPY=1 C build (rebuilds C into a
# tmpdir; does not touch the canonical traffic_cypher_in_C/traffic-cypher-pm):
BUILD_VARIANT=traffic_entropy python3 parity/parity_test.py --max-cases 4
```

The harness exits **0** when every case either matched exactly or was
flagged `expected_diff: true`. It exits **1** on any unflagged
divergence or infrastructure failure (binary missing, port stuck, boot
timeout).

## Why it exists

Two implementations of the same JSON HTTP API can diverge silently in
hundreds of small ways — field naming, list ordering, status codes for
edge cases, presence-or-absence of optional fields. The two bugs that
inspired this harness:

- **#8** — the C build was dropping the `tags` array on
  `POST /api/credentials`. The Rust build kept it. A user who switched
  builds lost their tag metadata.
- **#1 / streams** — `GET /api/streams` returned hardcoded
  `"status":"Active"` in C and the actual stream state in Rust.

Both bugs would have been caught instantly by replaying the same
sequence against both binaries and diffing the responses. Running this
harness on every push makes the parity surface a tested contract rather
than an unverified hope.

## Design

Pure-stdlib Python (`subprocess`, `urllib.request`, `json`, `tempfile`,
`pathlib`, `time`, `socket`). No `pytest`, no `requests` — the
harness should run on a minimal CI image without an extra `pip install`
step.

Per-case flow (one case = one full vault lifecycle):

1. Boot the **C** PM with `TRAFFIC_CYPHER_VAULT_PATH=<tmp>` and
   `HOME=<tmp>`. Wait up to 5 s for the listener to bind.
2. Walk the request list. After each request, fail the case if the
   status is non-2xx and no `expect_status` override was set.
3. `terminate()` the PM, `unlink` the vault, sleep 1 s for the port to
   drain.
4. Repeat steps 1-3 with the **Rust** PM, using a fresh tmp vault.
5. Normalise both response lists: drop volatile keys
   (`normalize_drop`), sort `tags` arrays.
6. Compare element-by-element. On mismatch, print a unified diff.

Each impl uses its own tmp vault, so cross-impl encryption mismatches
do not propagate between runs.

## `cases.json` schema

**This schema is the contract for future PRs to extend.** Do not change
existing keys without bumping the version.

```jsonc
{
  "cases": [
    {
      "name": "create_with_tags",          // human label
      "requests": [
        {
          "method": "POST",                 // GET | POST | PUT | DELETE
          "path":   "/api/auth/unlock",     // may contain ${var}
          "body":   {"master_password": "testpass"},
          "save_token_from": "token"        // store response.token as ${token},
                                            // also auto-sends Authorization: Bearer
        },
        {
          "method": "POST",
          "path":   "/api/credentials",
          "body":   {"label": "t", "password": "p", "tags": ["a","b"]},
          "save_id_from":    "id"           // store response.id as ${id}
        },
        {
          "method": "GET",
          "path":   "/api/credentials/${id}",
          "expect_status": 200              // override the 2xx-or-fail rule
        },
        { "method": "GET", "path": "/api/credentials" }
      ],
      "normalize_drop": [
        "id", "created_at", "updated_at", "token", "session_token"
      ],
      "expected_diff": false,               // optional; default false
      "reason":        ""                   // optional; required if expected_diff
    }
  ]
}
```

### Field reference

| Field             | Type           | Purpose                                                                |
|-------------------|----------------|------------------------------------------------------------------------|
| `name`            | string         | Shown in the run output. Must be unique within `cases`.                |
| `requests`        | array<request> | Replayed in order. See below for the request shape.                    |
| `normalize_drop`  | array<string>  | JSON keys whose values are stripped before comparison (recursive).     |
| `expected_diff`   | bool or object | If true, divergence is reported as `KNOWN-DIVERGENT` instead of fail. May also be an object keyed by `BUILD_VARIANT` (e.g. `{"default": true, "traffic_entropy": false}`); the runner resolves it to a scalar using the active variant, falling back to the `"default"` key and then to `false`. |
| `reason`          | string         | Why `expected_diff` is set. Link the tracking issue.                   |

| Request field      | Type   | Purpose                                                                |
|--------------------|--------|------------------------------------------------------------------------|
| `method`           | string | `GET` `POST` `PUT` `DELETE`. (`OPTIONS` works too if you need it.)     |
| `path`             | string | URL path including `?query` if any. `${var}` references are expanded.  |
| `body`             | any    | JSON-serialisable request body. Omit for GET/DELETE.                   |
| `expect_status`    | int    | Override the default "any 2xx" rule (use for testing 4xx/5xx paths).   |
| `save_token_from`  | string | Key on the JSON response to save as `${token}`. Also sets the auth header. |
| `save_id_from`     | string | Key on the JSON response to save as `${id}`.                           |

### Normalisation rules

- **Drop**: any key whose name appears in `normalize_drop` is removed
  before comparison. Apply at any depth. Use for `id`, `created_at`,
  `updated_at`, `token`, `session_token`, `entry_count` (per-impl-tmp
  vaults always start empty, so the count *should* match — but listing
  this makes test cases robust against future seeded fixtures).
- **Sort `tags`**: arrays under the key `tags` are sorted before
  compare. The two impls do not guarantee insertion order on this set
  field.

## `BUILD_VARIANT` axis

The harness can run against either C build flavour:

| Variant            | C binary                                                                                                  | When to use                                                                                  |
|--------------------|-----------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| `default` (unset)  | `traffic_cypher_in_C/traffic-cypher-pm` (the canonical default build)                                     | Every push. This is what `tests/60_parity_smoke.sh` runs from `tests/run.sh`.                |
| `traffic_entropy`  | Built fresh into `mktemp -d` via `make ENABLE_TRAFFIC_ENTROPY=1`. Canonical default binary is untouched.  | A separate CI job; exercises `/api/build/info` + `/api/streams` parity under the flag.       |

Selecting:

- env var: `BUILD_VARIANT=traffic_entropy python3 parity/parity_test.py`
- CLI flag: `python3 parity/parity_test.py --variant traffic_entropy`

How it flows through:

1. `BUILD_VARIANT` is read from the environment in `parity_test.py`
   (default `"default"`). The `--variant` CLI flag overrides it.
2. If `variant == "traffic_entropy"`, the harness rsyncs the C tree
   into a tmpdir, symlinks `<repo>/frontend` next to it (so the
   Makefile's `frontend` phony resolves the same way it does at the
   repo root), runs `make ENABLE_TRAFFIC_ENTROPY=1`, and points the
   replay loop at the tmp binary. The canonical
   `traffic_cypher_in_C/traffic-cypher-pm` is never touched.
3. For each case, `expected_diff` is resolved via
   `resolve_expected_diff(case, variant)`: a scalar bool wins as-is;
   an object is looked up by `variant`, then by `"default"`, then
   falls back to `False`. This keeps old scalar-style flags
   backwards-compatible.

The `tests/60_parity_smoke.sh` wrapper passes `BUILD_VARIANT` through
unchanged, so an unset env runs exactly the same code path as before.
Doubling the smoke up with both variants would double parity wall time
on every CI run, so we don't — the second variant is for a separate
CI job.

## Anchor cases (initial four)

| Name                | Purpose                                                                                                            | `default` outcome    | `traffic_entropy` outcome |
|---------------------|--------------------------------------------------------------------------------------------------------------------|----------------------|---------------------------|
| `unlock_and_status` | Unlock → status → lock → status. Locks in the auth state-machine.                                                  | PASS                 | PASS                      |
| `create_with_tags`  | Unlock, create with `tags`, GET, list. Catches future regressions of #8 (C `tags` drop).                           | PASS                 | PASS                      |
| `streams_status`    | Unlock, GET `/api/streams`. Default C build returns the static "Disabled" stub; ENABLE_TRAFFIC_ENTROPY=1 reads from `multi_stream_manager_t`. | KNOWN-DIVERGENT      | PASS                      |
| `build_info`        | GET `/api/build/info`. Default C returns `traffic_entropy:false`; ENABLE_TRAFFIC_ENTROPY=1 flips to `traffic_entropy:true`. The `build` field (`c` vs `rust`) is normalised out. | KNOWN-DIVERGENT      | PASS                      |

## Adding a new case

1. Append to `cases.json` `cases[]`. Don't reuse `name`s.
2. List every volatile field (ids, timestamps, tokens, anything random)
   in `normalize_drop`.
3. Run `python3 parity/parity_test.py --case <name> --verbose` until
   it passes against both impls.
4. If divergence is intentional, set `expected_diff: true` and write a
   one-line `reason` linking the tracking item — never delete the case.
   The point is to make divergence *visible*, not to hide it.

## Performance notes

- Per-impl boot + drain: ~3-4 s on a 2024 laptop.
- Per-case wall time: ~7-8 s (two boots).
- Four-case smoke run: ~30 s. Full run scales linearly with case count.
- The 1 s port drain after each impl is deliberate — without it,
  rapid-fire reuse of TCP port 9876 occasionally races on macOS.

## Layout

```
parity/
├── README.md          ← this file
├── cases.json         ← declarative cases (schema is frozen)
└── parity_test.py     ← driver (stdlib only)
```

The repo-root `tests/60_parity_smoke.sh` is a thin wrapper that runs
`parity_test.py --max-cases 4` and integrates with `tests/run.sh`.
