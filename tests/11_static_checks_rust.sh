#!/bin/bash
# 11 — Static grep guards that pin the structural invariants from
# #6 (ffmpeg orphans) and #9 (unused deps). These run in <1 s and
# catch regressions like "someone deleted kill_on_drop again".
set -e
source "$(dirname "$0")/lib/common.sh"

RUST="$REPO_ROOT/traffic_cypher_in_Rust"

# --- #6: ffmpeg orphan fix ---

grep -q "kill_on_drop(true)" "$RUST/src/frame_sampler.rs" \
    || fail "frame_sampler.rs missing .kill_on_drop(true)"
pass "frame_sampler.rs sets kill_on_drop(true)"

grep -Eq "child:\s*Option<\s*tokio::process::Child\s*>" "$RUST/src/multi_stream.rs" \
    || fail "StreamHandle missing child: Option<tokio::process::Child>"
pass "StreamHandle stores Child for explicit lifecycle"

grep -q "pub async fn remove_stream" "$RUST/src/multi_stream.rs" \
    || fail "remove_stream is not async"
pass "remove_stream is async (can kill+wait the Child)"

# Either main.rs ends the CLI with explicit wait(), or it'd leak on panic.
grep -Eq "ffmpeg_child\.wait\(\)\.await" "$RUST/src/main.rs" \
    || fail "main.rs missing explicit ffmpeg_child.wait().await"
pass "CLI does explicit kill+wait for deterministic reap"

# --- #9: unused deps removed ---

CARGO="$RUST/Cargo.toml"
grep -E '^image\s*=' "$CARGO" >/dev/null && fail "image crate still in Cargo.toml"
grep -E '^rpassword\s*=' "$CARGO" >/dev/null && fail "rpassword crate still in Cargo.toml"
grep -E '^hmac\s*=' "$CARGO" >/dev/null && fail "hmac crate still as a direct dep"
pass "Cargo.toml has no image/rpassword/hmac direct deps"

grep -q 'features = \["full"\]' "$CARGO" \
    && fail "tokio still uses features=[\"full\"]"
pass "tokio features narrowed (no longer 'full')"
