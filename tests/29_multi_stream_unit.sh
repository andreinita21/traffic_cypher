#!/bin/bash
# 29 — Week 4+ #1a stage 1: multi_stream C unit-test regression.
#
# The full C MultiStreamManager port lands in stages. Stage 1 introduced the
# module + bounded MPSC ring + per-stream forwarder + statuses query, with a
# dedicated msm_test binary that exercises the ring/pick/statuses paths
# without spawning ffmpeg or yt-dlp.
#
# This script enforces:
#   1. Scaffolding files exist and are wired into the Makefile.
#   2. The production build never picks up -DENABLE_MSM_TEST_API.
#   3. The msm_test binary builds and every assertion inside it PASSes.
#   4. multi_stream.c is in the regular SOURCES so the production binary
#      contains the symbols (a future commit wires web_server.c without
#      Makefile churn).
set -e
source "$(dirname "$0")/lib/common.sh"

C="$REPO_ROOT/traffic_cypher_in_C"

# 1. Scaffolding files present.
[ -f "$C/include/multi_stream.h" ] || fail "include/multi_stream.h missing"
[ -f "$C/src_c/multi_stream.c" ]   || fail "src_c/multi_stream.c missing"
[ -f "$C/tests_c/msm_test.c" ]     || fail "tests_c/msm_test.c missing"
pass "multi_stream module + unit-test binary source present"

# 2. Public API is exported via the header.
for sym in msm_new msm_free msm_add_stream msm_remove_stream \
           msm_pick_random_frame msm_get_statuses msm_stream_count; do
    grep -q "$sym" "$C/include/multi_stream.h" \
        || fail "header missing public symbol $sym"
done
pass "multi_stream.h exports the documented public API"

# 3. Test-only seams are #ifdef-gated and never compiled into production.
grep -q 'ENABLE_MSM_TEST_API' "$C/include/multi_stream.h" \
    || fail "header missing ENABLE_MSM_TEST_API gate"
grep -q 'ENABLE_MSM_TEST_API' "$C/src_c/multi_stream.c" \
    || fail "multi_stream.c missing ENABLE_MSM_TEST_API gate"
grep -E '^CFLAGS\s*=' "$C/Makefile" | grep -q 'ENABLE_MSM_TEST_API' \
    && fail "production CFLAGS leaks ENABLE_MSM_TEST_API"
pass "production build never defines ENABLE_MSM_TEST_API"

# 4. multi_stream.c is in regular SOURCES (so symbols ship in the binary).
grep -q 'multi_stream.c' "$C/Makefile" \
    || fail "Makefile SOURCES does not include multi_stream.c"
pass "multi_stream.c is part of the production build"

# 5. Makefile has the msm_test target with ENABLE_MSM_TEST_API.
grep -q '^msm_test:' "$C/Makefile" || fail "Makefile missing msm_test target"
grep -q 'DENABLE_MSM_TEST_API' "$C/Makefile" \
    || fail "msm_test target does not define ENABLE_MSM_TEST_API"
pass "msm_test Makefile target present and correctly gated"

# 6. Build the production binary fresh (catches link issues from the new
#    multi_stream.o), then build and run msm_test.
( cd "$C" && make clean && make ) >/dev/null 2>&1 \
    || fail "production build failed after adding multi_stream module"
pass "production build is clean with multi_stream.c in SOURCES"

( cd "$C" && make msm_test-clean && make msm_test ) >/dev/null 2>&1 \
    || fail "msm_test build failed"

if ! ( cd "$C" && ./msm_test ) >/dev/null 2>&1; then
    # Re-run to surface output on failure.
    ( cd "$C" && ./msm_test ) || true
    fail "msm_test assertions did not all pass"
fi
pass "msm_test: all unit assertions pass"

# 7. Production binaries do NOT export msm_test_* symbols (paranoid check).
if command -v nm >/dev/null 2>&1; then
    for bin in "$C/traffic-cypher" "$C/traffic-cypher-pm"; do
        [ -f "$bin" ] || continue
        if nm -j "$bin" 2>/dev/null | grep -q msm_test_; then
            fail "$bin leaks msm_test_* symbols"
        fi
    done
    pass "production binaries do not leak msm_test_* symbols"
fi
