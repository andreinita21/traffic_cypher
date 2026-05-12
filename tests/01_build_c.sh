#!/bin/bash
# 01 — C build must succeed. Required by later tests.
set -e
source "$(dirname "$0")/lib/common.sh"

require_cmd make

cd "$REPO_ROOT/traffic_cypher_in_C"
info "make clean && make"
make clean >/dev/null 2>&1 || true
make 2>&1 | tail -5
[ -x ./traffic-cypher ] || fail "C CLI binary (traffic-cypher) not produced"
[ -x ./traffic-cypher-pm ] || fail "C PM binary (traffic-cypher-pm) not produced"
pass "C build clean; CLI + PM binaries present"
