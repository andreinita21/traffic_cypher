#!/usr/bin/env bash
# 40_str_buf.sh — compile and run the str_buf unit tests.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

BIN="/tmp/test_str_buf_$$"
trap 'rm -f "$BIN"' EXIT

cc -Wall -Wextra -O2 -std=c11 -I traffic_cypher_in_C/include \
   tests/_c_helpers/test_str_buf.c traffic_cypher_in_C/src_c/str_buf.c \
   -o "$BIN"

"$BIN"
echo "40_str_buf: OK"
