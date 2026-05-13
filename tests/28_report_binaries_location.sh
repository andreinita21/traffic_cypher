#!/bin/bash
# 28 — Backlog: report binaries (*.docx, *.pdf) moved out of the repo root.
# REMEDIATION_PLAN.md "What does not fit in this plan" called for moving the
# benchmark report binaries off main. We chose an in-tree reorg into
# reports/ (safe, fully reversible, no LFS migration required); enforce
# here that nobody re-adds new .pdf/.docx blobs at the root.
set -e
source "$(dirname "$0")/lib/common.sh"

# 1. Reports directory exists with the canonical files.
[ -d "$REPO_ROOT/reports" ] \
    || fail "reports/ directory missing — benchmark reports should live there"
[ -f "$REPO_ROOT/reports/traffic_cypher_benchmark_report.pdf" ] \
    || fail "reports/traffic_cypher_benchmark_report.pdf missing"
[ -f "$REPO_ROOT/reports/traffic_cypher_benchmark_report.docx" ] \
    || fail "reports/traffic_cypher_benchmark_report.docx missing"
pass "reports/ contains both benchmark report binaries"

# 2. No .pdf or .docx at the repo root (they belong in reports/).
strays=$(find "$REPO_ROOT" -maxdepth 1 -type f \( -name '*.pdf' -o -name '*.docx' \))
if [ -n "$strays" ]; then
    printf '%s\n' "$strays"
    fail "binary report files at repo root — move into reports/"
fi
pass "no .pdf/.docx at repo root"

# 3. README points at the new path (the file-tree comment block).
grep -q 'reports/' "$REPO_ROOT/README.md" \
    || fail "README.md does not mention the reports/ directory"
pass "README.md references reports/"
