#!/usr/bin/env bash
# 36 — README pinning for the ENABLE_TRAFFIC_ENTROPY build flag.
#
# After #1a stages 1-3 (2026-05-13), the C build is no longer monolithically
# "OS entropy only" — it has two build variants, with the default off until
# the parity harness exercises the flag-on build. The README must describe
# both variants accurately. This regression test prevents anyone from
# silently reverting to an unqualified claim that the C build has no stream
# ingestion or unconditionally returns traffic_entropy:false.
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

README="$REPO_ROOT/README.md"
[ -f "$README" ] || fail "README.md not found at $README"

# 1. The flag name must be documented.
grep -q 'ENABLE_TRAFFIC_ENTROPY' "$README" \
    || fail "README.md does not mention ENABLE_TRAFFIC_ENTROPY — the C build-time toggle is undocumented"
pass "README.md documents the ENABLE_TRAFFIC_ENTROPY flag"

# 2. The parity-table cell (or an equivalent qualifier) must be present so a
#    reader can tell "default build: No" from "flag-on build: Yes" without
#    reading the source.
grep -q 'default build: No' "$README" \
    || fail "README.md missing 'default build: No' parity qualifier for traffic entropy"
pass "README.md preserves the 'default build: No' parity qualifier"

# 3. Refuse any new *unqualified* claim that the C build lacks stream
#    ingestion. Specifically: if the phrase "no stream ingestion" appears,
#    "default build" must appear within ~5 lines so the claim is conditional.
if grep -n -i 'no stream ingestion\|OS-entropy-only\|OS entropy only' "$README" >/dev/null 2>&1; then
    # For every line containing one of those phrases, check that "default build"
    # or "ENABLE_TRAFFIC_ENTROPY" appears within +/- 5 lines as a qualifier.
    while IFS=: read -r lineno _; do
        start=$((lineno > 5 ? lineno - 5 : 1))
        end=$((lineno + 5))
        if ! sed -n "${start},${end}p" "$README" \
                | grep -q -E 'default build|ENABLE_TRAFFIC_ENTROPY|two build variants|Build variants|build variants'; then
            sed -n "${start},${end}p" "$README" >&2
            fail "README.md line $lineno asserts no-stream-ingestion / OS-only without a default-build qualifier nearby"
        fi
    done < <(grep -n -i 'no stream ingestion\|OS-entropy-only\|OS entropy only' "$README")
fi
pass "no unqualified 'C build has no stream ingestion' claim in README.md"

# 4. The Build variants table / subsection must reference the progress doc
#    so a future reader can trace the staged remediation.
grep -q 'REMEDIATION_PROGRESS.md' "$README" \
    || fail "README.md should link to REMEDIATION_PROGRESS.md from the build-variants discussion"
pass "README.md links to REMEDIATION_PROGRESS.md for the staged remediation entries"
