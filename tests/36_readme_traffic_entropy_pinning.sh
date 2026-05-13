#!/usr/bin/env bash
# 36 — README pinning for the ENABLE_TRAFFIC_ENTROPY build flag.
#
# Post-flip (NEXT_STEPS.md Phase C, 2026-05-13): traffic entropy is the
# DEFAULT. `make ENABLE_TRAFFIC_ENTROPY=0` is the opt-out for the legacy
# OS-only path. The README must describe both variants accurately and not
# silently revert to an unqualified claim that the default C build is
# OS-entropy-only.
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

README="$REPO_ROOT/README.md"
[ -f "$README" ] || fail "README.md not found at $README"

# 1. The flag name must be documented.
grep -q 'ENABLE_TRAFFIC_ENTROPY' "$README" \
    || fail "README.md does not mention ENABLE_TRAFFIC_ENTROPY — the C build-time toggle is undocumented"
pass "README.md documents the ENABLE_TRAFFIC_ENTROPY flag"

# 2. The post-flip parity-table cell must say the default is Yes, and the
#    opt-out path must reference ENABLE_TRAFFIC_ENTROPY=0.
grep -q 'Yes (default since' "$README" \
    || grep -q 'default build: Yes' "$README" \
    || fail "README.md missing post-flip 'default build: Yes' / 'Yes (default since …)' parity qualifier"
pass "README.md reflects the post-flip default (traffic entropy on)"

grep -q 'ENABLE_TRAFFIC_ENTROPY=0' "$README" \
    || fail "README.md must document the ENABLE_TRAFFIC_ENTROPY=0 opt-out"
pass "README.md documents the ENABLE_TRAFFIC_ENTROPY=0 opt-out"

# 3. Refuse any new *unqualified* claim that the default C build lacks stream
#    ingestion or is OS-only. The phrases below MUST appear next to an
#    "opt-out" / "ENABLE_TRAFFIC_ENTROPY=0" qualifier within ~5 lines.
if grep -n -i 'no stream ingestion\|OS-entropy-only\|OS entropy only' "$README" >/dev/null 2>&1; then
    while IFS=: read -r lineno _; do
        start=$((lineno > 5 ? lineno - 5 : 1))
        end=$((lineno + 5))
        if ! sed -n "${start},${end}p" "$README" \
                | grep -q -E 'opt-out|ENABLE_TRAFFIC_ENTROPY=0|Opt-out|two build variants|Build variants|build variants'; then
            sed -n "${start},${end}p" "$README" >&2
            fail "README.md line $lineno asserts no-stream-ingestion / OS-only without an opt-out qualifier nearby"
        fi
    done < <(grep -n -i 'no stream ingestion\|OS-entropy-only\|OS entropy only' "$README")
fi
pass "no unqualified 'C build has no stream ingestion' claim in README.md"

# 4. The Build variants table / subsection must reference the progress doc
#    so a future reader can trace the staged remediation.
grep -q 'REMEDIATION_PROGRESS.md' "$README" \
    || fail "README.md should link to REMEDIATION_PROGRESS.md from the build-variants discussion"
pass "README.md links to REMEDIATION_PROGRESS.md for the staged remediation entries"
