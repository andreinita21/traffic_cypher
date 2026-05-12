#!/bin/bash
# Run every tests/NN_*.sh in numeric order. Exits non-zero if any fail.
set -u

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$TEST_DIR/lib/common.sh"

PASS=0; FAIL=0; SKIP=0
FAILED=()

START_TS=$(date +%s)

for test in $(find "$TEST_DIR" -maxdepth 1 -name '[0-9]*.sh' | sort); do
    name="$(basename "$test")"
    printf '\n%b==> %s%b\n' "$BOLD$CYAN" "$name" "$NC"
    if bash "$test"; then
        PASS=$((PASS + 1))
    else
        rc=$?
        if [ $rc -eq 77 ]; then
            SKIP=$((SKIP + 1))
        else
            FAIL=$((FAIL + 1))
            FAILED+=("$name")
        fi
    fi
done

ELAPSED=$(( $(date +%s) - START_TS ))

printf '\n%b%s%b\n' "$BOLD" "========================================" "$NC"
printf '  %bPASSED%b: %d   %bFAILED%b: %d   %bSKIPPED%b: %d   (%ds)\n' \
    "$GREEN" "$NC" "$PASS" \
    "$RED" "$NC" "$FAIL" \
    "$YELLOW" "$NC" "$SKIP" \
    "$ELAPSED"

if [ "$FAIL" -gt 0 ]; then
    printf '  %bFailed:%b\n' "$RED" "$NC"
    for f in "${FAILED[@]}"; do
        printf '    - %s\n' "$f"
    done
    exit 1
fi
