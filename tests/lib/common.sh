# Shared test helpers. Source from any tests/NN_*.sh.

# Color only if stdout is a TTY.
if [ -t 1 ]; then
    GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

pass() { printf '  %bPASS%b: %s\n' "$GREEN" "$NC" "$1"; }
fail() { printf '  %bFAIL%b: %s\n' "$RED" "$NC" "$1"; exit 1; }
skip() { printf '  %bSKIP%b: %s\n' "$YELLOW" "$NC" "$1"; exit 77; }
info() { printf '  %s\n' "$1"; }

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        skip "$1 not installed"
    fi
}

# Repo root, regardless of where the test was invoked from.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && cd .. && pwd)"
export REPO_ROOT
