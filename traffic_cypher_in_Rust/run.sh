#!/bin/bash
set -e

# ============================================================================
#  Traffic Cypher (Rust) — Auto Runner
#  Installs Rust + system deps, builds release binaries, then launches.
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[-]${NC} $1"; exit 1; }

cd "$(dirname "$0")"

echo ""
echo "+==========================================================+"
echo "|                                                          |"
echo "|     T R A F F I C   C Y P H E R   (Rust)                |"
echo "|   Auto Runner — Install, Build & Launch                  |"
echo "|                                                          |"
echo "+==========================================================+"
echo ""

# -----------------------------------------------------------
# 1. macOS: ensure Homebrew exists
# -----------------------------------------------------------
if [[ "$(uname)" == "Darwin" ]]; then
    if ! command -v brew &>/dev/null; then
        warn "Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        ok "Homebrew installed"
    else
        ok "Homebrew found"
    fi
fi

# -----------------------------------------------------------
# 2. Install system dependencies (ffmpeg, yt-dlp)
# -----------------------------------------------------------
install_if_missing() {
    local cmd="$1"
    local pkg="${2:-$1}"
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd found ($(command -v "$cmd"))"
    else
        info "Installing $pkg..."
        if [[ "$(uname)" == "Darwin" ]]; then
            brew install "$pkg"
        elif command -v apt-get &>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y "$pkg"
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y "$pkg"
        elif command -v pacman &>/dev/null; then
            sudo pacman -S --noconfirm "$pkg"
        else
            fail "Cannot install $pkg — unknown package manager"
        fi
        ok "$pkg installed"
    fi
}

install_if_missing "ffmpeg" "ffmpeg"
install_if_missing "yt-dlp" "yt-dlp"
install_if_missing "curl"   "curl"

# -----------------------------------------------------------
# 3. Install Rust toolchain if missing
# -----------------------------------------------------------
if ! command -v cargo &>/dev/null; then
    warn "Rust toolchain not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
    ok "Rust installed: $(rustc --version)"
else
    ok "Rust found: $(rustc --version)"
fi

echo ""

# -----------------------------------------------------------
# 4. Build release binaries
# -----------------------------------------------------------
info "Building Traffic Cypher (Rust, --release)..."
cargo build --release --bins
ok "Build successful"
echo "   target/release/traffic_cypher  — CLI key generator"
echo "   target/release/pm              — Password manager web UI"
echo "   target/release/bench           — Benchmark harness"
echo ""

# -----------------------------------------------------------
# 5. Choose mode
# -----------------------------------------------------------
echo "How would you like to run Traffic Cypher?"
echo ""
echo "  1) Password Manager only        (web UI on http://127.0.0.1:9876)"
echo "  2) CLI key generator only        (requires a YouTube live URL)"
echo "  3) Both (PM in background + CLI)"
echo "  4) Just build, don't run"
echo ""
read -rp "Choose [1-4] (default: 1): " choice
choice="${choice:-1}"

cleanup() {
    echo ""
    info "Shutting down..."
    if [[ -n "${PM_PID:-}" ]]; then
        kill "$PM_PID" 2>/dev/null && ok "Password manager stopped"
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM

launch_pm() {
    echo ""
    info "Starting Password Manager..."
    ./target/release/pm &
    PM_PID=$!
    sleep 1
    if kill -0 "$PM_PID" 2>/dev/null; then
        ok "Password Manager running — http://127.0.0.1:9876"
        if [[ "$(uname)" == "Darwin" ]]; then
            open "http://127.0.0.1:9876" 2>/dev/null || true
        elif command -v xdg-open &>/dev/null; then
            xdg-open "http://127.0.0.1:9876" 2>/dev/null || true
        fi
    else
        fail "Password Manager failed to start"
    fi
}

launch_cli() {
    local url="$1"
    if [[ -z "$url" ]]; then
        echo ""
        read -rp "Enter YouTube livestream URL: " url
        if [[ -z "$url" ]]; then
            fail "No URL provided"
        fi
    fi
    echo ""
    info "Starting CLI key generator..."
    info "Press Ctrl+C to stop"
    echo ""
    ./target/release/traffic_cypher -u "$url" --show-metrics
}

case "$choice" in
    1)
        launch_pm
        echo ""
        ok "Press Ctrl+C to stop"
        wait "$PM_PID"
        ;;
    2)
        launch_cli "${2:-}"
        ;;
    3)
        launch_pm
        echo ""
        read -rp "Enter YouTube livestream URL for CLI: " stream_url
        if [[ -n "$stream_url" ]]; then
            echo ""
            info "Starting CLI key generator in foreground..."
            info "Password Manager still running in background"
            info "Press Ctrl+C to stop everything"
            echo ""
            ./target/release/traffic_cypher -u "$stream_url" --show-metrics
        else
            warn "No URL given — running Password Manager only"
            ok "Press Ctrl+C to stop"
            wait "$PM_PID"
        fi
        ;;
    4)
        ok "Build complete. Run manually:"
        echo "   ./target/release/pm                              # password manager"
        echo "   ./target/release/traffic_cypher -u <url>         # CLI key gen"
        exit 0
        ;;
    *)
        fail "Invalid choice"
        ;;
esac
