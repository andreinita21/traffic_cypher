#!/bin/bash
set -e

# ============================================================================
#  Traffic Cypher — Auto Runner
#  Installs dependencies, builds, and launches the full stack
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
echo "|     T R A F F I C   C Y P H E R                         |"
echo "|   Auto Runner — Install, Build & Launch                  |"
echo "|                                                          |"
echo "+==========================================================+"
echo ""

# -----------------------------------------------------------
# 1. Check / install Homebrew (macOS only)
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
# 2. Check / install dependencies
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

# OpenSSL (check for library, not just binary)
if [[ "$(uname)" == "Darwin" ]]; then
    OPENSSL_PREFIX="$(brew --prefix openssl 2>/dev/null || true)"
    if [[ -z "$OPENSSL_PREFIX" ]] || [[ ! -d "$OPENSSL_PREFIX" ]]; then
        info "Installing openssl..."
        brew install openssl
        OPENSSL_PREFIX="$(brew --prefix openssl)"
    fi
    ok "OpenSSL found at $OPENSSL_PREFIX"
else
    if ! pkg-config --exists openssl 2>/dev/null; then
        info "Installing libssl-dev..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y libssl-dev
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y openssl-devel
        fi
    fi
    ok "OpenSSL dev libraries found"
fi

install_if_missing "ffmpeg" "ffmpeg"
install_if_missing "yt-dlp" "yt-dlp"
install_if_missing "make"   "make"

# Ensure a C compiler exists
if command -v cc &>/dev/null; then
    ok "C compiler found ($(cc --version 2>&1 | head -1))"
elif command -v gcc &>/dev/null; then
    ok "GCC found"
else
    if [[ "$(uname)" == "Darwin" ]]; then
        info "Installing Xcode command line tools..."
        xcode-select --install 2>/dev/null || true
    else
        install_if_missing "gcc" "gcc"
    fi
fi

echo ""

# -----------------------------------------------------------
# 3. Build
# -----------------------------------------------------------
info "Building Traffic Cypher..."
make clean 2>/dev/null || true
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)" 2>&1

if [[ ! -f ./traffic-cypher ]] || [[ ! -f ./traffic-cypher-pm ]]; then
    fail "Build failed — binaries not found"
fi

ok "Build successful"
echo "   traffic-cypher    — CLI key generator"
echo "   traffic-cypher-pm — Password manager web UI"
echo ""

# -----------------------------------------------------------
# 4. Launch mode selection
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
    if [[ -n "$PM_PID" ]]; then
        kill "$PM_PID" 2>/dev/null && ok "Password manager stopped"
    fi
    if [[ -n "$CLI_PID" ]]; then
        kill "$CLI_PID" 2>/dev/null && ok "CLI stopped"
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM

launch_pm() {
    echo ""
    info "Starting Password Manager..."
    ./traffic-cypher-pm &
    PM_PID=$!
    sleep 1
    if kill -0 "$PM_PID" 2>/dev/null; then
        ok "Password Manager running — http://127.0.0.1:9876"
        # Auto-open browser
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
    ./traffic-cypher -u "$url" --show-metrics
}

case "$choice" in
    1)
        launch_pm
        echo ""
        ok "Press Ctrl+C to stop"
        wait "$PM_PID"
        ;;
    2)
        launch_cli "$2"
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
            ./traffic-cypher -u "$stream_url" --show-metrics
        else
            warn "No URL given — running Password Manager only"
            ok "Press Ctrl+C to stop"
            wait "$PM_PID"
        fi
        ;;
    4)
        ok "Build complete. Run manually:"
        echo "   ./traffic-cypher-pm                              # password manager"
        echo "   ./traffic-cypher -u <youtube_live_url>           # CLI key gen"
        exit 0
        ;;
    *)
        fail "Invalid choice"
        ;;
esac
