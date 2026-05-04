#!/bin/bash
# =============================================================================
# Traffic Cypher Benchmark Suite — Rust vs C Comparison
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$PROJECT_DIR/traffic_cypher_in_Rust"
C_DIR="$PROJECT_DIR/traffic_cypher_in_C"
RESULTS_DIR="$SCRIPT_DIR/results"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

mkdir -p "$RESULTS_DIR"

header() {
    echo ""
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

section() {
    echo -e "\n${YELLOW}▸ $1${NC}"
}

# =============================================================================
# Phase 1: Build Time Comparison
# =============================================================================
header "PHASE 1: BUILD TIME COMPARISON"

section "Building C implementation (clean build)..."
cd "$C_DIR"
make clean >/dev/null 2>&1 || true
C_BUILD_START=$(python3 -c 'import time; print(time.time())')
make -j$(sysctl -n hw.ncpu) 2>&1 | tail -1
C_BUILD_END=$(python3 -c 'import time; print(time.time())')
C_BUILD_TIME=$(python3 -c "print(f'{($C_BUILD_END - $C_BUILD_START):.2f}')")
echo -e "${GREEN}  C build time: ${C_BUILD_TIME}s${NC}"

section "Building C benchmark harness..."
cd "$SCRIPT_DIR"
make clean >/dev/null 2>&1 || true
make 2>&1 | tail -1
echo -e "${GREEN}  C benchmark built${NC}"

section "Building Rust implementation (clean build)..."
cd "$RUST_DIR"
cargo clean 2>/dev/null || true
RUST_BUILD_START=$(python3 -c 'import time; print(time.time())')
cargo build --release --bins 2>&1 | tail -5
RUST_BUILD_END=$(python3 -c 'import time; print(time.time())')
RUST_BUILD_TIME=$(python3 -c "print(f'{($RUST_BUILD_END - $RUST_BUILD_START):.2f}')")
echo -e "${GREEN}  Rust build time: ${RUST_BUILD_TIME}s${NC}"

# =============================================================================
# Phase 2: Binary Size Comparison
# =============================================================================
header "PHASE 2: BINARY SIZE COMPARISON"

C_PM_SIZE=$(stat -f%z "$C_DIR/traffic-cypher-pm" 2>/dev/null || echo 0)
C_CLI_SIZE=$(stat -f%z "$C_DIR/traffic-cypher" 2>/dev/null || echo 0)
RUST_PM_SIZE=$(stat -f%z "$RUST_DIR/target/release/pm" 2>/dev/null || echo 0)
RUST_CLI_SIZE=$(stat -f%z "$RUST_DIR/target/release/traffic_cypher" 2>/dev/null || echo 0)
RUST_BENCH_SIZE=$(stat -f%z "$RUST_DIR/target/release/bench" 2>/dev/null || echo 0)

format_size() {
    local bytes=$1
    if [ "$bytes" -gt 1048576 ]; then
        python3 -c "print(f'{$bytes/1048576:.2f} MB')"
    elif [ "$bytes" -gt 1024 ]; then
        python3 -c "print(f'{$bytes/1024:.1f} KB')"
    else
        echo "${bytes} B"
    fi
}

echo -e "  ${BOLD}C Implementation:${NC}"
echo -e "    traffic-cypher (CLI): $(format_size $C_CLI_SIZE)"
echo -e "    traffic-cypher-pm:    $(format_size $C_PM_SIZE)"
echo -e "  ${BOLD}Rust Implementation:${NC}"
echo -e "    traffic_cypher (CLI): $(format_size $RUST_CLI_SIZE)"
echo -e "    pm:                   $(format_size $RUST_PM_SIZE)"

# =============================================================================
# Phase 3: Code Metrics
# =============================================================================
header "PHASE 3: CODE METRICS"

C_LOC=$(find "$C_DIR/src_c" -name '*.c' -exec cat {} + | wc -l | tr -d ' ')
C_HEADERS=$(find "$C_DIR/include" -name '*.h' -exec cat {} + | wc -l | tr -d ' ')
C_FILES=$(find "$C_DIR/src_c" -name '*.c' | wc -l | tr -d ' ')
C_HEADER_FILES=$(find "$C_DIR/include" -name '*.h' | wc -l | tr -d ' ')

RUST_LOC=$(find "$RUST_DIR/src" -name '*.rs' -exec cat {} + | wc -l | tr -d ' ')
RUST_FILES=$(find "$RUST_DIR/src" -name '*.rs' | wc -l | tr -d ' ')

echo -e "  ${BOLD}C Implementation:${NC}"
echo -e "    Source files: ${C_FILES} (.c) + ${C_HEADER_FILES} (.h)"
echo -e "    Lines of code: ${C_LOC} (.c) + ${C_HEADERS} (.h) = $((C_LOC + C_HEADERS)) total"

echo -e "  ${BOLD}Rust Implementation:${NC}"
echo -e "    Source files: ${RUST_FILES} (.rs)"
echo -e "    Lines of code: ${RUST_LOC}"

# Count dependencies
C_DEPS="OpenSSL, pthread, libm (3 external libs)"
RUST_DEPS=$(grep -c '=' "$RUST_DIR/Cargo.toml" | head -1 || echo "?")
echo -e "\n  ${BOLD}Dependencies:${NC}"
echo -e "    C:    ${C_DEPS}"
echo -e "    Rust: ~${RUST_DEPS} crate dependencies (Cargo.toml)"

# =============================================================================
# Phase 4: Startup Time
# =============================================================================
header "PHASE 4: STARTUP TIME (--help or quick exit)"

section "Measuring C startup time..."
C_STARTUP_TOTAL=0
for i in $(seq 1 20); do
    t=$( { /usr/bin/time -l "$C_DIR/traffic-cypher" --help; } 2>&1 | grep real | awk '{print $1}' || echo "0.01")
    C_STARTUP_TOTAL=$(python3 -c "print($C_STARTUP_TOTAL + $t)" 2>/dev/null || echo "0")
done
C_STARTUP_AVG=$(python3 -c "print(f'{$C_STARTUP_TOTAL/20*1000:.2f}')")
echo -e "${GREEN}  C avg startup: ${C_STARTUP_AVG}ms${NC}"

section "Measuring Rust startup time..."
RUST_STARTUP_TOTAL=0
for i in $(seq 1 20); do
    t=$( { /usr/bin/time -l "$RUST_DIR/target/release/traffic_cypher" --help; } 2>&1 | grep real | awk '{print $1}' || echo "0.01")
    RUST_STARTUP_TOTAL=$(python3 -c "print($RUST_STARTUP_TOTAL + $t)" 2>/dev/null || echo "0")
done
RUST_STARTUP_AVG=$(python3 -c "print(f'{$RUST_STARTUP_TOTAL/20*1000:.2f}')")
echo -e "${GREEN}  Rust avg startup: ${RUST_STARTUP_AVG}ms${NC}"

# =============================================================================
# Phase 5: Performance Benchmarks
# =============================================================================
header "PHASE 5: PERFORMANCE BENCHMARKS (17 tests each)"

section "Running C benchmarks..."
"$SCRIPT_DIR/bench_c" > "$RESULTS_DIR/c_results.json"
echo -e "${GREEN}  C benchmarks complete${NC}"

section "Running Rust benchmarks..."
"$RUST_DIR/target/release/bench" > "$RESULTS_DIR/rust_results.json"
echo -e "${GREEN}  Rust benchmarks complete${NC}"

# =============================================================================
# Phase 6: HTTP API Latency (if servers can be started)
# =============================================================================
header "PHASE 6: HTTP API LATENCY"

test_api_latency() {
    local name=$1
    local binary=$2
    local port=9876

    # Start server in background
    "$binary" &
    local pid=$!
    sleep 1

    # Check if server is running
    if ! kill -0 $pid 2>/dev/null; then
        echo -e "  ${RED}$name server failed to start${NC}"
        return
    fi

    echo -e "  ${BOLD}$name Server (PID $pid):${NC}"

    # Unlock vault first
    curl -s -X POST "http://127.0.0.1:$port/api/auth/unlock" \
        -H "Content-Type: application/json" \
        -d '{"master_password":"benchmark_test_2024"}' > /dev/null 2>&1

    local token
    token=$(curl -s -X POST "http://127.0.0.1:$port/api/auth/unlock" \
        -H "Content-Type: application/json" \
        -d '{"master_password":"benchmark_test_2024"}' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")

    if [ -z "$token" ]; then
        echo -e "    ${RED}Could not get auth token, skipping API tests${NC}"
        kill $pid 2>/dev/null || true
        wait $pid 2>/dev/null || true
        return
    fi

    local auth_header="Authorization: Bearer $token"

    # Test endpoints
    local endpoints=(
        "GET /api/auth/status"
        "GET /api/credentials"
        "GET /api/status"
        "POST /api/generate-password"
        "GET /api/settings"
        "GET /api/entropy-snapshot"
    )

    for endpoint in "${endpoints[@]}"; do
        local method=$(echo "$endpoint" | cut -d' ' -f1)
        local path=$(echo "$endpoint" | cut -d' ' -f2)
        local total=0
        local count=50

        for i in $(seq 1 $count); do
            local start_t=$(python3 -c 'import time; print(time.time())')
            if [ "$method" = "POST" ]; then
                curl -s -X POST "http://127.0.0.1:$port$path" \
                    -H "$auth_header" \
                    -H "Content-Type: application/json" \
                    -d '{"length":24,"uppercase":true,"lowercase":true,"digits":true,"symbols":true}' > /dev/null 2>&1
            else
                curl -s "http://127.0.0.1:$port$path" \
                    -H "$auth_header" > /dev/null 2>&1
            fi
            local end_t=$(python3 -c 'import time; print(time.time())')
            total=$(python3 -c "print($total + ($end_t - $start_t))")
        done

        local avg_ms=$(python3 -c "print(f'{$total/$count*1000:.2f}')")
        echo -e "    $endpoint: ${GREEN}${avg_ms}ms${NC} avg (${count} reqs)"
    done

    # Get memory usage of the server
    local rss_kb=$(ps -o rss= -p $pid 2>/dev/null | tr -d ' ')
    if [ -n "$rss_kb" ]; then
        local rss_mb=$(python3 -c "print(f'{int($rss_kb)/1024:.1f}')")
        echo -e "    Server RSS: ${rss_mb} MB"
    fi

    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
    sleep 1
}

# Use temp vault for API tests
export TRAFFIC_CYPHER_VAULT_PATH="/tmp/bench_api_vault.json"
rm -f "$TRAFFIC_CYPHER_VAULT_PATH"

section "Testing C server..."
test_api_latency "C" "$C_DIR/traffic-cypher-pm"

rm -f "$TRAFFIC_CYPHER_VAULT_PATH"

section "Testing Rust server..."
test_api_latency "Rust" "$RUST_DIR/target/release/pm"

rm -f "$TRAFFIC_CYPHER_VAULT_PATH"
unset TRAFFIC_CYPHER_VAULT_PATH

# =============================================================================
# Phase 7: Comparison Report
# =============================================================================
header "PHASE 7: DETAILED COMPARISON REPORT"

python3 << 'PYEOF'
import json
import sys
import os

results_dir = os.path.join(os.path.dirname(os.path.abspath(".")), "results")
# Try multiple paths
for d in ["results", "./results", os.path.join(os.environ.get("SCRIPT_DIR", "."), "results")]:
    c_path = os.path.join(d, "c_results.json")
    r_path = os.path.join(d, "rust_results.json")
    if os.path.exists(c_path):
        break

try:
    with open(c_path) as f:
        c_data = json.load(f)
    with open(r_path) as f:
        r_data = json.load(f)
except FileNotFoundError:
    # Try absolute path
    script_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else "."
    c_path = os.path.join(script_dir, "results", "c_results.json")
    r_path = os.path.join(script_dir, "results", "rust_results.json")
    with open(c_path) as f:
        c_data = json.load(f)
    with open(r_path) as f:
        r_data = json.load(f)

c_bench = {b["name"]: b for b in c_data["benchmarks"]}
r_bench = {b["name"]: b for b in r_data["benchmarks"]}

print()
print("┌─────────────────────────────┬────────────┬────────────┬──────────┬────────────┐")
print("│ Benchmark                   │ C median   │ Rust median│ Ratio    │ Winner     │")
print("│                             │ (μs)       │ (μs)       │ C/Rust   │            │")
print("├─────────────────────────────┼────────────┼────────────┼──────────┼────────────┤")

c_wins = 0
r_wins = 0
ties = 0

for name in c_bench:
    if name not in r_bench:
        continue

    c_med = c_bench[name]["median_us"]
    r_med = r_bench[name]["median_us"]

    if r_med > 0:
        ratio = c_med / r_med
    else:
        ratio = float('inf')

    # Determine winner (within 5% = tie)
    if ratio < 0.95:
        winner = "✓ C"
        c_wins += 1
    elif ratio > 1.05:
        winner = "✓ Rust"
        r_wins += 1
    else:
        winner = "≈ Tie"
        ties += 1

    short_name = name[:27]
    print(f"│ {short_name:<27} │ {c_med:>10.2f} │ {r_med:>10.2f} │ {ratio:>8.2f} │ {winner:<10} │")

print("└─────────────────────────────┴────────────┴────────────┴──────────┴────────────┘")

print(f"\n  Summary: C wins {c_wins}, Rust wins {r_wins}, Ties {ties}")

# Memory comparison
c_rss = c_data.get("memory_rss_mb", 0)
r_rss = r_data.get("memory_rss_mb", 0)
print(f"\n  Memory (benchmark RSS):  C = {c_rss:.1f} MB  |  Rust = {r_rss:.1f} MB")
print(f"  Total bench time:        C = {c_data.get('total_time_ms', 0):.0f} ms  |  Rust = {r_data.get('total_time_ms', 0):.0f} ms")

# Categories analysis
print("\n  ─── Performance by Category ───")
categories = {
    "Crypto (HKDF/DEK)": ["hkdf_derive_key", "dek_generate_os", "dek_generate_traffic"],
    "Entropy Pipeline": ["entropy_extract_single", "entropy_extract_delta", "entropy_pool_push_digest", "entropy_mix", "full_entropy_pipeline"],
    "Vault Operations": ["vault_entry_create", "vault_crud_cycle", "vault_serialize_10", "vault_save_load_cycle", "vault_search_100_entries"],
    "Utilities": ["password_generate_24", "password_strength_calc", "totp_generate", "hex_encode_256b"],
}

for cat_name, bench_names in categories.items():
    c_total = sum(c_bench[n]["median_us"] for n in bench_names if n in c_bench)
    r_total = sum(r_bench[n]["median_us"] for n in bench_names if n in r_bench)
    ratio = c_total / r_total if r_total > 0 else float('inf')
    winner = "C" if ratio < 0.95 else ("Rust" if ratio > 1.05 else "Tie")
    print(f"    {cat_name:<25}  C: {c_total:>10.1f}μs  Rust: {r_total:>10.1f}μs  → {winner} ({ratio:.2f}x)")

PYEOF

# =============================================================================
# Phase 8: Qualitative Analysis
# =============================================================================
header "PHASE 8: QUALITATIVE COMPARISON"

cat << 'QUALEOF'

  ┌──────────────────────┬─────────────────────────────┬─────────────────────────────┐
  │ Aspect               │ C Implementation            │ Rust Implementation         │
  ├──────────────────────┼─────────────────────────────┼─────────────────────────────┤
  │ Memory Safety        │ Manual (malloc/free)        │ Guaranteed (ownership)      │
  │ Buffer Overflows     │ Possible (strncpy/snprintf) │ Prevented at compile time   │
  │ Null Pointer Derefs  │ Possible                    │ Option<T> / Result<T>       │
  │ Thread Safety        │ Manual (pthread_mutex)      │ Compiler-enforced (Send/Sync│
  │ JSON Handling        │ Hand-written parser         │ serde (derive macros)       │
  │ Error Handling       │ Return codes (-1/0)         │ Result<T,E> + anyhow        │
  │ Async I/O            │ Threads (pthread)           │ tokio async/await           │
  │ HTTP Server          │ Raw socket + manual parse   │ axum (production-grade)     │
  │ Crypto Library       │ OpenSSL (C binding)         │ RustCrypto (pure Rust)      │
  │ Build System         │ Makefile                    │ Cargo (deps auto-resolved)  │
  │ Package Management   │ Manual (brew install)       │ Cargo.toml (automatic)      │
  │ Test Framework       │ None built-in               │ Built-in (#[test])          │
  │ Cross-platform       │ macOS-centric (framework)   │ Portable (getrandom crate)  │
  │ Vault Capacity       │ Fixed 256 entries           │ Dynamic (Vec, unlimited)    │
  │ String Handling      │ Fixed-size buffers          │ Dynamic String/Vec<u8>      │
  │ Code Reuse           │ Copy/paste patterns         │ Traits, generics, derives   │
  │ Secure Memory Wipe   │ Neither implements          │ Neither implements          │
  └──────────────────────┴─────────────────────────────┴─────────────────────────────┘

  KEY TRADE-OFFS:

  C Advantages:
    • Faster compile time (significantly)
    • Smaller binary size (no runtime, no async executor)
    • Lower baseline memory usage
    • Direct OpenSSL access (hardware-accelerated AES-NI)
    • No dependency download on build
    • Predictable performance (no allocator overhead)

  Rust Advantages:
    • Memory safety without runtime cost
    • No buffer overflow vulnerabilities
    • Fearless concurrency (data races impossible)
    • Rich ecosystem (serde, axum, tokio)
    • Better error handling (no silent failures)
    • Dynamic data structures (no fixed limits)
    • Built-in testing framework
    • Cross-platform portability
    • Automatic dependency management

  Security Considerations:
    • C version: hand-written JSON parser is a vulnerability surface
    • C version: strncpy/snprintf can silently truncate
    • C version: manual memory management risks use-after-free
    • Rust version: unsafe{} blocks need audit (RSS measurement)
    • Both: neither uses secure memory wiping (zeroize)
    • Both: master password held in plaintext in memory while unlocked

QUALEOF

header "BENCHMARK COMPLETE"
echo -e "  Results saved to: ${BOLD}$RESULTS_DIR/${NC}"
echo -e "  JSON files: c_results.json, rust_results.json"
echo ""
