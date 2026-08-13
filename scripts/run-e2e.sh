#!/bin/bash
#
# Run E2E tests with automatic localnet setup
#
# Usage:
#   ./scripts/run-e2e.sh           # Run all E2E tests
#   ./scripts/run-e2e.sh account   # Run tests matching "account"
#   ./scripts/run-e2e.sh --no-localnet  # Skip localnet startup (use existing)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
LOCALNET_PID=""
START_LOCALNET=true
TEST_FILTER=""
TIMEOUT=120

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-localnet)
            START_LOCALNET=false
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        *)
            TEST_FILTER="$1"
            shift
            ;;
    esac
done

# Cleanup function
cleanup() {
    if [[ -n "$LOCALNET_PID" ]]; then
        echo -e "${YELLOW}Stopping localnet (PID: $LOCALNET_PID)...${NC}"
        kill "$LOCALNET_PID" 2>/dev/null || true
        # Also kill any child processes
        pkill -f "aptos node" 2>/dev/null || true
    fi
}

# Set up trap for cleanup
trap cleanup EXIT

# Check if Aptos CLI is installed
check_aptos_cli() {
    if ! command -v aptos &> /dev/null; then
        echo -e "${RED}Error: Aptos CLI is not installed${NC}"
        echo "Install it with: curl -fsSL https://aptos.dev/scripts/install_cli.py | python3"
        exit 1
    fi
    echo -e "${GREEN}✓ Aptos CLI found: $(aptos --version)${NC}"
}

# True when the CLI readiness server, node API, and faucet are all up.
# Faucet OpenAPI health is GET / ("Ok"), not /health (that 404s).
check_localnet_running() {
    curl -sf --max-time 5 http://127.0.0.1:8070/ >/dev/null 2>&1 || return 1
    curl -sf --max-time 5 http://127.0.0.1:8080/v1 | python3 -c 'import json,sys; d=json.load(sys.stdin); assert isinstance(d.get("chain_id"), int)' >/dev/null 2>&1 || return 1
    curl -sf --max-time 5 http://127.0.0.1:8081/ >/dev/null 2>&1 || return 1
    return 0
}

# Start localnet
start_localnet() {
    echo -e "${YELLOW}Starting localnet...${NC}"
    
    # Kill any existing localnet
    pkill -f "aptos node" 2>/dev/null || true
    sleep 2
    
    # Start localnet in background
    aptos node run-localnet --with-faucet --force-restart > /tmp/localnet.log 2>&1 &
    LOCALNET_PID=$!
    
    echo "Localnet PID: $LOCALNET_PID"
    echo "Waiting for localnet to be ready..."
    
    # Wait for localnet to be ready
    local elapsed=0
    while [[ $elapsed -lt $TIMEOUT ]]; do
        if check_localnet_running; then
            echo -e "${GREEN}✓ Localnet is ready${NC}"
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
        echo "  Waiting... ($elapsed/$TIMEOUT seconds)"
    done
    
    if [[ $elapsed -ge $TIMEOUT ]]; then
        echo -e "${RED}Error: Localnet did not start within $TIMEOUT seconds${NC}"
        echo "Check logs: /tmp/localnet.log"
        exit 1
    fi
}

# Run E2E tests
run_tests() {
    echo -e "${YELLOW}Running E2E tests...${NC}"
    
    cd "$PROJECT_DIR"
    
    export APTOS_LOCAL_NODE_URL="http://127.0.0.1:8080/v1"
    export APTOS_LOCAL_FAUCET_URL="http://127.0.0.1:8081"
    
    local test_cmd="cargo test -p aptos-sdk --features 'e2e,full' --tests -- --ignored --test-threads=1"
    
    if [[ -n "$TEST_FILTER" ]]; then
        test_cmd="cargo test -p aptos-sdk --features 'e2e,full' --tests -- --ignored --test-threads=1 $TEST_FILTER"
    fi
    
    echo "Running: $test_cmd"
    eval "$test_cmd"
}

# Main
main() {
    echo "======================================"
    echo "  Aptos Rust SDK E2E Test Runner"
    echo "======================================"
    echo
    
    check_aptos_cli
    
    if [[ "$START_LOCALNET" == "true" ]]; then
        if check_localnet_running; then
            echo -e "${YELLOW}Localnet is already running. Using existing instance.${NC}"
            echo "Use --no-localnet flag if this is intentional."
        else
            start_localnet
        fi
    else
        if ! check_localnet_running; then
            echo -e "${RED}Error: --no-localnet specified but localnet is not running${NC}"
            exit 1
        fi
        echo -e "${GREEN}✓ Using existing localnet${NC}"
    fi
    
    echo
    run_tests
    
    echo
    echo -e "${GREEN}======================================"
    echo "  E2E tests completed successfully!"
    echo "======================================${NC}"
}

main
