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

# Check if localnet is already running
check_localnet_running() {
    if curl -s http://127.0.0.1:8080/v1 > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Start localnet
start_localnet() {
    echo -e "${YELLOW}Starting localnet...${NC}"
    
    # Kill any existing localnet
    pkill -f "aptos node" 2>/dev/null || true
    sleep 2
    
    # Start localnet in background (with indexer API for full test coverage)
    aptos node run-localnet --with-faucet --with-indexer-api --force-restart > /tmp/localnet.log 2>&1 &
    LOCALNET_PID=$!
    
    echo "Localnet PID: $LOCALNET_PID"
    echo "Waiting for localnet to be ready..."
    
    # Wait for localnet to be ready
    local elapsed=0
    while [[ $elapsed -lt $TIMEOUT ]]; do
        if curl -s http://127.0.0.1:8080/v1 > /dev/null 2>&1; then
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
    
    # Wait for faucet
    echo "Waiting for faucet..."
    elapsed=0
    while [[ $elapsed -lt 60 ]]; do
        if curl -s http://127.0.0.1:8081/health > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Faucet is ready${NC}"
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    # Wait for indexer API (non-fatal if unavailable)
    echo "Waiting for indexer API..."
    elapsed=0
    while [[ $elapsed -lt 120 ]]; do
        if curl -s -X POST http://127.0.0.1:8090/v1/graphql \
            -H "Content-Type: application/json" \
            -d '{"query":"{ processor_status { processor } }"}' 2>/dev/null | grep -q "processor_status"; then
            echo -e "${GREEN}✓ Indexer API is ready${NC}"
            export APTOS_LOCAL_INDEXER_URL="http://127.0.0.1:8090/v1/graphql"
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    if [[ $elapsed -ge 120 ]]; then
        echo -e "${YELLOW}⚠ Indexer API not available (indexer tests will be skipped)${NC}"
    fi
}

# Run E2E tests
run_tests() {
    echo -e "${YELLOW}Running E2E tests...${NC}"
    
    cd "$PROJECT_DIR"
    
    export APTOS_LOCAL_NODE_URL="http://127.0.0.1:8080/v1"
    export APTOS_LOCAL_FAUCET_URL="http://127.0.0.1:8081"
    # APTOS_LOCAL_INDEXER_URL is set during start_localnet if indexer is available
    if [[ -n "${APTOS_LOCAL_INDEXER_URL:-}" ]]; then
        export APTOS_LOCAL_INDEXER_URL
    fi
    
    local test_cmd="cargo test -p aptos-sdk --features 'e2e,full' -- --ignored"
    
    if [[ -n "$TEST_FILTER" ]]; then
        test_cmd="cargo test -p aptos-sdk --features 'e2e,full' -- --ignored $TEST_FILTER"
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
