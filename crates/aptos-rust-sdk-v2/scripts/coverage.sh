#!/bin/bash
# Coverage helper script for aptos-rust-sdk-v2
#
# Usage:
#   ./scripts/coverage.sh          # Unit tests only (default)
#   ./scripts/coverage.sh full     # Unit tests with all features
#   ./scripts/coverage.sh e2e      # Include E2E tests (requires localnet)
#   ./scripts/coverage.sh all      # All tests including E2E
#   ./scripts/coverage.sh ci       # CI mode (XML + HTML output)

set -euo pipefail

PROFILE="${1:-default}"
SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Running coverage with profile: $PROFILE"
echo "Working directory: $SDK_DIR"

cd "$SDK_DIR"

case "$PROFILE" in
    "default")
        echo "Running unit tests with default features..."
        cargo tarpaulin -p aptos-rust-sdk-v2 --features "ed25519,secp256k1" --skip-clean --out Stdout
        ;;
    "full")
        echo "Running unit tests with all features..."
        cargo tarpaulin -p aptos-rust-sdk-v2 --features "full" --skip-clean --out Stdout
        ;;
    "e2e")
        echo "Running unit tests + E2E tests (ensure localnet is running)..."
        echo "To start localnet: aptos node run-localnet"
        cargo tarpaulin -p aptos-rust-sdk-v2 --features "full,e2e" --ignored --skip-clean --timeout 300 --out Stdout
        ;;
    "all")
        echo "Running all tests including E2E (ensure localnet is running)..."
        cargo tarpaulin -p aptos-rust-sdk-v2 --features "full,e2e" --ignored --skip-clean --timeout 300 --out Stdout
        ;;
    "ci")
        echo "Running CI coverage (unit tests, XML + HTML output)..."
        mkdir -p target/coverage
        cargo tarpaulin -p aptos-rust-sdk-v2 --features "full" --skip-clean --out Xml --out Html --output-dir target/coverage
        echo "Coverage report written to target/coverage/"
        ;;
    *)
        echo "Unknown profile: $PROFILE"
        echo "Usage: $0 [default|full|e2e|all|ci]"
        exit 1
        ;;
esac

echo "Done!"

