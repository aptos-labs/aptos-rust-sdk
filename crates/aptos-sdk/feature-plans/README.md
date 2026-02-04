# Feature Design Documents

This directory contains detailed design documents for each major feature of the Aptos Rust SDK v2.

## Purpose

These documents serve to:
1. Provide detailed specifications for implementation
2. Enable validation by other agents/reviewers
3. Document architectural decisions and trade-offs
4. Serve as reference during development

## Document Status

| Document | Status | Priority |
|----------|--------|----------|
| [01-core-types.md](./01-core-types.md) | ✅ Implemented | P0 |
| [02-cryptography.md](./02-cryptography.md) | ✅ Implemented | P0 |
| [03-account-management.md](./03-account-management.md) | ✅ Implemented | P0 |
| [04-transaction-building.md](./04-transaction-building.md) | ✅ Implemented | P0 |
| [05-api-clients.md](./05-api-clients.md) | ✅ Implemented | P0 |
| [06-error-handling.md](./06-error-handling.md) | ✅ Implemented | P1 |
| [07-testing-strategy.md](./07-testing-strategy.md) | ✅ Implemented | P1 |
| [08-multi-signature.md](./08-multi-signature.md) | ✅ Implemented | P2 |
| [09-keyless-accounts.md](./09-keyless-accounts.md) | ✅ Implemented | P2 |
| [10-advanced-features.md](./10-advanced-features.md) | 📋 Planned | P3 |
| [11-multi-key-accounts.md](./11-multi-key-accounts.md) | ✅ Implemented | P2 |
| [12-code-generation.md](./12-code-generation.md) | ✅ Implemented | P1 |
| [13-type-safe-bindings.md](./13-type-safe-bindings.md) | ✅ Implemented | P1 |
| [14-auto-retry-backoff.md](./14-auto-retry-backoff.md) | ✅ Implemented | P1 |
| [15-connection-pooling.md](./15-connection-pooling.md) | ✅ Implemented | P2 |
| [16-sponsored-transactions.md](./16-sponsored-transactions.md) | ✅ Implemented | P1 |
| [18-transaction-batching.md](./18-transaction-batching.md) | ✅ Implemented | P1 |
| [19-input-entry-function-data.md](./19-input-entry-function-data.md) | ✅ Implemented | P1 |
| [20-secp256r1-passkey.md](./20-secp256r1-passkey.md) | ✅ Implemented | P2 |
| [21-local-simulation.md](./21-local-simulation.md) | ✅ Implemented | P1 |

## How to Use These Documents

### For Implementers
1. Read the relevant design doc before implementing
2. Follow the API specifications exactly
3. Implement all listed test cases
4. Update status when complete

### For Reviewers
1. Verify implementation matches specification
2. Check that all test cases are covered
3. Validate error handling scenarios
4. Ensure documentation matches API

## Template

Each design document follows this structure:

```markdown
# Feature Name

## Overview
Brief description and motivation

## Goals
What this feature achieves

## Non-Goals
What this feature explicitly does NOT do

## API Design
Public interfaces and types

## Implementation Details
Internal architecture and algorithms

## Error Handling
Error types and scenarios

## Testing Requirements
Required test cases

## Security Considerations
Security implications and mitigations

## Dependencies
External crates and internal modules

## Open Questions
Unresolved design decisions
```
