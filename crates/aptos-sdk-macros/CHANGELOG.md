# Changelog

All notable changes to `aptos-sdk-macros` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [0.2.1] - 2026-03-04

### Changed
- Patch version bump to align with `aptos-sdk` 0.4.1 release

## [0.2.0] - 2026-02-25

### Security
- Made path traversal check in `aptos_contract_file!` non-bypassable via path canonicalization
- Added input validation for Rust identifiers generated from Move ABI to prevent panics on malformed input
- Added Rust keyword detection with automatic raw identifier (`r#`) fallback

### Changed
- Updated generated code to use `const-hex` instead of `hex` crate (aligns with aptos-sdk 0.4.0)
- Removed unused `extra-traits` feature from `syn` dependency
- Configured `docs.rs` publishing metadata

## [0.1.0] - 2026-01-06

### Added
- `aptos_contract!` procedural macro for inline ABI-based contract bindings
- `aptos_contract_file!` procedural macro for file-based ABI contract bindings
- Type-safe Rust code generation from Move module ABIs
- Support for entry functions, view functions, and struct definitions
- Move-to-Rust type mapping (primitives, vectors, options, objects)

[0.2.0]: https://github.com/aptos-labs/aptos-rust-sdk/releases/tag/macros-v0.2.0
[0.1.0]: https://github.com/aptos-labs/aptos-rust-sdk/releases/tag/macros-v0.1.0
