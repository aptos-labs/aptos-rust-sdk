# Aptos CLI — Build & Compatibility Notes

## Build Profiles

| Profile | Command | Use Case |
|---------|---------|----------|
| `dev` | `cargo build -p aptos-cli` | Local development (fast compile, large binary) |
| `release` | `cargo build -p aptos-cli --release` | Standard release build |
| `cli` | `cargo build -p aptos-cli --profile cli` | Size-optimized release (`opt-level=z`, fat LTO, `panic=abort`, stripped) |

The `cli` profile produces the smallest binary and is used for all CI release
artifacts.

---

## Platform Support Matrix

### Release binaries (CI-built)

| Artifact | Runner | Target Triple | OS | Arch | Min GLIBC | TLS Backend |
|----------|--------|---------------|-----|------|-----------|-------------|
| `linux-x86_64` | ubuntu-22.04 | `x86_64-unknown-linux-gnu` | Linux | x86_64 | **2.35** | OpenSSL 3.x (dynamic) |
| `linux-x86_64-generic` | ubuntu-22.04 | `x86_64-unknown-linux-gnu` | Linux | x86_64 | **2.35** | OpenSSL 3.x (dynamic) |
| `linux-arm64` | ubuntu-24.04-arm | `aarch64-unknown-linux-gnu` | Linux | aarch64 | **2.39** | OpenSSL 3.x (dynamic) |
| `macos-x86_64` | macos-13 | `x86_64-apple-darwin` | macOS | x86_64 | — | Security.framework |
| `macos-arm64` | macos-latest | `aarch64-apple-darwin` | macOS | aarch64 | — | Security.framework |
| `windows-x86_64` | windows-latest | `x86_64-pc-windows-msvc` | Windows | x86_64 | — | SChannel |

### Linux GLIBC requirements

Linux binaries are dynamically linked against **GLIBC** and **OpenSSL**.
The minimum GLIBC version is determined by the Ubuntu runner used in CI:

| Ubuntu Version | GLIBC | OpenSSL | Used For |
|----------------|-------|---------|----------|
| 22.04 (Jammy)  | 2.35  | 3.0.x   | x86_64 builds |
| 24.04 (Noble)  | 2.39  | 3.0.x   | aarch64 builds |

**Checking your system:**

```bash
# GLIBC version
ldd --version 2>&1 | head -1

# OpenSSL version
openssl version
```

**Compatible distributions (x86_64 — GLIBC ≥ 2.35):**

- Ubuntu 22.04+
- Debian 12 (Bookworm)+
- Fedora 36+
- RHEL/CentOS 9+
- Arch Linux (rolling)
- Amazon Linux 2023

**Compatible distributions (aarch64 — GLIBC ≥ 2.39):**

- Ubuntu 24.04+
- Debian 13 (Trixie)+
- Fedora 40+

If your distribution ships an older GLIBC, build from source on your system
(see below).

### macOS requirements

macOS builds use the native **Security.framework** for TLS. No additional
dependencies are needed.

| Build | Minimum macOS |
|-------|---------------|
| `macos-x86_64` | macOS 13 (Ventura) |
| `macos-arm64` | macOS 14 (Sonoma) |

### Windows requirements

Windows builds use **SChannel** for TLS. No additional dependencies needed.
Minimum: Windows 10.

---

## Linux x86_64-generic (no SIMD)

The `linux-x86_64-generic` build is compiled with:

```
RUSTFLAGS="-C target-cpu=generic -C target-feature=-sse4.2,-avx,-avx2"
```

This disables SSE4.2, AVX, and AVX2 instructions, producing a binary that runs
on **any** x86_64 CPU (including older Intel Core 2 / AMD Phenom era and
virtualized environments that mask SIMD extensions).

Use the standard `linux-x86_64` build if your CPU supports SSE4.2+ (nearly all
CPUs manufactured after 2008).

---

## TLS / SSL Details

The SDK uses `reqwest` with the **`native-tls`** backend (the default). This
means the TLS implementation differs per platform:

| Platform | TLS Library | Linking |
|----------|-------------|---------|
| Linux | **OpenSSL 3.x** (`openssl-sys`) | Dynamic (`libssl.so.3`, `libcrypto.so.3`) |
| macOS | **Security.framework** | System framework (static) |
| Windows | **SChannel** | System DLL (static) |

### OpenSSL on Linux

The binary dynamically links OpenSSL at runtime. Most modern Linux distributions
ship OpenSSL 3.x. If yours doesn't:

```bash
# Debian/Ubuntu: install OpenSSL 3
sudo apt-get install libssl3

# RHEL/Fedora: usually included by default
# If missing:
sudo dnf install openssl-libs
```

### Building with rustls (no OpenSSL dependency)

If you want a fully statically-linked TLS stack on Linux (no OpenSSL runtime
dependency), you can build from source with the `rustls-tls` feature on
`reqwest`. This requires modifying the workspace `Cargo.toml`:

```toml
# In workspace Cargo.toml, change:
reqwest = { version = "0.12.15", default-features = false, features = [
    "blocking", "cookies", "json", "multipart", "stream",
    "rustls-tls",   # <-- use rustls instead of native-tls
] }
```

---

## System Dependencies for Building from Source

### Linux

```bash
# Ubuntu/Debian
sudo apt-get install -y build-essential pkg-config libssl-dev lld

# Fedora/RHEL
sudo dnf install gcc openssl-devel lld

# Note: lld is required by .cargo/config.toml for x86_64-unknown-linux-gnu
```

### macOS

```bash
# Xcode command-line tools (includes the required frameworks)
xcode-select --install
```

### Windows

- Visual Studio Build Tools with the "C++ build tools" workload
- Or full Visual Studio with C++ support

---

## Rust Toolchain

- **Minimum**: Rust 1.90+ (specified in `rust-toolchain.toml`)
- **Edition**: 2024
- **Stable rustfmt** is used for formatting

---

## Reproducing CI Builds Locally

```bash
# Standard optimized build (same as CI release artifacts)
cargo build -p aptos-cli --profile cli

# Generic / no-SIMD build (Linux x86_64 only)
RUSTFLAGS="-C target-cpu=generic -C target-feature=-sse4.2,-avx,-avx2" \
  cargo build -p aptos-cli --profile cli

# Cross-compile for a different target
rustup target add aarch64-apple-darwin
cargo build -p aptos-cli --profile cli --target aarch64-apple-darwin
```
