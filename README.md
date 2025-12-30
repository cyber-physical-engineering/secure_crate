# ZTL Secure Engine

**A reference implementation for high-assurance cryptographic operations in Rust.**

This crate extracts the core cryptographic engine from the Zero Trust Ledger (ZTL) architecture built by **Big Data Plumbing**. It provides a reusable, secure foundation for systems requiring authenticated encryption, digital signatures, and strict key management policies.

We are releasing this component to the open-source community to demonstrate how to implement "Zero Trust" principles—specifically Strict IV Reuse Policies and HKDF-based key derivation—in a production-ready Rust crate.

## Why This Matters

Many cryptographic implementations fail not because the algorithms are broken, but because the **usage patterns** are insecure (e.g., reusing Nonces in AES-GCM). This engine enforces safety at the API level.

### Key Features

- **Authenticated Encryption**: AES-256-GCM with integral tag validation.
- **Strict IV Policy**: Optional in-memory tracking of Nonces (IVs) to mathematically prevent reuse attacks during the process lifecycle.
- **Key Derivation**: Implements **HKDF-SHA384** to derive ephemeral encryption keys from master seeds, preventing direct key exposure.
- **Digital Signatures**: ECDSA P-256 (NIST curve) support for immutable audit trails.
- **Testable Architecture**: Uses a `CryptoEngine` trait to allow seamless mocking in unit/integration tests without compromising production security.

## Usage

Add this to your `Cargo.toml` to start building secure ledgers or audit logs.

```rust
use ztl_secure::{RealCryptoEngine, CryptoEngine};
use std::env;

fn main() {
    // 1. Setup environment (Use secrets management in production)
    env::set_var("ZTL_ENC_SEED_B64", "your_base64_encoded_seed_value...");

    // 2. Initialize engine with Strict Policy enabled
    let engine = RealCryptoEngine::new_from_env_with_strict_iv_policy(true)
        .expect("Failed to initialize secure engine");

    // 3. Encrypt data (automatically generates unique IV)
    let data = b"Confidential Audit Record";
    let encrypted = engine.encrypt(data).unwrap();

    // 4. Decrypt and verify integrity
    let decrypted = engine.decrypt(&encrypted).unwrap();
    assert_eq!(data, &decrypted[..]);
}
```

## Security Philosophy

This crate is built on the principle of **"Secure by Design"**:
1.  **Fail Safe**: Cryptographic failures (auth tag mismatch, invalid key) always return explicit errors.
2.  **No Magic**: Keys must be provided explicitly via environment or secure injection, never hardcoded.
3.  **Audit Ready**: The code is structured to be easily auditable by security teams.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
*Built with ❤️ and 🦀 by [Big Data Plumbing](https://bigdataplumbing.com).*
