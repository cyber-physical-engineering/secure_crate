# ztl-secure

A small Rust library that puts AES-256-GCM encryption, ECDSA P-256 signatures and SHA-384 hashing behind one `CryptoEngine` trait. It is the cryptographic engine of the ZeroTrust Ledger prototype.

**Status: prototype.** 6 unit tests pass on Rust 1.99 (October 2026). `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` are clean.

[![CI](https://github.com/cyber-physical-engineering/secure_crate/actions/workflows/ci.yml/badge.svg)](https://github.com/cyber-physical-engineering/secure_crate/actions/workflows/ci.yml)

James Thornton set the architecture and requirements. The code was written with AI-assisted development in late 2025. The tests and checks were re-run in October 2026.

## Where it comes from

The ZeroTrust Ledger is a tamper-evident record of what happened, who triggered it, and what changed, designed for control systems and field devices that lose their network. It is a ten-crate Rust workspace named for five actions (Secure, Control, Comply, Verify, Prove), and the workspace is not public. Each record is hashed and chained to the one before it. The 2025 build signed with Dilithium and wrapped keys with Kyber, now standardized as ML-DSA and ML-KEM. The current workspace signs with ECDSA P-256 and carries the post-quantum modules as a staged port. It was proposed to the Army C5ISR Center in 2025 as a prototype for securing tactical data in use.

This crate is the engine from that workspace. It is P-256 only.

## What it does

- AES-256-GCM with a fresh random 96-bit nonce per message. The output is the 12-byte nonce, then the ciphertext, then the 16-byte tag. A changed byte fails decryption (tested).
- The AES key comes from `ZTL_ENC_KEY_B64` (32 bytes, base64), or is derived from `ZTL_ENC_SEED_B64` with HKDF-SHA384 and a fixed demo salt. `VITE_ENC_KEY_B64` and `VITE_ENC_SEED_B64` are accepted as fallbacks.
- ECDSA P-256 signing and verification with DER signatures. Keys load from `ZTL_SIGN_PRIVKEY_PEM` (PKCS#8 or SEC1) and `ZTL_SIGN_PUBKEY_PEM` (SPKI). `sign()` with no key configured returns `ConfigError`.
- `hash()` returns SHA-384 as `sha384:<hex>`.
- An optional strict nonce mode remembers every nonce an engine instance has used and refuses a repeat. It lives in memory, per instance.
- The `CryptoEngine` trait has a `MockCryptoEngine` for tests. Its `verify()` always returns true, so it is for tests only.

## Quick start

The crate is not on crates.io. Add it as a git dependency:

```toml
[dependencies]
ztl-secure = { git = "https://github.com/cyber-physical-engineering/secure_crate" }
```

Make a seed and export it:

```bash
export ZTL_ENC_SEED_B64="$(openssl rand -base64 32)"
```

Encrypt, decrypt and hash:

```rust
use ztl_secure::{CryptoEngine, RealCryptoEngine, TrustError};

fn main() -> Result<(), TrustError> {
    let engine = RealCryptoEngine::new_from_env_with_strict_iv_policy(true)?;

    let record = b"audit record 0001";
    let sealed = engine.encrypt(record)?; // 12-byte nonce + ciphertext + 16-byte tag
    let opened = engine.decrypt(&sealed)?;
    assert_eq!(&opened[..], record);

    println!("{}", engine.hash(record)?); // sha384:<hex>
    Ok(())
}
```

Run the tests:

```bash
cargo test
```

## How it works

`RealCryptoEngine::new_from_env()` reads the key or seed, and the signing keys if they are set. `encrypt()` draws a random nonce, encrypts with AES-256-GCM and returns the nonce, ciphertext and tag in one buffer. `decrypt()` splits that buffer and fails if the tag does not match. With strict mode on, the engine keeps a set of the nonces it has used in this process and refuses one it has seen.

## Limits

- Not audited.
- Keys live in environment variables. That is a demo choice; a real deployment uses a secrets manager or an HSM.
- Keys are not zeroized. They stay in memory after use.
- The HKDF salt is fixed and labeled as a demo salt in the code. The derived key is one fixed key per seed, not a per-message key.
- Strict nonce mode is per engine instance and in memory. It is lost on restart, not shared across instances, and grows without bound.
- The mock engine's `verify()` always returns true.

## License

MIT. See [LICENSE](LICENSE).
