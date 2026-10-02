pub mod crypto_engine;

pub use crypto_engine::*;

/// Error types for the secure engine
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rand_core::OsRng;
    use std::env;

    #[test]
    fn test_mock_crypto_engine_hash() {
        let engine = MockCryptoEngine;
        let out = engine.hash(b"hello").unwrap();
        assert!(out.starts_with("sha384:"));
    }

    #[test]
    fn test_mock_crypto_engine_basic_functionality() {
        let engine = MockCryptoEngine;
        let test_data = b"test data for prototype";

        // Test signature generation - should produce 64-byte signatures
        let signature = engine.sign(test_data).unwrap();
        assert_eq!(signature.len(), 64, "Signature should be 64 bytes");
        assert!(
            !signature.iter().all(|&x| x == 0),
            "Signature should not be all zeros"
        );

        // Test verification - mock always returns true
        assert!(
            engine.verify(test_data, &signature),
            "Mock verification should always return true"
        );

        // Test encryption/decryption - mock returns input data
        let encrypted = engine.encrypt(test_data).unwrap();
        assert_eq!(
            encrypted, test_data,
            "Mock encryption should return input data"
        );

        let decrypted = engine.decrypt(&encrypted).unwrap();
        assert_eq!(
            decrypted, test_data,
            "Mock decryption should return input data"
        );

        // Test different inputs produce different signatures
        let sig1 = engine.sign(b"data1").unwrap();
        let sig2 = engine.sign(b"data2").unwrap();
        assert_ne!(
            sig1, sig2,
            "Different inputs should produce different signatures"
        );
    }

    #[test]
    fn test_aes_gcm_round_trip() {
        // Provide a deterministic seed via env (HKDF -> 32-byte key)
        let seed_b64 = STANDARD.encode("unit-test-seed-aes-gcm");
        env::set_var("ZTL_ENC_SEED_B64", seed_b64);
        env::remove_var("ZTL_ENC_KEY_B64");
        env::remove_var("VITE_ENC_KEY_B64");
        env::remove_var("VITE_ENC_SEED_B64");

        let engine = RealCryptoEngine::new_from_env_with_strict_iv_policy(true).unwrap();
        let plaintext = b"hello aes-gcm";
        let ciphertext = engine.encrypt(plaintext).unwrap();

        // Format: IV (12) || ciphertext+tag
        assert!(ciphertext.len() >= 12 + 16, "must contain IV + auth tag");
        assert_ne!(&ciphertext[12..], plaintext, "ciphertext must differ");

        let decrypted = engine.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_authentication_failure_on_tamper() {
        let seed_b64 = STANDARD.encode("unit-test-seed-aes-gcm-tamper");
        env::set_var("ZTL_ENC_SEED_B64", seed_b64);
        env::remove_var("ZTL_ENC_KEY_B64");
        env::remove_var("VITE_ENC_KEY_B64");
        env::remove_var("VITE_ENC_SEED_B64");

        let engine = RealCryptoEngine::new_from_env_with_strict_iv_policy(true).unwrap();
        let plaintext = b"secure data";
        let mut ciphertext = engine.encrypt(plaintext).unwrap();

        // Flip a bit in the last byte (tag/ciphertext)
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;
        let res = engine.decrypt(&ciphertext);
        assert!(res.is_err(), "tamper must fail authentication");
    }

    #[test]
    fn test_iv_reuse_policy_detects_duplicate() {
        let seed_b64 = STANDARD.encode("unit-test-seed-aes-gcm-iv-dup");
        env::set_var("ZTL_ENC_SEED_B64", seed_b64);
        env::remove_var("ZTL_ENC_KEY_B64");
        env::remove_var("VITE_ENC_KEY_B64");
        env::remove_var("VITE_ENC_SEED_B64");

        let engine = RealCryptoEngine::new_from_env_with_strict_iv_policy(true).unwrap();
        let iv = [7u8; 12];
        let pt1 = b"data-one";
        let pt2 = b"data-two";

        // First encrypt with IV should succeed
        let _c1 = engine.encrypt_with_iv(pt1, iv).unwrap();
        // Second encrypt with the same IV must fail under strict policy
        let c2 = engine.encrypt_with_iv(pt2, iv);
        assert!(c2.is_err(), "IV reuse must be rejected");
    }

    #[test]
    fn test_p256_sign_verify_success_and_tamper() {
        // Generate a fresh keypair and export to PEM envs
        let sk = SigningKey::random(&mut OsRng);
        let vk: VerifyingKey = *sk.verifying_key();

        // Export as PKCS#8 and SPKI PEM
        let priv_pem = sk
            .to_pkcs8_pem(LineEnding::LF)
            .expect("pkcs8 pem")
            .to_string();
        let pub_pem = vk
            .to_public_key_pem(LineEnding::LF)
            .expect("spki pem")
            .to_string();

        env::set_var("ZTL_SIGN_PRIVKEY_PEM", &priv_pem);
        env::set_var("ZTL_SIGN_PUBKEY_PEM", &pub_pem);

        // Ensure AES seed present for engine init
        let seed_b64 = STANDARD.encode("unit-test-seed-aes-gcm-p256");
        env::set_var("ZTL_ENC_SEED_B64", seed_b64);
        env::remove_var("ZTL_ENC_KEY_B64");

        let engine = RealCryptoEngine::new_from_env().unwrap();

        let msg = b"canonical-payload-bytes";
        let sig_der = engine.sign(msg).expect("sign");
        assert!(
            sig_der.len() >= 64 && sig_der.len() <= 72,
            "DER-encoded ECDSA signature length should be reasonable"
        );
        assert!(engine.verify(msg, &sig_der), "verify should succeed");

        let mut tampered = msg.to_vec();
        tampered[0] ^= 0x01;
        assert!(
            !engine.verify(&tampered, &sig_der),
            "verify should fail on tampered message"
        );
    }
}
