use rand::{thread_rng, Rng};
use std::collections::HashSet;
use std::sync::Mutex;
use crate::TrustError;
use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Cryptographic operations trait
pub trait CryptoEngine {
    fn hash(&self, data: &[u8]) -> Result<String, TrustError>;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TrustError>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool;
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, TrustError>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, TrustError>;
}

/// Real AES-256-GCM implementation with HKDF(SHA-384) key derivation support
pub struct RealCryptoEngine {
    key: [u8; 32],
    strict_iv_policy: bool,
    used_nonces: Mutex<HashSet<[u8; 12]>>,
    // ECDSA P-256
    signing_key: Option<p256::ecdsa::SigningKey>,
    verifying_key: Option<p256::ecdsa::VerifyingKey>,
}

impl RealCryptoEngine {
    /// Construct from environment:
    /// - Prefer ZTL_ENC_KEY_B64 (or VITE_ENC_KEY_B64) as a 32-byte base64 key
    /// - Else derive from ZTL_ENC_SEED_B64 (or VITE_ENC_SEED_B64) via HKDF(SHA-384)
    pub fn new_from_env() -> Result<Self, TrustError> {
        Self::new_from_env_with_strict_iv_policy(false)
    }

    pub fn new_from_env_with_strict_iv_policy(strict: bool) -> Result<Self, TrustError> {
        let key = load_or_derive_key()?;
        let (sk, vk) = load_sign_keys_from_env()?;
        Ok(Self {
            key,
            strict_iv_policy: strict,
            used_nonces: Mutex::new(HashSet::new()),
            signing_key: sk,
            verifying_key: vk,
        })
    }

    /// Test-only hook: encrypt with an explicit IV; enforces IV uniqueness policy.
    #[cfg(test)]
    pub fn encrypt_with_iv(&self, data: &[u8], iv: [u8; 12]) -> Result<Vec<u8>, TrustError> {
        self.encrypt_inner(data, Some(iv))
    }

    fn encrypt_inner(&self, data: &[u8], explicit_iv: Option<[u8; 12]>) -> Result<Vec<u8>, TrustError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        // Build cipher
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| TrustError::CryptoError(format!("aes init: {e}")))?;

        // 96-bit random IV per encryption unless explicit IV provided (tests)
        let iv: [u8; 12] = if let Some(iv) = explicit_iv {
            iv
        } else {
            let mut rng = thread_rng();
            let mut tmp = [0u8; 12];
            rng.fill(&mut tmp);
            tmp
        };

        // Enforce IV uniqueness policy if enabled
        if self.strict_iv_policy {
            let mut guard = self
                .used_nonces
                .lock()
                .map_err(|_| TrustError::CryptoError("nonce set poisoned".into()))?;
            if !guard.insert(iv) {
                return Err(TrustError::CryptoError(
                    "IV reuse detected under strict policy".into(),
                ));
            }
        }

        // Encrypt; ciphertext includes the 16-byte tag appended
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&iv);
        let ciphertext_and_tag = cipher
            .encrypt(nonce, data)
            .map_err(|e| TrustError::CryptoError(format!("encrypt failed: {e}")))?;

        // Output format: [IV (12 bytes)] || [ciphertext || tag]
        let mut out = Vec::with_capacity(12 + ciphertext_and_tag.len());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ciphertext_and_tag);
        Ok(out)
    }
}

impl CryptoEngine for RealCryptoEngine {
    fn hash(&self, data: &[u8]) -> Result<String, TrustError> {
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(data);
        let result = hasher.finalize();
        Ok(format!("sha384:{}", hex::encode(result)))
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TrustError> {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::Signature as RawSignature;

        let sk = self
            .signing_key
            .as_ref()
            .ok_or_else(|| TrustError::ConfigError("signing key not configured".into()))?;
        let sig: RawSignature = sk.sign(data);
        let der = sig.to_der();
        Ok(der.as_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature as RawSignature, VerifyingKey};

        let vk: VerifyingKey = if let Some(v) = &self.verifying_key {
            v.clone()
        } else if let Some(sk) = &self.signing_key {
            sk.verifying_key().clone()
        } else {
            return false;
        };

        let parsed = RawSignature::from_der(signature);
        match parsed {
            Ok(sig) => vk.verify(data, &sig).is_ok(),
            Err(_) => false,
        }
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, TrustError> {
        self.encrypt_inner(data, None)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, TrustError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        if data.len() < 12 + 16 {
            return Err(TrustError::CryptoError(
                "ciphertext too short (need iv + tag)".into(),
            ));
        }
        let (iv_bytes, ct_and_tag) = data.split_at(12);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(iv_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| TrustError::CryptoError(format!("aes init: {e}")))?;

        cipher
            .decrypt(nonce, ct_and_tag)
            .map_err(|_| TrustError::CryptoError("decrypt failed: authentication error".into()))
    }
}

/// Mock implementation for prototype
pub struct MockCryptoEngine;

impl CryptoEngine for MockCryptoEngine {
    fn hash(&self, data: &[u8]) -> Result<String, TrustError> {
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(data);
        let result = hasher.finalize();
        Ok(format!("sha384:{}", hex::encode(result)))
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TrustError> {
        // Generate a unique signature by combining input data with random bytes
        let mut rng = thread_rng();
        let mut signature = vec![0u8; 64];

        // Use a combination of input data and random bytes
        for (i, byte) in signature.iter_mut().enumerate() {
            // Mix input data (if available) with random bytes
            *byte = if i < data.len() {
                data[i].wrapping_add(rng.gen())
            } else {
                rng.gen()
            };
        }

        Ok(signature)
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> bool {
        // Mock verification - always returns true for prototype
        true
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, TrustError> {
        // Mock AES-256 encryption - just return the data for prototype
        Ok(data.to_vec())
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, TrustError> {
        // Mock decryption - just return the data for prototype
        Ok(data.to_vec())
    }
}

// Add hex encoding dependency
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

fn load_or_derive_key() -> Result<[u8; 32], TrustError> {
    use std::env;
    // Try direct key first (base64)
    let key_b64 = env::var("ZTL_ENC_KEY_B64")
        .ok()
        .or_else(|| env::var("VITE_ENC_KEY_B64").ok());
    if let Some(k) = key_b64 {
        let raw = STANDARD.decode(k)
            .map_err(|e| TrustError::ConfigError(format!("invalid base64 key: {e}")))?;
        if raw.len() != 32 {
            return Err(TrustError::ConfigError(format!(
                "AES-256 key must be 32 bytes; got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        return Ok(out);
    }

    // Else derive from seed using HKDF(SHA-384)
    let seed_b64 = env::var("ZTL_ENC_SEED_B64")
        .ok()
        .or_else(|| env::var("VITE_ENC_SEED_B64").ok())
        .ok_or_else(|| {
            TrustError::ConfigError(
                "missing ZTL_ENC_KEY_B64/VITE_ENC_KEY_B64 or ZTL_ENC_SEED_B64/VITE_ENC_SEED_B64"
                    .into(),
            )
        })?;
    let seed = STANDARD.decode(seed_b64)
        .map_err(|e| TrustError::ConfigError(format!("invalid base64 seed: {e}")))?;

    use hkdf::Hkdf;
    use sha2::Sha384;
    let salt = b"ZTL-AES-256-GCM-Demo-Salt-v1";
    let info = b"ZTL|data-encryption-key|v1";
    let hk = Hkdf::<Sha384>::new(Some(salt), &seed);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| TrustError::ConfigError("HKDF expand failed".into()))?;
    Ok(okm)
}

fn load_sign_keys_from_env(
) -> Result<
    (
        Option<p256::ecdsa::SigningKey>,
        Option<p256::ecdsa::VerifyingKey>,
    ),
    TrustError,
> {
    use std::env;
    let priv_pem = env::var("ZTL_SIGN_PRIVKEY_PEM").ok();
    let pub_pem = env::var("ZTL_SIGN_PUBKEY_PEM").ok();

    let mut signing_key: Option<p256::ecdsa::SigningKey> = None;
    let mut verifying_key: Option<p256::ecdsa::VerifyingKey> = None;

    if let Some(pem) = priv_pem {
        use p256::pkcs8::DecodePrivateKey;
        // Try PKCS#8 first
        let sk_res = p256::ecdsa::SigningKey::from_pkcs8_pem(&pem);
        let sk = match sk_res {
            Ok(sk) => sk,
            Err(_) => {
                // Try SEC1 via SecretKey then convert
                let secret = p256::SecretKey::from_sec1_pem(&pem)
                    .map_err(|e| TrustError::ConfigError(format!("invalid SEC1 private key PEM: {e}")))?;
                p256::ecdsa::SigningKey::from(secret)
            }
        };
        verifying_key = Some(sk.verifying_key().clone());
        signing_key = Some(sk);
    }

    if let Some(pem) = pub_pem {
        use p256::pkcs8::DecodePublicKey;
        // If pub provided, parse and prefer it for verification (explicit)
        let vk = p256::ecdsa::VerifyingKey::from_public_key_pem(&pem)
            .map_err(|e| TrustError::ConfigError(format!("invalid public key PEM: {e}")))?;
        verifying_key = Some(vk);
    }

    Ok((signing_key, verifying_key))
}
