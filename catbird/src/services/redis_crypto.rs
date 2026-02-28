//! AES-256-GCM encryption for Redis values.
//!
//! Sealed format: base64(nonce_12bytes || ciphertext || gcm_tag_16bytes)

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::Engine;

const NONCE_LEN: usize = 12;

/// Encrypt plaintext with AES-256-GCM. Returns base64(nonce || ciphertext).
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<String, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key length");

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce_bytes);
    sealed.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&sealed))
}

/// Decrypt base64(nonce || ciphertext) with AES-256-GCM.
pub fn open(key: &[u8; 32], sealed_b64: &str) -> Result<Vec<u8>, SealError> {
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(sealed_b64)
        .map_err(|_| SealError::InvalidBase64)?;

    if sealed.len() < NONCE_LEN + 16 {
        return Err(SealError::TooShort);
    }

    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key length");

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SealError::DecryptionFailed)
}

#[derive(Debug)]
pub enum SealError {
    InvalidBase64,
    TooShort,
    DecryptionFailed,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::InvalidBase64 => write!(f, "invalid base64"),
            SealError::TooShort => write!(f, "sealed data too short"),
            SealError::DecryptionFailed => write!(f, "decryption failed"),
        }
    }
}

impl std::error::Error for SealError {}

/// Conditionally encrypt a value for Redis storage.
/// Returns the value unchanged if no key is configured.
pub fn encrypt_for_redis(key: Option<&[u8; 32]>, plaintext: &str) -> String {
    if let Some(key) = key {
        match seal(key, plaintext.as_bytes()) {
            Ok(sealed) => sealed,
            Err(e) => {
                tracing::error!(error = ?e, "Redis encryption failed, storing plaintext");
                plaintext.to_string()
            }
        }
    } else {
        plaintext.to_string()
    }
}

/// Conditionally decrypt a value read from Redis.
/// Falls back to returning the raw value if decryption fails (graceful migration).
pub fn decrypt_from_redis(key: Option<&[u8; 32]>, value: &str) -> String {
    if let Some(key) = key {
        match open(key, value) {
            Ok(plaintext) => String::from_utf8(plaintext).unwrap_or_else(|_| {
                tracing::warn!("Decrypted Redis value is not valid UTF-8");
                value.to_string()
            }),
            Err(_) => {
                // Graceful migration: treat as old unencrypted data
                tracing::debug!("Redis value not encrypted, using as-is (migration)");
                value.to_string()
            }
        }
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [0x42u8; 32];
        let plaintext = r#"{"access_token":"secret"}"#;
        let sealed = seal(&key, plaintext.as_bytes()).unwrap();
        assert_ne!(sealed, plaintext);
        let decrypted = open(&key, &sealed).unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn graceful_migration_unencrypted() {
        let key = [0x42u8; 32];
        let raw_json = r#"{"access_token":"secret"}"#;
        // Old unencrypted value should fall through gracefully
        let result = decrypt_from_redis(Some(&key), raw_json);
        assert_eq!(result, raw_json);
    }

    #[test]
    fn no_key_passthrough() {
        let plaintext = "hello";
        assert_eq!(encrypt_for_redis(None, plaintext), plaintext);
        assert_eq!(decrypt_from_redis(None, plaintext), plaintext);
    }
}
