//! AES-256-GCM encryption for Redis values.
//!
//! Sealed format: base64(nonce_12bytes || ciphertext || gcm_tag_16bytes)

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::Engine;

const NONCE_LEN: usize = 12;

fn seal_with_rng<R: RngCore>(
    key: &[u8; 32],
    plaintext: &[u8],
    mut rng: R,
) -> Result<String, SealError> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key length");

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| SealError::RandomnessFailed)?;
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| SealError::EncryptionFailed)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce_bytes);
    sealed.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&sealed))
}

/// Encrypt plaintext with AES-256-GCM. Returns base64(nonce || ciphertext).
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<String, SealError> {
    seal_with_rng(key, plaintext, OsRng)
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
    let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| SealError::DecryptionFailed)?;
    let nonce = Nonce::from(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key length");

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| SealError::DecryptionFailed)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    InvalidBase64,
    TooShort,
    DecryptionFailed,
    EncryptionFailed,
    InvalidUtf8,
    RandomnessFailed,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::InvalidBase64 => write!(f, "invalid base64 encoding"),
            SealError::TooShort => write!(f, "sealed data too short"),
            SealError::DecryptionFailed => write!(f, "decryption failed"),
            SealError::EncryptionFailed => write!(f, "encryption failed"),
            SealError::InvalidUtf8 => write!(f, "decrypted data is not valid UTF-8"),
            SealError::RandomnessFailed => write!(f, "randomness generation failed"),
        }
    }
}

impl std::error::Error for SealError {}

/// Strictly encrypt a string plaintext with AES-256-GCM.
/// Returns an error on failure without logging secret values or falling back to plaintext.
pub fn seal_strict(key: &[u8; 32], plaintext: &str) -> Result<String, SealError> {
    seal(key, plaintext.as_bytes())
}

/// Strictly decrypt a sealed string with AES-256-GCM.
/// Returns an error on failure without logging secret values or falling back to raw data.
pub fn open_strict(key: &[u8; 32], sealed_b64: &str) -> Result<String, SealError> {
    let bytes = open(key, sealed_b64)?;
    String::from_utf8(bytes).map_err(|_| SealError::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingRng;

    impl RngCore for FailingRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            panic!("unexpected call to fill_bytes");
        }
        fn try_fill_bytes(
            &mut self,
            _dest: &mut [u8],
        ) -> Result<(), aes_gcm::aead::rand_core::Error> {
            Err(aes_gcm::aead::rand_core::Error::new(Box::new(
                std::io::Error::new(std::io::ErrorKind::Other, "forced rng failure"),
            )))
        }
    }

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
    fn strict_round_trip_and_failures() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = r#"{"access_token":"strict_secret"}"#;

        let sealed = seal_strict(&key, plaintext).expect("seal_strict should succeed");
        assert_ne!(sealed, plaintext);

        let decrypted = open_strict(&key, &sealed).expect("open_strict should succeed");
        assert_eq!(decrypted, plaintext);

        // Fails with wrong key
        assert_eq!(
            open_strict(&wrong_key, &sealed).unwrap_err(),
            SealError::DecryptionFailed
        );

        // Fails on raw unencrypted input (no fallback)
        assert!(open_strict(&key, plaintext).is_err());

        // Fails on corrupted/invalid base64
        assert_eq!(
            open_strict(&key, "not-valid-base64!").unwrap_err(),
            SealError::InvalidBase64
        );

        // Fails when sealed data is too short
        let too_short_b64 = base64::engine::general_purpose::STANDARD.encode(&[0u8; 10]);
        assert_eq!(
            open_strict(&key, &too_short_b64).unwrap_err(),
            SealError::TooShort
        );
    }

    #[test]
    fn seal_randomness_failure() {
        let key = [0x42u8; 32];
        let plaintext = b"payload";
        let err = seal_with_rng(&key, plaintext, FailingRng).unwrap_err();
        assert_eq!(err, SealError::RandomnessFailed);
    }
}
