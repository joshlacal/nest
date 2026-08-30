//! AES-256-GCM encryption for Redis values with versioned envelopes and AAD.
//!
//! v2 sealed format: "v2:" || base64(nonce_12bytes || ciphertext || gcm_tag_16bytes)
//! v1 legacy format: base64(nonce_12bytes || ciphertext || gcm_tag_16bytes)

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use base64::Engine;

const NONCE_LEN: usize = 12;
pub const V2_PREFIX: &str = "v2:";

/// Routing and identity metadata stored in the cleartext header of a v2 envelope.
/// This metadata is fed into AES-256-GCM as AAD, making any header tampering fail decryption.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnvelopeMetadata {
    pub record_class: String,
    pub redis_key: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lineage: Option<String>,
}

impl EnvelopeMetadata {
    pub fn new(
        record_class: &str,
        redis_key: &str,
        did: Option<&str>,
        lineage: Option<&str>,
    ) -> Self {
        Self {
            record_class: record_class.to_string(),
            redis_key: redis_key.to_string(),
            did: did.map(String::from),
            lineage: lineage.map(String::from),
        }
    }

    pub fn to_aad(&self) -> Vec<u8> {
        build_aad(
            &self.record_class,
            &self.redis_key,
            self.did.as_deref(),
            self.lineage.as_deref(),
        )
    }
}

/// Constructs a canonical length-prefixed AAD binding record class, Redis key, DID, and lineage.
pub fn build_aad(
    record_class: &str,
    redis_key: &str,
    did: Option<&str>,
    lineage: Option<&str>,
) -> Vec<u8> {
    let mut aad = Vec::new();
    append_field(&mut aad, record_class.as_bytes());
    append_field(&mut aad, redis_key.as_bytes());
    append_field(&mut aad, did.unwrap_or("").as_bytes());
    append_field(&mut aad, lineage.unwrap_or("").as_bytes());
    aad
}

fn append_field(buf: &mut Vec<u8>, field: &[u8]) {
    let len = field.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(field);
}

fn seal_with_rng_aad<R: RngCore>(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    mut rng: R,
) -> Result<String, SealError> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key length");

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| SealError::RandomnessFailed)?;
    let nonce = Nonce::from(nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| SealError::EncryptionFailed)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce_bytes);
    sealed.extend_from_slice(&ciphertext);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&sealed);
    Ok(format!("{V2_PREFIX}{b64}"))
}

/// Encrypt plaintext with AES-256-GCM and AAD. Returns "v2:" || base64(nonce || ciphertext).
pub fn seal_with_aad(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<String, SealError> {
    seal_with_rng_aad(key, plaintext, aad, OsRng)
}

/// Dual-read decryptor for persistent session records.
/// Returns `(plaintext_bytes, is_legacy_v1)`.
/// If the record is v1, the caller MUST re-encrypt and store as v2 immediately.
pub fn open_session_dual_read(
    key: &[u8; 32],
    sealed_str: &str,
    aad: &[u8],
) -> Result<(Vec<u8>, bool), SealError> {
    let is_v2 = sealed_str.starts_with(V2_PREFIX);
    let raw_b64 = if is_v2 {
        &sealed_str[V2_PREFIX.len()..]
    } else {
        sealed_str
    };

    let sealed = base64::engine::general_purpose::STANDARD
        .decode(raw_b64)
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

    let effective_aad = if is_v2 { aad } else { &[] };
    let payload = Payload {
        msg: ciphertext,
        aad: effective_aad,
    };

    let bytes = cipher
        .decrypt(&nonce, payload)
        .map_err(|_| SealError::DecryptionFailed)?;
    Ok((bytes, !is_v2))
}

/// Decrypt sealed data with AES-256-GCM and AAD. Supports dual-read for legacy v1 format.
pub fn open_with_aad(key: &[u8; 32], sealed_str: &str, aad: &[u8]) -> Result<Vec<u8>, SealError> {
    open_session_dual_read(key, sealed_str, aad).map(|(bytes, _)| bytes)
}
/// Encrypt plaintext without AAD (uses empty AAD).
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<String, SealError> {
    seal_with_aad(key, plaintext, &[])
}

/// Decrypt sealed data without AAD (uses empty AAD).
pub fn open(key: &[u8; 32], sealed_b64: &str) -> Result<Vec<u8>, SealError> {
    open_with_aad(key, sealed_b64, &[])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    InvalidBase64,
    TooShort,
    DecryptionFailed,
    EncryptionFailed,
    InvalidUtf8,
    RandomnessFailed,
    LegacyV1Rejected,
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
            SealError::LegacyV1Rejected => write!(f, "legacy v1 format strictly rejected"),
        }
    }
}

impl std::error::Error for SealError {}

/// Encrypt a string with AES-256-GCM in a v2 envelope carrying authenticated routing metadata in its header.
pub fn seal_v2_with_metadata(
    key: &[u8; 32],
    plaintext: &str,
    metadata: &EnvelopeMetadata,
) -> Result<String, SealError> {
    let header_json = serde_json::to_vec(metadata).map_err(|_| SealError::EncryptionFailed)?;
    let header_b64 = base64::engine::general_purpose::STANDARD.encode(&header_json);
    let aad = metadata.to_aad();

    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key length");
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| SealError::RandomnessFailed)?;
    let nonce = Nonce::from(nonce_bytes);

    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| SealError::EncryptionFailed)?;

    let mut payload_bytes = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    payload_bytes.extend_from_slice(&nonce_bytes);
    payload_bytes.extend_from_slice(&ciphertext);

    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload_bytes);
    Ok(format!("{V2_PREFIX}{header_b64}:{payload_b64}"))
}

/// Decrypt a v2 envelope with authenticated routing metadata.
/// Validates that `metadata.record_class` and `metadata.redis_key` match expected values.
/// Returns `(plaintext, metadata, is_legacy_v1)`.
/// For non-session records, legacy v1 format is strictly rejected.
pub fn open_v2_with_metadata(
    key: &[u8; 32],
    sealed_str: &str,
    expected_record_class: &str,
    expected_redis_key: &str,
) -> Result<(String, EnvelopeMetadata, bool), SealError> {
    if !sealed_str.starts_with(V2_PREFIX) {
        // v1 legacy format: only permitted for session class dual-read
        if expected_record_class == "session" {
            let sealed = base64::engine::general_purpose::STANDARD
                .decode(sealed_str)
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
            let payload = Payload {
                msg: ciphertext,
                aad: &[],
            };
            let bytes = cipher
                .decrypt(&nonce, payload)
                .map_err(|_| SealError::DecryptionFailed)?;
            let text = String::from_utf8(bytes).map_err(|_| SealError::InvalidUtf8)?;
            return Ok((
                text,
                EnvelopeMetadata::new(expected_record_class, expected_redis_key, None, None),
                true,
            ));
        } else {
            return Err(SealError::LegacyV1Rejected);
        }
    }

    let rest = &sealed_str[V2_PREFIX.len()..];
    if let Some((header_b64, payload_b64)) = rest.split_once(':') {
        let header_json = base64::engine::general_purpose::STANDARD
            .decode(header_b64)
            .map_err(|_| SealError::InvalidBase64)?;
        let metadata: EnvelopeMetadata =
            serde_json::from_slice(&header_json).map_err(|_| SealError::DecryptionFailed)?;

        if metadata.record_class != expected_record_class || metadata.redis_key != expected_redis_key {
            return Err(SealError::DecryptionFailed);
        }

        let sealed = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
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

        let aad = metadata.to_aad();
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };

        let bytes = cipher
            .decrypt(&nonce, payload)
            .map_err(|_| SealError::DecryptionFailed)?;
        let text = String::from_utf8(bytes).map_err(|_| SealError::InvalidUtf8)?;
        Ok((text, metadata, false))
    } else {
        // v2 legacy single-blob format (direct AAD)
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(rest)
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

        let aad = build_aad(expected_record_class, expected_redis_key, None, None);
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };
        let bytes = cipher
            .decrypt(&nonce, payload)
            .map_err(|_| SealError::DecryptionFailed)?;
        let text = String::from_utf8(bytes).map_err(|_| SealError::InvalidUtf8)?;
        Ok((
            text,
            EnvelopeMetadata::new(expected_record_class, expected_redis_key, None, None),
            false,
        ))
    }
}

/// Strictly encrypt a string plaintext with AES-256-GCM and AAD.
pub fn seal_strict_with_aad(
    key: &[u8; 32],
    plaintext: &str,
    aad: &[u8],
) -> Result<String, SealError> {
    seal_with_aad(key, plaintext.as_bytes(), aad)
}

/// Strictly decrypt a sealed string with AES-256-GCM and AAD.
/// Strictly enforces the "v2:" prefix envelope and rejects legacy v1 format.
pub fn open_strict_with_aad(
    key: &[u8; 32],
    sealed_str: &str,
    aad: &[u8],
) -> Result<String, SealError> {
    if !sealed_str.starts_with(V2_PREFIX) {
        return Err(SealError::LegacyV1Rejected);
    }
    let raw_b64 = &sealed_str[V2_PREFIX.len()..];
    if let Some((header_b64, payload_b64)) = raw_b64.split_once(':') {
        let header_json = base64::engine::general_purpose::STANDARD
            .decode(header_b64)
            .map_err(|_| SealError::InvalidBase64)?;
        let metadata: EnvelopeMetadata =
            serde_json::from_slice(&header_json).map_err(|_| SealError::DecryptionFailed)?;
        let header_aad = metadata.to_aad();
        if !aad.is_empty() && header_aad != aad {
            return Err(SealError::DecryptionFailed);
        }
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
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
        let payload = Payload {
            msg: ciphertext,
            aad: &header_aad,
        };
        let bytes = cipher
            .decrypt(&nonce, payload)
            .map_err(|_| SealError::DecryptionFailed)?;
        String::from_utf8(bytes).map_err(|_| SealError::InvalidUtf8)
    } else {
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(raw_b64)
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

        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        let bytes = cipher
            .decrypt(&nonce, payload)
            .map_err(|_| SealError::DecryptionFailed)?;
        String::from_utf8(bytes).map_err(|_| SealError::InvalidUtf8)
    }
}

/// Strictly encrypt a string plaintext with AES-256-GCM.
pub fn seal_strict(key: &[u8; 32], plaintext: &str) -> Result<String, SealError> {
    seal_strict_with_aad(key, plaintext, &[])
}

/// Strictly decrypt a sealed string with AES-256-GCM.
pub fn open_strict(key: &[u8; 32], sealed_b64: &str) -> Result<String, SealError> {
    open_strict_with_aad(key, sealed_b64, &[])
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
        assert_eq!(
            open_strict(&key, plaintext).unwrap_err(),
            SealError::LegacyV1Rejected
        );

        // Fails on corrupted/invalid base64 with v2 prefix
        assert_eq!(
            open_strict(&key, "v2:not-valid-base64!").unwrap_err(),
            SealError::InvalidBase64
        );

        // Fails when sealed data is too short
        let too_short_b64 = base64::engine::general_purpose::STANDARD.encode(&[0u8; 10]);
        assert_eq!(
            open_strict(&key, &format!("{V2_PREFIX}{too_short_b64}")).unwrap_err(),
            SealError::TooShort
        );
    }
    #[test]
    fn seal_randomness_failure() {
        let key = [0x42u8; 32];
        let plaintext = b"payload";
        let err = seal_with_rng_aad(&key, plaintext, &[], FailingRng).unwrap_err();
        assert_eq!(err, SealError::RandomnessFailed);
    }

    #[test]
    fn test_aad_binding_and_transplantation_rejection() {
        let key = [0x55u8; 32];
        let plaintext = "secret_session_payload";

        let aad_session = build_aad("session", "catbird:v2:session:fp1", Some("did:plc:alice"), None);
        let aad_upgrade = build_aad("upgrade_candidate", "catbird:v2:upgrade_candidate:fp2", Some("did:plc:bob"), Some("sess_old"));

        let sealed = seal_strict_with_aad(&key, plaintext, &aad_session).unwrap();
        assert!(sealed.starts_with(V2_PREFIX));

        // Decrypt with identical AAD succeeds
        let decrypted = open_strict_with_aad(&key, &sealed, &aad_session).unwrap();
        assert_eq!(decrypted, plaintext);

        // Decrypt with transplanted AAD (different record class / key / did / lineage) fails
        let err = open_strict_with_aad(&key, &sealed, &aad_upgrade).unwrap_err();
        assert_eq!(err, SealError::DecryptionFailed);

        // Decrypt with different DID fails
        let aad_wrong_did = build_aad("session", "catbird:v2:session:fp1", Some("did:plc:eve"), None);
        assert_eq!(
            open_strict_with_aad(&key, &sealed, &aad_wrong_did).unwrap_err(),
            SealError::DecryptionFailed
        );

        // Decrypt with different key fails
        let aad_wrong_key = build_aad("session", "catbird:v2:session:fp2", Some("did:plc:alice"), None);
        assert_eq!(
            open_strict_with_aad(&key, &sealed, &aad_wrong_key).unwrap_err(),
            SealError::DecryptionFailed
        );
    }

    #[test]
    fn test_legacy_v1_dual_read_support() {
        let key = [0x55u8; 32];
        let plaintext = "legacy_v1_data";

        // Construct a raw v1 (no "v2:" prefix) ciphertext
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from([0x01u8; 12]);
        let ct = cipher.encrypt(&nonce, plaintext.as_bytes()).unwrap();
        let mut raw = Vec::new();
        raw.extend_from_slice(&[0x01u8; 12]);
        raw.extend_from_slice(&ct);
        let v1_sealed = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert!(!v1_sealed.starts_with(V2_PREFIX));

        // open_session_dual_read accepts legacy v1 under dual-read disposition
        let aad = build_aad("session", "catbird:v2:session:fp1", Some("did:plc:alice"), None);
        let (decrypted_bytes, is_v1) = open_session_dual_read(&key, &v1_sealed, &aad).unwrap();
        assert!(is_v1);
        assert_eq!(decrypted_bytes, plaintext.as_bytes());

        // open_v2_with_metadata accepts legacy v1 for "session" record class
        let (decrypted_str, meta, is_v1_meta) = open_v2_with_metadata(
            &key,
            &v1_sealed,
            "session",
            "catbird:v2:session:fp1",
        )
        .unwrap();
        assert!(is_v1_meta);
        assert_eq!(decrypted_str, plaintext);
        assert_eq!(meta.record_class, "session");

        // open_v2_with_metadata strictly rejects legacy v1 for non-session record classes
        let err = open_v2_with_metadata(
            &key,
            &v1_sealed,
            "upgrade_flow",
            "catbird:v2:upgrade_flow:fp1",
        )
        .unwrap_err();
        assert_eq!(err, SealError::LegacyV1Rejected);

        // open_strict_with_aad strictly rejects legacy v1
        let strict_err = open_strict_with_aad(&key, &v1_sealed, &aad).unwrap_err();
        assert_eq!(strict_err, SealError::LegacyV1Rejected);
    }

    #[test]
    fn test_v2_envelope_metadata_aad_roundtrip() {
        let key = [0x55u8; 32];
        let plaintext = "secret_payload";
        let metadata = EnvelopeMetadata::new(
            "upgrade_candidate",
            "catbird:v2:upgrade_candidate:fp1",
            Some("did:plc:alice"),
            Some("session_old_123"),
        );

        let sealed = seal_v2_with_metadata(&key, plaintext, &metadata).unwrap();
        assert!(sealed.starts_with(V2_PREFIX));

        // Successful open with matching class and key
        let (opened_text, opened_meta, is_v1) = open_v2_with_metadata(
            &key,
            &sealed,
            "upgrade_candidate",
            "catbird:v2:upgrade_candidate:fp1",
        )
        .unwrap();
        assert!(!is_v1);
        assert_eq!(opened_text, plaintext);
        assert_eq!(opened_meta, metadata);

        // Fails if expected record_class mismatches
        let err_class = open_v2_with_metadata(
            &key,
            &sealed,
            "session",
            "catbird:v2:upgrade_candidate:fp1",
        )
        .unwrap_err();
        assert_eq!(err_class, SealError::DecryptionFailed);

        // Fails if expected redis_key mismatches (anti-transplantation)
        let _err_key = open_v2_with_metadata(
            &key,
            &sealed,
            "upgrade_candidate",
            "catbird:v2:upgrade_candidate:fp2",
        )
        .unwrap_err();
    }

    #[test]
    fn test_envelope_metadata_header_tampering_rejected() {
        let key = [0x55u8; 32];
        let plaintext = "secret_payload";
        let metadata = EnvelopeMetadata::new(
            "upgrade_flow",
            "catbird:v2:upgrade_flow:fp1",
            Some("did:plc:alice"),
            Some("hmac_lineage_fp_123"),
        );

        let sealed = seal_v2_with_metadata(&key, plaintext, &metadata).unwrap();
        
        // Header tampering: change lineage in the clear header
        let rest = &sealed[V2_PREFIX.len()..];
        let (header_b64, payload_b64) = rest.split_once(':').unwrap();
        let header_json: Vec<u8> = base64::engine::general_purpose::STANDARD.decode(header_b64).unwrap();
        let mut tampered_meta: EnvelopeMetadata = serde_json::from_slice(&header_json).unwrap();
        tampered_meta.lineage = Some("hmac_lineage_fp_456_tampered".into());
        let tampered_header_b64 = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&tampered_meta).unwrap());
        let tampered_sealed = format!("{V2_PREFIX}{tampered_header_b64}:{payload_b64}");

        // Decryption fails with AAD mismatch
        let err = open_v2_with_metadata(
            &key,
            &tampered_sealed,
            "upgrade_flow",
            "catbird:v2:upgrade_flow:fp1",
        ).unwrap_err();
        assert_eq!(err, SealError::DecryptionFailed);
    }
}
