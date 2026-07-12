//! Authenticated, versioned encryption for Redis values.
//!
//! Envelope format: `v1:<kid>:<base64(nonce || ciphertext || tag)>`.

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ENVELOPE_VERSION: &str = "v1";
const AAD_DOMAIN: &[u8] = b"catbird-redis-envelope-v1";
pub const MAX_PREVIOUS_KEYS: usize = 3;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    kid: String,
    key: [u8; 32],
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyMaterial")
            .field("kid", &self.kid)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl KeyMaterial {
    pub fn new(kid: impl Into<String>, key: [u8; 32]) -> Result<Self, CryptoError> {
        let kid = kid.into();
        if kid.is_empty()
            || kid.len() > 32
            || !kid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CryptoError::InvalidKeyId);
        }
        Ok(Self { kid, key })
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Keyring {
    active: KeyMaterial,
    previous: Vec<KeyMaterial>,
    identifier_key: [u8; 32],
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Keyring")
            .field("active", &self.active)
            .field("previous_key_count", &self.previous.len())
            .field("identifier_key", &"[REDACTED]")
            .finish()
    }
}

impl Keyring {
    pub fn new(
        active: KeyMaterial,
        previous: Vec<KeyMaterial>,
        identifier_key: [u8; 32],
    ) -> Result<Self, CryptoError> {
        if previous.len() > MAX_PREVIOUS_KEYS {
            return Err(CryptoError::TooManyPreviousKeys);
        }
        if previous.iter().any(|key| key.kid == active.kid)
            || previous
                .iter()
                .enumerate()
                .any(|(index, key)| previous[..index].iter().any(|other| other.kid == key.kid))
        {
            return Err(CryptoError::DuplicateKeyId);
        }
        if identifier_key == active.key || previous.iter().any(|key| identifier_key == key.key) {
            return Err(CryptoError::IdentifierKeyReuse);
        }
        Ok(Self {
            active,
            previous,
            identifier_key,
        })
    }

    pub fn seal(
        &self,
        context: &RecordContext<'_>,
        plaintext: &[u8],
    ) -> Result<String, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.active.key)
            .map_err(|_| CryptoError::InvalidKeyLength)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let aad = context.aad();
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(format!(
            "{ENVELOPE_VERSION}:{}:{}",
            self.active.kid,
            base64::engine::general_purpose::STANDARD.encode(sealed)
        ))
    }

    pub fn open(
        &self,
        context: &RecordContext<'_>,
        envelope: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(self.open_with_status(context, envelope)?.plaintext)
    }

    pub fn open_with_status(
        &self,
        context: &RecordContext<'_>,
        envelope: &str,
    ) -> Result<OpenedRecord, CryptoError> {
        let mut parts = envelope.splitn(3, ':');
        if parts.next() != Some(ENVELOPE_VERSION) {
            return Err(CryptoError::UnknownVersion);
        }
        let kid = parts.next().ok_or(CryptoError::MalformedEnvelope)?;
        let encoded = parts.next().ok_or(CryptoError::MalformedEnvelope)?;
        let material = if self.active.kid == kid {
            &self.active
        } else {
            self.previous
                .iter()
                .find(|key| key.kid == kid)
                .ok_or(CryptoError::UnknownKeyId)?
        };
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| CryptoError::InvalidBase64)?;
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::TooShort);
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
        let cipher =
            Aes256Gcm::new_from_slice(&material.key).map_err(|_| CryptoError::InvalidKeyLength)?;
        let aad = context.aad();
        let nonce_bytes: [u8; NONCE_LEN] =
            nonce_bytes.try_into().map_err(|_| CryptoError::TooShort)?;
        let nonce = Nonce::from(nonce_bytes);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(OpenedRecord {
            plaintext,
            key_id: kid.to_string(),
            needs_rewrap: kid != self.active.kid,
        })
    }

    pub fn opaque_id(&self, domain: &str, logical_id: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hmac_sha256(
            &self.identifier_key,
            &[domain.as_bytes(), b"\0", logical_id.as_bytes()].concat(),
        ))
    }

    pub(crate) fn open_legacy_active(&self, encoded: &str) -> Result<Vec<u8>, CryptoError> {
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| CryptoError::InvalidBase64)?;
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::TooShort);
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::from(
            <[u8; NONCE_LEN]>::try_from(nonce_bytes).map_err(|_| CryptoError::TooShort)?,
        );
        Aes256Gcm::new_from_slice(&self.active.key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct OpenedRecord {
    pub plaintext: Vec<u8>,
    pub key_id: String,
    pub needs_rewrap: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct RecordContext<'a> {
    kind: &'a str,
    logical_key: &'a str,
}

impl<'a> RecordContext<'a> {
    pub fn new(kind: &'a str, logical_key: &'a str) -> Self {
        Self { kind, logical_key }
    }

    fn aad(&self) -> Vec<u8> {
        [
            AAD_DOMAIN,
            b"\0",
            self.kind.as_bytes(),
            b"\0",
            self.logical_key.as_bytes(),
        ]
        .concat()
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_LEN: usize = 64;
    let mut normalized = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK_LEN];
    let mut outer_pad = [0x5cu8; BLOCK_LEN];
    for index in 0..BLOCK_LEN {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let inner = Sha256::new()
        .chain_update(inner_pad)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(outer_pad)
        .chain_update(inner)
        .finalize()
        .into()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid key identifier")]
    InvalidKeyId,
    #[error("duplicate key identifier")]
    DuplicateKeyId,
    #[error("identifier HMAC key must be distinct from encryption keys")]
    IdentifierKeyReuse,
    #[error("too many previous keys")]
    TooManyPreviousKeys,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("unknown envelope version")]
    UnknownVersion,
    #[error("malformed encrypted envelope")]
    MalformedEnvelope,
    #[error("unknown encryption key identifier")]
    UnknownKeyId,
    #[error("invalid envelope base64")]
    InvalidBase64,
    #[error("encrypted envelope is too short")]
    TooShort,
    #[error("encrypted envelope authentication failed")]
    AuthenticationFailed,
    #[error("decrypted value is not UTF-8")]
    InvalidUtf8,
}

pub fn open_utf8_with_status(
    keyring: &Keyring,
    context: &RecordContext<'_>,
    envelope: &str,
) -> Result<(String, bool), CryptoError> {
    let opened = keyring.open_with_status(context, envelope)?;
    let plaintext = String::from_utf8(opened.plaintext).map_err(|_| CryptoError::InvalidUtf8)?;
    Ok((plaintext, opened.needs_rewrap))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_is_versioned_and_bound_to_record_context() {
        let keyring = Keyring::new(
            KeyMaterial::new("2026-07", [0x42; 32]).unwrap(),
            vec![],
            [0x24; 32],
        )
        .unwrap();
        let context = RecordContext::new("session", "catbird:session:opaque-a");
        let plaintext = r#"{"access_token":"secret"}"#;

        let envelope = keyring.seal(&context, plaintext.as_bytes()).unwrap();

        assert!(envelope.starts_with("v1:2026-07:"));
        assert_eq!(
            keyring.open(&context, &envelope).unwrap(),
            plaintext.as_bytes()
        );
        assert!(matches!(
            keyring.open(
                &RecordContext::new("auth_req", "catbird:session:opaque-a"),
                &envelope
            ),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert!(matches!(
            keyring.open(
                &RecordContext::new("session", "catbird:session:opaque-b"),
                &envelope
            ),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn invalid_and_plaintext_records_fail_closed_with_typed_errors() {
        let keyring = Keyring::new(
            KeyMaterial::new("active", [1; 32]).unwrap(),
            vec![],
            [2; 32],
        )
        .unwrap();
        let context = RecordContext::new("session", "logical");

        assert!(matches!(
            keyring.open(&context, r#"{"session_id":"plaintext"}"#),
            Err(CryptoError::UnknownVersion)
        ));
        assert!(matches!(
            keyring.open(&context, "v1:missing:AAAA"),
            Err(CryptoError::UnknownKeyId)
        ));
        assert!(matches!(
            keyring.open(&context, "v1:active:%%%"),
            Err(CryptoError::InvalidBase64)
        ));
        assert!(matches!(
            keyring.open(&context, "v1:active:AA=="),
            Err(CryptoError::TooShort)
        ));
    }

    #[test]
    fn key_rotation_reads_bounded_previous_keys_and_writes_active_key() {
        let previous = KeyMaterial::new("old", [3; 32]).unwrap();
        let old_ring = Keyring::new(previous.clone(), vec![], [9; 32]).unwrap();
        let context = RecordContext::new("session_index", "logical");
        let old_envelope = old_ring.seal(&context, b"did:plc:alice").unwrap();

        let rotated = Keyring::new(
            KeyMaterial::new("new", [4; 32]).unwrap(),
            vec![previous],
            [9; 32],
        )
        .unwrap();

        assert_eq!(
            rotated.open(&context, &old_envelope).unwrap(),
            b"did:plc:alice"
        );
        assert!(rotated
            .seal(&context, b"new")
            .unwrap()
            .starts_with("v1:new:"));
        assert!(matches!(
            Keyring::new(
                KeyMaterial::new("active", [1; 32]).unwrap(),
                (0..=MAX_PREVIOUS_KEYS)
                    .map(|i| KeyMaterial::new(format!("old-{i}"), [i as u8; 32]).unwrap())
                    .collect(),
                [2; 32]
            ),
            Err(CryptoError::TooManyPreviousKeys)
        ));
    }

    #[test]
    fn opaque_identifiers_do_not_expose_bearer_values() {
        let keyring = Keyring::new(
            KeyMaterial::new("active", [1; 32]).unwrap(),
            vec![],
            [2; 32],
        )
        .unwrap();

        let opaque = keyring.opaque_id("session-index", "live-session-secret");
        assert!(!opaque.contains("live-session-secret"));
        assert_eq!(
            opaque,
            keyring.opaque_id("session-index", "live-session-secret")
        );
        assert_ne!(
            opaque,
            keyring.opaque_id("auth-request", "live-session-secret")
        );
    }

    #[test]
    fn identifier_key_must_be_distinct_from_all_encryption_keys() {
        let active = KeyMaterial::new("active", [1; 32]).unwrap();
        assert!(matches!(
            Keyring::new(active.clone(), vec![], [1; 32]),
            Err(CryptoError::IdentifierKeyReuse)
        ));
        assert!(matches!(
            Keyring::new(
                active,
                vec![KeyMaterial::new("previous", [2; 32]).unwrap()],
                [2; 32]
            ),
            Err(CryptoError::IdentifierKeyReuse)
        ));
    }

    #[test]
    fn previous_key_open_reports_rewrap_and_removed_key_rejects_after_rewrap() {
        let context = RecordContext::new("session", "opaque-key");
        let previous = KeyMaterial::new("old", [3; 32]).unwrap();
        let old = Keyring::new(previous.clone(), vec![], [9; 32]).unwrap();
        let envelope = old.seal(&context, b"record").unwrap();
        let rotated = Keyring::new(
            KeyMaterial::new("new", [4; 32]).unwrap(),
            vec![previous],
            [9; 32],
        )
        .unwrap();

        let opened = rotated.open_with_status(&context, &envelope).unwrap();
        assert!(opened.needs_rewrap);
        assert_eq!(opened.key_id, "old");
        let rewrapped = rotated.seal(&context, &opened.plaintext).unwrap();
        assert!(rewrapped.starts_with("v1:new:"));

        let after_removal =
            Keyring::new(KeyMaterial::new("new", [4; 32]).unwrap(), vec![], [9; 32]).unwrap();
        assert!(matches!(
            after_removal.open(&context, &envelope),
            Err(CryptoError::UnknownKeyId)
        ));
        assert_eq!(after_removal.open(&context, &rewrapped).unwrap(), b"record");
    }

    #[test]
    fn key_material_debug_output_never_contains_secret_bytes() {
        let material = KeyMaterial::new("active", [0x5a; 32]).unwrap();
        let debug = format!("{material:?}");
        assert!(!debug.contains("90, 90"));
        assert!(debug.contains("active"));
    }
}
