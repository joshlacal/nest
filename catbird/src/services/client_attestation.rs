//! Client Attestation Provider for ATProto Space Hosts
//!
//! Generates short-lived (60s) ES256 client assertions signed with Nest's active KeyStore key.
//! Claims:
//! - `iss`: configured OAuth client_id
//! - `sub`: configured OAuth client_id
//! - `aud`: target space host service identifier (e.g. did:plc:...#atproto_space_host)
//! - `iat`: current unix timestamp
//! - `exp`: iat + 60
//! - `jti`: random unique nonce
//!
//! The provider returns the JWT only to the caller and NEVER stores or logs it.

use crate::config::AppState;
use crate::error::AppError;
use crate::services::KeyStore;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ClientAttestationError {
    #[error("Key store is not available in application state")]
    MissingKeyStore,
    #[error("Invalid audience: {0}")]
    InvalidAudience(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<ClientAttestationError> for AppError {
    fn from(err: ClientAttestationError) -> Self {
        match err {
            ClientAttestationError::MissingKeyStore => AppError::Config(err.to_string()),
            ClientAttestationError::InvalidAudience(msg) => AppError::BadRequest(msg),
            ClientAttestationError::Crypto(msg) => AppError::Crypto(msg),
            ClientAttestationError::Serialization(msg) => AppError::Internal(msg),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AttestationHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AttestationClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
    jti: String,
}

pub struct ClientAttestationProvider {
    key_store: Arc<KeyStore>,
    client_id: String,
}

impl ClientAttestationProvider {
    pub fn new(key_store: Arc<KeyStore>, client_id: impl Into<String>) -> Self {
        Self {
            key_store,
            client_id: client_id.into(),
        }
    }

    pub fn from_state(state: &AppState) -> Result<Self, ClientAttestationError> {
        let key_store = state
            .key_store
            .clone()
            .ok_or(ClientAttestationError::MissingKeyStore)?;
        let client_id = state.config.oauth.client_id.clone();
        Ok(Self::new(key_store, client_id))
    }

    /// Mints a fresh 60-second ES256 client attestation JWT addressed to `space_host_audience`.
    ///
    /// Never stores or logs the minted JWT.
    pub fn mint(&self, space_host_audience: &str) -> Result<String, ClientAttestationError> {
        let trimmed_aud = space_host_audience.trim();
        if trimmed_aud.is_empty() || trimmed_aud.contains('*') || trimmed_aud.contains(char::is_whitespace) {
            return Err(ClientAttestationError::InvalidAudience(
                format!("Invalid space host audience: {space_host_audience:?}")
            ));
        }

        let active_key = self.key_store.active_key();
        let now = Utc::now().timestamp();
        let exp = now + 60;
        let jti = Uuid::new_v4().to_string();

        let header = AttestationHeader {
            alg: "ES256".to_string(),
            typ: "JWT".to_string(),
            kid: active_key.kid,
        };

        let claims = AttestationClaims {
            iss: self.client_id.clone(),
            sub: self.client_id.clone(),
            aud: trimmed_aud.to_string(),
            iat: now,
            exp,
            jti,
        };

        let header_json = serde_json::to_vec(&header)
            .map_err(|e| ClientAttestationError::Serialization(e.to_string()))?;
        let claims_json = serde_json::to_vec(&claims)
            .map_err(|e| ClientAttestationError::Serialization(e.to_string()))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json);
        let signing_input = format!("{header_b64}.{claims_b64}");

        let signing_key = SigningKey::from(active_key.secret_key);
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{signing_input}.{signature_b64}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::signature::Verifier;

    fn configured_client_id() -> String {
        "https://api.catbird.blue".to_string()
    }

    fn test_key_store() -> KeyStore {
        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        KeyStore::from_key("catbird-key-1", secret_key)
    }

    fn decode_claim(token: &str, claim: &str) -> String {
        let payload = token.split('.').nth(1).expect("jwt payload segment");
        let bytes = URL_SAFE_NO_PAD.decode(payload).expect("payload decodes");
        let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("payload is json");
        claims[claim].as_str().unwrap_or_default().to_string()
    }

    fn decode_num_claim(token: &str, claim: &str) -> i64 {
        let payload = token.split('.').nth(1).expect("jwt payload segment");
        let bytes = URL_SAFE_NO_PAD.decode(payload).expect("payload decodes");
        let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("payload is json");
        claims[claim].as_i64().expect("numeric claim")
    }

    #[test]
    fn client_attestation_is_single_use_and_addressed_to_space_host() {
        let key_store = Arc::new(test_key_store());
        let attestation_provider = ClientAttestationProvider::new(key_store.clone(), configured_client_id());
        let jwt = attestation_provider.mint("did:plc:owner#atproto_space_host").unwrap();
        assert_eq!(decode_claim(&jwt, "iss"), configured_client_id());
        assert_eq!(decode_claim(&jwt, "sub"), configured_client_id());
        assert_eq!(decode_claim(&jwt, "aud"), "did:plc:owner#atproto_space_host");
        assert!(!decode_claim(&jwt, "jti").is_empty());

        let iat = decode_num_claim(&jwt, "iat");
        let exp = decode_num_claim(&jwt, "exp");
        assert_eq!(exp - iat, 60, "attestation exp must be iat + 60s");

        // Verify ES256 signature
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let signature = Signature::from_bytes(signature_bytes.as_slice().into()).unwrap();
        let signing_key = SigningKey::from(key_store.active_key().secret_key);
        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(signing_input.as_bytes(), &signature).is_ok());

        // Single-use: minting twice produces different jti and signatures
        let jwt2 = attestation_provider.mint("did:plc:owner#atproto_space_host").unwrap();
        assert_ne!(decode_claim(&jwt, "jti"), decode_claim(&jwt2, "jti"));
        assert_ne!(jwt, jwt2);
    }

    #[test]
    fn rejects_invalid_audiences() {
        let key_store = Arc::new(test_key_store());
        let attestation_provider = ClientAttestationProvider::new(key_store, configured_client_id());
        assert!(attestation_provider.mint("").is_err());
        assert!(attestation_provider.mint("   ").is_err());
        assert!(attestation_provider.mint("did:plc:owner#*").is_err());
        assert!(attestation_provider.mint("did:plc:owner with spaces").is_err());
    }
}
