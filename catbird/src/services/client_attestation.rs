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
        if space_host_audience.is_empty()
            || space_host_audience != space_host_audience.trim()
            || space_host_audience.contains('*')
            || space_host_audience.contains(char::is_whitespace)
        {
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
            aud: space_host_audience.to_string(),
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

    fn test_multi_key_store() -> (KeyStore, String, String) {
        let legacy_key_id = "catbird-legacy-key-1".to_string();
        let active_key_id = "catbird-active-key-2".to_string();
        let legacy_secret = p256::SecretKey::random(&mut rand::thread_rng());
        let active_secret = p256::SecretKey::random(&mut rand::thread_rng());

        let store = KeyStore::from_keys(
            vec![
                (legacy_key_id.clone(), legacy_secret),
                (active_key_id.clone(), active_secret),
            ],
            &active_key_id,
        );
        (store, legacy_key_id, active_key_id)
    }

    fn decode_header(token: &str) -> serde_json::Value {
        let header_b64 = token.split('.').next().expect("jwt header segment");
        let bytes = URL_SAFE_NO_PAD.decode(header_b64).expect("header decodes");
        serde_json::from_slice(&bytes).expect("header is json")
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
        let (key_store_raw, legacy_key_id, active_key_id) = test_multi_key_store();
        let key_store = Arc::new(key_store_raw);
        let attestation_provider = ClientAttestationProvider::new(key_store.clone(), configured_client_id());
        let jwt = attestation_provider.mint("did:plc:owner#atproto_space_host").unwrap();

        // JOSE protected header assertions
        let header = decode_header(&jwt);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], active_key_id.as_str());
        assert_eq!(header["kid"], key_store.active_key().kid.as_str());
        assert_ne!(header["kid"], legacy_key_id.as_str());

        // Payload assertions
        assert_eq!(decode_claim(&jwt, "iss"), configured_client_id());
        assert_eq!(decode_claim(&jwt, "sub"), configured_client_id());
        assert_eq!(decode_claim(&jwt, "aud"), "did:plc:owner#atproto_space_host");
        assert!(!decode_claim(&jwt, "jti").is_empty());

        let iat = decode_num_claim(&jwt, "iat");
        let exp = decode_num_claim(&jwt, "exp");
        assert_eq!(exp - iat, 60, "attestation exp must be iat + 60s");

        // Verify ES256 signature with active key
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let signature = Signature::from_bytes(signature_bytes.as_slice().into()).unwrap();
        let active_signing_key = SigningKey::from(key_store.active_key().secret_key);
        let active_verifying_key = active_signing_key.verifying_key();
        assert!(active_verifying_key.verify(signing_input.as_bytes(), &signature).is_ok());

        // Verify signature check fails with legacy/inactive key
        let legacy_key = key_store.get_key(&legacy_key_id).unwrap();
        let legacy_signing_key = SigningKey::from(legacy_key.secret_key);
        let legacy_verifying_key = legacy_signing_key.verifying_key();
        assert!(legacy_verifying_key.verify(signing_input.as_bytes(), &signature).is_err());

        // Single-use: minting twice produces different jti and signatures
        let jwt2 = attestation_provider.mint("did:plc:owner#atproto_space_host").unwrap();
        assert_ne!(decode_claim(&jwt, "jti"), decode_claim(&jwt2, "jti"));
        assert_ne!(jwt, jwt2);
    }

    #[test]
    fn rejects_invalid_audiences() {
        let (key_store_raw, _, _) = test_multi_key_store();
        let key_store = Arc::new(key_store_raw);
        let attestation_provider = ClientAttestationProvider::new(key_store, configured_client_id());
        assert!(attestation_provider.mint("").is_err());
        assert!(attestation_provider.mint("   ").is_err());
        assert!(attestation_provider.mint("did:plc:owner#*").is_err());
        assert!(attestation_provider.mint("did:plc:owner with spaces").is_err());
        assert!(attestation_provider.mint(" did:plc:owner#atproto_space_host").is_err());
        assert!(attestation_provider.mint("did:plc:owner#atproto_space_host ").is_err());
        assert!(attestation_provider.mint("did:plc:owner#atproto_space_host\n").is_err());
    }
}
