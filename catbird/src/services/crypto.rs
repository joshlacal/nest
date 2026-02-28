//! Cryptographic helpers for OAuth

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// A loaded signing key with its key ID
#[derive(Clone)]
pub struct SigningKey {
    pub kid: String,
    pub secret_key: SecretKey,
}

/// Store for multiple signing keys, supporting key rotation
#[derive(Clone)]
pub struct KeyStore {
    keys: HashMap<String, SecretKey>,
    active_key_id: String,
}

impl KeyStore {
    /// Create a new KeyStore from configuration
    pub fn from_config(state: &AppState) -> AppResult<Self> {
        let mut keys = HashMap::new();
        let oauth_config = &state.config.oauth;

        // Load keys from private_key_paths (multi-key mode)
        for path in &oauth_config.private_key_paths {
            let kid = derive_kid_from_path(path);
            let pem = fs::read_to_string(path)
                .map_err(|e| AppError::Config(format!("Failed to read key {}: {}", path, e)))?;
            let secret_key = SecretKey::from_pkcs8_pem(&pem)
                .map_err(|e| AppError::Crypto(format!("Failed to parse key {}: {}", path, e)))?;
            tracing::info!(kid = %kid, path = %path, "Loaded signing key");
            keys.insert(kid, secret_key);
        }

        // Load single key (backward compatibility) if no multi-key paths
        if keys.is_empty() {
            if let Some(secret_key) = load_legacy_key(oauth_config)? {
                let kid = "catbird-key-1".to_string();
                tracing::info!(kid = %kid, "Loaded legacy signing key");
                keys.insert(kid, secret_key);
            }
        }

        if keys.is_empty() {
            return Err(AppError::Config(
                "No OAuth private keys configured".to_string(),
            ));
        }

        let active_key_id = oauth_config.active_key_id.clone();

        // Validate active key exists
        if !keys.contains_key(&active_key_id) {
            return Err(AppError::Config(format!(
                "Active key '{}' not found in loaded keys: {:?}",
                active_key_id,
                keys.keys().collect::<Vec<_>>()
            )));
        }

        tracing::info!(
            active_key = %active_key_id,
            total_keys = %keys.len(),
            "KeyStore initialized"
        );

        Ok(Self { keys, active_key_id })
    }

    /// Get the active signing key (used for signing new JWTs)
    pub fn active_key(&self) -> SigningKey {
        SigningKey {
            kid: self.active_key_id.clone(),
            secret_key: self.keys.get(&self.active_key_id).unwrap().clone(),
        }
    }

    /// Get all keys (used for JWKS endpoint)
    pub fn all_keys(&self) -> Vec<SigningKey> {
        self.keys
            .iter()
            .map(|(kid, secret_key)| SigningKey {
                kid: kid.clone(),
                secret_key: secret_key.clone(),
            })
            .collect()
    }

    /// Get a specific key by kid
    pub fn get_key(&self, kid: &str) -> Option<SigningKey> {
        self.keys.get(kid).map(|secret_key| SigningKey {
            kid: kid.to_string(),
            secret_key: secret_key.clone(),
        })
    }

    /// Convert loaded keys into a Jacquard `Keyset` for OAuth client authentication.
    pub fn to_jacquard_keyset(&self) -> AppResult<jacquard_oauth::keyset::Keyset> {
        let jwks: Vec<jose_jwk::Jwk> = self
            .keys
            .iter()
            .map(|(kid, secret_key)| jose_jwk::Jwk {
                key: {
                    let crypto_key = jose_jwk::crypto::Key::from(secret_key.clone());
                    jose_jwk::Key::from(&crypto_key)
                },
                prm: jose_jwk::Parameters {
                    kid: Some(kid.clone()),
                    ..Default::default()
                },
            })
            .collect();

        jacquard_oauth::keyset::Keyset::try_from(jwks)
            .map_err(|e| AppError::Crypto(format!("Failed to create Jacquard keyset: {}", e)))
    }

    /// Convert all public keys to JWK format for JWKS endpoint
    pub fn to_jwks(&self) -> Vec<serde_json::Value> {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        
        self.all_keys()
            .iter()
            .map(|key| {
                let public_key = key.secret_key.public_key();
                let ec_point = public_key.to_encoded_point(false);
                let x = ec_point
                    .x()
                    .map(|bytes| b64.encode(bytes))
                    .unwrap_or_default();
                let y = ec_point
                    .y()
                    .map(|bytes| b64.encode(bytes))
                    .unwrap_or_default();

                serde_json::json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "use": "sig",
                    "kid": key.kid,
                    "x": x,
                    "y": y,
                })
            })
            .collect()
    }
}

/// Derive a key ID from a file path
/// e.g., "/path/to/key1.pem" -> "catbird-key1"
fn derive_kid_from_path(path: &str) -> String {
    let filename = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("key");
    
    // If filename already starts with "catbird-", use as-is
    if filename.starts_with("catbird-") {
        filename.to_string()
    } else {
        format!("catbird-{}", filename)
    }
}

/// Load a key using legacy single-key configuration
fn load_legacy_key(oauth_config: &crate::config::OAuthConfig) -> AppResult<Option<SecretKey>> {
    // Try base64-encoded key first
    if let Some(base64_pem) = &oauth_config.private_key_base64 {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(base64_pem)
            .map_err(|e| AppError::Config(format!("Invalid base64 private key: {}", e)))?;
        let pem = String::from_utf8(decoded)
            .map_err(|e| AppError::Config(format!("Invalid PEM encoding: {}", e)))?;
        let key = SecretKey::from_pkcs8_pem(&pem)
            .map_err(|e| AppError::Crypto(format!("Failed to parse private key: {}", e)))?;
        return Ok(Some(key));
    }

    // Try file path
    if let Some(path) = &oauth_config.private_key_path {
        let pem = fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("Failed to read private key: {}", e)))?;
        let key = SecretKey::from_pkcs8_pem(&pem)
            .map_err(|e| AppError::Crypto(format!("Failed to parse private key: {}", e)))?;
        return Ok(Some(key));
    }

    Ok(None)
}

