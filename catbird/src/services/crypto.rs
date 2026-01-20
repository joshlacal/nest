//! Cryptographic helpers for OAuth

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use base64::Engine;
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use std::fs;
use std::sync::Arc;

pub struct CryptoService {
    state: Arc<AppState>,
}

impl CryptoService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub fn load_private_key_pem(&self) -> AppResult<String> {
        if let Some(base64_pem) = &self.state.config.oauth.private_key_base64 {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(base64_pem)
                .map_err(|e| AppError::Config(format!("Invalid base64 private key: {}", e)))?;
            return String::from_utf8(decoded)
                .map_err(|e| AppError::Config(format!("Invalid PEM encoding: {}", e)));
        }

        if let Some(path) = &self.state.config.oauth.private_key_path {
            return fs::read_to_string(path)
                .map_err(|e| AppError::Config(format!("Failed to read private key: {}", e)));
        }

        Err(AppError::Config(
            "OAuth private key not configured".to_string(),
        ))
    }

    pub fn load_private_key(&self) -> AppResult<SecretKey> {
        let pem = self.load_private_key_pem()?;
        SecretKey::from_pkcs8_pem(&pem)
            .map_err(|e| AppError::Crypto(format!("Failed to parse private key: {}", e)))
    }
}
