//! MLS Service Authentication
//!
//! Generates service auth tokens for direct Gateway → MLS server communication.
//! Uses the Gateway's signing key to create JWTs that the MLS server can verify.

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::models::CatbirdSession;
use crate::services::CryptoService;
use super::atproto_client::MAX_RESPONSE_SIZE;
use base64::Engine;
use chrono::Utc;
use futures_util::StreamExt;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Service for generating MLS service auth tokens
pub struct MlsAuthService {
    state: Arc<AppState>,
}

impl MlsAuthService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Check if a lexicon is an MLS endpoint that should be routed directly
    pub fn is_mls_lexicon(lexicon: &str) -> bool {
        lexicon.starts_with("blue.catbird.mls.")
    }

    /// Check if direct MLS routing is enabled
    pub fn is_enabled(&self) -> bool {
        self.state.config.mls.service_url.is_some() 
            && self.state.config.mls.gateway_did.is_some()
    }

    /// Get the MLS service URL
    pub fn service_url(&self) -> Option<&str> {
        self.state.config.mls.service_url.as_deref()
    }

    /// Generate a service auth token for MLS requests
    ///
    /// Creates a JWT with:
    /// - iss: Gateway's DID (the signer)
    /// - sub: User's DID (the authenticated user)
    /// - aud: MLS service DID
    /// - lxm: The lexicon method being called
    /// - exp: Short expiration (2 minutes)
    pub fn generate_service_token(
        &self,
        session: &CatbirdSession,
        lexicon: &str,
    ) -> AppResult<String> {
        let gateway_did = self.state.config.mls.gateway_did.as_ref()
            .ok_or_else(|| AppError::Config("MLS gateway_did not configured".into()))?;

        let now = Utc::now().timestamp();

        let claims = json!({
            "iss": gateway_did,
            "sub": session.did,
            "aud": self.state.config.mls.service_did,
            "exp": now + 120,  // 2 minute expiry
            "iat": now,
            "lxm": lexicon,
            "jti": Uuid::new_v4().to_string(),
        });

        // Use KeyStore for signing if available
        if let Some(key_store) = &self.state.key_store {
            let active_key = key_store.active_key();
            let signing_key = SigningKey::from(&active_key.secret_key);
            return self.sign_jwt_with_kid(&claims, &signing_key, &active_key.kid);
        }

        // Fallback to legacy single key
        let crypto = CryptoService::new(self.state.clone());
        let secret_key = crypto.load_private_key()?;
        let signing_key = SigningKey::from(&secret_key);

        self.sign_jwt(&claims, &signing_key)
    }

    /// Sign a JWT with ES256 (legacy, no kid)
    fn sign_jwt(
        &self,
        claims: &serde_json::Value,
        signing_key: &SigningKey,
    ) -> AppResult<String> {
        self.sign_jwt_with_kid(claims, signing_key, "catbird-key-1")
    }

    /// Sign a JWT with ES256 and include kid in header
    fn sign_jwt_with_kid(
        &self,
        claims: &serde_json::Value,
        signing_key: &SigningKey,
        kid: &str,
    ) -> AppResult<String> {
        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // Build header with kid
        let header = json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": kid
        });

        // Encode header and payload
        let encoded_header = b64url.encode(
            serde_json::to_string(&header)
                .map_err(|e| AppError::Internal(e.to_string()))?
                .as_bytes()
        );
        let encoded_payload = b64url.encode(
            serde_json::to_string(claims)
                .map_err(|e| AppError::Internal(e.to_string()))?
                .as_bytes()
        );

        let signing_input = format!("{}.{}", encoded_header, encoded_payload);

        // Sign with ES256
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let encoded_signature = b64url.encode(signature.to_bytes());

        Ok(format!("{}.{}", signing_input, encoded_signature))
    }

    /// Make an authenticated request to the MLS service
    pub async fn proxy_request(
        &self,
        session: &CatbirdSession,
        method: reqwest::Method,
        lexicon: &str,
        query_string: Option<&str>,
        body: Option<bytes::Bytes>,
        content_type: Option<&str>,
    ) -> AppResult<(u16, reqwest::header::HeaderMap, bytes::Bytes)> {
        let service_url = self.service_url()
            .ok_or_else(|| AppError::Config("MLS service_url not configured".into()))?;

        // Build the URL
        let url = if let Some(qs) = query_string {
            format!("{}/xrpc/{}?{}", service_url, lexicon, qs)
        } else {
            format!("{}/xrpc/{}", service_url, lexicon)
        };

        // Generate service auth token
        let token = self.generate_service_token(session, lexicon)?;

        // Build request
        let mut request = self.state.http_client
            .request(method, &url)
            .header("Authorization", format!("Bearer {}", token));

        if let Some(ct) = content_type {
            request = request.header("Content-Type", ct);
        }

        if let Some(b) = body {
            request = request.body(b);
        }

        // Send request
        let response = request.send().await
            .map_err(|e| AppError::Internal(format!("MLS request failed: {}", e)))?;

        let status = response.status().as_u16();
        let headers = response.headers().clone();

        // Check Content-Length for size limits
        let content_length = headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        if let Some(len) = content_length {
            if len > MAX_RESPONSE_SIZE {
                return Err(AppError::ResponseTooLarge(format!(
                    "MLS response size {} bytes exceeds maximum allowed {} bytes",
                    len, MAX_RESPONSE_SIZE
                )));
            }
        }

        // Read response with size limit protection
        let mut stream = response.bytes_stream();
        let mut body_vec = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| AppError::Internal(format!("Failed to read MLS response: {}", e)))?;
            if body_vec.len() + chunk.len() > MAX_RESPONSE_SIZE {
                return Err(AppError::ResponseTooLarge(format!(
                    "MLS response exceeded maximum size of {} bytes while reading",
                    MAX_RESPONSE_SIZE
                )));
            }
            body_vec.extend_from_slice(&chunk);
        }

        let body = bytes::Bytes::from(body_vec);

        tracing::debug!(
            lexicon = %lexicon,
            status = %status,
            body_len = %body.len(),
            "MLS direct proxy response"
        );

        Ok((status, headers, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_mls_lexicon() {
        assert!(MlsAuthService::is_mls_lexicon("blue.catbird.mls.getConvos"));
        assert!(MlsAuthService::is_mls_lexicon("blue.catbird.mls.sendMessage"));
        assert!(!MlsAuthService::is_mls_lexicon("app.bsky.feed.getTimeline"));
        assert!(!MlsAuthService::is_mls_lexicon("chat.bsky.convo.listConvos"));
    }
}
