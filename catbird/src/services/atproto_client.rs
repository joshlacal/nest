//! ATProto Client Service
//!
//! Handles communication with ATProto PDS servers, including:
//! - OAuth token management (refresh, DPoP)
//! - Request proxying
//! - Token refresh logic

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::models::{CatbirdSession, DPoPKeyPair};
use chrono::{Duration, Utc};
use redis::AsyncCommands;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::sync::Arc;

/// ATProto client for making authenticated requests to PDS
pub struct AtProtoClient {
    state: Arc<AppState>,
}

impl AtProtoClient {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Make an authenticated GET request to the user's PDS
    pub async fn get(
        &self,
        session: &CatbirdSession,
        path: &str,
        query_params: Option<&[(String, String)]>,
    ) -> AppResult<Value> {
        let url = format!("{}{}", session.pds_url, path);

        let mut request = self.state.http_client.get(&url);

        if let Some(params) = query_params {
            request = request.query(params);
        }

        let headers = self
            .build_auth_headers_for_request(session, "GET", &url)
            .await?;
        request = request.headers(headers);

        let response = request.send().await?;
        self.handle_response(response).await
    }

    /// Make an authenticated POST request to the user's PDS
    pub async fn post(
        &self,
        session: &CatbirdSession,
        path: &str,
        body: Value,
    ) -> AppResult<Value> {
        let url = format!("{}{}", session.pds_url, path);

        let headers = self
            .build_auth_headers_for_request(session, "POST", &url)
            .await?;

        let response = self
            .state
            .http_client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        self.handle_response(response).await
    }

    /// Proxy a raw request to the PDS, preserving method and body
    pub async fn proxy_request(
        &self,
        session: &CatbirdSession,
        method: reqwest::Method,
        path: &str,
        query_string: Option<&str>,
        body: Option<bytes::Bytes>,
        content_type: Option<&str>,
    ) -> AppResult<(u16, HeaderMap, bytes::Bytes)> {
        let url = if let Some(qs) = query_string {
            format!("{}{}?{}", session.pds_url, path, qs)
        } else {
            format!("{}{}", session.pds_url, path)
        };

        let mut headers = self
            .build_auth_headers_for_request(session, method.as_str(), &url)
            .await?;

        if let Some(ct) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(ct).unwrap());
        }

        let mut request = self
            .state
            .http_client
            .request(method, &url)
            .headers(headers);

        if let Some(b) = body {
            request = request.body(b);
        }

        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    "Request failed to {}: {:?} (is_builder: {}, is_request: {}, is_connect: {}, is_body: {})",
                    url,
                    e,
                    e.is_builder(),
                    e.is_request(),
                    e.is_connect(),
                    e.is_body()
                );
                return Err(e.into());
            }
        };

        let status = response.status().as_u16();
        let response_headers = response.headers().clone();
        let body = response.bytes().await?;

        Ok((status, response_headers, body))
    }

    /// Build authentication headers including DPoP if needed
    async fn build_auth_headers(&self, session: &CatbirdSession) -> AppResult<HeaderMap> {
        self.build_auth_headers_for_request(session, "GET", &session.pds_url)
            .await
    }

    /// Build authentication headers with DPoP for a specific request
    pub async fn build_auth_headers_for_request(
        &self,
        session: &CatbirdSession,
        method: &str,
        url: &str,
    ) -> AppResult<HeaderMap> {
        let mut headers = HeaderMap::new();

        // If we have a DPoP key, generate a DPoP proof
        if let Some(ref dpop_jkt) = session.dpop_jkt {
            // Generate DPoP proof JWT
            let dpop_proof = self.generate_dpop_proof(session, method, url).await?;

            // Use DPoP token scheme (not Bearer)
            let auth_value = format!("DPoP {}", session.access_token);
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_value)
                    .map_err(|e| AppError::Internal(e.to_string()))?,
            );

            // Add DPoP proof header
            headers.insert(
                "DPoP",
                HeaderValue::from_str(&dpop_proof)
                    .map_err(|e| AppError::Internal(e.to_string()))?,
            );
        } else {
            // Fall back to Bearer token
            let auth_value = format!("Bearer {}", session.access_token);
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_value)
                    .map_err(|e| AppError::Internal(e.to_string()))?,
            );
        }

        Ok(headers)
    }

    /// Generate a DPoP proof JWT per RFC 9449
    async fn generate_dpop_proof(
        &self,
        session: &CatbirdSession,
        http_method: &str,
        http_url: &str,
    ) -> AppResult<String> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // Create access token hash (ath claim)
        let ath = {
            let mut hasher = Sha256::new();
            hasher.update(session.access_token.as_bytes());
            b64url.encode(hasher.finalize())
        };

        // Parse the URL to get just the origin and path (excluding query params for htu)
        let htu = {
            let parsed = url::Url::parse(http_url)
                .map_err(|e| AppError::Internal(format!("Invalid URL: {}", e)))?;
            format!(
                "{}://{}{}",
                parsed.scheme(),
                parsed.host_str().unwrap_or(""),
                parsed.path()
            )
        };

        // Generate unique token ID
        let jti = uuid::Uuid::new_v4().to_string();

        // Current timestamp
        let iat = chrono::Utc::now().timestamp();

        // Load the DPoP private key from session or config
        // For now, we need to retrieve the DPoP key from Redis (stored during OAuth)
        let dpop_key = self.get_dpop_private_key(session).await?;

        // Build the DPoP JWT header
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": dpop_key.public_jwk
        });

        // Build the DPoP JWT payload
        let payload = serde_json::json!({
            "jti": jti,
            "htm": http_method.to_uppercase(),
            "htu": htu,
            "iat": iat,
            "ath": ath
        });

        // Encode header and payload
        let encoded_header = b64url.encode(serde_json::to_string(&header)?.as_bytes());
        let encoded_payload = b64url.encode(serde_json::to_string(&payload)?.as_bytes());
        let signing_input = format!("{}.{}", encoded_header, encoded_payload);

        // Sign with ES256
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let signing_key = SigningKey::from_bytes(&dpop_key.private_key_bytes.into())
            .map_err(|e| AppError::Crypto(format!("Invalid DPoP key: {}", e)))?;

        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let encoded_signature = b64url.encode(signature.to_bytes());

        Ok(format!("{}.{}", signing_input, encoded_signature))
    }

    /// Retrieve the DPoP private key for a session
    async fn get_dpop_private_key(&self, session: &CatbirdSession) -> AppResult<DPoPKeyPair> {
        // The DPoP key should be stored in Redis alongside the session
        let key = format!(
            "{}dpop_key:{}",
            self.state.config.redis.key_prefix, session.did
        );
        let mut conn = self.state.redis.clone();

        let key_data: Option<String> = conn.get(&key).await?;

        match key_data {
            Some(data) => serde_json::from_str(&data)
                .map_err(|e| AppError::Internal(format!("Failed to parse DPoP key: {}", e))),
            None => Err(AppError::Internal(
                "DPoP key not found for session".to_string(),
            )),
        }
    }

    /// Handle the response from PDS
    async fn handle_response(&self, response: reqwest::Response) -> AppResult<Value> {
        let status = response.status();

        if status.is_success() {
            let json: Value = response.json().await?;
            Ok(json)
        } else {
            let status_code = status.as_u16();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            Err(AppError::Upstream {
                status: status_code,
                message: error_text,
            })
        }
    }

    /// Resolve a handle to a DID
    pub async fn resolve_handle(handle: &str) -> AppResult<String> {
        // Simple DNS resolution for now or HTTP
        // In production, use atrium-identity or specialized resolver
        let url = format!(
            "https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle={}",
            handle
        );
        let client = reqwest::Client::new();
        let res = client.get(&url).send().await?;

        if !res.status().is_success() {
            return Err(AppError::Upstream {
                status: res.status().as_u16(),
                message: "Failed to resolve handle".into(),
            });
        }

        let json: Value = res.json().await?;
        json["did"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| AppError::Internal("Invalid resolution response".into()))
    }

    /// Resolve a DID to a PDS URL
    pub async fn resolve_pds(did: &str) -> AppResult<String> {
        // Handle did:plc
        if did.starts_with("did:plc:") {
            let url = format!("https://plc.directory/{}", did);
            let client = reqwest::Client::new();
            let res = client.get(&url).send().await?;
            if !res.status().is_success() {
                return Err(AppError::Upstream {
                    status: res.status().as_u16(),
                    message: "Failed to resolve DID".into(),
                });
            }
            let json: Value = res.json().await?;
            // Find service with type AtprotoPds or similar?
            // Actually, usually we look for "atproto_pds" service
            if let Some(services) = json["service"].as_array() {
                for service in services {
                    if service["type"] == "AtprotoPersonalDataServer" {
                        return service["serviceEndpoint"]
                            .as_str()
                            .map(|s| s.to_string())
                            .ok_or_else(|| AppError::Internal("Invalid service endpoint".into()));
                    }
                }
            }
            return Err(AppError::Internal("No PDS service found for DID".into()));
        }

        // Fallback or Handle did:web (omitted for brevity, assume main bsky for now if fail)
        // For development, we default to the implementation check
        Err(AppError::Internal("Unsupported DID method".into()))
    }

    // Token refresh is now handled by the OAuthClient / OAuthSession.
    // AtProtoClient is for proxying requests only.
}

/// Session management service with automatic token refresh via OAuthClient
pub struct SessionService {
    state: Arc<AppState>,
}

impl SessionService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Get a session by ID (without refresh)
    pub async fn get_session(&self, session_id: &str) -> AppResult<Option<CatbirdSession>> {
        let key = format!(
            "{}catbird_session:{}",
            self.state.config.redis.key_prefix, session_id
        );

        let mut conn = self.state.redis.clone();
        let data: Option<String> = conn.get(&key).await?;

        match data {
            Some(json) => {
                let session: CatbirdSession = serde_json::from_str(&json)?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Save a session to Redis
    pub async fn save_session(&self, session: &CatbirdSession) -> AppResult<()> {
        let key = format!(
            "{}catbird_session:{}",
            self.state.config.redis.key_prefix, session.id
        );
        let json = serde_json::to_string(session)?;

        let mut conn = self.state.redis.clone();
        conn.set_ex::<_, _, ()>(&key, json, self.state.config.redis.session_ttl_seconds)
            .await?;

        Ok(())
    }

    /// Delete a session
    pub async fn delete_session(&self, session_id: &str) -> AppResult<()> {
        let key = format!(
            "{}catbird_session:{}",
            self.state.config.redis.key_prefix, session_id
        );

        let mut conn = self.state.redis.clone();
        conn.del::<_, ()>(&key).await?;

        Ok(())
    }

    /// Get session with automatic token refresh via OAuthClient
    ///
    /// Uses atrium-oauth's OAuthClient.restore() to get a session that
    /// automatically handles token refresh when the access token is expired.
    pub async fn get_valid_session(&self, session_id: &str) -> AppResult<CatbirdSession> {
        let mut session = self
            .get_session(session_id)
            .await?
            .ok_or(AppError::InvalidSession)?;

        // Update last used time
        session.last_used_at = Utc::now();

        // If pds_url is empty (legacy sessions), sync from oauth_session
        let needs_pds_sync = session.pds_url.is_empty();

        // Check if token refresh is needed
        if session.is_access_token_expired() || needs_pds_sync {
            if session.is_access_token_expired() {
                tracing::info!(
                    "Session {} has expired token, refreshing via OAuthClient",
                    session_id
                );
            }
            if needs_pds_sync {
                tracing::info!(
                    "Session {} has empty pds_url, syncing from oauth session",
                    session_id
                );
            }

            // Use OAuthClient.restore() to get a refreshed session
            // This automatically handles token refresh via atrium-oauth
            session = self.refresh_session_tokens(&session).await?;
        }

        self.save_session(&session).await?;
        Ok(session)
    }

    /// Refresh session tokens using OAuthClient.restore()
    ///
    /// OAuthSession automatically handles token refresh when restored.
    /// After restore(), we read the updated Session from Redis to sync our CatbirdSession.
    async fn refresh_session_tokens(&self, session: &CatbirdSession) -> AppResult<CatbirdSession> {
        use crate::services::oauth::RedisSessionStore;
        use atrium_api::types::string::Did;
        use atrium_common::store::Store;

        // Parse the DID
        let did: Did = session
            .did
            .parse()
            .map_err(|_| AppError::Internal(format!("Invalid DID: {}", session.did)))?;

        // Get OAuth client (must be configured for token refresh)
        let oauth_client = self
            .state
            .oauth_client
            .as_ref()
            .ok_or_else(|| AppError::Config("OAuth client not configured".to_string()))?;

        // Restore the OAuth session - this triggers automatic token refresh
        // The OAuthSession will update the Session in our RedisSessionStore
        let _oauth_session = oauth_client
            .restore(&did)
            .await
            .map_err(|e| AppError::OAuth(format!("Failed to restore OAuth session: {}", e)))?;

        // Read the updated Session from our RedisSessionStore
        let session_store = RedisSessionStore::new(
            self.state.redis.clone(),
            self.state.config.redis.key_prefix.clone(),
        );

        let atrium_session = session_store
            .get(&did)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read session from store: {}", e)))?
            .ok_or_else(|| AppError::Internal("Session not found after restore".to_string()))?;

        // Extract tokens from atrium-oauth's Session and update CatbirdSession
        let refreshed_session = CatbirdSession {
            id: session.id,
            did: session.did.clone(),
            handle: session.handle.clone(),
            // Use pds_url from atrium session (aud field) as the authoritative source
            pds_url: atrium_session.token_set.aud.clone(),
            access_token: atrium_session.token_set.access_token.clone(),
            refresh_token: atrium_session
                .token_set
                .refresh_token
                .clone()
                .unwrap_or_else(|| session.refresh_token.clone()),
            access_token_expires_at: atrium_session
                .token_set
                .expires_at
                .map(|dt| dt.as_ref().with_timezone(&chrono::Utc))
                .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::seconds(3600)),
            created_at: session.created_at,
            last_used_at: chrono::Utc::now(),
            dpop_jkt: session.dpop_jkt.clone(),
        };

        tracing::info!("Successfully refreshed tokens for session {}", session.id);
        Ok(refreshed_session)
    }

    /// Revoke a session (logout)
    ///
    /// Revokes the OAuth session via OAuthClient and deletes the local session.
    pub async fn revoke_session(&self, session: &CatbirdSession) -> AppResult<()> {
        use atrium_api::types::string::Did;

        // Parse the DID
        let did: Did = session
            .did
            .parse()
            .map_err(|_| AppError::Internal(format!("Invalid DID: {}", session.did)))?;

        // Revoke the OAuth session if client is configured
        if let Some(oauth_client) = self.state.oauth_client.as_ref() {
            if let Err(e) = oauth_client.revoke(&did).await {
                tracing::warn!("Failed to revoke OAuth session: {}", e);
                // Continue with local cleanup even if revoke fails
            }
        }

        // Delete local session
        self.delete_session(&session.id.to_string()).await?;

        Ok(())
    }
}
