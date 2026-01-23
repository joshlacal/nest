//! ATProto Client Service
//!
//! Handles communication with ATProto PDS servers, including:
//! - OAuth token management (refresh, DPoP)
//! - Request proxying with DPoP nonce retry
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
            .build_auth_headers_for_request(session, "GET", &url, None)
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
            .build_auth_headers_for_request(session, "POST", &url, None)
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
    /// Handles DPoP nonce retry automatically
    pub async fn proxy_request(
        &self,
        session: &CatbirdSession,
        method: reqwest::Method,
        path: &str,
        query_string: Option<&str>,
        body: Option<bytes::Bytes>,
        content_type: Option<&str>,
        client_headers: Option<&HeaderMap>,
        request_id: &str,
    ) -> AppResult<(u16, HeaderMap, bytes::Bytes)> {
        let url = if let Some(qs) = query_string {
            format!("{}{}?{}", session.pds_url, path, qs)
        } else {
            format!("{}{}", session.pds_url, path)
        };

        let body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
        tracing::debug!(
            request_id = %request_id,
            url = %url,
            method = %method,
            body_size = body_size,
            "[BFF-UPSTREAM] First attempt (no nonce)"
        );

        // First attempt without nonce
        let (status, response_headers, response_body) = self
            .do_proxy_request(session, method.clone(), &url, body.clone(), content_type, None, client_headers, request_id, 1)
            .await?;

        // Check if we got a DPoP nonce error (401 with use_dpop_nonce)
        if status == 401 {
            if let Ok(error_json) = serde_json::from_slice::<Value>(&response_body) {
                if error_json.get("error").and_then(|e| e.as_str()) == Some("use_dpop_nonce") {
                    // Extract nonce from DPoP-Nonce header
                    if let Some(nonce_value) = response_headers.get("dpop-nonce") {
                        if let Ok(nonce) = nonce_value.to_str() {
                            let retry_body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
                            tracing::info!(
                                request_id = %request_id,
                                retry_body_size = retry_body_size,
                                original_body_size = body_size,
                                body_preserved = (retry_body_size == body_size),
                                "[BFF-DPOP-RETRY] Received nonce challenge, retrying"
                            );
                            
                            // Retry with the nonce
                            return self
                                .do_proxy_request(
                                    session,
                                    method,
                                    &url,
                                    body,
                                    content_type,
                                    Some(nonce.to_string()),
                                    client_headers,
                                    request_id,
                                    2,
                                )
                                .await;
                        }
                    }
                    tracing::warn!(
                        request_id = %request_id,
                        "[BFF-DPOP-RETRY] Got use_dpop_nonce error but no DPoP-Nonce header in response"
                    );
                }
            }
        }

        Ok((status, response_headers, response_body))
    }

    /// Internal helper to perform the actual proxy request
    async fn do_proxy_request(
        &self,
        session: &CatbirdSession,
        method: reqwest::Method,
        url: &str,
        body: Option<bytes::Bytes>,
        content_type: Option<&str>,
        nonce: Option<String>,
        client_headers: Option<&HeaderMap>,
        request_id: &str,
        attempt: u8,
    ) -> AppResult<(u16, HeaderMap, bytes::Bytes)> {
        let has_nonce = nonce.is_some();
        let mut headers = self
            .build_auth_headers_for_request(session, method.as_str(), url, nonce)
            .await?;

        if let Some(ct) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(ct).unwrap());
        }

        // Forward all client headers except hop-by-hop and headers we set ourselves
        if let Some(ch) = client_headers {
            for (name, value) in ch.iter() {
                let name_lower = name.as_str().to_lowercase();
                // Skip hop-by-hop headers and headers we manage
                if matches!(
                    name_lower.as_str(),
                    "host" | "connection" | "keep-alive" | "transfer-encoding" 
                    | "te" | "trailer" | "upgrade" | "proxy-authorization"
                    | "proxy-connection" | "authorization" | "dpop" | "content-length"
                ) {
                    continue;
                }
                // Don't overwrite content-type if we already set it
                if name_lower == "content-type" && headers.contains_key(CONTENT_TYPE) {
                    continue;
                }
                headers.insert(name.clone(), value.clone());
            }
        }

        let body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
        tracing::debug!(
            request_id = %request_id,
            attempt = attempt,
            url = %url,
            method = %method,
            body_size = body_size,
            has_nonce = has_nonce,
            "[BFF-UPSTREAM-SEND] Sending to PDS"
        );

        let mut request = self
            .state
            .http_client
            .request(method, url)
            .headers(headers);

        if let Some(b) = body {
            request = request.body(b);
        }

        let start = std::time::Instant::now();
        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    request_id = %request_id,
                    attempt = attempt,
                    url = %url,
                    error = %e,
                    is_builder = e.is_builder(),
                    is_request = e.is_request(),
                    is_connect = e.is_connect(),
                    is_body = e.is_body(),
                    "[BFF-UPSTREAM-ERR] Request failed"
                );
                return Err(e.into());
            }
        };

        let status = response.status().as_u16();
        let response_headers = response.headers().clone();
        let body = response.bytes().await?;
        let elapsed_ms = start.elapsed().as_millis();

        tracing::debug!(
            request_id = %request_id,
            attempt = attempt,
            status = status,
            elapsed_ms = elapsed_ms,
            body_size = body.len(),
            "[BFF-UPSTREAM-RECV] Response from PDS"
        );

        Ok((status, response_headers, body))
    }

    /// Build authentication headers including DPoP if needed
    async fn build_auth_headers(&self, session: &CatbirdSession) -> AppResult<HeaderMap> {
        self.build_auth_headers_for_request(session, "GET", &session.pds_url, None)
            .await
    }

    /// Build authentication headers with DPoP for a specific request
    pub async fn build_auth_headers_for_request(
        &self,
        session: &CatbirdSession,
        method: &str,
        url: &str,
        nonce: Option<String>,
    ) -> AppResult<HeaderMap> {
        let mut headers = HeaderMap::new();

        // If we have a DPoP key, generate a DPoP proof
        if let Some(ref _dpop_jkt) = session.dpop_jkt {
            // Generate DPoP proof JWT
            let dpop_proof = self.generate_dpop_proof(session, method, url, nonce).await?;

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
    pub async fn generate_dpop_proof(
        &self,
        session: &CatbirdSession,
        http_method: &str,
        http_url: &str,
        nonce: Option<String>,
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

        // Build the DPoP JWT payload - include nonce if provided
        let mut payload = serde_json::json!({
            "jti": jti,
            "htm": http_method.to_uppercase(),
            "htu": htu,
            "iat": iat,
            "ath": ath
        });

        // Add nonce claim if provided (required for DPoP nonce retry)
        if let Some(nonce_value) = nonce {
            payload["nonce"] = serde_json::Value::String(nonce_value);
        }

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
    pub async fn get_dpop_private_key(&self, session: &CatbirdSession) -> AppResult<DPoPKeyPair> {
        // The DPoP key is stored by session ID (not DID) to support multiple devices
        let key = format!(
            "{}dpop_key:{}",
            self.state.config.redis.key_prefix, session.id
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
    /// Revokes the OAuth session via direct HTTP call to the PDS revocation endpoint,
    /// then deletes the local session.
    /// Revoke a session (logout)
    ///
    /// Revokes the OAuth session via direct HTTP call to the Authorization Server revocation endpoint,
    /// then deletes the local session.
    pub async fn revoke_session(&self, session: &CatbirdSession) -> AppResult<()> {
        // Resolve the authorization server and revocation endpoint per ATProto OAuth spec
        let revocation_url = self.get_revocation_endpoint(&session.pds_url).await?;
        
        tracing::info!("Revoking OAuth token at {}", revocation_url);
        
        // Generate client assertion for confidential client authentication
        let client_assertion = self.generate_client_assertion(&revocation_url).await?;
        
        // Build form body with client authentication
        let body = format!(
            "token={}&client_id={}&client_assertion_type={}&client_assertion={}",
            urlencoding::encode(&session.access_token),
            urlencoding::encode(&self.state.config.oauth.client_id),
            urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            urlencoding::encode(&client_assertion)
        );
        
        // First attempt - no nonce, no ath (auth server requests don't use ath)
        let dpop_proof = self.generate_dpop_proof_for_auth_server(
            session,
            "POST",
            &revocation_url,
            None,
        ).await?;
        
        let response = self
            .state
            .http_client
            .post(&revocation_url)
            .header("DPoP", dpop_proof)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.clone())
            .send()
            .await?;
        
        // Check if we need to retry with DPoP nonce
        let response = if response.status() == reqwest::StatusCode::BAD_REQUEST {
            let nonce = response.headers()
                .get("DPoP-Nonce")
                .or_else(|| response.headers().get("dpop-nonce"))
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            
            if let Some(nonce) = nonce {
                tracing::info!("Received DPoP nonce challenge for revoke, retrying with nonce");
                
                // Regenerate DPoP proof with nonce (no ath for auth server)
                let dpop_proof_with_nonce = self.generate_dpop_proof_for_auth_server(
                    session,
                    "POST",
                    &revocation_url,
                    Some(nonce),
                ).await?;
                
                // Regenerate client assertion (needs fresh jti)
                let client_assertion = self.generate_client_assertion(&revocation_url).await?;
                let body = format!(
                    "token={}&client_id={}&client_assertion_type={}&client_assertion={}",
                    urlencoding::encode(&session.access_token),
                    urlencoding::encode(&self.state.config.oauth.client_id),
                    urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    urlencoding::encode(&client_assertion)
                );
                
                self.state
                    .http_client
                    .post(&revocation_url)
                    .header("DPoP", dpop_proof_with_nonce)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(body)
                    .send()
                    .await?
            } else {
                response
            }
        } else {
            response
        };
        
        // Per RFC 7009, revocation should return 200, but some implementations return 204
        // Accept either as success
        if response.status().is_success() {
            tracing::info!("Successfully revoked OAuth token for {}", session.did);
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            tracing::warn!("OAuth revocation returned {}: {}", status, body);
            // Continue with local cleanup even if revoke fails
        }

        // Delete local session
        self.delete_session(&session.id.to_string()).await?;

        Ok(())
    }
    
    /// Generate a DPoP proof for auth server requests (without ath claim)
    /// 
    /// Auth server endpoints (token, revoke) should NOT include the ath claim.
    /// Only resource server requests include ath.
    async fn generate_dpop_proof_for_auth_server(
        &self,
        session: &CatbirdSession,
        http_method: &str,
        http_url: &str,
        nonce: Option<String>,
    ) -> AppResult<String> {
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        
        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;

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

        // Load the DPoP private key from Redis
        let atproto_client = AtProtoClient::new(Arc::clone(&self.state));
        let dpop_key = atproto_client.get_dpop_private_key(session).await?;

        // Build the DPoP JWT header
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": dpop_key.public_jwk
        });

        // Build the DPoP JWT payload - NO ath claim for auth server requests
        let mut payload = serde_json::json!({
            "jti": jti,
            "htm": http_method.to_uppercase(),
            "htu": htu,
            "iat": iat
        });

        // Add nonce claim if provided
        if let Some(nonce_value) = nonce {
            payload["nonce"] = serde_json::Value::String(nonce_value);
        }

        // Encode header and payload
        let header_b64 = b64url.encode(serde_json::to_string(&header)?.as_bytes());
        let payload_b64 = b64url.encode(serde_json::to_string(&payload)?.as_bytes());
        let message = format!("{}.{}", header_b64, payload_b64);

        // Sign with the DPoP private key
        let signing_key = SigningKey::from_bytes(&dpop_key.private_key_bytes.into())
            .map_err(|e| AppError::Internal(format!("Failed to create signing key: {}", e)))?;
        let signature: Signature = signing_key.sign(message.as_bytes());
        let sig_b64 = b64url.encode(signature.to_bytes());

        Ok(format!("{}.{}", message, sig_b64))
    }
    
    /// Generate a client assertion JWT for confidential client authentication
    async fn generate_client_assertion(&self, audience: &str) -> AppResult<String> {
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        
        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        
        // Load the client's private key
        let crypto = super::CryptoService::new(Arc::clone(&self.state));
        let secret_key = crypto.load_private_key()?;
        let signing_key = SigningKey::from(&secret_key);
        
        // Extract the issuer (authorization server base URL) from the revocation URL
        let issuer = url::Url::parse(audience)
            .map(|u| format!("{}://{}", u.scheme(), u.host_str().unwrap_or("")))
            .unwrap_or_else(|_| audience.to_string());
        
        // Generate unique JWT ID
        let jti = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        
        // Build JWT header
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT"
        });
        
        // Build JWT claims per RFC 7523
        let claims = serde_json::json!({
            "iss": self.state.config.oauth.client_id,
            "sub": self.state.config.oauth.client_id,
            "aud": issuer,
            "iat": now,
            "exp": now + 300, // 5 minutes
            "jti": jti
        });
        
        // Encode header and claims
        let header_b64 = b64url.encode(serde_json::to_string(&header)?.as_bytes());
        let claims_b64 = b64url.encode(serde_json::to_string(&claims)?.as_bytes());
        let message = format!("{}.{}", header_b64, claims_b64);
        
        // Sign the JWT
        let signature: Signature = signing_key.sign(message.as_bytes());
        let sig_b64 = b64url.encode(signature.to_bytes());
        
        Ok(format!("{}.{}", message, sig_b64))
    }
    
    /// Get the revocation endpoint by resolving the authorization server per ATProto OAuth spec
    async fn get_revocation_endpoint(&self, pds_url: &str) -> AppResult<String> {
        // Step 1: Fetch Resource Server metadata from the PDS
        let resource_metadata_url = format!("{}/.well-known/oauth-protected-resource", pds_url);
        
        let response = self
            .state
            .http_client
            .get(&resource_metadata_url)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(AppError::Internal(format!(
                "Failed to fetch resource server metadata from {}: {}",
                pds_url,
                response.status()
            )));
        }
        
        let resource_metadata: serde_json::Value = response.json().await?;
        
        // Step 2: Extract the authorization server URL
        let auth_server_url = resource_metadata["authorization_servers"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AppError::Internal("No authorization_servers in resource metadata".into())
            })?;
        
        // Step 3: Fetch Authorization Server metadata
        let auth_metadata_url = format!("{}/.well-known/oauth-authorization-server", auth_server_url);
        
        let response = self
            .state
            .http_client
            .get(&auth_metadata_url)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(AppError::Internal(format!(
                "Failed to fetch auth server metadata from {}: {}",
                auth_server_url,
                response.status()
            )));
        }
        
        let auth_metadata: serde_json::Value = response.json().await?;
        
        // Step 4: Extract the revocation endpoint
        auth_metadata["revocation_endpoint"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                AppError::Internal("No revocation_endpoint in auth server metadata".into())
            })
    }
}
