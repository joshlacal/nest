//! ATProto Client Service
//!
//! Handles communication with ATProto PDS servers, including:
//! - OAuth token management (refresh, DPoP)
//! - Request proxying with DPoP nonce retry
//! - Token refresh logic

use super::ssrf::validate_pds_url;
use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::metrics;
use crate::models::{CatbirdSession, DPoPKeyPair};
use chrono::Utc;
use futures_util::StreamExt;
use redis::AsyncCommands;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::sync::Arc;

/// Maximum response size allowed (50MB)
pub const MAX_RESPONSE_SIZE: usize = 50 * 1024 * 1024;

/// Threshold above which responses are streamed instead of buffered (1MB)
pub const STREAM_THRESHOLD: usize = 1 * 1024 * 1024;

/// Response from proxy request - either buffered bytes or a streaming body
pub enum ProxyResponse {
    /// Buffered response for smaller payloads (can be inspected/modified)
    Buffered {
        status: u16,
        headers: HeaderMap,
        body: bytes::Bytes,
    },
    /// Streaming response for larger payloads (passed through directly)
    Streaming {
        status: u16,
        headers: HeaderMap,
        body: reqwest::Response,
    },
}

impl ProxyResponse {
    /// Get the status code
    pub fn status(&self) -> u16 {
        match self {
            ProxyResponse::Buffered { status, .. } => *status,
            ProxyResponse::Streaming { status, .. } => *status,
        }
    }

    /// Get the response headers
    pub fn headers(&self) -> &HeaderMap {
        match self {
            ProxyResponse::Buffered { headers, .. } => headers,
            ProxyResponse::Streaming { headers, .. } => headers,
        }
    }
}

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
    /// 
    /// Returns a ProxyResponse which can be either buffered (for small JSON responses
    /// that may need processing) or streaming (for large responses like blobs).
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
    ) -> AppResult<ProxyResponse> {
        // SSRF protection: validate the PDS URL before making any requests
        validate_pds_url(&session.pds_url)?;

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

        // First attempt without nonce - always buffer since we may need to inspect for DPoP nonce
        let first_response = self
            .do_proxy_request_buffered(session, method.clone(), &url, body.clone(), content_type, None, client_headers, request_id, 1)
            .await?;

        // Check if we got a DPoP nonce error (401 with use_dpop_nonce)
        if first_response.0 == 401 {
            if let Ok(error_json) = serde_json::from_slice::<Value>(&first_response.2) {
                if error_json.get("error").and_then(|e| e.as_str()) == Some("use_dpop_nonce") {
                    // Extract nonce from DPoP-Nonce header
                    if let Some(nonce_value) = first_response.1.get("dpop-nonce") {
                        if let Ok(nonce) = nonce_value.to_str() {
                            let retry_body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
                            tracing::info!(
                                request_id = %request_id,
                                retry_body_size = retry_body_size,
                                original_body_size = body_size,
                                body_preserved = (retry_body_size == body_size),
                                "[BFF-DPOP-RETRY] Received nonce challenge, retrying"
                            );
                            
                            // Retry with the nonce - use streaming-aware version
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

        Ok(ProxyResponse::Buffered {
            status: first_response.0,
            headers: first_response.1,
            body: first_response.2,
        })
    }

    /// Internal helper to perform the actual proxy request with streaming support
    /// 
    /// Decides whether to buffer or stream based on content-length and content-type:
    /// - Responses > MAX_RESPONSE_SIZE (50MB): Rejected with error
    /// - Responses > STREAM_THRESHOLD (1MB) or non-JSON: Streamed directly
    /// - Small JSON responses: Buffered for potential processing
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
    ) -> AppResult<ProxyResponse> {
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

        // Check Content-Length for size limits
        let content_length = response_headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        // Reject responses that are too large
        if let Some(len) = content_length {
            if len > MAX_RESPONSE_SIZE {
                tracing::warn!(
                    request_id = %request_id,
                    content_length = len,
                    max_size = MAX_RESPONSE_SIZE,
                    "[BFF-UPSTREAM-ERR] Response too large"
                );
                return Err(AppError::ResponseTooLarge(format!(
                    "Response size {} bytes exceeds maximum allowed {} bytes",
                    len, MAX_RESPONSE_SIZE
                )));
            }
        }

        // Determine if we should stream or buffer
        let response_content_type = response_headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        
        let is_json = response_content_type.contains("application/json");
        let should_stream = content_length.map(|l| l > STREAM_THRESHOLD).unwrap_or(false) || !is_json;

        if should_stream {
            let elapsed_ms = start.elapsed().as_millis();
            tracing::debug!(
                request_id = %request_id,
                attempt = attempt,
                status = status,
                elapsed_ms = elapsed_ms,
                content_length = ?content_length,
                streaming = true,
                "[BFF-UPSTREAM-RECV] Response from PDS (streaming)"
            );

            Ok(ProxyResponse::Streaming {
                status,
                headers: response_headers,
                body: response,
            })
        } else {
            // Buffer small JSON responses
            let body = self.read_response_with_limit(response, MAX_RESPONSE_SIZE, request_id).await?;
            let elapsed_ms = start.elapsed().as_millis();

            tracing::debug!(
                request_id = %request_id,
                attempt = attempt,
                status = status,
                elapsed_ms = elapsed_ms,
                body_size = body.len(),
                "[BFF-UPSTREAM-RECV] Response from PDS (buffered)"
            );

            Ok(ProxyResponse::Buffered {
                status,
                headers: response_headers,
                body,
            })
        }
    }

    /// Internal helper for first request that always buffers (needed for DPoP nonce inspection)
    async fn do_proxy_request_buffered(
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
        
        // Check Content-Length for size limits on initial request
        let content_length = response_headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        if let Some(len) = content_length {
            if len > MAX_RESPONSE_SIZE {
                tracing::warn!(
                    request_id = %request_id,
                    content_length = len,
                    max_size = MAX_RESPONSE_SIZE,
                    "[BFF-UPSTREAM-ERR] Response too large"
                );
                return Err(AppError::ResponseTooLarge(format!(
                    "Response size {} bytes exceeds maximum allowed {} bytes",
                    len, MAX_RESPONSE_SIZE
                )));
            }
        }

        // Read response with size limit protection
        let body = self.read_response_with_limit(response, MAX_RESPONSE_SIZE, request_id).await?;
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

    /// Read response body with size limit protection
    /// 
    /// Reads the response body in chunks and enforces a maximum size limit
    /// to prevent memory exhaustion from untrusted responses.
    async fn read_response_with_limit(
        &self,
        response: reqwest::Response,
        max_size: usize,
        request_id: &str,
    ) -> AppResult<bytes::Bytes> {
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            if body.len() + chunk.len() > max_size {
                tracing::warn!(
                    request_id = %request_id,
                    current_size = body.len(),
                    chunk_size = chunk.len(),
                    max_size = max_size,
                    "[BFF-UPSTREAM-ERR] Response exceeded size limit while reading"
                );
                return Err(AppError::ResponseTooLarge(format!(
                    "Response exceeded maximum size of {} bytes while reading",
                    max_size
                )));
            }
            body.extend_from_slice(&chunk);
        }

        Ok(bytes::Bytes::from(body))
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
                        let endpoint = service["serviceEndpoint"]
                            .as_str()
                            .map(|s| s.to_string())
                            .ok_or_else(|| AppError::Internal("Invalid service endpoint".into()))?;

                        // SSRF protection: validate the resolved PDS URL
                        validate_pds_url(&endpoint)?;

                        return Ok(endpoint);
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

    /// Clear all session-related data from Redis
    ///
    /// Removes the catbird session, DPoP key, and OAuth session.
    /// Used when a refresh token is rejected and the session is no longer valid.
    pub async fn clear_session_data(&self, session_id: &str) -> AppResult<()> {
        let prefix = &self.state.config.redis.key_prefix;
        let catbird_session_key = format!("{}catbird_session:{}", prefix, session_id);
        let dpop_key = format!("{}dpop_key:{}", prefix, session_id);
        let oauth_session_key = format!("{}oauth_session:{}", prefix, session_id);

        let mut conn = self.state.redis.clone();
        
        // Delete all session-related keys (ignore individual failures)
        let _: Result<(), _> = conn.del(&catbird_session_key).await;
        let _: Result<(), _> = conn.del(&dpop_key).await;
        let _: Result<(), _> = conn.del(&oauth_session_key).await;

        tracing::info!("Cleared all session data for session {}", session_id);
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

    /// Refresh session tokens using per-session OAuth data
    ///
    /// This performs a manual token refresh using the refresh_token stored in
    /// `oauth_session:{session_id}` rather than the DID-keyed session store.
    /// This is critical for multi-device support where each device has its own
    /// refresh token that must not be overwritten by other devices.
    async fn refresh_session_tokens(&self, session: &CatbirdSession) -> AppResult<CatbirdSession> {
        use atrium_oauth::store::session::Session;

        // Load the per-session OAuth data from Redis (not the DID-keyed store)
        let oauth_session_key = format!(
            "{}oauth_session:{}",
            self.state.config.redis.key_prefix,
            session.id
        );
        let mut conn = self.state.redis.clone();
        let oauth_session_json: Option<String> = conn.get(&oauth_session_key).await?;
        
        let oauth_session: Session = match oauth_session_json {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| AppError::Internal(format!("Failed to parse OAuth session: {}", e)))?,
            None => {
                return Err(AppError::Internal(format!(
                    "No per-session OAuth data found for session {}",
                    session.id
                )));
            }
        };

        // Get the refresh token from the per-session data
        let refresh_token = oauth_session
            .token_set
            .refresh_token
            .clone()
            .ok_or_else(|| AppError::OAuth("No refresh token in session".to_string()))?;

        // Get the token endpoint from the authorization server
        let token_endpoint = self.get_token_endpoint(&session.pds_url).await?;
        
        tracing::info!(
            "Refreshing tokens for session {} via {}",
            session.id,
            token_endpoint
        );

        // Generate client assertion JWT for confidential client auth
        let client_assertion = self.generate_client_assertion(&token_endpoint).await?;
        
        // Build the refresh token request body
        let body = format!(
            "grant_type=refresh_token&refresh_token={}&client_id={}&client_assertion_type={}&client_assertion={}",
            urlencoding::encode(&refresh_token),
            urlencoding::encode(&self.state.config.oauth.client_id),
            urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            urlencoding::encode(&client_assertion)
        );

        // First attempt without DPoP nonce
        let dpop_proof = self.generate_dpop_proof_for_auth_server(
            session,
            "POST",
            &token_endpoint,
            None,
        ).await?;

        let response = self
            .state
            .http_client
            .post(&token_endpoint)
            .header("DPoP", dpop_proof)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.clone())
            .send()
            .await?;

        // Check if we need to retry with DPoP nonce
        let response = if response.status() == reqwest::StatusCode::BAD_REQUEST 
            || response.status() == reqwest::StatusCode::UNAUTHORIZED 
        {
            let nonce = response.headers()
                .get("DPoP-Nonce")
                .or_else(|| response.headers().get("dpop-nonce"))
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            
            if let Some(nonce) = nonce {
                tracing::info!("Received DPoP nonce challenge for token refresh, retrying with nonce");
                
                // Regenerate DPoP proof with nonce
                let dpop_proof_with_nonce = self.generate_dpop_proof_for_auth_server(
                    session,
                    "POST",
                    &token_endpoint,
                    Some(nonce),
                ).await?;
                
                // Regenerate client assertion (needs fresh jti)
                let client_assertion = self.generate_client_assertion(&token_endpoint).await?;
                let body = format!(
                    "grant_type=refresh_token&refresh_token={}&client_id={}&client_assertion_type={}&client_assertion={}",
                    urlencoding::encode(&refresh_token),
                    urlencoding::encode(&self.state.config.oauth.client_id),
                    urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    urlencoding::encode(&client_assertion)
                );
                
                self.state
                    .http_client
                    .post(&token_endpoint)
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

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            
            // Record token refresh failure
            metrics::record_token_refresh(false);
            
            // Check for invalid_grant - this means the refresh token was rejected
            // This can happen when: user revoked access, token was already used,
            // or PDS invalidated the session
            if body.contains("invalid_grant") || body.contains("InvalidGrant") {
                tracing::warn!(
                    "Refresh token rejected for session {} (invalid_grant), clearing session data. Response: {}",
                    session.id,
                    body
                );
                
                // Clear all session data from Redis since the refresh token is no longer valid
                if let Err(cleanup_err) = self.clear_session_data(&session.id.to_string()).await {
                    tracing::error!("Failed to clear session data after invalid_grant: {}", cleanup_err);
                }
                
                // Return TokenRefresh error which maps to 401, prompting re-authentication
                return Err(AppError::TokenRefresh(
                    "Session expired. Please log in again.".to_string()
                ));
            }
            
            return Err(AppError::OAuth(format!(
                "Token refresh failed with status {}: {}",
                status, body
            )));
        }

        // Parse the token response
        let token_response: serde_json::Value = response.json().await?;
        
        let new_access_token = token_response["access_token"]
            .as_str()
            .ok_or_else(|| AppError::OAuth("No access_token in refresh response".to_string()))?
            .to_string();
        
        let new_refresh_token = token_response["refresh_token"]
            .as_str()
            .map(String::from)
            .unwrap_or_else(|| refresh_token.clone());
        
        let expires_in = token_response["expires_in"]
            .as_i64()
            .unwrap_or(3600);
        
        let new_expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in);

        // Update the per-session OAuth data with new tokens
        let mut updated_oauth_session = oauth_session.clone();
        updated_oauth_session.token_set.access_token = new_access_token.clone();
        updated_oauth_session.token_set.refresh_token = Some(new_refresh_token.clone());
        updated_oauth_session.token_set.expires_at = Some(atrium_api::types::string::Datetime::new(new_expires_at.fixed_offset()));
        
        let updated_oauth_json = serde_json::to_string(&updated_oauth_session)
            .map_err(|e| AppError::Internal(format!("Failed to serialize OAuth session: {}", e)))?;
        conn.set_ex::<_, _, ()>(
            &oauth_session_key,
            updated_oauth_json,
            self.state.config.redis.session_ttl_seconds,
        ).await?;

        // Build the updated CatbirdSession
        let refreshed_session = CatbirdSession {
            id: session.id,
            did: session.did.clone(),
            handle: session.handle.clone(),
            pds_url: session.pds_url.clone(),
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            access_token_expires_at: new_expires_at,
            created_at: session.created_at,
            last_used_at: chrono::Utc::now(),
            dpop_jkt: session.dpop_jkt.clone(),
        };

        tracing::info!("Successfully refreshed tokens for session {}", session.id);
        metrics::record_token_refresh(true);
        Ok(refreshed_session)
    }
    
    /// Get the token endpoint by resolving the authorization server per ATProto OAuth spec
    async fn get_token_endpoint(&self, pds_url: &str) -> AppResult<String> {
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
        
        // Step 4: Extract the token endpoint
        auth_metadata["token_endpoint"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                AppError::Internal("No token_endpoint in auth server metadata".into())
            })
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
        // SSRF protection: validate the PDS URL before making any requests
        validate_pds_url(&session.pds_url)?;

        // Resolve the authorization server and revocation endpoint per ATProto OAuth spec
        let revocation_url = self.get_revocation_endpoint(&session.pds_url).await?;
        
        tracing::info!("Revoking OAuth token at {}", revocation_url);
        
        // Generate client assertion for confidential client authentication
        let client_assertion = self.generate_client_assertion(&revocation_url).await?;
        
        // Per RFC 7009, prefer revoking refresh_token over access_token:
        // - Refresh tokens are long-lived credentials
        // - Revoking refresh token prevents future access token issuance
        // - Access tokens expire soon anyway
        let token_to_revoke = if !session.refresh_token.is_empty() {
            &session.refresh_token
        } else {
            &session.access_token
        };
        
        // Build form body with client authentication
        let body = format!(
            "token={}&client_id={}&client_assertion_type={}&client_assertion={}",
            urlencoding::encode(token_to_revoke),
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
                    urlencoding::encode(token_to_revoke),
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
