//! ATProto Client Service
//!
//! Handles communication with ATProto PDS servers, including:
//! - Request proxying with DPoP nonce retry
//! - DPoP proof generation via Jacquard

use super::ssrf::validate_pds_url;
use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::models::CatbirdSession;
use futures_util::StreamExt;
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
        jacquard_dpop: Option<&crate::middleware::JacquardDpopData>,
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
            .do_proxy_request_buffered(
                session,
                method.clone(),
                &url,
                body.clone(),
                content_type,
                None,
                client_headers,
                request_id,
                1,
                jacquard_dpop,
            )
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
                                    jacquard_dpop,
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
        jacquard_dpop: Option<&crate::middleware::JacquardDpopData>,
    ) -> AppResult<ProxyResponse> {
        let has_nonce = nonce.is_some();
        let mut headers = self
            .build_auth_headers_for_request(session, method.as_str(), url, nonce, jacquard_dpop)
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
                    "host"
                        | "connection"
                        | "keep-alive"
                        | "transfer-encoding"
                        | "te"
                        | "trailer"
                        | "upgrade"
                        | "proxy-authorization"
                        | "proxy-connection"
                        | "authorization"
                        | "dpop"
                        | "content-length"
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

        let mut request = self.state.http_client.request(method, url).headers(headers);

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
        let should_stream = content_length
            .map(|l| l > STREAM_THRESHOLD)
            .unwrap_or(false)
            || !is_json;

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
            let body = self
                .read_response_with_limit(response, MAX_RESPONSE_SIZE, request_id)
                .await?;
            let elapsed_ms = start.elapsed().as_millis();

            tracing::debug!(
                request_id = %request_id,
                attempt = attempt,
                status = status,
                elapsed_ms = elapsed_ms,
                body_size = body.len(),
                "[BFF-UPSTREAM-RECV] Response from PDS (buffered)"
            );

            // Log error response bodies for debugging
            if status >= 400 && status != 401 {
                if let Ok(error_text) = std::str::from_utf8(&body) {
                    let truncated = if error_text.len() > 200 { &error_text[..200] } else { error_text };
                    tracing::warn!(
                        request_id = %request_id,
                        attempt = attempt,
                        status = status,
                        error_body = %truncated,
                        "[BFF-UPSTREAM-ERR] PDS error response"
                    );
                }
            }

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
        jacquard_dpop: Option<&crate::middleware::JacquardDpopData>,
    ) -> AppResult<(u16, HeaderMap, bytes::Bytes)> {
        let has_nonce = nonce.is_some();
        let mut headers = self
            .build_auth_headers_for_request(session, method.as_str(), url, nonce, jacquard_dpop)
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
                    "host"
                        | "connection"
                        | "keep-alive"
                        | "transfer-encoding"
                        | "te"
                        | "trailer"
                        | "upgrade"
                        | "proxy-authorization"
                        | "proxy-connection"
                        | "authorization"
                        | "dpop"
                        | "content-length"
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

        let mut request = self.state.http_client.request(method, url).headers(headers);

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
        let body = self
            .read_response_with_limit(response, MAX_RESPONSE_SIZE, request_id)
            .await?;
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

    /// Build authentication headers with DPoP for a specific request
    pub async fn build_auth_headers_for_request(
        &self,
        session: &CatbirdSession,
        method: &str,
        url: &str,
        nonce: Option<String>,
        jacquard_dpop: Option<&crate::middleware::JacquardDpopData>,
    ) -> AppResult<HeaderMap> {
        let mut headers = HeaderMap::new();

        let dpop_data = jacquard_dpop.ok_or_else(|| {
            AppError::Internal("Missing Jacquard DPoP data for request".into())
        })?;

        use base64::Engine;
        use sha2::{Digest, Sha256};

        // Compute access token hash (ath)
        let ath = {
            let hash = Sha256::digest(session.access_token.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
        };

        let dpop_proof = jacquard_oauth::dpop::build_dpop_proof(
            &dpop_data.dpop_key,
            method.to_string().into(),
            url.to_string().into(),
            nonce.map(|n| n.into()),
            Some(ath.into()),
        )
        .map_err(|e| AppError::Internal(format!("Jacquard DPoP proof failed: {}", e)))?;

        let auth_value = format!("DPoP {}", session.access_token);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value)
                .map_err(|e| AppError::Internal(e.to_string()))?,
        );
        headers.insert(
            "DPoP",
            HeaderValue::from_str(dpop_proof.as_ref())
                .map_err(|e| AppError::Internal(e.to_string()))?,
        );

        Ok(headers)
    }

    // Token refresh is now handled by Jacquard's SessionRegistry.
    // AtProtoClient is for proxying requests only.
}
