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
    Buffered {
        status: u16,
        headers: HeaderMap,
        body: bytes::Bytes,
        bytes_transferred: usize,
    },
    /// Streaming response for larger payloads (passed through directly)
    Streaming {
        status: u16,
        headers: HeaderMap,
        body: reqwest::Response,
        max_bytes: usize,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
        rate_limit: Option<Arc<crate::middleware::RateLimitState>>,
        session_id: Option<String>,
        bytes_transferred: usize,
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

    /// Total bytes transferred / consumed across all attempts (including any prior nonce challenge)
    pub fn bytes_transferred(&self) -> usize {
        match self {
            ProxyResponse::Buffered {
                bytes_transferred, ..
            } => *bytes_transferred,
            ProxyResponse::Streaming {
                bytes_transferred, ..
            } => *bytes_transferred,
        }
    }
}

impl std::fmt::Debug for ProxyResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyResponse::Buffered {
                status,
                headers,
                body,
                bytes_transferred,
            } => f
                .debug_struct("ProxyResponse::Buffered")
                .field("status", status)
                .field("headers", headers)
                .field("body_len", &body.len())
                .field("bytes_transferred", bytes_transferred)
                .finish(),
            ProxyResponse::Streaming {
                status,
                headers,
                max_bytes,
                bytes_transferred,
                ..
            } => f
                .debug_struct("ProxyResponse::Streaming")
                .field("status", status)
                .field("headers", headers)
                .field("max_bytes", max_bytes)
                .field("bytes_transferred", bytes_transferred)
                .finish(),
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
        self.proxy_request_with_limit(
            session,
            method,
            path,
            query_string,
            body,
            content_type,
            client_headers,
            request_id,
            jacquard_dpop,
            MAX_RESPONSE_SIZE,
        )
        .await
    }

    /// Proxy a raw request to the PDS with an explicit maximum response size limit.
    /// Handles DPoP nonce retry automatically with remaining cumulative budget.
    #[allow(clippy::too_many_arguments)]
    pub async fn proxy_request_with_limit(
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
        max_bytes: usize,
    ) -> AppResult<ProxyResponse> {
        // SSRF protection & endpoint origin binding: validate PDS URL and target URL
        validate_pds_url(&session.pds_url)?;
        let pds_parsed = url::Url::parse(&session.pds_url)
            .map_err(|e| AppError::BadRequest(format!("Invalid PDS URL: {e}")))?;

        let base = session.pds_url.trim_end_matches('/');
        let url = if let Some(qs) = query_string {
            format!("{}{}?{}", base, path, qs)
        } else {
            format!("{}{}", base, path)
        };

        validate_pds_url(&url)?;
        let target_parsed = url::Url::parse(&url)
            .map_err(|e| AppError::BadRequest(format!("Invalid target URL: {e}")))?;
        if pds_parsed.origin() != target_parsed.origin() {
            return Err(AppError::BadRequest(
                "Request destination origin does not match session PDS origin".into(),
            ));
        }

        // Per-origin DPoP nonce cache: if we've already seen a nonce for
        // this origin (from any prior request, on any code path that
        // shares this cache), supply it on attempt 1 instead of always
        // paying a guaranteed `use_dpop_nonce` 401 round trip.
        let origin = crate::services::DpopNonceCache::origin_key(&url);
        let cached_nonce = origin
            .as_deref()
            .and_then(|o| self.state.dpop_nonce_cache.get(o));

        let body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
        let safe_url = sanitize_url_for_logging(&url);
        tracing::debug!(
            request_id = %request_id,
            url = %safe_url,
            method = %method,
            body_size = body_size,
            has_cached_nonce = cached_nonce.is_some(),
            "[BFF-UPSTREAM] First attempt"
        );

        // First attempt, with the cached nonce if we have one
        let mut headers = self
            .build_auth_headers_for_request(
                session,
                method.as_str(),
                &url,
                cached_nonce,
                jacquard_dpop,
            )
            .await?;

        if let Some(ct) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(ct).unwrap());
        }

        if let Some(ch) = client_headers {
            filter_client_headers(ch, &mut headers);
        }

        let mut request = self
            .state
            .http_client
            .request(method.clone(), &url)
            .headers(headers);
        if let Some(b) = body.clone() {
            request = request.body(b);
        }

        let start = std::time::Instant::now();
        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                let clean_err = e.without_url();
                let safe_url = sanitize_url_for_logging(&url);
                tracing::error!(
                    request_id = %request_id,
                    attempt = 1,
                    url = %safe_url,
                    error = %clean_err,
                    is_builder = clean_err.is_builder(),
                    is_request = clean_err.is_request(),
                    is_connect = clean_err.is_connect(),
                    is_body = clean_err.is_body(),
                    "[BFF-UPSTREAM-ERR] Request failed"
                );
                return Err(clean_err.into());
            }
        };

        let status = response.status().as_u16();
        let response_headers = response.headers().clone();

        self.record_nonce_from_headers(origin.as_deref(), &response_headers);

        let content_length = response_headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        // Check if we got a DPoP nonce error (401 with use_dpop_nonce)
        if status == 401 {
            let challenge_limit = max_bytes.min(STREAM_THRESHOLD);
            if challenge_limit == 0 {
                return Err(AppError::ResponseTooLarge(format!(
                    "Cumulative response size exceeded maximum allowed limit of {max_bytes} bytes"
                )));
            }
            let permit = if content_length.is_none() {
                Some(self.state.active_stream_semaphore.clone().try_acquire_owned().map_err(|_| {
                    tracing::warn!(
                        request_id = %request_id,
                        "[BFF-UPSTREAM-ERR] Active stream concurrency limit reached while buffering 401 (64 max)"
                    );
                    AppError::RateLimitExceeded { retry_after: 5 }
                })?)
            } else {
                None
            };
            let error_body = self
                .read_response_with_limit(
                    response,
                    challenge_limit,
                    request_id,
                    Some(&session.id.to_string()),
                    permit,
                )
                .await?;
            if let Ok(error_json) = serde_json::from_slice::<Value>(&error_body) {
                if error_json.get("error").and_then(|e| e.as_str()) == Some("use_dpop_nonce") {
                    if let Some(nonce_value) = response_headers.get("dpop-nonce") {
                        if let Ok(nonce) = nonce_value.to_str() {
                            let initial_bytes = error_body.len();
                            let remaining_budget = max_bytes.saturating_sub(initial_bytes);
                            if remaining_budget == 0 {
                                return Err(AppError::ResponseTooLarge(format!(
                                    "Cumulative response size exceeded maximum allowed limit of {max_bytes} bytes across attempts"
                                )));
                            }
                            let retry_body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
                            tracing::info!(
                                request_id = %request_id,
                                retry_body_size = retry_body_size,
                                original_body_size = body_size,
                                initial_consumed_bytes = initial_bytes,
                                remaining_budget = remaining_budget,
                                body_preserved = (retry_body_size == body_size),
                                "[BFF-DPOP-RETRY] Received nonce challenge, retrying"
                            );

                            // Retry with the nonce - use streaming-aware version with remaining cumulative budget.
                            let mut retry_response = self
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
                                    origin.as_deref(),
                                    remaining_budget,
                                )
                                .await?;

                            match &mut retry_response {
                                ProxyResponse::Buffered {
                                    bytes_transferred, ..
                                } => {
                                    *bytes_transferred =
                                        bytes_transferred.saturating_add(initial_bytes);
                                }
                                ProxyResponse::Streaming {
                                    bytes_transferred, ..
                                } => {
                                    *bytes_transferred =
                                        bytes_transferred.saturating_add(initial_bytes);
                                }
                            }

                            return Ok(retry_response);
                        }
                    }
                    tracing::warn!(
                        request_id = %request_id,
                        "[BFF-DPOP-RETRY] Got use_dpop_nonce error but no DPoP-Nonce header in response"
                    );
                }
            }

            let initial_bytes = error_body.len();
            return Ok(ProxyResponse::Buffered {
                status,
                headers: response_headers,
                body: error_body,
                bytes_transferred: initial_bytes,
            });
        }

        // For non-401 responses on attempt 1: apply size limits and streaming/buffering decision
        if let Some(len) = content_length {
            if len > max_bytes {
                tracing::warn!(
                    request_id = %request_id,
                    content_length = len,
                    max_size = max_bytes,
                    "[BFF-UPSTREAM-ERR] Response too large"
                );
                return Err(AppError::ResponseTooLarge(format!(
                    "Response size {} bytes exceeds maximum allowed {} bytes",
                    len, max_bytes
                )));
            }
        }

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
                attempt = 1,
                status = status,
                elapsed_ms = elapsed_ms,
                content_length = ?content_length,
                max_bytes = max_bytes,
                streaming = true,
                "[BFF-UPSTREAM-RECV] Response from PDS (streaming)"
            );

            let permit = match self
                .state
                .active_stream_semaphore
                .clone()
                .try_acquire_owned()
            {
                Ok(permit) => permit,
                Err(_) => {
                    tracing::warn!(
                        request_id = %request_id,
                        "[BFF-UPSTREAM-ERR] Active stream concurrency limit reached (64 max)"
                    );
                    return Err(AppError::RateLimitExceeded { retry_after: 5 });
                }
            };

            Ok(ProxyResponse::Streaming {
                status,
                headers: response_headers,
                body: response,
                max_bytes,
                permit: Some(permit),
                rate_limit: Some(self.state.rate_limit.clone()),
                session_id: Some(session.id.to_string()),
                bytes_transferred: 0,
            })
        } else {
            let permit = if content_length.is_none() {
                Some(self.state.active_stream_semaphore.clone().try_acquire_owned().map_err(|_| {
                    tracing::warn!(
                        request_id = %request_id,
                        "[BFF-UPSTREAM-ERR] Active stream concurrency limit reached while buffering unknown-length JSON response (64 max)"
                    );
                    AppError::RateLimitExceeded { retry_after: 5 }
                })?)
            } else {
                None
            };

            let body = self
                .read_response_with_limit(
                    response,
                    max_bytes,
                    request_id,
                    Some(&session.id.to_string()),
                    permit,
                )
                .await?;
            let elapsed_ms = start.elapsed().as_millis();

            tracing::debug!(
                request_id = %request_id,
                attempt = 1,
                status = status,
                elapsed_ms = elapsed_ms,
                body_size = body.len(),
                "[BFF-UPSTREAM-RECV] Response from PDS (buffered)"
            );

            let body_len = body.len();
            Ok(ProxyResponse::Buffered {
                status,
                headers: response_headers,
                body,
                bytes_transferred: body_len,
            })
        }
    }

    /// Internal helper to perform the actual proxy request with streaming support
    ///
    /// Decides whether to buffer or stream based on content-length and content-type:
    /// - Responses > max_bytes: Rejected with error
    /// - Responses > STREAM_THRESHOLD (1MB) or non-JSON: Streamed directly
    /// - Small JSON responses: Buffered for potential processing
    #[allow(clippy::too_many_arguments)]
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
        origin: Option<&str>,
        max_bytes: usize,
    ) -> AppResult<ProxyResponse> {
        let has_nonce = nonce.is_some();
        let mut headers = self
            .build_auth_headers_for_request(session, method.as_str(), url, nonce, jacquard_dpop)
            .await?;

        if let Some(ct) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(ct).unwrap());
        }

        // Forward all safe client headers using positive allowlist
        if let Some(ch) = client_headers {
            filter_client_headers(ch, &mut headers);
        }

        let body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
        let safe_url = sanitize_url_for_logging(url);
        tracing::debug!(
            request_id = %request_id,
            attempt = attempt,
            url = %safe_url,
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
                let clean_err = e.without_url();
                let safe_url = sanitize_url_for_logging(url);
                tracing::error!(
                    request_id = %request_id,
                    attempt = attempt,
                    url = %safe_url,
                    error = %clean_err,
                    is_builder = clean_err.is_builder(),
                    is_request = clean_err.is_request(),
                    is_connect = clean_err.is_connect(),
                    is_body = clean_err.is_body(),
                    "[BFF-UPSTREAM-ERR] Request failed"
                );
                return Err(clean_err.into());
            }
        };

        let status = response.status().as_u16();
        let response_headers = response.headers().clone();

        self.record_nonce_from_headers(origin, &response_headers);

        // Check Content-Length for size limits
        let content_length = response_headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        // Reject responses that are too large
        if let Some(len) = content_length {
            if len > max_bytes {
                tracing::warn!(
                    request_id = %request_id,
                    content_length = len,
                    max_size = max_bytes,
                    "[BFF-UPSTREAM-ERR] Response too large"
                );
                return Err(AppError::ResponseTooLarge(format!(
                    "Response size {} bytes exceeds maximum allowed {} bytes",
                    len, max_bytes
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
                max_bytes = max_bytes,
                streaming = true,
                "[BFF-UPSTREAM-RECV] Response from PDS (streaming)"
            );

            let permit = match self
                .state
                .active_stream_semaphore
                .clone()
                .try_acquire_owned()
            {
                Ok(permit) => permit,
                Err(_) => {
                    tracing::warn!(
                        request_id = %request_id,
                        "[BFF-UPSTREAM-ERR] Active stream concurrency limit reached (64 max)"
                    );
                    return Err(AppError::RateLimitExceeded { retry_after: 5 });
                }
            };

            Ok(ProxyResponse::Streaming {
                status,
                headers: response_headers,
                body: response,
                max_bytes,
                permit: Some(permit),
                rate_limit: Some(self.state.rate_limit.clone()),
                session_id: Some(session.id.to_string()),
                bytes_transferred: 0,
            })
        } else {
            // Buffer small JSON responses. If content_length is unknown (None), acquire semaphore permit before buffering.
            let permit = if content_length.is_none() {
                Some(self.state.active_stream_semaphore.clone().try_acquire_owned().map_err(|_| {
                    tracing::warn!(
                        request_id = %request_id,
                        "[BFF-UPSTREAM-ERR] Active stream concurrency limit reached while buffering unknown-length JSON response (64 max)"
                    );
                    AppError::RateLimitExceeded { retry_after: 5 }
                })?)
            } else {
                None
            };

            let body = self
                .read_response_with_limit(
                    response,
                    max_bytes,
                    request_id,
                    Some(&session.id.to_string()),
                    permit,
                )
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

            // Log error response metadata (never raw bodies)
            if status >= 400 && status != 401 {
                tracing::warn!(
                    request_id = %request_id,
                    attempt = attempt,
                    status = status,
                    "[BFF-UPSTREAM-ERR] PDS error response"
                );
            }

            let body_len = body.len();
            Ok(ProxyResponse::Buffered {
                status,
                headers: response_headers,
                body,
                bytes_transferred: body_len,
            })
        }
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
        session_id: Option<&str>,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> AppResult<bytes::Bytes> {
        let _permit = permit;
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
            if let Some(sess_id) = session_id {
                self.state
                    .rate_limit
                    .check_and_record_bytes(sess_id, chunk.len() as u64)
                    .await
                    .map_err(|retry_after| AppError::RateLimitExceeded { retry_after })?;
            }
            body.extend_from_slice(&chunk);
        }

        Ok(bytes::Bytes::from(body))
    }

    /// Update the shared per-origin DPoP nonce cache from a response's
    /// `DPoP-Nonce` header, if present.
    pub(crate) fn record_nonce_from_headers(&self, origin: Option<&str>, headers: &HeaderMap) {
        let Some(origin) = origin else {
            return;
        };
        if let Some(value) = headers.get("dpop-nonce") {
            if let Ok(nonce) = value.to_str() {
                self.state
                    .dpop_nonce_cache
                    .set(origin.to_string(), nonce.to_string());
            }
        }
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

        let dpop_data = jacquard_dpop
            .ok_or_else(|| AppError::Internal("Missing Jacquard DPoP data for request".into()))?;

        use base64::Engine;
        use sha2::{Digest, Sha256};

        // Compute access token hash (ath)
        let ath = {
            let hash = Sha256::digest(session.access_token.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
        };

        let dpop_htu = url.split('?').next().unwrap_or(url);

        let dpop_proof = jacquard_oauth::dpop::build_dpop_proof(
            &dpop_data.dpop_key,
            method,
            dpop_htu,
            nonce.as_deref(),
            Some(ath.as_str()),
        )
        .map_err(|e| AppError::Internal(format!("Jacquard DPoP proof failed: {}", e)))?;

        let auth_value = format!("DPoP {}", session.access_token);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value).map_err(|e| AppError::Internal(e.to_string()))?,
        );
        headers.insert(
            "DPoP",
            HeaderValue::from_str(dpop_proof.as_ref())
                .map_err(|e| AppError::Internal(e.to_string()))?,
        );

        Ok(headers)
    }
}

/// Redacts query parameters from URLs for privacy-safe tracing.
fn sanitize_url_for_logging(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

/// Filter client headers before forwarding to upstream PDS using a strict positive allowlist.
/// Allows documented AT Protocol and application headers:
/// - accept
/// - accept-encoding
/// - accept-language
/// - content-type
/// - atproto-proxy
/// - atproto-accept-labelers
/// All other headers (e.g. host, forwarded, x-forwarded-*, sec-*, cookie, authorization, dpop, hop-by-hop) are dropped.
pub fn filter_client_headers(client_headers: &HeaderMap, out_headers: &mut HeaderMap) {
    for (name, value) in client_headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if matches!(
            name_lower.as_str(),
            "accept"
                | "accept-encoding"
                | "accept-language"
                | "content-type"
                | "atproto-proxy"
                | "atproto-accept-labelers"
        ) {
            if name_lower == "content-type" && out_headers.contains_key(CONTENT_TYPE) {
                continue;
            }
            out_headers.insert(name.clone(), value.clone());
        }
    }
}

/// Wraps a byte stream with cumulative size enforcement up to `max_bytes` and optional held semaphore permit.
/// Aborts the stream with an error if total transferred bytes exceed the limit.
pub fn bounded_byte_stream_with_accounting<S, E>(
    stream: S,
    max_bytes: usize,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    rate_limit: Option<Arc<crate::middleware::RateLimitState>>,
    session_id: Option<String>,
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Unpin + Send + 'static
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    let total_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _permit = permit;
    Box::pin(stream.then(move |chunk_res| {
        let _ = &_permit;
        let total_bytes = total_bytes.clone();
        let rate_limit = rate_limit.clone();
        let session_id = session_id.clone();
        async move {
            match chunk_res {
                Ok(chunk) => {
                    let prev =
                        total_bytes.fetch_add(chunk.len(), std::sync::atomic::Ordering::Relaxed);
                    let current = prev + chunk.len();
                    if current > max_bytes {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Response exceeded maximum allowed size of {max_bytes} bytes"),
                        ));
                    }
                    if let (Some(rl), Some(sess)) = (rate_limit, session_id) {
                        if let Err(retry_after) =
                            rl.check_and_record_bytes(&sess, chunk.len() as u64).await
                        {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("Rate limit exceeded: retry after {retry_after}s"),
                            ));
                        }
                    }
                    Ok(chunk)
                }
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Upstream stream error: {e}"),
                )),
            }
        }
    }))
}

/// Wraps a byte stream with cumulative size enforcement up to `max_bytes` and optional held semaphore permit.
/// Aborts the stream with an error if total transferred bytes exceed the limit.
pub fn bounded_byte_stream_with_permit<S, E>(
    stream: S,
    max_bytes: usize,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Unpin + Send + 'static
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    bounded_byte_stream_with_accounting(stream, max_bytes, permit, None, None)
}

/// Wraps a byte stream with cumulative size enforcement up to `max_bytes`.
/// Aborts the stream with an error if total transferred bytes exceed the limit.
pub fn bounded_byte_stream<S, E>(
    stream: S,
    max_bytes: usize,
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Unpin + Send + 'static
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    bounded_byte_stream_with_permit(stream, max_bytes, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    #[test]
    fn test_filter_client_headers_strips_cookie_and_gateway_auth() {
        let mut client_headers = HeaderMap::new();
        client_headers.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_static(
                "catbird_session=550e8400-e29b-41d4-a716-446655440000; other=1",
            ),
        );
        client_headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer nest-secret-bearer"),
        );
        client_headers.insert(
            HeaderName::from_static("dpop"),
            HeaderValue::from_static("inbound-dpop-proof"),
        );
        client_headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_static("nest.catbird.blue"),
        );
        client_headers.insert(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("1234"),
        );
        client_headers.insert(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("application/json"),
        );

        let mut out_headers = HeaderMap::new();
        out_headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("DPoP pds-access-token"),
        );

        filter_client_headers(&client_headers, &mut out_headers);

        assert!(!out_headers.contains_key("cookie"));
        assert_eq!(
            out_headers.get("authorization").unwrap(),
            "DPoP pds-access-token"
        );
        assert!(!out_headers.contains_key("dpop"));
        assert!(!out_headers.contains_key("host"));
        assert!(!out_headers.contains_key("content-length"));
        assert_eq!(out_headers.get("accept").unwrap(), "application/json");
    }

    #[test]
    fn test_filter_client_headers_positive_allowlist_drops_forwarded_and_sec_headers() {
        let mut client_headers = HeaderMap::new();
        client_headers.insert(
            HeaderName::from_static("forwarded"),
            HeaderValue::from_static("for=192.0.2.60;proto=http;by=203.0.113.43"),
        );
        client_headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("192.0.2.60, 203.0.113.43"),
        );
        client_headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static("https"),
        );
        client_headers.insert(
            HeaderName::from_static("sec-fetch-site"),
            HeaderValue::from_static("same-origin"),
        );
        client_headers.insert(
            HeaderName::from_static("sec-fetch-mode"),
            HeaderValue::from_static("cors"),
        );
        client_headers.insert(
            HeaderName::from_static("set-cookie"),
            HeaderValue::from_static("session=stolen; Secure"),
        );
        client_headers.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("nest=secret"),
        );
        client_headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer nest-secret"),
        );
        client_headers.insert(
            HeaderName::from_static("dpop"),
            HeaderValue::from_static("inbound-proof"),
        );
        client_headers.insert(
            HeaderName::from_static("x-custom-header"),
            HeaderValue::from_static("untrusted"),
        );

        // Allowlisted headers:
        client_headers.insert(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("application/json"),
        );
        client_headers.insert(
            HeaderName::from_static("accept-language"),
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        client_headers.insert(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("gzip, deflate, br"),
        );
        client_headers.insert(
            HeaderName::from_static("atproto-proxy"),
            HeaderValue::from_static("did:web:api.bsky.chat#bsky_chat"),
        );
        client_headers.insert(
            HeaderName::from_static("atproto-accept-labelers"),
            HeaderValue::from_static("did:plc:ar7c404540u662fuut8jh7tr;redact"),
        );
        client_headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        let mut out_headers = HeaderMap::new();
        out_headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("DPoP pds-token"),
        );

        filter_client_headers(&client_headers, &mut out_headers);

        assert!(!out_headers.contains_key("forwarded"));
        assert!(!out_headers.contains_key("x-forwarded-for"));
        assert!(!out_headers.contains_key("x-forwarded-proto"));
        assert!(!out_headers.contains_key("sec-fetch-site"));
        assert!(!out_headers.contains_key("sec-fetch-mode"));
        assert!(!out_headers.contains_key("set-cookie"));
        assert!(!out_headers.contains_key("cookie"));
        assert!(!out_headers.contains_key("dpop"));
        assert!(!out_headers.contains_key("x-custom-header"));
        assert_eq!(out_headers.get("authorization").unwrap(), "DPoP pds-token");
        assert_eq!(out_headers.get("accept").unwrap(), "application/json");
        assert_eq!(
            out_headers.get("accept-language").unwrap(),
            "en-US,en;q=0.9"
        );
        assert_eq!(
            out_headers.get("accept-encoding").unwrap(),
            "gzip, deflate, br"
        );
        assert_eq!(
            out_headers.get("atproto-proxy").unwrap(),
            "did:web:api.bsky.chat#bsky_chat"
        );
        assert_eq!(
            out_headers.get("atproto-accept-labelers").unwrap(),
            "did:plc:ar7c404540u662fuut8jh7tr;redact"
        );
        assert_eq!(out_headers.get("content-type").unwrap(), "application/json");
    }

    #[tokio::test]
    async fn test_bounded_byte_stream_enforces_limit() {
        let chunks = vec![
            Ok::<_, String>(bytes::Bytes::from(vec![0u8; 100])),
            Ok(bytes::Bytes::from(vec![0u8; 100])),
            Ok(bytes::Bytes::from(vec![0u8; 100])),
        ];
        let input_stream = stream::iter(chunks);
        let mut bounded = bounded_byte_stream(input_stream, 250);

        let first = bounded.next().await.unwrap();
        assert!(first.is_ok());
        assert_eq!(first.unwrap().len(), 100);

        let second = bounded.next().await.unwrap();
        assert!(second.is_ok());
        assert_eq!(second.unwrap().len(), 100);

        // Third chunk exceeds 250 bytes total limit (300 > 250)
        let third = bounded.next().await.unwrap();
        assert!(third.is_err());
        let err_msg = third.unwrap_err().to_string();
        assert!(err_msg.contains("Response exceeded maximum allowed size"));
    }

    #[tokio::test]
    async fn test_bounded_byte_stream_with_permit_releases_semaphore() {
        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = sem.clone().try_acquire_owned().unwrap();
        assert_eq!(sem.available_permits(), 0);

        let chunks = vec![Ok::<_, String>(bytes::Bytes::from(vec![0u8; 100]))];
        let input_stream = stream::iter(chunks);
        let mut bounded = bounded_byte_stream_with_permit(input_stream, 250, Some(permit));

        let chunk = bounded.next().await.unwrap();
        assert!(chunk.is_ok());

        drop(bounded);
        assert_eq!(sem.available_permits(), 1);
    }

    #[tokio::test]
    async fn test_byte_rate_limiter_enforces_budget() {
        use crate::middleware::{ByteRateLimitConfig, ByteRateLimiter};
        use std::time::Duration;

        let limiter = ByteRateLimiter::new();
        let config = ByteRateLimitConfig {
            max_bytes: 500,
            window: Duration::from_secs(60),
        };

        // First 300 bytes ok
        assert!(limiter
            .check_and_record("sess_1", 300, &config)
            .await
            .is_ok());
        // Next 150 bytes ok (450 total <= 500)
        assert!(limiter
            .check_and_record("sess_1", 150, &config)
            .await
            .is_ok());
        // Next 100 bytes exceeds budget (550 > 500)
        let err = limiter
            .check_and_record("sess_1", 100, &config)
            .await
            .unwrap_err();
        assert!(err >= 1);

        // Independent session has its own budget
        assert!(limiter
            .check_and_record("sess_2", 400, &config)
            .await
            .is_ok());
    }
    #[tokio::test]
    async fn test_bounded_byte_stream_with_accounting_enforces_session_and_global_rate_limits() {
        use crate::middleware::{ByteRateLimitConfig, RateLimitConfig, RateLimitState};
        use std::time::Duration;

        let rl = Arc::new(RateLimitState {
            session_limiter: Arc::new(crate::middleware::RateLimiter::new()),
            ip_limiter: Arc::new(crate::middleware::RateLimiter::new()),
            session_byte_limiter: Arc::new(crate::middleware::ByteRateLimiter::new()),
            global_byte_limiter: Arc::new(crate::middleware::ByteRateLimiter::new()),
            session_config: RateLimitConfig::default(),
            ip_config: RateLimitConfig::default(),
            session_byte_config: ByteRateLimitConfig {
                max_bytes: 250, // 250 bytes session limit
                window: Duration::from_secs(60),
            },
            global_byte_config: ByteRateLimitConfig {
                max_bytes: 1000,
                window: Duration::from_secs(60),
            },
            trusted_proxies: Vec::new(),
        });

        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = sem.clone().try_acquire_owned().unwrap();

        let chunks = vec![
            Ok::<_, String>(bytes::Bytes::from(vec![0u8; 100])),
            Ok(bytes::Bytes::from(vec![0u8; 100])),
            Ok(bytes::Bytes::from(vec![0u8; 100])), // 300 total > 250 session limit
        ];
        let input_stream = stream::iter(chunks);
        let mut bounded = bounded_byte_stream_with_accounting(
            input_stream,
            1000,
            Some(permit),
            Some(rl.clone()),
            Some("session_abc".to_string()),
        );

        let first = bounded.next().await.unwrap();
        assert!(first.is_ok());
        assert_eq!(first.unwrap().len(), 100);

        let second = bounded.next().await.unwrap();
        assert!(second.is_ok());
        assert_eq!(second.unwrap().len(), 100);

        // Third chunk exceeds 250 byte rate limit budget
        let third = bounded.next().await.unwrap();
        assert!(third.is_err());
        let err = third.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("Rate limit exceeded"));

        // Drop stream releases semaphore permit
        drop(bounded);
        assert_eq!(sem.available_permits(), 1);
    }

    #[tokio::test]
    #[ignore = "requires running Redis (REDIS_URL)"]
    async fn test_proxy_request_with_limit_bounds_dpop_challenge_and_tracks_cumulative_bytes() {
        use chrono::Utc;
        use uuid::Uuid;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;

        let error_body = serde_json::json!({
            "error": "use_dpop_nonce",
            "message": "Use DPoP nonce"
        });
        let error_body_bytes = serde_json::to_vec(&error_body).unwrap();
        let error_len = error_body_bytes.len();

        let success_body = serde_json::json!({
            "convos": []
        });
        let success_body_bytes = serde_json::to_vec(&success_body).unwrap();
        let success_len = success_body_bytes.len();

        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("dpop-nonce", "fresh-nonce-test-123")
                    .set_body_json(error_body),
            )
            .up_to_n_times(1)
            .mount(&pds)
            .await;

        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .respond_with(ResponseTemplate::new(200).set_body_json(success_body))
            .mount(&pds)
            .await;

        let config = crate::config::AppConfig::test_default();
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client()
                .expect("hardened raw client"),
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(crate::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:test_dpop_challenge_user".to_string(),
            handle: "user.test".to_string(),
            pds_url: pds.uri(),
            access_token: "mock_token".to_string(),
            refresh_token: "mock_refresh".to_string(),
            scopes: vec!["atproto".to_string()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".to_string()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = crate::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        let client = AtProtoClient::new(state.clone());
        let response = client
            .proxy_request_with_limit(
                &session,
                reqwest::Method::GET,
                "/xrpc/chat.bsky.convo.listConvos",
                None,
                None,
                None,
                None,
                "test_dpop_req",
                Some(&dpop_data),
                10000,
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let total_transferred = response.bytes_transferred();
        assert_eq!(
            total_transferred,
            error_len + success_len,
            "ProxyResponse bytes_transferred must be cumulative across 401 challenge and retry attempt"
        );
    }

    #[tokio::test]
    #[ignore = "requires running Redis (REDIS_URL)"]
    async fn test_proxy_request_with_limit_rejects_when_dpop_challenge_exceeds_budget() {
        use chrono::Utc;
        use uuid::Uuid;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;

        let large_error_body = serde_json::json!({
            "error": "use_dpop_nonce",
            "padding": "a".repeat(400)
        });

        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("dpop-nonce", "fresh-nonce-test-456")
                    .set_body_json(large_error_body),
            )
            .mount(&pds)
            .await;

        let config = crate::config::AppConfig::test_default();
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client()
                .expect("hardened raw client"),
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(crate::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:test_dpop_budget_user".to_string(),
            handle: "user.test".to_string(),
            pds_url: pds.uri(),
            access_token: "mock_token".to_string(),
            refresh_token: "mock_refresh".to_string(),
            scopes: vec!["atproto".to_string()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".to_string()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = crate::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        let client = AtProtoClient::new(state.clone());
        // Limit is only 200 bytes, while the 401 challenge body is > 400 bytes.
        // Bounding by min(max_bytes, STREAM_THRESHOLD) must abort with ResponseTooLarge before buffering 1MB.
        let res = client
            .proxy_request_with_limit(
                &session,
                reqwest::Method::GET,
                "/xrpc/chat.bsky.convo.listConvos",
                None,
                None,
                None,
                None,
                "test_dpop_req_exceeded",
                Some(&dpop_data),
                200,
            )
            .await;

        assert!(res.is_err());
        match res.unwrap_err() {
            AppError::ResponseTooLarge(msg) => {
                assert!(
                    msg.contains("exceeded maximum size")
                        || msg.contains("exceeds maximum allowed")
                );
            }
            other => panic!("Expected ResponseTooLarge, got {:?}", other),
        }
    }
}
