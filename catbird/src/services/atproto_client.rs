//! ATProto Client Service
//!
//! Handles communication with ATProto PDS servers, including:
//! - Request proxying with DPoP nonce retry
//! - DPoP proof generation via Jacquard

use super::ssrf::validate_pds_url;
use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::models::CatbirdSession;
use futures_util::{Stream, StreamExt};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::{fmt, future::Future, pin::Pin, sync::Arc};

/// Maximum response size allowed (50MB)
pub const MAX_RESPONSE_SIZE: usize = 50 * 1024 * 1024;

/// Threshold above which responses are streamed instead of buffered (1MB)
pub const STREAM_THRESHOLD: usize = 1 * 1024 * 1024;

trait ProxyTransport: Send + Sync {
    fn send_before<'a>(
        &'a self,
        method: reqwest::Method,
        url: &'a str,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
        deadline: tokio::time::Instant,
    ) -> Pin<Box<dyn Future<Output = Result<reqwest::Response, String>> + Send + 'a>>;
}

impl ProxyTransport for crate::config::outbound_policy::OutboundPolicy {
    fn send_before<'a>(
        &'a self,
        method: reqwest::Method,
        url: &'a str,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
        deadline: tokio::time::Instant,
    ) -> Pin<Box<dyn Future<Output = Result<reqwest::Response, String>> + Send + 'a>> {
        Box::pin(async move {
            crate::config::outbound_policy::OutboundPolicy::send_before(
                self, method, url, headers, body, deadline,
            )
            .await
            .map_err(|error| error.to_string())
        })
    }
}

fn remaining_response_budget(consumed: usize) -> AppResult<usize> {
    MAX_RESPONSE_SIZE.checked_sub(consumed).ok_or_else(|| {
        AppError::ResponseTooLarge(format!(
            "cumulative response size exceeds maximum allowed {} bytes",
            MAX_RESPONSE_SIZE
        ))
    })
}

struct BoundedStreamState<S> {
    stream: Pin<Box<S>>,
    seen: usize,
    max_size: usize,
    deadline: tokio::time::Instant,
    declared_oversize: bool,
    terminal: bool,
}

fn bounded_response_stream<S, E>(
    stream: S,
    content_length: Option<u64>,
    max_size: usize,
    deadline: tokio::time::Instant,
) -> impl Stream<Item = AppResult<bytes::Bytes>> + Send
where
    S: Stream<Item = Result<bytes::Bytes, E>> + Send + 'static,
    E: fmt::Display,
{
    let state = BoundedStreamState {
        stream: Box::pin(stream),
        seen: 0,
        max_size,
        deadline,
        declared_oversize: content_length.is_some_and(|length| length > max_size as u64),
        terminal: false,
    };

    futures_util::stream::unfold(state, |mut state| async move {
        if state.terminal {
            return None;
        }
        if state.declared_oversize {
            state.terminal = true;
            return Some((
                Err(AppError::ResponseTooLarge(format!(
                    "declared response size exceeds maximum allowed {} bytes",
                    state.max_size
                ))),
                state,
            ));
        }

        match tokio::time::timeout_at(state.deadline, state.stream.next()).await {
            Err(_) => {
                state.terminal = true;
                Some((
                    Err(AppError::Upstream {
                        status: 504,
                        message: "outbound request deadline exceeded reading stream".to_string(),
                    }),
                    state,
                ))
            }
            Ok(None) => None,
            Ok(Some(Err(error))) => {
                state.terminal = true;
                Some((
                    Err(AppError::Upstream {
                        status: 502,
                        message: format!("upstream response read failed: {error}"),
                    }),
                    state,
                ))
            }
            Ok(Some(Ok(chunk))) => {
                let next_size = state.seen.checked_add(chunk.len());
                if next_size.is_none_or(|size| size > state.max_size) {
                    state.terminal = true;
                    Some((
                        Err(AppError::ResponseTooLarge(format!(
                            "response exceeded maximum size of {} bytes while streaming",
                            state.max_size
                        ))),
                        state,
                    ))
                } else {
                    state.seen = next_size.expect("checked above");
                    Some((Ok(chunk), state))
                }
            }
        }
    })
}

pub struct BoundedResponse {
    response: reqwest::Response,
    max_size: usize,
    deadline: tokio::time::Instant,
}

impl BoundedResponse {
    fn new(response: reqwest::Response, max_size: usize, deadline: tokio::time::Instant) -> Self {
        Self {
            response,
            max_size,
            deadline,
        }
    }

    pub fn bytes_stream(self) -> impl Stream<Item = AppResult<bytes::Bytes>> + Send {
        let content_length = self.response.content_length();
        bounded_response_stream(
            self.response.bytes_stream(),
            content_length,
            self.max_size,
            self.deadline,
        )
    }
}

const FORWARDED_CLIENT_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "atproto-proxy",
    "atproto-accept-labelers",
    "range",
    "if-range",
    "if-none-match",
    "if-modified-since",
];

fn merge_allowed_client_headers(headers: &mut HeaderMap, client_headers: Option<&HeaderMap>) {
    let Some(client_headers) = client_headers else {
        return;
    };

    for (name, value) in client_headers {
        if FORWARDED_CLIENT_HEADERS.contains(&name.as_str()) {
            headers.insert(name.clone(), value.clone());
        }
    }
}

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
        body: BoundedResponse,
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
    transport: Arc<dyn ProxyTransport>,
}

impl AtProtoClient {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            transport: Arc::new(state.outbound_policy.clone()),
        }
    }

    #[cfg(test)]
    fn with_transport(transport: Arc<dyn ProxyTransport>) -> Self {
        Self { transport }
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
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        // SSRF protection: validate the PDS URL before making any requests
        validate_pds_url(&session.pds_url)?;

        let base = session.pds_url.trim_end_matches('/');
        let url = if let Some(qs) = query_string {
            format!("{}{}?{}", base, path, qs)
        } else {
            format!("{}{}", base, path)
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
                deadline,
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
                            let remaining_budget =
                                remaining_response_budget(first_response.2.len())?;
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
                                    deadline,
                                    remaining_budget,
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
        deadline: tokio::time::Instant,
        max_response_size: usize,
    ) -> AppResult<ProxyResponse> {
        let has_nonce = nonce.is_some();
        let mut headers = self
            .build_auth_headers_for_request(session, method.as_str(), url, nonce, jacquard_dpop)
            .await?;

        if let Some(ct) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(ct).unwrap());
        }

        merge_allowed_client_headers(&mut headers, client_headers);

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

        let start = std::time::Instant::now();
        let response = match self
            .transport
            .send_before(method, url, headers, body, deadline)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    request_id = %request_id,
                    attempt = attempt,
                    url = %url,
                    error = %e,
                    "[BFF-UPSTREAM-ERR] Request failed"
                );
                return Err(AppError::Upstream {
                    status: 502,
                    message: e.to_string(),
                });
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
            if len > max_response_size {
                tracing::warn!(
                    request_id = %request_id,
                    content_length = len,
                    max_size = max_response_size,
                    "[BFF-UPSTREAM-ERR] Response too large"
                );
                return Err(AppError::ResponseTooLarge(format!(
                    "Response size {} bytes exceeds maximum allowed {} bytes",
                    len, max_response_size
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
                body: BoundedResponse::new(response, max_response_size, deadline),
            })
        } else {
            // Buffer small JSON responses
            let body = tokio::time::timeout_at(
                deadline,
                self.read_response_with_limit(response, max_response_size, request_id),
            )
            .await
            .map_err(|_| AppError::Upstream {
                status: 504,
                message: "outbound request deadline exceeded reading body".to_string(),
            })??;
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
                    let truncated = if error_text.len() > 200 {
                        &error_text[..200]
                    } else {
                        error_text
                    };
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
        deadline: tokio::time::Instant,
    ) -> AppResult<(u16, HeaderMap, bytes::Bytes)> {
        let has_nonce = nonce.is_some();
        let mut headers = self
            .build_auth_headers_for_request(session, method.as_str(), url, nonce, jacquard_dpop)
            .await?;

        if let Some(ct) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(ct).unwrap());
        }

        if let Some(ch) = client_headers {
            let client_proxy = ch.get("atproto-proxy").map(|v| v.to_str().unwrap_or("?"));
            tracing::info!(
                request_id = %request_id,
                client_atproto_proxy = ?client_proxy,
                client_header_count = ch.len(),
                "[BFF-HDR] Client headers received (buffered)"
            );
        }
        merge_allowed_client_headers(&mut headers, client_headers);

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

        let start = std::time::Instant::now();
        let response = match self
            .transport
            .send_before(method, url, headers, body, deadline)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    request_id = %request_id,
                    attempt = attempt,
                    url = %url,
                    error = %e,
                    "[BFF-UPSTREAM-ERR] Request failed"
                );
                return Err(AppError::Upstream {
                    status: 502,
                    message: e.to_string(),
                });
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
        let body = tokio::time::timeout_at(
            deadline,
            self.read_response_with_limit(response, MAX_RESPONSE_SIZE, request_id),
        )
        .await
        .map_err(|_| AppError::Upstream {
            status: 504,
            message: "outbound request deadline exceeded reading body".to_string(),
        })??;
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

        let dpop_data = jacquard_dpop
            .ok_or_else(|| AppError::Internal("Missing Jacquard DPoP data for request".into()))?;

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
            HeaderValue::from_str(&auth_value).map_err(|e| AppError::Internal(e.to_string()))?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;
    use jacquard_common::CowStr;
    use std::collections::VecDeque;
    use std::io;
    use std::sync::Mutex;
    use std::time::Duration;

    struct QueueProxyTransport {
        replies: Mutex<VecDeque<(Duration, reqwest::Response)>>,
        deadlines: Mutex<Vec<tokio::time::Instant>>,
    }

    impl QueueProxyTransport {
        fn new(replies: Vec<(Duration, reqwest::Response)>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                deadlines: Mutex::new(Vec::new()),
            }
        }
    }

    impl ProxyTransport for QueueProxyTransport {
        fn send_before<'a>(
            &'a self,
            _method: reqwest::Method,
            _url: &'a str,
            _headers: HeaderMap,
            _body: Option<bytes::Bytes>,
            deadline: tokio::time::Instant,
        ) -> Pin<Box<dyn Future<Output = Result<reqwest::Response, String>> + Send + 'a>> {
            self.deadlines.lock().expect("deadline lock").push(deadline);
            let (delay, response) = self
                .replies
                .lock()
                .expect("reply lock")
                .pop_front()
                .expect("queued response");
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(response)
            })
        }
    }

    fn test_response(
        status: reqwest::StatusCode,
        headers: &[(&str, &str)],
        body: reqwest::Body,
    ) -> reqwest::Response {
        let mut builder = http::Response::builder().status(status);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(body).expect("test response").into()
    }

    fn nonce_challenge() -> bytes::Bytes {
        bytes::Bytes::from_static(br#"{"error":"use_dpop_nonce","padding":"bounded"}"#)
    }

    fn test_session() -> CatbirdSession {
        let now = chrono::Utc::now();
        CatbirdSession {
            id: uuid::Uuid::new_v4(),
            did: "did:plc:alice".to_string(),
            handle: "alice.example".to_string(),
            pds_url: "https://pds.example".to_string(),
            access_token: "access-token".to_string(),
            refresh_token: "refresh-token".to_string(),
            access_token_expires_at: now + chrono::Duration::hours(1),
            created_at: now,
            last_used_at: now,
        }
    }

    fn test_dpop() -> crate::middleware::JacquardDpopData {
        crate::middleware::JacquardDpopData {
            dpop_key: jacquard_oauth::utils::generate_key(&[CowStr::new_static("ES256")])
                .expect("test DPoP key"),
            dpop_host_nonce: String::new(),
        }
    }

    async fn run_nonce_retry(
        retry_body: reqwest::Body,
        retry_headers: &[(&str, &str)],
        first_delay: Duration,
    ) -> (ProxyResponse, Arc<QueueProxyTransport>) {
        let challenge = nonce_challenge();
        let first = test_response(
            reqwest::StatusCode::UNAUTHORIZED,
            &[
                ("content-type", "application/json"),
                ("dpop-nonce", "server-nonce"),
            ],
            reqwest::Body::from(challenge),
        );
        let second = test_response(reqwest::StatusCode::OK, retry_headers, retry_body);
        let transport = Arc::new(QueueProxyTransport::new(vec![
            (first_delay, first),
            (Duration::ZERO, second),
        ]));
        let client = AtProtoClient::with_transport(transport.clone());
        let response = client
            .proxy_request(
                &test_session(),
                reqwest::Method::GET,
                "/xrpc/app.bsky.feed.getTimeline",
                None,
                None,
                None,
                None,
                "nonce-retry-test",
                Some(&test_dpop()),
            )
            .await
            .expect("proxy response");
        (response, transport)
    }

    #[test]
    fn proxy_headers_forward_only_the_explicit_allowlist() {
        let mut outbound = HeaderMap::new();
        outbound.insert(
            AUTHORIZATION,
            HeaderValue::from_static("DPoP upstream-token"),
        );
        outbound.insert("dpop", HeaderValue::from_static("upstream-proof"));
        outbound.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let mut client = HeaderMap::new();
        for (name, value) in [
            ("accept", "application/json"),
            ("accept-language", "en-US"),
            ("atproto-proxy", "did:web:example.com#atproto_labeler"),
            ("atproto-accept-labelers", "did:plc:labeler;redact"),
            ("range", "bytes=0-99"),
            ("if-range", "etag-a"),
            ("if-none-match", "etag-b"),
            ("if-modified-since", "Sat, 12 Jul 2026 00:00:00 GMT"),
            ("cookie", "sid=browser-secret"),
            ("cookie2", "sid=legacy-secret"),
            ("authorization", "Bearer browser-secret"),
            ("dpop", "browser-proof"),
            ("host", "attacker.example"),
            ("content-length", "999"),
            ("connection", "keep-alive"),
            ("forwarded", "for=192.0.2.1"),
            ("x-forwarded-for", "192.0.2.1"),
            ("sec-fetch-site", "same-origin"),
            ("origin", "https://app.example"),
            ("referer", "https://app.example/private"),
            ("x-unknown", "must-not-cross"),
            ("content-type", "text/plain"),
        ] {
            client.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }

        merge_allowed_client_headers(&mut outbound, Some(&client));

        for name in [
            "accept",
            "accept-language",
            "atproto-proxy",
            "atproto-accept-labelers",
            "range",
            "if-range",
            "if-none-match",
            "if-modified-since",
        ] {
            assert_eq!(
                outbound.get(name),
                client.get(name),
                "allowed header {name}"
            );
        }

        assert_eq!(outbound.get(AUTHORIZATION).unwrap(), "DPoP upstream-token");
        assert_eq!(outbound.get("dpop").unwrap(), "upstream-proof");
        assert_eq!(outbound.get(CONTENT_TYPE).unwrap(), "application/json");

        for name in [
            "cookie",
            "cookie2",
            "host",
            "content-length",
            "connection",
            "forwarded",
            "x-forwarded-for",
            "sec-fetch-site",
            "origin",
            "referer",
            "x-unknown",
        ] {
            assert!(!outbound.contains_key(name), "blocked header {name}");
        }
    }

    #[tokio::test]
    async fn streamed_response_rejects_declared_oversize_before_polling() {
        let stream = stream::pending::<Result<bytes::Bytes, io::Error>>();
        let results: Vec<_> = bounded_response_stream(
            stream,
            Some((MAX_RESPONSE_SIZE + 1) as u64),
            MAX_RESPONSE_SIZE,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .collect()
        .await;
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], Err(AppError::ResponseTooLarge(_))));
    }

    #[tokio::test]
    async fn streamed_response_rejects_unknown_length_oversize() {
        let stream = stream::iter([
            Ok::<_, io::Error>(bytes::Bytes::from(vec![0; MAX_RESPONSE_SIZE])),
            Ok(bytes::Bytes::from_static(b"x")),
        ]);
        let results: Vec<_> = bounded_response_stream(
            stream,
            None,
            MAX_RESPONSE_SIZE,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .collect()
        .await;
        assert_eq!(results.len(), 2);
        assert!(results[0]
            .as_ref()
            .is_ok_and(|chunk| chunk.len() == MAX_RESPONSE_SIZE));
        assert!(matches!(results[1], Err(AppError::ResponseTooLarge(_))));
    }

    #[tokio::test]
    async fn streamed_response_accepts_exact_limit() {
        let stream = stream::iter([Ok::<_, io::Error>(bytes::Bytes::from(vec![
            0;
            MAX_RESPONSE_SIZE
        ]))]);
        let results: Vec<_> = bounded_response_stream(
            stream,
            None,
            MAX_RESPONSE_SIZE,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .collect()
        .await;
        assert_eq!(results.len(), 1);
        assert!(results[0]
            .as_ref()
            .is_ok_and(|chunk| chunk.len() == MAX_RESPONSE_SIZE));
    }

    #[tokio::test(start_paused = true)]
    async fn streamed_response_uses_absolute_deadline() {
        let stream = stream::once(async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok::<_, io::Error>(bytes::Bytes::from_static(b"late"))
        });
        let results: Vec<_> = bounded_response_stream(
            stream,
            None,
            MAX_RESPONSE_SIZE,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .collect()
        .await;
        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            Err(AppError::Upstream { status: 504, .. })
        ));
    }

    #[test]
    fn nonce_retry_uses_remaining_cumulative_response_budget() {
        assert_eq!(remaining_response_budget(0).unwrap(), MAX_RESPONSE_SIZE);
        assert_eq!(remaining_response_budget(MAX_RESPONSE_SIZE - 8).unwrap(), 8);
        assert_eq!(remaining_response_budget(MAX_RESPONSE_SIZE).unwrap(), 0);
        assert!(matches!(
            remaining_response_budget(MAX_RESPONSE_SIZE + 1),
            Err(AppError::ResponseTooLarge(_))
        ));
    }

    #[tokio::test]
    async fn proxy_nonce_retry_accepts_exact_cumulative_stream_limit() {
        let remaining = MAX_RESPONSE_SIZE - nonce_challenge().len();
        let content_length = remaining.to_string();
        let (response, transport) = run_nonce_retry(
            reqwest::Body::from(vec![0_u8; remaining]),
            &[
                ("content-type", "application/octet-stream"),
                ("content-length", content_length.as_str()),
            ],
            Duration::ZERO,
        )
        .await;

        let ProxyResponse::Streaming { body, .. } = response else {
            panic!("retry response was not streamed");
        };
        let chunks: Vec<_> = body.bytes_stream().collect().await;
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ref().unwrap().len(), remaining);
        assert_eq!(transport.deadlines.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn proxy_nonce_retry_rejects_cumulative_unknown_length_oversize() {
        let remaining = MAX_RESPONSE_SIZE - nonce_challenge().len();
        let retry_stream = stream::iter([Ok::<_, io::Error>(bytes::Bytes::from(vec![
            0_u8;
            remaining
                + 1
        ]))]);
        let (response, _) = run_nonce_retry(
            reqwest::Body::wrap_stream(retry_stream),
            &[("content-type", "application/octet-stream")],
            Duration::ZERO,
        )
        .await;

        let ProxyResponse::Streaming { body, .. } = response else {
            panic!("retry response was not streamed");
        };
        let chunks: Vec<_> = body.bytes_stream().collect().await;
        assert_eq!(chunks.len(), 1);
        assert!(matches!(chunks[0], Err(AppError::ResponseTooLarge(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn proxy_nonce_retry_stream_keeps_original_absolute_deadline() {
        let retry_stream = stream::once(async {
            tokio::time::sleep(Duration::from_secs(6)).await;
            Ok::<_, io::Error>(bytes::Bytes::from_static(b"late"))
        });
        let (response, transport) = run_nonce_retry(
            reqwest::Body::wrap_stream(retry_stream),
            &[("content-type", "application/octet-stream")],
            Duration::from_secs(25),
        )
        .await;

        let ProxyResponse::Streaming { body, .. } = response else {
            panic!("retry response was not streamed");
        };
        let chunks: Vec<_> = body.bytes_stream().collect().await;
        assert_eq!(chunks.len(), 1);
        assert!(matches!(
            &chunks[0],
            Err(AppError::Upstream { status: 504, .. })
        ));
        let deadlines = transport.deadlines.lock().unwrap();
        assert_eq!(deadlines.len(), 2);
        assert_eq!(deadlines[0], deadlines[1]);
    }
}
