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
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, LazyLock},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Maximum response size allowed (50MB)
pub const MAX_RESPONSE_SIZE: usize = 50 * 1024 * 1024;

/// Threshold above which responses are streamed instead of buffered (1MB)
pub const STREAM_THRESHOLD: usize = 1 * 1024 * 1024;

/// Moderation synchronization consumes buffered JSON and has a documented
/// four-MiB cumulative response ceiling. Preserve that contract while routing
/// larger declared JSON responses to the streaming path.
const MAX_BUFFERED_JSON_RESPONSE_SIZE: usize = 4 * STREAM_THRESHOLD;

/// A DPoP nonce challenge is a tiny JSON error document. Cap inspection well
/// below ordinary JSON responses so an attacker cannot disguise a large 401 as
/// a challenge that must be materialized before retry selection.
const MAX_DPOP_NONCE_CHALLENGE_SIZE: usize = 64 * 1024;

/// Process-wide ceiling for response heap capacity retained by buffered proxy
/// responses.
///
/// Streaming responses do not consume this budget. Buffered allocations retain
/// their permits until the final `Bytes` clone is dropped, so concurrent first
/// attempts cannot each materialize the per-response maximum. Charging capacity
/// (rather than length) also covers allocator space retained after `Vec` growth.
const MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES: usize = MAX_RESPONSE_SIZE;

static IN_FLIGHT_BUFFER_BUDGET: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES)));

struct BudgetedResponseBody {
    body: Vec<u8>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl AsRef<[u8]> for BudgetedResponseBody {
    fn as_ref(&self) -> &[u8] {
        &self.body
    }
}

/// Owns an already-materialized transport chunk together with its aggregate
/// retention charge. `Bytes::from_owner` propagates this owner through clones
/// and slices, so yielding the chunk cannot release its permit prematurely.
struct BudgetedPrefetchedChunk {
    body: bytes::Bytes,
    _permit: Option<OwnedSemaphorePermit>,
}

impl AsRef<[u8]> for BudgetedPrefetchedChunk {
    fn as_ref(&self) -> &[u8] {
        &self.body
    }
}

fn reserve_buffer_bytes(
    budget: &Arc<Semaphore>,
    len: usize,
) -> AppResult<Option<OwnedSemaphorePermit>> {
    if len == 0 {
        return Ok(None);
    }
    let permits = u32::try_from(len).map_err(|_| {
        AppError::ResponseTooLarge(
            "response chunk exceeds aggregate buffered response budget".to_string(),
        )
    })?;
    budget
        .clone()
        .try_acquire_many_owned(permits)
        .map(Some)
        .map_err(|_| {
            AppError::ResponseTooLarge(format!(
                "aggregate buffered response budget exhausted (maximum {} bytes)",
                MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES
            ))
        })
}

fn retain_prefetched_chunk(
    chunk: bytes::Bytes,
    budget: &Arc<Semaphore>,
) -> AppResult<bytes::Bytes> {
    let permit = reserve_buffer_bytes(budget, chunk.len())?;
    Ok(bytes::Bytes::from_owner(BudgetedPrefetchedChunk {
        body: chunk,
        _permit: permit,
    }))
}

struct BudgetedResponseBuilder {
    body: Vec<u8>,
    permit: Option<OwnedSemaphorePermit>,
    budget: Arc<Semaphore>,
    max_capacity: usize,
}

impl BudgetedResponseBuilder {
    fn new(budget: Arc<Semaphore>, max_capacity: usize) -> Self {
        Self {
            body: Vec::new(),
            permit: None,
            budget,
            max_capacity,
        }
    }

    fn append(&mut self, chunk: &[u8]) -> AppResult<()> {
        let next_len = self.body.len().checked_add(chunk.len()).ok_or_else(|| {
            AppError::ResponseTooLarge("buffered response length overflow".to_string())
        })?;
        if next_len > self.max_capacity {
            return Err(AppError::ResponseTooLarge(format!(
                "Response exceeded maximum size of {} bytes while reading",
                self.max_capacity
            )));
        }
        self.reserve_retained_capacity(next_len)?;
        self.body.extend_from_slice(chunk);
        debug_assert_eq!(self.charged_capacity(), self.body.capacity());
        Ok(())
    }

    fn reserve_retained_capacity(&mut self, required_capacity: usize) -> AppResult<()> {
        let old_capacity = self.body.capacity();
        if required_capacity <= old_capacity {
            return Ok(());
        }

        // Grow geometrically to keep highly fragmented responses from forcing
        // one allocation per frame, but acquire permits for the entire retained
        // target before allocating. The per-response ceiling bounds the target.
        let growth_target = old_capacity
            .checked_mul(2)
            .unwrap_or(self.max_capacity)
            .max(required_capacity)
            .min(self.max_capacity);
        let required_growth = growth_target - old_capacity;
        let required_permit = reserve_buffer_bytes(&self.budget, required_growth)?;
        self.body
            .try_reserve_exact(growth_target - self.body.len())
            .map_err(|_| AppError::Internal("failed to allocate response buffer".to_string()))?;

        // An allocator may round reserve_exact upward. Reconcile that excess
        // before retaining or exposing the buffer. If the aggregate budget
        // cannot cover it, returning drops this builder and its allocation.
        let actual_growth = self.body.capacity() - old_capacity;
        let excess_permit = reserve_buffer_bytes(&self.budget, actual_growth - required_growth)?;
        if let Some(permit) = required_permit {
            self.merge_permit(permit);
        }
        if let Some(permit) = excess_permit {
            self.merge_permit(permit);
        }
        Ok(())
    }

    fn merge_permit(&mut self, permit: OwnedSemaphorePermit) {
        if let Some(retained) = &mut self.permit {
            retained.merge(permit);
        } else {
            self.permit = Some(permit);
        }
    }

    fn charged_capacity(&self) -> usize {
        self.permit
            .as_ref()
            .map_or(0, OwnedSemaphorePermit::num_permits)
    }

    #[cfg(test)]
    fn permit_object_count(&self) -> usize {
        usize::from(self.permit.is_some())
    }

    fn finish(self) -> bytes::Bytes {
        debug_assert_eq!(self.charged_capacity(), self.body.capacity());
        bytes::Bytes::from_owner(BudgetedResponseBody {
            body: self.body,
            _permit: self.permit,
        })
    }
}

fn is_json_media_type(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence.ends_with("/json") || essence.ends_with("+json")
}

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
    stream: Pin<Box<dyn Stream<Item = AppResult<bytes::Bytes>> + Send>>,
}

impl BoundedResponse {
    fn new(response: reqwest::Response, max_size: usize, deadline: tokio::time::Instant) -> Self {
        let content_length = response.content_length();
        Self {
            stream: Box::pin(bounded_response_stream(
                response.bytes_stream(),
                content_length,
                max_size,
                deadline,
            )),
        }
    }

    fn from_prefetched<S, E>(
        prefix: bytes::Bytes,
        crossing_chunk: bytes::Bytes,
        remaining: S,
        max_size: usize,
        deadline: tokio::time::Instant,
    ) -> Self
    where
        S: Stream<Item = Result<bytes::Bytes, E>> + Send + 'static,
        E: fmt::Display + Send + 'static,
    {
        let prefetched =
            futures_util::stream::iter([Ok::<_, E>(prefix), Ok::<_, E>(crossing_chunk)]);
        Self {
            stream: Box::pin(bounded_response_stream(
                prefetched.chain(remaining),
                None,
                max_size,
                deadline,
            )),
        }
    }

    pub fn bytes_stream(self) -> impl Stream<Item = AppResult<bytes::Bytes>> + Send {
        self.stream
    }
}

enum UnknownLengthJsonBody {
    Buffered(bytes::Bytes),
    Streaming(BoundedResponse),
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

        // Large or non-JSON first responses stream immediately. Only small JSON
        // responses are buffered because a DPoP nonce challenge must be inspected.
        let first_response = self
            .do_proxy_request(
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
                MAX_RESPONSE_SIZE,
            )
            .await?;

        let (first_status, first_headers, first_body) = match first_response {
            ProxyResponse::Streaming {
                status,
                headers,
                body,
            } => {
                return Ok(ProxyResponse::Streaming {
                    status,
                    headers,
                    body,
                });
            }
            ProxyResponse::Buffered {
                status,
                headers,
                body,
            } => (status, headers, body),
        };

        // Check if we got a DPoP nonce error (401 with use_dpop_nonce)
        if first_status == 401 {
            if let Ok(error_json) = serde_json::from_slice::<Value>(&first_body) {
                if error_json.get("error").and_then(|e| e.as_str()) == Some("use_dpop_nonce") {
                    // Extract nonce from DPoP-Nonce header
                    if let Some(nonce_value) = first_headers.get("dpop-nonce") {
                        if let Ok(nonce) = nonce_value.to_str() {
                            let nonce = nonce.to_string();
                            let retry_body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
                            tracing::info!(
                                request_id = %request_id,
                                retry_body_size = retry_body_size,
                                original_body_size = body_size,
                                body_preserved = (retry_body_size == body_size),
                                "[BFF-DPOP-RETRY] Received nonce challenge, retrying"
                            );

                            // Retry with the nonce - use streaming-aware version
                            let remaining_budget = remaining_response_budget(first_body.len())?;
                            // The first response is already accounted for by the
                            // cumulative size budget; release its in-flight memory
                            // permits before the retry starts buffering.
                            drop(first_body);
                            return self
                                .do_proxy_request(
                                    session,
                                    method,
                                    &url,
                                    body,
                                    content_type,
                                    Some(nonce),
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
            status: first_status,
            headers: first_headers,
            body: first_body,
        })
    }

    /// Internal helper to perform the actual proxy request with streaming support
    ///
    /// Decides whether to buffer or stream based on content-length and content-type:
    /// - Responses > MAX_RESPONSE_SIZE (50MB): Rejected with error
    /// - Declared JSON responses above the moderation-safe buffer cap, or
    ///   non-JSON responses: streamed directly
    /// - Bounded JSON responses: buffered for potential processing
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

        let is_json = is_json_media_type(response_content_type);
        // A nonce-bearing 401 must be inspected even when the upstream omits or
        // mislabels Content-Type. The body remains subject to the strict 64-KiB
        // challenge cap before JSON parsing and retry selection.
        let is_nonce_challenge_candidate =
            !has_nonce && status == 401 && response_headers.contains_key("dpop-nonce");
        let max_buffered_size = if is_nonce_challenge_candidate {
            max_response_size.min(MAX_DPOP_NONCE_CHALLENGE_SIZE)
        } else {
            max_response_size.min(MAX_BUFFERED_JSON_RESPONSE_SIZE)
        };

        if is_nonce_challenge_candidate
            && content_length.is_some_and(|length| length > max_buffered_size)
        {
            return Err(AppError::ResponseTooLarge(format!(
                "DPoP nonce challenge exceeds maximum allowed {} bytes",
                max_buffered_size
            )));
        }

        let should_stream = !is_nonce_challenge_candidate
            && (content_length.is_some_and(|length| length > MAX_BUFFERED_JSON_RESPONSE_SIZE)
                || !is_json);

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
            // Unknown-length JSON remains buffered through the moderation cap,
            // then transitions to the same cumulative bounded stream used by
            // declared-large responses. The prefetched prefix retains its
            // aggregate-memory permit until downstream releases that chunk.
            let body = if !is_nonce_challenge_candidate && is_json && content_length.is_none() {
                match tokio::time::timeout_at(
                    deadline,
                    self.read_unknown_length_json(
                        response,
                        max_buffered_size,
                        max_response_size,
                        request_id,
                        deadline,
                    ),
                )
                .await
                .map_err(|_| AppError::Upstream {
                    status: 504,
                    message: "outbound request deadline exceeded reading body".to_string(),
                })?? {
                    UnknownLengthJsonBody::Buffered(body) => body,
                    UnknownLengthJsonBody::Streaming(body) => {
                        let elapsed_ms = start.elapsed().as_millis();
                        tracing::debug!(
                            request_id = %request_id,
                            attempt = attempt,
                            status = status,
                            elapsed_ms = elapsed_ms,
                            streaming = true,
                            adaptive = true,
                            "[BFF-UPSTREAM-RECV] Response from PDS (streaming)"
                        );
                        return Ok(ProxyResponse::Streaming {
                            status,
                            headers: response_headers,
                            body,
                        });
                    }
                }
            } else {
                tokio::time::timeout_at(
                    deadline,
                    self.read_response_with_limit(response, max_buffered_size, request_id),
                )
                .await
                .map_err(|_| AppError::Upstream {
                    status: 504,
                    message: "outbound request deadline exceeded reading body".to_string(),
                })??
            };
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
        self.read_response_with_limit_and_budget(
            response,
            max_size,
            request_id,
            IN_FLIGHT_BUFFER_BUDGET.clone(),
        )
        .await
    }

    async fn read_unknown_length_json(
        &self,
        response: reqwest::Response,
        max_buffered_size: usize,
        max_response_size: usize,
        request_id: &str,
        deadline: tokio::time::Instant,
    ) -> AppResult<UnknownLengthJsonBody> {
        let mut stream = response.bytes_stream();
        let mut body =
            BudgetedResponseBuilder::new(IN_FLIGHT_BUFFER_BUDGET.clone(), max_buffered_size);

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            let next_size = body.body.len().checked_add(chunk.len()).ok_or_else(|| {
                AppError::ResponseTooLarge("buffered response length overflow".to_string())
            })?;
            if next_size > max_response_size {
                tracing::warn!(
                    request_id = %request_id,
                    buffered_size = body.body.len(),
                    crossing_chunk_size = chunk.len(),
                    max_size = max_response_size,
                    "[BFF-UPSTREAM-ERR] Unknown-length JSON exceeded cumulative response limit"
                );
                return Err(AppError::ResponseTooLarge(format!(
                    "Response exceeded maximum size of {} bytes while reading",
                    max_response_size
                )));
            }
            if next_size > max_buffered_size {
                tracing::debug!(
                    request_id = %request_id,
                    buffered_size = body.body.len(),
                    crossing_chunk_size = chunk.len(),
                    "[BFF-UPSTREAM-RECV] Unknown-length JSON crossed buffer cap"
                );
                let chunk = retain_prefetched_chunk(chunk, &IN_FLIGHT_BUFFER_BUDGET)?;
                return Ok(UnknownLengthJsonBody::Streaming(
                    BoundedResponse::from_prefetched(
                        body.finish(),
                        chunk,
                        stream,
                        max_response_size,
                        deadline,
                    ),
                ));
            }
            body.append(&chunk)?;
        }

        Ok(UnknownLengthJsonBody::Buffered(body.finish()))
    }

    async fn read_response_with_limit_and_budget(
        &self,
        response: reqwest::Response,
        max_size: usize,
        request_id: &str,
        budget: Arc<Semaphore>,
    ) -> AppResult<bytes::Bytes> {
        Ok(self
            .read_response_builder_with_limit_and_budget(response, request_id, max_size, budget)
            .await?
            .finish())
    }

    async fn read_response_builder_with_limit_and_budget(
        &self,
        response: reqwest::Response,
        request_id: &str,
        max_size: usize,
        budget: Arc<Semaphore>,
    ) -> AppResult<BudgetedResponseBuilder> {
        let mut stream = response.bytes_stream();
        let mut body = BudgetedResponseBuilder::new(budget, max_size);

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            let next_size = body.body.len().checked_add(chunk.len());
            if next_size.is_none_or(|size| size > max_size) {
                tracing::warn!(
                    request_id = %request_id,
                    current_size = body.body.len(),
                    chunk_size = chunk.len(),
                    max_size = max_size,
                    "[BFF-UPSTREAM-ERR] Response exceeded size limit while reading"
                );
                return Err(AppError::ResponseTooLarge(format!(
                    "Response exceeded maximum size of {} bytes while reading",
                    max_size
                )));
            }
            body.append(&chunk)?;
        }

        Ok(body)
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
        run_nonce_retry_with_challenge_content_type(
            retry_body,
            retry_headers,
            first_delay,
            "application/json",
        )
        .await
    }

    async fn run_nonce_retry_with_challenge_content_type(
        retry_body: reqwest::Body,
        retry_headers: &[(&str, &str)],
        first_delay: Duration,
        challenge_content_type: &str,
    ) -> (ProxyResponse, Arc<QueueProxyTransport>) {
        run_nonce_retry_with_optional_challenge_content_type(
            retry_body,
            retry_headers,
            first_delay,
            Some(challenge_content_type),
        )
        .await
    }

    async fn run_nonce_retry_with_optional_challenge_content_type(
        retry_body: reqwest::Body,
        retry_headers: &[(&str, &str)],
        first_delay: Duration,
        challenge_content_type: Option<&str>,
    ) -> (ProxyResponse, Arc<QueueProxyTransport>) {
        let challenge = nonce_challenge();
        let mut challenge_headers = vec![("dpop-nonce", "server-nonce")];
        if let Some(content_type) = challenge_content_type {
            challenge_headers.push(("content-type", content_type));
        }
        let first = test_response(
            reqwest::StatusCode::UNAUTHORIZED,
            &challenge_headers,
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

    async fn run_single_proxy_response(response: reqwest::Response) -> AppResult<ProxyResponse> {
        let transport = Arc::new(QueueProxyTransport::new(vec![(Duration::ZERO, response)]));
        AtProtoClient::with_transport(transport)
            .proxy_request(
                &test_session(),
                reqwest::Method::GET,
                "/xrpc/app.bsky.feed.getTimeline",
                None,
                None,
                None,
                None,
                "single-response-test",
                Some(&test_dpop()),
            )
            .await
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
    async fn proxy_nonce_retry_still_buffers_small_json_response() {
        let expected = bytes::Bytes::from_static(br#"{"ok":true}"#);
        let (response, transport) = run_nonce_retry(
            reqwest::Body::from(expected.clone()),
            &[("content-type", "application/json")],
            Duration::ZERO,
        )
        .await;

        let ProxyResponse::Buffered { status, body, .. } = response else {
            panic!("small JSON nonce retry response must remain buffered");
        };
        assert_eq!(status, 200);
        assert_eq!(body, expected);
        let deadlines = transport.deadlines.lock().unwrap();
        assert_eq!(deadlines.len(), 2);
        assert_eq!(deadlines[0], deadlines[1]);
    }

    #[tokio::test]
    async fn proxy_nonce_retry_accepts_case_insensitive_json_media_type() {
        let expected = bytes::Bytes::from_static(br#"{"ok":true}"#);
        let (response, transport) = run_nonce_retry_with_challenge_content_type(
            reqwest::Body::from(expected.clone()),
            &[("content-type", "application/problem+json")],
            Duration::ZERO,
            "Application/JSON; Charset=UTF-8",
        )
        .await;

        let ProxyResponse::Buffered { status, body, .. } = response else {
            panic!("mixed-case JSON nonce challenge must still trigger retry");
        };
        assert_eq!(status, 200);
        assert_eq!(body, expected);
        assert_eq!(transport.deadlines.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn proxy_nonce_retry_buffers_challenge_when_content_type_is_untrusted() {
        for challenge_content_type in [None, Some("text/plain")] {
            let expected = bytes::Bytes::from_static(br#"{"ok":true}"#);
            let (response, transport) = run_nonce_retry_with_optional_challenge_content_type(
                reqwest::Body::from(expected.clone()),
                &[("content-type", "application/json")],
                Duration::ZERO,
                challenge_content_type,
            )
            .await;

            let ProxyResponse::Buffered { status, body, .. } = response else {
                panic!("nonce header must select bounded challenge inspection");
            };
            assert_eq!(status, 200);
            assert_eq!(body, expected);
            assert_eq!(transport.deadlines.lock().unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn unknown_length_json_crossing_buffer_cap_transitions_to_streaming() {
        let prefix = bytes::Bytes::from(vec![b'a'; MAX_BUFFERED_JSON_RESPONSE_SIZE]);
        let suffix = bytes::Bytes::from_static(b"b");
        let chunks = stream::iter([
            Ok::<_, io::Error>(prefix.clone()),
            Ok::<_, io::Error>(suffix.clone()),
        ]);
        let response = test_response(
            reqwest::StatusCode::OK,
            &[("content-type", "application/json")],
            reqwest::Body::wrap_stream(chunks),
        );

        let response = run_single_proxy_response(response)
            .await
            .expect("large chunked JSON remains a valid response");
        let ProxyResponse::Streaming { body, .. } = response else {
            panic!("unknown-length JSON above the buffer cap must stream");
        };
        let streamed: Vec<_> = body.bytes_stream().collect().await;
        let total: usize = streamed
            .iter()
            .map(|chunk| chunk.as_ref().expect("stream chunk").len())
            .sum();
        assert_eq!(total, prefix.len() + suffix.len());
    }

    #[tokio::test]
    async fn unknown_length_json_at_buffer_cap_remains_buffered() {
        let expected = bytes::Bytes::from(vec![b'a'; MAX_BUFFERED_JSON_RESPONSE_SIZE]);
        let chunks = stream::iter([
            Ok::<_, io::Error>(expected.slice(..2 * STREAM_THRESHOLD)),
            Ok::<_, io::Error>(expected.slice(2 * STREAM_THRESHOLD..)),
        ]);
        let response = test_response(
            reqwest::StatusCode::OK,
            &[("content-type", "application/json")],
            reqwest::Body::wrap_stream(chunks),
        );

        let response = run_single_proxy_response(response)
            .await
            .expect("JSON at the moderation cap remains valid");
        let ProxyResponse::Buffered { body, .. } = response else {
            panic!("unknown-length JSON at the buffer cap must remain buffered");
        };
        assert_eq!(body, expected);
    }

    #[tokio::test]
    async fn nonce_retry_rejects_oversized_json_crossing_chunk_before_streaming() {
        let challenge = nonce_challenge();
        let first = test_response(
            reqwest::StatusCode::UNAUTHORIZED,
            &[
                ("content-type", "application/json"),
                ("dpop-nonce", "server-nonce"),
            ],
            reqwest::Body::from(challenge),
        );
        let oversized_retry_chunk = bytes::Bytes::from(vec![0_u8; MAX_RESPONSE_SIZE]);
        let retry_stream = stream::iter([Ok::<_, io::Error>(oversized_retry_chunk)]);
        let second = test_response(
            reqwest::StatusCode::OK,
            &[("content-type", "application/json")],
            reqwest::Body::wrap_stream(retry_stream),
        );
        let transport = Arc::new(QueueProxyTransport::new(vec![
            (Duration::ZERO, first),
            (Duration::ZERO, second),
        ]));

        let result = AtProtoClient::with_transport(transport)
            .proxy_request(
                &test_session(),
                reqwest::Method::GET,
                "/xrpc/app.bsky.feed.getTimeline",
                None,
                None,
                None,
                None,
                "oversized-adaptive-retry-test",
                Some(&test_dpop()),
            )
            .await;

        assert!(matches!(result, Err(AppError::ResponseTooLarge(_))));
    }

    #[tokio::test]
    async fn concurrent_adaptive_crossing_chunks_share_aggregate_budget() {
        const CROSSING_SIZE: usize = 24 * 1024 * 1024;
        let responses = (0..2).map(|_| {
            let chunks = stream::iter([
                Ok::<_, io::Error>(bytes::Bytes::from(vec![
                    b'a';
                    MAX_BUFFERED_JSON_RESPONSE_SIZE
                ])),
                Ok::<_, io::Error>(bytes::Bytes::from(vec![b'b'; CROSSING_SIZE])),
            ]);
            let response = test_response(
                reqwest::StatusCode::OK,
                &[("content-type", "application/json")],
                reqwest::Body::wrap_stream(chunks),
            );
            run_single_proxy_response(response)
        });
        let results = futures_util::future::join_all(responses).await;
        let retained_responses = results
            .iter()
            .filter(|result| matches!(result, Ok(ProxyResponse::Streaming { .. })))
            .count();
        let charged =
            MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES - IN_FLIGHT_BUFFER_BUDGET.available_permits();

        assert!(
            charged >= retained_responses * (MAX_BUFFERED_JSON_RESPONSE_SIZE + CROSSING_SIZE),
            "aggregate permits must cover prefetched crossing chunks until yield or drop"
        );
        assert!(results.iter().any(|result| {
            matches!(result, Err(AppError::ResponseTooLarge(message)) if message.contains("aggregate"))
        }));

        drop(results);
        assert_eq!(
            IN_FLIGHT_BUFFER_BUDGET.available_permits(),
            MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES,
            "dropping unpolled adaptive streams must release all aggregate permits"
        );
    }

    #[test]
    fn prefetched_crossing_charge_survives_clones_and_slices() {
        let budget = Arc::new(Semaphore::new(1024));
        let body = retain_prefetched_chunk(bytes::Bytes::from(vec![b'a'; 512]), &budget)
            .expect("crossing chunk fits isolated budget");
        let clone = body.clone();
        let slice = clone.slice(1..clone.len() - 1);

        assert_eq!(budget.available_permits(), 512);
        drop(body);
        drop(clone);
        assert_eq!(budget.available_permits(), 512);
        drop(slice);
        assert_eq!(budget.available_permits(), 1024);
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

    #[tokio::test]
    async fn concurrent_first_attempt_buffers_share_one_aggregate_budget() {
        let body_size = MAX_BUFFERED_JSON_RESPONSE_SIZE;
        let responses = (0..13).map(|index| {
            let response = test_response(
                reqwest::StatusCode::OK,
                &[("content-type", "application/json")],
                reqwest::Body::from(vec![b'a' + index; body_size]),
            );
            run_single_proxy_response(response)
        });
        let results = futures_util::future::join_all(responses).await;
        let buffered_bytes: usize = results
            .iter()
            .filter_map(|result| match result {
                Ok(ProxyResponse::Buffered { body, .. }) => Some(body.len()),
                _ => None,
            })
            .sum();
        let rejected = results
            .iter()
            .filter(|result| matches!(result, Err(AppError::ResponseTooLarge(message)) if message.contains("aggregate")))
            .count();

        assert!(
            buffered_bytes <= MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES,
            "retained buffers must remain within the process-wide budget"
        );
        assert!(rejected >= 1, "aggregate exhaustion must fail closed");
    }

    #[tokio::test]
    async fn aggregate_budget_accounts_for_retained_vec_capacity() {
        const FIRST_CHUNK_SIZE: usize = 2 * 1024 * 1024 + 1;
        const SECOND_CHUNK_SIZE: usize = 1024 * 1024 - 1;
        let budget = Arc::new(Semaphore::new(MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES));
        let first_chunk = vec![b'a'; FIRST_CHUNK_SIZE];
        let second_chunk = vec![b'b'; SECOND_CHUNK_SIZE];
        let legacy_retained_capacity = {
            let mut body = Vec::new();
            body.extend_from_slice(&first_chunk);
            body.extend_from_slice(&second_chunk);
            assert!(
                body.capacity() > body.len(),
                "chunk pattern must force the prior geometric over-allocation"
            );
            body.capacity()
        };
        let client = AtProtoClient::with_transport(Arc::new(QueueProxyTransport::new(vec![])));
        let mut retained = Vec::new();
        let mut rejected = 0;

        for _ in 0..17 {
            let chunks = stream::iter(vec![
                Ok::<_, io::Error>(bytes::Bytes::from(first_chunk.clone())),
                Ok::<_, io::Error>(bytes::Bytes::from(second_chunk.clone())),
            ]);
            let response = test_response(
                reqwest::StatusCode::OK,
                &[("content-type", "application/json")],
                reqwest::Body::wrap_stream(chunks),
            );
            match client
                .read_response_with_limit_and_budget(
                    response,
                    MAX_BUFFERED_JSON_RESPONSE_SIZE,
                    "capacity-accounting-test",
                    budget.clone(),
                )
                .await
            {
                Ok(body) => retained.push(body),
                Err(AppError::ResponseTooLarge(message)) if message.contains("aggregate") => {
                    rejected += 1;
                }
                Err(error) => panic!("unexpected buffering error: {error}"),
            }
        }

        let charged = MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES - budget.available_permits();
        assert!(retained
            .iter()
            .all(|body| body.len() == FIRST_CHUNK_SIZE + SECOND_CHUNK_SIZE));

        assert!(
            charged <= MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES,
            "aggregate accounting must cover retained capacity"
        );
        assert!(
            (MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES / (FIRST_CHUNK_SIZE + SECOND_CHUNK_SIZE))
                * legacy_retained_capacity
                > MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES,
            "fixture must exceed the budget under prior length-only accounting"
        );
        assert!(
            rejected >= 1,
            "aggregate capacity exhaustion must fail closed"
        );

        let clone = retained[0].clone();
        let slice = clone.slice(1..clone.len() - 1);
        drop(retained);
        let shared_allocation_charge =
            MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES - budget.available_permits();
        assert!(shared_allocation_charge >= FIRST_CHUNK_SIZE + SECOND_CHUNK_SIZE);
        assert_eq!(
            MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES - budget.available_permits(),
            shared_allocation_charge,
            "clones and slices must retain the owner's capacity charge"
        );
        drop(clone);
        assert_eq!(
            MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES - budget.available_permits(),
            shared_allocation_charge,
            "a remaining slice must retain the owner's capacity charge"
        );
        drop(slice);
        assert_eq!(
            budget.available_permits(),
            MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES
        );
    }

    #[tokio::test]
    async fn fragmented_json_buffer_keeps_constant_permit_bookkeeping() {
        let budget = Arc::new(Semaphore::new(MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES));
        let fragments =
            stream::iter((0..4096).map(|_| Ok::<_, io::Error>(bytes::Bytes::from_static(b"a"))));
        let response = test_response(
            reqwest::StatusCode::OK,
            &[("content-type", "application/json")],
            reqwest::Body::wrap_stream(fragments),
        );
        let client = AtProtoClient::with_transport(Arc::new(QueueProxyTransport::new(vec![])));
        let builder = client
            .read_response_builder_with_limit_and_budget(
                response,
                "fragmented-capacity-test",
                MAX_BUFFERED_JSON_RESPONSE_SIZE,
                budget.clone(),
            )
            .await
            .expect("fragmented response fits");

        assert_eq!(builder.permit_object_count(), 1);
        assert_eq!(builder.charged_capacity(), builder.body.capacity());
        assert_eq!(builder.body.len(), 4096);

        let body = builder.finish();
        let clone = body.clone();
        let slice = clone.slice(1..clone.len() - 1);
        drop(body);
        drop(clone);
        assert!(budget.available_permits() < MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES);
        drop(slice);
        assert_eq!(
            budget.available_permits(),
            MAX_IN_FLIGHT_BUFFERED_RESPONSE_BYTES
        );
    }

    #[tokio::test(start_paused = true)]
    async fn declared_large_first_attempt_streams_without_polling_body() {
        let declared_length = 4 * 1024 * 1024 + 1;
        let pending_body =
            reqwest::Body::wrap_stream(stream::pending::<Result<bytes::Bytes, io::Error>>());
        let response = test_response(
            reqwest::StatusCode::OK,
            &[
                ("content-type", "application/json"),
                ("content-length", &declared_length.to_string()),
            ],
            pending_body,
        );

        let response = tokio::time::timeout(
            Duration::from_millis(1),
            run_single_proxy_response(response),
        )
        .await
        .expect("declared-large first attempt must not poll its body")
        .expect("declared-large first attempt remains a valid response");

        assert!(matches!(response, ProxyResponse::Streaming { .. }));
    }

    #[tokio::test]
    async fn declared_moderation_sized_json_first_attempt_remains_buffered() {
        let body = bytes::Bytes::from(vec![b' '; STREAM_THRESHOLD + 1]);
        let declared_length = body.len().to_string();
        let response = test_response(
            reqwest::StatusCode::OK,
            &[
                ("content-type", "application/json"),
                ("content-length", &declared_length),
            ],
            reqwest::Body::from(body.clone()),
        );

        let response = run_single_proxy_response(response)
            .await
            .expect("moderation-sized JSON remains valid");
        let ProxyResponse::Buffered { body: actual, .. } = response else {
            panic!("moderation-sized JSON must remain buffered for its consumer");
        };
        assert_eq!(actual, body);
    }

    #[tokio::test]
    async fn ordinary_empty_no_content_type_success_remains_streaming_compatible() {
        let response = test_response(
            reqwest::StatusCode::OK,
            &[],
            reqwest::Body::from(bytes::Bytes::new()),
        );

        let response = run_single_proxy_response(response)
            .await
            .expect("empty no-output procedure response remains valid");
        assert!(matches!(
            response,
            ProxyResponse::Streaming { status: 200, .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn declared_oversize_nonce_challenge_rejects_before_polling_body() {
        let pending_body =
            reqwest::Body::wrap_stream(stream::pending::<Result<bytes::Bytes, io::Error>>());
        let declared_length = (64 * 1024 + 1).to_string();
        let response = test_response(
            reqwest::StatusCode::UNAUTHORIZED,
            &[
                ("content-type", "application/json"),
                ("content-length", &declared_length),
                ("dpop-nonce", "server-nonce"),
            ],
            pending_body,
        );

        let result = tokio::time::timeout(
            Duration::from_millis(1),
            run_single_proxy_response(response),
        )
        .await
        .expect("oversized nonce challenge must reject before body polling");
        assert!(matches!(result, Err(AppError::ResponseTooLarge(_))));
    }
}
