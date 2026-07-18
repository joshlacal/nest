//! Validated, DNS-pinned transport for requests to attacker-selected hosts.

use futures_util::{pin_mut, Stream, StreamExt};
use jacquard_common::http_client::HttpClient;
use jacquard_common::types::{did::Did, string::Handle};
use jacquard_identity::resolver::{DidDocResponse, IdentityResolver, ResolverOptions};
use jacquard_oauth::dpop::DpopOperationContext;
use reqwest::{header::HeaderMap, Method, Response, Url};
use std::{
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    time::Duration,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECT_HOPS: usize = 3;
const MAX_OPERATION_ATTEMPTS: usize = 2 * (MAX_REDIRECT_HOPS + 1);
/// OAuth metadata, identity documents, and post-login profile enrichment are
/// compact JSON/text documents. One MiB leaves ample room for real DID docs
/// while preventing discovery endpoints from turning a login into an
/// unbounded allocation. The authenticated XRPC proxy keeps its separate
/// 50 MiB response policy.
const DISCOVERY_RESPONSE_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RedirectMode {
    FollowSameOrigin,
    Reject,
}

trait OutboundIo: Send + Sync {
    fn validate_before<'a>(
        &'a self,
        input: &'a str,
        deadline: tokio::time::Instant,
    ) -> Pin<Box<dyn Future<Output = Result<ValidatedUrl, PolicyError>> + Send + 'a>>;

    fn send_once<'a>(
        &'a self,
        method: Method,
        target: &'a ValidatedUrl,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
        remaining: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Response, PolicyError>> + Send + 'a>>;
}

#[derive(Debug, Clone)]
pub struct PolicyError(String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for PolicyError {}

#[derive(Clone, Debug)]
pub struct ValidatedUrl {
    url: Url,
    addresses: Vec<IpAddr>,
}

impl ValidatedUrl {
    pub fn parse(input: &str) -> Result<Self, PolicyError> {
        let url = Url::parse(input).map_err(|e| PolicyError(format!("invalid URL: {e}")))?;
        if url.scheme() != "https" || url.host_str().is_none() {
            return Err(PolicyError(
                "outbound URL must use HTTPS and have a host".into(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(PolicyError(
                "outbound URL cannot contain userinfo or a fragment".into(),
            ));
        }
        Ok(Self {
            url,
            addresses: Vec::new(),
        })
    }

    pub fn require_same_origin(&self, candidate: &str) -> Result<Url, PolicyError> {
        let candidate = Self::parse(candidate)?.url;
        if origin(&self.url) != origin(&candidate) {
            return Err(PolicyError(
                "credential endpoint must have the issuer's exact origin".into(),
            ));
        }
        Ok(candidate)
    }

    pub fn with_addresses(mut self, addresses: Vec<IpAddr>) -> Result<Self, PolicyError> {
        if addresses.is_empty() || addresses.iter().any(|ip| !is_global(*ip)) {
            return Err(PolicyError(
                "DNS result contains a non-global address".into(),
            ));
        }
        addresses.iter().for_each(|ip| {
            if !self.addresses.contains(ip) {
                self.addresses.push(*ip);
            }
        });
        Ok(self)
    }

    #[cfg(test)]
    fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
}

fn origin(url: &Url) -> (&str, &str, u16) {
    (
        url.scheme(),
        url.host_str().expect("validated host"),
        url.port_or_known_default().expect("https port"),
    )
}

#[derive(Clone, Default)]
pub struct OutboundPolicy;

impl OutboundPolicy {
    pub async fn validate(&self, input: &str) -> Result<ValidatedUrl, PolicyError> {
        self.validate_before(input, tokio::time::Instant::now() + REQUEST_TIMEOUT)
            .await
    }

    async fn validate_before(
        &self,
        input: &str,
        deadline: tokio::time::Instant,
    ) -> Result<ValidatedUrl, PolicyError> {
        let parsed = ValidatedUrl::parse(input)?;
        let host = parsed.url.host_str().expect("validated host").to_owned();
        let port = parsed.url.port_or_known_default().expect("https port");
        let answers =
            tokio::time::timeout_at(deadline, tokio::net::lookup_host((host.as_str(), port)))
                .await
                .map_err(|_| PolicyError("outbound request deadline exceeded during DNS".into()))?
                .map_err(|e| PolicyError(format!("DNS resolution failed: {e}")))?
                .map(|address| address.ip())
                .collect();
        parsed.with_addresses(answers)
    }

    pub async fn send(
        &self,
        method: Method,
        input: &str,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
    ) -> Result<Response, PolicyError> {
        self.send_bounded(
            method,
            input,
            headers,
            body,
            REQUEST_TIMEOUT,
            RedirectMode::FollowSameOrigin,
        )
        .await
        .map(|(response, _)| response)
    }

    pub(crate) async fn send_before(
        &self,
        method: Method,
        input: &str,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
        deadline: tokio::time::Instant,
    ) -> Result<Response, PolicyError> {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| PolicyError("outbound request deadline exceeded".into()))?;
        self.send_bounded(
            method,
            input,
            headers,
            body,
            remaining,
            RedirectMode::FollowSameOrigin,
        )
        .await
        .map(|(response, _)| response)
    }

    /// Send a discovery/enrichment request and collect its body under the
    /// policy's one-MiB byte budget and the same absolute request deadline.
    pub async fn send_discovery(
        &self,
        method: Method,
        input: &str,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
    ) -> Result<(reqwest::StatusCode, HeaderMap, bytes::Bytes), PolicyError> {
        let (response, deadline) = self
            .send_bounded(
                method,
                input,
                headers,
                body,
                REQUEST_TIMEOUT,
                RedirectMode::FollowSameOrigin,
            )
            .await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = read_response_bounded(response, DISCOVERY_RESPONSE_LIMIT, deadline).await?;
        Ok((status, headers, body))
    }

    /// Send a credential-bearing request without ever replaying its headers
    /// across a redirect, and collect the response under the caller's byte
    /// budget and absolute deadline.
    ///
    /// DNS is resolved and classified immediately before dispatch, and the
    /// accepted addresses are pinned into the per-request HTTP client. This
    /// is the authenticated counterpart to [`Self::send_discovery`].
    pub(crate) async fn send_credential_bounded_before(
        &self,
        method: Method,
        input: &str,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
        max_response_bytes: usize,
        deadline: tokio::time::Instant,
    ) -> Result<(reqwest::StatusCode, HeaderMap, bytes::Bytes), PolicyError> {
        send_credential_bounded_before_with_io(
            self,
            method,
            input,
            headers,
            body,
            max_response_bytes,
            deadline,
        )
        .await
    }

    async fn send_bounded(
        &self,
        method: Method,
        input: &str,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
        budget: Duration,
        redirect_mode: RedirectMode,
    ) -> Result<(Response, tokio::time::Instant), PolicyError> {
        send_bounded_with_io(self, method, input, headers, body, budget, redirect_mode).await
    }

    async fn send_once(
        &self,
        method: Method,
        target: &ValidatedUrl,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
        remaining: Duration,
    ) -> Result<Response, PolicyError> {
        let host = target.url.host_str().expect("validated host");
        let port = target.url.port_or_known_default().expect("https port");
        let pinned: Vec<_> = target
            .addresses
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT.min(remaining))
            .timeout(remaining)
            .resolve_to_addrs(host, &pinned)
            .build()
            .map_err(|e| PolicyError(format!("HTTP client setup failed: {e}")))?;
        let mut request = client.request(method, target.url.clone()).headers(headers);
        if let Some(body) = body {
            request = request.body(body);
        }
        request
            .send()
            .await
            .map_err(|e| PolicyError(format!("outbound request failed: {e}")))
    }
}

async fn send_credential_bounded_before_with_io<I: OutboundIo + ?Sized>(
    io: &I,
    method: Method,
    input: &str,
    headers: HeaderMap,
    body: Option<bytes::Bytes>,
    max_response_bytes: usize,
    deadline: tokio::time::Instant,
) -> Result<(reqwest::StatusCode, HeaderMap, bytes::Bytes), PolicyError> {
    let (response, deadline) = send_bounded_until_with_io(
        io,
        method,
        input,
        headers,
        body,
        deadline,
        RedirectMode::Reject,
        None,
        1,
    )
    .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = read_response_bounded(response, max_response_bytes, deadline).await?;
    Ok((status, headers, body))
}

async fn send_bounded_with_io<I: OutboundIo + ?Sized>(
    io: &I,
    method: Method,
    input: &str,
    headers: HeaderMap,
    body: Option<bytes::Bytes>,
    budget: Duration,
    redirect_mode: RedirectMode,
) -> Result<(Response, tokio::time::Instant), PolicyError> {
    let deadline = tokio::time::Instant::now() + budget;
    send_bounded_until_with_io(
        io,
        method,
        input,
        headers,
        body,
        deadline,
        redirect_mode,
        None,
        MAX_REDIRECT_HOPS + 1,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_bounded_until_with_io<I: OutboundIo + ?Sized>(
    io: &I,
    mut method: Method,
    input: &str,
    headers: HeaderMap,
    mut body: Option<bytes::Bytes>,
    deadline: tokio::time::Instant,
    redirect_mode: RedirectMode,
    operation: Option<&DpopOperationContext>,
    max_operation_attempts: usize,
) -> Result<(Response, tokio::time::Instant), PolicyError> {
    let original = ValidatedUrl::parse(input)?;
    let mut current = original.url.clone();
    for hop in 0..=MAX_REDIRECT_HOPS {
        let target = io.validate_before(current.as_str(), deadline).await?;
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| PolicyError("outbound request deadline exceeded".into()))?;
        if operation.is_some_and(|operation| !operation.try_record_attempt(max_operation_attempts))
        {
            return Err(PolicyError(
                "outbound operation attempt limit exceeded".into(),
            ));
        }
        let response = io
            .send_once(
                method.clone(),
                &target,
                headers.clone(),
                body.clone(),
                remaining,
            )
            .await?;
        if !should_follow_redirect(response.status(), redirect_mode) {
            return Ok((response, deadline));
        }
        if hop == MAX_REDIRECT_HOPS {
            return Err(PolicyError("outbound redirect limit exceeded".into()));
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| PolicyError("redirect missing valid Location".into()))?;
        let next = current
            .join(location)
            .map_err(|e| PolicyError(format!("invalid redirect Location: {e}")))?;
        original.require_same_origin(next.as_str())?;
        if matches!(response.status().as_u16(), 301..=303) {
            method = Method::GET;
            body = None;
        }
        current = next;
    }
    unreachable!("bounded redirect loop returns")
}

impl OutboundIo for OutboundPolicy {
    fn validate_before<'a>(
        &'a self,
        input: &'a str,
        deadline: tokio::time::Instant,
    ) -> Pin<Box<dyn Future<Output = Result<ValidatedUrl, PolicyError>> + Send + 'a>> {
        Box::pin(OutboundPolicy::validate_before(self, input, deadline))
    }

    fn send_once<'a>(
        &'a self,
        method: Method,
        target: &'a ValidatedUrl,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
        remaining: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Response, PolicyError>> + Send + 'a>> {
        Box::pin(OutboundPolicy::send_once(
            self, method, target, headers, body, remaining,
        ))
    }
}

async fn read_response_bounded(
    response: Response,
    max_bytes: usize,
    deadline: tokio::time::Instant,
) -> Result<bytes::Bytes, PolicyError> {
    let content_length = response.content_length();
    collect_bounded_stream(response.bytes_stream(), content_length, max_bytes, deadline).await
}

async fn collect_bounded_stream<S, E>(
    stream: S,
    content_length: Option<u64>,
    max_bytes: usize,
    deadline: tokio::time::Instant,
) -> Result<bytes::Bytes, PolicyError>
where
    S: Stream<Item = Result<bytes::Bytes, E>>,
    E: fmt::Display,
{
    if content_length.is_some_and(|length| length > max_bytes as u64) {
        return Err(PolicyError(format!(
            "response Content-Length exceeds {max_bytes}-byte limit"
        )));
    }

    let collect = async move {
        pin_mut!(stream);
        let initial_capacity = content_length
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(max_bytes);
        let mut body = Vec::with_capacity(initial_capacity);
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|error| PolicyError(format!("response read failed: {error}")))?;
            let next_size = body
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| PolicyError("response byte limit exceeded".into()))?;
            if next_size > max_bytes {
                return Err(PolicyError(format!(
                    "response byte limit exceeded ({max_bytes} bytes)"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(bytes::Bytes::from(body))
    };

    tokio::time::timeout_at(deadline, collect)
        .await
        .map_err(|_| PolicyError("outbound request deadline exceeded reading body".into()))?
}

impl HttpClient for OutboundPolicy {
    type Error = PolicyError;

    async fn send_http(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, Self::Error> {
        send_http_with_io(self, request).await
    }
}

async fn send_http_with_io<I: OutboundIo + ?Sized>(
    io: &I,
    request: http::Request<Vec<u8>>,
) -> Result<http::Response<Vec<u8>>, PolicyError> {
    send_http_with_io_limits(
        io,
        request,
        REQUEST_TIMEOUT,
        DISCOVERY_RESPONSE_LIMIT,
        MAX_OPERATION_ATTEMPTS,
    )
    .await
}

async fn send_http_with_io_limits<I: OutboundIo + ?Sized>(
    io: &I,
    request: http::Request<Vec<u8>>,
    timeout: Duration,
    max_response_bytes: usize,
    max_operation_attempts: usize,
) -> Result<http::Response<Vec<u8>>, PolicyError> {
    let (mut parts, body) = request.into_parts();
    let operation = parts
        .extensions
        .remove::<DpopOperationContext>()
        .unwrap_or_default();
    let deadline = operation
        .started_at()
        .checked_add(timeout)
        .map(tokio::time::Instant::from_std)
        .ok_or_else(|| PolicyError("outbound request deadline is invalid".into()))?;
    let redirect_mode = take_redirect_mode(&mut parts.headers);
    let method = Method::from_bytes(parts.method.as_str().as_bytes())
        .map_err(|e| PolicyError(format!("invalid method: {e}")))?;
    let (response, deadline) = send_bounded_until_with_io(
        io,
        method,
        &parts.uri.to_string(),
        parts.headers,
        Some(body.into()),
        deadline,
        redirect_mode,
        Some(&operation),
        max_operation_attempts,
    )
    .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let remaining_bytes = operation
        .remaining_response_bytes(max_response_bytes)
        .ok_or_else(|| PolicyError("response byte limit exceeded".into()))?;
    let bytes = read_response_bounded(response, remaining_bytes, deadline).await?;
    if !operation.try_record_response_bytes(bytes.len(), max_response_bytes) {
        return Err(PolicyError(format!(
            "response byte limit exceeded ({max_response_bytes} bytes)"
        )));
    }
    let mut builder = http::Response::builder().status(status);
    *builder.headers_mut().expect("response builder headers") = headers;
    builder
        .body(bytes.to_vec())
        .map_err(|e| PolicyError(format!("response build failed: {e}")))
}

#[derive(Clone)]
pub struct PolicyOAuthResolver {
    identity: jacquard_identity::JacquardResolver<OutboundPolicy>,
    policy: OutboundPolicy,
}

impl PolicyOAuthResolver {
    pub fn new(identity: jacquard_identity::JacquardResolver<OutboundPolicy>) -> Self {
        Self {
            identity,
            policy: OutboundPolicy,
        }
    }
}

impl HttpClient for PolicyOAuthResolver {
    type Error = PolicyError;
    async fn send_http(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, Self::Error> {
        self.policy.send_http(request).await
    }
}

impl IdentityResolver for PolicyOAuthResolver {
    fn options(&self) -> &ResolverOptions {
        self.identity.options()
    }
    async fn resolve_handle(
        &self,
        handle: &Handle<'_>,
    ) -> jacquard_identity::resolver::Result<Did<'static>> {
        self.identity.resolve_handle(handle).await
    }
    async fn resolve_did_doc(
        &self,
        did: &Did<'_>,
    ) -> jacquard_identity::resolver::Result<DidDocResponse> {
        self.identity.resolve_did_doc(did).await
    }
}

impl jacquard_oauth::resolver::OAuthResolver for PolicyOAuthResolver {}
impl jacquard_oauth::dpop::DpopExt for PolicyOAuthResolver {}

/// Shared fail-closed SSRF classifier for literal and DNS-resolved addresses.
///
/// IPv6 is limited to IANA's global-unicast `2000::/3` allocation, with the
/// existing special-purpose exclusions applied inside that allocation. IPv4-
/// mapped IPv6 addresses deliberately reuse the IPv4 policy.
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_v4(ip),
        IpAddr::V6(ip) => is_global_v6(ip),
    }
}

fn is_followed_redirect(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

fn should_follow_redirect(status: reqwest::StatusCode, mode: RedirectMode) -> bool {
    mode == RedirectMode::FollowSameOrigin && is_followed_redirect(status)
}

fn take_redirect_mode(headers: &mut HeaderMap) -> RedirectMode {
    if headers
        .remove(jacquard_oauth::request::OAUTH_CREDENTIAL_REQUEST_HEADER)
        .is_some()
    {
        RedirectMode::Reject
    } else {
        RedirectMode::FollowSameOrigin
    }
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 224
        || ip.is_broadcast()
        || ip.is_documentation())
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_global_v4(v4);
    }
    let segments = ip.segments();
    (segments[0] & 0xe000) == 0x2000
        && !(ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
            || (segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0)
            || (segments[0] == 0x0064 && segments[1] == 0xff9b)
            || (segments[0] == 0x0100 && segments[1] == 0)
            || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
            || segments[0] == 0x2002
            || (segments[0] & 0xfff0) == 0x3ff0
            || segments[0] == 0x5f00
            || (segments[0] & 0xfe00) == 0xfc00
            || (segments[0] & 0xffc0) == 0xfe80
            || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures_util::stream;
    use jacquard_common::http_client::HttpClient;
    use jacquard_oauth::{dpop::wrap_request_with_dpop, session::DpopReqData};
    use reqwest::StatusCode;
    use std::collections::VecDeque;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug)]
    struct CapturedDispatch {
        url: String,
        headers: HeaderMap,
        body: Option<Bytes>,
    }

    #[derive(Clone)]
    struct CaptureIo {
        redirect_status: StatusCode,
        dispatches: Arc<Mutex<Vec<CapturedDispatch>>>,
    }

    #[derive(Clone, Debug)]
    struct CapturedPinnedDispatch {
        url: String,
        addresses: Vec<IpAddr>,
        headers: HeaderMap,
    }

    #[derive(Clone)]
    struct ScriptedAddressIo {
        answers: Arc<Mutex<VecDeque<Vec<IpAddr>>>>,
        validations: Arc<Mutex<usize>>,
        dispatches: Arc<Mutex<Vec<CapturedPinnedDispatch>>>,
        response_status: StatusCode,
        response_body: Bytes,
    }

    #[derive(Clone, Default)]
    struct DpopRetryIo {
        dispatches: Arc<Mutex<usize>>,
        delay: Duration,
    }

    impl DpopRetryIo {
        fn response(status: StatusCode, nonce: Option<&str>, body: Vec<u8>) -> Response {
            let mut builder = http::Response::builder().status(status);
            if let Some(nonce) = nonce {
                builder = builder.header("DPoP-Nonce", nonce);
            }
            builder
                .body(reqwest::Body::from(body))
                .expect("test response")
                .into()
        }
    }

    impl OutboundIo for DpopRetryIo {
        fn validate_before<'a>(
            &'a self,
            input: &'a str,
            _deadline: tokio::time::Instant,
        ) -> Pin<Box<dyn Future<Output = Result<ValidatedUrl, PolicyError>> + Send + 'a>> {
            Box::pin(async move {
                Ok(ValidatedUrl {
                    url: Url::parse(input).expect("test URL"),
                    addresses: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                })
            })
        }

        fn send_once<'a>(
            &'a self,
            _method: Method,
            _target: &'a ValidatedUrl,
            _headers: HeaderMap,
            _body: Option<Bytes>,
            remaining: Duration,
        ) -> Pin<Box<dyn Future<Output = Result<Response, PolicyError>> + Send + 'a>> {
            Box::pin(async move {
                if self.delay > remaining {
                    tokio::time::sleep(remaining).await;
                    return Err(PolicyError("outbound request deadline exceeded".into()));
                }
                tokio::time::sleep(self.delay).await;
                let dispatch = {
                    let mut dispatches = self.dispatches.lock().expect("dispatch lock");
                    *dispatches += 1;
                    *dispatches
                };
                let mut body = if dispatch == 1 {
                    br#"{"error":"use_dpop_nonce"}"#.to_vec()
                } else {
                    Vec::new()
                };
                body.resize(600 * 1024, b' ');
                Ok(if dispatch == 1 {
                    Self::response(StatusCode::BAD_REQUEST, Some("retry-nonce"), body)
                } else {
                    Self::response(StatusCode::OK, None, body)
                })
            })
        }
    }

    #[derive(Clone)]
    struct DpopPolicyClient {
        io: DpopRetryIo,
        timeout: Duration,
        max_response_bytes: usize,
        max_operation_attempts: usize,
    }

    impl Default for DpopPolicyClient {
        fn default() -> Self {
            Self {
                io: DpopRetryIo::default(),
                timeout: REQUEST_TIMEOUT,
                max_response_bytes: DISCOVERY_RESPONSE_LIMIT,
                max_operation_attempts: MAX_OPERATION_ATTEMPTS,
            }
        }
    }

    impl HttpClient for DpopPolicyClient {
        type Error = PolicyError;

        async fn send_http(
            &self,
            request: http::Request<Vec<u8>>,
        ) -> Result<http::Response<Vec<u8>>, Self::Error> {
            send_http_with_io_limits(
                &self.io,
                request,
                self.timeout,
                self.max_response_bytes,
                self.max_operation_attempts,
            )
            .await
        }
    }

    impl CaptureIo {
        fn new(redirect_status: StatusCode) -> Self {
            Self {
                redirect_status,
                dispatches: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn response(status: StatusCode, location: Option<&str>) -> Response {
            let mut builder = http::Response::builder().status(status);
            if let Some(location) = location {
                builder = builder.header(reqwest::header::LOCATION, location);
            }
            builder
                .body(reqwest::Body::from(Vec::new()))
                .expect("test response")
                .into()
        }
    }

    impl ScriptedAddressIo {
        fn new(answers: Vec<Vec<IpAddr>>, response_status: StatusCode) -> Self {
            Self {
                answers: Arc::new(Mutex::new(answers.into())),
                validations: Arc::new(Mutex::new(0)),
                dispatches: Arc::new(Mutex::new(Vec::new())),
                response_status,
                response_body: Bytes::new(),
            }
        }

        fn with_response_body(mut self, response_body: Bytes) -> Self {
            self.response_body = response_body;
            self
        }
    }

    impl OutboundIo for ScriptedAddressIo {
        fn validate_before<'a>(
            &'a self,
            input: &'a str,
            _deadline: tokio::time::Instant,
        ) -> Pin<Box<dyn Future<Output = Result<ValidatedUrl, PolicyError>> + Send + 'a>> {
            Box::pin(async move {
                *self.validations.lock().expect("validation lock") += 1;
                let answers = self
                    .answers
                    .lock()
                    .expect("answer lock")
                    .pop_front()
                    .ok_or_else(|| PolicyError("missing scripted DNS answer".into()))?;
                ValidatedUrl::parse(input)?.with_addresses(answers)
            })
        }

        fn send_once<'a>(
            &'a self,
            _method: Method,
            target: &'a ValidatedUrl,
            headers: HeaderMap,
            _body: Option<Bytes>,
            _remaining: Duration,
        ) -> Pin<Box<dyn Future<Output = Result<Response, PolicyError>> + Send + 'a>> {
            Box::pin(async move {
                self.dispatches
                    .lock()
                    .expect("dispatch lock")
                    .push(CapturedPinnedDispatch {
                        url: target.url.to_string(),
                        addresses: target.addresses.clone(),
                        headers,
                    });
                let mut builder = http::Response::builder().status(self.response_status);
                if self.response_status.is_redirection() {
                    builder = builder.header(reqwest::header::LOCATION, "/rebound");
                }
                Ok(builder
                    .body(reqwest::Body::from(self.response_body.clone()))
                    .expect("test response")
                    .into())
            })
        }
    }

    impl OutboundIo for CaptureIo {
        fn validate_before<'a>(
            &'a self,
            input: &'a str,
            _deadline: tokio::time::Instant,
        ) -> Pin<Box<dyn Future<Output = Result<ValidatedUrl, PolicyError>> + Send + 'a>> {
            Box::pin(async move {
                Ok(ValidatedUrl {
                    url: Url::parse(input).expect("test URL"),
                    addresses: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                })
            })
        }

        fn send_once<'a>(
            &'a self,
            _method: Method,
            target: &'a ValidatedUrl,
            headers: HeaderMap,
            body: Option<Bytes>,
            _remaining: Duration,
        ) -> Pin<Box<dyn Future<Output = Result<Response, PolicyError>> + Send + 'a>> {
            Box::pin(async move {
                self.dispatches
                    .lock()
                    .expect("capture lock")
                    .push(CapturedDispatch {
                        url: target.url.to_string(),
                        headers,
                        body,
                    });
                if target.url.path() == "/source" {
                    Ok(Self::response(self.redirect_status, Some("/target")))
                } else {
                    Ok(Self::response(StatusCode::OK, None))
                }
            })
        }
    }

    #[test]
    fn rejects_non_https_and_ambiguous_urls() {
        for url in [
            "http://example.com/x",
            "https://user@example.com/x",
            "https://example.com/x#fragment",
            "file:///etc/passwd",
        ] {
            assert!(ValidatedUrl::parse(url).is_err(), "accepted {url}");
        }
    }

    #[test]
    fn rejects_private_and_mixed_dns_answers() {
        let url = ValidatedUrl::parse("https://pds.example/x").unwrap();
        assert!(url
            .clone()
            .with_addresses(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))])
            .is_err());
        assert!(url
            .with_addresses(vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ])
            .is_err());
    }

    #[test]
    fn accepts_only_global_dns_answers_and_retains_them_for_pinning() {
        let addresses = vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
        ];
        let pinned = ValidatedUrl::parse("https://example.com/x")
            .unwrap()
            .with_addresses(addresses.clone())
            .unwrap();
        assert_eq!(pinned.addresses(), addresses.as_slice());
    }

    #[test]
    fn exact_origin_binding_rejects_lookalikes_and_cross_origin_secrets() {
        let issuer = ValidatedUrl::parse("https://auth.example/issuer").unwrap();
        assert!(issuer
            .require_same_origin("https://auth.example/token")
            .is_ok());
        assert!(issuer
            .require_same_origin("https://auth.example.evil/token")
            .is_err());
        assert!(issuer
            .require_same_origin("https://auth.example:444/token")
            .is_err());
    }

    #[test]
    fn global_address_classifier_covers_special_ranges() {
        for ip in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
            "2001:db8::1",
            "fec0::1",
            "4000::1",
        ] {
            assert!(!is_global(ip.parse().unwrap()), "classified {ip} global");
        }
        assert!(is_global("93.184.216.34".parse().unwrap()));
        assert!(is_global("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn ipv6_global_unicast_and_special_purpose_boundaries_fail_closed() {
        for ip in [
            "1fff:ffff::1",
            "2001:1ff::1",
            "2001:db8::1",
            "3fff::1",
            "4000::1",
            "5f00::1",
            "fec0::1",
        ] {
            assert!(!is_global(ip.parse().unwrap()), "classified {ip} global");
        }

        assert!(is_global("2001:200::1".parse().unwrap()));
        assert!(is_global("2606:4700:4700::1111".parse().unwrap()));
        assert!(is_global("::ffff:8.8.8.8".parse().unwrap()));
        assert!(!is_global("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn globally_routable_neighbors_of_special_ipv4_ranges_remain_allowed() {
        assert!(is_global("192.0.1.1".parse().unwrap()));
        assert!(is_global("192.88.1.1".parse().unwrap()));
        assert!(!is_global("192.0.0.1".parse().unwrap()));
        assert!(!is_global("192.88.99.1".parse().unwrap()));
    }

    #[test]
    fn only_true_redirect_statuses_are_followed() {
        for status in [301, 302, 303, 307, 308] {
            assert!(is_followed_redirect(StatusCode::from_u16(status).unwrap()));
        }
        for status in [300, 304, 305, 306] {
            assert!(!is_followed_redirect(StatusCode::from_u16(status).unwrap()));
        }
    }

    #[test]
    fn credential_transport_never_follows_redirects_and_consumes_marker() {
        for status in [301, 302, 303, 307, 308] {
            let status = StatusCode::from_u16(status).unwrap();
            assert!(should_follow_redirect(
                status,
                RedirectMode::FollowSameOrigin
            ));
            assert!(!should_follow_redirect(status, RedirectMode::Reject));
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            jacquard_oauth::request::OAUTH_CREDENTIAL_REQUEST_HEADER,
            "1".parse().unwrap(),
        );
        assert!(matches!(
            take_redirect_mode(&mut headers),
            RedirectMode::Reject
        ));
        assert!(!headers.contains_key(jacquard_oauth::request::OAUTH_CREDENTIAL_REQUEST_HEADER));
    }

    #[tokio::test]
    async fn credential_transport_dispatches_once_and_never_replays_secrets_to_redirect_target() {
        for status in [301, 302, 303, 307, 308] {
            let io = CaptureIo::new(StatusCode::from_u16(status).unwrap());
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri("https://issuer.example/source")
                .header(
                    jacquard_oauth::request::OAUTH_CREDENTIAL_REQUEST_HEADER,
                    "1",
                )
                .header("DPoP", "proof-secret")
                .header("Authorization", "DPoP access-secret")
                .body(b"client_assertion=assertion-secret".to_vec())
                .unwrap();

            let response = send_http_with_io(&io, request).await.unwrap();
            assert_eq!(response.status().as_u16(), status);

            let dispatches = io.dispatches.lock().expect("capture lock");
            assert_eq!(dispatches.len(), 1, "status {status} followed redirect");
            let source = &dispatches[0];
            assert_eq!(source.url, "https://issuer.example/source");
            assert!(!source
                .headers
                .contains_key(jacquard_oauth::request::OAUTH_CREDENTIAL_REQUEST_HEADER));
            assert_eq!(source.headers.get("dpop").unwrap(), "proof-secret");
            assert!(source
                .body
                .as_ref()
                .is_some_and(|body| body.as_ref().starts_with(b"client_assertion=")));
            let target_dispatches: Vec<_> = dispatches
                .iter()
                .filter(|dispatch| dispatch.url == "https://issuer.example/target")
                .collect();
            assert!(
                target_dispatches.is_empty(),
                "status {status} reached target"
            );
            assert!(target_dispatches.iter().all(|dispatch| {
                !dispatch
                    .headers
                    .values()
                    .any(|value| value.as_bytes().windows(6).any(|part| part == b"secret"))
                    && dispatch
                        .body
                        .as_ref()
                        .is_none_or(|body| !body.as_ref().windows(6).any(|part| part == b"secret"))
            }));
        }
    }

    #[tokio::test]
    async fn credential_transport_rejects_private_and_mixed_dns_before_dispatch() {
        for answers in [
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        ] {
            let io = ScriptedAddressIo::new(vec![answers], StatusCode::OK);
            let mut headers = HeaderMap::new();
            headers.insert("authorization", "DPoP access-secret".parse().unwrap());
            headers.insert("dpop", "proof-secret".parse().unwrap());

            let error = send_credential_bounded_before_with_io(
                &io,
                Method::GET,
                "https://pds.example/xrpc/chat.bsky.convo.getLog",
                headers,
                None,
                1024,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap_err();

            assert!(error.to_string().contains("non-global address"));
            assert!(io.dispatches.lock().expect("dispatch lock").is_empty());
        }
    }

    #[tokio::test]
    async fn credential_transport_pins_dns_and_never_replays_to_a_rebound_redirect() {
        let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let io = ScriptedAddressIo::new(
            vec![vec![public], vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]],
            StatusCode::TEMPORARY_REDIRECT,
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "DPoP access-secret".parse().unwrap());
        headers.insert("dpop", "proof-secret".parse().unwrap());

        let (status, _, _) = send_credential_bounded_before_with_io(
            &io,
            Method::GET,
            "https://pds.example/xrpc/chat.bsky.convo.getLog",
            headers,
            None,
            1024,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(*io.validations.lock().expect("validation lock"), 1);
        assert_eq!(io.answers.lock().expect("answer lock").len(), 1);
        let dispatches = io.dispatches.lock().expect("dispatch lock");
        assert_eq!(dispatches.len(), 1);
        assert_eq!(
            dispatches[0].url,
            "https://pds.example/xrpc/chat.bsky.convo.getLog"
        );
        assert_eq!(dispatches[0].addresses, vec![public]);
        assert!(dispatches[0].headers.contains_key("authorization"));
        assert!(dispatches[0].headers.contains_key("dpop"));
    }

    #[tokio::test]
    async fn credential_transport_enforces_the_caller_response_bound() {
        let io = ScriptedAddressIo::new(
            vec![vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]],
            StatusCode::OK,
        )
        .with_response_body(Bytes::from_static(b"ninebytes"));

        let error = send_credential_bounded_before_with_io(
            &io,
            Method::GET,
            "https://pds.example/xrpc/chat.bsky.convo.getLog",
            HeaderMap::new(),
            None,
            8,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();

        assert!(
            error.to_string().contains("Content-Length")
                || error.to_string().contains("response byte limit exceeded")
        );
        assert_eq!(io.dispatches.lock().expect("dispatch lock").len(), 1);
    }

    #[tokio::test]
    async fn noncredential_same_origin_redirect_still_dispatches_target() {
        let io = CaptureIo::new(StatusCode::TEMPORARY_REDIRECT);
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://issuer.example/source")
            .body(Vec::new())
            .unwrap();

        let response = send_http_with_io(&io, request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let dispatches = io.dispatches.lock().expect("capture lock");
        assert_eq!(dispatches.len(), 2);
        assert_eq!(dispatches[0].url, "https://issuer.example/source");
        assert_eq!(dispatches[1].url, "https://issuer.example/target");
        assert!(dispatches.iter().all(|dispatch| !dispatch
            .headers
            .contains_key(jacquard_oauth::request::OAUTH_CREDENTIAL_REQUEST_HEADER)));
    }

    #[test]
    fn rejects_all_reviewed_special_use_and_compatible_forms() {
        for ip in [
            "192.0.0.1",
            "192.88.99.1",
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "100::1",
            "2001:2::1",
            "2001:20::1",
            "2002:7f00:1::1",
            "3fff::1",
            "5f00::1",
        ] {
            assert!(!is_global(ip.parse().unwrap()), "classified {ip} global");
        }
    }

    #[tokio::test]
    async fn zero_remaining_budget_opens_no_socket() {
        let error = OutboundPolicy
            .send_bounded(
                Method::GET,
                "https://example.com/",
                HeaderMap::new(),
                None,
                Duration::ZERO,
                RedirectMode::FollowSameOrigin,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("deadline exceeded"));
    }

    #[tokio::test(start_paused = true)]
    async fn cumulative_deadline_is_not_reset_for_a_retry() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        tokio::time::advance(Duration::from_secs(31)).await;
        let error = OutboundPolicy
            .send_before(
                Method::GET,
                "https://example.com/",
                HeaderMap::new(),
                None,
                deadline,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("deadline exceeded"));
    }

    #[tokio::test]
    async fn did_web_identity_fetch_uses_policy_and_rejects_loopback() {
        let resolver =
            jacquard_identity::JacquardResolver::new(OutboundPolicy, ResolverOptions::default());
        let did = Did::new("did:web:127.0.0.1").unwrap();
        assert!(resolver.resolve_did_doc(&did).await.is_err());
    }

    #[tokio::test]
    async fn bounded_body_rejects_declared_oversize_before_polling() {
        let body = stream::pending::<Result<Bytes, io::Error>>();
        let error = collect_bounded_stream(
            body,
            Some((DISCOVERY_RESPONSE_LIMIT + 1) as u64),
            DISCOVERY_RESPONSE_LIMIT,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("Content-Length"));
    }

    #[tokio::test]
    async fn bounded_body_rejects_chunked_oversize_without_content_length() {
        let body = stream::iter([
            Ok::<_, io::Error>(Bytes::from(vec![0_u8; DISCOVERY_RESPONSE_LIMIT])),
            Ok(Bytes::from_static(b"x")),
        ]);
        let error = collect_bounded_stream(
            body,
            None,
            DISCOVERY_RESPONSE_LIMIT,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("response byte limit exceeded"));
    }

    #[tokio::test]
    async fn dpop_nonce_retry_shares_one_cumulative_response_budget() {
        let client = DpopPolicyClient::default();
        let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let mut dpop = DpopReqData {
            dpop_key: jose_jwk::Key::from(&jose_jwk::crypto::Key::from(secret)),
            dpop_authserver_nonce: None,
        };
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://issuer.example/token")
            .body(Vec::new())
            .unwrap();

        let error = wrap_request_with_dpop(&client, &mut dpop, true, request)
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains("Content-Length")
                || error.to_string().contains("response byte limit exceeded"),
            "unexpected error: {error}"
        );
        assert_eq!(*client.io.dispatches.lock().expect("dispatch lock"), 2);
    }

    #[tokio::test]
    async fn dpop_nonce_retry_shares_one_absolute_deadline() {
        let client = DpopPolicyClient {
            io: DpopRetryIo {
                dispatches: Arc::new(Mutex::new(0)),
                delay: Duration::from_millis(120),
            },
            timeout: Duration::from_millis(200),
            max_response_bytes: 2 * DISCOVERY_RESPONSE_LIMIT,
            max_operation_attempts: MAX_OPERATION_ATTEMPTS,
        };
        let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let mut dpop = DpopReqData {
            dpop_key: jose_jwk::Key::from(&jose_jwk::crypto::Key::from(secret)),
            dpop_authserver_nonce: None,
        };
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://issuer.example/token")
            .body(Vec::new())
            .unwrap();

        let error = wrap_request_with_dpop(&client, &mut dpop, true, request)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("deadline exceeded"));
        assert_eq!(*client.io.dispatches.lock().expect("dispatch lock"), 1);
    }

    #[tokio::test]
    async fn dpop_nonce_retry_counts_against_one_attempt_limit() {
        let client = DpopPolicyClient {
            max_response_bytes: 2 * DISCOVERY_RESPONSE_LIMIT,
            max_operation_attempts: 1,
            ..DpopPolicyClient::default()
        };
        let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let mut dpop = DpopReqData {
            dpop_key: jose_jwk::Key::from(&jose_jwk::crypto::Key::from(secret)),
            dpop_authserver_nonce: None,
        };
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://issuer.example/token")
            .body(Vec::new())
            .unwrap();

        let error = wrap_request_with_dpop(&client, &mut dpop, true, request)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("attempt limit exceeded"));
        assert_eq!(*client.io.dispatches.lock().expect("dispatch lock"), 1);
    }

    #[tokio::test]
    async fn bounded_body_accepts_exact_limit_without_content_length() {
        let body = stream::iter([Ok::<_, io::Error>(Bytes::from(vec![
            0_u8;
            DISCOVERY_RESPONSE_LIMIT
        ]))]);
        let bytes = collect_bounded_stream(
            body,
            None,
            DISCOVERY_RESPONSE_LIMIT,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(bytes.len(), DISCOVERY_RESPONSE_LIMIT);
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_body_uses_the_existing_absolute_deadline() {
        let body = stream::once(async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok::<_, io::Error>(Bytes::from_static(b"late"))
        });
        let error = collect_bounded_stream(
            body,
            None,
            DISCOVERY_RESPONSE_LIMIT,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("deadline exceeded reading body"));
    }
}
