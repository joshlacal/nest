//! Rate Limiting Middleware
//!
//! Provides rate limiting to protect against abuse:
//! - Per-session rate limiting for XRPC proxy endpoints
//! - Per-IP rate limiting for authentication endpoints

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use redis::aio::ConnectionManager;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::metrics;

const MAX_LOCAL_RATE_LIMIT_KEYS: usize = 100_000;
const SHARED_RATE_LIMIT_TIMEOUT: Duration = Duration::from_millis(250);
const SHARED_RATE_LIMIT_SCRIPT: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {count, ttl}
"#;

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests allowed in the window
    pub max_requests: u32,
    /// Time window for rate limiting
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window: Duration::from_secs(60),
        }
    }
}

/// Rate limit entry tracking requests for a key
#[derive(Debug, Clone)]
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

/// Bounded per-instance limiter used for both the normal local ceiling and the
/// Redis-unavailable fallback.
#[derive(Debug)]
pub struct RateLimiter {
    entries: RwLock<HashMap<String, RateLimitEntry>>,
    max_entries: usize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries: MAX_LOCAL_RATE_LIMIT_KEYS,
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries,
        }
    }

    /// Check if a request should be allowed for the given key
    /// Returns Ok(remaining) if allowed, Err(retry_after_secs) if rate limited
    pub async fn check(&self, key: &str, config: &RateLimitConfig) -> Result<u32, u64> {
        let now = Instant::now();
        let mut entries = self.entries.write().await;

        // New identities fail closed once the bounded fallback map is full.
        // Existing identities continue to receive their normal fixed-window
        // decision until cleanup frees capacity.
        if !entries.contains_key(key) && entries.len() >= self.max_entries {
            return Err(config.window.as_secs().max(1));
        }

        let entry = entries.entry(key.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) >= config.window {
            entry.count = 0;
            entry.window_start = now;
        }

        // Check limit
        if entry.count >= config.max_requests {
            let retry_after =
                config.window.as_secs() - now.duration_since(entry.window_start).as_secs();
            return Err(retry_after.max(1));
        }

        entry.count += 1;
        Ok(config.max_requests - entry.count)
    }

    /// Periodically clean up expired entries to prevent memory growth
    pub async fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        entries.retain(|_, entry| now.duration_since(entry.window_start) < max_age);
    }
}

/// A fleet-shared fixed-window counter with an always-on bounded local ceiling.
///
/// The local decision runs first on every request. Redis then provides the
/// cross-instance aggregate. If Redis is unavailable, the already-consumed
/// local decision is used, so degradation never becomes unlimited access.
struct SharedRateLimiter {
    local: Arc<RateLimiter>,
    redis: Option<ConnectionManager>,
    redis_key_prefix: Arc<str>,
    namespace: &'static str,
    redis_fallback_logged: AtomicBool,
}

impl SharedRateLimiter {
    fn new(
        redis: Option<ConnectionManager>,
        redis_key_prefix: impl Into<Arc<str>>,
        namespace: &'static str,
    ) -> Self {
        Self {
            local: Arc::new(RateLimiter::new()),
            redis,
            redis_key_prefix: redis_key_prefix.into(),
            namespace,
            redis_fallback_logged: AtomicBool::new(false),
        }
    }

    fn redis_key(&self, logical_key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.namespace.as_bytes());
        hasher.update([0]);
        hasher.update(logical_key.as_bytes());
        format!(
            "{}rate_limit:{}:{:x}",
            self.redis_key_prefix,
            self.namespace,
            hasher.finalize()
        )
    }

    async fn check(&self, key: &str, config: &RateLimitConfig) -> Result<u32, u64> {
        let local_remaining = self.local.check(key, config).await?;
        let Some(redis) = self.redis.as_ref() else {
            return Ok(local_remaining);
        };

        let window_ms = config.window.as_millis().clamp(1, i64::MAX as u128) as i64;
        let mut redis = redis.clone();
        let result = tokio::time::timeout(
            SHARED_RATE_LIMIT_TIMEOUT,
            redis::Script::new(SHARED_RATE_LIMIT_SCRIPT)
                .key(self.redis_key(key))
                .arg(window_ms)
                .invoke_async::<_, (i64, i64)>(&mut redis),
        )
        .await;

        if let Ok(Ok((count, ttl_ms))) = result {
            if let Some(decision) = shared_rate_limit_decision(count, ttl_ms, config) {
                self.redis_fallback_logged.store(false, Ordering::Relaxed);
                return decision;
            }
        }

        // Do not include the Redis error or logical key: connection details
        // and session-derived identifiers do not belong here.
        if !self.redis_fallback_logged.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                namespace = self.namespace,
                "Redis rate limiter unavailable; enforcing bounded local limit"
            );
        }
        Ok(local_remaining)
    }

    async fn cleanup(&self, max_age: Duration) {
        self.local.cleanup(max_age).await;
    }
}

fn shared_rate_limit_decision(
    count: i64,
    ttl_ms: i64,
    config: &RateLimitConfig,
) -> Option<Result<u32, u64>> {
    if count < 1 || ttl_ms < 1 {
        return None;
    }
    if count > i64::from(config.max_requests) {
        let retry_after = u64::try_from((ttl_ms.saturating_add(999)) / 1000)
            .unwrap_or(u64::MAX)
            .max(1);
        return Some(Err(retry_after));
    }
    Some(Ok(config.max_requests - count as u32))
}

/// Shared rate limiter state for the application
#[derive(Clone)]
pub struct RateLimitState {
    /// Rate limiter for session-based limits (XRPC proxy)
    session_limiter: Arc<SharedRateLimiter>,
    /// Rate limiter for IP-based limits (auth endpoints)
    ip_limiter: Arc<SharedRateLimiter>,
    /// Configuration for session-based rate limiting
    pub session_config: RateLimitConfig,
    /// Configuration for IP-based rate limiting
    pub ip_config: RateLimitConfig,
    trusted_proxy_ips: Arc<HashSet<IpAddr>>,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self::new(default_session_config(), default_ip_config())
    }
}

fn default_session_config() -> RateLimitConfig {
    RateLimitConfig {
        // 1200 req/min for XRPC proxy — generous to handle app startup burst
        // (initial sync fetches conversations + messages for all groups)
        // With WebSocket for live events, sustained rate is much lower
        max_requests: 1200,
        window: Duration::from_secs(60),
    }
}

fn default_ip_config() -> RateLimitConfig {
    RateLimitConfig {
        // 20 req/min for auth endpoints (login/exchange)
        max_requests: 20,
        window: Duration::from_secs(60),
    }
}

impl RateLimitState {
    /// Create a new rate limit state with custom configurations
    pub fn new(session_config: RateLimitConfig, ip_config: RateLimitConfig) -> Self {
        Self::build(None, String::new(), Vec::new(), session_config, ip_config)
    }

    /// Create the production limiter using the application's existing Redis
    /// connection manager and an explicit trusted-proxy set.
    pub fn distributed(
        redis: ConnectionManager,
        redis_key_prefix: String,
        trusted_proxy_ips: Vec<IpAddr>,
    ) -> Self {
        Self::build(
            Some(redis),
            redis_key_prefix,
            trusted_proxy_ips,
            default_session_config(),
            default_ip_config(),
        )
    }

    fn build(
        redis: Option<ConnectionManager>,
        redis_key_prefix: String,
        trusted_proxy_ips: Vec<IpAddr>,
        session_config: RateLimitConfig,
        ip_config: RateLimitConfig,
    ) -> Self {
        let redis_key_prefix: Arc<str> = redis_key_prefix.into();
        Self {
            session_limiter: Arc::new(SharedRateLimiter::new(
                redis.clone(),
                redis_key_prefix.clone(),
                "session",
            )),
            ip_limiter: Arc::new(SharedRateLimiter::new(redis, redis_key_prefix, "auth")),
            session_config,
            ip_config,
            trusted_proxy_ips: Arc::new(trusted_proxy_ips.into_iter().collect()),
        }
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
            loop {
                interval.tick().await;
                self.session_limiter.cleanup(Duration::from_secs(120)).await;
                self.ip_limiter.cleanup(Duration::from_secs(120)).await;
                tracing::debug!("Rate limiter cleanup completed");
            }
        });
    }
}

/// Response for rate limit exceeded
fn rate_limit_response(retry_after: u64) -> Response {
    let body = Json(json!({
        "error": "rate_limit_exceeded",
        "message": "Too many requests. Please slow down.",
        "retry_after": retry_after,
    }));

    (
        StatusCode::TOO_MANY_REQUESTS,
        [("Retry-After", retry_after.to_string())],
        body,
    )
        .into_response()
}

/// Extract the rate-limit identity from socket metadata and, only for an
/// explicitly trusted peer, forwarding headers.
///
/// X-Forwarded-For is evaluated from right to left. Trusted hops are skipped;
/// the first untrusted hop is the client boundary. Values farther left are not
/// trusted because that hop could have received them from the caller.
fn extract_client_ip(req: &Request<Body>, trusted_proxy_ips: &HashSet<IpAddr>) -> Option<IpAddr> {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())?;
    if !trusted_proxy_ips.contains(&peer) {
        return Some(peer);
    }

    let forwarded_values: Vec<_> = req.headers().get_all("x-forwarded-for").iter().collect();
    if !forwarded_values.is_empty() {
        let mut chain = Vec::new();
        for value in forwarded_values {
            let Ok(value) = value.to_str() else {
                return Some(peer);
            };
            for item in value.split(',') {
                let Ok(ip) = item.trim().parse::<IpAddr>() else {
                    return Some(peer);
                };
                chain.push(ip);
            }
        }
        if chain.is_empty() {
            return Some(peer);
        }
        for hop in chain.iter().rev() {
            if !trusted_proxy_ips.contains(hop) {
                return Some(*hop);
            }
        }
        return Some(chain.first().copied().unwrap_or(peer));
    }

    let mut real_ip_values = req.headers().get_all("x-real-ip").iter();
    match (real_ip_values.next(), real_ip_values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
            .or(Some(peer)),
        _ => Some(peer),
    }
}

/// Extract session ID from request for rate limiting
fn extract_session_for_rate_limit(req: &Request<Body>) -> Option<String> {
    // Try Authorization header first
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    // Try cookie
    let cookies = req
        .headers()
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");

    for cookie in cookies.split(';') {
        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == "catbird_session" {
            return Some(parts[1].to_string());
        }
    }

    None
}

/// Per-session rate limiting middleware for XRPC proxy endpoints
/// Limits: 1200 requests per minute per session
pub async fn session_rate_limit(
    State(rate_limit): State<Arc<RateLimitState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Extract session ID for rate limiting
    let (key, key_kind) = match extract_session_for_rate_limit(&req) {
        Some(session_id) => {
            use sha2::{Digest, Sha256};
            (
                format!("session:{:x}", Sha256::digest(session_id)),
                "session",
            )
        }
        None => {
            // No session - use IP as fallback
            match extract_client_ip(&req, &rate_limit.trusted_proxy_ips) {
                Some(ip) => (format!("ip:{}", ip), "ip"),
                None => ("unknown".to_string(), "unknown"),
            }
        }
    };

    match rate_limit
        .session_limiter
        .check(&key, &rate_limit.session_config)
        .await
    {
        Ok(remaining) => {
            tracing::trace!(key_kind, remaining, "Session rate limit check passed");
            next.run(req).await
        }
        Err(retry_after) => {
            tracing::warn!(key_kind, retry_after, "Session rate limit exceeded");
            metrics::record_rate_limit_exceeded("xrpc");
            rate_limit_response(retry_after)
        }
    }
}

/// Per-IP rate limiting middleware for auth endpoints
/// Limits: 20 requests per minute per IP
pub async fn ip_rate_limit(
    State(rate_limit): State<Arc<RateLimitState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let key = match extract_client_ip(&req, &rate_limit.trusted_proxy_ips) {
        Some(ip) => format!("auth:{}", ip),
        None => "auth:unknown".to_string(),
    };

    match rate_limit
        .ip_limiter
        .check(&key, &rate_limit.ip_config)
        .await
    {
        Ok(remaining) => {
            tracing::trace!(remaining, "IP rate limit check passed");
            next.run(req).await
        }
        Err(retry_after) => {
            tracing::warn!(retry_after, "Auth rate limit exceeded");
            metrics::record_rate_limit_exceeded("auth");
            rate_limit_response(retry_after)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware, routing::get, Router};
    use tower::ServiceExt;

    fn request_with_peer(
        peer: Option<IpAddr>,
        forwarded_for: Option<&str>,
        real_ip: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder().uri("/auth/login");
        if let Some(forwarded_for) = forwarded_for {
            builder = builder.header("x-forwarded-for", forwarded_for);
        }
        if let Some(real_ip) = real_ip {
            builder = builder.header("x-real-ip", real_ip);
        }
        let mut request = builder.body(Body::empty()).unwrap();
        if let Some(peer) = peer {
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(peer, 443)));
        }
        request
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn limiter_app(trusted_proxy_ips: Vec<IpAddr>) -> Router {
        let state = Arc::new(RateLimitState::build(
            None,
            "test:".into(),
            trusted_proxy_ips,
            RateLimitConfig {
                max_requests: 10,
                window: Duration::from_secs(60),
            },
            RateLimitConfig {
                max_requests: 1,
                window: Duration::from_secs(60),
            },
        ));
        Router::new()
            .route("/auth/login", get(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn_with_state(state, ip_rate_limit))
    }

    #[tokio::test]
    async fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new();
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
        };

        for i in 0..5 {
            let result = limiter.check("test", &config).await;
            assert!(result.is_ok(), "Request {} should be allowed", i);
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new();
        let config = RateLimitConfig {
            max_requests: 3,
            window: Duration::from_secs(60),
        };

        // Use up the limit
        for _ in 0..3 {
            let result = limiter.check("test", &config).await;
            assert!(result.is_ok());
        }

        // Should be blocked
        let result = limiter.check("test", &config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_different_keys() {
        let limiter = RateLimiter::new();
        let config = RateLimitConfig {
            max_requests: 2,
            window: Duration::from_secs(60),
        };

        // Key A uses its limit
        for _ in 0..2 {
            assert!(limiter.check("key_a", &config).await.is_ok());
        }
        assert!(limiter.check("key_a", &config).await.is_err());

        // Key B should still work
        assert!(limiter.check("key_b", &config).await.is_ok());
    }

    #[tokio::test]
    async fn local_fallback_fails_closed_when_identity_capacity_is_full() {
        let limiter = RateLimiter::with_max_entries(2);
        let config = RateLimitConfig {
            max_requests: 2,
            window: Duration::from_secs(60),
        };

        assert!(limiter.check("key_a", &config).await.is_ok());
        assert!(limiter.check("key_b", &config).await.is_ok());
        assert_eq!(limiter.check("key_c", &config).await, Err(60));
        assert!(limiter.check("key_a", &config).await.is_ok());
        assert!(limiter.check("key_a", &config).await.is_err());
    }

    #[tokio::test]
    async fn shared_limiter_without_redis_remains_locally_bounded() {
        let limiter = SharedRateLimiter::new(None, "test:", "auth");
        let config = RateLimitConfig {
            max_requests: 2,
            window: Duration::from_secs(60),
        };

        assert_eq!(limiter.check("client", &config).await, Ok(1));
        assert_eq!(limiter.check("client", &config).await, Ok(0));
        assert!(limiter.check("client", &config).await.is_err());
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL pointing to disposable standalone Redis/Valkey"]
    async fn live_redis_counter_is_shared_across_independent_instances() {
        let redis_url = std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required");
        let client = redis::Client::open(redis_url).expect("TEST_REDIS_URL must be valid");
        let manager = redis::aio::ConnectionManager::new(client)
            .await
            .expect("TEST_REDIS_URL must be reachable");
        let prefix = format!("codex-rate-limit:{}:", uuid::Uuid::new_v4());
        let first = SharedRateLimiter::new(Some(manager.clone()), prefix.clone(), "auth");
        let second = SharedRateLimiter::new(Some(manager.clone()), prefix.clone(), "auth");
        let third = SharedRateLimiter::new(Some(manager.clone()), prefix, "auth");
        let config = RateLimitConfig {
            max_requests: 2,
            window: Duration::from_secs(60),
        };

        assert_eq!(first.check("client", &config).await, Ok(1));
        assert_eq!(second.check("client", &config).await, Ok(0));
        let retry_after = third
            .check("client", &config)
            .await
            .expect_err("the fleet-shared third request must be rejected");
        assert!((1..=60).contains(&retry_after));

        let mut cleanup = manager;
        let deleted: i64 = redis::cmd("DEL")
            .arg(first.redis_key("client"))
            .query_async(&mut cleanup)
            .await
            .expect("remove disposable rate-limit key");
        assert_eq!(deleted, 1);
    }

    #[test]
    fn redis_counter_key_is_stable_across_instances_and_hides_logical_identity() {
        let first = SharedRateLimiter::new(None, "catbird:test:", "auth");
        let second = SharedRateLimiter::new(None, "catbird:test:", "auth");
        let session = SharedRateLimiter::new(None, "catbird:test:", "session");

        let first_key = first.redis_key("auth:203.0.113.8");
        assert_eq!(first_key, second.redis_key("auth:203.0.113.8"));
        assert_ne!(first_key, session.redis_key("auth:203.0.113.8"));
        assert!(!first_key.contains("203.0.113.8"));
    }

    #[test]
    fn shared_counter_result_preserves_the_configured_numeric_limit() {
        let config = RateLimitConfig {
            max_requests: 20,
            window: Duration::from_secs(60),
        };
        assert_eq!(shared_rate_limit_decision(1, 60_000, &config), Some(Ok(19)));
        assert_eq!(shared_rate_limit_decision(20, 1_001, &config), Some(Ok(0)));
        assert_eq!(shared_rate_limit_decision(21, 1_001, &config), Some(Err(2)));
        assert_eq!(shared_rate_limit_decision(0, 60_000, &config), None);
        assert_eq!(shared_rate_limit_decision(1, -1, &config), None);
    }

    #[test]
    fn direct_peer_cannot_spoof_forwarding_headers() {
        let peer = ip("198.51.100.10");
        let trusted = HashSet::new();
        let request = request_with_peer(Some(peer), Some("203.0.113.99"), Some("192.0.2.44"));
        assert_eq!(extract_client_ip(&request, &trusted), Some(peer));
    }

    #[tokio::test]
    async fn rotating_forwarded_headers_cannot_bypass_direct_peer_limit() {
        let app = limiter_app(Vec::new());
        let peer = ip("198.51.100.10");

        let first = app
            .clone()
            .oneshot(request_with_peer(Some(peer), Some("203.0.113.1"), None))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::NO_CONTENT);

        let second = app
            .oneshot(request_with_peer(Some(peer), Some("203.0.113.2"), None))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn trusted_proxy_uses_right_to_left_untrusted_boundary() {
        let peer = ip("10.0.0.10");
        let trusted = HashSet::from([peer, ip("10.0.0.9")]);
        let request =
            request_with_peer(Some(peer), Some("192.0.2.66, 203.0.113.8, 10.0.0.9"), None);

        // 192.0.2.66 is a caller-supplied left-side value. The closest
        // untrusted hop is 203.0.113.8, so the farther-left value is ignored.
        assert_eq!(
            extract_client_ip(&request, &trusted),
            Some(ip("203.0.113.8"))
        );
    }

    #[test]
    fn trusted_proxy_can_assert_a_single_forwarded_or_real_ip() {
        let peer = ip("10.0.0.10");
        let trusted = HashSet::from([peer]);
        let forwarded = request_with_peer(Some(peer), Some("203.0.113.8"), None);
        assert_eq!(
            extract_client_ip(&forwarded, &trusted),
            Some(ip("203.0.113.8"))
        );

        let real = request_with_peer(Some(peer), None, Some("203.0.113.9"));
        assert_eq!(extract_client_ip(&real, &trusted), Some(ip("203.0.113.9")));
    }

    #[tokio::test]
    async fn explicitly_trusted_proxy_preserves_distinct_client_budgets() {
        let peer = ip("10.0.0.10");
        let app = limiter_app(vec![peer]);

        for client in ["203.0.113.8", "203.0.113.9"] {
            let response = app
                .clone()
                .oneshot(request_with_peer(Some(peer), Some(client), None))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
    }

    #[test]
    fn malformed_forwarding_chain_fails_back_to_trusted_socket_peer() {
        let peer = ip("10.0.0.10");
        let trusted = HashSet::from([peer]);
        let request = request_with_peer(
            Some(peer),
            Some("203.0.113.8, not-an-ip"),
            Some("192.0.2.44"),
        );
        assert_eq!(extract_client_ip(&request, &trusted), Some(peer));
    }

    #[test]
    fn forwarding_headers_are_never_trusted_without_socket_metadata() {
        let trusted = HashSet::from([ip("10.0.0.10")]);
        let request = request_with_peer(None, Some("203.0.113.8"), Some("203.0.113.9"));
        assert_eq!(extract_client_ip(&request, &trusted), None);
    }
}
