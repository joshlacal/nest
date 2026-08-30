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
use serde_json::json;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::metrics;

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

/// In-memory rate limiter state
///
/// NOTE: This is per-instance only. For horizontal scaling behind a load balancer,
/// migrate to a Redis-backed sliding window or GCRA algorithm so rate limits
/// are shared across all Nest instances.
#[derive(Debug, Default)]
pub struct RateLimiter {
    entries: RwLock<HashMap<String, RateLimitEntry>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a request should be allowed for the given key
    /// Returns Ok(remaining) if allowed, Err(retry_after_secs) if rate limited
    pub async fn check(&self, key: &str, config: &RateLimitConfig) -> Result<u32, u64> {
        let now = Instant::now();
        let mut entries = self.entries.write().await;

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

/// Byte rate limit configuration
#[derive(Debug, Clone)]
pub struct ByteRateLimitConfig {
    /// Maximum bytes allowed in the window
    pub max_bytes: u64,
    /// Time window for byte rate limiting
    pub window: Duration,
}

impl Default for ByteRateLimitConfig {
    fn default() -> Self {
        Self {
            max_bytes: 100 * 1024 * 1024, // 100 MB per window default
            window: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone)]
struct ByteRateLimitEntry {
    bytes: u64,
    window_start: Instant,
}

/// In-memory byte-rate limiter state for cumulative bandwidth tracking
#[derive(Debug, Default)]
pub struct ByteRateLimiter {
    entries: RwLock<HashMap<String, ByteRateLimitEntry>>,
}

impl ByteRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check and record byte consumption for key. Returns Ok(()) if within budget, Err(retry_after) if exceeded.
    pub async fn check_and_record(
        &self,
        key: &str,
        bytes: u64,
        config: &ByteRateLimitConfig,
    ) -> Result<(), u64> {
        let now = Instant::now();
        let mut entries = self.entries.write().await;

        let entry = entries
            .entry(key.to_string())
            .or_insert(ByteRateLimitEntry {
                bytes: 0,
                window_start: now,
            });

        if now.duration_since(entry.window_start) >= config.window {
            entry.bytes = 0;
            entry.window_start = now;
        }

        if entry.bytes + bytes > config.max_bytes {
            let retry_after = config
                .window
                .as_secs()
                .saturating_sub(now.duration_since(entry.window_start).as_secs());
            return Err(retry_after.max(1));
        }

        entry.bytes += bytes;
        Ok(())
    }

    pub async fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        entries.retain(|_, entry| now.duration_since(entry.window_start) < max_age);
    }
}

/// Shared rate limiter state for the application
#[derive(Clone)]
pub struct RateLimitState {
    /// Rate limiter for session-based limits (XRPC proxy)
    pub session_limiter: Arc<RateLimiter>,
    /// Rate limiter for IP-based limits (auth endpoints)
    pub ip_limiter: Arc<RateLimiter>,
    /// Rate limiter for per-session byte consumption
    pub session_byte_limiter: Arc<ByteRateLimiter>,
    /// Rate limiter for global byte consumption
    pub global_byte_limiter: Arc<ByteRateLimiter>,
    /// Configuration for session-based rate limiting
    pub session_config: RateLimitConfig,
    /// Configuration for IP-based rate limiting
    pub ip_config: RateLimitConfig,
    /// Configuration for session byte-rate limiting (100MB/min)
    pub session_byte_config: ByteRateLimitConfig,
    /// Configuration for global byte-rate limiting (1GB/min)
    pub global_byte_config: ByteRateLimitConfig,
    /// Allowlist of trusted reverse proxy CIDRs. If empty, forwarding headers are ignored.
    pub trusted_proxies: Vec<ipnet::IpNet>,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self {
            session_limiter: Arc::new(RateLimiter::new()),
            ip_limiter: Arc::new(RateLimiter::new()),
            session_byte_limiter: Arc::new(ByteRateLimiter::new()),
            global_byte_limiter: Arc::new(ByteRateLimiter::new()),
            session_config: RateLimitConfig {
                max_requests: 1200,
                window: Duration::from_secs(60),
            },
            ip_config: RateLimitConfig {
                max_requests: 20,
                window: Duration::from_secs(60),
            },
            session_byte_config: ByteRateLimitConfig {
                max_bytes: 100 * 1024 * 1024, // 100 MB/min per session
                window: Duration::from_secs(60),
            },
            global_byte_config: ByteRateLimitConfig {
                max_bytes: 1024 * 1024 * 1024, // 1 GB/min global
                window: Duration::from_secs(60),
            },
            trusted_proxies: Vec::new(),
        }
    }
}

impl RateLimitState {
    /// Create a new rate limit state with custom configurations
    pub fn new(
        session_config: RateLimitConfig,
        ip_config: RateLimitConfig,
        trusted_proxies: Vec<ipnet::IpNet>,
    ) -> Self {
        Self {
            session_limiter: Arc::new(RateLimiter::new()),
            ip_limiter: Arc::new(RateLimiter::new()),
            session_byte_limiter: Arc::new(ByteRateLimiter::new()),
            global_byte_limiter: Arc::new(ByteRateLimiter::new()),
            session_config,
            ip_config,
            session_byte_config: ByteRateLimitConfig {
                max_bytes: 100 * 1024 * 1024,
                window: Duration::from_secs(60),
            },
            global_byte_config: ByteRateLimitConfig {
                max_bytes: 1024 * 1024 * 1024,
                window: Duration::from_secs(60),
            },
            trusted_proxies,
        }
    }

    /// Create a rate limit state with default configurations and trusted proxy allowlist
    pub fn with_trusted_proxies(trusted_proxies: Vec<ipnet::IpNet>) -> Self {
        Self {
            trusted_proxies,
            ..Self::default()
        }
    }
    /// Check and record byte consumption for session and global limiters.
    /// Returns Ok(()) if within budget, Err(retry_after) if exceeded.
    pub async fn check_and_record_bytes(&self, session_id: &str, bytes: u64) -> Result<(), u64> {
        self.session_byte_limiter
            .check_and_record(session_id, bytes, &self.session_byte_config)
            .await?;
        self.global_byte_limiter
            .check_and_record("global", bytes, &self.global_byte_config)
            .await?;
        Ok(())
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
            loop {
                interval.tick().await;
                self.session_limiter.cleanup(Duration::from_secs(120)).await;
                self.ip_limiter.cleanup(Duration::from_secs(120)).await;
                self.session_byte_limiter
                    .cleanup(Duration::from_secs(120))
                    .await;
                self.global_byte_limiter
                    .cleanup(Duration::from_secs(120))
                    .await;
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

/// Extract client IP from request.
/// Only trusts forwarding headers (X-Forwarded-For, X-Real-IP) if the immediate
/// connection peer matches an explicit trusted-proxy CIDR in `trusted_proxies`.
pub fn extract_client_ip(req: &Request<Body>, trusted_proxies: &[ipnet::IpNet]) -> Option<IpAddr> {
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let Some(peer) = peer_ip else {
        return None;
    };

    // If trusted_proxies is empty or peer is not in trusted_proxies, ignore forwarding headers
    let is_trusted_proxy = trusted_proxies.iter().any(|net| net.contains(&peer));
    if !is_trusted_proxy {
        return Some(peer);
    }

    // Trusted proxy: check X-Forwarded-For header first
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = value.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    Some(peer)
}

/// Extract session fingerprint from request for rate limiting.
/// Hashes the raw token to prevent logging or exposing replayable credentials.
pub fn extract_session_for_rate_limit(req: &Request<Body>) -> Option<String> {
    use sha2::{Digest, Sha256};

    let raw_token = if let Some(auth_header) = req.headers().get("authorization") {
        auth_header
            .to_str()
            .ok()
            .and_then(|s| s.strip_prefix("Bearer ").map(|t| t.to_string()))
    } else {
        let cookies = req
            .headers()
            .get_all("cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join("; ");

        let mut token = None;
        for cookie in cookies.split(';') {
            let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
            if parts.len() == 2 && parts[0] == "catbird_session" {
                token = Some(parts[1].to_string());
                break;
            }
        }
        token
    };

    raw_token.map(|t| {
        let hash = Sha256::digest(t.as_bytes());
        let mut hex_str = String::with_capacity(32);
        for byte in &hash[..16] {
            use std::fmt::Write;
            let _ = write!(&mut hex_str, "{:02x}", byte);
        }
        hex_str
    })
}

/// Per-session rate limiting middleware for XRPC proxy endpoints
/// Limits: 100 requests per minute per session
pub async fn session_rate_limit(
    State(rate_limit): State<Arc<RateLimitState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Extract session ID for rate limiting
    let key = match extract_session_for_rate_limit(&req) {
        Some(session_fp) => format!("session:{}", session_fp),
        None => {
            // No session - use IP as fallback
            match extract_client_ip(&req, &rate_limit.trusted_proxies) {
                Some(ip) => format!("ip:{}", ip),
                None => "unknown".to_string(),
            }
        }
    };

    match rate_limit
        .session_limiter
        .check(&key, &rate_limit.session_config)
        .await
    {
        Ok(remaining) => {
            tracing::trace!(key = %key, remaining = remaining, "Session rate limit check passed");
            next.run(req).await
        }
        Err(retry_after) => {
            tracing::warn!(key = %key, retry_after = retry_after, "Session rate limit exceeded");
            metrics::record_rate_limit_exceeded("xrpc");
            rate_limit_response(retry_after)
        }
    }
}

/// Per-IP rate limiting middleware for auth endpoints
/// Limits: 10 requests per minute per IP
pub async fn ip_rate_limit(
    State(rate_limit): State<Arc<RateLimitState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let key = match extract_client_ip(&req, &rate_limit.trusted_proxies) {
        Some(ip) => format!("auth:{}", ip),
        None => "auth:unknown".to_string(),
    };

    match rate_limit
        .ip_limiter
        .check(&key, &rate_limit.ip_config)
        .await
    {
        Ok(remaining) => {
            tracing::trace!(key = %key, remaining = remaining, "IP rate limit check passed");
            next.run(req).await
        }
        Err(retry_after) => {
            tracing::warn!(key = %key, retry_after = retry_after, "Auth rate limit exceeded");
            metrics::record_rate_limit_exceeded("auth");
            rate_limit_response(retry_after)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_extract_client_ip_with_untrusted_peer_ignores_forwarded_headers() {
        let req = Request::builder()
            .header("x-forwarded-for", "203.0.113.195, 10.0.0.1")
            .header("x-real-ip", "203.0.113.195")
            .extension(ConnectInfo(SocketAddr::from(([198, 51, 100, 50], 8080))))
            .body(Body::empty())
            .unwrap();

        // Default empty trusted_proxies: immediate peer IP is used, X-Forwarded-For ignored
        let ip = extract_client_ip(&req, &[]).unwrap();
        assert_eq!(ip, IpAddr::from([198, 51, 100, 50]));
    }

    #[test]
    fn test_extract_client_ip_with_trusted_peer_honors_forwarded_headers() {
        let trusted_net: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let req = Request::builder()
            .header("x-forwarded-for", "203.0.113.195, 10.0.0.1")
            .extension(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 8080))))
            .body(Body::empty())
            .unwrap();

        let ip = extract_client_ip(&req, &[trusted_net]).unwrap();
        assert_eq!(ip, IpAddr::from([203, 0, 113, 195]));
    }

    #[test]
    fn test_extract_session_for_rate_limit_hashes_bearer() {
        let raw_token = "550e8400-e29b-41d4-a716-446655440000";
        let req = Request::builder()
            .header("authorization", format!("Bearer {raw_token}"))
            .body(Body::empty())
            .unwrap();

        let fp = extract_session_for_rate_limit(&req).unwrap();
        assert_ne!(fp, raw_token);
        assert!(!fp.contains(raw_token));
        assert_eq!(fp.len(), 32); // 16 bytes in hex = 32 chars
    }

    #[test]
    fn test_extract_client_ip_with_conflicting_headers_and_trusted_peer() {
        let trusted_net: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        // Multiple IPs in X-Forwarded-For: should use the first (client) IP
        let req = Request::builder()
            .header("x-forwarded-for", "198.51.100.1, 10.0.0.2, 10.0.0.3")
            .header("x-real-ip", "198.51.100.2")
            .extension(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 8080))))
            .body(Body::empty())
            .unwrap();

        let ip = extract_client_ip(&req, &[trusted_net]).unwrap();
        assert_eq!(ip, IpAddr::from([198, 51, 100, 1]));
    }

    #[test]
    fn test_extract_client_ip_missing_connect_info_returns_none() {
        let req = Request::builder()
            .header("x-forwarded-for", "198.51.100.1")
            .body(Body::empty())
            .unwrap();

        let ip = extract_client_ip(&req, &[]);
        assert!(ip.is_none());
    }
}
