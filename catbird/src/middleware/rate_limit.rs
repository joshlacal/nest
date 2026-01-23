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
            let retry_after = config.window.as_secs()
                - now.duration_since(entry.window_start).as_secs();
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

/// Shared rate limiter state for the application
#[derive(Clone)]
pub struct RateLimitState {
    /// Rate limiter for session-based limits (XRPC proxy)
    pub session_limiter: Arc<RateLimiter>,
    /// Rate limiter for IP-based limits (auth endpoints)
    pub ip_limiter: Arc<RateLimiter>,
    /// Configuration for session-based rate limiting
    pub session_config: RateLimitConfig,
    /// Configuration for IP-based rate limiting
    pub ip_config: RateLimitConfig,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self {
            session_limiter: Arc::new(RateLimiter::new()),
            ip_limiter: Arc::new(RateLimiter::new()),
            session_config: RateLimitConfig {
                max_requests: 100,
                window: Duration::from_secs(60),
            },
            ip_config: RateLimitConfig {
                max_requests: 10,
                window: Duration::from_secs(60),
            },
        }
    }
}

impl RateLimitState {
    /// Create a new rate limit state with custom configurations
    pub fn new(session_config: RateLimitConfig, ip_config: RateLimitConfig) -> Self {
        Self {
            session_limiter: Arc::new(RateLimiter::new()),
            ip_limiter: Arc::new(RateLimiter::new()),
            session_config,
            ip_config,
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

/// Extract client IP from request
/// Checks X-Forwarded-For header first, then falls back to connection info
fn extract_client_ip(req: &Request<Body>) -> Option<IpAddr> {
    // Check X-Forwarded-For header (from reverse proxy)
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            // Take the first IP in the chain (original client)
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

    // Fall back to connection info
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
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
/// Limits: 100 requests per minute per session
pub async fn session_rate_limit(
    State(rate_limit): State<Arc<RateLimitState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Extract session ID for rate limiting
    let key = match extract_session_for_rate_limit(&req) {
        Some(session_id) => format!("session:{}", session_id),
        None => {
            // No session - use IP as fallback
            match extract_client_ip(&req) {
                Some(ip) => format!("ip:{}", ip),
                None => "unknown".to_string(),
            }
        }
    };

    match rate_limit.session_limiter.check(&key, &rate_limit.session_config).await {
        Ok(remaining) => {
            tracing::trace!(key = %key, remaining = remaining, "Session rate limit check passed");
            next.run(req).await
        }
        Err(retry_after) => {
            tracing::warn!(key = %key, retry_after = retry_after, "Session rate limit exceeded");
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
    let key = match extract_client_ip(&req) {
        Some(ip) => format!("auth:{}", ip),
        None => "auth:unknown".to_string(),
    };

    match rate_limit.ip_limiter.check(&key, &rate_limit.ip_config).await {
        Ok(remaining) => {
            tracing::trace!(key = %key, remaining = remaining, "IP rate limit check passed");
            next.run(req).await
        }
        Err(retry_after) => {
            tracing::warn!(key = %key, retry_after = retry_after, "Auth rate limit exceeded");
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
}
