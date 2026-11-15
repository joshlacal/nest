//! Middleware module for Catbird Gateway
//!
//! Contains authentication, rate limiting, request ID, and response enrichment middleware.

mod auth;
mod rate_limit;
mod request_id;

pub use auth::{
    auth_middleware, authenticate_session_headers, JacquardDpopData, SESSION_COOKIE_NAME,
};
pub use rate_limit::{
    ip_rate_limit, push_deliver_ip_rate_limit, session_rate_limit, ByteRateLimitConfig,
    ByteRateLimiter, RateLimitConfig, RateLimitState, RateLimiter, PUSH_DELIVER_IP_LIMIT,
};
pub use request_id::{request_id_middleware, RequestId};
