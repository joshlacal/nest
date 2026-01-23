//! Middleware module for Catbird Gateway
//!
//! Contains authentication, rate limiting, and response enrichment middleware.

mod auth;
mod rate_limit;

pub use auth::{auth_middleware, optional_auth_middleware, SessionExt, SESSION_COOKIE_NAME};
pub use rate_limit::{
    ip_rate_limit, session_rate_limit, RateLimitConfig, RateLimitState,
};
