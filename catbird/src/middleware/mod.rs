//! Middleware module for Catbird Gateway
//!
//! Contains authentication, rate limiting, request ID, and response enrichment middleware.

mod auth;
mod rate_limit;
mod request_id;

pub use auth::{auth_middleware, JacquardDpopData, SESSION_COOKIE_NAME};
pub use rate_limit::{
    ip_rate_limit, session_rate_limit, RateLimitConfig, RateLimitState,
};
pub use request_id::{request_id_middleware, RequestId};
