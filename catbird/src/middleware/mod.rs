//! Middleware module for Catbird Gateway
//!
//! Contains authentication and response enrichment middleware.

mod auth;
pub use auth::{auth_middleware, optional_auth_middleware, SessionExt, SESSION_COOKIE_NAME};
