//! Authentication Middleware
//!
//! Validates Catbird session cookies/tokens and injects session into request extensions.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::config::AppState;
use crate::models::CatbirdSession;
use crate::services::SessionService;

/// Cookie name for the Catbird session
pub const SESSION_COOKIE_NAME: &str = "catbird_session";

/// Header name for Bearer token authentication (alternative to cookie)
pub const AUTH_HEADER_NAME: &str = "authorization";

/// Extract session ID from request (cookie or Authorization header)
fn extract_session_id(req: &Request<Body>) -> Option<String> {
    // Try Authorization header first (for mobile apps)
    if let Some(auth_header) = req.headers().get(AUTH_HEADER_NAME) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    // Fall back to cookie
    let cookies = req
        .headers()
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");

    // Simple cookie parsing
    for cookie in cookies.split(';') {
        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == SESSION_COOKIE_NAME {
            return Some(parts[1].to_string());
        }
    }

    None
}

/// Authentication middleware
/// 
/// This middleware:
/// 1. Extracts the session ID from cookie or Authorization header
/// 2. Validates the session exists in Redis
/// 3. Refreshes the access token if expired
/// 4. Injects the session into request extensions
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let session_id = extract_session_id(&req).ok_or(StatusCode::UNAUTHORIZED)?;

    let session_service = SessionService::new(state.clone());
    
    let session = session_service
        .get_valid_session(&session_id)
        .await
        .map_err(|e| {
            tracing::warn!("Session validation failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    // Insert session into request extensions for handlers to use
    req.extensions_mut().insert(session);

    Ok(next.run(req).await)
}

/// Optional authentication middleware
/// 
/// Like auth_middleware but doesn't fail if no session is present.
/// Useful for endpoints that work with or without authentication.
pub async fn optional_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if let Some(session_id) = extract_session_id(&req) {
        let session_service = SessionService::new(state.clone());
        
        if let Ok(session) = session_service.get_valid_session(&session_id).await {
            req.extensions_mut().insert(session);
        }
    }

    next.run(req).await
}

/// Extension trait to get session from request
pub trait SessionExt {
    fn session(&self) -> Option<&CatbirdSession>;
}

impl<B> SessionExt for Request<B> {
    fn session(&self) -> Option<&CatbirdSession> {
        self.extensions().get::<CatbirdSession>()
    }
}
