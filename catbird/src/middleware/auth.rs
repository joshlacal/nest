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
use crate::error::AppError;
use crate::models::CatbirdSession;
use crate::services::SessionService;

/// Cookie name for the Catbird session
pub const SESSION_COOKIE_NAME: &str = "catbird_session";

/// Header name for Bearer token authentication (alternative to cookie)
pub const AUTH_HEADER_NAME: &str = "authorization";

fn atproto_auth_error(status: StatusCode, error: &str, message: impl Into<String>) -> AppError {
    AppError::AtprotoResponse {
        status,
        error: error.to_string(),
        message: message.into(),
    }
}

fn classify_auth_error(error: AppError) -> AppError {
    match error {
        AppError::InvalidSession => atproto_auth_error(
            StatusCode::UNAUTHORIZED,
            "InvalidToken",
            "Session is invalid or missing. Please log in again.",
        ),
        AppError::SessionExpired | AppError::TokenRefresh(_) => atproto_auth_error(
            StatusCode::UNAUTHORIZED,
            "ExpiredToken",
            "Session expired. Please log in again.",
        ),
        AppError::AuthTemporarilyUnavailable(message) => atproto_auth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "TemporarilyUnavailable",
            message,
        ),
        AppError::Redis(_) | AppError::HttpClient(_) => atproto_auth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "TemporarilyUnavailable",
            "Authentication service is temporarily unavailable. Please retry.",
        ),
        AppError::OAuth(message) => {
            let lower = message.to_ascii_lowercase();
            if lower.contains("invalid_grant")
                || lower.contains("invalid_token")
                || lower.contains("no refresh token")
                || lower.contains("no per-session oauth data")
            {
                atproto_auth_error(
                    StatusCode::UNAUTHORIZED,
                    "ExpiredToken",
                    "Session expired. Please log in again.",
                )
            } else {
                atproto_auth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "TemporarilyUnavailable",
                    "Authentication service is temporarily unavailable. Please retry.",
                )
            }
        }
        AppError::AtprotoResponse { .. } => error,
        other => {
            tracing::warn!("Unexpected auth failure type: {}", other);
            atproto_auth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "TemporarilyUnavailable",
                "Authentication service is temporarily unavailable. Please retry.",
            )
        }
    }
}

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
) -> Result<Response, AppError> {
    let session_id = extract_session_id(&req).ok_or_else(|| {
        atproto_auth_error(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "Missing authentication session.",
        )
    })?;

    let session_service = SessionService::new(state.clone());

    let session = session_service
        .get_valid_session(&session_id)
        .await
        .map_err(|e| {
            tracing::warn!("Session validation failed: {}", e);
            classify_auth_error(e)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn extracts_session_from_bearer_header() {
        let request = Request::builder()
            .header(AUTH_HEADER_NAME, "Bearer abc123")
            .body(Body::empty())
            .expect("request");

        assert_eq!(extract_session_id(&request), Some("abc123".to_string()));
    }

    #[test]
    fn extracts_session_from_cookie() {
        let request = Request::builder()
            .header("cookie", "foo=bar; catbird_session=cookie-token; baz=1")
            .body(Body::empty())
            .expect("request");

        assert_eq!(
            extract_session_id(&request),
            Some("cookie-token".to_string())
        );
    }

    #[test]
    fn classifies_invalid_session_as_invalid_token() {
        let mapped = classify_auth_error(AppError::InvalidSession);
        match mapped {
            AppError::AtprotoResponse {
                status,
                error,
                message: _,
            } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(error, "InvalidToken");
            }
            _ => panic!("expected AtprotoResponse"),
        }
    }

    #[test]
    fn classifies_transient_auth_failure_as_temporarily_unavailable() {
        let mapped = classify_auth_error(AppError::AuthTemporarilyUnavailable(
            "upstream timeout".into(),
        ));
        match mapped {
            AppError::AtprotoResponse {
                status,
                error,
                message: _,
            } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(error, "TemporarilyUnavailable");
            }
            _ => panic!("expected AtprotoResponse"),
        }
    }
}
