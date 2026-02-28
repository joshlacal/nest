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
use chrono::Utc;

/// DPoP key data from Jacquard session, inserted into request extensions for the proxy.
#[derive(Clone)]
pub struct JacquardDpopData {
    pub dpop_key: jose_jwk::Key,
    pub dpop_host_nonce: String,
}

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
/// 2. Validates the session via Jacquard SessionRegistry (with automatic token refresh)
/// 3. Attempts legacy session migration if Jacquard lookup fails
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

    let auth_store = state.auth_store.as_ref().ok_or_else(|| {
        classify_auth_error(AppError::Internal("Auth store not configured".into()))
    })?;
    let jacquard_client = state.jacquard_client.as_ref().ok_or_else(|| {
        classify_auth_error(AppError::Internal("Jacquard client not configured".into()))
    })?;

    // Try Jacquard path (new sessions + already-migrated sessions)
    match resolve_session_via_jacquard(auth_store, jacquard_client, &session_id).await {
        Ok((session, dpop_data)) => {
            req.extensions_mut().insert(session);
            req.extensions_mut().insert(dpop_data);
            return Ok(next.run(req).await);
        }
        Err(AppError::InvalidSession) => {
            // Session not found — attempt legacy migration
            tracing::debug!(session_id = %session_id, "Jacquard session not found, attempting legacy migration");
        }
        Err(e) => {
            return Err(classify_auth_error(e));
        }
    }

    // Attempt to migrate a legacy (pre-Jacquard) session
    match auth_store.try_migrate_legacy_session(&session_id).await {
        Ok(Some(_)) => {
            tracing::info!(session_id = %session_id, "Legacy session migrated, retrying Jacquard lookup");
            // Migration succeeded — retry Jacquard lookup
            let (session, dpop_data) =
                resolve_session_via_jacquard(auth_store, jacquard_client, &session_id)
                    .await
                    .map_err(classify_auth_error)?;
            req.extensions_mut().insert(session);
            req.extensions_mut().insert(dpop_data);
            Ok(next.run(req).await)
        }
        Ok(None) => {
            // No legacy session either
            Err(classify_auth_error(AppError::InvalidSession))
        }
        Err(e) => {
            tracing::warn!(session_id = %session_id, error = %e, "Legacy session migration failed");
            Err(classify_auth_error(AppError::InvalidSession))
        }
    }
}

/// Resolve a session via Jacquard's SessionRegistry with automatic token refresh.
///
/// iOS sends only session_id. We use the session_index to look up the DID,
/// then call SessionRegistry.get() which handles token refresh atomically
/// using in-process DashMap mutex (no Redis distributed locks needed).
async fn resolve_session_via_jacquard(
    auth_store: &crate::services::RedisAuthStore,
    jacquard_client: &crate::config::JacquardOAuthClient,
    session_id: &str,
) -> Result<(CatbirdSession, JacquardDpopData), AppError> {
    use jacquard_common::types::did::Did;

    // Step 1: Look up DID from session index
    let did_str = auth_store
        .lookup_did_for_session(session_id)
        .await
        .map_err(|e| AppError::Internal(format!("Session index lookup failed: {e}")))?
        .ok_or(AppError::InvalidSession)?;

    let did = Did::new(&did_str)
        .map_err(|e| AppError::Internal(format!("Invalid DID in session index: {e}")))?;

    // Step 2: Get session from registry (auto_refresh=true triggers token refresh if needed)
    let session_data = jacquard_client
        .registry
        .get(&did, session_id, true)
        .await
        .map_err(|e| AppError::OAuth(format!("Jacquard session get failed: {e}")))?;

    // Step 3: Convert ClientSessionData → CatbirdSession for backward compatibility
    let expires_at = session_data
        .token_set
        .expires_at
        .as_ref()
        .and_then(|dt| {
            // Parse jacquard Datetime to chrono
            let s = dt.as_str();
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        })
        .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(3600));

    // Extract DPoP data for the proxy
    let dpop_data = JacquardDpopData {
        dpop_key: session_data.dpop_data.dpop_key.clone(),
        dpop_host_nonce: session_data.dpop_data.dpop_host_nonce.to_string(),
    };

    // Try to resolve handle (best effort)
    let handle = did_str.clone(); // Will be enriched by handler if needed

    let session = CatbirdSession {
        id: uuid::Uuid::parse_str(session_id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
        did: did_str,
        handle,
        pds_url: session_data.host_url.to_string(),
        access_token: session_data.token_set.access_token.to_string(),
        refresh_token: session_data
            .token_set
            .refresh_token
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_default(),
        access_token_expires_at: expires_at,
        created_at: Utc::now(), // Not tracked in Jacquard session
        last_used_at: Utc::now(),
    };

    Ok((session, dpop_data))
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
