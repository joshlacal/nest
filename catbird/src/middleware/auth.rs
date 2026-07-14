//! Authentication Middleware
//!
//! Validates Catbird session cookies/tokens and injects session into request extensions.

use axum::{
    body::Body,
    extract::State,
    http::{header::SET_COOKIE, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::Cookie;
use std::sync::Arc;

use crate::config::AppState;
use crate::error::AppError;
use crate::handlers::atproto::AuthenticatedSessionId;
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
        AppError::ReauthenticationRequired => atproto_auth_error(
            StatusCode::UNAUTHORIZED,
            "ExpiredToken",
            "Session safety could not be confirmed. Please log in again.",
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

fn map_jacquard_session_error(error: jacquard_oauth::session::Error) -> AppError {
    match error {
        jacquard_oauth::session::Error::SessionNotFound => AppError::InvalidSession,
        jacquard_oauth::session::Error::ReauthenticationRequired => {
            AppError::ReauthenticationRequired
        }
        jacquard_oauth::session::Error::OperationInProgress => {
            AppError::AuthTemporarilyUnavailable(
                "Authentication session update is in progress. Please retry.".into(),
            )
        }
        other => AppError::OAuth(format!("Jacquard session get failed: {other}")),
    }
}

fn expire_session_cookie(mut response: Response) -> Response {
    let cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .max_age(time::Duration::ZERO)
        .build();
    response.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string()).expect("session cookie is a valid header"),
    );
    response
}

fn logout_auth_failure_response(error: AppError) -> Result<Response, AppError> {
    match error {
        AppError::ReauthenticationRequired | AppError::InvalidSession => Ok(expire_session_cookie(
            classify_auth_error(error).into_response(),
        )),
        other => Err(classify_auth_error(other)),
    }
}

fn extract_bearer_session_id(req: &Request<Body>) -> Option<String> {
    if let Some(auth_header) = req.headers().get(AUTH_HEADER_NAME) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    None
}

fn extract_cookie_session_id(req: &Request<Body>) -> Option<String> {
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

/// Ordinary protected routes preserve bearer precedence for mobile clients.
fn extract_session_id(req: &Request<Body>) -> Option<String> {
    extract_bearer_session_id(req).or_else(|| extract_cookie_session_id(req))
}

/// Browser logout is specifically responsible for the HTTP-only cookie
/// session. Prefer it whenever present so an unrelated stale bearer cannot
/// prevent revocation/cleanup of the browser credential. Bearer-only mobile
/// logout remains supported.
fn extract_logout_session_id(req: &Request<Body>) -> Option<String> {
    extract_cookie_session_id(req).or_else(|| extract_bearer_session_id(req))
}

/// Authentication middleware
///
/// This middleware:
/// 1. Extracts the session ID from cookie or Authorization header
/// 2. Validates the session via Jacquard SessionRegistry (with automatic token refresh)
/// 3. Rejects missing or unauthenticated records without runtime migration
/// 4. Injects the session into request extensions
async fn authenticate_request(
    state: &AppState,
    req: Request<Body>,
) -> Result<Request<Body>, AppError> {
    let session_id = extract_session_id(&req).ok_or_else(|| {
        atproto_auth_error(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "Missing authentication session.",
        )
    })?;
    authenticate_request_with_session_id(state, req, session_id).await
}

async fn authenticate_request_with_session_id(
    state: &AppState,
    mut req: Request<Body>,
    session_id: String,
) -> Result<Request<Body>, AppError> {
    let auth_store = state.auth_store.as_ref().ok_or_else(|| {
        classify_auth_error(AppError::Internal("Auth store not configured".into()))
    })?;
    let jacquard_client = state.jacquard_client.as_ref().ok_or_else(|| {
        classify_auth_error(AppError::Internal("Jacquard client not configured".into()))
    })?;

    match resolve_session_via_jacquard(auth_store, jacquard_client, &session_id).await {
        Ok((session, dpop_data)) => {
            req.extensions_mut()
                .insert(AuthenticatedSessionId::new(session_id));
            req.extensions_mut().insert(session);
            req.extensions_mut().insert(dpop_data);
            Ok(req)
        }
        Err(error) => Err(error),
    }
}

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let req = authenticate_request(&state, req)
        .await
        .map_err(classify_auth_error)?;
    Ok(next.run(req).await)
}

/// Authentication boundary for logout.
///
/// A session quarantined after an uncertain refresh/revoke cannot be used for
/// any protected operation, but the browser must still be able to discard its
/// HTTP-only session cookie. Only that terminal reauthentication signal gets a
/// cookie-expiring 401 here; transient leases and corrupt records retain their
/// normal retryable 503 behavior and keep the cookie for a later logout retry.
pub async fn logout_auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let session_id = extract_logout_session_id(&req).ok_or_else(|| {
        atproto_auth_error(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "Missing authentication session.",
        )
    });
    let authenticated = match session_id {
        Ok(session_id) => authenticate_request_with_session_id(&state, req, session_id).await,
        Err(error) => Err(error),
    };
    match authenticated {
        Ok(req) => Ok(next.run(req).await),
        Err(error) => logout_auth_failure_response(error),
    }
}

/// Resolve a session via Jacquard's SessionRegistry with automatic token refresh.
///
/// iOS sends only session_id. We use the session_index to look up the DID,
/// then call SessionRegistry.get() which handles token refresh atomically
/// using an in-process mutex for local coalescing plus Redis lifecycle-generation
/// CAS for cross-registry and cross-process correctness (no distributed lock).
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
        .map_err(map_jacquard_session_error)?;

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
    use axum::{extract::Extension, http::Request, middleware, routing::post, Router};
    use tower::ServiceExt;

    async fn quarantined_logout_auth_failure(request: Request<Body>, _next: Next) -> Response {
        let _ = request;
        logout_auth_failure_response(AppError::ReauthenticationRequired)
            .expect("quarantined logout response")
    }

    async fn invalid_logout_auth_failure(request: Request<Body>, _next: Next) -> Response {
        let _ = request;
        logout_auth_failure_response(AppError::InvalidSession).expect("invalid logout response")
    }

    async fn logout_credential_probe(mut request: Request<Body>, next: Next) -> Response {
        let Some(session_id) = extract_logout_session_id(&request) else {
            return logout_auth_failure_response(AppError::InvalidSession)
                .expect("missing logout credential response");
        };
        if session_id == "invalid-cookie" || session_id == "stale-bearer" {
            return logout_auth_failure_response(AppError::InvalidSession)
                .expect("invalid logout credential response");
        }
        request
            .extensions_mut()
            .insert(AuthenticatedSessionId::new(session_id));
        next.run(request).await
    }

    async fn selected_logout_session(
        Extension(session_id): Extension<AuthenticatedSessionId>,
    ) -> Response {
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("x-selected-session", session_id.as_str())
            .body(Body::empty())
            .unwrap()
    }

    fn logout_credential_probe_app() -> Router {
        Router::new()
            .route("/auth/logout", post(selected_logout_session))
            .layer(middleware::from_fn(logout_credential_probe))
    }

    #[tokio::test]
    async fn logout_route_prefers_valid_cookie_over_stale_bearer() {
        let response = logout_credential_probe_app()
            .oneshot(
                Request::post("/auth/logout")
                    .header(AUTH_HEADER_NAME, "Bearer stale-bearer")
                    .header("cookie", "catbird_session=cookie-valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()["x-selected-session"], "cookie-valid");
        assert!(response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .next()
            .is_none());
    }

    #[tokio::test]
    async fn logout_route_chooses_cookie_when_bearer_and_cookie_are_both_valid() {
        let response = logout_credential_probe_app()
            .oneshot(
                Request::post("/auth/logout")
                    .header(AUTH_HEADER_NAME, "Bearer bearer-valid")
                    .header("cookie", "catbird_session=cookie-valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()["x-selected-session"], "cookie-valid");
    }

    #[tokio::test]
    async fn logout_route_keeps_bearer_only_mobile_compatibility() {
        let response = logout_credential_probe_app()
            .oneshot(
                Request::post("/auth/logout")
                    .header(AUTH_HEADER_NAME, "Bearer bearer-valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()["x-selected-session"], "bearer-valid");
    }

    #[tokio::test]
    async fn logout_route_expires_invalid_cookie_instead_of_using_valid_bearer() {
        let response = logout_credential_probe_app()
            .oneshot(
                Request::post("/auth/logout")
                    .header(AUTH_HEADER_NAME, "Bearer bearer-valid")
                    .header("cookie", "catbird_session=invalid-cookie")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let set_cookie = response
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn logout_route_expires_cookie_when_session_requires_reauthentication() {
        let app = Router::new()
            .route("/auth/logout", post(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn(quarantined_logout_auth_failure));
        let response = app
            .oneshot(
                Request::post("/auth/logout")
                    .header("cookie", "catbird_session=quarantined-session")
                    .body(Body::empty())
                    .expect("logout request"),
            )
            .await
            .expect("logout response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let set_cookie = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("catbird_session="))
            .expect("quarantined logout must expire the browser session cookie");
        assert!(set_cookie.contains("Max-Age=0"));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(!set_cookie.contains("quarantined-session"));
    }

    #[tokio::test]
    async fn logout_route_expires_cookie_when_session_is_missing() {
        let app = Router::new()
            .route("/auth/logout", post(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn(invalid_logout_auth_failure));
        let response = app
            .oneshot(
                Request::post("/auth/logout")
                    .header("cookie", "catbird_session=expired-session")
                    .body(Body::empty())
                    .expect("logout request"),
            )
            .await
            .expect("logout response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let set_cookie = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("catbird_session="))
            .expect("missing session logout must expire the browser cookie");
        assert!(set_cookie.contains("Max-Age=0"));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(!set_cookie.contains("expired-session"));
    }

    #[test]
    fn logout_auth_keeps_active_operation_failures_retryable() {
        let response = logout_auth_failure_response(AppError::AuthTemporarilyUnavailable(
            "session is quarantined by an active operation".into(),
        ))
        .expect_err("active operation must not become a terminal logout")
        .into_response();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .next()
            .is_none());
    }

    #[test]
    fn logout_auth_keeps_corrupt_session_failures_retryable() {
        let response = logout_auth_failure_response(AppError::Internal(
            "Session index lookup failed: invalid encrypted record".into(),
        ))
        .expect_err("corrupt state must remain unavailable instead of terminal")
        .into_response();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .next()
            .is_none());
    }

    #[test]
    fn extracts_session_from_bearer_header() {
        let request = Request::builder()
            .header(AUTH_HEADER_NAME, "Bearer abc123")
            .body(Body::empty())
            .expect("request");

        assert_eq!(extract_session_id(&request), Some("abc123".to_string()));
    }

    #[test]
    fn ordinary_auth_keeps_bearer_precedence_when_cookie_is_also_present() {
        let request = Request::builder()
            .header(AUTH_HEADER_NAME, "Bearer bearer-token")
            .header("cookie", "catbird_session=cookie-token")
            .body(Body::empty())
            .expect("request");

        assert_eq!(
            extract_session_id(&request),
            Some("bearer-token".to_string())
        );
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
    fn authenticated_session_capability_preserves_non_uuid_bearer_exactly() {
        let capability = AuthenticatedSessionId::new("opaque.non-uuid/session-token");
        assert_eq!(capability.as_str(), "opaque.non-uuid/session-token");
        assert!(!format!("{capability:?}").contains("opaque.non-uuid/session-token"));
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

    #[test]
    fn classifies_uncertain_refresh_as_clean_reauthentication() {
        let app_error =
            map_jacquard_session_error(jacquard_oauth::session::Error::ReauthenticationRequired);
        assert!(matches!(app_error, AppError::ReauthenticationRequired));
        let mapped = classify_auth_error(app_error);
        match mapped {
            AppError::AtprotoResponse {
                status,
                error,
                message,
            } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(error, "ExpiredToken");
                assert!(message.contains("log in again"));
            }
            _ => panic!("expected AtprotoResponse"),
        }
    }

    #[test]
    fn classifies_missing_jacquard_session_as_invalid_session() {
        let app_error = map_jacquard_session_error(jacquard_oauth::session::Error::SessionNotFound);
        assert!(matches!(app_error, AppError::InvalidSession));
        let mapped = classify_auth_error(app_error);
        match mapped {
            AppError::AtprotoResponse { status, error, .. } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(error, "InvalidToken");
            }
            _ => panic!("expected AtprotoResponse"),
        }
    }

    #[test]
    fn classifies_active_session_operation_as_retryable_unavailability() {
        let app_error =
            map_jacquard_session_error(jacquard_oauth::session::Error::OperationInProgress);
        assert!(matches!(app_error, AppError::AuthTemporarilyUnavailable(_)));
        let response = classify_auth_error(app_error).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn classifies_corrupt_session_store_state_as_retryable_unavailability() {
        let store_error = jacquard_common::session::SessionStoreError::Other(
            "invalid encrypted session record".into(),
        );
        let app_error =
            map_jacquard_session_error(jacquard_oauth::session::Error::Store(store_error));
        let response = classify_auth_error(app_error).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
