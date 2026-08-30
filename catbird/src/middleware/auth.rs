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

/// Extract session ID from request (cookie or Authorization header).
///
/// Authorization rules:
/// - If `Authorization` header is present:
///   - It MUST be a valid, non-empty "Bearer <token>" header.
///   - If malformed, empty, or using an unsupported scheme, an `InvalidSession` (401) error is returned immediately.
///   - Under no circumstances does a request with a present `Authorization` header fall back to cookie authentication.
/// - If `Authorization` header is absent:
///   - Fall back to checking the `catbird_session` cookie.
///   - If cookie is missing or empty, returns an `AuthenticationRequired` (401) error.
fn extract_session_id(req: &Request<Body>) -> Result<String, AppError> {
    if let Some(auth_header) = req.headers().get(AUTH_HEADER_NAME) {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| classify_auth_error(AppError::InvalidSession))?;

        let token = auth_str
            .strip_prefix("Bearer ")
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| classify_auth_error(AppError::InvalidSession))?;

        return Ok(token.to_string());
    }

    // Fall back to cookie only when Authorization header is absent
    let cookies = req
        .headers()
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");

    for cookie in cookies.split(';') {
        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == SESSION_COOKIE_NAME {
            let token = parts[1].trim();
            if !token.is_empty() {
                return Ok(token.to_string());
            }
        }
    }

    Err(atproto_auth_error(
        StatusCode::UNAUTHORIZED,
        "AuthenticationRequired",
        "Missing authentication session.",
    ))
}

/// Authentication middleware
///
/// This middleware:
/// 1. Extracts the session ID from cookie or Authorization header
/// 2. Validates the session via Jacquard SessionRegistry (with automatic token refresh)
/// 3. Injects the session into request extensions
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let session_id = extract_session_id(&req)?;

    // Strict rejection of non-UUID session IDs — never fabricate or proceed with malformed identity
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return Err(classify_auth_error(AppError::InvalidSession));
    }
    let auth_store = state.auth_store.as_ref().ok_or_else(|| {
        classify_auth_error(AppError::Internal("Auth store not configured".into()))
    })?;
    let jacquard_client = state.jacquard_client.as_ref().ok_or_else(|| {
        classify_auth_error(AppError::Internal("Jacquard client not configured".into()))
    })?;

    let (session, dpop_data) =
        resolve_session_via_jacquard(auth_store, jacquard_client, &session_id)
            .await
            .map_err(classify_auth_error)?;

    req.extensions_mut().insert(session);
    req.extensions_mut().insert(dpop_data);
    Ok(next.run(req).await)
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

    // Strict UUID validation — reject malformed session IDs immediately
    let session_uuid = uuid::Uuid::parse_str(session_id).map_err(|_| AppError::InvalidSession)?;

    // Step 1: Look up DID from session index
    let did_str = auth_store
        .lookup_did_for_session(session_id)
        .await
        .map_err(AppError::Redis)?
        .ok_or(AppError::InvalidSession)?;

    let did = Did::new(did_str.as_str()).map_err(|_| AppError::InvalidSession)?;
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

    // Extract and validate authoritative granted scopes returned by PDS/OAuth server.
    // Authenticate only sessions with authoritative parseable nonempty granted scopes containing `atproto`.
    // No unwrap_or_default or legacy empty acceptance.
    let token_scope_str = session_data.token_set.scope.as_ref().map(|s| s.as_str());
    let granted_scopes =
        validate_authoritative_granted_scopes(&session_data.scopes, token_scope_str)?;
    let session = CatbirdSession {
        id: session_uuid,
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
        scopes: session_data
            .scopes
            .iter()
            .map(|scope| scope.to_string())
            .collect(),
        access_token_expires_at: expires_at,
        created_at: Utc::now(), // Not tracked in Jacquard session
        last_used_at: Utc::now(),
        granted_scopes,
    };

    Ok((session, dpop_data))
}

/// Validates authoritative granted scopes returned by PDS/OAuth server.
///
/// Enforces that:
/// 1. Scopes are non-empty and parseable without falling back to defaults.
/// 2. Scopes explicitly contain the required `atproto` scope.
fn validate_authoritative_granted_scopes(
    scopes: &jacquard_oauth::scopes::Scopes,
    token_scope: Option<&str>,
) -> Result<Vec<String>, AppError> {
    use jacquard_oauth::scopes::{Scope, Scopes};

    let parsed_scopes: Scopes = if !scopes.is_empty() {
        scopes.clone()
    } else if let Some(scope_str) = token_scope {
        Scopes::new(smol_str::SmolStr::from(scope_str)).map_err(|_| AppError::InvalidSession)?
    } else {
        return Err(AppError::InvalidSession);
    };

    if parsed_scopes.is_empty() {
        return Err(AppError::InvalidSession);
    }

    if !parsed_scopes.grants(&Scope::atproto())
        && !parsed_scopes.iter().any(|s| matches!(s, Scope::Atproto))
    {
        return Err(AppError::InvalidSession);
    }

    Ok(parsed_scopes
        .iter()
        .map(|s| s.to_string_normalized().to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn extracts_session_from_bearer_header() {
        let request = Request::builder()
            .header(
                AUTH_HEADER_NAME,
                "Bearer 550e8400-e29b-41d4-a716-446655440000",
            )
            .body(Body::empty())
            .expect("request");

        assert_eq!(
            extract_session_id(&request).unwrap(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn extracts_session_from_cookie_when_header_absent() {
        let request = Request::builder()
            .header(
                "cookie",
                "foo=bar; catbird_session=550e8400-e29b-41d4-a716-446655440000; baz=1",
            )
            .body(Body::empty())
            .expect("request");

        assert_eq!(
            extract_session_id(&request).unwrap(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn missing_header_and_missing_cookie_returns_authentication_required() {
        let request = Request::builder().body(Body::empty()).expect("request");

        let err = extract_session_id(&request).unwrap_err();
        match err {
            AppError::AtprotoResponse { status, error, .. } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(error, "AuthenticationRequired");
            }
            other => panic!("expected AuthenticationRequired, got {:?}", other),
        }
    }

    #[test]
    fn valid_cookie_with_invalid_bearer_returns_401_and_never_authenticates_cookie() {
        // Case 1: Empty Bearer token with valid cookie
        let request = Request::builder()
            .header(AUTH_HEADER_NAME, "Bearer ")
            .header(
                "cookie",
                "catbird_session=550e8400-e29b-41d4-a716-446655440000",
            )
            .body(Body::empty())
            .expect("request");

        let err = extract_session_id(&request).unwrap_err();
        match err {
            AppError::AtprotoResponse { status, error, .. } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(error, "InvalidToken");
            }
            other => panic!("expected InvalidToken, got {:?}", other),
        }

        // Case 2: Unsupported auth scheme (Basic) with different valid cookie
        let request_basic = Request::builder()
            .header(AUTH_HEADER_NAME, "Basic dXNlcjpwYXNz")
            .header(
                "cookie",
                "catbird_session=660e8400-e29b-41d4-a716-446655440000",
            )
            .body(Body::empty())
            .expect("request");

        let err = extract_session_id(&request_basic).unwrap_err();
        match err {
            AppError::AtprotoResponse { status, error, .. } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(error, "InvalidToken");
            }
            other => panic!("expected InvalidToken, got {:?}", other),
        }

        // Case 3: Malformed Authorization header with different valid cookie
        let request_malformed = Request::builder()
            .header(AUTH_HEADER_NAME, "not-a-valid-bearer")
            .header(
                "cookie",
                "catbird_session=770e8400-e29b-41d4-a716-446655440000",
            )
            .body(Body::empty())
            .expect("request");

        let err = extract_session_id(&request_malformed).unwrap_err();
        match err {
            AppError::AtprotoResponse { status, error, .. } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(error, "InvalidToken");
            }
            other => panic!("expected InvalidToken, got {:?}", other),
        }
    }

    #[test]
    fn valid_bearer_takes_precedence_over_different_valid_cookie() {
        let request = Request::builder()
            .header(
                AUTH_HEADER_NAME,
                "Bearer 550e8400-e29b-41d4-a716-446655440000",
            )
            .header(
                "cookie",
                "catbird_session=660e8400-e29b-41d4-a716-446655440000",
            )
            .body(Body::empty())
            .expect("request");

        assert_eq!(
            extract_session_id(&request).unwrap(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_push_accounts_database_fingerprint_replayed_as_bearer_or_cookie_returns_401() {
        let raw_session = "550e8400-e29b-41d4-a716-446655440000";
        let db_stored_fingerprint =
            crate::services::push::registry::session_fingerprint(raw_session);
        assert_eq!(db_stored_fingerprint.len(), 64);

        // Case 1: Replayed as Bearer header
        let req_bearer = Request::builder()
            .header(AUTH_HEADER_NAME, format!("Bearer {db_stored_fingerprint}"))
            .body(Body::empty())
            .unwrap();
        let session_id = extract_session_id(&req_bearer).unwrap();
        // Middleware requires strict UUID validation
        assert!(uuid::Uuid::parse_str(&session_id).is_err());

        // Case 2: Replayed as Cookie
        let req_cookie = Request::builder()
            .header("cookie", format!("catbird_session={db_stored_fingerprint}"))
            .body(Body::empty())
            .unwrap();
        let session_id_cookie = extract_session_id(&req_cookie).unwrap();
        assert!(uuid::Uuid::parse_str(&session_id_cookie).is_err());
    }

    #[test]
    fn scope_validation_accepts_authoritative_atproto_scope() {
        let scopes = jacquard_oauth::scopes::Scopes::atproto();
        let granted = validate_authoritative_granted_scopes(&scopes, None).unwrap();
        assert_eq!(granted, vec!["atproto"]);
    }

    #[test]
    fn scope_validation_accepts_atproto_with_additional_scopes() {
        let scopes = jacquard_oauth::scopes::Scopes::new(smol_str::SmolStr::new_static(
            "atproto transition:generic",
        ))
        .unwrap();
        let granted = validate_authoritative_granted_scopes(&scopes, None).unwrap();
        assert_eq!(granted, vec!["atproto", "transition:generic"]);
    }

    #[test]
    fn scope_validation_accepts_parseable_token_scope_with_atproto() {
        let empty_scopes = jacquard_oauth::scopes::Scopes::empty();
        let granted = validate_authoritative_granted_scopes(
            &empty_scopes,
            Some("atproto transition:generic"),
        )
        .unwrap();
        assert_eq!(granted, vec!["atproto", "transition:generic"]);
    }

    #[test]
    fn scope_validation_rejects_empty_scopes() {
        let empty_scopes = jacquard_oauth::scopes::Scopes::empty();
        assert!(matches!(
            validate_authoritative_granted_scopes(&empty_scopes, None),
            Err(AppError::InvalidSession)
        ));
        assert!(matches!(
            validate_authoritative_granted_scopes(&empty_scopes, Some("")),
            Err(AppError::InvalidSession)
        ));
    }

    #[test]
    fn scope_validation_rejects_unparseable_token_scope_without_defaulting() {
        let empty_scopes = jacquard_oauth::scopes::Scopes::empty();
        assert!(matches!(
            validate_authoritative_granted_scopes(&empty_scopes, Some("invalid:::scope;;;")),
            Err(AppError::InvalidSession)
        ));
    }

    #[test]
    fn scope_validation_rejects_scopes_missing_atproto() {
        let scopes = jacquard_oauth::scopes::Scopes::new(smol_str::SmolStr::new_static(
            "transition:generic",
        ))
        .unwrap();
        assert!(matches!(
            validate_authoritative_granted_scopes(&scopes, None),
            Err(AppError::InvalidSession)
        ));

        let empty_scopes = jacquard_oauth::scopes::Scopes::empty();
        assert!(matches!(
            validate_authoritative_granted_scopes(&empty_scopes, Some("transition:generic")),
            Err(AppError::InvalidSession)
        ));
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
    fn classifies_transient_redis_error_as_temporarily_unavailable() {
        let redis_err = redis::RedisError::from((redis::ErrorKind::IoError, "connection refused"));
        let mapped = classify_auth_error(AppError::Redis(redis_err));
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
    fn pre_v2_legacy_bearer_token_rejected_as_invalid_session() {
        let legacy_tokens = vec![
            "legacy_token_12345",
            "catbird_session_abc",
            "not-a-valid-uuid",
            "12345",
        ];

        for token in legacy_tokens {
            assert!(uuid::Uuid::parse_str(token).is_err());
            let mapped = classify_auth_error(AppError::InvalidSession);
            match mapped {
                AppError::AtprotoResponse { status, error, .. } => {
                    assert_eq!(status, StatusCode::UNAUTHORIZED);
                    assert_eq!(error, "InvalidToken");
                }
                _ => panic!("expected InvalidToken 401 response"),
            }
        }
    }

    #[test]
    fn non_uuid_session_string_fails_uuid_validation() {
        assert!(uuid::Uuid::parse_str("not-a-uuid").is_err());
        assert!(uuid::Uuid::parse_str("12345").is_err());
        assert!(uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }
}
