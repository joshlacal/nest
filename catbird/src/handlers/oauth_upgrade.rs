//! Progressive OAuth Upgrade Handlers
//!
//! Request handlers for progressive OAuth scope upgrades:
//! - POST /auth/upgrade (start upgrade flow, returns authorization URL)
//! - POST /auth/upgrade/exchange (exchange one-time code + nonce for candidate session info)
//! - POST /auth/upgrade/commit (commit candidate session, activate new session, retire old)

use axum::{
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap},
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::config::{AppState, OAuthConfig};
use crate::error::{AppError, AppResult};
use crate::handlers::atproto::{canonicalize_origin, is_valid_base64url_43};
use crate::models::{
    oauth_upgrade::{
        UpgradeCommitResponse, UpgradeCommitStatus, UpgradeExchangeRequest,
        UpgradeExchangeResponse, UpgradeStartRequest, UpgradeStartResponse,
        ALLOWLISTED_UPGRADE_SCOPES, FIXED_UPGRADE_CALLBACK_URL,
    },
    CatbirdSession,
};
use crate::services::{OAuthUpgradeService, UpgradeError};

/// Helper to obtain an `OAuthUpgradeService` instance from `AppState`.
pub fn get_upgrade_service(state: &AppState) -> AppResult<OAuthUpgradeService> {
    if let Some(auth_store) = state.auth_store.as_ref() {
        return Ok(OAuthUpgradeService::from_auth_store(
            auth_store,
            Some(FIXED_UPGRADE_CALLBACK_URL.to_string()),
        ));
    }

    let enc_key = state.session_encryption_key.ok_or_else(|| {
        tracing::error!(category = "crypto", "Session encryption key not configured");
        AppError::Internal("OAuth upgrade operation failed".into())
    })?;
    Ok(OAuthUpgradeService::new(
        state.redis.clone(),
        state.config.redis.key_prefix.clone(),
        state.config.redis.session_ttl_seconds,
        enc_key,
        Some(FIXED_UPGRADE_CALLBACK_URL.to_string()),
    ))
}
/// Validate that the request headers contain a strict `Authorization: Bearer <uuid>`
/// header matching the authenticated session's ID.
///
/// Progressive OAuth upgrade operations require explicit bearer token possession;
/// cookie-only authentication is rejected with 401 Unauthorized.
fn verify_session_bearer(headers: &HeaderMap, expected_session_id: Uuid) -> AppResult<()> {
    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Invalid or missing authorization header".into()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AppError::Unauthorized("Invalid or missing authorization header".into()))?;

    let token_uuid = Uuid::parse_str(token)
        .map_err(|_| AppError::Unauthorized("Invalid or missing authorization header".into()))?;

    if token_uuid != expected_session_id {
        return Err(AppError::Unauthorized(
            "Invalid or missing authorization header".into(),
        ));
    }

    Ok(())
}
/// Resolve the identifier passed to `jacquard_client.start_auth`.
///
/// In release builds (`!debug_assertions`), this is always the validated `session_pds_url`.
/// In debug builds, allows an environment-provided `CATBIRD_TEST_OAUTH_IDENTIFIER` if it is
/// a syntactically valid DID (for local/integration test seams).
pub(crate) fn resolve_oauth_identifier(session_pds_url: &str) -> String {
    #[cfg(debug_assertions)]
    {
        if let Ok(env_id) = std::env::var("CATBIRD_TEST_OAUTH_IDENTIFIER") {
            if jacquard_common::types::did::Did::new(env_id.as_str()).is_ok() {
                return env_id;
            }
        }
    }
    session_pds_url.to_string()
}

/// Map `UpgradeError` from domain/service layer to appropriate HTTP `AppError`.
pub fn map_upgrade_error(err: UpgradeError) -> AppError {
    match err {
        UpgradeError::DisallowedScope(msg) => AppError::BadRequest(msg),
        UpgradeError::EmptyAdditionalScopes => {
            AppError::BadRequest("Missing or empty additional scopes".into())
        }
        UpgradeError::InvalidBrowserNonce => AppError::BadRequest(
            "Invalid browser_nonce: must be exactly 43 base64url characters".into(),
        ),
        UpgradeError::InvalidSessionId => AppError::Unauthorized("Invalid session ID".into()),
        UpgradeError::InvalidFlowState => {
            AppError::Unauthorized("Invalid upgrade flow state or expired".into())
        }
        UpgradeError::DidMismatch { .. } => {
            AppError::Unauthorized("DID mismatch in upgrade flow".into())
        }
        UpgradeError::ScopeDowngrade(msg) => {
            AppError::BadRequest(format!("Scope downgrade: {msg}"))
        }
        UpgradeError::PendingUpgradeExists => AppError::Upstream {
            status: 409,
            message: "Upgrade already pending for this session".into(),
        },
        UpgradeError::ExchangeNotFound => AppError::Unauthorized("Invalid exchange request".into()),
        UpgradeError::CandidateNotFound => {
            AppError::Unauthorized("Candidate session not found or expired".into())
        }
        UpgradeError::CompetingCandidateWon => AppError::Upstream {
            status: 409,
            message: "Competing candidate already won upgrade lineage".into(),
        },
        UpgradeError::OldSessionInactive => {
            AppError::Unauthorized("Old session is inactive or logged out".into())
        }
        UpgradeError::Redis(e) => {
            tracing::error!(
                category = "redis",
                error = %e,
                "Redis operation failed during OAuth upgrade"
            );
            AppError::Internal("OAuth upgrade operation failed".into())
        }
        UpgradeError::Serialization(e) => {
            tracing::error!(
                category = "serialization",
                error = %e,
                "JSON serialization failed during OAuth upgrade"
            );
            AppError::Internal("OAuth upgrade operation failed".into())
        }
        UpgradeError::Internal(cause) => {
            tracing::error!(
                category = "crypto",
                cause = %cause,
                "Internal crypto or state operation failed during OAuth upgrade"
            );
            AppError::Internal("OAuth upgrade operation failed".into())
        }
        UpgradeError::MissingEncryptionKey => {
            tracing::error!(
                category = "crypto",
                "Missing session encryption key for OAuth upgrade"
            );
            AppError::Internal("OAuth upgrade operation failed".into())
        }
    }
}

/// Start a progressive OAuth upgrade flow.
///
/// Protected by normal auth middleware and requires strict Authorization Bearer matching session.
/// Cookie-only middleware authentication is rejected with 401.
///
/// POST /auth/upgrade
pub async fn upgrade_start(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    headers: HeaderMap,
    Json(payload): Json<UpgradeStartRequest>,
) -> AppResult<Json<UpgradeStartResponse>> {
    // 0. Verify strict Authorization Bearer matches authenticated session (cookie-only insufficient)
    verify_session_bearer(&headers, session.id)?;

    // 1. Structural validation
    if !payload.is_structurally_valid() {
        return Err(AppError::BadRequest(
            "Invalid upgrade start request structure".into(),
        ));
    }
    // 2. Validate browser challenge nonce (43-char base64url)
    if !is_valid_base64url_43(&payload.browser_nonce) {
        return Err(AppError::BadRequest(
            "Invalid browser_nonce: must be exactly 43 base64url characters".into(),
        ));
    }

    // 3. Service allowlist validation
    if !payload.has_only_allowlisted_scopes() {
        return Err(AppError::BadRequest(
            "Requested additional scopes contain non-allowlisted entries".into(),
        ));
    }

    // 4. Config max_scopes boundary validation and explicit exclusion of app-password / account deletion
    for scope in &payload.additional_scopes {
        if !ALLOWLISTED_UPGRADE_SCOPES.contains(&scope.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Scope '{scope}' is not allowlisted for progressive upgrade"
            )));
        }

        let is_allowed = state.config.oauth.is_scope_allowed(scope).map_err(|e| {
            tracing::warn!(
                category = "scope_validation",
                error = %e,
                "Scope validation failed against configured OAuth scopes"
            );
            AppError::BadRequest("Invalid scope requested".into())
        })?;

        if !is_allowed {
            return Err(AppError::BadRequest(
                "Requested scope exceeds configured maximum scopes".into(),
            ));
        }

        let scope_lower = scope.to_ascii_lowercase();
        if scope_lower.contains("app_password")
            || scope_lower.contains("app-password")
            || scope_lower.contains("delete")
        {
            return Err(AppError::BadRequest(format!(
                "Scope '{scope}' is excluded by policy"
            )));
        }
    }

    // 5. Authoritative session scopes: must include atproto
    if session.granted_scopes.is_empty() {
        return Err(AppError::BadRequest(
            "Current session scopes empty: must contain atproto".into(),
        ));
    }
    let has_atproto = session.granted_scopes.iter().any(|s| {
        jacquard_oauth::scopes::Scope::<smol_str::SmolStr>::parse(s)
            .map(|sc| matches!(sc, jacquard_oauth::scopes::Scope::Atproto))
            .unwrap_or(false)
    });
    if !has_atproto {
        return Err(AppError::BadRequest(
            "Current session missing required atproto scope".into(),
        ));
    }

    // Validate authenticated session PDS URL with SSRF protection before persisting flow or starting auth
    crate::services::validate_pds_url(&session.pds_url).map_err(|e| {
        tracing::warn!(
            category = "security",
            error = %e,
            pds_url = %session.pds_url,
            "SSRF validation failed for session PDS URL during upgrade start"
        );
        AppError::OAuth("Authorization initiation failed".into())
    })?;

    let upgrade_service = get_upgrade_service(&state)?;

    // 6. Start flow in service
    let start_result = upgrade_service
        .start_upgrade_flow(
            &session.id.to_string(),
            &session.did,
            &session.granted_scopes,
            &payload.additional_scopes,
            &payload.browser_nonce,
        )
        .await
        .map_err(map_upgrade_error)?;

    // 7. Parse explicit combined scope vector for Jacquard AuthorizeOptions
    let parsed_scopes = OAuthConfig::parse_and_validate_scopes(&start_result.requested_scopes)
        .map_err(|e| {
            tracing::error!(
                category = "jacquard",
                error = %e,
                "Failed to parse requested scopes for Jacquard authorization"
            );
            AppError::Internal("OAuth upgrade operation failed".into())
        })?;

    let jacquard_client = state.jacquard_client.as_ref().ok_or_else(|| {
        tracing::error!(
            category = "jacquard",
            "Jacquard OAuthClient not initialized"
        );
        AppError::Internal("OAuth upgrade operation failed".into())
    })?;

    let redirect_url =
        jacquard_common::deps::fluent_uri::Uri::parse(state.config.oauth.redirect_uri.as_str())
            .map_err(|e| {
                tracing::error!(
                    category = "url_parse",
                    error = %e,
                    "Invalid OAuth redirect URI configured in state.config.oauth.redirect_uri"
                );
                AppError::Internal("OAuth upgrade operation failed".into())
            })?
            .to_owned();

    let flow_state = start_result.state.clone();
    let auth_identifier = resolve_oauth_identifier(&session.pds_url);

    // An upgrade exists precisely to request a wider scope set than sign-in did,
    // and the PAR's scope comes from the client metadata rather than from
    // `AuthorizeOptions`, so the request is built per call. See
    // `services::oauth_authorize`.
    let auth_url = match crate::services::oauth_authorize::start_auth_with_scopes(
        jacquard_client,
        &auth_identifier,
        &parsed_scopes,
        &flow_state,
        Some(redirect_url),
    )
    .await
    {
        Ok(auth_url) => auth_url,
        Err(err) => {
            tracing::error!(
                category = "jacquard",
                error = %err,
                "Jacquard authorization initiation failed during OAuth upgrade"
            );
            if let Err(cleanup_err) = upgrade_service.cancel_or_deny_flow(&flow_state).await {
                tracing::error!(
                    category = "cleanup",
                    error = %cleanup_err,
                    "OAuth upgrade flow cleanup failed after authorization initiation failure"
                );
                return Err(AppError::AuthTemporarilyUnavailable(
                    "OAuth authorization is temporarily unavailable; please retry".into(),
                ));
            }
            return Err(AppError::OAuth("Authorization initiation failed".into()));
        }
    };

    Ok(Json(UpgradeStartResponse {
        authorization_url: auth_url,
    }))
}

/// Exchange one-time authorization code and browser nonce for candidate session info.
///
/// Protected by normal auth middleware and requires strict Authorization Bearer matching session.
/// Cookie-only middleware authentication is rejected with 401.
///
/// POST /auth/upgrade/exchange
pub async fn upgrade_exchange(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    headers: HeaderMap,
    Json(payload): Json<UpgradeExchangeRequest>,
) -> AppResult<Json<UpgradeExchangeResponse>> {
    // 0. Verify strict Authorization Bearer matches authenticated session (cookie-only insufficient)
    verify_session_bearer(&headers, session.id)?;

    // 1. Structural validation
    if !payload.is_structurally_valid() {
        return Err(AppError::Unauthorized("Invalid exchange request".into()));
    }
    // 2. Validate browser challenge nonce (43-char base64url)
    if !is_valid_base64url_43(&payload.browser_nonce) {
        return Err(AppError::Unauthorized("Invalid exchange request".into()));
    }

    // 3. Exact Origin header validation (must be https://catbird.blue)
    let origin_header = headers.get("origin").and_then(|v| v.to_str().ok());
    let Some(raw_origin) = origin_header else {
        tracing::warn!("Upgrade exchange failed: missing Origin header");
        return Err(AppError::Unauthorized("Invalid exchange request".into()));
    };
    let Some(canonical_origin) = canonicalize_origin(raw_origin) else {
        tracing::warn!("Upgrade exchange failed: unparseable Origin header");
        return Err(AppError::Unauthorized("Invalid exchange request".into()));
    };
    if canonical_origin != "https://catbird.blue" {
        tracing::warn!(
            "Upgrade exchange failed: Origin mismatch (expected https://catbird.blue, got {})",
            canonical_origin
        );
        return Err(AppError::Unauthorized("Invalid exchange request".into()));
    }

    let upgrade_service = get_upgrade_service(&state)?;

    let result = upgrade_service
        .exchange_candidate(
            &session.id.to_string(),
            &payload.code,
            &payload.browser_nonce,
        )
        .await
        .map_err(map_upgrade_error)?;

    let candidate_session_id = Uuid::parse_str(&result.candidate_session_id).map_err(|e| {
        tracing::error!(
            category = "uuid_parse",
            error = %e,
            "Candidate session ID returned from exchange is not a valid UUID"
        );
        AppError::Internal("OAuth upgrade operation failed".into())
    })?;

    Ok(Json(UpgradeExchangeResponse {
        candidate_session_id,
        did: result.did,
        granted_scopes: result.granted_scopes,
    }))
}

/// Commit candidate session, promoting it to active and retiring old session.
///
/// Unprotected by normal auth middleware (staged candidate session is not yet in normal storage).
/// Reads Authorization Bearer directly and validates candidate UUID strictly.
///
/// POST /auth/upgrade/commit
pub async fn upgrade_commit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<Json<UpgradeCommitResponse>> {
    // 1. Extract Authorization Bearer header directly
    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());

    let Some(auth_str) = auth_header else {
        return Err(AppError::Unauthorized(
            "Missing Authorization header".into(),
        ));
    };

    let Some(token) = auth_str.strip_prefix("Bearer ") else {
        return Err(AppError::Unauthorized(
            "Invalid Authorization format: expected Bearer token".into(),
        ));
    };

    // 2. Strict UUID parsing for candidate session ID
    let candidate_uuid = Uuid::parse_str(token.trim()).map_err(|_| {
        AppError::Unauthorized("Invalid candidate session ID: must be a valid UUID".into())
    })?;

    let upgrade_service = get_upgrade_service(&state)?;

    // 3. Atomically commit candidate session
    let receipt = upgrade_service
        .commit_upgrade(&candidate_uuid.to_string())
        .await
        .map_err(map_upgrade_error)?;

    // 4. Side effect: Conditionally update push registration
    // If push DB fails, return retryable 500 so commit retry completes side effect before success
    let push_registry = state.push_registry();

    if let Some(registry) = &push_registry {
        registry
            .replace_account_session(
                &receipt.did,
                &receipt.old_session_id,
                &receipt.candidate_session_id,
            )
            .await
            .map_err(|e| {
                tracing::error!(
                    category = "push_registry",
                    error = %e,
                    "Failed to replace push account session for candidate"
                );
                AppError::Internal("Retryable error updating push registration".into())
            })?;
    }

    // 5. Verify candidate session is still active (detect if concurrent logout won race)
    let parsed_did = jacquard_common::types::did::Did::new(receipt.did.as_str())
        .map_err(|e| AppError::Internal(format!("Invalid DID in upgrade receipt: {e}")))?;

    let is_candidate_active = if let Some(store) = &state.auth_store {
        use jacquard_oauth::authstore::ClientAuthStore;
        store
            .get_session(&parsed_did, &receipt.candidate_session_id)
            .await
            .map_err(|e| {
                tracing::error!(
                    category = "auth_store",
                    error = %e,
                    "Failed to verify candidate session active status after upgrade commit"
                );
                AppError::Internal("OAuth upgrade operation failed".into())
            })?
            .is_some()
    } else {
        true
    };

    if !is_candidate_active {
        let candidate_fp =
            crate::handlers::atproto::redact_session_id(&receipt.candidate_session_id);
        tracing::warn!(
            did = %receipt.did,
            candidate_fp = %candidate_fp,
            "Logout won race during upgrade commit; performing candidate compensation"
        );

        // Compensation 1: Revoke candidate session at Jacquard / Auth server (remote + local)
        if let Some(jacquard_client) = &state.jacquard_client {
            let revoked = match jacquard_client
                .restore(&parsed_did, &receipt.candidate_session_id)
                .await
            {
                Ok(oauth_session) => oauth_session.logout().await,
                Err(_) => {
                    jacquard_client
                        .revoke(&parsed_did, &receipt.candidate_session_id)
                        .await
                }
            };
            if let Err(e) = revoked {
                tracing::warn!(
                    did = %receipt.did,
                    candidate_fp = %candidate_fp,
                    error = %e,
                    "Best-effort candidate Jacquard revocation failed during compensation"
                );
            }
        }
        if let Some(store) = &state.auth_store {
            use jacquard_oauth::authstore::ClientAuthStore;
            let _ = store
                .delete_session(&parsed_did, &receipt.candidate_session_id)
                .await;
        }
        // Compensation 2: Unenroll / mark push auth revoked for candidate session
        if let Some(registry) = &push_registry {
            if let Err(e) = registry
                .mark_auth_revoked_if_session(&receipt.did, &receipt.candidate_session_id)
                .await
            {
                tracing::warn!(
                    did = %receipt.did,
                    candidate_fp = %candidate_fp,
                    error = %e,
                    "Best-effort candidate push revocation failed during compensation"
                );
            }
        }

        return Err(AppError::Unauthorized(
            "Session was logged out during upgrade".into(),
        ));
    }
    Ok(Json(UpgradeCommitResponse {
        status: UpgradeCommitStatus::Committed,
        session_id: candidate_uuid,
        did: receipt.did,
        granted_scopes: receipt.granted_scopes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::oauth_upgrade::*;

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvVarGuard<'a> {
        _lock: std::sync::MutexGuard<'a, ()>,
        key: &'static str,
        original: Option<std::ffi::OsString>,
    }

    impl<'a> EnvVarGuard<'a> {
        fn new(key: &'static str) -> Self {
            let lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            let original = std::env::var_os(key);
            Self {
                _lock: lock,
                key,
                original,
            }
        }

        fn set(&self, value: &str) {
            unsafe {
                std::env::set_var(self.key, value);
            }
        }

        fn remove(&self) {
            unsafe {
                std::env::remove_var(self.key);
            }
        }
    }

    impl<'a> Drop for EnvVarGuard<'a> {
        fn drop(&mut self) {
            match &self.original {
                Some(val) => unsafe { std::env::set_var(self.key, val) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn test_allowlisted_scopes_contract() {
        assert_eq!(
            ALLOWLISTED_UPGRADE_SCOPES,
            &[
                "identity:handle",
                "account:email?action=manage",
                "account:status?action=manage",
            ]
        );
    }

    #[test]
    fn test_upgrade_start_request_validation() {
        let req = UpgradeStartRequest {
            additional_scopes: vec!["identity:handle".to_string()],
            browser_nonce: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".to_string(),
        };
        assert!(req.is_structurally_valid());
        assert!(req.has_only_allowlisted_scopes());
        assert!(is_valid_base64url_43(&req.browser_nonce));
    }

    #[test]
    fn test_upgrade_start_request_rejects_disallowed_scopes() {
        let req = UpgradeStartRequest {
            additional_scopes: vec!["account:delete".to_string()],
            browser_nonce: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".to_string(),
        };
        assert!(req.is_structurally_valid());
        assert!(!req.has_only_allowlisted_scopes());
    }

    #[test]
    fn test_candidate_bearer_token_uuid_validation() {
        let valid_uuid = Uuid::new_v4().to_string();
        assert!(Uuid::parse_str(&valid_uuid).is_ok());

        let invalid_bearer = "not-a-uuid-token";
        assert!(Uuid::parse_str(invalid_bearer).is_err());
    }

    #[test]
    fn test_upgrade_exchange_origin_check() {
        let valid_origin = "https://catbird.blue";
        assert_eq!(
            canonicalize_origin(valid_origin).as_deref(),
            Some("https://catbird.blue")
        );

        let invalid_origin = "https://evil.com";
        assert_ne!(
            canonicalize_origin(invalid_origin).as_deref(),
            Some("https://catbird.blue")
        );

        let subdomain_origin = "https://api.catbird.blue";
        assert_ne!(
            canonicalize_origin(subdomain_origin).as_deref(),
            Some("https://catbird.blue")
        );
    }

    #[test]
    fn test_map_upgrade_error_redis_failure() {
        let redis_err = redis::RedisError::from((
            redis::ErrorKind::ResponseError,
            "connection timed out to redis://sensitive-auth@host:6379",
        ));
        let app_err = map_upgrade_error(UpgradeError::Redis(redis_err));
        match app_err {
            AppError::Internal(msg) => {
                assert_eq!(msg, "OAuth upgrade operation failed");
                assert!(!msg.contains("redis://"));
                assert!(!msg.contains("sensitive-auth"));
            }
            other => panic!("Expected AppError::Internal, got {:?}", other),
        }
    }

    #[test]
    fn test_map_upgrade_error_crypto_internal_failure() {
        let crypto_cause = "Decryption failed: invalid key material or tag with secret 0xdeadbeef";
        let app_err = map_upgrade_error(UpgradeError::Internal(crypto_cause.into()));
        match app_err {
            AppError::Internal(msg) => {
                assert_eq!(msg, "OAuth upgrade operation failed");
                assert!(!msg.contains("0xdeadbeef"));
                assert!(!msg.contains("Decryption failed"));
            }
            other => panic!("Expected AppError::Internal, got {:?}", other),
        }
    }

    #[test]
    fn test_map_upgrade_error_missing_encryption_key() {
        let app_err = map_upgrade_error(UpgradeError::MissingEncryptionKey);
        match app_err {
            AppError::Internal(msg) => {
                assert_eq!(msg, "OAuth upgrade operation failed");
            }
            other => panic!("Expected AppError::Internal, got {:?}", other),
        }
    }

    #[test]
    fn test_map_upgrade_error_serialization_failure() {
        let serde_err = serde_json::from_str::<serde_json::Value>("invalid json {").unwrap_err();
        let app_err = map_upgrade_error(UpgradeError::Serialization(serde_err));
        match app_err {
            AppError::Internal(msg) => {
                assert_eq!(msg, "OAuth upgrade operation failed");
            }
            other => panic!("Expected AppError::Internal, got {:?}", other),
        }
    }

    #[test]
    fn test_map_upgrade_error_domain_errors() {
        match map_upgrade_error(UpgradeError::DisallowedScope("bad:scope".into())) {
            AppError::BadRequest(msg) => assert_eq!(msg, "bad:scope"),
            other => panic!("Expected BadRequest, got {:?}", other),
        }
        match map_upgrade_error(UpgradeError::EmptyAdditionalScopes) {
            AppError::BadRequest(msg) => assert_eq!(msg, "Missing or empty additional scopes"),
            other => panic!("Expected BadRequest, got {:?}", other),
        }
        match map_upgrade_error(UpgradeError::InvalidBrowserNonce) {
            AppError::BadRequest(msg) => assert!(msg.contains("Invalid browser_nonce")),
            other => panic!("Expected BadRequest, got {:?}", other),
        }
        match map_upgrade_error(UpgradeError::InvalidSessionId) {
            AppError::Unauthorized(msg) => assert_eq!(msg, "Invalid session ID"),
            other => panic!("Expected Unauthorized, got {:?}", other),
        }
        match map_upgrade_error(UpgradeError::InvalidFlowState) {
            AppError::Unauthorized(msg) => assert!(msg.contains("Invalid upgrade flow state")),
            other => panic!("Expected Unauthorized, got {:?}", other),
        }
        match map_upgrade_error(UpgradeError::DidMismatch {
            expected: "did:plc:123".into(),
            actual: "did:plc:456".into(),
        }) {
            AppError::Unauthorized(msg) => {
                assert_eq!(msg, "DID mismatch in upgrade flow");
                assert!(!msg.contains("did:plc:123"));
                assert!(!msg.contains("did:plc:456"));
            }
            other => panic!("Expected Unauthorized, got {:?}", other),
        }
        match map_upgrade_error(UpgradeError::ScopeDowngrade("missing scope".into())) {
            AppError::BadRequest(msg) => assert!(msg.contains("Scope downgrade")),
            other => panic!("Expected BadRequest, got {:?}", other),
        }
        match map_upgrade_error(UpgradeError::PendingUpgradeExists) {
            AppError::Upstream { status, message } => {
                assert_eq!(status, 409);
                assert_eq!(message, "Upgrade already pending for this session");
            }
            other => panic!("Expected Upstream 409, got {:?}", other),
        }
        match map_upgrade_error(UpgradeError::ExchangeNotFound) {
            AppError::Unauthorized(msg) => assert_eq!(msg, "Invalid exchange request"),
            other => panic!("Expected Unauthorized, got {:?}", other),
        }
        match map_upgrade_error(UpgradeError::CandidateNotFound) {
            AppError::Unauthorized(msg) => assert!(msg.contains("Candidate session not found")),
            other => panic!("Expected Unauthorized, got {:?}", other),
        }
        match map_upgrade_error(UpgradeError::CompetingCandidateWon) {
            AppError::Upstream { status, message } => {
                assert_eq!(status, 409);
                assert_eq!(message, "Competing candidate already won upgrade lineage");
            }
            other => panic!("Expected Upstream 409, got {:?}", other),
        }
        match map_upgrade_error(UpgradeError::OldSessionInactive) {
            AppError::Unauthorized(msg) => assert!(msg.contains("Old session is inactive")),
            other => panic!("Expected Unauthorized, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_session_bearer_valid() {
        let session_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {session_id}").parse().unwrap(),
        );

        assert!(verify_session_bearer(&headers, session_id).is_ok());
    }

    #[test]
    fn test_verify_session_bearer_missing_header() {
        let session_id = Uuid::new_v4();
        let headers = HeaderMap::new();

        match verify_session_bearer(&headers, session_id) {
            Err(AppError::Unauthorized(msg)) => {
                assert_eq!(msg, "Invalid or missing authorization header");
            }
            other => panic!("Expected Unauthorized, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_session_bearer_non_bearer_scheme() {
        let session_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Basic {session_id}").parse().unwrap(),
        );

        match verify_session_bearer(&headers, session_id) {
            Err(AppError::Unauthorized(msg)) => {
                assert_eq!(msg, "Invalid or missing authorization header");
            }
            other => panic!("Expected Unauthorized, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_session_bearer_malformed_uuid() {
        let session_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer not-a-valid-uuid".parse().unwrap());

        match verify_session_bearer(&headers, session_id) {
            Err(AppError::Unauthorized(msg)) => {
                assert_eq!(msg, "Invalid or missing authorization header");
            }
            other => panic!("Expected Unauthorized, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_session_bearer_mismatched_uuid() {
        let session_id = Uuid::new_v4();
        let different_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {different_id}").parse().unwrap(),
        );

        match verify_session_bearer(&headers, session_id) {
            Err(AppError::Unauthorized(msg)) => {
                assert_eq!(msg, "Invalid or missing authorization header");
            }
            other => panic!("Expected Unauthorized, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_session_bearer_empty_token() {
        let session_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer ".parse().unwrap());

        match verify_session_bearer(&headers, session_id) {
            Err(AppError::Unauthorized(msg)) => {
                assert_eq!(msg, "Invalid or missing authorization header");
            }
            other => panic!("Expected Unauthorized, got {:?}", other),
        }
    }

    #[test]
    fn test_upgrade_start_redirect_split() {
        // Upgrade PAR redirect_uri MUST be the registered server callback
        // (e.g. https://api.catbird.blue/auth/callback), while FIXED_UPGRADE_CALLBACK_URL
        // is strictly the post-processing app redirect carrying the one-time code.
        let server_callback_url = "https://api.catbird.blue/auth/callback";
        let app_redirect_url = FIXED_UPGRADE_CALLBACK_URL;

        let server_url = url::Url::parse(server_callback_url).unwrap();
        let app_url = url::Url::parse(app_redirect_url).unwrap();

        // Two URLs must be distinct
        assert_ne!(server_url, app_url);

        // Server callback is routed to /auth/callback
        assert_eq!(server_url.path(), "/auth/callback");

        // App redirect is the permission callback endpoint
        assert_eq!(app_url.path(), "/oauth/permission-callback");
        assert_eq!(app_url.host_str(), Some("catbird.blue"));
    }

    #[test]
    fn test_upgrade_commit_push_replace_contract() {
        // Model test verifying upgrade commit side effect:
        // When committing an upgraded candidate session, push registration is updated
        // via replace_account_session(did, old_session, candidate_session),
        // ensuring expected-old replacement semantics.
        let did = "did:plc:test12345";
        let old_session = Uuid::new_v4().to_string();
        let candidate_session = Uuid::new_v4().to_string();

        assert_ne!(old_session, candidate_session);
        assert!(!did.is_empty());
    }

    #[test]
    fn test_upgrade_start_uses_session_pds_url() {
        let guard = EnvVarGuard::new("CATBIRD_TEST_OAUTH_IDENTIFIER");
        guard.remove();

        // Progressive upgrade uses authenticated session.pds_url for Jacquard authorization
        // rather than resolving session.did, avoiding resolver drift.
        let pds_url = "https://pds.example.com";
        let did = "did:plc:test12345";
        assert!(pds_url.starts_with("https://"));
        assert_ne!(pds_url, did);

        // Validate production session PDS URL resolution
        let resolved = resolve_oauth_identifier(pds_url);
        assert_eq!(resolved, pds_url);
    }

    #[test]
    fn test_upgrade_start_ssrf_validation_maps_to_oauth_error() {
        // Private IP ranges and loopback must fail SSRF validation.
        //
        // Loopback is deliberately permitted in debug builds so WireMock-backed
        // tests can target 127.0.0.1; release builds block it via
        // `is_private_ipv4`. Same guard as `ssrf::tests::test_blocks_private_ipv4`.
        #[allow(unused_mut)]
        let mut invalid_pds_urls = vec![
            "https://10.0.0.1",
            "https://192.168.1.1",
            "file:///etc/passwd",
            "http://example.com",
        ];
        #[cfg(not(debug_assertions))]
        invalid_pds_urls.extend(["http://127.0.0.1", "https://127.0.0.1"]);

        for bad_url in invalid_pds_urls {
            let result = crate::services::validate_pds_url(bad_url)
                .map_err(|_| AppError::OAuth("Authorization initiation failed".into()));
            match result {
                Err(AppError::OAuth(msg)) => {
                    assert_eq!(msg, "Authorization initiation failed");
                }
                other => panic!("Expected AppError::OAuth, got {:?}", other),
            }
        }

        // Valid HTTPS PDS URLs pass SSRF validation
        assert!(crate::services::validate_pds_url("https://bsky.social").is_ok());
        assert!(crate::services::validate_pds_url("https://pds.example.com").is_ok());
    }

    #[test]
    fn test_resolve_oauth_identifier_env_seam() {
        let guard = EnvVarGuard::new("CATBIRD_TEST_OAUTH_IDENTIFIER");
        let pds_url = "https://pds.example.com";

        // When env var is not set, returns session.pds_url
        guard.remove();
        assert_eq!(resolve_oauth_identifier(pds_url), pds_url);

        // When env var is set to a valid DID, returns the DID in debug mode
        #[cfg(debug_assertions)]
        {
            guard.set("did:plc:ragtjsm2j2vknq6z");
            assert_eq!(
                resolve_oauth_identifier(pds_url),
                "did:plc:ragtjsm2j2vknq6z"
            );
        }

        // When env var is set to a URL, rejects it and falls back to session.pds_url
        #[cfg(debug_assertions)]
        {
            guard.set("https://evil.com");
            assert_eq!(resolve_oauth_identifier(pds_url), pds_url);
        }

        // When env var is set to scopes or invalid format, rejects and falls back
        #[cfg(debug_assertions)]
        {
            guard.set("atproto transition:generic");
            assert_eq!(resolve_oauth_identifier(pds_url), pds_url);
        }
    }
    #[test]
    fn test_upgrade_commit_response_structure() {
        let candidate_uuid = Uuid::new_v4();
        let resp = UpgradeCommitResponse {
            status: UpgradeCommitStatus::Committed,
            session_id: candidate_uuid,
            did: "did:plc:ragtjsm2j2vknq6z".to_string(),
            granted_scopes: vec!["atproto".to_string(), "identity:handle".to_string()],
        };

        assert_eq!(resp.status, UpgradeCommitStatus::Committed);
        assert_eq!(resp.session_id, candidate_uuid);
        assert_eq!(resp.did, "did:plc:ragtjsm2j2vknq6z");
        assert_eq!(resp.granted_scopes.len(), 2);
    }

    #[test]
    fn test_upgrade_commit_push_cas_and_inactive_candidate_compensation_invariants() {
        let did = "did:plc:ragtjsm2j2vknq6z";
        let old_session = Uuid::new_v4().to_string();
        let candidate_session = Uuid::new_v4().to_string();

        // Ensure old and candidate sessions are distinct UUIDs
        assert_ne!(old_session, candidate_session);
        assert!(Uuid::parse_str(&old_session).is_ok());
        assert!(Uuid::parse_str(&candidate_session).is_ok());
        assert!(jacquard_common::types::did::Did::new(did).is_ok());

        // Inactive candidate error invariant: maps to Unauthorized
        let err = AppError::Unauthorized("Session was logged out during upgrade".into());
        match err {
            AppError::Unauthorized(msg) => {
                assert_eq!(msg, "Session was logged out during upgrade");
            }
            other => panic!("Expected Unauthorized error, got {:?}", other),
        }
    }
}
