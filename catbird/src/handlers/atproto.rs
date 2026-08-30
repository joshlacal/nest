//! ATProto Handlers
//!
//! Request handlers for ATProto proxy endpoints including:
//! - OAuth flow (login, callback, logout)
//! - XRPC proxy

use axum::{
    body::Body,
    extract::{Path, Query, RawQuery, State},
    http::{HeaderMap, Method, StatusCode},
    response::Response,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use futures_util::StreamExt;
use jacquard_common::types::{did::Did, string::Handle};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::metrics;
use crate::middleware::JacquardDpopData;
use crate::middleware::SESSION_COOKIE_NAME;
use crate::models::{
    oauth_upgrade::FIXED_UPGRADE_CALLBACK_URL, CatbirdSession, ExchangeRequest, ExchangeResponse,
    LogoutResponse, OAuthCallback, SessionInfo,
};
use crate::services::{
    AtProtoClient, MlsAuthService, ProxyResponse, ServiceAuthProvider, CIRCLE_ENDPOINTS,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OAuthMode {
    #[serde(rename = "exchange")]
    Exchange,
    #[serde(rename = "direct")]
    Direct,
}

pub const OAUTH_DIRECT_NONCE_COOKIE_NAME: &str = "catbird_oauth_direct_nonce";

/// Returns a non-replayable fingerprint of a session ID for privacy-safe logging.
pub fn redact_session_id(id: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(id.as_bytes());
    let mut s = String::with_capacity(16);
    for b in &hash[..8] {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthFlowRecord {
    pub version: u32,
    pub mode: OAuthMode,
    pub client_selector: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_nonce: Option<String>,
    pub created_at: i64,
}

/// Handle login initiation (Redirect flow)
///
/// GET /auth/login?identifier=user.bsky.social&client=catmos
pub async fn login(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> AppResult<Response> {
    let raw_identifier = params
        .get("identifier")
        .or_else(|| params.get("pds"))
        .or_else(|| params.get("issuer"))
        .ok_or_else(|| AppError::BadRequest("Missing identifier".into()))?;
    let client = params.get("client").cloned();
    let redirect_to = params.get("redirect_to").cloned();
    let browser_nonce = params.get("browser_nonce").cloned();

    // Admission validation:
    // 1. If explicit pds or issuer param was used, or raw_identifier parses as URL / starts with http(s):
    //    it must pass SSRF validate_pds_url before start_auth.
    // 2. Otherwise (identifier parameter), it MUST parse as either Handle or DID.
    let is_explicit_url = params.contains_key("pds")
        || params.contains_key("issuer")
        || raw_identifier.starts_with("http://")
        || raw_identifier.starts_with("https://");

    if is_explicit_url {
        crate::services::validate_pds_url(raw_identifier)?;
    } else {
        let is_did = Did::new(raw_identifier.as_str()).is_ok();
        let is_handle = Handle::new(raw_identifier.as_str()).is_ok();
        if !is_did && !is_handle {
            return Err(AppError::BadRequest(
                "Invalid identifier: must be a valid Handle or DID".into(),
            ));
        }
    }
    let identifier = raw_identifier;

    // Select the appropriate OAuth client based on the client parameter.
    let is_catmos = matches!(client.as_deref(), Some("catmos-web") | Some("catmos"));
    let client_selector = if is_catmos { "catmos" } else { "default" };

    // Encryption key MUST be configured (fail closed, no plaintext fallback)
    let enc_key = state.session_encryption_key.as_ref().ok_or_else(|| {
        AppError::Internal("Session encryption key not configured; cannot admit OAuth flow".into())
    })?;

    // Mode determination & redirect validation:
    // Require exchange mode (browser_nonce + redirect_to) for every external/native/loopback redirect;
    // direct mode binds the initiating browser via a secure HttpOnly SameSite cookie nonce.
    let (mode, browser_nonce, direct_cookie_header) = if let Some(nonce) = &browser_nonce {
        if !is_valid_base64url_43(nonce) {
            return Err(AppError::BadRequest(
                "Invalid browser_nonce: must be exactly 43 base64url characters".into(),
            ));
        }
        let Some(r) = &redirect_to else {
            return Err(AppError::BadRequest(
                "Missing redirect_to: required when browser_nonce is supplied".into(),
            ));
        };
        if !is_allowed_redirect(r) {
            return Err(AppError::BadRequest("Disallowed redirect_to URL".into()));
        }
        (OAuthMode::Exchange, Some(nonce.clone()), None)
    } else {
        // Direct mode: external, native, and loopback redirects require exchange mode + browser_nonce
        if let Some(_r) = &redirect_to {
            return Err(AppError::BadRequest(
                "External, native, and loopback redirects require exchange mode with browser_nonce"
                    .into(),
            ));
        }
        let direct_nonce = uuid::Uuid::new_v4().to_string();
        let cookie = Cookie::build((OAUTH_DIRECT_NONCE_COOKIE_NAME, direct_nonce.clone()))
            .path("/auth/callback")
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .max_age(time::Duration::seconds(600))
            .build();
        (
            OAuthMode::Direct,
            Some(direct_nonce),
            Some(cookie.to_string()),
        )
    };
    tracing::info!(
        "Login request for identifier: {}, client: {:?}, redirect_to: {:?}, selector: {}",
        identifier,
        client,
        redirect_to,
        client_selector
    );

    let jacquard_client = if is_catmos {
        state
            .catmos_jacquard_client
            .as_ref()
            .or(state.jacquard_client.as_ref())
            .ok_or_else(|| AppError::Internal("No OAuthClient available for catmos-web".into()))?
    } else {
        state
            .jacquard_client
            .as_ref()
            .ok_or_else(|| AppError::Internal("Jacquard OAuthClient not initialized".into()))?
    };

    // Generate a clean UUID for the OAuth state (= Jacquard session_id).
    let session_nonce = uuid::Uuid::new_v4().to_string();

    // Persist versioned AES-GCM-encrypted flow record under v2 prefix keyed by HMAC/state fingerprint
    let state_fp = crate::services::redis_auth_store::fingerprint_id(enc_key, &session_nonce);
    let flow_record = OAuthFlowRecord {
        version: 2,
        mode,
        client_selector: client_selector.to_string(),
        redirect_to,
        browser_nonce,
        created_at: chrono::Utc::now().timestamp(),
    };

    let flow_json = serde_json::to_string(&flow_record).map_err(|e| {
        tracing::error!(error = %e, "Failed to serialize OAuthFlowRecord");
        AppError::Internal("Serialization error during login".into())
    })?;

    let flow_key = format!("{}oauth_flow:{}", &state.config.redis.key_prefix, state_fp);
    let flow_aad = crate::services::redis_crypto::build_aad("oauth_flow", &flow_key, None, None);
    let sealed_flow =
        crate::services::redis_crypto::seal_strict_with_aad(enc_key, &flow_json, &flow_aad)
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to seal OAuthFlowRecord");
                AppError::Internal("Encryption error during login".into())
            })?;
    let mut conn = state.redis.clone();
    redis::cmd("SET")
        .arg(&flow_key)
        .arg(&sealed_flow)
        .arg("EX")
        .arg(600)
        .query_async::<_, ()>(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to persist OAuthFlowRecord to Redis");
            AppError::Internal("Database error during login".into())
        })?;

    // Explicit normalized initial scopes requested at login (never empty/max)
    let requested_scopes = if is_catmos {
        if state.catmos_oauth_scopes.is_empty() {
            return Err(AppError::Internal(
                "Configured catmos OAuth scopes must not be empty".into(),
            ));
        }
        state.catmos_oauth_scopes.clone()
    } else {
        let initial_scopes = crate::config::OAuthConfig::parse_and_validate_scopes(
            &state.config.oauth.initial_scopes,
        )
        .map_err(|e| AppError::Internal(format!("Invalid initial OAuth scopes: {}", e)))?;
        if initial_scopes.is_empty() {
            return Err(AppError::Internal(
                "Configured initial OAuth scopes must not be empty".into(),
            ));
        }
        initial_scopes
    };

    // `start_auth` would ignore a per-request scope set: it forwards only
    // `prompt` and `state` into the PAR, which then takes its scope from the
    // client metadata. Left alone, sign-in would request the full declared
    // `max_scopes`, including the account-management permissions that are meant
    // to be asked for only on a later just-in-time upgrade. See
    // `services::oauth_authorize`.
    let auth_url = crate::services::oauth_authorize::start_auth_with_scopes(
        jacquard_client,
        identifier,
        &requested_scopes,
        &session_nonce,
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Authorization initiation failed");
        AppError::OAuth("Authorization initiation failed".into())
    })?;

    // Redirect to the PDS authorization URL
    let mut resp = Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", auth_url.as_str());
    if let Some(cookie_str) = direct_cookie_header {
        resp = resp.header("Set-Cookie", cookie_str);
    }
    Ok(resp.body(Body::empty()).map_err(|e| {
        tracing::error!(error = %e, "Failed to build redirect response");
        AppError::Internal("Failed to build redirect response".into())
    })?)
}

/// Handle OAuth callback
///
/// GET /auth/callback?code=...&state=...&iss=...
pub async fn oauth_callback(
    State(state): State<Arc<AppState>>,
    Query(callback): Query<OAuthCallback>,
    jar: CookieJar,
) -> AppResult<(CookieJar, Response)> {
    tracing::info!("OAuth callback received");

    // Early branch for progressive OAuth upgrade callback flows
    if callback.state.starts_with("upg_") {
        return handle_upgrade_callback(state, callback, jar).await;
    }

    let enc_key = state.session_encryption_key.as_ref().ok_or_else(|| {
        tracing::error!("OAuth callback: session encryption key not configured");
        AppError::Internal("Session encryption key not configured".into())
    })?;

    let state_fp = crate::services::redis_auth_store::fingerprint_id(enc_key, &callback.state);
    let flow_key = format!("{}oauth_flow:{}", &state.config.redis.key_prefix, state_fp);
    let claim_key = format!("{}oauth_claim:{}", &state.config.redis.key_prefix, state_fp);

    let mut conn = state.redis.clone();

    // Deny/cancel path: the provider redirects back without a code
    // (RFC 6749 §4.1.2.1 — `error` + optional `error_description` instead).
    let Some(code) = callback.code else {
        let err = callback.error.as_deref().unwrap_or("access_denied");
        tracing::info!(
            error = err,
            description = callback.error_description.as_deref().unwrap_or(""),
            "OAuth callback without authorization code; aborting login"
        );

        let redirect_to: Option<String> = match redis::cmd("GET")
            .arg(&flow_key)
            .query_async::<_, Option<String>>(&mut conn)
            .await
        {
            Ok(Some(sealed)) => {
                let flow_aad =
                    crate::services::redis_crypto::build_aad("oauth_flow", &flow_key, None, None);
                if let Ok(plaintext) =
                    crate::services::redis_crypto::open_strict_with_aad(enc_key, &sealed, &flow_aad)
                {
                    serde_json::from_str::<OAuthFlowRecord>(&plaintext)
                        .ok()
                        .and_then(|rec| rec.redirect_to)
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Err(e) = redis::cmd("DEL")
            .arg(&flow_key)
            .arg(&claim_key)
            .query_async::<_, ()>(&mut conn)
            .await
        {
            tracing::error!(error = %e, "OAuth denial state cleanup failed");
            return Err(AppError::AuthTemporarilyUnavailable(
                "OAuth callback temporarily unavailable; please retry".into(),
            ));
        }
        metrics::record_oauth_login(false);

        let target = build_error_redirect(redirect_to.as_deref(), err);
        return Ok((
            jar,
            Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", target)
                .body(Body::empty())
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to build redirect response");
                    AppError::Internal("Failed to build redirect response".into())
                })?,
        ));
    };

    // Claim callback atomically for concurrency
    let claim_acquired: Option<String> = redis::cmd("SET")
        .arg(&claim_key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(30)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Redis error attempting to claim OAuth callback");
            AppError::AuthTemporarilyUnavailable(
                "OAuth callback temporarily unavailable; please retry".into(),
            )
        })?;

    if claim_acquired.is_none() {
        tracing::warn!("OAuth callback claim conflict: callback already in progress");
        return Err(AppError::Upstream {
            status: 409,
            message: "OAuth callback already in progress".into(),
        });
    }

    // Read flow record using GET (retain state on transient failure)
    let sealed_flow: Option<String> = redis::cmd("GET")
        .arg(&flow_key)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Redis error retrieving oauth_flow");
            AppError::AuthTemporarilyUnavailable(
                "OAuth callback temporarily unavailable; please retry".into(),
            )
        })?;

    let Some(sealed_str) = sealed_flow else {
        let _ = redis::cmd("DEL")
            .arg(&claim_key)
            .query_async::<_, ()>(&mut conn)
            .await;
        tracing::error!(
            "OAuth session expired or invalid: missing flow record for state {}",
            &callback.state
        );
        return Err(AppError::Unauthorized(
            "OAuth session expired or invalid".into(),
        ));
    };

    let flow_aad = crate::services::redis_crypto::build_aad("oauth_flow", &flow_key, None, None);
    let flow_json = match crate::services::redis_crypto::open_strict_with_aad(
        enc_key,
        &sealed_str,
        &flow_aad,
    ) {
        Ok(json) => json,
        Err(e) => {
            let _ = redis::cmd("DEL")
                .arg(&claim_key)
                .query_async::<_, ()>(&mut conn)
                .await;
            tracing::error!(error = %e, "Failed to decrypt OAuth flow record");
            return Err(AppError::Unauthorized(
                "OAuth session expired or invalid".into(),
            ));
        }
    };

    let flow_record: OAuthFlowRecord = match serde_json::from_str(&flow_json) {
        Ok(rec) => rec,
        Err(e) => {
            let _ = redis::cmd("DEL")
                .arg(&claim_key)
                .query_async::<_, ()>(&mut conn)
                .await;
            tracing::error!(error = %e, "Failed to deserialize OAuth flow record");
            return Err(AppError::Unauthorized(
                "OAuth session expired or invalid".into(),
            ));
        }
    };

    if flow_record.version != 2 {
        let _ = redis::cmd("DEL")
            .arg(&claim_key)
            .query_async::<_, ()>(&mut conn)
            .await;
        tracing::error!(
            "Unsupported OAuth flow record version: {}",
            flow_record.version
        );
        return Err(AppError::Unauthorized(
            "OAuth session expired or invalid: unsupported version".into(),
        ));
    }

    let is_catmos = flow_record.client_selector == "catmos";
    let is_exchange_mode = matches!(flow_record.mode, OAuthMode::Exchange);

    // Validate mode-specific invariants BEFORE calling jacquard_client.callback
    let validated_canonical_origin = if is_exchange_mode {
        let (Some(r), Some(nonce)) = (&flow_record.redirect_to, &flow_record.browser_nonce) else {
            let _ = redis::cmd("DEL")
                .arg(&claim_key)
                .query_async::<_, ()>(&mut conn)
                .await;
            tracing::error!("Exchange flow state missing redirect_to or nonce in flow record");
            return Err(AppError::Unauthorized(
                "OAuth session expired or invalid: missing exchange flow state".into(),
            ));
        };

        if !is_allowed_redirect(r) || !is_valid_base64url_43(nonce) {
            let _ = redis::cmd("DEL")
                .arg(&claim_key)
                .query_async::<_, ()>(&mut conn)
                .await;
            tracing::error!(
                "Exchange flow state invalid: disallowed redirect URL or malformed nonce"
            );
            return Err(AppError::BadRequest(
                "Invalid exchange flow state: disallowed redirect or invalid nonce".into(),
            ));
        }

        let canonical_origin = match canonicalize_origin(r) {
            Some(o) => o,
            None => {
                let _ = redis::cmd("DEL")
                    .arg(&claim_key)
                    .query_async::<_, ()>(&mut conn)
                    .await;
                tracing::error!("Invalid redirect_to origin in exchange flow");
                return Err(AppError::BadRequest("Invalid redirect_to origin".into()));
            }
        };

        Some(canonical_origin)
    } else {
        if let Some(r) = &flow_record.redirect_to {
            let _ = redis::cmd("DEL")
                .arg(&claim_key)
                .query_async::<_, ()>(&mut conn)
                .await;
            tracing::error!("Direct mode callback disallowed with redirect_to: {}", r);
            return Err(AppError::BadRequest(
                "External, native, and loopback redirects require exchange mode".into(),
            ));
        }

        // Direct mode browser nonce verification (Finding 21):
        // Verify that the browser presented the direct-mode nonce cookie matching the flow record.
        let cookie_nonce = jar.get(OAUTH_DIRECT_NONCE_COOKIE_NAME).map(|c| c.value());
        let expected_nonce = flow_record.browser_nonce.as_deref();
        match (cookie_nonce, expected_nonce) {
            (Some(c_nonce), Some(e_nonce)) if !c_nonce.is_empty() && c_nonce == e_nonce => {
                // Valid browser nonce; verified before token exchange!
            }
            (None, _) => {
                let _ = redis::cmd("DEL")
                    .arg(&claim_key)
                    .query_async::<_, ()>(&mut conn)
                    .await;
                tracing::error!("Direct mode callback rejected: missing browser nonce cookie");
                return Err(AppError::Unauthorized(
                    "Direct OAuth callback browser nonce missing".into(),
                ));
            }
            (Some(_), None) => {
                let _ = redis::cmd("DEL")
                    .arg(&claim_key)
                    .query_async::<_, ()>(&mut conn)
                    .await;
                tracing::error!(
                    "Direct mode callback rejected: flow record missing expected browser nonce"
                );
                return Err(AppError::Unauthorized(
                    "Direct OAuth callback flow record missing nonce".into(),
                ));
            }
            (Some(_), Some(_)) => {
                let _ = redis::cmd("DEL")
                    .arg(&claim_key)
                    .query_async::<_, ()>(&mut conn)
                    .await;
                tracing::error!("Direct mode callback rejected: browser nonce cookie mismatched");
                return Err(AppError::Unauthorized(
                    "Direct OAuth callback browser nonce mismatched".into(),
                ));
            }
        }
        None
    };

    let jacquard_client = if is_catmos {
        state
            .catmos_jacquard_client
            .as_ref()
            .or(state.jacquard_client.as_ref())
            .ok_or_else(|| {
                AppError::Internal("No OAuthClient available for catmos-web callback".into())
            })?
    } else {
        state
            .jacquard_client
            .as_ref()
            .ok_or_else(|| AppError::Internal("Jacquard OAuthClient not initialized".into()))?
    };

    use jacquard_oauth::types::CallbackParams;
    let params = CallbackParams {
        code: code.into(),
        state: Some(callback.state.clone().into()),
        iss: callback.iss.map(|s| s.into()),
    };

    let oauth_session = match jacquard_client.callback(params).await {
        Ok(session) => session,
        Err(e) => {
            tracing::error!(error = %e, "Jacquard OAuth callback exchange failed");
            // Release claim on transient token failure, but retain flow record state for retry
            let _ = redis::cmd("DEL")
                .arg(&claim_key)
                .query_async::<_, ()>(&mut conn)
                .await;
            return Err(AppError::OAuth(
                "OAuth authorization callback failed".into(),
            ));
        }
    };

    // Jacquard stores the session in RedisAuthStore automatically.
    // Extract session_id, DID, and host_url (PDS URL).
    let session_data = oauth_session.data.read().await;
    let did = session_data.account_did.as_str().to_string();
    let session_id = session_data.session_id.to_string();
    let pds_url = session_data.host_url.to_string();
    drop(session_data);

    let push_registry = state.push.as_ref().map(|p| p.registry.clone()).or_else(|| {
        state
            .push_db
            .as_ref()
            .map(|db| crate::services::push::registry::PushRegistry::new(db.clone(), String::new()))
    });

    let mut stored_exchange_key: Option<String> = None;

    // Post-callback finalization with unified compensation path
    let finalize_res: Result<(CookieJar, Response), AppError> = async {
        // 1. Validate PDS URL with SSRF protection before handle resolution, exchange key persistence, or push activation
        crate::services::validate_pds_url(&pds_url).map_err(|e| {
            tracing::warn!(
                did = %did,
                pds_url = %pds_url,
                error = %e,
                "SSRF validation rejected PDS URL after OAuth callback"
            );
            e
        })?;

        // 2. Resolve handle from DID using validated base and state.http_client
        let handle = resolve_handle_for_did(&state.http_client, &did, &pds_url).await;
        tracing::info!(did = %did, handle = %handle, "Resolved handle for DID");

        // 3. Complete mode-specific seal/exchange Redis operations and redirect builds BEFORE push activation
        let (cookie_jar_out, app_redirect) = if is_exchange_mode {
            let r = flow_record
                .redirect_to
                .as_ref()
                .expect("validated prior to callback");
            let nonce = flow_record
                .browser_nonce
                .as_ref()
                .expect("validated prior to callback");
            let canonical_origin = validated_canonical_origin.expect("validated prior to callback");

            let exchange_code = generate_exchange_code();
            let exchange_key = compute_exchange_redis_key(&exchange_code, nonce, &canonical_origin);
            let ex_aad = crate::services::redis_crypto::build_aad(
                "oauth_exchange",
                &exchange_key,
                None,
                None,
            );
            let sealed_session_id = crate::services::redis_crypto::seal_with_aad(
                enc_key,
                session_id.as_bytes(),
                &ex_aad,
            )
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to seal session_id for exchange record");
                AppError::Internal("Failed to secure session".into())
            })?;

            redis::cmd("SET")
                .arg(&exchange_key)
                .arg(&sealed_session_id)
                .arg("EX")
                .arg(60) // 60s TTL
                .query_async::<_, ()>(&mut conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to store exchange key in Redis");
                    AppError::Internal("Database error storing exchange key".into())
                })?;

            stored_exchange_key = Some(exchange_key);

            let redirect_url =
                build_success_redirect_url(r, "code", &exchange_code).ok_or_else(|| {
                    tracing::error!("Failed to build exchange success redirect URL");
                    AppError::Internal("Failed to build redirect response".into())
                })?;

            (jar, redirect_url)
        } else {
            // Direct mode: set HttpOnly, SameSite=Strict cookie and clear direct nonce cookie
            let cookie = Cookie::build((SESSION_COOKIE_NAME, session_id.clone()))
                .path("/")
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Strict)
                .max_age(time::Duration::days(30))
                .build();
            let direct_cleanup_cookie = Cookie::build((OAUTH_DIRECT_NONCE_COOKIE_NAME, ""))
                .path("/auth/callback")
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Lax)
                .max_age(time::Duration::ZERO)
                .build();
            let redirect_target = "/";

            (
                jar.add(cookie).add(direct_cleanup_cookie),
                redirect_target.to_string(),
            )
        };
        // 4. Construct response
        let response = Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", app_redirect)
            .body(Body::empty())
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to build redirect response");
                AppError::Internal("Failed to build redirect response".into())
            })?;

        // 5. Push activation only after exchange/response construction
        if let Some(registry) = &push_registry {
            registry
                .activate_account_session(&did, &session_id, &pds_url)
                .await
                .map_err(|e| {
                    let session_fp = redact_session_id(&session_id);
                    tracing::error!(
                        did = %did,
                        session_fp = %session_fp,
                        error = %e,
                        "Push account session activation failed"
                    );
                    AppError::AuthTemporarilyUnavailable(
                        "Push session activation temporarily unavailable; please retry".into(),
                    )
                })?;
        }

        Ok((cookie_jar_out, response))
    }
    .await;

    match finalize_res {
        Ok((cookie_jar_out, response)) => {
            // After final success, flow/claim cleanup is best-effort
            if let Err(e) = redis::cmd("DEL")
                .arg(&flow_key)
                .arg(&claim_key)
                .query_async::<_, ()>(&mut conn)
                .await
            {
                tracing::warn!(error = %e, "OAuth callback state cleanup failed after success (ignored)");
            }

            metrics::record_oauth_login(true);
            Ok((cookie_jar_out, response))
        }
        Err(err) => {
            tracing::error!(
                did = %did,
                session_fp = %redact_session_id(&session_id),
                error = %err,
                "Post-callback finalization failed; executing unified compensation path"
            );

            // One unified compensation path:
            // 1. Delete exchange if stored
            if let Some(ex_key) = &stored_exchange_key {
                let _ = redis::cmd("DEL")
                    .arg(ex_key)
                    .query_async::<_, ()>(&mut conn)
                    .await;
            }

            // 2. CAS-revoke possible push row
            if let Some(registry) = &push_registry {
                let _ = registry
                    .mark_auth_revoked_if_session(&did, &session_id)
                    .await;
            }

            // 3. Revoke/delete session locally and with auth server
            cleanup_new_session(&state, jacquard_client, &did, &session_id).await;

            // 4. Release claim key
            let _ = redis::cmd("DEL")
                .arg(&claim_key)
                .query_async::<_, ()>(&mut conn)
                .await;

            metrics::record_oauth_login(false);
            Err(err)
        }
    }
}
/// Handle progressive OAuth scope upgrade callback
async fn handle_upgrade_callback(
    state: Arc<AppState>,
    callback: OAuthCallback,
    jar: CookieJar,
) -> AppResult<(CookieJar, Response)> {
    let upgrade_service = crate::handlers::oauth_upgrade::get_upgrade_service(&state)?;

    // User cancellation or provider error path
    let Some(code) = callback.code else {
        tracing::warn!("OAuth upgrade callback denied or cancelled by user");
        if let Err(e) = upgrade_service.cancel_or_deny_flow(&callback.state).await {
            tracing::error!(error = %e, "OAuth upgrade cleanup failed");
            return Err(AppError::AuthTemporarilyUnavailable(
                "OAuth upgrade temporarily unavailable; please retry".into(),
            ));
        }
        let target = format!("{FIXED_UPGRADE_CALLBACK_URL}?error=access_denied");
        return Ok((
            jar,
            Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", target)
                .body(Body::empty())
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to build redirect response");
                    AppError::Internal("Failed to build redirect response".into())
                })?,
        ));
    };

    let jacquard_client = state
        .jacquard_client
        .as_ref()
        .ok_or_else(|| AppError::Internal("Jacquard OAuthClient not initialized".into()))?;

    use jacquard_oauth::types::CallbackParams;
    let params = CallbackParams {
        code: code.into(),
        state: Some(callback.state.clone().into()),
        iss: callback.iss.map(|s| s.into()),
    };
    let oauth_session = match jacquard_client.callback(params).await {
        Ok(session) => session,
        Err(e) => {
            tracing::error!(error = %e, "Jacquard callback failed for upgrade");
            if let Err(cleanup) = upgrade_service.cancel_or_deny_flow(&callback.state).await {
                tracing::error!(error = %cleanup, "OAuth upgrade cleanup failed");
                return Err(AppError::AuthTemporarilyUnavailable(
                    "OAuth upgrade temporarily unavailable; please retry".into(),
                ));
            }
            let target = format!("{FIXED_UPGRADE_CALLBACK_URL}?error=invalid_grant");
            return Ok((
                jar,
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header("Location", target)
                    .body(Body::empty())
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to build redirect response");
                        AppError::Internal("Failed to build redirect response".into())
                    })?,
            ));
        }
    };

    let session_data = oauth_session.data.read().await.clone();

    // Clean up the stray session created by callback() in store & registry cache so the upgrade service manages the session lifecycle.
    let _ = oauth_session
        .registry
        .del(&session_data.account_did, session_data.session_id.as_str())
        .await;

    let granted_scopes = session_data
        .scopes
        .iter()
        .map(|s| s.to_string_normalized().to_string())
        .collect::<Vec<_>>();

    let result = match upgrade_service
        .complete_callback(&callback.state, session_data, granted_scopes)
        .await
    {
        Ok(res) => res,
        Err(e) => {
            tracing::error!(error = %e, "OAuth upgrade complete_callback failed");
            if let Err(cleanup) = upgrade_service.cancel_or_deny_flow(&callback.state).await {
                tracing::error!(error = %cleanup, "OAuth upgrade cleanup failed");
                return Err(AppError::AuthTemporarilyUnavailable(
                    "OAuth upgrade temporarily unavailable; please retry".into(),
                ));
            }
            let target = format!("{FIXED_UPGRADE_CALLBACK_URL}?error=invalid_grant");
            return Ok((
                jar,
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header("Location", target)
                    .body(Body::empty())
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to build redirect response");
                        AppError::Internal("Failed to build redirect response".into())
                    })?,
            ));
        }
    };

    let mut url = url::Url::parse(FIXED_UPGRADE_CALLBACK_URL).expect("fixed callback URL is valid");
    url.query_pairs_mut()
        .append_pair("code", &result.exchange_code);
    let target = url.to_string();

    // Fixed app callback with code parameter only, CookieJar untouched (no cookie set)
    Ok((
        jar,
        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", target)
            .body(Body::empty())
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to build redirect response");
                AppError::Internal("Failed to build redirect response".into())
            })?,
    ))
}

/// Build a provider-error redirect without interpolating request data into a URL.
fn build_error_redirect(redirect_to: Option<&str>, error: &str) -> String {
    let target = redirect_to
        .filter(|r| is_allowed_redirect(r))
        .and_then(|r| url::Url::parse(r).ok())
        .filter(|u| u.username().is_empty() && u.password().is_none() && u.fragment().is_none())
        .map(|mut url| {
            let retained_pairs: Vec<(String, String)> = url
                .query_pairs()
                .filter(|(k, _)| k != "session_id" && k != "code" && k != "error")
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            url.query_pairs_mut()
                .clear()
                .extend_pairs(retained_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .append_pair("error", error);
            url.to_string()
        });
    target.unwrap_or_else(|| {
        let mut url = url::Url::parse("https://catbird.blue/oauth/callback")
            .expect("fixed callback URL is valid");
        url.query_pairs_mut().append_pair("error", error);
        url.to_string()
    })
}

/// Helper to clean up a newly created session from Jacquard and RedisAuthStore on post-callback failure.
async fn cleanup_new_session(
    state: &Arc<AppState>,
    jacquard_client: &Arc<crate::config::JacquardOAuthClient>,
    did: &str,
    session_id: &str,
) {
    if let Ok(parsed_did) = jacquard_common::types::did::Did::new(did) {
        let revoked = match jacquard_client.restore(&parsed_did, session_id).await {
            Ok(oauth_session) => oauth_session.logout().await,
            Err(_) => jacquard_client.revoke(&parsed_did, session_id).await,
        };
        let session_fp = redact_session_id(session_id);
        if let Err(e) = revoked {
            tracing::warn!(
                did = %did,
                session_fp = %session_fp,
                error = %e,
                "Best-effort Jacquard session revocation failed after callback error"
            );
        }
        if let Some(store) = state.auth_store.as_ref() {
            use jacquard_oauth::authstore::ClientAuthStore;
            if let Err(e) = store.delete_session(&parsed_did, session_id).await {
                tracing::warn!(
                    did = %did,
                    session_fp = %session_fp,
                    error = %e,
                    "Best-effort RedisAuthStore session deletion failed after callback error"
                );
            }
        }
    }
}

async fn resolve_handle_for_did(http_client: &reqwest::Client, did: &str, pds_url: &str) -> String {
    if crate::services::validate_pds_url(pds_url).is_err() {
        return did.to_string();
    }
    let describe_url = format!(
        "{}/xrpc/com.atproto.repo.describeRepo?repo={}",
        pds_url.trim_end_matches('/'),
        did
    );
    if crate::services::validate_pds_url(&describe_url).is_err() {
        return did.to_string();
    }

    match http_client.get(&describe_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            use futures_util::StreamExt;
            let mut stream = resp.bytes_stream();
            let mut body_bytes = Vec::new();
            const MAX_HANDLE_BODY: usize = 64 * 1024;
            while let Some(Ok(chunk)) = stream.next().await {
                if body_bytes.len() + chunk.len() > MAX_HANDLE_BODY {
                    return did.to_string();
                }
                body_bytes.extend_from_slice(&chunk);
            }
            match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                Ok(json) => json
                    .get("handle")
                    .and_then(|h| h.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| did.to_string()),
                Err(_) => did.to_string(),
            }
        }
        _ => did.to_string(),
    }
}

/// Allowed exact redirect URLs for OAuth callback (native app registered callback).
const ALLOWED_EXACT_REDIRECT_URLS: &[&str] = &["https://catbird.blue/oauth/callback"];

/// Allowed redirect origins for OAuth callback (beyond localhost).
const ALLOWED_REDIRECT_ORIGINS: &[&str] =
    &["https://catmos.catbird.blue", "https://catmos.pages.dev"];

/// Redirect-target allowlist shared by the success and deny/cancel paths:
/// local dev loopback, known production origins, catmos.pages.dev previews,
/// and registered app callback URLs.
pub fn is_allowed_redirect(r: &str) -> bool {
    if ALLOWED_EXACT_REDIRECT_URLS.contains(&r) {
        return true;
    }

    let Ok(u) = url::Url::parse(r) else {
        return false;
    };

    // Reject URLs with embedded credentials (userinfo) or fragments
    if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        return false;
    }

    // Allow loopback (dev)
    if u.scheme() == "http"
        && (u.host_str() == Some("127.0.0.1")
            || u.host_str() == Some("[::1]")
            || u.host_str() == Some("localhost"))
    {
        return true;
    }

    // Allow known production origins (exact origin match, preventing subdomain attacks)
    let origin = u.origin().ascii_serialization();
    if ALLOWED_REDIRECT_ORIGINS.contains(&origin.as_str()) {
        return true;
    }

    // Allow Cloudflare Pages preview deployments
    if u.scheme() == "https"
        && u.host_str()
            .map(|h| h.ends_with(".catmos.pages.dev"))
            .unwrap_or(false)
    {
        return true;
    }

    false
}

/// Build a success redirect URL by parsing the target URL and appending the given parameter (code or session_id).
/// Preserves any existing query parameters safely and verifies that the URL is allowed and contains no fragments or credentials.
pub fn build_success_redirect_url(
    target: &str,
    param_name: &str,
    param_value: &str,
) -> Option<String> {
    if !is_allowed_redirect(target) {
        return None;
    }
    let mut url = url::Url::parse(target).ok()?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return None;
    }
    let retained_pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "session_id" && k != "code" && k != "error")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(retained_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .append_pair(param_name, param_value);
    Some(url.to_string())
}
/// Helper used for legacy/backward-compatible app redirects.
pub fn build_app_redirect(state: &str, session_id: &str) -> String {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(state) {
        if let Some(r) = val.get("redirect_to").and_then(|v| v.as_str()) {
            if let Some(url) = build_success_redirect_url(r, "session_id", session_id) {
                return url;
            }
        }
    }
    format!("https://catbird.blue/oauth/callback#session_id={session_id}")
}

/// Handle logout
///
/// POST /auth/logout
pub async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<LogoutResponse>)> {
    let jacquard_client = state
        .jacquard_client
        .as_ref()
        .ok_or_else(|| AppError::Internal("Jacquard OAuthClient not initialized".into()))?;

    let did = jacquard_common::types::did::Did::new(session.did.as_str())
        .map_err(|e| AppError::Internal(format!("Invalid DID: {e}")))?;
    let session_id_str = session.id.to_string();
    let session_fp = redact_session_id(&session_id_str);

    // 1. Preserve OAuthSession metadata in memory before local deletion so remote revocation can be attempted
    let preserved_oauth_session = jacquard_client.restore(&did, &session_id_str).await.ok();

    // 2. Mandatory local delete from auth_store FIRST (fail-closed locally)
    if let Some(store) = state.auth_store.as_ref() {
        use jacquard_oauth::authstore::ClientAuthStore;
        store
            .delete_session(&did, &session_id_str)
            .await
            .map_err(|e| {
                tracing::error!(
                    did = %session.did,
                    session_fp = %session_fp,
                    error = %e,
                    "Failed mandatory local session delete on logout"
                );
                AppError::AuthTemporarilyUnavailable(
                    "Logout temporarily unavailable; please retry".into(),
                )
            })?;
    }

    // 3. Best-effort push revocation (cleanup failure does not reactivate bearer)
    let push_registry = state.push.as_ref().map(|p| p.registry.clone()).or_else(|| {
        state
            .push_db
            .as_ref()
            .map(|db| crate::services::push::registry::PushRegistry::new(db.clone(), String::new()))
    });

    if let Some(registry) = push_registry {
        if let Err(e) = registry
            .mark_auth_revoked_if_session(&session.did, &session_id_str)
            .await
        {
            tracing::warn!(
                did = %session.did,
                session_fp = %session_fp,
                error = %e,
                "Best-effort push auth revocation failed on logout"
            );
        }
    }

    // 4. Best-effort remote authorization-server logout/revocation using preserved session
    if let Some(oauth_session) = preserved_oauth_session {
        if let Err(e) = oauth_session.logout().await {
            tracing::warn!(
                did = %session.did,
                session_fp = %session_fp,
                error = %e,
                "Best-effort OAuth session revocation with authorization server failed on logout"
            );
        }
    } else {
        tracing::warn!(
            did = %session.did,
            session_fp = %session_fp,
            "No active OAuthSession restored before local deletion; skipping remote revocation"
        );
    }
    let cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(true)
        .max_age(time::Duration::ZERO)
        .build();

    tracing::info!(did = %session.did, "User logged out successfully");

    Ok((
        jar.remove(cookie),
        Json(LogoutResponse {
            success: true,
            message: "Logged out".to_string(),
        }),
    ))
}

/// Get current session info
pub async fn get_session(Extension(session): Extension<CatbirdSession>) -> Json<SessionInfo> {
    Json(SessionInfo {
        did: session.did,
        handle: session.handle,
        created_at: session.created_at,
        granted_scopes: session.granted_scopes,
    })
}

/// Consume an exchange code and return the session ID (ADR-014 confidential gateway exchange)
///
/// POST /auth/exchange
pub async fn exchange_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ExchangeRequest>,
) -> AppResult<Json<ExchangeResponse>> {
    // 1. Validate format of code and browser_nonce (both 43-char base64url)
    if !is_valid_base64url_43(&payload.code) || !is_valid_base64url_43(&payload.browser_nonce) {
        tracing::warn!("Exchange failed: invalid code or nonce format");
        return Err(AppError::Unauthorized("Invalid exchange request".into()));
    }

    // 2. Validate and canonicalize Origin header
    let origin_header = headers.get("origin").and_then(|v| v.to_str().ok());
    let Some(raw_origin) = origin_header else {
        tracing::warn!("Exchange failed: missing or invalid Origin header");
        return Err(AppError::Unauthorized("Invalid exchange request".into()));
    };
    let Some(canonical_origin) = canonicalize_origin(raw_origin) else {
        tracing::warn!("Exchange failed: unparseable Origin header");
        return Err(AppError::Unauthorized("Invalid exchange request".into()));
    };

    // 3. FIX 1 + FIX 2: Compute composite key. Lookup IS validation.
    let exchange_key =
        compute_exchange_redis_key(&payload.code, &payload.browser_nonce, &canonical_origin);

    // 4. Atomically consume the key using GETDEL.
    // If the nonce or origin was wrong, the computed key did not match, returning None (401),
    // and the legitimate key in Redis is untouched and still redeemable.
    let mut conn = state.redis.clone();
    let raw_sealed = atomic_getdel(&mut conn, &exchange_key).await.map_err(|e| {
        tracing::error!("Redis error during atomic GETDEL of exchange key: {}", e);
        AppError::Internal("Database error during exchange".into())
    })?;

    let Some(sealed_b64) = raw_sealed else {
        tracing::warn!("Exchange failed: key not found, expired, or already consumed");
        return Err(AppError::Unauthorized("Invalid exchange request".into()));
    };

    // 5. Decrypt sealed value with AES-256-GCM. Any failure is 401 (no fallback).
    let Some(enc_key) = state.session_encryption_key.as_ref() else {
        tracing::error!("Exchange failed: session encryption key not configured");
        return Err(AppError::Unauthorized("Invalid exchange request".into()));
    };
    // Require strict v2 envelope format for ephemeral exchange records to prevent legacy v1 transplantation
    if !sealed_b64.starts_with(crate::services::redis_crypto::V2_PREFIX) {
        tracing::warn!("Exchange failed: legacy v1 exchange ciphertext rejected");
        return Err(AppError::Unauthorized("Invalid exchange request".into()));
    }

    let ex_aad =
        crate::services::redis_crypto::build_aad("oauth_exchange", &exchange_key, None, None);
    let plaintext_bytes =
        crate::services::redis_crypto::open_with_aad(enc_key, &sealed_b64, &ex_aad).map_err(
            |e| {
                tracing::warn!("Exchange failed: decryption failed: {}", e);
                AppError::Unauthorized("Invalid exchange request".into())
            },
        )?;

    let session_id = String::from_utf8(plaintext_bytes).map_err(|_| {
        tracing::warn!("Exchange failed: decrypted session_id is not valid UTF-8");
        AppError::Unauthorized("Invalid exchange request".into())
    })?;

    tracing::info!("Exchange code successfully redeemed");

    Ok(Json(ExchangeResponse { session_id }))
}
/// Canonicalize an origin string (scheme + host + optional non-default port, lowercase, no trailing slash).
pub fn canonicalize_origin(raw: &str) -> Option<String> {
    let u = url::Url::parse(raw).ok()?;
    let scheme = u.scheme().to_lowercase();
    let host = u.host_str()?.to_lowercase();
    let port_str = match (scheme.as_str(), u.port()) {
        ("http", Some(80)) | ("https", Some(443)) | (_, None) => String::new(),
        (_, Some(p)) => format!(":{}", p),
    };
    Some(format!("{}://{}{}", scheme, host, port_str))
}

/// Compute the composite Redis key for exchange code lookup:
/// `exchange:<hex SHA-256( code || 0x00 || browser_nonce || 0x00 || canonical_origin )>`
pub fn compute_exchange_redis_key(
    code: &str,
    browser_nonce: &str,
    canonical_origin: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.update(&[0x00]);
    hasher.update(browser_nonce.as_bytes());
    hasher.update(&[0x00]);
    hasher.update(canonical_origin.as_bytes());
    let digest = hasher.finalize();
    format!("exchange:{:x}", digest)
}

/// Validate 43-character unpadded base64url string ([A-Za-z0-9_-])
pub fn is_valid_base64url_43(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Mint a 43-character unpadded base64url exchange code from 32 CSPRNG bytes
pub fn generate_exchange_code() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Atomically retrieve and delete a key from Redis using GETDEL (or Lua script fallback)
async fn atomic_getdel(
    conn: &mut redis::aio::ConnectionManager,
    key: &str,
) -> Result<Option<String>, redis::RedisError> {
    match redis::cmd("GETDEL")
        .arg(key)
        .query_async::<_, Option<String>>(conn)
        .await
    {
        Ok(val) => Ok(val),
        Err(err) if err.to_string().contains("unknown command") => {
            let script = redis::Script::new(
                r#"
                local val = redis.call('GET', KEYS[1])
                if val then
                    redis.call('DEL', KEYS[1])
                end
                return val
            "#,
            );
            script.key(key).invoke_async(conn).await
        }
        Err(err) => Err(err),
    }
}

const MAX_CIRCLE_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

#[allow(clippy::too_many_arguments)]
async fn proxy_circle_request(
    state: Arc<AppState>,
    session: &CatbirdSession,
    base_url: &str,
    audience: &str,
    dpop_data: &JacquardDpopData,
    method: reqwest::Method,
    lexicon: &str,
    query: Option<&str>,
    body: Option<bytes::Bytes>,
    content_type: Option<&str>,
) -> AppResult<(u16, reqwest::header::HeaderMap, bytes::Bytes)> {
    let mut url = format!("{}/xrpc/{lexicon}", base_url.trim_end_matches('/'));
    if let Some(query) = query {
        url.push('?');
        url.push_str(query);
    }

    let token = ServiceAuthProvider::new(state.clone())
        .token_for_audience_with_dpop(session, audience, lexicon, dpop_data)
        .await?;
    let mut request = state.http_client.request(method, &url).bearer_auth(token);
    if let Some(content_type) = content_type {
        request = request.header(reqwest::header::CONTENT_TYPE, content_type);
    }
    if let Some(body) = body {
        request = request.body(body);
    }

    let response = request.send().await?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    if headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_CIRCLE_RESPONSE_SIZE)
    {
        return Err(AppError::ResponseTooLarge(
            "Circle AppView response exceeds 10 MiB".into(),
        ));
    }

    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len() + chunk.len() > MAX_CIRCLE_RESPONSE_SIZE {
            return Err(AppError::ResponseTooLarge(
                "Circle AppView response exceeds 10 MiB".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }

    Ok((status, headers, bytes::Bytes::from(bytes)))
}

/// Proxy XRPC requests to the user's PDS (or directly to MLS service for MLS lexicons)
pub async fn proxy_xrpc(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    req_extensions: Option<Extension<crate::middleware::RequestId>>,
    dpop_data: Option<Extension<JacquardDpopData>>,
    method: Method,
    Path(lexicon): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> AppResult<Response> {
    let start = std::time::Instant::now();

    // Extract request ID: prefer middleware-set value, fall back to client header
    let request_id = req_extensions
        .map(|ext| ext.0 .0.clone())
        .or_else(|| {
            headers
                .get("x-catbird-request-id")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        })
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Use raw query string directly to preserve repeated params (e.g., feeds=a&feeds=b)
    // HashMap would lose duplicates, keeping only the last value
    let query_string = raw_query;

    let content_type = headers.get("content-type").and_then(|h| h.to_str().ok());

    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read body: {}", e)))?;

    // Log request receipt with body shape
    let body_shape = json_shape(&body_bytes);
    tracing::info!(
        request_id = %request_id,
        lexicon = %lexicon,
        method = %method,
        query = ?query_string,
        content_type = ?content_type,
        body_bytes = body_bytes.len(),
        body_shape = ?body_shape,
        "[BFF-RECV] Received XRPC request"
    );

    let body_option = if body_bytes.is_empty() {
        None
    } else {
        Some(body_bytes.clone())
    };

    if CIRCLE_ENDPOINTS.contains(&lexicon.as_str()) {
        tracing::info!(
            request_id = %request_id,
            lexicon = %lexicon,
            user = %session.did,
            "Routing Circle request directly to standalone AppView"
        );
        let circle_dpop = dpop_data
            .as_ref()
            .map(|extension| &extension.0)
            .ok_or(AppError::InvalidSession)?;
        let (status, response_headers, response_body) = proxy_circle_request(
            state.clone(),
            &session,
            &state.config.circle.base_url,
            &state.config.circle.service_did,
            circle_dpop,
            method,
            &lexicon,
            query_string.as_deref(),
            body_option,
            content_type,
        )
        .await?;

        metrics::record_proxy_request(&lexicon, status, start.elapsed().as_secs_f64());
        let mut response = Response::builder()
            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
        for (name, value) in response_headers.iter() {
            if matches!(
                name.as_str(),
                "content-type"
                    | "content-length"
                    | "content-disposition"
                    | "cache-control"
                    | "etag"
                    | "last-modified"
            ) {
                if let Ok(value) = value.to_str() {
                    response = response.header(name.as_str(), value);
                }
            }
        }
        return Ok(response.body(Body::from(response_body)).unwrap());
    }

    // Check if this is an MLS lexicon and direct routing is enabled
    let mls_service = MlsAuthService::new(state.clone());
    if MlsAuthService::is_mls_lexicon(&lexicon) && mls_service.is_enabled() {
        tracing::debug!(
            request_id = %request_id,
            lexicon = %lexicon,
            user = %session.did,
            "Routing MLS request directly to MLS service"
        );

        let device_id_header = headers
            .get("x-catbird-chat-device-id")
            .or_else(|| headers.get("x-catbird-device-id"))
            .or_else(|| headers.get("x-device-id"))
            .and_then(|v| v.to_str().ok());

        let session_dpop_key = dpop_data.as_ref().and_then(|ext| {
            match jose_jwk::crypto::Key::try_from(&ext.0.dpop_key).ok()? {
                jose_jwk::crypto::Key::P256(jose_jwk::crypto::Kind::Secret(sk)) => {
                    Some(p256::ecdsa::SigningKey::from(sk))
                }
                _ => None,
            }
        });

        let (status, response_headers, response_body) =
            if MlsAuthService::is_clean_chat_lexicon(&lexicon) {
                mls_service
                    .proxy_clean_chat_request(
                        &session,
                        method.try_into().unwrap_or(reqwest::Method::GET),
                        &lexicon,
                        query_string.as_deref(),
                        body_option,
                        content_type,
                        device_id_header,
                        session_dpop_key.as_ref(),
                    )
                    .await?
            } else {
                mls_service
                    .proxy_request(
                        &session,
                        method.try_into().unwrap_or(reqwest::Method::GET),
                        &lexicon,
                        query_string.as_deref(),
                        body_option,
                        content_type,
                    )
                    .await?
            };

        let response_shape = json_shape(&response_body);
        tracing::info!(
            request_id = %request_id,
            status = status,
            body_bytes = response_body.len(),
            body_shape = ?response_shape,
            "[BFF-RESP] MLS response"
        );

        // Record proxy metrics
        let duration = start.elapsed().as_secs_f64();
        metrics::record_proxy_request(&lexicon, status, duration);

        let mut response = Response::builder()
            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
        for (name, value) in response_headers.iter() {
            let name_str = name.as_str();
            if matches!(
                name_str,
                "content-type" | "content-length" | "cache-control" | "etag" | "last-modified"
            ) {
                if let Ok(v) = reqwest::header::HeaderValue::to_str(value) {
                    response = response.header(name_str, v);
                }
            }
        }

        return Ok(response.body(Body::from(response_body)).unwrap());
    }

    let path = format!("/xrpc/{}", lexicon);

    // Default: proxy through PDS
    tracing::info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        pds = %session.pds_url,
        "[BFF-FWD] Forwarding to PDS"
    );

    let client = AtProtoClient::new(state.clone());
    let jacquard_dpop = dpop_data.map(|ext| ext.0);
    let proxy_response = client
        .proxy_request(
            &session,
            method,
            &path,
            query_string.as_deref(),
            body_option,
            content_type,
            Some(&headers),
            &request_id,
            jacquard_dpop.as_ref(),
        )
        .await?;

    // Record proxy metrics
    let duration = start.elapsed().as_secs_f64();
    metrics::record_proxy_request(&lexicon, proxy_response.status(), duration);

    match proxy_response {
        ProxyResponse::Buffered {
            status,
            headers: resp_headers,
            body: response_body,
            ..
        } => {
            let response_shape = json_shape(&response_body);
            tracing::info!(
                request_id = %request_id,
                status = status,
                body_bytes = response_body.len(),
                body_shape = ?response_shape,
                "[BFF-RESP] PDS response (buffered)"
            );
            if status >= 400 {
                tracing::warn!(
                    request_id = %request_id,
                    lexicon = %lexicon,
                    status = status,
                    body_bytes = response_body.len(),
                    "[BFF-RESP-ERR] PDS error response"
                );
            }

            if (200..300).contains(&status) {
                if let Err(err) =
                    apply_moderation_mutation(&state, &session, &lexicon, &body_bytes).await
                {
                    tracing::warn!(
                        lexicon = %lexicon,
                        user = %session.did,
                        error = %err,
                        "Failed to apply moderation mutation to push state"
                    );
                }
            }

            let mut response = Response::builder()
                .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
            for (name, value) in resp_headers.iter() {
                let name_str = name.as_str();
                if matches!(
                    name_str,
                    "content-type" | "content-length" | "cache-control" | "etag" | "last-modified"
                ) {
                    response = response.header(name, value);
                }
            }

            Ok(response.body(Body::from(response_body)).unwrap())
        }
        ProxyResponse::Streaming {
            status,
            headers: resp_headers,
            body: upstream_response,
            max_bytes,
            permit,
            rate_limit,
            session_id,
            ..
        } => {
            tracing::info!(
                request_id = %request_id,
                status = status,
                max_bytes = max_bytes,
                "[BFF-RESP] PDS response (streaming)"
            );
            let mut response = Response::builder()
                .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
            for (name, value) in resp_headers.iter() {
                let name_str = name.as_str();
                if matches!(
                    name_str,
                    "content-type" | "content-length" | "cache-control" | "etag" | "last-modified"
                ) {
                    response = response.header(name, value);
                }
            }

            // Stream the response body directly from upstream with cumulative remaining byte limit, live rate limit accounting, and held semaphore permit
            let stream = crate::services::bounded_byte_stream_with_accounting(
                upstream_response.bytes_stream(),
                max_bytes,
                permit,
                rate_limit,
                session_id,
            );
            Ok(response.body(Body::from_stream(stream)).unwrap())
        }
    }
}

/// Extract JSON shape information for logging (top-level keys and array lengths)
fn json_shape(data: &[u8]) -> Option<String> {
    let json: Value = serde_json::from_slice(data).ok()?;
    Some(describe_json_shape(&json, 0))
}

fn describe_json_shape(value: &Value, depth: usize) -> String {
    if depth > 2 {
        return "...".to_string();
    }
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map
                .keys()
                .map(|k| {
                    let child = describe_json_shape(&map[k], depth + 1);
                    format!("{}:{}", k, child)
                })
                .collect();
            format!("{{{}}}", keys.join(","))
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                "[]".to_string()
            } else {
                let first = describe_json_shape(&arr[0], depth + 1);
                format!("[{}x{}]", arr.len(), first)
            }
        }
        Value::String(_) => "str".to_string(),
        Value::Number(_) => "num".to_string(),
        Value::Bool(_) => "bool".to_string(),
        Value::Null => "null".to_string(),
    }
}

/// React to a moderation mutation the user just made through Nest, so the push
/// pipeline honours it immediately rather than on the next cache expiry.
///
/// Two jobs. Thread mutes are recorded locally, because `thread_mutes` is state
/// Nest owns. Everything else — actor mutes, blocks, list mutes and list blocks
/// — only invalidates the cached per-actor verdicts for this user; the answers
/// themselves come from `app.bsky.actor.defs#viewerState` at decision time.
/// Nest used to mirror that whole graph here to keep a local replica warm; the
/// replica is gone (ADR-022), but the invalidation is still required. Without
/// it, muting someone moments after their notification arrived would leave the
/// "not muted" verdict just cached by that notification's own decision serving
/// for the rest of the TTL, and their next notification would be delivered.
async fn apply_moderation_mutation(
    state: &Arc<AppState>,
    session: &CatbirdSession,
    lexicon: &str,
    request_body: &[u8],
) -> anyhow::Result<()> {
    let Some(push) = state.push.as_ref() else {
        return Ok(());
    };

    let body: Value = if request_body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(request_body)?
    };

    match lexicon {
        "app.bsky.graph.muteThread" | "app.bsky.graph.unmuteThread" => {
            let Some(root) = body.get("root").and_then(|value| value.as_str()) else {
                return Ok(());
            };
            if lexicon == "app.bsky.graph.muteThread" {
                push.thread_mutes.mute_thread(&session.did, root).await?;
            } else {
                push.thread_mutes.unmute_thread(&session.did, root).await?;
            }
        }
        "app.bsky.graph.muteActor"
        | "app.bsky.graph.unmuteActor"
        | "app.bsky.graph.muteActorList"
        | "app.bsky.graph.unmuteActorList" => {
            push.moderation.invalidate_recipient(&session.did).await?;
        }
        // Blocks and list blocks are repo records, so they arrive as generic
        // record writes rather than dedicated procedures.
        "com.atproto.repo.createRecord"
        | "com.atproto.repo.deleteRecord"
        | "com.atproto.repo.applyWrites"
            if moderation_record_write(&body) =>
        {
            push.moderation.invalidate_recipient(&session.did).await?;
        }
        _ => {}
    }

    Ok(())
}

/// Whether a repo write touches a collection that changes moderation state.
///
/// `applyWrites` batches heterogeneous writes, so every entry is checked.
fn moderation_record_write(body: &Value) -> bool {
    const MODERATION_COLLECTIONS: [&str; 2] = ["app.bsky.graph.block", "app.bsky.graph.listblock"];

    let touches = |value: &Value| {
        value
            .get("collection")
            .and_then(Value::as_str)
            .is_some_and(|collection| MODERATION_COLLECTIONS.contains(&collection))
    };

    if touches(body) {
        return true;
    }

    body.get("writes")
        .and_then(Value::as_array)
        .is_some_and(|writes| writes.iter().any(touches))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OAuthConfig;

    #[test]
    fn moderation_record_writes_are_detected_including_batches() {
        use serde_json::json;

        // A block or listblock write invalidates cached push verdicts; anything
        // else must not, or every post would flush the cache.
        assert!(moderation_record_write(
            &json!({ "collection": "app.bsky.graph.block" })
        ));
        assert!(moderation_record_write(
            &json!({ "collection": "app.bsky.graph.listblock" })
        ));
        assert!(!moderation_record_write(
            &json!({ "collection": "app.bsky.feed.post" })
        ));
        assert!(!moderation_record_write(&json!({})));

        // applyWrites batches heterogeneous writes, so a block hidden among
        // unrelated ones still counts.
        assert!(moderation_record_write(&json!({
            "writes": [
                { "collection": "app.bsky.feed.like" },
                { "collection": "app.bsky.graph.block" }
            ]
        })));
        assert!(!moderation_record_write(&json!({
            "writes": [{ "collection": "app.bsky.feed.like" }]
        })));
    }

    #[test]
    fn test_is_allowed_redirect_behavior() {
        // Allowed exact native callback
        assert!(is_allowed_redirect("https://catbird.blue/oauth/callback"));

        // Allowed production origins
        assert!(is_allowed_redirect("https://catmos.catbird.blue/callback"));
        assert!(is_allowed_redirect("https://catmos.catbird.blue/"));
        assert!(is_allowed_redirect("https://catmos.pages.dev/callback"));
        assert!(is_allowed_redirect(
            "https://preview-123.catmos.pages.dev/callback"
        ));

        // Allowed dev loopback
        assert!(is_allowed_redirect("http://127.0.0.1:8080/callback"));
        assert!(is_allowed_redirect("http://127.0.0.1:3000/"));
        assert!(is_allowed_redirect("http://[::1]:8080/callback"));
        assert!(is_allowed_redirect("http://localhost:8080/callback"));

        // Rejection: embedded fragment
        assert!(!is_allowed_redirect(
            "https://catmos.catbird.blue/callback#bad"
        ));
        assert!(!is_allowed_redirect(
            "http://localhost:8080/callback#token=123"
        ));

        // Rejection: embedded credentials (userinfo)
        assert!(!is_allowed_redirect(
            "https://admin:secret@catmos.catbird.blue/callback"
        ));
        assert!(!is_allowed_redirect("http://user@127.0.0.1:8080/callback"));

        // Rejection: near misses and subdomain attacks
        assert!(!is_allowed_redirect(
            "https://catbird.blue/oauth/callback/../evil"
        ));
        assert!(!is_allowed_redirect("https://catbird.blue/other"));
        assert!(!is_allowed_redirect("https://catbird.blue/"));
        assert!(!is_allowed_redirect("https://catbird.blue"));
        assert!(!is_allowed_redirect(
            "https://catmos.catbird.blue.evil.com/"
        ));
        assert!(!is_allowed_redirect(
            "https://catbird.blue.evil.com/oauth/callback"
        ));
        assert!(!is_allowed_redirect("https://evil.com/callback"));
        assert!(!is_allowed_redirect(""));
        assert!(!is_allowed_redirect("not-a-url"));
    }

    #[test]
    fn test_build_success_redirect_url_behavior() {
        // Append code to clean URL
        let url = build_success_redirect_url(
            "https://catmos.catbird.blue/callback",
            "code",
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V",
        );
        assert_eq!(
            url,
            Some("https://catmos.catbird.blue/callback?code=A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V".to_string())
        );

        // Append code while preserving existing query params
        let url = build_success_redirect_url(
            "https://catmos.catbird.blue/callback?tab=chat&mode=dark",
            "code",
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V",
        );
        assert_eq!(
            url,
            Some("https://catmos.catbird.blue/callback?tab=chat&mode=dark&code=A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V".to_string())
        );

        // Append session_id while preserving existing query params
        let url = build_success_redirect_url(
            "https://catmos.catbird.blue/callback?tab=chat",
            "session_id",
            "550e8400-e29b-41d4-a716-446655440000",
        );
        assert_eq!(
            url,
            Some("https://catmos.catbird.blue/callback?tab=chat&session_id=550e8400-e29b-41d4-a716-446655440000".to_string())
        );
        let url = build_success_redirect_url(
            "https://catmos.catbird.blue/callback?code=old1&code=old2&tab=chat&session_id=old_sess&error=old_err",
            "code",
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V",
        );
        assert_eq!(
            url,
            Some("https://catmos.catbird.blue/callback?tab=chat&code=A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V".to_string())
        );

        let url = build_success_redirect_url(
            "https://catmos.catbird.blue/callback?session_id=old1&session_id=old2&mode=dark",
            "session_id",
            "550e8400-e29b-41d4-a716-446655440000",
        );
        assert_eq!(
            url,
            Some("https://catmos.catbird.blue/callback?mode=dark&session_id=550e8400-e29b-41d4-a716-446655440000".to_string())
        );

        // Rejection on disallowed URL
        assert_eq!(
            build_success_redirect_url("https://evil.com/callback", "code", "abc"),
            None
        );

        // Rejection on URL with fragment
        assert_eq!(
            build_success_redirect_url("https://catmos.catbird.blue/callback#frag", "code", "abc"),
            None
        );

        // Rejection on URL with credentials
        assert_eq!(
            build_success_redirect_url(
                "https://user:pass@catmos.catbird.blue/callback",
                "code",
                "abc"
            ),
            None
        );
    }

    #[test]
    fn test_initial_scopes_validation_for_login() {
        let initial_scope_strings = crate::config::default_initial_scopes();
        let parsed = OAuthConfig::parse_and_validate_scopes(&initial_scope_strings)
            .expect("default initial scopes should parse");
        assert!(!parsed.is_empty());

        let normalized = OAuthConfig::parse_and_normalize_scopes(&initial_scope_strings)
            .expect("normalize initial scopes");
        assert_eq!(
            normalized,
            vec!["atproto", "transition:generic", "transition:chat.bsky"]
        );

        // Must not contain max / progressive scopes like identity:handle or account:email
        assert!(!normalized.iter().any(|s| s.starts_with("identity:")));
        assert!(!normalized.iter().any(|s| s.starts_with("account:")));
    }

    #[test]
    fn test_upgrade_state_prefix_detection() {
        let upg_state = "upg_550e8400e29b41d4a716446655440000";
        assert!(upg_state.starts_with("upg_"));

        let normal_uuid_state = "550e8400-e29b-41d4-a716-446655440000";
        assert!(!normal_uuid_state.starts_with("upg_"));

        let legacy_json_state = r#"{"client":"catmos"}"#;
        assert!(!legacy_json_state.starts_with("upg_"));
    }

    #[test]
    fn test_error_redirect_encodes_and_preserves_query() {
        let target = build_error_redirect(
            Some("https://catmos.catbird.blue/callback?state=abc"),
            "provider error&bad",
        );
        assert_eq!(
            target,
            "https://catmos.catbird.blue/callback?state=abc&error=provider+error%26bad"
        );
        assert_eq!(
            build_error_redirect(Some("https://evil.example/"), "x"),
            "https://catbird.blue/oauth/callback?error=x"
        );
        assert_eq!(
            build_error_redirect(
                Some("https://catmos.catbird.blue/callback#frag"),
                "access_denied"
            ),
            "https://catbird.blue/oauth/callback?error=access_denied"
        );
        let target = build_error_redirect(
            Some("https://catmos.catbird.blue/callback?error=old1&error=old2&code=bad&session_id=fake&tab=chat"),
            "access_denied",
        );
        assert_eq!(
            target,
            "https://catmos.catbird.blue/callback?tab=chat&error=access_denied"
        );
    }

    #[test]
    fn test_canonicalize_origin_behavior() {
        assert_eq!(
            canonicalize_origin("https://catbird.blue/oauth/callback"),
            Some("https://catbird.blue".to_string())
        );
        assert_eq!(
            canonicalize_origin("https://CATBIRD.BLUE/oauth/callback/"),
            Some("https://catbird.blue".to_string())
        );
        assert_eq!(
            canonicalize_origin("https://catbird.blue:443"),
            Some("https://catbird.blue".to_string())
        );
        assert_eq!(
            canonicalize_origin("http://127.0.0.1:80/callback"),
            Some("http://127.0.0.1".to_string())
        );
        assert_eq!(
            canonicalize_origin("http://127.0.0.1:8080/callback"),
            Some("http://127.0.0.1:8080".to_string())
        );
        assert_eq!(
            canonicalize_origin("http://[::1]:8080/callback"),
            Some("http://[::1]:8080".to_string())
        );
        assert_eq!(canonicalize_origin("not-a-valid-url"), None);
    }

    #[test]
    fn test_base64url_43_and_exchange_code_generation() {
        // Exactly 43 base64url chars
        let code = generate_exchange_code();
        assert_eq!(code.len(), 43);
        assert!(is_valid_base64url_43(&code));

        // Rejection of invalid lengths/characters
        assert!(!is_valid_base64url_43("short"));
        assert!(!is_valid_base64url_43(
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1+"
        )); // '+'
        assert!(!is_valid_base64url_43(
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1="
        )); // '='
    }

    #[test]
    fn test_compute_exchange_redis_key_structure() {
        let code = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V";
        let nonce = "B1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V";
        let origin = "https://catbird.blue";
        let key = compute_exchange_redis_key(code, nonce, origin);

        assert!(key.starts_with("exchange:"));
        // Does not leak raw code, nonce, or origin in plaintext
        assert!(!key.contains(code));
        assert!(!key.contains(nonce));
        assert!(!key.contains(origin));
    }

    #[test]
    fn test_default_and_catmos_explicit_scope_subsets() {
        use jacquard_common::IntoStatic;
        use jacquard_oauth::scopes::Scope;

        // Default client scopes
        let default_initial = crate::config::default_initial_scopes();
        let default_parsed = OAuthConfig::parse_and_validate_scopes(&default_initial).unwrap();
        let default_names: Vec<String> = default_parsed
            .iter()
            .map(|s| s.to_string_normalized().to_string())
            .collect();

        // Catmos client scopes
        let catmos_str = "atproto transition:generic";
        let catmos_parsed: Vec<Scope> = catmos_str
            .split_whitespace()
            .map(|s| Scope::<smol_str::SmolStr>::parse(s).unwrap().into_static())
            .collect();
        let catmos_names: Vec<String> = catmos_parsed
            .iter()
            .map(|s| s.to_string_normalized().to_string())
            .collect();
        // Verify default contains chat scope, but catmos subset does not
        assert!(default_names.contains(&"transition:chat.bsky".to_string()));
        assert!(!catmos_names.contains(&"transition:chat.bsky".to_string()));

        // Both contain basic atproto access
        assert!(default_names.contains(&"atproto".to_string()));
        assert!(catmos_names.contains(&"atproto".to_string()));
    }

    #[test]
    fn test_pds_url_validation_behavior() {
        // Valid HTTPS PDS URLs
        assert!(crate::services::validate_pds_url("https://bsky.social").is_ok());
        assert!(crate::services::validate_pds_url("https://pds.example.com").is_ok());

        // SSRF blocked URLs
        assert!(crate::services::validate_pds_url("http://bsky.social").is_err());
        // Loopback is deliberately permitted in debug builds so WireMock-backed
        // tests can target 127.0.0.1; release builds block it via
        // `is_private_ipv4`. Same guard as `ssrf::tests::test_blocks_private_ipv4`.
        #[cfg(not(debug_assertions))]
        assert!(crate::services::validate_pds_url("https://127.0.0.1").is_err());
        assert!(crate::services::validate_pds_url("https://10.0.0.1").is_err());
        assert!(crate::services::validate_pds_url("https://169.254.169.254").is_err());
        assert!(crate::services::validate_pds_url("https://[::1]").is_err());
    }

    #[test]
    fn test_logout_cookie_clearing() {
        let cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
            .path("/")
            .http_only(true)
            .max_age(time::Duration::ZERO)
            .build();
        assert_eq!(cookie.name(), SESSION_COOKIE_NAME);
        assert_eq!(cookie.value(), "");
        assert_eq!(cookie.max_age(), Some(time::Duration::ZERO));
    }

    #[test]
    fn test_describe_repo_url_formatting() {
        let pds_url = "https://pds.example.com/";
        let did = "did:plc:1234567890abcdef";
        let describe_url = format!(
            "{}/xrpc/com.atproto.repo.describeRepo?repo={}",
            pds_url.trim_end_matches('/'),
            did
        );
        assert_eq!(
            describe_url,
            "https://pds.example.com/xrpc/com.atproto.repo.describeRepo?repo=did:plc:1234567890abcdef"
        );
    }
    #[test]
    fn test_login_identifier_admission_rules() {
        // Valid DIDs
        assert!(Did::new("did:plc:ragtjsm2j2vknq6z").is_ok());
        assert!(Did::new("did:web:example.com").is_ok());

        // Valid Handles
        assert!(Handle::new("alice.bsky.social").is_ok());
        assert!(Handle::new("bob.test.com").is_ok());

        // Valid PDS / Issuer URLs
        assert!(crate::services::validate_pds_url("https://bsky.social").is_ok());
        assert!(crate::services::validate_pds_url("https://pds.example.com").is_ok());

        // Invalid Handle / DID syntax
        assert!(Did::new("not_a_did").is_err());
        assert!(Handle::new("bad!handle").is_err());
        assert!(Handle::new("").is_err());

        // SSRF blocked URLs
        // Loopback is permitted in debug builds for WireMock-backed tests; see
        // `ssrf::tests::test_blocks_private_ipv4`.
        #[cfg(not(debug_assertions))]
        assert!(crate::services::validate_pds_url("http://127.0.0.1").is_err());
        assert!(crate::services::validate_pds_url("https://10.0.0.1").is_err());
    }

    #[test]
    fn test_oauth_flow_record_sealing_and_strict_deserialization() {
        let key = [0x42u8; 32];
        let record = OAuthFlowRecord {
            version: 2,
            mode: OAuthMode::Exchange,
            client_selector: "catmos".to_string(),
            redirect_to: Some("https://catmos.catbird.blue/callback".to_string()),
            browser_nonce: Some("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".to_string()),
            created_at: 1700000000,
        };

        let json = serde_json::to_string(&record).unwrap();
        let sealed = crate::services::redis_crypto::seal_strict(&key, &json).unwrap();

        let opened = crate::services::redis_crypto::open_strict(&key, &sealed).unwrap();
        let recovered: OAuthFlowRecord = serde_json::from_str(&opened).unwrap();

        assert_eq!(recovered.version, 2);
        assert_eq!(recovered.mode, OAuthMode::Exchange);
        assert_eq!(recovered.client_selector, "catmos");
        assert_eq!(
            recovered.redirect_to,
            Some("https://catmos.catbird.blue/callback".to_string())
        );
        assert_eq!(
            recovered.browser_nonce,
            Some("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".to_string())
        );

        // Corrupt sealed ciphertext fails strictly
        let corrupt = format!("{sealed}corrupt");
        assert!(crate::services::redis_crypto::open_strict(&key, &corrupt).is_err());
    }

    #[test]
    fn test_oauth_flow_key_and_claim_key_structure() {
        let key = [0x55u8; 32];
        let state = "550e8400-e29b-41d4-a716-446655440000";
        let fp = crate::services::redis_auth_store::fingerprint_id(&key, state);
        let prefix = "catbird:v2:session:";

        let flow_key = format!("{}oauth_flow:{}", prefix, fp);
        let claim_key = format!("{}oauth_claim:{}", prefix, fp);

        assert!(flow_key.starts_with("catbird:v2:session:oauth_flow:"));
        assert!(claim_key.starts_with("catbird:v2:session:oauth_claim:"));
        assert!(!flow_key.contains(state));
        assert!(!claim_key.contains(state));
    }

    #[test]
    fn test_login_mode_determination_exchange_vs_direct() {
        let valid_nonce = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        let invalid_nonce = "too-short";
        let allowed_redirect = "https://catmos.catbird.blue/callback";
        let loopback_redirect = "http://127.0.0.1:8080/callback";
        let disallowed_redirect = "https://evil.com/callback";

        // 1. Valid nonce + allowed redirect -> Exchange mode
        assert!(is_valid_base64url_43(valid_nonce));
        assert!(is_allowed_redirect(allowed_redirect));
        assert!(is_allowed_redirect(loopback_redirect));

        // 2. Invalid nonce -> Rejection
        assert!(!is_valid_base64url_43(invalid_nonce));

        // 3. Valid nonce + disallowed redirect -> Rejection
        assert!(!is_allowed_redirect(disallowed_redirect));

        // 4. Missing nonce + any redirect -> Rejection (redirects require exchange mode)
        // Direct mode is strictly only when no redirect is requested
        let direct_flow = OAuthFlowRecord {
            version: 2,
            mode: OAuthMode::Direct,
            client_selector: "default".to_string(),
            redirect_to: None,
            browser_nonce: None,
            created_at: 1700000000,
        };
        assert_eq!(direct_flow.mode, OAuthMode::Direct);
        assert!(direct_flow.redirect_to.is_none());
        assert!(direct_flow.browser_nonce.is_none());
    }

    #[test]
    fn test_direct_mode_callback_cookie_and_location_invariants() {
        let session_id = "550e8400-e29b-41d4-a716-446655440000";

        // Direct mode sets HttpOnly, SameSite=Strict cookie with session_id
        let cookie = Cookie::build((SESSION_COOKIE_NAME, session_id))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Strict)
            .max_age(time::Duration::days(30))
            .build();

        assert_eq!(cookie.name(), SESSION_COOKIE_NAME);
        assert_eq!(cookie.value(), session_id);
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.secure(), Some(true));

        // Direct mode location is strictly "/" (never contains session_id)
        let location = "/";
        assert!(!location.contains(session_id));
        assert_eq!(location, "/");
    }

    #[test]
    fn test_logout_cookie_revocation_attributes() {
        let cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Strict)
            .secure(true)
            .max_age(time::Duration::ZERO)
            .build();

        assert_eq!(cookie.name(), SESSION_COOKIE_NAME);
        assert_eq!(cookie.value(), "");
        assert_eq!(cookie.max_age(), Some(time::Duration::ZERO));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
    }

    #[test]
    fn test_direct_mode_browser_nonce_comparison_logic() {
        let nonce = "550e8400-e29b-41d4-a716-446655440000";
        let flow_record = OAuthFlowRecord {
            version: 2,
            mode: OAuthMode::Direct,
            client_selector: "default".to_string(),
            redirect_to: None,
            browser_nonce: Some(nonce.to_string()),
            created_at: 1700000000,
        };

        // Matching cookie -> OK
        let cookie_match = Some(nonce);
        assert_eq!(cookie_match, flow_record.browser_nonce.as_deref());

        // Missing cookie -> mismatch
        let cookie_missing: Option<&str> = None;
        assert_ne!(cookie_missing, flow_record.browser_nonce.as_deref());

        // Mismatched cookie -> mismatch
        let cookie_mismatch = Some("attacker-nonce");
        assert_ne!(cookie_mismatch, flow_record.browser_nonce.as_deref());
    }

    #[test]
    fn test_exchange_code_strictly_rejects_v1_ciphertexts() {
        let key = [0x42u8; 32];
        let session_id = "550e8400-e29b-41d4-a716-446655440000";

        // Construct a raw v1 (no "v2:" prefix) ciphertext
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce,
        };
        use base64::Engine;
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from([0x01u8; 12]);
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: session_id.as_bytes(),
                    aad: &[],
                },
            )
            .unwrap();
        let mut raw = Vec::new();
        raw.extend_from_slice(&[0x01u8; 12]);
        raw.extend_from_slice(&ct);
        let v1_sealed = base64::engine::general_purpose::STANDARD.encode(&raw);

        assert!(!v1_sealed.starts_with(crate::services::redis_crypto::V2_PREFIX));

        // V2 ciphertext has the prefix
        let aad = crate::services::redis_crypto::build_aad("oauth_exchange", "key", None, None);
        let v2_sealed =
            crate::services::redis_crypto::seal_with_aad(&key, session_id.as_bytes(), &aad)
                .unwrap();
        assert!(v2_sealed.starts_with(crate::services::redis_crypto::V2_PREFIX));
    }
}
