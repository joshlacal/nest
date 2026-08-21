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
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::metrics;
use crate::middleware::JacquardDpopData;
use crate::middleware::SESSION_COOKIE_NAME;
use crate::models::{
    CatbirdSession, ExchangeRequest, ExchangeResponse, LogoutResponse, OAuthCallback,
    SessionInfo,
};
use crate::services::{AtProtoClient, MlsAuthService, ProxyResponse};

/// Handle login initiation (Redirect flow)
///
/// GET /auth/login?identifier=user.bsky.social&client=catmos
pub async fn login(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> AppResult<Response> {
    let identifier = params
        .get("identifier")
        .or_else(|| params.get("pds"))
        .or_else(|| params.get("issuer"))
        .ok_or_else(|| AppError::BadRequest("Missing identifier".into()))?;
    let client = params.get("client").cloned();
    let redirect_to = params.get("redirect_to").cloned();
    let browser_nonce = params.get("browser_nonce").cloned();

    // Select the appropriate OAuth client based on the client parameter.
    // The chosen selector is persisted to Redis so the callback handler can
    // redeem the authorization code with the EXACT same client_id that
    // initiated the PAR request (PDS binds codes to client_id).
    let is_catmos = matches!(client.as_deref(), Some("catmos-web") | Some("catmos"));
    let client_selector = if is_catmos { "catmos" } else { "default" };

    // FIX 3: The native callback (ALLOWED_EXACT_REDIRECT_URLS) is valid ONLY in
    // exchange-code mode. If requested without browser_nonce, reject with 400.
    if let Some(ref r) = redirect_to {
        if ALLOWED_EXACT_REDIRECT_URLS.contains(&r.as_str()) && browser_nonce.is_none() {
            return Err(AppError::BadRequest(
                "Native callback requires browser_nonce".into(),
            ));
        }
    }

    // ADR-014 validations BEFORE any Redis write or PDS redirect:
    // If browser_nonce is supplied:
    // 1. Encryption key MUST be configured (fail closed, no plaintext fallback)
    // 2. Must be exactly 43 base64url characters
    // 3. redirect_to must be present
    // 4. redirect_to must pass is_allowed_redirect
    if let Some(ref nonce) = browser_nonce {
        if state.session_encryption_key.is_none() {
            return Err(AppError::Internal(
                "Session encryption key not configured; cannot admit exchange flow".into(),
            ));
        }
        if !is_valid_base64url_43(nonce) {
            return Err(AppError::BadRequest(
                "Invalid browser_nonce: must be exactly 43 base64url characters".into(),
            ));
        }
        let Some(ref r) = redirect_to else {
            return Err(AppError::BadRequest(
                "Missing redirect_to: required when browser_nonce is supplied".into(),
            ));
        };
        if !is_allowed_redirect(r) {
            return Err(AppError::BadRequest("Disallowed redirect_to URL".into()));
        }
    }
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

    use jacquard_oauth::types::AuthorizeOptions;

    // Generate a clean UUID for the OAuth state (= Jacquard session_id).
    let session_nonce = uuid::Uuid::new_v4().to_string();

    // Persist session state to Redis.
    // Contract Rule 2: Fail closed in exchange mode on ANY persistence error.
    // FIX 4: Persist explicit oauth_mode:"exchange" marker for admitted exchange flows.
    // Absent browser_nonce: maintain legacy tolerant error handling.
    if let Some(ref nonce) = browser_nonce {
        let mut conn = state.redis.clone();

        // 1. oauth_mode marker
        let mode_key = format!("oauth_mode:{}", session_nonce);
        redis::cmd("SET")
            .arg(&mode_key)
            .arg("exchange")
            .arg("EX")
            .arg(600)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to persist oauth_mode: {}", e)))?;

        // 2. oauth_client
        let client_key = format!("oauth_client:{}", session_nonce);
        redis::cmd("SET")
            .arg(&client_key)
            .arg(client_selector)
            .arg("EX")
            .arg(600)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to persist oauth_client: {}", e)))?;

        // 3. oauth_redirect
        if let Some(ref r) = redirect_to {
            let redirect_key = format!("oauth_redirect:{}", session_nonce);
            redis::cmd("SET")
                .arg(&redirect_key)
                .arg(r.as_str())
                .arg("EX")
                .arg(600)
                .query_async::<_, ()>(&mut conn)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to persist oauth_redirect: {}", e)))?;
        }

        // 4. oauth_nonce
        let nonce_key = format!("oauth_nonce:{}", session_nonce);
        redis::cmd("SET")
            .arg(&nonce_key)
            .arg(nonce.as_str())
            .arg("EX")
            .arg(600)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to persist oauth_nonce: {}", e)))?;
    } else {
        {
            let mut conn = state.redis.clone();
            let key = format!("oauth_client:{}", session_nonce);
            if let Err(e) = redis::cmd("SET")
                .arg(&key)
                .arg(client_selector)
                .arg("EX")
                .arg(600)
                .query_async::<_, ()>(&mut conn)
                .await
            {
                // Don't fail login — callback will fall back to legacy inference.
                tracing::warn!(
                    "Failed to persist oauth_client selector to Redis: {}",
                    e
                );
            }
        }

        // Store redirect_to in Redis so the callback can look it up.
        if let Some(ref r) = redirect_to {
            let mut conn = state.redis.clone();
            let key = format!("oauth_redirect:{}", session_nonce);
            let _: Result<(), _> = redis::cmd("SET")
                .arg(&key)
                .arg(r.as_str())
                .arg("EX")
                .arg(600) // 10 minute TTL
                .query_async(&mut conn)
                .await;
        }
    }

    let options = AuthorizeOptions {
        state: Some(session_nonce.into()),
        ..Default::default()
    };

    let auth_url = jacquard_client
        .start_auth(identifier, options)
        .await
        .map_err(|e| AppError::OAuth(format!("Authorization failed: {}", e)))?;

    // Redirect to the PDS authorization URL
    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", auth_url.as_str())
        .body(Body::empty())
        .unwrap())
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

    // FIX 4: Check if this session was admitted as an exchange flow
    let stored_mode: Option<String> = {
        let mut conn = state.redis.clone();
        let key = format!("oauth_mode:{}", &callback.state);
        redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .ok()
    };
    if stored_mode.is_some() {
        let mut conn = state.redis.clone();
        let key = format!("oauth_mode:{}", &callback.state);
        let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
    }

    // Check if this session has a stored redirect_to
    let redirect_to: Option<String> = {
        let mut conn = state.redis.clone();
        let key = format!("oauth_redirect:{}", &callback.state);
        redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .ok()
    };
    // Clean up the redirect key (one-time use)
    if redirect_to.is_some() {
        let mut conn = state.redis.clone();
        let key = format!("oauth_redirect:{}", &callback.state);
        let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
    }

    // Check if this session has a stored browser_nonce (ADR-014 exchange flow)
    let stored_nonce: Option<String> = {
        let mut conn = state.redis.clone();
        let key = format!("oauth_nonce:{}", &callback.state);
        redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .ok()
    };
    // Clean up the nonce key (one-time use)
    if stored_nonce.is_some() {
        let mut conn = state.redis.clone();
        let key = format!("oauth_nonce:{}", &callback.state);
        let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
    }
    // Deny/cancel path: the provider redirects back without a code
    // (RFC 6749 §4.1.2.1 — `error` + optional `error_description` instead).
    let Some(code) = callback.code else {
        let err = callback.error.as_deref().unwrap_or("access_denied");
        tracing::info!(
            error = err,
            description = callback.error_description.as_deref().unwrap_or(""),
            "OAuth callback without authorization code; aborting login"
        );
        metrics::record_oauth_login(false);
        // The selector key is one-time; the flow is dead, so drop it.
        let mut conn = state.redis.clone();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(format!("oauth_client:{}", &callback.state))
            .query_async(&mut conn)
            .await;
        let target = match redirect_to.as_deref() {
            Some(r) if is_allowed_redirect(r) => format!("{}?error={}", r, err),
            _ => format!("https://catbird.blue/oauth/callback#error={}", err),
        };
        return Ok((
            jar,
            Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", target)
                .body(Body::empty())
                .unwrap(),
        ));
    };

    // Read back the client selector persisted by the login handler. This is
    // the authoritative source for which jacquard_client to use — the PDS
    // binds the authorization code to the client_id that issued the PAR
    // request, so login and callback MUST use the same client.
    let stored_selector: Option<String> = {
        let mut conn = state.redis.clone();
        let key = format!("oauth_client:{}", &callback.state);
        redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .ok()
    };
    // Clean up the selector key (one-time use)
    if stored_selector.is_some() {
        let mut conn = state.redis.clone();
        let key = format!("oauth_client:{}", &callback.state);
        let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
    }

    // Determine which Jacquard client to use.
    // Preferred: the selector persisted at login time.
    // Legacy fallback (for sessions started before this deploy OR the old
    // JSON-state format): infer from redirect_to presence or JSON-state
    // payload. Remove once in-flight legacy sessions have drained from
    // prod logs.
    let is_catmos = match stored_selector.as_deref() {
        Some("catmos") => true,
        Some("default") => false,
        Some(other) => {
            tracing::warn!(
                "Unrecognized oauth_client selector {:?} in Redis; falling back to legacy inference",
                other
            );
            legacy_infer_catmos(&redirect_to, &callback.state)
        }
        None => {
            tracing::info!(
                "No oauth_client selector in Redis for state {}; using legacy inference (pre-deploy in-flight session or JSON-state legacy)",
                &callback.state
            );
            legacy_infer_catmos(&redirect_to, &callback.state)
        }
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
        state: Some(callback.state.into()),
        iss: callback.iss.map(|s| s.into()),
    };

    let oauth_session = jacquard_client
        .callback(params)
        .await
        .map_err(|e| AppError::OAuth(format!("Callback failed: {}", e)))?;

    // Jacquard stores the session in RedisAuthStore automatically.
    // Extract the session_id (now a clean UUID) and DID from the session data.
    let session_data = oauth_session.data.read().await;
    let did = session_data.account_did.as_str().to_string();
    let session_id = session_data.session_id.to_string();
    let pds_url = session_data.host_url.to_string();
    drop(session_data);

    // Resolve handle from DID
    let handle = resolve_handle_for_did(&did, &pds_url).await;
    tracing::info!("Resolved handle for DID {}: {}", &did, &handle);

    // Record successful OAuth login
    metrics::record_oauth_login(true);

    // Set cookie — session_id is the Jacquard state/session identifier (clean UUID)
    let cookie = Cookie::build((SESSION_COOKIE_NAME, session_id.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::days(30))
        .build();

    // Mode selection (Contract Rule 1 & FIX 4):
    // If the flow was admitted in exchange mode (stored_mode == "exchange"),
    // it MUST complete in exchange mode or FAIL CLOSED (refusing downgrade).
    let is_exchange_mode = stored_mode.as_deref() == Some("exchange");

    let app_redirect = if is_exchange_mode {
        let (Some(ref r), Some(ref nonce)) = (&redirect_to, &stored_nonce) else {
            tracing::error!("Exchange flow state missing from Redis for state");
            return Err(AppError::Internal(
                "Exchange flow state missing; refusing downgrade to session-bearing redirect".into(),
            ));
        };

        if !is_allowed_redirect(r) || !is_valid_base64url_43(nonce) {
            tracing::error!("Exchange flow state invalid for state");
            return Err(AppError::Internal(
                "Exchange flow state invalid; refusing downgrade to session-bearing redirect".into(),
            ));
        }

        let canonical_origin = canonicalize_origin(r)
            .ok_or_else(|| AppError::Internal("Invalid redirect_to origin".into()))?;

        let exchange_code = generate_exchange_code();
        let exchange_key = compute_exchange_redis_key(&exchange_code, nonce, &canonical_origin);

        // FIX 1 + FIX 2 (Amended): Seal session_id directly with AES-256-GCM (fail closed, no fallback).
        let enc_key = state.session_encryption_key.as_ref().ok_or_else(|| {
            AppError::Internal("Session encryption key required for exchange record".into())
        })?;
        let sealed_session_id = crate::services::redis_crypto::seal(enc_key, session_id.as_bytes())
            .map_err(|e| AppError::Internal(format!("Failed to seal session_id: {}", e)))?;

        let mut conn = state.redis.clone();
        redis::cmd("SET")
            .arg(&exchange_key)
            .arg(&sealed_session_id)
            .arg("EX")
            .arg(60) // 60s TTL
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to store exchange key in Redis: {}", e)))?;
        format!("{}?code={}", r, exchange_code)
    } else if let Some(ref r) = redirect_to {
        // catmos-web: redirect_to was stored in Redis during login (no browser_nonce)
        if is_allowed_redirect(r) {
            format!("{}?session_id={}", r, session_id)
        } else {
            tracing::warn!("Rejected redirect_to from Redis: {}", r);
            format!(
                "https://catbird.blue/oauth/callback#session_id={}",
                session_id
            )
        }
    } else {
        // Legacy / iOS: no redirect_to stored in Redis
        build_app_redirect(&session_id, &session_id)
    };
    Ok((
        jar.add(cookie),
        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", app_redirect)
            .body(Body::empty())
            .unwrap(),
    ))
}

/// Resolve a handle for a DID by calling com.atproto.repo.describeRepo on the PDS.
async fn resolve_handle_for_did(did: &str, pds_url: &str) -> String {
    let describe_url = format!(
        "{}/xrpc/com.atproto.repo.describeRepo?repo={}",
        pds_url.trim_end_matches('/'),
        did
    );

    match reqwest::get(&describe_url).await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(json) => json
                .get("handle")
                .and_then(|h| h.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| did.to_string()),
            Err(_) => did.to_string(),
        },
        _ => did.to_string(),
    }
}

/// Legacy inference of the catmos client from callback signals.
///
/// Used only when `oauth_client:{state}` is absent from Redis (in-flight
/// sessions started before the selector-persistence fix deployed, or the old
/// JSON-state callback format). Should be removed after enough time has
/// passed for any in-flight sessions to drain (600s TTL + safety margin).
fn legacy_infer_catmos(redirect_to: &Option<String>, state_str: &str) -> bool {
    redirect_to.is_some()
        || (state_str.starts_with('{')
            && serde_json::from_str::<serde_json::Value>(state_str)
                .ok()
                .and_then(|v| {
                    v.get("client")
                        .and_then(|c| c.as_str())
                        .map(|c| c == "catmos-web" || c == "catmos")
                })
                .unwrap_or(false))
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

pub fn build_app_redirect(state_str: &str, session_id: &str) -> String {
    if state_str.starts_with('{') {
        if let Ok(state_json) = serde_json::from_str::<serde_json::Value>(state_str) {
            if let Some(redirect_to) = state_json.get("redirect_to").and_then(|v| v.as_str()) {
                if is_allowed_redirect(redirect_to) {
                    return format!("{}?session_id={}", redirect_to, session_id);
                }
                tracing::warn!("Rejected redirect_to: {}", redirect_to);
            }
        }
    }
    format!(
        "https://catbird.blue/oauth/callback#session_id={}",
        session_id
    )
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

    // Revoke via Jacquard (handles token revocation at auth server + store cleanup)
    let did = jacquard_common::types::did::Did::new(&session.did)
        .map_err(|e| AppError::Internal(format!("Invalid DID: {e}")))?;

    if let Err(e) = jacquard_client.revoke(&did, &session.id.to_string()).await {
        tracing::warn!("Failed to revoke Jacquard session: {}", e);
        // Continue with logout even if revocation fails
    }

    let cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .max_age(time::Duration::ZERO)
        .build();

    tracing::info!("User {} logged out successfully", session.did);

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
    let exchange_key = compute_exchange_redis_key(&payload.code, &payload.browser_nonce, &canonical_origin);

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

    let plaintext_bytes = crate::services::redis_crypto::open(enc_key, &sealed_b64).map_err(|e| {
        tracing::warn!("Exchange failed: decryption failed: {}", e);
        AppError::Unauthorized("Invalid exchange request".into())
    })?;

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
pub fn compute_exchange_redis_key(code: &str, browser_nonce: &str, canonical_origin: &str) -> String {
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
    s.len() == 43 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
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
    match redis::cmd("GETDEL").arg(key).query_async::<_, Option<String>>(conn).await {
        Ok(val) => Ok(val),
        Err(err) if err.to_string().contains("unknown command") => {
            let script = redis::Script::new(r#"
                local val = redis.call('GET', KEYS[1])
                if val then
                    redis.call('DEL', KEYS[1])
                end
                return val
            "#);
            script.key(key).invoke_async(conn).await
        }
        Err(err) => Err(err),
    }
}

/// Proxy XRPC requests to the user's PDS. MLS v2 uses the standard ATProto
/// service-proxy path; Nest never mints MLS authorization.
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

    if MlsAuthService::is_retired_chat_lexicon(&lexicon) {
        return Ok(Response::builder()
            .status(StatusCode::UPGRADE_REQUIRED)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "error": "ProtocolUpgradeRequired",
                    "message": "This MLS protocol version or endpoint is retired"
                })
                .to_string(),
            ))
            .unwrap());
    }

    if lexicon == "blue.catbird.chat.subscribeEvents" {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "error": "InvalidRequest",
                    "message": "subscribeEvents is a direct WebSocket transport authenticated via getSubscriptionTicket; direct HTTP proxying is not supported"
                })
                .to_string(),
            ))
            .unwrap());
    }

    let mut upstream_headers = headers.clone();
    if MlsAuthService::is_active_chat_http_lexicon(&lexicon) {
        let chat = &state.config.chat;
        let is_canary = chat.enabled && chat.canary_dids.iter().any(|did| did == &session.did);
        if !is_canary {
            return Ok(Response::builder()
                .status(StatusCode::UPGRADE_REQUIRED)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "error": "ProtocolUpgradeRequired",
                        "message": "MLS v2 standard AppView access is not enabled for this account"
                    })
                    .to_string(),
                ))
                .unwrap());
        }
        if chat.service_ref != "did:web:chat.catbird.blue#atproto_mls" {
            return Err(AppError::Internal(
                "CHAT_SERVICE_REF must equal did:web:chat.catbird.blue#atproto_mls".into(),
            ));
        }
        upstream_headers.insert(
            "atproto-proxy",
            reqwest::header::HeaderValue::from_static("did:web:chat.catbird.blue#atproto_mls"),
        );
    } else if MlsAuthService::is_clean_chat_lexicon(&lexicon) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "error": "InvalidRequest",
                    "message": "This chat endpoint is not supported for HTTP proxying"
                })
                .to_string(),
            ))
            .unwrap());
    }

    // Default: proxy through PDS
    let path = format!("/xrpc/{}", lexicon);
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
            Some(&upstream_headers),
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
        } => {
            let response_shape = json_shape(&response_body);
            tracing::info!(
                request_id = %request_id,
                status = status,
                body_bytes = response_body.len(),
                body_shape = ?response_shape,
                "[BFF-RESP] PDS response (buffered)"
            );

            // Log error response bodies for debugging (truncated, no PII)
            if status >= 400 {
                if let Ok(error_text) = std::str::from_utf8(&response_body) {
                    let truncated = if error_text.len() > 200 {
                        &error_text[..200]
                    } else {
                        error_text
                    };
                    tracing::warn!(
                        request_id = %request_id,
                        status = status,
                        error_body = %truncated,
                        "[BFF-RESP-ERR] PDS error response body"
                    );
                }
            }

            if (200..300).contains(&status) {
                if let Err(err) = mirror_push_mutation_if_needed(
                    &state,
                    &session,
                    jacquard_dpop.as_ref(),
                    &lexicon,
                    &body_bytes,
                )
                .await
                {
                    tracing::warn!(
                        lexicon = %lexicon,
                        user = %session.did,
                        error = %err,
                        "Failed to mirror push moderation mutation"
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
        } => {
            tracing::info!(
                request_id = %request_id,
                status = status,
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

            // Stream the response body directly from upstream
            let stream = upstream_response.bytes_stream();
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

async fn mirror_push_mutation_if_needed(
    state: &Arc<AppState>,
    session: &CatbirdSession,
    jacquard_dpop: Option<&JacquardDpopData>,
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
        "app.bsky.graph.muteActor" => {
            if let Some(actor) = body.get("actor").and_then(|value| value.as_str()) {
                push.moderation_cache
                    .upsert_actor_mute(&session.did, actor)
                    .await?;
            }
        }
        "app.bsky.graph.unmuteActor" => {
            if let Some(actor) = body.get("actor").and_then(|value| value.as_str()) {
                push.moderation_cache
                    .remove_actor_mute(&session.did, actor)
                    .await?;
            }
        }
        "app.bsky.graph.muteActorList" => {
            if let (Some(list), Some(dpop)) = (
                body.get("list").and_then(|value| value.as_str()),
                jacquard_dpop,
            ) {
                push.moderation_cache
                    .sync_list_subscription(state, session, dpop, list, "curatelist")
                    .await?;
            }
        }
        "app.bsky.graph.unmuteActorList" => {
            if let Some(list) = body.get("list").and_then(|value| value.as_str()) {
                push.moderation_cache
                    .remove_list_subscription(&session.did, list)
                    .await?;
            }
        }
        "app.bsky.graph.muteThread" => {
            if let Some(root) = body.get("root").and_then(|value| value.as_str()) {
                push.moderation_cache
                    .mute_thread(&session.did, root)
                    .await?;
            }
        }
        "app.bsky.graph.unmuteThread" => {
            if let Some(root) = body.get("root").and_then(|value| value.as_str()) {
                push.moderation_cache
                    .unmute_thread(&session.did, root)
                    .await?;
            }
        }
        "com.atproto.repo.createRecord" => {
            if let Some(collection) = body.get("collection").and_then(|value| value.as_str()) {
                match collection {
                    "app.bsky.graph.block" => {
                        if let Some(subject) = body
                            .get("record")
                            .and_then(|value| value.get("subject"))
                            .and_then(|value| value.as_str())
                        {
                            push.moderation_cache
                                .upsert_actor_block(&session.did, subject)
                                .await?;
                        }
                    }
                    "app.bsky.graph.listblock" => {
                        if let (Some(subject), Some(dpop)) = (
                            body.get("record")
                                .and_then(|value| value.get("subject"))
                                .and_then(|value| value.as_str()),
                            jacquard_dpop,
                        ) {
                            push.moderation_cache
                                .sync_list_subscription(state, session, dpop, subject, "modlist")
                                .await?;
                        }
                    }
                    _ => {}
                }
            }
        }
        "com.atproto.repo.deleteRecord" => {
            if let (Some(collection), Some(dpop)) = (
                body.get("collection").and_then(|value| value.as_str()),
                jacquard_dpop,
            ) {
                match collection {
                    "app.bsky.graph.block" => {
                        push.moderation_cache
                            .refresh_actor_relationships_for_session(state, session, dpop)
                            .await?;
                    }
                    "app.bsky.graph.listblock" => {
                        push.moderation_cache
                            .refresh_list_relationships_for_session(state, session, dpop)
                            .await?;
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    Ok(())
}
