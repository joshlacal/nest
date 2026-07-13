//! ATProto Handlers
//!
//! Request handlers for ATProto proxy endpoints including:
//! - OAuth flow (login, callback, logout)
//! - XRPC proxy

#[path = "exchange_store.rs"]
mod exchange_store;

use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, RawQuery, State},
    http::{HeaderMap, Method, StatusCode},
    response::Response,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::metrics;
use crate::middleware::JacquardDpopData;
use crate::middleware::SESSION_COOKIE_NAME;
use crate::models::{CatbirdSession, LogoutResponse, OAuthCallback, SessionInfo};
use crate::services::{AtProtoClient, MlsAuthService, ProxyResponse};
use exchange_store::{ExchangeError, ExchangeStore};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRequest {
    code: String,
    browser_nonce: String,
}

#[derive(Debug, Serialize)]
pub struct ExchangeResponse {
    session_id: String,
}

fn parse_exchange_request(body: &[u8]) -> Result<ExchangeRequest, ExchangeError> {
    let request: ExchangeRequest =
        serde_json::from_slice(body).map_err(|_| ExchangeError::Unauthorized)?;
    if request.code.len() != 43
        || !request
            .code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !(16..=256).contains(&request.browser_nonce.len())
    {
        return Err(ExchangeError::Unauthorized);
    }
    Ok(request)
}

fn exchange_store(state: &AppState) -> Result<ExchangeStore, AppError> {
    let keyring = state
        .auth_store
        .as_ref()
        .ok_or_else(|| AppError::Internal("OAuth exchange unavailable".into()))?
        .encryption_keyring();
    Ok(ExchangeStore::new(
        state.redis.clone(),
        state.config.redis.key_prefix.clone(),
        keyring,
    ))
}

fn legacy_callback_allowed() -> bool {
    static DEADLINE: std::sync::OnceLock<Option<chrono::DateTime<chrono::FixedOffset>>> =
        std::sync::OnceLock::new();
    DEADLINE
        .get_or_init(|| {
            std::env::var("OAUTH_LEGACY_CALLBACK_UNTIL")
                .ok()
                .and_then(|deadline| chrono::DateTime::parse_from_rfc3339(&deadline).ok())
        })
        .as_ref()
        .map(|deadline| deadline > &chrono::Utc::now())
        .unwrap_or(false)
}

#[cfg(test)]
fn legacy_callback_allowed_at(deadline: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    chrono::DateTime::parse_from_rfc3339(deadline)
        .map(|deadline| deadline > now)
        .unwrap_or(false)
}

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
    let store = exchange_store(&state)?;

    if let Some(nonce) = browser_nonce.as_deref() {
        if nonce.len() < 16 || nonce.len() > 256 {
            return Err(AppError::BadRequest("Invalid browser nonce".into()));
        }
    } else if !legacy_callback_allowed() {
        return Err(AppError::BadRequest("Browser nonce required".into()));
    }
    store
        .store_init(
            &session_nonce,
            browser_nonce.as_deref(),
            redirect_to.as_deref(),
            client_selector,
        )
        .await
        .map_err(|error| match error {
            ExchangeError::Unauthorized | ExchangeError::Missing => {
                AppError::BadRequest("Invalid OAuth flow".into())
            }
            ExchangeError::Unavailable => AppError::Internal("OAuth exchange unavailable".into()),
        })?;

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
    let store = exchange_store(&state)?;
    let legacy_allowed = legacy_callback_allowed();
    // Consume all initiation state atomically before any terminal callback path.
    let (exchange_init, legacy_init) = match store.take_init(&callback.state).await {
        Ok(init) => (Some(init), None),
        Err(ExchangeError::Missing) if legacy_allowed => {
            let legacy =
                store
                    .take_legacy_init(&callback.state)
                    .await
                    .map_err(|error| match error {
                        ExchangeError::Unauthorized | ExchangeError::Missing => {
                            AppError::OAuth("OAuth exchange failed".into())
                        }
                        ExchangeError::Unavailable => {
                            AppError::Internal("OAuth exchange unavailable".into())
                        }
                    })?;
            (None, legacy)
        }
        Err(ExchangeError::Unauthorized) => {
            return Err(AppError::OAuth("OAuth exchange failed".into()))
        }
        Err(ExchangeError::Missing) => return Err(AppError::OAuth("OAuth exchange failed".into())),
        Err(ExchangeError::Unavailable) => {
            return Err(AppError::Internal("OAuth exchange unavailable".into()))
        }
    };
    let redirect_to = exchange_init
        .as_ref()
        .and_then(|init| init.redirect_target.clone())
        .or_else(|| {
            legacy_init
                .as_ref()
                .and_then(|init| init.redirect_target.clone())
        });

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
        let target = redirect_to
            .as_deref()
            .and_then(|r| redirect_with_query(r, "error", err))
            .unwrap_or_else(|| format!("https://catbird.blue/oauth/callback#error={}", err));
        return Ok((
            jar,
            Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", target)
                .body(Body::empty())
                .unwrap(),
        ));
    };

    // Determine which Jacquard client to use.
    // Preferred: the selector persisted at login time.
    // Legacy fallback (for sessions started before this deploy OR the old
    // JSON-state format): infer from redirect_to presence or JSON-state
    // payload. Remove once in-flight legacy sessions have drained from
    // prod logs.
    let client_selector = exchange_init
        .as_ref()
        .map(|init| init.client_selector.as_str())
        .or_else(|| {
            legacy_init
                .as_ref()
                .map(|init| init.client_selector.as_str())
        });
    let is_catmos = match client_selector {
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
            tracing::info!("No OAuth client selector in Redis; using bounded legacy inference");
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
        state: Some(callback.state.clone().into()),
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
    let handle = resolve_handle_for_did(&state, &did, &pds_url).await;
    tracing::info!("Resolved handle for DID {}: {}", &did, &handle);

    // Record successful OAuth login
    metrics::record_oauth_login(true);

    let (app_redirect, jar) = if exchange_init
        .as_ref()
        .and_then(|init| init.nonce_hash.as_ref())
        .is_some()
    {
        let init = exchange_init.expect("checked exchange init");
        let exchange_code = store
            .issue(&session_id, init)
            .await
            .map_err(|_| AppError::Internal("OAuth exchange unavailable".into()))?;
        let target = redirect_to
            .as_deref()
            .unwrap_or("https://catbird.blue/oauth/callback");
        let redirect = redirect_with_query(target, "code", &exchange_code)
            .ok_or_else(|| AppError::OAuth("Invalid OAuth redirect".into()))?;
        (redirect, jar)
    } else if legacy_allowed {
        metrics::record_oauth_exchange("legacy_callback");
        let cookie = session_cookie(&session_id);
        let redirect =
            legacy_success_redirect(redirect_to.as_deref(), &callback.state, &session_id)
                .ok_or_else(|| AppError::OAuth("Invalid OAuth redirect".into()))?;
        (redirect, jar.add(cookie))
    } else {
        return Err(AppError::OAuth("OAuth exchange failed".into()));
    };

    Ok((
        jar,
        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", app_redirect)
            .body(Body::empty())
            .unwrap(),
    ))
}

fn session_cookie(session_id: &str) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, session_id.to_string()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::days(30))
        .build()
}

/// Atomically redeem a short-lived callback exchange code.
pub async fn exchange_oauth_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> AppResult<(CookieJar, Json<ExchangeResponse>)> {
    let unauthorized = || AppError::Unauthorized("OAuth exchange failed".into());
    let body = body.map_err(|_| unauthorized())?;
    let request = match parse_exchange_request(&body) {
        Ok(request) => request,
        Err(_) => {
            metrics::record_oauth_exchange("rejected");
            return Err(unauthorized());
        }
    };
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|origin| origin.len() <= 256)
        .ok_or_else(unauthorized)?;
    let redemption = exchange_store(&state)?
        .redeem(&request.code, &request.browser_nonce, origin)
        .await;
    let session_id = match redemption {
        Ok(session_id) => {
            metrics::record_oauth_exchange("success");
            session_id
        }
        Err(ExchangeError::Unauthorized | ExchangeError::Missing) => {
            metrics::record_oauth_exchange("rejected");
            return Err(AppError::Unauthorized("OAuth exchange failed".into()));
        }
        Err(ExchangeError::Unavailable) => {
            metrics::record_oauth_exchange("unavailable");
            return Err(AppError::Internal("OAuth exchange unavailable".into()));
        }
    };
    let cookie = session_cookie(&session_id);
    Ok((jar.add(cookie), Json(ExchangeResponse { session_id })))
}

/// Resolve a handle for a DID by calling com.atproto.repo.describeRepo on the PDS.
async fn resolve_handle_for_did(state: &AppState, did: &str, pds_url: &str) -> String {
    let describe_url = format!(
        "{}/xrpc/com.atproto.repo.describeRepo?repo={}",
        pds_url.trim_end_matches('/'),
        did
    );

    match state
        .outbound_policy
        .send_discovery(
            reqwest::Method::GET,
            &describe_url,
            reqwest::header::HeaderMap::new(),
            None,
        )
        .await
    {
        Ok((status, _, body)) if status.is_success() => {
            match serde_json::from_slice::<serde_json::Value>(&body) {
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

/// Allowed redirect origins for OAuth callback (beyond localhost).
const ALLOWED_REDIRECT_ORIGINS: &[&str] = &[
    "https://catbird.blue",
    "https://catmos.catbird.blue",
    "https://catmos.pages.dev",
];

/// Build the redirect URL after OAuth callback.
/// Redirect-target allowlist shared by the success and deny/cancel paths:
/// local dev loopback, known production origins, and catmos.pages.dev previews.
fn is_allowed_redirect(r: &str) -> bool {
    let Ok(url) = url::Url::parse(r) else {
        return false;
    };

    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return false;
    }

    let Some(host) = url.host_str() else {
        return false;
    };

    match url.scheme() {
        "https" => {
            url.port_or_known_default() == Some(443)
                && (ALLOWED_REDIRECT_ORIGINS.iter().any(|origin| {
                    url::Url::parse(origin)
                        .ok()
                        .and_then(|allowed| allowed.host_str().map(|allowed| allowed == host))
                        .unwrap_or(false)
                }) || host.ends_with(".catmos.pages.dev"))
        }
        "http" => explicit_loopback_port(r).is_some(),
        _ => false,
    }
}

fn explicit_loopback_port(target: &str) -> Option<u16> {
    let authority = target
        .strip_prefix("http://")?
        .split(['/', '?', '#'])
        .next()?;
    let port = authority
        .strip_prefix("127.0.0.1:")
        .or_else(|| authority.strip_prefix("[::1]:"))?;

    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let port = port.parse::<u32>().ok()?;
    (1..=u16::MAX as u32).contains(&port).then_some(port as u16)
}

fn redirect_with_query(target: &str, key: &str, value: &str) -> Option<String> {
    if !is_allowed_redirect(target) {
        return None;
    }

    let mut url = url::Url::parse(target).ok()?;
    url.query_pairs_mut().append_pair(key, value);
    Some(url.into())
}

fn legacy_success_redirect(
    redirect_to: Option<&str>,
    state: &str,
    session_id: &str,
) -> Option<String> {
    match redirect_to {
        Some(target) => redirect_with_query(target, "session_id", session_id),
        None => Some(build_app_redirect(state, session_id)),
    }
}

fn build_app_redirect(state_str: &str, session_id: &str) -> String {
    if state_str.starts_with('{') {
        if let Ok(state_json) = serde_json::from_str::<serde_json::Value>(state_str) {
            if let Some(redirect_to) = state_json.get("redirect_to").and_then(|v| v.as_str()) {
                if let Some(target) = redirect_with_query(redirect_to, "session_id", session_id) {
                    return target;
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

    // Check if this is an MLS lexicon and direct routing is enabled
    let mls_service = MlsAuthService::new(state.clone());
    if MlsAuthService::is_mls_lexicon(&lexicon) && mls_service.is_enabled() {
        tracing::debug!(
            request_id = %request_id,
            lexicon = %lexicon,
            user = %session.did,
            "Routing MLS request directly to MLS service"
        );

        let (status, response_headers, response_body) = mls_service
            .proxy_request(
                &session,
                method.try_into().unwrap_or(reqwest::Method::GET),
                &lexicon,
                query_string.as_deref(),
                body_option,
                content_type,
            )
            .await?;

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

#[cfg(test)]
mod redirect_tests {
    use super::{
        build_app_redirect, is_allowed_redirect, legacy_callback_allowed_at,
        legacy_success_redirect, parse_exchange_request, redirect_with_query,
    };

    #[test]
    fn redirect_allowlist_accepts_supported_catmos_targets() {
        let accepted = [
            "https://catmos.catbird.blue/callback",
            "https://catmos.pages.dev/auth/callback?client=web",
            "https://pr-42.catmos.pages.dev/callback",
            "http://127.0.0.1:1420/callback",
            "http://127.0.0.1:80/callback",
            "http://[::1]:49152/auth/callback",
            "http://[::1]:80/auth/callback",
        ];

        for target in accepted {
            assert!(is_allowed_redirect(target), "expected to allow {target}");
        }
    }

    #[test]
    fn redirect_allowlist_rejects_untrusted_authorities_and_schemes() {
        let rejected = [
            "https://catmos.catbird.blue.evil.example/callback",
            "https://catmos.pages.dev@evil.example/callback",
            "https://user@catmos.catbird.blue/callback",
            "http://127.0.0.1:1420@evil.example/callback",
            "http://pr-42.catmos.pages.dev/callback",
            "https://pr-42.catmos.pages.dev:8443/callback",
            "http://localhost:1420/callback",
            "http://192.168.1.10:1420/callback",
            "http://127.0.0.1/callback",
            "http://[::1]/callback",
            "http://127.0.0.1:0/callback",
            "http://[::1]:0/callback",
            "http://127.1:1420/callback",
            "http://2130706433:1420/callback",
            "https://evilcatmos.pages.dev/callback",
            "https://catmos.catbird.blue/callback#fragment",
        ];

        for target in rejected {
            assert!(!is_allowed_redirect(target), "expected to reject {target}");
        }
    }

    #[test]
    fn callback_parameters_are_encoded_and_preserve_existing_query() {
        assert_eq!(
            redirect_with_query(
                "https://catmos.catbird.blue/auth/callback?client=web",
                "error",
                "access denied&retry=false",
            ),
            Some(
                "https://catmos.catbird.blue/auth/callback?client=web&error=access+denied%26retry%3Dfalse"
                    .to_string()
            )
        );
    }

    #[test]
    fn exchange_callback_url_contains_code_but_never_session_credential() {
        let location = redirect_with_query(
            "https://catmos.catbird.blue/auth/callback",
            "code",
            "opaque-exchange-code",
        )
        .unwrap();
        assert!(location.contains("code=opaque-exchange-code"));
        assert!(!location.contains("session_id"));
        assert!(!location.contains("live-session-credential"));
    }

    #[test]
    fn legacy_redirect_uses_the_same_validation_policy() {
        let allowed_state = serde_json::json!({
            "redirect_to": "https://preview.catmos.pages.dev/auth/callback"
        })
        .to_string();
        assert_eq!(
            build_app_redirect(&allowed_state, "session value"),
            "https://preview.catmos.pages.dev/auth/callback?session_id=session+value"
        );

        let rejected_state = serde_json::json!({
            "redirect_to": "https://catmos.pages.dev@evil.example/callback"
        })
        .to_string();
        assert_eq!(
            build_app_redirect(&rejected_state, "secret"),
            "https://catbird.blue/oauth/callback#session_id=secret"
        );
    }

    #[test]
    fn default_legacy_redirect_keeps_session_credentials_in_fragment() {
        let location = legacy_success_redirect(None, "opaque-state", "session secret").unwrap();
        assert_eq!(
            location,
            "https://catbird.blue/oauth/callback#session_id=session secret"
        );
        assert!(!location.contains("?session_id="));
    }

    #[test]
    fn legacy_callback_window_is_explicit_and_bounded() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-12T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(legacy_callback_allowed_at("2026-07-12T12:00:01Z", now));
        assert!(!legacy_callback_allowed_at("2026-07-12T12:00:00Z", now));
        assert!(!legacy_callback_allowed_at("not-a-deadline", now));
    }

    #[test]
    fn malformed_exchange_shapes_share_one_rejection() {
        let valid_code = "A".repeat(43);
        let cases = [
            "not-json".to_string(),
            serde_json::json!({"code": valid_code, "browser_nonce": "short"}).to_string(),
            serde_json::json!({"code": "bad!", "browser_nonce": "0123456789abcdef"}).to_string(),
            serde_json::json!({"code": "A".repeat(43), "browser_nonce": "0123456789abcdef", "extra": true}).to_string(),
        ];
        for body in cases {
            assert_eq!(
                parse_exchange_request(body.as_bytes())
                    .unwrap_err()
                    .to_string(),
                "exchange failed"
            );
        }
    }
}
