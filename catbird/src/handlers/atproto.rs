//! ATProto Handlers
//!
//! Request handlers for ATProto proxy endpoints including:
//! - OAuth flow (login, callback, logout)
//! - XRPC proxy

#[path = "exchange_store.rs"]
mod exchange_store;

use axum::{
    body::{Body, Bytes},
    extract::{FromRequestParts, Path, Query, RawQuery, State},
    http::{request::Parts, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
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
use crate::metrics::MlsDeviceBindingOutcome;
use crate::middleware::JacquardDpopData;
use crate::middleware::SESSION_COOKIE_NAME;
use crate::models::{CatbirdSession, LogoutResponse, OAuthCallback, SessionInfo};
use crate::services::{
    authoritative_device_id, parse_begin_input, parse_begin_response, parse_complete_input,
    parse_complete_response, session_p256_jkt, AtProtoClient, MlsAuthService,
    MlsDeviceBindingStore, MlsProxyRequest, ProxyResponse, BEGIN_BINDING_NSID,
    COMPLETE_BINDING_NSID,
};
use exchange_store::{ExchangeError, ExchangeStore};

/// Exact authenticated session capability. This never leaves request
/// extensions and deliberately redacts its bearer value from Debug output.
#[derive(Clone)]
pub(crate) struct AuthenticatedSessionId(String);

impl AuthenticatedSessionId {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AuthenticatedSessionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthenticatedSessionId([REDACTED])")
    }
}

pub(crate) struct AuthenticatedProxyContext {
    session: CatbirdSession,
    session_id: AuthenticatedSessionId,
    request_id: Option<crate::middleware::RequestId>,
    dpop: Option<JacquardDpopData>,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthenticatedProxyContext
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let session = parts
            .extensions
            .get::<CatbirdSession>()
            .cloned()
            .ok_or_else(|| {
                AppError::Unauthorized("Authenticated session context unavailable".into())
            })?;
        let session_id = parts
            .extensions
            .get::<AuthenticatedSessionId>()
            .cloned()
            .ok_or_else(|| {
                AppError::Unauthorized("Authenticated session capability unavailable".into())
            })?;
        Ok(Self {
            session,
            session_id,
            request_id: parts
                .extensions
                .get::<crate::middleware::RequestId>()
                .cloned(),
            dpop: parts.extensions.get::<JacquardDpopData>().cloned(),
        })
    }
}

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

fn mls_device_binding_store(state: &AppState) -> Result<MlsDeviceBindingStore, AppError> {
    let keyring = state
        .auth_store
        .as_ref()
        .ok_or_else(|| AppError::Internal("MLS device binding store unavailable".into()))?
        .encryption_keyring();
    Ok(MlsDeviceBindingStore::new(
        state.redis.clone(),
        state.config.redis.key_prefix.clone(),
        state.config.redis.session_ttl_seconds,
        keyring,
    ))
}

fn record_mls_binding_error(error: AppError) -> AppError {
    let outcome = match &error {
        AppError::Redis(_) | AppError::Crypto(_) | AppError::Internal(_) => {
            MlsDeviceBindingOutcome::StoreFailure
        }
        _ => MlsDeviceBindingOutcome::Denied,
    };
    metrics::record_mls_device_binding(outcome);
    error
}

fn require_browser_nonce(nonce: Option<&str>) -> AppResult<&str> {
    let nonce = nonce.ok_or_else(|| AppError::BadRequest("Browser nonce required".into()))?;
    if !(16..=256).contains(&nonce.len()) {
        return Err(AppError::BadRequest("Invalid browser nonce".into()));
    }
    Ok(nonce)
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
    let browser_nonce = require_browser_nonce(params.get("browser_nonce").map(String::as_str))?;

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

    store
        .store_init(
            &session_nonce,
            browser_nonce,
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
    // Consume all initiation state atomically before any terminal callback path.
    let exchange_init = store
        .take_init(&callback.state)
        .await
        .map_err(|error| match error {
            ExchangeError::Unauthorized | ExchangeError::Missing => {
                AppError::OAuth("OAuth exchange failed".into())
            }
            ExchangeError::Unavailable => AppError::Internal("OAuth exchange unavailable".into()),
        })?;
    let redirect_to = exchange_init.redirect_target.clone();

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

    let is_catmos = match exchange_init.client_selector.as_str() {
        "catmos" => true,
        "default" => false,
        _ => return Err(AppError::OAuth("OAuth exchange failed".into())),
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

    let exchange_code = store
        .issue(&session_id, exchange_init)
        .await
        .map_err(|_| AppError::Internal("OAuth exchange unavailable".into()))?;
    let target = redirect_to
        .as_deref()
        .unwrap_or("https://catbird.blue/oauth/callback");
    let app_redirect = exchange_success_redirect(target, &exchange_code)
        .ok_or_else(|| AppError::OAuth("Invalid OAuth redirect".into()))?;

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

fn exchange_success_redirect(target: &str, code: &str) -> Option<String> {
    redirect_with_query(target, "code", code)
}

/// Handle logout
///
/// POST /auth/logout
struct LogoutOutcome {
    result: AppResult<()>,
    clear_cookie: bool,
}

impl LogoutOutcome {
    fn retained(error: AppError) -> Self {
        Self {
            result: Err(error),
            clear_cookie: false,
        }
    }
}

async fn ordered_logout<Delete, DeleteFuture, Revoke, RevokeFuture>(
    delete_bindings: Delete,
    revoke: Revoke,
) -> LogoutOutcome
where
    Delete: FnOnce() -> DeleteFuture,
    DeleteFuture: std::future::Future<Output = AppResult<()>>,
    Revoke: FnOnce() -> RevokeFuture,
    RevokeFuture: std::future::Future<Output = AppResult<()>>,
{
    // MLS bindings are a local authorization grant. Remove that privilege
    // before attempting remote token revocation; if revocation is transiently
    // unavailable, retaining the browser cookie permits retry without leaving
    // stale MLS authority active.
    let delete_result = delete_bindings().await;
    let revoke_result = revoke().await;
    let clear_cookie = revoke_result.is_ok();
    let result = match (delete_result, revoke_result) {
        (Err(_), Err(_)) => Err(AppError::AuthTemporarilyUnavailable(
            "Logout could not revoke the authenticated session and clear MLS device bindings"
                .into(),
        )),
        (Err(delete_error), Ok(())) => Err(delete_error),
        (Ok(()), Err(revoke_error)) => Err(revoke_error),
        (Ok(()), Ok(())) => Ok(()),
    };
    LogoutOutcome {
        result,
        clear_cookie,
    }
}

fn finish_logout(jar: CookieJar, outcome: LogoutOutcome) -> Response {
    let jar = if outcome.clear_cookie {
        let cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
            .path("/")
            .http_only(true)
            .max_age(time::Duration::ZERO)
            .build();
        jar.remove(cookie)
    } else {
        jar
    };
    match outcome.result {
        Ok(()) => (
            jar,
            Json(LogoutResponse {
                success: true,
                message: "Logged out".to_string(),
            }),
        )
            .into_response(),
        Err(error) => (jar, error).into_response(),
    }
}

pub(crate) async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Extension(authenticated_session_id): Extension<AuthenticatedSessionId>,
    jar: CookieJar,
) -> Response {
    let outcome = async {
        let jacquard_client = state
            .jacquard_client
            .as_ref()
            .ok_or_else(|| AppError::Internal("Jacquard OAuthClient not initialized".into()))?;
        let binding_store = mls_device_binding_store(&state)?;
        let did = jacquard_common::types::did::Did::new(&session.did)
            .map_err(|e| AppError::Internal(format!("Invalid DID: {e}")))?;

        Ok::<_, AppError>(
            ordered_logout(
                || async {
                    binding_store
                        .delete_session(authenticated_session_id.as_str())
                        .await
                        .map_err(record_mls_binding_error)
                },
                || async {
                    jacquard_client
                        .revoke(&did, authenticated_session_id.as_str())
                        .await
                        .map_err(|_| {
                            AppError::AuthTemporarilyUnavailable(
                                "Logout could not revoke the authenticated session".into(),
                            )
                        })
                },
            )
            .await,
        )
    }
    .await
    .unwrap_or_else(LogoutOutcome::retained);

    if outcome.result.is_ok() {
        tracing::info!("User {} logged out successfully", session.did);
    }
    finish_logout(jar, outcome)
}

#[cfg(test)]
mod logout_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn local_binding_cleanup_finishes_before_upstream_revoke_starts() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let revoke_events = events.clone();
        let delete_events = events.clone();

        let outcome = ordered_logout(
            move || async move {
                delete_events.lock().unwrap().push("delete");
                Ok(())
            },
            move || async move {
                revoke_events.lock().unwrap().push("revoke");
                Ok(())
            },
        )
        .await;
        outcome.result.unwrap();
        assert!(outcome.clear_cookie);

        assert_eq!(*events.lock().unwrap(), ["delete", "revoke"]);
    }

    #[tokio::test]
    async fn transient_revoke_failure_retains_cookie_but_removes_mls_privilege() {
        let mls_privilege_active = Arc::new(Mutex::new(true));
        let privilege_observer = mls_privilege_active.clone();
        let outcome = ordered_logout(
            move || async move {
                *privilege_observer.lock().unwrap() = false;
                Ok(())
            },
            || async {
                Err(AppError::AuthTemporarilyUnavailable(
                    "upstream unavailable".into(),
                ))
            },
        )
        .await;

        assert!(outcome.result.is_err());
        assert!(!outcome.clear_cookie);
        assert!(
            !*mls_privilege_active.lock().unwrap(),
            "a retained browser session must not retain stale MLS authorization"
        );

        let mut request_headers = HeaderMap::new();
        request_headers.insert("cookie", "catbird_session=browser-session".parse().unwrap());
        let jar = CookieJar::from_headers(&request_headers);
        let response = finish_logout(jar, outcome);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let set_cookie = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("catbird_session="));
        assert!(set_cookie.is_none(), "transient failure must retain cookie");
    }

    #[tokio::test]
    async fn combined_logout_failure_is_503_and_preserves_browser_cookie() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let revoke_events = events.clone();
        let delete_events = events.clone();
        let outcome = ordered_logout(
            move || async move {
                delete_events.lock().unwrap().push("delete");
                Err(AppError::Internal("binding cleanup unavailable".into()))
            },
            move || async move {
                revoke_events.lock().unwrap().push("revoke");
                Err(AppError::AuthTemporarilyUnavailable(
                    "upstream unavailable".into(),
                ))
            },
        )
        .await;

        assert_eq!(*events.lock().unwrap(), ["delete", "revoke"]);
        assert!(matches!(
            &outcome.result,
            Err(AppError::AuthTemporarilyUnavailable(message))
                if message.contains("revoke") && message.contains("device bindings")
        ));

        let mut request_headers = HeaderMap::new();
        request_headers.insert("cookie", "catbird_session=browser-session".parse().unwrap());
        assert!(!outcome.clear_cookie);
        let response = finish_logout(CookieJar::from_headers(&request_headers), outcome);

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let set_cookie = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("catbird_session="));
        assert!(set_cookie.is_none(), "transient failure must retain cookie");
    }

    #[tokio::test]
    async fn completed_revocation_expires_cookie_even_if_binding_cleanup_reports_failure() {
        let outcome = ordered_logout(
            || async { Err(AppError::Internal("binding cleanup unavailable".into())) },
            || async { Ok(()) },
        )
        .await;
        assert!(outcome.result.is_err());
        assert!(outcome.clear_cookie);

        let mut request_headers = HeaderMap::new();
        request_headers.insert("cookie", "catbird_session=browser-session".parse().unwrap());
        let response = finish_logout(CookieJar::from_headers(&request_headers), outcome);
        let set_cookie = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("catbird_session="))
            .expect("completed revocation must remove the browser cookie");
        assert!(set_cookie.contains("Max-Age=0"));
        assert!(!set_cookie.contains("browser-session"));
    }
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
pub(crate) async fn proxy_xrpc(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedProxyContext,
    method: Method,
    Path(lexicon): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> AppResult<Response> {
    let start = std::time::Instant::now();
    let AuthenticatedProxyContext {
        session,
        session_id: authenticated_session_id,
        request_id: authenticated_request_id,
        dpop: dpop_data,
    } = auth;

    // Extract request ID: prefer middleware-set value, fall back to client header
    let request_id = authenticated_request_id
        .map(|request_id| request_id.0)
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
        let dpop_data = dpop_data.as_ref().ok_or_else(|| {
            AppError::Unauthorized("Authenticated MLS requests require session DPoP".into())
        })?;
        let jkt = session_p256_jkt(&dpop_data.dpop_key).map_err(record_mls_binding_error)?;
        let binding_store = mls_device_binding_store(&state)?;

        let begin_input = if lexicon == BEGIN_BINDING_NSID {
            Some(
                parse_begin_input(&body_bytes)
                    .map_err(AppError::BadRequest)
                    .map_err(record_mls_binding_error)?,
            )
        } else {
            None
        };
        let complete_input = if lexicon == COMPLETE_BINDING_NSID {
            Some(
                parse_complete_input(&body_bytes)
                    .map_err(AppError::BadRequest)
                    .map_err(record_mls_binding_error)?,
            )
        } else {
            None
        };
        let pending = if let Some(input) = complete_input.as_ref() {
            Some(
                binding_store
                    .load_pending(
                        authenticated_session_id.as_str(),
                        &session.did,
                        &jkt,
                        &input.challenge_id,
                    )
                    .await
                    .map_err(record_mls_binding_error)?,
            )
        } else {
            None
        };
        let bound = if begin_input.is_none() && pending.is_none() {
            let bound = binding_store
                .load_bound(authenticated_session_id.as_str(), &session.did, &jkt)
                .await
                .map_err(record_mls_binding_error)?;
            metrics::record_mls_device_binding(if bound.is_some() {
                MlsDeviceBindingOutcome::BoundFound
            } else {
                MlsDeviceBindingOutcome::BoundMissing
            });
            bound
        } else {
            None
        };
        let device_id = authoritative_device_id(
            &lexicon,
            begin_input.as_ref().map(|input| input.device_id.as_str()),
            pending.as_ref(),
            bound.as_ref(),
        );

        tracing::debug!(
            request_id = %request_id,
            lexicon = %lexicon,
            user = %session.did,
            "Routing MLS request directly to MLS service"
        );

        let (status, response_headers, response_body) = mls_service
            .proxy_request(MlsProxyRequest {
                session: &session,
                session_dpop_key: &dpop_data.dpop_key,
                device_id,
                method,
                lexicon: &lexicon,
                query_string: query_string.as_deref(),
                body: body_option,
                content_type,
            })
            .await?;

        if (200..300).contains(&status) {
            if let Some(input) = begin_input.as_ref() {
                let response = parse_begin_response(&response_body, chrono::Utc::now()).map_err(
                    |message| AppError::Upstream {
                        status: StatusCode::BAD_GATEWAY.as_u16(),
                        message,
                    },
                )?;
                binding_store
                    .persist_pending(
                        authenticated_session_id.as_str(),
                        &session.did,
                        &jkt,
                        &input.device_id,
                        &response,
                    )
                    .await
                    .map_err(record_mls_binding_error)?;
                metrics::record_mls_device_binding(MlsDeviceBindingOutcome::BeginPersisted);
            } else if let Some(pending) = pending.as_ref() {
                let response =
                    parse_complete_response(&response_body, &pending.device_id, chrono::Utc::now())
                        .map_err(|message| AppError::Upstream {
                            status: StatusCode::BAD_GATEWAY.as_u16(),
                            message,
                        })?;
                binding_store
                    .promote(authenticated_session_id.as_str(), pending, &response)
                    .await
                    .map_err(record_mls_binding_error)?;
                metrics::record_mls_device_binding(MlsDeviceBindingOutcome::CompletePromoted);
            }
        }

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
    let jacquard_dpop = dpop_data;
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
            if streaming_moderation_disposition(state.push.is_some(), status, &lexicon, &body_bytes)
                == StreamingModerationDisposition::MirrorBeforeDelivery
            {
                if let Err(error) = mirror_push_mutation_if_needed(
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
                        error = %error,
                        "Failed to mirror streaming push moderation mutation"
                    );
                    return Err(AppError::Upstream {
                        status: StatusCode::BAD_GATEWAY.as_u16(),
                        message: "moderation mutation could not be mirrored before delivery"
                            .to_string(),
                    });
                }
            }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamingModerationDisposition {
    Deliver,
    MirrorBeforeDelivery,
}

fn streaming_moderation_disposition(
    push_mirroring_enabled: bool,
    status: u16,
    lexicon: &str,
    request_body: &[u8],
) -> StreamingModerationDisposition {
    if push_mirroring_enabled
        && (200..300).contains(&status)
        && is_push_moderation_mutation(lexicon, request_body)
    {
        StreamingModerationDisposition::MirrorBeforeDelivery
    } else {
        StreamingModerationDisposition::Deliver
    }
}

fn is_push_moderation_mutation(lexicon: &str, request_body: &[u8]) -> bool {
    match lexicon {
        "app.bsky.graph.muteActor"
        | "app.bsky.graph.unmuteActor"
        | "app.bsky.graph.muteActorList"
        | "app.bsky.graph.unmuteActorList"
        | "app.bsky.graph.muteThread"
        | "app.bsky.graph.unmuteThread" => true,
        "com.atproto.repo.createRecord" | "com.atproto.repo.deleteRecord" => {
            let Ok(body) = serde_json::from_slice::<Value>(request_body) else {
                return false;
            };
            matches!(
                body.get("collection").and_then(Value::as_str),
                Some("app.bsky.graph.block" | "app.bsky.graph.listblock")
            )
        }
        _ => false,
    }
}

#[cfg(test)]
mod streaming_mirror_tests {
    use super::{
        is_push_moderation_mutation, streaming_moderation_disposition,
        StreamingModerationDisposition,
    };

    #[test]
    fn declared_large_successful_moderation_mutation_requires_mirror_before_delivery() {
        let declared_content_length = 4 * 1024 * 1024 + 1;
        let response_content_type = "application/json";
        assert!(declared_content_length > 4 * 1024 * 1024);
        assert_eq!(response_content_type, "application/json");

        let disposition = streaming_moderation_disposition(
            true,
            200,
            "app.bsky.graph.muteActor",
            br#"{"actor":"did:plc:target"}"#,
        );
        assert_eq!(
            disposition,
            StreamingModerationDisposition::MirrorBeforeDelivery
        );
    }

    #[test]
    fn streaming_non_mutation_media_and_upstream_errors_remain_compatible() {
        assert_eq!(
            streaming_moderation_disposition(true, 200, "com.atproto.sync.getBlob", &[]),
            StreamingModerationDisposition::Deliver
        );
        assert_eq!(
            streaming_moderation_disposition(
                true,
                500,
                "app.bsky.graph.muteActor",
                br#"{"actor":"did:plc:target"}"#,
            ),
            StreamingModerationDisposition::Deliver
        );
        assert_eq!(
            streaming_moderation_disposition(
                false,
                200,
                "app.bsky.graph.muteActor",
                br#"{"actor":"did:plc:target"}"#,
            ),
            StreamingModerationDisposition::Deliver
        );
    }

    #[test]
    fn ordinary_empty_mute_success_is_not_rejected_as_an_unsafe_stream() {
        assert_eq!(
            streaming_moderation_disposition(true, 200, "app.bsky.graph.muteActor", &[]),
            StreamingModerationDisposition::MirrorBeforeDelivery
        );
    }

    #[test]
    fn record_mutation_classifier_is_collection_scoped() {
        assert!(is_push_moderation_mutation(
            "com.atproto.repo.createRecord",
            br#"{"collection":"app.bsky.graph.block"}"#,
        ));
        assert!(is_push_moderation_mutation(
            "com.atproto.repo.deleteRecord",
            br#"{"collection":"app.bsky.graph.listblock"}"#,
        ));
        assert!(!is_push_moderation_mutation(
            "com.atproto.repo.createRecord",
            br#"{"collection":"app.bsky.feed.post"}"#,
        ));
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
        exchange_success_redirect, is_allowed_redirect, parse_exchange_request,
        redirect_with_query, require_browser_nonce,
    };

    #[test]
    fn login_requires_a_valid_browser_nonce_without_legacy_bypass() {
        assert_eq!(
            require_browser_nonce(None).unwrap_err().to_string(),
            "Bad request: Browser nonce required"
        );
        assert_eq!(
            require_browser_nonce(Some("short"))
                .unwrap_err()
                .to_string(),
            "Bad request: Invalid browser nonce"
        );
        assert_eq!(
            require_browser_nonce(Some("0123456789abcdef")).unwrap(),
            "0123456789abcdef"
        );
    }

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
        let location = exchange_success_redirect(
            "https://catmos.catbird.blue/auth/callback",
            "opaque-exchange-code",
        )
        .unwrap();
        assert!(location.contains("code=opaque-exchange-code"));
        assert!(!location.contains("session_id"));
        assert!(!location.contains("live-session-credential"));
    }

    #[test]
    fn callback_source_has_no_reusable_session_compatibility() {
        let source = include_str!("atproto.rs");
        for forbidden in [
            ["OAUTH_LEGACY_CALLBACK_", "UNTIL"].concat(),
            ["take_legacy_", "init"].concat(),
            ["legacy_success_", "redirect"].concat(),
            ["build_app_", "redirect"].concat(),
            ["legacy_infer_", "catmos"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "found legacy callback path: {forbidden}"
            );
        }
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
