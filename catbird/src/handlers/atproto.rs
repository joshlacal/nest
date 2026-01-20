//! ATProto Handlers
//!
//! Request handlers for ATProto proxy endpoints including:
//! - OAuth flow (login, callback, logout)
//! - XRPC proxy

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::Response,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::SESSION_COOKIE_NAME;
use crate::models::{
    CatbirdSession, LoginRequest, LoginResponse, LogoutResponse, OAuthCallback,
    SessionInfo,
};
use crate::services::{AtProtoClient, SessionService};

/// Handle login initiation (Redirect flow)
///
/// GET /auth/login?identifier=user.bsky.social
pub async fn login(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> AppResult<Response> {
    let identifier = params.get("identifier").ok_or_else(|| AppError::BadRequest("Missing identifier".into()))?;
    tracing::info!("Login request for identifier: {}", identifier);

    let oauth_client = state.oauth_client.as_ref()
        .ok_or_else(|| AppError::Internal("OAuthClient not initialized".into()))?;

    use atrium_oauth::{AuthorizeOptions, KnownScope, Scope};
    
    let options = AuthorizeOptions {
        scopes: vec![
            Scope::Known(KnownScope::Atproto),
            Scope::Known(KnownScope::TransitionGeneric),
        ],
        ..Default::default()
    };

    let auth_url = oauth_client.authorize(identifier, options).await
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

    let oauth_client = state.oauth_client.as_ref()
        .ok_or_else(|| AppError::Internal("OAuthClient not initialized".into()))?;

    use atrium_oauth::CallbackParams;
    
    let params = CallbackParams {
        code: callback.code,
        state: Some(callback.state),
        iss: callback.iss,
    };

    let (oauth_session, _app_state) = oauth_client.callback(params).await
        .map_err(|e| AppError::OAuth(format!("Callback failed: {}", e)))?;

    // Create our own Catbird session
    use atrium_api::agent::SessionManager;
    let did = oauth_session.did().await
        .ok_or_else(|| AppError::OAuth("Failed to get DID from session".into()))?
        .to_string();
    
    let session_id = Uuid::new_v4();
    let now = Utc::now();

    let session = CatbirdSession {
        id: session_id,
        did: did.clone(),
        handle: did.clone(),
        pds_url: "".to_string(),
        access_token: "managed_by_atrium".to_string(),
        refresh_token: "managed_by_atrium".to_string(),
        access_token_expires_at: now + Duration::days(1),
        created_at: now,
        last_used_at: now,
        dpop_jkt: None,
    };

    let session_service = SessionService::new(state.clone());
    session_service.save_session(&session).await?;

    // Set cookie
    let cookie = Cookie::build((SESSION_COOKIE_NAME, session_id.to_string()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::days(30))
        .build();

    // Redirect to App Scheme with session_id (optional, mostly for confirmation)
    // The cookie is the real auth artifact, but the app needs to close the browser window.
    // Scheme: catbird://gateway-success?session_id=...
    let app_redirect = format!("catbird://gateway-success?session_id={}", session_id);

    Ok((
        jar.add(cookie),
        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", app_redirect)
            .body(Body::empty())
            .unwrap()
    ))
}

/// Handle logout
///
/// POST /auth/logout
pub async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<LogoutResponse>)> {
    let session_service = SessionService::new(state.clone());
    session_service.delete_session(&session.id.to_string()).await?;

    // TODO: Also revoke via OAuthClient.revoke()

    let cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .max_age(time::Duration::ZERO)
        .build();

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

/// Proxy XRPC requests to the user's PDS
pub async fn proxy_xrpc(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    method: Method,
    Path(lexicon): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> AppResult<Response> {
    let path = format!("/xrpc/{}", lexicon);
    tracing::debug!("Proxying {} {} to {}", method, path, session.pds_url);

    let query_string = if params.is_empty() {
        None
    } else {
        Some(
            params.iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&"),
        )
    };

    let content_type = headers.get("content-type").and_then(|h| h.to_str().ok());

    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024).await
        .map_err(|e| AppError::BadRequest(format!("Failed to read body: {}", e)))?;
    
    let body_option = if body_bytes.is_empty() { None } else { Some(body_bytes) };

    let client = AtProtoClient::new(state.clone());
    let (status, response_headers, response_body) = client
        .proxy_request(&session, method, &path, query_string.as_deref(), body_option, content_type)
        .await?;

    let mut response = Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (name, value) in response_headers.iter() {
        let name_str = name.as_str();
        if matches!(name_str, "content-type" | "content-length" | "cache-control" | "etag" | "last-modified") {
            response = response.header(name, value);
        }
    }

    Ok(response.body(Body::from(response_body)).unwrap())
}
