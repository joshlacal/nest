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
use base64::Engine;
use chrono::{Duration, Utc};
use redis::AsyncCommands;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::SESSION_COOKIE_NAME;
use crate::models::{
    CatbirdSession, DPoPKeyPair, LoginRequest, LoginResponse, LogoutResponse, OAuthCallback,
    SessionInfo,
};
use crate::services::{oauth::RedisSessionStore, AtProtoClient, MlsAuthService, SessionService};

/// Handle login initiation (Redirect flow)
///
/// GET /auth/login?identifier=user.bsky.social
pub async fn login(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> AppResult<Response> {
    let identifier = params
        .get("identifier")
        .or_else(|| params.get("pds"))
        .or_else(|| params.get("issuer"))
        .ok_or_else(|| AppError::BadRequest("Missing identifier".into()))?;
    tracing::info!("Login request for identifier: {}", identifier);

    let oauth_client = state
        .oauth_client
        .as_ref()
        .ok_or_else(|| AppError::Internal("OAuthClient not initialized".into()))?;

    use atrium_oauth::{AuthorizeOptions, KnownScope, Scope};

    let options = AuthorizeOptions {
        scopes: vec![
            Scope::Known(KnownScope::Atproto),
            Scope::Known(KnownScope::TransitionGeneric),
            Scope::Known(KnownScope::TransitionChatBsky),
        ],
        ..Default::default()
    };

    let auth_url = oauth_client
        .authorize(identifier, options)
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

    let oauth_client = state
        .oauth_client
        .as_ref()
        .ok_or_else(|| AppError::Internal("OAuthClient not initialized".into()))?;

    use atrium_oauth::CallbackParams;

    let params = CallbackParams {
        code: callback.code,
        state: Some(callback.state),
        iss: callback.iss,
    };

    let (oauth_session, _app_state) = oauth_client
        .callback(params)
        .await
        .map_err(|e| AppError::OAuth(format!("Callback failed: {}", e)))?;

    // Create our own Catbird session
    use atrium_api::agent::SessionManager;
    let did = oauth_session
        .did()
        .await
        .ok_or_else(|| AppError::OAuth("Failed to get DID from session".into()))?
        .to_string();

    // Read the issued token set + DPoP key from atrium's RedisSessionStore
    use atrium_api::types::string::Did;
    use atrium_common::store::Store;

    let did_typed: Did = did
        .parse()
        .map_err(|_| AppError::OAuth(format!("Invalid DID from session: {did}")))?;

    let session_store = RedisSessionStore::new(
        state.redis.clone(),
        state.config.redis.key_prefix.clone(),
    );

    let atrium_session = session_store
        .get(&did_typed)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read OAuth session: {e}")))?
        .ok_or_else(|| AppError::Internal("OAuth session missing after callback".into()))?;

    // Persist DPoP private key for request signing
    // ATProto OAuth always uses DPoP, so we extract and store the key
    let dpop_jkt = {
        let jwk_value = serde_json::to_value(&atrium_session.dpop_key)
            .map_err(|e| AppError::Internal(format!("Failed to serialize DPoP key: {e}")))?;

        let d_b64 = jwk_value
            .get("d")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("DPoP key missing private component".into()))?;

        let d_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(d_b64)
            .map_err(|e| AppError::Internal(format!("Invalid DPoP key encoding: {e}")))?;

        let private_key_bytes: [u8; 32] = d_bytes
            .try_into()
            .map_err(|_| AppError::Internal("Invalid DPoP key length".into()))?;

        let mut public_jwk = jwk_value;
        if let Some(obj) = public_jwk.as_object_mut() {
            obj.remove("d");
        }

        let dpop_pair = DPoPKeyPair {
            public_jwk,
            private_key_bytes,
        };

        // Generate session_id first so we can key the DPoP by session, not DID
        // This allows multiple devices per account
        let session_id = Uuid::new_v4();

        // Store DPoP key by session_id (not DID) to support multiple devices
        let redis_key = format!(
            "{}dpop_key:{}",
            state.config.redis.key_prefix,
            session_id
        );
        let json = serde_json::to_string(&dpop_pair)
            .map_err(|e| AppError::Internal(format!("Failed to serialize DPoP keypair: {e}")))?;

        let mut conn = state.redis.clone();
        conn.set_ex::<_, _, ()>(&redis_key, json, state.config.redis.session_ttl_seconds)
            .await?;

        // Also store OAuth session by session_id for per-device token refresh
        let oauth_session_key = format!(
            "{}oauth_session:{}",
            state.config.redis.key_prefix,
            session_id
        );
        let oauth_session_json = serde_json::to_string(&atrium_session)
            .map_err(|e| AppError::Internal(format!("Failed to serialize OAuth session: {e}")))?;
        conn.set_ex::<_, _, ()>(&oauth_session_key, oauth_session_json, state.config.redis.session_ttl_seconds)
            .await?;

        (Some("dpop".to_string()), session_id)
    };

    let session_id = dpop_jkt.1;
    let dpop_jkt = dpop_jkt.0;
    let now = Utc::now();

    let access_token_expires_at = atrium_session
        .token_set
        .expires_at
        .as_ref()
        .map(|dt| dt.as_ref().with_timezone(&Utc))
        .unwrap_or_else(|| now + Duration::seconds(3600));

    let session = CatbirdSession {
        id: session_id,
        did: did.clone(),
        handle: did.clone(),
        pds_url: atrium_session.token_set.aud.clone(),
        access_token: atrium_session.token_set.access_token.clone(),
        refresh_token: atrium_session
            .token_set
            .refresh_token
            .clone()
            .unwrap_or_default(),
        access_token_expires_at,
        created_at: now,
        last_used_at: now,
        dpop_jkt,
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

    // Redirect back to the app via Universal Link (iOS Associated Domains)
    // Note: the cookie is still set for browser-based clients; mobile should use the session_id.
    // Use a URL fragment so the session token isn't sent to catbird.blue (avoids access logs/referrers).
    let app_redirect = format!("https://catbird.blue/oauth/callback#session_id={}", session_id);

    Ok((
        jar.add(cookie),
        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", app_redirect)
            .body(Body::empty())
            .unwrap(),
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
    
    // Revoke the OAuth session at the authorization server and clean up locally
    if let Err(e) = session_service.revoke_session(&session).await {
        tracing::warn!("Failed to revoke OAuth session: {}", e);
        // Continue with logout even if revocation fails
    }

    // Also clean up the DPoP key and session-scoped OAuth session from Redis
    let dpop_key = format!(
        "{}dpop_key:{}",
        state.config.redis.key_prefix, session.id
    );
    let oauth_session_key = format!(
        "{}oauth_session:{}",
        state.config.redis.key_prefix, session.id
    );
    let mut conn = state.redis.clone();
    let _: Result<(), _> = conn.del(&dpop_key).await;
    let _: Result<(), _> = conn.del(&oauth_session_key).await;

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
    method: Method,
    Path(lexicon): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> AppResult<Response> {
    // Extract request ID from client for end-to-end correlation
    let request_id = headers
        .get("x-catbird-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

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
        Some(body_bytes)
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
    let (status, response_headers, response_body) = client
        .proxy_request(
            &session,
            method,
            &path,
            query_string.as_deref(),
            body_option,
            content_type,
            Some(&headers),
            &request_id,
        )
        .await?;

    let response_shape = json_shape(&response_body);
    tracing::info!(
        request_id = %request_id,
        status = status,
        body_bytes = response_body.len(),
        body_shape = ?response_shape,
        "[BFF-RESP] PDS response"
    );

    let mut response =
        Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (name, value) in response_headers.iter() {
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
