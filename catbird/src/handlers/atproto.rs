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
use crate::middleware::SESSION_COOKIE_NAME;
use crate::models::{
    CatbirdSession, LogoutResponse, OAuthCallback, SessionInfo,
};
use crate::middleware::JacquardDpopData;
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
    tracing::info!("Login request for identifier: {}, client: {:?}, redirect_to: {:?}", identifier, client, redirect_to);

    let jacquard_client = state
        .jacquard_client
        .as_ref()
        .ok_or_else(|| AppError::Internal("Jacquard OAuthClient not initialized".into()))?;

    use jacquard_oauth::types::AuthorizeOptions;

    let state_value = match (&client, &redirect_to) {
        (Some(c), Some(r)) => Some(format!("{{\"client\":\"{}\",\"redirect_to\":\"{}\"}}", c, r)),
        (Some(c), None) => Some(c.clone()),
        _ => None,
    };

    let options = AuthorizeOptions {
        state: state_value.map(|s| s.into()),
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

    let jacquard_client = state
        .jacquard_client
        .as_ref()
        .ok_or_else(|| AppError::Internal("Jacquard OAuthClient not initialized".into()))?;

    use jacquard_oauth::types::CallbackParams;

    let params = CallbackParams {
        code: callback.code.into(),
        state: Some(callback.state.into()),
        iss: callback.iss.map(|s| s.into()),
    };

    let oauth_session = jacquard_client
        .callback(params)
        .await
        .map_err(|e| AppError::OAuth(format!("Callback failed: {}", e)))?;

    // Jacquard stores the session in RedisAuthStore automatically.
    // Extract the session_id and DID from the session data.
    let session_data = oauth_session.data.read().await;
    let did = session_data.account_did.as_str().to_string();
    let session_id = session_data.session_id.to_string();
    let pds_url = session_data.host_url.to_string();
    // Read the custom state that was passed through (client identifier, redirect_to)
    let app_state_str = {
        // session_id IS the state string from start_auth — Jacquard uses it as AuthRequestData.state
        // Try to parse it as JSON to extract redirect_to
        // But the actual OAuth state was passed via AuthorizeOptions.state, which becomes session_id.
        // We need to get it from the session_id field itself.
        session_id.clone()
    };
    drop(session_data);

    // Resolve handle from DID
    let handle = resolve_handle_for_did(&did, &pds_url).await;
    tracing::info!("Resolved handle for DID {}: {}", &did, &handle);

    // Record successful OAuth login
    metrics::record_oauth_login(true);

    // Set cookie — session_id is the Jacquard state/session identifier
    let cookie = Cookie::build((SESSION_COOKIE_NAME, session_id.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::days(30))
        .build();

    // Redirect back to the app via Universal Link (iOS Associated Domains)
    let app_redirect = build_app_redirect(&app_state_str, &session_id);

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
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<serde_json::Value>().await {
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

/// Build the redirect URL after OAuth callback.
fn build_app_redirect(state_str: &str, session_id: &str) -> String {
    if state_str.starts_with('{') {
        if let Ok(state_json) = serde_json::from_str::<serde_json::Value>(state_str) {
            if let Some(redirect_to) = state_json.get("redirect_to").and_then(|v| v.as_str()) {
                // SECURITY: Only allow localhost redirects
                if redirect_to.starts_with("http://127.0.0.1:") || redirect_to.starts_with("http://[::1]:") {
                    return format!("{}?session_id={}", redirect_to, session_id);
                }
                tracing::warn!("Rejected non-localhost redirect_to: {}", redirect_to);
            }
        }
    }
    format!("https://catbird.blue/oauth/callback#session_id={}", session_id)
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

    // Debug: log whether atproto-proxy header is present from client
    let has_proxy_header = headers.get("atproto-proxy");
    tracing::info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        pds = %session.pds_url,
        atproto_proxy = ?has_proxy_header,
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
        ProxyResponse::Buffered { status, headers: resp_headers, body: response_body } => {
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
                    let truncated = if error_text.len() > 200 { &error_text[..200] } else { error_text };
                    tracing::warn!(
                        request_id = %request_id,
                        status = status,
                        error_body = %truncated,
                        "[BFF-RESP-ERR] PDS error response body"
                    );
                }
            }

            let mut response =
                Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
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
        ProxyResponse::Streaming { status, headers: resp_headers, body: upstream_response } => {
            tracing::info!(
                request_id = %request_id,
                status = status,
                "[BFF-RESP] PDS response (streaming)"
            );

            let mut response =
                Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
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
