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
use crate::models::{CatbirdSession, LogoutResponse, OAuthCallback, SessionInfo};
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
    tracing::info!(
        "Login request for identifier: {}, client: {:?}, redirect_to: {:?}",
        identifier,
        client,
        redirect_to
    );

    // Select the appropriate OAuth client based on the client parameter
    let is_catmos = client.as_deref() == Some("catmos-web");
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
    // Store redirect_to in Redis so the callback can look it up.
    let session_nonce = uuid::Uuid::new_v4().to_string();
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

    // Check if this session has a stored redirect_to (catmos-web flow).
    // Legacy sessions with JSON state won't have this key.
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

    // Determine which Jacquard client to use.
    // New flow: redirect_to presence means catmos-web.
    // Legacy flow: JSON state with {"client":"catmos-web",...}.
    let is_catmos = redirect_to.is_some()
        || (callback.state.starts_with('{')
            && serde_json::from_str::<serde_json::Value>(&callback.state)
                .ok()
                .and_then(|v| {
                    v.get("client")
                        .and_then(|c| c.as_str())
                        .map(|c| c == "catmos-web")
                })
                .unwrap_or(false));

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
        code: callback.code.into(),
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

    // Redirect back to the app
    let app_redirect = if let Some(ref r) = redirect_to {
        // catmos-web: redirect_to was stored in Redis during login
        let is_allowed = r.starts_with("http://127.0.0.1:")
            || r.starts_with("http://[::1]:")
            || ALLOWED_REDIRECT_ORIGINS
                .iter()
                .any(|origin| r.starts_with(origin));
        if is_allowed {
            format!("{}?session_id={}", r, session_id)
        } else {
            tracing::warn!("Rejected redirect_to from Redis: {}", r);
            format!(
                "https://catbird.blue/oauth/callback#session_id={}",
                session_id
            )
        }
    } else {
        // Legacy: try parsing session_id as JSON state (for in-flight sessions)
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

/// Allowed redirect origins for OAuth callback (beyond localhost).
const ALLOWED_REDIRECT_ORIGINS: &[&str] =
    &["https://catmos.catbird.blue", "https://catmos.pages.dev"];

/// Build the redirect URL after OAuth callback.
fn build_app_redirect(state_str: &str, session_id: &str) -> String {
    if state_str.starts_with('{') {
        if let Ok(state_json) = serde_json::from_str::<serde_json::Value>(state_str) {
            if let Some(redirect_to) = state_json.get("redirect_to").and_then(|v| v.as_str()) {
                // Allow localhost redirects (dev)
                if redirect_to.starts_with("http://127.0.0.1:")
                    || redirect_to.starts_with("http://[::1]:")
                {
                    return format!("{}?session_id={}", redirect_to, session_id);
                }
                // Allow known production origins
                if ALLOWED_REDIRECT_ORIGINS
                    .iter()
                    .any(|origin| redirect_to.starts_with(origin))
                {
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
                push.moderation_cache.mute_thread(&session.did, root).await?;
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
            if let (Some(collection), Some(dpop)) =
                (body.get("collection").and_then(|value| value.as_str()), jacquard_dpop)
            {
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
