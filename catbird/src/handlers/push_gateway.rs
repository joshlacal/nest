//! XRPC handlers for Catbird's authenticated Push Gateway (`D2`, `D-09`, Spec §6.2):
//! - `POST /xrpc/blue.catbird.push.registerKey` (dual-auth: Nest session OR PDS `ServiceJWT`)
//! - `POST /xrpc/blue.catbird.push.deliver` (`mls-ds` `#atproto` DID-JWT authenticated)

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Extension, Json, Router,
};
use serde_json::json;

use crate::{
    config::AppState,
    error::AppResult,
    middleware::authenticate_session_headers,
    models::CatbirdSession,
    services::push::{gateway::PushGatewayService, push_unavailable_error},
};
use petrel_catbird::generated::blue::catbird::push::register_key::{
    Input as RegisterKey, Output as RegisterKeyOutput,
};

fn bearer_looks_like_compact_jwt(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())?;
    if token.contains('.') {
        Some(raw)
    } else {
        None
    }
}

fn configured_gateway_audiences(state: &AppState) -> Vec<String> {
    let mut out = Vec::with_capacity(3);
    if let Some(did) = state.config.push.service_did.as_ref() {
        if !did.trim().is_empty() {
            out.push(did.trim().to_string());
        }
    }
    if let Some(did) = state.config.mls.gateway_did.as_ref() {
        if !did.trim().is_empty() {
            out.push(did.trim().to_string());
        }
    }
    if let Ok(parsed) = url::Url::parse(&state.config.server.base_url) {
        if let Some(host) = parsed.host_str() {
            out.push(format!("did:web:{}", host.to_ascii_lowercase()));
        }
    }
    out
}

fn parse_register_input(value: serde_json::Value) -> AppResult<RegisterKey> {
    let known = ["appId", "deviceId", "nativeToken", "platform"];
    if value
        .as_object()
        .is_none_or(|m| m.keys().any(|k| !known.contains(&k.as_str())))
    {
        return Err(crate::error::AppError::BadRequest(
            "Invalid registerKey fields".into(),
        ));
    }
    serde_json::from_value(value)
        .map_err(|_| crate::error::AppError::BadRequest("Invalid registerKey input".into()))
}

/// `POST /xrpc/blue.catbird.push.registerKey` (`D-09` dual authentication):
/// - First-party Nest clients authenticate with `Bearer <session_uuid>` or `catbird_session` cookie.
/// - External / direct ATProto clients authenticate with a PDS-minted `ServiceJWT`
///   (`aud == gateway DID`, `lxm == "blue.catbird.push.registerKey"`, `#atproto` signature).
pub async fn register_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> AppResult<Json<RegisterKeyOutput>> {
    let input = parse_register_input(value)?;
    if let Some(raw_auth) = bearer_looks_like_compact_jwt(&headers) {
        let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
        let allowed_aud = configured_gateway_audiences(&state);
        let allowed_refs: Vec<&str> = allowed_aud.iter().map(String::as_str).collect();
        let caller_did = push
            .gateway
            .authenticate_register_service_jwt(Some(raw_auth), &allowed_refs)
            .await?;
        if let Err(retry_after) = state
            .rate_limit
            .session_limiter
            .check(
                &format!("service_jwt:{caller_did}"),
                &state.rate_limit.session_config,
            )
            .await
        {
            return Err(crate::error::AppError::RateLimitExceeded { retry_after });
        }
        let out = push
            .gateway
            .register_key_with_optional_session(&caller_did, None, &input)
            .await?;
        return Ok(Json(out));
    }

    let (session, _dpop) = authenticate_session_headers(&state, &headers).await?;
    if let Err(retry_after) = state
        .rate_limit
        .session_limiter
        .check(&session.id.to_string(), &state.rate_limit.session_config)
        .await
    {
        return Err(crate::error::AppError::RateLimitExceeded { retry_after });
    }
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    register_key_with_service(State(push.gateway.clone()), Extension(session), Json(input)).await
}

/// Direct session-scoped handler for `blue.catbird.push.registerKey`.
pub async fn register_key_with_service(
    State(gateway): State<Arc<PushGatewayService>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<RegisterKey>,
) -> AppResult<Json<RegisterKeyOutput>> {
    let out = gateway
        .register_key(&session.did, &session.id.to_string(), &input)
        .await?;
    Ok(Json(out))
}

/// Direct `ServiceJWT`-authenticated handler for isolated gateway tests (`D-09`).
pub async fn register_key_service_jwt_with_service(
    State(gateway): State<Arc<PushGatewayService>>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> AppResult<Json<RegisterKeyOutput>> {
    let input = parse_register_input(value)?;
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let caller_did = gateway
        .authenticate_register_service_jwt(auth_header, &[])
        .await?;
    let out = gateway
        .register_key_with_optional_session(&caller_did, None, &input)
        .await?;
    Ok(Json(out))
}

/// `POST /xrpc/blue.catbird.push.deliver` (authenticated via `mls-ds` `#atproto` DID-JWT).
pub async fn deliver(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let Some(push) = state.push.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "ServiceUnavailable",
                "message": "Push gateway is not configured"
            })),
        );
    };
    deliver_with_service(State(push.gateway.clone()), headers, body).await
}

/// Direct service-scoped handler for `blue.catbird.push.deliver`.
pub async fn deliver_with_service(
    State(gateway): State<Arc<PushGatewayService>>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let (status, payload) = gateway.deliver_wake(auth_header, &body).await;
    (status, Json(payload))
}

/// Standalone Axum router exposing `/xrpc/blue.catbird.push.deliver` and
/// `ServiceJWT`-authenticated `/xrpc/blue.catbird.push.registerKey` for isolated gateway tests.
pub fn standalone_gateway_router(gateway: Arc<PushGatewayService>) -> Router {
    Router::new()
        .route(
            "/xrpc/blue.catbird.push.deliver",
            post(deliver_with_service).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/xrpc/blue.catbird.push.registerKey",
            post(register_key_service_jwt_with_service).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .with_state(gateway)
}
