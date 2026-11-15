//! XRPC handlers for Catbird's authenticated Push Gateway (`D2`, Spec §6.2):
//! - `POST /xrpc/blue.catbird.push.registerKey` (session-authenticated)
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
    models::CatbirdSession,
    services::push::{gateway::PushGatewayService, push_unavailable_error},
};
use catbird_atproto::generated::blue_catbird::push::register_key::{
    RegisterKey, RegisterKeyOutput,
};

/// `POST /xrpc/blue.catbird.push.registerKey` (mounted under `auth_middleware`).
pub async fn register_key(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<RegisterKey>,
) -> AppResult<Json<RegisterKeyOutput>> {
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    register_key_with_service(State(push.gateway.clone()), Extension(session), Json(input)).await
}

/// Direct service-scoped handler for `blue.catbird.push.registerKey`.
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

/// Standalone Axum router exposing `/xrpc/blue.catbird.push.deliver` for isolated gateway tests.
pub fn standalone_gateway_router(gateway: Arc<PushGatewayService>) -> Router {
    Router::new()
        .route(
            "/xrpc/blue.catbird.push.deliver",
            post(deliver_with_service).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .with_state(gateway)
}
