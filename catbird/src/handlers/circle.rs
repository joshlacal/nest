//! Circle XRPC handlers
//!
//! Exposes Circle management procedures and typed AppView proxy routes.

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::{JacquardDpopData, RequestId};
use crate::models::CatbirdSession;
use crate::services::{CircleService, ServiceAuthProvider};
use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, StatusCode},
    response::Response,
    Extension, Json,
};
use catbird_atproto::generated::blue_catbird::circle::activate_space::{
    ActivateSpace, ActivateSpaceOutput,
};
use catbird_atproto::generated::blue_catbird::circle::create_circle::{
    CreateCircle, CreateCircleOutput,
};
use catbird_atproto::generated::blue_catbird::circle::delete_circle::{
    DeleteCircle, DeleteCircleOutput,
};
use catbird_atproto::generated::blue_catbird::circle::get_capabilities::GetCapabilitiesOutput;
use catbird_atproto::generated::blue_catbird::circle::get_feed::GetFeed;
use catbird_atproto::generated::blue_catbird::circle::get_media::GetMedia;
use catbird_atproto::generated::blue_catbird::circle::get_post_thread::GetPostThread;
use catbird_atproto::generated::blue_catbird::circle::list_circles::ListCircles;
use catbird_atproto::generated::blue_catbird::circle::list_notifications::ListNotifications;
use catbird_atproto::generated::blue_catbird::circle::report_record::ReportRecord;
use catbird_atproto::generated::blue_catbird::circle::update_member::{
    UpdateMember, UpdateMemberOutput,
};
use catbird_atproto::generated::blue_catbird::circle::update_preferences::UpdatePreferences;
use std::sync::Arc;

/// GET /xrpc/blue.catbird.circle.getCapabilities
///
/// Uses the production Circle capability probe service from AppState.
pub async fn get_capabilities(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    dpop_data: Option<Extension<JacquardDpopData>>,
    request_id: Option<Extension<RequestId>>,
) -> AppResult<Json<GetCapabilitiesOutput>> {
    let req_id = request_id
        .map(|r| r.0.0.clone())
        .unwrap_or_else(|| "circle-capability".into());

    let fallback_dpop;
    let dpop_ref = match &dpop_data {
        Some(ext) => &ext.0,
        None => {
            fallback_dpop = resolve_dpop_data(&state, &session).await;
            &fallback_dpop
        }
    };

    let cap = state
        .circle_capability
        .get_with_request(&session, Some(dpop_ref), &req_id)
        .await?;

    Ok(Json(GetCapabilitiesOutput {
        enabled: cap.enabled,
        protocol_revision: cap.protocol_revision.into(),
        supports_images: cap.supports_images,
        extra_data: None,
    }))
}

/// POST /xrpc/blue.catbird.circle.createCircle
pub async fn create_circle(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<CreateCircle>,
) -> AppResult<Json<CreateCircleOutput>> {
    let service = CircleService::new(state);
    let op = service.create_circle(&session, input).await?;
    Ok(Json(CreateCircleOutput {
        value: op,
        extra_data: None,
    }))
}

/// POST /xrpc/blue.catbird.circle.updateMember
pub async fn update_member(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<UpdateMember>,
) -> AppResult<Json<UpdateMemberOutput>> {
    let service = CircleService::new(state);
    let op = service.update_member(&session, input).await?;
    Ok(Json(UpdateMemberOutput {
        value: op,
        extra_data: None,
    }))
}

/// POST /xrpc/blue.catbird.circle.deleteCircle
pub async fn delete_circle(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<DeleteCircle>,
) -> AppResult<Json<DeleteCircleOutput>> {
    let service = CircleService::new(state);
    let op = service.delete_circle(&session, input).await?;
    Ok(Json(DeleteCircleOutput {
        value: op,
        extra_data: None,
    }))
}

/// POST /xrpc/blue.catbird.circle.activateSpace
pub async fn activate_space(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<ActivateSpace>,
) -> AppResult<Json<ActivateSpaceOutput>> {
    let service = CircleService::new(state);
    let out = service.activate_space(&session, input).await?;
    Ok(Json(out))
}

/// GET /xrpc/blue.catbird.circle.listCircles
pub async fn list_circles(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    request_id: Option<Extension<RequestId>>,
    Query(query): Query<ListCircles>,
) -> AppResult<Response> {
    if let Some(limit) = query.limit {
        if !(1..=100).contains(&limit) {
            return Err(AppError::AtprotoResponse {
                status: StatusCode::BAD_REQUEST,
                error: "InvalidRequest".into(),
                message: "Limit must be between 1 and 100".into(),
            });
        }
    }

    let mut params = Vec::new();
    if let Some(cursor) = &query.cursor {
        params.push(format!("cursor={}", urlencoding::encode(cursor)));
    }
    if let Some(limit) = query.limit {
        params.push(format!("limit={limit}"));
    }
    let qs = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };

    forward_get_to_appview(
        &state,
        &session,
        "blue.catbird.circle.listCircles",
        &qs,
        request_id,
    )
    .await
}

/// POST /xrpc/blue.catbird.circle.updatePreferences
pub async fn update_preferences(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    request_id: Option<Extension<RequestId>>,
    Json(input): Json<UpdatePreferences>,
) -> AppResult<Response> {
    let body = serde_json::json!({
        "space": input.space.as_str(),
        "muted": input.muted
    });

    forward_post_to_appview(
        &state,
        &session,
        "blue.catbird.circle.updatePreferences",
        body,
        request_id,
    )
    .await
}

/// POST /xrpc/blue.catbird.circle.reportRecord
pub async fn report_record(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    request_id: Option<Extension<RequestId>>,
    Json(input): Json<ReportRecord>,
) -> AppResult<Response> {
    if let Some(details) = &input.details {
        if details.chars().count() > 2000 {
            return Err(AppError::AtprotoResponse {
                status: StatusCode::BAD_REQUEST,
                error: "InvalidRequest".into(),
                message: "Report details must not exceed 2000 characters".into(),
            });
        }
    }

    let reason_val = serde_json::to_value(&input.reason).map_err(|e| AppError::AtprotoResponse {
        status: StatusCode::BAD_REQUEST,
        error: "InvalidRequest".into(),
        message: format!("Invalid report reason: {e}"),
    })?;

    let mut body_map = serde_json::Map::new();
    body_map.insert(
        "space".into(),
        serde_json::Value::String(input.space.as_str().to_string()),
    );
    body_map.insert(
        "uri".into(),
        serde_json::Value::String(input.uri.as_str().to_string()),
    );
    body_map.insert("reason".into(), reason_val);
    if let Some(details) = &input.details {
        body_map.insert(
            "details".into(),
            serde_json::Value::String(details.to_string()),
        );
    }

    forward_post_to_appview(
        &state,
        &session,
        "blue.catbird.circle.reportRecord",
        serde_json::Value::Object(body_map),
        request_id,
    )
    .await
}

/// GET /xrpc/blue.catbird.circle.getFeed
pub async fn get_feed(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    request_id: Option<Extension<RequestId>>,
    Query(query): Query<GetFeed>,
) -> AppResult<Response> {
    if let Some(limit) = query.limit {
        if !(1..=100).contains(&limit) {
            return Err(AppError::AtprotoResponse {
                status: StatusCode::BAD_REQUEST,
                error: "InvalidRequest".into(),
                message: "Limit must be between 1 and 100".into(),
            });
        }
    }

    let mut params = Vec::new();
    if let Some(space) = &query.space {
        params.push(format!("space={}", urlencoding::encode(space.as_str())));
    }
    if let Some(cursor) = &query.cursor {
        params.push(format!("cursor={}", urlencoding::encode(cursor)));
    }
    if let Some(limit) = query.limit {
        params.push(format!("limit={limit}"));
    }
    let qs = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };

    forward_get_to_appview(
        &state,
        &session,
        "blue.catbird.circle.getFeed",
        &qs,
        request_id,
    )
    .await
}

/// GET /xrpc/blue.catbird.circle.getPostThread
pub async fn get_post_thread(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    request_id: Option<Extension<RequestId>>,
    Query(query): Query<GetPostThread>,
) -> AppResult<Response> {
    if let Some(depth) = query.depth {
        if !(0..=10).contains(&depth) {
            return Err(AppError::AtprotoResponse {
                status: StatusCode::BAD_REQUEST,
                error: "InvalidRequest".into(),
                message: "Depth must be between 0 and 10".into(),
            });
        }
    }
    if let Some(parent_height) = query.parent_height {
        if !(0..=10).contains(&parent_height) {
            return Err(AppError::AtprotoResponse {
                status: StatusCode::BAD_REQUEST,
                error: "InvalidRequest".into(),
                message: "Parent height must be between 0 and 10".into(),
            });
        }
    }

    let mut params = Vec::new();
    params.push(format!("space={}", urlencoding::encode(query.space.as_str())));
    params.push(format!("uri={}", urlencoding::encode(query.uri.as_str())));
    if let Some(depth) = query.depth {
        params.push(format!("depth={depth}"));
    }
    if let Some(ph) = query.parent_height {
        params.push(format!("parentHeight={ph}"));
    }
    let qs = format!("?{}", params.join("&"));

    forward_get_to_appview(
        &state,
        &session,
        "blue.catbird.circle.getPostThread",
        &qs,
        request_id,
    )
    .await
}

/// GET /xrpc/blue.catbird.circle.listNotifications
pub async fn list_notifications(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    request_id: Option<Extension<RequestId>>,
    Query(query): Query<ListNotifications>,
) -> AppResult<Response> {
    if let Some(limit) = query.limit {
        if !(1..=100).contains(&limit) {
            return Err(AppError::AtprotoResponse {
                status: StatusCode::BAD_REQUEST,
                error: "InvalidRequest".into(),
                message: "Limit must be between 1 and 100".into(),
            });
        }
    }

    let mut params = Vec::new();
    if let Some(cursor) = &query.cursor {
        params.push(format!("cursor={}", urlencoding::encode(cursor)));
    }
    if let Some(limit) = query.limit {
        params.push(format!("limit={limit}"));
    }
    let qs = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };

    forward_get_to_appview(
        &state,
        &session,
        "blue.catbird.circle.listNotifications",
        &qs,
        request_id,
    )
    .await
}

/// GET /xrpc/blue.catbird.circle.getMedia
pub async fn get_media(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    request_id: Option<Extension<RequestId>>,
    Query(query): Query<GetMedia>,
) -> AppResult<Response> {
    let qs = format!(
        "?space={}&did={}&cid={}",
        urlencoding::encode(query.space.as_str()),
        urlencoding::encode(query.did.as_str()),
        urlencoding::encode(query.cid.as_str())
    );

    forward_get_to_appview(
        &state,
        &session,
        "blue.catbird.circle.getMedia",
        &qs,
        request_id,
    )
    .await
}

async fn forward_get_to_appview(
    state: &AppState,
    session: &CatbirdSession,
    nsid: &str,
    qs: &str,
    request_id: Option<Extension<RequestId>>,
) -> AppResult<Response> {
    let req_id_str = request_id
        .map(|r| r.0.0.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let service_url = state
        .config
        .circle
        .service_url
        .as_deref()
        .ok_or_else(|| AppError::AtprotoResponse {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: "UpstreamUnavailable".into(),
            message: "Circle AppView service URL is not configured".into(),
        })?;

    let service_auth = ServiceAuthProvider::new(Arc::new(state.clone()));
    let token = service_auth
        .token_for_audience(session, &state.config.circle.service_did, nsid)
        .await?;

    let base = service_url.trim_end_matches('/');
    let target_url = format!("{base}/xrpc/{nsid}{qs}");

    let upstream_resp = state
        .http_client
        .get(&target_url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Request-Id", req_id_str)
        .send()
        .await
        .map_err(|e| AppError::AtprotoResponse {
            status: StatusCode::BAD_GATEWAY,
            error: "UpstreamUnavailable".into(),
            message: format!("Circle AppView request failed: {e}"),
        })?;

    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_builder = Response::builder().status(status);

    if let Some(content_type) = upstream_resp.headers().get(header::CONTENT_TYPE) {
        response_builder = response_builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(cache_control) = upstream_resp.headers().get(header::CACHE_CONTROL) {
        response_builder = response_builder.header(header::CACHE_CONTROL, cache_control);
    }

    let body_bytes = upstream_resp
        .bytes()
        .await
        .map_err(|e| AppError::AtprotoResponse {
            status: StatusCode::BAD_GATEWAY,
            error: "UpstreamUnavailable".into(),
            message: format!("Failed to read AppView response: {e}"),
        })?;

    response_builder
        .body(Body::from(body_bytes))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {e}")))
}

async fn forward_post_to_appview(
    state: &AppState,
    session: &CatbirdSession,
    nsid: &str,
    body: serde_json::Value,
    request_id: Option<Extension<RequestId>>,
) -> AppResult<Response> {
    let req_id_str = request_id
        .map(|r| r.0.0.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let service_url = state
        .config
        .circle
        .service_url
        .as_deref()
        .ok_or_else(|| AppError::AtprotoResponse {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: "UpstreamUnavailable".into(),
            message: "Circle AppView service URL is not configured".into(),
        })?;

    let service_auth = ServiceAuthProvider::new(Arc::new(state.clone()));
    let token = service_auth
        .token_for_audience(session, &state.config.circle.service_did, nsid)
        .await?;

    let base = service_url.trim_end_matches('/');
    let target_url = format!("{base}/xrpc/{nsid}");

    let upstream_resp = state
        .http_client
        .post(&target_url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-Request-Id", req_id_str)
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::AtprotoResponse {
            status: StatusCode::BAD_GATEWAY,
            error: "UpstreamUnavailable".into(),
            message: format!("Circle AppView request failed: {e}"),
        })?;

    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_builder = Response::builder().status(status);

    if let Some(content_type) = upstream_resp.headers().get(header::CONTENT_TYPE) {
        response_builder = response_builder.header(header::CONTENT_TYPE, content_type);
    }

    let body_bytes = upstream_resp
        .bytes()
        .await
        .map_err(|e| AppError::AtprotoResponse {
            status: StatusCode::BAD_GATEWAY,
            error: "UpstreamUnavailable".into(),
            message: format!("Failed to read AppView response: {e}"),
        })?;

    response_builder
        .body(Body::from(body_bytes))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {e}")))
}

async fn resolve_dpop_data(state: &AppState, session: &CatbirdSession) -> JacquardDpopData {
    if let Some(jacquard_client) = &state.jacquard_client {
        if let Ok(did) = jacquard_common::types::did::Did::new(&session.did) {
            if let Ok(session_data) = jacquard_client
                .registry
                .get(&did, &session.id.to_string(), true)
                .await
            {
                return JacquardDpopData {
                    dpop_key: session_data.dpop_data.dpop_key.clone(),
                    dpop_host_nonce: session_data.dpop_data.dpop_host_nonce.to_string(),
                };
            }
        }
    }

    let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
    let crypto_key = jose_jwk::crypto::Key::from(secret_key);
    let dpop_key = jose_jwk::Key::from(&crypto_key);
    JacquardDpopData {
        dpop_key,
        dpop_host_nonce: String::new(),
    }
}
