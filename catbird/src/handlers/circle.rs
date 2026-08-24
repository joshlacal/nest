//! Circle XRPC handlers
//!
//! Exposes Circle management procedures and AppView proxy routes.

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::{JacquardDpopData, RequestId};
use crate::models::CatbirdSession;
use crate::services::{CircleService, ServiceAuthProvider};
use axum::{
    body::Body,
    extract::State,
    http::{header, Method, StatusCode, Uri},
    response::Response,
    Extension, Json,
};
use bytes::Bytes;
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
use catbird_atproto::generated::blue_catbird::circle::update_member::{
    UpdateMember, UpdateMemberOutput,
};
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

/// Proxies read and action requests to the Circle AppView.
/// Obtains a fresh service-auth token for the authenticated DID and exact `lxm`,
/// strips inbound client authorization/cookies, and forwards only typed parameters and body.
pub async fn proxy_circle_appview(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    request_id: Option<Extension<RequestId>>,
    method: Method,
    uri: Uri,
    body: Option<Bytes>,
) -> AppResult<Response> {
    let nsid = extract_nsid_from_path(uri.path())?;
    let req_id_str = request_id
        .map(|r| r.0.0.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let service_auth = ServiceAuthProvider::new(state.clone());
    let token = service_auth
        .token_for_audience(&session, &state.config.circle.service_did, &nsid)
        .await?;

    let service_url = state
        .config
        .circle
        .service_url
        .as_deref()
        .ok_or_else(|| AppError::Config("Circle AppView service URL is not configured".into()))?;

    let base = service_url.trim_end_matches('/');
    let target_url = if let Some(query) = uri.query() {
        format!("{base}/xrpc/{nsid}?{query}")
    } else {
        format!("{base}/xrpc/{nsid}")
    };

    let mut req_builder = state
        .http_client
        .request(method, &target_url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Request-Id", req_id_str);

    if let Some(b) = body {
        if !b.is_empty() {
            req_builder = req_builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(b);
        }
    }

    let upstream_resp = req_builder
        .send()
        .await
        .map_err(|e| AppError::Upstream {
            status: 502,
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
        .map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("Failed to read AppView response: {e}"),
        })?;
    response_builder
        .body(Body::from(body_bytes))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {e}")))
}

/// Proxies media stream requests to the Circle AppView.
pub async fn proxy_circle_media(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    request_id: Option<Extension<RequestId>>,
    uri: Uri,
) -> AppResult<Response> {
    let req_id_str = request_id
        .map(|r| r.0.0.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let service_auth = ServiceAuthProvider::new(state.clone());
    let token = service_auth
        .token_for_audience(
            &session,
            &state.config.circle.service_did,
            "blue.catbird.circle.getMedia",
        )
        .await?;

    let service_url = state
        .config
        .circle
        .service_url
        .as_deref()
        .ok_or_else(|| AppError::Config("Circle AppView service URL is not configured".into()))?;

    let base = service_url.trim_end_matches('/');
    let target_url = if let Some(query) = uri.query() {
        format!("{base}/xrpc/blue.catbird.circle.getMedia?{query}")
    } else {
        format!("{base}/xrpc/blue.catbird.circle.getMedia")
    };

    let upstream_resp = state
        .http_client
        .get(&target_url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Request-Id", req_id_str)
        .send()
        .await
        .map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("Circle media request failed: {e}"),
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
        .map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("Failed to read media response: {e}"),
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

fn extract_nsid_from_path(path: &str) -> AppResult<String> {
    let clean_path = path.trim_start_matches('/');
    let nsid = clean_path
        .strip_prefix("xrpc/")
        .unwrap_or(clean_path);
    if nsid.is_empty() {
        return Err(AppError::BadRequest("Missing NSID in request path".into()));
    }
    Ok(nsid.to_string())
}
