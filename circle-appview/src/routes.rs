use axum::{
    extract::{Extension, Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    routing::{get, post},
    Json, Router,
};
use catbird_atproto::generated::blue_catbird::circle::{
    activate_space::ActivateSpaceOutput,
    defs::AccessState,
    get_capabilities::GetCapabilitiesOutput,
    get_feed::{GetFeed, GetFeedOutput},
    list_circles::{ListCircles, ListCirclesOutput},
    list_notifications::{ListNotifications, ListNotificationsOutput},
};
use catbird_atproto::jacquard_common::types::string::Datetime;
use serde::{Deserialize, Serialize};

use crate::access;
use crate::auth::{self, AuthenticatedUser};
use crate::config::AppState;
use crate::error::{AppError, AuthReason};
use crate::projections::{self, SyncProjectionInput};

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

pub fn create_router(state: AppState) -> Router {
    // Unauthenticated public endpoints
    let public_routes = Router::new()
        .route("/_health", get(health_check))
        .route("/xrpc/_health", get(health_check))
        .route(
            "/xrpc/blue.catbird.circle.getCapabilities",
            get(get_capabilities),
        );

    // Authenticated XRPC endpoints
    let authenticated_routes = Router::new()
        .route(
            "/xrpc/blue.catbird.circle.getFeed",
            get(get_feed_handler),
        )
        .route(
            "/xrpc/blue.catbird.circle.listCircles",
            get(list_circles_handler),
        )
        .route(
            "/xrpc/blue.catbird.circle.listNotifications",
            get(list_notifications_handler),
        )
        .route(
            "/xrpc/blue.catbird.circle.activateSpace",
            post(activate_space_handler),
        )
        .route(
            "/internal/projections",
            post(sync_projections_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ));

    Router::new()
        .merge(public_routes)
        .merge(authenticated_routes)
        .with_state(state)
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn get_capabilities() -> Json<GetCapabilitiesOutput> {
    Json(GetCapabilitiesOutput {
        enabled: true,
        protocol_revision: "1".into(),
        supports_images: true,
        extra_data: None,
    })
}

async fn get_feed_handler(
    Extension(_user): Extension<AuthenticatedUser>,
    Query(_query): Query<GetFeed>,
    State(_state): State<AppState>,
) -> Result<Json<GetFeedOutput>, AppError> {
    tracing::debug!("Handling getFeed request");

    Ok(Json(GetFeedOutput {
        feed: Vec::new(),
        cursor: None,
        extra_data: None,
    }))
}

async fn list_circles_handler(
    Extension(_user): Extension<AuthenticatedUser>,
    Query(_query): Query<ListCircles>,
    State(_state): State<AppState>,
) -> Result<Json<ListCirclesOutput>, AppError> {
    tracing::debug!("Handling listCircles request");

    Ok(Json(ListCirclesOutput {
        circles: Vec::new(),
        cursor: None,
        extra_data: None,
    }))
}

async fn list_notifications_handler(
    Extension(_user): Extension<AuthenticatedUser>,
    Query(_query): Query<ListNotifications>,
    State(_state): State<AppState>,
) -> Result<Json<ListNotificationsOutput>, AppError> {
    tracing::debug!("Handling listNotifications request");

    Ok(Json(ListNotificationsOutput {
        notifications: Vec::new(),
        cursor: None,
        extra_data: None,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateSpaceInput {
    pub space: String,
    pub delegation_token: String,
    pub client_attestation: String,
}

async fn activate_space_handler(
    Extension(user): Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(input): Json<ActivateSpaceInput>,
) -> Result<Json<ActivateSpaceOutput>, AppError> {
    tracing::debug!("Handling activateSpace request");

    if input.client_attestation.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "Missing or empty clientAttestation".into(),
        ));
    }

    let expires_at = access::activate_space(
        &state,
        &user.did,
        &input.space,
        &input.delegation_token,
        &input.client_attestation,
    )
    .await?;

    let dt = Datetime::try_from(expires_at.to_rfc3339())
        .map_err(|e| AppError::Internal(format!("Failed to format datetime: {e}")))?;

    Ok(Json(ActivateSpaceOutput {
        access_state: AccessState::Active,
        expires_at: Some(dt),
        extra_data: None,
    }))
}

async fn sync_projections_handler(
    headers: HeaderMap,
    Extension(user): Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(input): Json<SyncProjectionInput>,
) -> Result<StatusCode, AppError> {
    tracing::debug!(
        operation_id = %input.operation_id,
        kind = %input.kind,
        "Handling syncProjection request"
    );

    // 1. Validate service auth lxm
    if user.lxm != "blue.catbird.circle.syncProjection" {
        return Err(AppError::Unauthorized(AuthReason::LxmMismatch));
    }

    // 2. Validate authenticated actor binding
    if user.did != input.actor_did {
        return Err(AppError::Forbidden(
            "Authenticated actor does not match input actor_did".into(),
        ));
    }

    // 3. Validate actor authority binding
    let authority_did = access::extract_authority_did(&input.space_uri)?;
    match input.kind.as_str() {
        "circle_upsert" | "CircleUpsert" | "circle_delete" | "CircleDelete" | "member_add"
        | "MemberAdd" => {
            if input.actor_did != authority_did {
                return Err(AppError::Forbidden(
                    "Actor is not authorized for Circle operation: must be authority".into(),
                ));
            }
        }
        "member_remove" | "MemberRemove" => {
            let member = input
                .payload
                .get("member")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if input.actor_did != authority_did && input.actor_did != member {
                return Err(AppError::Forbidden(
                    "Actor is not authorized for member removal: must be authority or member self-removing".into(),
                ));
            }
        }
        _ => {}
    }

    // 4. Verify Nest client attestation (FAIL-CLOSED dual authentication)
    let attestation = headers
        .get("x-nest-client-attestation")
        .or_else(|| headers.get("nest-attestation"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            input
                .payload
                .get("clientAttestation")
                .or_else(|| input.payload.get("client_attestation"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .ok_or(AppError::Unauthorized(AuthReason::MissingHeader))?;

    auth::verify_nest_client_attestation(&state, &attestation, &state.config.service_did)
        .await?;

    let payload_digest = projections::compute_payload_digest(
        &input.operation_id,
        input.operation_key.as_deref(),
        &input.actor_did,
        &input.space_uri,
        &input.kind,
        &input.payload,
        input.generation,
    );

    let projection = input.to_projection()?;
    projections::apply_projection(
        &state.db,
        Some(&state.credential_store),
        Some(&state.space_locks),
        input.operation_id,
        projection,
        &payload_digest,
    )
    .await?;

    Ok(StatusCode::OK)
}
