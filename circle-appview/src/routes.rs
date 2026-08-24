use axum::{
    extract::{Query, State},
    middleware,
    response::Json,
    routing::get,
    Extension, Router,
};
use catbird_atproto::generated::blue_catbird::circle::{
    get_feed::GetFeedOutput,
    list_circles::ListCirclesOutput,
    list_notifications::ListNotificationsOutput,
};
use serde::{Deserialize, Serialize};

use crate::auth::{self, AuthenticatedUser};
use crate::config::AppState;
use crate::error::AppError;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Serialize)]
pub struct CapabilitiesResponse {
    pub enabled: bool,
    #[serde(rename = "protocolRevision")]
    pub protocol_revision: u32,
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

async fn get_capabilities() -> Json<CapabilitiesResponse> {
    Json(CapabilitiesResponse {
        enabled: true,
        protocol_revision: 1,
    })
}

#[derive(Debug, Deserialize)]
pub struct GetFeedQuery {
    pub space: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

async fn get_feed_handler(
    Extension(user): Extension<AuthenticatedUser>,
    Query(_query): Query<GetFeedQuery>,
    State(_state): State<AppState>,
) -> Result<Json<GetFeedOutput>, AppError> {
    tracing::debug!(did = %user.did, "Handling getFeed request");

    // Returns authenticated empty feed structure
    Ok(Json(GetFeedOutput {
        feed: Vec::new(),
        cursor: None,
        extra_data: Default::default(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ListCirclesQuery {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

async fn list_circles_handler(
    Extension(user): Extension<AuthenticatedUser>,
    Query(_query): Query<ListCirclesQuery>,
    State(_state): State<AppState>,
) -> Result<Json<ListCirclesOutput>, AppError> {
    tracing::debug!(did = %user.did, "Handling listCircles request");

    // Returns authenticated empty circle list structure
    Ok(Json(ListCirclesOutput {
        circles: Vec::new(),
        cursor: None,
        extra_data: Default::default(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ListNotificationsQuery {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

async fn list_notifications_handler(
    Extension(user): Extension<AuthenticatedUser>,
    Query(_query): Query<ListNotificationsQuery>,
    State(_state): State<AppState>,
) -> Result<Json<ListNotificationsOutput>, AppError> {
    tracing::debug!(did = %user.did, "Handling listNotifications request");

    // Returns authenticated empty notifications list structure
    Ok(Json(ListNotificationsOutput {
        notifications: Vec::new(),
        cursor: None,
        extra_data: Default::default(),
    }))
}
