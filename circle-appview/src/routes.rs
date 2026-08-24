use axum::{
    extract::{Extension, Query, State},
    middleware,
    routing::get,
    Json, Router,
};
use catbird_atproto::generated::blue_catbird::circle::{
    get_capabilities::GetCapabilitiesOutput,
    get_feed::{GetFeed, GetFeedOutput},
    list_circles::{ListCircles, ListCirclesOutput},
    list_notifications::{ListNotifications, ListNotificationsOutput},
};
use serde::Serialize;

use crate::auth::{self, AuthenticatedUser};
use crate::config::AppState;
use crate::error::AppError;

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
