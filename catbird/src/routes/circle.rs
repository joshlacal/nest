//! Circle routes definition

use crate::config::AppState;
use crate::handlers::circle;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

/// Creates the Circle XRPC router mounted relative to `/xrpc`.
pub fn create_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/blue.catbird.circle.getCapabilities", get(circle::get_capabilities))
        .route("/blue.catbird.circle.createCircle", post(circle::create_circle))
        .route("/blue.catbird.circle.updateMember", post(circle::update_member))
        .route("/blue.catbird.circle.deleteCircle", post(circle::delete_circle))
        .route("/blue.catbird.circle.activateSpace", post(circle::activate_space))
        .route("/blue.catbird.circle.listCircles", get(circle::proxy_circle_appview))
        .route("/blue.catbird.circle.updatePreferences", post(circle::proxy_circle_appview))
        .route("/blue.catbird.circle.reportRecord", post(circle::proxy_circle_appview))
        .route("/blue.catbird.circle.getFeed", get(circle::proxy_circle_appview))
        .route("/blue.catbird.circle.getPostThread", get(circle::proxy_circle_appview))
        .route("/blue.catbird.circle.listNotifications", get(circle::proxy_circle_appview))
        .route("/blue.catbird.circle.getMedia", get(circle::proxy_circle_media))
}

/// Standalone Circle router with explicit full `/xrpc` path prefixes.
pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/xrpc/blue.catbird.circle.getCapabilities", get(circle::get_capabilities))
        .route("/xrpc/blue.catbird.circle.createCircle", post(circle::create_circle))
        .route("/xrpc/blue.catbird.circle.updateMember", post(circle::update_member))
        .route("/xrpc/blue.catbird.circle.deleteCircle", post(circle::delete_circle))
        .route("/xrpc/blue.catbird.circle.activateSpace", post(circle::activate_space))
        .route("/xrpc/blue.catbird.circle.listCircles", get(circle::proxy_circle_appview))
        .route("/xrpc/blue.catbird.circle.updatePreferences", post(circle::proxy_circle_appview))
        .route("/xrpc/blue.catbird.circle.reportRecord", post(circle::proxy_circle_appview))
        .route("/xrpc/blue.catbird.circle.getFeed", get(circle::proxy_circle_appview))
        .route("/xrpc/blue.catbird.circle.getPostThread", get(circle::proxy_circle_appview))
        .route("/xrpc/blue.catbird.circle.listNotifications", get(circle::proxy_circle_appview))
        .route("/xrpc/blue.catbird.circle.getMedia", get(circle::proxy_circle_media))
        .with_state(Arc::new(state))
}
