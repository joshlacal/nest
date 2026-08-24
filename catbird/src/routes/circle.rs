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
        .route("/blue.catbird.circle.listCircles", get(circle::list_circles))
        .route("/blue.catbird.circle.updatePreferences", post(circle::update_preferences))
        .route("/blue.catbird.circle.reportRecord", post(circle::report_record))
        .route("/blue.catbird.circle.getFeed", get(circle::get_feed))
        .route("/blue.catbird.circle.getPostThread", get(circle::get_post_thread))
        .route("/blue.catbird.circle.listNotifications", get(circle::list_notifications))
        .route("/blue.catbird.circle.getMedia", get(circle::get_media))
}

/// Standalone Circle router with explicit full `/xrpc` path prefixes.
pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/xrpc/blue.catbird.circle.getCapabilities", get(circle::get_capabilities))
        .route("/xrpc/blue.catbird.circle.createCircle", post(circle::create_circle))
        .route("/xrpc/blue.catbird.circle.updateMember", post(circle::update_member))
        .route("/xrpc/blue.catbird.circle.deleteCircle", post(circle::delete_circle))
        .route("/xrpc/blue.catbird.circle.activateSpace", post(circle::activate_space))
        .route("/xrpc/blue.catbird.circle.listCircles", get(circle::list_circles))
        .route("/xrpc/blue.catbird.circle.updatePreferences", post(circle::update_preferences))
        .route("/xrpc/blue.catbird.circle.reportRecord", post(circle::report_record))
        .route("/xrpc/blue.catbird.circle.getFeed", get(circle::get_feed))
        .route("/xrpc/blue.catbird.circle.getPostThread", get(circle::get_post_thread))
        .route("/xrpc/blue.catbird.circle.listNotifications", get(circle::list_notifications))
        .route("/xrpc/blue.catbird.circle.getMedia", get(circle::get_media))
        .with_state(Arc::new(state))
}
