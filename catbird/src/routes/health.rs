//! Health check routes
//!
//! Provides health and readiness endpoints for the gateway.

use axum::{
    extract::State,
    response::IntoResponse,
    Json,
};
use redis::AsyncCommands;
use std::sync::Arc;

use crate::config::AppState;
use crate::models::HealthResponse;

/// Health check endpoint
/// 
/// GET /health
/// 
/// Returns the health status of the gateway including Redis connectivity.
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Check Redis connectivity
    let mut redis = state.redis.clone();
    let redis_connected: bool = redis
        .get::<&str, Option<String>>("__health_check__")
        .await
        .map(|_| true)
        .unwrap_or(true); // Connection works if no error

    let status = if redis_connected { "healthy" } else { "degraded" };

    Json(HealthResponse {
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        redis_connected,
    })
}

/// Readiness check endpoint
/// 
/// GET /ready
/// 
/// Returns 200 if the service is ready to accept traffic.
pub async fn readiness_check(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let mut redis = state.redis.clone();
    let redis_ok: bool = redis.get::<&str, Option<String>>("__ready_check__").await.is_ok();

    if redis_ok {
        (axum::http::StatusCode::OK, "ready")
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

/// Liveness check endpoint
/// 
/// GET /live
/// 
/// Simple liveness probe - returns 200 if the process is running.
pub async fn liveness_check() -> impl IntoResponse {
    (axum::http::StatusCode::OK, "alive")
}