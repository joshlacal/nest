//! Catbird Nest - ATProto BFF Gateway
//!
//! A Backend-for-Frontend (BFF) gateway that acts as a confidential OAuth client
//! for the AT Protocol. This gateway:
//!
//! - Handles OAuth authentication with ATProto PDS servers
//! - Manages user sessions and token refresh
//! - Proxies XRPC requests to the user's PDS
//! - Enriches responses (e.g., handling blocked posts)
//!
//! The iOS app communicates only with this gateway, never directly with the PDS.

use axum::{middleware as axum_mw, routing::get, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod handlers;
mod metrics;
mod middleware;
mod models;
mod routes;
mod services;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "catbird=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!(
        "Starting Catbird Nest Gateway v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Load configuration
    let app_config = config::AppConfig::load().map_err(|e| {
        tracing::error!("Failed to load configuration: {}", e);
        anyhow::anyhow!("Configuration error: {}", e)
    })?;

    tracing::info!(
        "Configuration loaded. Server will listen on {}:{}",
        app_config.server.host,
        app_config.server.port
    );

    // Initialize application state
    let state = Arc::new(config::AppState::new(app_config.clone()).await?);

    tracing::info!("Connected to Redis at {}", app_config.redis.url);

    // Register Prometheus metrics
    metrics::register_metrics();
    tracing::info!("Prometheus metrics registered");

    // Start background task to update active sessions gauge
    let metrics_state = state.clone();
    let key_prefix = app_config.redis.key_prefix.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            match count_active_sessions(&metrics_state.redis, &key_prefix).await {
                Ok(count) => metrics::set_active_sessions(count as f64),
                Err(e) => tracing::warn!("Failed to count active sessions: {}", e),
            }
        }
    });

    // Build CORS layer
    let cors = if app_config.server.allowed_origins.is_empty() {
        CorsLayer::permissive()
    } else {
        let origins: Vec<axum::http::HeaderValue> = app_config
            .server
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::DELETE,
                axum::http::Method::PUT,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
                axum::http::header::ACCEPT,
            ])
    };

    // Start admin metrics server on internal-only port
    let admin_port = app_config.server.admin_port;
    tokio::spawn(async move {
        let admin_app = Router::new().route("/metrics", get(metrics::metrics_handler));
        let admin_addr = SocketAddr::from(([127, 0, 0, 1], admin_port));
        tracing::info!("Admin metrics listening on http://{}", admin_addr);
        let listener = tokio::net::TcpListener::bind(admin_addr)
            .await
            .expect("Failed to bind admin metrics port");
        axum::serve(listener, admin_app)
            .await
            .expect("Admin metrics server failed");
    });

    // Build the router
    let app = Router::new()
        // Health endpoints
        .route("/health", get(routes::health::health_check))
        .route("/ready", get(routes::health::readiness_check))
        .route("/live", get(routes::health::liveness_check))
        // ATProto routes (auth + xrpc proxy)
        .merge(routes::atproto::create_router(state.clone()))
        // Global middleware
        .layer(TraceLayer::new_for_http())
        .layer(axum_mw::from_fn(middleware::request_id_middleware))
        .layer(cors)
        .with_state(state);

    // Start the server
    let addr = SocketAddr::from((
        app_config
            .server
            .host
            .parse::<std::net::IpAddr>()
            .unwrap_or([127, 0, 0, 1].into()),
        app_config.server.port,
    ));

    tracing::info!("Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Wait for SIGTERM or CTRL+C for graceful shutdown
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received CTRL+C, shutting down gracefully..."),
        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down gracefully..."),
    }
}

/// Count active sessions in Redis by scanning session keys
async fn count_active_sessions(
    redis: &redis::aio::ConnectionManager,
    key_prefix: &str,
) -> Result<usize, redis::RedisError> {
    let pattern = format!("{}session:*", key_prefix);
    let mut conn = redis.clone();
    let mut count = 0usize;
    let mut cursor: u64 = 0;
    loop {
        let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(100)
            .query_async(&mut conn)
            .await?;
        count += keys.len();
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }
    Ok(count)
}
