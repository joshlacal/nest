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

use axum::{routing::get, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod handlers;
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

    // Build CORS layer
    let cors = CorsLayer::new()
        .allow_origin(Any) // TODO: Restrict in production
        .allow_methods(Any)
        .allow_headers(Any);

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
    axum::serve(listener, app).await?;

    Ok(())
}
