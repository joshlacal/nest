use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use circle_appview::{
    config::{AppState, Config},
    db, routes,
};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "circle_appview=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let mut config = Config::from_env()?;
    tracing::info!(host = %config.host, port = config.port, "Starting Circle AppView");

    let pool = db::init_pool(&config.database_url).await?;
    tracing::info!("Running database migrations");
    db::run_migrations(&pool).await?;

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let did_resolver =
        circle_appview::auth::DidResolver::new(config.plc_directory_url.clone(), http_client);

    if config.nest_verifying_keys.is_empty() {
        tracing::info!(url = %config.nest_jwks_url, "Loading Nest JWKS at startup");
        let keys = circle_appview::auth::fetch_https_jwks(&did_resolver, &config.nest_jwks_url)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to load Nest JWKS from {}: {:?}",
                    config.nest_jwks_url,
                    e
                )
            })?;
        config.nest_verifying_keys = keys;
    }

    circle_appview::run_server_with_shutdown(config, pool, shutdown_signal()).await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => signal.recv().await,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to install SIGTERM handler");
                std::future::pending::<Option<()>>().await
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<Option<()>>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received SIGINT, initiating graceful shutdown");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        }
    }
}
