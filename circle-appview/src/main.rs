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

    let state = AppState::new(config.clone(), pool);
    let (sweep_handle, shutdown_tx) = circle_appview::sync::spawn_revision_sweep_task(
        state.clone(),
        std::time::Duration::from_secs(300),
    );

    let app = routes::create_router(state);
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Listening on {}", addr);

    let server = axum::serve(listener, app);
    tokio::select! {
        res = server => {
            if let Err(e) = res {
                tracing::error!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutdown signal received, draining server and background tasks");
        }
    }

    let _ = shutdown_tx.send(true);
    let _ = sweep_handle.await;
    Ok(())
}
