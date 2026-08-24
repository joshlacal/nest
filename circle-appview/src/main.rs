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

    let config = Config::from_env()?;
    tracing::info!(host = %config.host, port = config.port, "Starting Circle AppView");

    let pool = db::init_pool(&config.database_url).await?;
    tracing::info!("Running database migrations");
    db::run_migrations(&pool).await?;

    let state = AppState::new(config.clone(), pool);
    let app = routes::create_router(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Listening on {}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}
