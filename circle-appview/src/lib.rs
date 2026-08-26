pub mod access;
pub mod auth;
pub mod commit;
pub mod config;
pub mod db;
pub mod error;
pub mod feed;
pub mod handlers;
pub mod hydration;
pub mod media;
pub mod notifications;
pub mod oauth;
pub mod preferences;
pub mod purge;
pub mod push;
pub mod reports;
pub mod routes;
pub mod space_client;
pub mod sync;
pub mod thread;
pub mod validator;

use std::future::Future;

pub const CIRCLE_PROTOCOL_REVISION: &str = "89deb9faca20e56fa2a262fe9746ed52bc1095ba";

pub use auth::{
    authenticate, AuthenticatedUser, DidDocument, DidResolver, PublicKeyJwk, VerificationMethod,
};
pub use config::{AppState, Config};
pub use error::AppError;
pub use routes::create_router;
pub use push::CirclePushClient;

/// Run Circle AppView HTTP server with graceful shutdown and guaranteed background sweep drain.
pub async fn run_server_with_shutdown<F>(
    config: Config,
    pool: sqlx::PgPool,
    shutdown_signal: F,
) -> Result<(), anyhow::Error>
where
    F: Future<Output = ()> + Send + 'static,
{
    let state = AppState::new(config.clone(), pool);
    let (sweep_handle, shutdown_tx) = sync::spawn_revision_sweep_task(
        state.clone(),
        std::time::Duration::from_secs(300),
    );

    let app = routes::create_router(state);
    let addr: std::net::SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Listening on {}", addr);

    let server_res = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await;

    // ALWAYS signal and await the sweep task regardless of whether server succeeded or failed
    let _ = shutdown_tx.send(true);
    let sweep_res = sweep_handle.await;

    match (server_res, sweep_res) {
        (Err(server_err), Err(join_err)) => {
            tracing::error!(server_err = %server_err, join_err = %join_err, "Both server and sweep shutdown failed");
            Err(anyhow::anyhow!("Server failed: {server_err}; sweep join failed: {join_err}"))
        }
        (Err(server_err), Ok(())) => {
            tracing::error!(server_err = %server_err, "Server failed during execution");
            Err(server_err.into())
        }
        (Ok(()), Err(join_err)) => {
            tracing::error!(join_err = %join_err, "Sweep task panicked or join failed");
            Err(join_err.into())
        }
        (Ok(()), Ok(())) => Ok(()),
    }
}
