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
pub mod notify;
pub mod oauth;
pub mod preferences;
pub mod purge;
pub mod push;
pub mod reports;
pub mod routes;
pub mod space_client;
pub mod space_signature;
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
pub use push::CirclePushClient;
pub use routes::create_router;

/// Spawn and retain a production JTI nonce cleanup task on a repeating interval.
/// Runs `db::cleanup_expired_nonces` on each tick and terminates gracefully on shutdown or sender drop.
pub fn spawn_jti_cleanup_task(
    pool: sqlx::PgPool,
    interval_duration: std::time::Duration,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Sender<bool>,
) {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_duration);
        interval.tick().await;

        loop {
            tokio::select! {
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        tracing::info!("JTI cleanup background task shutting down");
                        break;
                    }
                }
                _ = interval.tick() => {
                    match db::cleanup_expired_nonces(&pool).await {
                        Ok(deleted) => {
                            if deleted > 0 {
                                tracing::info!(deleted_nonces = deleted, "Cleaned up expired JTI nonces");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Scheduled JTI nonce cleanup failed");
                        }
                    }
                }
            }
        }
    });
    (handle, shutdown_tx)
}

/// Spawn and retain a production rejection retention cleanup task on a repeating interval.
/// Runs `validator::prune_rejections` on each tick and terminates gracefully on shutdown or sender drop.
pub fn spawn_rejections_cleanup_task(
    pool: sqlx::PgPool,
    interval_duration: std::time::Duration,
    max_age_days: i32,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Sender<bool>,
) {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_duration);
        interval.tick().await;

        loop {
            tokio::select! {
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        tracing::info!("Rejections cleanup background task shutting down");
                        break;
                    }
                }
                _ = interval.tick() => {
                    match validator::prune_rejections(&pool, max_age_days).await {
                        Ok(deleted) => {
                            if deleted > 0 {
                                tracing::info!(deleted_rejections = deleted, "Pruned expired circle rejections");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Scheduled circle rejections pruning failed");
                        }
                    }
                }
            }
        }
    });
    (handle, shutdown_tx)
}
/// How long a deleted Circle's tombstone row is kept. While it exists, reads of
/// that Circle answer `AccessRemoved` so devices that were offline purge their
/// caches; after it is purged they get `NotFound`.
pub const TOMBSTONE_RETENTION_DAYS: i32 = 30;

/// Spawn and retain a production tombstone purge task on a repeating interval.
/// Runs `purge::purge_expired_tombstones` on each tick and terminates gracefully on shutdown or sender drop.
pub fn spawn_tombstone_purge_task(
    pool: sqlx::PgPool,
    interval_duration: std::time::Duration,
    max_age_days: i32,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Sender<bool>,
) {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_duration);
        interval.tick().await;

        loop {
            tokio::select! {
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        tracing::info!("Tombstone purge background task shutting down");
                        break;
                    }
                }
                _ = interval.tick() => {
                    match purge::purge_expired_tombstones(&pool, max_age_days).await {
                        Ok(deleted) => {
                            if deleted > 0 {
                                tracing::info!(deleted_tombstones = deleted, "Purged expired circle tombstones");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Scheduled circle tombstone purge failed");
                        }
                    }
                }
            }
        }
    });
    (handle, shutdown_tx)
}

/// Run Circle AppView HTTP server with graceful shutdown and guaranteed background sweep drain.
pub async fn run_server_with_shutdown<F>(
    config: Config,
    pool: sqlx::PgPool,
    shutdown_signal: F,
) -> Result<(), anyhow::Error>
where
    F: Future<Output = ()> + Send + 'static,
{
    let state = AppState::new(config.clone(), pool.clone());
    let app = routes::create_router(state.clone());
    let addr: std::net::SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Listening on {}", addr);

    let (sweep_handle, sweep_shutdown_tx) =
        sync::spawn_revision_sweep_task(state.clone(), std::time::Duration::from_secs(300));
    let (jti_handle, jti_shutdown_tx) =
        spawn_jti_cleanup_task(pool.clone(), std::time::Duration::from_secs(60));
    let (rejections_handle, rejections_shutdown_tx) =
        spawn_rejections_cleanup_task(pool.clone(), std::time::Duration::from_secs(3600), 7);
    let (tombstone_handle, tombstone_shutdown_tx) = spawn_tombstone_purge_task(
        pool,
        std::time::Duration::from_secs(3600),
        TOMBSTONE_RETENTION_DAYS,
    );
    let server_res = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await;

    // ALWAYS signal and await background tasks regardless of whether server succeeded or failed
    let _ = sweep_shutdown_tx.send(true);
    let _ = jti_shutdown_tx.send(true);
    let _ = rejections_shutdown_tx.send(true);
    let _ = tombstone_shutdown_tx.send(true);
    let sweep_res = sweep_handle.await;
    let jti_res = jti_handle.await;
    let rejections_res = rejections_handle.await;
    let tombstone_res = tombstone_handle.await;
    match (
        server_res,
        sweep_res,
        jti_res,
        rejections_res,
        tombstone_res,
    ) {
        (Err(server_err), _, _, _, _) => {
            tracing::error!(server_err = %server_err, "Server failed during execution");
            Err(server_err.into())
        }
        (Ok(()), Err(join_err), _, _, _) => {
            tracing::error!(join_err = %join_err, "Sweep task panicked or join failed");
            Err(join_err.into())
        }
        (Ok(()), _, Err(join_err), _, _) => {
            tracing::error!(join_err = %join_err, "JTI cleanup task panicked or join failed");
            Err(join_err.into())
        }
        (Ok(()), _, _, Err(join_err), _) => {
            tracing::error!(join_err = %join_err, "Rejections cleanup task panicked or join failed");
            Err(join_err.into())
        }
        (Ok(()), _, _, _, Err(join_err)) => {
            tracing::error!(join_err = %join_err, "Tombstone purge task panicked or join failed");
            Err(join_err.into())
        }
        (Ok(()), Ok(()), Ok(()), Ok(()), Ok(())) => Ok(()),
    }
}
