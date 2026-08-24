use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool};

pub async fn init_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

/// Atomically consume a single-use JTI nonce.
/// Returns Ok(true) if the nonce was new and recorded, or Ok(false) if it was already used (replay).
pub async fn consume_jti_nonce(
    pool: &PgPool,
    jti: &str,
    issuer_did: &str,
    audience: &str,
    expires_at: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        INSERT INTO auth_jti_nonce (jti, issuer_did, audience, expires_at, consumed_at)
        VALUES ($1, $2, $3, $4, now())
        ON CONFLICT (jti) DO NOTHING
        "#,
    )
    .bind(jti)
    .bind(issuer_did)
    .bind(audience)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Delete expired JTI nonces from the database.
pub async fn cleanup_expired_nonces(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM auth_jti_nonce WHERE expires_at < now()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
