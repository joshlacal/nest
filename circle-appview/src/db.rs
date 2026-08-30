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

pub const MAX_JTI_LEN: usize = 512;
pub const MAX_ACTIVE_JTIS_PER_ISSUER: i64 = 1000;
pub const MAX_ACTIVE_JTIS_GLOBAL: i64 = 200_000;
pub const MAX_JTI_CLEANUP_BATCH_SIZE: i64 = 5000;
pub const DEFAULT_CLEANUP_BATCHES_PER_RUN: usize = 50;

/// Atomically consume a single-use JTI nonce under an issuer advisory lock and transaction.
/// Returns Ok(true) if the nonce was new and recorded, or Ok(false) if it was already used (replay),
/// invalid, or exceeded per-issuer or global active admission limits.
pub async fn consume_jti_nonce(
    pool: &PgPool,
    jti: &str,
    issuer_did: &str,
    audience: &str,
    expires_at: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    if jti.is_empty() || jti.len() > MAX_JTI_LEN {
        return Ok(false);
    }

    let mut tx = pool.begin().await?;

    // Serialize admission per issuer using a transaction-scoped advisory lock
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(issuer_did)
        .execute(&mut *tx)
        .await?;

    // Check active unexpired JTIs count for this issuer to bound per-issuer retention/admission
    let active_issuer_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM auth_jti_nonce WHERE issuer_did = $1 AND expires_at > now()",
    )
    .bind(issuer_did)
    .fetch_one(&mut *tx)
    .await?;

    if active_issuer_count.0 >= MAX_ACTIVE_JTIS_PER_ISSUER {
        return Ok(false);
    }

    // Check global active unexpired JTIs count to enforce bounded global retention
    let active_global_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM auth_jti_nonce WHERE expires_at > now()")
            .fetch_one(&mut *tx)
            .await?;

    if active_global_count.0 >= MAX_ACTIVE_JTIS_GLOBAL {
        return Ok(false);
    }

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
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(result.rows_affected() > 0)
}

/// Backlog-aware cleanup that drains expired JTI nonces from the database in bounded batches without unbounded transactions.
pub async fn cleanup_expired_nonces(pool: &PgPool) -> Result<u64, sqlx::Error> {
    cleanup_expired_nonces_drain(pool, MAX_JTI_CLEANUP_BATCH_SIZE, 0).await
}

/// Delete expired JTI nonces from the database with a specified batch size and maximum batch count (0 = drain until exhausted).
pub async fn cleanup_expired_nonces_drain(
    pool: &PgPool,
    batch_size: i64,
    max_batches: usize,
) -> Result<u64, sqlx::Error> {
    let mut total_deleted = 0u64;
    let mut batches_run = 0;
    loop {
        if max_batches > 0 && batches_run >= max_batches {
            break;
        }
        let deleted = cleanup_expired_nonces_batch(pool, batch_size).await?;
        total_deleted += deleted;
        batches_run += 1;
        if (deleted as i64) < batch_size {
            break;
        }
    }
    Ok(total_deleted)
}

/// Delete a single bounded batch of expired JTI nonces from the database.
pub async fn cleanup_expired_nonces_batch(
    pool: &PgPool,
    batch_size: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM auth_jti_nonce
        WHERE jti IN (
            SELECT jti FROM auth_jti_nonce
            WHERE expires_at < now()
            LIMIT $1
        )
        "#,
    )
    .bind(batch_size)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
