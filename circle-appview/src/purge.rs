use crate::access::CredentialStore;
use sqlx::PgPool;

#[derive(Debug, thiserror::Error)]
pub enum PurgeError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

/// Member removal evicts that user from the cache and deletes unread notification visibility.
/// Published records by that member remain part of the Space history.
pub async fn remove_member(pool: &PgPool, space: &str, member: &str) -> Result<(), PurgeError> {
    let mut tx = pool.begin().await?;

    // 1. Evict member from cache
    sqlx::query("DELETE FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2")
        .bind(space)
        .bind(member)
        .execute(&mut *tx)
        .await?;

    // 2. Advance circles access_epoch, increment generation, then assign circle_member_cache_meta.access_epoch = circles.access_epoch
    let new_epoch: (i64,) = sqlx::query_as(
        r#"
        UPDATE circles
        SET access_epoch = access_epoch + 1
        WHERE space_uri = $1
        RETURNING access_epoch
        "#,
    )
    .bind(space)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count, access_epoch, app_access_granted, generation)
        VALUES ($1, now(), 0, $2, (SELECT app_access_granted FROM circles WHERE space_uri = $1), 1)
        ON CONFLICT (space_uri) DO UPDATE
        SET member_count = GREATEST(0, circle_member_cache_meta.member_count - 1),
            access_epoch = $2,
            generation = circle_member_cache_meta.generation + 1,
            last_refreshed_at = now()
        "#,
    )
    .bind(space)
    .bind(new_epoch.0)
    .execute(&mut *tx)
    .await?;

    // 3. Delete notifications directed to removed member in this Space
    sqlx::query("DELETE FROM circle_notifications WHERE space_uri = $1 AND recipient_did = $2")
        .bind(space)
        .bind(member)
        .execute(&mut *tx)
        .await?;

    // 4. Delete preferences
    sqlx::query("DELETE FROM circle_preferences WHERE space_uri = $1 AND member_did = $2")
        .bind(space)
        .bind(member)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

/// appAccess removal lifecycle:
/// 1. Persists grant state in its own transaction first: disables private serving immediately
///    (app_access_granted = false, app_access_revoked_at = now(), deleted_at = now()) and advances access_epoch.
/// 2. Revokes/deletes Space credentials from in-memory CredentialStore.
/// 3. Performs bounded batch purge of projected private data so a large purge failure cannot leave the Circle serving.
pub async fn revoke_app_access(
    pool: &PgPool,
    credentials: &CredentialStore,
    space: &str,
) -> Result<(), PurgeError> {
    // 1. Transaction 1: Commit the state flip and gate flag immediately
    let mut tx = pool.begin().await?;

    let new_epoch: (i64,) = sqlx::query_as(
        r#"
        UPDATE circles
        SET app_access_granted = false,
            app_access_revoked_at = now(),
            access_epoch = access_epoch + 1,
            deleted_at = COALESCE(deleted_at, now())
        WHERE space_uri = $1
        RETURNING access_epoch
        "#,
    )
    .bind(space)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count, access_epoch, app_access_granted, generation)
        VALUES ($1, now(), 0, $2, false, 1)
        ON CONFLICT (space_uri) DO UPDATE
        SET app_access_granted = false,
            access_epoch = $2,
            member_count = 0,
            generation = circle_member_cache_meta.generation + 1,
            last_refreshed_at = now()
        "#,
    )
    .bind(space)
    .bind(new_epoch.0)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // 2. Immediately revoke credentials in-memory
    credentials.remove(space).await;

    // 3. Purge projected rows in bounded batches
    purge_circle_projected_data(pool, space).await?;

    Ok(())
}

/// Purges projected rows for a space in bounded batches across all tables.
pub async fn purge_circle_projected_data(pool: &PgPool, space: &str) -> Result<(), PurgeError> {
    const BATCH_SIZE: i64 = 1000;

    // Notifications
    loop {
        let deleted = sqlx::query(
            r#"
            DELETE FROM circle_notifications
            WHERE ctid IN (
                SELECT ctid FROM circle_notifications
                WHERE space_uri = $1
                LIMIT $2
            )
            "#,
        )
        .bind(space)
        .bind(BATCH_SIZE)
        .execute(pool)
        .await?
        .rows_affected();
        if deleted < BATCH_SIZE as u64 {
            break;
        }
    }

    // Preferences
    loop {
        let deleted = sqlx::query(
            r#"
            DELETE FROM circle_preferences
            WHERE ctid IN (
                SELECT ctid FROM circle_preferences
                WHERE space_uri = $1
                LIMIT $2
            )
            "#,
        )
        .bind(space)
        .bind(BATCH_SIZE)
        .execute(pool)
        .await?
        .rows_affected();
        if deleted < BATCH_SIZE as u64 {
            break;
        }
    }

    // Member cache
    loop {
        let deleted = sqlx::query(
            r#"
            DELETE FROM circle_member_cache
            WHERE ctid IN (
                SELECT ctid FROM circle_member_cache
                WHERE space_uri = $1
                LIMIT $2
            )
            "#,
        )
        .bind(space)
        .bind(BATCH_SIZE)
        .execute(pool)
        .await?
        .rows_affected();
        if deleted < BATCH_SIZE as u64 {
            break;
        }
    }

    // Likes
    loop {
        let deleted = sqlx::query(
            r#"
            DELETE FROM circle_likes
            WHERE ctid IN (
                SELECT ctid FROM circle_likes
                WHERE space_uri = $1
                LIMIT $2
            )
            "#,
        )
        .bind(space)
        .bind(BATCH_SIZE)
        .execute(pool)
        .await?
        .rows_affected();
        if deleted < BATCH_SIZE as u64 {
            break;
        }
    }

    // Records
    loop {
        let deleted = sqlx::query(
            r#"
            DELETE FROM circle_records
            WHERE ctid IN (
                SELECT ctid FROM circle_records
                WHERE space_uri = $1
                LIMIT $2
            )
            "#,
        )
        .bind(space)
        .bind(BATCH_SIZE)
        .execute(pool)
        .await?
        .rows_affected();
        if deleted < BATCH_SIZE as u64 {
            break;
        }
    }

    // Rejections
    loop {
        let deleted = sqlx::query(
            r#"
            DELETE FROM circle_rejections
            WHERE ctid IN (
                SELECT ctid FROM circle_rejections
                WHERE space_uri = $1
                LIMIT $2
            )
            "#,
        )
        .bind(space)
        .bind(BATCH_SIZE)
        .execute(pool)
        .await?
        .rows_affected();
        if deleted < BATCH_SIZE as u64 {
            break;
        }
    }

    Ok(())
}

pub use delete_space as purge_space;

/// Space deletion cascades all Circle rows and removes the in-memory credential.
pub async fn delete_space(
    pool: &PgPool,
    credentials: &CredentialStore,
    space: &str,
) -> Result<(), PurgeError> {
    let mut tx = pool.begin().await?;

    // Linearizable tombstone: mark deleted_at = now()
    sqlx::query(
        "UPDATE circles SET deleted_at = now() WHERE space_uri = $1 AND deleted_at IS NULL",
    )
    .bind(space)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM circle_member_cache_meta WHERE space_uri = $1")
        .bind(space)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM circle_records WHERE space_uri = $1")
        .bind(space)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM circle_likes WHERE space_uri = $1")
        .bind(space)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM circle_repo_sync_state WHERE space_uri = $1")
        .bind(space)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM circle_notifications WHERE space_uri = $1")
        .bind(space)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM circle_preferences WHERE space_uri = $1")
        .bind(space)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM circle_reports WHERE space_uri = $1")
        .bind(space)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM circle_rejections WHERE space_uri = $1")
        .bind(space)
        .execute(&mut *tx)
        .await?;

    // Also remove from credential store
    credentials.remove(space).await;
    tx.commit().await?;
    Ok(())
}

/// Account deactivation hides that author's records without exposing a public tombstone.
pub async fn deactivate_author(pool: &PgPool, author: &str) -> Result<(), PurgeError> {
    let mut tx = pool.begin().await?;

    // 1. Soft-delete author records
    sqlx::query(
        "UPDATE circle_records SET deleted_at = now() WHERE author_did = $1 AND deleted_at IS NULL",
    )
    .bind(author)
    .execute(&mut *tx)
    .await?;

    // 2. Delete author's likes
    sqlx::query("DELETE FROM circle_likes WHERE author_did = $1")
        .bind(author)
        .execute(&mut *tx)
        .await?;

    // 3. Increment generation on spaces where author is a member and evict from cache
    sqlx::query(
        r#"
        UPDATE circle_member_cache_meta
        SET generation = generation + 1, last_refreshed_at = now()
        WHERE space_uri IN (SELECT space_uri FROM circle_member_cache WHERE member_did = $1)
        "#,
    )
    .bind(author)
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM circle_member_cache WHERE member_did = $1")
        .bind(author)
        .execute(&mut *tx)
        .await?;

    // 4. Delete notifications where author is recipient or actor
    sqlx::query("DELETE FROM circle_notifications WHERE recipient_did = $1 OR actor_did = $1")
        .bind(author)
        .execute(&mut *tx)
        .await?;

    // 5. Delete preferences
    sqlx::query("DELETE FROM circle_preferences WHERE member_did = $1")
        .bind(author)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}
