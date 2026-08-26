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

    // 2. Decrement cached member count
    sqlx::query(
        r#"
        UPDATE circle_member_cache_meta
        SET member_count = GREATEST(0, member_count - 1), last_refreshed_at = now()
        WHERE space_uri = $1
        "#,
    )
    .bind(space)
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

pub use delete_space as purge_space;

/// Space deletion cascades all Circle rows and removes the in-memory credential.
pub async fn delete_space(
    pool: &PgPool,
    credentials: &CredentialStore,
    space: &str,
) -> Result<(), PurgeError> {
    let mut tx = pool.begin().await?;

    // Deleting from circles cascades to circle_member_cache, circle_member_cache_meta,
    // circle_records, circle_likes, circle_repo_sync_state, circle_notifications,
    // circle_preferences, circle_reports
    sqlx::query("DELETE FROM circles WHERE space_uri = $1")
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

    // 3. Evict author from member cache
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
