use crate::access::CredentialStore;
use sqlx::PgPool;

#[derive(Debug, thiserror::Error)]
pub enum PurgeError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

/// Member removal deletes that user's lease and unread notification visibility only.
/// Published records by that member remain part of the Space history.
pub async fn remove_member(pool: &PgPool, space: &str, member: &str) -> Result<(), PurgeError> {
    let mut tx = pool.begin().await?;

    // 1. Mark member status as removed
    sqlx::query(
        r#"
        UPDATE circle_members
        SET status = 'removed', updated_at = now()
        WHERE space_uri = $1 AND member_did = $2
        "#,
    )
    .bind(space)
    .bind(member)
    .execute(&mut *tx)
    .await?;

    // 2. Delete active lease
    sqlx::query("DELETE FROM access_leases WHERE space_uri = $1 AND member_did = $2")
        .bind(space)
        .bind(member)
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

/// Space deletion cascades all Circle rows and removes the in-memory credential.
pub async fn delete_space(
    pool: &PgPool,
    credentials: &CredentialStore,
    space: &str,
) -> Result<(), PurgeError> {
    let mut tx = pool.begin().await?;

    // Deleting from circles cascades to circle_members, access_leases, circle_records,
    // circle_likes, circle_repo_sync_state, circle_notifications, circle_preferences, circle_reports
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

    // 3. Delete access leases
    sqlx::query("DELETE FROM access_leases WHERE member_did = $1")
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
