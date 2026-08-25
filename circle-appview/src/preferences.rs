use crate::access;
use crate::error::AppError;
use sqlx::PgPool;

pub async fn update_preferences(
    pool: &PgPool,
    member_did: &str,
    space_uri: &str,
    muted: bool,
) -> Result<bool, AppError> {
    // Requires a live lease
    access::check_active_lease(pool, space_uri, member_did).await?;

    sqlx::query(
        r#"
        INSERT INTO circle_preferences (space_uri, member_did, muted, updated_at)
        VALUES ($1, $2, $3, now())
        ON CONFLICT (space_uri, member_did)
        DO UPDATE SET muted = EXCLUDED.muted, updated_at = now()
        "#,
    )
    .bind(space_uri)
    .bind(member_did)
    .bind(muted)
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    Ok(muted)
}
