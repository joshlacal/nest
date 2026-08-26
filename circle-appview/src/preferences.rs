use crate::access;
use crate::config::AppState;
use crate::error::AppError;

pub async fn update_preferences(
    state: &AppState,
    member_did: &str,
    space_uri: &str,
    muted: bool,
) -> Result<bool, AppError> {
    // Requires verified member access in the Space
    access::check_member_access(state, space_uri, member_did).await?;

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
    .execute(&state.db)
    .await
    .map_err(AppError::Database)?;

    Ok(muted)
}
