use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    extract::{Extension, Query, State},
    Json,
};
use catbird_atproto::generated::blue_catbird::circle::list_notifications::{
    ListNotifications, ListNotificationsOutput,
};

pub async fn list_notifications_handler(
    Extension(user): Extension<AuthenticatedUser>,
    Query(query): Query<ListNotifications>,
    State(state): State<AppState>,
) -> Result<Json<ListNotificationsOutput>, AppError> {
    tracing::debug!("Handling listNotifications request");
    let output = crate::notifications::list_notifications(
        &state.db,
        &state.profile_hydrator,
        &user.did,
        query.limit,
        query.cursor.as_deref(),
    )
    .await?;

    Ok(Json(output))
}
