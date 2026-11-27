use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    extract::{Extension, State},
    Json,
};
use petrel_catbird::generated::blue::catbird::circle::list_notifications::Output as ListNotificationsOutput;
use petrel_catbird::generated::blue::catbird::circle::list_notifications::Parameters as ListNotifications;

pub async fn list_notifications_handler(
    Extension(user): Extension<AuthenticatedUser>,
    crate::xrpc_query::XrpcQuery(query): crate::xrpc_query::XrpcQuery<ListNotifications>,
    State(state): State<AppState>,
) -> Result<Json<ListNotificationsOutput>, AppError> {
    tracing::debug!("Handling listNotifications request");
    let output = crate::notifications::list_notifications(
        &state,
        &user.did,
        Some(query.limit),
        query.cursor.as_deref(),
    )
    .await?;

    Ok(Json(output))
}
