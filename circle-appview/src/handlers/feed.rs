use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    extract::{Extension, State},
    Json,
};
use petrel_catbird::generated::blue::catbird::circle::get_feed::Output as GetFeedOutput;
use petrel_catbird::generated::blue::catbird::circle::get_feed::Parameters as GetFeed;

pub async fn get_feed_handler(
    Extension(user): Extension<AuthenticatedUser>,
    crate::xrpc_query::XrpcQuery(query): crate::xrpc_query::XrpcQuery<GetFeed>,
    State(state): State<AppState>,
) -> Result<Json<GetFeedOutput>, AppError> {
    tracing::debug!("Handling getFeed request");
    let space_filter = query.space.as_ref().map(|s| s.as_str());
    let output = crate::feed::get_feed(
        &state,
        &user.did,
        space_filter,
        Some(query.limit),
        query.cursor.as_deref(),
        query.include_encrypted.unwrap_or(false),
    )
    .await?;

    Ok(Json(output))
}
