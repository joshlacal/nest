use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    extract::{Extension, Query, State},
    Json,
};
use catbird_atproto::generated::blue_catbird::circle::get_feed::{GetFeed, GetFeedOutput};

pub async fn get_feed_handler(
    Extension(user): Extension<AuthenticatedUser>,
    Query(query): Query<GetFeed>,
    State(state): State<AppState>,
) -> Result<Json<GetFeedOutput>, AppError> {
    tracing::debug!("Handling getFeed request");
    let space_filter = query.space.as_ref().map(|s| s.as_str());
    let output = crate::feed::get_feed(
        &state.db,
        &state.profile_hydrator,
        &user.did,
        space_filter,
        query.limit,
        query.cursor.as_deref(),
        &state.config.circle_media_base_url,
    )
    .await?;

    Ok(Json(output))
}
