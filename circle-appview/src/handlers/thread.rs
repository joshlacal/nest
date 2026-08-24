use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    extract::{Extension, Query, State},
    Json,
};
use catbird_atproto::generated::blue_catbird::circle::get_post_thread::{
    GetPostThread, GetPostThreadOutput,
};

pub async fn get_post_thread_handler(
    Extension(user): Extension<AuthenticatedUser>,
    Query(query): Query<GetPostThread>,
    State(state): State<AppState>,
) -> Result<Json<GetPostThreadOutput>, AppError> {
    let output = crate::thread::get_post_thread(
        &state.db,
        &state.profile_hydrator,
        &user.did,
        query.uri.as_str(),
        query.space.as_str(),
        query.depth,
        query.parent_height,
        &state.config.circle_media_base_url,
    )
    .await?;

    Ok(Json(output))
}
