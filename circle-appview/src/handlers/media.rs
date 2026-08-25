use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    extract::{Extension, Query, State},
    response::Response,
};
use catbird_atproto::generated::blue_catbird::circle::get_media::GetMedia;

pub async fn get_media_handler(
    Extension(user): Extension<AuthenticatedUser>,
    Query(query): Query<GetMedia>,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    tracing::debug!("Handling getMedia request");
    crate::media::get_media(
        &state,
        user,
        query.space.as_str(),
        query.did.as_str(),
        query.cid.as_str(),
    )
    .await
}
