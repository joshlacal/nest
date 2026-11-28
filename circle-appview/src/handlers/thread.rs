use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    extract::{Extension, State},
    Json,
};
use petrel_catbird::generated::blue::catbird::circle::get_post_thread::Output as GetPostThreadOutput;
use petrel_catbird::generated::blue::catbird::circle::get_post_thread::Parameters as GetPostThread;

pub async fn get_post_thread_handler(
    Extension(user): Extension<AuthenticatedUser>,
    crate::xrpc_query::XrpcQuery(query): crate::xrpc_query::XrpcQuery<GetPostThread>,
    State(state): State<AppState>,
) -> Result<Json<GetPostThreadOutput>, AppError> {
    tracing::debug!("Handling getPostThread request");
    let output = crate::thread::get_post_thread(
        &state,
        &user.did,
        query.uri.as_str(),
        query.space.as_str(),
        Some(query.depth),
        Some(query.parent_height),
        query.include_encrypted.unwrap_or(false),
    )
    .await?;
    Ok(Json(output))
}
