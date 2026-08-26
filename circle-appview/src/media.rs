use crate::access;
use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::{AppError, AuthReason};
use axum::{
    body::Body,
    http::{header, HeaderValue},
    response::Response,
};

pub async fn get_media(
    state: &AppState,
    user: AuthenticatedUser,
    space: &str,
    did: &str,
    cid: &str,
) -> Result<Response, AppError> {
    // 1. Require verified member access in the Space for the requesting user
    access::check_member_access(state, space, &user.did).await?;

    // 2. Validate author DID is a verified member in the Space (or Space authority)
    access::check_member_access(state, space, did).await?;

    // 3. Obtain active Space credential from CredentialStore
    let credential = state
        .credential_store
        .get(space)
        .await
        .ok_or(AppError::Unauthorized(AuthReason::Expired))?;

    // 4. Resolve exact author #atproto_pds endpoint
    let author_doc = state
        .did_resolver
        .resolve(did)
        .await
        .map_err(AppError::Unauthorized)?;

    let (pds_endpoint, _) = crate::access::resolve_pds_endpoint(&author_doc, did)?;

    // 5. Fetch blob via SpaceClient with active Space credential and DPoP proof
    let (content_type, bytes) = state
        .space_client
        .get_blob(
            &pds_endpoint,
            space,
            did,
            cid,
            &credential.token,
            &credential.dpop_key,
        )
        .await?;

    // Layered enforcement: DefaultSpaceHostTransport::get_blob streaming cap is the primary
    // line of defense to abort oversized network transfers without exhausting memory.
    let max_bytes: usize = 20 * 1024 * 1024; // 20 MiB
    if bytes.len() > max_bytes {
        return Err(AppError::InvalidRequest(
            "Media blob size exceeds maximum permitted size".into(),
        ));
    }

    let content_type_str = content_type
        .as_deref()
        .unwrap_or("application/octet-stream");

    // Validate content type does not contain control characters
    let header_val = HeaderValue::from_str(content_type_str)
        .map_err(|_| AppError::InvalidRequest("Invalid Content-Type header from upstream".into()))?;
    let response = Response::builder()
        .header(header::CONTENT_TYPE, header_val)
        .header(header::CONTENT_LENGTH, bytes.len())
        .header(header::CACHE_CONTROL, "no-store, private")
        .body(Body::from(bytes))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {e}")))?;

    Ok(response)
}
