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
    // 1. Require a live lease in the Space for the requesting user
    access::check_active_lease(&state.db, space, &user.did).await?;

    // 2. Validate author DID is an active writer/member in the Space (or Space authority)
    let is_authority = match access::extract_authority_did(space) {
        Ok(auth_did) => auth_did == did,
        Err(_) => false,
    };

    if !is_authority {
        let is_active_member: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT member_did
            FROM circle_members
            WHERE space_uri = $1 AND member_did = $2 AND status = 'active'
            "#,
        )
        .bind(space)
        .bind(did)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::Database)?;

        if is_active_member.is_none() {
            return Err(AppError::Forbidden(
                "Author is not an active writer in this Space".into(),
            ));
        }
    }

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

    let pds_endpoint = author_doc
        .service
        .iter()
        .find(|svc| {
            svc.id == "#atproto_pds"
                || svc.id.ends_with("#atproto_pds")
                || svc.r#type == "AtprotoPersonalDataServer"
        })
        .map(|svc| svc.service_endpoint.clone())
        .ok_or_else(|| {
            AppError::InvalidRequest("Author DID doc does not declare #atproto_pds".into())
        })?;

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
    // The handler-level check below acts as defense-in-depth / belt-and-suspenders.
    let max_bytes: usize = 20 * 1024 * 1024; // 20 MiB
    if bytes.len() > max_bytes {
        return Err(AppError::InvalidRequest(
            "Media payload exceeds maximum size of 20 MiB".into(),
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
