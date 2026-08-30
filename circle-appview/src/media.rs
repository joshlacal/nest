use crate::access;
use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    body::Body,
    http::{header, HeaderValue},
    response::Response,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;

pub const MAX_CONCURRENT_MEDIA_TRANSFERS: usize = 16;
pub const MAX_MEDIA_BLOB_BYTES: usize = 20 * 1024 * 1024; // 20 MiB
pub const MAX_AGGREGATE_MEDIA_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

static MEDIA_CONCURRENCY_SEMAPHORE: std::sync::LazyLock<Arc<Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_MEDIA_TRANSFERS)));
static ACTIVE_MEDIA_BYTES: AtomicUsize = AtomicUsize::new(0);

pub struct MediaByteGuard(pub usize);
impl Drop for MediaByteGuard {
    fn drop(&mut self) {
        if self.0 > 0 {
            ACTIVE_MEDIA_BYTES.fetch_sub(self.0, Ordering::SeqCst);
        }
    }
}

pub fn active_media_bytes() -> usize {
    ACTIVE_MEDIA_BYTES.load(Ordering::SeqCst)
}

pub fn active_media_available_permits() -> usize {
    MEDIA_CONCURRENCY_SEMAPHORE.available_permits()
}

struct GuardedMediaStream {
    data: Option<bytes::Bytes>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _byte_guard: MediaByteGuard,
}

impl n0_future::Stream for GuardedMediaStream {
    type Item = Result<bytes::Bytes, std::convert::Infallible>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if let Some(data) = self.data.take() {
            std::task::Poll::Ready(Some(Ok(data)))
        } else {
            std::task::Poll::Ready(None)
        }
    }
}

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

    // 3. Validate CID syntax strictly (fail-closed before database or network)
    let _parsed_cid =
        cid::Cid::try_from(cid).map_err(|_| AppError::NotFound("Not Found".into()))?;

    // 4. Local active-accepted-record CID authorization before any Space media request.
    // Must match either exact record CID or an exact blob reference in record_json.
    // If unauthorized, unknown, or removed, return uniform 404 without hitting upstream.
    let record_exists: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT uri FROM circle_records
        WHERE space_uri = $1
          AND author_did = $2
          AND deleted_at IS NULL
          AND (
            cid = $3
            OR jsonb_path_exists(record_json, '$.**."$link" ? (@ == $cid)', jsonb_build_object('cid', $3))
          )
        LIMIT 1
        "#,
    )
    .bind(space)
    .bind(did)
    .bind(cid)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::Database)?;

    if record_exists.is_none() {
        return Err(AppError::NotFound("Not Found".into()));
    }

    // 5. Enforce aggregate concurrent media transfer limit before upstream request
    let permit = MEDIA_CONCURRENCY_SEMAPHORE
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            AppError::InvalidRequest("Aggregate concurrent media transfer limit reached".into())
        })?;
    // 5. Obtain active Space credential from CredentialStore
    let credential = state
        .credential_store
        .get(space)
        .await
        .ok_or(AppError::NotFound("Not Found".into()))?;

    // 6. Resolve exact author #atproto_pds endpoint
    let author_doc = match state.did_resolver.resolve(did).await {
        Ok(doc) => doc,
        Err(_) => return Err(AppError::NotFound("Not Found".into())),
    };

    let (pds_endpoint, _) = match crate::access::resolve_pds_endpoint(&author_doc, did) {
        Ok(ep) => ep,
        Err(_) => return Err(AppError::NotFound("Not Found".into())),
    };

    // 7. Fetch blob via SpaceClient with active Space credential and DPoP proof
    let (content_type, bytes) = match state
        .space_client
        .get_blob(
            &pds_endpoint,
            space,
            did,
            cid,
            &credential.token,
            &credential.dpop_key,
        )
        .await
    {
        Ok(res) => res,
        Err(_) => return Err(AppError::NotFound("Not Found".into())),
    };

    // 8. Layered enforcement: per-response streaming cap and aggregate byte budget
    if bytes.len() > MAX_MEDIA_BLOB_BYTES {
        return Err(AppError::InvalidRequest(
            "Media blob size exceeds maximum permitted size".into(),
        ));
    }

    let byte_len = bytes.len();
    let prev_bytes = ACTIVE_MEDIA_BYTES.fetch_add(byte_len, Ordering::SeqCst);
    if prev_bytes + byte_len > MAX_AGGREGATE_MEDIA_BYTES {
        ACTIVE_MEDIA_BYTES.fetch_sub(byte_len, Ordering::SeqCst);
        return Err(AppError::InvalidRequest(
            "Aggregate active media byte budget exceeded".into(),
        ));
    }
    let byte_guard = MediaByteGuard(byte_len);

    let content_type_str = content_type
        .as_deref()
        .unwrap_or("application/octet-stream");

    // Validate content type does not contain control characters
    let header_val = HeaderValue::from_str(content_type_str).map_err(|_| {
        AppError::InvalidRequest("Invalid Content-Type header from upstream".into())
    })?;

    let stream = GuardedMediaStream {
        data: Some(bytes::Bytes::from(bytes)),
        _permit: permit,
        _byte_guard: byte_guard,
    };

    let response = Response::builder()
        .header(header::CONTENT_TYPE, header_val)
        .header(header::CONTENT_LENGTH, byte_len)
        .header(header::CACHE_CONTROL, "no-store, private")
        .body(Body::from_stream(stream))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {e}")))?;

    Ok(response)
}
