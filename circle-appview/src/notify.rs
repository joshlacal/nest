//! Notification registration at a Circle's space host (CIRCLES-06).
//!
//! Upstream space hosts forward notifyWrite and notifySpaceDeleted only to
//! services registered with `com.atproto.space.registerNotify` on the
//! authority's space host. A registration lasts 24 h, so it is renewed once it
//! is within [`RENEW_MARGIN`] of `expiresAt`.

use chrono::{DateTime, Utc};

use crate::access::{
    extract_authority_did, resolve_space_host_endpoint, space_fingerprint, ActiveSpaceCredential,
};
use crate::config::AppState;
use crate::error::{AppError, AuthReason};

/// Renew a registration this long before the space host's `expiresAt`.
pub const RENEW_MARGIN: chrono::Duration = chrono::Duration::hours(1);

/// Register, or renew, this AppView's notify registration for `space_uri`.
/// Returns the new `expiresAt`, or `None` when the stored registration is still
/// fresh and no request was sent.
pub async fn ensure_registration(
    state: &AppState,
    space_uri: &str,
    cred: &ActiveSpaceCredential,
) -> Result<Option<DateTime<Utc>>, AppError> {
    ensure_registration_at(state, space_uri, cred, Utc::now()).await
}

/// [`ensure_registration`] with an explicit clock, for renewal tests.
pub async fn ensure_registration_at(
    state: &AppState,
    space_uri: &str,
    cred: &ActiveSpaceCredential,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, AppError> {
    let service = state.config.notify_service_identifier();
    let existing: Option<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT service, expires_at FROM circle_notify_registrations WHERE space_uri = $1",
    )
    .bind(space_uri)
    .fetch_optional(&state.db)
    .await?;
    if let Some((registered_service, expires_at)) = existing {
        if registered_service == service && expires_at - RENEW_MARGIN > now {
            return Ok(None);
        }
    }

    // The alpha accepts registrations only on the authority's own space host.
    let authority_did = extract_authority_did(space_uri)?;
    let authority_doc = state
        .did_resolver
        .resolve(&authority_did)
        .await
        .map_err(|e| match e {
            AuthReason::SsrfBlocked => AppError::Unauthorized(AuthReason::SsrfBlocked),
            other => AppError::Internal(format!(
                "Failed to resolve DID document for {authority_did}: {other}"
            )),
        })?;
    let (space_host_endpoint, _) = resolve_space_host_endpoint(&authority_doc, &authority_did)?;

    let expires_at = state
        .space_client
        .register_notify(
            &space_host_endpoint,
            space_uri,
            &cred.token,
            &cred.dpop_key,
            &service,
        )
        .await?;

    sqlx::query(
        r#"
        INSERT INTO circle_notify_registrations (space_uri, service, space_host_endpoint, expires_at, registered_at)
        VALUES ($1, $2, $3, $4, now())
        ON CONFLICT (space_uri) DO UPDATE
        SET service = EXCLUDED.service,
            space_host_endpoint = EXCLUDED.space_host_endpoint,
            expires_at = EXCLUDED.expires_at,
            registered_at = now()
        "#,
    )
    .bind(space_uri)
    .bind(&service)
    .bind(&space_host_endpoint)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    tracing::info!(
        space = %space_fingerprint(space_uri),
        %expires_at,
        "Registered for space notifications"
    );
    Ok(Some(expires_at))
}

/// Best-effort `com.atproto.space.unregisterNotify` when this AppView loses
/// access to a space, then forget the registration. A failure only means the
/// host keeps sending notifications the receiver now rejects until the 24 h
/// registration lapses.
pub async fn unregister(state: &AppState, space_uri: &str) {
    let registration: Option<(String, String)> = match sqlx::query_as(
        "SELECT service, space_host_endpoint FROM circle_notify_registrations WHERE space_uri = $1",
    )
    .bind(space_uri)
    .fetch_optional(&state.db)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to read notify registration");
            return;
        }
    };
    let Some((service, endpoint)) = registration else {
        return;
    };

    if let Some(cred) = state.credential_store.get(space_uri).await {
        let call = state.space_client.unregister_notify(
            &endpoint,
            space_uri,
            &cred.token,
            &cred.dpop_key,
            &service,
        );
        match tokio::time::timeout(std::time::Duration::from_secs(5), call).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(
                error = %e,
                space = %space_fingerprint(space_uri),
                "unregisterNotify failed"
            ),
            Err(_) => tracing::warn!(
                space = %space_fingerprint(space_uri),
                "unregisterNotify timed out"
            ),
        }
    }

    if let Err(e) = sqlx::query("DELETE FROM circle_notify_registrations WHERE space_uri = $1")
        .bind(space_uri)
        .execute(&state.db)
        .await
    {
        tracing::warn!(error = %e, "Failed to delete notify registration");
    }
}
