//! Mute sync — background task that periodically fetches each account's
//! conversation list via `chat.bsky.convo.listConvos` and syncs the muted
//! set into the `chat_muted_convos` table.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use reqwest::header::HeaderValue;
use sqlx::{Pool, Postgres};

use crate::config::AppState;
use crate::services::push::{is_auth_revocation_error, resolve_background_session};

use super::scheduler::ChatPollScheduler;
use super::types::ListConvosResponse;

/// Run a mute sync for all enrolled accounts.
///
/// This is intended to be called periodically (e.g. every 10 minutes) from
/// the main chat poll service loop. It iterates all distinct accounts in
/// `chat_poll_state` and syncs their muted conversation set.
pub async fn sync_all_mutes(
    state: &Arc<AppState>,
    db_pool: &Pool<Postgres>,
    scheduler: &ChatPollScheduler,
) -> Result<()> {
    let dids: Vec<String> = sqlx::query_scalar("SELECT account_did FROM chat_poll_state")
        .fetch_all(db_pool)
        .await?;

    for did in &dids {
        if let Err(err) = sync_mutes_for_account(state, db_pool, scheduler, did).await {
            if is_auth_revocation_error(&err) {
                tracing::info!(did = %did, "Auth revoked during mute sync; unenrolling");
                let _ = scheduler.unenroll_account(did).await;
            } else {
                tracing::warn!(did = %did, error = %err, "Mute sync failed for account");
            }
        }
    }

    Ok(())
}

/// Sync the muted conversations for a single account by paginating through
/// `chat.bsky.convo.listConvos` and collecting all muted convo IDs.
async fn sync_mutes_for_account(
    state: &Arc<AppState>,
    db_pool: &Pool<Postgres>,
    scheduler: &ChatPollScheduler,
    did: &str,
) -> Result<()> {
    let (session_id, pds_url) = lookup_push_account(db_pool, did).await?;
    let (session, dpop) = resolve_background_session(state, did, &session_id, &pds_url).await?;

    let client = crate::services::AtProtoClient::new(state.clone());

    // Go through `proxy_request` rather than hand-rolling the call on
    // `state.http_client`: it owns the `use_dpop_nonce` retry. Issuing the
    // request directly made every 401 terminal, so the mandatory nonce
    // challenge failed the whole sync and mute state silently stopped syncing.
    let mut client_headers = reqwest::header::HeaderMap::new();
    client_headers.insert(
        "atproto-proxy",
        HeaderValue::from_static("did:web:api.bsky.chat#bsky_chat"),
    );

    let mut muted_ids: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let query = match cursor.as_deref() {
            Some(c) => format!("limit=100&cursor={}", urlencoding::encode(c)),
            None => "limit=100".to_string(),
        };

        let response = client
            .proxy_request(
                &session,
                reqwest::Method::GET,
                "/xrpc/chat.bsky.convo.listConvos",
                Some(&query),
                None,
                None,
                Some(&client_headers),
                "mute-sync",
                Some(&dpop),
            )
            .await?;

        let body_bytes = match response {
            crate::services::ProxyResponse::Buffered { status, body, .. } => {
                if !(200..300).contains(&status) {
                    return Err(anyhow!(
                        "listConvos returned {} for {}: {}",
                        status,
                        did,
                        String::from_utf8_lossy(&body)
                            .chars()
                            .take(200)
                            .collect::<String>()
                    ));
                }
                body
            }
            crate::services::ProxyResponse::Streaming { .. } => {
                return Err(anyhow!("Unexpected streaming response for listConvos"))
            }
        };

        let page: ListConvosResponse = serde_json::from_slice(&body_bytes)?;

        for convo in &page.convos {
            if convo.muted {
                muted_ids.push(convo.id.clone());
            }
        }

        match page.cursor {
            Some(c) if !c.is_empty() => cursor = Some(c),
            _ => break,
        }
    }

    // Bulk-replace the muted set in the database
    scheduler.sync_muted_convos(did, &muted_ids).await?;

    tracing::debug!(
        did = %did,
        muted_count = muted_ids.len(),
        "Mute sync completed"
    );

    Ok(())
}

/// Look up session_id and pds_url from push_accounts for a given DID.
async fn lookup_push_account(db_pool: &Pool<Postgres>, did: &str) -> Result<(String, String)> {
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT COALESCE(session_fingerprint, encode(sha256(session_id::bytea), 'hex')) AS session_id, pds_url FROM push_accounts WHERE account_did = $1 AND auth_revoked_at IS NULL",
    )
    .bind(did)
    .fetch_optional(db_pool)
    .await?
    .ok_or_else(|| anyhow!("No active push account for DID {}", did))?;

    Ok(row)
}
