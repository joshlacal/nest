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

    let base = session.pds_url.trim_end_matches('/');
    let client = crate::services::AtProtoClient::new(state.clone());

    let mut muted_ids: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let url = if let Some(ref c) = cursor {
            format!(
                "{}/xrpc/chat.bsky.convo.listConvos?limit=100&cursor={}",
                base,
                urlencoding::encode(c)
            )
        } else {
            format!("{}/xrpc/chat.bsky.convo.listConvos?limit=100", base)
        };

        let mut headers = client
            .build_auth_headers_for_request(&session, "GET", &url, None, Some(&dpop))
            .await
            .map_err(|e| anyhow!("Failed to build auth headers: {}", e))?;

        headers.insert(
            "atproto-proxy",
            HeaderValue::from_static("did:web:api.bsky.chat#bsky_chat"),
        );

        let response = state.http_client.get(&url).headers(headers).send().await?;

        let status = response.status().as_u16();
        if status != 200 {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "listConvos returned {} for {}: {}",
                status,
                did,
                body.chars().take(200).collect::<String>()
            ));
        }

        let body_bytes = response.bytes().await?;
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
        "SELECT session_id, pds_url FROM push_accounts WHERE account_did = $1 AND auth_revoked_at IS NULL",
    )
    .bind(did)
    .fetch_optional(db_pool)
    .await?
    .ok_or_else(|| anyhow!("No active push account for DID {}", did))?;

    Ok(row)
}
