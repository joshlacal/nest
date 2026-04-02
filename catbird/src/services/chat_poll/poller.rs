//! Chat poller — polls `chat.bsky.convo.getLog` for each claimed account,
//! processes new-message events, and enqueues push notifications.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use reqwest::header::HeaderValue;
use sqlx::{Pool, Postgres};

use crate::config::AppState;
use crate::services::push::{is_auth_revocation_error, resolve_background_session};

use super::rate_budget::PdsRateBudget;
use super::scheduler::ChatPollScheduler;
use super::types::{ChatPollRow, ChatPushEvent, GetLogResponse, LogEntry};

/// Polls a single account's chat log and returns new messages that need push notifications.
pub async fn poll_account(
    state: &Arc<AppState>,
    db_pool: &Pool<Postgres>,
    scheduler: &ChatPollScheduler,
    rate_budget: &PdsRateBudget,
    row: &ChatPollRow,
) -> Result<()> {
    // Rate-limit check for this PDS host
    if !rate_budget.try_acquire(&row.pds_host) {
        tracing::debug!(
            did = %row.account_did,
            pds = %row.pds_host,
            "Chat poll skipped: PDS rate budget exhausted"
        );
        // Reschedule slightly later so we don't spin
        scheduler.reschedule(&row.account_did, 10).await?;
        return Ok(());
    }

    // Resolve session + DPoP data for this account
    let (session_id, pds_url) = lookup_push_account(db_pool, &row.account_did).await?;
    let (session, dpop) =
        match resolve_background_session(state, &row.account_did, &session_id, &pds_url).await {
            Ok(pair) => pair,
            Err(err) if is_auth_revocation_error(&err) => {
                tracing::info!(
                    did = %row.account_did,
                    "Auth revoked for chat poll account; unenrolling"
                );
                scheduler.unenroll_account(&row.account_did).await?;
                return Ok(());
            }
            Err(err) => return Err(err),
        };

    // Build the getLog URL
    let base = session.pds_url.trim_end_matches('/');
    let url = if let Some(ref cursor) = row.chat_cursor {
        format!(
            "{}/xrpc/chat.bsky.convo.getLog?cursor={}",
            base,
            urlencoding::encode(cursor)
        )
    } else {
        format!("{}/xrpc/chat.bsky.convo.getLog", base)
    };

    // Build auth headers via AtProtoClient helper
    let client = crate::services::AtProtoClient::new(state.clone());
    let mut headers = client
        .build_auth_headers_for_request(&session, "GET", &url, None, Some(&dpop))
        .await
        .map_err(|e| anyhow!("Failed to build auth headers: {}", e))?;

    // Chat proxy header — required for chat.bsky.* routing
    headers.insert(
        "atproto-proxy",
        HeaderValue::from_static("did:web:api.bsky.chat#bsky_chat"),
    );

    // Make the request
    let response = state
        .http_client
        .get(&url)
        .headers(headers)
        .send()
        .await?;

    let status = response.status().as_u16();

    // Handle rate limiting (429)
    if status == 429 {
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(60);

        tracing::warn!(
            did = %row.account_did,
            pds = %row.pds_host,
            retry_after = retry_after,
            "Chat poll got 429 from PDS"
        );

        rate_budget.backoff_host(&row.pds_host, Duration::from_secs(retry_after.max(60) as u64));
        scheduler
            .backoff_pds_host(&row.pds_host, retry_after)
            .await?;
        return Ok(());
    }

    // Handle auth errors
    if status == 401 {
        tracing::warn!(
            did = %row.account_did,
            "Chat poll got 401; will retry on next cycle"
        );
        scheduler.reschedule(&row.account_did, 120).await?;
        return Ok(());
    }

    if status != 200 {
        let body = response.text().await.unwrap_or_default();
        tracing::warn!(
            did = %row.account_did,
            status = status,
            body = %body.chars().take(200).collect::<String>(),
            "Chat poll unexpected status"
        );
        scheduler.reschedule(&row.account_did, 60).await?;
        return Ok(());
    }

    // Parse the response
    let body_bytes = response.bytes().await?;
    let log_response: GetLogResponse = serde_json::from_slice(&body_bytes)?;

    // Process log entries
    let mut had_incoming_message = false;
    let mut last_message_id: Option<String> = None;

    for entry in &log_response.logs {
        if let LogEntry::CreateMessage(event) = entry {
            // Only process messages from other users (not the account owner)
            if event.message.sender.did == row.account_did {
                continue;
            }

            had_incoming_message = true;
            let msg_id = &event.message.id;

            // Skip if we already notified for this message
            if let Some(ref last_notified) = row.last_notified_message_id {
                if msg_id == last_notified {
                    continue;
                }
            }

            // Check if conversation is muted
            if scheduler
                .is_convo_muted(&row.account_did, &event.convo_id)
                .await?
            {
                tracing::debug!(
                    did = %row.account_did,
                    convo_id = %event.convo_id,
                    "Skipping muted conversation"
                );
                continue;
            }

            let push_event = ChatPushEvent {
                recipient_did: row.account_did.clone(),
                sender_did: event.message.sender.did.clone(),
                convo_id: event.convo_id.clone(),
                message_id: msg_id.clone(),
                message_text: event
                    .message
                    .text
                    .clone()
                    .unwrap_or_default()
                    .chars()
                    .take(300)
                    .collect(),
                sent_at: event.message.sent_at.clone(),
            };

            // Enqueue push notification
            if let Err(err) = enqueue_push(db_pool, &push_event).await {
                tracing::warn!(
                    did = %row.account_did,
                    error = %err,
                    "Failed to enqueue chat push notification"
                );
            }

            // Publish to Redis for real-time delivery
            if let Err(err) = publish_to_redis(state, &push_event).await {
                tracing::debug!(
                    did = %row.account_did,
                    error = %err,
                    "Failed to publish chat event to Redis (non-fatal)"
                );
            }

            last_message_id = Some(msg_id.clone());
        }
    }

    // Update cursor and tier
    scheduler
        .update_after_poll(
            &row.account_did,
            &log_response.cursor,
            had_incoming_message,
            row.poll_tier,
        )
        .await?;

    // Update last_notified_message_id if we processed new messages
    if let Some(msg_id) = last_message_id {
        update_last_notified(db_pool, &row.account_did, &msg_id).await?;
    }

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

/// Insert a chat push event into the push_event_queue.
async fn enqueue_push(db_pool: &Pool<Postgres>, event: &ChatPushEvent) -> Result<()> {
    let dedupe_key = format!(
        "{}:chat_message:{}:{}",
        event.recipient_did, event.convo_id, event.message_id
    );
    let event_json = serde_json::to_value(event)?;
    let now_epoch = chrono::Utc::now().timestamp();

    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type,
            event_cid, event_path, event_record_json,
            event_timestamp, dedupe_key
        )
        VALUES ($1, $2, 'chat_message', $3, 'chat.bsky.convo.getLog', $4, $5, $6)
        ON CONFLICT (dedupe_key) DO NOTHING
        "#,
    )
    .bind(&event.recipient_did)
    .bind(&event.sender_did)
    .bind(&event.message_id)
    .bind(&event_json)
    .bind(now_epoch)
    .bind(&dedupe_key)
    .execute(db_pool)
    .await?;

    Ok(())
}

/// Publish a chat push event to Redis pub/sub for real-time connected clients.
async fn publish_to_redis(state: &Arc<AppState>, event: &ChatPushEvent) -> Result<()> {
    let payload = serde_json::to_string(event)?;
    let mut conn = state.redis.clone();
    let _: () = redis::cmd("PUBLISH")
        .arg("chat_push")
        .arg(&payload)
        .query_async(&mut conn)
        .await?;
    Ok(())
}

/// Update the last_notified_message_id for a polled account.
async fn update_last_notified(
    db_pool: &Pool<Postgres>,
    did: &str,
    message_id: &str,
) -> Result<()> {
    sqlx::query("UPDATE chat_poll_state SET last_notified_message_id = $2 WHERE account_did = $1")
        .bind(did)
        .bind(message_id)
        .execute(db_pool)
        .await?;
    Ok(())
}
