//! Chat poller — polls `chat.bsky.convo.getLog` for each claimed account,
//! processes new-message events, and enqueues push notifications.

use std::collections::HashMap;
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

    // PRIME PASS: first poll for this account. Fast-forward the cursor to
    // "now" WITHOUT notifying — enrolling must never replay backlog.
    //
    // Gated on `primed_at` (not `chat_cursor`): a partial run — page-cap
    // exhausted, or aborted on backoff/non-200 — persists its progress and
    // returns, but `primed_at` stays NULL, so the next claim resumes the
    // prime pass instead of falling through to the normal loop and
    // notifying for backlog it never finished skipping.
    if row.primed_at.is_none() {
        let mut cursor: Option<String> = row.chat_cursor.clone();
        let mut done = false;

        for _page in 0..100 {
            let (status, body) = fetch_log_page(state, &session, &dpop, cursor.as_deref()).await?;

            // Handle rate limiting (429) identically to the main path —
            // retry-after was packed into the body by fetch_log_page.
            if status == 429 {
                let retry_after: i64 = String::from_utf8_lossy(&body).parse().unwrap_or(60);

                tracing::warn!(
                    did = %row.account_did,
                    pds = %row.pds_host,
                    retry_after = retry_after,
                    "Prime pass got 429 from PDS"
                );

                rate_budget.backoff_host(
                    &row.pds_host,
                    Duration::from_secs(retry_after.max(60) as u64),
                );
                scheduler
                    .backoff_pds_host(&row.pds_host, retry_after)
                    .await?;
                return Ok(());
            }

            if status != 200 {
                tracing::warn!(did = %row.account_did, status, "Prime pass got non-200; will resume next cycle");
                scheduler.reschedule(&row.account_did, 120).await?;
                return Ok(());
            }

            let page: GetLogResponse = serde_json::from_slice(&body)?;

            // Seed watermarks from every entry seen while priming, so the
            // first normal-loop poll after `mark_primed` doesn't re-notify
            // for messages that already existed (and may already be read)
            // by the time priming finished.
            let mut dirty: HashMap<String, String> = HashMap::new();
            for entry in &page.logs {
                match entry {
                    LogEntry::CreateMessage(event) | LogEntry::ReadMessage(event) => {
                        raise_watermark(&mut dirty, &event.convo_id, &event.rev);
                    }
                    _ => {}
                }
            }

            // Flush watermarks BEFORE the cursor: same crash-safety
            // rationale as the normal loop below — if we crash between the
            // two, the next resumed page re-raises the same (idempotent)
            // watermarks instead of losing them.
            for (convo_id, rev) in &dirty {
                scheduler
                    .bump_watermark(&row.account_did, convo_id, rev)
                    .await?;
            }

            let page_done = page.logs.is_empty() || Some(&page.cursor) == cursor.as_ref();
            cursor = Some(page.cursor);
            if let Some(c) = &cursor {
                scheduler.update_prime_cursor(&row.account_did, c).await?;
            }

            if page_done {
                done = true;
                break;
            }
        }

        if done {
            scheduler.mark_primed(&row.account_did).await?;
            if let Some(c) = &cursor {
                scheduler
                    .update_after_poll(&row.account_did, c, false, row.poll_tier)
                    .await?;
            }
            tracing::info!(did = %row.account_did, "Chat poll primed (cursor fast-forwarded, watermarks seeded, no notifications)");
        }
        // If the page cap was exhausted without finishing, progress (cursor
        // + watermarks) is already persisted per-page above; the next claim
        // resumes from `row.chat_cursor` since `primed_at` is still NULL.

        return Ok(());
    }

    let (status, body) = fetch_log_page(state, &session, &dpop, row.chat_cursor.as_deref()).await?;

    // Handle rate limiting (429) — retry-after was packed into the body by fetch_log_page.
    if status == 429 {
        let retry_after: i64 = String::from_utf8_lossy(&body).parse().unwrap_or(60);

        tracing::warn!(
            did = %row.account_did,
            pds = %row.pds_host,
            retry_after = retry_after,
            "Chat poll got 429 from PDS"
        );

        rate_budget.backoff_host(
            &row.pds_host,
            Duration::from_secs(retry_after.max(60) as u64),
        );
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
        let body_text = String::from_utf8_lossy(&body);
        tracing::warn!(
            did = %row.account_did,
            status = status,
            body = %body_text.chars().take(200).collect::<String>(),
            "Chat poll unexpected status"
        );
        scheduler.reschedule(&row.account_did, 60).await?;
        return Ok(());
    }

    // Parse the response
    let log_response: GetLogResponse = serde_json::from_slice(&body)?;

    let watermarks = scheduler.get_watermarks(&row.account_did).await?;
    let mut had_incoming_message = false;

    // Pass 1: seed the in-memory watermark from every ReadMessage in this
    // batch BEFORE evaluating any CreateMessage. Without this, a page
    // ordered [Create(convo, rev=3), Read(convo, rev=5)] would evaluate the
    // create first and push a notification for a message the same batch
    // shows was already read.
    let mut dirty: HashMap<String, String> = batch_read_maxima(&log_response.logs);

    // Pass 2: evaluate + notify CreateMessage entries against the
    // read-seeded watermark.
    for entry in &log_response.logs {
        if let LogEntry::CreateMessage(event) = entry {
            let wm = effective_watermark(&watermarks, &dirty, &event.convo_id);
            if !should_notify(&event.rev, wm.as_deref()) {
                continue;
            }
            // Own messages and muted convos advance the watermark
            // without notifying (unmuting must not replay history).
            let own = event.message.sender.did == row.account_did;
            let muted = !own
                && scheduler
                    .is_convo_muted(&row.account_did, &event.convo_id)
                    .await?;

            if !own {
                had_incoming_message = true;
            }

            if !own && !muted {
                let push_event = ChatPushEvent {
                    recipient_did: row.account_did.clone(),
                    sender_did: event.message.sender.did.clone(),
                    convo_id: event.convo_id.clone(),
                    message_id: event.message.id.clone(),
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
                if let Err(err) = enqueue_push(db_pool, &push_event, 15).await {
                    tracing::warn!(did = %row.account_did, error = %err, "Failed to enqueue chat push");
                }
                if let Err(err) = publish_to_redis(state, &push_event).await {
                    tracing::debug!(did = %row.account_did, error = %err, "Redis publish failed (durable path covers it)");
                }
            }

            raise_watermark(&mut dirty, &event.convo_id, &event.rev);
        }
    }

    // Flush watermarks BEFORE the cursor: if we crash between the two, the
    // next poll re-reads the same logs and the watermarks suppress them.
    // (Cursor-first would re-notify on the inverse crash.)
    for (convo_id, rev) in &dirty {
        scheduler
            .bump_watermark(&row.account_did, convo_id, rev)
            .await?;
    }

    scheduler
        .update_after_poll(
            &row.account_did,
            &log_response.cursor,
            had_incoming_message,
            row.poll_tier,
        )
        .await?;

    Ok(())
}

/// One getLog page. Returns (status, body_bytes). Auth headers + chat proxy
/// header are rebuilt per call (DPoP nonces are single-use).
async fn fetch_log_page(
    state: &Arc<AppState>,
    session: &crate::models::CatbirdSession,
    dpop: &crate::middleware::JacquardDpopData,
    cursor: Option<&str>,
) -> Result<(u16, Vec<u8>)> {
    let base = session.pds_url.trim_end_matches('/');
    let url = match cursor {
        Some(c) => format!(
            "{}/xrpc/chat.bsky.convo.getLog?cursor={}",
            base,
            urlencoding::encode(c)
        ),
        None => format!("{}/xrpc/chat.bsky.convo.getLog", base),
    };

    let client = crate::services::AtProtoClient::new(state.clone());
    let mut headers = client
        .build_auth_headers_for_request(session, "GET", &url, None, Some(dpop))
        .await
        .map_err(|e| anyhow!("Failed to build auth headers: {}", e))?;
    headers.insert(
        "atproto-proxy",
        HeaderValue::from_static("did:web:api.bsky.chat#bsky_chat"),
    );

    let response = state.http_client.get(&url).headers(headers).send().await?;
    let status = response.status().as_u16();

    if status == 429 {
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(60);
        return Ok((429, retry_after.to_string().into_bytes()));
    }

    let body = response.bytes().await?;
    Ok((status, body.to_vec()))
}

/// Whether a CreateMessage at `rev` should trigger a push, given the
/// account+convo watermark. Revs are TIDs — lexicographic order is time order.
fn should_notify(rev: &str, watermark: Option<&str>) -> bool {
    match watermark {
        Some(wm) => rev > wm,
        None => true,
    }
}

/// Monotonically raise the watermark for `convo_id` in `dirty` to `rev` (a
/// lower rev never overwrites). Revs are TIDs — lexicographic order is time
/// order.
fn raise_watermark(dirty: &mut HashMap<String, String>, convo_id: &str, rev: &str) {
    let entry = dirty.entry(convo_id.to_string()).or_default();
    if rev > entry.as_str() {
        *entry = rev.to_string();
    }
}

/// Effective watermark for `convo_id`: max(persisted, raised-this-poll).
fn effective_watermark(
    persisted: &HashMap<String, String>,
    dirty: &HashMap<String, String>,
    convo_id: &str,
) -> Option<String> {
    match (persisted.get(convo_id), dirty.get(convo_id)) {
        (Some(a), Some(b)) => Some(std::cmp::max(a.as_str(), b.as_str()).to_string()),
        (Some(a), None) => Some(a.clone()),
        (None, Some(b)) => Some(b.clone()),
        (None, None) => None,
    }
}

/// Per-convo maximum rev among ReadMessage entries in a single getLog page.
///
/// Used to seed the in-memory watermark BEFORE any CreateMessage in the same
/// page is evaluated: a page ordered [Create, ..., Read(higher rev)] for the
/// same convo must suppress the create rather than notify for a message the
/// same batch shows was already read (a single forward pass gets this wrong
/// because it would evaluate the create before reaching the later read).
fn batch_read_maxima(logs: &[LogEntry]) -> HashMap<String, String> {
    let mut maxima = HashMap::new();
    for entry in logs {
        if let LogEntry::ReadMessage(event) = entry {
            raise_watermark(&mut maxima, &event.convo_id, &event.rev);
        }
    }
    maxima
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

/// Insert a chat push event into the push_event_queue. `delay_secs` sets how
/// long the row is invisible to the durable worker (`available_at`): new chat
/// enqueues pass the durable grace window (15s) so the fast-path subscriber
/// gets first crack at claiming and delivering; requeues after a fast-path
/// delivery failure pass 0 so the durable worker can pick it up immediately.
pub(crate) async fn enqueue_push(
    db_pool: &Pool<Postgres>,
    event: &ChatPushEvent,
    delay_secs: i64,
) -> Result<()> {
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
            event_timestamp, dedupe_key, available_at
        )
        VALUES ($1, $2, 'chat_message', $3, 'chat.bsky.convo.getLog', $4, $5, $6,
                NOW() + make_interval(secs => $7))
        ON CONFLICT (dedupe_key) DO NOTHING
        "#,
    )
    .bind(&event.recipient_did)
    .bind(&event.sender_did)
    .bind(&event.message_id)
    .bind(&event_json)
    .bind(now_epoch)
    .bind(&dedupe_key)
    .bind(delay_secs)
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

#[cfg(test)]
mod tests {
    use super::super::types::{LogMessage, LogMessageEvent, LogSender};
    use super::*;

    #[test]
    fn notify_when_no_watermark() {
        assert!(should_notify("3lsomerev22", None));
    }

    #[test]
    fn suppress_at_or_below_watermark() {
        assert!(!should_notify("3laaa", Some("3laaa"))); // equal → already handled
        assert!(!should_notify("3laaa", Some("3lbbb"))); // older than watermark
    }

    #[test]
    fn notify_above_watermark() {
        assert!(should_notify("3lccc", Some("3lbbb")));
    }

    fn log_message_event(
        convo_id: &str,
        rev: &str,
        sender_did: &str,
        message_id: &str,
    ) -> LogMessageEvent {
        LogMessageEvent {
            convo_id: convo_id.to_string(),
            rev: rev.to_string(),
            message: LogMessage {
                id: message_id.to_string(),
                sender: LogSender {
                    did: sender_did.to_string(),
                },
                text: Some("hello".to_string()),
                sent_at: "2026-07-06T00:00:00Z".to_string(),
            },
        }
    }

    #[test]
    fn batch_read_maxima_tracks_per_convo_max_rev() {
        let logs = vec![
            LogEntry::ReadMessage(log_message_event("convo1", "3laaa", "did:plc:self", "r1")),
            LogEntry::ReadMessage(log_message_event("convo1", "3lccc", "did:plc:self", "r2")),
            LogEntry::ReadMessage(log_message_event("convo2", "3lbbb", "did:plc:self", "r3")),
            LogEntry::CreateMessage(log_message_event("convo1", "3lzzz", "did:plc:other", "m1")),
        ];

        let maxima = batch_read_maxima(&logs);

        assert_eq!(maxima.get("convo1").map(String::as_str), Some("3lccc"));
        assert_eq!(maxima.get("convo2").map(String::as_str), Some("3lbbb"));
    }

    #[test]
    fn same_batch_read_after_create_suppresses_notification() {
        // A page ordered [Create(rev=3laaa), Read(rev=3lbbb)] for the same
        // convo — the read arrives later in the page but covers the create.
        // Finding 3: a naive single forward pass would notify for the
        // create before ever seeing the read. The fix seeds the watermark
        // from ALL same-batch reads (batch_read_maxima) before evaluating
        // any create.
        let logs = vec![
            LogEntry::CreateMessage(log_message_event("convo1", "3laaa", "did:plc:other", "m1")),
            LogEntry::ReadMessage(log_message_event("convo1", "3lbbb", "did:plc:self", "r1")),
        ];

        let persisted: HashMap<String, String> = HashMap::new();
        let dirty = batch_read_maxima(&logs);

        let wm = effective_watermark(&persisted, &dirty, "convo1");
        assert!(!should_notify("3laaa", wm.as_deref()));
    }
}
