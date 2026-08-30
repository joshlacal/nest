//! Chat poller — polls `chat.bsky.convo.getLog` for each claimed account,
//! processes new-message events, and enqueues push notifications.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
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

    // Resolve session + DPoP data for this account and capture auth_generation before network
    let (session_id, pds_url, auth_generation) = lookup_push_account(db_pool, &row.account_did).await?;
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

    // Host DPoP nonce to try first. Seeded from the registry snapshot above;
    // `fetch_log_page` updates it in place whenever a `use_dpop_nonce` 401
    // forces a retry with a fresh one, so later pages in this same poll (and
    // the persist call below) reuse it instead of eating the round trip again.
    //
    // When this account's own persisted nonce is empty (e.g. its first-ever
    // poll, or the persisted value was never set), fall back to the
    // process-wide per-origin cache shared with `AtProtoClient::proxy_request`
    // — many accounts share the same PDS host (bsky.social etc.), so another
    // account's (or the XRPC proxy's) recent traffic to the same origin has
    // likely already primed a usable nonce.
    let mut dpop_nonce: Option<String> = if dpop.dpop_host_nonce.is_empty() {
        crate::services::DpopNonceCache::origin_key(&session.pds_url)
            .and_then(|origin| state.dpop_nonce_cache.get(&origin))
    } else {
        Some(dpop.dpop_host_nonce.clone())
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
            let (status, body, next_nonce) = fetch_log_page(
                state,
                &session,
                &dpop,
                cursor.as_deref(),
                dpop_nonce.as_deref(),
            )
            .await?;
            if next_nonce != dpop_nonce {
                if let Some(n) = &next_nonce {
                    persist_host_nonce(state, &row.account_did, &session_id, n).await;
                }
                dpop_nonce = next_nonce;
            }

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
                let body_snippet: String =
                    String::from_utf8_lossy(&body).chars().take(300).collect();
                tracing::warn!(
                    did = %row.account_did,
                    status,
                    body = %body_snippet,
                    "Prime pass got non-200; will resume next cycle"
                );
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

    let (status, body, next_nonce) = fetch_log_page(
        state,
        &session,
        &dpop,
        row.chat_cursor.as_deref(),
        dpop_nonce.as_deref(),
    )
    .await?;
    if next_nonce != dpop_nonce {
        if let Some(n) = &next_nonce {
            persist_host_nonce(state, &row.account_did, &session_id, n).await;
        }
    }

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
                    auth_generation,
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

/// Single HTTP attempt against `chat.bsky.convo.getLog` with the given DPoP
/// nonce (or none, for a cycle's very first attempt). Returns the raw
/// status, response headers (needed to read `retry-after` / `DPoP-Nonce`),
/// and buffered body.
async fn send_get_log_request(
    client: &crate::services::AtProtoClient,
    state: &Arc<AppState>,
    session: &crate::models::CatbirdSession,
    dpop: &crate::middleware::JacquardDpopData,
    url: &str,
    nonce: Option<String>,
) -> Result<(u16, HeaderMap, bytes::Bytes)> {
    let mut headers = client
        .build_auth_headers_for_request(session, "GET", url, nonce, Some(dpop))
        .await
        .map_err(|e| anyhow!("Failed to build auth headers: {}", e))?;
    headers.insert(
        "atproto-proxy",
        HeaderValue::from_static("did:web:api.bsky.chat#bsky_chat"),
    );

    let response = state.http_client.get(url).headers(headers).send().await?;
    let status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let body = response.bytes().await?;
    Ok((status, response_headers, body))
}

fn retry_after_body(headers: &HeaderMap) -> Vec<u8> {
    let retry_after = headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(60);
    retry_after.to_string().into_bytes()
}

/// One getLog page. Returns (status, body_bytes, dpop_nonce_for_next_call).
///
/// Auth headers + chat proxy header are rebuilt per call (DPoP nonces are
/// single-use). On a `use_dpop_nonce` 401 the fresh nonce advertised in the
/// `DPoP-Nonce` response header is captured and the request retried once —
/// this mirrors `AtProtoClient::proxy_request`'s nonce-retry pattern, which
/// the live XRPC proxy path already relies on. The returned nonce should be
/// fed into the next `fetch_log_page` call (the prime-pass loop does this
/// across pages) and persisted by the caller so later poll cycles don't pay
/// the extra round trip again.
async fn fetch_log_page(
    state: &Arc<AppState>,
    session: &crate::models::CatbirdSession,
    dpop: &crate::middleware::JacquardDpopData,
    cursor: Option<&str>,
    nonce_hint: Option<&str>,
) -> Result<(u16, Vec<u8>, Option<String>)> {
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
    let origin = crate::services::DpopNonceCache::origin_key(&url);

    let (status, headers, body) = send_get_log_request(
        &client,
        state,
        session,
        dpop,
        &url,
        nonce_hint.map(str::to_string),
    )
    .await?;

    // Feed the shared per-origin cache from every response, success or
    // not — a 200 can hand out the next nonce just as a 401 challenge
    // does, and doing this unconditionally lets other accounts on the
    // same PDS (and the XRPC proxy path) skip a round trip too.
    client.record_nonce_from_headers(origin.as_deref(), &headers);

    if status == 401 {
        let is_use_dpop_nonce = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
            .as_deref()
            == Some("use_dpop_nonce");

        if is_use_dpop_nonce {
            if let Some(fresh_nonce) = headers
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
            {
                tracing::info!(
                    did = %session.did,
                    "Chat poll getLog got use_dpop_nonce challenge; retrying with fresh nonce"
                );
                let (status, headers, body) = send_get_log_request(
                    &client,
                    state,
                    session,
                    dpop,
                    &url,
                    Some(fresh_nonce.clone()),
                )
                .await?;
                client.record_nonce_from_headers(origin.as_deref(), &headers);

                if status == 429 {
                    return Ok((429, retry_after_body(&headers), Some(fresh_nonce)));
                }
                return Ok((status, body.to_vec(), Some(fresh_nonce)));
            }
            tracing::warn!(
                did = %session.did,
                "Chat poll getLog got use_dpop_nonce error but no DPoP-Nonce header in response"
            );
        }
    }

    if status == 429 {
        return Ok((
            429,
            retry_after_body(&headers),
            nonce_hint.map(str::to_string),
        ));
    }

    Ok((status, body.to_vec(), nonce_hint.map(str::to_string)))
}

/// Persist a freshly-issued DPoP host nonce back to the Jacquard session
/// registry so the next poll cycle for this account starts with a valid
/// nonce instead of paying the `use_dpop_nonce` round trip again. Best
/// effort: on failure the next cycle just repeats the retry-once dance in
/// `fetch_log_page`.
async fn persist_host_nonce(
    state: &Arc<AppState>,
    account_did: &str,
    session_id: &str,
    nonce: &str,
) {
    use jacquard_common::types::did::Did;

    let Some(jacquard_client) = state.jacquard_client.as_ref() else {
        return;
    };

    let did = match Did::new(account_did) {
        Ok(did) => did,
        Err(err) => {
            tracing::debug!(
                did = %account_did,
                error = %err,
                "Chat poll: invalid DID, skipping DPoP nonce persist"
            );
            return;
        }
    };

    let mut session_data = match jacquard_client.registry.get(&did, session_id, false).await {
        Ok(data) => data,
        Err(err) => {
            tracing::debug!(
                did = %account_did,
                error = %err,
                "Chat poll: failed to load session for DPoP nonce persist"
            );
            return;
        }
    };

    session_data.dpop_data.dpop_host_nonce = nonce.to_string().into();
    if let Err(err) = jacquard_client.registry.set(session_data).await {
        tracing::debug!(
            did = %account_did,
            error = %err,
            "Chat poll: failed to persist DPoP host nonce"
        );
    }
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

/// Look up session_id, pds_url, and auth_generation from push_accounts for a given DID.
async fn lookup_push_account(db_pool: &Pool<Postgres>, did: &str) -> Result<(String, String, i64)> {
    let row = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT session_id, pds_url, auth_generation FROM push_accounts WHERE account_did = $1 AND auth_revoked_at IS NULL",
    )
    .bind(did)
    .fetch_optional(db_pool)
    .await?
    .ok_or_else(|| anyhow!("No active push account for DID {}", did))?;

    if row.2 <= 0 {
        return Err(anyhow!("Invalid non-positive auth_generation for DID {}", did));
    }

    Ok(row)
}

/// Insert a chat push event into the push_event_queue. `delay_secs` sets how
/// long the row is invisible to the durable worker (`available_at`): new chat
/// enqueues pass the durable grace window (15s) so the fast-path subscriber
/// gets first crack at claiming and delivering; requeues after a fast-path
/// delivery failure pass 0 so the durable worker can pick it up immediately.
///
/// `message_text` is deliberately dropped before persisting — the queue row
/// only needs to survive long enough to build a generic notification. The
/// fast (Redis pub/sub) path carries the real text for the one immediate
/// delivery attempt and never writes it to disk; see `publish_to_redis`.
pub async fn enqueue_push(
    db_pool: &Pool<Postgres>,
    event: &ChatPushEvent,
    delay_secs: i64,
) -> Result<()> {
    if event.auth_generation <= 0 {
        return Err(anyhow!(
            "Cannot enqueue push event with invalid auth_generation {}",
            event.auth_generation
        ));
    }
    let dedupe_key = event.dedupe_key();
    let mut persisted_event = event.clone();
    persisted_event.message_text.clear();
    let event_json = serde_json::to_value(&persisted_event)?;
    let now_epoch = chrono::Utc::now().timestamp();

    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type,
            event_cid, event_path, event_record_json,
            event_timestamp, dedupe_key, available_at,
            auth_generation
        )
        VALUES ($1, $2, 'chat_message', $3, 'chat.bsky.convo.getLog', $4, $5, $6,
                NOW() + make_interval(secs => $7), $8)
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
    .bind(event.auth_generation)
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
