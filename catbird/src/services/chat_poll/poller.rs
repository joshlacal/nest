//! Chat poller — polls `chat.bsky.convo.getLog` for each claimed account,
//! processes new-message events, and enqueues push notifications.

use anyhow::{anyhow, Result};
use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use sqlx::{Pool, Postgres};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::config::AppState;
use crate::services::push::{is_auth_revocation_error, resolve_background_session};

/// Maximum number of log entries to process per prime pass page.
pub const MAX_PRIME_LOGS_PER_PAGE: usize = 1000;

enum PrimeStepResult {
    LocalBudgetExhausted,
    PdsRateLimited {
        retry_after: u64,
        next_nonce: Option<String>,
    },
    Non200 {
        status: u16,
        body: Vec<u8>,
        next_nonce: Option<String>,
    },
    Success {
        next_nonce: Option<String>,
        new_cursor: String,
        page_done: bool,
    },
}
use super::rate_budget::PdsRateBudget;
use super::scheduler::ChatPollScheduler;
use super::types::{ChatPollRow, ChatPushEvent, GetLogResponse, LogEntry};

/// Outcome of a single getLog page fetch operation.
#[derive(Debug, PartialEq, Eq)]
pub enum FetchLogOutcome {
    /// Successful fetch with HTTP status, response body bytes, and optional next DPoP nonce.
    Success {
        status: u16,
        body: Vec<u8>,
        next_nonce: Option<String>,
    },
    /// Upstream PDS returned HTTP 429 with parsed retry-after duration in seconds.
    PdsRateLimited {
        retry_after: u64,
        next_nonce: Option<String>,
    },
    /// Local/Nest rate budget permit could not be acquired for this PDS host.
    LocalBudgetExhausted,
}

/// Maximum execution time allowed for the prime pass loop before yielding.
pub const MAX_PRIME_PASS_DURATION: Duration = Duration::from_secs(15);

/// Polls a single account's chat log and returns new messages that need push notifications.
pub async fn poll_account(
    state: &Arc<AppState>,
    db_pool: &Pool<Postgres>,
    scheduler: &ChatPollScheduler,
    rate_budget: &PdsRateBudget,
    row: &ChatPollRow,
) -> Result<()> {
    // Resolve session + DPoP data for this account and capture auth_generation before network
    let (session_id, pds_url, auth_generation) =
        lookup_push_account(db_pool, &row.account_did).await?;
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

    poll_account_with_session(
        state,
        db_pool,
        scheduler,
        rate_budget,
        row,
        &session,
        &dpop,
        &session_id,
        auth_generation,
        std::time::Instant::now(),
    )
    .await
}

pub(crate) async fn poll_account_with_session(
    state: &Arc<AppState>,
    db_pool: &Pool<Postgres>,
    scheduler: &ChatPollScheduler,
    rate_budget: &PdsRateBudget,
    row: &ChatPollRow,
    session: &crate::models::CatbirdSession,
    dpop: &crate::middleware::JacquardDpopData,
    session_id: &str,
    auth_generation: i64,
    prime_start: std::time::Instant,
) -> Result<()> {
    // Host DPoP nonce to try first. Seeded from dpop data or cached PDS origin nonce;
    // `fetch_log_page` updates it in place whenever a `use_dpop_nonce` 401
    // forces a retry with a fresh one, so later pages in this same poll (and
    // the persist call below) reuse it instead of eating the round trip again.
    let mut dpop_nonce: Option<String> = if dpop.dpop_host_nonce.is_empty() {
        crate::services::DpopNonceCache::origin_key(&session.pds_url)
            .and_then(|origin| state.dpop_nonce_cache.get(&origin))
    } else {
        Some(dpop.dpop_host_nonce.clone())
    };

    // PRIME PASS: first poll for this account. Fast-forward the cursor to
    // "now" WITHOUT notifying — enrolling must never replay backlog.
    if row.primed_at.is_none() {
        let mut cursor: Option<String> = row.chat_cursor.clone();
        let mut done = false;

        for _page in 0..100 {
            let elapsed = prime_start.elapsed();
            if elapsed >= MAX_PRIME_PASS_DURATION {
                tracing::debug!(
                    did = %row.account_did,
                    elapsed = ?elapsed,
                    "Prime pass time slice elapsed; yielding to reschedule without blocking later DIDs"
                );
                scheduler.reschedule(&row.account_did, 5).await?;
                return Ok(());
            }

            let remaining_time = MAX_PRIME_PASS_DURATION - elapsed;

            let page_fut = async {
                let outcome = fetch_log_page(
                    state,
                    &session,
                    &dpop,
                    cursor.as_deref(),
                    dpop_nonce.as_deref(),
                    rate_budget,
                    &row.pds_host,
                )
                .await?;

                let res: Result<PrimeStepResult> = match outcome {
                    FetchLogOutcome::LocalBudgetExhausted => {
                        Ok(PrimeStepResult::LocalBudgetExhausted)
                    }
                    FetchLogOutcome::PdsRateLimited {
                        retry_after,
                        next_nonce,
                    } => Ok(PrimeStepResult::PdsRateLimited {
                        retry_after,
                        next_nonce,
                    }),
                    FetchLogOutcome::Success {
                        status,
                        body,
                        next_nonce,
                    } => {
                        if status != 200 {
                            return Ok(PrimeStepResult::Non200 {
                                status,
                                body,
                                next_nonce,
                            });
                        }

                        let page: GetLogResponse = serde_json::from_slice(&body)?;

                        let mut dirty: HashMap<String, String> = HashMap::new();
                        for entry in page.logs.iter().take(MAX_PRIME_LOGS_PER_PAGE) {
                            match entry {
                                LogEntry::CreateMessage(event) | LogEntry::ReadMessage(event) => {
                                    raise_watermark(&mut dirty, &event.convo_id, &event.rev);
                                }
                                _ => {}
                            }
                        }

                        // Flush watermarks in ONE batched query BEFORE updating the cursor
                        scheduler
                            .bump_watermarks_batch(&row.account_did, &dirty)
                            .await?;

                        let page_done =
                            page.logs.is_empty() || Some(&page.cursor) == cursor.as_ref();
                        let new_cursor = page.cursor;
                        if !new_cursor.is_empty() {
                            scheduler
                                .update_prime_cursor(&row.account_did, &new_cursor)
                                .await?;
                        }

                        Ok(PrimeStepResult::Success {
                            next_nonce,
                            new_cursor,
                            page_done,
                        })
                    }
                };
                res
            };

            let step = match tokio::time::timeout(remaining_time, page_fut).await {
                Ok(res) => res?,
                Err(_) => {
                    tracing::debug!(
                        did = %row.account_did,
                        elapsed = ?prime_start.elapsed(),
                        "Prime pass timed out against remaining time slice; yielding to reschedule"
                    );
                    scheduler.reschedule(&row.account_did, 5).await?;
                    return Ok(());
                }
            };

            match step {
                PrimeStepResult::LocalBudgetExhausted => {
                    tracing::debug!(
                        did = %row.account_did,
                        pds = %row.pds_host,
                        "Prime pass paused: local PDS rate budget exhausted"
                    );
                    scheduler.reschedule(&row.account_did, 10).await?;
                    return Ok(());
                }
                PrimeStepResult::PdsRateLimited {
                    retry_after,
                    next_nonce,
                } => {
                    if next_nonce != dpop_nonce {
                        if let Some(n) = &next_nonce {
                            persist_host_nonce(state, &row.account_did, session_id, n).await;
                        }
                    }

                    tracing::warn!(
                        did = %row.account_did,
                        pds = %row.pds_host,
                        retry_after = retry_after,
                        "Prime pass got 429 from PDS"
                    );

                    rate_budget.backoff_host(&row.pds_host, Duration::from_secs(retry_after));
                    scheduler
                        .backoff_pds_host(&row.pds_host, retry_after as i64)
                        .await?;
                    return Ok(());
                }
                PrimeStepResult::Non200 {
                    status,
                    body,
                    next_nonce,
                } => {
                    if next_nonce != dpop_nonce {
                        if let Some(n) = &next_nonce {
                            persist_host_nonce(state, &row.account_did, session_id, n).await;
                        }
                    }

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
                PrimeStepResult::Success {
                    next_nonce,
                    new_cursor,
                    page_done,
                } => {
                    if next_nonce != dpop_nonce {
                        if let Some(n) = &next_nonce {
                            persist_host_nonce(state, &row.account_did, session_id, n).await;
                        }
                        dpop_nonce = next_nonce;
                    }

                    cursor = Some(new_cursor);
                    if page_done {
                        done = true;
                        break;
                    }
                }
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

    let outcome = fetch_log_page(
        state,
        session,
        dpop,
        row.chat_cursor.as_deref(),
        dpop_nonce.as_deref(),
        rate_budget,
        &row.pds_host,
    )
    .await?;

    let (status, body, _) = match outcome {
        FetchLogOutcome::LocalBudgetExhausted => {
            tracing::debug!(
                did = %row.account_did,
                pds = %row.pds_host,
                "Chat poll skipped: local PDS rate budget exhausted"
            );
            scheduler.reschedule(&row.account_did, 10).await?;
            return Ok(());
        }
        FetchLogOutcome::PdsRateLimited {
            retry_after,
            next_nonce,
        } => {
            if next_nonce != dpop_nonce {
                if let Some(n) = &next_nonce {
                    persist_host_nonce(state, &row.account_did, session_id, n).await;
                }
            }
            tracing::warn!(
                did = %row.account_did,
                pds = %row.pds_host,
                retry_after = retry_after,
                "Chat poll got 429 from PDS"
            );
            rate_budget.backoff_host(&row.pds_host, Duration::from_secs(retry_after));
            scheduler
                .backoff_pds_host(&row.pds_host, retry_after as i64)
                .await?;
            return Ok(());
        }
        FetchLogOutcome::Success {
            status,
            body,
            next_nonce,
        } => {
            if next_nonce != dpop_nonce {
                if let Some(n) = &next_nonce {
                    persist_host_nonce(state, &row.account_did, session_id, n).await;
                }
            }
            (status, body, next_nonce)
        }
    };

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
    scheduler
        .bump_watermarks_batch(&row.account_did, &dirty)
        .await?;

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

/// Maximum decompressed response size allowed for getLog (5MB).
pub const MAX_GET_LOG_BODY_SIZE: usize = 5 * 1024 * 1024;

/// Single HTTP attempt against `chat.bsky.convo.getLog` with the given DPoP
/// nonce (or none, for a cycle's very first attempt). Returns the raw
/// status, response headers (needed to read `retry-after` / `DPoP-Nonce`),
/// and buffered body.
/// Decompresses encoded body bytes with a bounded decoded counter, rejecting
/// unsupported encodings and preventing decompression bombs.
pub fn decompress_bounded(
    data: &[u8],
    encoding: Option<&str>,
    max_decoded_bytes: usize,
) -> Result<Vec<u8>> {
    let encoding = encoding.unwrap_or("identity").trim().to_ascii_lowercase();
    match encoding.as_str() {
        "identity" | "" => {
            if data.len() > max_decoded_bytes {
                anyhow::bail!(
                    "Decompressed body size {} exceeds limit {}",
                    data.len(),
                    max_decoded_bytes
                );
            }
            Ok(data.to_vec())
        }
        "gzip" => {
            use flate2::read::GzDecoder;
            use std::io::Read;
            let mut decoder = GzDecoder::new(data);
            let mut decoded = Vec::new();
            let mut buffer = [0u8; 8192];
            let mut total_decoded = 0;
            loop {
                let n = decoder
                    .read(&mut buffer)
                    .map_err(|e| anyhow!("Gzip decompression failed: {e}"))?;
                if n == 0 {
                    break;
                }
                total_decoded += n;
                if total_decoded > max_decoded_bytes {
                    anyhow::bail!(
                        "Decompressed gzip body size exceeded limit of {max_decoded_bytes} bytes"
                    );
                }
                decoded.extend_from_slice(&buffer[..n]);
            }
            Ok(decoded)
        }
        "deflate" => {
            use flate2::read::ZlibDecoder;
            use std::io::Read;
            let mut decoder = ZlibDecoder::new(data);
            let mut decoded = Vec::new();
            let mut buffer = [0u8; 8192];
            let mut total_decoded = 0;
            loop {
                let n = decoder
                    .read(&mut buffer)
                    .map_err(|e| anyhow!("Deflate decompression failed: {e}"))?;
                if n == 0 {
                    break;
                }
                total_decoded += n;
                if total_decoded > max_decoded_bytes {
                    anyhow::bail!(
                        "Decompressed deflate body size exceeded limit of {max_decoded_bytes} bytes"
                    );
                }
                decoded.extend_from_slice(&buffer[..n]);
            }
            Ok(decoded)
        }
        "br" | "brotli" => {
            use std::io::Read;
            let mut decoder = brotli::Decompressor::new(data, 4096);
            let mut decoded = Vec::new();
            let mut buffer = [0u8; 8192];
            let mut total_decoded = 0;
            loop {
                let n = decoder
                    .read(&mut buffer)
                    .map_err(|e| anyhow!("Brotli decompression failed: {e}"))?;
                if n == 0 {
                    break;
                }
                total_decoded += n;
                if total_decoded > max_decoded_bytes {
                    anyhow::bail!(
                        "Decompressed brotli body size exceeded limit of {max_decoded_bytes} bytes"
                    );
                }
                decoded.extend_from_slice(&buffer[..n]);
            }
            Ok(decoded)
        }
        other => {
            anyhow::bail!("Unsupported Content-Encoding: {other}");
        }
    }
}

/// Single HTTP attempt against `chat.bsky.convo.getLog` with the given DPoP
/// nonce (or none, for a cycle's very first attempt). Returns the raw
/// status, response headers (needed to read `retry-after` / `DPoP-Nonce`),
/// decoded body, and raw encoded wire byte count.
async fn send_get_log_request(
    client: &crate::services::AtProtoClient,
    state: &Arc<AppState>,
    session: &crate::models::CatbirdSession,
    dpop: &crate::middleware::JacquardDpopData,
    url: &str,
    nonce: Option<String>,
    max_bytes: usize,
) -> Result<(u16, HeaderMap, bytes::Bytes, usize)> {
    crate::services::validate_pds_url(&session.pds_url)?;
    crate::services::validate_pds_url(url)?;

    let mut headers = client
        .build_auth_headers_for_request(session, "GET", url, nonce, Some(dpop))
        .await
        .map_err(|e| anyhow!("Failed to build auth headers: {}", e))?;
    headers.insert(
        "atproto-proxy",
        HeaderValue::from_static("did:web:api.bsky.chat#bsky_chat"),
    );

    let response = state
        .raw_http_client
        .get(url)
        .headers(headers)
        .send()
        .await?;
    let status = response.status().as_u16();
    let response_headers = response.headers().clone();

    // Check Content-Length header early on raw wire response
    if let Some(content_length) = response_headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        if content_length > max_bytes {
            anyhow::bail!(
                "getLog response Content-Length {} exceeds limit {}",
                content_length,
                max_bytes
            );
        }
    }

    // Check Content-Encoding early and reject unsupported encodings
    let content_encoding = response_headers
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    if let Some(enc) = &content_encoding {
        let norm = enc.trim().to_ascii_lowercase();
        if !matches!(
            norm.as_str(),
            "" | "identity" | "gzip" | "deflate" | "br" | "brotli"
        ) {
            anyhow::bail!("Unsupported Content-Encoding: {enc}");
        }
    }

    // Acquire stream permit for bounded concurrent memory — MUST fail closed on exhaustion
    let permit = match state.active_stream_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("Active stream concurrency limit reached (64 max) in getLog");
            anyhow::bail!("Active stream concurrency limit reached (64 max)");
        }
    };

    // Route through Task 1 bounded byte stream with live chunk byte accounting for encoded wire bytes
    let stream = crate::services::bounded_byte_stream_with_accounting(
        response.bytes_stream(),
        max_bytes,
        Some(permit),
        Some(state.rate_limit.clone()),
        Some(session.id.to_string()),
    );
    let mut stream = std::pin::pin!(stream);
    let mut encoded_body = Vec::new();

    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.map_err(|e| anyhow!("getLog stream error: {}", e))?;
        encoded_body.extend_from_slice(&chunk);
    }
    let encoded_wire_bytes = encoded_body.len();

    // Manually decode through a second bounded decoded counter
    let decoded_body = decompress_bounded(&encoded_body, content_encoding.as_deref(), max_bytes)?;

    Ok((
        status,
        response_headers,
        bytes::Bytes::from(decoded_body),
        encoded_wire_bytes,
    ))
}

/// One getLog page. Returns FetchLogOutcome.
///
/// Auth headers + chat proxy header are rebuilt per call (DPoP nonces are
/// single-use). On a `use_dpop_nonce` 401 the fresh nonce advertised in the
/// `DPoP-Nonce` response header is captured and the request retried once —
/// this mirrors `AtProtoClient::proxy_request`'s nonce-retry pattern.
/// Permits are charged once per physical request immediately before sending.
/// Both attempt 1 and the DPoP retry share ONE cumulative 5MB body budget.
async fn fetch_log_page(
    state: &Arc<AppState>,
    session: &crate::models::CatbirdSession,
    dpop: &crate::middleware::JacquardDpopData,
    cursor: Option<&str>,
    nonce_hint: Option<&str>,
    rate_budget: &PdsRateBudget,
    pds_host: &str,
) -> Result<FetchLogOutcome> {
    // Acquire permit immediately before attempt 1
    if !rate_budget.try_acquire(pds_host) {
        tracing::debug!(
            pds = %pds_host,
            "Chat poll attempt skipped: PDS rate budget exhausted"
        );
        return Ok(FetchLogOutcome::LocalBudgetExhausted);
    }

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

    let (status, headers, body, initial_encoded_bytes) = send_get_log_request(
        &client,
        state,
        session,
        dpop,
        &url,
        nonce_hint.map(str::to_string),
        MAX_GET_LOG_BODY_SIZE,
    )
    .await?;

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
                // Charge permit immediately before physical retry attempt
                if !rate_budget.try_acquire(pds_host) {
                    tracing::debug!(
                        pds = %pds_host,
                        "Chat poll nonce retry skipped: PDS rate budget exhausted"
                    );
                    return Ok(FetchLogOutcome::LocalBudgetExhausted);
                }

                // Enforce single cumulative budget across attempt 1 and DPoP retry
                let initial_used = std::cmp::max(initial_encoded_bytes, body.len());
                let remaining_budget = MAX_GET_LOG_BODY_SIZE.saturating_sub(initial_used);
                if remaining_budget == 0 {
                    anyhow::bail!(
                        "Cumulative getLog response size exceeded maximum allowed limit of {} bytes across attempts",
                        MAX_GET_LOG_BODY_SIZE
                    );
                }

                let (status, headers, retry_body, _retry_encoded_bytes) = send_get_log_request(
                    &client,
                    state,
                    session,
                    dpop,
                    &url,
                    Some(fresh_nonce.clone()),
                    remaining_budget,
                )
                .await?;
                client.record_nonce_from_headers(origin.as_deref(), &headers);

                if status == 429 {
                    let retry_after =
                        crate::services::chat_poll::rate_budget::parse_and_clamp_retry_after(
                            headers.get("retry-after").and_then(|v| v.to_str().ok()),
                        );
                    return Ok(FetchLogOutcome::PdsRateLimited {
                        retry_after,
                        next_nonce: Some(fresh_nonce),
                    });
                }
                return Ok(FetchLogOutcome::Success {
                    status,
                    body: retry_body.to_vec(),
                    next_nonce: Some(fresh_nonce),
                });
            }
            tracing::warn!(
                did = %session.did,
                "Chat poll getLog got use_dpop_nonce error but no DPoP-Nonce header in response"
            );
        }
    }

    if status == 429 {
        let retry_after = crate::services::chat_poll::rate_budget::parse_and_clamp_retry_after(
            headers.get("retry-after").and_then(|v| v.to_str().ok()),
        );
        return Ok(FetchLogOutcome::PdsRateLimited {
            retry_after,
            next_nonce: nonce_hint.map(str::to_string),
        });
    }

    Ok(FetchLogOutcome::Success {
        status,
        body: body.to_vec(),
        next_nonce: nonce_hint.map(str::to_string),
    })
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
        "SELECT COALESCE(session_fingerprint, encode(sha256(session_id::bytea), 'hex')) AS session_id, pds_url, auth_generation FROM push_accounts WHERE account_did = $1 AND auth_revoked_at IS NULL",
    )
    .bind(did)
    .fetch_optional(db_pool)
    .await?
    .ok_or_else(|| anyhow!("No active push account for DID {}", did))?;
    if row.2 <= 0 {
        return Err(anyhow!(
            "Invalid non-positive auth_generation for DID {}",
            did
        ));
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

    #[tokio::test]
    async fn test_get_log_bounded_chunks_rejection() {
        use futures_util::stream;
        let limit = 1000;
        let chunks = vec![
            Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0u8; 600])),
            Ok(bytes::Bytes::from(vec![0u8; 600])),
        ];
        let mut stream = stream::iter(chunks);
        let mut body = Vec::new();
        let mut exceeded = false;
        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res.unwrap();
            if body.len() + chunk.len() > limit {
                exceeded = true;
                break;
            }
            body.extend_from_slice(&chunk);
        }
        assert!(exceeded);
        assert_eq!(body.len(), 600); // stopped before full allocation
    }

    #[tokio::test]
    #[ignore = "requires running Redis (REDIS_URL)"]
    async fn test_active_stream_semaphore_fail_closed_on_exhaustion() {
        use chrono::Utc;
        use uuid::Uuid;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;

        let payload = serde_json::json!({
            "logs": []
        });

        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getLog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(payload))
            .mount(&pds)
            .await;

        let config = crate::config::AppConfig::test_default();
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client()
                .expect("hardened raw client"),
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(0)),
            rate_limit: Arc::new(crate::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:test_semaphore_exhaustion".to_string(),
            handle: "user.test".to_string(),
            pds_url: pds.uri(),
            access_token: "mock_token".to_string(),
            refresh_token: "mock_refresh".to_string(),
            scopes: vec!["atproto".to_string()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".to_string()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = crate::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        let client = crate::services::AtProtoClient::new(state.clone());
        let url = format!("{}/xrpc/chat.bsky.convo.getLog", pds.uri());

        let res = send_get_log_request(
            &client,
            &state,
            &session,
            &dpop_data,
            &url,
            None,
            MAX_GET_LOG_BODY_SIZE,
        )
        .await;

        assert!(
            res.is_err(),
            "getLog must fail when active stream semaphore is exhausted"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("Active stream concurrency limit reached (64 max)"),
            "Error message must indicate stream semaphore exhaustion, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    #[ignore = "requires running Redis (REDIS_URL)"]
    async fn test_send_get_log_routes_through_task1_byte_accounting() {
        use chrono::Utc;
        use uuid::Uuid;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;

        let payload = serde_json::json!({
            "logs": [
                {
                    "$type": "chat.bsky.convo.defs#logCreateMessage",
                    "convoId": "convo1",
                    "rev": "3laaa",
                    "message": {
                        "id": "msg1",
                        "sender": { "did": "did:plc:sender" },
                        "text": "a".repeat(400),
                        "sentAt": "2026-07-06T00:00:00Z"
                    }
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getLog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(payload))
            .mount(&pds)
            .await;

        let config = crate::config::AppConfig::test_default();
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        // Rate limit state configured with only 250 bytes budget
        let rate_limit = Arc::new(crate::middleware::RateLimitState {
            session_limiter: Arc::new(crate::middleware::RateLimiter::new()),
            ip_limiter: Arc::new(crate::middleware::RateLimiter::new()),
            session_byte_limiter: Arc::new(crate::middleware::ByteRateLimiter::new()),
            global_byte_limiter: Arc::new(crate::middleware::ByteRateLimiter::new()),
            session_config: crate::middleware::RateLimitConfig::default(),
            ip_config: crate::middleware::RateLimitConfig::default(),
            session_byte_config: crate::middleware::ByteRateLimitConfig {
                max_bytes: 250,
                window: Duration::from_secs(60),
            },
            global_byte_config: crate::middleware::ByteRateLimitConfig {
                max_bytes: 1000,
                window: Duration::from_secs(60),
            },
            trusted_proxies: Vec::new(),
        });

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client()
                .expect("hardened raw client"),
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit,
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:test_get_log_accounting".to_string(),
            handle: "user.test".to_string(),
            pds_url: pds.uri(),
            access_token: "mock_token".to_string(),
            refresh_token: "mock_refresh".to_string(),
            scopes: vec!["atproto".to_string()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".to_string()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = crate::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        let client = crate::services::AtProtoClient::new(state.clone());
        let url = format!("{}/xrpc/chat.bsky.convo.getLog", pds.uri());

        // The >400 byte response body must exceed the 250 byte rate limit budget live during stream reading
        let res = send_get_log_request(
            &client,
            &state,
            &session,
            &dpop_data,
            &url,
            None,
            MAX_GET_LOG_BODY_SIZE,
        )
        .await;

        assert!(
            res.is_err(),
            "getLog must fail when rate limit budget is exceeded"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("Rate limit exceeded") || err_msg.contains("PermissionDenied"),
            "Error should reflect rate limit rejection: {}",
            err_msg
        );
    }

    #[tokio::test]
    #[ignore = "requires running Redis (REDIS_URL)"]
    async fn test_send_get_log_enforces_content_length_ceiling() {
        use chrono::Utc;
        use uuid::Uuid;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getLog"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 6_000_000]))
            .mount(&pds)
            .await;

        let config = crate::config::AppConfig::test_default();
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client()
                .expect("hardened raw client"),
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(crate::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:test_get_log_content_len".to_string(),
            handle: "user.test".to_string(),
            pds_url: pds.uri(),
            access_token: "mock_token".to_string(),
            refresh_token: "mock_refresh".to_string(),
            scopes: vec!["atproto".to_string()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".to_string()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = crate::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        let client = crate::services::AtProtoClient::new(state.clone());
        let url = format!("{}/xrpc/chat.bsky.convo.getLog", pds.uri());

        let res = send_get_log_request(
            &client,
            &state,
            &session,
            &dpop_data,
            &url,
            None,
            MAX_GET_LOG_BODY_SIZE,
        )
        .await;

        assert!(
            res.is_err(),
            "getLog must reject Content-Length > MAX_GET_LOG_BODY_SIZE"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("Content-Length 6000000 exceeds limit"));
    }

    #[tokio::test]
    #[ignore = "requires running Redis (REDIS_URL)"]
    async fn test_fetch_log_page_real_nonce_retry_and_cumulative_budget() {
        use chrono::Utc;
        use uuid::Uuid;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let config = crate::config::AppConfig::test_default();
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client()
                .expect("hardened raw client"),
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(crate::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = crate::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        // Scenario 1: Normal successful retry under cumulative budget
        {
            let pds = MockServer::start().await;

            // Attempt 1: 401 with use_dpop_nonce
            Mock::given(method("GET"))
                .and(path("/xrpc/chat.bsky.convo.getLog"))
                .respond_with(
                    ResponseTemplate::new(401)
                        .insert_header("dpop-nonce", "fresh-getlog-nonce-xyz")
                        .set_body_json(serde_json::json!({
                            "error": "use_dpop_nonce",
                            "message": "Use DPoP nonce"
                        })),
                )
                .up_to_n_times(1)
                .mount(&pds)
                .await;

            // Attempt 2: 200 OK
            Mock::given(method("GET"))
                .and(path("/xrpc/chat.bsky.convo.getLog"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "logs": [],
                    "cursor": "cursor_after_retry"
                })))
                .mount(&pds)
                .await;

            let session = crate::models::CatbirdSession {
                id: Uuid::new_v4(),
                did: "did:plc:test_getlog_retry_user".to_string(),
                handle: "user.test".to_string(),
                pds_url: pds.uri(),
                access_token: "mock_token".to_string(),
                refresh_token: "mock_refresh".to_string(),
                scopes: vec!["atproto".to_string()],
                access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
                created_at: Utc::now(),
                last_used_at: Utc::now(),
                granted_scopes: vec!["atproto".to_string()],
            };

            let rate_budget = PdsRateBudget::new(100.0);
            let pds_host = "127.0.0.1";

            let outcome = fetch_log_page(
                &state,
                &session,
                &dpop_data,
                None,
                None,
                &rate_budget,
                pds_host,
            )
            .await
            .unwrap();

            match outcome {
                FetchLogOutcome::Success {
                    status, next_nonce, ..
                } => {
                    assert_eq!(status, 200);
                    assert_eq!(next_nonce, Some("fresh-getlog-nonce-xyz".to_string()));
                }
                other => panic!("Expected FetchLogOutcome::Success, got {:?}", other),
            }
        }

        // Scenario 2: Attempt 1 challenge body consumes entire 5MB budget -> cumulative bail before retry
        {
            let pds = MockServer::start().await;
            let template = "{\"error\":\"use_dpop_nonce\",\"p\":\"\"}";
            let padding_len = MAX_GET_LOG_BODY_SIZE.saturating_sub(template.len());
            let full_budget_body = format!(
                "{{\"error\":\"use_dpop_nonce\",\"p\":\"{}\"}}",
                "e".repeat(padding_len)
            )
            .into_bytes();
            assert_eq!(full_budget_body.len(), MAX_GET_LOG_BODY_SIZE);

            Mock::given(method("GET"))
                .and(path("/xrpc/chat.bsky.convo.getLog"))
                .respond_with(
                    ResponseTemplate::new(401)
                        .insert_header("dpop-nonce", "fresh-nonce-full-budget")
                        .set_body_bytes(full_budget_body),
                )
                .up_to_n_times(1)
                .mount(&pds)
                .await;

            let session = crate::models::CatbirdSession {
                id: Uuid::new_v4(),
                did: "did:plc:test_getlog_exhaust_user".to_string(),
                handle: "user.test".to_string(),
                pds_url: pds.uri(),
                access_token: "mock_token".to_string(),
                refresh_token: "mock_refresh".to_string(),
                scopes: vec!["atproto".to_string()],
                access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
                created_at: Utc::now(),
                last_used_at: Utc::now(),
                granted_scopes: vec!["atproto".to_string()],
            };

            let rate_budget = PdsRateBudget::new(100.0);
            let pds_host = "127.0.0.1";

            let err = fetch_log_page(
                &state,
                &session,
                &dpop_data,
                None,
                None,
                &rate_budget,
                pds_host,
            )
            .await
            .unwrap_err();

            let err_msg = err.to_string();
            assert!(
                err_msg.contains("Cumulative getLog response size exceeded maximum allowed limit"),
                "Expected cumulative limit bail on 5MB challenge body, got: {err_msg}"
            );
        }

        // Scenario 3: Attempt 1 consumes 3MB, leaving 2MB remaining budget. Attempt 2 response is 3MB (> 2MB remaining, but <= 5MB full constant).
        // Proves that retry receives the reduced remaining_budget and fails closed.
        {
            let pds = MockServer::start().await;
            let attempt1_bytes: usize = 3 * 1024 * 1024;
            let attempt2_bytes: usize = 3 * 1024 * 1024;
            let template = "{\"error\":\"use_dpop_nonce\",\"p\":\"\"}";
            let padding_len = attempt1_bytes.saturating_sub(template.len());
            let attempt1_body = format!(
                "{{\"error\":\"use_dpop_nonce\",\"p\":\"{}\"}}",
                "a".repeat(padding_len)
            )
            .into_bytes();
            assert_eq!(attempt1_body.len(), attempt1_bytes);

            // Attempt 1: 401 with 3MB body
            Mock::given(method("GET"))
                .and(path("/xrpc/chat.bsky.convo.getLog"))
                .respond_with(
                    ResponseTemplate::new(401)
                        .insert_header("dpop-nonce", "fresh-nonce-split-budget")
                        .set_body_bytes(attempt1_body.clone()),
                )
                .up_to_n_times(1)
                .mount(&pds)
                .await;

            // Attempt 2: 200 OK with 3MB body (header indicates 3MB, which exceeds remaining budget)
            Mock::given(method("GET"))
                .and(path("/xrpc/chat.bsky.convo.getLog"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-length", attempt2_bytes.to_string())
                        .set_body_bytes(vec![b'b'; attempt2_bytes]),
                )
                .mount(&pds)
                .await;

            let session = crate::models::CatbirdSession {
                id: Uuid::new_v4(),
                did: "did:plc:test_getlog_split_user".to_string(),
                handle: "user.test".to_string(),
                pds_url: pds.uri(),
                access_token: "mock_token".to_string(),
                refresh_token: "mock_refresh".to_string(),
                scopes: vec!["atproto".to_string()],
                access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
                created_at: Utc::now(),
                last_used_at: Utc::now(),
                granted_scopes: vec!["atproto".to_string()],
            };

            let rate_budget = PdsRateBudget::new(100.0);
            let pds_host = "127.0.0.1";

            let err = fetch_log_page(
                &state,
                &session,
                &dpop_data,
                None,
                None,
                &rate_budget,
                pds_host,
            )
            .await
            .unwrap_err();

            let err_msg = err.to_string();
            let expected_remaining = MAX_GET_LOG_BODY_SIZE.saturating_sub(attempt1_body.len());
            assert!(
                err_msg.contains(&format!("exceeds limit {}", expected_remaining)),
                "Expected retry to fail with limit of remaining budget ({expected_remaining}), got: {err_msg}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL and Redis (DATABASE_URL and REDIS_URL)"]
    async fn test_prime_pass_enforces_timeout_deadline_and_reschedules_current_item() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getLog"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(500))
                    .set_body_json(serde_json::json!({
                        "cursor": "next_cursor_xyz",
                        "logs": []
                    })),
            )
            .mount(&pds)
            .await;

        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let scheduler = ChatPollScheduler::new(pool.clone());
        let config = crate::config::AppConfig::test_default();
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client()
                .expect("hardened raw client"),
            redis,
            push_db: Some(pool.clone()),
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(crate::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let test_did = format!("did:plc:prime_timeout_{}", uuid::Uuid::new_v4());
        let pds_host = pds.uri().replace("http://", "").replace("https://", "");
        scheduler
            .enroll_account(&test_did, &pds_host)
            .await
            .unwrap();

        let row = ChatPollRow {
            account_did: test_did.clone(),
            chat_cursor: None,
            next_poll_at: time::OffsetDateTime::now_utc(),
            last_poll_at: None,
            poll_tier: 1,
            foreground_lease_until: None,
            pds_host: pds_host.clone(),
            last_429_at: None,
            last_retry_after_secs: None,
            last_notified_message_id: None,
            primed_at: None,
        };

        let session = crate::models::CatbirdSession {
            id: uuid::Uuid::new_v4(),
            did: test_did.clone(),
            handle: "user.test".to_string(),
            pds_url: pds.uri(),
            access_token: "mock_token".to_string(),
            refresh_token: "mock_refresh".to_string(),
            scopes: vec!["atproto".to_string()],
            access_token_expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            last_used_at: chrono::Utc::now(),
            granted_scopes: vec!["atproto".to_string()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = crate::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        let session_id = format!("sess_{}", uuid::Uuid::new_v4());
        let rate_budget = PdsRateBudget::new(20.0);
        // Start time configured so only 50ms remains of the 15s prime pass slice
        let prime_start =
            std::time::Instant::now() - (MAX_PRIME_PASS_DURATION - Duration::from_millis(50));

        let res = poll_account_with_session(
            &state,
            &pool,
            &scheduler,
            &rate_budget,
            &row,
            &session,
            &dpop_data,
            &session_id,
            1,
            prime_start,
        )
        .await;

        assert!(
            res.is_ok(),
            "Prime pass timeout must yield cleanly with Ok(()) without panicking or erroring"
        );

        // Verify account primed_at remains NULL in DB
        let primed_at: (Option<time::OffsetDateTime>,) =
            sqlx::query_as("SELECT primed_at FROM chat_poll_state WHERE account_did = $1")
                .bind(&test_did)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            primed_at.0.is_none(),
            "Account must not be marked primed when timed out"
        );

        // Clean up
        let _ = scheduler.unenroll_account(&test_did).await;
    }

    #[test]
    fn test_decompress_bounded_gzip_success() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let raw = b"{\"logs\":[{\"createMessage\":{\"convoId\":\"c1\",\"rev\":\"r1\"}}]}";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(raw).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_bounded(&compressed, Some("gzip"), 1024).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn test_decompress_bounded_brotli_success() {
        let raw = b"{\"logs\":[{\"createMessage\":{\"convoId\":\"c2\",\"rev\":\"r2\"}}]}";
        let mut compressed = Vec::new();
        let mut reader = &raw[..];
        brotli::BrotliCompress(
            &mut reader,
            &mut compressed,
            &brotli::enc::BrotliEncoderParams::default(),
        )
        .unwrap();

        let decompressed = decompress_bounded(&compressed, Some("br"), 1024).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn test_decompress_bounded_deflate_success() {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let raw = b"{\"logs\":[{\"createMessage\":{\"convoId\":\"c3\",\"rev\":\"r3\"}}]}";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(raw).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_bounded(&compressed, Some("deflate"), 1024).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn test_decompress_bounded_rejects_unsupported_encoding() {
        let raw = b"dummy content";
        let res = decompress_bounded(raw, Some("zstd"), 1024);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("Unsupported Content-Encoding: zstd"));
    }

    #[test]
    fn test_decompress_bounded_decompression_bomb_protection() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        // 100KB of zeros compresses to ~100 bytes
        let bomb = vec![0u8; 100 * 1024];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&bomb).unwrap();
        let compressed = encoder.finish().unwrap();

        // Budget of only 1KB must reject before completing decompression
        let res = decompress_bounded(&compressed, Some("gzip"), 1024);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("exceeded limit of 1024 bytes"));
    }

    #[tokio::test]
    #[ignore = "requires running Redis (REDIS_URL)"]
    async fn test_send_get_log_gzip_wire_counting_and_manual_decompression() {
        use chrono::Utc;
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        use uuid::Uuid;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let raw_json = serde_json::json!({
            "logs": [],
            "cursor": "cursor_gzip_test"
        });
        let raw_bytes = serde_json::to_vec(&raw_json).unwrap();

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&raw_bytes).unwrap();
        let compressed_bytes = encoder.finish().unwrap();

        let pds = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getLog"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(compressed_bytes.clone()),
            )
            .mount(&pds)
            .await;

        let config = crate::config::AppConfig::test_default();
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client()
                .expect("hardened raw client"),
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(crate::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:test_gzip_wire".to_string(),
            handle: "user.test".to_string(),
            pds_url: pds.uri(),
            access_token: "mock_token".to_string(),
            refresh_token: "mock_refresh".to_string(),
            scopes: vec!["atproto".to_string()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".to_string()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = crate::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        let client = crate::services::AtProtoClient::new(state.clone());
        let url = format!("{}/xrpc/chat.bsky.convo.getLog", pds.uri());

        let (status, headers, body, encoded_bytes) = send_get_log_request(
            &client,
            &state,
            &session,
            &dpop_data,
            &url,
            None,
            MAX_GET_LOG_BODY_SIZE,
        )
        .await
        .unwrap();

        assert_eq!(status, 200);
        assert_eq!(encoded_bytes, compressed_bytes.len());
        assert_eq!(headers.get("content-encoding").unwrap(), "gzip");
        assert_eq!(body.as_ref(), raw_bytes.as_slice());
    }

    #[tokio::test]
    #[ignore = "requires running Redis (REDIS_URL)"]
    async fn test_send_get_log_rejects_unsupported_content_encoding() {
        use chrono::Utc;
        use uuid::Uuid;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getLog"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "zstd")
                    .set_body_bytes(vec![1, 2, 3, 4]),
            )
            .mount(&pds)
            .await;

        let config = crate::config::AppConfig::test_default();
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client()
                .expect("hardened raw client"),
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(crate::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:test_zstd_reject".to_string(),
            handle: "user.test".to_string(),
            pds_url: pds.uri(),
            access_token: "mock_token".to_string(),
            refresh_token: "mock_refresh".to_string(),
            scopes: vec!["atproto".to_string()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".to_string()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = crate::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        let client = crate::services::AtProtoClient::new(state.clone());
        let url = format!("{}/xrpc/chat.bsky.convo.getLog", pds.uri());

        let res = send_get_log_request(
            &client,
            &state,
            &session,
            &dpop_data,
            &url,
            None,
            MAX_GET_LOG_BODY_SIZE,
        )
        .await;

        assert!(
            res.is_err(),
            "Must reject unsupported content-encoding zstd"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("Unsupported Content-Encoding: zstd"));
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL and Redis (DATABASE_URL and REDIS_URL)"]
    async fn test_prime_pass_bounds_logs_item_count_and_batches_watermarks() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;
        // Generate 1500 log items (exceeding MAX_PRIME_LOGS_PER_PAGE of 1000)
        let logs = (0..1500)
            .map(|i| {
                serde_json::json!({
                    "$type": "chat.bsky.convo.defs#logCreateMessage",
                    "convoId": format!("convo_{i}"),
                    "rev": format!("3lrev_{i:04}"),
                    "message": {
                        "id": format!("msg_{i}"),
                        "sender": { "did": "did:plc:sender" },
                        "text": "hello",
                        "sentAt": "2026-08-30T00:00:00Z"
                    }
                })
            })
            .collect::<Vec<_>>();

        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getLog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cursor": "cursor_page_1",
                "logs": logs
            })))
            .mount(&pds)
            .await;

        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let scheduler = ChatPollScheduler::new(pool.clone());
        let config = crate::config::AppConfig::test_default();
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client()
                .expect("hardened raw client"),
            redis,
            push_db: Some(pool.clone()),
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(crate::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let test_did = format!("did:plc:prime_bound_{}", uuid::Uuid::new_v4());
        let pds_host = pds.uri().replace("http://", "").replace("https://", "");
        scheduler
            .enroll_account(&test_did, &pds_host)
            .await
            .unwrap();

        let row = ChatPollRow {
            account_did: test_did.clone(),
            chat_cursor: None,
            next_poll_at: time::OffsetDateTime::now_utc(),
            last_poll_at: None,
            poll_tier: 1,
            foreground_lease_until: None,
            pds_host: pds_host.clone(),
            last_429_at: None,
            last_retry_after_secs: None,
            last_notified_message_id: None,
            primed_at: None,
        };

        let session = crate::models::CatbirdSession {
            id: uuid::Uuid::new_v4(),
            did: test_did.clone(),
            handle: "user.test".to_string(),
            pds_url: pds.uri(),
            access_token: "mock_token".to_string(),
            refresh_token: "mock_refresh".to_string(),
            scopes: vec!["atproto".to_string()],
            access_token_expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            last_used_at: chrono::Utc::now(),
            granted_scopes: vec!["atproto".to_string()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = crate::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        let session_id = format!("sess_{}", uuid::Uuid::new_v4());
        let rate_budget = PdsRateBudget::new(20.0);

        poll_account_with_session(
            &state,
            &pool,
            &scheduler,
            &rate_budget,
            &row,
            &session,
            &dpop_data,
            &session_id,
            1,
            std::time::Instant::now(),
        )
        .await
        .unwrap();

        // Verify EXACTLY 1000 watermarks were committed (not 1500) via bump_watermarks_batch
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM chat_notified_watermarks WHERE account_did = $1")
                .bind(&test_did)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            count.0, 1000,
            "Must bound watermark items to MAX_PRIME_LOGS_PER_PAGE (1000)"
        );

        // Clean up
        let _ = scheduler.unenroll_account(&test_did).await;
    }
}
