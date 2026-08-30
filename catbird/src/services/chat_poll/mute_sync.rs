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

/// Maximum number of listConvos pages fetched per account during mute sync.
pub const MAX_MUTE_SYNC_PAGES: usize = 20;

/// Maximum number of muted conversations collected per account during mute sync.
pub const MAX_MUTE_SYNC_ENTRIES: usize = 1000;

/// Maximum cumulative response bytes read per account during mute sync (5MB).
pub const MAX_MUTE_SYNC_BYTES: usize = 5 * 1024 * 1024;

/// Maximum execution time allowed for a single account's mute sync run.
pub const MAX_MUTE_SYNC_DURATION: std::time::Duration = std::time::Duration::from_secs(30);

/// Maximum length in bytes for a pagination cursor.
pub const MAX_MUTE_SYNC_CURSOR_LEN: usize = 512;

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
pub(crate) async fn sync_mutes_for_account(
    state: &Arc<AppState>,
    db_pool: &Pool<Postgres>,
    scheduler: &ChatPollScheduler,
    did: &str,
) -> Result<()> {
    let start_time = std::time::Instant::now();

    let (session_id, pds_url) = match tokio::time::timeout(
        MAX_MUTE_SYNC_DURATION,
        lookup_push_account(db_pool, did),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            tracing::warn!(did = %did, "Mute sync account lookup timed out");
            return Err(anyhow!("Mute sync account lookup timed out for {}", did));
        }
    };

    let remaining = match MAX_MUTE_SYNC_DURATION.checked_sub(start_time.elapsed()) {
        Some(t) if !t.is_zero() => t,
        _ => {
            tracing::warn!(
                did = %did,
                elapsed = ?start_time.elapsed(),
                "Mute sync duration budget exhausted before session resolution"
            );
            return Err(anyhow!(
                "Mute sync duration budget exhausted before session resolution for {}",
                did
            ));
        }
    };

    let (session, dpop) = match tokio::time::timeout(
        remaining,
        resolve_background_session(state, did, &session_id, &pds_url),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            tracing::warn!(did = %did, "Mute sync session resolution timed out");
            return Err(anyhow!("Mute sync session resolution timed out for {}", did));
        }
    };

    sync_mutes_for_session(state, scheduler, &session, &dpop, did, start_time).await
}

pub(crate) async fn sync_mutes_for_session(
    state: &Arc<AppState>,
    scheduler: &ChatPollScheduler,
    session: &crate::models::CatbirdSession,
    dpop: &crate::middleware::JacquardDpopData,
    did: &str,
    start_time: std::time::Instant,
) -> Result<()> {
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

    let mut staged_muted_ids: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut page_count: usize = 0;
    let mut total_bytes: usize = 0;
    let mut total_items_seen: usize = 0;
    let mut completed_cleanly = false;

    loop {
        if page_count >= MAX_MUTE_SYNC_PAGES {
            tracing::warn!(
                did = %did,
                page_count,
                "Mute sync page budget exhausted; aborting without modifying stored mutes"
            );
            break;
        }

        let remaining_time = match MAX_MUTE_SYNC_DURATION.checked_sub(start_time.elapsed()) {
            Some(t) if !t.is_zero() => t,
            _ => {
                tracing::warn!(
                    did = %did,
                    elapsed = ?start_time.elapsed(),
                    "Mute sync duration budget exhausted; aborting without modifying stored mutes"
                );
                break;
            }
        };

        let remaining_bytes = MAX_MUTE_SYNC_BYTES.saturating_sub(total_bytes);
        if remaining_bytes == 0 {
            tracing::warn!(
                did = %did,
                total_bytes,
                "Mute sync byte budget exhausted; aborting without modifying stored mutes"
            );
            break;
        }

        if let Some(c) = cursor.as_deref() {
            if c.len() > MAX_MUTE_SYNC_CURSOR_LEN {
                tracing::warn!(
                    did = %did,
                    cursor_len = c.len(),
                    "Mute sync received oversized cursor; aborting"
                );
                break;
            }
            if !seen_cursors.insert(c.to_string()) {
                tracing::warn!(
                    did = %did,
                    cursor = %c,
                    "Mute sync detected cursor cycle; aborting"
                );
                break;
            }
        }

        page_count += 1;

        let query = match cursor.as_deref() {
            Some(c) => format!("limit=100&cursor={}", urlencoding::encode(c)),
            None => "limit=100".to_string(),
        };

        // Pass remaining mute budget before buffering and wrap in remaining time slice
        let response = match tokio::time::timeout(
            remaining_time,
            client.proxy_request_with_limit(
                &session,
                reqwest::Method::GET,
                "/xrpc/chat.bsky.convo.listConvos",
                Some(&query),
                None,
                None,
                Some(&client_headers),
                "mute-sync",
                Some(&dpop),
                remaining_bytes,
            ),
        )
        .await
        {
            Ok(res) => res?,
            Err(_) => {
                tracing::warn!(
                    did = %did,
                    elapsed = ?start_time.elapsed(),
                    "Mute sync request timed out against remaining duration slice; aborting"
                );
                break;
            }
        };

        // Post-request deadline check before proceeding with parsing
        if start_time.elapsed() >= MAX_MUTE_SYNC_DURATION {
            tracing::warn!(
                did = %did,
                elapsed = ?start_time.elapsed(),
                "Mute sync duration budget exhausted after request; aborting without modifying stored mutes"
            );
            break;
        }

        let consumed = response.bytes_transferred();
        total_bytes = total_bytes.saturating_add(consumed);
        if total_bytes > MAX_MUTE_SYNC_BYTES {
            tracing::warn!(
                did = %did,
                total_bytes,
                consumed,
                "Mute sync byte budget exceeded after read; aborting without modifying stored mutes"
            );
            break;
        }

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
                return Err(anyhow!("Unexpected streaming response for listConvos"));
            }
        };

        let page: ListConvosResponse = serde_json::from_slice(&body_bytes)?;

        let mut has_invalid_item = false;
        for convo in &page.convos {
            total_items_seen += 1;
            if total_items_seen > MAX_MUTE_SYNC_ENTRIES {
                tracing::warn!(
                    did = %did,
                    total_items_seen,
                    "Mute sync total returned items entry budget exhausted; aborting"
                );
                break;
            }

            if convo.muted {
                if !crate::services::chat_poll::scheduler::is_valid_convo_id(&convo.id) {
                    tracing::warn!(
                        did = %did,
                        convo_id = %convo.id,
                        "Mute sync encountered invalid/malformed muted convo ID; aborting sync to preserve prior complete set"
                    );
                    has_invalid_item = true;
                    break;
                }
                staged_muted_ids.push(convo.id.clone());
            }
        }

        if has_invalid_item || total_items_seen > MAX_MUTE_SYNC_ENTRIES {
            break;
        }

        match page.cursor {
            Some(c) if !c.is_empty() => cursor = Some(c),
            _ => {
                completed_cleanly = true;
                break;
            }
        }
    }
    if completed_cleanly {
        let commit_remaining = match MAX_MUTE_SYNC_DURATION.checked_sub(start_time.elapsed()) {
            Some(t) if !t.is_zero() => t,
            _ => {
                tracing::warn!(
                    did = %did,
                    elapsed = ?start_time.elapsed(),
                    "Mute sync duration budget exhausted before commit; aborting without modifying stored mutes"
                );
                return Err(anyhow!("Mute sync duration budget exhausted before commit for {}", did));
            }
        };

        // Bulk-replace the muted set in the database ONLY on full clean completion within deadline
        match tokio::time::timeout(commit_remaining, scheduler.sync_muted_convos(did, &staged_muted_ids)).await {
            Ok(res) => res?,
            Err(_) => {
                tracing::warn!(
                    did = %did,
                    elapsed = ?start_time.elapsed(),
                    "Mute sync DB commit timed out"
                );
                return Err(anyhow!("Mute sync DB commit timed out for {}", did));
            }
        };

        tracing::debug!(
            did = %did,
            muted_count = staged_muted_ids.len(),
            "Mute sync completed successfully"
        );

        Ok(())
    } else {
        tracing::warn!(
            did = %did,
            "Mute sync did not complete cleanly; preserving prior database state and failing closed"
        );
        Err(anyhow!("Mute sync did not complete cleanly for {}", did))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mute_sync_constants_and_budgets() {
        assert_eq!(MAX_MUTE_SYNC_PAGES, 20);
        assert_eq!(MAX_MUTE_SYNC_ENTRIES, 1000);
        assert_eq!(MAX_MUTE_SYNC_BYTES, 5 * 1024 * 1024);
        assert_eq!(MAX_MUTE_SYNC_CURSOR_LEN, 512);
        assert_eq!(MAX_MUTE_SYNC_DURATION, std::time::Duration::from_secs(30));
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL and Redis (DATABASE_URL and REDIS_URL)"]
    async fn test_cursor_cycle_detection() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use chrono::Utc;
        use uuid::Uuid;

        let server = MockServer::start().await;
        // Page 1 returns cursor "cycle_cursor_token"
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .and(query_param("limit", "100"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "convos": [
                        { "id": "convo-1", "muted": true }
                    ],
                    "cursor": "cycle_cursor_token"
                })),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Page 2 returns the exact same cursor "cycle_cursor_token" (cycle)
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .and(query_param("cursor", "cycle_cursor_token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "convos": [
                        { "id": "convo-2", "muted": true }
                    ],
                    "cursor": "cycle_cursor_token"
                })),
            )
            .mount(&server)
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
        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client().expect("hardened raw client"),
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
        });

        let test_did = format!("did:plc:mute_cycle_{}", Uuid::new_v4());
        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: test_did.clone(),
            handle: "user.test".to_string(),
            pds_url: server.uri(),
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

        let start_time = std::time::Instant::now();
        let res = sync_mutes_for_session(&state, &scheduler, &session, &dpop_data, &test_did, start_time).await;
        assert!(res.is_err(), "Must fail when cursor cycle is detected");
        let err = res.unwrap_err().to_string();
        assert!(err.contains("did not complete cleanly"), "Error was: {err}");

        let requests = server.received_requests().await.expect("received requests");
        assert_eq!(
            requests.len(),
            2,
            "Cycle detection must abort after 2 requests instead of spinning until page cap"
        );
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM chat_muted_convos WHERE account_did = $1")
            .bind(&test_did)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0, "No mutes must be committed on cycle abort");
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL and Redis (DATABASE_URL and REDIS_URL)"]
    async fn test_cursor_length_validation() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use chrono::Utc;
        use uuid::Uuid;

        let server = MockServer::start().await;
        // Upstream returns an oversized cursor > 512 bytes
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "convos": [
                        { "id": "convo-1", "muted": true }
                    ],
                    "cursor": "a".repeat(MAX_MUTE_SYNC_CURSOR_LEN + 1)
                })),
            )
            .mount(&server)
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
        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client().expect("hardened raw client"),
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
        });

        let test_did = format!("did:plc:mute_cursor_len_{}", Uuid::new_v4());
        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: test_did.clone(),
            handle: "user.test".to_string(),
            pds_url: server.uri(),
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

        let start_time = std::time::Instant::now();
        let res = sync_mutes_for_session(&state, &scheduler, &session, &dpop_data, &test_did, start_time).await;
        assert!(res.is_err(), "Must fail when cursor length exceeds maximum");
        let err = res.unwrap_err().to_string();
        assert!(err.contains("did not complete cleanly"), "Error was: {err}");

        let requests = server.received_requests().await.expect("received requests");
        assert_eq!(
            requests.len(),
            1,
            "Cursor length guard must abort after 1 request instead of fetching subsequent pages"
        );
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM chat_muted_convos WHERE account_did = $1")
            .bind(&test_did)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0, "No mutes must be committed on oversized cursor abort");
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL and Redis (DATABASE_URL and REDIS_URL)"]
    async fn test_mute_sync_all_items_counted_against_budget() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use chrono::Utc;
        use uuid::Uuid;

        let server = MockServer::start().await;
        // Upstream returns 1001 unmuted conversations (> MAX_MUTE_SYNC_ENTRIES = 1000)
        let convos: Vec<_> = (0..1001)
            .map(|i| serde_json::json!({
                "id": format!("convo-unmuted-{}", i),
                "muted": false
            }))
            .collect();

        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "convos": convos
                })),
            )
            .mount(&server)
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
        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client().expect("hardened raw client"),
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
        });

        let test_did = format!("did:plc:mute_entries_budget_{}", Uuid::new_v4());
        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: test_did.clone(),
            handle: "user.test".to_string(),
            pds_url: server.uri(),
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

        let start_time = std::time::Instant::now();
        let res = sync_mutes_for_session(&state, &scheduler, &session, &dpop_data, &test_did, start_time).await;
        assert!(res.is_err(), "Must fail when total returned items exceed entry budget");
        let err = res.unwrap_err().to_string();
        assert!(err.contains("did not complete cleanly"), "Error was: {err}");

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM chat_muted_convos WHERE account_did = $1")
            .bind(&test_did)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0, "No mutes must be committed when entry budget is exceeded");
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL and Redis (DATABASE_URL and REDIS_URL)"]
    async fn test_mute_sync_invalid_item_aborts_without_partial_staging() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use chrono::Utc;
        use uuid::Uuid;

        let server = MockServer::start().await;
        // Upstream returns one valid muted conversation and one invalid/malformed conversation ID
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "convos": [
                        { "id": "valid-convo-12345", "muted": true },
                        { "id": "invalid convo id with spaces!", "muted": true }
                    ]
                })),
            )
            .mount(&server)
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
        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client().expect("hardened raw client"),
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
        });

        let test_did = format!("did:plc:mute_invalid_item_{}", Uuid::new_v4());
        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: test_did.clone(),
            handle: "user.test".to_string(),
            pds_url: server.uri(),
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

        let start_time = std::time::Instant::now();
        let res = sync_mutes_for_session(&state, &scheduler, &session, &dpop_data, &test_did, start_time).await;
        assert!(res.is_err(), "Must fail when invalid/malformed conversation ID is encountered");
        let err = res.unwrap_err().to_string();
        assert!(err.contains("did not complete cleanly"), "Error was: {err}");

        // Verify database has NO committed mutes (valid-convo-12345 must not be partially staged)
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM chat_muted_convos WHERE account_did = $1")
            .bind(&test_did)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0, "No mutes must be committed when invalid item is encountered");
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL and Redis (DATABASE_URL and REDIS_URL)"]
    async fn test_mute_sync_enforces_duration_deadline_and_aborts_without_committing() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use std::time::Duration;
        use chrono::Utc;
        use uuid::Uuid;

        let server = MockServer::start().await;
        // Slow upstream response with 500ms delay
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(500))
                    .set_body_json(serde_json::json!({
                        "convos": [
                            { "id": "convo-12345", "muted": true }
                        ]
                    })),
            )
            .mount(&server)
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
        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let state = Arc::new(crate::config::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: crate::services::build_hardened_raw_http_client().expect("hardened raw client"),
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
        });

        let test_did = format!("did:plc:mute_timeout_{}", Uuid::new_v4());
        let session = crate::models::CatbirdSession {
            id: Uuid::new_v4(),
            did: test_did.clone(),
            handle: "user.test".to_string(),
            pds_url: server.uri(),
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

        // Start time set so only 50ms remains of the 30s budget
        let start_time = std::time::Instant::now() - (MAX_MUTE_SYNC_DURATION - Duration::from_millis(50));

        let res = sync_mutes_for_session(&state, &scheduler, &session, &dpop_data, &test_did, start_time).await;
        assert!(res.is_err(), "Must fail when upstream delay exceeds remaining duration");
        let err = res.unwrap_err().to_string();
        assert!(err.contains("did not complete cleanly") || err.contains("timed out"), "Error was: {err}");

        // Verify database has NO committed mutes for this account
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM chat_muted_convos WHERE account_did = $1")
            .bind(&test_did)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0, "No mutes must be committed on timeout");
    }
}
