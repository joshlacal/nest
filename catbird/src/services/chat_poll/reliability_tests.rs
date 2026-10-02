//! Local-only failure injection for poller transaction and catch-up semantics.
use super::super::types::{LogMessage, LogMessageEvent, LogSender};
use super::*;
use sqlx::Row;

struct TestDb {
    admin: Pool<Postgres>,
    pool: Pool<Postgres>,
    name: String,
}

impl TestDb {
    async fn new() -> Self {
        let dsn = std::env::var("DATABASE_URL").expect("explicit disposable DATABASE_URL required");
        let mut url = url::Url::parse(&dsn).unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(
            url.port(),
            Some(55471),
            "dedicated LITE-001 PostgreSQL only"
        );
        assert_eq!(url.username(), "lite_push_test");
        let admin = Pool::<Postgres>::connect(&dsn).await.unwrap();
        let name = format!("lite_poller_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        url.set_path(&name);
        let pool = Pool::<Postgres>::connect(url.as_str()).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        Self { admin, pool, name }
    }

    async fn account(&self) -> ChatPollRow {
        let did = "did:plc:localpollfixture";
        sqlx::query("INSERT INTO push_accounts (account_did, session_id, pds_url, auth_generation) VALUES ($1, 'fixture-session', 'https://pds.invalid', 1)")
            .bind(did).execute(&self.pool).await.unwrap();
        ChatPollScheduler::new(self.pool.clone())
            .enroll_account(did, "pds.invalid")
            .await
            .unwrap();
        sqlx::query("UPDATE chat_poll_state SET chat_cursor = 'before', primed_at = NOW(), last_successful_poll_at = NOW() WHERE account_did = $1")
            .bind(did).execute(&self.pool).await.unwrap();
        self.row().await
    }

    async fn row(&self) -> ChatPollRow {
        sqlx::query_as(
            "SELECT * FROM chat_poll_state WHERE account_did = 'did:plc:localpollfixture'",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn counts(&self) -> (i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT COUNT(*) FROM push_event_queue), (SELECT COUNT(*) FROM push_event_receipts), (SELECT COUNT(*) FROM chat_notified_watermarks)")
            .fetch_one(&self.pool).await.unwrap()
    }

    async fn finish(self) {
        self.pool.close().await;
        sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}

fn message(convo: &str, rev: &str, id: &str) -> LogMessageEvent {
    LogMessageEvent {
        convo_id: convo.into(),
        rev: rev.into(),
        message: LogMessage {
            id: id.into(),
            sender: LogSender {
                did: "did:plc:senderfixture".into(),
            },
            text: Some("fixture only, must not persist".into()),
            sent_at: chrono::Utc::now().to_rfc3339(),
        },
    }
}

fn page(logs: Vec<LogEntry>) -> GetLogResponse {
    GetLogResponse {
        cursor: "after".into(),
        logs,
    }
}

#[tokio::test]
#[ignore = "requires dedicated disposable LITE-001 PostgreSQL"]
async fn poller_atomic_page_rolls_back_failed_outbox_and_replays_after_restart() {
    let db = TestDb::new().await;
    let row = db.account().await;
    sqlx::raw_sql(
        r#"
        CREATE FUNCTION crash_before_queue_insert() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.event_cid = 'bad' THEN PERFORM pg_terminate_backend(pg_backend_pid()); END IF;
            RETURN NEW;
        END $$;
        CREATE TRIGGER inject_failure BEFORE INSERT ON push_event_queue
            FOR EACH ROW EXECUTE FUNCTION crash_before_queue_insert();
    "#,
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let logs = page(vec![
        LogEntry::CreateMessage(message("convo", "3la", "good")),
        LogEntry::CreateMessage(message("convo", "3lb", "bad")),
    ]);
    assert!(persist_log_page(&db.pool, &row, &logs, 1).await.is_err());
    assert_eq!(db.counts().await, (0, 0, 0));
    assert_eq!(db.row().await.chat_cursor.as_deref(), Some("before"));
    sqlx::query("DROP TRIGGER inject_failure ON push_event_queue")
        .execute(&db.pool)
        .await
        .unwrap();
    // A restarted worker receives the same still-uncommitted source page.
    let restarted_row = db.row().await;
    persist_log_page(&db.pool, &restarted_row, &logs, 1)
        .await
        .unwrap();
    assert_eq!(db.counts().await, (2, 2, 1));
    assert_eq!(db.row().await.chat_cursor.as_deref(), Some("after"));
    db.finish().await;
}

#[tokio::test]
#[ignore = "requires dedicated disposable LITE-001 PostgreSQL"]
async fn poller_duplicate_reordered_pages_keep_distinct_events_once() {
    let db = TestDb::new().await;
    let row = db.account().await;
    let logs = page(vec![
        LogEntry::CreateMessage(message("convo", "3lb", "second")),
        LogEntry::CreateMessage(message("convo", "3la", "first")),
        LogEntry::CreateMessage(message("convo", "3la", "first")),
    ]);
    persist_log_page(&db.pool, &row, &logs, 1).await.unwrap();
    persist_log_page(&db.pool, &row, &logs, 1).await.unwrap(); // obsolete overlapping claim
    let restarted = db.row().await;
    persist_log_page(&db.pool, &restarted, &logs, 1)
        .await
        .unwrap(); // replayed upstream page
    assert_eq!(db.counts().await, (2, 2, 1));
    let records: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT event_record_json FROM push_event_queue")
            .fetch_all(&db.pool)
            .await
            .unwrap();
    assert!(records.iter().all(|r| r["messageText"] == ""));
    assert!(records.iter().all(|r| r["logRev"].as_str().is_some()));
    db.finish().await;
}

#[tokio::test]
#[ignore = "requires dedicated disposable LITE-001 PostgreSQL"]
async fn poller_read_mute_and_own_suppression_preserve_read_watermark() {
    let db = TestDb::new().await;
    let row = db.account().await;
    ChatPollScheduler::new(db.pool.clone())
        .set_convo_muted(&row.account_did, "muted", true)
        .await
        .unwrap();
    let mut own = message("own", "3la", "own");
    own.message.sender.did = row.account_did.clone();
    let logs = page(vec![
        LogEntry::CreateMessage(message("read", "3la", "read")),
        LogEntry::ReadMessage(message("read", "3lc", "read")),
        LogEntry::CreateMessage(message("muted", "3la", "muted")),
        LogEntry::CreateMessage(own),
        LogEntry::CreateMessage(message("visible", "3la", "visible")),
    ]);
    persist_log_page(&db.pool, &row, &logs, 1).await.unwrap();
    assert_eq!(db.counts().await, (1, 1, 4));
    let read: Option<String> = sqlx::query_scalar(
        "SELECT last_read_rev FROM chat_notified_watermarks WHERE convo_id = 'read'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(read.as_deref(), Some("3lc"));
    db.finish().await;
}

#[tokio::test]
#[ignore = "requires dedicated disposable LITE-001 PostgreSQL"]
async fn poller_old_source_message_holds_entire_page_without_discard() {
    let db = TestDb::new().await;
    let row = db.account().await;
    let mut old = message("convo", "3lb", "old");
    old.message.sent_at = (chrono::Utc::now() - chrono::Duration::days(2)).to_rfc3339();
    let logs = page(vec![
        LogEntry::CreateMessage(message("convo", "3la", "fresh")),
        LogEntry::CreateMessage(old),
    ]);
    persist_log_page(&db.pool, &row, &logs, 1).await.unwrap();
    assert_eq!(db.counts().await, (0, 0, 0));
    assert_eq!(db.row().await.chat_cursor.as_deref(), Some("before"));
    let reason: Option<String> = sqlx::query_scalar("SELECT catch_up_reason FROM chat_poll_state")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(reason.as_deref(), Some("source_message_older_than_24h"));
    assert!(ChatPollScheduler::new(db.pool.clone())
        .claim_due_accounts(10)
        .await
        .unwrap()
        .is_empty());
    db.finish().await;
}

#[tokio::test]
#[ignore = "requires dedicated disposable LITE-001 PostgreSQL"]
async fn poller_reopening_holds_stale_and_unattested_but_not_fresh_accounts() {
    let db = TestDb::new().await;
    let row = db.account().await;
    let scheduler = ChatPollScheduler::new(db.pool.clone());
    assert!(!scheduler
        .hold_if_catch_up_required(&row.account_did)
        .await
        .unwrap());
    sqlx::query("UPDATE chat_poll_state SET last_successful_poll_at = NOW() - INTERVAL '2 days', next_poll_at = NOW()")
        .execute(&db.pool).await.unwrap();
    let claimed = scheduler.claim_due_accounts(1).await.unwrap();
    assert_eq!(claimed.len(), 1);
    assert!(scheduler
        .hold_if_catch_up_required(&row.account_did)
        .await
        .unwrap());
    assert_eq!(db.row().await.chat_cursor.as_deref(), Some("before"));
    sqlx::query("UPDATE chat_poll_state SET catch_up_required_at = NULL, catch_up_reason = NULL, last_successful_poll_at = NULL")
        .execute(&db.pool).await.unwrap();
    assert!(scheduler
        .hold_if_catch_up_required(&row.account_did)
        .await
        .unwrap());
    let reason: Option<String> = sqlx::query_scalar("SELECT catch_up_reason FROM chat_poll_state")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(reason.as_deref(), Some("unattested_initialized_cursor"));
    sqlx::query("UPDATE chat_poll_state SET catch_up_required_at = NULL, catch_up_reason = NULL, primed_at = NULL")
        .execute(&db.pool).await.unwrap();
    assert!(!scheduler
        .hold_if_catch_up_required(&row.account_did)
        .await
        .unwrap());
    db.finish().await;
}

#[tokio::test]
#[ignore = "requires dedicated disposable LITE-001 PostgreSQL"]
async fn poller_prime_transactions_are_alert_free_and_fenced() {
    let db = TestDb::new().await;
    let row = db.account().await;
    sqlx::query("UPDATE chat_poll_state SET primed_at = NULL, last_successful_poll_at = NULL")
        .execute(&db.pool)
        .await
        .unwrap();
    let watermarks = HashMap::from([("convo".into(), "3lb".into())]);
    assert!(
        persist_prime_page(&db.pool, &row, Some("before"), "middle", &watermarks, false)
            .await
            .unwrap()
    );
    assert!(
        !persist_prime_page(&db.pool, &row, Some("before"), "stale", &watermarks, true)
            .await
            .unwrap()
    );
    assert!(
        persist_prime_page(&db.pool, &row, Some("middle"), "head", &watermarks, true)
            .await
            .unwrap()
    );
    assert_eq!(db.counts().await, (0, 0, 1));
    let current = db.row().await;
    assert_eq!(current.chat_cursor.as_deref(), Some("head"));
    assert!(current.primed_at.is_some());
    assert!(!ChatPollScheduler::new(db.pool.clone())
        .hold_if_catch_up_required(&row.account_did)
        .await
        .unwrap());
    db.finish().await;
}

#[test]
fn poller_rejects_oversized_page_without_accepting_truncated_progress() {
    let logs = page(
        (0..=MAX_PRIME_LOGS_PER_PAGE)
            .map(|_| LogEntry::Unknown)
            .collect(),
    );
    assert!(validate_log_page(&logs).is_err());
}

#[tokio::test]
#[ignore = "requires dedicated disposable LITE-001 PostgreSQL"]
async fn poller_stale_auth_generation_cannot_advance_cursor_or_watermark() {
    let db = TestDb::new().await;
    let row = db.account().await;
    sqlx::query("UPDATE push_accounts SET auth_generation = 2")
        .execute(&db.pool)
        .await
        .unwrap();
    let logs = page(vec![LogEntry::CreateMessage(message(
        "convo", "3la", "first",
    ))]);
    assert!(persist_log_page(&db.pool, &row, &logs, 1).await.is_err());
    assert_eq!(db.counts().await, (0, 0, 0));
    assert_eq!(db.row().await.chat_cursor.as_deref(), Some("before"));
    persist_log_page(&db.pool, &row, &logs, 2).await.unwrap();
    assert_eq!(db.counts().await, (1, 1, 1));
    db.finish().await;
}

#[tokio::test]
#[ignore = "requires dedicated disposable LITE-001 PostgreSQL and Redis"]
async fn poller_live_getlog_priming_and_reopening_emit_no_push() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};
    let db = TestDb::new().await;
    let row = db.account().await;
    sqlx::query("UPDATE chat_poll_state SET primed_at = NULL, chat_cursor = NULL, last_successful_poll_at = NULL")
        .execute(&db.pool).await.unwrap();
    let row = db.row().await;
    let pds = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.getLog"))
        .respond_with(|request: &Request| {
            let logs = if request.url.query().is_none() {
                serde_json::json!([{
                    "$type": "chat.bsky.convo.defs#logCreateMessage",
                    "convoId": "history", "rev": "3la",
                    "message": {"id": "old", "sender": {"did": "did:plc:senderfixture"},
                        "text": "old fixture", "sentAt": "2026-01-01T00:00:00Z"}
                }])
            } else {
                serde_json::json!([])
            };
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"cursor": "head", "logs": logs}))
        })
        .mount(&pds)
        .await;
    let redis_dsn = std::env::var("REDIS_URL").expect("explicit disposable REDIS_URL required");
    assert_eq!(redis_dsn, "redis://127.0.0.1:56381");
    let client = redis::Client::open(redis_dsn).unwrap();
    let mut subscriber = client.get_async_pubsub().await.unwrap();
    subscriber.subscribe("chat_push").await.unwrap();
    let redis = redis::aio::ConnectionManager::new(client).await.unwrap();
    let state = Arc::new(crate::config::AppState {
        config: Arc::new(crate::config::AppConfig::test_default()),
        http_client: reqwest::Client::new(),
        raw_http_client: crate::services::build_hardened_raw_http_client().unwrap(),
        redis,
        push_db: Some(db.pool.clone()),
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
        id: uuid::Uuid::new_v4(),
        did: row.account_did.clone(),
        handle: "fixture.test".into(),
        pds_url: pds.uri(),
        access_token: "mock".into(),
        refresh_token: "mock".into(),
        scopes: vec!["atproto".into()],
        granted_scopes: vec!["atproto".into()],
        access_token_expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        created_at: chrono::Utc::now(),
        last_used_at: chrono::Utc::now(),
    };
    let secret = p256::SecretKey::random(&mut rand::thread_rng());
    let crypto_key = jose_jwk::crypto::Key::from(secret);
    let dpop = crate::middleware::JacquardDpopData {
        dpop_key: jose_jwk::Key::from(&crypto_key),
        dpop_host_nonce: String::new(),
    };
    let scheduler = ChatPollScheduler::new(db.pool.clone());
    let budget = PdsRateBudget::new(20.0);
    poll_account_with_session(
        &state,
        &db.pool,
        &scheduler,
        &budget,
        &row,
        &session,
        &dpop,
        "fixture-session",
        1,
        std::time::Instant::now(),
    )
    .await
    .unwrap();
    assert_eq!(db.counts().await, (0, 0, 1));
    assert!(db.row().await.primed_at.is_some());
    assert_eq!(db.row().await.chat_cursor.as_deref(), Some("head"));
    assert_eq!(pds.received_requests().await.unwrap().len(), 2);
    sqlx::query("UPDATE chat_poll_state SET last_successful_poll_at = NOW() - INTERVAL '2 days'")
        .execute(&db.pool)
        .await
        .unwrap();
    let stale_row = db.row().await;
    poll_account_with_session(
        &state,
        &db.pool,
        &scheduler,
        &budget,
        &stale_row,
        &session,
        &dpop,
        "fixture-session",
        1,
        std::time::Instant::now(),
    )
    .await
    .unwrap();
    assert_eq!(
        pds.received_requests().await.unwrap().len(),
        2,
        "held cursor must not fetch more history"
    );
    assert_eq!(db.row().await.chat_cursor.as_deref(), Some("head"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), subscriber.on_message().next())
            .await
            .is_err()
    );
    drop(state);
    db.finish().await;
}
