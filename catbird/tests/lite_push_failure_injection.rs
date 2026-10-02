//! Independent LITE-001 qualification through the production enqueue and worker APIs.
//! No APNs connections are made. Each test creates its own database in an explicitly
//! selected disposable local PostgreSQL instance and uses an explicit local Redis.
//! Worker cancellation models lost process state; it is not a phone-delivery receipt.

use std::collections::{HashMap, VecDeque};
use std::sync::{atomic::AtomicBool, Arc};
use std::time::Duration;

use catbird::config::{AppConfig, AppState, PushConfig};
use catbird::models::CatbirdSession;
use catbird::services::chat_poll::{poller::enqueue_push, types::ChatPushEvent};
use catbird::services::push::{
    apns::{ApnsNotification, ApnsSender},
    types::{RegisterPushInput, RegistrationRow},
    PushServices,
};
use chrono::Utc;
use serde_json::json;
use sqlx::{Pool, Postgres};
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

const RECIPIENT: &str = "did:plc:litefailuretest";
const SENDER: &str = "did:plc:litefailuresender";
const CONVO: &str = "lite-failure-convo";

fn isolated_url(name: &str, scheme: &str, shared_port: u16) -> String {
    assert_eq!(
        std::env::var("LITE_PUSH_DISPOSABLE").as_deref(),
        Ok("1"),
        "LITE_PUSH_DISPOSABLE=1 is required; never run on shared or production stores"
    );
    let value = std::env::var(name).expect("explicit disposable store URL required");
    let url = url::Url::parse(&value).expect("valid disposable store URL");
    assert_eq!(url.scheme(), scheme);
    assert_eq!(url.host_str(), Some("127.0.0.1"));
    let port = url.port().expect("explicit nondefault port required");
    assert_ne!(
        port, shared_port,
        "default/shared store ports are forbidden"
    );
    value
}

#[derive(Clone, Copy)]
enum Outcome {
    Accepted,
    Rejected,
    AcceptedWithoutResponse,
    WaitingBeforeAcceptance,
}

#[derive(Default)]
struct FakeApns {
    outcomes: Mutex<HashMap<String, VecDeque<Outcome>>>,
    attempts: Mutex<Vec<String>>,
    accepted: Mutex<Vec<String>>,
    entered: Notify,
}

impl FakeApns {
    async fn plan(&self, token: &str, outcomes: &[Outcome]) {
        self.outcomes
            .lock()
            .await
            .insert(token.to_owned(), outcomes.iter().copied().collect());
    }

    async fn attempts_for(&self, token: &str) -> usize {
        self.attempts
            .lock()
            .await
            .iter()
            .filter(|t| *t == token)
            .count()
    }

    async fn accepted_for(&self, token: &str) -> usize {
        self.accepted
            .lock()
            .await
            .iter()
            .filter(|t| *t == token)
            .count()
    }
}

#[async_trait::async_trait]
impl ApnsSender for FakeApns {
    async fn send(
        &self,
        registration: &RegistrationRow,
        notification: &ApnsNotification,
    ) -> anyhow::Result<&'static str> {
        assert_eq!(
            notification.custom_data.get("type").map(String::as_str),
            Some("chat_message")
        );
        self.attempts
            .lock()
            .await
            .push(registration.device_token.clone());
        let outcome = self
            .outcomes
            .lock()
            .await
            .get_mut(&registration.device_token)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Outcome::Accepted);
        match outcome {
            Outcome::Accepted => {
                self.accepted
                    .lock()
                    .await
                    .push(registration.device_token.clone());
                self.entered.notify_one();
                Ok("sandbox")
            }
            Outcome::Rejected => {
                self.entered.notify_one();
                Err(a2::Error::ResponseError(a2::Response {
                    error: Some(a2::ErrorBody {
                        reason: a2::ErrorReason::ServiceUnavailable,
                        timestamp: None,
                    }),
                    apns_id: Some(Uuid::new_v4().to_string()),
                    code: 503,
                })
                .into())
            }
            Outcome::AcceptedWithoutResponse => {
                self.accepted
                    .lock()
                    .await
                    .push(registration.device_token.clone());
                self.entered.notify_one();
                std::future::pending().await
            }
            Outcome::WaitingBeforeAcceptance => {
                self.entered.notify_one();
                std::future::pending().await
            }
        }
    }
}

struct Fixture {
    pool: Pool<Postgres>,
    database_url: String,
    redis_url: String,
    fake: Arc<FakeApns>,
    session: CatbirdSession,
    event: ChatPushEvent,
}

impl Fixture {
    async fn new(devices: usize) -> Self {
        Self::new_at_schema(devices, true).await
    }

    async fn new_at_schema(devices: usize, delivery_schema: bool) -> Self {
        let database_url = isolated_url("DATABASE_URL", "postgres", 5432);
        let redis_url = isolated_url("REDIS_URL", "redis", 6379);
        let admin = Pool::<Postgres>::connect(&database_url).await.unwrap();
        let name = format!("lite_push_failure_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&database_url).unwrap();
        url.set_path(&name);
        let pool = Pool::<Postgres>::connect(url.as_str()).await.unwrap();
        let migrator = sqlx::migrate!("./migrations");
        if delivery_schema {
            migrator.run(&pool).await.unwrap();
        } else {
            for migration in migrator.iter().filter(|migration| {
                migration.version < 20261002000200 && migration.migration_type.is_up_migration()
            }) {
                sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
            }
        }
        admin.close().await;
        // Keep the database within the disposable instance for evidence after a
        // failure. The cluster's owner performs its final cleanup, not this test.
        eprintln!("LITE-001 fixture database: {name}");

        let now = Utc::now();
        let session = CatbirdSession {
            id: Uuid::new_v4(),
            did: RECIPIENT.to_string(),
            handle: "fixture.test".to_string(),
            pds_url: "http://127.0.0.1:9".to_string(),
            access_token: "fixture-access".to_string(),
            refresh_token: "fixture-refresh".to_string(),
            scopes: vec!["atproto".to_string()],
            access_token_expires_at: now + chrono::Duration::hours(1),
            created_at: now,
            last_used_at: now,
            granted_scopes: vec!["atproto".to_string()],
        };
        let event = serde_json::from_value(json!({
            "recipientDid": RECIPIENT,
            "senderDid": SENDER,
            "convoId": CONVO,
            "messageId": "fixture-message-1",
            "messageText": "private fixture preview must never persist",
            "sentAt": now.to_rfc3339(),
            "authGeneration": 1,
            "logRev": "0000000000003"
        }))
        .unwrap();
        let fixture = Self {
            pool,
            database_url: url.to_string(),
            redis_url,
            fake: Arc::new(FakeApns::default()),
            session,
            event,
        };
        let services = fixture.services();
        for index in 1..=devices {
            fixture.register(&services, index).await;
        }
        sqlx::query(
            "INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at, generation) \
             SELECT account_did, $2, '{}'::jsonb, 'Fixture Sender', NOW(), moderation_generation \
             FROM push_accounts WHERE account_did = $1"
        ).bind(RECIPIENT).bind(SENDER).execute(&fixture.pool).await.unwrap();
        fixture
    }

    fn services(&self) -> Arc<PushServices> {
        let mut config = PushConfig::default();
        config.service_did = Some("did:web:push.fixture.test".to_string());
        config.apns.enabled = false;
        config.send_timeout_seconds = 1;
        Arc::new(
            PushServices::new(self.pool.clone(), config)
                .unwrap()
                .with_apns_sender(self.fake.clone()),
        )
    }

    async fn state(&self, services: Arc<PushServices>) -> Arc<AppState> {
        make_state(self.pool.clone(), &self.redis_url, services).await
    }

    async fn register(&self, services: &PushServices, index: usize) {
        services
            .registry
            .upsert_registration(
                &self.session,
                &RegisterPushInput {
                    service_did: "did:web:push.fixture.test".to_string(),
                    token: format!("{index:064x}"),
                    platform: "ios".to_string(),
                    app_id: "blue.catbird.fixture".to_string(),
                    age_restricted: Some(false),
                },
            )
            .await
            .unwrap();
    }

    async fn enqueue(&self) {
        enqueue_push(&self.pool, &self.event, 0).await.unwrap();
    }

    async fn process_with_new_worker(&self) -> usize {
        let services = self.services();
        let state = self.state(services.clone()).await;
        services.process_queue_batch(&state).await.unwrap()
    }

    async fn make_due(&self) {
        sqlx::query("UPDATE push_event_queue SET available_at = NOW(), leased_until = NOW() - INTERVAL '1 second'")
            .execute(&self.pool).await.unwrap();
    }

    async fn receipt_state(&self) -> String {
        sqlx::query_scalar("SELECT state FROM push_event_receipts WHERE dedupe_key = $1")
            .bind(self.event.dedupe_key())
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn queue_count(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM push_event_queue")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn device_state(&self, token: &str) -> String {
        sqlx::query_scalar("SELECT pd.state FROM push_device_deliveries pd JOIN user_devices ud ON ud.id = pd.device_id WHERE pd.dedupe_key = $1 AND ud.device_token = $2")
            .bind(self.event.dedupe_key()).bind(token).fetch_one(&self.pool).await.unwrap()
    }
}

async fn make_state(
    pool: Pool<Postgres>,
    redis_url: &str,
    services: Arc<PushServices>,
) -> Arc<AppState> {
    let mut config = AppConfig::test_default();
    config.redis.url = redis_url.to_string();
    let redis = redis::aio::ConnectionManager::new(redis::Client::open(redis_url).unwrap())
        .await
        .unwrap();
    Arc::new(AppState {
        config: Arc::new(config),
        http_client: reqwest::Client::new(),
        raw_http_client: reqwest::Client::new(),
        redis,
        push_db: Some(pool),
        key_store: None,
        jacquard_client: None,
        catmos_jacquard_client: None,
        catmos_oauth_scopes: vec![],
        trusted_proxies: vec![],
        auth_store: None,
        push: Some(services),
        dpop_nonce_cache: Arc::new(catbird::services::DpopNonceCache::new()),
        session_encryption_key: None,
        active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
        session_index_ready: Arc::new(AtomicBool::new(true)),
        session_index_readiness: Arc::new(Notify::new()),
    })
}

#[tokio::test]
async fn committed_event_survives_absent_hint_and_completed_replay_with_new_device() {
    let fixture = Fixture::new(1).await;
    fixture.enqueue().await;
    fixture.enqueue().await;
    assert_eq!(fixture.queue_count().await, 1);
    let persisted: serde_json::Value =
        sqlx::query_scalar("SELECT event_record_json FROM push_event_queue")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(!persisted.to_string().contains("private fixture preview"));
    // No Redis hint was published, and a newly constructed worker owns delivery.
    assert_eq!(fixture.process_with_new_worker().await, 1);
    assert_eq!(fixture.fake.accepted.lock().await.len(), 1);
    assert_eq!(fixture.receipt_state().await, "completed");
    assert_eq!(fixture.queue_count().await, 0);

    // A completed event must not reappear for either its prior device or a newly
    // registered device when the poller re-reads a duplicate source page.
    fixture.register(&fixture.services(), 2).await;
    fixture.enqueue().await;
    assert_eq!(fixture.process_with_new_worker().await, 0);
    assert_eq!(fixture.fake.attempts.lock().await.len(), 1);
    assert_eq!(fixture.queue_count().await, 0);
}

#[tokio::test]
async fn partial_device_acceptance_survives_worker_restart_and_retries_only_rejection() {
    let fixture = Fixture::new(2).await;
    let devices = fixture
        .services()
        .registry
        .list_active_registrations(RECIPIENT)
        .await
        .unwrap();
    let accepted = &devices[0].device_token;
    let rejected = &devices[1].device_token;
    fixture
        .fake
        .plan(rejected, &[Outcome::Rejected, Outcome::Accepted])
        .await;
    fixture.enqueue().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.device_state(accepted).await, "accepted");
    assert_eq!(fixture.device_state(rejected).await, "retry");
    assert_eq!(fixture.fake.accepted_for(accepted).await, 1);
    assert_eq!(fixture.fake.accepted_for(rejected).await, 0);

    fixture.enqueue().await;
    fixture.make_due().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.fake.attempts_for(accepted).await, 1);
    assert_eq!(fixture.fake.attempts_for(rejected).await, 2);
    assert_eq!(fixture.fake.accepted_for(rejected).await, 1);
    assert_eq!(fixture.receipt_state().await, "completed");
    assert_eq!(fixture.queue_count().await, 0);
}

#[tokio::test]
async fn accepted_but_lost_response_is_held_across_timeout_restart_and_source_replay() {
    let fixture = Fixture::new(1).await;
    let token = format!("{:064x}", 1);
    fixture
        .fake
        .plan(&token, &[Outcome::AcceptedWithoutResponse])
        .await;
    fixture.enqueue().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.fake.accepted_for(&token).await, 1);
    assert_eq!(fixture.device_state(&token).await, "held");
    assert_eq!(fixture.receipt_state().await, "held");
    fixture.enqueue().await;
    fixture.make_due().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.fake.attempts_for(&token).await, 1);
    assert_eq!(fixture.receipt_state().await, "held");
    assert_eq!(
        fixture.queue_count().await,
        1,
        "ambiguous work remains inspectable"
    );
}

async fn abort_worker_at_send_boundary(outcome: Outcome, expected_accepted: usize) {
    let fixture = Fixture::new(1).await;
    let token = format!("{:064x}", 1);
    fixture.fake.plan(&token, &[outcome]).await;
    fixture.enqueue().await;
    let services = fixture.services();
    let state = fixture.state(services.clone()).await;
    let task = tokio::spawn(async move { services.process_queue_batch(&state).await });
    tokio::time::timeout(Duration::from_secs(5), fixture.fake.entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        fixture.device_state(&token).await,
        "attempting",
        "send-start must commit before external I/O"
    );
    fixture.make_due().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.device_state(&token).await, "held");
    assert_eq!(fixture.receipt_state().await, "held");
    assert_eq!(fixture.fake.attempts_for(&token).await, 1);
    assert_eq!(fixture.fake.accepted_for(&token).await, expected_accepted);
}

#[tokio::test]
async fn worker_abort_after_acceptance_preserves_attempt_and_prevents_resend() {
    abort_worker_at_send_boundary(Outcome::AcceptedWithoutResponse, 1).await;
}

#[tokio::test]
async fn worker_abort_before_acceptance_is_explicitly_uncertain_not_silently_retried() {
    // The sender cannot distinguish this from acceptance with a lost response.
    // The guarantee deliberately trades a possible missed alert for no blind resend.
    abort_worker_at_send_boundary(Outcome::WaitingBeforeAcceptance, 0).await;
}

#[tokio::test]
async fn read_after_enqueue_suppresses_delivery_but_processed_watermark_does_not() {
    let fixture = Fixture::new(1).await;
    fixture.enqueue().await;
    sqlx::query("INSERT INTO chat_notified_watermarks (account_did, convo_id, last_rev, last_read_rev) VALUES ($1, $2, '0000000000009', '0000000000001')")
        .bind(RECIPIENT).bind(CONVO).execute(&fixture.pool).await.unwrap();
    fixture.process_with_new_worker().await;
    assert_eq!(
        fixture.fake.accepted.lock().await.len(),
        1,
        "processed progress must not be mistaken for read progress"
    );

    let mut second = fixture.event.clone();
    second.message_id = "fixture-message-2".to_string();
    second.log_rev = Some("0000000000004".to_string());
    enqueue_push(&fixture.pool, &second, 0).await.unwrap();
    sqlx::query("UPDATE chat_notified_watermarks SET last_read_rev = '0000000000005' WHERE account_did = $1 AND convo_id = $2")
        .bind(RECIPIENT).bind(CONVO).execute(&fixture.pool).await.unwrap();
    fixture.process_with_new_worker().await;
    assert_eq!(
        fixture.fake.attempts.lock().await.len(),
        1,
        "a read arriving after enqueue must suppress queued chat"
    );
    assert_eq!(fixture.queue_count().await, 0);
    enqueue_push(&fixture.pool, &second, 0).await.unwrap();
    assert_eq!(
        fixture.process_with_new_worker().await,
        0,
        "read suppression is terminal for this event"
    );
}

#[tokio::test]
async fn conversation_muted_after_partial_send_prevents_retry_and_unmute_replay() {
    let fixture = Fixture::new(2).await;
    let devices = fixture
        .services()
        .registry
        .list_active_registrations(RECIPIENT)
        .await
        .unwrap();
    let rejected = &devices[1].device_token;
    fixture.fake.plan(rejected, &[Outcome::Rejected]).await;
    fixture.enqueue().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.fake.attempts.lock().await.len(), 2);
    sqlx::query("INSERT INTO chat_muted_convos (account_did, convo_id) VALUES ($1, $2)")
        .bind(RECIPIENT)
        .bind(CONVO)
        .execute(&fixture.pool)
        .await
        .unwrap();
    fixture.make_due().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.fake.attempts.lock().await.len(), 2);
    assert_eq!(fixture.receipt_state().await, "completed");
    sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1 AND convo_id = $2")
        .bind(RECIPIENT)
        .bind(CONVO)
        .execute(&fixture.pool)
        .await
        .unwrap();
    fixture.enqueue().await;
    assert_eq!(fixture.process_with_new_worker().await, 0);
    assert_eq!(fixture.fake.attempts.lock().await.len(), 2);
}

#[tokio::test]
async fn two_workers_cannot_send_same_device_while_first_attempt_is_in_flight() {
    let fixture = Fixture::new(1).await;
    let token = format!("{:064x}", 1);
    fixture
        .fake
        .plan(&token, &[Outcome::AcceptedWithoutResponse])
        .await;
    fixture.enqueue().await;
    let services = fixture.services();
    let state = fixture.state(services.clone()).await;
    let first = tokio::spawn(async move { services.process_queue_batch(&state).await });
    tokio::time::timeout(Duration::from_secs(5), fixture.fake.entered.notified())
        .await
        .unwrap();
    assert_eq!(
        fixture.process_with_new_worker().await,
        0,
        "leased queue event cannot be claimed concurrently"
    );
    first.await.unwrap().unwrap();
    assert_eq!(fixture.fake.attempts_for(&token).await, 1);
    assert_eq!(fixture.receipt_state().await, "held");
}

#[tokio::test]
async fn held_device_does_not_starve_a_distinct_definite_rejection_retry() {
    let fixture = Fixture::new(2).await;
    let devices = fixture
        .services()
        .registry
        .list_active_registrations(RECIPIENT)
        .await
        .unwrap();
    let uncertain = &devices[0].device_token;
    let retryable = &devices[1].device_token;
    fixture
        .fake
        .plan(uncertain, &[Outcome::AcceptedWithoutResponse])
        .await;
    fixture
        .fake
        .plan(retryable, &[Outcome::Rejected, Outcome::Accepted])
        .await;
    fixture.enqueue().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.device_state(uncertain).await, "held");
    assert_eq!(fixture.device_state(retryable).await, "retry");
    fixture.make_due().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.fake.attempts_for(uncertain).await, 1);
    assert_eq!(fixture.fake.accepted_for(retryable).await, 1);
    assert_eq!(fixture.fake.attempts_for(retryable).await, 2);
    assert_eq!(fixture.receipt_state().await, "held");
}

#[tokio::test]
async fn accepted_response_with_receipt_write_failure_remains_uncertain_on_restart() {
    let fixture = Fixture::new(1).await;
    let token = format!("{:064x}", 1);
    sqlx::raw_sql(
        "CREATE FUNCTION reject_acceptance_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.state = 'accepted' THEN RAISE EXCEPTION 'fixture receipt persistence crash'; END IF; RETURN NEW; END; $$; \
         CREATE TRIGGER reject_acceptance_receipt BEFORE UPDATE ON push_device_deliveries \
         FOR EACH ROW EXECUTE FUNCTION reject_acceptance_receipt();"
    ).execute(&fixture.pool).await.unwrap();
    fixture.enqueue().await;
    let services = fixture.services();
    let state = fixture.state(services.clone()).await;
    assert!(services.process_queue_batch(&state).await.is_err());
    assert_eq!(fixture.fake.accepted_for(&token).await, 1);
    assert_eq!(fixture.device_state(&token).await, "attempting");
    sqlx::query("DROP TRIGGER reject_acceptance_receipt ON push_device_deliveries")
        .execute(&fixture.pool)
        .await
        .unwrap();
    fixture.make_due().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.device_state(&token).await, "held");
    assert_eq!(fixture.fake.attempts_for(&token).await, 1);
    assert_eq!(fixture.receipt_state().await, "held");
}

#[tokio::test]
async fn queue_ack_failure_after_persisted_acceptance_restarts_without_resending() {
    let fixture = Fixture::new(1).await;
    let token = format!("{:064x}", 1);
    sqlx::raw_sql(
        "CREATE FUNCTION reject_queue_ack() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'fixture queue acknowledgement crash'; END; $$; \
         CREATE TRIGGER reject_queue_ack BEFORE DELETE ON push_event_queue \
         FOR EACH ROW EXECUTE FUNCTION reject_queue_ack();",
    )
    .execute(&fixture.pool)
    .await
    .unwrap();
    fixture.enqueue().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.fake.accepted_for(&token).await, 1);
    assert_eq!(fixture.device_state(&token).await, "accepted");
    assert_eq!(fixture.queue_count().await, 1);
    sqlx::query("DROP TRIGGER reject_queue_ack ON push_event_queue")
        .execute(&fixture.pool)
        .await
        .unwrap();
    fixture.make_due().await;
    fixture.process_with_new_worker().await;
    assert_eq!(fixture.fake.attempts_for(&token).await, 1);
    assert_eq!(fixture.receipt_state().await, "completed");
    assert_eq!(fixture.queue_count().await, 0);
}

#[tokio::test]
async fn chat_mute_writer_waits_for_inflight_send_fence_before_returning() {
    let fixture = Fixture::new(1).await;
    let token = format!("{:064x}", 1);
    fixture
        .fake
        .plan(&token, &[Outcome::AcceptedWithoutResponse])
        .await;
    fixture.enqueue().await;
    let services = fixture.services();
    let state = fixture.state(services.clone()).await;
    let worker = tokio::spawn(async move { services.process_queue_batch(&state).await });
    tokio::time::timeout(Duration::from_secs(5), fixture.fake.entered.notified())
        .await
        .unwrap();
    let scheduler =
        catbird::services::chat_poll::scheduler::ChatPollScheduler::new(fixture.pool.clone());
    let mut mute =
        tokio::spawn(async move { scheduler.set_convo_muted(RECIPIENT, CONVO, true).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut mute)
            .await
            .is_err(),
        "a conversation mute must share the account lock held through the send fence"
    );
    worker.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(5), mute)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(fixture.fake.attempts_for(&token).await, 1);
}

#[tokio::test]
async fn legacy_chat_without_source_revision_is_held_without_sending_or_discarding() {
    let fixture = Fixture::new(1).await;
    let mut legacy = fixture.event.clone();
    legacy.log_rev = None;
    enqueue_push(&fixture.pool, &legacy, 0).await.unwrap();
    fixture.process_with_new_worker().await;
    assert!(fixture.fake.attempts.lock().await.is_empty());
    assert_eq!(fixture.receipt_state().await, "held");
    assert_eq!(fixture.queue_count().await, 1);
    let reason: String = sqlx::query_scalar("SELECT delivery_hold_reason FROM push_event_queue")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(reason, "chat_missing_log_rev");
    fixture.make_due().await;
    fixture.process_with_new_worker().await;
    assert!(fixture.fake.attempts.lock().await.is_empty());
}

#[tokio::test]
async fn queued_chat_obeys_log_mute_and_cached_mute_survives_log_unmute() {
    let fixture = Fixture::new(1).await;
    fixture.enqueue().await;
    sqlx::query("INSERT INTO chat_notified_watermarks (account_did, convo_id, last_rev, last_mute_rev, log_muted) VALUES ($1, $2, '0000000000005', '0000000000005', TRUE)")
        .bind(RECIPIENT).bind(CONVO).execute(&fixture.pool).await.unwrap();
    fixture.process_with_new_worker().await;
    assert!(fixture.fake.attempts.lock().await.is_empty());
    assert_eq!(fixture.queue_count().await, 0);
    catbird::services::chat_poll::scheduler::ChatPollScheduler::new(fixture.pool.clone())
        .set_convo_muted(RECIPIENT, CONVO, true)
        .await
        .unwrap();
    // Poller tests qualify monotonic log ordering. At the delivery boundary,
    // neither an older nor a newer unmute state may erase a cached client mute.
    for revision in ["0000000000004", "0000000000007"] {
        sqlx::query("UPDATE chat_notified_watermarks SET last_mute_rev = $1, log_muted = FALSE WHERE account_did = $2 AND convo_id = $3")
            .bind(revision).bind(RECIPIENT).bind(CONVO).execute(&fixture.pool).await.unwrap();
        let mut event = fixture.event.clone();
        event.message_id = format!("message-after-unmute-{revision}");
        event.log_rev = Some("0000000000008".to_string());
        enqueue_push(&fixture.pool, &event, 0).await.unwrap();
        fixture.process_with_new_worker().await;
        assert!(fixture.fake.attempts.lock().await.is_empty());
        assert_eq!(fixture.queue_count().await, 0);
        let muted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat_muted_convos WHERE account_did = $1 AND convo_id = $2)")
            .bind(RECIPIENT).bind(CONVO).fetch_one(&fixture.pool).await.unwrap();
        assert!(muted);
    }
}

#[tokio::test]
async fn migration_holds_legacy_queue_without_changing_payload_or_history() {
    let fixture = Fixture::new_at_schema(1, false).await;
    catbird::services::chat_poll::scheduler::ChatPollScheduler::new(fixture.pool.clone())
        .enroll_account(RECIPIENT, "fixture.test")
        .await
        .unwrap();
    let payload = json!({
        "recipientDid": RECIPIENT, "senderDid": SENDER,
        "convoId": CONVO, "messageId": fixture.event.message_id,
        "messageText": "", "sentAt": fixture.event.sent_at,
        "authGeneration": 1
    });
    sqlx::query("INSERT INTO push_event_queue (recipient_did, actor_did, notification_type, event_cid, event_path, event_record_json, event_timestamp, dedupe_key, auth_generation) VALUES ($1, $2, 'chat_message', 'fixture-message-1', 'chat.bsky.convo.getLog', $3, $4, $5, 1)")
        .bind(RECIPIENT).bind(SENDER).bind(&payload).bind(Utc::now().timestamp())
        .bind(fixture.event.dedupe_key()).execute(&fixture.pool).await.unwrap();
    sqlx::query("UPDATE chat_poll_state SET chat_cursor = 'preserved-old-cursor', primed_at = NOW() - INTERVAL '48 hours' WHERE account_did = $1")
        .bind(RECIPIENT).execute(&fixture.pool).await.unwrap();
    let before: (i64, serde_json::Value) =
        sqlx::query_as("SELECT id, event_record_json FROM push_event_queue")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    sqlx::raw_sql(include_str!(
        "../migrations/20261002000200_push_delivery_receipts.up.sql"
    ))
    .execute(&fixture.pool)
    .await
    .unwrap();
    let after: (i64, serde_json::Value) =
        sqlx::query_as("SELECT id, event_record_json FROM push_event_queue")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(before, after);
    let cursor: Option<String> =
        sqlx::query_scalar("SELECT chat_cursor FROM chat_poll_state WHERE account_did = $1")
            .bind(RECIPIENT)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(cursor.as_deref(), Some("preserved-old-cursor"));
    assert_eq!(fixture.receipt_state().await, "held");
    let reason: String = sqlx::query_scalar("SELECT delivery_hold_reason FROM push_event_queue")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(reason, "legacy_chat_missing_log_rev");
    assert_eq!(fixture.process_with_new_worker().await, 0);
    assert!(fixture.fake.attempts.lock().await.is_empty());
    assert_eq!(fixture.queue_count().await, 1);
}

/// Owns exactly one test child. Panic, assertion failure, or timeout all kill and
/// synchronously reap it; std::process::Child by itself does neither on Drop.
#[cfg(unix)]
struct OwnedChild {
    child: std::process::Child,
    reaped: bool,
}

#[cfg(unix)]
impl OwnedChild {
    fn spawn(fixture: &Fixture, mode: &str) -> Self {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "subprocess_delivery_worker_entrypoint",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("LITE_PUSH_SUBPROCESS_MODE", mode)
            .env("DATABASE_URL", &fixture.database_url)
            .env("REDIS_URL", &fixture.redis_url)
            .env("LITE_PUSH_DISPOSABLE", "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        eprintln!("LITE-001 child pid={} mode={mode}", child.id());
        Self {
            child,
            reaped: false,
        }
    }

    fn kill_and_reap(&mut self) -> std::process::ExitStatus {
        let _ = self.child.kill();
        let status = self.child.wait().unwrap();
        self.reaped = true;
        eprintln!("LITE-001 reaped pid={} status={status}", self.child.id());
        status
    }

    fn try_reap(&mut self) -> Option<std::process::ExitStatus> {
        let status = self.child.try_wait().unwrap();
        if status.is_some() {
            self.reaped = true;
        }
        status
    }

    fn output(&mut self) -> String {
        use std::io::Read;
        assert!(self.reaped);
        let mut text = String::new();
        if let Some(stdout) = &mut self.child.stdout {
            stdout.read_to_string(&mut text).unwrap();
        }
        if let Some(stderr) = &mut self.child.stderr {
            stderr.read_to_string(&mut text).unwrap();
        }
        text
    }
}

#[cfg(unix)]
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}

struct DurableFakeApns {
    pool: Pool<Postgres>,
    stall_after_acceptance: bool,
}

#[async_trait::async_trait]
impl ApnsSender for DurableFakeApns {
    async fn send(
        &self,
        registration: &RegistrationRow,
        _notification: &ApnsNotification,
    ) -> anyhow::Result<&'static str> {
        // This is a fake provider's receipt, committed separately from Nest's
        // delivery marker. It survives both test-worker process lifetimes.
        sqlx::query("INSERT INTO fixture_apns_acceptances(device_id) VALUES ($1)")
            .bind(registration.id)
            .execute(&self.pool)
            .await?;
        if self.stall_after_acceptance {
            std::future::pending::<()>().await;
        }
        Ok("sandbox")
    }
}

#[tokio::test]
#[ignore = "subprocess helper only; a direct include-ignored invocation is a no-op"]
async fn subprocess_delivery_worker_entrypoint() {
    let Ok(mode) = std::env::var("LITE_PUSH_SUBPROCESS_MODE") else {
        eprintln!("LITE-001 subprocess helper not invoked; no independent test receipt");
        return;
    };
    assert!(matches!(mode.as_str(), "accept-then-stall" | "recover"));
    let database_url = isolated_url("DATABASE_URL", "postgres", 5432);
    let redis_url = isolated_url("REDIS_URL", "redis", 6379);
    let parsed = url::Url::parse(&database_url).unwrap();
    assert!(parsed.path().starts_with("/lite_push_failure_"));
    let pool = Pool::<Postgres>::connect(&database_url).await.unwrap();
    let fake = Arc::new(DurableFakeApns {
        pool: pool.clone(),
        stall_after_acceptance: mode == "accept-then-stall",
    });
    let mut config = PushConfig::default();
    config.service_did = Some("did:web:push.fixture.test".to_string());
    config.apns.enabled = false;
    config.send_timeout_seconds = 60;
    let services = Arc::new(
        PushServices::new(pool.clone(), config)
            .unwrap()
            .with_apns_sender(fake),
    );
    let state = make_state(pool, &redis_url, services.clone()).await;
    assert_eq!(services.process_queue_batch(&state).await.unwrap(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn killed_worker_process_restarts_and_holds_without_second_provider_acceptance() {
    use std::os::unix::process::ExitStatusExt;

    let fixture = Fixture::new(1).await;
    let token = format!("{:064x}", 1);
    sqlx::query("CREATE TABLE fixture_apns_acceptances(id BIGSERIAL PRIMARY KEY, device_id UUID NOT NULL, accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
        .execute(&fixture.pool).await.unwrap();
    fixture.enqueue().await;
    let mut first = OwnedChild::spawn(&fixture, "accept-then-stall");
    let observed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fixture_apns_acceptances")
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
            if count > 0 {
                break count;
            }
            if first.try_reap().is_some() {
                break 0;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    // Clean up before any assertion, including timeouts and premature exits.
    let killed = first.kill_and_reap();
    let first_output = first.output();
    assert_eq!(
        observed.unwrap_or(0),
        1,
        "first child failed: {first_output}"
    );
    assert_eq!(
        killed.signal(),
        Some(9),
        "the first worker must terminate by SIGKILL"
    );
    assert_eq!(fixture.device_state(&token).await, "attempting");

    // Advance only this disposable fixture's lease to model its expiration;
    // the second OS process must use the durable intent, not parent memory.
    fixture.make_due().await;
    let mut second = OwnedChild::spawn(&fixture, "recover");
    let finished = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = second.try_reap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let status = match finished {
        Ok(status) => status,
        Err(_) => second.kill_and_reap(),
    };
    let second_output = second.output();
    assert!(status.success(), "restart child failed: {second_output}");
    eprintln!(
        "LITE-001 recovery child reaped pid={} status={status}",
        second.child.id()
    );
    let acceptances: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fixture_apns_acceptances")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(
        acceptances, 1,
        "restart must not obtain a second fake provider acceptance"
    );
    assert_eq!(fixture.device_state(&token).await, "held");
    assert_eq!(fixture.receipt_state().await, "held");
    assert_eq!(fixture.queue_count().await, 1);
}
