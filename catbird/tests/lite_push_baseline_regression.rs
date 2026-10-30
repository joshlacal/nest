//! Identical before/after worker regression. Uses only baseline public APIs and
//! direct queue SQL; intentionally requires corrected behavior on the old source.
//! All APNs sends are fake and both stores must be explicitly disposable/local.

use std::collections::{HashMap, VecDeque};
use std::sync::{atomic::AtomicBool, Arc};

use catbird::config::{AppConfig, AppState, PushConfig};
use catbird::services::push::{
    apns::{ApnsNotification, ApnsSender},
    types::RegistrationRow,
    PushServices,
};
use serde_json::json;
use sqlx::{Pool, Postgres};
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

#[path = "support/cleanup_auth.rs"]
mod cleanup_auth;

const DID: &str = "did:plc:baselinecontrol";
const ACTOR: &str = "did:plc:baselineactor";

#[derive(Clone, Copy)]
enum Outcome {
    Accepted,
    Rejected503,
    AcceptedResponseLost,
}

#[derive(Default)]
struct FakeApns {
    plan: Mutex<HashMap<String, VecDeque<Outcome>>>,
    attempts: Mutex<HashMap<String, usize>>,
    accepted: Mutex<HashMap<String, usize>>,
}

#[async_trait::async_trait]
impl ApnsSender for FakeApns {
    async fn send(
        &self,
        device: &RegistrationRow,
        _: &ApnsNotification,
    ) -> anyhow::Result<&'static str> {
        *self
            .attempts
            .lock()
            .await
            .entry(device.device_token.clone())
            .or_default() += 1;
        let outcome = self
            .plan
            .lock()
            .await
            .get_mut(&device.device_token)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Outcome::Accepted);
        if matches!(outcome, Outcome::Rejected503) {
            return Err(a2::Error::ResponseError(a2::Response {
                error: Some(a2::ErrorBody {
                    reason: a2::ErrorReason::ServiceUnavailable,
                    timestamp: None,
                }),
                apns_id: None,
                code: 503,
            })
            .into());
        }
        *self
            .accepted
            .lock()
            .await
            .entry(device.device_token.clone())
            .or_default() += 1;
        if matches!(outcome, Outcome::AcceptedResponseLost) {
            return std::future::pending().await;
        }
        Ok("sandbox")
    }
}

fn local_url(name: &str, scheme: &str, disallowed_port: u16) -> String {
    assert_eq!(std::env::var("LITE_PUSH_DISPOSABLE").as_deref(), Ok("1"));
    let value = std::env::var(name).expect("explicit disposable local store URL required");
    let parsed = url::Url::parse(&value).unwrap();
    assert_eq!(parsed.scheme(), scheme);
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_ne!(
        parsed.port().expect("explicit nondefault port required"),
        disallowed_port
    );
    value
}

struct Fixture {
    pool: Pool<Postgres>,
    fake: Arc<FakeApns>,
    redis_url: String,
    auth_store: Arc<catbird::services::RedisAuthStore>,
}

impl Fixture {
    async fn new(devices: usize) -> Self {
        let db_url = local_url("DATABASE_URL", "postgres", 5432);
        let redis_url = local_url("REDIS_URL", "redis", 6379);
        let admin = Pool::<Postgres>::connect(&db_url).await.unwrap();
        let name = format!("lite_push_baseline_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&db_url).unwrap();
        url.set_path(&name);
        let pool = Pool::<Postgres>::connect(url.as_str()).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        admin.close().await;
        eprintln!("Baseline regression fixture retained in disposable cluster: {name}");
        let auth_store = cleanup_auth::store().await;
        let bearer = Uuid::new_v4().to_string();
        use jacquard_oauth::authstore::ClientAuthStore;
        auth_store
            .upsert_session(cleanup_auth::grant(DID, &bearer, "http://127.0.0.1:9"))
            .await
            .unwrap();
        let generation = auth_store.next_auth_generation().await.unwrap();
        let fingerprint = catbird::services::push::registry::session_fingerprint(&bearer);
        sqlx::query("INSERT INTO push_accounts(account_did,session_id,session_fingerprint,pds_url,auth_generation) VALUES($1,$2,$2,'http://127.0.0.1:9',$3)")
            .bind(DID).bind(fingerprint).bind(generation).execute(&pool).await.unwrap();
        // Explicit complete preference input for this delivery fixture.
        sqlx::query("INSERT INTO push_preferences(account_did,preferences_json) VALUES($1,$2)")
            .bind(DID)
            .bind(
                serde_json::to_value(
                    catbird::services::push::types::PushPreferencesDocument::default(),
                )
                .unwrap(),
            )
            .execute(&pool)
            .await
            .unwrap();
        for index in 1..=devices {
            sqlx::query("INSERT INTO user_devices(did,device_token,platform,app_id,is_active,apns_environment,updated_at) VALUES($1,$2,'ios','blue.catbird.fixture',true,'sandbox',NOW() - make_interval(secs => $3))")
                .bind(DID).bind(format!("device-{index}")).bind(index as f64)
                .execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO actor_moderation_verdict(recipient_did,actor_did,verdict,generation) VALUES($1,$2,'{}',1)")
            .bind(DID).bind(ACTOR).execute(&pool).await.unwrap();
        let event = json!({"recipientDid":DID,"senderDid":ACTOR,"convoId":"fixture-convo","messageId":"fixture-message","messageText":"","sentAt":chrono::Utc::now().to_rfc3339(),"authGeneration":generation,"logRev":"0000003"});
        sqlx::query("INSERT INTO push_event_queue(recipient_did,actor_did,notification_type,event_cid,event_path,event_record_json,event_timestamp,dedupe_key,auth_generation) VALUES($1,$2,'chat_message','fixture-message','chat.bsky.convo.getLog',$3,$4,'baseline-fixture-event',$5)")
            .bind(DID).bind(ACTOR).bind(event).bind(chrono::Utc::now().timestamp()).bind(generation)
            .execute(&pool).await.unwrap();
        Self {
            pool,
            fake: Arc::new(FakeApns::default()),
            redis_url,
            auth_store,
        }
    }

    async fn process(&self) {
        let mut push_config = PushConfig::default();
        push_config.service_did = Some("did:web:push.fixture.test".to_string());
        push_config.apns.enabled = false;
        push_config.send_timeout_seconds = 1;
        let services = Arc::new(
            PushServices::new(self.pool.clone(), push_config)
                .unwrap()
                .with_auth_store(self.auth_store.clone())
                .with_apns_sender(self.fake.clone()),
        );
        let mut config = AppConfig::test_default();
        config.redis.url = self.redis_url.clone();
        config.redis.key_prefix = self.auth_store.key_prefix().into();
        let redis = redis::aio::ConnectionManager::new(
            redis::Client::open(self.redis_url.as_str()).unwrap(),
        )
        .await
        .unwrap();
        let state = Arc::new(AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: reqwest::Client::new(),
            redis,
            push_db: Some(self.pool.clone()),
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: Some(self.auth_store.clone()),
            push: Some(services.clone()),
            dpop_nonce_cache: Arc::new(catbird::services::DpopNonceCache::new()),
            session_encryption_key: Some(cleanup_auth::KEY),
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(AtomicBool::new(true)),
            session_index_readiness: Arc::new(Notify::new()),
        });
        services.process_queue_batch(&state).await.unwrap();
    }

    async fn due_again(&self) {
        sqlx::query(
            "UPDATE push_event_queue SET available_at=NOW(),leased_until=NOW()-INTERVAL '1 second'",
        )
        .execute(&self.pool)
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn accepted_device_is_not_resent_after_other_device_rejection() {
    let fixture = Fixture::new(2).await;
    fixture.fake.plan.lock().await.insert(
        "device-2".into(),
        [Outcome::Rejected503, Outcome::Accepted].into(),
    );
    fixture.process().await;
    assert_eq!(
        fixture.fake.accepted.lock().await.get("device-1"),
        Some(&1),
        "first device must reach APNs acceptance before retry scenario"
    );
    fixture.due_again().await;
    fixture.process().await;
    let attempts = fixture.fake.attempts.lock().await;
    assert_eq!(
        attempts.get("device-2"),
        Some(&2),
        "definite rejection must still retry"
    );
    assert_eq!(
        attempts.get("device-1"),
        Some(&1),
        "accepted device must not receive the event again"
    );
}

#[tokio::test]
async fn accepted_request_with_lost_response_is_not_blindly_resent() {
    let fixture = Fixture::new(1).await;
    fixture
        .fake
        .plan
        .lock()
        .await
        .insert("device-1".into(), [Outcome::AcceptedResponseLost].into());
    fixture.process().await;
    assert_eq!(fixture.fake.accepted.lock().await.get("device-1"), Some(&1));
    fixture.due_again().await;
    fixture.process().await;
    assert_eq!(
        fixture.fake.attempts.lock().await.get("device-1"),
        Some(&1),
        "timeout does not prove APNs rejected an accepted push"
    );
}

// These source-age cases extend the two historical replay controls above.
#[tokio::test]
async fn old_social_source_event_in_fresh_queue_never_sends() {
    for kind in ["like", "repost", "follow", "mention"] {
        let fixture = Fixture::new(1).await;
        sqlx::query("UPDATE push_event_queue SET notification_type=$1, event_timestamp=$2, created_at=NOW()")
            .bind(kind).bind(chrono::Utc::now().timestamp() - 2 * 86400)
            .execute(&fixture.pool).await.unwrap();
        fixture.process().await;
        assert!(
            fixture.fake.attempts.lock().await.is_empty(),
            "old {kind} reached APNs"
        );
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM push_event_queue")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert_eq!(left, 0, "old {kind} must leave the ready queue");
    }
}

#[tokio::test]
async fn fresh_social_source_event_keeps_normal_delivery() {
    let fixture = Fixture::new(1).await;
    sqlx::query("UPDATE push_event_queue SET notification_type='like', event_timestamp=$1, created_at=NOW()")
        .bind(chrono::Utc::now().timestamp()).execute(&fixture.pool).await.unwrap();
    fixture.process().await;
    assert_eq!(fixture.fake.accepted.lock().await.get("device-1"), Some(&1));
}
