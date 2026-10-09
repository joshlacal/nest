//! Disposable Redis + SQL + authenticated mock PDS + fake APNs qualification.
//! No live provider credentials or external notification delivery are used.
//! Run only through the explicitly configured LITE_PUSH_DISPOSABLE runner.

use catbird::{
    config::{AppState, PushConfig},
    models::CatbirdSession,
    services::push::{
        apns::{ApnsNotification, ApnsSender},
        lock::acquire_account_lock,
        types::{PutPreferencesInput, RegisterPushInput, RegistrationRow},
        PushServices,
    },
};
use chrono::Utc;
use jacquard_oauth::authstore::ClientAuthStore;
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use wiremock::{
    matchers::{header, header_exists, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

#[path = "support/cleanup_auth.rs"]
mod cleanup_auth;

const DID: &str = "did:plc:threadrecipient";
const ACTOR: &str = "did:plc:threadactor";
const SUBJECT: &str = "at://did:plc:threadsubject/app.bsky.feed.post/subject";
const ROOT: &str = "at://did:plc:threadroot/app.bsky.feed.post/root";

struct TestDb {
    admin_pool: Pool<Postgres>,
    db_name: String,
    pool: Pool<Postgres>,
    auth_store: Arc<catbird::services::RedisAuthStore>,
}

impl TestDb {
    async fn new() -> Self {
        let base_url = cleanup_auth::disposable_url("DATABASE_URL", "postgres", 5432);

        let admin_pool = Pool::<Postgres>::connect(&base_url)
            .await
            .expect("Failed to connect to admin postgres");

        let db_name = format!("test_thread_evidence_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE \"{}\"", db_name))
            .execute(&admin_pool)
            .await
            .expect("Failed to create test database");

        let mut test_url = url::Url::parse(&base_url).unwrap();
        test_url.set_path(&db_name);

        let pool = Pool::<Postgres>::connect(test_url.as_str())
            .await
            .expect("Failed to connect to test database");

        // Run baseline migrations
        let migrations = [
            include_str!("../migrations/20260311000000_push_control_plane.up.sql"),
            include_str!("../migrations/20260311100000_push_auth_revoked_tracking.up.sql"),
            include_str!("../migrations/20260402000000_chat_poll.up.sql"),
            include_str!("../migrations/20260706000000_chat_watermarks.up.sql"),
            include_str!("../migrations/20260706000001_chat_poll_primed.up.sql"),
            include_str!("../migrations/20260707000000_apns_environment.up.sql"),
            include_str!("../migrations/20260827000000_actor_moderation_verdict.up.sql"),
            include_str!("../migrations/20260827000001_drop_moderation_mirror.up.sql"),
            include_str!("../migrations/20260830000001_moderation_cache_generation.up.sql"),
            include_str!("../migrations/20260830020000_push_accounts_session_fingerprint.up.sql"),
        ];

        for migration_sql in migrations {
            sqlx::raw_sql(migration_sql)
                .execute(&pool)
                .await
                .expect("Failed to run baseline migration");
        }
        Self {
            admin_pool,
            db_name,
            pool,
            auth_store: cleanup_auth::store().await,
        }
    }

    async fn run_hardening_migration(&self) {
        let sql = include_str!("../migrations/20260830000000_push_security_hardening.up.sql");
        sqlx::raw_sql(sql)
            .execute(&self.pool)
            .await
            .expect("Failed to run push security hardening migration");
        for sql in [
            include_str!("../migrations/20261002000100_chat_poll_catchup_hold.up.sql"),
            include_str!("../migrations/20261002000200_push_delivery_receipts.up.sql"),
            include_str!("../migrations/20261008000100_device_auth_session.up.sql"),
        ] {
            sqlx::raw_sql(sql)
                .execute(&self.pool)
                .await
                .expect("Failed to run LITE-001 push reliability migration");
        }
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let admin_pool = self.admin_pool.clone();
        let db_name = self.db_name.clone();
        tokio::spawn(async move {
            let _ = sqlx::query(&format!(
                "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
                db_name
            ))
            .execute(&admin_pool)
            .await;
        });
    }
}

async fn make_test_app_state(
    pool: Pool<Postgres>,
    services: Arc<PushServices>,
    auth_store: Arc<catbird::services::RedisAuthStore>,
) -> Arc<AppState> {
    let mut config = catbird::config::AppConfig {
        server: catbird::config::ServerConfig {
            host: "127.0.0.1".into(),
            port: 3000,
            admin_port: 3001,
            base_url: "http://127.0.0.1:3000".into(),
            allowed_origins: vec![],
            trusted_proxies: vec![],
        },
        redis: catbird::config::RedisConfig {
            url: "redis://127.0.0.1:6379".into(),
            key_prefix: "catbird:v2:session:".into(),
            session_ttl_seconds: 86400,
        },
        oauth: catbird::config::OAuthConfig {
            client_id: "http://127.0.0.1:3000/oauth/client-metadata.json".into(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".into(),
            redirect_uri: "http://127.0.0.1:3000/oauth/callback".into(),
            initial_scopes: vec!["atproto".into()],
            max_scopes: vec!["atproto".into()],
            scopes: vec!["atproto".into()],
        },
        mls: Default::default(),
        push: Default::default(),
        chat: Default::default(),
        circle: Default::default(),
    };
    let http_client = reqwest::Client::new();
    config.redis.url = cleanup_auth::disposable_url("REDIS_URL", "redis", 6379);
    config.redis.key_prefix = auth_store.key_prefix().into();
    let redis = auth_store.redis_connection();

    let metadata = jacquard_oauth::atproto::AtprotoClientMetadata::new(
        vec![
            jacquard_common::deps::fluent_uri::Uri::parse(config.oauth.redirect_uri.as_str())
                .unwrap()
                .to_owned(),
        ],
        jacquard_common::deps::fluent_uri::Uri::parse(config.oauth.client_id.as_str())
            .unwrap()
            .to_owned(),
        Some(
            jacquard_oauth::scopes::Scopes::new(smol_str::SmolStr::new_static("atproto")).unwrap(),
        ),
    );
    let resolver = jacquard_identity::JacquardResolver::new(
        catbird::services::HardenedHttpClient::new(http_client.clone()),
        jacquard_identity::resolver::ResolverOptions::default(),
    );
    let client = catbird::config::JacquardOAuthClient::new_from_resolver(
        auth_store.as_ref().clone(),
        resolver,
        jacquard_oauth::session::ClientData::new(None, metadata),
    );
    Arc::new(AppState {
        config: Arc::new(config),
        http_client: http_client.clone(),
        raw_http_client: http_client,
        redis,
        push_db: Some(pool),
        key_store: None,
        jacquard_client: Some(Arc::new(client)),
        catmos_jacquard_client: None,
        catmos_oauth_scopes: vec![],
        trusted_proxies: vec![],
        auth_store: Some(auth_store),
        push: Some(services),
        dpop_nonce_cache: Arc::new(catbird::services::DpopNonceCache::new()),
        session_encryption_key: Some(cleanup_auth::KEY),
        active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
        session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        session_index_readiness: Arc::new(tokio::sync::Notify::new()),
    })
}

#[derive(Default)]
struct FakeApns {
    sends: tokio::sync::Mutex<Vec<(RegistrationRow, ApnsNotification)>>,
}

#[async_trait::async_trait]
impl ApnsSender for FakeApns {
    async fn send(
        &self,
        registration: &RegistrationRow,
        notification: &ApnsNotification,
    ) -> anyhow::Result<&'static str> {
        self.sends
            .lock()
            .await
            .push((registration.clone(), notification.clone()));
        Ok("sandbox")
    }
}

struct Fixture {
    db: TestDb,
    provider: MockServer,
    services: Arc<PushServices>,
    state: Arc<AppState>,
    fake: Arc<FakeApns>,
    generation: i64,
    cutoff: i64,
}

impl Fixture {
    async fn new() -> Self {
        let db = TestDb::new().await;
        db.run_hardening_migration().await;
        let provider = MockServer::start().await;
        let now = Utc::now();
        let session = CatbirdSession {
            id: Uuid::new_v4(),
            did: DID.into(),
            handle: "thread.test".into(),
            pds_url: provider.uri(),
            access_token: "synthetic-fixture-access".into(),
            refresh_token: "synthetic-fixture-refresh".into(),
            scopes: vec!["atproto".into()],
            access_token_expires_at: now + chrono::Duration::hours(1),
            created_at: now,
            last_used_at: now,
            granted_scopes: vec!["atproto".into()],
        };
        let mut grant = cleanup_auth::grant(DID, &session.id.to_string(), &provider.uri());
        grant.token_set.expires_at = Some(
            jacquard_common::types::string::Datetime::try_from(
                session.access_token_expires_at.to_rfc3339(),
            )
            .unwrap(),
        );
        db.auth_store.upsert_session(grant).await.unwrap();
        let fake = Arc::new(FakeApns::default());
        let config = PushConfig {
            service_did: Some("did:web:push.catbird.blue".into()),
            ..Default::default()
        };
        let services = Arc::new(
            PushServices::new(db.pool.clone(), config)
                .unwrap()
                .with_auth_store(db.auth_store.clone())
                .with_apns_sender(fake.clone()),
        );
        services
            .registry
            .upsert_registration(
                &session,
                &RegisterPushInput {
                    service_did: "did:web:push.catbird.blue".into(),
                    token: "ed".repeat(32),
                    platform: "ios".into(),
                    app_id: "blue.catbird".into(),
                    age_restricted: Some(false),
                },
            )
            .await
            .unwrap();
        catbird::services::login_apply::ensure_local_preferences(
            &db.pool,
            &db.auth_store,
            &session,
        )
        .await
        .unwrap();
        let choice: PutPreferencesInput =
            serde_json::from_value(json!({"like":{"include":"all","push":true}})).unwrap();
        services
            .preferences
            .patch_authenticated(&db.auth_store, DID, &session.id.to_string(), Some(choice))
            .await
            .unwrap();
        let generation =
            sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did=$1")
                .bind(DID)
                .fetch_one(&db.pool)
                .await
                .unwrap();
        let cutoff = sqlx::query_scalar("SELECT (preferences_json->'_catbirdRestore'->>'consentSourceTime')::bigint FROM push_preferences WHERE account_did=$1")
            .bind(DID).fetch_one(&db.pool).await.unwrap();
        // A fresh synthetic profile verdict isolates the thread lookup. Any
        // accidental provider preference read/write remains an unmatched call.
        sqlx::query("INSERT INTO actor_moderation_verdict(recipient_did,actor_did,verdict,display_label,generation) SELECT account_did,$2,'{}'::jsonb,'Synthetic actor',moderation_generation FROM push_accounts WHERE account_did=$1")
            .bind(DID).bind(ACTOR).execute(&db.pool).await.unwrap();
        let state =
            make_test_app_state(db.pool.clone(), services.clone(), db.auth_store.clone()).await;
        Self {
            db,
            provider,
            services,
            state,
            fake,
            generation,
            cutoff,
        }
    }

    async fn enqueue(&self, key: &str) -> i64 {
        sqlx::query_scalar("INSERT INTO push_event_queue(recipient_did,actor_did,notification_type,event_cid,event_path,subject_uri,event_record_json,event_timestamp,dedupe_key,auth_generation) VALUES($1,$2,'like',$3,'app.bsky.feed.like/fixture',$4,$5,$6,$3,$7) RETURNING id")
            .bind(DID).bind(ACTOR).bind(key).bind(SUBJECT)
            .bind(json!({"$type":"app.bsky.feed.like","subject":{"uri":SUBJECT,"cid":"synthetic-subject-cid"}}))
            .bind(self.cutoff).bind(self.generation).fetch_one(&self.db.pool).await.unwrap()
    }

    async fn response(&self, viewer: Option<Value>) {
        self.provider.reset().await;
        let mut post = json!({"uri":SUBJECT,"record":{"$type":"app.bsky.feed.post","reply":{"root":{"uri":ROOT}}}});
        if let Some(viewer) = viewer {
            post["viewer"] = viewer;
        }
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.feed.getPosts"))
            .and(query_param("uris", SUBJECT))
            .and(header("authorization", "DPoP synthetic-fixture-access"))
            .and(header_exists("dpop"))
            .and(header("atproto-proxy", "did:web:api.bsky.app#bsky_appview"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"posts":[post]})))
            .expect(1)
            .mount(&self.provider)
            .await;
    }

    async fn assert_only_lookup(&self) {
        self.provider.verify().await;
        let requests = self.provider.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            1,
            "no provider preference reads/writes or refresh calls"
        );
        assert_eq!(requests[0].method.as_str(), "GET");
        assert_eq!(requests[0].url.path(), "/xrpc/app.bsky.feed.getPosts");
    }

    async fn process(&self) {
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(20),
                self.services.process_queue_batch(&self.state)
            )
            .await
            .unwrap()
            .unwrap(),
            1
        );
    }

    async fn assert_gone(&self, id: i64) {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM push_event_queue WHERE id=$1)")
                .bind(id)
                .fetch_one(&self.db.pool)
                .await
                .unwrap();
        assert!(!exists);
    }

    async fn assert_retry(&self, id: i64, reason: &str) {
        let row: (Option<String>, Option<String>, bool, bool) = sqlx::query_as("SELECT delivery_hold_reason,last_error,lease_token IS NULL,available_at>NOW() FROM push_event_queue WHERE id=$1")
            .bind(id).fetch_one(&self.db.pool).await.unwrap();
        assert_eq!(
            row.0, None,
            "unknown evidence must not become a permanent delivery hold"
        );
        assert_eq!(row.1.as_deref(), Some(reason));
        assert!(
            row.2 && row.3,
            "retry must release the lease and schedule backoff"
        );
    }

    // Waiting for a real blocked advisory-lock acquisition proves the decision
    // and its post-fetch generation check have completed. No guessed sleep is
    // used to place mutations between evidence resolution and the final fence.
    async fn await_final_lock_waiter(&self) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))")
                    .fetch_one(&self.db.pool).await.unwrap();
                if blocked { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("worker did not reach the final account lock");
    }
}

#[tokio::test]
async fn authenticated_post_evidence_sends_vetoes_and_retries_then_recovers() {
    let f = Fixture::new().await;
    f.response(Some(json!({"threadMuted":false}))).await;
    let id = f.enqueue("explicit-unmuted").await;
    f.process().await;
    f.assert_gone(id).await;
    assert_eq!(f.fake.sends.lock().await.len(), 1);
    f.assert_only_lookup().await;

    f.response(Some(json!({"threadMuted":true}))).await;
    let id = f.enqueue("explicit-muted").await;
    f.process().await;
    f.assert_gone(id).await;
    assert_eq!(
        f.fake.sends.lock().await.len(),
        1,
        "provider thread mute vetoes delivery"
    );
    f.assert_only_lookup().await;

    f.response(None).await;
    let id = f.enqueue("missing-viewer").await;
    f.process().await;
    f.assert_retry(id, "thread_evidence_viewer").await;
    assert_eq!(f.fake.sends.lock().await.len(), 1);
    f.assert_only_lookup().await;
    f.response(Some(json!({"threadMuted":false}))).await;
    sqlx::query("UPDATE push_event_queue SET available_at=NOW() WHERE id=$1")
        .bind(id)
        .execute(&f.db.pool)
        .await
        .unwrap();
    f.process().await;
    f.assert_gone(id).await;
    assert_eq!(
        f.fake.sends.lock().await.len(),
        2,
        "same row becomes deliverable once proof is available"
    );
    f.assert_only_lookup().await;

    f.response(Some(json!({}))).await;
    let id = f.enqueue("omitted-thread-muted").await;
    f.process().await;
    f.assert_retry(id, "thread_evidence_unknown_mute").await;
    assert_eq!(
        f.fake.sends.lock().await.len(),
        2,
        "missing optional flag is not false"
    );
    f.assert_only_lookup().await;
}

#[tokio::test]
async fn final_send_fence_rejects_changed_event_and_moderation_generation() {
    for change in [
        "event_identity",
        "moderation_generation",
        "auth_generation",
        "canonical_root_mute",
    ] {
        let f = Fixture::new().await;
        f.response(Some(json!({"threadMuted":false}))).await;
        let id = f.enqueue(change).await;
        let mut lock = f.db.pool.begin().await.unwrap();
        acquire_account_lock(&mut lock, DID).await.unwrap();
        let (services, state) = (f.services.clone(), f.state.clone());
        let worker = tokio::spawn(async move { services.process_queue_batch(&state).await });
        f.await_final_lock_waiter().await;
        match change {
            "event_identity" => {
                sqlx::query(
                    "UPDATE push_event_queue SET event_cid='changed-after-observation' WHERE id=$1",
                )
                .bind(id)
                .execute(&mut *lock)
                .await
                .unwrap();
            }
            "moderation_generation" => {
                sqlx::query("UPDATE push_accounts SET moderation_generation=moderation_generation+1 WHERE account_did=$1").bind(DID).execute(&mut *lock).await.unwrap();
            }
            "auth_generation" => {
                sqlx::query("UPDATE push_accounts SET auth_generation=auth_generation+1 WHERE account_did=$1").bind(DID).execute(&mut *lock).await.unwrap();
            }
            "canonical_root_mute" => {
                // The like producer has no thread_root_uri; only the resolved
                // original post supplies this canonical root for the final veto.
                sqlx::query("INSERT INTO thread_mutes(user_did,thread_root_uri) VALUES($1,$2)")
                    .bind(DID)
                    .bind(ROOT)
                    .execute(&mut *lock)
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        lock.commit().await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(15), worker)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            1
        );
        assert!(
            f.fake.sends.lock().await.is_empty(),
            "final fence must veto {change}"
        );
        if matches!(change, "event_identity" | "moderation_generation") {
            f.assert_retry(id, "upstream_thread_mute_evidence_expired")
                .await;
        } else {
            f.assert_gone(id).await;
        }
        f.assert_only_lookup().await;
    }
}

#[tokio::test]
async fn expired_thread_proof_retries_at_final_send_fence() {
    let f = Fixture::new().await;
    f.response(Some(json!({"threadMuted":false}))).await;
    let id = f.enqueue("expired-evidence").await;
    let mut lock = f.db.pool.begin().await.unwrap();
    acquire_account_lock(&mut lock, DID).await.unwrap();
    let (services, state) = (f.services.clone(), f.state.clone());
    let worker = tokio::spawn(async move { services.process_queue_batch(&state).await });
    f.await_final_lock_waiter().await;
    // std::time::Instant intentionally uses real elapsed time. The real queue
    // heartbeat must keep the lease alive while the evidence's 30s TTL expires.
    tokio::time::sleep(Duration::from_secs(31)).await;
    lock.commit().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(15), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        1
    );
    assert!(f.fake.sends.lock().await.is_empty());
    f.assert_retry(id, "upstream_thread_mute_evidence_expired")
        .await;
    f.assert_only_lookup().await;
}
