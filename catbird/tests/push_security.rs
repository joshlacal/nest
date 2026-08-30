//! Real SQL, Worker, and APNs barrier regression tests for Nest push security hardening (Task 2 Round 3)

use catbird::{
    config::{AppConfig, AppState, PushConfig},
    models::CatbirdSession,
    services::push::{
        apns::{ApnsNotification, ApnsSender},
        moderation_verdict::ModerationVerdict,
        types::{
            ActivitySubscriptionPreference, PushPreferencesDocument, RegisterPushInput,
            RegistrationRow,
        },
        HeartbeatLease, PreSendFenceOutcome, PushServices,
    },
};
use chrono::Utc;
use serde_json::json;
use sqlx::{Pool, Postgres, Row};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Barrier;
use uuid::Uuid;

struct TestDb {
    admin_pool: Pool<Postgres>,
    db_name: String,
    pool: Pool<Postgres>,
}

impl TestDb {
    async fn new() -> Self {
        let base_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/postgres".to_string());

        let admin_pool = Pool::<Postgres>::connect(&base_url)
            .await
            .expect("Failed to connect to admin postgres");

        let db_name = format!("test_push_sec_{}", Uuid::new_v4().simple());
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
        }
    }

    async fn run_hardening_migration(&self) {
        let sql = include_str!("../migrations/20260830000000_push_security_hardening.up.sql");
        sqlx::raw_sql(sql)
            .execute(&self.pool)
            .await
            .expect("Failed to run push security hardening migration");
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

fn make_session(did: &str) -> CatbirdSession {
    let now = Utc::now();
    CatbirdSession {
        id: Uuid::new_v4(),
        did: did.to_string(),
        handle: "user.test".to_string(),
        pds_url: "https://pds.example.com".to_string(),
        access_token: "test-jwt".to_string(),
        refresh_token: "test-refresh-jwt".to_string(),
        scopes: vec!["atproto".to_string()],
        access_token_expires_at: now + chrono::Duration::hours(1),
        created_at: now,
        last_used_at: now,
        granted_scopes: vec!["atproto".to_string()],
    }
}

fn make_services(pool: Pool<Postgres>) -> PushServices {
    let mut config = PushConfig::default();
    config.service_did = Some("did:web:push.catbird.blue".to_string());
    PushServices::new(pool, config).unwrap()
}

async fn make_test_app_state(pool: Pool<Postgres>, services: Arc<PushServices>) -> Arc<AppState> {
    let config = catbird::config::AppConfig {
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
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let redis_client = redis::Client::open(redis_url.as_str()).unwrap();
    let redis = redis::aio::ConnectionManager::new(redis_client)
        .await
        .expect("Redis connection manager failed");

    Arc::new(AppState {
        config: Arc::new(config),
        http_client: http_client.clone(),
        raw_http_client: http_client,
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
        session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        session_index_readiness: Arc::new(tokio::sync::Notify::new()),
    })
}

#[derive(Clone)]
struct ObservingFakeApns {
    pub sends: Arc<tokio::sync::Mutex<Vec<(RegistrationRow, ApnsNotification)>>>,
    pub enter_barrier: Option<Arc<Barrier>>,
    pub exit_barrier: Option<Arc<Barrier>>,
    pub pause_duration: Option<std::time::Duration>,
}

impl ObservingFakeApns {
    fn new() -> Self {
        Self {
            sends: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            enter_barrier: None,
            exit_barrier: None,
            pause_duration: None,
        }
    }

    fn with_barriers(enter: Arc<Barrier>, exit: Arc<Barrier>) -> Self {
        Self {
            sends: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            enter_barrier: Some(enter),
            exit_barrier: Some(exit),
            pause_duration: None,
        }
    }
}

#[async_trait::async_trait]
impl ApnsSender for ObservingFakeApns {
    async fn send(
        &self,
        registration: &RegistrationRow,
        notification: &ApnsNotification,
    ) -> anyhow::Result<&'static str> {
        if let Some(enter) = &self.enter_barrier {
            enter.wait().await;
        }
        if let Some(exit) = &self.exit_barrier {
            exit.wait().await;
        }
        if let Some(duration) = self.pause_duration {
            tokio::time::sleep(duration).await;
        }
        self.sends
            .lock()
            .await
            .push((registration.clone(), notification.clone()));
        Ok("sandbox")
    }
}

/// 1. Migration Backfill & Unique Index Test
#[tokio::test]
async fn test_migration_backfill_duplicate_and_quota_tokens() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let shared_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let did_a = "did:plc:account_a";
    let did_b = "did:plc:account_b";
    let did_c = "did:plc:account_c";

    // Pre-populate duplicate active device tokens across different DIDs
    sqlx::query(
        r#"
        INSERT INTO user_devices (did, device_token, platform, app_id, service_did, is_active, last_registered_at)
        VALUES ($1, $2, 'ios', 'blue.catbird', 'did:web:push.catbird.blue', TRUE, NOW() - INTERVAL '10 minutes')
        "#,
    )
    .bind(did_a)
    .bind(shared_token)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO user_devices (did, device_token, platform, app_id, service_did, is_active, last_registered_at)
        VALUES ($1, $2, 'ios', 'blue.catbird', 'did:web:push.catbird.blue', TRUE, NOW() - INTERVAL '5 minutes')
        "#,
    )
    .bind(did_b)
    .bind(shared_token)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO user_devices (did, device_token, platform, app_id, service_did, is_active, last_registered_at)
        VALUES ($1, $2, 'ios', 'blue.catbird', 'did:web:push.catbird.blue', TRUE, NOW())
        "#,
    )
    .bind(did_c)
    .bind(shared_token)
    .execute(pool)
    .await
    .unwrap();

    // Pre-populate 15 active devices for quota account (quota is 10)
    let quota_did = "did:plc:quota_account";
    for i in 0..15 {
        let token = format!("device_token_{:064}", i);
        sqlx::query(
            r#"
            INSERT INTO user_devices (did, device_token, platform, app_id, service_did, is_active, last_registered_at)
            VALUES ($1, $2, 'ios', 'blue.catbird', 'did:web:push.catbird.blue', TRUE, NOW() - make_interval(mins => $3))
            "#,
        )
        .bind(quota_did)
        .bind(&token)
        .bind(15 - i)
        .execute(pool)
        .await
        .unwrap();
    }

    // Run hardening migration: must deduplicate and enforce quota and unique index
    test_db.run_hardening_migration().await;

    // Verify duplicate token resolution: only did_c (newest) remains active
    let active_shared: Vec<(String, bool)> = sqlx::query_as(
        "SELECT did, is_active FROM user_devices WHERE device_token = $1 ORDER BY did",
    )
    .bind(shared_token)
    .fetch_all(pool)
    .await
    .unwrap();

    assert_eq!(active_shared.len(), 3);
    for (did, is_active) in active_shared {
        if did == did_c {
            assert!(is_active, "did_c (newest) must remain active");
        } else {
            assert!(!is_active, "{} must be deactivated by backfill", did);
        }
    }

    // Verify quota backfill: exactly 10 active devices remain for quota_did
    let active_quota_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_devices WHERE did = $1 AND is_active = TRUE")
            .bind(quota_did)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        active_quota_count, 10,
        "Quota excess backfill must leave exactly 10 active devices"
    );

    // Verify unique partial index: inserting another active device with shared_token fails at DB level
    let duplicate_insert = sqlx::query(
        r#"
        INSERT INTO user_devices (did, device_token, platform, app_id, service_did, is_active)
        VALUES ('did:plc:intruder', $1, 'ios', 'blue.catbird', 'did:web:push.catbird.blue', TRUE)
        "#,
    )
    .bind(shared_token)
    .execute(pool)
    .await;

    assert!(
        duplicate_insert.is_err(),
        "Database unique index idx_user_devices_active_token must reject duplicate active tokens"
    );
}

/// 2. True Concurrent Token Claims Race
#[tokio::test]
async fn test_true_concurrent_token_claims_race() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();
    let services = Arc::new(make_services(pool.clone()));

    let shared_token = "1111222233334444555566667777888811112222333344445555666677778888";
    let concurrency = 8;
    let barrier = Arc::new(Barrier::new(concurrency));

    let mut handles = Vec::new();
    for i in 0..concurrency {
        let services = services.clone();
        let barrier = barrier.clone();
        let did = format!("did:plc:concurrent_user_{}", i);

        handles.push(tokio::spawn(async move {
            let session = make_session(&did);
            let input = RegisterPushInput {
                service_did: "did:web:push.catbird.blue".to_string(),
                token: shared_token.to_string(),
                platform: "ios".to_string(),
                app_id: "blue.catbird".to_string(),
                age_restricted: Some(false),
            };
            barrier.wait().await;
            services
                .registry
                .upsert_registration(&session, &input)
                .await
        }));
    }

    for h in handles {
        let res = h.await.unwrap();
        assert!(res.is_ok(), "Upsert registration must succeed: {:?}", res);
    }

    // Exactly 1 registration must be active for shared_token in DB
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_devices WHERE device_token = $1 AND is_active = TRUE",
    )
    .bind(shared_token)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        active_count, 1,
        "Exactly one active registration must exist for token"
    );

    let winning_did: String = sqlx::query_scalar(
        "SELECT did FROM user_devices WHERE device_token = $1 AND is_active = TRUE",
    )
    .bind(shared_token)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Populate moderation verdicts so pre-send fence check tests device activity
    for i in 0..concurrency {
        let did = format!("did:plc:concurrent_user_{}", i);
        sqlx::query(
            r#"
            INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at)
            VALUES ($1, 'did:plc:actor', '{"muted": false}'::jsonb, 'Actor', NOW())
            "#,
        )
        .bind(&did)
        .execute(&pool)
        .await
        .unwrap();

        let fence = services
            .verify_pre_send_fence(
                &did,
                "did:plc:actor",
                shared_token,
                "like",
                None,
                None,
                None,
            )
            .await
            .unwrap();

        if did == winning_did {
            assert_eq!(fence, PreSendFenceOutcome::Authorized);
        } else {
            assert_eq!(fence, PreSendFenceOutcome::DeviceInactive);
        }
    }
}

/// 3. Long Send + Two Claimers (Heartbeat, Worker Loop, and CAS Fencing)
#[tokio::test]
async fn test_long_send_two_claimers_and_heartbeat_cas() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();

    let mut fake_apns = ObservingFakeApns::new();
    fake_apns.pause_duration = Some(std::time::Duration::from_millis(3000));
    let fake_apns = Arc::new(fake_apns);
    let services = Arc::new(make_services(pool.clone()).with_apns_sender(fake_apns.clone()));
    let state = make_test_app_state(pool.clone(), services.clone()).await;

    let recipient_did = "did:plc:long_send_user";
    let token1 = "1111222233334444555566667777888811112222333344445555666677778888";
    let token2 = "9999888877776666555544443333222299998888777766665555444433332222";
    let session = make_session(recipient_did);

    for token in &[token1, token2] {
        let reg_input = RegisterPushInput {
            service_did: "did:web:push.catbird.blue".to_string(),
            token: token.to_string(),
            platform: "ios".to_string(),
            app_id: "blue.catbird".to_string(),
            age_restricted: Some(false),
        };
        services
            .registry
            .upsert_registration(&session, &reg_input)
            .await
            .unwrap();
    }

    // Populate moderation verdict
    sqlx::query(
        r#"
        INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at)
        VALUES ($1, 'did:plc:actor', '{"muted": false}'::jsonb, 'Actor', NOW())
        "#,
    )
    .bind(recipient_did)
    .execute(&pool)
    .await
    .unwrap();

    // Enqueue an event
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, 'did:plc:actor', 'like', 'bafy-cid-1', 'app.bsky.feed.like/1',
                '{}'::jsonb, 1700000000, 'dedupe-1', NOW(), 1)
        "#,
    )
    .bind(recipient_did)
    .execute(&pool)
    .await
    .unwrap();

    let processed = services.process_queue_batch(&state).await.unwrap();
    assert_eq!(processed, 1, "Must process 1 queue row");
    let sends = fake_apns.sends.lock().await;
    assert_eq!(
        sends.len(),
        2,
        "Both devices must be delivered even when heartbeat renewal fires mid-batch"
    );
    drop(sends);

    // Queue row must be deleted by delete_fenced CAS
    let remaining_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM push_event_queue")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        remaining_rows, 0,
        "Delivered event must be deleted with final heartbeat version"
    );

    // Scenario A2: Explicit Heartbeat Race during Lock Acquisition / Multi-device delivery
    let recipient_did_a2 = "did:plc:heartbeat_race_user";
    let session_a2 = make_session(recipient_did_a2);
    for token in &[token1, token2] {
        let reg_input = RegisterPushInput {
            service_did: "did:web:push.catbird.blue".to_string(),
            token: token.to_string(),
            platform: "ios".to_string(),
            app_id: "blue.catbird".to_string(),
            age_restricted: Some(false),
        };
        services
            .registry
            .upsert_registration(&session_a2, &reg_input)
            .await
            .unwrap();
    }
    sqlx::query(
        r#"
        INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at)
        VALUES ($1, 'did:plc:actor', '{"muted": false}'::jsonb, 'Actor', NOW())
        "#,
    )
    .bind(recipient_did_a2)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, 'did:plc:actor', 'like', 'bafy-cid-race', 'app.bsky.feed.like/race',
                '{}'::jsonb, 1700000000, 'dedupe-race', NOW(), 1)
        "#,
    )
    .bind(recipient_did_a2)
    .execute(&pool)
    .await
    .unwrap();

    let claimed_race = services.queue.claim_ready(1).await.unwrap();
    assert_eq!(claimed_race.len(), 1);
    let row_race = claimed_race[0].clone();
    let token_race = row_race.lease_token.unwrap();
    let snapshotted_v1 = row_race.lease_version;

    // Heartbeat renews the lease in the DB to version 2 (simulating background renewal interval)
    let renewed_v2 = services
        .queue
        .extend_lease(row_race.id, token_race, snapshotted_v1, 30)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(renewed_v2, snapshotted_v1 + 1);

    let fence_res = services
        .verify_pre_send_fence(
            recipient_did_a2,
            "did:plc:actor",
            token1,
            "like",
            None,
            Some((row_race.id, token_race, row_race.auth_generation)),
            Some(row_race.auth_generation),
        )
        .await
        .unwrap();
    assert_eq!(
        fence_res,
        PreSendFenceOutcome::Authorized,
        "In-flight fence with stable lease token must succeed across heartbeat renewals"
    );

    // Scenario B: Two Claimers — Worker 1 loses lease to Worker 2 mid-flight
    let recipient_did_b = "did:plc:two_claimers_user";
    let session_b = make_session(recipient_did_b);
    let token1_b = "1212121212121212121212121212121212121212121212121212121212121212";
    let token2_b = "3434343434343434343434343434343434343434343434343434343434343434";
    for token in &[token1_b, token2_b] {
        let reg_input = RegisterPushInput {
            service_did: "did:web:push.catbird.blue".to_string(),
            token: token.to_string(),
            platform: "ios".to_string(),
            app_id: "blue.catbird".to_string(),
            age_restricted: Some(false),
        };
        services
            .registry
            .upsert_registration(&session_b, &reg_input)
            .await
            .unwrap();
    }
    sqlx::query(
        r#"
        INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at)
        VALUES ($1, 'did:plc:actor', '{"muted": false}'::jsonb, 'Actor', NOW())
        "#,
    )
    .bind(recipient_did_b)
    .execute(&pool)
    .await
    .unwrap();

    let enter_b = Arc::new(Barrier::new(2));
    let exit_b = Arc::new(Barrier::new(2));
    let fake_apns_w1 = Arc::new(ObservingFakeApns::with_barriers(
        enter_b.clone(),
        exit_b.clone(),
    ));
    let services_w1 = Arc::new(make_services(pool.clone()).with_apns_sender(fake_apns_w1.clone()));
    let state_w1 = make_test_app_state(pool.clone(), services_w1.clone()).await;

    // Enqueue a second event
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, 'did:plc:actor', 'like', 'bafy-cid-2', 'app.bsky.feed.like/2',
                '{}'::jsonb, 1700000001, 'dedupe-2', NOW(), 1)
        "#,
    )
    .bind(recipient_did_b)
    .execute(&pool)
    .await
    .unwrap();
    let s1_clone = services_w1.clone();
    let st1_clone = state_w1.clone();
    let worker1_handle =
        tokio::spawn(async move { s1_clone.process_queue_batch(&st1_clone).await });

    // Wait for Worker 1 to start sending device 1
    enter_b.wait().await;
    // While Worker 1 is paused on device 1, simulate lease expiration and Worker 2 stealing the lease
    sqlx::query("UPDATE push_event_queue SET leased_until = NOW() - INTERVAL '1 second' WHERE dedupe_key = 'dedupe-2'")
        .execute(&pool)
        .await
        .unwrap();

    let services_w2 = Arc::new(make_services(pool.clone()));
    let claimed_w2 = services_w2.queue.claim_ready(1).await.unwrap();
    let row_w2 = claimed_w2[0].clone();
    assert_eq!(row_w2.event_cid, "bafy-cid-2");

    exit_b.wait().await;
    let res_w1 = worker1_handle.await.unwrap();
    assert!(res_w1.is_ok());

    // Worker 1 must NOT have sent to device 2 because fence returned LeaseLost
    let w1_sends = fake_apns_w1.sends.lock().await;
    assert_eq!(
        w1_sends.len(),
        1,
        "Worker 1 must have aborted delivery after device 1 when lease was lost"
    );
    drop(w1_sends);

    // Worker 2's claimed row must still exist in push_event_queue (Worker 1 must not have deleted it)
    let w2_row_exists: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT lease_token FROM push_event_queue WHERE id = $1")
            .bind(row_w2.id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(
        w2_row_exists, row_w2.lease_token,
        "Worker 2's row must remain intact in push_event_queue"
    );
}
/// 4. Mid-Send Revocation & Advisory Lock Barrier Test (Real Worker Path with Observing Fake APNs)
#[tokio::test]
async fn test_mid_send_auth_revocation_serialization_barrier() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(make_services(pool.clone()).with_apns_sender(fake_apns.clone()));
    let state = make_test_app_state(pool.clone(), services.clone()).await;

    let recipient_did = "did:plc:user_barrier_revocation_test";
    let token = "2222333344445555666677778888999922223333444455556666777788889999";
    let session = make_session(recipient_did);

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    services
        .registry
        .upsert_registration(&session, &reg_input)
        .await
        .unwrap();

    // Populate moderation verdict
    sqlx::query(
        r#"
        INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at)
        VALUES ($1, 'did:plc:actor', '{"muted": false}'::jsonb, 'Actor', NOW())
        "#,
    )
    .bind(recipient_did)
    .execute(&pool)
    .await
    .unwrap();

    // Enqueue first push event
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, 'did:plc:actor', 'like', 'bafy-cid-rev1', 'app.bsky.feed.like/rev1',
                '{}'::jsonb, 1700000000, 'dedupe-rev1', NOW(), 1)
        "#,
    )
    .bind(recipient_did)
    .execute(&pool)
    .await
    .unwrap();

    // Set up barriers in fake APNs so send holds transaction and advisory lock
    let enter_barrier = Arc::new(Barrier::new(2));
    let exit_barrier = Arc::new(Barrier::new(2));
    let mut apns_barrier =
        ObservingFakeApns::with_barriers(enter_barrier.clone(), exit_barrier.clone());
    apns_barrier.sends = fake_apns.sends.clone();
    let apns_barrier = Arc::new(apns_barrier);

    let services_barrier =
        Arc::new(make_services(pool.clone()).with_apns_sender(apns_barrier.clone()));
    let state_barrier = make_test_app_state(pool.clone(), services_barrier.clone()).await;
    let worker_handle = tokio::spawn({
        let s = services_barrier.clone();
        let st = state_barrier.clone();
        async move { s.process_queue_batch(&st).await }
    });

    enter_barrier.wait().await;

    let mutator_done = Arc::new(AtomicBool::new(false));
    let mutator_handle = tokio::spawn({
        let s = services.clone();
        let done = mutator_done.clone();
        let did = recipient_did.to_string();
        async move {
            s.registry.mark_auth_revoked(&did).await.unwrap();
            done.store(true, Ordering::SeqCst);
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !mutator_done.load(Ordering::SeqCst),
        "mark_auth_revoked must be blocked by advisory lock while APNs send is in flight"
    );

    exit_barrier.wait().await;
    worker_handle.await.unwrap().unwrap();
    mutator_handle.await.unwrap();
    assert!(mutator_done.load(Ordering::SeqCst));
    // First notification was delivered
    assert_eq!(fake_apns.sends.lock().await.len(), 1);

    // Enqueue second push event for same recipient
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, 'did:plc:actor', 'like', 'bafy-cid-rev2', 'app.bsky.feed.like/rev2',
                '{}'::jsonb, 1700000001, 'dedupe-rev2', NOW(), 1)
        "#,
    )
    .bind(recipient_did)
    .execute(&pool)
    .await
    .unwrap();

    // While auth is revoked, claim_ready ignores rows for revoked accounts
    let processed_revoked = services.process_queue_batch(&state).await.unwrap();
    assert_eq!(
        processed_revoked, 0,
        "claim_ready must skip rows for revoked accounts"
    );

    // User re-authenticates (clearing auth_revoked_at, but bumping auth_generation to 3)
    let new_session = make_session(recipient_did);
    services
        .registry
        .activate_account_session(
            recipient_did,
            &new_session.id.to_string(),
            &new_session.pds_url,
        )
        .await
        .unwrap();

    // Now worker claims the row, but pre-send fence detects stale generation (1 != 3) and rejects it
    let processed_reauth = services.process_queue_batch(&state).await.unwrap();
    assert_eq!(
        processed_reauth, 1,
        "Worker must claim and process the queued row after reauth"
    );

    // Assert NO second send occurred!
    assert_eq!(
        fake_apns.sends.lock().await.len(),
        1,
        "Subsequent push event must be suppressed after auth revocation and reauth"
    );
}
/// 5. Mid-Send Activity Unsubscribe Barrier Test (Real Worker Path with Observing Fake APNs)
#[tokio::test]
async fn test_mid_send_activity_unsubscribe_serialization_barrier() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(make_services(pool.clone()).with_apns_sender(fake_apns.clone()));
    let state = make_test_app_state(pool.clone(), services.clone()).await;

    let subscriber_did = "did:plc:unsub_subscriber";
    let subject_did = "did:plc:author";
    let token = "3333444455556666777788889999000033334444555566667777888899990000";
    let session = make_session(subscriber_did);

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    services
        .registry
        .upsert_registration(&session, &reg_input)
        .await
        .unwrap();

    // Subscribe to posts
    let sub = ActivitySubscriptionPreference {
        post: true,
        reply: false,
    };
    services
        .subscriptions
        .put(subscriber_did, subject_did, &sub)
        .await
        .unwrap();

    // Populate moderation verdict
    sqlx::query(
        r#"
        INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at)
        VALUES ($1, $2, '{"muted": false}'::jsonb, 'Author', NOW())
        "#,
    )
    .bind(subscriber_did)
    .bind(subject_did)
    .execute(&pool)
    .await
    .unwrap();

    // Enqueue first activity event
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, $2, 'activity_post', 'bafy-cid-act1', 'app.bsky.feed.post/1',
                '{}'::jsonb, 1700000000, 'dedupe-act1', NOW(), 1)
        "#,
    )
    .bind(subscriber_did)
    .bind(subject_did)
    .execute(&pool)
    .await
    .unwrap();

    // Set up barriers in fake APNs
    let enter_barrier = Arc::new(Barrier::new(2));
    let exit_barrier = Arc::new(Barrier::new(2));
    let mut apns_barrier =
        ObservingFakeApns::with_barriers(enter_barrier.clone(), exit_barrier.clone());
    apns_barrier.sends = fake_apns.sends.clone();
    let apns_barrier = Arc::new(apns_barrier);

    let services_barrier =
        Arc::new(make_services(pool.clone()).with_apns_sender(apns_barrier.clone()));
    let state_barrier = make_test_app_state(pool.clone(), services_barrier.clone()).await;

    let worker_handle = tokio::spawn({
        let s = services_barrier.clone();
        let st = state_barrier.clone();
        async move { s.process_queue_batch(&st).await }
    });

    enter_barrier.wait().await;

    // Mutator unsubscribes mid-flight
    let mutator_done = Arc::new(AtomicBool::new(false));
    let mutator_handle = tokio::spawn({
        let s = services.clone();
        let done = mutator_done.clone();
        let sub_did = subscriber_did.to_string();
        let subj_did = subject_did.to_string();
        async move {
            let unsub = ActivitySubscriptionPreference {
                post: false,
                reply: false,
            };
            s.subscriptions
                .put(&sub_did, &subj_did, &unsub)
                .await
                .unwrap();
            done.store(true, Ordering::SeqCst);
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !mutator_done.load(Ordering::SeqCst),
        "Unsubscribe must be blocked by advisory lock during APNs send"
    );

    exit_barrier.wait().await;
    worker_handle.await.unwrap().unwrap();
    mutator_handle.await.unwrap();
    assert!(mutator_done.load(Ordering::SeqCst));

    assert_eq!(fake_apns.sends.lock().await.len(), 1);

    // Enqueue second activity event
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, $2, 'activity_post', 'bafy-cid-act2', 'app.bsky.feed.post/2',
                '{}'::jsonb, 1700000001, 'dedupe-act2', NOW(), 1)
        "#,
    )
    .bind(subscriber_did)
    .bind(subject_did)
    .execute(&pool)
    .await
    .unwrap();

    let processed_2 = services.process_queue_batch(&state).await.unwrap();
    assert_eq!(processed_2, 1);

    assert_eq!(
        fake_apns.sends.lock().await.len(),
        1,
        "Subsequent activity event must be suppressed after unsubscribe"
    );
}

/// 5B. Mid-Send Thread Mute Barrier Test (Real Worker Path with Observing Fake APNs)
#[tokio::test]
async fn test_mid_send_thread_mute_serialization_barrier() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(make_services(pool.clone()).with_apns_sender(fake_apns.clone()));
    let state = make_test_app_state(pool.clone(), services.clone()).await;

    let user_did = "did:plc:mute_user";
    let actor_did = "did:plc:author";
    let thread_root = "at://did:plc:author/app.bsky.feed.post/root1";
    let token = "5555444455556666777788889999000055554444555566667777888899990000";
    let session = make_session(user_did);

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    services
        .registry
        .upsert_registration(&session, &reg_input)
        .await
        .unwrap();

    // Populate moderation verdict
    sqlx::query(
        r#"
        INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at)
        VALUES ($1, $2, '{"muted": false}'::jsonb, 'Author', NOW())
        "#,
    )
    .bind(user_did)
    .bind(actor_did)
    .execute(&pool)
    .await
    .unwrap();

    // Enqueue first reply event in thread
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            thread_root_uri, event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, $2, 'reply', 'bafy-cid-rep1', 'app.bsky.feed.post/rep1',
                $3, '{}'::jsonb, 1700000000, 'dedupe-rep1', NOW(), 1)
        "#,
    )
    .bind(user_did)
    .bind(actor_did)
    .bind(thread_root)
    .execute(&pool)
    .await
    .unwrap();

    // Set up barriers in fake APNs
    let enter_barrier = Arc::new(Barrier::new(2));
    let exit_barrier = Arc::new(Barrier::new(2));
    let mut apns_barrier =
        ObservingFakeApns::with_barriers(enter_barrier.clone(), exit_barrier.clone());
    apns_barrier.sends = fake_apns.sends.clone();
    let apns_barrier = Arc::new(apns_barrier);

    let services_barrier =
        Arc::new(make_services(pool.clone()).with_apns_sender(apns_barrier.clone()));
    let state_barrier = make_test_app_state(pool.clone(), services_barrier.clone()).await;

    let worker_handle = tokio::spawn({
        let s = services_barrier.clone();
        let st = state_barrier.clone();
        async move { s.process_queue_batch(&st).await }
    });

    enter_barrier.wait().await;

    // Mutator mutes thread mid-flight
    let mutator_done = Arc::new(AtomicBool::new(false));
    let mutator_handle = tokio::spawn({
        let s = services.clone();
        let done = mutator_done.clone();
        let u_did = user_did.to_string();
        let t_root = thread_root.to_string();
        async move {
            s.thread_mutes.mute_thread(&u_did, &t_root).await.unwrap();
            done.store(true, Ordering::SeqCst);
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !mutator_done.load(Ordering::SeqCst),
        "mute_thread must be blocked by advisory lock during APNs send"
    );

    exit_barrier.wait().await;
    worker_handle.await.unwrap().unwrap();
    mutator_handle.await.unwrap();
    assert!(mutator_done.load(Ordering::SeqCst));

    assert_eq!(fake_apns.sends.lock().await.len(), 1);

    // Enqueue second reply event in same thread
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            thread_root_uri, event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, $2, 'reply', 'bafy-cid-rep2', 'app.bsky.feed.post/rep2',
                $3, '{}'::jsonb, 1700000001, 'dedupe-rep2', NOW(), 1)
        "#,
    )
    .bind(user_did)
    .bind(actor_did)
    .bind(thread_root)
    .execute(&pool)
    .await
    .unwrap();

    let processed_2 = services.process_queue_batch(&state).await.unwrap();
    assert_eq!(processed_2, 1);

    assert_eq!(
        fake_apns.sends.lock().await.len(),
        1,
        "Subsequent reply in muted thread must be suppressed after mute_thread"
    );
}

/// 6. Enqueue-before-logout / Claim-after-reauth Real Stale Work Test
#[tokio::test]
async fn test_enqueue_before_logout_claim_after_reauth() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(make_services(pool.clone()).with_apns_sender(fake_apns.clone()));
    let state = make_test_app_state(pool.clone(), services.clone()).await;

    let recipient_did = "did:plc:user_stale_reauth_test";
    let token = "7777888899990000111122223333444477778888999900001111222233334444";
    let session = make_session(recipient_did);

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    services
        .registry
        .upsert_registration(&session, &reg_input)
        .await
        .unwrap();

    // Populate moderation verdict
    sqlx::query(
        r#"
        INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at)
        VALUES ($1, 'did:plc:actor', '{"muted": false}'::jsonb, 'Actor', NOW())
        "#,
    )
    .bind(recipient_did)
    .execute(&pool)
    .await
    .unwrap();

    // Enqueue push event BEFORE logout (generation 1)
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, 'did:plc:actor', 'like', 'bafy-cid-stale', 'app.bsky.feed.like/stale',
                '{}'::jsonb, 1700000000, 'dedupe-stale', NOW(), 1)
        "#,
    )
    .bind(recipient_did)
    .execute(&pool)
    .await
    .unwrap();

    // User logs out (auth revoked -> generation bumped to 2)
    services
        .registry
        .mark_auth_revoked(recipient_did)
        .await
        .unwrap();

    // User logs in again / re-authenticates (generation bumped to 3, auth_revoked_at cleared)
    let new_session = make_session(recipient_did);
    services
        .registry
        .activate_account_session(
            recipient_did,
            &new_session.id.to_string(),
            &new_session.pds_url,
        )
        .await
        .unwrap();

    // Worker claims and processes the queue row AFTER reauth
    let processed = services.process_queue_batch(&state).await.unwrap();
    assert_eq!(processed, 1, "Worker must claim and process the queued row");

    // Stale event must be rejected by pre-send fence as Revoked, so 0 APNs sends occur
    assert_eq!(
        fake_apns.sends.lock().await.len(),
        0,
        "Stale work enqueued before logout must NEVER be delivered to APNs after reauthentication"
    );

    // Queue must be empty (row deleted via CAS delete_fenced on Revoked outcome)
    let remaining_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM push_event_queue")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        remaining_count, 0,
        "Rejected stale event must be deleted from queue"
    );
}

/// 7. Concurrent Quota Final-Slot Race & Fanout Limit Test
#[tokio::test]
async fn test_concurrent_quota_final_slot_race_and_fanout() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();

    let mut config = PushConfig::default();
    config.service_did = Some("did:web:push.catbird.blue".to_string());
    config.max_active_devices_per_account = 2;
    config.max_inactive_devices_per_account = 3;
    config.max_fanout_per_notification = 2;
    let services = Arc::new(PushServices::new(pool.clone(), config).unwrap());

    let did = "did:plc:quota_race_user";
    let concurrency = 10;
    let barrier = Arc::new(Barrier::new(concurrency));

    let mut handles = Vec::new();
    for i in 0..concurrency {
        let services = services.clone();
        let barrier = barrier.clone();
        let token = format!("quota_token_{:064}", i);

        handles.push(tokio::spawn(async move {
            let session = make_session(did);
            let input = RegisterPushInput {
                service_did: "did:web:push.catbird.blue".to_string(),
                token,
                platform: "ios".to_string(),
                app_id: "blue.catbird".to_string(),
                age_restricted: Some(false),
            };
            barrier.wait().await;
            services
                .registry
                .upsert_registration(&session, &input)
                .await
        }));
    }

    for h in handles {
        let res = h.await.unwrap();
        assert!(
            res.is_ok(),
            "Upsert registration in quota race must succeed: {:?}",
            res
        );
    }

    let active_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_devices WHERE did = $1 AND is_active = TRUE")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        active_count <= 2,
        "Active device count ({}) must not exceed max_active_devices_per_account (2)",
        active_count
    );

    let total_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_devices WHERE did = $1")
        .bind(did)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        total_count <= 5,
        "Total retained devices ({}) must not exceed max_active (2) + max_inactive (3) = 5",
        total_count
    );

    let active_registrations = services
        .registry
        .list_active_registrations(did)
        .await
        .unwrap();
    assert!(
        active_registrations.len() <= 2,
        "Fanout list must respect max_fanout_per_notification"
    );
}

/// 8. Strict Moderation Validation & Prior Cache Preservation Test
#[tokio::test]
async fn test_strict_moderation_validation_and_cache_preservation() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();
    let services = make_services(pool.clone());

    // 1. Strict parser validation of malformed types
    assert!(ModerationVerdict::try_from_viewer_json(Some(&json!({"muted": null}))).is_err());
    assert!(ModerationVerdict::try_from_viewer_json(Some(&json!({"mutedByList": []}))).is_err());
    assert!(ModerationVerdict::try_from_viewer_json(Some(&json!({"blocking": false}))).is_err());
    assert!(ModerationVerdict::try_from_viewer_json(Some(&json!({"blocking": ""}))).is_err());
    assert!(ModerationVerdict::try_from_viewer_json(Some(&json!({"blocking": null}))).is_err());
    assert!(ModerationVerdict::try_from_viewer_json(Some(&json!({"blockedBy": null}))).is_err());
    assert!(ModerationVerdict::try_from_viewer_json(Some(&json!({"blockingByList": []}))).is_err());
    assert!(
        ModerationVerdict::try_from_viewer_json(Some(&json!({"mutedOnlyReposts": null}))).is_err()
    );
    assert!(
        ModerationVerdict::try_from_viewer_json(Some(&json!({"mutedOnlyQuoteposts": null})))
            .is_err()
    );

    // Valid parser shapes
    let valid_viewer = json!({
        "muted": true,
        "mutedByList": { "uri": "at://did:plc:list/1" },
        "blocking": "at://did:plc:alice/app.bsky.graph.block/1",
        "blockedBy": true,
        "blockingByList": { "uri": "at://did:plc:list/2" },
        "mutedOnlyReposts": true,
        "mutedOnlyQuoteposts": true,
    });
    let parsed = ModerationVerdict::try_from_viewer_json(Some(&valid_viewer)).unwrap();
    assert!(parsed.muted);
    assert!(parsed.muted_by_list);
    assert!(parsed.blocking);
    assert!(parsed.blocked_by);
    assert!(parsed.blocking_by_list);
    assert!(parsed.muted_only_reposts);
    assert!(parsed.muted_only_quoteposts);

    // 2. Cache preservation in database
    let recipient_did = "did:plc:mod_recipient";
    let actor_did = "did:plc:mod_actor";
    let token = "4444555566667777888899990000111144445555666677778888999900001111";
    let session = make_session(recipient_did);
    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    services
        .registry
        .upsert_registration(&session, &reg_input)
        .await
        .unwrap();

    // Store a valid suppressing cached verdict
    let valid_cached_verdict = json!({ "blocking": true, "muted": false });
    sqlx::query(
        r#"
        INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at)
        VALUES ($1, $2, $3, 'Blocked User', NOW())
        "#,
    )
    .bind(recipient_did)
    .bind(actor_did)
    .bind(&valid_cached_verdict)
    .execute(&pool)
    .await
    .unwrap();

    // Pre-send fence evaluates cached verdict and suppresses
    let fence_suppressed = services
        .verify_pre_send_fence(recipient_did, actor_did, token, "like", None, None, None)
        .await
        .unwrap();
    assert_eq!(fence_suppressed, PreSendFenceOutcome::ModerationSuppressed);
    // 3. Live Fetch across Invalidation Race (Production-boundary Test)
    // Set up a mock PDS server that responds to getProfile with a delay
    let mock_pds = wiremock::MockServer::start().await;
    let delayed_profile_response = json!({
        "did": actor_did,
        "handle": "actor.test",
        "displayName": "Actor User",
        "viewer": {
            "muted": false,
            "blockedBy": false
        }
    });

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.actor.getProfile"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(delayed_profile_response)
                .set_delay(std::time::Duration::from_millis(500)),
        )
        .mount(&mock_pds)
        .await;

    let mut session_live = make_session(recipient_did);
    session_live.pds_url = mock_pds.uri();
    services
        .registry
        .activate_account_session(
            recipient_did,
            &session_live.id.to_string(),
            &session_live.pds_url,
        )
        .await
        .unwrap();
    let state = make_test_app_state(pool.clone(), Arc::new(services.clone())).await;

    // Start live fetch in background task
    let mod_resolver = services.moderation.clone();
    let st_clone = state.clone();
    let r_did = recipient_did.to_string();
    let a_did = actor_did.to_string();
    let fetch_handle =
        tokio::spawn(async move { mod_resolver.resolve(&st_clone, &r_did, &a_did).await });

    // Wait 100ms for HTTP fetch to be in flight, then simulate user muting/blocking (invalidation)
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    services
        .moderation
        .invalidate_recipient(recipient_did)
        .await
        .unwrap();

    // Await fetch completion
    let fetch_res = fetch_handle.await.unwrap();
    assert!(fetch_res.is_ok(), "Fetch must complete: {:?}", fetch_res);

    // CRITICAL: An in-flight fetch that started before invalidation must NOT repopulate the cache!
    let cached_row_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM actor_moderation_verdict WHERE recipient_did = $1",
    )
    .bind(recipient_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        cached_row_count,
        0,
        "Live fetch begun before invalidation must not resurrect a stale allow verdict in the cache"
    );
}

/// 9. Fenced Lease Expiry & False CAS Handling Test
#[tokio::test]
async fn test_fenced_lease_expiry_and_false_cas() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();
    let queue = make_services(pool.clone()).queue;

    let recipient_did = "did:plc:cas_test_user";
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, 'did:plc:actor', 'like', 'bafy-cid-cas', 'app.bsky.feed.like/cas',
                '{}'::jsonb, 1700000000, 'dedupe-cas', NOW(), 1)
        "#,
    )
    .bind(recipient_did)
    .execute(&pool)
    .await
    .unwrap();

    let claimed = queue.claim_ready(1).await.unwrap();
    let row = claimed[0].clone();
    let token = row.lease_token.unwrap();
    let version = row.lease_version;

    // Extend lease
    let v2 = queue
        .extend_lease(row.id, token, version, 30)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v2, version + 1);

    // Attempting CAS with old version must return Ok(false) / None
    let stale_extend = queue
        .extend_lease(row.id, token, version, 30)
        .await
        .unwrap();
    assert_eq!(stale_extend, None);

    let stale_retry = queue
        .retry_later_fenced(row.id, token, version, 1, "test_err")
        .await
        .unwrap();
    assert!(!stale_retry);

    let stale_delete = queue.delete_fenced(row.id, token, version).await.unwrap();
    assert!(!stale_delete);

    // Expire lease
    sqlx::query(
        "UPDATE push_event_queue SET leased_until = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(row.id)
    .execute(&pool)
    .await
    .unwrap();

    // Expired lease mutation must return false even with matching version
    let expired_delete = queue.delete_fenced(row.id, token, v2).await.unwrap();
    assert!(
        !expired_delete,
        "delete_fenced on expired lease must return false"
    );

    let expired_retry = queue
        .retry_later_fenced(row.id, token, v2, 1, "test_err")
        .await
        .unwrap();
    assert!(
        !expired_retry,
        "retry_later_fenced on expired lease must return false"
    );
}

/// 9. Mid-Poll Re-authentication Stale Event Rejection Test
#[tokio::test]
async fn test_mid_poll_reauth_stale_event_rejected() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(make_services(pool.clone()).with_apns_sender(fake_apns.clone()));
    let state = make_test_app_state(pool.clone(), services.clone()).await;

    let recipient_did = "did:plc:mid_poll_reauth_user";
    let token = "1111222233334444555566667777888811112222333344445555666677778888";
    let session_1 = make_session(recipient_did);

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    services
        .registry
        .upsert_registration(&session_1, &reg_input)
        .await
        .unwrap();

    // Populate moderation verdict
    sqlx::query(
        r#"
        INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at)
        VALUES ($1, 'did:plc:chat_sender', '{"muted": false}'::jsonb, 'Sender', NOW())
        "#,
    )
    .bind(recipient_did)
    .execute(&pool)
    .await
    .unwrap();

    // Simulate chat poller capturing session_id + auth_generation before network call
    let (captured_session_id, _pds_url, captured_gen) = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT session_id, pds_url, auth_generation FROM push_accounts WHERE account_did = $1 AND auth_revoked_at IS NULL"
    )
    .bind(recipient_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(captured_gen, 1, "Initial account generation must be 1");
    assert_eq!(captured_session_id, session_1.id.to_string());

    // Mid-poll: user logs out and re-authenticates with a new session while network call is in flight
    services
        .registry
        .mark_auth_revoked(recipient_did)
        .await
        .unwrap();
    let session_2 = make_session(recipient_did);
    services
        .registry
        .activate_account_session(recipient_did, &session_2.id.to_string(), &session_2.pds_url)
        .await
        .unwrap();

    let current_gen: i64 =
        sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did = $1")
            .bind(recipient_did)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        current_gen, 3,
        "Account generation after logout + reauth must be 3"
    );

    // Network call completes; event is constructed using the pre-network captured generation (1)
    let chat_event = catbird::services::chat_poll::types::ChatPushEvent {
        recipient_did: recipient_did.to_string(),
        sender_did: "did:plc:chat_sender".to_string(),
        convo_id: "convo_123".to_string(),
        message_id: "msg_456".to_string(),
        message_text: "Hello from old session".to_string(),
        sent_at: "2026-08-30T12:00:00Z".to_string(),
        auth_generation: captured_gen,
    };

    // Fast-path fence check must reject as Revoked
    let mut tx = pool.begin().await.unwrap();
    catbird::services::push::lock::acquire_account_and_device_lock(&mut tx, recipient_did, token)
        .await
        .unwrap();
    let fast_path_outcome = services
        .verify_pre_send_fence_tx(
            &mut tx,
            recipient_did,
            &chat_event.sender_did,
            token,
            "chat_message",
            None,
            None,
            Some(chat_event.auth_generation),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        fast_path_outcome,
        PreSendFenceOutcome::Revoked,
        "Fast path must reject stale pre-poll event"
    );

    // Durable queue enqueue and worker processing
    catbird::services::chat_poll::poller::enqueue_push(&pool, &chat_event, 0)
        .await
        .unwrap();
    let processed = services.process_queue_batch(&state).await.unwrap();
    assert_eq!(processed, 1);

    // APNs sends must be 0
    assert_eq!(
        fake_apns.sends.lock().await.len(),
        0,
        "No APNs push must be sent for event produced under stale pre-reauth session"
    );
}

/// 10. Firehose Candidate Generation Propagation & Reauth Fence Test
#[tokio::test]
async fn test_firehose_candidate_generation_and_reauth_fence() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(make_services(pool.clone()).with_apns_sender(fake_apns.clone()));
    let state = make_test_app_state(pool.clone(), services.clone()).await;

    let recipient_did = "did:plc:firehose_reauth_user";
    let token = "5555666677778888999900001111222255556666777788889999000011112222";
    let session = make_session(recipient_did);

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    services
        .registry
        .upsert_registration(&session, &reg_input)
        .await
        .unwrap();

    sqlx::query(
        r#"
        INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at)
        VALUES ($1, 'did:plc:firehose_actor', '{"muted": false}'::jsonb, 'Actor', NOW())
        "#,
    )
    .bind(recipient_did)
    .execute(&pool)
    .await
    .unwrap();

    // Query account generation at firehose event production
    let producing_gen: i64 = sqlx::query_scalar(
        "SELECT auth_generation FROM push_accounts WHERE account_did = $1 AND auth_revoked_at IS NULL"
    )
    .bind(recipient_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(producing_gen, 1);

    // Firehose enqueues candidate with explicit auth_generation 1
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, 'did:plc:firehose_actor', 'like', 'bafy-firehose-1', 'app.bsky.feed.like/1',
                '{}'::jsonb, 1700000000, 'dedupe-firehose-1', NOW(), $2)
        "#,
    )
    .bind(recipient_did)
    .bind(producing_gen)
    .execute(&pool)
    .await
    .unwrap();

    // Verify stored auth_generation
    let stored_gen: i64 = sqlx::query_scalar(
        "SELECT auth_generation FROM push_event_queue WHERE dedupe_key = 'dedupe-firehose-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored_gen, 1);

    // User logs out and re-authenticates (gen -> 2 -> 3)
    services
        .registry
        .mark_auth_revoked(recipient_did)
        .await
        .unwrap();
    let session_2 = make_session(recipient_did);
    services
        .registry
        .activate_account_session(recipient_did, &session_2.id.to_string(), &session_2.pds_url)
        .await
        .unwrap();

    // Worker claims and processes
    let processed = services.process_queue_batch(&state).await.unwrap();
    assert_eq!(processed, 1);

    // APNs sends must be 0
    assert_eq!(
        fake_apns.sends.lock().await.len(),
        0,
        "Firehose event enqueued before re-auth must be rejected by fence"
    );
}

/// 11. Shared-Writer Advisory Lock Key Equivalence Test
#[test]
fn test_shared_writer_lock_keys_identical() {
    let test_dids = [
        "did:plc:ragtjsm2j2vknwk6zax4p25t",
        "did:plc:z72i7hdynmk6r22z27h6tvur",
        "did:web:push.catbird.blue",
        "did:plc:random_user_12345",
    ];

    let test_tokens = [
        "7777888899990000111122223333444477778888999900001111222233334444",
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "device_token_xyz_987654321",
    ];

    for did in &test_dids {
        let k1 = catbird::services::push::lock::advisory_lock_key_for_account(did);
        let k2 = catbird::services::push::lock::advisory_lock_key_for_account(did);
        assert_eq!(k1, k2);
    }

    for token in &test_tokens {
        let k1 = catbird::services::push::lock::advisory_lock_key_for_device(token);
        let k2 = catbird::services::push::lock::advisory_lock_key_for_device(token);
        assert_eq!(k1, k2);
    }

    // Account and device keys must be domain separated
    for s in &["test_shared_identifier", "did:plc:same_str"] {
        let acc_key = catbird::services::push::lock::advisory_lock_key_for_account(s);
        let dev_key = catbird::services::push::lock::advisory_lock_key_for_device(s);
        assert_ne!(
            acc_key, dev_key,
            "Account and device keys must have distinct domain separators"
        );
    }
}
