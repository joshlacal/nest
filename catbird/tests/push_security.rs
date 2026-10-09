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

#[path = "support/cleanup_auth.rs"]
mod cleanup_auth;

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

async fn make_session(store: &catbird::services::RedisAuthStore, did: &str) -> CatbirdSession {
    let now = Utc::now();
    let session = CatbirdSession {
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
    };
    cleanup_auth::seed(store, &session).await;
    session
}

fn make_services(
    pool: Pool<Postgres>,
    auth_store: Arc<catbird::services::RedisAuthStore>,
) -> PushServices {
    let mut config = PushConfig::default();
    config.service_did = Some("did:web:push.catbird.blue".to_string());
    PushServices::new(pool, config)
        .unwrap()
        .with_auth_store(auth_store)
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

/// Simulates the fixture's complete preference restore after registration.
async fn register(
    services: &PushServices,
    _store: &catbird::services::RedisAuthStore,
    session: &CatbirdSession,
    input: &RegisterPushInput,
) -> anyhow::Result<()> {
    services
        .registry
        .upsert_registration(session, input)
        .await?;
    if services.preferences.get(&session.did).await?.is_none() {
        services
            .preferences
            .put(&session.did, &PushPreferencesDocument::default())
            .await?;
    }
    Ok(())
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

// A suppressed send or lost barrier partner must fail the fixture, not hang it.
async fn wait_for_test_barrier(barrier: &Barrier) {
    tokio::time::timeout(std::time::Duration::from_secs(30), barrier.wait())
        .await
        .expect("push-security test barrier timed out");
}

#[async_trait::async_trait]
impl ApnsSender for ObservingFakeApns {
    async fn send(
        &self,
        registration: &RegistrationRow,
        notification: &ApnsNotification,
    ) -> anyhow::Result<&'static str> {
        if let Some(enter) = &self.enter_barrier {
            wait_for_test_barrier(enter).await;
        }
        if let Some(exit) = &self.exit_barrier {
            wait_for_test_barrier(exit).await;
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
    let auth_store = test_db.auth_store.clone();
    let services = Arc::new(make_services(pool.clone(), auth_store.clone()));

    let shared_token = "1111222233334444555566667777888811112222333344445555666677778888";
    let concurrency = 8;
    let barrier = Arc::new(Barrier::new(concurrency));

    let mut handles = Vec::new();
    for i in 0..concurrency {
        let services = services.clone();
        let barrier = barrier.clone();
        let auth_store = auth_store.clone();
        let did = format!("did:plc:concurrent_user_{}", i);

        handles.push(tokio::spawn(async move {
            let session = make_session(&auth_store, &did).await;
            let input = RegisterPushInput {
                service_did: "did:web:push.catbird.blue".to_string(),
                token: shared_token.to_string(),
                platform: "ios".to_string(),
                app_id: "blue.catbird".to_string(),
                age_restricted: Some(false),
            };
            wait_for_test_barrier(&barrier).await;
            register(&services, &auth_store, &session, &input).await
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
    let auth_store = test_db.auth_store.clone();

    let mut fake_apns = ObservingFakeApns::new();
    fake_apns.pause_duration = Some(std::time::Duration::from_millis(3000));
    let fake_apns = Arc::new(fake_apns);
    let services = Arc::new(
        make_services(pool.clone(), auth_store.clone()).with_apns_sender(fake_apns.clone()),
    );
    let state = make_test_app_state(pool.clone(), services.clone(), auth_store.clone()).await;

    let recipient_did = "did:plc:long_send_user";
    let token1 = "1111222233334444555566667777888811112222333344445555666677778888";
    let token2 = "9999888877776666555544443333222299998888777766665555444433332222";
    let session = make_session(&auth_store, recipient_did).await;

    for token in &[token1, token2] {
        let reg_input = RegisterPushInput {
            service_did: "did:web:push.catbird.blue".to_string(),
            token: token.to_string(),
            platform: "ios".to_string(),
            app_id: "blue.catbird".to_string(),
            age_restricted: Some(false),
        };
        register(&services, &auth_store, &session, &reg_input)
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
                '{}'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT, 'dedupe-1', NOW(), (SELECT auth_generation FROM push_accounts WHERE account_did = $1))
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
    let session_a2 = make_session(&auth_store, recipient_did_a2).await;
    for token in &[token1, token2] {
        let reg_input = RegisterPushInput {
            service_did: "did:web:push.catbird.blue".to_string(),
            token: token.to_string(),
            platform: "ios".to_string(),
            app_id: "blue.catbird".to_string(),
            age_restricted: Some(false),
        };
        register(&services, &auth_store, &session_a2, &reg_input)
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
                '{}'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT, 'dedupe-race', NOW(), (SELECT auth_generation FROM push_accounts WHERE account_did = $1))
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
    let session_b = make_session(&auth_store, recipient_did_b).await;
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
        register(&services, &auth_store, &session_b, &reg_input)
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
    let services_w1 = Arc::new(
        make_services(pool.clone(), auth_store.clone()).with_apns_sender(fake_apns_w1.clone()),
    );
    let state_w1 = make_test_app_state(pool.clone(), services_w1.clone(), auth_store.clone()).await;

    // Enqueue a second event
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, 'did:plc:actor', 'like', 'bafy-cid-2', 'app.bsky.feed.like/2',
                '{}'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT, 'dedupe-2', NOW(), (SELECT auth_generation FROM push_accounts WHERE account_did = $1))
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
    wait_for_test_barrier(&enter_b).await;
    // While Worker 1 is paused on device 1, simulate lease expiration and Worker 2 stealing the lease
    sqlx::query("UPDATE push_event_queue SET leased_until = NOW() - INTERVAL '1 second' WHERE dedupe_key = 'dedupe-2'")
        .execute(&pool)
        .await
        .unwrap();

    let services_w2 = Arc::new(make_services(pool.clone(), auth_store.clone()));
    let claimed_w2 = services_w2.queue.claim_ready(1).await.unwrap();
    let row_w2 = claimed_w2[0].clone();
    assert_eq!(row_w2.event_cid, "bafy-cid-2");

    wait_for_test_barrier(&exit_b).await;
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
    let auth_store = test_db.auth_store.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(
        make_services(pool.clone(), auth_store.clone()).with_apns_sender(fake_apns.clone()),
    );
    let state = make_test_app_state(pool.clone(), services.clone(), auth_store.clone()).await;

    let recipient_did = "did:plc:user_barrier_revocation_test";
    let token = "2222333344445555666677778888999922223333444455556666777788889999";
    let session = make_session(&auth_store, recipient_did).await;

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    register(&services, &auth_store, &session, &reg_input)
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
                '{}'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT, 'dedupe-rev1', NOW(), (SELECT auth_generation FROM push_accounts WHERE account_did = $1))
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

    let services_barrier = Arc::new(
        make_services(pool.clone(), auth_store.clone()).with_apns_sender(apns_barrier.clone()),
    );
    let state_barrier =
        make_test_app_state(pool.clone(), services_barrier.clone(), auth_store.clone()).await;
    let worker_handle = tokio::spawn({
        let s = services_barrier.clone();
        let st = state_barrier.clone();
        async move { s.process_queue_batch(&st).await }
    });

    wait_for_test_barrier(&enter_barrier).await;

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

    wait_for_test_barrier(&exit_barrier).await;
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
                '{}'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT, 'dedupe-rev2', NOW(), (SELECT auth_generation FROM push_accounts WHERE account_did = $1))
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

    // User re-authenticates, clearing revocation and issuing a new authorization epoch.
    let new_session = make_session(&auth_store, recipient_did).await;
    services
        .registry
        .activate_account_session(
            recipient_did,
            &new_session.id.to_string(),
            &new_session.pds_url,
        )
        .await
        .unwrap();

    // Now the pre-send fence rejects the row captured under the previous authorization epoch.
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
    let auth_store = test_db.auth_store.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(
        make_services(pool.clone(), auth_store.clone()).with_apns_sender(fake_apns.clone()),
    );
    let state = make_test_app_state(pool.clone(), services.clone(), auth_store.clone()).await;

    let subscriber_did = "did:plc:unsub_subscriber";
    let subject_did = "did:plc:author";
    let token = "3333444455556666777788889999000033334444555566667777888899990000";
    let session = make_session(&auth_store, subscriber_did).await;

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    register(&services, &auth_store, &session, &reg_input)
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
                '{}'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT, 'dedupe-act1', NOW(), (SELECT auth_generation FROM push_accounts WHERE account_did = $1))
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

    let services_barrier = Arc::new(
        make_services(pool.clone(), auth_store.clone()).with_apns_sender(apns_barrier.clone()),
    );
    let state_barrier =
        make_test_app_state(pool.clone(), services_barrier.clone(), auth_store.clone()).await;

    let worker_handle = tokio::spawn({
        let s = services_barrier.clone();
        let st = state_barrier.clone();
        async move { s.process_queue_batch(&st).await }
    });

    wait_for_test_barrier(&enter_barrier).await;

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

    wait_for_test_barrier(&exit_barrier).await;
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
                '{}'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT, 'dedupe-act2', NOW(), (SELECT auth_generation FROM push_accounts WHERE account_did = $1))
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
    let auth_store = test_db.auth_store.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(
        make_services(pool.clone(), auth_store.clone()).with_apns_sender(fake_apns.clone()),
    );
    let state = make_test_app_state(pool.clone(), services.clone(), auth_store.clone()).await;

    let user_did = "did:plc:mute_user";
    let actor_did = "did:plc:author";
    let thread_root = "at://did:plc:author/app.bsky.feed.post/root1";
    let token = "5555444455556666777788889999000055554444555566667777888899990000";
    let session = make_session(&auth_store, user_did).await;

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    register(&services, &auth_store, &session, &reg_input)
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
                $3, '{}'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT, 'dedupe-rep1', NOW(), (SELECT auth_generation FROM push_accounts WHERE account_did = $1))
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

    let services_barrier = Arc::new(
        make_services(pool.clone(), auth_store.clone()).with_apns_sender(apns_barrier.clone()),
    );
    let state_barrier =
        make_test_app_state(pool.clone(), services_barrier.clone(), auth_store.clone()).await;

    let worker_handle = tokio::spawn({
        let s = services_barrier.clone();
        let st = state_barrier.clone();
        async move { s.process_queue_batch(&st).await }
    });

    wait_for_test_barrier(&enter_barrier).await;

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

    wait_for_test_barrier(&exit_barrier).await;
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
                $3, '{}'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT, 'dedupe-rep2', NOW(), (SELECT auth_generation FROM push_accounts WHERE account_did = $1))
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
    let auth_store = test_db.auth_store.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(
        make_services(pool.clone(), auth_store.clone()).with_apns_sender(fake_apns.clone()),
    );
    let state = make_test_app_state(pool.clone(), services.clone(), auth_store.clone()).await;

    let recipient_did = "did:plc:user_stale_reauth_test";
    let token = "7777888899990000111122223333444477778888999900001111222233334444";
    let session = make_session(&auth_store, recipient_did).await;

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    register(&services, &auth_store, &session, &reg_input)
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

    // Enqueue under the current authorization epoch BEFORE logout.
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, 'did:plc:actor', 'like', 'bafy-cid-stale', 'app.bsky.feed.like/stale',
                '{}'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT, 'dedupe-stale', NOW(), (SELECT auth_generation FROM push_accounts WHERE account_did = $1))
        "#,
    )
    .bind(recipient_did)
    .execute(&pool)
    .await
    .unwrap();

    // User logs out, invalidating the previous authorization epoch.
    services
        .registry
        .mark_auth_revoked(recipient_did)
        .await
        .unwrap();

    // User logs in again, issuing a fresh authorization epoch and clearing revocation.
    let new_session = make_session(&auth_store, recipient_did).await;
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
    let auth_store = test_db.auth_store.clone();

    let mut config = PushConfig::default();
    config.service_did = Some("did:web:push.catbird.blue".to_string());
    config.max_active_devices_per_account = 2;
    config.max_inactive_devices_per_account = 3;
    config.max_fanout_per_notification = 2;
    let services = Arc::new(
        PushServices::new(pool.clone(), config)
            .unwrap()
            .with_auth_store(auth_store.clone()),
    );

    let did = "did:plc:quota_race_user";
    let concurrency = 10;
    let barrier = Arc::new(Barrier::new(concurrency));

    let mut handles = Vec::new();
    for i in 0..concurrency {
        let services = services.clone();
        let barrier = barrier.clone();
        let auth_store = auth_store.clone();
        let token = format!("quota_token_{:064}", i);

        handles.push(tokio::spawn(async move {
            let session = make_session(&auth_store, did).await;
            let input = RegisterPushInput {
                service_did: "did:web:push.catbird.blue".to_string(),
                token,
                platform: "ios".to_string(),
                app_id: "blue.catbird".to_string(),
                age_restricted: Some(false),
            };
            wait_for_test_barrier(&barrier).await;
            register(&services, &auth_store, &session, &input).await
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
    let auth_store = test_db.auth_store.clone();
    let services = make_services(pool.clone(), auth_store.clone());

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
    let session = make_session(&auth_store, recipient_did).await;
    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    register(&services, &auth_store, &session, &reg_input)
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

    let mut session_live = make_session(&auth_store, recipient_did).await;
    session_live.pds_url = mock_pds.uri();
    cleanup_auth::seed(&auth_store, &session_live).await;
    services
        .registry
        .activate_account_session(
            recipient_did,
            &session_live.id.to_string(),
            &session_live.pds_url,
        )
        .await
        .unwrap();
    let state =
        make_test_app_state(pool.clone(), Arc::new(services.clone()), auth_store.clone()).await;

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
    let auth_store = test_db.auth_store.clone();
    let queue = make_services(pool.clone(), auth_store.clone()).queue;

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
    let auth_store = test_db.auth_store.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(
        make_services(pool.clone(), auth_store.clone()).with_apns_sender(fake_apns.clone()),
    );
    let state = make_test_app_state(pool.clone(), services.clone(), auth_store.clone()).await;

    let recipient_did = "did:plc:mid_poll_reauth_user";
    let token = "1111222233334444555566667777888811112222333344445555666677778888";
    let session_1 = make_session(&auth_store, recipient_did).await;

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    register(&services, &auth_store, &session_1, &reg_input)
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
    assert!(
        captured_gen > 0,
        "Initial account generation must be issued"
    );
    // Phase-2 writers (the default) store only the non-replayable fingerprint, never the bearer.
    assert_eq!(
        captured_session_id,
        catbird::services::push::registry::session_fingerprint(&session_1.id.to_string())
    );
    assert_ne!(captured_session_id, session_1.id.to_string());

    // Mid-poll: user logs out and re-authenticates with a new session while network call is in flight
    services
        .registry
        .mark_auth_revoked(recipient_did)
        .await
        .unwrap();
    let session_2 = make_session(&auth_store, recipient_did).await;
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
    assert!(
        current_gen > captured_gen,
        "Reauth must issue a newer generation"
    );

    // Network call completes using the authorization epoch captured before the call.
    let chat_event = catbird::services::chat_poll::types::ChatPushEvent {
        recipient_did: recipient_did.to_string(),
        sender_did: "did:plc:chat_sender".to_string(),
        convo_id: "convo_123".to_string(),
        message_id: "msg_456".to_string(),
        message_text: "Hello from old session".to_string(),
        // Keep this event fresh so the source-age hold cannot mask the
        // authorization-generation fence this regression is exercising.
        sent_at: Utc::now().to_rfc3339(),
        auth_generation: captured_gen,
        log_rev: Some("0000000000003".to_string()),
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
    let auth_store = test_db.auth_store.clone();

    let fake_apns = Arc::new(ObservingFakeApns::new());
    let services = Arc::new(
        make_services(pool.clone(), auth_store.clone()).with_apns_sender(fake_apns.clone()),
    );
    let state = make_test_app_state(pool.clone(), services.clone(), auth_store.clone()).await;

    let recipient_did = "did:plc:firehose_reauth_user";
    let token = "5555666677778888999900001111222255556666777788889999000011112222";
    let session = make_session(&auth_store, recipient_did).await;

    let reg_input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".to_string(),
        token: token.to_string(),
        platform: "ios".to_string(),
        app_id: "blue.catbird".to_string(),
        age_restricted: Some(false),
    };
    register(&services, &auth_store, &session, &reg_input)
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
    assert!(producing_gen > 0);

    // Firehose enqueues the candidate with its explicitly captured authorization epoch.
    sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did, actor_did, notification_type, event_cid, event_path,
            event_record_json, event_timestamp, dedupe_key, available_at, auth_generation
        )
        VALUES ($1, 'did:plc:firehose_actor', 'like', 'bafy-firehose-1', 'app.bsky.feed.like/1',
                '{}'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT, 'dedupe-firehose-1', NOW(), $2)
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
    assert_eq!(stored_gen, producing_gen);

    // User logs out and re-authenticates, invalidating the captured epoch.
    services
        .registry
        .mark_auth_revoked(recipient_did)
        .await
        .unwrap();
    let session_2 = make_session(&auth_store, recipient_did).await;
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

/// A completed provider response can wait behind account erasure and a fresh
/// login after the send transaction has released its lock. Exercise the real
/// guarded outcome writers against that ordering, using real SQL and Redis.
#[tokio::test]
async fn late_apns_outcome_preserves_fresh_same_token_registration() {
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();
    let auth_store = test_db.auth_store.clone();
    let services = Arc::new(make_services(pool.clone(), auth_store.clone()));
    let did = "did:plc:lateapnsfixture";
    let token = "ab".repeat(32);
    let input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".into(),
        token: token.clone(),
        platform: "ios".into(),
        app_id: "blue.catbird".into(),
        age_restricted: Some(false),
    };
    let old = make_session(&auth_store, did).await;
    register(&services, &auth_store, &old, &input)
        .await
        .unwrap();
    let old_device = services
        .registry
        .device_row_id(did, &token)
        .await
        .unwrap()
        .unwrap();
    let old_generation: i64 =
        sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    let captured = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let old_response = {
        let services = services.clone();
        let captured = captured.clone();
        let resume = resume.clone();
        let token = token.clone();
        tokio::spawn(async move {
            wait_for_test_barrier(&captured).await;
            wait_for_test_barrier(&resume).await;
            let environment_changed = services
                .registry
                .set_apns_environment_if_current(
                    did,
                    old_device,
                    &token,
                    old_generation,
                    "production",
                )
                .await
                .unwrap();
            let device_disabled = services
                .registry
                .deactivate_invalid_token_if_current(
                    did,
                    old_device,
                    &token,
                    old_generation,
                    "apns_unregistered",
                )
                .await
                .unwrap();
            (environment_changed, device_disabled)
        })
    };
    wait_for_test_barrier(&captured).await;
    // Synthetic erasure of this fixture's three populated account tables. The
    // production erasure inventory has separate all-table transaction fixtures.
    use jacquard_oauth::authstore::ClientAuthStore;
    let parsed_did: jacquard_common::types::did::Did =
        jacquard_common::types::did::Did::new_owned(did.to_string()).unwrap();
    auth_store
        .delete_session(&parsed_did, &old.id.to_string())
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    catbird::services::push::lock::acquire_account_lock(&mut tx, did)
        .await
        .unwrap();
    for query in [
        "DELETE FROM push_preferences WHERE account_did=$1",
        "DELETE FROM user_devices WHERE did=$1",
        "DELETE FROM push_accounts WHERE account_did=$1",
    ] {
        sqlx::query(query)
            .bind(did)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let fresh = make_session(&auth_store, did).await;
    register(&services, &auth_store, &fresh, &input)
        .await
        .unwrap();
    let new_device = services
        .registry
        .device_row_id(did, &token)
        .await
        .unwrap()
        .unwrap();
    let new_generation: i64 =
        sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_ne!(old_device, new_device);
    assert!(new_generation > old_generation);
    sqlx::query("INSERT INTO chat_poll_state(account_did,pds_host) VALUES($1,'fixture.invalid')")
        .bind(did)
        .execute(&pool)
        .await
        .unwrap();
    wait_for_test_barrier(&resume).await;
    assert_eq!(old_response.await.unwrap(), (false, false));
    // Each component of the captured identity is independently required.
    assert!(!services
        .registry
        .deactivate_invalid_token_if_current(
            did,
            old_device,
            &token,
            new_generation,
            "stale_device"
        )
        .await
        .unwrap());
    assert!(!services
        .registry
        .deactivate_invalid_token_if_current(did, new_device, &token, old_generation, "stale_epoch")
        .await
        .unwrap());
    let actual: (bool, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT is_active,apns_environment,last_error FROM user_devices WHERE id=$1",
    )
    .bind(new_device)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(actual, (true, None, None));
    let polling: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat_poll_state WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(polling, 1);
    assert!(services
        .registry
        .set_apns_environment_if_current(did, new_device, &token, new_generation, "sandbox")
        .await
        .unwrap());
    assert!(services
        .registry
        .deactivate_invalid_token_if_current(
            did,
            new_device,
            &token,
            new_generation,
            "apns_unregistered"
        )
        .await
        .unwrap());
    let polling: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat_poll_state WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        polling, 0,
        "current invalid token still unenrolls within the guarded transaction"
    );
}

/// A restore marker cannot be removed or promoted by ordinary preference edits,
/// and a marker written after decision evaluation is checked again before send.
#[tokio::test]
async fn restored_preferences_retry_and_survive_client_edits() {
    use catbird::services::push::decision::QueueDisposition;
    use catbird::services::push::types::PutPreferencesInput;
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();
    let auth_store = test_db.auth_store.clone();
    let fake = Arc::new(ObservingFakeApns::new());
    let services =
        Arc::new(make_services(pool.clone(), auth_store.clone()).with_apns_sender(fake.clone()));
    let state = make_test_app_state(pool.clone(), services.clone(), auth_store.clone()).await;
    let did = "did:plc:restoregatefixture";
    let actor = "did:plc:restoregateactor";
    let session = make_session(&auth_store, did).await;
    let input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".into(),
        token: "cd".repeat(32),
        platform: "ios".into(),
        app_id: "blue.catbird".into(),
        age_restricted: Some(false),
    };
    register(&services, &auth_store, &session, &input)
        .await
        .unwrap();
    let generation: i64 =
        sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("INSERT INTO actor_moderation_verdict(recipient_did,actor_did,verdict,display_label,generation) \
        SELECT account_did,$2,'{}'::jsonb,'Synthetic',moderation_generation FROM push_accounts WHERE account_did=$1")
        .bind(did).bind(actor).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO push_event_queue(recipient_did,actor_did,notification_type,event_cid,event_path,event_record_json,event_timestamp,dedupe_key,auth_generation) \
        VALUES($1,$2,'like','fixture-cid','app.bsky.feed.like/fixture','{}'::jsonb,$3,'fixture-restore-gate',$4)")
        .bind(did).bind(actor).bind(Utc::now().timestamp()).bind(generation).execute(&pool).await.unwrap();
    let row = services.queue.claim_ready(1).await.unwrap().pop().unwrap();
    assert!(matches!(
        services
            .decision
            .evaluate(&state, &services, &row)
            .await
            .unwrap(),
        QueueDisposition::Deliver(_)
    ));
    let metadata = json!({
        "version": 1, "source": "bluesky_login", "status": "Complete", "snapshotComplete": true,
        "automaticPushReady": false, "authGeneration": generation,
        "sourceStatus": {"actorPreferences":"Complete","notificationPreferences":"Complete","chatPreferences":"Complete","activitySubscriptions":"Complete","conversationMutes":"Complete","threadMutes":"Unsupported"},
        "blockers":["threadMuteStateUnavailable"],"unknown":["threadMutes"],"unsupported":["threadMutes"],
        "providerChatRequest":{"include":"all","push":true},
        "appliedStatus":{"activitySubscriptions":"Complete","conversationMutes":"Complete"}
    });
    let mut tx = pool.begin().await.unwrap();
    catbird::services::push::lock::acquire_account_lock(&mut tx, did)
        .await
        .unwrap();
    sqlx::query("UPDATE push_preferences SET preferences_json=jsonb_set(preferences_json,'{_catbirdRestore}',$2) WHERE account_did=$1")
        .bind(did).bind(&metadata).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        services
            .verify_pre_send_fence(
                did,
                actor,
                &input.token,
                "like",
                None,
                Some((row.id, row.lease_token.unwrap(), generation)),
                Some(generation)
            )
            .await
            .unwrap(),
        PreSendFenceOutcome::RestorePending
    );
    assert!(matches!(
        services
            .decision
            .evaluate(&state, &services, &row)
            .await
            .unwrap(),
        QueueDisposition::Retry("preferences_restore_required")
    ));

    // Neither a full typed replacement nor a client-supplied reserved key clears
    // the server marker. Exercise authenticated and internal typed writers.
    services
        .preferences
        .put_authenticated(
            &auth_store,
            did,
            &session.id.to_string(),
            &PushPreferencesDocument::default(),
        )
        .await
        .unwrap();
    let patch: PutPreferencesInput = serde_json::from_value(json!({"chat":{"include":"all","push":false},"_catbirdRestore":{"automaticPushReady":true}})).unwrap();
    services
        .preferences
        .patch_authenticated(&auth_store, did, &session.id.to_string(), Some(patch))
        .await
        .unwrap();
    services
        .preferences
        .put(did, &PushPreferencesDocument::default())
        .await
        .unwrap();
    services
        .preferences
        .patch(
            did,
            serde_json::from_value(json!({"chat":{"include":"all","push":true}})).unwrap(),
        )
        .await
        .unwrap();
    let preserved: serde_json::Value = sqlx::query_scalar(
        "SELECT preferences_json->'_catbirdRestore' FROM push_preferences WHERE account_did=$1",
    )
    .bind(did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(preserved, metadata);

    // Let the actual queue worker claim it again. Missing readiness must retain
    // retryable work with a reason and never reach the fake provider.
    sqlx::query("UPDATE push_event_queue SET leased_until=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(row.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(services.process_queue_batch(&state).await.unwrap(), 1);
    assert!(fake.sends.lock().await.is_empty());
    let retry: (Option<String>, Option<String>, bool, bool) = sqlx::query_as(
        "SELECT delivery_hold_reason,last_error,lease_token IS NULL,available_at>NOW() FROM push_event_queue WHERE id=$1",
    )
    .bind(row.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retry.0, None, "readiness must not create a durable hold");
    assert_eq!(retry.1.as_deref(), Some("preferences_restore_required"));
    assert!(retry.2 && retry.3, "retry releases its lease and backs off");
    assert_eq!(services.process_queue_batch(&state).await.unwrap(), 0);

    // Corrupt and unsupported readiness values stay blocked rather than falling
    // through serde's legacy defaults. No supported true writer exists yet.
    for marker in [
        serde_json::Value::Null,
        json!("bad"),
        json!({"automaticPushReady":true}),
        json!({"version":1,"source":"bluesky_login","snapshotComplete":true,"automaticPushReady":true,"authGeneration":generation}),
    ] {
        sqlx::query("UPDATE push_preferences SET preferences_json=jsonb_set(preferences_json,'{_catbirdRestore}',$2) WHERE account_did=$1")
            .bind(did).bind(marker).execute(&pool).await.unwrap();
        assert!(services
            .preferences
            .get_for_delivery(did)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            services
                .verify_pre_send_fence(
                    did,
                    actor,
                    &input.token,
                    "like",
                    None,
                    None,
                    Some(generation)
                )
                .await
                .unwrap(),
            PreSendFenceOutcome::RestorePending
        );
    }
    sqlx::query("DELETE FROM push_preferences WHERE account_did=$1")
        .bind(did)
        .execute(&pool)
        .await
        .unwrap();
    assert!(services
        .preferences
        .put_authenticated(
            &auth_store,
            did,
            &session.id.to_string(),
            &PushPreferencesDocument::default()
        )
        .await
        .is_err());
    assert_eq!(
        services
            .verify_pre_send_fence(
                did,
                actor,
                &input.token,
                "like",
                None,
                None,
                Some(generation)
            )
            .await
            .unwrap(),
        PreSendFenceOutcome::RestorePending
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM push_preferences WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count, 0,
        "typed PUT cannot recreate permissive state after erasure"
    );
}

/// Actual queue/APNs execution is independent of the provider's push flag.
/// The provider endpoint is configured in both directions and must receive no
/// preference read or write; actor moderation is a current synthetic cache row.
#[tokio::test]
async fn explicit_catbird_consent_delivers_independently_and_rejects_old_source_events() {
    use catbird::services::push::decision::QueueDisposition;
    use catbird::services::push::types::PutPreferencesInput;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn enqueue(
        pool: &Pool<Postgres>,
        did: &str,
        actor: &str,
        generation: i64,
        key: &str,
        source_time: i64,
    ) -> i64 {
        sqlx::query_scalar("INSERT INTO push_event_queue(recipient_did,actor_did,notification_type,event_cid,event_path,event_record_json,event_timestamp,dedupe_key,auth_generation) VALUES($1,$2,'follow',$3,'app.bsky.graph.follow/fixture','{}'::jsonb,$4,$3,$5) RETURNING id")
            .bind(did).bind(actor).bind(key).bind(source_time).bind(generation)
            .fetch_one(pool).await.unwrap()
    }
    async fn choose(
        services: &PushServices,
        store: &catbird::services::RedisAuthStore,
        session: &CatbirdSession,
        input: serde_json::Value,
    ) {
        let input: PutPreferencesInput = serde_json::from_value(input).unwrap();
        services
            .preferences
            .patch_authenticated(store, &session.did, &session.id.to_string(), Some(input))
            .await
            .unwrap();
    }

    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();
    let store = test_db.auth_store.clone();
    let provider = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.notification.getPreferences"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"preferences":{"follow":{"include":"all","list":true,"push":false}}}),
        ))
        .expect(0)
        .mount(&provider)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&provider)
        .await;
    let fake = Arc::new(ObservingFakeApns::new());
    let services =
        Arc::new(make_services(pool.clone(), store.clone()).with_apns_sender(fake.clone()));
    let state = make_test_app_state(pool.clone(), services.clone(), store.clone()).await;
    let did = "did:plc:independentconsent";
    let actor = "did:plc:independentactor";
    let mut session = make_session(&store, did).await;
    session.pds_url = provider.uri();
    cleanup_auth::seed(&store, &session).await;
    let registration = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".into(),
        token: "dc".repeat(32),
        platform: "ios".into(),
        app_id: "blue.catbird".into(),
        age_restricted: Some(false),
    };
    // Use production initialization, never the permissive legacy test helper.
    services
        .registry
        .upsert_registration(&session, &registration)
        .await
        .unwrap();
    catbird::services::login_apply::ensure_local_preferences(&pool, &store, &session)
        .await
        .unwrap();
    let generation: i64 =
        sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("INSERT INTO actor_moderation_verdict(recipient_did,actor_did,verdict,display_label,generation) SELECT account_did,$2,'{}'::jsonb,'Synthetic',moderation_generation FROM push_accounts WHERE account_did=$1")
        .bind(did).bind(actor).execute(&pool).await.unwrap();
    let required_id = enqueue(
        &pool,
        did,
        actor,
        generation,
        "consent-required",
        Utc::now().timestamp() - 1,
    )
    .await;
    assert_eq!(services.process_queue_batch(&state).await.unwrap(), 1);
    let retry_state: (Option<String>, Option<String>, bool, bool) = sqlx::query_as(
        "SELECT delivery_hold_reason,last_error,lease_token IS NULL,available_at>NOW() FROM push_event_queue WHERE id=$1",
    )
    .bind(required_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        retry_state.0, None,
        "missing consent must remain reclaimable"
    );
    assert_eq!(
        retry_state.1.as_deref(),
        Some("preferences_restore_required")
    );
    assert!(
        retry_state.2 && retry_state.3,
        "retry releases its lease and schedules backoff"
    );
    assert!(fake.sends.lock().await.is_empty());

    // A metadata-only forgery cannot count as an explicit local choice.
    let forged: PutPreferencesInput = serde_json::from_value(json!({"_catbirdRestore":{"localConsent":"Configured","automaticPushReady":true,"consentSourceTime":1}})).unwrap();
    assert!(services
        .preferences
        .patch_authenticated(&store, did, &session.id.to_string(), Some(forged))
        .await
        .is_err());
    assert!(services
        .preferences
        .get_for_delivery(did)
        .await
        .unwrap()
        .is_none());
    let before: i64 =
        sqlx::query_scalar("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint")
            .fetch_one(&pool)
            .await
            .unwrap();
    choose(&services,&store,&session,json!({"follow":{"push":true},"_catbirdRestore":{"automaticPushReady":true,"consentSourceTime":1}})).await;
    let metadata: serde_json::Value = sqlx::query_scalar(
        "SELECT preferences_json->'_catbirdRestore' FROM push_preferences WHERE account_did=$1",
    )
    .bind(did)
    .fetch_one(&pool)
    .await
    .unwrap();
    let cutoff = metadata["consentSourceTime"].as_i64().unwrap();
    assert!(cutoff >= before);
    assert_eq!(metadata["localConsent"], "Configured");
    assert_eq!(metadata["automaticPushReady"], false);
    assert_eq!(metadata["authGeneration"], generation);
    let response =
        catbird::services::login_apply::ensure_local_preferences(&pool, &store, &session)
            .await
            .unwrap();
    let status = catbird::services::login_apply::setup_status_response(
        &response.body,
        services
            .preferences
            .get_for_delivery(did)
            .await
            .unwrap()
            .is_some(),
    );
    assert_eq!(status["status"], "configured");
    assert_eq!(status["deliveryScope"], "per_event");

    // Advance only this fixture's backoff. The worker must reclaim the same
    // consent-pending row after repair, then reject its original source time.
    // No global requeue or clearing of durable delivery holds is involved.
    sqlx::query("UPDATE push_event_queue SET available_at=NOW() WHERE id=$1")
        .bind(required_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(services.process_queue_batch(&state).await.unwrap(), 1);
    let pending_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM push_event_queue WHERE id=$1)")
            .bind(required_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !pending_exists,
        "repaired consent must reclaim and drop the pre-consent event"
    );
    assert!(fake.sends.lock().await.is_empty());

    enqueue(
        &pool,
        did,
        actor,
        generation,
        "provider-off-catbird-on",
        cutoff,
    )
    .await;
    assert_eq!(services.process_queue_batch(&state).await.unwrap(), 1);
    assert_eq!(
        fake.sends.lock().await.len(),
        1,
        "provider-off must not suppress an independently enabled Catbird follow"
    );
    let old_id = enqueue(
        &pool,
        did,
        actor,
        generation,
        "preconsent-replay",
        cutoff - 1,
    )
    .await;
    assert_eq!(services.process_queue_batch(&state).await.unwrap(), 1);
    let old_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM push_event_queue WHERE id=$1)")
            .bind(old_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !old_exists,
        "new enqueue time cannot revive a pre-consent source event"
    );
    assert_eq!(fake.sends.lock().await.len(), 1);

    // Decision uses its snapshot; the final fence must independently re-read
    // q.event_timestamp and the persisted consent under the shared account lock.
    enqueue(&pool, did, actor, generation, "late-source-fence", cutoff).await;
    let row = services.queue.claim_ready(1).await.unwrap().pop().unwrap();
    assert!(matches!(
        services
            .decision
            .evaluate(&state, &services, &row)
            .await
            .unwrap(),
        QueueDisposition::Deliver(_)
    ));
    sqlx::query("UPDATE push_event_queue SET event_timestamp=$2 WHERE id=$1")
        .bind(row.id)
        .bind(cutoff - 1)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        services
            .verify_pre_send_fence(
                did,
                actor,
                &registration.token,
                "follow",
                None,
                Some((row.id, row.lease_token.unwrap(), generation)),
                Some(generation)
            )
            .await
            .unwrap(),
        PreSendFenceOutcome::SourceEventBeforeConsent
    );
    sqlx::query("UPDATE push_event_queue SET leased_until=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(row.id)
        .execute(&pool)
        .await
        .unwrap();
    services.process_queue_batch(&state).await.unwrap();
    assert_eq!(fake.sends.lock().await.len(), 1);
    assert!(provider.received_requests().await.unwrap().is_empty());
    provider.verify().await;
    provider.reset().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.notification.getPreferences"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"preferences":{"follow":{"include":"all","list":true,"push":true}}}),
        ))
        .expect(0)
        .mount(&provider)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&provider)
        .await;
    choose(
        &services,
        &store,
        &session,
        json!({"follow":{"push":false}}),
    )
    .await;
    let preserved_cutoff: i64 = sqlx::query_scalar("SELECT (preferences_json->'_catbirdRestore'->>'consentSourceTime')::bigint FROM push_preferences WHERE account_did=$1").bind(did).fetch_one(&pool).await.unwrap();
    assert_eq!(
        preserved_cutoff, cutoff,
        "ordinary edits must not reset the replay boundary"
    );
    enqueue(
        &pool,
        did,
        actor,
        generation,
        "provider-on-catbird-off",
        cutoff,
    )
    .await;
    assert_eq!(services.process_queue_batch(&state).await.unwrap(), 1);
    assert_eq!(
        fake.sends.lock().await.len(),
        1,
        "provider-on must not enable independently disabled Catbird push"
    );

    choose(
        &services,
        &store,
        &session,
        json!({"follow":{"push":true,"include":"follows"}}),
    )
    .await;
    let follows_id = enqueue(
        &pool,
        did,
        actor,
        generation,
        "following-proof-required",
        cutoff,
    )
    .await;
    services.process_queue_batch(&state).await.unwrap();
    let reason: Option<String> =
        sqlx::query_scalar("SELECT delivery_hold_reason FROM push_event_queue WHERE id=$1")
            .bind(follows_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        reason, None,
        "unknown relationship evidence must retry, not become a permanent category hold"
    );
    assert_eq!(fake.sends.lock().await.len(), 1);
    sqlx::query("UPDATE actor_moderation_verdict SET verdict=jsonb_set(verdict,'{following}','false'),fetched_at=NOW() WHERE recipient_did=$1 AND actor_did=$2")
        .bind(did).bind(actor).execute(&pool).await.unwrap();
    sqlx::query("UPDATE push_event_queue SET available_at=NOW() WHERE id=$1")
        .bind(follows_id)
        .execute(&pool)
        .await
        .unwrap();
    services.process_queue_batch(&state).await.unwrap();
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM push_event_queue WHERE id=$1)")
            .bind(follows_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!exists, "verified not-following suppresses the event");
    assert_eq!(fake.sends.lock().await.len(), 1);
    // A second unknown-proof row must deliver after the proof is repaired,
    // without enqueueing a replacement notification or changing its cutoff.
    sqlx::query("UPDATE actor_moderation_verdict SET verdict=verdict-'following',fetched_at=NOW() WHERE recipient_did=$1 AND actor_did=$2")
        .bind(did).bind(actor).execute(&pool).await.unwrap();
    let repaired_id = enqueue(&pool, did, actor, generation, "repaired-following", cutoff).await;
    assert_eq!(services.process_queue_batch(&state).await.unwrap(), 1);
    let pending_hold: Option<String> =
        sqlx::query_scalar("SELECT delivery_hold_reason FROM push_event_queue WHERE id=$1")
            .bind(repaired_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pending_hold, None);
    assert_eq!(fake.sends.lock().await.len(), 1);
    sqlx::query("UPDATE actor_moderation_verdict SET verdict=jsonb_set(verdict,'{following}','true'),fetched_at=NOW() WHERE recipient_did=$1 AND actor_did=$2")
        .bind(did).bind(actor).execute(&pool).await.unwrap();
    sqlx::query("UPDATE push_event_queue SET available_at=NOW() WHERE id=$1")
        .bind(repaired_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(services.process_queue_batch(&state).await.unwrap(), 1);
    assert_eq!(
        fake.sends.lock().await.len(),
        2,
        "repaired following proof permits the same queued Catbird event"
    );
    let repaired_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM push_event_queue WHERE id=$1)")
            .bind(repaired_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!repaired_exists);
    assert!(
        provider.received_requests().await.unwrap().is_empty(),
        "Catbird choices must never read or write provider notification preferences"
    );
    provider.verify().await;
}

/// Account-level consent survives a second live device and nonfinal handover;
/// per-event authorization still rejects work captured under the previous epoch.
#[tokio::test]
async fn account_consent_survives_live_session_activation_and_handover() {
    use catbird::services::push::registry::session_fingerprint;
    use catbird::services::push::types::{PushAccountSignOut, PutPreferencesInput};
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();
    let store = test_db.auth_store.clone();
    let services = make_services(pool.clone(), store.clone());
    let did = "did:plc:accountconsentlife";
    let actor = "did:plc:accountconsentactor";
    let a = make_session(&store, did).await;
    let b = make_session(&store, did).await;
    let input_a = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".into(),
        token: "ca".repeat(32),
        platform: "ios".into(),
        app_id: "blue.catbird".into(),
        age_restricted: Some(false),
    };
    let input_b = RegisterPushInput {
        token: "cb".repeat(32),
        ..input_a.clone()
    };
    services
        .registry
        .upsert_registration(&a, &input_a)
        .await
        .unwrap();
    catbird::services::login_apply::ensure_local_preferences(&pool, &store, &a)
        .await
        .unwrap();
    let choice: PutPreferencesInput =
        serde_json::from_value(json!({"follow":{"push":true}})).unwrap();
    services
        .preferences
        .patch_authenticated(&store, did, &a.id.to_string(), Some(choice))
        .await
        .unwrap();
    let generation_a: i64 =
        sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    // Represent an already-established choice without sleeping. This distinct
    // past cutoff makes an accidental reset on B's later PUT observable.
    sqlx::query("UPDATE push_preferences SET preferences_json=jsonb_set(preferences_json,'{_catbirdRestore,consentSourceTime}',to_jsonb((preferences_json->'_catbirdRestore'->>'consentSourceTime')::bigint-60)) WHERE account_did=$1")
        .bind(did).execute(&pool).await.unwrap();
    let original: serde_json::Value =
        sqlx::query_scalar("SELECT preferences_json FROM push_preferences WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    let cutoff = original["_catbirdRestore"]["consentSourceTime"]
        .as_i64()
        .unwrap();
    sqlx::query("INSERT INTO actor_moderation_verdict(recipient_did,actor_did,verdict,display_label,generation) SELECT account_did,$2,'{}'::jsonb,'Synthetic',moderation_generation FROM push_accounts WHERE account_did=$1")
        .bind(did).bind(actor).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO push_event_queue(recipient_did,actor_did,notification_type,event_cid,event_path,event_record_json,event_timestamp,dedupe_key,auth_generation) VALUES($1,$2,'follow','before-b','app.bsky.graph.follow/lifetime','{}'::jsonb,$3,'before-b',$4)")
        .bind(did).bind(actor).bind(cutoff).bind(generation_a).execute(&pool).await.unwrap();
    let queued_a = services.queue.claim_ready(1).await.unwrap().pop().unwrap();

    services
        .registry
        .activate_account_session(did, &b.id.to_string(), &b.pds_url)
        .await
        .unwrap();
    services
        .registry
        .upsert_registration(&b, &input_b)
        .await
        .unwrap();
    let generation_b: i64 =
        sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(generation_b > generation_a);
    let after_activation: serde_json::Value =
        sqlx::query_scalar("SELECT preferences_json FROM push_preferences WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(after_activation, original);
    assert!(
        services
            .preferences
            .get_for_delivery(did)
            .await
            .unwrap()
            .unwrap()
            .follow
            .push,
        "a legitimate B login must preserve A's account consent"
    );
    assert_eq!(
        services
            .verify_pre_send_fence(
                did,
                actor,
                &input_a.token,
                "follow",
                None,
                Some((queued_a.id, queued_a.lease_token.unwrap(), generation_a)),
                Some(generation_b)
            )
            .await
            .unwrap(),
        PreSendFenceOutcome::Revoked,
        "old queued epoch remains independently fenced"
    );

    let choice: PutPreferencesInput =
        serde_json::from_value(json!({"follow":{"push":true}})).unwrap();
    services
        .preferences
        .patch_authenticated(&store, did, &b.id.to_string(), Some(choice))
        .await
        .unwrap();
    let after_edit: serde_json::Value =
        sqlx::query_scalar("SELECT preferences_json FROM push_preferences WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut expected = original.clone();
    expected["_catbirdRestore"]["authGeneration"] = json!(generation_b);
    assert_eq!(
        after_edit, expected,
        "explicit PUT updates provenance but preserves choices and the original account cutoff"
    );

    // Simulate the coordinator's irreversible local retirement boundary, then
    // invoke its actual SQL/device-cleanup effect. A is still a verified live
    // device owner, so B's nonfinal departure hands the account back to A.
    let mut conn = store.redis_connection();
    let _: () = redis::cmd("SET")
        .arg(store.retired_key(&b.id.to_string()))
        .arg("synthetic-logout")
        .arg("EX")
        .arg(store.retired_ttl())
        .query_async(&mut conn)
        .await
        .unwrap();
    let outcome = services
        .registry
        .cleanup_retired_session(did, &session_fingerprint(&b.id.to_string()))
        .await
        .unwrap();
    assert_eq!(outcome.account, PushAccountSignOut::HandedOver);
    let generation_handover: i64 =
        sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(generation_handover > generation_b);
    let after_handover: serde_json::Value =
        sqlx::query_scalar("SELECT preferences_json FROM push_preferences WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(after_handover, after_edit);
    assert!(
        services
            .preferences
            .get_for_delivery(did)
            .await
            .unwrap()
            .unwrap()
            .follow
            .push
    );
    assert_eq!(
        after_handover["_catbirdRestore"]["consentSourceTime"],
        cutoff
    );
    let fresh_id: i64 = sqlx::query_scalar("INSERT INTO push_event_queue(recipient_did,actor_did,notification_type,event_cid,event_path,event_record_json,event_timestamp,dedupe_key,auth_generation) VALUES($1,$2,'follow','after-handover','app.bsky.graph.follow/lifetime','{}'::jsonb,$3,'after-handover',$4) RETURNING id")
        .bind(did).bind(actor).bind(cutoff).bind(generation_handover).fetch_one(&pool).await.unwrap();
    let fresh = services
        .queue
        .claim_ready(10)
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.id == fresh_id)
        .unwrap();
    assert_eq!(
        services
            .verify_pre_send_fence(
                did,
                actor,
                &input_a.token,
                "follow",
                None,
                Some((fresh.id, fresh.lease_token.unwrap(), generation_handover)),
                Some(generation_handover)
            )
            .await
            .unwrap(),
        PreSendFenceOutcome::Authorized,
        "retained consent still authorizes new work after handover"
    );
    let active_tokens: Vec<String> = sqlx::query_scalar("SELECT device_token FROM user_devices WHERE did=$1 AND is_active=TRUE ORDER BY device_token").bind(did).fetch_all(&pool).await.unwrap();
    assert_eq!(active_tokens, vec![input_a.token]);
}

#[tokio::test]
async fn reset_chat_uses_complete_empty_snapshot_and_prime_then_independent_push() {
    use catbird::services::chat_poll::scheduler::ChatPollScheduler;
    use catbird::services::push::types::PutPreferencesInput;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    async fn enqueue(
        pool: &Pool<Postgres>,
        did: &str,
        actor: &str,
        generation: i64,
        cutoff: i64,
        key: &str,
        convo: &str,
    ) -> i64 {
        sqlx::query_scalar("INSERT INTO push_event_queue(recipient_did,actor_did,notification_type,event_cid,event_path,event_record_json,event_timestamp,dedupe_key,auth_generation) VALUES($1,$2,'chat_message',$3,'chat.bsky.convo.getLog',$4,$5,$3,$6) RETURNING id")
            .bind(did).bind(actor).bind(key).bind(json!({"convoId":convo,"messageId":key,"logRev":key})).bind(cutoff).bind(generation).fetch_one(pool).await.unwrap()
    }
    let test_db = TestDb::new().await;
    test_db.run_hardening_migration().await;
    let pool = test_db.pool.clone();
    let store = test_db.auth_store.clone();
    let provider = MockServer::start().await;
    Mock::given(method("GET")).and(path("/xrpc/chat.bsky.notification.getPreferences"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"preferences":{"chat":{"include":"all","push":false},"chatRequest":{"include":"all","push":false}}}))).expect(0).mount(&provider).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&provider)
        .await;
    let fake = Arc::new(ObservingFakeApns::new());
    let services =
        Arc::new(make_services(pool.clone(), store.clone()).with_apns_sender(fake.clone()));
    let state = make_test_app_state(pool.clone(), services.clone(), store.clone()).await;
    let did = "did:plc:chatbootstrapfixture";
    let actor = "did:plc:chatbootstrapactor";
    let mut session = make_session(&store, did).await;
    session.pds_url = provider.uri();
    cleanup_auth::seed(&store, &session).await;
    let input = RegisterPushInput {
        service_did: "did:web:push.catbird.blue".into(),
        token: "ce".repeat(32),
        platform: "ios".into(),
        app_id: "blue.catbird".into(),
        age_restricted: Some(false),
    };
    services
        .registry
        .upsert_registration(&session, &input)
        .await
        .unwrap();
    catbird::services::login_apply::ensure_local_preferences(&pool, &store, &session)
        .await
        .unwrap();
    let choice: PutPreferencesInput =
        serde_json::from_value(json!({"chat":{"push":true,"include":"all"}})).unwrap();
    services
        .preferences
        .patch_authenticated(&store, did, &session.id.to_string(), Some(choice))
        .await
        .unwrap();
    let generation: i64 =
        sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did=$1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .unwrap();
    let cutoff:i64=sqlx::query_scalar("SELECT (preferences_json->'_catbirdRestore'->>'consentSourceTime')::bigint FROM push_preferences WHERE account_did=$1").bind(did).fetch_one(&pool).await.unwrap();
    sqlx::query("INSERT INTO actor_moderation_verdict(recipient_did,actor_did,verdict,display_label,generation) SELECT account_did,$2,'{}'::jsonb,'Synthetic',moderation_generation FROM push_accounts WHERE account_did=$1")
        .bind(did).bind(actor).execute(&pool).await.unwrap();
    let scheduler = ChatPollScheduler::new(pool.clone());
    scheduler
        .enroll_account_authenticated(&session, &store, "fixture.invalid")
        .await
        .unwrap();
    assert!(scheduler
        .needs_initial_mute_sync(did, generation)
        .await
        .unwrap());
    let pending = enqueue(
        &pool,
        did,
        actor,
        generation,
        cutoff,
        "chat-pending-bootstrap",
        "visible",
    )
    .await;
    services.process_queue_batch(&state).await.unwrap();
    assert!(fake.sends.lock().await.is_empty());
    let pending_state: (Option<String>, Option<String>) =
        sqlx::query_as("SELECT delivery_hold_reason,last_error FROM push_event_queue WHERE id=$1")
            .bind(pending)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pending_state.0, None);
    assert!(pending_state.1.unwrap().contains("chat_bootstrap_pending"));
    // This is the production complete-snapshot commit seam; no completion is
    // stamped by missing, partial, stale or ordinary local-mutation input.
    assert!(!scheduler
        .sync_muted_convos_fenced(did, &[], 0, generation + 1)
        .await
        .unwrap());
    assert!(scheduler
        .needs_initial_mute_sync(did, generation)
        .await
        .unwrap());
    assert!(scheduler
        .sync_muted_convos_fenced(did, &[], 0, generation)
        .await
        .unwrap());
    assert!(!scheduler
        .needs_initial_mute_sync(did, generation)
        .await
        .unwrap());
    let snapshot:serde_json::Value=sqlx::query_scalar("SELECT preferences_json->'_catbirdRestore'->'chatMuteSnapshot' FROM push_preferences WHERE account_did=$1").bind(did).fetch_one(&pool).await.unwrap();
    assert_eq!(snapshot["authGeneration"], generation);
    assert_eq!(snapshot["muteGeneration"], 1);
    assert!(snapshot["completedAt"].as_i64().unwrap() > 0);
    // Complete mute knowledge alone cannot authorize unprimed chat.
    sqlx::query("UPDATE push_event_queue SET available_at=NOW() WHERE id=$1")
        .bind(pending)
        .execute(&pool)
        .await
        .unwrap();
    services.process_queue_batch(&state).await.unwrap();
    assert!(fake.sends.lock().await.is_empty());
    // Existing task-4 prime transaction fixtures prove silent log priming; this
    // worker fixture independently tests the persisted completion prerequisite.
    scheduler.mark_primed(did).await.unwrap();
    sqlx::query("UPDATE push_event_queue SET available_at=NOW() WHERE id=$1")
        .bind(pending)
        .execute(&pool)
        .await
        .unwrap();
    services.process_queue_batch(&state).await.unwrap();
    assert_eq!(
        fake.sends.lock().await.len(),
        1,
        "provider chat push off must not veto Catbird on"
    );
    // A known mutation maintains completeness while still changing the final
    // mute veto. It must not pause unrelated conversations until periodic sync.
    scheduler
        .set_convo_muted_authenticated(&session, &store, "muted", true)
        .await
        .unwrap();
    assert!(!scheduler
        .needs_initial_mute_sync(did, generation)
        .await
        .unwrap());
    enqueue(&pool, did, actor, generation, cutoff, "chat-muted", "muted").await;
    services.process_queue_batch(&state).await.unwrap();
    assert_eq!(fake.sends.lock().await.len(), 1);
    let before = scheduler.mute_generation(did).await.unwrap();
    assert!(!scheduler
        .sync_muted_convos_fenced(did, &[], before - 1, generation)
        .await
        .unwrap());
    assert!(scheduler.is_convo_muted(did, "muted").await.unwrap());
    let late = enqueue(
        &pool,
        did,
        actor,
        generation,
        cutoff,
        "chat-late-read",
        "visible",
    )
    .await;
    let row = services.queue.claim_ready(1).await.unwrap().pop().unwrap();
    assert_eq!(row.id, late);
    sqlx::query("INSERT INTO chat_notified_watermarks(account_did,convo_id,last_rev,last_read_rev) VALUES($1,'visible','chat-late-read','chat-late-read') ON CONFLICT(account_did,convo_id) DO UPDATE SET last_read_rev=EXCLUDED.last_read_rev")
        .bind(did).execute(&pool).await.unwrap();
    assert_eq!(
        services
            .verify_pre_send_fence(
                did,
                actor,
                &input.token,
                "chat_message",
                None,
                Some((row.id, row.lease_token.unwrap(), generation)),
                Some(generation)
            )
            .await
            .unwrap(),
        PreSendFenceOutcome::ChatRead
    );
    services
        .queue
        .delete_fenced(row.id, row.lease_token.unwrap(), row.lease_version)
        .await
        .unwrap();
    provider.verify().await;
    assert!(provider.received_requests().await.unwrap().is_empty());
    provider.reset().await;
    Mock::given(method("GET")).and(path("/xrpc/chat.bsky.notification.getPreferences"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"preferences":{"chat":{"include":"all","push":true},"chatRequest":{"include":"all","push":true}}}))).expect(0).mount(&provider).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&provider)
        .await;
    let choice: PutPreferencesInput =
        serde_json::from_value(json!({"chat":{"push":false}})).unwrap();
    services
        .preferences
        .patch_authenticated(&store, did, &session.id.to_string(), Some(choice))
        .await
        .unwrap();
    enqueue(
        &pool,
        did,
        actor,
        generation,
        cutoff,
        "chat-provider-on-catbird-off",
        "other",
    )
    .await;
    services.process_queue_batch(&state).await.unwrap();
    assert_eq!(fake.sends.lock().await.len(), 1);
    assert!(provider.received_requests().await.unwrap().is_empty());
    provider.verify().await;
}
