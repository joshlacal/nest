//! Original-bearer and generation barriers using fresh synthetic stores only.
#[path = "support/cleanup_auth.rs"]
mod cleanup_auth;

use catbird::{
    models::CatbirdSession,
    services::{
        chat_poll::scheduler::ChatPollScheduler,
        push::{
            lock::acquire_account_lock,
            preferences::PushPreferences,
            subscriptions::PushSubscriptions,
            thread_mutes::ThreadMuteStore,
            types::{ActivitySubscriptionPreference, PushPreferencesDocument},
        },
        RedisAuthStore,
    },
};
use jacquard_common::types::did::Did;
use jacquard_oauth::authstore::ClientAuthStore;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const DID: &str = "did:plc:tasksevenwriterfence";

fn session() -> CatbirdSession {
    let now = chrono::Utc::now();
    CatbirdSession {
        id: Uuid::new_v4(),
        did: DID.into(),
        handle: "fixture.invalid".into(),
        pds_url: "https://fixture.invalid".into(),
        access_token: "synthetic".into(),
        refresh_token: "synthetic".into(),
        scopes: vec!["atproto".into()],
        access_token_expires_at: now + chrono::Duration::hours(1),
        created_at: now,
        last_used_at: now,
        granted_scopes: vec!["atproto".into()],
    }
}

struct Fixture {
    pool: PgPool,
    admin: PgPool,
    name: String,
    store: Arc<RedisAuthStore>,
}
impl Fixture {
    async fn new() -> Self {
        let url = cleanup_auth::disposable_url("DATABASE_URL", "postgres", 5432);
        let admin = PgPool::connect(&url).await.unwrap();
        let name = format!("task7_writers_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&url).unwrap();
        url.set_path(&name);
        let pool = PgPool::connect(url.as_str()).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        Self {
            pool,
            admin,
            name,
            store: cleanup_auth::store().await,
        }
    }
    async fn finish(self) {
        self.pool.close().await;
        sqlx::query(&format!("DROP DATABASE \"{}\" WITH (FORCE)", self.name))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}

#[tokio::test]
#[ignore = "root-owned disposable PostgreSQL and Redis fixtures"]
async fn request_waiting_for_account_lock_cannot_change_preferences_after_retirement() {
    let f = Fixture::new().await;
    let old = session();
    cleanup_auth::seed(&f.store, &old).await;
    catbird::services::push::registry::PushRegistry::new(
        f.pool.clone(),
        "did:web:fixture.invalid".into(),
    )
    .with_auth_store(f.store.clone())
    .touch_account_session(&old)
    .await
    .unwrap();
    let mut initial = PushPreferencesDocument::default();
    initial.chat.push = false;
    PushPreferences::new(f.pool.clone())
        .put(DID, &initial)
        .await
        .unwrap();
    let mut lock = f.pool.begin().await.unwrap();
    acquire_account_lock(&mut lock, DID).await.unwrap();
    let prefs = PushPreferences::new(f.pool.clone());
    let store = f.store.clone();
    let bearer = old.id.to_string();
    let pending = tokio::spawn(async move {
        prefs
            .put_authenticated(&store, DID, &bearer, &PushPreferencesDocument::default())
            .await
    });
    // Retirement happens while the stale writer cannot yet hold its write lock.
    f.store
        .delete_session(&Did::new(DID).unwrap(), &old.id.to_string())
        .await
        .unwrap();
    lock.commit().await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(
        !PushPreferences::new(f.pool.clone())
            .get(DID)
            .await
            .unwrap()
            .unwrap()
            .chat
            .push
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "root-owned disposable PostgreSQL and Redis fixtures"]
async fn fresh_login_does_not_reauthorize_an_old_bearer_for_any_experience_writer() {
    let f = Fixture::new().await;
    let old = session();
    cleanup_auth::seed(&f.store, &old).await;
    f.store
        .delete_session(&Did::new(DID).unwrap(), &old.id.to_string())
        .await
        .unwrap();
    let fresh = session();
    cleanup_auth::seed(&f.store, &fresh).await;
    catbird::services::push::registry::PushRegistry::new(
        f.pool.clone(),
        "did:web:fixture.invalid".into(),
    )
    .with_auth_store(f.store.clone())
    .touch_account_session(&fresh)
    .await
    .unwrap();
    let prefs = PushPreferences::new(f.pool.clone());
    let mut restored = PushPreferencesDocument::default();
    restored.chat.push = false;
    prefs.put(DID, &restored).await.unwrap(); // explicit synthetic complete seed
    assert!(prefs
        .put_authenticated(
            &f.store,
            DID,
            &old.id.to_string(),
            &PushPreferencesDocument::default()
        )
        .await
        .is_err());
    let subs = PushSubscriptions::new(f.pool.clone());
    assert!(subs
        .put_authenticated(
            &f.store,
            &old.id.to_string(),
            DID,
            "did:plc:othersubject",
            &ActivitySubscriptionPreference {
                post: true,
                reply: false
            }
        )
        .await
        .is_err());
    assert!(ThreadMuteStore::new(f.pool.clone())
        .set_thread_mute_authenticated(
            &f.store,
            DID,
            &old.id.to_string(),
            "at://did:plc:othersubject/app.bsky.feed.post/fixture",
            true
        )
        .await
        .is_err());
    let scheduler = ChatPollScheduler::new(f.pool.clone());
    assert!(scheduler
        .enroll_account_authenticated(&old, &f.store, "fixture.invalid")
        .await
        .is_err());
    assert!(scheduler
        .set_convo_muted_authenticated(&old, &f.store, "fixture-convo", true)
        .await
        .is_err());
    assert!(scheduler
        .update_foreground_lease_authenticated(&old, &f.store, 90)
        .await
        .is_err());
    assert!(!prefs.get(DID).await.unwrap().unwrap().chat.push);
    assert!(subs.list(DID).await.unwrap().is_empty());
    prefs
        .put_authenticated(
            &f.store,
            DID,
            &fresh.id.to_string(),
            &PushPreferencesDocument::default(),
        )
        .await
        .unwrap();
    assert!(prefs.get(DID).await.unwrap().is_some());
    f.finish().await;
}

#[tokio::test]
#[ignore = "root-owned disposable PostgreSQL and Redis fixtures"]
async fn old_snapshot_cannot_match_a_new_account_after_mute_generation_is_erased() {
    let f = Fixture::new().await;
    let old_epoch = f.store.next_auth_generation().await.unwrap();
    let new_epoch = f.store.next_auth_generation().await.unwrap();
    assert!(new_epoch > old_epoch);
    sqlx::query("INSERT INTO push_accounts(account_did,session_id,pds_url,auth_generation) VALUES($1,'fixture','https://fixture.invalid',$2)").bind(DID).bind(new_epoch).execute(&f.pool).await.unwrap();
    let scheduler = ChatPollScheduler::new(f.pool.clone());
    assert!(!scheduler
        .sync_muted_convos_fenced(DID, &["old-private-convo".into()], 0, old_epoch)
        .await
        .unwrap());
    assert!(!scheduler
        .is_convo_muted(DID, "old-private-convo")
        .await
        .unwrap());
    assert!(scheduler
        .sync_muted_convos_fenced(DID, &["fresh-convo".into()], 0, new_epoch)
        .await
        .unwrap());
    assert!(scheduler.is_convo_muted(DID, "fresh-convo").await.unwrap());
    f.finish().await;
}

fn fixture_state(
    f: &Fixture,
    push: Arc<catbird::services::PushServices>,
) -> catbird::config::AppState {
    let mut config = catbird::config::AppConfig::test_default();
    config.redis.url = cleanup_auth::disposable_url("REDIS_URL", "redis", 6379);
    config.redis.key_prefix = f.store.key_prefix().into();
    catbird::config::AppState {
        config: Arc::new(config),
        http_client: reqwest::Client::new(),
        raw_http_client: reqwest::Client::new(),
        redis: f.store.redis_connection(),
        push_db: Some(f.pool.clone()),
        key_store: None,
        jacquard_client: None,
        catmos_jacquard_client: None,
        catmos_oauth_scopes: vec![],
        trusted_proxies: vec![],
        auth_store: Some(f.store.clone()),
        push: Some(push),
        dpop_nonce_cache: Arc::new(catbird::services::DpopNonceCache::new()),
        session_encryption_key: Some(cleanup_auth::KEY),
        active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
        rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
        session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        session_index_readiness: Arc::new(tokio::sync::Notify::new()),
    }
}

#[tokio::test]
#[ignore = "root-owned disposable PostgreSQL and Redis fixtures; no provider client"]
async fn real_coordinator_preserves_second_device_then_erases_last_session_experience() {
    use catbird::services::{
        logout_cleanup::{
            run_runtime_cleanup, CredentialRetention, LogoutRequest, UpstreamStatus, WorkStatus,
        },
        push::types::RegisterPushInput,
        PushServices,
    };
    let f = Fixture::new().await;
    let first = session();
    let second = session();
    cleanup_auth::seed(&f.store, &first).await;
    cleanup_auth::seed(&f.store, &second).await;
    let mut config = catbird::config::PushConfig::default();
    config.service_did = Some("did:web:push.fixture.test".into());
    config.apns.enabled = false;
    let push = Arc::new(
        PushServices::new(f.pool.clone(), config)
            .unwrap()
            .with_auth_store(f.store.clone()),
    );
    for (s, token) in [(&first, "first-device"), (&second, "second-device")] {
        push.registry
            .upsert_registration(
                s,
                &RegisterPushInput {
                    service_did: "did:web:push.fixture.test".into(),
                    token: token.into(),
                    platform: "ios".into(),
                    app_id: "blue.catbird.fixture".into(),
                    age_restricted: None,
                },
            )
            .await
            .unwrap();
    }
    push.preferences
        .put(DID, &PushPreferencesDocument::default())
        .await
        .unwrap();
    sqlx::query("INSERT INTO push_accounts(account_did,session_id,pds_url) VALUES('did:plc:untouchedotheraccount','synthetic','https://fixture.invalid')").execute(&f.pool).await.unwrap();
    let state = fixture_state(&f, push.clone());
    let first_result = run_runtime_cleanup(
        &state,
        &LogoutRequest::new(first.id.to_string(), CredentialRetention::Forbidden).unwrap(),
    )
    .await
    .unwrap();
    assert!(first_result.session_retired);
    assert_eq!(first_result.device_cleanup, WorkStatus::Complete);
    assert!(!first_result.account_cleanup.required);
    assert!(f
        .store
        .read_session_local(DID, &first.id.to_string())
        .await
        .unwrap()
        .is_none());
    assert!(f
        .store
        .read_session_local(DID, &second.id.to_string())
        .await
        .unwrap()
        .is_some());
    assert!(push.preferences.get(DID).await.unwrap().is_some());
    let active: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_devices WHERE did=$1 AND is_active")
            .bind(DID)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(active, 1);
    let last_request =
        LogoutRequest::new(second.id.to_string(), CredentialRetention::Forbidden).unwrap();
    let last_result = run_runtime_cleanup(&state, &last_request).await.unwrap();
    assert!(last_result.account_cleanup.required);
    assert_eq!(last_result.account_cleanup.status, WorkStatus::Complete);
    assert_eq!(last_result.device_cleanup, WorkStatus::Complete);
    // Deliberately no provider client: live-store erasure is separately confirmed,
    // but the response must never fabricate upstream revocation success.
    assert_eq!(last_result.upstream_revocation, UpstreamStatus::Unconfirmed);
    assert!(push.preferences.get(DID).await.unwrap().is_none());
    let owned: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_devices WHERE did=$1")
        .bind(DID)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(owned, 0);
    let account: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM push_accounts WHERE account_did=$1")
            .bind(DID)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(account, 0);
    let other: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM push_accounts WHERE account_did='did:plc:untouchedotheraccount'",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(other, 1);
    assert_eq!(
        run_runtime_cleanup(&state, &last_request).await.unwrap(),
        last_result
    );
    let fresh = session();
    cleanup_auth::seed(&f.store, &fresh).await;
    assert!(f
        .store
        .read_session_local(DID, &fresh.id.to_string())
        .await
        .unwrap()
        .is_some());
    assert!(push.preferences.get(DID).await.unwrap().is_none());
    drop(state);
    drop(push);
    f.finish().await;
}

/// Only explicit logout may erase. Session expiry, an upstream auth failure and
/// an account switch on the same device keep the account's Catbird experience,
/// and the next sign-in finds it intact.
#[tokio::test]
#[ignore = "root-owned disposable PostgreSQL and Redis fixtures"]
async fn expiry_auth_failure_and_account_switch_never_erase_account_experience() {
    use catbird::services::{
        login_apply::{ensure_local_preferences_with, NewAccountChoices},
        push::{registry::PushRegistry, types::RegisterPushInput, PushServices},
    };
    let f = Fixture::new().await;
    let expired = session();
    cleanup_auth::seed(&f.store, &expired).await;
    let mut config = catbird::config::PushConfig::default();
    config.service_did = Some("did:web:push.fixture.test".into());
    config.apns.enabled = false;
    let push = Arc::new(
        PushServices::new(f.pool.clone(), config)
            .unwrap()
            .with_auth_store(f.store.clone()),
    );
    let register = |token: &str| RegisterPushInput {
        service_did: "did:web:push.fixture.test".into(),
        token: token.into(),
        platform: "ios".into(),
        app_id: "blue.catbird.fixture".into(),
        age_restricted: None,
    };
    push.registry
        .upsert_registration(&expired, &register("shared-device"))
        .await
        .unwrap();
    let mut chosen = PushPreferencesDocument::default();
    chosen.like.push = false;
    push.preferences.put(DID, &chosen).await.unwrap();
    PushSubscriptions::new(f.pool.clone())
        .put(
            DID,
            "did:plc:keptsubject",
            &ActivitySubscriptionPreference {
                post: true,
                reply: false,
            },
        )
        .await
        .unwrap();

    // Account switch: another account registers the same device token.
    let mut other = session();
    other.did = "did:plc:switchedtoaccount".into();
    cleanup_auth::seed(&f.store, &other).await;
    push.registry
        .upsert_registration(&other, &register("shared-device"))
        .await
        .unwrap();
    // Upstream refresh failure for the original session, then TTL expiry of
    // its Redis session (no logout request is ever made).
    let registry = PushRegistry::new(f.pool.clone(), "did:web:fixture.invalid".into())
        .with_auth_store(f.store.clone());
    registry
        .mark_auth_revoked_if_session(DID, &expired.id.to_string())
        .await
        .unwrap();
    f.store
        .delete_session(&Did::new(DID).unwrap(), &expired.id.to_string())
        .await
        .unwrap();

    let kept = |table: &'static str, column: &'static str| {
        let pool = f.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table} WHERE {column}=$1"))
                .bind(DID)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(kept("push_preferences", "account_did").await, 1);
    assert_eq!(kept("activity_subscriptions", "subscriber_did").await, 1);
    assert_eq!(kept("push_accounts", "account_did").await, 1);
    assert_eq!(kept("user_devices", "did").await, 1);
    assert!(!push.preferences.get(DID).await.unwrap().unwrap().like.push);

    // Signing in again (the OAuth callback's activation) resumes with the
    // retained Catbird choices and clears the earlier auth failure.
    let fresh = session();
    cleanup_auth::seed(&f.store, &fresh).await;
    registry
        .activate_account_session(DID, &fresh.id.to_string(), &fresh.pds_url)
        .await
        .unwrap();
    push.registry
        .upsert_registration(&fresh, &register("shared-device"))
        .await
        .unwrap();
    for mode in [
        NewAccountChoices::CatbirdDefaults,
        NewAccountChoices::Required,
    ] {
        let response = ensure_local_preferences_with(&f.pool, &f.store, &fresh, mode)
            .await
            .unwrap();
        assert_eq!(response.body["preferences"]["like"]["push"], false);
        assert!(response.body.get("restoreStatus").is_none());
    }
    assert!(push
        .preferences
        .get_for_delivery(DID)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        PushSubscriptions::new(f.pool.clone())
            .list(DID)
            .await
            .unwrap()
            .len(),
        1
    );
    drop(push);
    f.finish().await;
}
