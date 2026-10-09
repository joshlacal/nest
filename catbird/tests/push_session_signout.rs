//! Signing out one session ends only that session's notification access.
//!
//! Requires explicit disposable loopback PostgreSQL/Redis URLs and
//! LITE_PUSH_DISPOSABLE=1; ignored otherwise. Tests the device sign-out primitive;
//! the final-session account-erasure coordinator has separate integration tests.

use catbird::{
    config::PushConfig,
    models::CatbirdSession,
    services::{
        push::{
            registry::{session_fingerprint, PushRegistry},
            session_devices,
            types::{PushAccountSignOut, RegisterPushInput},
        },
        RedisAuthStore,
    },
};
use chrono::Utc;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[path = "support/cleanup_auth.rs"]
mod cleanup_auth;

const DID: &str = "did:plc:signouttestaccount";

struct TestDb {
    admin_pool: Pool<Postgres>,
    db_name: String,
    pool: Pool<Postgres>,
}

impl TestDb {
    async fn new() -> Self {
        let base_url = cleanup_auth::disposable_url("DATABASE_URL", "postgres", 5432);
        let admin_pool = Pool::<Postgres>::connect(&base_url)
            .await
            .expect("admin postgres");
        let db_name = format!("test_push_signout_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&admin_pool)
            .await
            .expect("create test database");
        let mut url = url::Url::parse(&base_url).unwrap();
        url.set_path(&db_name);
        let pool = Pool::<Postgres>::connect(url.as_str())
            .await
            .expect("test database");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations");
        Self {
            admin_pool,
            db_name,
            pool,
        }
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let admin_pool = self.admin_pool.clone();
        let db_name = self.db_name.clone();
        tokio::spawn(async move {
            let _ = sqlx::query(&format!(
                "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
            ))
            .execute(&admin_pool)
            .await;
        });
    }
}

fn catbird_session() -> CatbirdSession {
    let now = Utc::now();
    CatbirdSession {
        id: Uuid::new_v4(),
        did: DID.to_string(),
        handle: "user.test".to_string(),
        pds_url: "https://pds.example.com".to_string(),
        access_token: String::new(),
        refresh_token: String::new(),
        scopes: vec!["atproto".to_string()],
        access_token_expires_at: now + chrono::Duration::hours(1),
        created_at: now,
        last_used_at: now,
        granted_scopes: vec!["atproto".to_string()],
    }
}

/// Signs in a session (live grant in Redis) and registers one device for it.
async fn sign_in_with_device(
    store: &RedisAuthStore,
    registry: &PushRegistry,
    token: &str,
) -> (CatbirdSession, Uuid) {
    let session = catbird_session();
    cleanup_auth::seed(store, &session).await;
    registry
        .activate_account_session(DID, &session.id.to_string(), &session.pds_url)
        .await
        .expect("activate");
    registry
        .upsert_registration(
            &session,
            &RegisterPushInput {
                service_did: "did:web:push.catbird.blue".to_string(),
                token: token.to_string(),
                platform: "ios".to_string(),
                app_id: "blue.catbird".to_string(),
                age_restricted: Some(false),
            },
        )
        .await
        .expect("register");
    let device = registry
        .device_row_id(DID, token)
        .await
        .unwrap()
        .expect("device row");
    registry.link_device_session(DID,device,&session.id.to_string())
        .await
        .expect("link");
    (session, device)
}

async fn is_active(pool: &Pool<Postgres>, device: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_active FROM user_devices WHERE id = $1")
        .bind(device)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn push_account(pool: &Pool<Postgres>) -> (String, String, bool) {
    sqlx::query_as(
        "SELECT session_id, session_fingerprint, auth_revoked_at IS NOT NULL FROM push_accounts WHERE account_did = $1",
    )
    .bind(DID)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires local Postgres and Redis"]
async fn signing_out_one_session_keeps_other_devices_and_user_data() {
    let db = TestDb::new().await;
    let store = cleanup_auth::store().await;
    let registry = PushRegistry::with_config(
        db.pool.clone(),
        &PushConfig {
            service_did: Some("did:web:push.catbird.blue".to_string()),
            ..PushConfig::default()
        },
    )
    .with_auth_store(store.clone());

    // Phone signs in first, then the iPad; the iPad's session becomes the push session.
    let (phone, phone_device) =
        sign_in_with_device(&store, &registry, "aa".repeat(32).as_str()).await;
    let (ipad, ipad_device) =
        sign_in_with_device(&store, &registry, "bb".repeat(32).as_str()).await;
    sqlx::query("INSERT INTO push_preferences (account_did, preferences_json) VALUES ($1, '{\"mention\":true}'::jsonb) ON CONFLICT DO NOTHING")
        .bind(DID)
        .execute(&db.pool)
        .await
        .unwrap();
    let (stored_id, stored_fp, _) = push_account(&db.pool).await;
    assert_eq!(stored_fp, session_fingerprint(&ipad.id.to_string()));
    assert_eq!(
        stored_id, stored_fp,
        "push_accounts must never hold the raw session ID"
    );

    // 1. The phone (not the push session) signs out: only its device stops.
    let outcome =
        session_devices::sign_out_session(Some(&store), &registry, DID, &phone.id.to_string())
            .await
            .unwrap();
    assert_eq!(outcome.account, PushAccountSignOut::NotPushSession);
    assert_eq!(outcome.devices_deactivated, 1);
    assert!(!is_active(&db.pool, phone_device).await);
    assert!(is_active(&db.pool, ipad_device).await);
    assert!(
        !push_account(&db.pool).await.2,
        "account push must stay active"
    );

    // 2. The phone signs in again and becomes the push session; the iPad is still signed in.
    let (phone2, phone2_device) =
        sign_in_with_device(&store, &registry, "cc".repeat(32).as_str()).await;
    let outcome =
        session_devices::sign_out_session(Some(&store), &registry, DID, &phone2.id.to_string())
            .await
            .unwrap();
    assert_eq!(outcome.account, PushAccountSignOut::HandedOver);
    assert!(!is_active(&db.pool, phone2_device).await);
    assert!(is_active(&db.pool, ipad_device).await);
    let (stored_id, stored_fp, revoked) = push_account(&db.pool).await;
    assert!(!revoked, "the iPad keeps notifications");
    assert_eq!(stored_fp, session_fingerprint(&ipad.id.to_string()));
    assert_eq!(stored_id, stored_fp);

    // 3. This lower-level device primitive revokes push. Account erasure is
    // owned by the separately tested final-session cleanup coordinator.
    let outcome =
        session_devices::sign_out_session(Some(&store), &registry, DID, &ipad.id.to_string())
            .await
            .unwrap();
    assert_eq!(outcome.account, PushAccountSignOut::Revoked);
    assert!(!is_active(&db.pool, ipad_device).await);
    assert!(push_account(&db.pool).await.2);
    let prefs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM push_preferences WHERE account_did = $1")
            .bind(DID)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(
        prefs, 1,
        "device primitive leaves preferences for the account-erasure coordinator"
    );
}

#[tokio::test]
#[ignore = "requires local Postgres and Redis"]
async fn re_registered_device_belongs_to_the_newer_session() {
    let db = TestDb::new().await;
    let store = cleanup_auth::store().await;
    let registry = PushRegistry::with_config(
        db.pool.clone(),
        &PushConfig {
            service_did: Some("did:web:push.catbird.blue".to_string()),
            ..PushConfig::default()
        },
    )
    .with_auth_store(store.clone());
    let token = "dd".repeat(32);
    let (old, device) = sign_in_with_device(&store, &registry, &token).await;
    // Same device signs in again: the device link moves to the new session.
    let (_new, same_device) = sign_in_with_device(&store, &registry, &token).await;
    assert_eq!(device, same_device);

    let outcome =
        session_devices::sign_out_session(Some(&store), &registry, DID, &old.id.to_string())
            .await
            .unwrap();
    assert_eq!(
        outcome.devices_deactivated, 0,
        "the old session no longer owns the device"
    );
    assert_eq!(outcome.account, PushAccountSignOut::NotPushSession);
    assert!(is_active(&db.pool, device).await);
}

#[tokio::test]
#[ignore = "requires explicit disposable Postgres and Redis"]
async fn sql_device_owner_survives_expired_redis_links() {
    let db = TestDb::new().await;
    let store = cleanup_auth::store().await;
    let registry = PushRegistry::with_config(
        db.pool.clone(),
        &PushConfig {
            service_did: Some("did:web:push.catbird.blue".into()),
            ..PushConfig::default()
        },
    )
    .with_auth_store(store.clone());
    let (leaving, leaving_device) = sign_in_with_device(&store, &registry, &"aa".repeat(32)).await;
    let (_other, other_device) = sign_in_with_device(&store, &registry, &"bb".repeat(32)).await;
    let leaving_fp = session_fingerprint(&leaving.id.to_string());
    let mut conn = store.redis_connection();
    let _: () = redis::cmd("DEL")
        .arg(format!(
            "{}push_device_session:{leaving_device}",
            store.key_prefix()
        ))
        .arg(format!(
            "{}push_session_devices:{leaving_fp}",
            store.key_prefix()
        ))
        .query_async(&mut conn)
        .await
        .unwrap();
    let outcome = registry
        .cleanup_retired_session(DID, &leaving_fp)
        .await
        .unwrap();
    assert_eq!(outcome.devices_deactivated, 1);
    let remains: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_devices WHERE id=$1)")
            .bind(leaving_device)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(
        !remains,
        "logout removes the owned device and raw APNs token"
    );
    assert!(is_active(&db.pool, other_device).await);
}

#[tokio::test]
#[ignore = "requires explicit disposable Postgres and Redis"]
async fn legacy_active_device_without_verified_owner_is_incomplete() {
    let db = TestDb::new().await;
    let store = cleanup_auth::store().await;
    let registry = PushRegistry::with_config(
        db.pool.clone(),
        &PushConfig {
            service_did: Some("did:web:push.catbird.blue".into()),
            ..PushConfig::default()
        },
    )
    .with_auth_store(store.clone());
    let (leaving, device) = sign_in_with_device(&store, &registry, &"cc".repeat(32)).await;
    sqlx::query("UPDATE user_devices SET auth_session_fingerprint = NULL WHERE id = $1")
        .bind(device)
        .execute(&db.pool)
        .await
        .unwrap();
    let mut conn = store.redis_connection();
    let _: () = redis::cmd("DEL")
        .arg(format!(
            "{}push_device_session:{device}",
            store.key_prefix()
        ))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(registry
        .cleanup_retired_session(DID, &session_fingerprint(&leaving.id.to_string()))
        .await
        .is_err());
    assert!(
        is_active(&db.pool, device).await,
        "unknown ownership must not be guessed"
    );
}

#[tokio::test]
#[ignore = "requires explicit disposable Postgres and Redis"]
async fn upgraded_session_keeps_its_device_ownership_when_another_session_owns_push() {
    use catbird::services::logout_cleanup::{CleanupStore, CredentialRetention, LogoutRequest, RedisCleanupStore};
    use jacquard_oauth::authstore::ClientAuthStore;
    let db=TestDb::new().await;
    let store=cleanup_auth::store().await;
    let registry=PushRegistry::with_config(db.pool.clone(),&PushConfig {
        service_did:Some("did:web:push.catbird.blue".into()),..PushConfig::default()
    }).with_auth_store(store.clone());
    let a_token="ab".repeat(32);
    let (a,a_device)=sign_in_with_device(&store,&registry,&a_token).await;
    // A second device represents a pre-migration registration: SQL has no
    // owner, but the current reverse link proves this exact old bearer.
    let legacy_token="cd".repeat(32);
    registry.upsert_registration(&a,&RegisterPushInput {
        service_did:"did:web:push.catbird.blue".into(),token:legacy_token.clone(),platform:"ios".into(),
        app_id:"blue.catbird".into(),age_restricted:Some(false),
    }).await.unwrap();
    let legacy_device=registry.device_row_id(DID,&legacy_token).await.unwrap().unwrap();
    session_devices::link(&store,legacy_device,&a.id.to_string()).await.unwrap();
    sqlx::query("UPDATE user_devices SET auth_session_fingerprint=NULL WHERE id=$1")
        .bind(legacy_device).execute(&db.pool).await.unwrap();
    let (b,b_device)=sign_in_with_device(&store,&registry,&"bc".repeat(32)).await;
    let successor=catbird_session();
    cleanup_auth::seed(&store,&successor).await;
    let a_id=a.id.to_string();let successor_id=successor.id.to_string();
    let old_fp=session_fingerprint(&a_id);let new_fp=session_fingerprint(&successor_id);
    // Model the successful local upgrade-commit boundary: the candidate is live
    // and the old bearer is irreversibly retired. No provider calls are made.
    let parsed_did=jacquard_common::types::did::Did::new(DID).unwrap();
    store.delete_session(&parsed_did,&a_id).await.unwrap();
    let mut conn=store.redis_connection();
    let _:()=redis::cmd("SET").arg(store.retired_key(&a_id)).arg(store.fingerprint(&successor_id))
        .arg("EX").arg(store.retired_ttl()).query_async(&mut conn).await.unwrap();
    assert!(registry.link_device_session(DID,a_device,&b.id.to_string()).await.is_err(),
        "delayed B link cannot overwrite A's current SQL ownership");
    // Reproduce a stale link left by an older writer before the new guard. The
    // locked SQL owner is sufficient to repair it without inheriting B's device.
    let b_fp=session_fingerprint(&b.id.to_string());
    let _:()=redis::pipe().cmd("SET").arg(format!("{}push_device_session:{a_device}",store.key_prefix())).arg(&b_fp).ignore()
        .cmd("SADD").arg(format!("{}push_session_devices:{b_fp}",store.key_prefix())).arg(a_device.to_string()).ignore()
        .query_async(&mut conn).await.unwrap();
    assert_eq!(registry.replace_account_session(DID,&a_id,&successor_id).await.unwrap(),0,
        "B owns the account pointer; device migration must not depend on changing it");
    let b_kept:bool=redis::cmd("SISMEMBER").arg(format!("{}push_session_devices:{b_fp}",store.key_prefix())).arg(b_device.to_string()).query_async(&mut conn).await.unwrap();assert!(b_kept);
    let a_removed:bool=redis::cmd("SISMEMBER").arg(format!("{}push_session_devices:{b_fp}",store.key_prefix())).arg(a_device.to_string()).query_async(&mut conn).await.unwrap();assert!(!a_removed);
    assert!(registry.link_device_session(DID,a_device,&b.id.to_string()).await.is_err(),"B remains unable to overwrite successor SQL ownership");
    assert_eq!(push_account(&db.pool).await.1,session_fingerprint(&b.id.to_string()));
    let owner:String=sqlx::query_scalar("SELECT auth_session_fingerprint FROM user_devices WHERE id=$1")
        .bind(a_device).fetch_one(&db.pool).await.unwrap();assert_eq!(owner,new_fp);
    let legacy_owner:String=sqlx::query_scalar("SELECT auth_session_fingerprint FROM user_devices WHERE id=$1")
        .bind(legacy_device).fetch_one(&db.pool).await.unwrap();assert_eq!(legacy_owner,new_fp);
    let legacy_link:String=redis::cmd("GET").arg(format!("{}push_device_session:{legacy_device}",store.key_prefix())).query_async(&mut conn).await.unwrap();assert_eq!(legacy_link,new_fp);
    let b_owner:String=sqlx::query_scalar("SELECT auth_session_fingerprint FROM user_devices WHERE id=$1")
        .bind(b_device).fetch_one(&db.pool).await.unwrap();assert_eq!(b_owner,session_fingerprint(&b.id.to_string()));
    let link:String=redis::cmd("GET").arg(format!("{}push_device_session:{a_device}",store.key_prefix())).query_async(&mut conn).await.unwrap();assert_eq!(link,new_fp);
    let stale_member:bool=redis::cmd("SISMEMBER").arg(format!("{}push_session_devices:{old_fp}",store.key_prefix())).arg(a_device.to_string()).query_async(&mut conn).await.unwrap();assert!(!stale_member);
    // A repeat receipt repairs a missing link although the account CAS is still
    // a no-op and SQL device ownership already moved on the first attempt.
    let _:()=redis::cmd("DEL").arg(format!("{}push_device_session:{a_device}",store.key_prefix())).query_async(&mut conn).await.unwrap();
    assert_eq!(registry.replace_account_session(DID,&a_id,&successor_id).await.unwrap(),0);
    let link:String=redis::cmd("GET").arg(format!("{}push_device_session:{a_device}",store.key_prefix())).query_async(&mut conn).await.unwrap();assert_eq!(link,new_fp);
    // The old bearer cannot re-register or relink the migrated device.
    assert!(registry.upsert_registration(&a,&RegisterPushInput {
        service_did:"did:web:push.catbird.blue".into(),token:a_token,platform:"ios".into(),
        app_id:"blue.catbird".into(),age_restricted:Some(false),
    }).await.is_err());
    assert!(session_devices::link(&store,a_device,&a_id).await.is_err());
    let request=LogoutRequest::new(successor_id.clone(),CredentialRetention::Forbidden).unwrap();
    let attempt=RedisCleanupStore {store:&store}.begin_or_resume(&request,chrono::Utc::now().timestamp()).await.unwrap();
    assert!(!attempt.journal.account_cleanup.required,"B remains locally live");
    let outcome=registry.cleanup_retired_session(DID,&new_fp).await.unwrap();assert_eq!(outcome.devices_deactivated,2);
    let a_remains:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_devices WHERE id=$1)")
        .bind(a_device).fetch_one(&db.pool).await.unwrap();assert!(!a_remains);
    let legacy_remains:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_devices WHERE id=$1)")
        .bind(legacy_device).fetch_one(&db.pool).await.unwrap();assert!(!legacy_remains);
    assert!(is_active(&db.pool,b_device).await);
    assert!(store.read_session_local(DID,&b.id.to_string()).await.unwrap().is_some());
    let old_link:bool=redis::cmd("EXISTS").arg(format!("{}push_device_session:{a_device}",store.key_prefix())).query_async(&mut conn).await.unwrap();assert!(!old_link);
    assert!(registry.replace_account_session(DID,&a_id,&successor_id).await.is_err(),"retired successor cannot be reopened by stale commit retry");
}


#[tokio::test]
#[ignore = "requires explicit disposable Postgres and Redis"]
async fn interrupted_upgrade_transfer_cannot_claim_candidate_device_cleanup_complete() {
    use catbird::services::logout_cleanup::{run_cleanup,CleanupEffects,CleanupTarget,CredentialRetention,LogoutRequest,RedisCleanupStore,WorkFailure,WorkStatus,Completion};
    use catbird::services::revocation::RevokeOutcome;
    use jacquard_oauth::{authstore::ClientAuthStore,session::ClientSessionData};
    struct Effects<'a>(&'a PushRegistry);
    #[async_trait::async_trait]
    impl CleanupEffects for Effects<'_> {
        async fn stop_devices(&self,target:&CleanupTarget)->Result<(),WorkFailure> {
            self.0.cleanup_retired_session(&target.did,&target.session_fingerprint).await
                .map(|_|()).map_err(|_|WorkFailure::Retryable)
        }
        async fn erase_account(&self,_:&CleanupTarget,_:Uuid)->Result<(),WorkFailure> {panic!("B is still live")}
        async fn revoke(&self,_:&mut ClientSessionData,_:Uuid)->RevokeOutcome {panic!("shared-grant revocation must be deferred")}
    }
    let db=TestDb::new().await;let store=cleanup_auth::store().await;
    let registry=PushRegistry::with_config(db.pool.clone(),&PushConfig {
        service_did:Some("did:web:push.catbird.blue".into()),..PushConfig::default()
    }).with_auth_store(store.clone());
    let (a,a_device)=sign_in_with_device(&store,&registry,&"de".repeat(32)).await;
    let (b,b_device)=sign_in_with_device(&store,&registry,&"ef".repeat(32)).await;
    let successor=catbird_session();cleanup_auth::seed(&store,&successor).await;
    let did=jacquard_common::types::did::Did::new(DID).unwrap();
    store.delete_session(&did,&a.id.to_string()).await.unwrap();
    let mut conn=store.redis_connection();
    let _:()=redis::cmd("SET").arg(store.retired_key(&a.id.to_string())).arg(store.fingerprint(&successor.id.to_string()))
        .arg("EX").arg(store.retired_ttl()).query_async(&mut conn).await.unwrap();
    // Simulate interruption after Redis commit but before SQL ownership transfer.
    let request=LogoutRequest::new(successor.id.to_string(),CredentialRetention::Forbidden).unwrap();
    let response=run_cleanup(&RedisCleanupStore {store:&store},&Effects(&registry),&request,chrono::Utc::now().timestamp()).await.unwrap();
    assert!(response.session_retired);
    assert!(!response.account_cleanup.required);
    assert_eq!(response.device_cleanup,WorkStatus::Pending);
    assert_ne!(response.completion,Completion::Complete);
    assert!(is_active(&db.pool,a_device).await,"unproven predecessor ownership is reported incomplete, never guessed");
    assert!(is_active(&db.pool,b_device).await);
    assert!(store.read_session_local(DID,&b.id.to_string()).await.unwrap().is_some());
}
