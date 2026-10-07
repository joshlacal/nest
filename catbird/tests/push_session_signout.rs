//! Signing out one session ends only that session's notification access.
//!
//! Requires a local Postgres (`DATABASE_URL`, default `postgres://localhost/postgres`)
//! and Redis (`REDIS_URL`, default `redis://127.0.0.1:6379`); ignored otherwise.

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
use jacquard_oauth::authstore::ClientAuthStore;
use jacquard_oauth::session::{ClientSessionData, DpopClientData};
use jacquard_oauth::types::{OAuthTokenType, TokenSet};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

const DID: &str = "did:plc:signouttestaccount";

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

fn grant(session_id: &str) -> ClientSessionData {
    let did = jacquard_common::types::did::Did::new_owned(DID.to_string()).unwrap();
    let dpop_key: jose_jwk::Key = serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xFMTbKEBaGizdGlIUKEWx5q15odEB00stfg",
        "y": "x_daaqundbgUvJV358vRBgULGnpH7aRFZZDYyEiNg2g",
        "d": "jpsQnnGQmL-YxOmH1UmOBHg10OJ45DBTWh0n52qxzMQ"
    }))
    .unwrap();
    ClientSessionData {
        account_did: did.clone(),
        session_id: session_id.to_string().into(),
        host_url: jacquard_common::deps::fluent_uri::Uri::parse("https://pds.example.com")
            .unwrap()
            .to_owned(),
        authserver_url: "https://pds.example.com".to_string().into(),
        authserver_token_endpoint: "".into(),
        authserver_revocation_endpoint: None,
        scopes: jacquard_oauth::scopes::Scopes::new(smol_str::SmolStr::new_static("atproto"))
            .unwrap(),
        dpop_data: DpopClientData {
            dpop_key,
            dpop_authserver_nonce: "".into(),
            dpop_host_nonce: "".into(),
        },
        token_set: TokenSet {
            iss: "https://pds.example.com".to_string().into(),
            sub: did,
            aud: "https://pds.example.com".to_string().into(),
            scope: Some("atproto".into()),
            refresh_token: Some("refresh".into()),
            access_token: "access".into(),
            token_type: OAuthTokenType::DPoP,
            expires_at: None,
        },
        resolved_scopes: None,
    }
}

async fn redis_store() -> RedisAuthStore {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let conn = redis::aio::ConnectionManager::new(redis::Client::open(url).unwrap())
        .await
        .expect("redis");
    let prefix = format!("catbird:v2:test_signout_{}:", Uuid::new_v4().simple());
    RedisAuthStore::from_key(conn, prefix, 3600, [0x24u8; 32]).expect("auth store")
}

/// Signs in a session (live grant in Redis) and registers one device for it.
async fn sign_in_with_device(
    store: &RedisAuthStore,
    registry: &PushRegistry,
    token: &str,
) -> (CatbirdSession, Uuid) {
    let session = catbird_session();
    store
        .upsert_session(grant(&session.id.to_string()))
        .await
        .expect("install grant");
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
    session_devices::link(store, device, &session.id.to_string())
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
    let store = redis_store().await;
    let registry = PushRegistry::with_config(
        db.pool.clone(),
        &PushConfig {
            service_did: Some("did:web:push.catbird.blue".to_string()),
            ..PushConfig::default()
        },
    );

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

    // 3. The last session signs out: account push is revoked, user data is kept.
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
    assert_eq!(prefs, 1, "sign-out must not delete preferences");
}

#[tokio::test]
#[ignore = "requires local Postgres and Redis"]
async fn re_registered_device_belongs_to_the_newer_session() {
    let db = TestDb::new().await;
    let store = redis_store().await;
    let registry = PushRegistry::with_config(
        db.pool.clone(),
        &PushConfig {
            service_did: Some("did:web:push.catbird.blue".to_string()),
            ..PushConfig::default()
        },
    );
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
