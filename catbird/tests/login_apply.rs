//! Independent Catbird notification setup against disposable PostgreSQL + Redis.
#[path = "support/cleanup_auth.rs"]
mod cleanup_auth;
use catbird::{
    models::CatbirdSession,
    services::{
        login_apply::ensure_local_preferences,
        push::{
            preferences::PushPreferences,
            subscriptions::PushSubscriptions,
            types::{ActivitySubscriptionPreference, PushPreferencesDocument, PutPreferencesInput},
        },
        RedisAuthStore,
    },
};
use jacquard_oauth::authstore::ClientAuthStore;
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    store: RedisAuthStore,
    session: CatbirdSession,
}
impl Fixture {
    async fn new() -> Self {
        let redis_url =
            cleanup_auth::disposable_url("TASK7_ACCOUNT_CLEANUP_FIXTURE_REDIS_URL", "redis", 6379);
        let pg_url = cleanup_auth::disposable_url(
            "TASK7_ACCOUNT_CLEANUP_FIXTURE_DATABASE_URL",
            "postgres",
            5432,
        );
        let parsed = url::Url::parse(&pg_url).unwrap();
        assert_eq!(parsed.username(), "lite_push_test");
        assert!(parsed.path().starts_with("/task7_"));
        let nonce = Uuid::new_v4().simple().to_string();
        let schema = format!("login_apply_{nonce}");
        let admin = PgPool::connect(&pg_url).await.unwrap();
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&admin)
            .await
            .unwrap();
        let search_path = format!("SET search_path TO \"{schema}\"");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .after_connect(move |connection, _| {
                let statement = search_path.clone();
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&pg_url)
            .await
            .unwrap();
        for statement in [
            "CREATE TABLE push_accounts(account_did text PRIMARY KEY,auth_generation bigint NOT NULL,auth_revoked_at timestamptz)",
            "CREATE TABLE push_preferences(account_did text PRIMARY KEY,preferences_json jsonb NOT NULL,created_at timestamptz,updated_at timestamptz)",
            "CREATE TABLE activity_subscriptions(subscriber_did text,subject_did text,include_posts boolean,include_replies boolean,created_at timestamptz,updated_at timestamptz,PRIMARY KEY(subscriber_did,subject_did))",
        ] {sqlx::query(statement).execute(&pool).await.unwrap();}
        // Delivery-policy reads include chat readiness even for social choices.
        // Use the actual chat schema so this fixture follows that dependency.
        for migration in [
            include_str!("../migrations/20260402000000_chat_poll.up.sql"),
            include_str!("../migrations/20260706000000_chat_watermarks.up.sql"),
            include_str!("../migrations/20260706000001_chat_poll_primed.up.sql"),
            include_str!("../migrations/20261002000100_chat_poll_catchup_hold.up.sql"),
        ] {
            sqlx::raw_sql(migration).execute(&pool).await.unwrap();
        }
        let connection =
            redis::aio::ConnectionManager::new(redis::Client::open(redis_url).unwrap())
                .await
                .unwrap();
        let store = RedisAuthStore::from_key(
            connection,
            format!("task7:v2:login_apply_{nonce}:"),
            3600,
            cleanup_auth::KEY,
        )
        .unwrap();
        let session = CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:syntheticloginrestore".into(),
            handle: "synthetic.test".into(),
            pds_url: "http://127.0.0.1:9".into(),
            access_token: "synthetic".into(),
            refresh_token: "synthetic".into(),
            scopes: vec!["atproto".into()],
            access_token_expires_at: chrono::Utc::now() + chrono::Duration::minutes(30),
            created_at: chrono::Utc::now(),
            last_used_at: chrono::Utc::now(),
            granted_scopes: vec!["atproto".into()],
        };
        store
            .upsert_session(cleanup_auth::grant(
                &session.did,
                &session.id.to_string(),
                &session.pds_url,
            ))
            .await
            .unwrap();
        sqlx::query("INSERT INTO push_accounts(account_did,auth_generation) VALUES($1,7)")
            .bind(&session.did)
            .execute(&pool)
            .await
            .unwrap();
        Self {
            admin,
            pool,
            schema,
            store,
            session,
        }
    }
    async fn count(&self, table: &str) -> i64 {
        assert!([
            "push_preferences",
            "activity_subscriptions",
            "chat_muted_convos"
        ]
        .contains(&table));
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn finish(self) {
        let raw = self.session.id.to_string();
        let keys = vec![
            self.store.session_key(&self.session.did, &raw),
            self.store.session_index_key(&raw),
            self.store.session_fp_index_key(
                &catbird::services::push::registry::session_fingerprint(&raw),
            ),
            self.store.did_index_key(&self.session.did),
            self.store.retired_key(&raw),
            self.store.pending_upgrade_key(&raw),
        ];
        redis::cmd("DEL")
            .arg(keys)
            .query_async::<_, usize>(&mut self.store.redis_connection())
            .await
            .unwrap();
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}
async fn stored(fixture: &Fixture) -> Value {
    sqlx::query_scalar("SELECT preferences_json FROM push_preferences")
        .fetch_one(&fixture.pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires explicit disposable PostgreSQL and Redis"]
async fn official_push_true_false_or_offline_never_influences_local_setup_or_receives_requests() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for official_push in [Some(true), Some(false), None] {
        let requests = Arc::new(AtomicUsize::new(0));
        let mut fixture = Fixture::new().await;
        let server = if let Some(push) = official_push {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            fixture.session.pds_url = format!("http://{}", listener.local_addr().unwrap());
            let observed = requests.clone();
            Some(tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    observed.fetch_add(1, Ordering::SeqCst);
                    let mut input = [0u8; 4096];
                    let _ = stream.read(&mut input).await;
                    let body = json!({"preferences":{"like":{"list":true,"push":push,"include":"all"},"chat":{"include":"all","push":push}}}).to_string();
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body);
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            }))
        } else {
            None
        };
        let response = ensure_local_preferences(&fixture.pool, &fixture.store, &fixture.session)
            .await
            .unwrap();
        assert!(response.ready);
        for (category, value) in response.body["preferences"].as_object().unwrap() {
            assert_eq!(
                value["push"], false,
                "{category}; official={official_push:?}"
            );
        }
        assert_eq!(response.body["restoreStatus"]["source"], "catbird_local");
        assert_eq!(response.body["restoreStatus"]["localConsent"], "Required");
        assert_eq!(response.body["restoreStatus"]["automaticPushReady"], false);
        assert_eq!(fixture.count("activity_subscriptions").await, 0);
        assert_eq!(fixture.count("chat_muted_convos").await, 0);
        assert!(stored(&fixture).await["_catbirdRestore"]
            .get("providerChatRequest")
            .is_none());
        assert_eq!(
            requests.load(Ordering::SeqCst),
            0,
            "setup must make no provider GET or write"
        );
        if let Some(server) = server {
            server.abort();
        }
        fixture.finish().await;
    }
}

#[tokio::test]
#[ignore = "requires explicit disposable PostgreSQL and Redis"]
async fn explicit_local_choices_work_offline_and_metadata_or_omissions_cannot_consent() {
    let fixture = Fixture::new().await; // Provider endpoint is deliberately unavailable.
    ensure_local_preferences(&fixture.pool, &fixture.store, &fixture.session)
        .await
        .unwrap();
    let preferences = PushPreferences::new(fixture.pool.clone());
    for raw in [
        json!({}),
        json!({"_catbirdRestore":{"localConsent":"Configured","automaticPushReady":true}}),
        json!({"unknownCategory":{"push":true}}),
    ] {
        let input: PutPreferencesInput = serde_json::from_value(raw).unwrap();
        assert!(preferences
            .patch_authenticated(
                &fixture.store,
                &fixture.session.did,
                &fixture.session.id.to_string(),
                Some(input)
            )
            .await
            .is_err());
    }
    assert_eq!(
        stored(&fixture).await["_catbirdRestore"]["localConsent"],
        "Required"
    );
    for raw in [
        json!({"like":{}}),
        json!({"chat":{"include":"all"}}),
        json!({"verified":{"list":false}}),
        json!({"reply":{"push":null}}),
    ] {
        assert!(serde_json::from_value::<PutPreferencesInput>(raw).is_err());
    }
    let input = serde_json::from_value(
        json!({"like":{"push":true},"_catbirdRestore":{"automaticPushReady":true}}),
    )
    .unwrap();
    let first = preferences
        .patch_authenticated(
            &fixture.store,
            &fixture.session.did,
            &fixture.session.id.to_string(),
            Some(input),
        )
        .await
        .unwrap();
    assert!(first.like.push);
    assert!(!first.reply.push);
    assert!(!first.chat.push);
    let metadata = stored(&fixture).await["_catbirdRestore"].clone();
    assert_eq!(metadata["localConsent"], "Configured");
    assert_eq!(metadata["automaticPushReady"], false);
    let deliverable = preferences
        .get_for_delivery(&fixture.session.did)
        .await
        .unwrap()
        .expect("configured local choices permit the independently guarded delivery lane");
    assert!(deliverable.like.push);
    assert!(!deliverable.reply.push);
    let status = catbird::services::login_apply::setup_status_response(
        &json!({"preferences": first.to_lexicon_json(), "restoreStatus": metadata}),
        true,
    );
    assert_eq!(status["status"], "configured");
    assert_eq!(status["deliveryScope"], "per_event");
    assert_eq!(status["choicesConfigured"], true);
    assert_eq!(status["heldCategories"], json!([]));
    assert_eq!(status["heldConditions"], json!([]));
    let input =
        serde_json::from_value(json!({"reply":{"push":false,"include":"follows","list":false}}))
            .unwrap();
    preferences
        .patch_authenticated(
            &fixture.store,
            &fixture.session.did,
            &fixture.session.id.to_string(),
            Some(input),
        )
        .await
        .unwrap();
    let input =
        serde_json::from_value(json!({"reply":{"push":true},"like":{"push":false}})).unwrap();
    let updated = preferences
        .patch_authenticated(
            &fixture.store,
            &fixture.session.did,
            &fixture.session.id.to_string(),
            Some(input),
        )
        .await
        .unwrap();
    assert!(updated.reply.push);
    assert_eq!(updated.reply.include, "follows");
    assert!(!updated.reply.list);
    assert!(!updated.like.push);
    assert!(!updated.chat.push);
    let invalid =
        serde_json::from_value(json!({"like":{"push":true,"include":"everyone"}})).unwrap();
    assert!(preferences
        .patch_authenticated(
            &fixture.store,
            &fixture.session.did,
            &fixture.session.id.to_string(),
            Some(invalid)
        )
        .await
        .is_err());
    let subscriptions = PushSubscriptions::new(fixture.pool.clone());
    assert!(subscriptions
        .list(&fixture.session.did)
        .await
        .unwrap()
        .is_empty());
    subscriptions
        .put_authenticated(
            &fixture.store,
            &fixture.session.id.to_string(),
            &fixture.session.did,
            "did:plc:localchoice",
            &ActivitySubscriptionPreference {
                post: true,
                reply: false,
            },
        )
        .await
        .unwrap();
    let rows = subscriptions.list(&fixture.session.did).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].subject_did, "did:plc:localchoice");
    assert!(rows[0].include_posts);
    assert!(!rows[0].include_replies);
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires explicit disposable PostgreSQL and Redis"]
async fn revoked_account_or_original_bearer_cannot_recreate_local_settings() {
    let fixture = Fixture::new().await;
    sqlx::query("UPDATE push_accounts SET auth_revoked_at=NOW()")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(
        ensure_local_preferences(&fixture.pool, &fixture.store, &fixture.session)
            .await
            .is_err()
    );
    assert_eq!(fixture.count("push_preferences").await, 0);
    sqlx::query("UPDATE push_accounts SET auth_revoked_at=NULL")
        .execute(&fixture.pool)
        .await
        .unwrap();
    fixture
        .store
        .delete_session(
            &jacquard_common::types::did::Did::new(fixture.session.did.as_str()).unwrap(),
            &fixture.session.id.to_string(),
        )
        .await
        .unwrap();
    assert!(
        ensure_local_preferences(&fixture.pool, &fixture.store, &fixture.session)
            .await
            .is_err()
    );
    assert_eq!(fixture.count("push_preferences").await, 0);
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires explicit disposable PostgreSQL and Redis"]
async fn existing_catbird_settings_and_local_subscription_mutes_are_unchanged() {
    let fixture = Fixture::new().await;
    let mut local = PushPreferencesDocument::default();
    local.reply.push = false;
    local.chat.push = false;
    local.like.list = false;
    let payload = json!(local);
    sqlx::query("INSERT INTO push_preferences(account_did,preferences_json) VALUES($1,$2)")
        .bind(&fixture.session.did)
        .bind(&payload)
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO activity_subscriptions(subscriber_did,subject_did,include_posts,include_replies) VALUES($1,'did:plc:existinglocal',FALSE,TRUE)")
        .bind(&fixture.session.did).execute(&fixture.pool).await.unwrap();
    sqlx::query("INSERT INTO chat_muted_convos(account_did,convo_id) VALUES($1,'existing-muted')")
        .bind(&fixture.session.did)
        .execute(&fixture.pool)
        .await
        .unwrap();
    let response = ensure_local_preferences(&fixture.pool, &fixture.store, &fixture.session)
        .await
        .unwrap();
    assert_eq!(response.body["preferences"]["reply"]["push"], false);
    assert_eq!(response.body["preferences"]["follow"]["push"], true);
    assert!(response.body.get("restoreStatus").is_none());
    assert_eq!(stored(&fixture).await, payload);
    assert_eq!(fixture.count("activity_subscriptions").await, 1);
    assert_eq!(fixture.count("chat_muted_convos").await, 1);
    assert!(PushPreferences::new(fixture.pool.clone())
        .get_for_delivery(&fixture.session.did)
        .await
        .unwrap()
        .is_some());
    fixture.finish().await;
}
