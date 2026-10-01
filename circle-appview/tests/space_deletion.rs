//! CIRCLES-04: a space host that answers getSpaceCredential with `SpaceDeleted`
//! makes the AppView purge every copy of that Circle and tombstone it, at every
//! credential exchange site (sweep, activation, request-path sync). No other
//! credential failure purges. A tombstoned Circle answers reads with the declared
//! `AccessRemoved`, and expired tombstones are purged by a scheduled task.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use circle_appview::access::{self, CredentialStore, SpaceLockManager};
use circle_appview::auth::{
    DidDocument, DidResolver, DidService, PublicKeyJwk, VerificationMethod,
};
use circle_appview::commit::CommitVerificationPolicy;
use circle_appview::config::{AppState, Config};
use circle_appview::error::AppError;
use circle_appview::oauth::UserOAuthSession;
use circle_appview::space_client::{
    MockSpaceHostTransport, SpaceAppAccess, SpaceClient, SpaceConfig, SpacePolicy,
};
use circle_appview::sync::{sweep_once, SyncEngine};

const OWNER_DID: &str = "did:plc:owner-space-deletion";
const BOB_DID: &str = "did:plc:bob-space-deletion";
const SPACE_URI: &str = "at://did:plc:owner-space-deletion/space/blue.catbird.circle/3l7deleted111";

struct Setup {
    state: AppState,
    mock_transport: Arc<MockSpaceHostTransport>,
}

fn register_did_doc(resolver: &DidResolver, did: &str, services: Vec<DidService>) {
    let key = SigningKey::random(&mut OsRng);
    let point = EncodedPoint::from(key.verifying_key());
    resolver.insert_cached(
        did.into(),
        DidDocument {
            id: did.into(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#atproto"),
                r#type: "JsonWebKey2020".into(),
                controller: did.into(),
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    y: Some(URL_SAFE_NO_PAD.encode(point.y().unwrap())),
                    kid: None,
                }),
                public_key_multibase: None,
            }],
            service: services,
        },
    );
}

async fn setup(pool: PgPool) -> Setup {
    std::env::set_var(
        "SESSION_ENCRYPTION_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: "did:web:circles.catbird.blue#atproto_circles".into(),
        plc_directory_url: "https://plc.directory".into(),
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: "did:web:circles.catbird.blue#atproto_circles".into(),
        push_signing_key_path: None,
        push_signing_key_hex: None,
        commit_verification_policy: CommitVerificationPolicy::default(),
    };
    let did_resolver = Arc::new(DidResolver::new(
        config.plc_directory_url.clone(),
        reqwest::Client::builder().no_proxy().build().unwrap(),
    ));
    register_did_doc(
        &did_resolver,
        OWNER_DID,
        vec![
            DidService {
                id: "#atproto_space_host".into(),
                r#type: "AtprotoSpaceHost".into(),
                service_endpoint: "https://space.owner.example".into(),
            },
            DidService {
                id: "#atproto_pds".into(),
                r#type: "AtprotoPersonalDataServer".into(),
                service_endpoint: "https://pds.owner.example".into(),
            },
        ],
    );
    register_did_doc(
        &did_resolver,
        BOB_DID,
        vec![DidService {
            id: "#atproto_pds".into(),
            r#type: "AtprotoPersonalDataServer".into(),
            service_endpoint: "https://pds.bob.example".into(),
        }],
    );

    let mock_transport = Arc::new(MockSpaceHostTransport::new());
    let state = AppState::with_services(
        config,
        pool.clone(),
        did_resolver,
        Arc::new(CredentialStore::new()),
        Arc::new(SpaceClient::with_transport(mock_transport.clone())),
        Arc::new(SpaceLockManager::new()),
    );

    // The AppView holds an OAuth session for the authority, so a credential
    // exchange actually reaches the (mock) space host.
    state
        .oauth_service
        .store_session(UserOAuthSession {
            user_did: OWNER_DID.into(),
            access_token: "owner-access-token".into(),
            refresh_token: None,
            token_endpoint: "https://pds.owner.example/oauth/token".into(),
            auth_server_iss: "https://pds.owner.example".into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: SigningKey::random(&mut OsRng),
        })
        .await
        .unwrap();

    Setup {
        state,
        mock_transport,
    }
}

async fn seed_active_circle(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at) VALUES ($1, '3l7deleted111', $2, 'Doomed Circle', now())",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO circle_member_cache (space_uri, member_did, can_read, can_write, cached_at) VALUES ($1, $2, true, true, now()), ($1, $3, true, true, now())",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(BOB_DID)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count) VALUES ($1, now(), 2)",
    )
    .bind(SPACE_URI)
    .execute(pool)
    .await
    .unwrap();
    let post = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7deletedpost");
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, 'cidowner', $2, $3, 'app.bsky.feed.post', '3l7deletedpost', $4, now())
        "#,
    )
    .bind(&post)
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(json!({"text": "soon gone", "createdAt": Utc::now().to_rfc3339()}))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
        VALUES ($1, $2, $3, $4, 'reply', $5, $6, false, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(OWNER_DID)
    .bind(SPACE_URI)
    .bind(BOB_DID)
    .bind(&post)
    .bind(format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.post/3l7bobreply"))
    .execute(pool)
    .await
    .unwrap();
}

async fn count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT count(*) FROM {table} WHERE space_uri = $1"
    ))
    .bind(SPACE_URI)
    .fetch_one(pool)
    .await
    .unwrap()
}

const PROJECTION_TABLES: [&str; 9] = [
    "circle_member_cache",
    "circle_member_cache_meta",
    "circle_records",
    "circle_likes",
    "circle_repo_sync_state",
    "circle_notifications",
    "circle_preferences",
    "circle_reports",
    "circle_rejections",
];

async fn tombstoned(pool: &PgPool) -> bool {
    let deleted: Option<Option<chrono::DateTime<Utc>>> =
        sqlx::query_scalar("SELECT deleted_at FROM circles WHERE space_uri = $1")
            .bind(SPACE_URI)
            .fetch_optional(pool)
            .await
            .unwrap();
    matches!(deleted, Some(Some(_)))
}

fn space_host_error(code: &str) -> Result<String, String> {
    Err(json!({"error": code, "message": "from the space host"}).to_string())
}

async fn assert_fully_purged(setup: &Setup, pool: &PgPool) {
    for table in PROJECTION_TABLES {
        assert_eq!(count(pool, table).await, 0, "{table} must be purged");
    }
    assert!(tombstoned(pool).await, "the Circle must be marked deleted");
    assert!(
        setup.state.credential_store.get(SPACE_URI).await.is_none(),
        "the space credential must be dropped"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn sweep_purges_circle_when_space_host_reports_space_deleted(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    seed_active_circle(&pool).await;
    setup
        .mock_transport
        .set_credential_response(SPACE_URI, space_host_error("SpaceDeleted"));

    let summary = sweep_once(&setup.state).await.unwrap();
    assert_eq!(summary.spaces_checked, 1);
    assert_eq!(summary.spaces_purged, 1);
    assert_eq!(summary.repos_failed, 0);
    assert_fully_purged(&setup, &pool).await;

    // Reads of the purged Circle surface the declared AccessRemoved (not
    // Forbidden or NotFound), which makes the device purge its caches.
    for viewer in [BOB_DID, OWNER_DID] {
        let err = access::check_member_access(&setup.state, SPACE_URI, viewer)
            .await
            .expect_err("a deleted Circle must not be readable");
        assert!(
            matches!(err, AppError::AccessRemoved(_)),
            "expected AccessRemoved for {viewer}, got {err:?}"
        );
    }

    // The next sweep no longer visits the tombstoned Circle.
    let summary = sweep_once(&setup.state).await.unwrap();
    assert_eq!(summary.spaces_checked, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn other_credential_failures_never_purge(pool: PgPool) {
    for code in ["UserNotAuthorized", "AppNotAuthorized", "SpaceNotFound"] {
        // sqlx::test gives one database; reset between cases.
        sqlx::query("DELETE FROM circles")
            .execute(&pool)
            .await
            .unwrap();
        let setup = setup(pool.clone()).await;
        seed_active_circle(&pool).await;
        setup
            .mock_transport
            .set_credential_response(SPACE_URI, space_host_error(code));

        let summary = sweep_once(&setup.state).await.unwrap();
        assert_eq!(summary.spaces_purged, 0, "{code} must not purge");
        assert_eq!(summary.repos_failed, 1, "{code} is an ordinary failure");
        assert!(!tombstoned(&pool).await, "{code} must not tombstone");
        assert_eq!(count(&pool, "circle_records").await, 1, "{code}");
        assert_eq!(count(&pool, "circle_member_cache").await, 2, "{code}");
        assert_eq!(count(&pool, "circle_notifications").await, 1, "{code}");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn request_path_sync_purges_on_space_deleted(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    seed_active_circle(&pool).await;
    setup
        .mock_transport
        .set_credential_response(SPACE_URI, space_host_error("SpaceDeleted"));

    let err = SyncEngine::new(&setup.state)
        .sync_repo(SPACE_URI, OWNER_DID)
        .await
        .expect_err("sync of a deleted space must fail");
    assert!(access::is_space_deleted(&err), "got {err:?}");
    assert_fully_purged(&setup, &pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn activation_of_a_deleted_space_purges_and_reports_access_removed(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    seed_active_circle(&pool).await;
    let client_id = setup.state.oauth_service.client_id.clone();
    setup.mock_transport.set_space_config(
        SPACE_URI,
        SpaceConfig {
            authority: OWNER_DID.into(),
            space_type: "blue.catbird.circle".into(),
            skey: "3l7deleted111".into(),
            app_access: SpaceAppAccess::AllowList(vec![client_id]),
            read_policy: SpacePolicy::MemberList,
            write_policy: SpacePolicy::MemberList,
            user_policy: None,
            name: None,
            description: None,
        },
    );
    setup
        .mock_transport
        .set_space_members(SPACE_URI, vec![OWNER_DID.into(), BOB_DID.into()]);
    setup
        .mock_transport
        .set_credential_response(SPACE_URI, space_host_error("SpaceDeleted"));

    let err = access::activate_circle(&setup.state, OWNER_DID, SPACE_URI)
        .await
        .expect_err("activating a deleted space must fail");
    assert!(
        matches!(err, AppError::AccessRemoved(_)),
        "expected AccessRemoved, got {err:?}"
    );
    assert_fully_purged(&setup, &pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn scheduled_tombstone_purge_removes_only_expired_tombstones(pool: PgPool) {
    for (space, age_days) in [("3l7expired111", 40), ("3l7recent1111", 1)] {
        sqlx::query(
            "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, deleted_at) VALUES ($1, $2, $3, 'Gone', now(), now() - make_interval(days => $4))",
        )
        .bind(format!("at://{OWNER_DID}/space/blue.catbird.circle/{space}"))
        .bind(space)
        .bind(OWNER_DID)
        .bind(age_days)
        .execute(&pool)
        .await
        .unwrap();
    }

    let (handle, shutdown) = circle_appview::spawn_tombstone_purge_task(
        pool.clone(),
        std::time::Duration::from_millis(20),
        circle_appview::TOMBSTONE_RETENTION_DAYS,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let remaining: Vec<String> = sqlx::query_scalar("SELECT circle_id FROM circles")
            .fetch_all(&pool)
            .await
            .unwrap();
        if remaining == vec!["3l7recent1111".to_string()] {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expired tombstone was not purged; remaining {remaining:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    shutdown.send(true).unwrap();
    handle.await.unwrap();
}
