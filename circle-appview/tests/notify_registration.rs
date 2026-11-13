//! Nov-12 notification registration, token authentication, and catch-up behavior.

mod support;

use std::sync::Arc;

use axum::{body::to_bytes, extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use chrono::{Duration, Utc};
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng, EncodedPoint};
use serde_json::{json, Value};
use sqlx::PgPool;

use circle_appview::{
    access::{ActiveSpaceCredential, CredentialStore, SpaceLockManager},
    auth::{DidDocument, DidResolver, DidService, PublicKeyJwk, VerificationMethod},
    config::{AppState, Config},
    db,
    error::{AppError, AuthReason},
    notify::{self, ConfirmRegistrationInput, NotifyRegistration},
    oauth::UserOAuthSession,
    space_client::{
        ListWritersOutput, MockSpaceHostTransport, RepoRemoved, RepoWrite, SpaceClient,
        WriterUpdate,
    },
    sync,
};

const OWNER_DID: &str = "did:plc:owner-notify-registration";
const MEMBER_DID: &str = "did:plc:member-notify-registration";
const SPACE_URI: &str =
    "at://did:plc:owner-notify-registration/space/blue.catbird.circle/3l7notifyreg1";
const SPACE_HOST: &str = "https://space.owner.example";

struct Setup {
    state: AppState,
    transport: Arc<MockSpaceHostTransport>,
}

fn config() -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: "did:web:circles.catbird.blue#atproto_circles".into(),
        plc_directory_url: "https://plc.directory".into(),
        identity_relay_url: Some(url::Url::parse("wss://relay.fixture.example.com/").unwrap()),
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: "did:web:circles.catbird.blue#atproto_circles".into(),
        push_signing_key_path: None,
        push_signing_key_hex: None,
    }
}

async fn setup(pool: PgPool) -> Setup {
    support::healthy_identity_fixture(&pool, &[OWNER_DID, MEMBER_DID]).await;
    std::env::set_var(
        "SESSION_ENCRYPTION_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );

    let config = config();
    let resolver = Arc::new(DidResolver::new(
        config.plc_directory_url.clone(),
        reqwest::Client::builder().no_proxy().build().unwrap(),
    ));
    let authority_key = SigningKey::random(&mut OsRng);
    let point = EncodedPoint::from(authority_key.verifying_key());
    resolver.insert_cached(
        OWNER_DID.into(),
        DidDocument {
            id: OWNER_DID.into(),
            verification_method: vec![VerificationMethod {
                id: format!("{OWNER_DID}#atproto"),
                r#type: "JsonWebKey2020".into(),
                controller: OWNER_DID.into(),
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    y: Some(URL_SAFE_NO_PAD.encode(point.y().unwrap())),
                    kid: None,
                }),
                public_key_multibase: None,
            }],
            service: vec![
                DidService {
                    id: "#atproto_space_host".into(),
                    r#type: "AtprotoSpaceHost".into(),
                    service_endpoint: SPACE_HOST.into(),
                },
                DidService {
                    id: "#atproto_pds".into(),
                    r#type: "AtprotoPersonalDataServer".into(),
                    service_endpoint: "https://pds.owner.example".into(),
                },
            ],
        },
    );

    let transport = Arc::new(MockSpaceHostTransport::new());
    transport.set_authority_signing_key(OWNER_DID, authority_key);
    let credential_store = Arc::new(CredentialStore::new());
    credential_store
        .insert(
            SPACE_URI.into(),
            ActiveSpaceCredential {
                token: "existing-space-credential".into(),
                signing_key: SigningKey::random(&mut OsRng),
                expires_at: Utc::now() + Duration::hours(1),
            },
        )
        .await;
    let state = AppState::with_services(
        config,
        pool.clone(),
        resolver,
        credential_store,
        Arc::new(SpaceClient::with_transport(transport.clone())),
        Arc::new(SpaceLockManager::new()),
    );
    state
        .oauth_service
        .store_session(UserOAuthSession {
            user_did: OWNER_DID.into(),
            access_token: "owner-access-token".into(),
            refresh_token: None,
            token_endpoint: "https://pds.owner.example/oauth/token".into(),
            auth_server_iss: "https://pds.owner.example".into(),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: SigningKey::random(&mut OsRng),
        })
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at) VALUES ($1, '3l7notifyreg1', $2, 'Notify Circle', now())",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO circle_member_cache (space_uri, member_did, can_read, can_write, cached_at) VALUES ($1, $2, true, true, now()), ($1, $3, true, true, now())",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(MEMBER_DID)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count) VALUES ($1, now(), 2)",
    )
    .bind(SPACE_URI)
    .execute(&pool)
    .await
    .unwrap();

    Setup { state, transport }
}

async fn registration(pool: &PgPool) -> NotifyRegistration {
    notify::get_or_create_registration(pool, SPACE_URI, "http://127.0.0.1:3002")
        .await
        .unwrap()
}

async fn send_update(state: &AppState, token: &str, update: Value) -> Result<StatusCode, AppError> {
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "space": SPACE_URI,
            "token": token,
            "update": update,
        }))
        .unwrap(),
    );
    sync::notify_space_update_handler(State(state.clone()), body)
        .await
        .map(|response| response.status())
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_is_stable_and_confirmation_authenticates_token(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    let first = registration(&pool).await;
    let second = notify::get_or_create_registration(&pool, SPACE_URI, "https://new.example")
        .await
        .unwrap();
    assert_eq!(
        first.token, second.token,
        "endpoint changes must not rotate tokens"
    );
    assert_eq!(second.endpoint, "https://new.example");

    let Json(output) = notify::confirm_registration_handler(
        State(setup.state.clone()),
        Json(ConfirmRegistrationInput {
            space: SPACE_URI.into(),
            token: first.token.clone(),
            challenge: "host-challenge".into(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(output, json!({"challenge": "host-challenge"}));

    let mut rejections = Vec::new();
    for (space, token) in [
        (SPACE_URI, "wrong-token"),
        ("at://did:plc:missing/space/x/y", first.token.as_str()),
    ] {
        let error = notify::confirm_registration_handler(
            State(setup.state.clone()),
            Json(ConfirmRegistrationInput {
                space: space.into(),
                token: token.into(),
                challenge: "challenge".into(),
            }),
        )
        .await
        .expect_err("unknown registration or token must be rejected");
        assert!(matches!(
            &error,
            AppError::Unauthorized(AuthReason::InvalidToken)
        ));
        rejections.push(error.into_response());
    }
    assert!(rejections
        .iter()
        .all(|response| response.status() == StatusCode::UNAUTHORIZED));
    let unknown = rejections.pop().unwrap();
    let wrong = rejections.pop().unwrap();
    assert_eq!(
        to_bytes(wrong.into_body(), usize::MAX).await.unwrap(),
        to_bytes(unknown.into_body(), usize::MAX).await.unwrap(),
        "unknown spaces and wrong tokens must disclose the same response"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn repo_write_requires_token_and_records_revision_gap(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    let registration = registration(&pool).await;
    notify::checkpoint(&pool, SPACE_URI, "3l7checkpoint1")
        .await
        .unwrap();
    let update = serde_json::to_value(WriterUpdate::RepoWrite(RepoWrite {
        repo: MEMBER_DID.into(),
        repo_rev: "3l7reporev2".into(),
        data: Bytes::from(vec![7; 32]),
        space_rev: "3l7spacerev2".into(),
        prev_space_rev: Some("3l7missedrev".into()),
    }))
    .unwrap();

    let error = send_update(&setup.state, "wrong-token", update.clone())
        .await
        .expect_err("wrong callback token must fail");
    assert!(matches!(
        error,
        AppError::Unauthorized(AuthReason::InvalidToken)
    ));
    assert_eq!(
        send_update(&setup.state, &registration.token, update)
            .await
            .unwrap(),
        StatusCode::OK
    );
    sync::wait_for_notify_syncs_idle().await;
    assert_eq!(
        notify::catchup_state(&pool, SPACE_URI).await.unwrap(),
        (Some("3l7checkpoint1".into()), Some("3l7spacerev2".into()))
    );

    let unsupported = send_update(
        &setup.state,
        &registration.token,
        json!({"$type": "com.atproto.space.notifySpaceUpdate#unknown"}),
    )
    .await
    .expect_err("unknown update type must fail closed");
    assert!(matches!(unsupported, AppError::InvalidRequest(_)));
}

#[sqlx::test(migrations = "./migrations")]
async fn repo_removed_drops_writer_state_without_deleting_history(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    let registration = registration(&pool).await;
    sqlx::query(
        "INSERT INTO circle_repo_sync_state (space_uri, author_did, last_rev, last_hash, last_synced_at) VALUES ($1, $2, '3l7oldrev', $3, now())",
    )
    .bind(SPACE_URI)
    .bind(MEMBER_DID)
    .bind(vec![0_u8; 2048])
    .execute(&pool)
    .await
    .unwrap();
    let record_uri = format!("{SPACE_URI}/{MEMBER_DID}/app.bsky.feed.post/3l7post");
    sqlx::query(
        "INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at) VALUES ($1, 'cid', $2, $3, 'app.bsky.feed.post', '3l7post', $4, now())",
    )
    .bind(&record_uri)
    .bind(SPACE_URI)
    .bind(MEMBER_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "history"}))
    .execute(&pool)
    .await
    .unwrap();

    let update = serde_json::to_value(WriterUpdate::RepoRemoved(RepoRemoved {
        repo: MEMBER_DID.into(),
        space_rev: "3l7removed1".into(),
        prev_space_rev: None,
    }))
    .unwrap();
    assert_eq!(
        send_update(&setup.state, &registration.token, update)
            .await
            .unwrap(),
        StatusCode::OK
    );

    let member_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2)",
    )
    .bind(SPACE_URI)
    .bind(MEMBER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    let sync_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2)",
    )
    .bind(SPACE_URI)
    .bind(MEMBER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    let record_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM circle_records WHERE uri = $1 AND deleted_at IS NULL)",
    )
    .bind(&record_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!member_exists);
    assert!(!sync_exists);
    assert!(record_exists, "repoRemoved preserves Space history");
    assert_eq!(
        notify::checkpoint_rev(&pool, SPACE_URI)
            .await
            .unwrap()
            .as_deref(),
        Some("3l7removed1")
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_expired_reauthorizes_and_catches_up_with_list_writers(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    let registration = registration(&pool).await;
    setup
        .transport
        .set_authorize_space_rev(SPACE_URI, Some("3l7expiredrev".into()));
    setup.transport.set_list_writers_response(
        SPACE_URI,
        ListWritersOutput {
            repos: Vec::new(),
            cursor: None,
        },
    );

    assert_eq!(
        send_update(
            &setup.state,
            &registration.token,
            json!({
                "$type": "com.atproto.space.notifySpaceUpdate#registrationExpired",
                "spaceRev": "3l7expiredrev",
            }),
        )
        .await
        .unwrap(),
        StatusCode::OK
    );
    sync::wait_for_notify_syncs_idle().await;

    assert!(setup.transport.recorded_calls().iter().any(|call| call
        .endpoint_url
        .ends_with("/xrpc/com.atproto.space.authorizeSpaceSync")));
    assert!(setup
        .transport
        .recorded_credential_uses()
        .iter()
        .any(|call| call.method == "com.atproto.space.listWriters"));
    assert_eq!(
        notify::catchup_state(&pool, SPACE_URI).await.unwrap(),
        (Some("3l7expiredrev".into()), None)
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn token_migration_replaces_old_registration_rows(pool: PgPool) {
    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at) VALUES ($1, '3l7notifyreg1', $2, 'Notify Circle', now())",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DROP TABLE circle_notify_registrations")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 20261112000001")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE circle_notify_registrations (space_uri TEXT PRIMARY KEY REFERENCES circles(space_uri) ON DELETE CASCADE, service TEXT NOT NULL, space_host_endpoint TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, registered_at TIMESTAMPTZ NOT NULL DEFAULT now())",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO circle_notify_registrations (space_uri, service, space_host_endpoint, expires_at) VALUES ($1, 'did:web:old', 'https://old.example', now() + interval '1 hour')",
    )
    .bind(SPACE_URI)
    .execute(&pool)
    .await
    .unwrap();

    db::run_migrations(&pool).await.unwrap();

    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'circle_notify_registrations' ORDER BY column_name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(columns.iter().any(|column| column == "endpoint"));
    assert!(columns.iter().any(|column| column == "token"));
    assert!(!columns.iter().any(|column| column == "service"));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM circle_notify_registrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "legacy leases cannot be translated into tokens");
}
