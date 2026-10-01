//! CIRCLES-06: the AppView registers for notifications at each Circle's space
//! host, persists `expiresAt`, renews an hour before it lapses, unregisters when
//! it loses access, and acknowledges notifyWrite before syncing.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use sqlx::PgPool;

use circle_appview::access::{ActiveSpaceCredential, CredentialStore, SpaceLockManager};
use circle_appview::auth::{
    DidDocument, DidResolver, DidService, PublicKeyJwk, VerificationMethod,
};
use circle_appview::config::{AppState, Config};
use circle_appview::notify;
use circle_appview::space_client::{
    MockSpaceHostTransport, RecordedNotifyCall, SpaceAppAccess, SpaceClient, SpaceConfig,
    SpacePolicy,
};
use circle_appview::sync::sweep_once;

const OWNER_DID: &str = "did:plc:owner-notify-registration";
const SPACE_URI: &str =
    "at://did:plc:owner-notify-registration/space/blue.catbird.circle/3l7notifyreg1";
const SPACE_HOST: &str = "https://space.owner.example";

struct Setup {
    state: AppState,
    mock_transport: Arc<MockSpaceHostTransport>,
    owner_key: SigningKey,
}

fn config(service_did: &str) -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: service_did.into(),
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
    }
}

async fn setup(pool: PgPool, service_did: &str) -> Setup {
    std::env::set_var(
        "SESSION_ENCRYPTION_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let config = config(service_did);
    let did_resolver = Arc::new(DidResolver::new(
        config.plc_directory_url.clone(),
        reqwest::Client::builder().no_proxy().build().unwrap(),
    ));
    let owner_key = SigningKey::random(&mut OsRng);
    let point = EncodedPoint::from(owner_key.verifying_key());
    did_resolver.insert_cached(
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

    let mock_transport = Arc::new(MockSpaceHostTransport::new());
    let credential_store = Arc::new(CredentialStore::new());
    credential_store
        .insert(
            SPACE_URI.into(),
            credential(Utc::now() + Duration::hours(2)),
        )
        .await;
    let state = AppState::with_services(
        config,
        pool.clone(),
        did_resolver,
        credential_store,
        Arc::new(SpaceClient::with_transport(mock_transport.clone())),
        Arc::new(SpaceLockManager::new()),
    );

    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at) VALUES ($1, '3l7notifyreg1', $2, 'Notify Circle', now())",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO circle_member_cache (space_uri, member_did, can_read, can_write, cached_at) VALUES ($1, $2, true, true, now())",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .execute(&pool)
    .await
    .unwrap();

    Setup {
        state,
        mock_transport,
        owner_key,
    }
}

fn credential(expires_at: DateTime<Utc>) -> ActiveSpaceCredential {
    ActiveSpaceCredential {
        token: "space.credential.jwt".into(),
        dpop_key: SigningKey::random(&mut OsRng),
        expires_at,
    }
}

async fn stored_registration(pool: &PgPool) -> Option<(String, String, DateTime<Utc>)> {
    sqlx::query_as(
        "SELECT service, space_host_endpoint, expires_at FROM circle_notify_registrations WHERE space_uri = $1",
    )
    .bind(SPACE_URI)
    .fetch_optional(pool)
    .await
    .unwrap()
}

fn expected_call(service: &str) -> RecordedNotifyCall {
    RecordedNotifyCall {
        endpoint_url: format!("{SPACE_HOST}/xrpc/com.atproto.space.registerNotify"),
        space_uri: SPACE_URI.into(),
        service: service.into(),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn sweep_registers_at_the_authority_space_host_and_persists_expiry(pool: PgPool) {
    let setup = setup(pool.clone(), "did:web:circles.catbird.blue#atproto_circles").await;
    let expires_at = DateTime::from_timestamp(Utc::now().timestamp() + 86_400, 0).unwrap();
    setup
        .mock_transport
        .set_register_notify_response(SPACE_URI, expires_at);

    sweep_once(&setup.state).await.unwrap();

    assert_eq!(
        setup.mock_transport.recorded_register_notify_calls(),
        vec![expected_call(
            "did:web:circles.catbird.blue#atproto_circles"
        )]
    );
    let (service, endpoint, stored_expiry) = stored_registration(&pool).await.unwrap();
    assert_eq!(service, "did:web:circles.catbird.blue#atproto_circles");
    assert_eq!(endpoint, SPACE_HOST);
    assert_eq!(stored_expiry, expires_at);

    // A fresh registration is not re-sent on the next sweep.
    sweep_once(&setup.state).await.unwrap();
    assert_eq!(
        setup.mock_transport.recorded_register_notify_calls().len(),
        1
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_renews_one_hour_before_expiry(pool: PgPool) {
    let setup = setup(pool.clone(), "did:web:circles.catbird.blue#atproto_circles").await;
    let start = Utc::now();
    let expires_at = DateTime::from_timestamp(start.timestamp() + 86_400, 0).unwrap();
    setup
        .mock_transport
        .set_register_notify_response(SPACE_URI, expires_at);
    let cred = credential(start + Duration::hours(2));

    let first = notify::ensure_registration_at(&setup.state, SPACE_URI, &cred, start)
        .await
        .unwrap();
    assert_eq!(first, Some(expires_at));

    // 22 h later the registration still has more than an hour left.
    let later = start + Duration::hours(22);
    assert_eq!(
        notify::ensure_registration_at(&setup.state, SPACE_URI, &cred, later)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        setup.mock_transport.recorded_register_notify_calls().len(),
        1
    );

    // Inside the final hour it is renewed and the new expiry persisted.
    let renewed_expiry = expires_at + Duration::hours(24);
    setup
        .mock_transport
        .set_register_notify_response(SPACE_URI, renewed_expiry);
    let inside_margin = expires_at - Duration::minutes(59);
    assert_eq!(
        notify::ensure_registration_at(&setup.state, SPACE_URI, &cred, inside_margin)
            .await
            .unwrap(),
        Some(renewed_expiry)
    );
    assert_eq!(
        setup.mock_transport.recorded_register_notify_calls().len(),
        2
    );
    assert_eq!(stored_registration(&pool).await.unwrap().2, renewed_expiry);
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_service_comes_from_config(pool: PgPool) {
    let setup = setup(pool.clone(), "did:web:circles.staging.example").await;
    notify::ensure_registration(&setup.state, SPACE_URI, &credential(Utc::now()))
        .await
        .unwrap();
    assert_eq!(
        setup.mock_transport.recorded_register_notify_calls(),
        vec![expected_call(
            "did:web:circles.staging.example#atproto_circles"
        )]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn space_deletion_drops_the_registration(pool: PgPool) {
    let setup = setup(pool.clone(), "did:web:circles.catbird.blue#atproto_circles").await;
    notify::ensure_registration(&setup.state, SPACE_URI, &credential(Utc::now()))
        .await
        .unwrap();
    assert!(stored_registration(&pool).await.is_some());

    circle_appview::purge::delete_space(&pool, &setup.state.credential_store, SPACE_URI)
        .await
        .unwrap();
    assert!(stored_registration(&pool).await.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn app_access_revocation_unregisters_at_the_space_host(pool: PgPool) {
    let setup = setup(pool.clone(), "did:web:circles.catbird.blue#atproto_circles").await;
    notify::ensure_registration(&setup.state, SPACE_URI, &credential(Utc::now()))
        .await
        .unwrap();
    setup.mock_transport.set_space_config(
        SPACE_URI,
        SpaceConfig {
            authority: OWNER_DID.into(),
            space_type: "blue.catbird.circle".into(),
            skey: "3l7notifyreg1".into(),
            app_access: SpaceAppAccess::AllowList(vec!["https://another.app/client".into()]),
            read_policy: SpacePolicy::MemberList,
            write_policy: SpacePolicy::MemberList,
            user_policy: None,
            name: None,
            description: None,
        },
    );

    circle_appview::access::refresh_member_cache(&setup.state, SPACE_URI)
        .await
        .expect_err("an explicit appAccess revocation denies");

    let mut expected = expected_call("did:web:circles.catbird.blue#atproto_circles");
    expected.endpoint_url = format!("{SPACE_HOST}/xrpc/com.atproto.space.unregisterNotify");
    assert_eq!(
        setup.mock_transport.recorded_unregister_notify_calls(),
        vec![expected]
    );
    assert!(stored_registration(&pool).await.is_none());
}

/// notifyWrite is acknowledged once validated, without running the sync inline:
/// here the sync itself would fail (no listRepoOps is configured) yet the
/// receiver still answers 200.
#[sqlx::test(migrations = "./migrations")]
async fn notify_write_acknowledges_before_syncing(pool: PgPool) {
    let setup = setup(pool.clone(), "did:web:circles.catbird.blue#atproto_circles").await;
    let now = Utc::now().timestamp();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "iss": OWNER_DID,
            "aud": "did:web:circles.catbird.blue#atproto_circles",
            "lxm": "com.atproto.space.notifyWrite",
            "iat": now,
            "exp": now + 60,
            "jti": uuid::Uuid::new_v4().to_string(),
        })
        .to_string(),
    );
    let signing_input = format!("{header}.{claims}");
    use p256::ecdsa::signature::Signer;
    let sig: p256::ecdsa::Signature = setup.owner_key.sign(signing_input.as_bytes());
    let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));

    let body = catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite {
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&[7u8; 32]),
        repo: catbird_atproto::jacquard_common::types::string::Did::from(String::from(OWNER_DID)),
        rev: catbird_atproto::jacquard_common::types::string::Tid::from(String::from(
            "3l7aaaaaaaaaa",
        )),
        space: catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new_owned(SPACE_URI)
            .unwrap(),
        extra_data: None,
    };
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    let resp = circle_appview::sync::notify_write_handler(
        axum::extract::State(setup.state.clone()),
        headers,
        bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
    )
    .await
    .expect("a validated notifyWrite is acknowledged");
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    circle_appview::sync::wait_for_notify_syncs_idle().await;
    let synced: Option<String> =
        sqlx::query_scalar("SELECT last_rev FROM circle_repo_sync_state WHERE space_uri = $1")
            .bind(SPACE_URI)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(
        synced.is_none(),
        "the failed background sync must not advance state"
    );
}
