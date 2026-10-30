use axum::response::IntoResponse;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use circle_appview::{
    access::{self, ActiveSpaceCredential},
    auth::{DidDocument, DidResolver, DidService, PublicKeyJwk, VerificationMethod},
    config::{AppState, Config},
    db,
    error::{AppError, AuthReason},
    routes::create_router,
    space_client::{
        DefaultSpaceHostTransport, MockSpaceHostTransport, SpaceClient, SpaceHostDnsResolver,
        SpaceHostTransport,
    },
};
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use uuid::Uuid;

pub const CIRCLE_AUDIENCE: &str = "did:web:circles.catbird.blue#atproto_circles";
pub const ALICE_DID: &str = "did:plc:alice-access-test";
pub const BOB_DID: &str = "did:plc:bob-access-test";
pub const AUTHORITY_DID: &str = "did:plc:authority-circle-space";
pub const SPACE_HOST_ENDPOINT: &str = "https://space-host.example.com";

#[allow(dead_code)]
struct TestSetup {
    app: axum::Router,
    alice_signing_key: p256::ecdsa::SigningKey,
    bob_signing_key: p256::ecdsa::SigningKey,
    authority_signing_key: p256::ecdsa::SigningKey,
    mock_transport: Arc<MockSpaceHostTransport>,
    state: AppState,
    pool: PgPool,
}

async fn setup_test(pool: PgPool) -> TestSetup {
    db::run_migrations(&pool)
        .await
        .expect("Migrations must succeed");

    // Explicit local lifecycle fixture: this proves route gating, not relay or
    // live PDS readiness. Production uses the real event consumer to write it.
    sqlx::query("INSERT INTO circle_identity_cursor(relay_url,cursor,last_event_at,last_received_at,reconciled_at,caught_up) VALUES('wss://relay.fixture.example.com/',1,now(),now(),now(),true)")
        .execute(&pool).await.unwrap();
    for did in [ALICE_DID, BOB_DID, AUTHORITY_DID] {
        sqlx::query("INSERT INTO circle_account_status(did,active,pds_url,source_seq,relay_url) VALUES($1,true,'https://pds.fixture.example',1,'wss://relay.fixture.example.com/')")
            .bind(did).execute(&pool).await.unwrap();
    }

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
        identity_relay_url: Some(url::Url::parse("wss://relay.fixture.example.com/").unwrap()),
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circles"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
    };

    let alice_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let bob_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let authority_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    let mock_transport = Arc::new(MockSpaceHostTransport::new());
    let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
    let did_resolver = Arc::new(DidResolver::new(
        "https://plc.directory".into(),
        reqwest::Client::new(),
    ));
    let credential_store = Arc::new(access::CredentialStore::new());
    let space_locks = Arc::new(access::SpaceLockManager::new());
    let profile_hydrator = Arc::new(circle_appview::hydration::ProfileHydrator::new(
        config.public_appview_url.clone(),
        reqwest::Client::new(),
    ));
    let oauth_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let oauth_service = Arc::new(circle_appview::oauth::OAuthService::new(
        pool.clone(),
        config.appview_base_url.clone(),
        oauth_signing_key,
        None,
    ));
    space_client.set_deps(circle_appview::space_client::SpaceClientDeps {
        http_client: reqwest::Client::new(),
        did_resolver: did_resolver.clone(),
        oauth_service: oauth_service.clone(),
    });

    mock_transport.set_space_config(
        &space_uri(),
        circle_appview::space_client::SpaceConfig {
            authority: AUTHORITY_DID.to_string(),
            space_type: "blue.catbird.circle".to_string(),
            skey: "skey-test".to_string(),
            app_access: circle_appview::space_client::SpaceAppAccess::AllowList(vec![
                oauth_service.client_id.clone(),
            ]),
            read_policy: circle_appview::space_client::SpacePolicy::MemberList,
            write_policy: circle_appview::space_client::SpacePolicy::MemberList,
            user_policy: None,
            name: Some("Test Circle".to_string()),
            description: Some("Test Circle Desc".to_string()),
        },
    );

    let state = AppState {
        config: Arc::new(config),
        db: pool.clone(),
        http_client: reqwest::Client::new(),
        did_resolver: did_resolver.clone(),
        credential_store,
        space_client,
        space_locks,
        listing_resume: Default::default(),
        profile_hydrator,
        oauth_service,
        push_client: None,
    };
    // Register DID documents
    register_did_doc(&state.did_resolver, ALICE_DID, &alice_signing_key, None);
    register_did_doc(&state.did_resolver, BOB_DID, &bob_signing_key, None);
    register_did_doc(
        &state.did_resolver,
        AUTHORITY_DID,
        &authority_signing_key,
        Some(vec![DidService {
            id: "#atproto_pds".into(),
            r#type: "AtprotoPersonalDataServer".into(),
            service_endpoint: SPACE_HOST_ENDPOINT.into(),
        }]),
    );

    let app = create_router(state.clone());

    TestSetup {
        app,
        alice_signing_key,
        bob_signing_key,
        authority_signing_key,
        mock_transport,
        state,
        pool,
    }
}

fn register_did_doc(
    resolver: &DidResolver,
    did: &str,
    key: &p256::ecdsa::SigningKey,
    services: Option<Vec<DidService>>,
) {
    let vk = key.verifying_key();
    let point = EncodedPoint::from(vk);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let p256_sec1 = vk.to_encoded_point(true);
    let mut p256_multikey_bytes = vec![0x80, 0x24];
    p256_multikey_bytes.extend_from_slice(p256_sec1.as_bytes());
    let p256_multikey = multibase::encode(multibase::Base::Base58Btc, &p256_multikey_bytes);

    let did_doc = DidDocument {
        id: did.into(),
        verification_method: vec![
            VerificationMethod {
                id: format!("{did}#atproto"),
                r#type: "Multikey".into(),
                controller: did.into(),
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: x.clone(),
                    y: Some(y.clone()),
                    kid: None,
                }),
                public_key_multibase: Some(p256_multikey),
            },
            VerificationMethod {
                id: format!("{did}#key-jwk"),
                r#type: "JsonWebKey2020".into(),
                controller: did.into(),
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x,
                    y: Some(y),
                    kid: None,
                }),
                public_key_multibase: None,
            },
        ],
        service: services.unwrap_or_default(),
    };

    resolver.insert_cached(did.into(), did_doc);
}

fn space_uri() -> String {
    format!("at://{AUTHORITY_DID}/space/blue.catbird.circle/3k2space1")
}

fn mint_delegation_token(
    signing_key: &p256::ecdsa::SigningKey,
    iss: &str,
    sub: &str,
    aud: &str,
    exp: i64,
    iat: i64,
) -> String {
    let header = json!({
        "alg": "ES256",
        "typ": "atproto-delegation-token+jwt",
        "kid": "#atproto"
    });
    let claims = json!({
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "exp": exp,
        "iat": iat,
        "jti": Uuid::new_v4().to_string()
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

#[sqlx::test(migrations = "./migrations")]
async fn dpop_proof_and_credential_store_lifecycle(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let store = setup.state.credential_store.clone();
    let space = space_uri();

    assert!(store.get(&space).await.is_none());
    assert_eq!(store.count().await, 0);

    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let cred1 = ActiveSpaceCredential {
        token: "jwt_token_1".into(),
        signing_key: signing_key.clone(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
    };

    store.insert(space.clone(), cred1).await;
    assert_eq!(store.count().await, 1);

    let retrieved = store.get(&space).await;
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().token, "jwt_token_1");

    // Monotonic overwrite with longer lifetime
    let cred2 = ActiveSpaceCredential {
        token: "jwt_token_2".into(),
        signing_key: signing_key.clone(),
        expires_at: Utc::now() + chrono::Duration::hours(2),
    };
    store.insert(space.clone(), cred2).await;
    assert_eq!(store.get(&space).await.unwrap().token, "jwt_token_2");

    // Overwrite with shorter lifetime is ignored
    let cred_shorter = ActiveSpaceCredential {
        token: "jwt_token_shorter".into(),
        signing_key,
        expires_at: Utc::now() + chrono::Duration::minutes(30),
    };
    store.insert(space.clone(), cred_shorter).await;
    assert_eq!(store.get(&space).await.unwrap().token, "jwt_token_2");

    // Removal
    store.remove(&space).await;
    assert!(store.get(&space).await.is_none());
    assert_eq!(store.count().await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn delegation_token_validation_passes_and_fails_on_tampering(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    let user_doc = setup
        .state
        .did_resolver
        .resolve(ALICE_DID)
        .await
        .expect("Alice doc must resolve");

    let valid_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        CIRCLE_AUDIENCE,
        now + 300,
        now,
    );

    // 1. Valid token succeeds
    let claims = access::parse_and_validate_delegation_token(
        &valid_token,
        ALICE_DID,
        &space,
        CIRCLE_AUDIENCE,
        &user_doc,
    )
    .expect("Valid delegation token must pass");
    assert_eq!(claims.iss, ALICE_DID);
    assert_eq!(claims.sub, space);

    // 2. Expired token fails
    let expired_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        CIRCLE_AUDIENCE,
        now - 10,
        now - 300,
    );
    assert!(access::parse_and_validate_delegation_token(
        &expired_token,
        ALICE_DID,
        &space,
        CIRCLE_AUDIENCE,
        &user_doc,
    )
    .is_err());

    // 3. Mismatched issuer fails
    let bob_token = mint_delegation_token(
        &setup.bob_signing_key,
        BOB_DID,
        &space,
        CIRCLE_AUDIENCE,
        now + 300,
        now,
    );
    assert!(access::parse_and_validate_delegation_token(
        &bob_token,
        ALICE_DID,
        &space,
        CIRCLE_AUDIENCE,
        &user_doc,
    )
    .is_err());

    // 4. Mismatched space sub fails
    let wrong_space_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        "at://did:plc:other/space/blue.catbird.circle/3k2other",
        CIRCLE_AUDIENCE,
        now + 300,
        now,
    );
    assert!(access::parse_and_validate_delegation_token(
        &wrong_space_token,
        ALICE_DID,
        &space,
        CIRCLE_AUDIENCE,
        &user_doc,
    )
    .is_err());

    // 5. Wrong audience fails
    let wrong_aud_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        "did:web:wrong-audience",
        now + 300,
        now,
    );
    assert!(access::parse_and_validate_delegation_token(
        &wrong_aud_token,
        ALICE_DID,
        &space,
        CIRCLE_AUDIENCE,
        &user_doc,
    )
    .is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn authority_host_resolution_uses_atproto_pds(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let pds_endpoint = "https://pds-fallback.example.com";

    // Re-register authority DID doc with ONLY #atproto_pds
    let pds_doc = DidDocument {
        id: AUTHORITY_DID.into(),
        verification_method: vec![VerificationMethod {
            id: format!("{AUTHORITY_DID}#atproto_space"),
            r#type: "Multikey".into(),
            controller: AUTHORITY_DID.into(),
            public_key_jwk: None,
            public_key_multibase: None,
        }],
        service: vec![DidService {
            id: "#atproto_pds".into(),
            r#type: "AtprotoPersonalDataServer".into(),
            service_endpoint: pds_endpoint.into(),
        }],
    };
    setup
        .state
        .did_resolver
        .insert_cached(AUTHORITY_DID.into(), pds_doc);

    let (endpoint, service_id) = access::resolve_space_host_endpoint(
        &setup
            .state
            .did_resolver
            .resolve(AUTHORITY_DID)
            .await
            .unwrap(),
        AUTHORITY_DID,
    )
    .unwrap();

    // October 22 uses the authority account PDS for both endpoint and audience.
    assert_eq!(endpoint, pds_endpoint);
    assert_eq!(service_id, format!("{AUTHORITY_DID}#atproto_pds"));
}

#[sqlx::test(migrations = "./migrations")]
async fn check_member_access_and_cache_validation(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();

    // 1. Seed circle in database
    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at) VALUES ($1, '3k2space1tid', $2, 'Test Circle', now())",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Pre-populate Alice in cache
    sqlx::query(
        "INSERT INTO circle_member_cache (space_uri, member_did, cached_at) VALUES ($1, $2, now())",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count) VALUES ($1, now(), 1)",
    )
    .bind(&space)
    .execute(&pool)
    .await
    .unwrap();

    // 3. Alice should be allowed via fresh cache
    access::check_member_access(&setup.state, &space, ALICE_DID)
        .await
        .expect("Alice should be granted member access via cache");

    // 4. Bob (not in cache and PDS lookup fails / not member) is denied
    assert!(access::check_member_access(&setup.state, &space, BOB_DID)
        .await
        .is_err());

    // A confirmed inactive authority denies even a cached member, and restoring
    // activity preserves the authority-issued membership grant.
    sqlx::query("UPDATE circle_account_status SET active=false,status='suspended' WHERE did=$1")
        .bind(AUTHORITY_DID)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        access::check_member_access(&setup.state, &space, ALICE_DID).await,
        Err(AppError::Forbidden(_))
    ));
    let grants: i64 =
        sqlx::query_scalar("SELECT count(*) FROM circle_member_cache WHERE member_did=$1")
            .bind(ALICE_DID)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(grants, 1);
    sqlx::query("UPDATE circle_account_status SET active=true,status=NULL WHERE did=$1")
        .bind(AUTHORITY_DID)
        .execute(&pool)
        .await
        .unwrap();
    access::check_member_access(&setup.state, &space, ALICE_DID)
        .await
        .unwrap();
    sqlx::query("UPDATE circle_account_status SET active=false,status='suspended' WHERE did=$1")
        .bind(ALICE_DID)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        access::check_member_access(&setup.state, &space, ALICE_DID).await,
        Err(AppError::Forbidden(_))
    ));
}

#[derive(Clone)]
struct TestLogBuffer(Arc<parking_lot::Mutex<Vec<u8>>>);

impl std::io::Write for TestLogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TestLogBuffer {
    type Writer = TestLogBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn mint_service_jwt(did: &str, lxm: &str, signing_key: &p256::ecdsa::SigningKey) -> String {
    let now = Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();
    let header = json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": format!("{did}#atproto")
    });
    let claims = json!({
        "iss": did,
        "aud": CIRCLE_AUDIENCE,
        "lxm": lxm,
        "exp": now + 60,
        "iat": now,
        "jti": jti
    });
    let header_bytes = serde_json::to_vec(&header).unwrap();
    let claims_bytes = serde_json::to_vec(&claims).unwrap();
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&header_bytes),
        URL_SAFE_NO_PAD.encode(&claims_bytes)
    );
    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

#[sqlx::test(migrations = "./migrations")]
async fn unreadable_member_list_denies_without_signalling_removal(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();

    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted) VALUES ($1, '3k2space1tidx', $2, 'Test Circle', now(), true)",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&pool)
    .await
    .unwrap();

    // Bob has no cache entry and PDS is unreadable
    let outcome = access::verify_member_access(&setup.state, &space, BOB_DID)
        .await
        .expect("verify_member_access must not fail with internal db error");
    assert_eq!(outcome, access::MemberAccessOutcome::IndeterminateDenied);

    let err = access::check_member_access(&setup.state, &space, BOB_DID)
        .await
        .expect_err("check_member_access must deny on indeterminate membership");

    match err {
        circle_appview::error::AppError::Forbidden(msg) => {
            assert!(
                msg.contains("Unable to establish membership"),
                "Expected Forbidden error message, got: {msg}"
            );
        }
        other => panic!("Expected AppError::Forbidden, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn authority_omitted_from_member_cache_is_authorized_in_shared_gate_while_outsider_fails_closed(
    pool: PgPool,
) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();

    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted) VALUES ($1, '3k2space1tidx', $2, 'Test Circle', now(), true)",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&pool)
    .await
    .unwrap();

    // The authority is implicit in membership, but its AppView grant still
    // requires a current policy snapshot, just like every other reader.
    sqlx::query("INSERT INTO circle_member_cache_meta(space_uri,last_refreshed_at,member_count) VALUES($1,now(),0)")
        .bind(&space).execute(&pool).await.unwrap();

    // Authority is NOT in member cache
    let outcome = access::verify_member_access(&setup.state, &space, AUTHORITY_DID)
        .await
        .expect("verify_member_access must succeed for space authority");
    assert_eq!(outcome, access::MemberAccessOutcome::Authorized);

    access::check_member_access(&setup.state, &space, AUTHORITY_DID)
        .await
        .expect("check_member_access must succeed for space authority");

    // Outsider (Bob) fails closed
    let bob_err = access::check_member_access(&setup.state, &space, BOB_DID)
        .await
        .expect_err("check_member_access must deny outsider");
    assert!(
        matches!(
            bob_err,
            circle_appview::error::AppError::Forbidden(_)
                | circle_appview::error::AppError::AccessRemoved(_)
        ),
        "Expected Forbidden or AccessRemoved for outsider, got {bob_err:?}"
    );

    // When circle app_access is revoked or deleted, authority is also denied (invariants preserved)
    sqlx::query("UPDATE circles SET app_access_granted = false WHERE space_uri = $1")
        .bind(&space)
        .execute(&pool)
        .await
        .unwrap();

    let revoked_err = access::check_member_access(&setup.state, &space, AUTHORITY_DID)
        .await
        .expect_err("check_member_access must deny when appAccess revoked");
    // AccessRemoved (not NotFound) so the device purges its cached Circle (CIRCLES-04).
    assert!(
        matches!(
            revoked_err,
            circle_appview::error::AppError::AccessRemoved(_)
        ),
        "Expected AccessRemoved for revoked space, got {revoked_err:?}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn space_app_access_naming_only_service_did_is_rejected(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;

    let expected_client_id = &setup.state.oauth_service.client_id;
    let service_did = &setup.state.config.service_did;

    // A Space whose appAccess names ONLY the service DID
    let space_config_only_service_did = circle_appview::space_client::SpaceConfig {
        authority: AUTHORITY_DID.to_string(),
        space_type: "blue.catbird.circle".to_string(),
        skey: "3k2space1tidx".to_string(),
        app_access: circle_appview::space_client::SpaceAppAccess::AllowList(vec![
            service_did.clone()
        ]),
        read_policy: circle_appview::space_client::SpacePolicy::MemberList,
        write_policy: circle_appview::space_client::SpacePolicy::MemberList,
        user_policy: None,
        name: Some("Test".to_string()),
        description: None,
    };

    // Verify it is rejected because service_did is not the OAuth client_id
    assert!(!space_config_only_service_did
        .app_access
        .grants_access(expected_client_id));

    // A Space whose appAccess names the AppView client_id
    let space_config_client_id = circle_appview::space_client::SpaceConfig {
        authority: AUTHORITY_DID.to_string(),
        space_type: "blue.catbird.circle".to_string(),
        skey: "3k2space1tidx".to_string(),
        app_access: circle_appview::space_client::SpaceAppAccess::AllowList(vec![
            expected_client_id.clone(),
        ]),
        read_policy: circle_appview::space_client::SpacePolicy::MemberList,
        write_policy: circle_appview::space_client::SpacePolicy::MemberList,
        user_policy: None,
        name: Some("Test".to_string()),
        description: None,
    };

    assert!(space_config_client_id
        .app_access
        .grants_access(expected_client_id));
}

#[sqlx::test(migrations = "./migrations")]
async fn removed_member_is_denied_on_batch_and_fanout_endpoints(pool: PgPool) {
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
    use catbird_atproto::generated::blue_catbird::circle::get_feed::GetFeedOutput;
    use catbird_atproto::generated::blue_catbird::circle::list_circles::ListCirclesOutput;
    use catbird_atproto::generated::blue_catbird::circle::list_notifications::ListNotificationsOutput;
    use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
    use catbird_atproto::jacquard_common::types::string::{Did, Handle};
    use tower::ServiceExt;

    let setup = setup_test(pool.clone()).await;
    setup
        .state
        .profile_hydrator
        .set_cached_profile(
            AUTHORITY_DID,
            ProfileViewBasic {
                did: Did::new(SmolStr::new(AUTHORITY_DID)).unwrap(),
                handle: Handle::new(SmolStr::new("authority.test")).unwrap(),
                display_name: Some(SmolStr::new("Authority")),
                avatar: None,
                associated: None,
                viewer: None,
                labels: None,
                created_at: None,
                pronouns: None,
                status: None,
                verification: None,
                debug: None,
                extra_data: None,
            },
        )
        .await;

    setup
        .state
        .profile_hydrator
        .set_cached_profile(
            BOB_DID,
            ProfileViewBasic {
                did: Did::new(SmolStr::new(BOB_DID)).unwrap(),
                handle: Handle::new(SmolStr::new("bob.test")).unwrap(),
                display_name: Some(SmolStr::new("Bob Member")),
                avatar: None,
                associated: None,
                viewer: None,
                labels: None,
                created_at: None,
                pronouns: None,
                status: None,
                verification: None,
                debug: None,
                extra_data: None,
            },
        )
        .await;
    let space1 = format!("at://{AUTHORITY_DID}/space/blue.catbird.circle/3k2space1");
    let space2 = format!("at://{AUTHORITY_DID}/space/blue.catbird.circle/3k2space2");

    // Seed Space 1 and Space 2
    sqlx::query("INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at) VALUES ($1, '3k2space1tidx', $2, 'Circle 1', now())")
        .bind(&space1).bind(AUTHORITY_DID).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at) VALUES ($1, '3k2space2tidx', $2, 'Circle 2', now())")
        .bind(&space2).bind(AUTHORITY_DID).execute(&pool).await.unwrap();

    // Space 1: Stale cache (refreshed 10 minutes ago)
    let stale_time = Utc::now() - chrono::Duration::minutes(10);
    sqlx::query(
        "INSERT INTO circle_member_cache (space_uri, member_did, cached_at) VALUES ($1, $2, $3)",
    )
    .bind(&space1)
    .bind(BOB_DID)
    .bind(stale_time)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count) VALUES ($1, $2, 1)")
        .bind(&space1).bind(stale_time).execute(&pool).await.unwrap();

    // Space 2: Fresh cache (refreshed now)
    sqlx::query(
        "INSERT INTO circle_member_cache (space_uri, member_did, cached_at) VALUES ($1, $2, now())",
    )
    .bind(&space2)
    .bind(BOB_DID)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count) VALUES ($1, now(), 1)")
        .bind(&space2).execute(&pool).await.unwrap();

    // Insert records in Space 1 and Space 2
    let post1_json = json!({"$type": "app.bsky.feed.post", "text": "Post in Space 1", "createdAt": Utc::now().to_rfc3339()});
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, indexed_at, created_at)
        VALUES ($1, 'bafyreicid1', $2, $3, 'app.bsky.feed.post', 'post1', $4, now(), now())
        "#,
    )
    .bind(format!("{space1}/app.bsky.feed.post/post1"))
    .bind(&space1)
    .bind(AUTHORITY_DID)
    .bind(&post1_json)
    .execute(&pool)
    .await
    .unwrap();

    let post2_json = json!({"$type": "app.bsky.feed.post", "text": "Post in Space 2", "createdAt": Utc::now().to_rfc3339()});
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, indexed_at, created_at)
        VALUES ($1, 'bafyreicid2', $2, $3, 'app.bsky.feed.post', 'post2', $4, now(), now())
        "#,
    )
    .bind(format!("{space2}/app.bsky.feed.post/post2"))
    .bind(&space2)
    .bind(AUTHORITY_DID)
    .bind(&post2_json)
    .execute(&pool)
    .await
    .unwrap();

    // Insert notifications in Space 1 and Space 2
    sqlx::query(
        "INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, source_uri, created_at) VALUES ($1, $2, $3, $4, 'like', $5, now())",
    )
    .bind(Uuid::new_v4())
    .bind(BOB_DID)
    .bind(&space1)
    .bind(AUTHORITY_DID)
    .bind(format!("{space1}/app.bsky.feed.like/like1"))
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, source_uri, created_at) VALUES ($1, $2, $3, $4, 'like', $5, now())",
    )
    .bind(Uuid::new_v4())
    .bind(BOB_DID)
    .bind(&space2)
    .bind(AUTHORITY_DID)
    .bind(format!("{space2}/app.bsky.feed.like/like2"))
    .execute(&pool)
    .await
    .unwrap();

    // 1. Bob queries unified getFeed (space = None): Space 1 is stale & unreadable, so only Space 2 is returned
    let feed_jwt = mint_service_jwt(
        BOB_DID,
        "blue.catbird.circle.getFeed",
        &setup.bob_signing_key,
    );
    let req = Request::builder()
        .method("GET")
        .uri("/xrpc/blue.catbird.circle.getFeed")
        .header(header::AUTHORIZATION, format!("Bearer {feed_jwt}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    println!(
        "feed status: {status}, body: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(status, StatusCode::OK);
    let feed_output: GetFeedOutput = serde_json::from_slice(&body).unwrap();
    assert_eq!(feed_output.feed.len(), 1);
    assert_eq!(feed_output.feed[0].circle.uri.as_str(), space2);

    // 2. Bob queries listCircles: Space 1 is stale & unreadable, so only Space 2 is returned
    let list_jwt = mint_service_jwt(
        BOB_DID,
        "blue.catbird.circle.listCircles",
        &setup.bob_signing_key,
    );
    let req = Request::builder()
        .method("GET")
        .uri("/xrpc/blue.catbird.circle.listCircles")
        .header(header::AUTHORIZATION, format!("Bearer {list_jwt}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let list_output: ListCirclesOutput = serde_json::from_slice(&body).unwrap();
    assert_eq!(list_output.circles.len(), 1);
    assert_eq!(list_output.circles[0].uri.as_str(), space2);

    // 3. Bob queries listNotifications: Space 1 is stale & unreadable, so only Space 2 notification is returned
    let notif_jwt = mint_service_jwt(
        BOB_DID,
        "blue.catbird.circle.listNotifications",
        &setup.bob_signing_key,
    );
    let req = Request::builder()
        .method("GET")
        .uri("/xrpc/blue.catbird.circle.listNotifications")
        .header(header::AUTHORIZATION, format!("Bearer {notif_jwt}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let notif_output: ListNotificationsOutput = serde_json::from_slice(&body).unwrap();
    assert_eq!(notif_output.notifications.len(), 1);
    assert_eq!(notif_output.notifications[0].circle.uri.as_str(), space2);
}

#[sqlx::test(migrations = "./migrations")]
async fn no_space_uri_in_any_log_line_on_pds_failures(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();

    let log_bytes = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let buffer_writer = TestLogBuffer(log_bytes.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer_writer)
        .with_max_level(tracing::Level::TRACE)
        .finish();

    let _guard = tracing::subscriber::set_default(subscriber);

    // Trigger a refresh_member_cache failure
    let _ = access::refresh_member_cache(&setup.state, &space).await;

    // Trigger an activate_circle failure
    let _ = access::activate_circle(&setup.state, ALICE_DID, &space).await;

    let captured = {
        let lock = log_bytes.lock();
        String::from_utf8_lossy(&lock).to_string()
    };

    assert!(
        !captured.contains(&space),
        "Log output must not contain private Space URI: '{space}'. Captured logs:\n{captured}"
    );
    assert!(
        !captured.contains("space ="),
        "Log output must not contain space field: 'space ='. Captured logs:\n{captured}"
    );
}

#[tokio::test]
async fn ssrf_safe_transport_dns_seam_validations() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Generate TLS self-signed cert for space.example.org
    let params = rcgen::CertificateParams::new(vec!["space.example.org".to_string()]).unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    let rustls_cert = rustls::pki_types::CertificateDer::from(cert_der);
    let rustls_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
    );
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls_cert], rustls_key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let Ok(n) = tls_stream.read(&mut buf).await else {
                    return;
                };
                let req_str = String::from_utf8_lossy(&buf[..n]);
                if req_str.starts_with("POST /xrpc/com.atproto.space.getSpaceCredential") {
                    let body: serde_json::Value = req_str
                        .split_once("\r\n\r\n")
                        .and_then(|(_, body)| serde_json::from_str(body).ok())
                        .unwrap_or_default();
                    let lower = req_str.to_ascii_lowercase();
                    let body_contract = body["space"] == "at://did:plc:auth/space/1"
                        && body["delegationToken"] == "test-delegation-token"
                        && body["clientAttestation"] == "test-attestation"
                        && body["credentialKid"]
                            .as_str()
                            .is_some_and(|kid| kid.starts_with("did:key:"));
                    let no_proof_headers = !lower.contains("\r\nauthorization:")
                        && !lower.contains("\r\ndpop:")
                        && !lower.contains("\r\nsignature:")
                        && !lower.contains("\r\nsignature-input:");
                    if body_contract && no_proof_headers {
                        let body = r#"{"credential":"test.space.credential.jwt"}"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = tls_stream.write_all(response.as_bytes()).await;
                    } else {
                        let body = r#"{"error":"Unauthorized"}"#;
                        let response = format!(
                            "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = tls_stream.write_all(response.as_bytes()).await;
                    }
                } else if req_str.starts_with("POST /redirect-target") {
                    let body = r#"{"credential":"test.space.credential.jwt"}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                } else if req_str.starts_with("POST /redirect") {
                    let response = "HTTP/1.1 307 Temporary Redirect\r\nLocation: /redirect-target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                } else {
                    let response =
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                }
                let _ = tls_stream.shutdown().await;
            });
        }
    });

    let reqwest_cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();

    // 1. Successful pinned HTTPS transport exchange over real TLS
    struct FixtureDnsResolver {
        addr: SocketAddr,
    }
    impl SpaceHostDnsResolver for FixtureDnsResolver {
        fn resolve_dns<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, AuthReason>> + Send + 'a>>
        {
            let res = vec![self.addr];
            Box::pin(async move { Ok(res) })
        }
    }

    let fixture_resolver = Arc::new(FixtureDnsResolver { addr: fixture_addr });
    let transport_success = DefaultSpaceHostTransport::with_test_fixture(
        fixture_resolver,
        Some(reqwest_cert.clone()),
        true,
    );
    let target_url = url::Url::parse(&format!(
        "https://space.example.org:{}/xrpc/com.atproto.space.getSpaceCredential",
        fixture_addr.port()
    ))
    .unwrap();

    let exchange_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let exchange_request = circle_appview::space_client::SpaceCredentialRequest {
        space: "at://did:plc:auth/space/1".into(),
        credential_kid: circle_appview::space_signature::p256_did_key(exchange_key.verifying_key()),
        delegation_token: Some("test-delegation-token".into()),
        client_attestation: Some("test-attestation".into()),
    };
    let cred = transport_success
        .get_space_credential(&target_url, &exchange_request)
        .await
        .expect("Space host credential exchange over TLS must succeed");
    assert_eq!(cred, "test.space.credential.jwt");

    // 2. Redirect rejection (Policy::none())
    let redirect_url = url::Url::parse(&format!(
        "https://space.example.org:{}/redirect",
        fixture_addr.port()
    ))
    .unwrap();
    let redirect_res = transport_success
        .get_space_credential(&redirect_url, &exchange_request)
        .await;
    assert!(
        redirect_res.is_err(),
        "Redirect must be rejected by Policy::none()"
    );
}

#[tokio::test]
async fn space_lock_manager_idle_eviction_and_capacity_bounding() {
    let lock_mgr = access::SpaceLockManager::with_capacity(5);

    // Acquire and release a lock
    {
        let _guard = lock_mgr.acquire("at://did:plc:space1/space/1").await;
        assert_eq!(lock_mgr.lock_count().await, 1);
    }

    // Give background drop a small tick or clean idle
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    lock_mgr.clean_idle().await;
    assert_eq!(
        lock_mgr.lock_count().await,
        0,
        "Idle lock must be evicted when released"
    );

    // Fill to capacity
    let mut guards = Vec::new();
    for i in 0..5 {
        let space = format!("at://did:plc:space{i}/space/{i}");
        guards.push(lock_mgr.acquire(&space).await);
    }
    assert_eq!(lock_mgr.lock_count().await, 5);

    // Releasing guards evicts all
    drop(guards);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    lock_mgr.clean_idle().await;
    assert_eq!(lock_mgr.lock_count().await, 0);
}

#[tokio::test]
async fn space_lock_manager_concurrent_acquire_drop_race_maintains_mutual_exclusion() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    let lock_mgr = Arc::new(access::SpaceLockManager::with_capacity(10));
    let inside_critical = Arc::new(AtomicUsize::new(0));
    let violation_detected = Arc::new(AtomicBool::new(false));
    let space = "at://did:plc:race-test/space/race";

    let mut handles = Vec::new();
    for _ in 0..50 {
        let mgr = lock_mgr.clone();
        let inside = inside_critical.clone();
        let violation = violation_detected.clone();
        let s = space.to_string();

        handles.push(tokio::spawn(async move {
            for _ in 0..20 {
                let guard = mgr.acquire(&s).await;
                let current = inside.fetch_add(1, Ordering::SeqCst);
                if current > 0 {
                    violation.store(true, Ordering::SeqCst);
                }
                tokio::time::sleep(std::time::Duration::from_micros(50)).await;
                inside.fetch_sub(1, Ordering::SeqCst);
                drop(guard);
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert!(
        !violation_detected.load(Ordering::SeqCst),
        "Mutual exclusion violation: more than one task held the lock simultaneously"
    );
}

#[tokio::test]
async fn space_lock_manager_cancellation_decrements_waiter_count() {
    let lock_mgr = Arc::new(access::SpaceLockManager::with_capacity(10));
    let space = "at://did:plc:cancel-test/space/test";

    // First acquire the lock so subsequent acquires must wait
    let guard = lock_mgr.acquire(space).await;
    assert_eq!(lock_mgr.waiter_count(space).await, 1);

    // Spawn an acquire that will block and then cancel it via abort
    let mgr_clone = lock_mgr.clone();
    let s = space.to_string();
    let waiter_handle = tokio::spawn(async move {
        let _ = mgr_clone.acquire(&s).await;
    });

    // Give it a moment to enter acquire and increment waiters
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(lock_mgr.waiter_count(space).await, 2);

    // Abort the waiting acquire
    waiter_handle.abort();
    let _ = waiter_handle.await;

    // The waiter count must decrement back to 1 (only guard remains)
    assert_eq!(
        lock_mgr.waiter_count(space).await,
        1,
        "Cancelled waiter must decrement count"
    );

    drop(guard);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    lock_mgr.clean_idle().await;
    assert_eq!(lock_mgr.lock_count().await, 0);
}

#[tokio::test]
async fn did_resolver_and_profile_hydrator_cache_capacity_and_ttl_eviction() {
    use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
    use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
    use catbird_atproto::jacquard_common::types::string::{Did, Handle};
    use circle_appview::hydration::ProfileHydrator;

    let http_client = reqwest::Client::new();

    // 1. DidResolver strict capacity bounding test
    let small_resolver =
        DidResolver::with_capacity("https://plc.directory".into(), http_client.clone(), 5);
    for i in 0..10 {
        let did = format!("did:plc:boundeduser{i}");
        let doc = DidDocument {
            id: did.clone(),
            verification_method: vec![],
            service: vec![],
        };
        small_resolver.insert_cached_with_ttl(did, doc, chrono::Duration::hours(1));
    }
    assert_eq!(
        small_resolver.cached_count(),
        5,
        "DidResolver must strictly bound cache to configured capacity"
    );

    // 2. DidResolver TTL expiration eviction test
    let did_resolver = DidResolver::new("https://plc.directory".into(), http_client.clone());
    for i in 0..50 {
        let did = format!("did:plc:testuser{i}");
        let doc = DidDocument {
            id: did.clone(),
            verification_method: vec![],
            service: vec![],
        };
        did_resolver.insert_cached_with_ttl(did, doc, chrono::Duration::milliseconds(10));
    }

    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let doc = DidDocument {
        id: "did:plc:freshuser".into(),
        verification_method: vec![],
        service: vec![],
    };
    did_resolver.insert_cached("did:plc:freshuser".into(), doc);
    assert!(
        did_resolver.cached_count() <= 10,
        "Expired entries must be evicted on insert"
    );

    // 3. ProfileHydrator strict capacity bounding test
    let small_hydrator = ProfileHydrator::with_capacity(
        "https://public.api.bsky.app".into(),
        http_client.clone(),
        5,
    );
    let now = std::time::Instant::now();
    for i in 0..10 {
        let did = format!("did:plc:boundedprofile{i}");
        let profile = ProfileViewBasic {
            did: Did::new(SmolStr::new(&did)).unwrap(),
            handle: Handle::new(SmolStr::new(format!("bounded{i}.test"))).unwrap(),
            display_name: Some(SmolStr::new(format!("Bounded {i}"))),
            avatar: None,
            associated: None,
            viewer: None,
            labels: None,
            created_at: None,
            pronouns: None,
            status: None,
            verification: None,
            debug: None,
            extra_data: None,
        };
        small_hydrator
            .set_cached_profile_with_time(&did, profile, now)
            .await;
    }
    assert_eq!(
        small_hydrator.cached_count().await,
        5,
        "ProfileHydrator must strictly bound cache to configured capacity"
    );

    // 4. ProfileHydrator standard insertion and TTL eviction test
    let hydrator = ProfileHydrator::new("https://public.api.bsky.app".into(), http_client);
    for i in 0..50 {
        let did = format!("did:plc:hydrated{i}");
        let profile = ProfileViewBasic {
            did: Did::new(SmolStr::new(&did)).unwrap(),
            handle: Handle::new(SmolStr::new(format!("user{i}.test"))).unwrap(),
            display_name: Some(SmolStr::new(format!("User {i}"))),
            avatar: None,
            associated: None,
            viewer: None,
            labels: None,
            created_at: None,
            pronouns: None,
            status: None,
            verification: None,
            debug: None,
            extra_data: None,
        };
        hydrator
            .set_cached_profile_with_time(&did, profile, now)
            .await;
    }

    assert_eq!(hydrator.cached_count().await, 50);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_members_bounds_and_repeated_cursor_detection_fails_closed(pool: PgPool) {
    use circle_appview::space_client::SpaceClient;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let space = "at://did:plc:authspace/space/1";

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.simplespace.listMembers"))
        .and(query_param("space", space))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "members": [{"did": "did:plc:user1", "read": true, "write": true}],
            "cursor": "repeated_cursor_token"
        })))
        .mount(&mock_server)
        .await;

    let did_resolver = Arc::new(DidResolver::new(mock_server.uri(), reqwest::Client::new()));
    let alice_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let pds_service = vec![DidService {
        id: "did:plc:authspace#atproto_pds".into(),
        r#type: "AtprotoPersonalDataServer".into(),
        service_endpoint: mock_server.uri(),
    }];
    register_did_doc(
        &did_resolver,
        "did:plc:authspace",
        &alice_key,
        Some(pds_service),
    );

    // Create OAuth service and pre-seed active session
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let oauth_service = Arc::new(circle_appview::oauth::OAuthService::new(
        pool,
        "http://127.0.0.1:3002".into(),
        signing_key,
        None,
    ));
    let session = circle_appview::oauth::UserOAuthSession {
        user_did: "did:plc:authspace".to_string(),
        access_token: "mock-token".to_string(),
        refresh_token: None,
        token_endpoint: format!("{}/oauth/token", mock_server.uri()),
        auth_server_iss: mock_server.uri(),
        expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        scope: "blue.catbird.circle".to_string(),
        dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
    };
    let _ = oauth_service.store_session(session).await;

    let space_client = SpaceClient::new();
    space_client.set_deps(circle_appview::space_client::SpaceClientDeps {
        http_client: reqwest::Client::new(),
        did_resolver,
        oauth_service,
    });

    let res = space_client.member_dids(space).await;
    assert!(
        res.is_err(),
        "Repeated pagination cursor must fail closed: got {:?}",
        res
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn test_activate_circle_missing_grant_returns_auth_required_not_404_and_preserves_not_found_and_upstream(
    pool: PgPool,
) {
    let setup = setup_test(pool.clone()).await;
    register_did_doc(
        &setup.state.did_resolver,
        AUTHORITY_DID,
        &setup.authority_signing_key,
        Some(vec![DidService {
            id: "#atproto_pds".into(),
            r#type: "AtprotoPersonalDataServer".into(),
            service_endpoint: SPACE_HOST_ENDPOINT.into(),
        }]),
    );

    // 1. Missing AppView OAuth grant: AUTHORITY_DID has no session in oauth_sessions.
    // An unconfigured space triggers get_space which tries to fetch a token for AUTHORITY_DID.
    let ungranted_space = format!("at://{AUTHORITY_DID}/space/blue.catbird.circle/ungranted");
    let missing_grant_res =
        access::activate_circle(&setup.state, ALICE_DID, &ungranted_space).await;

    match missing_grant_res {
        Err(AppError::Unauthorized(reason)) => {
            assert_eq!(reason, AuthReason::MissingOAuthSession);
            let resp = AppError::Unauthorized(reason).into_response();
            assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        }
        other => panic!("Expected missing OAuth session to require authorization, got {other:?}"),
    }

    // Verify no database writes occurred before access authorization
    let circle_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM circles")
        .fetch_one(&setup.pool)
        .await
        .unwrap();
    assert_eq!(
        circle_count.0, 0,
        "No circle row must be written on authorization failure"
    );

    let member_cache_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM circle_member_cache")
        .fetch_one(&setup.pool)
        .await
        .unwrap();
    assert_eq!(
        member_cache_count.0, 0,
        "No member cache row must be written on authorization failure"
    );

    // 2. True NotFound: when PDS returns SpaceNotFound, it must return NotFound (404), not 401 or 500
    let not_found_space = format!("at://{AUTHORITY_DID}/space/blue.catbird.circle/nonexistent");
    setup
        .mock_transport
        .set_space_config_error(&not_found_space, "SpaceNotFound".into());

    let not_found_res = access::activate_circle(&setup.state, ALICE_DID, &not_found_space).await;
    match not_found_res {
        Err(AppError::NotFound(_)) => {
            let resp = not_found_res.unwrap_err().into_response();
            assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
        }
        other => panic!("Expected NotFound for true missing space, got {other:?}"),
    }

    // 3. Upstream failure: when PDS returns server error / unavailable, it must retain Internal (500), not 404
    let upstream_err_space = format!("at://{AUTHORITY_DID}/space/blue.catbird.circle/upstream-err");
    setup.mock_transport.set_space_config_error(
        &upstream_err_space,
        "Upstream server error (503 Service Unavailable)".into(),
    );

    let upstream_res = access::activate_circle(&setup.state, ALICE_DID, &upstream_err_space).await;
    match upstream_res {
        Err(AppError::Internal(_)) => {
            let resp = upstream_res.unwrap_err().into_response();
            assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
        other => panic!("Expected Internal for upstream failure, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn membership_and_authority_app_access_expire_after_thirty_seconds_with_expired_oauth(
    pool: PgPool,
) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    sqlx::query("INSERT INTO circles(space_uri,circle_id,authority_did,display_name,created_at) VALUES($1,'3jzfcijpj2m2a',$2,'TTL fixture',now())")
        .bind(&space).bind(AUTHORITY_DID).execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO circle_member_cache(space_uri,member_did,cached_at) VALUES($1,$2,now())",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO circle_member_cache_meta(space_uri,last_refreshed_at,member_count) VALUES($1,now(),1)")
        .bind(&space).execute(&pool).await.unwrap();
    // Use the actual OAuth and HTTP transport path. Expired access without a
    // refresh token must never reuse an older authorization snapshot.
    setup
        .state
        .oauth_service
        .store_session(circle_appview::oauth::UserOAuthSession {
            user_did: AUTHORITY_DID.into(),
            access_token: "expired-local-fixture".into(),
            refresh_token: None,
            token_endpoint: "https://pds.fixture.example.com/oauth/token".into(),
            auth_server_iss: "https://pds.fixture.example.com".into(),
            expires_at: Some(Utc::now() - chrono::Duration::seconds(60)),
            scope: "atproto".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        })
        .await
        .unwrap();
    let mut state = setup.state.clone();
    state.space_client = Arc::new(SpaceClient::new());
    state
        .space_client
        .set_deps(circle_appview::space_client::SpaceClientDeps {
            http_client: state.http_client.clone(),
            did_resolver: state.did_resolver.clone(),
            oauth_service: state.oauth_service.clone(),
        });
    access::check_member_access(&state, &space, ALICE_DID)
        .await
        .unwrap();
    access::check_member_access(&state, &space, AUTHORITY_DID)
        .await
        .unwrap();
    sqlx::query("UPDATE circle_member_cache_meta SET last_refreshed_at=now()-INTERVAL '31 seconds' WHERE space_uri=$1")
        .bind(&space).execute(&pool).await.unwrap();
    for did in [ALICE_DID, AUTHORITY_DID] {
        assert!(matches!(
            access::verify_member_access(&state, &space, did)
                .await
                .unwrap(),
            access::MemberAccessOutcome::IndeterminateDenied
        ));
    }
    let grant: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM circle_member_cache WHERE space_uri=$1 AND member_did=$2)",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        grant,
        "failed OAuth refresh denies without pretending membership was removed"
    );
}

/// Lists the Circles `did` sees through blue.catbird.circle.listCircles.
async fn listed_circles(
    setup: &TestSetup,
    did: &str,
    signing_key: &p256::ecdsa::SigningKey,
) -> Vec<String> {
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use catbird_atproto::generated::blue_catbird::circle::list_circles::ListCirclesOutput;
    use tower::ServiceExt;

    let jwt = mint_service_jwt(did, "blue.catbird.circle.listCircles", signing_key);
    let req = Request::builder()
        .method("GET")
        .uri("/xrpc/blue.catbird.circle.listCircles")
        .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let output: ListCirclesOutput = serde_json::from_slice(&body).unwrap();
    output
        .circles
        .iter()
        .map(|c| c.uri.as_str().to_string())
        .collect()
}

/// Seeds an active Circle whose mock host lists `members`, and caches that list.
async fn seed_circle_with_members(setup: &TestSetup, space: &str, members: &[&str]) {
    setup.mock_transport.set_space_config(
        space,
        circle_appview::space_client::SpaceConfig {
            authority: AUTHORITY_DID.to_string(),
            space_type: "blue.catbird.circle".to_string(),
            skey: "skey-test".to_string(),
            app_access: circle_appview::space_client::SpaceAppAccess::AllowList(vec![setup
                .state
                .oauth_service
                .client_id
                .clone()]),
            read_policy: circle_appview::space_client::SpacePolicy::MemberList,
            write_policy: circle_appview::space_client::SpacePolicy::MemberList,
            user_policy: None,
            name: Some("Test Circle".to_string()),
            description: None,
        },
    );
    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted) VALUES ($1, '3jzfcijpj2m2a', $2, 'Test Circle', now(), true)",
    )
    .bind(space)
    .bind(AUTHORITY_DID)
    .execute(&setup.pool)
    .await
    .unwrap();
    set_host_members(setup, space, members);
    access::refresh_member_cache(&setup.state, space)
        .await
        .unwrap();
}

fn set_host_members(setup: &TestSetup, space: &str, members: &[&str]) {
    setup
        .mock_transport
        .set_space_members(space, members.iter().map(|m| m.to_string()).collect());
}

/// Ages every Circle's member cache past the 30-second freshness window.
async fn age_member_caches(pool: &PgPool) {
    sqlx::query(
        "UPDATE circle_member_cache_meta SET last_refreshed_at = now() - INTERVAL '10 minutes'",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn fresh_member_cache_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM circle_member_cache_meta WHERE last_refreshed_at > now() - INTERVAL '30 seconds'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn readded_member_sees_quiet_circle_again_through_own_listing(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    seed_circle_with_members(&setup, &space, &[BOB_DID]).await;
    assert_eq!(
        listed_circles(&setup, BOB_DID, &setup.bob_signing_key).await,
        vec![space.clone()]
    );

    // The owner removes Bob; a refresh drops his cache row entirely.
    set_host_members(&setup, &space, &[]);
    access::refresh_member_cache(&setup.state, &space)
        .await
        .unwrap();
    let bob_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(BOB_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bob_rows, 0, "removal deletes the member's cache row");

    // The owner re-adds Bob and nobody else touches this quiet Circle.
    set_host_members(&setup, &space, &[BOB_DID]);
    age_member_caches(&pool).await;

    assert_eq!(
        listed_circles(&setup, BOB_DID, &setup.bob_signing_key).await,
        vec![space.clone()],
        "a re-added member's own listing must revalidate the Circle they left"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn former_member_revalidation_is_capped_and_reveals_nothing(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let spaces: Vec<String> = (0..7)
        .map(|i| format!("at://{AUTHORITY_DID}/space/blue.catbird.circle/3k2former{i}"))
        .collect();
    for space in &spaces {
        seed_circle_with_members(&setup, space, &[BOB_DID]).await;
        set_host_members(&setup, space, &[]);
        access::refresh_member_cache(&setup.state, space)
            .await
            .unwrap();
    }
    age_member_caches(&pool).await;

    // Alice was never a member of any of them: her listing makes no host call.
    assert!(listed_circles(&setup, ALICE_DID, &setup.alice_signing_key)
        .await
        .is_empty());
    assert_eq!(fresh_member_cache_count(&pool).await, 0);

    // Bob is still removed everywhere. Each listing revalidates at most the
    // per-request cap, in rotation, and never lists a Circle he cannot read.
    let cap = access::MAX_FORMER_MEMBER_REVALIDATIONS_PER_REQUEST;
    assert!(cap < spaces.len() as i64);
    assert!(listed_circles(&setup, BOB_DID, &setup.bob_signing_key)
        .await
        .is_empty());
    assert_eq!(fresh_member_cache_count(&pool).await, cap);
    assert!(listed_circles(&setup, BOB_DID, &setup.bob_signing_key)
        .await
        .is_empty());
    assert_eq!(fresh_member_cache_count(&pool).await, spaces.len() as i64);

    // Purging a Circle, then the account, drops the former-member rows.
    let former_rows = |pool: PgPool| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM circle_former_members WHERE member_did = $1",
        )
        .bind(BOB_DID)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    assert_eq!(former_rows(pool.clone()).await, spaces.len() as i64);
    circle_appview::purge::delete_space(&pool, &setup.state.credential_store, &spaces[0])
        .await
        .unwrap();
    assert_eq!(former_rows(pool.clone()).await, spaces.len() as i64 - 1);
    circle_appview::purge::purge_deleted_author(&pool, BOB_DID)
        .await
        .unwrap();
    assert_eq!(former_rows(pool.clone()).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn listed_member_regranted_read_sees_quiet_circle_through_own_listing(pool: PgPool) {
    use circle_appview::space_client::SpaceMember;

    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    seed_circle_with_members(&setup, &space, &[]).await;
    let bob = |read: bool| SpaceMember {
        did: BOB_DID.to_string(),
        read,
        write: true,
    };

    // Bob stays on the member list but without read access.
    setup
        .mock_transport
        .set_space_members_detailed(&space, vec![bob(false)]);
    access::refresh_member_cache(&setup.state, &space)
        .await
        .unwrap();
    assert!(listed_circles(&setup, BOB_DID, &setup.bob_signing_key)
        .await
        .is_empty());

    // The owner grants read again and nobody else touches the Circle.
    setup
        .mock_transport
        .set_space_members_detailed(&space, vec![bob(true)]);
    age_member_caches(&pool).await;
    assert_eq!(
        listed_circles(&setup, BOB_DID, &setup.bob_signing_key).await,
        vec![space.clone()]
    );
}

async fn former_member_row_count(pool: &PgPool, space: &str, did: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM circle_former_members WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(space)
    .bind(did)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn sorted(mut uris: Vec<String>) -> Vec<String> {
    uris.sort();
    uris
}

#[sqlx::test(migrations = "./migrations")]
async fn relisted_member_loses_former_row_and_frees_the_cap(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let readded = format!("at://{AUTHORITY_DID}/space/blue.catbird.circle/3k2readded");
    let removed: Vec<String> = (0..access::MAX_FORMER_MEMBER_REVALIDATIONS_PER_REQUEST)
        .map(|i| format!("at://{AUTHORITY_DID}/space/blue.catbird.circle/3k2removed{i}"))
        .collect();
    for space in std::iter::once(&readded).chain(&removed) {
        seed_circle_with_members(&setup, space, &[BOB_DID]).await;
        set_host_members(&setup, space, &[]);
        access::refresh_member_cache(&setup.state, space)
            .await
            .unwrap();
        assert_eq!(former_member_row_count(&pool, space, BOB_DID).await, 1);
    }

    // The owner re-adds Bob to one Circle and some other request refreshes it.
    set_host_members(&setup, &readded, &[BOB_DID]);
    access::refresh_member_cache(&setup.state, &readded)
        .await
        .unwrap();
    assert_eq!(
        former_member_row_count(&pool, &readded, BOB_DID).await,
        0,
        "a refresh that lists the member again forgets the former-member row"
    );

    // The re-added Circle now comes through the member branch, so the whole
    // former-member cap goes to the Circles Bob is still removed from.
    //
    // The count below catches a kept former-member row only because
    // `3k2readded` sorts before every `3k2removed*`: never-checked rows are
    // picked in `space_uri` order, so a kept row would take a cap slot and
    // leave one removed Circle unrefreshed. Sorted last, it would fall outside
    // the cap and the count would pass anyway. The `former_member_row_count`
    // assertion above is the check that does not depend on that order.
    age_member_caches(&pool).await;
    assert_eq!(
        listed_circles(&setup, BOB_DID, &setup.bob_signing_key).await,
        vec![readded.clone()]
    );
    assert_eq!(
        fresh_member_cache_count(&pool).await,
        1 + removed.len() as i64,
        "a stale former-member row must not take a slot from the cap"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn former_member_host_failures_are_retried_at_most_every_thirty_seconds(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let cap = access::MAX_FORMER_MEMBER_REVALIDATIONS_PER_REQUEST;
    // Ordered by URI: the first `cap` Circles are picked first and their host fails.
    let spaces: Vec<String> = (0..=cap)
        .map(|i| format!("at://{AUTHORITY_DID}/space/blue.catbird.circle/3k2throttle{i}"))
        .collect();
    let (failing, waiting) = spaces.split_at(cap as usize);
    for space in &spaces {
        seed_circle_with_members(&setup, space, &[BOB_DID]).await;
        set_host_members(&setup, space, &[]);
        access::refresh_member_cache(&setup.state, space)
            .await
            .unwrap();
    }
    for space in failing {
        setup
            .mock_transport
            .set_space_members_error(space, "Upstream unavailable".to_string());
    }
    age_member_caches(&pool).await;

    // First listing: the cap goes to the failing Circles and none refreshes.
    assert!(listed_circles(&setup, BOB_DID, &setup.bob_signing_key)
        .await
        .is_empty());
    assert_eq!(fresh_member_cache_count(&pool).await, 0);

    // Every host recovers and lists Bob again. Within 30 s the failed
    // Circles are not retried, so a host call to one would show up as a
    // fresh cache; the Circle that waited gets its turn instead.
    for space in &spaces {
        set_host_members(&setup, space, &[BOB_DID]);
    }
    assert_eq!(
        listed_circles(&setup, BOB_DID, &setup.bob_signing_key).await,
        waiting.to_vec(),
        "a former-member Circle is checked at most once per 30 s"
    );
    assert_eq!(fresh_member_cache_count(&pool).await, 1);

    // Once 30 s have passed the failed Circles are retried.
    sqlx::query(
        "UPDATE circle_former_members SET last_checked_at = now() - INTERVAL '31 seconds' WHERE member_did = $1",
    )
    .bind(BOB_DID)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        sorted(listed_circles(&setup, BOB_DID, &setup.bob_signing_key).await),
        spaces
    );
}

/// GETs an XRPC query as `did` and returns the body of its 200 response.
async fn xrpc_get_ok(
    setup: &TestSetup,
    did: &str,
    signing_key: &p256::ecdsa::SigningKey,
    method: &str,
) -> axum::body::Bytes {
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    let jwt = mint_service_jwt(did, method, signing_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/{method}"))
        .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    body
}

/// The Circle of every post `did` sees through unified blue.catbird.circle.getFeed.
async fn feed_circles(
    setup: &TestSetup,
    did: &str,
    signing_key: &p256::ecdsa::SigningKey,
) -> Vec<String> {
    use catbird_atproto::generated::blue_catbird::circle::get_feed::GetFeedOutput;

    let body = xrpc_get_ok(setup, did, signing_key, "blue.catbird.circle.getFeed").await;
    let output: GetFeedOutput = serde_json::from_slice(&body).unwrap();
    output
        .feed
        .iter()
        .map(|item| item.circle.uri.as_str().to_string())
        .collect()
}

/// The Circle of every notification `did` sees through blue.catbird.circle.listNotifications.
async fn notification_circles(
    setup: &TestSetup,
    did: &str,
    signing_key: &p256::ecdsa::SigningKey,
) -> Vec<String> {
    use catbird_atproto::generated::blue_catbird::circle::list_notifications::ListNotificationsOutput;

    let body = xrpc_get_ok(
        setup,
        did,
        signing_key,
        "blue.catbird.circle.listNotifications",
    )
    .await;
    let output: ListNotificationsOutput = serde_json::from_slice(&body).unwrap();
    output
        .notifications
        .iter()
        .map(|n| n.circle.uri.as_str().to_string())
        .collect()
}

async fn cache_profile(setup: &TestSetup, did: &str, handle: &str) {
    use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
    use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
    use catbird_atproto::jacquard_common::types::string::{Did, Handle};

    setup
        .state
        .profile_hydrator
        .set_cached_profile(
            did,
            ProfileViewBasic {
                did: Did::new(SmolStr::new(did)).unwrap(),
                handle: Handle::new(SmolStr::new(handle)).unwrap(),
                display_name: None,
                avatar: None,
                associated: None,
                viewer: None,
                labels: None,
                created_at: None,
                pronouns: None,
                status: None,
                verification: None,
                debug: None,
                extra_data: None,
            },
        )
        .await;
}

/// Seeds a Circle that lists Bob, with an owner post and a notification for Bob,
/// then has the owner remove and re-add Bob with nobody else touching the Circle.
async fn seed_quiet_circle_bob_was_readded_to(setup: &TestSetup) -> String {
    let space = space_uri();
    cache_profile(setup, AUTHORITY_DID, "authority.test").await;
    cache_profile(setup, BOB_DID, "bob.test").await;
    seed_circle_with_members(setup, &space, &[BOB_DID]).await;
    let post = json!({"$type": "app.bsky.feed.post", "text": "Owner post", "createdAt": Utc::now().to_rfc3339()});
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, indexed_at, created_at)
        VALUES ($1, 'bafyreicidreadded', $2, $3, 'app.bsky.feed.post', 'post1', $4, now(), now())
        "#,
    )
    .bind(format!("{space}/app.bsky.feed.post/post1"))
    .bind(&space)
    .bind(AUTHORITY_DID)
    .bind(&post)
    .execute(&setup.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, source_uri, created_at) VALUES ($1, $2, $3, $4, 'like', $5, now())",
    )
    .bind(Uuid::new_v4())
    .bind(BOB_DID)
    .bind(&space)
    .bind(AUTHORITY_DID)
    .bind(format!("{space}/app.bsky.feed.like/like1"))
    .execute(&setup.pool)
    .await
    .unwrap();
    assert_eq!(
        feed_circles(setup, BOB_DID, &setup.bob_signing_key).await,
        vec![space.clone()]
    );
    assert_eq!(
        notification_circles(setup, BOB_DID, &setup.bob_signing_key).await,
        vec![space.clone()]
    );

    set_host_members(setup, &space, &[]);
    access::refresh_member_cache(&setup.state, &space)
        .await
        .unwrap();
    assert!(feed_circles(setup, BOB_DID, &setup.bob_signing_key)
        .await
        .is_empty());
    assert!(notification_circles(setup, BOB_DID, &setup.bob_signing_key)
        .await
        .is_empty());

    set_host_members(setup, &space, &[BOB_DID]);
    age_member_caches(&setup.pool).await;
    space
}

#[sqlx::test(migrations = "./migrations")]
async fn readded_member_sees_quiet_circle_again_through_own_unified_feed(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = seed_quiet_circle_bob_was_readded_to(&setup).await;
    assert_eq!(
        feed_circles(&setup, BOB_DID, &setup.bob_signing_key).await,
        vec![space],
        "a re-added member's unified feed must revalidate the Circle they left"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn readded_member_sees_quiet_circle_again_through_own_notifications(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = seed_quiet_circle_bob_was_readded_to(&setup).await;
    assert_eq!(
        notification_circles(&setup, BOB_DID, &setup.bob_signing_key).await,
        vec![space],
        "a re-added member's notifications must revalidate the Circle they left"
    );
}
