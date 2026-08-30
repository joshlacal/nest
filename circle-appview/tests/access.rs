use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use circle_appview::{
    access::{self, ActiveSpaceCredential},
    auth::{DidDocument, DidResolver, DidService, PublicKeyJwk, VerificationMethod},
    config::{AppState, Config},
    db,
    error::AuthReason,
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

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circles"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
        commit_verification_policy: circle_appview::commit::CommitVerificationPolicy::default(),
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
            id: "#atproto_space_host".into(),
            r#type: "AtprotoSpaceHost".into(),
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
        "kid": format!("{iss}#atproto")
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
        dpop_key: signing_key.clone(),
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
        dpop_key: signing_key.clone(),
        expires_at: Utc::now() + chrono::Duration::hours(2),
    };
    store.insert(space.clone(), cred2).await;
    assert_eq!(store.get(&space).await.unwrap().token, "jwt_token_2");

    // Overwrite with shorter lifetime is ignored
    let cred_shorter = ActiveSpaceCredential {
        token: "jwt_token_shorter".into(),
        dpop_key: signing_key,
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
async fn space_host_resolution_falls_back_to_atproto_pds(pool: PgPool) {
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

    // Only the endpoint falls back. The service identifier is the audience of a
    // client attestation and of a delegation token, and always names the
    // space-host role fully qualified. Asserting "#atproto_pds" here is what let
    // the AppView send a bare relative fragment as an `aud`, which the live PDS
    // rejected with InvalidClientAttestation.
    assert_eq!(endpoint, pds_endpoint);
    assert_eq!(service_id, format!("{AUTHORITY_DID}#atproto_space_host"));
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
                    let has_auth = req_str.contains("authorization: Bearer test-delegation-token")
                        || req_str.contains("Authorization: Bearer test-delegation-token");
                    let has_dpop = req_str.contains("dpop: test-dpop-proof")
                        || req_str.contains("DPoP: test-dpop-proof");
                    if has_auth && has_dpop {
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

    let cred = transport_success
        .get_space_credential(
            &target_url,
            "test-delegation-token",
            "test-dpop-proof",
            "at://did:plc:auth/space/1",
            "test-attestation",
        )
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
        .get_space_credential(
            &redirect_url,
            "test-delegation-token",
            "test-dpop-proof",
            "at://did:plc:auth/space/1",
            "test-attestation",
        )
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
            "members": [{"did": "did:plc:user1"}],
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
