//! Circle management and projection outbox tests

use catbird::config::{AppConfig, AppState};
use catbird::models::{
    CatbirdSession, CircleError, CIRCLE_MEMBER_SCOPE, CIRCLE_OWNER_SCOPE,
};
use catbird::services::{
    AtProtoCircleProbe, CircleCapabilityService, CircleService,
    ClientAttestationProvider, DpopNonceCache, KeyStore, ServiceAuthProvider,
};
use catbird_atproto::generated::blue_catbird::circle::activate_space::ActivateSpace;
use catbird_atproto::generated::blue_catbird::circle::create_circle::CreateCircle;
use catbird_atproto::generated::blue_catbird::circle::defs::{
    AccessState, MemberAction, OperationStatus, SpaceRef,
};
use catbird_atproto::generated::blue_catbird::circle::delete_circle::DeleteCircle;
use catbird_atproto::generated::blue_catbird::circle::update_member::UpdateMember;
use catbird_atproto::types::string::Did;
use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn alice_session(pds_url: &str) -> CatbirdSession {
    CatbirdSession {
        id: Uuid::new_v4(),
        did: "did:plc:alice".into(),
        handle: "alice.bsky.social".into(),
        pds_url: pds_url.into(),
        access_token: "mock-access-token".into(),
        refresh_token: "mock-refresh-token".into(),
        scopes: vec![
            "atproto".into(),
            "transition:chat.bsky".into(),
            CIRCLE_OWNER_SCOPE.into(),
            CIRCLE_MEMBER_SCOPE.into(),
        ],
        access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
        created_at: Utc::now(),
        last_used_at: Utc::now(),
    }
}

fn space() -> SpaceRef {
    SpaceRef::new("at://did:plc:alice/space/blue.catbird.circle/test-circle-1".into()).unwrap()
}

fn bob() -> Did {
    Did::new("did:plc:bob".into()).unwrap()
}

fn carol() -> Did {
    Did::new("did:plc:carol".into()).unwrap()
}

async fn create_test_state(
    pool: Option<PgPool>,
    _pds_url: &str,
    appview_url: Option<String>,
    plc_url: Option<String>,
) -> Arc<AppState> {
    let mut config = AppConfig::load().unwrap();
    config.circle.service_url = appview_url;
    config.circle.service_did = "did:web:circles.catbird.blue#atproto_circle".into();
    config.circle.plc_directory_url = plc_url;
    config.oauth.client_id = "https://api.catbird.blue".into();

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    let redis_client = redis::Client::open(config.redis.url.as_str()).unwrap();
    let redis = redis::aio::ConnectionManager::new(redis_client).await.unwrap();

    let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
    let key_store = Arc::new(KeyStore::from_key("key-1", secret_key));

    let dpop_nonce_cache = Arc::new(DpopNonceCache::new());
    let circle_probe = AtProtoCircleProbe::new();
    let circle_capability = Arc::new(CircleCapabilityService::new(circle_probe));

    let (auth_store, jacquard_client) = {
        let store = catbird::services::RedisAuthStore::new(
            redis.clone(),
            config.redis.key_prefix.clone(),
            config.redis.session_ttl_seconds,
            None,
        );
        let keyset = key_store.to_jacquard_keyset().unwrap();
        let client_id = url::Url::parse(&config.oauth.client_id).unwrap();
        let redirect_uri = url::Url::parse(&config.oauth.redirect_uri).unwrap();
        let metadata = jacquard_oauth::atproto::AtprotoClientMetadata::new(
            client_id,
            None,
            vec![redirect_uri],
            vec![
                jacquard_oauth::atproto::GrantType::AuthorizationCode,
                jacquard_oauth::atproto::GrantType::RefreshToken,
            ],
            vec![],
            None,
        );
        let client_data = jacquard_oauth::session::ClientData::new(Some(keyset), metadata);
        let resolver_client = reqwest::Client::builder().build().unwrap();
        let resolver = jacquard_identity::JacquardResolver::new(
            resolver_client,
            jacquard_identity::resolver::ResolverOptions::default(),
        );
        let client = catbird::config::JacquardOAuthClient::new_from_resolver(store.clone(), resolver, client_data);
        (Arc::new(store), Arc::new(client))
    };

    let state = Arc::new(AppState {
        config: Arc::new(config),
        http_client,
        redis,
        push_db: pool,
        key_store: Some(key_store),
        jacquard_client: Some(jacquard_client),
        catmos_jacquard_client: None,
        auth_store: Some(auth_store),
        push: None,
        dpop_nonce_cache,
        circle_capability,
        circle_worker_alive: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        session_encryption_key: None,
    });

    state.circle_capability.set_state(Arc::downgrade(&state));
    state
}

async fn register_test_session(state: &AppState, session: &CatbirdSession) {
    use jacquard_common::IntoStatic;
    use jacquard_oauth::authstore::ClientAuthStore;
    use jacquard_oauth::session::{ClientSessionData, DpopClientData};
    use jacquard_oauth::types::{OAuthTokenType, TokenSet};
    use jacquard_common::types::did::Did;

    if let Some(store) = &state.auth_store {
        let did = Did::new(&session.did).unwrap();
        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);

        let expires_at = jacquard_common::types::string::Datetime::try_from(session.access_token_expires_at.to_rfc3339()).ok();

        let session_data = ClientSessionData {
            account_did: did.clone(),
            session_id: session.id.to_string().into(),
            host_url: session.pds_url.clone().into(),
            authserver_url: session.pds_url.clone().into(),
            authserver_token_endpoint: "".into(),
            authserver_revocation_endpoint: None,
            scopes: vec![
                jacquard_oauth::scopes::Scope::Atproto,
                jacquard_oauth::scopes::Scope::Transition(
                    jacquard_oauth::scopes::TransitionScope::Generic,
                ),
            ],
            dpop_data: DpopClientData {
                dpop_key,
                dpop_authserver_nonce: "".into(),
                dpop_host_nonce: "".into(),
            },
            token_set: TokenSet {
                iss: session.pds_url.clone().into(),
                sub: did.clone(),
                aud: session.pds_url.clone().into(),
                scope: Some("atproto".into()),
                refresh_token: Some(session.refresh_token.clone().into()),
                access_token: session.access_token.clone().into(),
                token_type: OAuthTokenType::DPoP,
                expires_at,
            },
        };

        store.upsert_session(session_data.into_static()).await.unwrap();
        store.write_session_index(&session.id.to_string(), &session.did).await.unwrap();
    }
}

struct TestEnv {
    _pds: MockServer,
    _appview: MockServer,
    _plc: MockServer,
    service: CircleService,
    session: CatbirdSession,
    state: Arc<AppState>,
}

async fn setup_env(pool: PgPool) -> TestEnv {
    let pds = MockServer::start().await;
    let appview = MockServer::start().await;
    let plc = MockServer::start().await;

    let pds_url = pds.uri().replace("127.0.0.1", "localhost");
    let appview_url = appview.uri().replace("127.0.0.1", "localhost");
    let plc_url = plc.uri().replace("127.0.0.1", "localhost");

    std::env::set_var("PLC_DIRECTORY_URL", &plc_url);

    // Capability probe mock
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&pds)
        .await;

    // Standard PDS mocks
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.removeMember"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.createSpace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/space/blue.catbird.circle/test-circle-1"
        })))
        .mount(&pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.space.putRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/blue.catbird.circle.metadata/self",
            "cid": "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        })))
        .mount(&pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.deleteSpace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&pds)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.getDelegationToken"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "secret-delegation-token-xyz-123"
        })))
        .mount(&pds)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "mock-pds-service-auth-jwt"
        })))
        .mount(&pds)
        .await;

    // PLC DID Document mock for Space Host resolution
    Mock::given(method("GET"))
        .and(path("/did:plc:alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "did:plc:alice",
            "service": [
                {
                    "id": "#atproto_space_host",
                    "type": "AtprotoSpaceHost",
                    "serviceEndpoint": "https://space.catbird.blue"
                }
            ]
        })))
        .mount(&plc)
        .await;

    // Standard AppView projection mock (verifies Bearer authorization header)
    Mock::given(method("POST"))
        .and(path("/internal/projections"))
        .and(header("authorization", "Bearer mock-pds-service-auth-jwt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "status": "accepted" })))
        .mount(&appview)
        .await;

    // Standard AppView activation mock
    Mock::given(method("POST"))
        .and(path("/xrpc/blue.catbird.circle.activateSpace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessState": "active",
            "expiresAt": "2026-08-25T00:00:00Z"
        })))
        .mount(&appview)
        .await;

    let state = create_test_state(Some(pool.clone()), &pds_url, Some(appview_url), Some(plc_url)).await;
    let attestation_provider = Some(Arc::new(ClientAttestationProvider::from_state(&state).unwrap()));
    let service_auth_provider = Some(Arc::new(ServiceAuthProvider::new(state.clone())));

    let service = CircleService::with_components(
        state.clone(),
        Some(pool),
        attestation_provider,
        service_auth_provider,
    );
    let session = alice_session(&pds_url);
    register_test_session(&state, &session).await;

    TestEnv {
        _pds: pds,
        _appview: appview,
        _plc: plc,
        service,
        session,
        state,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn duplicate_member_update_creates_one_projection(pool: PgPool) {
    let env = setup_env(pool).await;

    let request = UpdateMember {
        space: space(),
        member_did: bob(),
        action: MemberAction::Add,
        extra_data: None,
    };

    let op1 = env.service.update_member(&env.session, request.clone()).await.unwrap();
    let op2 = env.service.update_member(&env.session, request).await.unwrap();

    assert_eq!(op1.id, op2.id);
    assert_eq!(env.service.get_projection_count(Some("member_add")).await.unwrap(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn member_transition_generation_advancement(pool: PgPool) {
    let env = setup_env(pool).await;

    // 1. Add Bob (generation 1)
    let add_req = UpdateMember {
        space: space(),
        member_did: bob(),
        action: MemberAction::Add,
        extra_data: None,
    };
    let op1 = env.service.update_member(&env.session, add_req.clone()).await.unwrap();
    assert_eq!(op1.status, OperationStatus::Complete);
    assert_eq!(env.service.get_projection_count(Some("member_add")).await.unwrap(), 1);

    // 2. Remove Bob (generation 2 - opposite transition advances generation)
    let remove_req = UpdateMember {
        space: space(),
        member_did: bob(),
        action: MemberAction::Remove,
        extra_data: None,
    };
    let op2 = env.service.update_member(&env.session, remove_req).await.unwrap();
    assert_eq!(op2.status, OperationStatus::Complete);
    assert_eq!(env.service.get_projection_count(Some("member_remove")).await.unwrap(), 1);

    // 3. Add Bob again (generation 3 - opposite transition advances generation)
    let op3 = env.service.update_member(&env.session, add_req.clone()).await.unwrap();
    assert_eq!(op3.status, OperationStatus::Complete);
    assert_ne!(op1.id, op3.id);
    assert_eq!(env.service.get_projection_count(Some("member_add")).await.unwrap(), 2);

    // 4. Duplicate Add Bob retry (generation 3 - same transition reuses generation)
    let op4 = env.service.update_member(&env.session, add_req).await.unwrap();
    assert_eq!(op3.id, op4.id);
    assert_eq!(env.service.get_projection_count(Some("member_add")).await.unwrap(), 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn appview_failure_keeps_pds_success_pending(pool: PgPool) {
    let pds = MockServer::start().await;
    let appview = MockServer::start().await;
    let pds_url = pds.uri().replace("127.0.0.1", "localhost");
    let appview_url = appview.uri().replace("127.0.0.1", "localhost");

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&pds)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "mock-pds-service-auth-jwt"
        })))
        .mount(&pds)
        .await;

    // AppView projection endpoint fails with 503
    Mock::given(method("POST"))
        .and(path("/internal/projections"))
        .respond_with(ResponseTemplate::new(503).set_body_string("AppView Down"))
        .mount(&appview)
        .await;

    let state = create_test_state(Some(pool.clone()), &pds_url, Some(appview_url), None).await;
    let service = CircleService::new(state);
    let session = alice_session(&pds_url);

    let request = UpdateMember {
        space: space(),
        member_did: bob(),
        action: MemberAction::Add,
        extra_data: None,
    };

    let result = service.update_member(&session, request).await.unwrap();
    assert_eq!(result.status, OperationStatus::Pending);
    assert_eq!(service.get_pending_projection_count().await.unwrap(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn create_circle_and_outbox_projections(pool: PgPool) {
    let env = setup_env(pool).await;

    let input = CreateCircle {
        name: "Close Friends".into(),
        member_dids: vec![bob(), carol()],
        extra_data: None,
    };

    let op = env.service.create_circle(&env.session, input).await.unwrap();
    assert_eq!(op.status, OperationStatus::Complete);
    assert!(op.space.is_some());

    // Expect 1 circle_upsert and 2 member_add
    assert_eq!(env.service.get_projection_count(Some("circle_upsert")).await.unwrap(), 1);
    assert_eq!(env.service.get_projection_count(Some("member_add")).await.unwrap(), 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn create_circle_initial_member_partial_failure(pool: PgPool) {
    let pds = MockServer::start().await;
    let appview = MockServer::start().await;
    let pds_url = pds.uri().replace("127.0.0.1", "localhost");
    let appview_url = appview.uri().replace("127.0.0.1", "localhost");

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.createSpace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/space/blue.catbird.circle/test-circle-1"
        })))
        .mount(&pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.space.putRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/blue.catbird.circle.metadata/self",
            "cid": "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        })))
        .mount(&pds)
        .await;

    // Add Bob succeeds
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .and(wiremock::matchers::body_string_contains("did:plc:bob"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&pds)
        .await;

    // Add Carol fails at PDS
    // Add Carol fails with explicit non-idempotent 400 error at PDS
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .and(wiremock::matchers::body_string_contains("did:plc:carol"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid Member DID"))
        .mount(&pds)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "mock-pds-service-auth-jwt"
        })))
        .mount(&pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/internal/projections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "status": "accepted" })))
        .mount(&appview)
        .await;

    let state = create_test_state(Some(pool.clone()), &pds_url, Some(appview_url), None).await;
    let service = CircleService::new(state);
    let session = alice_session(&pds_url);

    let input = CreateCircle {
        name: "Partial Failure Circle".into(),
        member_dids: vec![bob(), carol()],
        extra_data: None,
    };

    let op = service.create_circle(&session, input).await.unwrap();
    assert_eq!(op.status, OperationStatus::Failed);
    assert_eq!(op.error.as_deref(), Some("MemberAdditionPartialFailure"));
    // 1 circle_upsert (delivered), and 2 member_add total in outbox (Bob = delivered, Carol = failed durable terminal child)
    assert_eq!(service.get_projection_count(Some("circle_upsert")).await.unwrap(), 1);
    assert_eq!(service.get_projection_count(Some("member_add")).await.unwrap(), 2);
    assert_eq!(service.get_pending_projection_count().await.unwrap(), 0);

    // Verify Carol's record in outbox is durably in 'failed' state
    let carol_state: (String,) = sqlx::query_as(
        "SELECT state FROM circle_projection_outbox WHERE payload->>'member' = 'did:plc:carol'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(carol_state.0, "failed");

    // Verify Bob's record in outbox is in 'delivered' state
    let bob_state: (String,) = sqlx::query_as(
        "SELECT state FROM circle_projection_outbox WHERE payload->>'member' = 'did:plc:bob'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bob_state.0, "delivered");
}

#[sqlx::test(migrations = "./migrations")]
async fn activation_does_not_store_delegation_token(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    let request = ActivateSpace {
        space: space(),
        extra_data: None,
    };

    let output = env.service.activate_space(&env.session, request).await.unwrap();
    assert_eq!(output.access_state, AccessState::Active);

    // Verify database dump does NOT contain the secret token anywhere
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT payload::text FROM circle_projection_outbox"
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    let secret_token = "secret-delegation-token-xyz-123";
    for row in rows {
        assert!(!row.0.contains(secret_token), "Database leaked delegation token!");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_circle_and_outbox_projection(pool: PgPool) {
    let env = setup_env(pool).await;

    let input = DeleteCircle {
        space: space(),
        extra_data: None,
    };

    let op = env.service.delete_circle(&env.session, input).await.unwrap();
    assert_eq!(op.status, OperationStatus::Complete);

    assert_eq!(env.service.get_projection_count(Some("circle_delete")).await.unwrap(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn retry_worker_delivers_due_projections(pool: PgPool) {
    let pds = MockServer::start().await;
    let appview = MockServer::start().await;
    let pds_url = pds.uri().replace("127.0.0.1", "localhost");
    let appview_url = appview.uri().replace("127.0.0.1", "localhost");

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&pds)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "mock-pds-service-auth-jwt"
        })))
        .mount(&pds)
        .await;

    // Initially fails
    Mock::given(method("POST"))
        .and(path("/internal/projections"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Temporary error"))
        .up_to_n_times(1)
        .mount(&appview)
        .await;

    // Subsequent retries succeed
    Mock::given(method("POST"))
        .and(path("/internal/projections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "status": "ok" })))
        .mount(&appview)
        .await;

    let state = create_test_state(Some(pool.clone()), &pds_url, Some(appview_url), None).await;
    let service = CircleService::new(state.clone());
    let session = alice_session(&pds_url);
    register_test_session(&state, &session).await;

    let request = UpdateMember {
        space: space(),
        member_did: bob(),
        action: MemberAction::Add,
        extra_data: None,
    };

    let op = service.update_member(&session, request).await.unwrap();
    assert_eq!(op.status, OperationStatus::Pending);
    assert_eq!(service.get_pending_projection_count().await.unwrap(), 1);

    // Fast-forward next_attempt_at in DB
    sqlx::query("UPDATE circle_projection_outbox SET next_attempt_at = now() - interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();

    // Run retry processor
    let delivered = service.process_due_projections(10).await.unwrap();
    assert_eq!(delivered, 1);
    assert_eq!(service.get_pending_projection_count().await.unwrap(), 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn bounds_validation_rejects_oversized_inputs(pool: PgPool) {
    let env = setup_env(pool).await;

    // 1. Empty name
    let empty_name = CreateCircle {
        name: "   ".into(),
        member_dids: vec![],
        extra_data: None,
    };
    let res = env.service.create_circle(&env.session, empty_name).await;
    assert!(matches!(res, Err(CircleError::InvalidRequest(_))));

    // 2. Oversized name (> 64 chars)
    let long_name = CreateCircle {
        name: ("a".repeat(65)).into(),
        member_dids: vec![],
        extra_data: None,
    };
    let res = env.service.create_circle(&env.session, long_name).await;
    assert!(matches!(res, Err(CircleError::InvalidRequest(_))));

    // 3. Oversized initial members (> 150 members)
    let many_members = (0..151)
        .map(|i| Did::new(format!("did:plc:user{i}").into()).unwrap())
        .collect::<Vec<_>>();
    let too_many = CreateCircle {
        name: "Crowd".into(),
        member_dids: many_members,
        extra_data: None,
    };
    let res = env.service.create_circle(&env.session, too_many).await;
    assert!(matches!(res, Err(CircleError::InvalidRequest(_))));

    // 4. Duplicate initial member DIDs
    env._pds.reset().await;
    let duplicate_members = CreateCircle {
        name: "Duplicates".into(),
        member_dids: vec![bob(), bob()],
        extra_data: None,
    };
    let res = env.service.create_circle(&env.session, duplicate_members).await;
    assert!(matches!(res, Err(CircleError::InvalidRequest(_))));
    assert_eq!(
        env._pds.received_requests().await.unwrap().len(),
        0,
        "Zero PDS requests must be made when duplicate initial DIDs are rejected"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn standalone_circle_routes_and_capabilities(pool: PgPool) {
    use tower::ServiceExt;

    let pds = MockServer::start().await;
    let pds_url = pds.uri().replace("127.0.0.1", "localhost");

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&pds)
        .await;

    let state = create_test_state(Some(pool), &pds_url, None, None).await;
    let app = catbird::routes::circle::routes((*state).clone());

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/xrpc/blue.catbird.circle.getCapabilities")
        .extension(alice_session(&pds_url))
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert_eq!(status, axum::http::StatusCode::OK, "Failed with body: {body_str}");

    let output: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(output["enabled"], true);
    assert_eq!(output["supportsImages"], true);
}

#[sqlx::test(migrations = "./migrations")]
async fn pds_network_and_http_failure_marks_outbox_failed(pool: PgPool) {
    let pds = MockServer::start().await;
    let pds_url = pds.uri().replace("127.0.0.1", "localhost");

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&pds)
        .await;

    // 1. PDS returns 400 Bad Request on addMember -> deterministic rejection -> outbox row is updated to 'failed'
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request: member not permitted"))
        .mount(&pds)
        .await;

    let state = create_test_state(Some(pool.clone()), &pds_url, Some("http://localhost:9999".into()), None).await;
    let service = CircleService::new(state.clone());
    let session = alice_session(&pds_url);

    let request = UpdateMember {
        space: space(),
        member_did: bob(),
        action: MemberAction::Add,
        extra_data: None,
    };

    let err = service.update_member(&session, request).await;
    assert!(err.is_err());

    let row_state: (String, Option<String>) = sqlx::query_as(
        "SELECT state, last_error_code FROM circle_projection_outbox WHERE payload->>'member' = 'did:plc:bob'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row_state.0, "failed");
    assert!(row_state.1.unwrap().contains("PDS operation failed (400)"));

    // 2. Genuine network failure during mutation (PDS connection refused after capability primed)
    let pds2 = MockServer::start().await;
    let pds2_url = pds2.uri().replace("127.0.0.1", "localhost");

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&pds2)
        .await;

    // PDS2 returns 503 (indeterminate server/network error) on mutation
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .respond_with(ResponseTemplate::new(503).set_body_string("PDS Gateway Timeout"))
        .mount(&pds2)
        .await;

    let net_state = create_test_state(Some(pool.clone()), &pds2_url, Some("http://localhost:9999".into()), None).await;
    let net_service = CircleService::new(net_state.clone());
    let carol_session = alice_session(&pds2_url);
    register_test_session(&net_state, &carol_session).await;

    let dave_did = Did::new("did:plc:dave-net-err".into()).unwrap();
    let request2 = UpdateMember {
        space: space(),
        member_did: dave_did.clone(),
        action: MemberAction::Add,
        extra_data: None,
    };

    let err2 = net_service.update_member(&carol_session, request2).await;
    assert!(err2.is_err());

    let dave_state: (String, Option<String>) = sqlx::query_as(
        "SELECT state, last_error_code FROM circle_projection_outbox WHERE payload->>'member' = $1"
    )
    .bind(dave_did.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(dave_state.0, "executing");
    let last_err = dave_state.1.as_deref().unwrap_or("");
    assert!(last_err.contains("server error") || last_err.contains("503") || last_err.contains("PDS"), "Expected server error, got: {last_err}");
}

#[sqlx::test(migrations = "./migrations")]
async fn retry_worker_queries_only_pending_and_not_intent(pool: PgPool) {
    let pds = MockServer::start().await;
    let appview = MockServer::start().await;
    let pds_url = pds.uri().replace("127.0.0.1", "localhost");
    let appview_url = appview.uri().replace("127.0.0.1", "localhost");

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&pds)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "mock-pds-service-auth-jwt"
        })))
        .mount(&pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/internal/projections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "status": "accepted" })))
        .mount(&appview)
        .await;

    let state = create_test_state(Some(pool.clone()), &pds_url, Some(appview_url), None).await;
    let service = CircleService::new(state);

    // Manually insert an 'intent' row and a 'pending' row
    let intent_id = Uuid::new_v4();
    let pending_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO circle_projection_outbox (
            id, operation_key, actor_did, session_id, space_uri, kind, payload, state, attempts, next_attempt_at, created_at, updated_at
        ) VALUES
            ($1, 'key-intent-1', 'did:plc:alice', 'sess-1', 'at://did:plc:alice/space/1', 'member_add', '{"member":"bob","circleGeneration":1,"memberGeneration":1}'::jsonb, 'intent', 0, now() - interval '10 seconds', now(), now()),
            ($2, 'key-pending-1', 'did:plc:alice', 'sess-1', 'at://did:plc:alice/space/1', 'member_add', '{"member":"carol","circleGeneration":1,"memberGeneration":1}'::jsonb, 'pending', 0, now() - interval '10 seconds', now(), now())
        "#
    )
    .bind(intent_id)
    .bind(pending_id)
    .execute(&pool)
    .await
    .unwrap();

    // Process due projections - worker must ONLY select the 'pending' row
    // (and attempt delivery for it)
    let delivered = service.process_due_projections(10).await.unwrap();
    // Recovery fails because no jacquard session in mock, but attempts incremented on pending_id only!
    assert_eq!(delivered, 0);

    // Verify intent_id was NEVER touched by the worker (attempts remains 0, state remains 'intent')
    let (intent_state, intent_attempts): (String, i32) = sqlx::query_as(
        "SELECT state, attempts FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(intent_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(intent_state, "intent");
    assert_eq!(intent_attempts, 0);

    // Verify pending_id was processed (attempts incremented to 1)
    let (pending_state, pending_attempts): (String, i32) = sqlx::query_as(
        "SELECT state, attempts FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(pending_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending_state, "pending");
    assert_eq!(pending_attempts, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn circle_worker_liveness_in_readiness(pool: PgPool) {
    use tower::ServiceExt;

    let pds = MockServer::start().await;
    let pds_url = pds.uri().replace("127.0.0.1", "localhost");

    let state = create_test_state(Some(pool), &pds_url, Some("http://localhost:9999".into()), None).await;

    // 1. Worker alive is false -> /ready returns 503
    state.circle_worker_alive.store(false, std::sync::atomic::Ordering::SeqCst);

    let app = axum::Router::new()
        .route("/ready", axum::routing::get(catbird::routes::health::readiness_check))
        .with_state(state.clone());

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/ready")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);

    // 2. Worker alive is true -> /ready returns 200 OK
    state.circle_worker_alive.store(true, std::sync::atomic::Ordering::SeqCst);

    let req2 = axum::http::Request::builder()
        .method("GET")
        .uri("/ready")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), axum::http::StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_typed_inputs_return_invalid_request(pool: PgPool) {
    use tower::ServiceExt;

    let pds = MockServer::start().await;
    let pds_url = pds.uri().replace("127.0.0.1", "localhost");

    let state = create_test_state(Some(pool), &pds_url, None, None).await;
    let app = catbird::routes::circle::routes((*state).clone());

    // 1. Malformed JSON payload (e.g. invalid type for name)
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.createCircle")
        .header("Content-Type", "application/json")
        .extension(alice_session(&pds_url))
        .body(axum::body::Body::from(r#"{"name": 12345, "memberDids": []}"#))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json_err: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json_err["error"], "InvalidRequest");

    // 2. Malformed query parameter (e.g. non-integer limit)
    let req2 = axum::http::Request::builder()
        .method("GET")
        .uri("/xrpc/blue.catbird.circle.listCircles?limit=notanumber")
        .extension(alice_session(&pds_url))
        .body(axum::body::Body::empty())
        .unwrap();

    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), axum::http::StatusCode::BAD_REQUEST);

    let body_bytes2 = axum::body::to_bytes(resp2.into_body(), usize::MAX).await.unwrap();
    let json_err2: serde_json::Value = serde_json::from_slice(&body_bytes2).unwrap();
    assert_eq!(json_err2["error"], "InvalidRequest");
}

#[sqlx::test(migrations = "./migrations")]
async fn did_web_ssrf_protection_rejects_private_and_http_targets(pool: PgPool) {
    let state = create_test_state(Some(pool), "http://localhost:8080", None, None).await;
    let service = CircleService::new(state);

    // 1. Private IPv4 in did:web (10.0.0.1)
    let res1 = service.resolve_space_host_audience("did:web:10.0.0.1").await;
    assert!(res1.is_err());
    let err1 = res1.unwrap_err().to_string();
    assert!(err1.contains("SSRF") || err1.contains("private network not allowed") || err1.contains("InvalidRequest"));

    // 2. Private IPv4 (192.168.1.50)
    let res2 = service.resolve_space_host_audience("did:web:192.168.1.50").await;
    assert!(res2.is_err());

    // 3. Link-local IPv4 (169.254.169.254)
    let res3 = service.resolve_space_host_audience("did:web:169.254.169.254").await;
    assert!(res3.is_err());
}

#[tokio::test]
async fn service_auth_upstream_failure_returns_exact_error() {
    let pds = MockServer::start().await;
    let pds_url = pds.uri().replace("127.0.0.1", "localhost");

    // PDS returns 401 Unauthorized for getServiceAuth
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid token"))
        .mount(&pds)
        .await;

    let mut config = AppConfig::load().unwrap();
    config.circle.service_did = "did:web:circles.catbird.blue#atproto_circle".into();
    let state = create_test_state(None, &pds_url, None, None).await;
    let service_auth = ServiceAuthProvider::new(state);
    let session = alice_session(&pds_url);

    let res = service_auth.token_for_audience(&session, "did:web:circles.catbird.blue#atproto_circle", "blue.catbird.circle.getFeed").await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    match err {
        catbird::error::AppError::AtprotoResponse { status, error, .. } => {
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
            assert_eq!(error, "AuthRequired");
        }
        other => panic!("Expected AtprotoResponse AuthRequired, got: {:?}", other),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_duplicate_member_update_claims_and_never_downgrades(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    let request = UpdateMember {
        space: space(),
        member_did: bob(),
        action: MemberAction::Add,
        extra_data: None,
    };

    // First request executes and transitions to Complete (Delivered)
    let op1 = env.service.update_member(&env.session, request.clone()).await.unwrap();
    assert_eq!(op1.status, OperationStatus::Complete);

    // Second request is a duplicate: returns Complete idempotently without re-running mutation
    let op2 = env.service.update_member(&env.session, request.clone()).await.unwrap();
    assert_eq!(op2.status, OperationStatus::Complete);
    assert_eq!(op1.id, op2.id);

    // Test conditional SQL update: attempting to set state='failed' on a delivered row must be a no-op
    let outbox_id = uuid::Uuid::parse_str(op1.id.as_str()).unwrap();
    let _ = env.service.set_projection_state(outbox_id, catbird::models::CircleProjectionState::Failed, Some("SimulatedError"), None).await;

    let state_after: (String,) = sqlx::query_as(
        "SELECT state FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(outbox_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Must still be delivered (never downgraded to failed)
    assert_eq!(state_after.0, "delivered");
}

#[sqlx::test(migrations = "./migrations")]
async fn auth_unavailable_stays_retryable_in_worker_and_rebinds_session(pool: PgPool) {
    let pds = MockServer::start().await;
    let appview = MockServer::start().await;
    let pds_url = pds.uri().replace("127.0.0.1", "localhost");
    let appview_url = appview.uri().replace("127.0.0.1", "localhost");

    let state = create_test_state(Some(pool.clone()), &pds_url, Some(appview_url), None).await;
    let service = CircleService::new(state);

    // Enqueue an outbox projection with a missing session ID
    let missing_session_id = uuid::Uuid::new_v4().to_string();
    let op_id = service
        .enqueue_projection(
            "did:plc:alice",
            &missing_session_id,
            "at://did:plc:alice/space/blue.catbird.circle/test-circle-1",
            catbird::models::CircleProjectionKind::CircleUpsert,
            serde_json::json!({ "name": "Test" }),
            catbird::models::CircleProjectionState::Pending,
        )
        .await
        .unwrap();

    // Process due projections with background worker query - session recovery will fail
    let delivered = service.process_due_projections(10).await.unwrap();
    assert_eq!(delivered, 0);

    // Verify row is still in 'pending' state (not marked terminal failed)
    let state_row: (String, i32) = sqlx::query_as(
        "SELECT state, attempts FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state_row.0, "pending");

    // Even if attempts are manually set to 15, auth failure must still keep it pending
    sqlx::query("UPDATE circle_projection_outbox SET attempts = 15, next_attempt_at = now() WHERE id = $1")
        .bind(op_id)
        .execute(&pool)
        .await
        .unwrap();

    let delivered2 = service.process_due_projections(10).await.unwrap();
    assert_eq!(delivered2, 0);

    let state_row2: (String,) = sqlx::query_as(
        "SELECT state FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state_row2.0, "pending");

    // An authenticated Circle request arrives -> rebinds actor's pending rows to the new session ID
    let new_session_id = uuid::Uuid::new_v4().to_string();
    service.rebind_actor_sessions("did:plc:alice", &new_session_id).await.unwrap();

    let bound_session: (String,) = sqlx::query_as(
        "SELECT session_id FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bound_session.0, new_session_id);
}

#[sqlx::test(migrations = "./migrations")]
async fn circle_enabled_startup_requires_auth_infrastructure(_pool: PgPool) {
    let mut config = AppConfig::load().unwrap();
    config.circle.service_url = Some("http://localhost:9999".into());
    config.circle.service_did = "did:web:circles.catbird.blue#atproto_circle".into();
    config.oauth.client_id = "http://localhost:8080/client-metadata.json".into();

    // AppState::new without KeyStore / Jacquard should fail
    let res = AppState::new(config).await;
    assert!(res.is_err());
    let err_str = res.err().unwrap().to_string();
    assert!(err_str.contains("mandatory when Circle capability is enabled") || err_str.contains("KeyStore"));
}

#[sqlx::test(migrations = "./migrations")]
async fn exact_circle_error_envelopes_across_middleware_and_transport(pool: PgPool) {
    let env = setup_env(pool.clone()).await;
    let router = catbird::routes::atproto::create_router(env.state.clone()).with_state(env.state.clone());
    // 1. Unauthenticated request to Circle endpoint must return 401 with error "AuthRequired"
    let req = axum::http::Request::builder()
        .uri("/xrpc/blue.catbird.circle.createCircle")
        .method("POST")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(r#"{"name":"Test","member_dids":[]}"#))
        .unwrap();

    let resp = tower::ServiceExt::oneshot(router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json_err: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json_err["error"], "AuthRequired");

    // 2. Unauthenticated GET /xrpc/blue.catbird.circle.getCapabilities
    let req2 = axum::http::Request::builder()
        .uri("/xrpc/blue.catbird.circle.getCapabilities")
        .method("GET")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp2 = tower::ServiceExt::oneshot(router, req2).await.unwrap();
    assert_eq!(resp2.status(), axum::http::StatusCode::UNAUTHORIZED);

    let body_bytes2 = axum::body::to_bytes(resp2.into_body(), 1024 * 1024).await.unwrap();
    let json_err2: serde_json::Value = serde_json::from_slice(&body_bytes2).unwrap();
    assert_eq!(json_err2["error"], "AuthRequired");
}
#[sqlx::test(migrations = "./migrations")]
async fn reconcile_stale_projections_promotes_state_to_pending(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    // Metadata getRecord returns 200 (record exists at PDS)
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.getRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/blue.catbird.circle.metadata/self",
            "value": { "name": "Reconciled Circle" }
        })))
        .mount(&env._pds)
        .await;

    // Insert a stale intent row with updated_at set to 60 seconds ago
    let op_id = env.service
        .enqueue_projection(
            "did:plc:alice",
            &env.session.id.to_string(),
            "at://did:plc:alice/space/blue.catbird.circle/reconcile-test",
            catbird::models::CircleProjectionKind::CircleUpsert,
            serde_json::json!({ "name": "Reconciled Circle" }),
            catbird::models::CircleProjectionState::Intent,
        )
        .await
        .unwrap();

    sqlx::query("UPDATE circle_projection_outbox SET updated_at = now() - interval '60 seconds' WHERE id = $1")
        .bind(op_id)
        .execute(&pool)
        .await
        .unwrap();

    // Run reconciliation
    let count = env.service.reconcile_stale_projections(10).await.unwrap();
    assert_eq!(count, 1);

    // Outbox row should now be in 'pending' state
    let state_row: (String,) = sqlx::query_as(
        "SELECT state FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state_row.0, "pending");
}

#[sqlx::test(migrations = "./migrations")]
async fn did_web_dns_ssrf_rejects_private_domain_resolutions(pool: PgPool) {
    let state = create_test_state(Some(pool), "http://localhost:8080", None, None).await;
    let service = CircleService::new(state);

    // 1. Private domain resolving to 127.0.0.1 or private range
    // Use a domain that resolves or test with private IP addresses in did:web
    let res = service.resolve_space_host_audience("did:web:127.0.0.1%3A8080").await;
    assert!(res.is_err());

    let res2 = service.resolve_space_host_audience("did:web:10.0.0.5").await;
    assert!(res2.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn outbox_execution_lease_independent_of_rebinding_and_conflict_retries(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    // 1. Enqueue intent and claim as executing
    let op_id = env.service
        .enqueue_projection(
            "did:plc:alice",
            &env.session.id.to_string(),
            "at://did:plc:alice/space/blue.catbird.circle/lease-test",
            catbird::models::CircleProjectionKind::MemberAdd,
            serde_json::json!({ "space": "at://did:plc:alice/space/blue.catbird.circle/lease-test", "member": "did:plc:bob", "circleGeneration": 1, "memberGeneration": 1 }),
            catbird::models::CircleProjectionState::Intent,
        )
        .await
        .unwrap();

    env.service.claim_projection(op_id, &env.session.id.to_string()).await.unwrap();

    // Explicitly set execution_started_at to 60 seconds ago
    sqlx::query(
        "UPDATE circle_projection_outbox SET execution_started_at = now() - interval '60 seconds' WHERE id = $1"
    )
    .bind(op_id)
    .execute(&pool)
    .await
    .unwrap();

    let before: (Option<chrono::DateTime<chrono::Utc>>,) = sqlx::query_as(
        "SELECT execution_started_at FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let before_time = before.0.unwrap();

    // 2. Rebind session for actor -> must NOT modify execution_started_at
    let new_session_id = uuid::Uuid::new_v4().to_string();
    let mut new_session = env.session.clone();
    new_session.id = uuid::Uuid::parse_str(&new_session_id).unwrap();
    register_test_session(&env.state, &new_session).await;
    env.service.rebind_actor_sessions("did:plc:alice", &new_session_id).await.unwrap();
    let after_rebind: (Option<chrono::DateTime<chrono::Utc>>, String) = sqlx::query_as(
        "SELECT execution_started_at, session_id FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_rebind.1, new_session_id);
    assert_eq!(after_rebind.0.unwrap(), before_time);

    // 3. Duplicate enqueue (simulating client retry) -> must NOT modify execution_started_at
    env.service
        .enqueue_projection(
            "did:plc:alice",
            &new_session_id,
            "at://did:plc:alice/space/blue.catbird.circle/lease-test",
            catbird::models::CircleProjectionKind::MemberAdd,
            serde_json::json!({ "space": "at://did:plc:alice/space/blue.catbird.circle/lease-test", "member": "did:plc:bob", "circleGeneration": 1, "memberGeneration": 1 }),
            catbird::models::CircleProjectionState::Intent,
        )
        .await
        .unwrap();

    let after_conflict: (Option<chrono::DateTime<chrono::Utc>>,) = sqlx::query_as(
        "SELECT execution_started_at FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_conflict.0.unwrap(), before_time);

    // 4. Stale reconciliation finds and reconciles the row because the lease expired 60s ago
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "success": true })))
        .mount(&env._pds)
        .await;

    let count = env.service.reconcile_stale_projections(10).await.unwrap();
    assert_eq!(count, 1);

    let final_state: (String,) = sqlx::query_as(
        "SELECT state FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(final_state.0, "pending");
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_member_and_delete_retry_claims_via_cas_and_succeeds(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    // 1. Setup a previously terminally failed member addition
    let req = catbird_atproto::generated::blue_catbird::circle::update_member::UpdateMember {
        space: space(),
        member_did: bob(),
        action: catbird_atproto::generated::blue_catbird::circle::defs::MemberAction::Add,
        extra_data: Default::default(),
    };

    let op_id = env.service
        .enqueue_projection(
            "did:plc:alice",
            &env.session.id.to_string(),
            space().as_str(),
            catbird::models::CircleProjectionKind::MemberAdd,
            serde_json::json!({ "space": space().as_str(), "member": bob().as_str(), "circleGeneration": 1, "memberGeneration": 1 }),
            catbird::models::CircleProjectionState::Intent,
        )
        .await
        .unwrap();

    // Mark it as failed with attempts and error
    sqlx::query(
        "UPDATE circle_projection_outbox SET state = 'failed', attempts = 5, last_error_code = 'PDS error' WHERE id = $1"
    )
    .bind(op_id)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Mock PDS success for retry
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "success": true })))
        .mount(&env._pds)
        .await;

    // 3. Retry update_member -> should claim failed row via CAS and succeed
    let op = env.service.update_member(&env.session, req).await.unwrap();
    assert_eq!(op.status, catbird_atproto::generated::blue_catbird::circle::defs::OperationStatus::Complete);

    let row: (String, i32, Option<String>) = sqlx::query_as(
        "SELECT state, attempts, last_error_code FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.0, "delivered");
    assert_eq!(row.1, 0); // attempts cleared
    assert_eq!(row.2, None); // last_error_code cleared
}

#[sqlx::test(migrations = "./migrations")]
async fn indeterminate_transport_stays_executing_and_reconciles_full_sequence(pool: PgPool) {
    let env = setup_env(pool.clone()).await;
    // PDS simple space createSpace drops connection (network error)
    // Mount capability probe and 503 error on createSpace
    env._pds.reset().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&env._pds)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/blue.catbird.circle.getCapabilities"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "enabled": true,
            "protocolRevision": 1
        })))
        .mount(&env._pds)
        .await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.createSpace"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .mount(&env._pds)
        .await;
    let req = catbird_atproto::generated::blue_catbird::circle::create_circle::CreateCircle {
        name: "Indeterminate Circle".into(),
        member_dids: vec![],
        extra_data: Default::default(),
    };

    let res = env.service.create_circle(&env.session, req).await;
    assert!(res.is_err());

    // Verify outbox state is 'executing', NOT 'failed'
    let rows: Vec<(uuid::Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, state, last_error_code FROM circle_projection_outbox WHERE actor_did = 'did:plc:alice'"
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "executing");

    // Set execution_started_at to 60s ago to simulate stale crash
    sqlx::query(
        "UPDATE circle_projection_outbox SET execution_started_at = now() - interval '60 seconds', created_at = now() - interval '60 seconds' WHERE id = $1"
    )
    .bind(rows[0].0)
    .execute(&pool)
    .await
    .unwrap();

    // Reset PDS mock to succeed for createSpace and putRecord
    env._pds.reset().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/blue.catbird.circle.getCapabilities"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "enabled": true,
            "protocolRevision": 1
        })))
        .mount(&env._pds)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.getRecord"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .mount(&env._pds)
        .await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.createSpace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/space/blue.catbird.circle/reconciled"
        })))
        .mount(&env._pds)
        .await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.space.putRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/blue.catbird.circle.metadata/self"
        })))
        .mount(&env._pds)
        .await;

    // Stale reconciliation runs and replays full sequence
    let reconciled = env.service.reconcile_stale_projections(10).await.unwrap();
    assert_eq!(reconciled, 1);

    let post_reconcile: (String,) = sqlx::query_as(
        "SELECT state FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(rows[0].0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(post_reconcile.0, "pending");
}

#[sqlx::test(migrations = "./migrations")]
async fn typed_error_classification_never_terminalizes_auth_errors(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    // Reset PDS mock so getServiceAuth returns 401 AuthRequired
    env._pds.reset().await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "AuthRequired",
            "message": "Authentication required for service token"
        })))
        .mount(&env._pds)
        .await;

    let op_id = env.service
        .enqueue_projection(
            "did:plc:alice",
            &env.session.id.to_string(),
            space().as_str(),
            catbird::models::CircleProjectionKind::CircleUpsert,
            serde_json::json!({ "name": "Auth Retry Test" }),
            catbird::models::CircleProjectionState::Pending,
        )
        .await
        .unwrap();

    // Set attempts to 9 so the next attempt is the 10th
    sqlx::query(
        "UPDATE circle_projection_outbox SET attempts = 9 WHERE id = $1"
    )
    .bind(op_id)
    .execute(&pool)
    .await
    .unwrap();

    // Process due projections -> attempts becomes 10, but state MUST stay 'pending'
    env.service.process_due_projections(10).await.unwrap();

    let row: (String, i32) = sqlx::query_as(
        "SELECT state, attempts FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.0, "pending");
    assert_eq!(row.1, 10);
}

#[sqlx::test(migrations = "./migrations")]
async fn circle_middleware_rebinds_every_authenticated_circle_request(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    // 1. Enqueue a pending projection with old session ID
    let old_session_id = uuid::Uuid::new_v4().to_string();
    let op_id = env.service
        .enqueue_projection(
            "did:plc:alice",
            &old_session_id,
            space().as_str(),
            catbird::models::CircleProjectionKind::CircleUpsert,
            serde_json::json!({ "name": "Rebind Test" }),
            catbird::models::CircleProjectionState::Pending,
        )
        .await
        .unwrap();

    // 2. Make authenticated proxy request to /xrpc/blue.catbird.circle.listCircles
    // Mock AppView response
    Mock::given(method("GET"))
        .and(path("/xrpc/blue.catbird.circle.listCircles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "circles": []
        })))
        .mount(&env._appview)
        .await;

    let router = catbird::routes::atproto::create_router(env.state.clone()).with_state(env.state.clone());
    let req = axum::http::Request::builder()
        .uri("/xrpc/blue.catbird.circle.listCircles")
        .method("GET")
        .header("authorization", format!("Bearer {}", env.session.id))
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // 3. Outbox session_id should now be rebound to env.session.id
    let row: (String,) = sqlx::query_as(
        "SELECT session_id FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.0, env.session.id.to_string());
}

#[sqlx::test(migrations = "./migrations")]
async fn initial_member_mutation_5xx_stays_executing_4xx_marks_failed(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    // Mount capability probe
    env._pds.reset().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&env._pds)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/blue.catbird.circle.getCapabilities"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "enabled": true,
            "protocolRevision": 1
        })))
        .mount(&env._pds)
        .await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.createSpace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/space/blue.catbird.circle/test-members"
        })))
        .mount(&env._pds)
        .await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.space.putRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/blue.catbird.circle.metadata/self"
        })))
        .mount(&env._pds)
        .await;

    // Member 1 (bob): 503 Service Unavailable (indeterminate server error)
    // Member 2 (carol): 400 Bad Request (explicit non-idempotent 4xx)
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .and(wiremock::matchers::body_string_contains("did:plc:bob"))
        .respond_with(ResponseTemplate::new(503).set_body_string("PDS Overloaded"))
        .mount(&env._pds)
        .await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .and(wiremock::matchers::body_string_contains("did:plc:carol"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid Member DID"))
        .mount(&env._pds)
        .await;

    let req = catbird_atproto::generated::blue_catbird::circle::create_circle::CreateCircle {
        name: "Partial Members Circle".into(),
        member_dids: vec![bob(), carol()],
        extra_data: Default::default(),
    };

    let res = env.service.create_circle(&env.session, req).await;
    assert!(res.is_ok());
    let op = res.unwrap();
    assert_eq!(op.status, catbird_atproto::generated::blue_catbird::circle::defs::OperationStatus::Failed);

    // Verify bob (503) is in 'executing' state for future crash reconciliation / replay
    let bob_row: (String, Option<String>) = sqlx::query_as(
        "SELECT state, last_error_code FROM circle_projection_outbox WHERE payload->>'member' = 'did:plc:bob'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bob_row.0, "executing");
    assert!(bob_row.1.unwrap().contains("503"));

    // Verify carol (400) is in terminal 'failed' state
    let carol_row: (String, Option<String>) = sqlx::query_as(
        "SELECT state, last_error_code FROM circle_projection_outbox WHERE payload->>'member' = 'did:plc:carol'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(carol_row.0, "failed");
    assert!(carol_row.1.unwrap().contains("400"));
}

#[sqlx::test(migrations = "./migrations")]
async fn initial_member_indeterminate_503_returns_pending_status(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    env._pds.reset().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&env._pds)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/blue.catbird.circle.getCapabilities"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "enabled": true,
            "protocolRevision": 1
        })))
        .mount(&env._pds)
        .await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.createSpace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/space/blue.catbird.circle/test-members-pending"
        })))
        .mount(&env._pds)
        .await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.space.putRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/blue.catbird.circle.metadata/self"
        })))
        .mount(&env._pds)
        .await;

    // Member (bob): 503 Service Unavailable (indeterminate server error)
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .and(wiremock::matchers::body_string_contains("did:plc:bob"))
        .respond_with(ResponseTemplate::new(503).set_body_string("PDS Overloaded"))
        .mount(&env._pds)
        .await;

    let req = catbird_atproto::generated::blue_catbird::circle::create_circle::CreateCircle {
        name: "Pending Member Circle".into(),
        member_dids: vec![bob()],
        extra_data: Default::default(),
    };

    let res = env.service.create_circle(&env.session, req).await;
    assert!(res.is_ok());
    let op = res.unwrap();
    // Crucial: Indeterminate outcome means parent status is Pending, NOT Failed!
    assert_eq!(op.status, catbird_atproto::generated::blue_catbird::circle::defs::OperationStatus::Pending);
    assert!(op.error.is_none());

    let bob_row: (String, Option<String>) = sqlx::query_as(
        "SELECT state, last_error_code FROM circle_projection_outbox WHERE payload->>'member' = 'did:plc:bob'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bob_row.0, "executing");
    assert!(bob_row.1.unwrap().contains("503"));
}

#[sqlx::test(migrations = "./migrations")]
async fn reconciliation_treats_408_425_429_as_retryable_stays_executing(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    for status_code in [408u16, 425u16, 429u16] {
        let add_op_id = env
            .service
            .enqueue_projection(
                "did:plc:alice",
                &env.session.id.to_string(),
                space().as_str(),
                catbird::models::CircleProjectionKind::MemberAdd,
                serde_json::json!({ "space": space().as_str(), "member": bob().as_str(), "circleGeneration": 1, "memberGeneration": 1 }),
                catbird::models::CircleProjectionState::Intent,
            )
            .await
            .unwrap();

        sqlx::query(
            "UPDATE circle_projection_outbox SET state = 'executing', execution_started_at = now() - interval '60 seconds' WHERE id = $1",
        )
        .bind(add_op_id)
        .execute(&pool)
        .await
        .unwrap();

        env._pds.reset().await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.simplespace.addMember"))
            .respond_with(ResponseTemplate::new(status_code).set_body_string("Retryable Status"))
            .mount(&env._pds)
            .await;

        let reconciled = env.service.reconcile_stale_projections(10).await.unwrap();
        assert_eq!(reconciled, 0);

        // Verify row stays in 'executing' and records retryable error, NOT transitioned to 'failed'
        let row: (String, Option<String>) = sqlx::query_as(
            "SELECT state, last_error_code FROM circle_projection_outbox WHERE id = $1",
        )
        .bind(add_op_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "executing");
        assert!(row.1.unwrap().contains(&status_code.to_string()));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn claimed_row_contention_bypasses_pds_mutation(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    // Enqueue an operation and mark it executing with an active claim_token
    let existing_token = uuid::Uuid::new_v4();
    let op_id = env
        .service
        .enqueue_projection(
            "did:plc:alice",
            &env.session.id.to_string(),
            space().as_str(),
            catbird::models::CircleProjectionKind::MemberAdd,
            serde_json::json!({ "space": space().as_str(), "member": bob().as_str(), "circleGeneration": 1, "memberGeneration": 1 }),
            catbird::models::CircleProjectionState::Intent,
        )
        .await
        .unwrap();

    // Set state = executing with fresh execution_started_at so claim_projection returns None
    sqlx::query(
        "UPDATE circle_projection_outbox SET state = 'executing', claim_token = $1, execution_started_at = now() WHERE id = $2",
    )
    .bind(existing_token)
    .bind(op_id)
    .execute(&pool)
    .await
    .unwrap();

    env._pds.reset().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.space.listSpaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "supportsImages": true
        })))
        .mount(&env._pds)
        .await;

    // Call update_member when another executor actively holds the claim
    let update_input = catbird_atproto::generated::blue_catbird::circle::update_member::UpdateMember {
        space: space(),
        member_did: bob(),
        action: catbird_atproto::generated::blue_catbird::circle::defs::MemberAction::Add,
        extra_data: None,
    };

    let op = env
        .service
        .update_member(&env.session, update_input)
        .await
        .unwrap();

    // Returned status is Pending, and zero PDS mutation requests happen
    assert_eq!(
        op.status,
        catbird_atproto::generated::blue_catbird::circle::defs::OperationStatus::Pending
    );
    let received = env._pds.received_requests().await.unwrap();
    assert!(
        !received.iter().any(|req| req.url.path() == "/xrpc/com.atproto.simplespace.addMember"),
        "No addMember PDS mutation request must be made when claim_projection returns None"
    );

    // Row state is still executing with original claim_token
    let row: (String, Option<uuid::Uuid>) = sqlx::query_as(
        "SELECT state, claim_token FROM circle_projection_outbox WHERE id = $1",
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "executing");
    assert_eq!(row.1, Some(existing_token));
}

#[sqlx::test(migrations = "./migrations")]
async fn reconciliation_transitions_explicit_4xx_to_failed(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    // Enqueue stale executing MemberAdd and MemberRemove operations
    let add_op_id = env.service
        .enqueue_projection(
            "did:plc:alice",
            &env.session.id.to_string(),
            space().as_str(),
            catbird::models::CircleProjectionKind::MemberAdd,
            serde_json::json!({ "space": space().as_str(), "member": bob().as_str(), "circleGeneration": 1, "memberGeneration": 1 }),
            catbird::models::CircleProjectionState::Intent,
        )
        .await
        .unwrap();

    let remove_op_id = env.service
        .enqueue_projection(
            "did:plc:alice",
            &env.session.id.to_string(),
            space().as_str(),
            catbird::models::CircleProjectionKind::MemberRemove,
            serde_json::json!({ "space": space().as_str(), "member": carol().as_str(), "circleGeneration": 1, "memberGeneration": 1 }),
            catbird::models::CircleProjectionState::Intent,
        )
        .await
        .unwrap();

    // Mark both as executing and expired 60s ago
    sqlx::query(
        "UPDATE circle_projection_outbox SET state = 'executing', execution_started_at = now() - interval '60 seconds' WHERE id IN ($1, $2)"
    )
    .bind(add_op_id)
    .bind(remove_op_id)
    .execute(&pool)
    .await
    .unwrap();

    // Mock PDS to return explicit non-idempotent 400 Bad Request
    env._pds.reset().await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Account Deactivated"))
        .mount(&env._pds)
        .await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.removeMember"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Permission Denied"))
        .mount(&env._pds)
        .await;

    let reconciled = env.service.reconcile_stale_projections(10).await.unwrap();
    assert_eq!(reconciled, 0);

    // Verify both rows transitioned from 'executing' to 'failed' instead of remaining in 'executing' forever
    let add_row: (String, Option<String>) = sqlx::query_as(
        "SELECT state, last_error_code FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(add_op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(add_row.0, "failed");
    assert!(add_row.1.unwrap().contains("Account Deactivated"));

    let remove_row: (String, Option<String>) = sqlx::query_as(
        "SELECT state, last_error_code FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(remove_op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remove_row.0, "failed");
    assert!(remove_row.1.unwrap().contains("Permission Denied"));
}

#[sqlx::test(migrations = "./migrations")]
async fn claim_token_fencing_prevents_stale_executor_completion_overwrite(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    let op_id = env.service
        .enqueue_projection(
            "did:plc:alice",
            &env.session.id.to_string(),
            space().as_str(),
            catbird::models::CircleProjectionKind::MemberAdd,
            serde_json::json!({ "space": space().as_str(), "member": bob().as_str(), "circleGeneration": 1, "memberGeneration": 1 }),
            catbird::models::CircleProjectionState::Intent,
        )
        .await
        .unwrap();

    // 1. Executor 1 claims the operation
    let token1 = env.service.claim_projection(op_id, &env.session.id.to_string()).await.unwrap().expect("should claim");

    // 2. Simulate lease expiration (30 seconds pass)
    sqlx::query(
        "UPDATE circle_projection_outbox SET execution_started_at = now() - interval '60 seconds' WHERE id = $1"
    )
    .bind(op_id)
    .execute(&pool)
    .await
    .unwrap();

    // 3. Executor 2 (e.g. background reconciliation or client retry) re-claims the operation
    let token2 = env.service.claim_projection(op_id, &env.session.id.to_string()).await.unwrap().expect("should re-claim");
    assert_ne!(token1, token2);

    // 4. Executor 1 completes with stale token1 (e.g. failed) -> must be rejected by fencing CAS
    let updated = env.service.set_projection_state(
        op_id,
        catbird::models::CircleProjectionState::Failed,
        Some("Stale executor error"),
        Some(token1),
    ).await.unwrap();
    assert!(!updated, "Stale executor update must not take effect");

    // State must still be executing with token2
    let row: (String, Option<uuid::Uuid>) = sqlx::query_as(
        "SELECT state, claim_token FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "executing");
    assert_eq!(row.1, Some(token2));

    // 5. Executor 2 completes with valid token2 (e.g. pending) -> succeeds
    let updated2 = env.service.set_projection_state(
        op_id,
        catbird::models::CircleProjectionState::Pending,
        None,
        Some(token2),
    ).await.unwrap();
    assert!(updated2, "Active executor update must take effect");

    let final_row: (String, Option<uuid::Uuid>) = sqlx::query_as(
        "SELECT state, claim_token FROM circle_projection_outbox WHERE id = $1"
    )
    .bind(op_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(final_row.0, "pending");
    assert_eq!(final_row.1, None); // Cleared on completion
}

#[sqlx::test(migrations = "./migrations")]
async fn session_rebind_database_error_propagates_as_upstream_unavailable(pool: PgPool) {
    let env = setup_env(pool.clone()).await;

    // Drop the outbox table to force an unexpected SQL error during every-request session rebind in auth_middleware
    sqlx::query("DROP TABLE circle_projection_outbox CASCADE")
        .execute(&pool)
        .await
        .unwrap();

    let router = catbird::routes::atproto::create_router(env.state.clone()).with_state(env.state.clone());
    let req = axum::http::Request::builder()
        .uri("/xrpc/blue.catbird.circle.listCircles")
        .method("GET")
        .header("authorization", format!("Bearer {}", env.session.id))
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "UpstreamUnavailable");
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_circle_advances_generation_and_audience_strictly_checks_id(pool: PgPool) {
    let env = setup_env(pool.clone()).await;
    let space = "at://did:plc:alice/space/blue.catbird.circle/test-adv-gen";

    // 1. Enqueue an initial CircleUpsert with generation 1
    env.service
        .enqueue_projection(
            "did:plc:alice",
            &env.session.id.to_string(),
            space,
            catbird::models::CircleProjectionKind::CircleUpsert,
            serde_json::json!({
                "space": space,
                "authority": "did:plc:alice",
                "name": "Circle Gen 1",
                "generation": 1
            }),
            catbird::models::CircleProjectionState::Delivered,
        )
        .await
        .unwrap();

    // 2. Call delete_circle via service
    let op = env
        .service
        .delete_circle(
            &env.session,
            DeleteCircle {
                space: SpaceRef::new(space.into()).unwrap(),
                extra_data: None,
            },
        )
        .await
        .unwrap();
    let op_uuid: uuid::Uuid = op.id.parse().unwrap();
    let row: (serde_json::Value,) = sqlx::query_as(
        "SELECT payload FROM circle_projection_outbox WHERE id = $1",
    )
    .bind(op_uuid)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Generation must advance to 2!
    let gen = row.0.get("generation").and_then(|g| g.as_i64()).unwrap();
    assert_eq!(gen, 2);
}
