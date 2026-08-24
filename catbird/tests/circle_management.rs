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
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .and(wiremock::matchers::body_string_contains("did:plc:carol"))
        .respond_with(ResponseTemplate::new(500).set_body_string("PDS Internal Error"))
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
    assert_eq!(op.status, OperationStatus::Complete);
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

    // 1. PDS returns 500 on addMember -> outbox row is updated to 'failed'
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.simplespace.addMember"))
        .respond_with(ResponseTemplate::new(500).set_body_string("PDS Internal Crash"))
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
    assert!(row_state.1.unwrap().contains("PDS operation failed (500)"));

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

    let net_state = create_test_state(Some(pool.clone()), &pds2_url, Some("http://localhost:9999".into()), None).await;
    let net_service = CircleService::new(net_state.clone());
    let carol_session = alice_session(&pds2_url);
    register_test_session(&net_state, &carol_session).await;

    // Prime capability cache for carol_session
    let _ = net_state.circle_capability.get(&carol_session).await;

    // Drop PDS2 so connection is refused on mutation
    drop(pds2);

    let request2 = UpdateMember {
        space: space(),
        member_did: carol(),
        action: MemberAction::Add,
        extra_data: None,
    };

    let err2 = net_service.update_member(&carol_session, request2).await;
    assert!(err2.is_err());

    let carol_state: (String, Option<String>) = sqlx::query_as(
        "SELECT state, last_error_code FROM circle_projection_outbox WHERE payload->>'member' = 'did:plc:carol'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(carol_state.0, "failed");
    let last_err = carol_state.1.as_deref().unwrap_or("");
    assert!(last_err.contains("Network error") || last_err.contains("error") || last_err.contains("PDS"), "Expected network error, got: {last_err}");
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
            ($1, 'key-intent-1', 'did:plc:alice', 'sess-1', 'at://did:plc:alice/space/1', 'member_add', '{"member":"bob"}'::jsonb, 'intent', 0, now() - interval '10 seconds', now(), now()),
            ($2, 'key-pending-1', 'did:plc:alice', 'sess-1', 'at://did:plc:alice/space/1', 'member_add', '{"member":"carol"}'::jsonb, 'pending', 0, now() - interval '10 seconds', now(), now())
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
