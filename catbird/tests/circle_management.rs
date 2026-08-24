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

    if let Some(p) = &pool {
        let _ = sqlx::query(
            r#"
            INSERT INTO push_accounts (account_did, session_id, pds_url, created_at, updated_at)
            VALUES ($1, $2, $3, now(), now())
            ON CONFLICT (account_did) DO UPDATE SET session_id = EXCLUDED.session_id, pds_url = EXCLUDED.pds_url, updated_at = now()
            "#,
        )
        .bind("did:plc:alice")
        .bind(Uuid::new_v4().to_string())
        .bind(_pds_url)
        .execute(p)
        .await;
    }

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

    let state = Arc::new(AppState {
        config: Arc::new(config),
        http_client,
        redis,
        push_db: pool,
        key_store: Some(key_store),
        jacquard_client: None,
        catmos_jacquard_client: None,
        auth_store: None,
        push: None,
        dpop_nonce_cache,
        circle_capability,
        session_encryption_key: None,
    });

    state.circle_capability.set_state(Arc::downgrade(&state));
    state
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
        state,
        Some(pool),
        attestation_provider,
        service_auth_provider,
    );

    let session = alice_session(&pds_url);

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
    // Must return Pending with partial failure error
    assert_eq!(op.status, OperationStatus::Pending);
    assert_eq!(op.error.as_deref(), Some("MemberAdditionPartialFailure"));

    // Crucial: only 1 member_add projection enqueued for Bob, NOT Carol!
    assert_eq!(service.get_projection_count(Some("circle_upsert")).await.unwrap(), 1);
    assert_eq!(service.get_projection_count(Some("member_add")).await.unwrap(), 1);
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
    let service = CircleService::new(state);
    let session = alice_session(&pds_url);

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
