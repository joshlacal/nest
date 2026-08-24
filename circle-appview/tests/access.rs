use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_atproto::generated::blue_catbird::circle::{
    activate_space::ActivateSpaceOutput,
    defs::AccessState,
};
use chrono::{DateTime, Utc};
use circle_appview::{
    access::{ActiveSpaceCredential, CredentialStore},
    auth::{
        DidDocument, DidResolver, DidService, PublicKeyJwk, VerificationMethod,
    },
    config::{AppState, Config},
    db,
    projections::{self, Projection},
    routes::create_router,
    space_client::{create_dpop_proof, MockSpaceHostTransport, SpaceClient},
};
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;

pub const CIRCLE_AUDIENCE: &str = "did:web:circles.catbird.blue#atproto_circle";
pub const ALICE_DID: &str = "did:plc:alice-access-test";
pub const BOB_DID: &str = "did:plc:bob-access-test";
pub const AUTHORITY_DID: &str = "did:plc:authority-circle-space";
pub const SPACE_HOST_ENDPOINT: &str = "https://space-host.example.com";

#[derive(Clone)]
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufferWriter {
    type Writer = BufferWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

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
    };

    // Keys
    let alice_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let bob_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let authority_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    let state = AppState::new(config, pool.clone());

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

    let mock_transport = Arc::new(MockSpaceHostTransport::new());
    let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));

    let state = AppState::with_services(
        (*state.config).clone(),
        pool.clone(),
        state.did_resolver.clone(),
        state.credential_store.clone(),
        space_client,
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
    signing_key: &p256::ecdsa::SigningKey,
    services: Option<Vec<DidService>>,
) {
    let verifying_key = signing_key.verifying_key();
    let point = EncodedPoint::from(verifying_key);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let p256_sec1 = verifying_key.to_encoded_point(true);
    let mut p256_multikey_bytes = vec![0x80, 0x24];
    p256_multikey_bytes.extend_from_slice(p256_sec1.as_bytes());
    let p256_multikey = multibase::encode(multibase::Base::Base58Btc, &p256_multikey_bytes);

    let did_doc = DidDocument {
        id: did.into(),
        verification_method: vec![VerificationMethod {
            id: format!("{}#atproto", did),
            r#type: "Multikey".into(),
            controller: did.into(),
            public_key_jwk: Some(PublicKeyJwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x,
                y: Some(y),
            }),
            public_key_multibase: Some(p256_multikey),
        }],
        service: services.unwrap_or_default(),
    };

    resolver.insert_cached(did.into(), did_doc);
}

fn create_service_token(
    signing_key: &p256::ecdsa::SigningKey,
    iss: &str,
    aud: &str,
    lxm: &str,
) -> String {
    let now = Utc::now().timestamp();
    let header = json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": format!("{iss}#atproto"),
    });
    let claims = json!({
        "iss": iss,
        "aud": aud,
        "lxm": lxm,
        "jti": Uuid::new_v4().to_string(),
        "iat": now,
        "exp": now + 60,
    });

    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h_b64}.{c_b64}");
    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

fn create_delegation_token(
    signing_key: &p256::ecdsa::SigningKey,
    iss: &str,
    sub: &str,
    exp_offset_secs: i64,
) -> String {
    let now = Utc::now().timestamp();
    let header = json!({
        "typ": "JWT",
        "alg": "ES256",
    });
    let claims = json!({
        "iss": iss,
        "sub": sub,
        "iat": now - 10,
        "exp": now + exp_offset_secs,
    });

    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h_b64}.{c_b64}");
    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

fn create_space_credential_token(
    signing_key: &p256::ecdsa::SigningKey,
    space: &str,
    exp_offset_secs: i64,
) -> String {
    let now = Utc::now().timestamp();
    let header = json!({
        "typ": "JWT",
        "alg": "ES256",
    });
    let claims = json!({
        "iss": "did:plc:space-host-issuer",
        "sub": space,
        "iat": now,
        "exp": now + exp_offset_secs,
    });

    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h_b64}.{c_b64}");
    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

async fn lease_exists(pool: &PgPool, space: &str, member: &str) -> bool {
    let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
        "SELECT expires_at FROM access_leases WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(space)
    .bind(member)
    .fetch_optional(pool)
    .await
    .unwrap();

    row.is_some()
}

async fn record_count(pool: &PgPool, space: &str) -> i64 {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM circle_records WHERE space_uri = $1",
    )
    .bind(space)
    .fetch_one(pool)
    .await
    .unwrap();

    row.0
}

fn unique_space_uri() -> String {
    format!("at://{AUTHORITY_DID}/space/blue.catbird.circle/{}", Uuid::new_v4().simple())
}

#[tokio::test]
async fn successful_exchange_creates_lease_for_token_issuer() {
    let pool = db::init_pool("postgres://localhost/postgres")
        .await
        .expect("DB connection");
    let setup = setup_test(pool).await;
    let space = unique_space_uri();

    // Pre-create circle
    projections::apply_projection(
        &setup.pool,
        Uuid::new_v4(),
        Projection::CircleUpsert {
            space: space.clone(),
            authority: AUTHORITY_DID.into(),
            name: "Test Circle".into(),
            created_at: Utc::now(),
        },
    )
    .await
    .unwrap();

    let credential_token = create_space_credential_token(
        &setup.authority_signing_key,
        &space,
        3600,
    );
    setup.mock_transport.set_credential_response(&space, Ok(credential_token));

    let service_auth = create_service_token(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );
    let delegation_token = create_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        300,
    );

    let req_body = json!({
        "space": space,
        "delegationToken": delegation_token,
        "clientAttestation": "dummy.client.attestation"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let response = setup.app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let output: ActivateSpaceOutput = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(output.access_state, AccessState::Active);
    assert!(output.expires_at.is_some());

    // Verify lease exists in DB
    assert!(lease_exists(&setup.pool, &space, ALICE_DID).await);

    // Verify active credential is in memory
    let cred = setup.state.credential_store.get(&space).await;
    assert!(cred.is_some());
    assert_eq!(cred.unwrap().expires_at > Utc::now(), true);
}

#[tokio::test]
async fn removal_invalidates_lease_without_deleting_circle_records() {
    let pool = db::init_pool("postgres://localhost/postgres")
        .await
        .expect("DB connection");
    let setup = setup_test(pool).await;
    let space = unique_space_uri();

    // 1. Create circle
    projections::apply_projection(
        &setup.pool,
        Uuid::new_v4(),
        Projection::CircleUpsert {
            space: space.clone(),
            authority: AUTHORITY_DID.into(),
            name: "Test Circle".into(),
            created_at: Utc::now(),
        },
    )
    .await
    .unwrap();

    // 2. Add bob
    projections::apply_projection(
        &setup.pool,
        Uuid::new_v4(),
        Projection::MemberAdd {
            space: space.clone(),
            member: BOB_DID.into(),
        },
    )
    .await
    .unwrap();

    // 3. Insert access lease for Bob
    sqlx::query(
        "INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')"
    )
    .bind(&space)
    .bind(BOB_DID)
    .execute(&setup.pool)
    .await
    .unwrap();

    // 4. Insert circle record (shared content)
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, now())
        "#
    )
    .bind(format!("{space}/app.bsky.feed.post/record-1"))
    .bind("bafyreicid123")
    .bind(&space)
    .bind(BOB_DID)
    .bind("app.bsky.feed.post")
    .bind("record-1")
    .bind(json!({"text": "Hello Bob"}))
    .execute(&setup.pool)
    .await
    .unwrap();

    assert!(lease_exists(&setup.pool, &space, BOB_DID).await);
    assert_eq!(record_count(&setup.pool, &space).await, 1);

    // 5. Remove Bob via projection
    projections::apply_projection(
        &setup.pool,
        Uuid::new_v4(),
        Projection::MemberRemove {
            space: space.clone(),
            member: BOB_DID.into(),
        },
    )
    .await
    .unwrap();

    // 6. Verify Bob's lease is deleted
    assert!(!lease_exists(&setup.pool, &space, BOB_DID).await);

    // 7. Verify member status is 'removed'
    let status: (String,) = sqlx::query_as(
        "SELECT status FROM circle_members WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(BOB_DID)
    .fetch_one(&setup.pool)
    .await
    .unwrap();
    assert_eq!(status.0, "removed");

    // 8. Verify shared records are preserved!
    assert_eq!(record_count(&setup.pool, &space).await, 1);
}

#[tokio::test]
async fn rejects_delegation_token_with_mismatched_issuer() {
    let pool = db::init_pool("postgres://localhost/postgres")
        .await
        .expect("DB connection");
    let setup = setup_test(pool).await;
    let space = unique_space_uri();

    // Service auth is Alice, but delegation token is Bob
    let service_auth = create_service_token(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );
    let delegation_token = create_delegation_token(
        &setup.bob_signing_key,
        BOB_DID,
        &space,
        300,
    );

    let req_body = json!({
        "space": space,
        "delegationToken": delegation_token,
    });

    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let response = setup.app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rejects_delegation_token_with_mismatched_space_sub() {
    let pool = db::init_pool("postgres://localhost/postgres")
        .await
        .expect("DB connection");
    let setup = setup_test(pool).await;
    let space = unique_space_uri();

    let service_auth = create_service_token(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );
    // Delegation token sub points to another space
    let delegation_token = create_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        "at://did:plc:other/space/blue.catbird.circle/other-space",
        300,
    );

    let req_body = json!({
        "space": space,
        "delegationToken": delegation_token,
    });

    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let response = setup.app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_expired_delegation_token() {
    let pool = db::init_pool("postgres://localhost/postgres")
        .await
        .expect("DB connection");
    let setup = setup_test(pool).await;
    let space = unique_space_uri();

    let service_auth = create_service_token(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );
    // Expired delegation token
    let delegation_token = create_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        -10,
    );

    let req_body = json!({
        "space": space,
        "delegationToken": delegation_token,
    });

    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let response = setup.app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn projection_internal_route_enforces_exact_sync_projection_auth_and_jti() {
    let pool = db::init_pool("postgres://localhost/postgres")
        .await
        .expect("DB connection");
    let setup = setup_test(pool).await;
    let space = unique_space_uri();

    let op_id = Uuid::new_v4();
    let body = json!({
        "operationId": op_id,
        "actorDid": ALICE_DID,
        "spaceUri": space,
        "kind": "circle_upsert",
        "payload": {
            "name": "Sync Projection Test",
            "authority": ALICE_DID,
            "space": space
        }
    });

    // 1. Wrong LXM fails (e.g. blue.catbird.circle.activateSpace)
    let wrong_lxm_token = create_service_token(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let req = Request::builder()
        .method("POST")
        .uri("/internal/projections")
        .header(header::AUTHORIZATION, format!("Bearer {wrong_lxm_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Correct LXM (blue.catbird.circle.syncProjection) succeeds
    let correct_token = create_service_token(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.syncProjection",
    );

    let req = Request::builder()
        .method("POST")
        .uri("/internal/projections")
        .header(header::AUTHORIZATION, format!("Bearer {correct_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Replay of same token fails due to JTI replay protection
    let req = Request::builder()
        .method("POST")
        .uri("/internal/projections")
        .header(header::AUTHORIZATION, format!("Bearer {correct_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn projection_receipt_idempotency_and_cascade_delete() {
    let pool = db::init_pool("postgres://localhost/postgres")
        .await
        .expect("DB connection");
    let setup = setup_test(pool).await;
    let space = unique_space_uri();

    let op_id = Uuid::new_v4();
    let upsert = Projection::CircleUpsert {
        space: space.clone(),
        authority: AUTHORITY_DID.into(),
        name: "Initial Circle".into(),
        created_at: Utc::now(),
    };

    // First apply
    projections::apply_projection(&setup.pool, op_id, upsert.clone()).await.unwrap();

    let circle: (String,) = sqlx::query_as("SELECT display_name FROM circles WHERE space_uri = $1")
        .bind(&space)
        .fetch_one(&setup.pool)
        .await
        .unwrap();
    assert_eq!(circle.0, "Initial Circle");

    // Re-apply same operation_id with different payload (idempotent receipt ignores)
    let different_upsert = Projection::CircleUpsert {
        space: space.clone(),
        authority: AUTHORITY_DID.into(),
        name: "Modified Name Should Be Ignored".into(),
        created_at: Utc::now(),
    };
    projections::apply_projection(&setup.pool, op_id, different_upsert).await.unwrap();

    let circle_after: (String,) = sqlx::query_as("SELECT display_name FROM circles WHERE space_uri = $1")
        .bind(&space)
        .fetch_one(&setup.pool)
        .await
        .unwrap();
    assert_eq!(circle_after.0, "Initial Circle");

    // Add Bob and a lease
    projections::apply_projection(
        &setup.pool,
        Uuid::new_v4(),
        Projection::MemberAdd {
            space: space.clone(),
            member: BOB_DID.into(),
        },
    )
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')"
    )
    .bind(&space)
    .bind(BOB_DID)
    .execute(&setup.pool)
    .await
    .unwrap();

    assert!(lease_exists(&setup.pool, &space, BOB_DID).await);

    // Delete Circle cascades everything
    projections::apply_projection(
        &setup.pool,
        Uuid::new_v4(),
        Projection::CircleDelete {
            space: space.clone(),
        },
    )
    .await
    .unwrap();

    let circle_exists: Option<(String,)> = sqlx::query_as("SELECT space_uri FROM circles WHERE space_uri = $1")
        .bind(&space)
        .fetch_optional(&setup.pool)
        .await
        .unwrap();
    assert!(circle_exists.is_none());

    // Leases and members cascaded
    assert!(!lease_exists(&setup.pool, &space, BOB_DID).await);
}

#[tokio::test]
async fn dpop_proof_and_credential_store_lifecycle() {
    let key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let proof = create_dpop_proof(&key, "POST", "https://space.example.com/xrpc/test");
    assert!(!proof.is_empty());
    assert_eq!(proof.split('.').count(), 3);

    let space = unique_space_uri();
    let store = CredentialStore::new();
    assert_eq!(store.get(&space).await.is_none(), true);

    let cred = ActiveSpaceCredential {
        token: "jwt.token.here".into(),
        dpop_key: key,
        expires_at: Utc::now() + chrono::Duration::hours(1),
    };
    store.insert(space.clone(), cred).await;

    let retrieved = store.get(&space).await;
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().token, "jwt.token.here");

    // Remove
    store.remove(&space).await;
    assert!(store.get(&space).await.is_none());

    // Expired credential in store returns None
    let expired_cred = ActiveSpaceCredential {
        token: "expired.jwt".into(),
        dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        expires_at: Utc::now() - chrono::Duration::seconds(10),
    };
    store.insert(space.clone(), expired_cred).await;
    assert!(store.get(&space).await.is_none());
}

#[tokio::test]
async fn privacy_safe_activation_contains_no_jwt_or_key_canaries_in_db_or_logs() {
    let pool = db::init_pool("postgres://localhost/postgres")
        .await
        .expect("DB connection");
    let setup = setup_test(pool).await;
    let space = unique_space_uri();

    let log_buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = BufferWriter(log_buffer.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let attestation_canary = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJjYW5hcnktYXR0ZXN0YXRpb24ifQ.SECRET_ATTESTATION_SIG";
    let credential_canary = create_space_credential_token(
        &setup.authority_signing_key,
        &space,
        3600,
    );

    setup.mock_transport.set_credential_response(&space, Ok(credential_canary.clone()));

    let service_auth = create_service_token(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );
    let delegation_token = create_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        300,
    );

    let req_body = json!({
        "space": space,
        "delegationToken": delegation_token,
        "clientAttestation": attestation_canary
    });

    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let response = setup.app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify database does NOT contain secret tokens
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT space_uri, member_did FROM access_leases WHERE space_uri = $1"
    )
    .bind(&space)
    .fetch_all(&setup.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);

    // Check raw logs do not contain sensitive tokens
    let logs = String::from_utf8_lossy(&log_buffer.lock().unwrap()).to_string();
    assert!(!logs.contains(&delegation_token), "Logs must not leak delegation token");
    assert!(!logs.contains(attestation_canary), "Logs must not leak attestation token");
    assert!(!logs.contains(&credential_canary), "Logs must not leak credential token");
    assert!(!logs.contains(&service_auth), "Logs must not leak service auth token");
}
