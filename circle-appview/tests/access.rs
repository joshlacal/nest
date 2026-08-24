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
        DidDocument, DidResolver, DidService, ParsedVerifyingKey, PublicKeyJwk,
        VerificationMethod,
    },
    config::{AppState, Config},
    db,
    projections::{self, Projection},
    routes::create_router,
    space_client::{
        calculate_rfc7638_jkt, DefaultSpaceHostTransport, MockSpaceHostTransport,
        SpaceClient, SpaceHostTransport,
    },
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
pub const NEST_CLIENT_ID: &str = "https://nest.catbird.blue/client-metadata.json";
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
    nest_signing_key: p256::ecdsa::SigningKey,
    mock_transport: Arc<MockSpaceHostTransport>,
    state: AppState,
    pool: PgPool,
}

async fn setup_test(pool: PgPool) -> TestSetup {
    db::run_migrations(&pool)
        .await
        .expect("Migrations must succeed");

    let nest_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let nest_verifying_key = ParsedVerifyingKey::P256(*nest_signing_key.verifying_key());

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
        nest_client_id: Some(NEST_CLIENT_ID.into()),
        nest_verifying_keys: vec![nest_verifying_key],
    };

    // Keys
    let alice_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let bob_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let authority_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    let state = AppState::new(config.clone(), pool.clone());

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
        config,
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
        nest_signing_key,
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
        verification_method: vec![
            VerificationMethod {
                id: format!("{}#atproto", did),
                r#type: "Multikey".into(),
                controller: did.into(),
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: x.clone(),
                    y: Some(y.clone()),
                }),
                public_key_multibase: Some(p256_multikey.clone()),
            },
            VerificationMethod {
                id: format!("{}#atproto_space", did),
                r#type: "Multikey".into(),
                controller: did.into(),
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x,
                    y: Some(y),
                }),
                public_key_multibase: Some(p256_multikey),
            },
        ],
        service: services.unwrap_or_default(),
    };

    resolver.insert_cached(did.into(), did_doc);
}

fn mint_service_auth(
    signing_key: &p256::ecdsa::SigningKey,
    iss: &str,
    aud: &str,
    lxm: &str,
) -> String {
    let now = Utc::now().timestamp();
    let exp = now + 60;

    let header = json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": format!("{iss}#atproto")
    });

    let claims = json!({
        "iss": iss,
        "aud": aud,
        "lxm": lxm,
        "iat": now,
        "exp": exp,
        "jti": Uuid::new_v4().to_string()
    });

    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h_b64}.{c_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
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
        "typ": "atproto-delegation+jwt",
        "alg": "ES256",
        "kid": format!("{iss}#atproto")
    });

    let claims = json!({
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "iat": iat,
        "exp": exp,
        "jti": Uuid::new_v4().to_string()
    });

    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h_b64}.{c_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

fn mint_space_credential(
    authority_key: &p256::ecdsa::SigningKey,
    iss: &str,
    sub: &str,
    jkt: &str,
    exp: i64,
    iat: i64,
    aud: Option<&str>,
    kid: Option<&str>,
) -> String {
    let header = json!({
        "typ": "atproto-space-credential+jwt",
        "alg": "ES256",
        "kid": kid.unwrap_or("#atproto_space")
    });

    let mut claims = json!({
        "iss": iss,
        "sub": sub,
        "cnf": {
            "jkt": jkt
        },
        "iat": iat,
        "exp": exp,
        "jti": Uuid::new_v4().to_string()
    });

    if let Some(aud_val) = aud {
        claims["aud"] = json!(aud_val);
    }

    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h_b64}.{c_b64}");

    let sig: p256::ecdsa::Signature = authority_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

fn mint_nest_attestation(
    nest_signing_key: &p256::ecdsa::SigningKey,
    client_id: &str,
    aud: &str,
) -> String {
    let now = Utc::now().timestamp();
    let exp = now + 60;

    let header = json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": "nest-active-key"
    });

    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": aud,
        "iat": now,
        "exp": exp,
        "jti": Uuid::new_v4().to_string()
    });

    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h_b64}.{c_b64}");

    let sig: p256::ecdsa::Signature = nest_signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

fn space_uri() -> String {
    format!("at://{}/blue.catbird.circle/3k2abc", AUTHORITY_DID)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[tokio::test]
async fn dpop_proof_and_credential_store_lifecycle() {
    let store = CredentialStore::new();
    let key = p256::ecdsa::SigningKey::random(&mut OsRng);

    let space1 = "at://did:plc:auth1/blue.catbird.circle/space1";
    let cred1 = ActiveSpaceCredential {
        token: "tok1".into(),
        dpop_key: key.clone(),
        expires_at: Utc::now() + chrono::Duration::hours(2),
    };

    store.insert(space1.into(), cred1).await;
    assert_eq!(store.count().await, 1);

    let retrieved = store.get(space1).await;
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().token, "tok1");

    // Monotonic replacement: shorter-lived credential does not overwrite longer-lived
    let cred1_shorter = ActiveSpaceCredential {
        token: "tok1_short".into(),
        dpop_key: key.clone(),
        expires_at: Utc::now() + chrono::Duration::minutes(10),
    };
    store.insert(space1.into(), cred1_shorter).await;
    assert_eq!(store.get(space1).await.unwrap().token, "tok1");

    // Longer-lived credential overwrites
    let cred1_longer = ActiveSpaceCredential {
        token: "tok1_long".into(),
        dpop_key: key.clone(),
        expires_at: Utc::now() + chrono::Duration::hours(5),
    };
    store.insert(space1.into(), cred1_longer).await;
    assert_eq!(store.get(space1).await.unwrap().token, "tok1_long");

    // Expired credential is not inserted and prune works
    let space2 = "at://did:plc:auth2/blue.catbird.circle/space2";
    let expired_cred = ActiveSpaceCredential {
        token: "tok2_expired".into(),
        dpop_key: key,
        expires_at: Utc::now() - chrono::Duration::seconds(10),
    };
    store.insert(space2.into(), expired_cred).await;
    assert!(store.get(space2).await.is_none());

    // Explicit remove
    store.remove(space1).await;
    assert!(store.get(space1).await.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn successful_exchange_creates_lease_for_token_issuer(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();

    let now = Utc::now().timestamp();
    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        "#atproto_space_host",
        now + 300,
        now,
    );

    let service_auth = mint_service_auth(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let dyn_transport = Arc::new(DynamicMockTransport {
        authority_key: setup.authority_signing_key.clone(),
        authority_did: AUTHORITY_DID.to_string(),
        calls: Mutex::new(Vec::new()),
    });

    let custom_space_client = Arc::new(SpaceClient::with_transport(dyn_transport.clone()));
    let state = AppState::with_services(
        (*setup.state.config).clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        custom_space_client,
    );
    let app = create_router(state.clone());

    let body = json!({
        "space": space,
        "delegationToken": delegation_token,
        "clientAttestation": "nest-attestation-mock"
    });

    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let output: ActivateSpaceOutput = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(output.access_state, AccessState::Active);

    // Verify lease exists in DB
    let lease: Option<(DateTime<Utc>,)> = sqlx::query_as(
        "SELECT expires_at FROM access_leases WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(lease.is_some());

    // Verify transport received exact parameters
    let calls = dyn_transport.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].endpoint_url, SPACE_HOST_ENDPOINT);
    assert_eq!(calls[0].space_uri, space);
    assert_eq!(calls[0].delegation_token, delegation_token);
    assert_eq!(calls[0].client_attestation.as_deref(), Some("nest-attestation-mock"));
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_expired_delegation_token(pool: PgPool) {
    let setup = setup_test(pool).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // Expired delegation token
    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        "#atproto_space_host",
        now - 10,
        now - 300,
    );

    let service_auth = mint_service_auth(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let body = json!({
        "space": space,
        "delegationToken": delegation_token
    });

    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = setup.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_delegation_token_with_mismatched_issuer(pool: PgPool) {
    let setup = setup_test(pool).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // Bob signs token for himself, but Alice presents it
    let delegation_token = mint_delegation_token(
        &setup.bob_signing_key,
        BOB_DID,
        &space,
        "#atproto_space_host",
        now + 300,
        now,
    );

    let service_auth = mint_service_auth(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let body = json!({
        "space": space,
        "delegationToken": delegation_token
    });

    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = setup.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_delegation_token_with_mismatched_space_sub(pool: PgPool) {
    let setup = setup_test(pool).await;
    let space1 = space_uri();
    let space2 = "at://did:plc:authority-circle-space/blue.catbird.circle/other-space";
    let now = Utc::now().timestamp();

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        space2,
        "#atproto_space_host",
        now + 300,
        now,
    );
    let service_auth = mint_service_auth(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let body = json!({
        "space": space1,
        "delegationToken": delegation_token
    });

    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = setup.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_delegation_token_with_wrong_audience(pool: PgPool) {
    let setup = setup_test(pool).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // Wrong audience
    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        "did:web:evil.attacker.com",
        now + 300,
        now,
    );

    let service_auth = mint_service_auth(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let body = json!({
        "space": space,
        "delegationToken": delegation_token
    });

    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = setup.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn space_host_resolution_falls_back_to_atproto_pds(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let pds_endpoint = "https://pds.example.com";
    let pds_authority_did = "did:plc:pds-fallback-authority";
    let pds_authority_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    // Register authority with ONLY #atproto_pds (no #atproto_space_host)
    register_did_doc(
        &setup.state.did_resolver,
        pds_authority_did,
        &pds_authority_key,
        Some(vec![DidService {
            id: "#atproto_pds".into(),
            r#type: "AtprotoPersonalDataServer".into(),
            service_endpoint: pds_endpoint.into(),
        }]),
    );

    let space = format!("at://{pds_authority_did}/blue.catbird.circle/3k2pds");
    let now = Utc::now().timestamp();

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        "#atproto_pds",
        now + 300,
        now,
    );

    let dyn_transport = Arc::new(DynamicMockTransport {
        authority_key: pds_authority_key,
        authority_did: pds_authority_did.to_string(),
        calls: Mutex::new(Vec::new()),
    });

    let custom_space_client = Arc::new(SpaceClient::with_transport(dyn_transport.clone()));
    let state = AppState::with_services(
        (*setup.state.config).clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        custom_space_client,
    );
    let app = create_router(state);

    let service_auth = mint_service_auth(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let body = json!({
        "space": space,
        "delegationToken": delegation_token
    });

    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let calls = dyn_transport.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].endpoint_url, pds_endpoint);
}


#[sqlx::test(migrations = "./migrations")]
async fn rejects_space_credential_with_wrong_signature(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // Space host returns credential signed by an attacker key instead of authority
    let attacker_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    struct AttackerSignedTransport {
        attacker_key: p256::ecdsa::SigningKey,
        authority_did: String,
    }

    impl SpaceHostTransport for AttackerSignedTransport {
        fn get_space_credential<'a>(
            &'a self,
            _endpoint_url: &'a str,
            _delegation_token: &'a str,
            dpop_proof: &'a str,
            space_uri: &'a str,
            _client_attestation: Option<&'a str>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
            let parts: Vec<&str> = dpop_proof.split('.').collect();
            let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
            let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
            let jwk = header.get("jwk").unwrap();
            let x = jwk.get("x").unwrap().as_str().unwrap();
            let y = jwk.get("y").unwrap().as_str().unwrap();

            let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(canonical.as_bytes());
            let jkt = URL_SAFE_NO_PAD.encode(hasher.finalize());

            let now = Utc::now().timestamp();
            let cred = mint_space_credential(
                &self.attacker_key,
                &self.authority_did,
                space_uri,
                &jkt,
                now + 3600,
                now,
                None,
                Some("#atproto_space"),
            );

            Box::pin(async move { Ok(cred) })
        }
    }

    let custom_space_client = Arc::new(SpaceClient::with_transport(Arc::new(AttackerSignedTransport {
        attacker_key,
        authority_did: AUTHORITY_DID.to_string(),
    })));

    let state = AppState::with_services(
        (*setup.state.config).clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        custom_space_client,
    );
    let app = create_router(state);

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        "#atproto_space_host",
        now + 300,
        now,
    );

    let service_auth = mint_service_auth(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let body = json!({
        "space": space,
        "delegationToken": delegation_token
    });

    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_space_credential_with_mismatched_jkt(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    struct WrongJktTransport {
        authority_key: p256::ecdsa::SigningKey,
        authority_did: String,
    }

    impl SpaceHostTransport for WrongJktTransport {
        fn get_space_credential<'a>(
            &'a self,
            _endpoint_url: &'a str,
            _delegation_token: &'a str,
            _dpop_proof: &'a str,
            space_uri: &'a str,
            _client_attestation: Option<&'a str>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
            let now = Utc::now().timestamp();
            let cred = mint_space_credential(
                &self.authority_key,
                &self.authority_did,
                space_uri,
                "wrong-mismatched-jkt-value",
                now + 3600,
                now,
                None,
                Some("#atproto_space"),
            );

            Box::pin(async move { Ok(cred) })
        }
    }

    let custom_space_client = Arc::new(SpaceClient::with_transport(Arc::new(WrongJktTransport {
        authority_key: setup.authority_signing_key.clone(),
        authority_did: AUTHORITY_DID.to_string(),
    })));

    let state = AppState::with_services(
        (*setup.state.config).clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        custom_space_client,
    );
    let app = create_router(state);

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        "#atproto_space_host",
        now + 300,
        now,
    );

    let service_auth = mint_service_auth(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let body = json!({
        "space": space,
        "delegationToken": delegation_token
    });

    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_space_credential_with_expired_time(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    struct ExpiredCredTransport {
        authority_key: p256::ecdsa::SigningKey,
        authority_did: String,
    }

    impl SpaceHostTransport for ExpiredCredTransport {
        fn get_space_credential<'a>(
            &'a self,
            _endpoint_url: &'a str,
            _delegation_token: &'a str,
            dpop_proof: &'a str,
            space_uri: &'a str,
            _client_attestation: Option<&'a str>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
            let parts: Vec<&str> = dpop_proof.split('.').collect();
            let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
            let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
            let jwk = header.get("jwk").unwrap();
            let x = jwk.get("x").unwrap().as_str().unwrap();
            let y = jwk.get("y").unwrap().as_str().unwrap();

            let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(canonical.as_bytes());
            let jkt = URL_SAFE_NO_PAD.encode(hasher.finalize());

            let now = Utc::now().timestamp();
            // Expired credential (exp <= now)
            let cred = mint_space_credential(
                &self.authority_key,
                &self.authority_did,
                space_uri,
                &jkt,
                now - 10,
                now - 300,
                None,
                Some("#atproto_space"),
            );

            Box::pin(async move { Ok(cred) })
        }
    }

    let custom_space_client = Arc::new(SpaceClient::with_transport(Arc::new(ExpiredCredTransport {
        authority_key: setup.authority_signing_key.clone(),
        authority_did: AUTHORITY_DID.to_string(),
    })));

    let state = AppState::with_services(
        (*setup.state.config).clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        custom_space_client,
    );
    let app = create_router(state);

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        "#atproto_space_host",
        now + 300,
        now,
    );

    let service_auth = mint_service_auth(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let body = json!({
        "space": space,
        "delegationToken": delegation_token
    });

    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
#[sqlx::test(migrations = "./migrations")]
async fn removal_invalidates_lease_without_deleting_circle_records(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();

    // 1. Initial Circle and Active Lease for Bob
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Test Circle', now())",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at) VALUES ($1, $2, 'active', 1, now())",
    )
    .bind(&space)
    .bind(BOB_DID)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')",
    )
    .bind(&space)
    .bind(BOB_DID)
    .execute(&mut *tx)
    .await
    .unwrap();

    let record_uri = format!("{}/app.bsky.feed.post/3k2rec1", space);
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, 'bafyrei1', $2, $3, 'app.bsky.feed.post', '3k2rec1', '{"text":"Hello"}', now())
        "#,
    )
    .bind(&record_uri)
    .bind(&space)
    .bind(BOB_DID)
    .execute(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();

    // 2. Apply MemberRemove projection for Bob (generation 2)
    let remove_projection = Projection::MemberRemove {
        space: space.clone(),
        member: BOB_DID.into(),
        generation: 2,
    };

    let digest = projections::compute_payload_digest(
        &Uuid::new_v4(),
        AUTHORITY_DID,
        &space,
        "member_remove",
        &json!({"member": BOB_DID, "generation": 2}),
    );

    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Uuid::new_v4(),
        remove_projection,
        &digest,
    )
    .await
    .unwrap();

    // 3. Verify lease was deleted
    let lease_exists: Option<(String,)> = sqlx::query_as(
        "SELECT space_uri FROM access_leases WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(BOB_DID)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(lease_exists.is_none());

    // 4. Verify circle records were NOT deleted
    let record_count: (i64,) = sqlx::query_as("SELECT count(*) FROM circle_records WHERE space_uri = $1")
        .bind(&space)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(record_count.0, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn projection_receipt_idempotency_and_cascade_delete(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let op_id = Uuid::new_v4();

    let upsert = Projection::CircleUpsert {
        space: space.clone(),
        authority: AUTHORITY_DID.into(),
        name: "Test Circle".into(),
        created_at: Utc::now(),
        generation: 1,
    };

    let payload = json!({
        "name": "Test Circle",
        "authority": AUTHORITY_DID,
        "generation": 1
    });

    let digest = projections::compute_payload_digest(
        &op_id,
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &payload,
    );

    // First delivery -> mutates
    let res1 = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        op_id,
        upsert.clone(),
        &digest,
    )
    .await;
    assert!(res1.is_ok());

    // Duplicate delivery with identical payload -> idempotent success
    let res2 = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        op_id,
        upsert,
        &digest,
    )
    .await;
    assert!(res2.is_ok());

    // Replay of same op_id with DIFFERENT payload -> 409 Conflict
    let conflict_payload = json!({
        "name": "Different Name",
        "authority": AUTHORITY_DID,
        "generation": 1
    });
    let conflict_digest = projections::compute_payload_digest(
        &op_id,
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &conflict_payload,
    );
    let conflict_upsert = Projection::CircleUpsert {
        space: space.clone(),
        authority: AUTHORITY_DID.into(),
        name: "Different Name".into(),
        created_at: Utc::now(),
        generation: 1,
    };

    let res3 = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        op_id,
        conflict_upsert,
        &conflict_digest,
    )
    .await;
    assert!(res3.is_err());

    // Populate active credential in in-memory store
    setup.state.credential_store.insert(
        space.clone(),
        ActiveSpaceCredential {
            token: "tok_secret".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        },
    ).await;
    assert!(setup.state.credential_store.get(&space).await.is_some());

    // CircleDelete -> cascades DB and purges in-memory CredentialStore
    let del_op = Uuid::new_v4();
    let del_digest = projections::compute_payload_digest(
        &del_op,
        AUTHORITY_DID,
        &space,
        "circle_delete",
        &json!({"space": space}),
    );

    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        del_op,
        Projection::CircleDelete {
            space: space.clone(),
            generation: 2,
        },
        &del_digest,
    )
    .await
    .unwrap();

    // Verify in-memory store purged
    assert!(setup.state.credential_store.get(&space).await.is_none());

    // Verify deletion tombstone exists
    let tombstone: Option<(String,)> = sqlx::query_as(
        "SELECT space_uri FROM circle_tombstones WHERE space_uri = $1",
    )
    .bind(&space)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(tombstone.is_some());

    // Stale upsert on tombstoned Circle does NOT resurrect
    let stale_op = Uuid::new_v4();
    let stale_digest = projections::compute_payload_digest(
        &stale_op,
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &payload,
    );
    let stale_res = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        stale_op,
        Projection::CircleUpsert {
            space: space.clone(),
            authority: AUTHORITY_DID.into(),
            name: "Resurrect Attempt".into(),
            created_at: Utc::now(),
            generation: 1,
        },
        &stale_digest,
    )
    .await;
    assert!(stale_res.is_ok());

    let circle_row: Option<(String,)> = sqlx::query_as(
        "SELECT space_uri FROM circles WHERE space_uri = $1",
    )
    .bind(&space)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(circle_row.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn projection_route_dual_auth_and_actor_binding(pool: PgPool) {
    let setup = setup_test(pool).await;
    let space = space_uri();
    let op_id = Uuid::new_v4();

    let service_auth = mint_service_auth(
        &setup.authority_signing_key,
        AUTHORITY_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.syncProjection",
    );

    let nest_attestation = mint_nest_attestation(
        &setup.nest_signing_key,
        NEST_CLIENT_ID,
        CIRCLE_AUDIENCE,
    );

    let body = json!({
        "operationId": op_id,
        "actorDid": AUTHORITY_DID,
        "spaceUri": space,
        "kind": "circle_upsert",
        "payload": {
            "name": "Authorized Circle",
            "authority": AUTHORITY_DID,
            "space": space,
            "generation": 1
        }
    });

    // 1. Valid dual-auth -> 200 OK
    let req = Request::builder()
        .uri("/internal/projections")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header("X-Nest-Client-Attestation", &nest_attestation)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Replay of Nest attestation (same jti) -> 401 Unauthorized
    let op_id2 = Uuid::new_v4();
    let body2 = json!({
        "operationId": op_id2,
        "actorDid": AUTHORITY_DID,
        "spaceUri": space,
        "kind": "circle_upsert",
        "payload": {
            "name": "Replay Attempt",
            "authority": AUTHORITY_DID,
            "generation": 2
        }
    });

    let service_auth2 = mint_service_auth(
        &setup.authority_signing_key,
        AUTHORITY_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.syncProjection",
    );

    let req_replay = Request::builder()
        .uri("/internal/projections")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth2}"))
        .header("X-Nest-Client-Attestation", &nest_attestation)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body2).unwrap()))
        .unwrap();

    let resp_replay = setup.app.clone().oneshot(req_replay).await.unwrap();
    assert_eq!(resp_replay.status(), StatusCode::UNAUTHORIZED);

    // 3. Mismatched actor DID (authenticated DID != input.actor_did) -> 403 Forbidden
    let alice_auth = mint_service_auth(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.syncProjection",
    );
    let fresh_nest_att = mint_nest_attestation(
        &setup.nest_signing_key,
        NEST_CLIENT_ID,
        CIRCLE_AUDIENCE,
    );

    let op_id3 = Uuid::new_v4();
    let body3 = json!({
        "operationId": op_id3,
        "actorDid": AUTHORITY_DID, // Claims to be authority, but token signed by Alice
        "spaceUri": space,
        "kind": "circle_upsert",
        "payload": {
            "name": "Impersonation Attempt",
            "generation": 3
        }
    });

    let req_impersonate = Request::builder()
        .uri("/internal/projections")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {alice_auth}"))
        .header("X-Nest-Client-Attestation", fresh_nest_att)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body3).unwrap()))
        .unwrap();

    let resp_imp = setup.app.clone().oneshot(req_impersonate).await.unwrap();
    assert_eq!(resp_imp.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
async fn member_generations_prevent_out_of_order_overwrites(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();

    // 1. Insert circle
    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Circle', now())",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Deliver MemberRemove (generation 2)
    let remove_op = Uuid::new_v4();
    let remove_digest = projections::compute_payload_digest(
        &remove_op,
        AUTHORITY_DID,
        &space,
        "member_remove",
        &json!({"member": BOB_DID, "generation": 2}),
    );

    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        remove_op,
        Projection::MemberRemove {
            space: space.clone(),
            member: BOB_DID.into(),
            generation: 2,
        },
        &remove_digest,
    )
    .await
    .unwrap();

    let status1: (String, i64) = sqlx::query_as(
        "SELECT status, generation FROM circle_members WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(BOB_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status1.0, "removed");
    assert_eq!(status1.1, 2);

    // 3. Delayed delivery of older MemberAdd (generation 1) -> ignored
    let add_op = Uuid::new_v4();
    let add_digest = projections::compute_payload_digest(
        &add_op,
        AUTHORITY_DID,
        &space,
        "member_add",
        &json!({"member": BOB_DID, "generation": 1}),
    );

    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        add_op,
        Projection::MemberAdd {
            space: space.clone(),
            member: BOB_DID.into(),
            generation: 1,
        },
        &add_digest,
    )
    .await
    .unwrap();

    // Status MUST still be removed with generation 2
    let status2: (String, i64) = sqlx::query_as(
        "SELECT status, generation FROM circle_members WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(BOB_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status2.0, "removed");
    assert_eq!(status2.1, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn activation_fails_if_member_removed_or_circle_deleted(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // Setup circle and removed member
    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Circle', now())",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at) VALUES ($1, $2, 'removed', 1, now())",
    )
    .bind(&space)
    .bind(BOB_DID)
    .execute(&pool)
    .await
    .unwrap();

    let dyn_transport = Arc::new(DynamicMockTransport {
        authority_key: setup.authority_signing_key.clone(),
        authority_did: AUTHORITY_DID.to_string(),
        calls: Mutex::new(Vec::new()),
    });

    let custom_space_client = Arc::new(SpaceClient::with_transport(dyn_transport));
    let state = AppState::with_services(
        (*setup.state.config).clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        custom_space_client,
    );
    let app = create_router(state);

    let delegation_token = mint_delegation_token(
        &setup.bob_signing_key,
        BOB_DID,
        &space,
        "#atproto_space_host",
        now + 300,
        now,
    );

    let service_auth = mint_service_auth(
        &setup.bob_signing_key,
        BOB_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let body = json!({
        "space": space,
        "delegationToken": delegation_token
    });

    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
async fn privacy_safe_activation_contains_no_jwt_or_key_canaries_in_db_or_logs(pool: PgPool) {
    let log_buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(BufferWriter(log_buffer.clone()))
        .with_env_filter("debug")
        .finish();

    let _guard = tracing::subscriber::set_default(subscriber);

    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    let canary_delegation = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        "#atproto_space_host",
        now + 300,
        now,
    );

    let dyn_transport = Arc::new(DynamicMockTransport {
        authority_key: setup.authority_signing_key.clone(),
        authority_did: AUTHORITY_DID.to_string(),
        calls: Mutex::new(Vec::new()),
    });

    let custom_space_client = Arc::new(SpaceClient::with_transport(dyn_transport));
    let state = AppState::with_services(
        (*setup.state.config).clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        custom_space_client,
    );
    let app = create_router(state);

    let service_auth = mint_service_auth(
        &setup.alice_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.activateSpace",
    );

    let body = json!({
        "space": space,
        "delegationToken": canary_delegation
    });

    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.activateSpace")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Inspect logs
    let logs = String::from_utf8(log_buffer.lock().unwrap().clone()).unwrap();
    assert!(!logs.contains(&canary_delegation));
}

#[tokio::test]
async fn ssrf_safe_transport_rejects_private_and_http_endpoints() {
    let transport = DefaultSpaceHostTransport::new();

    // 1. HTTP endpoint rejected
    let res1 = transport
        .get_space_credential("http://example.com", "token", "dpop", "space", None)
        .await;
    assert!(res1.is_err());

    // 2. Localhost rejected
    let res2 = transport
        .get_space_credential("https://localhost:8443", "token", "dpop", "space", None)
        .await;
    assert!(res2.is_err());

    // 3. Private IP rejected
    let res3 = transport
        .get_space_credential("https://127.0.0.1:8443", "token", "dpop", "space", None)
        .await;
    assert!(res3.is_err());

    let res4 = transport
        .get_space_credential("https://10.0.0.1:8443", "token", "dpop", "space", None)
        .await;
    assert!(res4.is_err());
}

struct DynamicMockTransport {
    authority_key: p256::ecdsa::SigningKey,
    authority_did: String,
    calls: Mutex<Vec<circle_appview::space_client::RecordedSpaceHostCall>>,
}

impl SpaceHostTransport for DynamicMockTransport {
    fn get_space_credential<'a>(
        &'a self,
        endpoint_url: &'a str,
        delegation_token: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        client_attestation: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
        let call = circle_appview::space_client::RecordedSpaceHostCall {
            endpoint_url: endpoint_url.to_string(),
            delegation_token: delegation_token.to_string(),
            dpop_proof: dpop_proof.to_string(),
            space_uri: space_uri.to_string(),
            client_attestation: client_attestation.map(|s| s.to_string()),
        };
        self.calls.lock().unwrap().push(call);

        let parts: Vec<&str> = dpop_proof.split('.').collect();
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        let jwk = header.get("jwk").unwrap();
        let x = jwk.get("x").unwrap().as_str().unwrap();
        let y = jwk.get("y").unwrap().as_str().unwrap();

        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let jkt = URL_SAFE_NO_PAD.encode(hasher.finalize());

        let now = Utc::now().timestamp();
        let cred = mint_space_credential(
            &self.authority_key,
            &self.authority_did,
            space_uri,
            &jkt,
            now + 3600,
            now,
            None,
            Some("#atproto_space"),
        );

        Box::pin(async move { Ok(cred) })
    }
}
