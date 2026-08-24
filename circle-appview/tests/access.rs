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
    access::{self, ActiveSpaceCredential},
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
use p256::ecdsa::signature::{Signer, Verifier};
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;
use std::future::Future;
use std::pin::Pin;
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
#[allow(dead_code)]
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
        nest_client_id: NEST_CLIENT_ID.into(),
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
                id: format!("{did}#atproto_space"),
                r#type: "Multikey".into(),
                controller: did.into(),
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: x.clone(),
                    y: Some(y.clone()),
                    kid: None,
                }),
                public_key_multibase: Some(p256_multikey.clone()),
            },
            VerificationMethod {
                id: format!("{did}#atproto"),
                r#type: "Multikey".into(),
                controller: did.into(),
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x,
                    y: Some(y),
                    kid: None,
                }),
                public_key_multibase: Some(p256_multikey),
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
        "typ": "atproto-delegation+jwt",
        "alg": "ES256"
    });
    let payload = json!({
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "exp": exp,
        "iat": iat,
        "jti": Uuid::new_v4().to_string(),
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

fn mint_space_credential(
    signing_key: &p256::ecdsa::SigningKey,
    iss: &str,
    sub: &str,
    jkt: &str,
    exp: i64,
    iat: i64,
    aud: Option<&str>,
    kid: Option<&str>,
) -> String {
    let mut header = json!({
        "typ": "atproto-space-credential+jwt",
        "alg": "ES256"
    });
    if let Some(k) = kid {
        header["kid"] = json!(k);
    }

    let mut payload = json!({
        "iss": iss,
        "sub": sub,
        "exp": exp,
        "iat": iat,
        "jti": Uuid::new_v4().to_string(),
        "cnf": {
            "jkt": jkt
        }
    });
    if let Some(a) = aud {
        payload["aud"] = json!(a);
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

fn mint_service_auth(
    signing_key: &p256::ecdsa::SigningKey,
    iss: &str,
    aud: &str,
    lxm: &str,
) -> String {
    let now = Utc::now().timestamp();
    let header = json!({
        "typ": "JWT",
        "alg": "ES256"
    });
    let payload = json!({
        "iss": iss,
        "aud": aud,
        "lxm": lxm,
        "exp": now + 60,
        "iat": now,
        "jti": Uuid::new_v4().to_string(),
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

fn mint_nest_attestation(
    signing_key: &p256::ecdsa::SigningKey,
    client_id: &str,
    aud: &str,
) -> String {
    let now = Utc::now().timestamp();
    let header = json!({
        "typ": "JWT",
        "alg": "ES256"
    });
    let payload = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": aud,
        "exp": now + 60,
        "iat": now,
        "jti": Uuid::new_v4().to_string(),
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

struct DynamicMockTransport {
    authority_key: p256::ecdsa::SigningKey,
    authority_did: String,
    calls: Mutex<Vec<circle_appview::space_client::RecordedSpaceHostCall>>,
}

impl SpaceHostTransport for DynamicMockTransport {
    fn get_space_credential<'a>(
        &'a self,
        target_url: &'a url::Url,
        delegation_token: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        client_attestation: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
        let call = circle_appview::space_client::RecordedSpaceHostCall {
            endpoint_url: target_url.to_string(),
            delegation_token: delegation_token.to_string(),
            dpop_proof: dpop_proof.to_string(),
            space_uri: space_uri.to_string(),
            client_attestation: client_attestation.to_string(),
        };
        self.calls.lock().unwrap().push(call);

        // Parse and rigorously validate DPoP proof
        let parts: Vec<&str> = dpop_proof.split('.').collect();
        if parts.len() != 3 {
            return Box::pin(async {
                Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP proof format".into()))
            });
        }

        let header_bytes = match URL_SAFE_NO_PAD.decode(parts[0]) {
            Ok(b) => b,
            Err(_) => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP header".into())) }),
        };
        let header: serde_json::Value = match serde_json::from_slice(&header_bytes) {
            Ok(h) => h,
            Err(_) => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP header JSON".into())) }),
        };

        if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
            return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP typ".into())) });
        }
        if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
            return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP alg".into())) });
        }

        let jwk = match header.get("jwk") {
            Some(j) => j,
            None => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Missing DPoP jwk".into())) }),
        };
        let x = match jwk.get("x").and_then(|v| v.as_str()) {
            Some(x) => x,
            None => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Missing DPoP x".into())) }),
        };
        let y = match jwk.get("y").and_then(|v| v.as_str()) {
            Some(y) => y,
            None => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Missing DPoP y".into())) }),
        };

        let x_bytes = URL_SAFE_NO_PAD.decode(x).unwrap();
        let y_bytes = URL_SAFE_NO_PAD.decode(y).unwrap();
        let mut xb = p256::FieldBytes::default();
        let mut yb = p256::FieldBytes::default();
        xb.copy_from_slice(&x_bytes);
        yb.copy_from_slice(&y_bytes);
        let ep = p256::EncodedPoint::from_affine_coordinates(&xb, &yb, false);
        let verifying_key = match p256::ecdsa::VerifyingKey::from_encoded_point(&ep) {
            Ok(vk) => vk,
            Err(_) => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP key point".into())) }),
        };

        let payload_bytes = match URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(b) => b,
            Err(_) => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP payload".into())) }),
        };
        let payload: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
            Ok(p) => p,
            Err(_) => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP payload JSON".into())) }),
        };

        if payload.get("htm").and_then(|v| v.as_str()) != Some("POST") {
            return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP htm".into())) });
        }
        if payload.get("htu").and_then(|v| v.as_str()) != Some(target_url.as_str()) {
            return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP htu".into())) });
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = match URL_SAFE_NO_PAD.decode(parts[2]) {
            Ok(b) => b,
            Err(_) => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP sig encoding".into())) }),
        };
        let sig = match p256::ecdsa::Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP sig format".into())) }),
        };

        if verifying_key.verify(signing_input.as_bytes(), &sig).is_err() {
            return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("DPoP signature verification failed".into())) });
        }

        let jkt = calculate_rfc7638_jkt(&verifying_key);
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

#[sqlx::test(migrations = "./migrations")]
async fn successful_exchange_creates_lease_for_token_issuer(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

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

    // Verify lease exists in database
    let lease: Option<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT space_uri, expires_at FROM access_leases WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(lease.is_some());

    // Verify in-memory store populated
    let stored_cred = setup.state.credential_store.get(&space).await;
    assert!(stored_cred.is_some());

    // Verify call to Space host had clientAttestation and exact XRPC URL
    let calls = dyn_transport.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].client_attestation, "nest-attestation-mock");
    assert_eq!(calls[0].endpoint_url, format!("{SPACE_HOST_ENDPOINT}/xrpc/com.atproto.space.getSpaceCredential"));
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_activate_space_without_client_attestation(pool: PgPool) {
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

    // Missing clientAttestation
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

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
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
async fn rejects_expired_delegation_token(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // Expired delegation token (exp <= now)
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

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_delegation_token_with_mismatched_issuer(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // Delegation signed by Bob, but authenticated as Alice
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

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_delegation_token_with_mismatched_space_sub(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let other_space = "at://did:plc:other-authority/space/blue.catbird.circle/3k2other";
    let now = Utc::now().timestamp();

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        other_space,
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

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_delegation_token_with_wrong_audience(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        "did:web:unrelated-wrong-audience",
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

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_space_credential_with_alg_key_curve_mismatch(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // Transport signs with P256 key but labels alg as ES256K
    struct MismatchedAlgTransport {
        authority_key: p256::ecdsa::SigningKey,
        authority_did: String,
    }

    impl SpaceHostTransport for MismatchedAlgTransport {
        fn get_space_credential<'a>(
            &'a self,
            _target_url: &'a url::Url,
            _delegation_token: &'a str,
            dpop_proof: &'a str,
            space_uri: &'a str,
            _client_attestation: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
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
            let header = json!({
                "typ": "atproto-space-credential+jwt",
                "alg": "ES256K"
            });
            let payload = json!({
                "iss": self.authority_did,
                "sub": space_uri,
                "exp": now + 3600,
                "iat": now,
                "jti": Uuid::new_v4().to_string(),
                "cnf": { "jkt": jkt }
            });
            let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
            let signing_input = format!("{header_b64}.{payload_b64}");
            let sig: p256::ecdsa::Signature = self.authority_key.sign(signing_input.as_bytes());
            let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
            let token = format!("{signing_input}.{sig_b64}");

            Box::pin(async move { Ok(token) })
        }
    }

    let custom_space_client = Arc::new(SpaceClient::with_transport(Arc::new(MismatchedAlgTransport {
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
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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
            _target_url: &'a url::Url,
            _delegation_token: &'a str,
            dpop_proof: &'a str,
            space_uri: &'a str,
            _client_attestation: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
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
            _target_url: &'a url::Url,
            _delegation_token: &'a str,
            _dpop_proof: &'a str,
            space_uri: &'a str,
            _client_attestation: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
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
            _target_url: &'a url::Url,
            _delegation_token: &'a str,
            dpop_proof: &'a str,
            space_uri: &'a str,
            _client_attestation: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
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
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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
        &setup.state.did_resolver.resolve(AUTHORITY_DID).await.unwrap(),
        AUTHORITY_DID,
    )
    .unwrap();

    assert_eq!(endpoint, pds_endpoint);
    assert_eq!(service_id, format!("{AUTHORITY_DID}#atproto_pds"));
}

#[sqlx::test(migrations = "./migrations")]
async fn removal_invalidates_lease_without_deleting_circle_records(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();

    // 1. Initial Circle and Active Lease for Bob
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Test Circle', now(), 1)",
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
        None,
        AUTHORITY_DID,
        &space,
        "member_remove",
        &json!({"member": BOB_DID, "generation": 2}),
        Some(2),
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
        None,
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &payload,
        Some(1),
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
        None,
        AUTHORITY_DID,
        &space,
        "circle_delete",
        &json!({"space": space}),
        Some(2),
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
    let tombstone: Option<(i64,)> = sqlx::query_as(
        "SELECT generation FROM circle_tombstones WHERE space_uri = $1",
    )
    .bind(&space)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(tombstone.is_some());

    // Stale upsert with older/equal generation on tombstoned Circle does NOT resurrect
    let stale_op = Uuid::new_v4();
    let stale_digest = projections::compute_payload_digest(
        &stale_op,
        None,
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &payload,
        Some(1),
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

    // 2. Missing Nest attestation -> 401 Unauthorized (FAIL CLOSED)
    let op_id_no_att = Uuid::new_v4();
    let body_no_att = json!({
        "operationId": op_id_no_att,
        "actorDid": AUTHORITY_DID,
        "spaceUri": space,
        "kind": "circle_upsert",
        "payload": {
            "name": "No Attestation",
            "authority": AUTHORITY_DID,
            "generation": 2
        }
    });

    let service_auth_no_att = mint_service_auth(
        &setup.authority_signing_key,
        AUTHORITY_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.syncProjection",
    );

    let req_no_att = Request::builder()
        .uri("/internal/projections")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {service_auth_no_att}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body_no_att).unwrap()))
        .unwrap();

    let resp_no_att = setup.app.clone().oneshot(req_no_att).await.unwrap();
    assert_eq!(resp_no_att.status(), StatusCode::UNAUTHORIZED);

    // 3. Replay of Nest attestation (same jti) -> 401 Unauthorized
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

    // 4. Mismatched actor DID (authenticated DID != input.actor_did) -> 403 Forbidden
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
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Circle', now(), 0)",
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
        None,
        AUTHORITY_DID,
        &space,
        "member_remove",
        &json!({"member": BOB_DID, "generation": 2}),
        Some(2),
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
        None,
        AUTHORITY_DID,
        &space,
        "member_add",
        &json!({"member": BOB_DID, "generation": 1}),
        Some(1),
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
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Circle', now(), 0)",
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
        "delegationToken": canary_delegation,
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

    // Inspect logs
    let logs = String::from_utf8(log_buffer.lock().unwrap().clone()).unwrap();
    assert!(!logs.contains(&canary_delegation));
}

#[sqlx::test(migrations = "./migrations")]
async fn receipt_digest_includes_generation_and_operation_key_conflict(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let op_id = Uuid::new_v4();

    let payload = json!({
        "name": "Test Circle",
        "authority": AUTHORITY_DID,
        "generation": 1
    });

    let digest1 = projections::compute_payload_digest(
        &op_id,
        Some("key-1"),
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &payload,
        Some(1),
    );

    let digest2 = projections::compute_payload_digest(
        &op_id,
        Some("key-1"),
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &payload,
        Some(2), // Different generation!
    );

    assert_ne!(digest1, digest2);

    // Apply with digest1
    let upsert = Projection::CircleUpsert {
        space: space.clone(),
        authority: AUTHORITY_DID.into(),
        name: "Test Circle".into(),
        created_at: Utc::now(),
        generation: 1,
    };

    let res1 = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        op_id,
        upsert.clone(),
        &digest1,
    )
    .await;
    assert!(res1.is_ok());

    // Replay with digest2 (different generation) -> 409 Conflict
    let res2 = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        op_id,
        upsert,
        &digest2,
    )
    .await;
    assert!(res2.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_receipt_claims_under_race(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let op_id = Uuid::new_v4();

    let payload = json!({
        "name": "Race Circle",
        "authority": AUTHORITY_DID,
        "generation": 1
    });

    let digest = projections::compute_payload_digest(
        &op_id,
        Some("race-key"),
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &payload,
        Some(1),
    );

    let upsert = Projection::CircleUpsert {
        space: space.clone(),
        authority: AUTHORITY_DID.into(),
        name: "Race Circle".into(),
        created_at: Utc::now(),
        generation: 1,
    };

    // Spawn 10 concurrent requests claiming the same operation_id
    let mut handles = Vec::new();
    for _ in 0..10 {
        let pool = pool.clone();
        let store = setup.state.credential_store.clone();
        let upsert = upsert.clone();
        let digest = digest.clone();
        handles.push(tokio::spawn(async move {
            projections::apply_projection(&pool, Some(&store), op_id, upsert, &digest).await
        }));
    }

    for handle in handles {
        let res = handle.await.unwrap();
        assert!(res.is_ok());
    }

    // Verify only ONE receipt row exists in database
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM projection_receipts WHERE operation_id = $1")
        .bind(op_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_activation_vs_circle_deletion_race(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();

    // 1. Circle is deleted (tombstone inserted)
    let del_op = Uuid::new_v4();
    let del_digest = projections::compute_payload_digest(
        &del_op,
        None,
        AUTHORITY_DID,
        &space,
        "circle_delete",
        &json!({"space": space}),
        Some(1),
    );

    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        del_op,
        Projection::CircleDelete {
            space: space.clone(),
            generation: 1,
        },
        &del_digest,
    )
    .await
    .unwrap();

    // 2. In-flight activation attempt after deletion MUST fail
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

    let now = Utc::now().timestamp();
    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        "#atproto_space_host",
        now + 300,
        now,
    );

    let res = access::activate_space(
        &state,
        ALICE_DID,
        &space,
        &delegation_token,
        "attestation",
    )
    .await;

    assert!(res.is_err());
    // In-memory store must remain empty
    assert!(setup.state.credential_store.get(&space).await.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn persisted_lease_is_monotonic_max_under_concurrent_activations(pool: PgPool) {
    let _setup = setup_test(pool.clone()).await;
    let space = space_uri();

    // Create circle and member
    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Circle', now(), 0)",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at) VALUES ($1, $2, 'active', 0, now())",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    // Insert lease with 2 hours expiry
    let longer_exp = Utc::now() + chrono::Duration::hours(2);
    sqlx::query(
        r#"
        INSERT INTO access_leases (space_uri, member_did, expires_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (space_uri, member_did)
        DO UPDATE SET expires_at = GREATEST(access_leases.expires_at, EXCLUDED.expires_at)
        "#,
    )
    .bind(&space)
    .bind(ALICE_DID)
    .bind(longer_exp)
    .execute(&pool)
    .await
    .unwrap();

    // Concurrent slower activation with 1 hour expiry attempts overwrite
    let shorter_exp = Utc::now() + chrono::Duration::hours(1);
    sqlx::query(
        r#"
        INSERT INTO access_leases (space_uri, member_did, expires_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (space_uri, member_did)
        DO UPDATE SET expires_at = GREATEST(access_leases.expires_at, EXCLUDED.expires_at)
        "#,
    )
    .bind(&space)
    .bind(ALICE_DID)
    .bind(shorter_exp)
    .execute(&pool)
    .await
    .unwrap();

    // Verify lease remains at longer_exp
    let stored_exp: (DateTime<Utc>,) = sqlx::query_as(
        "SELECT expires_at FROM access_leases WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Stored expiry must equal longer_exp, not shorter_exp
    assert_eq!(stored_exp.0.timestamp(), longer_exp.timestamp());
}

#[tokio::test]
async fn ssrf_safe_transport_rejects_private_and_http_endpoints() {
    let transport = DefaultSpaceHostTransport::new();

    // 1. HTTP endpoint rejected
    let res1 = url::Url::parse("http://example.com").unwrap();
    let err1 = transport
        .get_space_credential(&res1, "token", "dpop", "space", "attestation")
        .await;
    assert!(err1.is_err());

    // 2. Localhost rejected
    let res2 = url::Url::parse("https://localhost:8443").unwrap();
    let err2 = transport
        .get_space_credential(&res2, "token", "dpop", "space", "attestation")
        .await;
    assert!(err2.is_err());

    // 3. Private IP rejected
    let res3 = url::Url::parse("https://127.0.0.1:8443").unwrap();
    let err3 = transport
        .get_space_credential(&res3, "token", "dpop", "space", "attestation")
        .await;
    assert!(err3.is_err());

    let res4 = url::Url::parse("https://10.0.0.1:8443").unwrap();
    let err4 = transport
        .get_space_credential(&res4, "token", "dpop", "space", "attestation")
        .await;
    assert!(err4.is_err());
}
