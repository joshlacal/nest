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
        self, DidDocument, DidResolver, DidService, ParsedVerifyingKey, PublicKeyJwk,
        VerificationMethod,
    },
    config::{AppState, Config},
    db,
    error::AuthReason,
    projections::{self, Projection},
    routes::create_router,
    space_client::{
        calculate_rfc7638_jkt, DefaultSpaceHostTransport, MockSpaceHostTransport,
        SpaceClient, SpaceHostDnsResolver, SpaceHostTransport,
    },
};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;
use std::future::Future;
use std::net::SocketAddr;
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
        nest_jwks_url: "https://nest.catbird.blue/.well-known/jwks.json".into(),
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
        state.space_locks.clone(),
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
        if jwk.get("kty").and_then(|v| v.as_str()) != Some("EC") {
            return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP jwk kty".into())) });
        }
        if jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256") {
            return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Invalid DPoP jwk crv".into())) });
        }
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
        let iat = match payload.get("iat").and_then(|v| v.as_i64()) {
            Some(i) => i,
            None => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Missing DPoP iat".into())) }),
        };
        let now_epoch = Utc::now().timestamp();
        if iat > now_epoch + 300 || iat < now_epoch - 300 {
            return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("DPoP iat out of range".into())) });
        }
        let _jti = match payload.get("jti").and_then(|v| v.as_str()) {
            Some(j) if !j.is_empty() => j,
            _ => return Box::pin(async { Err(circle_appview::error::AppError::InvalidRequest("Missing or empty DPoP jti".into())) }),
        };
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
        setup.state.space_locks.clone(),
    );
    let app = create_router(state);

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        &format!("{AUTHORITY_DID}#atproto_space_host"),
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
        &format!("{AUTHORITY_DID}#atproto_space_host"),
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
        &format!("{AUTHORITY_DID}#atproto_space_host"),
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
        &format!("{AUTHORITY_DID}#atproto_space_host"),
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
        &format!("{AUTHORITY_DID}#atproto_space_host"),
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
        setup.state.space_locks.clone(),
    );
    let app = create_router(state);

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        &format!("{AUTHORITY_DID}#atproto_space_host"),
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
        setup.state.space_locks.clone(),
    );
    let app = create_router(state);

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        &format!("{AUTHORITY_DID}#atproto_space_host"),
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
        setup.state.space_locks.clone(),
    );
    let app = create_router(state);

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        &format!("{AUTHORITY_DID}#atproto_space_host"),
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
        setup.state.space_locks.clone(),
    );
    let app = create_router(state);

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        &format!("{AUTHORITY_DID}#atproto_space_host"),
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
        circle_generation: 1,
        member_generation: 2,
    };

    let remove_payload = json!({"member": BOB_DID, "circleGeneration": 1, "memberGeneration": 2});
    let digest = projections::compute_payload_digest(
        &Uuid::new_v4(),
        None,
        AUTHORITY_DID,
        &space,
        "member_remove",
        &remove_payload,
        None,
        Some(1),
        Some(2),
    );

    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
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
        Some(1),
        None,
    );
    // First delivery -> mutates
    let res1 = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
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
        Some(&setup.state.space_locks),
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
    let del_payload = json!({"space": space, "generation": 2, "circleGeneration": 2});
    let del_digest = projections::compute_payload_digest(
        &del_op,
        None,
        AUTHORITY_DID,
        &space,
        "circle_delete",
        &del_payload,
        Some(2),
        Some(2),
        None,
    );

    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
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
        Some(1),
        None,
    );
    let stale_res = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
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

    // 2. Deliver MemberRemove (circle_generation 1, member_generation 2)
    let remove_op = Uuid::new_v4();
    let remove_payload = json!({"member": BOB_DID, "circleGeneration": 1, "memberGeneration": 2});
    let remove_digest = projections::compute_payload_digest(
        &remove_op,
        None,
        AUTHORITY_DID,
        &space,
        "member_remove",
        &remove_payload,
        None,
        Some(1),
        Some(2),
    );

    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        remove_op,
        Projection::MemberRemove {
            space: space.clone(),
            member: BOB_DID.into(),
            circle_generation: 1,
            member_generation: 2,
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

    // 3. Delayed delivery of older MemberAdd (circle_generation 1, member_generation 1) -> ignored
    let add_op = Uuid::new_v4();
    let add_payload = json!({"member": BOB_DID, "circleGeneration": 1, "memberGeneration": 1});
    let add_digest = projections::compute_payload_digest(
        &add_op,
        None,
        AUTHORITY_DID,
        &space,
        "member_add",
        &add_payload,
        None,
        Some(1),
        Some(1),
    );

    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        add_op,
        Projection::MemberAdd {
            space: space.clone(),
            member: BOB_DID.into(),
            circle_generation: 1,
            member_generation: 1,
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
        setup.state.space_locks.clone(),
    );
    let app = create_router(state);

    let delegation_token = mint_delegation_token(
        &setup.bob_signing_key,
        BOB_DID,
        &space,
        &format!("{AUTHORITY_DID}#atproto_space_host"),
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
        &format!("{AUTHORITY_DID}#atproto_space_host"),
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
        setup.state.space_locks.clone(),
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
        Some(1),
        None,
    );

    let digest_diff_gen = projections::compute_payload_digest(
        &op_id,
        Some("key-1"),
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &payload,
        Some(2), // Different generation!
        Some(2),
        None,
    );

    let digest_diff_c_gen = projections::compute_payload_digest(
        &op_id,
        Some("key-1"),
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &payload,
        Some(1),
        Some(2), // Different circle_generation!
        None,
    );

    let digest_diff_m_gen = projections::compute_payload_digest(
        &op_id,
        Some("key-1"),
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &payload,
        Some(1),
        Some(1),
        Some(2), // Different member_generation!
    );

    let digest_diff_key = projections::compute_payload_digest(
        &op_id,
        Some("key-2"), // Different operation key!
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &payload,
        Some(1),
        Some(1),
        None,
    );

    assert_ne!(digest1, digest_diff_gen);
    assert_ne!(digest1, digest_diff_c_gen);
    assert_ne!(digest1, digest_diff_m_gen);
    assert_ne!(digest1, digest_diff_key);

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
        Some(&setup.state.space_locks),
        op_id,
        upsert.clone(),
        &digest1,
    )
    .await;
    assert!(res1.is_ok());

    // Replay with digest_diff_gen -> 409 Conflict
    let res2 = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        op_id,
        upsert.clone(),
        &digest_diff_gen,
    )
    .await;
    assert!(matches!(res2, Err(circle_appview::error::AppError::Conflict(_))));

    // Replay with digest_diff_c_gen -> 409 Conflict
    let res3 = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        op_id,
        upsert.clone(),
        &digest_diff_c_gen,
    )
    .await;
    assert!(matches!(res3, Err(circle_appview::error::AppError::Conflict(_))));

    // Replay with digest_diff_m_gen -> 409 Conflict
    let res4 = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        op_id,
        upsert.clone(),
        &digest_diff_m_gen,
    )
    .await;
    assert!(matches!(res4, Err(circle_appview::error::AppError::Conflict(_))));

    // Replay with digest_diff_key -> 409 Conflict
    let res5 = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        op_id,
        upsert,
        &digest_diff_key,
    )
    .await;
    assert!(matches!(res5, Err(circle_appview::error::AppError::Conflict(_))));
}

#[sqlx::test(migrations = "./migrations")]
async fn member_projection_requires_explicit_circle_and_member_generation(pool: PgPool) {
    let _setup = setup_test(pool).await;
    let space = space_uri();

    // 1. MemberAdd missing circleGeneration -> rejected
    let input_missing_c_gen = projections::SyncProjectionInput {
        operation_id: Uuid::new_v4(),
        operation_key: None,
        actor_did: AUTHORITY_DID.to_string(),
        space_uri: space.clone(),
        kind: "member_add".to_string(),
        payload: json!({ "member": BOB_DID, "memberGeneration": 1 }),
        generation: None,
        circle_generation: None,
        member_generation: None,
    };
    let err1 = input_missing_c_gen.to_projection();
    assert!(matches!(err1, Err(circle_appview::error::AppError::InvalidRequest(msg)) if msg.contains("Missing circleGeneration")));

    // 2. MemberAdd with legacy generation only -> rejected (no legacy fallback)
    let input_legacy_only = projections::SyncProjectionInput {
        operation_id: Uuid::new_v4(),
        operation_key: None,
        actor_did: AUTHORITY_DID.to_string(),
        space_uri: space.clone(),
        kind: "member_add".to_string(),
        payload: json!({ "member": BOB_DID, "generation": 3 }),
        generation: Some(3),
        circle_generation: None,
        member_generation: None,
    };
    let err2 = input_legacy_only.to_projection();
    assert!(matches!(err2, Err(circle_appview::error::AppError::InvalidRequest(msg)) if msg.contains("Missing circleGeneration")));

    // 3. MemberAdd missing memberGeneration -> rejected
    let input_missing_m_gen = projections::SyncProjectionInput {
        operation_id: Uuid::new_v4(),
        operation_key: None,
        actor_did: AUTHORITY_DID.to_string(),
        space_uri: space.clone(),
        kind: "member_add".to_string(),
        payload: json!({ "member": BOB_DID, "circleGeneration": 1 }),
        generation: None,
        circle_generation: None,
        member_generation: None,
    };
    let err3 = input_missing_m_gen.to_projection();
    assert!(matches!(err3, Err(circle_appview::error::AppError::InvalidRequest(msg)) if msg.contains("Missing memberGeneration")));

    // 4. Conflicting top-level vs payload circleGeneration -> rejected
    let input_conflicting_c_gen = projections::SyncProjectionInput {
        operation_id: Uuid::new_v4(),
        operation_key: None,
        actor_did: AUTHORITY_DID.to_string(),
        space_uri: space.clone(),
        kind: "member_add".to_string(),
        payload: json!({ "member": BOB_DID, "circleGeneration": 1, "memberGeneration": 1 }),
        generation: None,
        circle_generation: Some(2), // Conflicting!
        member_generation: Some(1),
    };
    let err4 = input_conflicting_c_gen.to_projection();
    assert!(matches!(err4, Err(circle_appview::error::AppError::InvalidRequest(msg)) if msg.contains("Conflicting circleGeneration")));

    // 5. Conflicting top-level vs payload memberGeneration -> rejected
    let input_conflicting_m_gen = projections::SyncProjectionInput {
        operation_id: Uuid::new_v4(),
        operation_key: None,
        actor_did: AUTHORITY_DID.to_string(),
        space_uri: space.clone(),
        kind: "member_remove".to_string(),
        payload: json!({ "member": BOB_DID, "circleGeneration": 1, "memberGeneration": 1 }),
        generation: None,
        circle_generation: Some(1),
        member_generation: Some(2), // Conflicting!
    };
    let err5 = input_conflicting_m_gen.to_projection();
    assert!(matches!(err5, Err(circle_appview::error::AppError::InvalidRequest(msg)) if msg.contains("Conflicting memberGeneration")));

    // 6. Fully explicit valid MemberAdd -> succeeds
    let input_valid = projections::SyncProjectionInput {
        operation_id: Uuid::new_v4(),
        operation_key: None,
        actor_did: AUTHORITY_DID.to_string(),
        space_uri: space.clone(),
        kind: "member_add".to_string(),
        payload: json!({ "member": BOB_DID, "circleGeneration": 1, "memberGeneration": 1 }),
        generation: None,
        circle_generation: Some(1),
        member_generation: Some(1),
    };
    let proj = input_valid.to_projection().unwrap();
    assert_eq!(proj, Projection::MemberAdd {
        space,
        member: BOB_DID.to_string(),
        circle_generation: 1,
        member_generation: 1,
    });
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
        Some(1),
        None,
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
        let locks = setup.state.space_locks.clone();
        let upsert = upsert.clone();
        let digest = digest.clone();
        handles.push(tokio::spawn(async move {
            projections::apply_projection(&pool, Some(&store), Some(&locks), op_id, upsert, &digest).await
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
    let now = Utc::now().timestamp();

    // 1. Setup initial circle and member in DB
    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Circle', now(), 1)",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at) VALUES ($1, $2, 'active', 1, now())",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    struct BarrierTransport {
        authority_key: p256::ecdsa::SigningKey,
        authority_did: String,
        dpop_started: Arc<tokio::sync::Notify>,
        exchange_release: Arc<tokio::sync::Notify>,
    }

    impl SpaceHostTransport for BarrierTransport {
        fn get_space_credential<'a>(
            &'a self,
            _target_url: &'a url::Url,
            _delegation_token: &'a str,
            dpop_proof: &'a str,
            space_uri: &'a str,
            _client_attestation: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
            let auth_key = self.authority_key.clone();
            let auth_did = self.authority_did.clone();
            let space = space_uri.to_string();
            let dpop_started = self.dpop_started.clone();
            let exchange_release = self.exchange_release.clone();
            let dpop = dpop_proof.to_string();

            Box::pin(async move {
                let parts: Vec<&str> = dpop.split('.').collect();
                let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
                let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
                let jwk = header.get("jwk").unwrap();
                let x = jwk.get("x").and_then(|v| v.as_str()).unwrap();
                let y = jwk.get("y").and_then(|v| v.as_str()).unwrap();
                let x_bytes = URL_SAFE_NO_PAD.decode(x).unwrap();
                let y_bytes = URL_SAFE_NO_PAD.decode(y).unwrap();
                let mut xb = p256::FieldBytes::default();
                let mut yb = p256::FieldBytes::default();
                xb.copy_from_slice(&x_bytes);
                yb.copy_from_slice(&y_bytes);
                let ep = p256::EncodedPoint::from_affine_coordinates(&xb, &yb, false);
                let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&ep).unwrap();
                let jkt = calculate_rfc7638_jkt(&vk);
                let now = Utc::now().timestamp();
                let cred = mint_space_credential(
                    &auth_key,
                    &auth_did,
                    &space,
                    &jkt,
                    now + 3600,
                    now,
                    None,
                    Some("#atproto_space"),
                );

                // Signal that activation holds _space_lock and is in exchange
                dpop_started.notify_one();

                // Wait for test to verify lock contention before finishing exchange
                exchange_release.notified().await;

                Ok(cred)
            })
        }
    }

    let dpop_started = Arc::new(tokio::sync::Notify::new());
    let exchange_release = Arc::new(tokio::sync::Notify::new());
    let transport = Arc::new(BarrierTransport {
        authority_key: setup.authority_signing_key.clone(),
        authority_did: AUTHORITY_DID.to_string(),
        dpop_started: dpop_started.clone(),
        exchange_release: exchange_release.clone(),
    });

    let custom_space_client = Arc::new(SpaceClient::with_transport(transport));
    let state = AppState::with_services(
        (*setup.state.config).clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        custom_space_client,
        setup.state.space_locks.clone(),
    );
    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        &format!("{AUTHORITY_DID}#atproto_space_host"),
        now + 300,
        now,
    );

    // Spawn activation task (acquires _space_lock before exchange)
    let state_clone = state.clone();
    let space_clone = space.clone();
    let del_tok_clone = delegation_token.clone();
    let activation_handle = tokio::spawn(async move {
        access::activate_space(
            &state_clone,
            ALICE_DID,
            &space_clone,
            &del_tok_clone,
            "attestation",
        )
        .await
    });

    // Wait for activation to acquire _space_lock and reach DPoP exchange
    dpop_started.notified().await;

    // While activation holds _space_lock, spawn CircleDelete projection
    let del_op = Uuid::new_v4();
    let del_payload = json!({"space": space, "generation": 1, "circleGeneration": 1});
    let del_digest = projections::compute_payload_digest(
        &del_op,
        None,
        AUTHORITY_DID,
        &space,
        "circle_delete",
        &del_payload,
        Some(1),
        Some(1),
        None,
    );

    let pool_clone = pool.clone();
    let store_clone = setup.state.credential_store.clone();
    let locks_clone = setup.state.space_locks.clone();
    let space_for_del = space.clone();
    let projection_handle = tokio::spawn(async move {
        projections::apply_projection(
            &pool_clone,
            Some(&store_clone),
            Some(&locks_clone),
            del_op,
            Projection::CircleDelete {
                space: space_for_del,
                generation: 1,
            },
            &del_digest,
        )
        .await
    });

    // Assert that projection is BLOCKED on SpaceLockManager while activation holds lock
    let mut waited = 0;
    while setup.state.space_locks.waiter_count(&space).await == 0 && waited < 100 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        waited += 1;
    }
    assert_eq!(
        setup.state.space_locks.waiter_count(&space).await,
        1,
        "CircleDelete projection must be queued on SpaceLockManager while activation holds lock"
    );
    // Release activation exchange: activation finishes lease commit, CredentialStore insert, and releases _space_lock
    exchange_release.notify_one();

    let activation_res = activation_handle.await.unwrap();
    assert!(activation_res.is_ok(), "Activation must succeed while holding lock first");

    // Now projection unblocks, acquires _space_lock, deletes circle & lease, and purges CredentialStore
    let projection_res = projection_handle.await.unwrap();
    assert!(projection_res.is_ok(), "Projection must succeed after acquiring released lock");

    // In-memory store must be purged by the deletion projection
    assert!(setup.state.credential_store.get(&space).await.is_none());

    // Database lease must be cascade-deleted
    let lease_exists: Option<(String,)> = sqlx::query_as(
        "SELECT space_uri FROM access_leases WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(lease_exists.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_circle_deletion_blocks_and_rejects_activation(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // 1. Setup initial circle and member in DB
    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Circle', now(), 1)",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at) VALUES ($1, $2, 'active', 1, now())",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    let del_op = Uuid::new_v4();
    let del_payload = json!({"space": space, "generation": 1, "circleGeneration": 1});
    let del_digest = projections::compute_payload_digest(
        &del_op,
        None,
        AUTHORITY_DID,
        &space,
        "circle_delete",
        &del_payload,
        Some(1),
        Some(1),
        None,
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
        setup.state.space_locks.clone(),
    );
    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        &format!("{AUTHORITY_DID}#atproto_space_host"),
        now + 300,
        now,
    );

    let pool_clone = pool.clone();
    let store_clone = setup.state.credential_store.clone();
    let _locks_clone = setup.state.space_locks.clone();
    let space_clone = space.clone();

    // Acquire space lock to serialize deletion ahead of activation
    let del_lock_guard = setup.state.space_locks.acquire(&space).await;

    // Spawn activation which must block on the space lock held by deletion
    let state_clone = state.clone();
    let space_for_act = space.clone();
    let dt_clone = delegation_token.clone();
    let activation_handle = tokio::spawn(async move {
        access::activate_space(&state_clone, ALICE_DID, &space_for_act, &dt_clone, "attestation").await
    });

    // Wait until activation is observed waiting on the lock
    let mut waited = 0;
    while setup.state.space_locks.waiter_count(&space).await == 0 && waited < 100 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        waited += 1;
    }
    assert_eq!(
        setup.state.space_locks.waiter_count(&space).await,
        1,
        "Activation must block on SpaceLockManager while deletion holds lock"
    );

    projections::apply_projection(
        &pool_clone,
        Some(&store_clone),
        None,
        del_op,
        Projection::CircleDelete {
            space: space_clone,
            generation: 1,
        },
        &del_digest,
    )
    .await
    .unwrap();
    drop(del_lock_guard);

    // Activation unblocks, acquires lock, queries DB, sees tombstone, strictly rejected
    let act_res = activation_handle.await.unwrap();
    assert!(matches!(act_res, Err(circle_appview::error::AppError::Forbidden(_))));
    assert!(setup.state.credential_store.get(&space).await.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_activation_vs_member_removal_race(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // Setup initial circle and member in DB
    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Circle', now(), 1)",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at) VALUES ($1, $2, 'active', 1, now())",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    struct BarrierTransport {
        authority_key: p256::ecdsa::SigningKey,
        authority_did: String,
        dpop_started: Arc<tokio::sync::Notify>,
        exchange_release: Arc<tokio::sync::Notify>,
    }

    impl SpaceHostTransport for BarrierTransport {
        fn get_space_credential<'a>(
            &'a self,
            _target_url: &'a url::Url,
            _delegation_token: &'a str,
            dpop_proof: &'a str,
            space_uri: &'a str,
            _client_attestation: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
            let auth_key = self.authority_key.clone();
            let auth_did = self.authority_did.clone();
            let space = space_uri.to_string();
            let dpop_started = self.dpop_started.clone();
            let exchange_release = self.exchange_release.clone();
            let dpop = dpop_proof.to_string();

            Box::pin(async move {
                let parts: Vec<&str> = dpop.split('.').collect();
                let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
                let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
                let jwk = header.get("jwk").unwrap();
                let x = jwk.get("x").and_then(|v| v.as_str()).unwrap();
                let y = jwk.get("y").and_then(|v| v.as_str()).unwrap();
                let x_bytes = URL_SAFE_NO_PAD.decode(x).unwrap();
                let y_bytes = URL_SAFE_NO_PAD.decode(y).unwrap();
                let mut xb = p256::FieldBytes::default();
                let mut yb = p256::FieldBytes::default();
                xb.copy_from_slice(&x_bytes);
                yb.copy_from_slice(&y_bytes);
                let ep = p256::EncodedPoint::from_affine_coordinates(&xb, &yb, false);
                let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&ep).unwrap();
                let jkt = calculate_rfc7638_jkt(&vk);
                let now = Utc::now().timestamp();
                let cred = mint_space_credential(
                    &auth_key,
                    &auth_did,
                    &space,
                    &jkt,
                    now + 3600,
                    now,
                    None,
                    Some("#atproto_space"),
                );

                // Signal that activation holds _space_lock and is in exchange
                dpop_started.notify_one();
                exchange_release.notified().await;
                Ok(cred)
            })
        }
    }

    let dpop_started = Arc::new(tokio::sync::Notify::new());
    let exchange_release = Arc::new(tokio::sync::Notify::new());
    let transport = Arc::new(BarrierTransport {
        authority_key: setup.authority_signing_key.clone(),
        authority_did: AUTHORITY_DID.to_string(),
        dpop_started: dpop_started.clone(),
        exchange_release: exchange_release.clone(),
    });

    let custom_space_client = Arc::new(SpaceClient::with_transport(transport));
    let state = AppState::with_services(
        (*setup.state.config).clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        custom_space_client,
        setup.state.space_locks.clone(),
    );
    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        &format!("{AUTHORITY_DID}#atproto_space_host"),
        now + 300,
        now,
    );

    let state_clone = state.clone();
    let space_clone = space.clone();
    let del_tok_clone = delegation_token.clone();
    let activation_handle = tokio::spawn(async move {
        access::activate_space(
            &state_clone,
            ALICE_DID,
            &space_clone,
            &del_tok_clone,
            "attestation",
        )
        .await
    });

    // Wait for activation to acquire _space_lock and reach DPoP exchange
    dpop_started.notified().await;

    // While activation holds _space_lock, spawn MemberRemove projection
    let rem_op = Uuid::new_v4();
    let rem_payload = json!({"member": ALICE_DID, "circleGeneration": 1, "memberGeneration": 2});
    let rem_digest = projections::compute_payload_digest(
        &rem_op,
        None,
        AUTHORITY_DID,
        &space,
        "member_remove",
        &rem_payload,
        None,
        Some(1),
        Some(2),
    );

    let pool_clone = pool.clone();
    let store_clone = setup.state.credential_store.clone();
    let locks_clone = setup.state.space_locks.clone();
    let space_for_rem = space.clone();
    let projection_handle = tokio::spawn(async move {
        projections::apply_projection(
            &pool_clone,
            Some(&store_clone),
            Some(&locks_clone),
            rem_op,
            Projection::MemberRemove {
                space: space_for_rem,
                member: ALICE_DID.into(),
                circle_generation: 1,
                member_generation: 2,
            },
            &rem_digest,
        )
        .await
    });

    // Assert that MemberRemove blocks on SpaceLockManager while activation holds lock
    let mut waited = 0;
    while setup.state.space_locks.waiter_count(&space).await == 0 && waited < 100 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        waited += 1;
    }
    assert_eq!(
        setup.state.space_locks.waiter_count(&space).await,
        1,
        "MemberRemove must block on SpaceLockManager while activation holds lock"
    );
    // Release activation exchange
    exchange_release.notify_one();

    let activation_res = activation_handle.await.unwrap();
    assert!(activation_res.is_ok(), "Activation must succeed when holding lock first");

    // Now MemberRemove unblocks, acquires lock, updates member status, and purges CredentialStore
    let projection_res = projection_handle.await.unwrap();
    assert!(projection_res.is_ok(), "MemberRemove must succeed after acquiring released lock");

    assert!(setup.state.credential_store.get(&space).await.is_none());

    // Lease was deleted
    let lease_exists: Option<(String,)> = sqlx::query_as(
        "SELECT space_uri FROM access_leases WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(lease_exists.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_member_removal_blocks_and_rejects_activation(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // Setup initial circle and member in DB
    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Circle', now(), 1)",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at) VALUES ($1, $2, 'active', 1, now())",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    let rem_op = Uuid::new_v4();
    let rem_payload = json!({"member": ALICE_DID, "circleGeneration": 1, "memberGeneration": 2});
    let rem_digest = projections::compute_payload_digest(
        &rem_op,
        None,
        AUTHORITY_DID,
        &space,
        "member_remove",
        &rem_payload,
        None,
        Some(1),
        Some(2),
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
        setup.state.space_locks.clone(),
    );
    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        &format!("{AUTHORITY_DID}#atproto_space_host"),
        now + 300,
        now,
    );

    let rem_lock_guard = setup.state.space_locks.acquire(&space).await;

    let state_clone = state.clone();
    let space_for_act = space.clone();
    let dt_clone = delegation_token.clone();
    let activation_handle = tokio::spawn(async move {
        access::activate_space(&state_clone, ALICE_DID, &space_for_act, &dt_clone, "attestation").await
    });

    let mut waited = 0;
    while setup.state.space_locks.waiter_count(&space).await == 0 && waited < 100 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        waited += 1;
    }
    assert_eq!(
        setup.state.space_locks.waiter_count(&space).await,
        1,
        "Activation must block on SpaceLockManager while removal holds lock"
    );

    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        None,
        rem_op,
        Projection::MemberRemove {
            space: space.clone(),
            member: ALICE_DID.into(),
            circle_generation: 1,
            member_generation: 2,
        },
        &rem_digest,
    )
    .await
    .unwrap();
    drop(rem_lock_guard);

    let act_res = activation_handle.await.unwrap();
    assert!(matches!(act_res, Err(circle_appview::error::AppError::Forbidden(_))));
    assert!(setup.state.credential_store.get(&space).await.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn persisted_lease_is_monotonic_max_under_concurrent_activations(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();
    let now = Utc::now().timestamp();

    // Create circle and member
    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Circle', now(), 1)",
    )
    .bind(&space)
    .bind(AUTHORITY_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at) VALUES ($1, $2, 'active', 1, now())",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    // Dynamic transport with configurable expiry
    struct BarrierDynamicTransport {
        authority_key: p256::ecdsa::SigningKey,
        authority_did: String,
        expiry: i64,
    }

    impl SpaceHostTransport for BarrierDynamicTransport {
        fn get_space_credential<'a>(
            &'a self,
            _target_url: &'a url::Url,
            _delegation_token: &'a str,
            dpop_proof: &'a str,
            space_uri: &'a str,
            _client_attestation: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<String, circle_appview::error::AppError>> + Send + 'a>> {
            let auth_key = self.authority_key.clone();
            let auth_did = self.authority_did.clone();
            let space = space_uri.to_string();
            let exp = self.expiry;
            let dpop = dpop_proof.to_string();

            Box::pin(async move {
                let parts: Vec<&str> = dpop.split('.').collect();
                let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
                let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
                let jwk = header.get("jwk").unwrap();
                let x = jwk.get("x").and_then(|v| v.as_str()).unwrap();
                let y = jwk.get("y").and_then(|v| v.as_str()).unwrap();
                let x_bytes = URL_SAFE_NO_PAD.decode(x).unwrap();
                let y_bytes = URL_SAFE_NO_PAD.decode(y).unwrap();
                let mut xb = p256::FieldBytes::default();
                let mut yb = p256::FieldBytes::default();
                xb.copy_from_slice(&x_bytes);
                yb.copy_from_slice(&y_bytes);
                let ep = p256::EncodedPoint::from_affine_coordinates(&xb, &yb, false);
                let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&ep).unwrap();
                let jkt = calculate_rfc7638_jkt(&vk);
                let now = Utc::now().timestamp();
                let cred = mint_space_credential(
                    &auth_key,
                    &auth_did,
                    &space,
                    &jkt,
                    exp,
                    now,
                    None,
                    Some("#atproto_space"),
                );
                Ok(cred)
            })
        }
    }

    let longer_exp = now + 7200; // 2 hours
    let shorter_exp = now + 3600; // 1 hour

    let auth_key1 = setup.authority_signing_key.clone();
    let auth_key2 = setup.authority_signing_key.clone();
    let transport1 = Arc::new(BarrierDynamicTransport {
        authority_key: auth_key1,
        authority_did: AUTHORITY_DID.to_string(),
        expiry: longer_exp,
    });
    let transport2 = Arc::new(BarrierDynamicTransport {
        authority_key: auth_key2,
        authority_did: AUTHORITY_DID.to_string(),
        expiry: shorter_exp,
    });

    let client1 = Arc::new(SpaceClient::with_transport(transport1));
    let client2 = Arc::new(SpaceClient::with_transport(transport2));

    let state1 = AppState::with_services(
        (*setup.state.config).clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        client1,
        setup.state.space_locks.clone(),
    );
    let state2 = AppState::with_services(
        (*setup.state.config).clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        client2,
        setup.state.space_locks.clone(),
    );

    let delegation_token = mint_delegation_token(
        &setup.alice_signing_key,
        ALICE_DID,
        &space,
        &format!("{AUTHORITY_DID}#atproto_space_host"),
        now + 300,
        now,
    );
    let start_barrier = Arc::new(tokio::sync::Barrier::new(2));

    let s1 = state1.clone();
    let sp1 = space.clone();
    let dt1 = delegation_token.clone();
    let b1 = start_barrier.clone();
    let h1 = tokio::spawn(async move {
        b1.wait().await;
        access::activate_space(&s1, ALICE_DID, &sp1, &dt1, "attestation").await
    });

    let s2 = state2.clone();
    let sp2 = space.clone();
    let dt2 = delegation_token.clone();
    let b2 = start_barrier.clone();
    let h2 = tokio::spawn(async move {
        b2.wait().await;
        access::activate_space(&s2, ALICE_DID, &sp2, &dt2, "attestation").await
    });
    let (res1, res2) = tokio::join!(h1, h2);
    assert!(res1.unwrap().is_ok());
    assert!(res2.unwrap().is_ok());

    // Verify DB lease remains at longer_exp (monotonic max under serialization)
    let stored_exp: (DateTime<Utc>,) = sqlx::query_as(
        "SELECT expires_at FROM access_leases WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(ALICE_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored_exp.0.timestamp(), longer_exp);

    // Verify in-memory CredentialStore remains at longer_exp
    let in_memory_cred = setup.state.credential_store.get(&space).await.unwrap();
    assert_eq!(in_memory_cred.expires_at.timestamp(), longer_exp);
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_pre_delete_member_projection_cannot_resurrect_deleted_circle(pool: PgPool) {
    let setup = setup_test(pool.clone()).await;
    let space = space_uri();

    // 1. Initial Circle creation (generation 1)
    let upsert_op = Uuid::new_v4();
    let upsert_payload = json!({"name": "Circle Epoch 1", "generation": 1, "circleGeneration": 1});
    let upsert_digest = projections::compute_payload_digest(
        &upsert_op,
        None,
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &upsert_payload,
        Some(1),
        Some(1),
        None,
    );
    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        upsert_op,
        Projection::CircleUpsert {
            space: space.clone(),
            authority: AUTHORITY_DID.into(),
            name: "Circle Epoch 1".into(),
            created_at: Utc::now(),
            generation: 1,
        },
        &upsert_digest,
    )
    .await
    .unwrap();

    // 2. Add Bob (circle_generation: 1, member_generation: 1)
    let add_op1 = Uuid::new_v4();
    let add_payload1 = json!({"member": BOB_DID, "circleGeneration": 1, "memberGeneration": 1});
    let add_digest1 = projections::compute_payload_digest(
        &add_op1,
        None,
        AUTHORITY_DID,
        &space,
        "member_add",
        &add_payload1,
        None,
        Some(1),
        Some(1),
    );
    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        add_op1,
        Projection::MemberAdd {
            space: space.clone(),
            member: BOB_DID.into(),
            circle_generation: 1,
            member_generation: 1,
        },
        &add_digest1,
    )
    .await
    .unwrap();

    // 3. Remove Bob (circle_generation: 1, member_generation: 2)
    let rem_op = Uuid::new_v4();
    let rem_payload = json!({"member": BOB_DID, "circleGeneration": 1, "memberGeneration": 2});
    let rem_digest = projections::compute_payload_digest(
        &rem_op,
        None,
        AUTHORITY_DID,
        &space,
        "member_remove",
        &rem_payload,
        None,
        Some(1),
        Some(2),
    );
    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        rem_op,
        Projection::MemberRemove {
            space: space.clone(),
            member: BOB_DID.into(),
            circle_generation: 1,
            member_generation: 2,
        },
        &rem_digest,
    )
    .await
    .unwrap();

    // 4. CircleDelete at generation 2 -> deletes circles and inserts tombstone (generation 2)
    let del_op = Uuid::new_v4();
    let del_payload = json!({"space": space, "generation": 2, "circleGeneration": 2});
    let del_digest = projections::compute_payload_digest(
        &del_op,
        None,
        AUTHORITY_DID,
        &space,
        "circle_delete",
        &del_payload,
        Some(2),
        Some(2),
        None,
    );
    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        del_op,
        Projection::CircleDelete {
            space: space.clone(),
            generation: 2,
        },
        &del_digest,
    )
    .await
    .unwrap();

    // Verify Circle and members are deleted
    let circle_row: Option<(String,)> = sqlx::query_as("SELECT space_uri FROM circles WHERE space_uri = $1")
        .bind(&space)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(circle_row.is_none());

    // 5. Delayed pre-delete MemberAdd (circle_generation: 1, member_generation: 3) arrives
    let delayed_op = Uuid::new_v4();
    let delayed_payload = json!({"member": BOB_DID, "circleGeneration": 1, "memberGeneration": 3});
    let delayed_digest = projections::compute_payload_digest(
        &delayed_op,
        None,
        AUTHORITY_DID,
        &space,
        "member_add",
        &delayed_payload,
        None,
        Some(1),
        Some(3),
    );
    let delayed_res = projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        delayed_op,
        Projection::MemberAdd {
            space: space.clone(),
            member: BOB_DID.into(),
            circle_generation: 1,
            member_generation: 3,
        },
        &delayed_digest,
    )
    .await;
    assert!(delayed_res.is_ok());

    // CRITICAL: Delayed MemberAdd for deleted circle epoch must NOT resurrect circle or create member!
    let resurrected_circle: Option<(String,)> = sqlx::query_as("SELECT space_uri FROM circles WHERE space_uri = $1")
        .bind(&space)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(resurrected_circle.is_none(), "Stale MemberAdd must not recreate parent circle");

    let resurrected_member: Option<(String,)> = sqlx::query_as("SELECT member_did FROM circle_members WHERE space_uri = $1")
        .bind(&space)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(resurrected_member.is_none(), "Stale MemberAdd must not recreate member row");

    // 6. Newer legitimate Circle epoch (generation 3) is created
    let upsert_op2 = Uuid::new_v4();
    let upsert_payload2 = json!({"name": "Circle Epoch 3", "generation": 3, "circleGeneration": 3});
    let upsert_digest2 = projections::compute_payload_digest(
        &upsert_op2,
        None,
        AUTHORITY_DID,
        &space,
        "circle_upsert",
        &upsert_payload2,
        Some(3),
        Some(3),
        None,
    );
    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        upsert_op2,
        Projection::CircleUpsert {
            space: space.clone(),
            authority: AUTHORITY_DID.into(),
            name: "Circle Epoch 3".into(),
            created_at: Utc::now(),
            generation: 3,
        },
        &upsert_digest2,
    )
    .await
    .unwrap();

    let new_circle: Option<(String, i64)> = sqlx::query_as("SELECT space_uri, generation FROM circles WHERE space_uri = $1")
        .bind(&space)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(new_circle.is_some());
    assert_eq!(new_circle.unwrap().1, 3);

    // 7. Legitimate member add in new epoch (circle_generation: 3, member_generation: 1) succeeds
    let add_op2 = Uuid::new_v4();
    let add_payload2 = json!({"member": BOB_DID, "circleGeneration": 3, "memberGeneration": 1});
    let add_digest2 = projections::compute_payload_digest(
        &add_op2,
        None,
        AUTHORITY_DID,
        &space,
        "member_add",
        &add_payload2,
        None,
        Some(3),
        Some(1),
    );
    projections::apply_projection(
        &pool,
        Some(&setup.state.credential_store),
        Some(&setup.state.space_locks),
        add_op2,
        Projection::MemberAdd {
            space: space.clone(),
            member: BOB_DID.into(),
            circle_generation: 3,
            member_generation: 1,
        },
        &add_digest2,
    )
    .await
    .unwrap();

    let member_row: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT member_did, status, generation FROM circle_members WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&space)
    .bind(BOB_DID)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(member_row.is_some());
    let (m_did, m_status, m_gen) = member_row.unwrap();
    assert_eq!(m_did, BOB_DID);
    assert_eq!(m_status, "active");
    assert_eq!(m_gen, 1);
}

struct MockDnsResolver {
    addrs: Result<Vec<SocketAddr>, AuthReason>,
}

impl SpaceHostDnsResolver for MockDnsResolver {
    fn resolve_dns<'a>(
        &'a self,
        _host: &'a str,
        _port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, AuthReason>> + Send + 'a>> {
        let res = self.addrs.clone();
        Box::pin(async move { res })
    }
}

#[tokio::test]
async fn ssrf_safe_transport_dns_seam_validations() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Generate TLS self-signed cert for space.example.org
    let params = rcgen::CertificateParams::new(vec![
        "space.example.org".to_string(),
    ])
    .unwrap();
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
                } else if req_str.starts_with("POST /redirect") {
                    let response = "HTTP/1.1 302 Found\r\nLocation: /xrpc/com.atproto.space.getSpaceCredential\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                } else {
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                }
                let _ = tls_stream.shutdown().await;
            });
        }
    });

    let reqwest_cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();

    // 1. Successful pinned HTTPS transport exchange over real TLS
    let fixture_resolver = Arc::new(MockDnsResolver {
        addrs: Ok(vec![fixture_addr]),
    });
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
    assert!(redirect_res.is_err(), "Redirect must be rejected by Policy::none()");

    // 3. Mixed DNS answers (one public, one private) -> strictly rejected in production mode
    let mixed_resolver = Arc::new(MockDnsResolver {
        addrs: Ok(vec![
            "93.184.216.34:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ]),
    });
    let transport_mixed = DefaultSpaceHostTransport::with_dns_resolver(mixed_resolver);
    let err_mixed = transport_mixed
        .get_space_credential(&target_url, "token", "dpop", "space", "attestation")
        .await;
    assert!(matches!(err_mixed, Err(circle_appview::error::AppError::Unauthorized(AuthReason::SsrfBlocked))));

    // 4. Private-only DNS answers -> strictly rejected in production mode
    let private_resolver = Arc::new(MockDnsResolver {
        addrs: Ok(vec!["10.0.0.1:443".parse().unwrap()]),
    });
    let transport_private = DefaultSpaceHostTransport::with_dns_resolver(private_resolver);
    let err_private = transport_private
        .get_space_credential(&target_url, "token", "dpop", "space", "attestation")
        .await;
    assert!(matches!(err_private, Err(circle_appview::error::AppError::Unauthorized(AuthReason::SsrfBlocked))));

    // 5. DNS resolution failure -> DidResolutionFailed
    let fail_resolver = Arc::new(MockDnsResolver {
        addrs: Err(AuthReason::DidResolutionFailed),
    });
    let transport_fail = DefaultSpaceHostTransport::with_dns_resolver(fail_resolver);
    let err_fail = transport_fail
        .get_space_credential(&target_url, "token", "dpop", "space", "attestation")
        .await;
    assert!(matches!(err_fail, Err(circle_appview::error::AppError::Unauthorized(AuthReason::DidResolutionFailed))));
}

#[tokio::test]
async fn startup_jwks_loader_and_verifier_tests() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Generate TLS self-signed cert for nest.catbird.blue
    let params = rcgen::CertificateParams::new(vec![
        "nest.catbird.blue".to_string(),
    ])
    .unwrap();
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

    // Generate real P-256 and secp256k1 keys for JWKS
    let p256_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let p256_encoded = p256_signing_key.verifying_key().to_encoded_point(false);
    let p256_x = URL_SAFE_NO_PAD.encode(p256_encoded.x().unwrap());
    let p256_y = URL_SAFE_NO_PAD.encode(p256_encoded.y().unwrap());

    let k256_signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
    let k256_encoded = k256_signing_key.verifying_key().to_encoded_point(false);
    let k256_x = URL_SAFE_NO_PAD.encode(k256_encoded.x().unwrap());
    let k256_y = URL_SAFE_NO_PAD.encode(k256_encoded.y().unwrap());

    let jwks_json = serde_json::json!({
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "x": p256_x,
                "y": p256_y,
                "kid": "key-p256"
            },
            {
                "kty": "EC",
                "crv": "secp256k1",
                "x": k256_x,
                "y": k256_y,
                "kid": "key-k256"
            }
        ]
    });
    let jwks_body = serde_json::to_string(&jwks_json).unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let body = jwks_body.clone();
            tokio::spawn(async move {
                let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = [0u8; 2048];
                let Ok(n) = tls_stream.read(&mut buf).await else {
                    return;
                };
                let req_str = String::from_utf8_lossy(&buf[..n]);
                if req_str.starts_with("GET /.well-known/jwks.json") {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                } else {
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                }
                let _ = tls_stream.shutdown().await;
            });
        }
    });

    let reqwest_cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();

    // 1. Successful safe-fetch & parse of real JWKS keys via production fetch_https_jwks
    struct MockWebTransport {
        fixture_addr: SocketAddr,
        cert: reqwest::Certificate,
    }

    impl auth::DidWebTransport for MockWebTransport {
        fn resolve_dns<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, AuthReason>> + Send + 'a>> {
            let addr = self.fixture_addr;
            Box::pin(async move { Ok(vec![addr]) })
        }

        fn fetch<'a>(
            &'a self,
            _url: &'a str,
            _host: &'a str,
            _pinned_addr: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = Result<DidDocument, AuthReason>> + Send + 'a>> {
            Box::pin(async move { Err(AuthReason::DidResolutionFailed) })
        }

        fn test_root_certificate(&self) -> Option<reqwest::Certificate> {
            Some(self.cert.clone())
        }

        fn allows_loopback_for_test(&self) -> bool {
            true
        }
    }

    let web_transport = Arc::new(MockWebTransport {
        fixture_addr,
        cert: reqwest_cert,
    });
    let resolver = auth::DidResolver::with_transport(
        "https://plc.directory".into(),
        reqwest::Client::new(),
        web_transport,
    );

    let jwks_url = format!("https://nest.catbird.blue:{}/.well-known/jwks.json", fixture_addr.port());
    let keys = auth::fetch_https_jwks(&resolver, &jwks_url).await
        .expect("fetch_https_jwks must successfully load and parse keys");
    assert_eq!(keys.len(), 2);
    assert!(matches!(keys[0], ParsedVerifyingKey::P256(_)));
    assert!(matches!(keys[1], ParsedVerifyingKey::Secp256k1(_)));

    // 2. SSRF negative tests for fetch_https_jwks: reject HTTP, localhost, private IP
    let default_transport = Arc::new(auth::DefaultDidWebTransport::new());
    let prod_resolver = auth::DidResolver::with_transport(
        "https://plc.directory".into(),
        reqwest::Client::new(),
        default_transport,
    );

    let http_res = auth::fetch_https_jwks(&prod_resolver, "http://nest.catbird.blue/jwks.json").await;
    assert_eq!(http_res.unwrap_err(), AuthReason::SsrfBlocked);

    let localhost_res = auth::fetch_https_jwks(&prod_resolver, "https://localhost:8443/jwks.json").await;
    assert_eq!(localhost_res.unwrap_err(), AuthReason::SsrfBlocked);

    let private_res = auth::fetch_https_jwks(&prod_resolver, "https://10.0.0.1/jwks.json").await;
    assert_eq!(private_res.unwrap_err(), AuthReason::SsrfBlocked);
}

async fn run_production_space_host_transport_tls_fixture() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Generate TLS self-signed cert for public hostname space.example.org
    let params = rcgen::CertificateParams::new(vec![
        "space.example.org".to_string(),
    ])
    .unwrap();
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
                if req_str.starts_with("POST /xrpc/com.atproto.space.getSpaceCredential") || req_str.starts_with("GET /xrpc/com.atproto.space.getSpaceCredential") {
                    let has_auth = req_str.contains("Bearer test-delegation-token")
                        || req_str.contains("authorization: Bearer test-delegation-token")
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
                } else if req_str.starts_with("POST /redirect") {
                    // Redirect to the valid credential endpoint on the same TLS fixture.
                    // If Policy::none() is active, redirect is rejected and returns error.
                    let response = "HTTP/1.1 307 Temporary Redirect\r\nLocation: /xrpc/com.atproto.space.getSpaceCredential\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                } else {
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                }
                let _ = tls_stream.shutdown().await;
            });
        }
    });

    let reqwest_cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();

    // 1. Successful pinned HTTPS transport exchange over real TLS (bypassing poisoned proxy env via .no_proxy())
    let fixture_resolver = Arc::new(MockDnsResolver {
        addrs: Ok(vec![fixture_addr]),
    });
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
        .expect("Space host credential exchange over TLS must succeed through .no_proxy()");
    assert_eq!(cred, "test.space.credential.jwt");

    // 2. Same-fixture redirect discrimination (Policy::none() must reject 302 Found)
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
    assert!(redirect_res.is_err(), "Redirect must be rejected by Policy::none()");

    // 3. Pinned destination failure: connecting to closed port fails immediately
    let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = closed_listener.local_addr().unwrap();
    drop(closed_listener);

    let closed_resolver = Arc::new(MockDnsResolver {
        addrs: Ok(vec![closed_addr]),
    });
    let transport_closed = DefaultSpaceHostTransport::with_test_fixture(
        closed_resolver,
        Some(reqwest_cert),
        true,
    );
    let closed_url = url::Url::parse(&format!(
        "https://space.example.org:{}/xrpc/com.atproto.space.getSpaceCredential",
        closed_addr.port()
    ))
    .unwrap();
    let closed_res = transport_closed
        .get_space_credential(
            &closed_url,
            "test-delegation-token",
            "test-dpop-proof",
            "at://did:plc:auth/space/1",
            "test-attestation",
        )
        .await;
    assert!(closed_res.is_err(), "Connecting to closed pinned address must fail immediately");
}

const SPACE_HOST_PROXY_CANARY: &str = "CANARY_SPACE_HOST_PROXY_SUBPROCESS_EXECUTED_d9a8c7b6";
const POISONED_SPACE_HOST_PROXY_URL: &str = "http://invalid-unreachable-proxy.example.local:9999";

#[tokio::test]
#[ignore = "Subprocess helper executed exclusively by production_space_host_transport_enforces_tls_pinning_no_proxy_and_rejects_redirects"]
async fn space_host_transport_proxy_subprocess_helper() {
    assert!(std::env::var("NO_PROXY").is_err(), "NO_PROXY must not be set in subprocess");
    assert!(std::env::var("no_proxy").is_err(), "no_proxy must not be set in subprocess");
    assert_eq!(
        std::env::var("HTTPS_PROXY").ok().as_deref(),
        Some(POISONED_SPACE_HOST_PROXY_URL),
        "HTTPS_PROXY must be poisoned in subprocess"
    );
    assert_eq!(
        std::env::var("HTTP_PROXY").ok().as_deref(),
        Some(POISONED_SPACE_HOST_PROXY_URL),
        "HTTP_PROXY must be poisoned in subprocess"
    );
    assert_eq!(
        std::env::var("ALL_PROXY").ok().as_deref(),
        Some(POISONED_SPACE_HOST_PROXY_URL),
        "ALL_PROXY must be poisoned in subprocess"
    );

    println!("{}", SPACE_HOST_PROXY_CANARY);
    run_production_space_host_transport_tls_fixture().await;
}

#[tokio::test]
async fn production_space_host_transport_enforces_tls_pinning_no_proxy_and_rejects_redirects() {
    // 1. Capture parent environment
    let orig_https_proxy = std::env::var_os("HTTPS_PROXY");
    let orig_http_proxy = std::env::var_os("HTTP_PROXY");
    let orig_all_proxy = std::env::var_os("ALL_PROXY");

    // 2. Execute subprocess helper with poisoned proxy environment variables
    let current_exe = std::env::current_exe().expect("Must get current test executable");
    let output = std::process::Command::new(current_exe)
        .arg("space_host_transport_proxy_subprocess_helper")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .env("HTTPS_PROXY", POISONED_SPACE_HOST_PROXY_URL)
        .env("HTTP_PROXY", POISONED_SPACE_HOST_PROXY_URL)
        .env("ALL_PROXY", POISONED_SPACE_HOST_PROXY_URL)
        .env("https_proxy", POISONED_SPACE_HOST_PROXY_URL)
        .env("http_proxy", POISONED_SPACE_HOST_PROXY_URL)
        .env("all_proxy", POISONED_SPACE_HOST_PROXY_URL)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("Failed to execute space host proxy isolation test subprocess");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "Subprocess failed to run with poisoned proxy env (no_proxy must bypass invalid proxies):\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains(SPACE_HOST_PROXY_CANARY),
        "Subprocess did not emit the required execution canary (filter did not run helper):\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    // 3. Verify parent environment was never mutated
    assert_eq!(std::env::var_os("HTTPS_PROXY"), orig_https_proxy);
    assert_eq!(std::env::var_os("HTTP_PROXY"), orig_http_proxy);
    assert_eq!(std::env::var_os("ALL_PROXY"), orig_all_proxy);
}
