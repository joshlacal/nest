use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::Response,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use circle_appview::{
    config::{AppState, Config},
    create_router,
    auth::{DidDocument, PublicKeyJwk, VerificationMethod},
    db,
};

pub const CIRCLE_AUDIENCE: &str = "did:web:circles.catbird.blue#atproto_circle";
pub const ALICE_DID: &str = "did:plc:alice-test-circle";

struct TestSetup {
    app: axum::Router,
    signing_key: SigningKey,
    _state: AppState,
}

async fn setup_test(pool: PgPool) -> TestSetup {
    db::run_migrations(&pool).await.expect("Migrations must succeed");

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
    };

    let state = AppState::new(config, pool);

    // Generate P-256 key pair for test issuer
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let point = EncodedPoint::from(verifying_key);

    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    // Register DID document in resolver cache
    let did_doc = DidDocument {
        id: ALICE_DID.into(),
        verification_method: vec![VerificationMethod {
            id: format!("{}#atproto", ALICE_DID),
            r#type: "Multikey".into(),
            controller: ALICE_DID.into(),
            public_key_jwk: Some(PublicKeyJwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x,
                y: Some(y),
            }),
            public_key_multibase: None,
        }],
    };

    state.did_resolver.insert_cached(ALICE_DID.into(), did_doc);
    let app = create_router(state.clone());
    TestSetup {
        app,
        signing_key,
        _state: state,
    }
}

fn create_service_token(
    signing_key: &SigningKey,
    iss: &str,
    aud: &str,
    lxm: &str,
    jti: &str,
    exp_offset_secs: i64,
    kid: Option<&str>,
) -> String {
    let now = Utc::now().timestamp();
    let exp = now + exp_offset_secs;

    let header = json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": kid.unwrap_or("#atproto")
    });

    let claims = json!({
        "iss": iss,
        "aud": aud,
        "lxm": lxm,
        "jti": jti,
        "iat": now,
        "exp": exp
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let sig: Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

async fn request_feed(app: &axum::Router, token: &str) -> Response {
    let request = Request::builder()
        .uri("/xrpc/blue.catbird.circle.getFeed")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    app.clone().oneshot(request).await.unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_wrong_audience_and_replayed_jti(pool: PgPool) {
    let setup = setup_test(pool).await;

    // 1. Wrong audience -> 401 Unauthorized
    let wrong = create_service_token(
        &setup.signing_key,
        ALICE_DID,
        "did:web:wrong.example#svc",
        "blue.catbird.circle.getFeed",
        "jti-1",
        60,
        None,
    );
    assert_eq!(request_feed(&setup.app, &wrong).await.status(), StatusCode::UNAUTHORIZED);

    // 2. Correct token -> 200 OK
    let token = create_service_token(
        &setup.signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-2",
        60,
        None,
    );
    assert_eq!(request_feed(&setup.app, &token).await.status(), StatusCode::OK);

    // 3. Replay same token (same jti) -> 401 Unauthorized
    assert_eq!(request_feed(&setup.app, &token).await.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_expired_service_token(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Expired 10 seconds ago
    let expired = create_service_token(
        &setup.signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-expired",
        -10,
        None,
    );
    assert_eq!(request_feed(&setup.app, &expired).await.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_invalid_cryptographic_signature(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Sign with a different key
    let wrong_key = SigningKey::random(&mut OsRng);
    let token = create_service_token(
        &wrong_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-wrong-sig",
        60,
        None,
    );
    assert_eq!(request_feed(&setup.app, &token).await.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_wrong_lxm(pool: PgPool) {
    let setup = setup_test(pool).await;

    let token = create_service_token(
        &setup.signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.otherEndpoint",
        "jti-wrong-lxm",
        60,
        None,
    );
    assert_eq!(request_feed(&setup.app, &token).await.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn verifies_public_health_and_capabilities_unauthenticated(pool: PgPool) {
    let setup = setup_test(pool).await;

    let health_req = Request::builder()
        .uri("/_health")
        .body(Body::empty())
        .unwrap();
    let health_resp = setup.app.clone().oneshot(health_req).await.unwrap();
    assert_eq!(health_resp.status(), StatusCode::OK);

    let caps_req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.getCapabilities")
        .body(Body::empty())
        .unwrap();
    let caps_resp = setup.app.clone().oneshot(caps_req).await.unwrap();
    assert_eq!(caps_resp.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_missing_or_malformed_auth_header(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Missing Authorization header
    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.getFeed")
        .body(Body::empty())
        .unwrap();
    assert_eq!(setup.app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // Non-Bearer header
    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.getFeed")
        .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
        .body(Body::empty())
        .unwrap();
    assert_eq!(setup.app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn handles_did_web_resolution_and_ssrf_rejection(pool: PgPool) {
    let setup = setup_test(pool).await;

    // SSRF target should be rejected
    let ssrf_token = create_service_token(
        &setup.signing_key,
        "did:web:127.0.0.1",
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-ssrf",
        60,
        None,
    );
    assert_eq!(request_feed(&setup.app, &ssrf_token).await.status(), StatusCode::UNAUTHORIZED);
}
