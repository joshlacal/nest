use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    response::Response,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_atproto::generated::blue_catbird::circle::get_capabilities::GetCapabilitiesOutput;
use chrono::Utc;
use circle_appview::{
    auth::{DidDocument, PublicKeyJwk, VerificationMethod},
    config::{AppState, Config},
    db,
    routes::create_router,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

pub const CIRCLE_AUDIENCE: &str = "did:web:circles.catbird.blue#atproto_circle";
pub const ALICE_DID: &str = "did:plc:alice-test-circle";

struct TestSetup {
    app: axum::Router,
    p256_signing_key: p256::ecdsa::SigningKey,
    secp_signing_key: k256::ecdsa::SigningKey,
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

    let state = AppState::new(config, pool.clone());

    // Generate P-256 key pair
    let p256_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let p256_verifying_key = p256_signing_key.verifying_key();
    let point = EncodedPoint::from(p256_verifying_key);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    // Generate secp256k1 key pair
    let secp_signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);

    // Multikey P-256 (0x1200 prefix -> varint [0x80, 0x24])
    let p256_sec1 = p256_verifying_key.to_encoded_point(true);
    let mut p256_multikey_bytes = vec![0x80, 0x24];
    p256_multikey_bytes.extend_from_slice(p256_sec1.as_bytes());
    let p256_multikey =
        multibase::encode(multibase::Base::Base58Btc, &p256_multikey_bytes);

    // Register DID document with both Multikey and JWK
    let did_doc = DidDocument {
        id: ALICE_DID.into(),
        verification_method: vec![
            VerificationMethod {
                id: format!("{}#atproto", ALICE_DID),
                r#type: "Multikey".into(),
                controller: ALICE_DID.into(),
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x,
                    y: Some(y),
                }),
                public_key_multibase: Some(p256_multikey),
            },
        ],
    };

    state.did_resolver.insert_cached(ALICE_DID.into(), did_doc);
    let app = create_router(state.clone());
    TestSetup {
        app,
        p256_signing_key,
        secp_signing_key,
        state,
        pool,
    }
}

#[derive(Default)]
struct TokenOptions<'a> {
    typ: Option<&'a str>,
    alg: Option<&'a str>,
    kid: Option<&'a str>,
    iss: Option<&'a str>,
    aud: Option<&'a str>,
    lxm: Option<&'a str>,
    jti: Option<&'a str>,
    iat: Option<i64>,
    exp: Option<i64>,
}

fn create_custom_service_token(
    signing_key: &p256::ecdsa::SigningKey,
    opts: TokenOptions,
) -> String {
    let now = Utc::now().timestamp();
    let header = json!({
        "typ": opts.typ.unwrap_or("JWT"),
        "alg": opts.alg.unwrap_or("ES256"),
        "kid": opts.kid.unwrap_or("#atproto"),
    });

    let mut claims = json!({
        "iss": opts.iss.unwrap_or(ALICE_DID),
        "aud": opts.aud.unwrap_or(CIRCLE_AUDIENCE),
        "lxm": opts.lxm.unwrap_or("blue.catbird.circle.getFeed"),
        "jti": opts.jti.unwrap_or("test-jti"),
        "exp": opts.exp.unwrap_or(now + 60),
    });

    if let Some(iat) = opts.iat {
        claims.as_object_mut().unwrap().insert("iat".into(), json!(iat));
    } else {
        claims.as_object_mut().unwrap().insert("iat".into(), json!(now));
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let sig: Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

fn create_service_token(
    signing_key: &p256::ecdsa::SigningKey,
    iss: &str,
    aud: &str,
    lxm: &str,
    jti: &str,
    exp_offset_secs: i64,
    kid: Option<&str>,
) -> String {
    let now = Utc::now().timestamp();
    create_custom_service_token(
        signing_key,
        TokenOptions {
            iss: Some(iss),
            aud: Some(aud),
            lxm: Some(lxm),
            jti: Some(jti),
            iat: Some(now),
            exp: Some(now + exp_offset_secs),
            kid,
            ..Default::default()
        },
    )
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

    // 1. Wrong audience
    let wrong = create_service_token(
        &setup.p256_signing_key,
        ALICE_DID,
        "did:web:wrong.example#svc",
        "blue.catbird.circle.getFeed",
        "jti-wrong-aud",
        60,
        None,
    );
    assert_eq!(
        request_feed(&setup.app, &wrong).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 2. Fresh token succeeds
    let token = create_service_token(
        &setup.p256_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-1",
        60,
        None,
    );
    assert_eq!(
        request_feed(&setup.app, &token).await.status(),
        StatusCode::OK
    );

    // 3. Replay of same token / JTI fails
    assert_eq!(
        request_feed(&setup.app, &token).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_jti_race_enforces_exactly_once(pool: PgPool) {
    let setup = setup_test(pool).await;
    let jti = "jti-concurrent-race-1";

    let token = create_service_token(
        &setup.p256_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        jti,
        60,
        None,
    );

    let app1 = setup.app.clone();
    let app2 = setup.app.clone();
    let token1 = token.clone();
    let token2 = token.clone();

    // Race two concurrent requests
    let (resp1, resp2) = tokio::join!(
        tokio::spawn(async move { request_feed(&app1, &token1).await }),
        tokio::spawn(async move { request_feed(&app2, &token2).await }),
    );

    let status1 = resp1.unwrap().status();
    let status2 = resp2.unwrap().status();

    let mut statuses = vec![status1, status2];
    statuses.sort_by_key(|s| s.as_u16());

    assert_eq!(
        statuses,
        vec![StatusCode::OK, StatusCode::UNAUTHORIZED],
        "Exactly one request must succeed with 200 and one must fail with 401"
    );

    // Verify exactly one nonce row exists in database
    let nonce_count: (i64,) = sqlx::query_as("SELECT count(*) FROM auth_jti_nonce WHERE jti = $1")
        .bind(jti)
        .fetch_one(&setup.pool)
        .await
        .unwrap();

    assert_eq!(nonce_count.0, 1, "Exactly one nonce row must exist in DB");
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

    let bytes = to_bytes(caps_resp.into_body(), 1024 * 1024).await.unwrap();
    let caps: GetCapabilitiesOutput = serde_json::from_slice(&bytes).unwrap();
    assert!(caps.enabled);
    assert_eq!(caps.protocol_revision.as_str(), "1");
    assert!(caps.supports_images);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_missing_or_invalid_typ_and_alg(pool: PgPool) {
    let setup = setup_test(pool).await;

    // 1. Wrong typ
    let token_wrong_typ = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            typ: Some("INVALID_TYPE"),
            jti: Some("jti-wrong-typ"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_wrong_typ).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 2. Missing typ
    let now = Utc::now().timestamp();
    let header_no_typ = json!({
        "alg": "ES256",
        "kid": "#atproto"
    });
    let claims = json!({
        "iss": ALICE_DID,
        "aud": CIRCLE_AUDIENCE,
        "lxm": "blue.catbird.circle.getFeed",
        "jti": "jti-no-typ",
        "iat": now,
        "exp": now + 60
    });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_no_typ).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let input = format!("{h_b64}.{c_b64}");
    let sig: Signature = setup.p256_signing_key.sign(input.as_bytes());
    let token_no_typ = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));

    assert_eq!(
        request_feed(&setup.app, &token_no_typ).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 3. Unsupported alg (RS256)
    let token_wrong_alg = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            alg: Some("RS256"),
            jti: Some("jti-wrong-alg"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_wrong_alg).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kid_binding_and_verification_method_selection(pool: PgPool) {
    let setup = setup_test(pool).await;

    // 1. Valid kid = "#atproto"
    let token_kid_atproto = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            kid: Some("#atproto"),
            jti: Some("jti-kid-atproto"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_kid_atproto).await.status(),
        StatusCode::OK
    );

    // 2. Valid kid = "<iss>#atproto"
    let full_kid = format!("{}#atproto", ALICE_DID);
    let token_kid_full = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            kid: Some(&full_kid),
            jti: Some("jti-kid-full"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_kid_full).await.status(),
        StatusCode::OK
    );

    // 3. Invalid kid = "#wrong"
    let token_kid_wrong = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            kid: Some("#wrong"),
            jti: Some("jti-kid-wrong"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_kid_wrong).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 4. Invalid kid = foreign DID #atproto
    let token_foreign_kid = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            kid: Some("did:plc:other-user#atproto"),
            jti: Some("jti-foreign-kid"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_foreign_kid).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn enforces_iat_exp_and_lifetime_constraints(pool: PgPool) {
    let setup = setup_test(pool).await;
    let now = Utc::now().timestamp();

    // 1. Missing iat
    let header = json!({ "typ": "JWT", "alg": "ES256", "kid": "#atproto" });
    let claims_no_iat = json!({
        "iss": ALICE_DID,
        "aud": CIRCLE_AUDIENCE,
        "lxm": "blue.catbird.circle.getFeed",
        "jti": "jti-no-iat",
        "exp": now + 60
    });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims_no_iat).unwrap());
    let input = format!("{h_b64}.{c_b64}");
    let sig: Signature = setup.p256_signing_key.sign(input.as_bytes());
    let token_no_iat = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    assert_eq!(
        request_feed(&setup.app, &token_no_iat).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 2. Future iat (iat > now + 5)
    let token_future_iat = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iat: Some(now + 60),
            exp: Some(now + 120),
            jti: Some("jti-future-iat"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_future_iat).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 3. Expired token (exp < now)
    let token_past_exp = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iat: Some(now - 100),
            exp: Some(now - 10),
            jti: Some("jti-past-exp"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_past_exp).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 4. exp == now (boundary case - rejected!)
    let token_exp_at_now = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iat: Some(now - 30),
            exp: Some(now),
            jti: Some("jti-exp-now"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_exp_at_now).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 5. Overlong lifetime (exp - iat > 120s)
    let token_overlong = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iat: Some(now),
            exp: Some(now + 300),
            jti: Some("jti-overlong"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_overlong).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn supports_real_multikey_p256_and_secp256k1(pool: PgPool) {
    let setup = setup_test(pool).await;

    // 1. P-256 Multikey was registered in setup_test for ALICE_DID -> verifies successfully
    let p256_token = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iss: Some(ALICE_DID),
            jti: Some("jti-multikey-p256"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &p256_token).await.status(),
        StatusCode::OK
    );

    // 2. Register a new user BOB_DID with secp256k1 Multikey
    let bob_did = "did:plc:bob-secp256k1";
    let secp_vk = setup.secp_signing_key.verifying_key();
    let secp_sec1 = secp_vk.to_encoded_point(true);

    // Secp256k1 multicodec prefix: 0xe7 -> varint [0xe7, 0x01]
    let mut secp_multikey_bytes = vec![0xe7, 0x01];
    secp_multikey_bytes.extend_from_slice(secp_sec1.as_bytes());
    let secp_multikey =
        multibase::encode(multibase::Base::Base58Btc, &secp_multikey_bytes);

    let bob_doc = DidDocument {
        id: bob_did.into(),
        verification_method: vec![VerificationMethod {
            id: format!("{bob_did}#atproto"),
            r#type: "Multikey".into(),
            controller: bob_did.into(),
            public_key_jwk: None,
            public_key_multibase: Some(secp_multikey),
        }],
    };
    setup.state.did_resolver.insert_cached(bob_did.into(), bob_doc);

    // Sign with secp256k1 (ES256K)
    let now = Utc::now().timestamp();
    let header_secp = json!({
        "typ": "JWT",
        "alg": "ES256K",
        "kid": "#atproto"
    });
    let claims_secp = json!({
        "iss": bob_did,
        "aud": CIRCLE_AUDIENCE,
        "lxm": "blue.catbird.circle.getFeed",
        "jti": "jti-secp256k1-1",
        "iat": now,
        "exp": now + 60
    });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_secp).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims_secp).unwrap());
    let input = format!("{h_b64}.{c_b64}");
    let sig: k256::ecdsa::Signature = setup.secp_signing_key.sign(input.as_bytes());
    let secp_token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));

    assert_eq!(
        request_feed(&setup.app, &secp_token).await.status(),
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_invalid_cryptographic_signature(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Sign with an unrelated private key
    let wrong_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let bad_sig_token = create_service_token(
        &wrong_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-bad-sig",
        60,
        None,
    );

    assert_eq!(
        request_feed(&setup.app, &bad_sig_token).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_wrong_lxm(pool: PgPool) {
    let setup = setup_test(pool).await;

    let wrong_lxm_token = create_service_token(
        &setup.p256_signing_key,
        ALICE_DID,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.wrongMethod",
        "jti-wrong-lxm",
        60,
        None,
    );

    assert_eq!(
        request_feed(&setup.app, &wrong_lxm_token).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn handles_did_web_ssrf_and_public_resolution(pool: PgPool) {
    let setup = setup_test(pool).await;

    // 1. Direct private IP: 127.0.0.1
    let ssrf_token_127 = create_service_token(
        &setup.p256_signing_key,
        "did:web:127.0.0.1",
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-ssrf-127",
        60,
        None,
    );
    assert_eq!(
        request_feed(&setup.app, &ssrf_token_127).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 2. Direct private IP: 10.0.0.1
    let ssrf_token_10 = create_service_token(
        &setup.p256_signing_key,
        "did:web:10.0.0.1",
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-ssrf-10",
        60,
        None,
    );
    assert_eq!(
        request_feed(&setup.app, &ssrf_token_10).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 3. Localhost hostname
    let ssrf_token_local = create_service_token(
        &setup.p256_signing_key,
        "did:web:localhost",
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-ssrf-local",
        60,
        None,
    );
    assert_eq!(
        request_feed(&setup.app, &ssrf_token_local).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 4. Successful public did:web resolution (using cached public web did doc)
    let public_web_did = "did:web:example.com:users:alice";
    let point = EncodedPoint::from(setup.p256_signing_key.verifying_key());
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let web_doc = DidDocument {
        id: public_web_did.into(),
        verification_method: vec![VerificationMethod {
            id: format!("{public_web_did}#atproto"),
            r#type: "JsonWebKey2020".into(),
            controller: public_web_did.into(),
            public_key_jwk: Some(PublicKeyJwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x,
                y: Some(y),
            }),
            public_key_multibase: None,
        }],
    };
    setup.state.did_resolver.insert_cached(public_web_did.into(), web_doc);

    let public_web_token = create_service_token(
        &setup.p256_signing_key,
        public_web_did,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-web-public",
        60,
        None,
    );
    assert_eq!(
        request_feed(&setup.app, &public_web_token).await.status(),
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn privacy_safe_auth_errors_contain_no_canaries(pool: PgPool) {
    let setup = setup_test(pool).await;

    let iss_canary = "did:plc:alice-secret-canary-42";
    let space_canary = "at://did:plc:alice/space/circle/canary99";
    let jti_canary = "jti-canary-secret-777";
    let lxm_canary = "blue.catbird.circle.secretLxmCanary";

    // Test 1: Bad signature with canaries
    let bad_sig_token = create_service_token(
        &p256::ecdsa::SigningKey::random(&mut OsRng),
        iss_canary,
        CIRCLE_AUDIENCE,
        lxm_canary,
        jti_canary,
        60,
        None,
    );

    let resp = request_feed(&setup.app, &bad_sig_token).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);

    assert!(
        !body_str.contains(iss_canary),
        "Response body must not contain issuer DID canary"
    );
    assert!(
        !body_str.contains(space_canary),
        "Response body must not contain space canary"
    );
    assert!(
        !body_str.contains(jti_canary),
        "Response body must not contain JTI canary"
    );
    assert!(
        !body_str.contains(lxm_canary),
        "Response body must not contain LXM canary"
    );

    let error_json: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(
        error_json["error"], "AuthRequired",
        "Error code must be standard AuthRequired"
    );
    assert_eq!(
        error_json["message"], "Authentication required",
        "Error message must be generic content-free"
    );
}
