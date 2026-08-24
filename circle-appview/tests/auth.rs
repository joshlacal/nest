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
    auth::{
        is_private_ipv6, DefaultDidWebTransport, DidDocument, DidResolver, DidWebTransport,
        PublicKeyJwk, VerificationMethod,
    },
    config::{AppState, Config},
    db,
    error::AuthReason,
    routes::create_router,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;
use std::future::Future;
use std::net::{Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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
        nest_client_id: None,
        nest_verifying_keys: Vec::new(),
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
    let p256_multikey = multibase::encode(multibase::Base::Base58Btc, &p256_multikey_bytes);

    // Register DID document with Multikey and JsonWebKey2020
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
            public_key_multibase: Some(p256_multikey),
        }],
        service: vec![],
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
    request_feed_with_uri(app, token, "/xrpc/blue.catbird.circle.getFeed").await
}

async fn request_feed_with_uri(app: &axum::Router, token: &str, uri: &str) -> Response {
    let request = Request::builder()
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    app.clone().oneshot(request).await.unwrap()
}
#[derive(Clone)]
struct MockDidWebTransport {
    dns_result: Result<Vec<SocketAddr>, AuthReason>,
    fetched_doc: Result<DidDocument, AuthReason>,
    captured_fetches: Arc<Mutex<Vec<(String, String, SocketAddr)>>>,
}

impl DidWebTransport for MockDidWebTransport {
    fn resolve_dns<'a>(
        &'a self,
        _host: &'a str,
        _port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, AuthReason>> + Send + 'a>> {
        let res = self.dns_result.clone();
        Box::pin(async move { res })
    }

    fn fetch<'a>(
        &'a self,
        url: &'a str,
        host: &'a str,
        pinned_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<DidDocument, AuthReason>> + Send + 'a>> {
        self.captured_fetches.lock().unwrap().push((
            url.to_string(),
            host.to_string(),
            pinned_addr,
        ));
        let res = self.fetched_doc.clone();
        Box::pin(async move { res })
    }
}

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
async fn enforces_exact_iat_exp_and_lifetime_bounds(pool: PgPool) {
    let setup = setup_test(pool).await;
    let now = Utc::now().timestamp();

    // 1. Missing iat -> rejected
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

    // 2. Future iat: exactly +1s in the future -> rejected (strictly iat <= now)
    let token_future_1s = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iat: Some(now + 1),
            exp: Some(now + 60),
            jti: Some("jti-future-1s"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_future_1s).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 3. Exactly now iat and 60s lifetime -> succeeds
    let token_exact_60s = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iat: Some(now),
            exp: Some(now + 60),
            jti: Some("jti-exact-60s"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_exact_60s).await.status(),
        StatusCode::OK
    );

    // 4. Overlong lifetime: exactly 61s lifetime -> rejected (strictly <= 60s)
    let token_lifetime_61s = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iat: Some(now),
            exp: Some(now + 61),
            jti: Some("jti-lifetime-61s"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_lifetime_61s).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 5. Expired token (exp < now) -> rejected
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

    // 6. exp == now boundary case -> rejected (strictly now < exp)
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

    // 7. Arithmetic extreme: iat = i64::MIN, exp = now + 10 -> rejected safely without panic
    let token_iat_min = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iat: Some(i64::MIN),
            exp: Some(now + 10),
            jti: Some("jti-iat-min"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_iat_min).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 8. Arithmetic extreme: iat = i64::MIN, exp = i64::MAX -> rejected safely without panic
    let token_iat_min_exp_max = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iat: Some(i64::MIN),
            exp: Some(i64::MAX),
            jti: Some("jti-iat-min-exp-max"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_iat_min_exp_max).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 9. Arithmetic extreme: iat = now, exp = i64::MAX -> rejected safely without panic
    let token_exp_max = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iat: Some(now),
            exp: Some(i64::MAX),
            jti: Some("jti-exp-max"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_exp_max).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 10. Arithmetic extreme: iat = i64::MIN, exp = i64::MIN -> rejected (exp <= iat)
    let token_both_min = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iat: Some(i64::MIN),
            exp: Some(i64::MIN),
            jti: Some("jti-both-min"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_both_min).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn enforces_algorithm_curve_matching_and_verification_method_types(pool: PgPool) {
    let setup = setup_test(pool).await;

    // 1. Mismatch: Token signed by P-256 key with alg: "ES256K" -> rejected
    let token_p256_with_es256k = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iss: Some(ALICE_DID),
            alg: Some("ES256K"),
            jti: Some("jti-p256-es256k-mismatch"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &token_p256_with_es256k)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // 2. Register BOB with secp256k1 Multikey
    let bob_did = "did:plc:bob-secp256k1";
    let secp_vk = setup.secp_signing_key.verifying_key();
    let secp_sec1 = secp_vk.to_encoded_point(true);
    let mut secp_multikey_bytes = vec![0xe7, 0x01];
    secp_multikey_bytes.extend_from_slice(secp_sec1.as_bytes());
    let secp_multikey = multibase::encode(multibase::Base::Base58Btc, &secp_multikey_bytes);

    let bob_doc = DidDocument {
        id: bob_did.into(),
        verification_method: vec![VerificationMethod {
            id: format!("{bob_did}#atproto"),
            r#type: "Multikey".into(),
            controller: bob_did.into(),
            public_key_jwk: None,
            public_key_multibase: Some(secp_multikey),
        }],
        service: vec![],
    };
    setup.state.did_resolver.insert_cached(bob_did.into(), bob_doc);
    // 3. Mismatch: Token signed by secp256k1 key with alg: "ES256" -> rejected
    let now = Utc::now().timestamp();
    let header_secp_wrong_alg = json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": "#atproto"
    });
    let claims_secp = json!({
        "iss": bob_did,
        "aud": CIRCLE_AUDIENCE,
        "lxm": "blue.catbird.circle.getFeed",
        "jti": "jti-secp-es256-mismatch",
        "iat": now,
        "exp": now + 60
    });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_secp_wrong_alg).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims_secp).unwrap());
    let input = format!("{h_b64}.{c_b64}");
    let sig: k256::ecdsa::Signature = setup.secp_signing_key.sign(input.as_bytes());
    let secp_wrong_alg_token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));

    assert_eq!(
        request_feed(&setup.app, &secp_wrong_alg_token).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 4. Valid: secp256k1 with ES256K -> succeeds
    let header_secp_correct = json!({
        "typ": "JWT",
        "alg": "ES256K",
        "kid": "#atproto"
    });
    let h_b64_ok = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_secp_correct).unwrap());
    let input_ok = format!("{h_b64_ok}.{c_b64}");
    let sig_ok: k256::ecdsa::Signature = setup.secp_signing_key.sign(input_ok.as_bytes());
    let secp_ok_token = format!("{input_ok}.{}", URL_SAFE_NO_PAD.encode(sig_ok.to_bytes()));

    assert_eq!(
        request_feed(&setup.app, &secp_ok_token).await.status(),
        StatusCode::OK
    );

    // 5. Invalid verification method type: arbitrary type carrying P-256 key -> rejected
    let charlie_did = "did:plc:charlie-invalid-type";
    let p256_vk = setup.p256_signing_key.verifying_key();
    let point = EncodedPoint::from(p256_vk);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let charlie_doc = DidDocument {
        id: charlie_did.into(),
        verification_method: vec![VerificationMethod {
            id: format!("{charlie_did}#atproto"),
            r#type: "RsaVerificationKey2018".into(),
            controller: charlie_did.into(),
            public_key_jwk: Some(PublicKeyJwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x,
                y: Some(y),
            }),
            public_key_multibase: None,
        }],
        service: vec![],
    };
    setup
        .state
        .did_resolver
        .insert_cached(charlie_did.into(), charlie_doc);

    let charlie_token = create_custom_service_token(
        &setup.p256_signing_key,
        TokenOptions {
            iss: Some(charlie_did),
            jti: Some("jti-charlie-invalid-vm-type"),
            ..Default::default()
        },
    );
    assert_eq!(
        request_feed(&setup.app, &charlie_token).await.status(),
        StatusCode::UNAUTHORIZED
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

#[test]
fn complete_ipv6_and_ipv4_non_global_policy_coverage() {
    use circle_appview::auth::is_private_ipv4;
    use std::net::Ipv4Addr;

    // IPv4: IANA globally reachable exceptions in 192.0.0.0/24
    assert!(!is_private_ipv4(&"192.0.0.9".parse::<Ipv4Addr>().unwrap())); // PCP Anycast (RFC 7723)
    assert!(!is_private_ipv4(&"192.0.0.10".parse::<Ipv4Addr>().unwrap())); // TURN Anycast (RFC 8155)
    // IPv4: Non-global remainder of 192.0.0.0/24
    assert!(is_private_ipv4(&"192.0.0.1".parse::<Ipv4Addr>().unwrap()));
    assert!(is_private_ipv4(&"192.0.0.8".parse::<Ipv4Addr>().unwrap()));
    assert!(is_private_ipv4(&"192.0.0.11".parse::<Ipv4Addr>().unwrap()));
    assert!(is_private_ipv4(&"192.0.0.254".parse::<Ipv4Addr>().unwrap()));

    // IPv6: IANA globally reachable exceptions inside 2001::/23
    assert!(!is_private_ipv6(&"2001:1::1".parse::<Ipv6Addr>().unwrap())); // PCP Anycast (RFC 7723)
    assert!(!is_private_ipv6(&"2001:1::2".parse::<Ipv6Addr>().unwrap())); // TURN Anycast (RFC 8155)
    assert!(!is_private_ipv6(&"2001:1::3".parse::<Ipv6Addr>().unwrap())); // DNS-SD Anycast
    assert!(!is_private_ipv6(&"2001:3::1".parse::<Ipv6Addr>().unwrap())); // AMT (RFC 7450)
    assert!(!is_private_ipv6(&"2001:4:112::1".parse::<Ipv6Addr>().unwrap())); // AS112-v6 (RFC 7535)
    assert!(!is_private_ipv6(&"2001:20::1".parse::<Ipv6Addr>().unwrap())); // ORCHIDv2 (RFC 7343)
    assert!(!is_private_ipv6(&"2001:2f:ffff::1".parse::<Ipv6Addr>().unwrap())); // ORCHIDv2 end of /28
    assert!(!is_private_ipv6(&"2001:30::1".parse::<Ipv6Addr>().unwrap())); // Drone Remote ID DETs (RFC 9374)
    assert!(!is_private_ipv6(&"2001:3f:ffff::1".parse::<Ipv6Addr>().unwrap())); // Drone Remote ID end of /28

    // IPv6: Non-global remainder inside 2001::/23
    assert!(is_private_ipv6(&"2001:0000::1".parse::<Ipv6Addr>().unwrap())); // TEREDO (RFC 4380)
    assert!(is_private_ipv6(&"2001:1::4".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"2001:2::1".parse::<Ipv6Addr>().unwrap())); // Benchmarking (RFC 5180)
    assert!(is_private_ipv6(&"2001:4:113::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"2001:5::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"2001:10::1".parse::<Ipv6Addr>().unwrap())); // Deprecated ORCHID (RFC 4843)
    assert!(is_private_ipv6(&"2001:1f::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"2001:40::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"2001:01ff:ffff:ffff:ffff:ffff:ffff:ffff".parse::<Ipv6Addr>().unwrap()));

    // Documentation ranges (2001:db8::/32 and 3fff::/20)
    assert!(is_private_ipv6(&"2001:db8::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"3fff:0::1".parse::<Ipv6Addr>().unwrap()));

    // Discard and Dummy prefixes (100::/64, 100:0:0:1::/64)
    assert!(is_private_ipv6(&"100::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"100:0:0:1::1".parse::<Ipv6Addr>().unwrap()));

    // SRv6 SIDs (5f00::/16)
    assert!(is_private_ipv6(&"5f00::1".parse::<Ipv6Addr>().unwrap()));

    // ULA (fc00::/7), Link-Local (fe80::/10), Site-Local (fec0::/10)
    assert!(is_private_ipv6(&"fc00::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"fd12:3456:789a::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"fe80::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"fec0::1".parse::<Ipv6Addr>().unwrap()));

    // Loopback and Unspecified
    assert!(is_private_ipv6(&"::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"::".parse::<Ipv6Addr>().unwrap()));

    // IPv4-mapped private
    assert!(is_private_ipv6(&"::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"::ffff:192.168.1.1".parse::<Ipv6Addr>().unwrap()));

    // Public globally reachable IPv6 addresses outside 2001::/23
    assert!(!is_private_ipv6(&"2600::1".parse::<Ipv6Addr>().unwrap()));
    assert!(!is_private_ipv6(&"2001:0200::1".parse::<Ipv6Addr>().unwrap()));
    assert!(!is_private_ipv6(&"2a00:1450:4009:81f::200e".parse::<Ipv6Addr>().unwrap()));
}

#[sqlx::test(migrations = "./migrations")]
async fn handles_did_web_transport_resolution_and_ssrf_policies(pool: PgPool) {
    let setup = setup_test(pool).await;

    // 1. Successful public resolution through injected transport (NO cache pre-insertion)
    let public_did = "did:web:bluecatbird.io";
    let point = EncodedPoint::from(setup.p256_signing_key.verifying_key());
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let public_doc = DidDocument {
        id: public_did.into(),
        verification_method: vec![VerificationMethod {
            id: format!("{public_did}#atproto"),
            r#type: "JsonWebKey2020".into(),
            controller: public_did.into(),
            public_key_jwk: Some(PublicKeyJwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x,
                y: Some(y),
            }),
            public_key_multibase: None,
        }],
        service: vec![],
    };
    let public_socket: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));

    let mock_transport = Arc::new(MockDidWebTransport {
        dns_result: Ok(vec![public_socket]),
        fetched_doc: Ok(public_doc),
        captured_fetches: captured.clone(),
    });

    let resolver = Arc::new(DidResolver::with_transport(
        "https://plc.directory".into(),
        reqwest::Client::new(),
        mock_transport,
    ));

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
        nest_client_id: None,
        nest_verifying_keys: Vec::new(),
    };
    let app_state = AppState::with_did_resolver(config, setup.pool.clone(), resolver);
    let app = create_router(app_state);

    let public_token = create_service_token(
        &setup.p256_signing_key,
        public_did,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-public-transport-1",
        60,
        None,
    );

    // Verify successful 200 OK without cache shortcut
    assert_eq!(request_feed(&app, &public_token).await.status(), StatusCode::OK);

    // Verify transport was actually invoked with correct URL, host, and pinned socket
    let fetches = captured.lock().unwrap().clone();
    assert_eq!(fetches.len(), 1);
    assert_eq!(fetches[0].0, "https://bluecatbird.io:443/.well-known/did.json");
    assert_eq!(fetches[0].1, "bluecatbird.io");
    assert_eq!(fetches[0].2, public_socket);

    // 2. Private-only DNS answer -> rejected as SSRF (401)
    let private_socket: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let mock_private = Arc::new(MockDidWebTransport {
        dns_result: Ok(vec![private_socket]),
        fetched_doc: Err(AuthReason::DidResolutionFailed),
        captured_fetches: Arc::new(Mutex::new(Vec::new())),
    });
    let resolver_private = Arc::new(DidResolver::with_transport(
        "https://plc.directory".into(),
        reqwest::Client::new(),
        mock_private,
    ));
    let app_state_private = AppState::with_did_resolver(
        Config {
            host: "127.0.0.1".into(),
            port: 3002,
            database_url: "postgres://localhost/postgres".into(),
            service_did: CIRCLE_AUDIENCE.into(),
            plc_directory_url: "https://plc.directory".into(),
            nest_client_id: None,
            nest_verifying_keys: Vec::new(),
        },
        setup.pool.clone(),
        resolver_private,
    );
    let app_private = create_router(app_state_private);

    let private_dns_token = create_service_token(
        &setup.p256_signing_key,
        "did:web:private-dns.catbird.blue",
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-private-dns",
        60,
        None,
    );
    assert_eq!(
        request_feed(&app_private, &private_dns_token).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 3. Mixed DNS answers (public + private) -> rejected as SSRF (401)
    let mixed_sockets = vec![public_socket, "192.168.1.1:443".parse().unwrap()];
    let mock_mixed = Arc::new(MockDidWebTransport {
        dns_result: Ok(mixed_sockets),
        fetched_doc: Err(AuthReason::DidResolutionFailed),
        captured_fetches: Arc::new(Mutex::new(Vec::new())),
    });
    let resolver_mixed = Arc::new(DidResolver::with_transport(
        "https://plc.directory".into(),
        reqwest::Client::new(),
        mock_mixed,
    ));
    let app_state_mixed = AppState::with_did_resolver(
        Config {
            host: "127.0.0.1".into(),
            port: 3002,
            database_url: "postgres://localhost/postgres".into(),
            service_did: CIRCLE_AUDIENCE.into(),
            plc_directory_url: "https://plc.directory".into(),
            nest_client_id: None,
            nest_verifying_keys: Vec::new(),
        },
        setup.pool.clone(),
        resolver_mixed,
    );
    let app_mixed = create_router(app_state_mixed);

    let mixed_dns_token = create_service_token(
        &setup.p256_signing_key,
        "did:web:mixed-dns.catbird.blue",
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-mixed-dns",
        60,
        None,
    );
    assert_eq!(
        request_feed(&app_mixed, &mixed_dns_token).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // 4. Literal IPv6 non-global (e.g. 2001:5::1) -> rejected as SSRF (401)
    let ssrf_token_ipv6 = create_service_token(
        &setup.p256_signing_key,
        "did:web:2001%3A5%3A%3A1",
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-ssrf-ipv6-2001-5",
        60,
        None,
    );
    assert_eq!(
        request_feed(&setup.app, &ssrf_token_ipv6).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

async fn run_production_pinned_client_tls_fixture() {
    use circle_appview::auth::build_did_web_client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = rustls::crypto::ring::default_provider().install_default();
    // 1. Generate test self-signed certificate for public hostname "did-web.example.org"
    let params = rcgen::CertificateParams::new(vec![
        "did-web.example.org".to_string(),
        "example.com".to_string(),
    ])
    .unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    // 2. Build tokio-rustls TLS server config
    let rustls_cert = rustls::pki_types::CertificateDer::from(cert_der);
    let rustls_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
    );
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls_cert], rustls_key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    // 3. Bind local TCP listener for TLS fixture
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture_addr = listener.local_addr().unwrap();

    // 4. Run local HTTPS server that handles did.json and redirect responses
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
                let mut buf = [0u8; 2048];
                let Ok(n) = tls_stream.read(&mut buf).await else {
                    return;
                };
                let req_str = String::from_utf8_lossy(&buf[..n]);
                if req_str.starts_with("GET /.well-known/did.json") {
                    let body = r#"{"id":"did:web:did-web.example.org","verificationMethod":[]}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                } else if req_str.starts_with("GET /redirect") {
                    // Redirect to the same TLS fixture's valid DID document endpoint.
                    // If Policy::none() is removed/absent, following this redirect would return 200 OK (and Ok(DidDocument)),
                    // proving that Policy::none() is what actively defends the endpoint and causes resolution to fail.
                    let response = "HTTP/1.1 302 Found\r\nLocation: /.well-known/did.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
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

    // 5. Test successful pinned HTTPS fetch via DefaultDidWebTransport (exercising production builder)
    let transport = DefaultDidWebTransport::with_test_root_certificate(reqwest_cert.clone());
    let valid_url = format!(
        "https://did-web.example.org:{}/.well-known/did.json",
        fixture_addr.port()
    );

    let doc = transport
        .fetch(&valid_url, "did-web.example.org", fixture_addr)
        .await
        .expect("Pinned HTTPS fetch must succeed via injected test certificate and resolve pin");
    assert_eq!(doc.id, "did:web:did-web.example.org");

    // 6. Test that redirects are rejected and not followed
    // The redirect target is /.well-known/did.json on this same TLS fixture which returns a valid DID document.
    // If redirects were followed, this would yield Ok; returning Err proves Policy::none() is enforced.
    let redirect_url = format!(
        "https://did-web.example.org:{}/redirect",
        fixture_addr.port()
    );
    let redirect_res = transport
        .fetch(&redirect_url, "did-web.example.org", fixture_addr)
        .await;
    assert!(
        redirect_res.is_err(),
        "Redirect must be rejected by Policy::none()"
    );
    assert_eq!(redirect_res.err().unwrap(), AuthReason::DidResolutionFailed);

    // 7. Test that connection strictly uses the pinned address (closed port fails immediately)
    let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = closed_listener.local_addr().unwrap();
    drop(closed_listener);

    let wrong_url = format!(
        "https://did-web.example.org:{}/.well-known/did.json",
        closed_addr.port()
    );
    let wrong_pin_res = transport
        .fetch(&wrong_url, "did-web.example.org", closed_addr)
        .await;
    assert!(
        wrong_pin_res.is_err(),
        "Connecting to non-listening pinned address must fail immediately"
    );
    assert_eq!(wrong_pin_res.err().unwrap(), AuthReason::DidResolutionFailed);

    // 8. Direct build_did_web_client verification (production builder function)
    let client = build_did_web_client(
        "did-web.example.org",
        fixture_addr,
        Some(reqwest_cert.clone()),
    )
    .expect("build_did_web_client must build successfully");
    let direct_resp = client
        .get(&valid_url)
        .send()
        .await
        .expect("Direct client must connect over pinned TLS");
    assert_eq!(direct_resp.status(), StatusCode::OK);
}

const PROXY_SUBPROCESS_CANARY: &str = "CANARY_PROXY_SUBPROCESS_EXECUTED_89f7a2d1";
const POISONED_PROXY_URL: &str = "http://invalid-unreachable-proxy.example.local:9999";

#[tokio::test]
#[ignore = "Subprocess helper executed exclusively by production_pinned_client_builder_enforces_tls_pinning_no_proxy_and_rejects_redirects"]
async fn production_pinned_client_builder_proxy_subprocess_helper() {
    assert_eq!(
        std::env::var("HTTPS_PROXY").ok().as_deref(),
        Some(POISONED_PROXY_URL),
        "HTTPS_PROXY must be poisoned in subprocess"
    );
    assert_eq!(
        std::env::var("HTTP_PROXY").ok().as_deref(),
        Some(POISONED_PROXY_URL),
        "HTTP_PROXY must be poisoned in subprocess"
    );
    assert_eq!(
        std::env::var("ALL_PROXY").ok().as_deref(),
        Some(POISONED_PROXY_URL),
        "ALL_PROXY must be poisoned in subprocess"
    );

    println!("{}", PROXY_SUBPROCESS_CANARY);
    run_production_pinned_client_tls_fixture().await;
}

#[tokio::test]
async fn production_pinned_client_builder_enforces_tls_pinning_no_proxy_and_rejects_redirects() {
    // 1. Capture parent process environment variables to assert they are never mutated
    let orig_https_proxy = std::env::var_os("HTTPS_PROXY");
    let orig_http_proxy = std::env::var_os("HTTP_PROXY");
    let orig_all_proxy = std::env::var_os("ALL_PROXY");

    // 2. Spawn subprocess with poisoned proxy environment variables
    let current_exe = std::env::current_exe().expect("Must get current test executable");
    let output = std::process::Command::new(current_exe)
        .arg("production_pinned_client_builder_proxy_subprocess_helper")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .env("HTTPS_PROXY", POISONED_PROXY_URL)
        .env("HTTP_PROXY", POISONED_PROXY_URL)
        .env("ALL_PROXY", POISONED_PROXY_URL)
        .output()
        .expect("Failed to execute proxy isolation test subprocess");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "Subprocess failed to run with invalid proxy env (no_proxy must bypass invalid proxies):\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains(PROXY_SUBPROCESS_CANARY),
        "Subprocess did not emit the required execution canary (filter did not run helper):\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    // 3. Verify parent process environment was never mutated
    assert_eq!(
        std::env::var_os("HTTPS_PROXY"),
        orig_https_proxy,
        "Parent process HTTPS_PROXY must not be mutated"
    );
    assert_eq!(
        std::env::var_os("HTTP_PROXY"),
        orig_http_proxy,
        "Parent process HTTP_PROXY must not be mutated"
    );
    assert_eq!(
        std::env::var_os("ALL_PROXY"),
        orig_all_proxy,
        "Parent process ALL_PROXY must not be mutated"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn privacy_safe_auth_errors_and_logs_contain_no_canaries(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Set up in-memory tracing subscriber to capture log outputs
    let log_buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = BufferWriter(log_buffer.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_max_level(tracing::Level::TRACE)
        .finish();

    let _guard = tracing::subscriber::set_default(subscriber);

    let iss_canary = "did:plc:alice-secret-canary-42";
    let space_canary = "at://did:plc:alice/space/circle/canary99";
    let jti_canary = "jti-canary-secret-777";
    let lxm_canary = "blue.catbird.circle.secretLxmCanary";

    // Bad signature token containing issuer, JTI, and LXM canaries
    let bad_sig_token = create_service_token(
        &p256::ecdsa::SigningKey::random(&mut OsRng),
        iss_canary,
        CIRCLE_AUDIENCE,
        lxm_canary,
        jti_canary,
        60,
        None,
    );

    // Build request URI explicitly including space_canary and query canary
    let request_uri = format!(
        "/xrpc/blue.catbird.circle.getFeed?space={}&canaryParam=secretQueryValue99",
        space_canary
    );

    let resp = request_feed_with_uri(&setup.app, &bad_sig_token, &request_uri).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Assert HTTP response body contains zero canaries
    assert!(
        !body_str.contains(iss_canary),
        "Response body must not contain issuer DID canary"
    );
    assert!(
        !body_str.contains(space_canary),
        "Response body must not contain space canary"
    );
    assert!(
        !body_str.contains("secretQueryValue99"),
        "Response body must not contain query canary"
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

    // Assert captured tracing logs contain zero canaries or raw tokens
    let logs = String::from_utf8_lossy(&log_buffer.lock().unwrap()).to_string();
    assert!(
        !logs.contains(iss_canary),
        "Captured logs must not contain issuer DID canary"
    );
    assert!(
        !logs.contains(space_canary),
        "Captured logs must not contain space canary"
    );
    assert!(
        !logs.contains("secretQueryValue99"),
        "Captured logs must not contain query canary"
    );
    assert!(
        !logs.contains(jti_canary),
        "Captured logs must not contain JTI canary"
    );
    assert!(
        !logs.contains(lxm_canary),
        "Captured logs must not contain LXM canary"
    );
    assert!(
        !logs.contains(&bad_sig_token),
        "Captured logs must not contain raw auth token"
    );
}
