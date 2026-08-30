use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    response::Response,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_atproto::generated::blue_catbird::circle::get_capabilities::GetCapabilitiesOutput;
use chrono::{DateTime, Utc};
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
use std::sync::{Arc, Mutex, RwLock};
use tower::ServiceExt;

pub const CIRCLE_AUDIENCE: &str = "did:web:circles.catbird.blue#atproto_circles";
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
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circles"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
        commit_verification_policy: circle_appview::commit::CommitVerificationPolicy::default(),
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
                kid: None,
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
        claims
            .as_object_mut()
            .unwrap()
            .insert("iat".into(), json!(iat));
    } else {
        claims
            .as_object_mut()
            .unwrap()
            .insert("iat".into(), json!(now));
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
struct ControllableMockDidWebTransport {
    dns_result: Result<Vec<SocketAddr>, AuthReason>,
    current_doc: Arc<RwLock<Result<DidDocument, AuthReason>>>,
    captured_fetches: Arc<Mutex<Vec<(String, String, SocketAddr)>>>,
}

impl ControllableMockDidWebTransport {
    fn new(initial_doc: DidDocument, socket: SocketAddr) -> Self {
        Self {
            dns_result: Ok(vec![socket]),
            current_doc: Arc::new(RwLock::new(Ok(initial_doc))),
            captured_fetches: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn set_doc(&self, doc: DidDocument) {
        let mut lock = self.current_doc.write().unwrap();
        *lock = Ok(doc);
    }

    fn fetch_count(&self) -> usize {
        self.captured_fetches.lock().unwrap().len()
    }
}

impl DidWebTransport for ControllableMockDidWebTransport {
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
        let res = self.current_doc.read().unwrap().clone();
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
    assert_eq!(
        caps.protocol_revision.as_str(),
        circle_appview::CIRCLE_PROTOCOL_REVISION
    );
    assert_eq!(
        caps.protocol_revision.as_str(),
        "89deb9faca20e56fa2a262fe9746ed52bc1095ba"
    );
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
        request_feed(&setup.app, &token_iat_min_exp_max)
            .await
            .status(),
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
    setup
        .state
        .did_resolver
        .insert_cached(bob_did.into(), bob_doc);
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
        request_feed(&setup.app, &secp_wrong_alg_token)
            .await
            .status(),
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
                kid: None,
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
    assert!(!is_private_ipv6(
        &"2001:4:112::1".parse::<Ipv6Addr>().unwrap()
    )); // AS112-v6 (RFC 7535)
    assert!(!is_private_ipv6(&"2001:20::1".parse::<Ipv6Addr>().unwrap())); // ORCHIDv2 (RFC 7343)
    assert!(!is_private_ipv6(
        &"2001:2f:ffff::1".parse::<Ipv6Addr>().unwrap()
    )); // ORCHIDv2 end of /28
    assert!(!is_private_ipv6(&"2001:30::1".parse::<Ipv6Addr>().unwrap())); // Drone Remote ID DETs (RFC 9374)
    assert!(!is_private_ipv6(
        &"2001:3f:ffff::1".parse::<Ipv6Addr>().unwrap()
    )); // Drone Remote ID end of /28

    // IPv6: Non-global remainder inside 2001::/23
    assert!(is_private_ipv6(
        &"2001:0000::1".parse::<Ipv6Addr>().unwrap()
    )); // TEREDO (RFC 4380)
    assert!(is_private_ipv6(&"2001:1::4".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"2001:2::1".parse::<Ipv6Addr>().unwrap())); // Benchmarking (RFC 5180)
    assert!(is_private_ipv6(
        &"2001:4:113::1".parse::<Ipv6Addr>().unwrap()
    ));
    assert!(is_private_ipv6(&"2001:5::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"2001:10::1".parse::<Ipv6Addr>().unwrap())); // Deprecated ORCHID (RFC 4843)
    assert!(is_private_ipv6(&"2001:1f::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"2001:40::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(
        &"2001:01ff:ffff:ffff:ffff:ffff:ffff:ffff"
            .parse::<Ipv6Addr>()
            .unwrap()
    ));

    // Documentation ranges (2001:db8::/32 and 3fff::/20)
    assert!(is_private_ipv6(&"2001:db8::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"3fff:0::1".parse::<Ipv6Addr>().unwrap()));

    // Discard and Dummy prefixes (100::/64, 100:0:0:1::/64)
    assert!(is_private_ipv6(&"100::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(
        &"100:0:0:1::1".parse::<Ipv6Addr>().unwrap()
    ));

    // SRv6 SIDs (5f00::/16)
    assert!(is_private_ipv6(&"5f00::1".parse::<Ipv6Addr>().unwrap()));

    // ULA (fc00::/7), Link-Local (fe80::/10), Site-Local (fec0::/10)
    assert!(is_private_ipv6(&"fc00::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(
        &"fd12:3456:789a::1".parse::<Ipv6Addr>().unwrap()
    ));
    assert!(is_private_ipv6(&"fe80::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"fec0::1".parse::<Ipv6Addr>().unwrap()));

    // Loopback and Unspecified
    assert!(is_private_ipv6(&"::1".parse::<Ipv6Addr>().unwrap()));
    assert!(is_private_ipv6(&"::".parse::<Ipv6Addr>().unwrap()));

    // IPv4-mapped private
    assert!(is_private_ipv6(
        &"::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap()
    ));
    assert!(is_private_ipv6(
        &"::ffff:192.168.1.1".parse::<Ipv6Addr>().unwrap()
    ));

    // Public globally reachable IPv6 addresses outside 2001::/23
    assert!(!is_private_ipv6(&"2600::1".parse::<Ipv6Addr>().unwrap()));
    assert!(!is_private_ipv6(
        &"2001:0200::1".parse::<Ipv6Addr>().unwrap()
    ));
    assert!(!is_private_ipv6(
        &"2a00:1450:4009:81f::200e".parse::<Ipv6Addr>().unwrap()
    ));
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
                kid: None,
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
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circles"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
        commit_verification_policy: circle_appview::commit::CommitVerificationPolicy::default(),
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
    assert_eq!(
        request_feed(&app, &public_token).await.status(),
        StatusCode::OK
    );

    // Verify transport was actually invoked with correct URL, host, and pinned socket
    let fetches = captured.lock().unwrap().clone();
    assert_eq!(fetches.len(), 1);
    assert_eq!(
        fetches[0].0,
        "https://bluecatbird.io:443/.well-known/did.json"
    );
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
            public_appview_url: "https://public.api.bsky.app".into(),
            circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
            appview_base_url: "http://127.0.0.1:3002".into(),
            oauth_key_id: None,
            oauth_signing_key_path: None,
            oauth_signing_key_hex: None,
            push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circles"),
            push_signing_key_path: None,
            push_signing_key_hex: None,
            commit_verification_policy: circle_appview::commit::CommitVerificationPolicy::default(),
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
        request_feed(&app_private, &private_dns_token)
            .await
            .status(),
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
            public_appview_url: "https://public.api.bsky.app".into(),
            circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
            appview_base_url: "http://127.0.0.1:3002".into(),
            oauth_key_id: None,
            oauth_signing_key_path: None,
            oauth_signing_key_hex: None,
            push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circles"),
            push_signing_key_path: None,
            push_signing_key_hex: None,
            commit_verification_policy: circle_appview::commit::CommitVerificationPolicy::default(),
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
                    let response =
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
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
    assert_eq!(
        wrong_pin_res.err().unwrap(),
        AuthReason::DidResolutionFailed
    );

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

#[sqlx::test(migrations = "./migrations")]
async fn did_document_endpoint_serves_single_atproto_circles_service_entry(pool: PgPool) {
    use circle_appview::access::resolve_circles_appview_endpoint;
    let setup = setup_test(pool).await;

    for path in ["/.well-known/did.json", "/did.json"] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();

        let resp = setup.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET {path} must return 200 OK"
        );

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let doc: DidDocument = serde_json::from_slice(&body).expect("Must parse valid DidDocument");

        assert_eq!(doc.id, "did:web:circles.catbird.blue");

        // Must expose EXACTLY ONE service entry: #atproto_circles
        assert_eq!(
            doc.service.len(),
            1,
            "DID document must expose exactly one service entry"
        );
        let svc = &doc.service[0];
        assert_eq!(
            svc.id, "#atproto_circles",
            "Service entry id must be #atproto_circles"
        );
        assert_eq!(
            svc.r#type, "AtprotoCirclesAppView",
            "Service entry type must be AtprotoCirclesAppView"
        );
        assert_eq!(
            svc.service_endpoint, "http://127.0.0.1:3002",
            "Service entry endpoint must match configured AppView base URL"
        );

        // Must expose verification method for key authentication
        assert_eq!(
            doc.verification_method.len(),
            1,
            "DID document must expose verification method"
        );
        assert_eq!(
            doc.verification_method[0].r#type, "JsonWebKey2020",
            "Verification method type must be JsonWebKey2020"
        );
        assert_eq!(
            doc.verification_method[0].controller, "did:web:circles.catbird.blue",
            "Verification method controller must match document DID"
        );

        // Resolution helper must succeed against the published document
        let (endpoint, svc_id) =
            resolve_circles_appview_endpoint(&doc, "did:web:circles.catbird.blue")
                .expect("resolve_circles_appview_endpoint must succeed");
        assert_eq!(endpoint, "http://127.0.0.1:3002");
        assert_eq!(svc_id, "#atproto_circles");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn oauth_metadata_and_jwks_endpoints_serve_consistent_identity(pool: PgPool) {
    use circle_appview::oauth::{JwksResponse, OAuthClientMetadata, CIRCLE_SCOPE};
    let setup = setup_test(pool).await;

    // 1. client-metadata.json
    for path in [
        "/oauth/client-metadata.json",
        "/.well-known/oauth-client-metadata.json",
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();

        let resp = setup.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET {path} must return 200 OK"
        );

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let meta: OAuthClientMetadata =
            serde_json::from_slice(&body).expect("Must parse OAuthClientMetadata");

        assert_eq!(
            meta.client_id,
            "http://127.0.0.1:3002/oauth/client-metadata.json"
        );
        assert_eq!(meta.client_name, "Catbird Circles AppView");
        assert_eq!(meta.client_uri, "http://127.0.0.1:3002");
        assert_eq!(
            meta.redirect_uris,
            vec!["http://127.0.0.1:3002/oauth/callback"]
        );
        assert_eq!(
            meta.grant_types,
            vec!["authorization_code", "refresh_token"]
        );
        assert_eq!(meta.response_types, vec!["code"]);
        assert_eq!(meta.scope, CIRCLE_SCOPE);
        assert_eq!(meta.token_endpoint_auth_method, "private_key_jwt");
        assert_eq!(meta.token_endpoint_auth_signing_alg, "ES256");
        assert_eq!(meta.jwks_uri, "http://127.0.0.1:3002/oauth/jwks.json");
        assert!(meta.dpop_bound_access_tokens);
    }

    // 2. jwks.json
    for path in ["/oauth/jwks.json", "/.well-known/jwks.json"] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();

        let resp = setup.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET {path} must return 200 OK"
        );

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let jwks: JwksResponse = serde_json::from_slice(&body).expect("Must parse JwksResponse");

        assert_eq!(jwks.keys.len(), 1, "JWKS must contain one public key");
        let key = &jwks.keys[0];
        assert_eq!(key.kty, "EC");
        assert_eq!(key.crv, "P-256");
        assert_eq!(key.kid, Some(setup.state.oauth_service.key_id.clone()));
        assert!(!key.x.is_empty());
        assert!(key.y.is_some());
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn space_authority_verifies_live_client_attestation_against_published_jwks(pool: PgPool) {
    use circle_appview::oauth::{
        verify_client_attestation_with_jwks, JwksResponse, OAuthClientMetadata,
    };
    let setup = setup_test(pool).await;

    let space_host_service = "did:web:space-authority.example.com#atproto_space_host";
    let expected_client_id = &setup.state.oauth_service.client_id;

    // 1. Sign a live attestation
    let token = setup
        .state
        .oauth_service
        .sign_client_attestation(space_host_service)
        .expect("sign_client_attestation must succeed");

    // 2. Direct verification with the helper
    let verified_claims = verify_client_attestation_with_jwks(
        &token,
        expected_client_id,
        space_host_service,
        &setup.state.oauth_service.jwks,
    )
    .expect("verify_client_attestation_with_jwks must succeed");

    assert_eq!(&verified_claims.iss, expected_client_id);
    assert_eq!(&verified_claims.sub, expected_client_id);
    assert_eq!(&verified_claims.aud, space_host_service);
    assert!(verified_claims.exp > Utc::now().timestamp());
    assert!(verified_claims.iat <= Utc::now().timestamp());
    assert!(!verified_claims.jti.is_empty());

    // 3. Space Authority procedure over HTTP endpoints:
    //    a) Decode token header & claims to resolve client_id
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: circle_appview::auth::JwtHeader = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(
        header.typ.as_deref(),
        Some("atproto-client-attestation+jwt")
    );
    assert_eq!(header.alg, "ES256");

    let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let claims_val: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
    let client_id = claims_val["iss"].as_str().unwrap();
    assert_eq!(client_id, expected_client_id);

    //    b) Resolve client_id -> fetch client-metadata.json
    let req_meta = Request::builder()
        .method("GET")
        .uri("/oauth/client-metadata.json")
        .body(Body::empty())
        .unwrap();
    let resp_meta = setup.app.clone().oneshot(req_meta).await.unwrap();
    assert_eq!(resp_meta.status(), StatusCode::OK);
    let meta_bytes = to_bytes(resp_meta.into_body(), usize::MAX).await.unwrap();
    let _metadata: OAuthClientMetadata = serde_json::from_slice(&meta_bytes).unwrap();

    //    c) Fetch JWKS from metadata.jwks_uri
    let req_jwks = Request::builder()
        .method("GET")
        .uri("/oauth/jwks.json")
        .body(Body::empty())
        .unwrap();
    let resp_jwks = setup.app.clone().oneshot(req_jwks).await.unwrap();
    assert_eq!(resp_jwks.status(), StatusCode::OK);
    let jwks_bytes = to_bytes(resp_jwks.into_body(), usize::MAX).await.unwrap();
    let jwks: JwksResponse = serde_json::from_slice(&jwks_bytes).unwrap();

    //    d) Match key by kid and verify ES256 signature
    let kid = header.kid.as_deref().unwrap();
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid.as_deref() == Some(kid))
        .expect("Must find key by kid");
    let parsed_key = circle_appview::auth::parse_public_key_jwk(jwk).unwrap();
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    parsed_key
        .verify(signing_input.as_bytes(), &sig_bytes)
        .expect("Signature verification must succeed");

    // 4. Negative tests
    // 4a. Tampered payload
    let tampered_claims = json!({
        "iss": "did:plc:evil",
        "sub": "did:plc:evil",
        "aud": space_host_service,
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 60,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let tampered_claims_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_string(&tampered_claims).unwrap().as_bytes());
    let tampered_token = format!("{}.{}.{}", parts[0], tampered_claims_b64, parts[2]);
    assert!(
        verify_client_attestation_with_jwks(
            &tampered_token,
            expected_client_id,
            space_host_service,
            &jwks
        )
        .is_err(),
        "Tampered payload must be rejected"
    );

    // 4b. Wrong audience
    assert!(
        verify_client_attestation_with_jwks(
            &token,
            expected_client_id,
            "did:web:wrong-host",
            &jwks
        )
        .is_err(),
        "Wrong audience must be rejected"
    );

    // 4c. Wrong client_id
    assert!(
        verify_client_attestation_with_jwks(
            &token,
            "https://wrong.client/oauth/client-metadata.json",
            space_host_service,
            &jwks
        )
        .is_err(),
        "Wrong client_id must be rejected"
    );

    // 4d. Wrong kid
    let wrong_kid_jwks = JwksResponse {
        keys: vec![PublicKeyJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: jwk.x.clone(),
            y: jwk.y.clone(),
            kid: Some("wrong-kid-123".into()),
        }],
    };
    assert!(
        verify_client_attestation_with_jwks(
            &token,
            expected_client_id,
            space_host_service,
            &wrong_kid_jwks
        )
        .is_err(),
        "Mismatched kid must be rejected"
    );
}
#[sqlx::test(migrations = "./migrations")]
async fn key_rotation_with_curve_change_and_controllable_upstream(pool: PgPool) {
    let setup = setup_test(pool).await;

    let rotated_did = "did:web:rotating-authority.example.com";
    let public_socket: SocketAddr = "93.184.216.34:443".parse().unwrap();

    // Key A: Initial active key is P-256
    let key_a = p256::ecdsa::SigningKey::random(&mut OsRng);
    let vk_a = key_a.verifying_key();
    let point_a = EncodedPoint::from(vk_a);
    let x_a = URL_SAFE_NO_PAD.encode(point_a.x().unwrap());
    let y_a = URL_SAFE_NO_PAD.encode(point_a.y().unwrap());

    let doc_a = DidDocument {
        id: rotated_did.into(),
        verification_method: vec![VerificationMethod {
            id: format!("{}#atproto", rotated_did),
            r#type: "JsonWebKey2020".into(),
            controller: rotated_did.into(),
            public_key_jwk: Some(PublicKeyJwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x: x_a,
                y: Some(y_a),
                kid: None,
            }),
            public_key_multibase: None,
        }],
        service: vec![],
    };

    let mock_transport = Arc::new(ControllableMockDidWebTransport::new(doc_a, public_socket));
    let resolver = Arc::new(DidResolver::with_transport(
        "https://plc.directory".into(),
        reqwest::Client::new(),
        mock_transport.clone(),
    ));

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circles"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
        commit_verification_policy: circle_appview::commit::CommitVerificationPolicy::default(),
    };
    let app_state = AppState::with_did_resolver(config, setup.pool.clone(), resolver);
    let app = create_router(app_state);

    // 1. Initial request with Key A (P-256 / ES256) -> succeeds, performs exactly 1 fetch
    let token_a1 = create_service_token(
        &key_a,
        rotated_did,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-key-a-1",
        60,
        None,
    );
    let resp_a1 = request_feed(&app, &token_a1).await;
    assert_eq!(
        resp_a1.status(),
        StatusCode::OK,
        "Key A token must succeed before rotation"
    );
    assert_eq!(
        mock_transport.fetch_count(),
        1,
        "First request must perform exactly 1 fetch"
    );

    // 2. Second request with Key A -> cached hit, does NOT perform an extra fetch
    let token_a2 = create_service_token(
        &key_a,
        rotated_did,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-key-a-2",
        60,
        None,
    );
    let resp_a2 = request_feed(&app, &token_a2).await;
    assert_eq!(
        resp_a2.status(),
        StatusCode::OK,
        "Key A token must succeed from cache"
    );
    assert_eq!(
        mock_transport.fetch_count(),
        1,
        "Cached request must not trigger redundant fetch"
    );

    // 3. Upstream rotation: DID rotates to Key B (secp256k1 / ES256K)
    let key_b = k256::ecdsa::SigningKey::random(&mut OsRng);
    let secp_vk = key_b.verifying_key();
    let secp_sec1 = secp_vk.to_encoded_point(true);
    let mut secp_multikey_bytes = vec![0xe7, 0x01];
    secp_multikey_bytes.extend_from_slice(secp_sec1.as_bytes());
    let secp_multikey = multibase::encode(multibase::Base::Base58Btc, &secp_multikey_bytes);

    let doc_b = DidDocument {
        id: rotated_did.into(),
        verification_method: vec![VerificationMethod {
            id: format!("{}#atproto", rotated_did),
            r#type: "Multikey".into(),
            controller: rotated_did.into(),
            public_key_jwk: None,
            public_key_multibase: Some(secp_multikey),
        }],
        service: vec![],
    };
    mock_transport.set_doc(doc_b);

    // Fresh token signed by Key B with alg "ES256K" -> initial verify fails cached P-256 doc,
    // resolves fresh doc B, validates algorithm against fresh secp256k1 key, and succeeds!
    let now = Utc::now().timestamp();
    let header_b = json!({
        "typ": "JWT",
        "alg": "ES256K",
        "kid": "#atproto"
    });
    let claims_b = json!({
        "iss": rotated_did,
        "aud": CIRCLE_AUDIENCE,
        "lxm": "blue.catbird.circle.getFeed",
        "jti": "jti-key-b-1",
        "iat": now,
        "exp": now + 60
    });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_b).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims_b).unwrap());
    let input_b = format!("{h_b64}.{c_b64}");
    let sig_b: k256::ecdsa::Signature = key_b.sign(input_b.as_bytes());
    let token_b = format!("{input_b}.{}", URL_SAFE_NO_PAD.encode(sig_b.to_bytes()));

    let resp_b = request_feed(&app, &token_b).await;
    assert_eq!(
        resp_b.status(),
        StatusCode::OK,
        "Key B (ES256K) token must succeed after rotation"
    );
    assert_eq!(
        mock_transport.fetch_count(),
        2,
        "Key rotation must trigger fresh resolution"
    );
    // Cooldown expires before next resolution
    tokio::time::sleep(std::time::Duration::from_millis(5100)).await;
    // 4. Token signed by retired Key A -> initial verify fails cached doc B, resolves fresh doc B,
    // Key A is not in fresh doc, fails with 401 UNAUTHORIZED!
    let token_a_retired = create_service_token(
        &key_a,
        rotated_did,
        CIRCLE_AUDIENCE,
        "blue.catbird.circle.getFeed",
        "jti-key-a-3",
        60,
        None,
    );
    let resp_a_retired = request_feed(&app, &token_a_retired).await;
    assert_eq!(
        resp_a_retired.status(),
        StatusCode::UNAUTHORIZED,
        "Retired Key A token must be rejected within SLO"
    );
    assert_eq!(
        mock_transport.fetch_count(),
        3,
        "Retired key token must trigger fresh resolution before rejection"
    );
}

#[tokio::test]
async fn transport_ssrf_and_redirect_denial_suite() {
    use circle_appview::space_client::{DefaultSpaceHostTransport, SpaceHostDnsResolver};

    let prod_transport = DefaultSpaceHostTransport::new();

    // 1. Non-HTTPS (HTTP) scheme -> rejected immediately before any connection or proof
    let http_url = url::Url::parse("http://example.com/xrpc/endpoint").unwrap();
    let res_http = prod_transport.build_pinned_client(&http_url).await;
    assert!(res_http.is_err(), "HTTP URL must be rejected");

    // 2. Private IPv4 host -> rejected
    let private_v4_url = url::Url::parse("https://10.0.0.1/oauth/token").unwrap();
    let res_v4 = prod_transport.build_pinned_client(&private_v4_url).await;
    assert!(res_v4.is_err(), "Private IPv4 URL must be rejected");

    // 3. Loopback 127.0.0.1 -> rejected
    let loopback_url = url::Url::parse("https://127.0.0.1:8080/oauth/token").unwrap();
    let res_loop = prod_transport.build_pinned_client(&loopback_url).await;
    assert!(
        res_loop.is_err(),
        "Loopback IPv4 must be rejected in prod transport"
    );

    // 4. Localhost hostname -> rejected
    let localhost_url = url::Url::parse("https://localhost:443/oauth/token").unwrap();
    let res_lh = prod_transport.build_pinned_client(&localhost_url).await;
    assert!(
        res_lh.is_err(),
        "Localhost hostname must be rejected in prod transport"
    );

    // 5. Mixed DNS answers (one public, one private) -> rejected as SSRF
    struct MixedDnsResolver;
    impl SpaceHostDnsResolver for MixedDnsResolver {
        fn resolve_dns<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, AuthReason>> + Send + 'a>>
        {
            Box::pin(async move {
                Ok(vec![
                    "93.184.216.34:443".parse().unwrap(),
                    "192.168.1.1:443".parse().unwrap(),
                ])
            })
        }
    }
    let mixed_transport = DefaultSpaceHostTransport::with_dns_resolver(Arc::new(MixedDnsResolver));
    let target = url::Url::parse("https://mixed-dns.example.com/oauth/token").unwrap();
    let res_mixed = mixed_transport.build_pinned_client(&target).await;
    assert!(
        res_mixed.is_err(),
        "Mixed DNS answer containing private IP must be rejected"
    );
}

#[tokio::test]
async fn bounded_response_reader_enforces_limits_and_aggregate_budget() {
    use circle_appview::auth::read_bounded_response_bytes;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    // 1. Response with Content-Length exceeding limit -> rejected immediately without chunk download
    Mock::given(method("GET"))
        .and(path("/oversized-content-length"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 10 * 1024 * 1024]))
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let resp1 = client
        .get(format!("{}/oversized-content-length", mock_server.uri()))
        .send()
        .await
        .unwrap();

    let res1 = read_bounded_response_bytes(resp1, 256 * 1024).await;
    assert!(res1.is_err(), "Oversized Content-Length must be rejected");
    assert!(res1.unwrap_err().to_string().contains("exceeds limit"));

    // 2. Chunked body exceeding limit -> stopped and rejected during streaming
    let large_body = vec![b'A'; 300 * 1024]; // 300 KiB > 256 KiB limit
    Mock::given(method("GET"))
        .and(path("/oversized-body"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(large_body))
        .mount(&mock_server)
        .await;

    let resp2 = client
        .get(format!("{}/oversized-body", mock_server.uri()))
        .send()
        .await
        .unwrap();

    let res2 = read_bounded_response_bytes(resp2, 256 * 1024).await;
    assert!(res2.is_err(), "Oversized chunked body must be rejected");
    let err_msg = res2.unwrap_err().to_string();
    assert!(err_msg.contains("exceeded maximum allowed size") || err_msg.contains("exceeds limit"));
}

#[sqlx::test(migrations = "./migrations")]
async fn jti_cleanup_production_task_and_shutdown_lifecycle(pool: PgPool) {
    use circle_appview::spawn_jti_cleanup_task;
    db::run_migrations(&pool).await.unwrap();

    let unexpired_jti = "jti-active-prod-future";
    let expired_jti = "jti-expired-prod-past";

    let now = Utc::now();
    let future_exp = now + chrono::Duration::seconds(300);
    let past_exp = now - chrono::Duration::seconds(300);

    // Insert active unexpired JTI
    let res1 = db::consume_jti_nonce(
        &pool,
        unexpired_jti,
        "did:plc:alice",
        CIRCLE_AUDIENCE,
        future_exp,
    )
    .await
    .unwrap();
    assert!(res1, "Insert unexpired JTI");

    // Insert expired JTI
    let res2 = db::consume_jti_nonce(
        &pool,
        expired_jti,
        "did:plc:alice",
        CIRCLE_AUDIENCE,
        past_exp,
    )
    .await
    .unwrap();
    assert!(res2, "Insert expired JTI");

    // Spawn production background cleanup task with 20ms interval
    let (jti_handle, shutdown_tx) =
        spawn_jti_cleanup_task(pool.clone(), std::time::Duration::from_millis(20));

    // Wait 80ms for at least a few ticks to complete
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // Verify active JTI is STILL present and replay is blocked
    let replay = db::consume_jti_nonce(
        &pool,
        unexpired_jti,
        "did:plc:alice",
        CIRCLE_AUDIENCE,
        future_exp,
    )
    .await
    .unwrap();
    assert!(!replay, "Active JTI must still be present and block replay");

    // Verify expired JTI was cleaned up
    let reinserted = db::consume_jti_nonce(
        &pool,
        expired_jti,
        "did:plc:alice",
        CIRCLE_AUDIENCE,
        future_exp,
    )
    .await
    .unwrap();
    assert!(
        reinserted,
        "Expired JTI must have been cleaned up and can be consumed fresh"
    );

    // Signal shutdown and ensure task terminates promptly
    let _ = shutdown_tx.send(true);
    let join_res = tokio::time::timeout(std::time::Duration::from_secs(2), jti_handle).await;
    assert!(
        join_res.is_ok(),
        "JTI cleanup task must join promptly on shutdown signal"
    );
}

struct FixtureDnsResolver {
    addr: SocketAddr,
}

impl circle_appview::space_client::SpaceHostDnsResolver for FixtureDnsResolver {
    fn resolve_dns<'a>(
        &'a self,
        _host: &'a str,
        _port: u16,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Vec<SocketAddr>, circle_appview::error::AuthReason>>
                + Send
                + 'a,
        >,
    > {
        let res = vec![self.addr];
        Box::pin(async move { Ok(res) })
    }
}

struct MapFixtureDnsResolver {
    hosts: std::collections::HashMap<String, SocketAddr>,
    default_addr: SocketAddr,
}

impl circle_appview::space_client::SpaceHostDnsResolver for MapFixtureDnsResolver {
    fn resolve_dns<'a>(
        &'a self,
        host: &'a str,
        _port: u16,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Vec<SocketAddr>, circle_appview::error::AuthReason>>
                + Send
                + 'a,
        >,
    > {
        let addr = self.hosts.get(host).copied().unwrap_or(self.default_addr);
        Box::pin(async move { Ok(vec![addr]) })
    }
}

struct TlsOAuthFixture {
    #[allow(dead_code)]
    pub port: u16,
    pub addr: SocketAddr,
    pub cert: reqwest::Certificate,
    pub base_url: String,
    pub requests: Arc<parking_lot::Mutex<Vec<(String, String)>>>,
    pub dns_resolver: Arc<dyn circle_appview::space_client::SpaceHostDnsResolver>,
}

impl TlsOAuthFixture {
    async fn spawn(
        hostname: &str,
        endpoints: std::collections::HashMap<String, (u16, String)>,
    ) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let params = rcgen::CertificateParams::new(vec![
            hostname.to_string(),
            "127.0.0.1".to_string(),
            "localhost".to_string(),
            "did-web.example.org".to_string(),
            "pds.example.com".to_string(),
            "attacker.example.com".to_string(),
            "auth.example.com".to_string(),
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
        let addr = listener.local_addr().unwrap();
        let base_url = format!("https://{}:{}", hostname, addr.port());

        let requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let requests_clone = requests.clone();
        let endpoints = Arc::new(endpoints);

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let reqs = requests_clone.clone();
                let eps = endpoints.clone();
                tokio::spawn(async move {
                    let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = [0u8; 8192];
                    let Ok(n) = tokio::io::AsyncReadExt::read(&mut tls_stream, &mut buf).await
                    else {
                        return;
                    };
                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line = req_str.lines().next().unwrap_or_default();
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    let method = parts.first().copied().unwrap_or_default().to_string();
                    let path = parts.get(1).copied().unwrap_or_default().to_string();
                    reqs.lock().push((method, path.clone()));

                    let (status, body) = if let Some((st, b)) = eps.get(&path) {
                        (*st, b.clone())
                    } else {
                        (404, r#"{"error":"not_found"}"#.to_string())
                    };

                    let response = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut tls_stream, response.as_bytes())
                            .await;
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls_stream).await;
                });
            }
        });

        let reqwest_cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
        let dns_resolver = Arc::new(FixtureDnsResolver { addr });

        Self {
            port: addr.port(),
            addr,
            cert: reqwest_cert,
            base_url,
            requests,
            dns_resolver,
        }
    }

    pub fn transport(&self) -> Arc<circle_appview::space_client::DefaultSpaceHostTransport> {
        Arc::new(
            circle_appview::space_client::DefaultSpaceHostTransport::with_test_fixture(
                self.dns_resolver.clone(),
                Some(self.cert.clone()),
                true, // allow loopback in tests
            ),
        )
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn oauth_callback_preserves_victim_session_and_enforces_subject_binding(pool: PgPool) {
    use circle_appview::oauth::{OAuthService, PendingOAuthState, UserOAuthSession};

    db::run_migrations(&pool).await.unwrap();

    let victim_did = "did:plc:victim-user-account";
    let attacker_did = "did:plc:attacker-user-account";
    let alice_did = "did:plc:alice-legit-user";
    let bob_did = "did:plc:bob-absent-sub-user";

    let mut endpoints = std::collections::HashMap::new();
    endpoints.insert(
        "/oauth/token".to_string(),
        (200, format!(r#"{{"access_token":"attacker-injected-token","refresh_token":"attacker-injected-refresh","expires_in":3600,"sub":"{victim_did}"}}"#)),
    );
    endpoints.insert(
        "/oauth/token-alice".to_string(),
        (200, format!(r#"{{"access_token":"alice-access-token","refresh_token":"alice-refresh-token","expires_in":3600,"sub":"{alice_did}"}}"#)),
    );
    endpoints.insert(
        "/oauth/token-bob".to_string(),
        (200, r#"{"access_token":"bob-access-token","refresh_token":"bob-refresh-token","expires_in":3600}"#.to_string()),
    );
    let fixture = TlsOAuthFixture::spawn("auth.example.com", endpoints).await;

    let transport = fixture.transport();
    let service = OAuthService::with_transport(
        pool.clone(),
        "http://127.0.0.1:3002".to_string(),
        p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
        None,
        transport,
    );
    let http_client = reqwest::Client::new();

    // Pre-seed an existing active session for the victim user
    let victim_dpop_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let victim_session = UserOAuthSession {
        user_did: victim_did.to_string(),
        access_token: "victim-original-access-token-123".to_string(),
        refresh_token: Some("victim-original-refresh-token-456".to_string()),
        token_endpoint: format!("{}/oauth/token", fixture.base_url),
        auth_server_iss: fixture.base_url.clone(),
        expires_at: Some(Utc::now() + chrono::Duration::seconds(3600)),
        scope: "blue.catbird.circle".to_string(),
        dpop_key: victim_dpop_key.clone(),
    };
    service.store_session(victim_session).await.unwrap();

    // 1. Attacker initiates authorization flow with their own DID, but token endpoint returns victim DID
    let state_attack = "state-attack-mismatch-1".to_string();
    let pending_attack = PendingOAuthState {
        state: state_attack.clone(),
        code_verifier: "verifier-attack-1".to_string(),
        user_did: attacker_did.to_string(),
        pds_endpoint: fixture.base_url.clone(),
        token_endpoint: format!("{}/oauth/token", fixture.base_url),
        auth_server_iss: Some(fixture.base_url.clone()),
        created_at: Utc::now(),
        in_flight: false,
    };
    service
        .pending_states
        .write()
        .insert(state_attack.clone(), pending_attack);

    let res = service
        .handle_callback("auth-code-attack", &state_attack, &http_client)
        .await;
    assert!(
        res.is_err(),
        "Callback must reject token response with mismatched subject DID"
    );

    // Verify victim's preseeded session was NOT modified and is byte-identical
    let loaded_victim = service
        .get_session(victim_did)
        .await
        .unwrap()
        .expect("Victim session must exist");
    assert_eq!(
        loaded_victim.access_token, "victim-original-access-token-123",
        "Victim access token must be preserved"
    );
    assert_eq!(
        loaded_victim.refresh_token.as_deref(),
        Some("victim-original-refresh-token-456"),
        "Victim refresh token must be preserved"
    );

    // 2. Legitimate matching `sub` succeeds and does not touch victim
    let state_alice = "state-alice-matching-2".to_string();
    let pending_alice = PendingOAuthState {
        state: state_alice.clone(),
        code_verifier: "verifier-alice-2".to_string(),
        user_did: alice_did.to_string(),
        pds_endpoint: fixture.base_url.clone(),
        token_endpoint: format!("{}/oauth/token-alice", fixture.base_url),
        auth_server_iss: Some(fixture.base_url.clone()),
        created_at: Utc::now(),
        in_flight: false,
    };
    service
        .pending_states
        .write()
        .insert(state_alice.clone(), pending_alice);

    let res_alice = service
        .handle_callback("auth-code-alice", &state_alice, &http_client)
        .await;
    assert!(res_alice.is_ok(), "Matching sub callback must succeed");

    let loaded_alice = service
        .get_session(alice_did)
        .await
        .unwrap()
        .expect("Alice session must exist");
    assert_eq!(loaded_alice.access_token, "alice-access-token");

    // 3. Absent `sub` (None) succeeds and uses pending user_did
    let state_bob = "state-bob-absent-sub-3".to_string();
    let pending_bob = PendingOAuthState {
        state: state_bob.clone(),
        code_verifier: "verifier-bob-3".to_string(),
        user_did: bob_did.to_string(),
        pds_endpoint: fixture.base_url.clone(),
        token_endpoint: format!("{}/oauth/token-bob", fixture.base_url),
        auth_server_iss: Some(fixture.base_url.clone()),
        created_at: Utc::now(),
        in_flight: false,
    };
    service
        .pending_states
        .write()
        .insert(state_bob.clone(), pending_bob);

    let res_bob = service
        .handle_callback("auth-code-bob", &state_bob, &http_client)
        .await;
    assert!(
        res_bob.is_ok(),
        "Absent sub callback must succeed and bind to pending user_did"
    );

    let loaded_bob = service
        .get_session(bob_did)
        .await
        .unwrap()
        .expect("Bob session must exist");
    assert_eq!(loaded_bob.access_token, "bob-access-token");
}

#[sqlx::test(migrations = "./migrations")]
async fn oauth_provider_origin_mismatch_and_proof_header_absence(pool: PgPool) {
    use circle_appview::oauth::{OAuthService, PendingOAuthState, UserOAuthSession};
    use circle_appview::space_client::DefaultSpaceHostTransport;

    db::run_migrations(&pool).await.unwrap();

    let attacker_fixture =
        TlsOAuthFixture::spawn("attacker.example.com", std::collections::HashMap::new()).await;

    let mut pds_endpoints = std::collections::HashMap::new();
    pds_endpoints.insert(
        "/.well-known/oauth-protected-resource".to_string(),
        (
            200,
            serde_json::json!({
                "resource": attacker_fixture.base_url,
                "authorization_servers": ["https://pds.example.com:443"]
            })
            .to_string(),
        ),
    );
    let pds_fixture = TlsOAuthFixture::spawn("pds.example.com", pds_endpoints).await;

    let mut host_map = std::collections::HashMap::new();
    host_map.insert("pds.example.com".to_string(), pds_fixture.addr);
    host_map.insert("attacker.example.com".to_string(), attacker_fixture.addr);
    let multi_resolver = Arc::new(MapFixtureDnsResolver {
        hosts: host_map,
        default_addr: pds_fixture.addr,
    });
    let transport = Arc::new(DefaultSpaceHostTransport::with_test_fixture(
        multi_resolver,
        Some(pds_fixture.cert.clone()),
        true,
    ));
    let service = OAuthService::with_transport(
        pool.clone(),
        "http://127.0.0.1:3002".to_string(),
        p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
        None,
        transport,
    );
    let http_client = reqwest::Client::new();

    // 1. Protected resource metadata with mismatched resource origin -> start_flow rejected
    let did_resolver = DidResolver::new("https://plc.directory".into(), http_client.clone());
    let doc = DidDocument {
        id: "did:plc:alice-provider-test".into(),
        verification_method: vec![],
        service: vec![circle_appview::auth::DidService {
            id: "#atproto_pds".into(),
            r#type: "AtprotoPersonalDataServer".into(),
            service_endpoint: pds_fixture.base_url.clone(),
        }],
    };
    did_resolver.insert_cached("did:plc:alice-provider-test".into(), doc);

    let flow_res = service
        .start_flow("did:plc:alice-provider-test", &did_resolver, &http_client)
        .await;
    assert!(
        flow_res.is_err(),
        "Start flow must reject protected resource with mismatched resource origin"
    );

    // 2. Callback with token_endpoint pointing to attacker origin -> rejected before client assertion/proof is sent
    let state_attack = "state-token-origin-mismatch".to_string();
    let pending_attack = PendingOAuthState {
        state: state_attack.clone(),
        code_verifier: "verifier-origin-mismatch".to_string(),
        user_did: "did:plc:alice-provider-test".to_string(),
        pds_endpoint: pds_fixture.base_url.clone(),
        token_endpoint: format!("{}/oauth/token-attacker", attacker_fixture.base_url),
        auth_server_iss: Some(pds_fixture.base_url.clone()),
        created_at: Utc::now(),
        in_flight: false,
    };
    service
        .pending_states
        .write()
        .insert(state_attack.clone(), pending_attack);

    let cb_res = service
        .handle_callback("auth-code", &state_attack, &http_client)
        .await;
    assert!(
        cb_res.is_err(),
        "Callback must reject token endpoint on foreign origin before assertion creation"
    );
    assert_eq!(
        attacker_fixture.requests.lock().len(),
        0,
        "Attacker server must NEVER receive any request or proof headers"
    );

    // 3. Token refresh with token_endpoint pointing to attacker origin -> rejected before assertion is sent
    let session_attack = UserOAuthSession {
        user_did: "did:plc:alice-refresh-attack".to_string(),
        access_token: "old-access-token".to_string(),
        refresh_token: Some("old-refresh-token".to_string()),
        token_endpoint: format!("{}/oauth/token-attacker", attacker_fixture.base_url),
        auth_server_iss: pds_fixture.base_url.clone(),
        expires_at: Some(Utc::now() - chrono::Duration::seconds(100)), // expired
        scope: "blue.catbird.circle".to_string(),
        dpop_key: p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
    };
    service.store_session(session_attack).await.unwrap();

    let refresh_res = service
        .get_valid_token("did:plc:alice-refresh-attack", &http_client)
        .await;
    assert!(
        refresh_res.is_err(),
        "Refresh must reject token endpoint on foreign origin before assertion creation"
    );
    assert_eq!(
        attacker_fixture.requests.lock().len(),
        0,
        "Attacker server must NEVER receive any request or proof headers during refresh"
    );
}

#[tokio::test]
async fn aggregate_byte_budget_drop_guard_and_concurrency() {
    use circle_appview::auth::{current_aggregate_public_bytes, read_bounded_response_bytes};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let initial_bytes = current_aggregate_public_bytes();
    assert_eq!(initial_bytes, 0, "Initial aggregate bytes must be 0");

    let large_body = vec![b'A'; 100 * 1024]; // 100 KiB
    Mock::given(method("GET"))
        .and(path("/large-body"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(large_body.clone()))
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();

    // 1. Successful read decrements guard back to 0
    let resp = client
        .get(format!("{}/large-body", mock_server.uri()))
        .send()
        .await
        .unwrap();
    let body = read_bounded_response_bytes(resp, 200 * 1024).await.unwrap();
    assert_eq!(body.len(), 100 * 1024);
    assert_eq!(
        current_aggregate_public_bytes(),
        initial_bytes,
        "Aggregate bytes must return to baseline after success"
    );

    // 2. Cancellation/drop releases reservation immediately
    let resp2 = client
        .get(format!("{}/large-body", mock_server.uri()))
        .send()
        .await
        .unwrap();
    {
        let mut future = Box::pin(read_bounded_response_bytes(resp2, 200 * 1024));
        // Poll once with a noop waker to trigger the initial chunk read and budget acquisition
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let _ = future.as_mut().poll(&mut cx);
        // Drop future mid-flight
        drop(future);
    }
    assert_eq!(
        current_aggregate_public_bytes(),
        initial_bytes,
        "Aggregate bytes must return to baseline after future drop"
    );
    // 3. Content-Length larger than max_bytes is rejected before reading
    Mock::given(method("GET"))
        .and(path("/oversized-content-length"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'B'; 1048576]))
        .mount(&mock_server)
        .await;

    let resp3 = client
        .get(format!("{}/oversized-content-length", mock_server.uri()))
        .send()
        .await
        .unwrap();
    let res3 = read_bounded_response_bytes(resp3, 512 * 1024).await;
    assert!(
        res3.is_err(),
        "Oversized Content-Length must be rejected immediately"
    );
    assert_eq!(current_aggregate_public_bytes(), initial_bytes);
}

#[sqlx::test(migrations = "./migrations")]
async fn jti_concurrent_exactly_once_insertion_and_backlog_drain(pool: PgPool) {
    db::run_migrations(&pool).await.unwrap();

    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(300);
    let jti = "jti-concurrent-test-exact-once";

    // 1. Concurrent exactly-once insertion across 50 concurrent tasks for duplicate JTI
    let mut handles = Vec::new();
    for _ in 0..50 {
        let p = pool.clone();
        let j = jti.to_string();
        handles.push(tokio::spawn(async move {
            db::consume_jti_nonce(&p, &j, "did:plc:concurrent-tester", CIRCLE_AUDIENCE, exp)
                .await
                .unwrap()
        }));
    }

    let mut successes = 0;
    for h in handles {
        if h.await.unwrap() {
            successes += 1;
        }
    }
    assert_eq!(
        successes, 1,
        "Exactly one concurrent insertion must succeed for duplicate JTI"
    );

    // 2. Concurrent distinct JTIs for same issuer under advisory lock
    // Pre-insert 990 active nonces for the issuer
    let issuer_concurrent = "did:plc:concurrent-issuer-advisory-lock";
    for i in 0..990 {
        let res = db::consume_jti_nonce(
            &pool,
            &format!("jti-preseed-{i}"),
            issuer_concurrent,
            CIRCLE_AUDIENCE,
            exp,
        )
        .await
        .unwrap();
        assert!(res);
    }
    // Now spawn 50 concurrent tasks attempting to insert 50 distinct JTIs for this issuer
    let mut distinct_handles = Vec::new();
    for i in 0..50 {
        let p = pool.clone();
        let j = format!("jti-race-{i}");
        distinct_handles.push(tokio::spawn(async move {
            db::consume_jti_nonce(&p, &j, issuer_concurrent, CIRCLE_AUDIENCE, exp)
                .await
                .unwrap()
        }));
    }
    let mut distinct_successes = 0;
    for h in distinct_handles {
        if h.await.unwrap() {
            distinct_successes += 1;
        }
    }
    assert_eq!(
        distinct_successes, 10,
        "Under advisory lock, exactly 10 nonces can be admitted up to limit 1000"
    );

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM auth_jti_nonce WHERE issuer_did = $1")
        .bind(issuer_concurrent)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count.0, 1000,
        "Active nonces for issuer must never exceed 1000"
    );

    // 3. Backlog drain beyond 50 batches: insert 55 batches of 100 expired nonces = 5,500 rows
    let past_exp = now - chrono::Duration::seconds(600);
    for batch in 0..55 {
        let mut query_builder = sqlx::QueryBuilder::new(
            "INSERT INTO auth_jti_nonce (jti, issuer_did, audience, expires_at, consumed_at) ",
        );
        let items: Vec<(String, String, String, DateTime<Utc>)> = (0..100)
            .map(|i| {
                (
                    format!("jti-backlog-55batch-{batch}-{i}"),
                    format!("did:plc:backlog-55b-{batch}-{i}"),
                    CIRCLE_AUDIENCE.to_string(),
                    past_exp,
                )
            })
            .collect();

        query_builder.push_values(items, |mut b, item| {
            b.push_bind(item.0)
                .push_bind(item.1)
                .push_bind(item.2)
                .push_bind(item.3)
                .push("now()");
        });
        query_builder.build().execute(&pool).await.unwrap();
    }

    // Drain all expired nonces across 55 batches using batch_size=100 (which is >50 batches)
    let deleted = db::cleanup_expired_nonces_drain(&pool, 100, 0)
        .await
        .unwrap();
    assert_eq!(
        deleted, 5500,
        "Cleanup must drain entire 55-batch expired backlog beyond 50 batch boundary"
    );

    // 4. Bounded per-issuer admission limit (MAX_ACTIVE_JTIS_PER_ISSUER = 1000)
    let issuer = "did:plc:rate-limited-issuer";
    for i in 0..1000 {
        let res = db::consume_jti_nonce(
            &pool,
            &format!("jti-issuer-limit-{i}"),
            issuer,
            CIRCLE_AUDIENCE,
            exp,
        )
        .await
        .unwrap();
        assert!(res, "Nonce {i} under issuer limit must be consumed");
    }

    // 1001st nonce must be rejected due to per-issuer active limit
    let overflow =
        db::consume_jti_nonce(&pool, "jti-issuer-limit-1001", issuer, CIRCLE_AUDIENCE, exp)
            .await
            .unwrap();
    assert!(
        !overflow,
        "Nonce exceeding MAX_ACTIVE_JTIS_PER_ISSUER must be rejected"
    );

    // Other legitimate issuer must NOT be starved by the rate-limited issuer
    let other_issuer = "did:plc:other-legitimate-issuer";
    let other_res = db::consume_jti_nonce(
        &pool,
        "jti-other-issuer-1",
        other_issuer,
        CIRCLE_AUDIENCE,
        exp,
    )
    .await
    .unwrap();
    assert!(other_res, "Legitimate issuer must not be starved");
}

#[tokio::test]
async fn space_authenticated_transfers_succeed_and_bypass_public_budget_while_public_flow_rejects_abuse(
) {
    use circle_appview::auth::{
        read_bounded_authenticated_response_bytes, read_bounded_public_response_bytes,
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    // 1. Legal 50 MiB CAR file transfer succeeds under AuthenticatedSpace budget
    let car_50mb = vec![0xCA; 50 * 1024 * 1024]; // 50 MiB
    Mock::given(method("GET"))
        .and(path("/legal-50mb-car"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(car_50mb.clone()))
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let resp_car = client
        .get(format!("{}/legal-50mb-car", mock_server.uri()))
        .send()
        .await
        .unwrap();

    let car_bytes = read_bounded_authenticated_response_bytes(resp_car, 50 * 1024 * 1024)
        .await
        .expect("50 MiB CAR transfer must succeed under AuthenticatedSpace budget");
    assert_eq!(car_bytes.len(), 50 * 1024 * 1024);

    // 2. Legal 20 MiB blob transfer succeeds under AuthenticatedSpace budget
    let blob_20mb = vec![0xBB; 20 * 1024 * 1024]; // 20 MiB
    Mock::given(method("GET"))
        .and(path("/legal-20mb-blob"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(blob_20mb.clone()))
        .mount(&mock_server)
        .await;

    let resp_blob = client
        .get(format!("{}/legal-20mb-blob", mock_server.uri()))
        .send()
        .await
        .unwrap();

    let blob_bytes = read_bounded_authenticated_response_bytes(resp_blob, 20 * 1024 * 1024)
        .await
        .expect("20 MiB blob transfer must succeed under AuthenticatedSpace budget");
    assert_eq!(blob_bytes.len(), 20 * 1024 * 1024);

    // 3. Public flow budget (16 MiB max aggregate) rejects aggregate abuse
    let chunk_10mb = vec![0xAA; 10 * 1024 * 1024]; // 10 MiB
    Mock::given(method("GET"))
        .and(path("/public-chunk-1"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(chunk_10mb.clone()))
        .mount(&mock_server)
        .await;

    // First 10 MiB public flow read succeeds (10 MiB <= 16 MiB)
    let resp_pub1 = client
        .get(format!("{}/public-chunk-1", mock_server.uri()))
        .send()
        .await
        .unwrap();
    let pub1_res = read_bounded_public_response_bytes(resp_pub1, 15 * 1024 * 1024).await;
    assert!(
        pub1_res.is_ok(),
        "Single 10 MiB public flow within 16 MiB budget must succeed"
    );

    // Single public response larger than 16 MiB aggregate limit is rejected
    let resp_pub_oversized = client
        .get(format!("{}/legal-20mb-blob", mock_server.uri()))
        .send()
        .await
        .unwrap();
    let pub_oversized_res =
        read_bounded_public_response_bytes(resp_pub_oversized, 25 * 1024 * 1024).await;
    assert!(
        pub_oversized_res.is_err(),
        "20 MiB public transfer must be rejected by 16 MiB aggregate public budget"
    );
    let err_str = pub_oversized_res.err().unwrap().to_string();
    assert!(
        err_str.contains("Aggregate public flow byte budget"),
        "Error message must indicate aggregate public budget exceeded: {err_str}"
    );
}

#[tokio::test]
async fn resolve_fresh_cooldown_and_concurrency_bounds() {
    use circle_appview::auth::{DidDocument, DidResolver, DidWebTransport};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingMockDidWebTransport {
        fetch_count: Arc<AtomicUsize>,
    }

    impl DidWebTransport for CountingMockDidWebTransport {
        fn resolve_dns<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            Vec<std::net::SocketAddr>,
                            circle_appview::error::AuthReason,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move { Ok(vec!["1.1.1.1:443".parse().unwrap()]) })
        }

        fn fetch<'a>(
            &'a self,
            url: &'a str,
            _host: &'a str,
            _pinned_addr: std::net::SocketAddr,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<DidDocument, circle_appview::error::AuthReason>>
                    + Send
                    + 'a,
            >,
        > {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            let did_str = if url.contains("cooldown.example.com") {
                "did:web:cooldown.example.com".to_string()
            } else {
                "did:web:example.com".to_string()
            };
            Box::pin(async move {
                Ok(DidDocument {
                    id: did_str,
                    verification_method: vec![],
                    service: vec![],
                })
            })
        }
    }
    let fetch_count = Arc::new(AtomicUsize::new(0));
    let mock_transport = Arc::new(CountingMockDidWebTransport {
        fetch_count: fetch_count.clone(),
    });

    let resolver = DidResolver::with_transport(
        "https://plc.directory".into(),
        reqwest::Client::new(),
        mock_transport,
    );

    let test_did = "did:web:cooldown.example.com";

    // First fresh resolution fetches from upstream
    let doc1 = resolver.resolve_fresh(test_did).await.unwrap();
    assert_eq!(doc1.id, test_did);
    assert_eq!(
        fetch_count.load(Ordering::SeqCst),
        1,
        "First resolve_fresh must query upstream"
    );

    // Immediate subsequent resolve_fresh calls within cooldown window return cached doc without upstream fetch
    for _ in 0..10 {
        let doc_cached = resolver.resolve_fresh(test_did).await.unwrap();
        assert_eq!(doc_cached.id, test_did);
    }
    assert_eq!(
        fetch_count.load(Ordering::SeqCst),
        1,
        "Subsequent resolve_fresh calls during cooldown must not generate upstream fetches"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn space_client_member_dids_and_get_space_keep_injected_fixture_transport(pool: PgPool) {
    use circle_appview::oauth::OAuthService;
    use circle_appview::space_client::{SpaceClient, SpaceClientDeps};

    db::run_migrations(&pool).await.unwrap();

    let mut endpoints = std::collections::HashMap::new();
    endpoints.insert(
        "/xrpc/com.atproto.simplespace.listMembers?space=at%3A%2F%2Fdid%3Aplc%3Aspace-auth%2Fspace%2Fpublic%2F1".to_string(),
        (200, serde_json::json!({
            "members": [{"did": "did:plc:member-1"}, {"did": "did:plc:member-2"}]
        }).to_string()),
    );
    endpoints.insert(
        "/xrpc/com.atproto.simplespace.getSpace?space=at%3A%2F%2Fdid%3Aplc%3Aspace-auth%2Fspace%2Fpublic%2F1".to_string(),
        (200, serde_json::json!({
            "authority": "did:plc:space-auth",
            "spaceType": "public",
            "name": "Test Space"
        }).to_string()),
    );
    let fixture = TlsOAuthFixture::spawn("pds.example.com", endpoints).await;

    let transport = fixture.transport();
    let space_client = SpaceClient::with_transport(transport.clone());

    let oauth_signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let oauth_service = Arc::new(OAuthService::with_transport(
        pool.clone(),
        "http://127.0.0.1:3002".to_string(),
        oauth_signing_key,
        None,
        transport.clone(),
    ));

    // Pre-seed an active session for the space authority
    let session = circle_appview::oauth::UserOAuthSession {
        user_did: "did:plc:space-auth".to_string(),
        access_token: "authority-valid-token".to_string(),
        refresh_token: None,
        token_endpoint: format!("{}/oauth/token", fixture.base_url),
        auth_server_iss: fixture.base_url.clone(),
        expires_at: Some(Utc::now() + chrono::Duration::seconds(3600)),
        scope: "blue.catbird.circle".to_string(),
        dpop_key: p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
    };
    oauth_service.store_session(session).await.unwrap();

    let did_resolver = DidResolver::new("https://plc.directory".into(), reqwest::Client::new());
    let doc = DidDocument {
        id: "did:plc:space-auth".into(),
        verification_method: vec![],
        service: vec![circle_appview::auth::DidService {
            id: "#atproto_pds".into(),
            r#type: "AtprotoPersonalDataServer".into(),
            service_endpoint: fixture.base_url.clone(),
        }],
    };
    did_resolver.insert_cached("did:plc:space-auth".into(), doc);

    space_client.set_deps(SpaceClientDeps {
        http_client: reqwest::Client::new(),
        did_resolver: Arc::new(did_resolver),
        oauth_service,
    });

    // 1. member_dids uses transport.build_pinned_client and succeeds over TLS with injected resolver/cert
    let members = space_client
        .member_dids("at://did:plc:space-auth/space/public/1")
        .await
        .unwrap();
    assert_eq!(members, vec!["did:plc:member-1", "did:plc:member-2"]);

    // 2. get_space uses transport.build_pinned_client and succeeds over TLS with injected resolver/cert
    let space_config = space_client
        .get_space("at://did:plc:space-auth/space/public/1")
        .await
        .unwrap();
    assert_eq!(space_config.name.as_deref(), Some("Test Space"));
}

#[tokio::test]
async fn did_resolver_last_fresh_resolution_capacity_bounding() {
    let did_resolver =
        DidResolver::with_capacity("https://plc.directory".into(), reqwest::Client::new(), 5);

    // Populate fresh resolutions
    for i in 0..10 {
        let did = format!("did:plc:flood-{i}");
        // Cache doc so resolve_fresh doesn't need network
        did_resolver.insert_cached(
            did.clone(),
            DidDocument {
                id: did.clone(),
                verification_method: vec![],
                service: vec![],
            },
        );
        let _ = did_resolver.resolve_fresh(&did).await;
    }

    // Capacity is 5, so fresh_resolution_count must be bounded by 5
    assert!(
        did_resolver.fresh_resolution_count() <= 5,
        "last_fresh_resolution must be bounded by capacity, got {}",
        did_resolver.fresh_resolution_count()
    );
}
