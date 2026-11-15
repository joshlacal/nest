//! Security regression suite for Catbird's authenticated Push Gateway (`D2`, `I12`, Spec §6.2).
//!
//! Verifies:
//! 1. Authorized `mls-ds` wake delivers `nest`-owned APNs `aps = {"alert": {"body": "New message"}, "mutable-content": 1}`
//!    + structured `catbird` payload with `apns-collapse-id = hex(SHA256(push_key || conversation_id))[..32]`,
//!    and binds `push_key` to the user's DID-resolved `#atproto_mls` service DID (including self-hosted DSes).
//! 2. Cross-DS `push_key` spoofing & enumeration: wrong `caller_ds_did` or unknown `push_key` returns uniform
//!    `202 Accepted`, sends `0` APNs/FCM calls, and increments `catbird_push_gateway_spoofed_caller_total`.
//! 3. Replay & body tampering protection: replaying the same `jti` within 60s or altering the body fails with `401`.
//! 4. Anti-phishing alert injection & `2200` B `I12` size bound: `ciphertext` of `2201` decoded bytes or any extra
//!    JSON display keys (`title`, `body`, `aps`, `alert`) fails with `400 InvalidRequest`.
//! 5. Dead-token zero-oracle rule: unregistered native token returns `410 Gone` to the authorized `mls-ds` and
//!    `202 Accepted` to any unauthorized `mls-ds`.
//! 6. Flood protection: per-`push_key` token bucket (burst `10`, `30/min`) drops excess wakes without exhausting
//!    Apple's push budget, and spoofed wakes from unauthorized DSes cannot drain a victim's `push_key` bucket.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use atproto_spaces::tokens::{SpaceSigningKey, SpaceVerifyingKey};
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    Extension, Json,
};
use base64::{
    engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD as BASE64URL},
    Engine as _,
};
use catbird::{
    handlers::push_gateway,
    models::CatbirdSession,
    services::push::gateway::{
        DispatchedGatewayPush, GatewayDeliveryOutcome, GatewayPlatform, MlsDsIdentityResolver,
        PushGatewayConfig, PushGatewayService, PushGatewayTransport,
    },
};
use catbird_atproto::generated::blue_catbird::push::register_key::{
    RegisterKey, RegisterKeyPlatform,
};
use chrono::Utc;
use p256::ecdsa::{
    signature::Signer as _, Signature as P256Signature, SigningKey as P256SigningKey,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Executor, PgPool, Row};
use tower::ServiceExt;
use uuid::Uuid;

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

#[derive(Clone, Default)]
struct SpyGatewayTransport {
    sent: Arc<Mutex<Vec<DispatchedGatewayPush>>>,
    next_outcome: Arc<Mutex<GatewayDeliveryOutcome>>,
}

impl SpyGatewayTransport {
    fn new() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
            next_outcome: Arc::new(Mutex::new(GatewayDeliveryOutcome::Delivered)),
        }
    }

    fn set_next_outcome(&self, outcome: GatewayDeliveryOutcome) {
        *self.next_outcome.lock().unwrap() = outcome;
    }

    fn sent_calls(&self) -> Vec<DispatchedGatewayPush> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl PushGatewayTransport for SpyGatewayTransport {
    async fn send(&self, push: DispatchedGatewayPush) -> anyhow::Result<GatewayDeliveryOutcome> {
        self.sent.lock().unwrap().push(push);
        Ok(*self.next_outcome.lock().unwrap())
    }
}

#[derive(Clone, Default)]
struct StaticDidResolver {
    user_mls_dids: Arc<Mutex<HashMap<String, String>>>,
    ds_keys: Arc<Mutex<HashMap<String, SpaceVerifyingKey>>>,
}

impl StaticDidResolver {
    fn with_entries(
        users: impl IntoIterator<Item = (&'static str, &'static str)>,
        ds_keys: impl IntoIterator<Item = (&'static str, SpaceVerifyingKey)>,
    ) -> Self {
        Self {
            user_mls_dids: Arc::new(Mutex::new(
                users
                    .into_iter()
                    .map(|(u, ds)| (u.to_string(), ds.to_string()))
                    .collect(),
            )),
            ds_keys: Arc::new(Mutex::new(
                ds_keys
                    .into_iter()
                    .map(|(ds, vk)| (ds.to_string(), vk))
                    .collect(),
            )),
        }
    }
}

#[async_trait::async_trait]
impl MlsDsIdentityResolver for StaticDidResolver {
    async fn resolve_user_mls_service_did(&self, account_did: &str) -> anyhow::Result<String> {
        self.user_mls_dids
            .lock()
            .unwrap()
            .get(account_did)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing #atproto_mls service for {account_did}"))
    }

    async fn resolve_ds_atproto_key(
        &self,
        caller_ds_did: &str,
        _force_refresh: bool,
    ) -> anyhow::Result<SpaceVerifyingKey> {
        self.ds_keys
            .lock()
            .unwrap()
            .get(caller_ds_did)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown caller_ds_did {caller_ds_did}"))
    }
}

fn sign_ds_wake_jwt(
    signing_key: &P256SigningKey,
    iss: &str,
    htu: &str,
    jti: &str,
    iat: i64,
    exp: i64,
    body_bytes: &[u8],
) -> String {
    let header = json!({
        "alg": "ES256",
        "typ": "atproto-push-wake+jwt",
        "kid": "#atproto",
    });
    let body_sha256 = hex_encode(&Sha256::digest(body_bytes));
    let claims = json!({
        "iss": iss,
        "htm": "POST",
        "htu": htu,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "body_sha256": body_sha256,
    });
    let hdr_b64 = BASE64URL.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = BASE64URL.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{hdr_b64}.{claims_b64}");
    let sig: P256Signature = signing_key.sign(signing_input.as_bytes());
    let norm = sig.normalize_s().unwrap_or(sig);
    let sig_b64 = BASE64URL.encode(norm.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

struct TestGatewayEnv {
    pool: PgPool,
    schema: String,
    gateway: Arc<PushGatewayService>,
    spy_transport: SpyGatewayTransport,
    alice_atproto_sk: P256SigningKey,
    catbird_ds_sk: P256SigningKey,
    self_hosted_ds_sk: P256SigningKey,
    evil_ds_sk: P256SigningKey,
}

impl TestGatewayEnv {
    async fn setup() -> Self {
        let user = std::env::var("USER").unwrap_or_else(|_| "postgres".to_string());
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| format!("postgres://{user}@localhost:5432/postgres"));
        let schema = format!("push_gw_test_{}", Uuid::new_v4().simple());

        let admin_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&db_url)
            .await
            .expect("local PostgreSQL must be reachable for push_gateway_security_tests");
        admin_pool
            .execute(format!("CREATE SCHEMA \"{schema}\"").as_str())
            .await
            .expect("create isolated test schema");

        let schema_for_conn = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .after_connect(move |conn, _meta| {
                let s = schema_for_conn.clone();
                Box::pin(async move {
                    conn.execute(format!("SET search_path TO \"{s}\"").as_str())
                        .await?;
                    Ok(())
                })
            })
            .connect(&db_url)
            .await
            .expect("connect scoped pool");

        let migration_sql = include_str!("../migrations/20261031000001_push_gateway_keys.up.sql");
        pool.execute(migration_sql)
            .await
            .expect("apply push_gateway_keys migration");
        pool.execute(include_str!(
            "../migrations/20261111000001_push_gateway_keys_session.up.sql"
        ))
        .await
        .expect("apply push_gateway_keys session migration");

        let alice_atproto_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let catbird_ds_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let self_hosted_ds_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let evil_ds_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);

        let alice_atproto_sk = P256SigningKey::from(&alice_atproto_secret);
        let catbird_ds_sk = P256SigningKey::from(&catbird_ds_secret);
        let self_hosted_ds_sk = P256SigningKey::from(&self_hosted_ds_secret);
        let evil_ds_sk = P256SigningKey::from(&evil_ds_secret);

        let resolver = StaticDidResolver::with_entries(
            [
                (
                    "did:plc:alicecatbird000000000001",
                    "did:web:chat.catbird.blue",
                ),
                (
                    "did:plc:bobselfhost0000000000002",
                    "did:web:mls.bob-home.org",
                ),
            ],
            [
                (
                    "did:plc:alicecatbird000000000001",
                    SpaceSigningKey::from_p256_secret(&alice_atproto_secret, "#atproto")
                        .verifying_key(),
                ),
                (
                    "did:web:chat.catbird.blue",
                    SpaceSigningKey::from_p256_secret(&catbird_ds_secret, "#atproto")
                        .verifying_key(),
                ),
                (
                    "did:web:mls.bob-home.org",
                    SpaceSigningKey::from_p256_secret(&self_hosted_ds_secret, "#atproto")
                        .verifying_key(),
                ),
                (
                    "did:web:evil-ds.example",
                    SpaceSigningKey::from_p256_secret(&evil_ds_secret, "#atproto").verifying_key(),
                ),
            ],
        );

        let spy_transport = SpyGatewayTransport::new();
        let gw_cfg = PushGatewayConfig {
            gateway_url: "https://api.catbird.blue/xrpc/blue.catbird.push.deliver".to_string(),
            token_encryption_key: [0x5Au8; 32],
            wake_envelope: catbird::services::push::gateway::WakeEnvelopeMode::ClearV1,
            per_key_burst: 10,
            per_key_per_minute: 30,
            per_ds_burst: 200,
            per_ds_per_minute: 600,
        };
        let gateway = Arc::new(PushGatewayService::new(
            pool.clone(),
            gw_cfg,
            Arc::new(resolver),
            Arc::new(spy_transport.clone()),
        ));

        Self {
            pool,
            schema,
            gateway,
            spy_transport,
            alice_atproto_sk,
            catbird_ds_sk,
            self_hosted_ds_sk,
            evil_ds_sk,
        }
    }

    async fn teardown(self) {
        let _ = self
            .pool
            .execute(format!("DROP SCHEMA IF EXISTS \"{}\" CASCADE", self.schema).as_str())
            .await;
    }

    fn router(&self) -> axum::Router {
        push_gateway::standalone_gateway_router(self.gateway.clone())
    }
}

fn make_session(did: &str) -> CatbirdSession {
    CatbirdSession {
        id: Uuid::new_v4(),
        did: did.to_string(),
        handle: "test.bsky.social".to_string(),
        pds_url: "https://swan.place".to_string(),
        access_token: "tok".to_string(),
        refresh_token: "ref".to_string(),
        scopes: vec!["atproto".to_string()],
        access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
        created_at: Utc::now(),
        last_used_at: Utc::now(),
        granted_scopes: vec!["atproto".to_string()],
    }
}

#[tokio::test]
async fn authorized_wake_delivers_nest_owned_aps_and_supports_self_hosted_ds() {
    let env = TestGatewayEnv::setup().await;
    let alice_did = "did:plc:alicecatbird000000000001";
    let alice_session = make_session(alice_did);
    let device_id = Uuid::new_v4().to_string();
    let native_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let Json(reg_out) = push_gateway::register_key_with_service(
        State(env.gateway.clone()),
        Extension(alice_session),
        Json(RegisterKey {
            app_id: "blue.catbird".into(),
            device_id: device_id.clone().into(),
            native_token: native_token.into(),
            platform: RegisterKeyPlatform::Apns,
            extra_data: None,
        }),
    )
    .await
    .expect("registerKey should succeed");

    assert_eq!(reg_out.app_id.as_str(), "blue.catbird");
    assert_eq!(
        reg_out.gateway_url.as_ref(),
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver"
    );
    assert_eq!(
        reg_out.push_key.len(),
        43,
        "32-byte CSPRNG base64url push_key"
    );

    // Verify DB stores SHA-256(push_key) and encrypted native token (never raw token).
    let expected_key_hash = Sha256::digest(reg_out.push_key.as_bytes()).to_vec();
    let row = sqlx::query(
        "SELECT encrypted_native_token, allowed_mls_service_did FROM push_gateway_keys WHERE push_key_sha256 = $1",
    )
    .bind(&expected_key_hash)
    .fetch_one(&env.pool)
    .await
    .expect("push_gateway_keys row must exist by SHA256(push_key)");
    let enc_tok: Vec<u8> = row.get("encrypted_native_token");
    let allowed_ds: String = row.get("allowed_mls_service_did");
    assert_eq!(allowed_ds, "did:web:chat.catbird.blue");
    assert!(
        !enc_tok
            .windows(native_token.len())
            .any(|w| w == native_token.as_bytes()),
        "native token must be encrypted at rest in push_gateway_keys"
    );

    let convo_id = Uuid::new_v4().to_string();
    let inline_ct = vec![0xABu8; 256];
    let body_json = json!({
        "pushKey": reg_out.push_key.as_str(),
        "appId": "blue.catbird",
        "payload": {
            "wakeKind": "applicationMessage",
            "conversationId": convo_id,
            "generation": 0,
            "seq": 7,
            "epoch": 3,
            "ciphertext": { "$bytes": BASE64_STD.encode(&inline_ct) }
        }
    });
    let body_bytes = serde_json::to_vec(&body_json).unwrap();
    let now = Utc::now().timestamp();
    let jwt = sign_ds_wake_jwt(
        &env.catbird_ds_sk,
        "did:web:chat.catbird.blue",
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        &Uuid::new_v4().to_string(),
        now,
        now + 30,
        &body_bytes,
    );

    let resp = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(body_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let calls = env.spy_transport.sent_calls();
    assert_eq!(calls.len(), 1);
    let dispatched = &calls[0];
    assert_eq!(dispatched.platform, GatewayPlatform::Apns);
    assert_eq!(dispatched.native_token, native_token);
    assert_eq!(dispatched.app_id, "blue.catbird");

    let mut collapse_hasher = Sha256::new();
    collapse_hasher.update(reg_out.push_key.as_bytes());
    collapse_hasher.update(convo_id.as_bytes());
    let expected_collapse = &hex_encode(&collapse_hasher.finalize())[..32];
    assert_eq!(dispatched.collapse_id, expected_collapse);

    assert_eq!(
        dispatched.apns_envelope["aps"],
        json!({
            "alert": { "body": "New message" },
            "mutable-content": 1
        }),
        "nest must exclusively own APNs aps construction"
    );
    let expected_acct_hash = hex_encode(&Sha256::digest(alice_did.as_bytes()));
    assert_eq!(
        dispatched.apns_envelope["catbird"]["recipientAccountHash"],
        json!(expected_acct_hash)
    );
    assert_eq!(
        dispatched.apns_envelope["catbird"]["conversationId"],
        json!(convo_id)
    );
    assert_eq!(dispatched.apns_envelope["catbird"]["seq"], json!(7));
    assert_eq!(dispatched.apns_envelope["catbird"]["epoch"], json!(3));
    assert_eq!(
        dispatched.apns_envelope["catbird"]["ciphertext"],
        json!(BASE64_STD.encode(&inline_ct))
    );

    // Self-hosted #atproto_mls user (Bob on did:web:mls.bob-home.org) also works end-to-end.
    let bob_session = make_session("did:plc:bobselfhost0000000000002");
    let Json(bob_reg) = push_gateway::register_key_with_service(
        State(env.gateway.clone()),
        Extension(bob_session),
        Json(RegisterKey {
            app_id: "blue.catbird".into(),
            device_id: Uuid::new_v4().to_string().into(),
            native_token: "fcm_token_bob_1234567890".into(),
            platform: RegisterKeyPlatform::Fcm,
            extra_data: None,
        }),
    )
    .await
    .expect("Bob self-hosted registerKey should succeed");

    let bob_body = serde_json::to_vec(&json!({
        "pushKey": bob_reg.push_key.as_str(),
        "appId": "blue.catbird",
        "payload": {
            "wakeKind": "welcome",
            "conversationId": Uuid::new_v4().to_string(),
            "generation": 0,
            "seq": 1,
            "epoch": 0
        }
    }))
    .unwrap();
    let bob_jwt = sign_ds_wake_jwt(
        &env.self_hosted_ds_sk,
        "did:web:mls.bob-home.org",
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        &Uuid::new_v4().to_string(),
        now,
        now + 30,
        &bob_body,
    );
    let bob_resp = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {bob_jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(bob_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_resp.status(), StatusCode::ACCEPTED);
    assert_eq!(env.spy_transport.sent_calls().len(), 2);
    assert_eq!(
        env.spy_transport.sent_calls()[1].platform,
        GatewayPlatform::Fcm
    );

    env.teardown().await;
}

#[tokio::test]
async fn wrong_caller_ds_did_and_unknown_keys_return_uniform_202_with_zero_apns_calls() {
    let env = TestGatewayEnv::setup().await;
    let alice_session = make_session("did:plc:alicecatbird000000000001");
    let Json(reg_out) = push_gateway::register_key_with_service(
        State(env.gateway.clone()),
        Extension(alice_session),
        Json(RegisterKey {
            app_id: "blue.catbird".into(),
            device_id: Uuid::new_v4().to_string().into(),
            native_token: "0123456789abcdef0123456789abcdef".into(),
            platform: RegisterKeyPlatform::Apns,
            extra_data: None,
        }),
    )
    .await
    .unwrap();

    let spoof_before = catbird::metrics::PUSH_GATEWAY_SPOOFED_CALLER_TOTAL.get();
    let now = Utc::now().timestamp();

    // 1. Evil DS signs a valid JWT targeting Alice's real push_key.
    let body_bytes = serde_json::to_vec(&json!({
        "pushKey": reg_out.push_key.as_str(),
        "appId": "blue.catbird",
        "payload": {
            "wakeKind": "applicationMessage",
            "conversationId": Uuid::new_v4().to_string(),
            "generation": 0,
            "seq": 1,
            "epoch": 0
        }
    }))
    .unwrap();
    let evil_jwt = sign_ds_wake_jwt(
        &env.evil_ds_sk,
        "did:web:evil-ds.example",
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        &Uuid::new_v4().to_string(),
        now,
        now + 30,
        &body_bytes,
    );

    let resp = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {evil_jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(body_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp_json: Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(resp_json, json!({ "accepted": true }));
    assert!(
        env.spy_transport.sent_calls().is_empty(),
        "wrong caller_ds_did must send ZERO APNs calls"
    );
    assert!(
        catbird::metrics::PUSH_GATEWAY_SPOOFED_CALLER_TOTAL.get() > spoof_before,
        "spoofing metric must increment when caller_ds_did != allowed_mls_service_did"
    );

    // 2. Evil DS probes a completely non-existent push_key -> identical 202 response body.
    let fake_key = BASE64URL.encode([0x99u8; 32]);
    let unknown_body = serde_json::to_vec(&json!({
        "pushKey": fake_key,
        "appId": "blue.catbird",
        "payload": {
            "wakeKind": "applicationMessage",
            "conversationId": Uuid::new_v4().to_string(),
            "generation": 0,
            "seq": 1,
            "epoch": 0
        }
    }))
    .unwrap();
    let unknown_jwt = sign_ds_wake_jwt(
        &env.evil_ds_sk,
        "did:web:evil-ds.example",
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        &Uuid::new_v4().to_string(),
        now,
        now + 30,
        &unknown_body,
    );
    let unknown_resp = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {unknown_jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(unknown_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_resp.status(), StatusCode::ACCEPTED);
    let unknown_json: Value =
        serde_json::from_slice(&to_bytes(unknown_resp.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(unknown_json, resp_json, "zero enumeration oracle");
    assert!(env.spy_transport.sent_calls().is_empty());

    env.teardown().await;
}

#[tokio::test]
async fn replayed_jti_and_tampered_body_fail_with_401() {
    let env = TestGatewayEnv::setup().await;
    let alice_session = make_session("did:plc:alicecatbird000000000001");
    let Json(reg_out) = push_gateway::register_key_with_service(
        State(env.gateway.clone()),
        Extension(alice_session),
        Json(RegisterKey {
            app_id: "blue.catbird".into(),
            device_id: Uuid::new_v4().to_string().into(),
            native_token: "0123456789abcdef0123456789abcdef".into(),
            platform: RegisterKeyPlatform::Apns,
            extra_data: None,
        }),
    )
    .await
    .unwrap();

    let body_bytes = serde_json::to_vec(&json!({
        "pushKey": reg_out.push_key.as_str(),
        "appId": "blue.catbird",
        "payload": {
            "wakeKind": "applicationMessage",
            "conversationId": Uuid::new_v4().to_string(),
            "generation": 0,
            "seq": 1,
            "epoch": 0
        }
    }))
    .unwrap();
    let now = Utc::now().timestamp();
    let shared_jti = Uuid::new_v4().to_string();
    let jwt = sign_ds_wake_jwt(
        &env.catbird_ds_sk,
        "did:web:chat.catbird.blue",
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        &shared_jti,
        now,
        now + 30,
        &body_bytes,
    );

    let first = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(body_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_eq!(env.spy_transport.sent_calls().len(), 1);

    // Replay same jti within 60s -> 401 Unauthorized.
    let replay = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(body_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(env.spy_transport.sent_calls().len(), 1);

    // Fresh jti but body tampered after signing -> 401 Unauthorized.
    let fresh_jwt = sign_ds_wake_jwt(
        &env.catbird_ds_sk,
        "did:web:chat.catbird.blue",
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        &Uuid::new_v4().to_string(),
        now,
        now + 30,
        &body_bytes,
    );
    let mut tampered = body_bytes;
    *tampered.last_mut().unwrap() = b' ';
    let tampered_resp = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {fresh_jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(tampered))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tampered_resp.status(), StatusCode::UNAUTHORIZED);

    env.teardown().await;
}

#[tokio::test]
async fn oversized_ciphertext_2201_bytes_and_injected_display_fields_return_400() {
    let env = TestGatewayEnv::setup().await;
    let alice_session = make_session("did:plc:alicecatbird000000000001");
    let Json(reg_out) = push_gateway::register_key_with_service(
        State(env.gateway.clone()),
        Extension(alice_session),
        Json(RegisterKey {
            app_id: "blue.catbird".into(),
            device_id: Uuid::new_v4().to_string().into(),
            native_token: "0123456789abcdef0123456789abcdef".into(),
            platform: RegisterKeyPlatform::Apns,
            extra_data: None,
        }),
    )
    .await
    .unwrap();

    let now = Utc::now().timestamp();
    let bad_payloads = vec![
        // 1. 2201-byte inline ciphertext (> I12's 2200-byte limit)
        json!({
            "pushKey": reg_out.push_key.as_str(),
            "appId": "blue.catbird",
            "payload": {
                "wakeKind": "applicationMessage",
                "conversationId": Uuid::new_v4().to_string(),
                "generation": 0,
                "seq": 1,
                "epoch": 0,
                "ciphertext": { "$bytes": BASE64_STD.encode(vec![0x42u8; 2201]) }
            }
        }),
        // 2. Phishing title/body injected inside payload
        json!({
            "pushKey": reg_out.push_key.as_str(),
            "appId": "blue.catbird",
            "payload": {
                "wakeKind": "applicationMessage",
                "conversationId": Uuid::new_v4().to_string(),
                "generation": 0,
                "seq": 1,
                "epoch": 0,
                "title": "Security Alert",
                "body": "Approve sign-in at evil.example"
            }
        }),
        // 3. Injected aps / alert at top level
        json!({
            "pushKey": reg_out.push_key.as_str(),
            "appId": "blue.catbird",
            "aps": { "alert": "Spoofed APNs alert" },
            "payload": {
                "wakeKind": "applicationMessage",
                "conversationId": Uuid::new_v4().to_string(),
                "generation": 0,
                "seq": 1,
                "epoch": 0
            }
        }),
    ];

    for bad in bad_payloads {
        let body_bytes = serde_json::to_vec(&bad).unwrap();
        let jwt = sign_ds_wake_jwt(
            &env.catbird_ds_sk,
            "did:web:chat.catbird.blue",
            "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
            &Uuid::new_v4().to_string(),
            now,
            now + 30,
            &body_bytes,
        );
        let resp = env
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/blue.catbird.push.deliver")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "malformed or phishing-injected payload {bad} must fail with 400"
        );
    }
    assert!(env.spy_transport.sent_calls().is_empty());

    env.teardown().await;
}

#[tokio::test]
async fn unregistered_token_returns_410_only_to_authorized_ds_and_202_to_unauthorized_ds() {
    let env = TestGatewayEnv::setup().await;
    let alice_session = make_session("did:plc:alicecatbird000000000001");
    let Json(reg_out) = push_gateway::register_key_with_service(
        State(env.gateway.clone()),
        Extension(alice_session),
        Json(RegisterKey {
            app_id: "blue.catbird".into(),
            device_id: Uuid::new_v4().to_string().into(),
            native_token: "dead_apns_token_0123456789abcdef".into(),
            platform: RegisterKeyPlatform::Apns,
            extra_data: None,
        }),
    )
    .await
    .unwrap();

    env.spy_transport
        .set_next_outcome(GatewayDeliveryOutcome::TokenUnregistered);

    let now = Utc::now().timestamp();
    let body_bytes = serde_json::to_vec(&json!({
        "pushKey": reg_out.push_key.as_str(),
        "appId": "blue.catbird",
        "payload": {
            "wakeKind": "applicationMessage",
            "conversationId": Uuid::new_v4().to_string(),
            "generation": 0,
            "seq": 1,
            "epoch": 0
        }
    }))
    .unwrap();

    // Authorized DS triggers APNs Unregistered -> 410 Gone and persists unregistered_at.
    let auth_jwt_1 = sign_ds_wake_jwt(
        &env.catbird_ds_sk,
        "did:web:chat.catbird.blue",
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        &Uuid::new_v4().to_string(),
        now,
        now + 30,
        &body_bytes,
    );
    let resp_410 = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {auth_jwt_1}"))
                .header("content-type", "application/json")
                .body(Body::from(body_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_410.status(), StatusCode::GONE);
    assert_eq!(env.spy_transport.sent_calls().len(), 1);

    // Unauthorized DS probing the now-unregistered push_key MUST STILL get 202 Accepted!
    let evil_jwt = sign_ds_wake_jwt(
        &env.evil_ds_sk,
        "did:web:evil-ds.example",
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        &Uuid::new_v4().to_string(),
        now,
        now + 30,
        &body_bytes,
    );
    let evil_resp = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {evil_jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(body_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        evil_resp.status(),
        StatusCode::ACCEPTED,
        "dead-token state must never leak 410 to an unauthorized caller_ds_did"
    );

    // Authorized DS subsequent call immediately gets 410 without hitting APNs again.
    let auth_jwt_2 = sign_ds_wake_jwt(
        &env.catbird_ds_sk,
        "did:web:chat.catbird.blue",
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        &Uuid::new_v4().to_string(),
        now,
        now + 30,
        &body_bytes,
    );
    let resp_410_cached = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {auth_jwt_2}"))
                .header("content-type", "application/json")
                .body(Body::from(body_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_410_cached.status(), StatusCode::GONE);
    assert_eq!(
        env.spy_transport.sent_calls().len(),
        1,
        "known-dead token must short-circuit before APNs"
    );

    env.teardown().await;
}

#[tokio::test]
async fn rate_bucket_enforces_burst_10_and_blocks_cross_ds_bucket_exhaustion() {
    let env = TestGatewayEnv::setup().await;
    let alice_session = make_session("did:plc:alicecatbird000000000001");
    let Json(reg_out) = push_gateway::register_key_with_service(
        State(env.gateway.clone()),
        Extension(alice_session),
        Json(RegisterKey {
            app_id: "blue.catbird".into(),
            device_id: Uuid::new_v4().to_string().into(),
            native_token: "0123456789abcdef0123456789abcdef".into(),
            platform: RegisterKeyPlatform::Apns,
            extra_data: None,
        }),
    )
    .await
    .unwrap();

    let now = Utc::now().timestamp();
    let body_bytes = serde_json::to_vec(&json!({
        "pushKey": reg_out.push_key.as_str(),
        "appId": "blue.catbird",
        "payload": {
            "wakeKind": "applicationMessage",
            "conversationId": Uuid::new_v4().to_string(),
            "generation": 0,
            "seq": 1,
            "epoch": 0
        }
    }))
    .unwrap();

    // First, evil DS sends 15 spoofed wakes — must NOT drain Alice's per-key burst of 10!
    for _ in 0..15 {
        let evil_jwt = sign_ds_wake_jwt(
            &env.evil_ds_sk,
            "did:web:evil-ds.example",
            "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
            &Uuid::new_v4().to_string(),
            now,
            now + 30,
            &body_bytes,
        );
        let r = env
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/blue.catbird.push.deliver")
                    .header("authorization", format!("Bearer {evil_jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::ACCEPTED);
    }
    assert!(env.spy_transport.sent_calls().is_empty());

    // Now Alice's authorized DS sends 12 wakes back-to-back: first 10 deliver, 11 & 12 are throttled.
    for i in 0..12 {
        let jwt = sign_ds_wake_jwt(
            &env.catbird_ds_sk,
            "did:web:chat.catbird.blue",
            "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
            &Uuid::new_v4().to_string(),
            now,
            now + 30,
            &body_bytes,
        );
        let r = env
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/blue.catbird.push.deliver")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        if i < 10 {
            assert_eq!(
                r.status(),
                StatusCode::ACCEPTED,
                "burst call {i} should pass"
            );
        } else {
            assert_eq!(
                r.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "call {i} past burst 10 must be rate-limited"
            );
        }
    }
    assert_eq!(
        env.spy_transport.sent_calls().len(),
        10,
        "excess wakes past burst 10 must send zero extra APNs requests"
    );

    env.teardown().await;
}

/// Sends one well-formed wake for `push_key` from the account's bound delivery service.
async fn wake(env: &TestGatewayEnv, push_key: &str) -> StatusCode {
    let body_bytes = serde_json::to_vec(&json!({
        "pushKey": push_key,
        "appId": "blue.catbird",
        "payload": {
            "wakeKind": "applicationMessage",
            "conversationId": Uuid::new_v4().to_string(),
            "generation": 0,
            "seq": 1,
            "epoch": 1
        }
    }))
    .unwrap();
    let now = Utc::now().timestamp();
    let jwt = sign_ds_wake_jwt(
        &env.catbird_ds_sk,
        "did:web:chat.catbird.blue",
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        &Uuid::new_v4().to_string(),
        now,
        now + 30,
        &body_bytes,
    );
    env.router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(body_bytes))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn register(
    env: &TestGatewayEnv,
    session: &CatbirdSession,
    device_id: &str,
    token: &str,
) -> String {
    let Json(out) = push_gateway::register_key_with_service(
        State(env.gateway.clone()),
        Extension(session.clone()),
        Json(RegisterKey {
            app_id: "blue.catbird".into(),
            device_id: device_id.to_string().into(),
            native_token: token.to_string().into(),
            platform: RegisterKeyPlatform::Apns,
            extra_data: None,
        }),
    )
    .await
    .expect("registerKey should succeed");
    out.push_key.to_string()
}

#[tokio::test]
async fn revoked_keys_stop_waking_and_revocation_is_scoped_to_the_session() {
    let env = TestGatewayEnv::setup().await;
    let alice_did = "did:plc:alicecatbird000000000001";
    let phone = make_session(alice_did);
    let ipad = make_session(alice_did);
    let phone_device = Uuid::new_v4().to_string();
    let ipad_device = Uuid::new_v4().to_string();
    let phone_key = register(&env, &phone, &phone_device, &"a1".repeat(32)).await;
    let ipad_key = register(&env, &ipad, &ipad_device, &"b2".repeat(32)).await;

    assert_eq!(wake(&env, &phone_key).await, StatusCode::ACCEPTED);
    assert_eq!(env.spy_transport.sent_calls().len(), 1);

    // The phone's session unregisters: its key is revoked, the iPad's is not.
    let revoked = env
        .gateway
        .revoke_keys_for_session_app(alice_did, &phone.id.to_string(), "blue.catbird")
        .await
        .unwrap();
    assert_eq!(revoked, 1);

    // A revoked key answers exactly like an unknown one and reaches no provider.
    assert_eq!(wake(&env, &phone_key).await, StatusCode::ACCEPTED);
    assert_eq!(
        env.spy_transport.sent_calls().len(),
        1,
        "a revoked key must not wake the device"
    );
    assert_eq!(wake(&env, &ipad_key).await, StatusCode::ACCEPTED);
    assert_eq!(env.spy_transport.sent_calls().len(), 2);

    // Signing in again on the phone registers a fresh key; the old one stays dead.
    let phone_again = make_session(alice_did);
    let phone_key_2 = register(&env, &phone_again, &phone_device, &"a1".repeat(32)).await;
    assert_ne!(phone_key_2, phone_key);
    assert_eq!(wake(&env, &phone_key_2).await, StatusCode::ACCEPTED);
    assert_eq!(env.spy_transport.sent_calls().len(), 3);
    assert_eq!(wake(&env, &phone_key).await, StatusCode::ACCEPTED);
    assert_eq!(env.spy_transport.sent_calls().len(), 3);

    // Account-wide revocation stops every remaining key.
    let revoked = env
        .gateway
        .revoke_keys_for_account(alice_did)
        .await
        .unwrap();
    assert_eq!(revoked, 2);
    assert_eq!(wake(&env, &ipad_key).await, StatusCode::ACCEPTED);
    assert_eq!(wake(&env, &phone_key_2).await, StatusCode::ACCEPTED);
    assert_eq!(env.spy_transport.sent_calls().len(), 3);

    env.teardown().await;
}

fn sign_pds_service_jwt(
    signing_key: &P256SigningKey,
    iss: &str,
    aud: &str,
    lxm: &str,
    jti: &str,
    iat: i64,
    exp: i64,
) -> String {
    let header = json!({
        "alg": "ES256",
        "typ": "JWT",
    });
    let claims = json!({
        "iss": iss,
        "aud": aud,
        "lxm": lxm,
        "iat": iat,
        "exp": exp,
        "jti": jti,
    });
    let hdr_b64 = BASE64URL.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = BASE64URL.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{hdr_b64}.{claims_b64}");
    let sig: P256Signature = signing_key.sign(signing_input.as_bytes());
    let norm = sig.normalize_s().unwrap_or(sig);
    let sig_b64 = BASE64URL.encode(norm.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

#[tokio::test]
async fn service_jwt_register_key_accepts_valid_token_and_rejects_forgery_and_replay() {
    let env = TestGatewayEnv::setup().await;
    let alice_did = "did:plc:alicecatbird000000000001";
    let device_id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    let req_body = serde_json::to_vec(&json!({
        "appId": "social.external.chat",
        "deviceId": device_id,
        "nativeToken": "c3".repeat(32),
        "platform": "apns",
    }))
    .unwrap();

    let valid_jti = Uuid::new_v4().to_string();
    let valid_jwt = sign_pds_service_jwt(
        &env.alice_atproto_sk,
        alice_did,
        "did:web:api.catbird.blue#atproto_push",
        "blue.catbird.push.registerKey",
        &valid_jti,
        now,
        now + 60,
    );

    let resp = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.registerKey")
                .header("authorization", format!("Bearer {valid_jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(req_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp_json: Value = serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap())
        .expect("parse registerKey output");
    let push_key = resp_json["pushKey"].as_str().expect("pushKey string");
    assert_eq!(resp_json["appId"], "social.external.chat");

    // Verify auth_session_fingerprint is NULL for external ServiceJWT registrations.
    let push_key_sha256: [u8; 32] = Sha256::digest(push_key.as_bytes()).into();
    let row = sqlx::query(
        "SELECT auth_session_fingerprint FROM push_gateway_keys WHERE push_key_sha256 = $1",
    )
    .bind(push_key_sha256.as_slice())
    .fetch_one(&env.pool)
    .await
    .expect("registered row must exist");
    let session_fp: Option<String> = row.get("auth_session_fingerprint");
    assert!(
        session_fp.is_none(),
        "ServiceJWT registration must leave auth_session_fingerprint NULL"
    );

    // Confirm a wake from Alice's bound mls-ds delivers cleanly for this external appId.
    let wake_body = serde_json::to_vec(&json!({
        "pushKey": push_key,
        "appId": "social.external.chat",
        "payload": {
            "wakeKind": "applicationMessage",
            "conversationId": Uuid::new_v4().to_string(),
            "generation": 0,
            "seq": 1,
            "epoch": 1
        }
    }))
    .unwrap();
    let wake_jwt = sign_ds_wake_jwt(
        &env.catbird_ds_sk,
        "did:web:chat.catbird.blue",
        "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        &Uuid::new_v4().to_string(),
        now,
        now + 30,
        &wake_body,
    );
    let wake_resp = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.deliver")
                .header("authorization", format!("Bearer {wake_jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(wake_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wake_resp.status(), StatusCode::ACCEPTED);
    assert_eq!(env.spy_transport.sent_calls().len(), 1);

    // Replaying the exact same ServiceJWT (`jti`) must fail with 401.
    let replay_resp = env
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/blue.catbird.push.registerKey")
                .header("authorization", format!("Bearer {valid_jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(req_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_resp.status(), StatusCode::UNAUTHORIZED);

    // Wrong lxm, wrong aud, expired exp, and forged signature must all fail with 401.
    for bad_jwt in [
        sign_pds_service_jwt(
            &env.alice_atproto_sk,
            alice_did,
            "did:web:api.catbird.blue",
            "blue.catbird.push.deliver",
            &Uuid::new_v4().to_string(),
            now,
            now + 60,
        ),
        sign_pds_service_jwt(
            &env.alice_atproto_sk,
            alice_did,
            "did:web:evil.example",
            "blue.catbird.push.registerKey",
            &Uuid::new_v4().to_string(),
            now,
            now + 60,
        ),
        sign_pds_service_jwt(
            &env.alice_atproto_sk,
            alice_did,
            "did:web:api.catbird.blue",
            "blue.catbird.push.registerKey",
            &Uuid::new_v4().to_string(),
            now - 120,
            now - 30,
        ),
        sign_pds_service_jwt(
            &env.evil_ds_sk,
            alice_did,
            "did:web:api.catbird.blue",
            "blue.catbird.push.registerKey",
            &Uuid::new_v4().to_string(),
            now,
            now + 60,
        ),
    ] {
        let r = env
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/blue.catbird.push.registerKey")
                    .header("authorization", format!("Bearer {bad_jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(req_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    env.teardown().await;
}
