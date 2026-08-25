//! Circle push notification tests

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird::config::{AppConfig, AppState};
use catbird::routes::circle;
use catbird::services::push::{circle_activity_payload, CircleActivityPayload};
use catbird::services::{
    AtProtoCircleProbe, CircleCapabilityService, DpopNonceCache, KeyStore,
};
use chrono::Utc;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

fn mint_circle_push_jwt(
    iss: &str,
    aud: &str,
    lxm: &str,
    signing_key: &p256::ecdsa::SigningKey,
) -> String {
    let now = Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();

    let header = json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": format!("{iss}#atproto"),
    });

    let claims = json!({
        "iss": iss,
        "aud": aud,
        "lxm": lxm,
        "jti": jti,
        "iat": now,
        "exp": now + 60,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

async fn create_test_state() -> AppState {
    let mut config = AppConfig::load().unwrap();

    config.oauth.client_id = "https://api.catbird.blue".into();
    config.circle.service_did = "did:web:circles.catbird.blue#atproto_circle".into();

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    let redis_client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
    let redis = redis::aio::ConnectionManager::new(redis_client).await.unwrap();

    let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
    let key_store = Arc::new(KeyStore::from_key("key-1", secret_key));

    let dpop_nonce_cache = Arc::new(DpopNonceCache::new());
    let circle_probe = AtProtoCircleProbe::new();
    let circle_capability = Arc::new(CircleCapabilityService::new(circle_probe));

    AppState {
        config: Arc::new(config),
        http_client,
        redis,
        push_db: None,
        key_store: Some(key_store),
        jacquard_client: None,
        catmos_jacquard_client: None,
        auth_store: None,
        push: None,
        dpop_nonce_cache,
        circle_capability,
        circle_worker_alive: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        session_encryption_key: None,
    }
}

#[test]
fn generic_push_contains_no_circle_metadata() {
    let payload = circle_activity_payload();
    let json = serde_json::to_string(&payload).unwrap();
    assert_eq!(json, r#"{"kind":"circle_activity"}"#);
}

#[tokio::test]
async fn circle_push_requires_service_auth_and_delivers_generic_payload() {
    let state = create_test_state().await;
    let app = circle::routes(state.clone());

    let recipient = "did:plc:alice-recipient";
    let body = json!({
        "recipient_did": recipient
    });

    // 1. Unauthenticated request -> 401 Unauthorized
    let req = Request::builder()
        .method("POST")
        .uri("/internal/circle/push")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Request with invalid lxm -> 401 Unauthorized
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let bad_lxm_jwt = mint_circle_push_jwt(
        &state.config.circle.service_did,
        &state.config.oauth.client_id,
        "blue.catbird.circle.wrongLexicon",
        &signing_key,
    );

    let req = Request::builder()
        .method("POST")
        .uri("/internal/circle/push")
        .header(header::AUTHORIZATION, format!("Bearer {bad_lxm_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Request with valid service JWT -> 200 OK
    let valid_jwt = mint_circle_push_jwt(
        &state.config.circle.service_did,
        &state.config.oauth.client_id,
        "blue.catbird.circle.push",
        &signing_key,
    );

    let req = Request::builder()
        .method("POST")
        .uri("/internal/circle/push")
        .header(header::AUTHORIZATION, format!("Bearer {valid_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    assert_eq!(resp_json["status"], "ok");
}
