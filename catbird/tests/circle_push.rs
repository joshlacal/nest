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

fn mint_custom_circle_push_jwt(
    typ: Option<&str>,
    alg: &str,
    kid: Option<&str>,
    iss: &str,
    aud: &str,
    lxm: &str,
    signing_key: &p256::ecdsa::SigningKey,
) -> String {
    let now = Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();

    let mut header = json!({
        "alg": alg,
    });
    if let Some(t) = typ {
        header["typ"] = json!(t);
    }
    if let Some(k) = kid {
        header["kid"] = json!(k);
    }

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

fn mint_circle_push_jwt(
    iss: &str,
    aud: &str,
    lxm: &str,
    signing_key: &p256::ecdsa::SigningKey,
) -> String {
    mint_custom_circle_push_jwt(
        Some("JWT"),
        "ES256",
        Some("did:web:circles.catbird.blue#atproto_circle"),
        iss,
        aud,
        lxm,
        signing_key,
    )
}

async fn create_test_state(verifying_key: Option<p256::ecdsa::VerifyingKey>) -> AppState {
    let mut config = AppConfig::load().unwrap();

    config.oauth.client_id = "https://api.catbird.blue".into();
    config.push.service_did = Some("did:web:push.catbird.blue".into());
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
        circle_verifying_key: verifying_key.map(Arc::new),
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
    let correct_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let state = create_test_state(Some(correct_signing_key.verifying_key().clone())).await;
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
    let bad_lxm_jwt = mint_circle_push_jwt(
        &state.config.circle.service_did,
        &state.config.oauth.client_id,
        "blue.catbird.circle.wrongLexicon",
        &correct_signing_key,
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

    // 3. Request signed with WRONG key -> 401 Unauthorized
    let wrong_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let wrong_key_jwt = mint_circle_push_jwt(
        &state.config.circle.service_did,
        &state.config.oauth.client_id,
        "blue.catbird.circle.push",
        &wrong_signing_key,
    );

    let req = Request::builder()
        .method("POST")
        .uri("/internal/circle/push")
        .header(header::AUTHORIZATION, format!("Bearer {wrong_key_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 4. Request with audience matching Circle service DID (issuer DID) -> 401 Unauthorized
    let issuer_aud_jwt = mint_circle_push_jwt(
        &state.config.circle.service_did,
        &state.config.circle.service_did,
        "blue.catbird.circle.push",
        &correct_signing_key,
    );

    let req = Request::builder()
        .method("POST")
        .uri("/internal/circle/push")
        .header(header::AUTHORIZATION, format!("Bearer {issuer_aud_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 5. Request with valid service JWT and aud = client_id -> 200 OK
    let valid_client_id_jwt = mint_circle_push_jwt(
        &state.config.circle.service_did,
        &state.config.oauth.client_id,
        "blue.catbird.circle.push",
        &correct_signing_key,
    );

    let req = Request::builder()
        .method("POST")
        .uri("/internal/circle/push")
        .header(header::AUTHORIZATION, format!("Bearer {valid_client_id_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    // 5. Request with missing/bad typ -> 401 Unauthorized
    let bad_typ_jwt = mint_custom_circle_push_jwt(
        Some("JOSE"),
        "ES256",
        Some("did:web:circles.catbird.blue#atproto_circle"),
        &state.config.circle.service_did,
        &state.config.oauth.client_id,
        "blue.catbird.circle.push",
        &correct_signing_key,
    );

    let req = Request::builder()
        .method("POST")
        .uri("/internal/circle/push")
        .header(header::AUTHORIZATION, format!("Bearer {bad_typ_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 6. Request with missing/bad kid -> 401 Unauthorized
    let bad_kid_jwt = mint_custom_circle_push_jwt(
        Some("JWT"),
        "ES256",
        Some("did:web:wrong.service#unrelated_key"),
        &state.config.circle.service_did,
        &state.config.oauth.client_id,
        "blue.catbird.circle.push",
        &correct_signing_key,
    );

    let req = Request::builder()
        .method("POST")
        .uri("/internal/circle/push")
        .header(header::AUTHORIZATION, format!("Bearer {bad_kid_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 7. Request with valid service JWT and aud = client_id -> 200 OK
    let valid_client_id_jwt = mint_circle_push_jwt(
        &state.config.circle.service_did,
        &state.config.oauth.client_id,
        "blue.catbird.circle.push",
        &correct_signing_key,
    );

    let req = Request::builder()
        .method("POST")
        .uri("/internal/circle/push")
        .header(header::AUTHORIZATION, format!("Bearer {valid_client_id_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    assert_eq!(resp_json["status"], "ok");

    // 8. Request with valid service JWT and aud = push.service_did -> 200 OK
    let valid_push_did_jwt = mint_circle_push_jwt(
        &state.config.circle.service_did,
        state.config.push.service_did.as_ref().unwrap(),
        "blue.catbird.circle.push",
        &correct_signing_key,
    );

    let req = Request::builder()
        .method("POST")
        .uri("/internal/circle/push")
        .header(header::AUTHORIZATION, format!("Bearer {valid_push_did_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    assert_eq!(resp_json["status"], "ok");
}

#[tokio::test]
async fn resolve_circle_verifying_key_from_wiremock_did_doc() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let vk = signing_key.verifying_key();
    let sec1 = vk.to_encoded_point(true);

    let mut multikey_bytes = vec![0x80, 0x24];
    multikey_bytes.extend_from_slice(sec1.as_bytes());
    let multikey_str = multibase::encode(multibase::Base::Base58Btc, &multikey_bytes);

    let host = mock_server.address().ip().to_string();
    let port = mock_server.address().port();
    let base_did = format!("did:web:{host}%3A{port}");
    let test_did = format!("{base_did}#atproto_circle");

    let did_doc = json!({
        "id": base_did,
        "verificationMethod": [{
            "id": format!("{base_did}#atproto_circle"),
            "type": "Multikey",
            "controller": base_did,
            "publicKeyMultibase": multikey_str
        }]
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc))
        .mount(&mock_server)
        .await;

    let resolved_vk = catbird::services::circle::resolve_circle_verifying_key(&test_did, None)
        .await
        .unwrap();

    assert_eq!(resolved_vk.to_encoded_point(false), vk.to_encoded_point(false));
}

#[tokio::test]
async fn resolve_circle_verifying_key_from_wiremock_jwk_did_doc() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let vk = signing_key.verifying_key();
    let encoded_point = vk.to_encoded_point(false);
    let x_b64 = URL_SAFE_NO_PAD.encode(encoded_point.x().unwrap());
    let y_b64 = URL_SAFE_NO_PAD.encode(encoded_point.y().unwrap());

    let host = mock_server.address().ip().to_string();
    let port = mock_server.address().port();
    let base_did = format!("did:web:{host}%3A{port}");
    let test_did = format!("{base_did}#atproto_circle");

    let did_doc = json!({
        "id": base_did,
        "verificationMethod": [{
            "id": format!("{base_did}#atproto_circle"),
            "type": "JsonWebKey2020",
            "controller": base_did,
            "publicKeyJwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": x_b64,
                "y": y_b64
            }
        }]
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc))
        .mount(&mock_server)
        .await;

    let resolved_vk = catbird::services::circle::resolve_circle_verifying_key(&test_did, None)
        .await
        .unwrap();

    assert_eq!(resolved_vk.to_encoded_point(false), vk.to_encoded_point(false));
}

#[tokio::test]
async fn resolve_circle_verifying_key_rejects_mismatched_did_doc_id() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let vk = signing_key.verifying_key();
    let sec1 = vk.to_encoded_point(true);

    let mut multikey_bytes = vec![0x80, 0x24];
    multikey_bytes.extend_from_slice(sec1.as_bytes());
    let multikey_str = multibase::encode(multibase::Base::Base58Btc, &multikey_bytes);

    let host = mock_server.address().ip().to_string();
    let port = mock_server.address().port();
    let base_did = format!("did:web:{host}%3A{port}");
    let test_did = format!("{base_did}#atproto_circle");

    // Serve a document with a DIFFERENT id
    let did_doc = json!({
        "id": "did:web:attacker.controlled.blue",
        "verificationMethod": [{
            "id": "did:web:attacker.controlled.blue#atproto_circle",
            "type": "Multikey",
            "controller": "did:web:attacker.controlled.blue",
            "publicKeyMultibase": multikey_str
        }]
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc))
        .mount(&mock_server)
        .await;

    let res = catbird::services::circle::resolve_circle_verifying_key(&test_did, None).await;
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("DID document ID mismatch"));
}

#[tokio::test]
async fn resolve_circle_verifying_key_multi_key_and_no_fallback() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let signing_key_1 = p256::ecdsa::SigningKey::random(&mut OsRng);
    let vk_1 = signing_key_1.verifying_key();
    let sec1_1 = vk_1.to_encoded_point(true);
    let mut multikey_1 = vec![0x80, 0x24];
    multikey_1.extend_from_slice(sec1_1.as_bytes());
    let multikey_str_1 = multibase::encode(multibase::Base::Base58Btc, &multikey_1);

    let signing_key_2 = p256::ecdsa::SigningKey::random(&mut OsRng);
    let vk_2 = signing_key_2.verifying_key();
    let sec1_2 = vk_2.to_encoded_point(true);
    let mut multikey_2 = vec![0x80, 0x24];
    multikey_2.extend_from_slice(sec1_2.as_bytes());
    let multikey_str_2 = multibase::encode(multibase::Base::Base58Btc, &multikey_2);

    let host = mock_server.address().ip().to_string();
    let port = mock_server.address().port();
    let base_did = format!("did:web:{host}%3A{port}");

    let did_doc = json!({
        "id": base_did,
        "verificationMethod": [
            {
                "id": format!("{base_did}#key-1"),
                "type": "Multikey",
                "controller": base_did,
                "publicKeyMultibase": multikey_str_1
            },
            {
                "id": format!("{base_did}#atproto_circle"),
                "type": "Multikey",
                "controller": base_did,
                "publicKeyMultibase": multikey_str_2
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc))
        .mount(&mock_server)
        .await;

    // 1. Resolve exact key 2 -> returns key 2 (not first key!)
    let test_did_2 = format!("{base_did}#atproto_circle");
    let resolved_vk_2 = catbird::services::circle::resolve_circle_verifying_key(&test_did_2, None)
        .await
        .unwrap();
    assert_eq!(resolved_vk_2.to_encoded_point(false), vk_2.to_encoded_point(false));
    assert_ne!(resolved_vk_2.to_encoded_point(false), vk_1.to_encoded_point(false));

    // 2. Resolve nonexistent key fragment -> fails with error (NO silent fallback to first key!)
    let test_did_bad = format!("{base_did}#nonexistent");
    let res_bad = catbird::services::circle::resolve_circle_verifying_key(&test_did_bad, None).await;
    assert!(res_bad.is_err());
}

#[tokio::test]
async fn resolve_circle_verifying_key_rejects_wrong_controller() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let vk = signing_key.verifying_key();
    let sec1 = vk.to_encoded_point(true);

    let mut multikey_bytes = vec![0x80, 0x24];
    multikey_bytes.extend_from_slice(sec1.as_bytes());
    let multikey_str = multibase::encode(multibase::Base::Base58Btc, &multikey_bytes);

    let host = mock_server.address().ip().to_string();
    let port = mock_server.address().port();
    let base_did = format!("did:web:{host}%3A{port}");
    let test_did = format!("{base_did}#atproto_circle");

    // Serve a document where controller does not match base_did
    let did_doc = json!({
        "id": base_did,
        "verificationMethod": [{
            "id": format!("{base_did}#atproto_circle"),
            "type": "Multikey",
            "controller": "did:web:unrelated.controller.blue",
            "publicKeyMultibase": multikey_str
        }]
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc))
        .mount(&mock_server)
        .await;

    let res = catbird::services::circle::resolve_circle_verifying_key(&test_did, None).await;
    assert!(res.is_err());
}
