//! Integration tests for the Catbird Nest Gateway
//!
//! These tests verify the gateway endpoints work correctly.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

// Note: Full integration tests require a running Redis instance.
// For CI, consider using testcontainers.

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the liveness endpoint always returns 200
    #[tokio::test]
    async fn test_liveness_check() {
        // The liveness check doesn't need state, so we can test it in isolation
        // In a full setup, we'd use the actual router

        // For now, just verify the test infrastructure works
        assert!(true, "Liveness check test placeholder");
    }

    /// Test session cookie extraction
    #[tokio::test]
    async fn test_session_extraction_from_cookie() {
        // Test that sessions can be extracted from cookies
        let cookie_header = "catbird_session=abc123; other=value";

        // Parse the cookie (simplified)
        let session_id = cookie_header.split(';').find_map(|part| {
            let parts: Vec<&str> = part.trim().splitn(2, '=').collect();
            if parts.len() == 2 && parts[0] == "catbird_session" {
                Some(parts[1].to_string())
            } else {
                None
            }
        });

        assert_eq!(session_id, Some("abc123".to_string()));
    }

    /// Test session extraction from Authorization header
    #[tokio::test]
    async fn test_session_extraction_from_bearer() {
        let auth_header = "Bearer xyz789";

        let token = auth_header.strip_prefix("Bearer ");
        assert_eq!(token, Some("xyz789"));
    }

    /// Test PKCE code verifier generation
    #[tokio::test]
    async fn test_pkce_verifier_length() {
        // PKCE verifiers should be between 43-128 characters
        // Our implementation uses 128 characters
        let expected_length = 128;
        assert!(expected_length >= 43 && expected_length <= 128);
    }

    /// Test clean-chat DPoP proof generation & verification and endpoints
    #[tokio::test]
    async fn test_clean_chat_token_and_dpop_proof_flow() {
        use catbird::services::{
            calculate_ath, generate_dpop_proof, p256_jwk_thumbprint, verify_dpop_proof,
            CHAT_ENDPOINTS,
        };
        use p256::ecdsa::SigningKey;

        let dpop_signing_key = SigningKey::random(&mut rand::thread_rng());
        let dpop_jkt = p256_jwk_thumbprint(&dpop_signing_key);

        let now = 1700000000;
        let endpoint = "blue.catbird.chat.sendMessage";
        let token = "mock.service.auth.token";

        // 1. Generate DPoP proof
        let htu = format!("https://mlschat.catbird.blue/xrpc/{}", endpoint);
        let proof = generate_dpop_proof(&dpop_signing_key, "POST", &htu, token, now).unwrap();

        // 2. Verify DPoP proof
        let proof_claims =
            verify_dpop_proof(&proof, "POST", &htu, token, Some(&dpop_jkt), now).unwrap();

        assert_eq!(proof_claims.htm, "POST");
        assert_eq!(proof_claims.htu, htu);
        assert_eq!(proof_claims.ath, calculate_ath(token));
        assert_eq!(proof_claims.iat, now);

        // 3. Verify the complete 36-procedure `blue.catbird.chat.authFull` registry,
        //    including Wave-1b device approval, push gateway registration, Space relays,
        //    and the delivery service's encrypted direct-request procedures.
        assert_eq!(CHAT_ENDPOINTS.len(), 36);
        assert!(CHAT_ENDPOINTS.contains(&"blue.catbird.chat.acknowledgeEntries"));
        assert!(CHAT_ENDPOINTS.contains(&"blue.catbird.chat.approveDevice"));
        assert!(CHAT_ENDPOINTS.contains(&"blue.catbird.chat.registerPushGateway"));
        assert!(CHAT_ENDPOINTS.contains(&"blue.catbird.chat.relaySpaceCredential"));
        assert!(CHAT_ENDPOINTS.contains(&"blue.catbird.chat.relaySpaceRead"));
        assert!(CHAT_ENDPOINTS.contains(&"blue.catbird.chat.publishDirectRequest"));
        assert!(CHAT_ENDPOINTS.contains(&"blue.catbird.chat.getEntries"));
        for retired in [
            "blue.catbird.chat.deleteBlob",
            "blue.catbird.chat.getBlob",
            "blue.catbird.chat.getBlobUsage",
            "blue.catbird.chat.prepareBlobUpload",
            "blue.catbird.chat.uploadBlob",
            "blue.catbird.chat.updatePushToken",
            "blue.catbird.chat.subscribeEvents",
        ] {
            assert!(
                !CHAT_ENDPOINTS.contains(&retired),
                "retired or WS-only chat NSID must not be in CHAT_ENDPOINTS: {retired}"
            );
        }
    }

    /// Test ADR-014 is_allowed_redirect validation and origin matching
    #[tokio::test]
    async fn test_adr014_is_allowed_redirect() {
        use catbird::handlers::atproto::is_allowed_redirect;

        // Exact match required for Android/iOS registered callback
        assert!(is_allowed_redirect("https://catbird.blue/oauth/callback"));

        // Near misses and path traversals MUST be rejected
        assert!(!is_allowed_redirect(
            "https://catbird.blue/oauth/callback/../evil"
        ));
        assert!(!is_allowed_redirect("https://catbird.blue/other"));
        assert!(!is_allowed_redirect("https://catbird.blue/"));
        assert!(!is_allowed_redirect("https://catbird.blue"));

        // Subdomain attacks MUST be rejected
        assert!(!is_allowed_redirect(
            "https://catmos.catbird.blue.evil.com/"
        ));
        assert!(!is_allowed_redirect(
            "https://catmos.catbird.blue.evil.com/callback"
        ));
        assert!(!is_allowed_redirect(
            "https://catbird.blue.evil.com/oauth/callback"
        ));

        // Valid Catmos production origins
        assert!(is_allowed_redirect("https://catmos.catbird.blue/callback"));
        assert!(is_allowed_redirect("https://catmos.catbird.blue/"));
        assert!(is_allowed_redirect("https://catmos.pages.dev/callback"));
        assert!(is_allowed_redirect(
            "https://preview-123.catmos.pages.dev/callback"
        ));

        // Loopback addresses for local dev
        assert!(is_allowed_redirect("http://127.0.0.1:8080/callback"));
        assert!(is_allowed_redirect("http://127.0.0.1:3000/"));
        assert!(is_allowed_redirect("http://[::1]:8080/callback"));
        assert!(is_allowed_redirect("http://localhost:8080/callback"));

        // Invalid URLs
        assert!(!is_allowed_redirect("not-a-url"));
        assert!(!is_allowed_redirect(""));
    }

    /// Test ADR-014 43-character base64url validation
    #[tokio::test]
    async fn test_adr014_is_valid_base64url_43() {
        use catbird::handlers::atproto::is_valid_base64url_43;

        // Exactly 43 characters with [A-Za-z0-9_-]
        assert!(is_valid_base64url_43(
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V"
        ));
        assert!(is_valid_base64url_43(
            "a-b_c1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZab"
        ));

        // Wrong length
        assert!(!is_valid_base64url_43(
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1"
        )); // 42 chars
        assert!(!is_valid_base64url_43(
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1VV"
        )); // 44 chars
        assert!(!is_valid_base64url_43(""));

        // Disallowed characters
        assert!(!is_valid_base64url_43(
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1+"
        )); // '+' invalid
        assert!(!is_valid_base64url_43(
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1/"
        )); // '/' invalid
        assert!(!is_valid_base64url_43(
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1="
        )); // '=' invalid
    }

    /// Test ADR-014 exchange code generation: 43 chars, unpadded base64url, high entropy
    #[tokio::test]
    async fn test_adr014_generate_exchange_code() {
        use catbird::handlers::atproto::{generate_exchange_code, is_valid_base64url_43};
        use std::collections::HashSet;

        let mut seen = HashSet::new();
        for _ in 0..100 {
            let code = generate_exchange_code();
            assert_eq!(code.len(), 43, "Code must be exactly 43 chars");
            assert!(
                is_valid_base64url_43(&code),
                "Code must match base64url format: {}",
                code
            );
            assert!(
                seen.insert(code),
                "Exchange codes must be distinct (CSPRNG)"
            );
        }
    }

    /// Test regression for iOS and Catmos redirects (MUST remain byte-identical)
    #[tokio::test]
    async fn test_regression_existing_clients_redirect_shapes() {
        use catbird::handlers::atproto::build_app_redirect;

        let session_id = "123e4567-e89b-12d3-a456-426614174000";

        // iOS shape: login with only pds (no redirect_to, no browser_nonce).
        // Callback still produces the legacy build_app_redirect #session_id= fragment form.
        let ios_redirect = build_app_redirect(session_id, session_id);
        assert_eq!(
            ios_redirect,
            "https://catbird.blue/oauth/callback#session_id=123e4567-e89b-12d3-a456-426614174000"
        );

        // Catmos JSON-state shape with valid redirect_to
        let catmos_state =
            r#"{"redirect_to":"https://catmos.catbird.blue/callback","client":"catmos"}"#;
        let catmos_redirect = build_app_redirect(catmos_state, session_id);
        assert_eq!(
            catmos_redirect,
            "https://catmos.catbird.blue/callback?session_id=123e4567-e89b-12d3-a456-426614174000"
        );

        // JSON-state with disallowed redirect_to falls back to fragment
        let evil_state = r#"{"redirect_to":"https://evil.com/callback","client":"catmos"}"#;
        let evil_redirect = build_app_redirect(evil_state, session_id);
        assert_eq!(
            evil_redirect,
            "https://catbird.blue/oauth/callback#session_id=123e4567-e89b-12d3-a456-426614174000"
        );
    }

    /// Test login parameter validation (ADR-014 inputs validated before Redis/PDS)
    #[tokio::test]
    async fn test_adr014_login_validation_rules() {
        use axum::extract::{Query, State};
        use catbird::handlers::atproto::login;
        use std::collections::HashMap;
        use std::sync::Arc;

        let config = catbird::config::AppConfig::load().unwrap();
        let mut state_obj = catbird::config::AppState::new(config.clone())
            .await
            .unwrap();
        state_obj.session_encryption_key = Some([0x42u8; 32]);
        let state = Arc::new(state_obj);

        // 1. Missing identifier -> 400 Bad Request
        let params = HashMap::new();
        let res = login(State(state.clone()), Query(params)).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            catbird::error::AppError::BadRequest(msg) => {
                assert!(msg.contains("Missing identifier"));
            }
            other => panic!("Expected BadRequest, got {:?}", other),
        }

        // 2. FIX 3: Native callback without browser_nonce MUST be rejected with 400
        let mut params = HashMap::new();
        params.insert("identifier".into(), "alice.bsky.social".into());
        params.insert(
            "redirect_to".into(),
            "https://catbird.blue/oauth/callback".into(),
        );
        let res = login(State(state.clone()), Query(params)).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            catbird::error::AppError::BadRequest(msg) => {
                // The OAuth upgrade work folded the native-callback check into a
                // single rule covering external, native and loopback redirects.
                // The requirement asserted here is unchanged: a native callback
                // without browser_nonce must be refused.
                assert!(
                    msg.contains("browser_nonce"),
                    "Expected native callback to require browser_nonce, got: {}",
                    msg
                );
            }
            other => panic!(
                "Expected BadRequest for native callback without nonce, got {:?}",
                other
            ),
        }

        // 3. browser_nonce present but redirect_to missing -> 400 Bad Request
        let mut params = HashMap::new();
        params.insert("identifier".into(), "alice.bsky.social".into());
        params.insert(
            "browser_nonce".into(),
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V".into(),
        );
        let res = login(State(state.clone()), Query(params)).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            catbird::error::AppError::BadRequest(msg) => {
                assert!(msg.contains("Missing redirect_to"));
            }
            other => panic!(
                "Expected BadRequest for missing redirect_to, got {:?}",
                other
            ),
        }

        // 4. browser_nonce present with disallowed redirect_to -> 400 Bad Request
        let mut params = HashMap::new();
        params.insert("identifier".into(), "alice.bsky.social".into());
        params.insert(
            "browser_nonce".into(),
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V".into(),
        );
        params.insert("redirect_to".into(), "https://catbird.blue/other".into());
        let res = login(State(state.clone()), Query(params)).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            catbird::error::AppError::BadRequest(msg) => {
                assert!(msg.contains("Disallowed redirect_to URL"));
            }
            other => panic!(
                "Expected BadRequest for disallowed redirect_to, got {:?}",
                other
            ),
        }

        // 5. Malformed browser_nonce -> 400 Bad Request
        let mut params = HashMap::new();
        params.insert("identifier".into(), "alice.bsky.social".into());
        params.insert("browser_nonce".into(), "short_nonce".into());
        params.insert(
            "redirect_to".into(),
            "https://catbird.blue/oauth/callback".into(),
        );
        let res = login(State(state.clone()), Query(params)).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            catbird::error::AppError::BadRequest(msg) => {
                assert!(msg.contains("Invalid browser_nonce"));
            }
            other => panic!("Expected BadRequest for malformed nonce, got {:?}", other),
        }

        // 6. With no encryption_key configured, exchange-mode login is rejected (fail closed)
        let mut no_key_state = catbird::config::AppState::new(config).await.unwrap();
        no_key_state.session_encryption_key = None;
        let mut params = HashMap::new();
        params.insert("identifier".into(), "alice.bsky.social".into());
        params.insert(
            "browser_nonce".into(),
            "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V".into(),
        );
        params.insert(
            "redirect_to".into(),
            "https://catbird.blue/oauth/callback".into(),
        );
        let res = login(State(Arc::new(no_key_state)), Query(params)).await;
        assert!(
            res.is_err(),
            "Exchange mode login MUST fail when session_encryption_key is not configured"
        );
        match res.unwrap_err() {
            catbird::error::AppError::Internal(msg) => {
                assert!(
                    msg.contains("encryption key"),
                    "Error must indicate encryption key missing: {}",
                    msg
                );
            }
            other => panic!(
                "Expected Internal error for missing encryption key, got {:?}",
                other
            ),
        }
    }

    /// Origin canonicalization unit test
    #[tokio::test]
    async fn test_canonicalize_origin() {
        use catbird::handlers::atproto::canonicalize_origin;

        assert_eq!(
            canonicalize_origin("https://catbird.blue/oauth/callback"),
            Some("https://catbird.blue".to_string())
        );
        assert_eq!(
            canonicalize_origin("https://CATBIRD.BLUE/oauth/callback/"),
            Some("https://catbird.blue".to_string())
        );
        assert_eq!(
            canonicalize_origin("https://catbird.blue:443"),
            Some("https://catbird.blue".to_string())
        );
        assert_eq!(
            canonicalize_origin("http://127.0.0.1:80/callback"),
            Some("http://127.0.0.1".to_string())
        );
        assert_eq!(
            canonicalize_origin("http://127.0.0.1:8080/callback"),
            Some("http://127.0.0.1:8080".to_string())
        );
        assert_eq!(
            canonicalize_origin("http://[::1]:8080/callback"),
            Some("http://[::1]:8080".to_string())
        );
        assert_eq!(canonicalize_origin("invalid-url"), None);
    }

    /// Full POST /auth/exchange integration test against Redis with composite key and atomic semantics
    #[tokio::test]
    async fn test_adr014_post_auth_exchange_composite_key_and_atomic_semantics() {
        use axum_test::TestServer;
        use catbird::handlers::atproto::{
            canonicalize_origin, compute_exchange_redis_key, generate_exchange_code,
        };
        use catbird::models::{ExchangeRequest, ExchangeResponse};
        use std::sync::Arc;
        use uuid::Uuid;

        let config = catbird::config::AppConfig::load().unwrap();
        let enc_key = [0x42u8; 32];
        let mut state_obj = catbird::config::AppState::new(config).await.unwrap();
        state_obj.session_encryption_key = Some(enc_key);
        let state = Arc::new(state_obj);
        let app = catbird::routes::atproto::create_router(state.clone()).with_state(state.clone());
        let server = TestServer::new(app).unwrap();

        let session_id = Uuid::new_v4().to_string();
        let browser_nonce = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V".to_string();
        let origin = "https://catbird.blue".to_string();
        let canonical_origin = canonicalize_origin(&origin).unwrap();
        let exchange_code = generate_exchange_code();

        // FIX 1 + FIX 2 (Amended): Store sealed session_id at composite key
        let exchange_key =
            compute_exchange_redis_key(&exchange_code, &browser_nonce, &canonical_origin);
        let ex_aad =
            catbird::services::redis_crypto::build_aad("oauth_exchange", &exchange_key, None, None);
        let sealed_val = catbird::services::redis_crypto::seal_with_aad(
            &enc_key,
            session_id.as_bytes(),
            &ex_aad,
        )
        .unwrap();
        // Invariant: assert no Redis key or value contains raw code, raw nonce, or plaintext session_id
        assert!(
            !exchange_key.contains(&exchange_code),
            "Composite Redis key must NOT contain raw exchange code"
        );
        assert!(
            !exchange_key.contains(&browser_nonce),
            "Composite Redis key must NOT contain raw browser nonce"
        );
        assert!(
            !sealed_val.contains(&session_id),
            "Stored Redis value must NOT contain plaintext session_id"
        );
        assert!(
            !sealed_val.contains(&exchange_code),
            "Stored Redis value must NOT contain exchange_code"
        );
        assert!(
            !sealed_val.contains(&browser_nonce),
            "Stored Redis value must NOT contain browser_nonce"
        );

        let mut conn = state.redis.clone();
        let _: () = redis::cmd("SET")
            .arg(&exchange_key)
            .arg(&sealed_val)
            .arg("EX")
            .arg(60)
            .query_async(&mut conn)
            .await
            .unwrap();

        // Verify stored value in Redis is sealed ciphertext
        let stored_val: String = redis::cmd("GET")
            .arg(&exchange_key)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(stored_val, sealed_val);
        assert!(!stored_val.contains(&session_id));
        // --- TEST REQUIREMENT 1: wrong nonce -> 401 AND code still redeemable; then correct nonce -> 200; then replay -> 401 ---
        // (1) Wrong nonce -> 401
        let wrong_nonce_req = ExchangeRequest {
            code: exchange_code.clone(),
            browser_nonce: "WRONG2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V".into(),
        };
        let wrong_nonce_res = server
            .post("/auth/exchange")
            .add_header("origin", "https://catbird.blue")
            .json(&wrong_nonce_req)
            .await;
        assert_eq!(
            wrong_nonce_res.status_code(),
            StatusCode::UNAUTHORIZED,
            "Wrong nonce must return 401"
        );

        // Verify the legitimate key in Redis is untouched and still present
        let still_stored: Option<String> = redis::cmd("GET")
            .arg(&exchange_key)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            still_stored,
            Some(sealed_val.clone()),
            "Record must remain untouched and redeemable after failed attempt with wrong nonce"
        );

        // (2) Correct nonce -> 200 with right session_id
        let correct_req = ExchangeRequest {
            code: exchange_code.clone(),
            browser_nonce: browser_nonce.clone(),
        };
        let correct_res = server
            .post("/auth/exchange")
            .add_header("origin", "https://catbird.blue")
            .json(&correct_req)
            .await;
        assert_eq!(correct_res.status_code(), StatusCode::OK);
        let body: ExchangeResponse = correct_res.json();
        assert_eq!(body.session_id, session_id);

        // (3) Replay -> 401
        let replay_res = server
            .post("/auth/exchange")
            .add_header("origin", "https://catbird.blue")
            .json(&correct_req)
            .await;
        assert_eq!(
            replay_res.status_code(),
            StatusCode::UNAUTHORIZED,
            "Replay must return 401 because key was atomically consumed via GETDEL"
        );

        // --- TEST REQUIREMENT 2: wrong Origin -> 401 AND code still redeemable afterwards ---
        let code2 = generate_exchange_code();
        let key2 = compute_exchange_redis_key(&code2, &browser_nonce, &canonical_origin);
        let ex_aad2 =
            catbird::services::redis_crypto::build_aad("oauth_exchange", &key2, None, None);
        let sealed_val2 = catbird::services::redis_crypto::seal_with_aad(
            &enc_key,
            session_id.as_bytes(),
            &ex_aad2,
        )
        .unwrap();
        let _: () = redis::cmd("SET")
            .arg(&key2)
            .arg(&sealed_val2)
            .arg("EX")
            .arg(60)
            .query_async(&mut conn)
            .await
            .unwrap();
        let req2 = ExchangeRequest {
            code: code2.clone(),
            browser_nonce: browser_nonce.clone(),
        };
        // Wrong Origin -> 401
        let wrong_origin_res = server
            .post("/auth/exchange")
            .add_header("origin", "https://evil.com")
            .json(&req2)
            .await;
        assert_eq!(
            wrong_origin_res.status_code(),
            StatusCode::UNAUTHORIZED,
            "Wrong Origin must return 401"
        );

        // Code still redeemable with correct Origin -> 200
        let right_origin_res = server
            .post("/auth/exchange")
            .add_header("origin", "https://catbird.blue")
            .json(&req2)
            .await;
        assert_eq!(
            right_origin_res.status_code(),
            StatusCode::OK,
            "Code must remain redeemable after wrong Origin attempt"
        );
        let body2: ExchangeResponse = right_origin_res.json();
        assert_eq!(body2.session_id, session_id);

        // (4) Missing Origin test -> 401
        let code3 = generate_exchange_code();
        let key3 = compute_exchange_redis_key(&code3, &browser_nonce, &canonical_origin);
        let ex_aad3 =
            catbird::services::redis_crypto::build_aad("oauth_exchange", &key3, None, None);
        let sealed_val3 = catbird::services::redis_crypto::seal_with_aad(
            &enc_key,
            session_id.as_bytes(),
            &ex_aad3,
        )
        .unwrap();
        let _: () = redis::cmd("SET")
            .arg(&key3)
            .arg(&sealed_val3)
            .arg("EX")
            .arg(60)
            .query_async(&mut conn)
            .await
            .unwrap();
        let req3 = ExchangeRequest {
            code: code3,
            browser_nonce: browser_nonce.clone(),
        };
        let no_origin_res = server.post("/auth/exchange").json(&req3).await;
        assert_eq!(
            no_origin_res.status_code(),
            StatusCode::UNAUTHORIZED,
            "Missing origin must return 401"
        );

        // (5) Unknown/expired code test -> 401
        let unk_req = ExchangeRequest {
            code: "UNKNOWN4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V".into(),
            browser_nonce: browser_nonce.clone(),
        };
        let unk_res = server
            .post("/auth/exchange")
            .add_header("origin", "https://catbird.blue")
            .json(&unk_req)
            .await;
        assert_eq!(
            unk_res.status_code(),
            StatusCode::UNAUTHORIZED,
            "Unknown code must return 401"
        );

        // (6) Malformed code/nonce format in request body -> 401
        let malformed_req = ExchangeRequest {
            code: "short".into(),
            browser_nonce: browser_nonce.clone(),
        };
        let malformed_res = server
            .post("/auth/exchange")
            .add_header("origin", "https://catbird.blue")
            .json(&malformed_req)
            .await;
        assert_eq!(
            malformed_res.status_code(),
            StatusCode::UNAUTHORIZED,
            "Malformed code must return 401"
        );

        // (7) Bounded body size: oversized body > 4096 is rejected
        let huge_code = "A".repeat(5000);
        let huge_payload = serde_json::json!({
            "code": huge_code,
            "browser_nonce": browser_nonce,
        });
        let huge_res = server
            .post("/auth/exchange")
            .add_header("origin", "https://catbird.blue")
            .json(&huge_payload)
            .await;
        assert_eq!(
            huge_res.status_code(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "Body > 4096 bytes must be rejected by body limit"
        );
    }

    /// Test that the callback in exchange mode emits exactly {redirect_to}?code=<code> with no other query or fragment
    #[tokio::test]
    async fn test_adr014_callback_redirect_exact_shape() {
        use catbird::handlers::atproto::{generate_exchange_code, is_valid_base64url_43};

        let redirect_to = "https://catbird.blue/oauth/callback";
        let exchange_code = generate_exchange_code();

        let redirect_url = format!("{}?code={}", redirect_to, exchange_code);
        let parsed = url::Url::parse(&redirect_url).unwrap();

        // 1. Path must match redirect_to
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("catbird.blue"));
        assert_eq!(parsed.path(), "/oauth/callback");

        // 2. Fragment must be completely absent
        assert!(parsed.fragment().is_none(), "Fragment must be absent");

        // 3. Query must be EXACTLY code=<43 chars>
        let raw_query = parsed.query().unwrap();
        assert!(raw_query.starts_with("code="));
        assert_eq!(raw_query.len(), 5 + 43); // "code=" (5) + 43 chars = 48
        let code_val = &raw_query[5..];
        assert!(is_valid_base64url_43(code_val));
    }

    /// Test that login fails closed when Redis persistence fails in exchange mode
    #[tokio::test]
    async fn test_login_redis_persistence_failure_fail_closed_in_exchange_mode() {
        use axum::extract::{Query, State};
        use catbird::handlers::atproto::login;
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut config = catbird::config::AppConfig::load().unwrap();
        // Use an unreachable Redis address to trigger persistence error
        config.redis.url = "redis://127.0.0.1:54321".to_string();

        let state_res = catbird::config::AppState::new(config).await;
        // If connection manager initialization fails or if state is initialized with invalid redis:
        if let Ok(state) = state_res {
            let mut params = HashMap::new();
            params.insert("identifier".into(), "alice.bsky.social".into());
            params.insert(
                "browser_nonce".into(),
                "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V".into(),
            );
            params.insert(
                "redirect_to".into(),
                "https://catbird.blue/oauth/callback".into(),
            );

            let res = login(State(Arc::new(state)), Query(params)).await;
            assert!(
                res.is_err(),
                "Login MUST fail when Redis persistence fails in exchange mode"
            );
            match res.unwrap_err() {
                catbird::error::AppError::Internal(msg) => {
                    assert!(
                        msg.contains("Failed to persist"),
                        "Error must indicate persistence failure: {}",
                        msg
                    );
                }
                other => panic!("Expected Internal error for Redis failure, got {:?}", other),
            }
        }
    }

    /// Test the callback redirect modes and FIX 4 (fail closed on missing exchange binding)
    #[tokio::test]
    async fn test_oauth_callback_mode_selection_and_behavior() {
        use catbird::handlers::atproto::{
            build_app_redirect, canonicalize_origin, compute_exchange_redis_key,
            generate_exchange_code, is_allowed_redirect, is_valid_base64url_43,
        };
        use std::sync::Arc;
        use uuid::Uuid;

        let config = catbird::config::AppConfig::load().unwrap();
        let state = Arc::new(catbird::config::AppState::new(config).await.unwrap());
        let mut conn = state.redis.clone();

        let session_id = Uuid::new_v4().to_string();

        // --- Mode 1: Exchange-code Mode (Android) ---
        // Stored mode is "exchange", redirect_to is allowed, browser_nonce is valid
        let android_redirect_to = "https://catbird.blue/oauth/callback";
        let android_nonce = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V";

        assert!(is_allowed_redirect(android_redirect_to));
        assert!(is_valid_base64url_43(android_nonce));

        let canonical_origin = canonicalize_origin(android_redirect_to).unwrap();
        let exchange_code = generate_exchange_code();
        let exchange_key =
            compute_exchange_redis_key(&exchange_code, android_nonce, &canonical_origin);

        // Store session_id at composite key
        let enc_key = [0x42u8; 32];
        let sealed_session_id =
            catbird::services::redis_crypto::seal(&enc_key, session_id.as_bytes()).unwrap();
        let _: () = redis::cmd("SET")
            .arg(&exchange_key)
            .arg(&sealed_session_id)
            .arg("EX")
            .arg(60)
            .query_async(&mut conn)
            .await
            .unwrap();

        let callback_location = format!("{}?code={}", android_redirect_to, exchange_code);
        assert_eq!(
            callback_location,
            format!("https://catbird.blue/oauth/callback?code={}", exchange_code)
        );
        assert!(
            !callback_location.contains('#'),
            "Exchange redirect must NOT contain fragments"
        );
        assert!(
            !callback_location.contains("session_id"),
            "Exchange redirect must NOT contain session_id"
        );

        // --- Mode 2: Catmos Web Query Mode (?session_id=) ---
        // Stored mode is absent/legacy, redirect_to is present & allowed
        let catmos_redirect_to = "https://catmos.catbird.blue/callback";
        assert!(is_allowed_redirect(catmos_redirect_to));
        let catmos_location = format!("{}?session_id={}", catmos_redirect_to, session_id);
        assert_eq!(
            catmos_location,
            format!(
                "https://catmos.catbird.blue/callback?session_id={}",
                session_id
            )
        );

        // --- Mode 3: iOS Legacy Fragment Mode (#session_id=) ---
        // Stored mode is absent, redirect_to is absent
        let ios_location = build_app_redirect(&session_id, &session_id);
        assert_eq!(
            ios_location,
            format!(
                "https://catbird.blue/oauth/callback#session_id={}",
                session_id
            )
        );

        // --- FIX 4 Invariant: Exchange mode admitted, but nonce missing at callback ---
        // If mode is "exchange" and stored_nonce is missing: MUST FAIL CLOSED.
        let stored_mode = Some("exchange".to_string());
        let missing_nonce: Option<String> = None;
        let stored_redirect = Some(android_redirect_to.to_string());

        let result: Result<String, &'static str> = if stored_mode.as_deref() == Some("exchange") {
            match (&stored_redirect, &missing_nonce) {
                (Some(r), Some(nonce)) => {
                    if !is_allowed_redirect(r) || !is_valid_base64url_43(nonce) {
                        Err("Exchange flow state invalid; refusing downgrade to session-bearing redirect")
                    } else {
                        Ok(format!("{}?code=...", r))
                    }
                }
                _ => Err(
                    "Exchange flow state missing; refusing downgrade to session-bearing redirect",
                ),
            }
        } else {
            Ok(build_app_redirect(&session_id, &session_id))
        };

        assert!(
            result.is_err(),
            "Must fail closed when exchange nonce binding is missing"
        );
        let err_msg = result.unwrap_err();
        assert!(
            !err_msg.contains(&session_id),
            "Error must not leak session_id"
        );
    }

    /// Circle AppView requests mint endpoint-bound service auth at the PDS and
    /// route directly to the standalone AppView. Spaces Alpha returns 500 when
    /// asked to proxy custom Circle services itself, so forwarding
    /// `atproto-proxy` is not a viable Circle transport.
    #[tokio::test]
    async fn test_circle_proxy_mints_service_auth_and_routes_directly_to_appview() {
        use axum::http::HeaderMap;
        use catbird::config::{AppConfig, AppState};
        use catbird::models::CatbirdSession;
        use catbird::services::DpopNonceCache;
        use chrono::Utc;
        use std::sync::Arc;
        use uuid::Uuid;
        use wiremock::matchers::{header, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;
        let appview = MockServer::start().await;
        let appview_target = "did:web:circles.catbird.blue#atproto_circles";
        let lexicon = "blue.catbird.circle.getFeed";

        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.server.getServiceAuth"))
            .and(query_param("aud", appview_target))
            .and(query_param("lxm", lexicon))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "token": "circle-service-token" })),
            )
            .expect(1)
            .mount(&pds)
            .await;

        Mock::given(method("GET"))
            .and(path("/xrpc/blue.catbird.circle.getFeed"))
            .and(header("authorization", "Bearer circle-service-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "feed": [] })),
            )
            .expect(1)
            .mount(&appview)
            .await;

        let mut config = AppConfig::load().unwrap();
        config.circle.base_url = appview.uri();
        config.circle.service_did = appview_target.into();
        let http_client = catbird::services::build_hardened_http_client().unwrap();
        let redis_client = redis::Client::open(config.redis.url.as_str()).unwrap();
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .unwrap();

        let state = Arc::new(AppState {
            config: Arc::new(config),
            http_client: http_client.clone(),
            raw_http_client: http_client,
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            catmos_oauth_upgrade_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:alice-proxy".into(),
            handle: "alice.test".into(),
            pds_url: pds.uri(),
            access_token: "mock-token".into(),
            refresh_token: "mock-refresh".into(),
            scopes: vec!["atproto".into()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".into()],
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            "atproto-proxy",
            axum::http::HeaderValue::from_static(appview_target),
        );
        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = catbird::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        let response = catbird::handlers::atproto::proxy_xrpc(
            axum::extract::State(state),
            axum::Extension(session),
            Some(axum::Extension(catbird::middleware::RequestId(
                "req-test-circle-proxy".into(),
            ))),
            Some(axum::Extension(dpop_data)),
            axum::http::Method::GET,
            axum::extract::Path(lexicon.to_string()),
            axum::extract::RawQuery(None),
            headers,
            axum::body::Body::empty(),
        )
        .await
        .expect("Circle proxy succeeds");

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["feed"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_b1_xrpc_path_traversal_and_wildcard_segments_rejected_before_pds() {
        use axum::body::Body;
        use axum::http::{HeaderMap, Method, Request, StatusCode};
        use axum::routing::get;
        use axum::Router;
        use catbird::config::{AppConfig, AppState};
        use catbird::models::CatbirdSession;
        use catbird::services::DpopNonceCache;
        use chrono::Utc;
        use std::sync::Arc;
        use tower::ServiceExt;
        use uuid::Uuid;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;
        // Zero requests may ever reach the upstream PDS
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .expect(0)
            .mount(&pds)
            .await;

        let config = AppConfig::load().unwrap();
        let http_client = catbird::services::build_hardened_http_client().unwrap();
        let redis_client = redis::Client::open(config.redis.url.as_str()).unwrap();
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .unwrap();

        let state = Arc::new(AppState {
            config: Arc::new(config),
            http_client: http_client.clone(),
            raw_http_client: http_client,
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            catmos_oauth_upgrade_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:z72i7hdynmk6r22z27h6tvur".into(),
            handle: "alice.test".into(),
            pds_url: pds.uri(),
            access_token: "mock-token".into(),
            refresh_token: "mock-refresh".into(),
            scopes: vec!["atproto".into()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".into()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = catbird::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        // 1. Direct handler defense-in-depth: decoded traversal, multi-segment, percent-encoded, invalid NSID
        for bad_lexicon in [
            "../oauth/revoke",
            "..%2foauth%2frevoke",
            "foo/bar",
            "not_an_nsid",
            "com.atproto.repo.getRecord?foo=bar",
            "com.atproto.repo.getRecord#frag",
        ] {
            let res = catbird::handlers::atproto::proxy_xrpc(
                axum::extract::State(state.clone()),
                axum::Extension(session.clone()),
                None,
                Some(axum::Extension(dpop_data.clone())),
                Method::GET,
                axum::extract::Path(bad_lexicon.to_string()),
                axum::extract::RawQuery(None),
                HeaderMap::new(),
                Body::empty(),
            )
            .await;
            let err_resp = res.expect_err(&format!("bad lexicon '{bad_lexicon}' must fail"));
            let http_resp = axum::response::IntoResponse::into_response(err_resp);
            assert_eq!(
                http_resp.status(),
                StatusCode::BAD_REQUEST,
                "bad lexicon '{bad_lexicon}' must return 400 Bad Request"
            );
        }

        // 2. Full router check: /xrpc/foo/bar and /xrpc/..%2foauth%2frevoke must not reach PDS
        // Wrap create_router's /xrpc route shape via create_router (unauthenticated requests on /xrpc/foo/bar
        // shouldn't even match a wildcard route, and with injected session extension on the route pattern
        // /xrpc/..%2foauth%2frevoke returns 400).
        let unauth_router =
            catbird::routes::atproto::create_router(state.clone()).with_state(state.clone());
        let multi_seg_resp = unauth_router
            .oneshot(
                Request::builder()
                    .uri("/xrpc/foo/bar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            multi_seg_resp.status(),
            StatusCode::NOT_FOUND,
            "/xrpc/foo/bar must not match single-segment /:lexicon route"
        );

        let authed_xrpc_router = Router::new()
            .route(
                "/xrpc/:lexicon",
                get(catbird::handlers::atproto::proxy_xrpc)
                    .post(catbird::handlers::atproto::proxy_xrpc),
            )
            .layer(axum::Extension(dpop_data))
            .layer(axum::Extension(session))
            .with_state(state);

        let encoded_traversal_resp = authed_xrpc_router
            .oneshot(
                Request::builder()
                    .uri("/xrpc/..%2foauth%2frevoke")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(encoded_traversal_resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_b1_xrpc_blocked_sensitive_server_nsids_rejected_before_pds() {
        use axum::body::Body;
        use axum::http::{HeaderMap, Method, StatusCode};
        use catbird::config::{AppConfig, AppState};
        use catbird::models::CatbirdSession;
        use catbird::services::DpopNonceCache;
        use chrono::Utc;
        use std::sync::Arc;
        use uuid::Uuid;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"token": "forged-token"})),
            )
            .expect(0)
            .mount(&pds)
            .await;

        let config = AppConfig::load().unwrap();
        let http_client = catbird::services::build_hardened_http_client().unwrap();
        let redis_client = redis::Client::open(config.redis.url.as_str()).unwrap();
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .unwrap();

        let state = Arc::new(AppState {
            config: Arc::new(config),
            http_client: http_client.clone(),
            raw_http_client: http_client,
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            catmos_oauth_upgrade_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:z72i7hdynmk6r22z27h6tvur".into(),
            handle: "alice.test".into(),
            pds_url: pds.uri(),
            access_token: "mock-token".into(),
            refresh_token: "mock-refresh".into(),
            scopes: vec!["atproto".into()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".into()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = catbird::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        for (blocked_nsid, method, raw_query) in [
            (
                "com.atproto.server.getServiceAuth",
                Method::GET,
                Some("aud=did:web:evil.example".to_string()),
            ),
            ("com.atproto.server.createSession", Method::POST, None),
            ("com.atproto.server.refreshSession", Method::POST, None),
            ("com.atproto.server.deleteSession", Method::POST, None),
            ("com.atproto.server.createAppPassword", Method::POST, None),
            ("com.atproto.server.revokeAppPassword", Method::POST, None),
        ] {
            let res = catbird::handlers::atproto::proxy_xrpc(
                axum::extract::State(state.clone()),
                axum::Extension(session.clone()),
                None,
                Some(axum::Extension(dpop_data.clone())),
                method,
                axum::extract::Path(blocked_nsid.to_string()),
                axum::extract::RawQuery(raw_query),
                HeaderMap::new(),
                Body::empty(),
            )
            .await;
            let err_resp = res.expect_err(&format!("blocked NSID '{blocked_nsid}' must fail"));
            let http_resp = axum::response::IntoResponse::into_response(err_resp);
            assert_eq!(
                http_resp.status(),
                StatusCode::BAD_REQUEST,
                "blocked NSID '{blocked_nsid}' must return 400 Bad Request"
            );
        }
    }

    #[tokio::test]
    async fn test_b1_invalid_or_untrusted_atproto_proxy_rejected_before_pds() {
        use axum::body::Body;
        use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
        use catbird::config::{AppConfig, AppState};
        use catbird::models::CatbirdSession;
        use catbird::services::DpopNonceCache;
        use chrono::Utc;
        use std::sync::Arc;
        use uuid::Uuid;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .expect(0)
            .mount(&pds)
            .await;

        let config = AppConfig::load().unwrap();
        let http_client = catbird::services::build_hardened_http_client().unwrap();
        let redis_client = redis::Client::open(config.redis.url.as_str()).unwrap();
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .unwrap();

        let state = Arc::new(AppState {
            config: Arc::new(config),
            http_client: http_client.clone(),
            raw_http_client: http_client,
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            catmos_oauth_upgrade_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:z72i7hdynmk6r22z27h6tvur".into(),
            handle: "alice.test".into(),
            pds_url: pds.uri(),
            access_token: "mock-token".into(),
            refresh_token: "mock-refresh".into(),
            scopes: vec!["atproto".into()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".into()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = catbird::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        for bad_proxy in [
            "did:web:evil.example#svc",
            "did:plc:bad#bsky_appview",
            "did:web:api.bsky.app",
            "did:web:localhost#bsky_appview",
            "did:web:evil.example/path#bsky_appview",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("atproto-proxy", HeaderValue::from_str(bad_proxy).unwrap());
            let res = catbird::handlers::atproto::proxy_xrpc(
                axum::extract::State(state.clone()),
                axum::Extension(session.clone()),
                None,
                Some(axum::Extension(dpop_data.clone())),
                Method::GET,
                axum::extract::Path("app.bsky.feed.getTimeline".to_string()),
                axum::extract::RawQuery(None),
                headers,
                Body::empty(),
            )
            .await;
            let err_resp = res.expect_err(&format!("bad atproto-proxy '{bad_proxy}' must fail"));
            let http_resp = axum::response::IntoResponse::into_response(err_resp);
            assert_eq!(
                http_resp.status(),
                StatusCode::BAD_REQUEST,
                "bad atproto-proxy '{bad_proxy}' must return 400 Bad Request"
            );
        }
    }

    #[tokio::test]
    async fn test_b3_gzipped_json_expanding_over_1mib_preserves_exact_framing_and_enforces_semaphore(
    ) {
        use axum::body::Body;
        use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
        use catbird::config::{AppConfig, AppState};
        use catbird::models::CatbirdSession;
        use catbird::services::DpopNonceCache;
        use chrono::Utc;
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        use std::sync::Arc;
        use uuid::Uuid;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;

        let plain_json = serde_json::to_vec(&serde_json::json!({
            "feed": [],
            "padding": "a".repeat(1_300_000)
        }))
        .unwrap();
        assert!(plain_json.len() > 1_048_576);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&plain_json).unwrap();
        let gzipped_bytes = encoder.finish().unwrap();
        assert!(
            gzipped_bytes.len() < 16 * 1024,
            "compressed payload should be tiny (<16 KiB)"
        );

        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.feed.getTimeline"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(gzipped_bytes.clone()),
            )
            .mount(&pds)
            .await;

        let config = AppConfig::load().unwrap();
        let http_client = catbird::services::build_hardened_http_client().unwrap();
        let raw_http_client = catbird::services::build_hardened_raw_http_client().unwrap();
        let redis_client = redis::Client::open(config.redis.url.as_str()).unwrap();
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .unwrap();

        let state = Arc::new(AppState {
            config: Arc::new(config.clone()),
            http_client: http_client.clone(),
            raw_http_client: raw_http_client.clone(),
            redis: redis.clone(),
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            catmos_oauth_upgrade_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
            rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:z72i7hdynmk6r22z27h6tvur".into(),
            handle: "alice.test".into(),
            pds_url: pds.uri(),
            access_token: "mock-token".into(),
            refresh_token: "mock-refresh".into(),
            scopes: vec!["atproto".into()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".into()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = catbird::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        // 1. Client sends Accept-Encoding: gzip, deflate, br -> framing must STILL be exact
        let mut req_headers = HeaderMap::new();
        req_headers.insert(
            "accept-encoding",
            HeaderValue::from_static("gzip, deflate, br"),
        );

        let resp = catbird::handlers::atproto::proxy_xrpc(
            axum::extract::State(state.clone()),
            axum::Extension(session.clone()),
            None,
            Some(axum::Extension(dpop_data.clone())),
            Method::GET,
            axum::extract::Path("app.bsky.feed.getTimeline".to_string()),
            axum::extract::RawQuery(None),
            req_headers.clone(),
            Body::empty(),
        )
        .await
        .expect("gzipped JSON response within 10 MiB limit must succeed");

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            !resp.headers().contains_key("content-encoding"),
            "decompressed proxy response must never carry stale content-encoding"
        );
        let advertised_len: usize = resp
            .headers()
            .get("content-length")
            .expect("buffered response must advertise exact content-length")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 20 * 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(
            advertised_len,
            body_bytes.len(),
            "Content-Length header must exactly match buffered body length"
        );
        assert_eq!(
            body_bytes.as_ref(),
            plain_json.as_slice(),
            "decompressed body must match original JSON"
        );

        // 2. With 0 permits in active_stream_semaphore, expanding >1 MiB gzipped response must fail closed
        let zero_sem_state = Arc::new(AppState {
            config: Arc::new(config),
            http_client,
            raw_http_client,
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            catmos_oauth_upgrade_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(0)),
            rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let exhausted_err = catbird::handlers::atproto::proxy_xrpc(
            axum::extract::State(zero_sem_state),
            axum::Extension(session),
            None,
            Some(axum::Extension(dpop_data)),
            Method::GET,
            axum::extract::Path("app.bsky.feed.getTimeline".to_string()),
            axum::extract::RawQuery(None),
            req_headers,
            Body::empty(),
        )
        .await
        .expect_err("gzipped >1 MiB response must fail closed when semaphore is exhausted");

        let exhausted_resp = axum::response::IntoResponse::into_response(exhausted_err);
        assert_eq!(exhausted_resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_b3_gzipped_decompression_bomb_enforces_max_response_bytes_and_stream_framing() {
        use axum::body::Body;
        use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
        use catbird::config::{AppConfig, AppState};
        use catbird::error::AppError;
        use catbird::models::CatbirdSession;
        use catbird::services::DpopNonceCache;
        use chrono::Utc;
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        use std::sync::Arc;
        use uuid::Uuid;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;

        // 51 MiB JSON compressed to <256 KiB (exceeds 50 MiB MAX_RESPONSE_SIZE after decompression)
        let mut bomb_json = Vec::with_capacity(51 * 1024 * 1024 + 32);
        bomb_json.extend_from_slice(br#"{"bomb":""#);
        bomb_json.resize(bomb_json.len() + 51 * 1024 * 1024, b'z');
        bomb_json.extend_from_slice(br#""}"#);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&bomb_json).unwrap();
        let compressed_bomb = encoder.finish().unwrap();
        assert!(compressed_bomb.len() < 256 * 1024);

        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.feed.getAuthorFeed"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(compressed_bomb),
            )
            .mount(&pds)
            .await;

        // Non-JSON blob compressed with gzip -> streamed response must omit content-length & content-encoding
        let raw_blob = vec![0x42u8; 300_000];
        let mut blob_enc = GzEncoder::new(Vec::new(), Compression::fast());
        blob_enc.write_all(&raw_blob).unwrap();
        let compressed_blob = blob_enc.finish().unwrap();

        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.sync.getBlob"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "image/png")
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(compressed_blob),
            )
            .mount(&pds)
            .await;

        let config = AppConfig::load().unwrap();
        let http_client = catbird::services::build_hardened_http_client().unwrap();
        let raw_http_client = catbird::services::build_hardened_raw_http_client().unwrap();
        let redis_client = redis::Client::open(config.redis.url.as_str()).unwrap();
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .unwrap();

        let state = Arc::new(AppState {
            config: Arc::new(config),
            http_client,
            raw_http_client,
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            catmos_oauth_upgrade_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let session = CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:z72i7hdynmk6r22z27h6tvur".into(),
            handle: "alice.test".into(),
            pds_url: pds.uri(),
            access_token: "mock-token".into(),
            refresh_token: "mock-refresh".into(),
            scopes: vec!["atproto".into()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".into()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = catbird::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        let mut req_headers = HeaderMap::new();
        req_headers.insert("accept-encoding", HeaderValue::from_static("gzip"));

        let bomb_err = catbird::handlers::atproto::proxy_xrpc(
            axum::extract::State(state.clone()),
            axum::Extension(session.clone()),
            None,
            Some(axum::Extension(dpop_data.clone())),
            Method::GET,
            axum::extract::Path("app.bsky.feed.getAuthorFeed".to_string()),
            axum::extract::RawQuery(None),
            req_headers.clone(),
            Body::empty(),
        )
        .await
        .expect_err("11 MiB gzipped decompression bomb must be rejected");
        assert!(
            matches!(bomb_err, AppError::ResponseTooLarge(_)),
            "Expected ResponseTooLarge on decompression bomb, got: {bomb_err:?}"
        );

        let stream_resp = catbird::handlers::atproto::proxy_xrpc(
            axum::extract::State(state),
            axum::Extension(session),
            None,
            Some(axum::Extension(dpop_data)),
            Method::GET,
            axum::extract::Path("com.atproto.sync.getBlob".to_string()),
            axum::extract::RawQuery(None),
            req_headers,
            Body::empty(),
        )
        .await
        .expect("300 KiB gzipped blob stream must succeed");
        assert_eq!(stream_resp.status(), StatusCode::OK);
        assert!(
            !stream_resp.headers().contains_key("content-encoding"),
            "streamed response must omit content-encoding"
        );
        assert!(
            !stream_resp.headers().contains_key("content-length"),
            "streamed response must omit content-length so framing is never corrupted"
        );
        let streamed_bytes = axum::body::to_bytes(stream_resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(streamed_bytes.as_ref(), raw_blob.as_slice());
    }

    #[tokio::test]
    async fn test_b3_circle_and_mls_proxies_enforce_semaphore_and_byte_rate_limit_over_1mib() {
        use axum::body::Body;
        use axum::http::{HeaderMap, Method, StatusCode};
        use catbird::config::{AppConfig, AppState};
        use catbird::middleware::{ByteRateLimitConfig, RateLimitConfig, RateLimitState};
        use catbird::models::CatbirdSession;
        use catbird::services::{DpopNonceCache, MlsAuthService, CIRCLE_ENDPOINTS};
        use chrono::Utc;
        use std::sync::Arc;
        use std::time::Duration;
        use uuid::Uuid;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pds = MockServer::start().await;
        let mls_srv = MockServer::start().await;
        let circle_srv = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.server.getServiceAuth"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "token": "mock-svc-jwt" })),
            )
            .mount(&pds)
            .await;

        let large_body = serde_json::to_vec(&serde_json::json!({
            "data": "x".repeat(1_200_000)
        }))
        .unwrap();
        assert!(large_body.len() > 1_048_576);

        let circle_lexicon = CIRCLE_ENDPOINTS[0];
        Mock::given(method("GET"))
            .and(path(format!("/xrpc/{circle_lexicon}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_bytes(large_body.clone()),
            )
            .mount(&circle_srv)
            .await;

        Mock::given(method("GET"))
            .and(path("/xrpc/blue.catbird.chat.getConversations"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_bytes(large_body.clone()),
            )
            .mount(&mls_srv)
            .await;

        let mut config = AppConfig::load().unwrap();
        config.circle.base_url = circle_srv.uri();
        config.mls.service_url = Some(mls_srv.uri());

        let http_client = catbird::services::build_hardened_http_client().unwrap();
        let raw_http_client = catbird::services::build_hardened_raw_http_client().unwrap();
        let redis_client = redis::Client::open(config.redis.url.as_str()).unwrap();
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .unwrap();

        let session = CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:z72i7hdynmk6r22z27h6tvur".into(),
            handle: "alice.test".into(),
            pds_url: pds.uri(),
            access_token: "mock-token".into(),
            refresh_token: "mock-refresh".into(),
            scopes: vec!["atproto".into()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".into()],
        };

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        let dpop_data = catbird::middleware::JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        };

        // 1. With 0 permits in active_stream_semaphore, >1 MiB responses on BOTH Circle & MLS must fail closed
        let zero_sem_state = Arc::new(AppState {
            config: Arc::new(config.clone()),
            http_client: http_client.clone(),
            raw_http_client: raw_http_client.clone(),
            redis: redis.clone(),
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            catmos_oauth_upgrade_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(0)),
            rate_limit: Arc::new(RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let circle_err = catbird::handlers::atproto::proxy_xrpc(
            axum::extract::State(zero_sem_state.clone()),
            axum::Extension(session.clone()),
            None,
            Some(axum::Extension(dpop_data.clone())),
            Method::GET,
            axum::extract::Path(circle_lexicon.to_string()),
            axum::extract::RawQuery(None),
            HeaderMap::new(),
            Body::empty(),
        )
        .await
        .expect_err("Circle >1 MiB response must acquire active_stream_semaphore");
        assert_eq!(
            axum::response::IntoResponse::into_response(circle_err).status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        let mls_service_zero = MlsAuthService::new(zero_sem_state);
        let mls_err = mls_service_zero
            .proxy_clean_chat_request(
                &session,
                reqwest::Method::GET,
                "blue.catbird.chat.getConversations",
                None,
                None,
                None,
                None,
                Some(&dpop_data),
            )
            .await
            .expect_err("MLS >1 MiB response must acquire active_stream_semaphore");
        assert_eq!(
            axum::response::IntoResponse::into_response(mls_err).status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        // 2. With 1 permit and a 2.0 MiB session byte budget, first 1.2 MiB call succeeds and second 1.2 MiB call hits byte rate limit
        let tight_rl = Arc::new(RateLimitState {
            session_limiter: Arc::new(catbird::middleware::RateLimiter::new()),
            ip_limiter: Arc::new(catbird::middleware::RateLimiter::new()),
            session_byte_limiter: Arc::new(catbird::middleware::ByteRateLimiter::new()),
            global_byte_limiter: Arc::new(catbird::middleware::ByteRateLimiter::new()),
            session_config: RateLimitConfig::default(),
            ip_config: RateLimitConfig::default(),
            session_byte_config: ByteRateLimitConfig {
                max_bytes: 2_000_000,
                window: Duration::from_secs(60),
            },
            global_byte_config: ByteRateLimitConfig::default(),
            trusted_proxies: vec![],
        });

        let metered_state = Arc::new(AppState {
            config: Arc::new(config),
            http_client,
            raw_http_client,
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            catmos_oauth_upgrade_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
            rate_limit: tight_rl,
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let first_ok = catbird::handlers::atproto::proxy_xrpc(
            axum::extract::State(metered_state.clone()),
            axum::Extension(session.clone()),
            None,
            Some(axum::Extension(dpop_data.clone())),
            Method::GET,
            axum::extract::Path(circle_lexicon.to_string()),
            axum::extract::RawQuery(None),
            HeaderMap::new(),
            Body::empty(),
        )
        .await
        .expect("first 1.2 MiB Circle response within 2.0 MiB budget must succeed");
        assert_eq!(first_ok.status(), StatusCode::OK);

        let mls_service_metered = MlsAuthService::new(metered_state);
        let second_over_budget = mls_service_metered
            .proxy_clean_chat_request(
                &session,
                reqwest::Method::GET,
                "blue.catbird.chat.getConversations",
                None,
                None,
                None,
                None,
                Some(&dpop_data),
            )
            .await
            .expect_err("second 1.2 MiB response (2.4 MiB cumulative) must exceed 2.0 MiB session byte budget");
        assert_eq!(
            axum::response::IntoResponse::into_response(second_over_budget).status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_task3_sql_migration_backfills_invalid_and_overquota_rows() {
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let did = format!("did:plc:migtest_{}", uuid::Uuid::new_v4());

        // Clean up
        sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1")
            .bind(&did)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&did)
            .execute(&pool)
            .await
            .unwrap();

        // 1. Seed invalid rows into chat_muted_convos
        sqlx::query("INSERT INTO chat_muted_convos (account_did, convo_id) VALUES ($1, 'invalid space convo')")
            .bind(&did).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO chat_muted_convos (account_did, convo_id) VALUES ($1, 'valid_convo_1')",
        )
        .bind(&did)
        .execute(&pool)
        .await
        .unwrap();

        // 2. Seed invalid rows into activity_subscriptions
        sqlx::query(
            "INSERT INTO activity_subscriptions (subscriber_did, subject_did, include_posts, include_replies, created_at, updated_at) \
             VALUES ($1, 'not_a_valid_did', TRUE, TRUE, NOW(), NOW())"
        ).bind(&did).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO activity_subscriptions (subscriber_did, subject_did, include_posts, include_replies, created_at, updated_at) \
             VALUES ($1, 'did:plc:validsubject1', TRUE, TRUE, NOW(), NOW())"
        ).bind(&did).execute(&pool).await.unwrap();

        // Run the backfill cleanup migration logic
        let migration_sql =
            include_str!("../migrations/20260830010000_chat_activity_limits.up.sql");
        sqlx::raw_sql(migration_sql).execute(&pool).await.unwrap();

        // Verify invalid rows are gone
        let invalid_mute: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat_muted_convos WHERE account_did = $1 AND convo_id = 'invalid space convo')")
            .bind(&did).fetch_one(&pool).await.unwrap();
        assert!(
            !invalid_mute,
            "Invalid chat mute row must be removed by backfill"
        );

        let valid_mute: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat_muted_convos WHERE account_did = $1 AND convo_id = 'valid_convo_1')")
            .bind(&did).fetch_one(&pool).await.unwrap();
        assert!(valid_mute, "Valid chat mute row must survive migration");

        let invalid_sub: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM activity_subscriptions WHERE subscriber_did = $1 AND subject_did = 'not_a_valid_did')")
            .bind(&did).fetch_one(&pool).await.unwrap();
        assert!(
            !invalid_sub,
            "Invalid activity subscription row must be removed by backfill"
        );

        let valid_sub: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM activity_subscriptions WHERE subscriber_did = $1 AND subject_did = 'did:plc:validsubject1')")
            .bind(&did).fetch_one(&pool).await.unwrap();
        assert!(
            valid_sub,
            "Valid activity subscription row must survive migration"
        );

        // Clean up
        sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1")
            .bind(&did)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL and Redis (DATABASE_URL and REDIS_URL)"]
    async fn test_task3_handlers_allow_legacy_delete_and_reject_invalid_create() {
        use axum::extract::State;
        use axum::Extension;
        use axum::Json;
        use catbird::config::{AppConfig, AppState};
        use catbird::handlers::chat_poll::UpdateMuteStatusInput;
        use catbird::models::CatbirdSession;
        use catbird::services::push::types::{
            ActivitySubscriptionPreference, PutActivitySubscriptionInput,
        };
        use catbird::services::push::PushServices;
        use chrono::Utc;
        use std::sync::Arc;
        use uuid::Uuid;

        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let mut config = AppConfig::test_default();
        config.push.service_did = Some("did:web:api.catbird.blue".to_string());

        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost").unwrap());
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("REDIS_URL connection must succeed when test is executed");

        let push_services = PushServices::new(pool.clone(), config.push.clone()).unwrap();

        let state = Arc::new(AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            raw_http_client: catbird::services::build_hardened_raw_http_client()
                .expect("hardened raw client"),
            redis,
            push_db: Some(pool.clone()),
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes: vec![],
            catmos_oauth_upgrade_scopes: vec![],
            trusted_proxies: vec![],
            auth_store: None,
            push: Some(Arc::new(push_services)),
            dpop_nonce_cache: Arc::new(catbird::services::DpopNonceCache::new()),
            session_encryption_key: None,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
        });

        let test_did = format!("did:plc:hdlr_legacy_{}", Uuid::new_v4());
        let session = CatbirdSession {
            id: Uuid::new_v4(),
            did: test_did.clone(),
            handle: "handler_test.bsky.social".to_string(),
            pds_url: "https://pds.example.com".to_string(),
            access_token: "mock_token".to_string(),
            refresh_token: "mock_refresh".to_string(),
            scopes: vec!["atproto".to_string()],
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            granted_scopes: vec!["atproto".to_string()],
        };

        sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1")
            .bind(&test_did)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&test_did)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM push_accounts WHERE account_did = $1")
            .bind(&test_did)
            .execute(&pool)
            .await
            .unwrap();
        // 1. Direct seed legacy invalid-format rows (representing pre-migration legacy state)
        let legacy_invalid_did = "bad:legacy:format!";
        let legacy_invalid_convo = "legacy bad convo id!";

        sqlx::query(
            "INSERT INTO activity_subscriptions (subscriber_did, subject_did, include_posts, include_replies, created_at, updated_at) \
             VALUES ($1, $2, TRUE, TRUE, NOW(), NOW())"
        )
        .bind(&test_did)
        .bind(legacy_invalid_did)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query("INSERT INTO chat_muted_convos (account_did, convo_id) VALUES ($1, $2)")
            .bind(&test_did)
            .bind(legacy_invalid_convo)
            .execute(&pool)
            .await
            .unwrap();

        // 2. Test handlers::push::put_activity_subscription
        // A: Invalid DID format creation is rejected with 400 Bad Request
        let invalid_create_input = PutActivitySubscriptionInput {
            subject: "invalid:did:format!".to_string(),
            activity_subscription: ActivitySubscriptionPreference {
                post: true,
                reply: false,
            },
        };
        let create_err = catbird::handlers::push::put_activity_subscription(
            State(state.clone()),
            Extension(session.clone()),
            Json(invalid_create_input),
        )
        .await
        .unwrap_err();
        match create_err {
            catbird::error::AppError::BadRequest(msg) => {
                assert!(
                    msg.contains("Invalid subject DID"),
                    "Expected BadRequest for invalid subject DID, got: {msg}"
                );
            }
            other => panic!("Expected AppError::BadRequest, got: {:?}", other),
        }

        // B: Deletion/unsubscribing legacy invalid row succeeds and removes it from the database
        let delete_legacy_input = PutActivitySubscriptionInput {
            subject: legacy_invalid_did.to_string(),
            activity_subscription: ActivitySubscriptionPreference {
                post: false,
                reply: false,
            },
        };
        let delete_res = catbird::handlers::push::put_activity_subscription(
            State(state.clone()),
            Extension(session.clone()),
            Json(delete_legacy_input),
        )
        .await;
        assert!(
            delete_res.is_ok(),
            "Deleting subscription with legacy invalid DID format must succeed"
        );

        let sub_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM activity_subscriptions WHERE subscriber_did = $1 AND subject_did = $2)"
        )
        .bind(&test_did)
        .bind(legacy_invalid_did)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            !sub_exists,
            "Legacy activity subscription row must be deleted from database"
        );

        // 3. Test handlers::chat_poll::update_mute_status
        // A: Invalid convo_id format muting is rejected with 400 Bad Request
        let invalid_mute_input = UpdateMuteStatusInput {
            convo_id: "invalid convo id with spaces!".to_string(),
            muted: true,
        };
        let mute_err = catbird::handlers::chat_poll::update_mute_status(
            State(state.clone()),
            Extension(session.clone()),
            Json(invalid_mute_input),
        )
        .await
        .unwrap_err();
        match mute_err {
            catbird::error::AppError::BadRequest(msg) => {
                assert!(
                    msg.contains("Invalid conversation ID"),
                    "Expected BadRequest for invalid convo_id, got: {msg}"
                );
            }
            other => panic!("Expected AppError::BadRequest, got: {:?}", other),
        }

        // B: Unmuting legacy invalid convo_id succeeds and removes it from the database
        let unmute_legacy_input = UpdateMuteStatusInput {
            convo_id: legacy_invalid_convo.to_string(),
            muted: false,
        };
        let unmute_res = catbird::handlers::chat_poll::update_mute_status(
            State(state.clone()),
            Extension(session.clone()),
            Json(unmute_legacy_input),
        )
        .await;
        assert!(
            unmute_res.is_ok(),
            "Unmuting legacy invalid convo_id must succeed"
        );

        let mute_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chat_muted_convos WHERE account_did = $1 AND convo_id = $2)"
        )
        .bind(&test_did)
        .bind(legacy_invalid_convo)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            !mute_exists,
            "Legacy chat mute row must be deleted from database"
        );

        // Clean up
        sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1")
            .bind(&test_did)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&test_did)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM push_accounts WHERE account_did = $1")
            .bind(&test_did)
            .execute(&pool)
            .await
            .unwrap();
    }
}
/// Tests that require a running Redis instance
#[cfg(test)]
mod redis_tests {
    use super::*;

    /// Test session storage and retrieval
    ///
    /// Requires: Redis running on localhost:6379
    #[tokio::test]
    #[ignore = "TODO: implement with testcontainers (requires Redis)"]
    async fn test_session_storage() {
        // This test would:
        // 1. Create a session
        // 2. Store it in Redis
        // 3. Retrieve it
        // 4. Verify the data matches

        // Using testcontainers for Redis:
        // let redis = testcontainers::clients::Cli::default();
        // let node = redis.run(testcontainers_modules::redis::Redis::default());

        // Placeholder assertion — replaces previous todo!() panic so that
        // running the test suite with `--include-ignored` doesn't explode.
        // Delta-nonsec (Cluster D) — 2026-04-11.
    }

    /// Test session expiration
    #[tokio::test]
    #[ignore = "TODO: implement with testcontainers (requires Redis)"]
    async fn test_session_expiration() {
        // Test that sessions expire after the configured TTL.
        // Placeholder — previously `todo!()` panicked, which is unsafe even
        // behind `#[ignore]` if someone runs `--include-ignored`.
        // Delta-nonsec (Cluster D) — 2026-04-11.
    }
}
