//! ATProto Routes
//!
//! Defines the routing structure for ATProto-related endpoints including:
//! - Authentication endpoints (/auth/*)
//! - XRPC proxy endpoints (/xrpc/*)
//! - OAuth metadata endpoints (/.well-known/*)

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::sync::Arc;

use crate::config::AppState;
use crate::handlers::atproto;
use crate::middleware::{auth_middleware, ip_rate_limit, session_rate_limit, RateLimitState};
use crate::services::CryptoService;

/// Create the ATProto router
///
/// This creates all routes for:
/// - /auth/* - Authentication endpoints
/// - /xrpc/* - AT Protocol XRPC proxy
/// - /.well-known/* - OAuth metadata
pub fn create_router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    // Create rate limit state with default configuration
    let rate_limit_state = Arc::new(RateLimitState::default());

    // Start background cleanup task for rate limiter
    rate_limit_state.clone().start_cleanup_task();

    // Auth routes (some protected, some public)
    // Login has stricter IP-based rate limiting
    let auth_routes = Router::new()
        .route(
            "/login",
            get(atproto::login)
                .post(atproto::login)
                .layer(middleware::from_fn_with_state(
                    rate_limit_state.clone(),
                    ip_rate_limit,
                )),
        )
        .route("/callback", get(atproto::oauth_callback))
        // Protected auth routes
        .route(
            "/logout",
            post(atproto::logout).layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .route(
            "/session",
            get(atproto::get_session).layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        );

    // XRPC proxy routes - protected with auth and session-based rate limiting
    let xrpc_routes = Router::new()
        .route(
            "/*lexicon",
            get(atproto::proxy_xrpc).post(atproto::proxy_xrpc),
        )
        .layer(middleware::from_fn_with_state(
            rate_limit_state.clone(),
            session_rate_limit,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Well-known routes for OAuth metadata
    let wellknown_routes = Router::new()
        .route("/did.json", get(did_document))
        .route("/jwks.json", get(jwks));

    Router::new()
        .nest("/auth", auth_routes)
        .nest("/xrpc", xrpc_routes)
        .nest("/.well-known", wellknown_routes)
}

// NOTE: OAuth client metadata is served statically by nginx at
// https://catbird.blue/oauth-client-metadata.json
// No dynamic endpoint needed here.

/// JWKS endpoint
///
/// GET /.well-known/jwks.json
///
/// Returns the public keys for client authentication.
/// Supports multiple keys for key rotation.
async fn jwks(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    // Use KeyStore if available (multi-key mode)
    if let Some(key_store) = &state.key_store {
        let keys = key_store.to_jwks();
        return axum::Json(serde_json::json!({ "keys": keys }));
    }

    // Fallback to legacy single-key mode
    let crypto_service = CryptoService::new(state.clone());
    let private_key = match crypto_service.load_private_key() {
        Ok(key) => key,
        Err(error) => {
            tracing::error!("Failed to load private key for JWKS: {}", error);
            return axum::Json(serde_json::json!({ "keys": [] }));
        }
    };
    let verifying_key = private_key.public_key();
    let encoded = verifying_key.to_encoded_point(false);
    let x = encoded
        .x()
        .map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
        .unwrap_or_default();
    let y = encoded
        .y()
        .map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
        .unwrap_or_default();

    axum::Json(serde_json::json!({
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "use": "sig",
                "kid": "catbird-key-1",
                "x": x,
                "y": y,
            }
        ]
    }))
}

/// DID Document endpoint
///
/// GET /.well-known/did.json
///
/// Returns the DID document for this gateway (did:web resolution).
/// This allows the MLS server to verify JWTs signed by this gateway.
/// Includes all configured keys for key rotation support.
async fn did_document(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    // Get the gateway DID from config, or derive from base_url
    let gateway_did = state.config.mls.gateway_did.clone().unwrap_or_else(|| {
        // Derive did:web from base_url (e.g., https://api.catbird.blue -> did:web:api.catbird.blue)
        let base = &state.config.server.base_url;
        let host = base
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("localhost");
        format!("did:web:{}", host)
    });

    // Use KeyStore if available (multi-key mode)
    if let Some(key_store) = &state.key_store {
        let keys = key_store.all_keys();
        let verification_methods: Vec<serde_json::Value> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let public_key = key.secret_key.public_key();
                let encoded = public_key.to_encoded_point(false);
                let x = encoded
                    .x()
                    .map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
                    .unwrap_or_default();
                let y = encoded
                    .y()
                    .map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
                    .unwrap_or_default();

                serde_json::json!({
                    "id": format!("{}#key-{}", gateway_did, i + 1),
                    "type": "JsonWebKey2020",
                    "controller": gateway_did,
                    "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "kid": key.kid,
                        "x": x,
                        "y": y,
                    }
                })
            })
            .collect();

        let key_refs: Vec<String> = (1..=keys.len())
            .map(|i| format!("{}#key-{}", gateway_did, i))
            .collect();

        return axum::Json(serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ],
            "id": gateway_did,
            "verificationMethod": verification_methods,
            "authentication": key_refs,
            "assertionMethod": key_refs
        }));
    }

    // Fallback to legacy single-key mode
    let crypto_service = CryptoService::new(state.clone());
    let private_key = match crypto_service.load_private_key() {
        Ok(key) => key,
        Err(error) => {
            tracing::error!("Failed to load private key for DID document: {}", error);
            return axum::Json(serde_json::json!({
                "error": "Failed to load signing key"
            }));
        }
    };
    
    let verifying_key = private_key.public_key();
    let encoded = verifying_key.to_encoded_point(false);
    let x = encoded
        .x()
        .map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
        .unwrap_or_default();
    let y = encoded
        .y()
        .map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
        .unwrap_or_default();

    axum::Json(serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": gateway_did,
        "verificationMethod": [
            {
                "id": format!("{}#key-1", gateway_did),
                "type": "JsonWebKey2020",
                "controller": gateway_did,
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": x,
                    "y": y,
                }
            }
        ],
        "authentication": [
            format!("{}#key-1", gateway_did)
        ],
        "assertionMethod": [
            format!("{}#key-1", gateway_did)
        ]
    }))
}
