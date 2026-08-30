//! ATProto Routes
//!
//! Defines the routing structure for ATProto-related endpoints including:
//! - Authentication endpoints (/auth/*)
//! - XRPC proxy endpoints (/xrpc/*)
//! - OAuth metadata endpoints (/.well-known/*)

use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
    Router,
};
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::sync::Arc;

use crate::config::AppState;
use crate::handlers::{atproto, oauth_upgrade, push};
use crate::middleware::{auth_middleware, ip_rate_limit, session_rate_limit, RateLimitState};

/// Create the ATProto router
///
/// This creates all routes for:
/// - /auth/* - Authentication endpoints
/// - /xrpc/* - AT Protocol XRPC proxy
/// - /.well-known/* - OAuth metadata
pub fn create_router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    let rate_limit_state = state.rate_limit.clone();
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
        .route(
            "/callback",
            get(atproto::oauth_callback).layer(middleware::from_fn_with_state(
                rate_limit_state.clone(),
                ip_rate_limit,
            )),
        )
        .route(
            "/exchange",
            post(atproto::exchange_code)
                .layer(DefaultBodyLimit::max(4096))
                .layer(middleware::from_fn_with_state(
                    rate_limit_state.clone(),
                    ip_rate_limit,
                )),
        )
        // Progressive OAuth scope upgrade routes
        .route(
            "/upgrade",
            post(oauth_upgrade::upgrade_start)
                .layer(DefaultBodyLimit::max(4096))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    rate_limit_state.clone(),
                    ip_rate_limit,
                )),
        )
        .route(
            "/upgrade/exchange",
            post(oauth_upgrade::upgrade_exchange)
                .layer(DefaultBodyLimit::max(4096))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    rate_limit_state.clone(),
                    ip_rate_limit,
                )),
        )
        .route(
            "/upgrade/commit",
            post(oauth_upgrade::upgrade_commit)
                .layer(DefaultBodyLimit::max(4096))
                .layer(middleware::from_fn_with_state(
                    rate_limit_state.clone(),
                    ip_rate_limit,
                )),
        )
        // Protected auth routes
        .route(
            "/logout",
            post(atproto::logout)
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    rate_limit_state.clone(),
                    ip_rate_limit,
                )),
        )
        .route(
            "/session",
            get(atproto::get_session)
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    rate_limit_state.clone(),
                    ip_rate_limit,
                )),
        );

    // XRPC proxy routes - protected with auth and session-based rate limiting
    let xrpc_routes = Router::new()
        .route(
            "/app.bsky.notification.registerPush",
            post(push::register_push),
        )
        .route(
            "/app.bsky.notification.unregisterPush",
            post(push::unregister_push),
        )
        .route(
            "/app.bsky.notification.getPreferences",
            get(push::get_preferences),
        )
        .route(
            "/app.bsky.notification.putPreferencesV2",
            post(push::put_preferences_v2),
        )
        .route(
            "/app.bsky.notification.listActivitySubscriptions",
            get(push::list_activity_subscriptions),
        )
        .route(
            "/app.bsky.notification.putActivitySubscription",
            post(push::put_activity_subscription),
        )
        .route(
            "/blue.catbird.bskychat.pushHeartbeat",
            post(crate::handlers::chat_poll::push_heartbeat),
        )
        .route(
            "/blue.catbird.bskychat.updateMuteStatus",
            post(crate::handlers::chat_poll::update_mute_status),
        )
        .route(
            "/*lexicon",
            get(atproto::proxy_xrpc).post(atproto::proxy_xrpc),
        )
        .layer(DefaultBodyLimit::max(11 * 1024 * 1024)) // 11 MB for blob uploads (10 MB + overhead)
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
        .route("/jwks.json", get(jwks))
        .route("/oauth-client-metadata", get(oauth_client_metadata));

    Router::new()
        .nest("/auth", auth_routes)
        .nest("/xrpc", xrpc_routes)
        .nest("/.well-known", wellknown_routes)
}

/// OAuth client metadata endpoint
///
/// GET /.well-known/oauth-client-metadata
///
/// Returns the OAuth client metadata document for this gateway.
/// Required by AT Protocol OAuth for client_id validation.
async fn oauth_client_metadata(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    let base_url = &state.config.server.base_url;
    axum::Json(serde_json::json!({
        "client_id": state.config.oauth.client_id,
        "client_name": "Catbird",
        "client_uri": base_url,
        "logo_uri": format!("{}/logo.png", base_url),
        "tos_uri": format!("{}/terms", base_url),
        "policy_uri": format!("{}/privacy", base_url),
        "redirect_uris": [&state.config.oauth.redirect_uri],
        "scope": state.config.oauth.scopes.join(" "),
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks_uri": format!("{}/.well-known/jwks.json", base_url),
        "application_type": "web",
        "dpop_bound_access_tokens": true,
    }))
}

/// JWKS endpoint
///
/// GET /.well-known/jwks.json
///
/// Returns the public keys for client authentication.
/// Supports multiple keys for key rotation.
async fn jwks(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    if let Some(key_store) = &state.key_store {
        let keys = key_store.to_jwks();
        return axum::Json(serde_json::json!({ "keys": keys }));
    }

    axum::Json(serde_json::json!({ "keys": [] }))
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

    if let Some(key_store) = &state.key_store {
        let keys = key_store.all_keys();
        let verification_methods: Vec<serde_json::Value> = keys
            .iter()
            .map(|key| {
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
                    "id": format!("{}#{}", gateway_did, key.kid),
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

        let key_refs: Vec<String> = keys
            .iter()
            .map(|key| format!("{}#{}", gateway_did, key.kid))
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

    // No key_store configured — return empty document
    axum::Json(serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": gateway_did,
        "verificationMethod": [],
        "authentication": [],
        "assertionMethod": []
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_callback_route_ip_rate_limit_enforced() {
        let trusted_net: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let rate_limit_state = Arc::new(RateLimitState::with_trusted_proxies(vec![trusted_net]));
        let proxy_peer = std::net::SocketAddr::from(([10, 0, 0, 1], 12345));

        let app = Router::new().route(
            "/auth/callback",
            get(|req: Request<Body>| async move {
                let uri = req.uri().to_string();
                assert!(uri.contains("code=test_code"));
                assert!(uri.contains("state=test_state"));
                StatusCode::OK
            })
            .layer(middleware::from_fn_with_state(
                rate_limit_state.clone(),
                ip_rate_limit,
            )),
        );

        // First 20 requests from same IP through trusted proxy should succeed and pass query params through
        for _ in 0..20 {
            let req = Request::builder()
                .uri("/auth/callback?code=test_code&state=test_state")
                .header("x-forwarded-for", "198.51.100.42")
                .extension(axum::extract::ConnectInfo(proxy_peer))
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

        // 21st request from same IP should be rate limited with 429
        let req = Request::builder()
            .uri("/auth/callback?code=test_code&state=test_state")
            .header("x-forwarded-for", "198.51.100.42")
            .extension(axum::extract::ConnectInfo(proxy_peer))
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

        // Request from a different IP through trusted proxy should still succeed
        let req = Request::builder()
            .uri("/auth/callback?code=test_code&state=test_state")
            .header("x-forwarded-for", "198.51.100.43")
            .extension(axum::extract::ConnectInfo(proxy_peer))
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
