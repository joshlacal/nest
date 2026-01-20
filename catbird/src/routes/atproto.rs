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
use crate::middleware::auth_middleware;
use crate::services::CryptoService;

/// Create the ATProto router
///
/// This creates all routes for:
/// - /auth/* - Authentication endpoints
/// - /xrpc/* - AT Protocol XRPC proxy
/// - /.well-known/* - OAuth metadata
pub fn create_router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    // Auth routes (some protected, some public)
    let auth_routes = Router::new()
        .route("/login", get(atproto::login).post(atproto::login))
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

    // XRPC proxy routes - protected and enriched
    let xrpc_routes = Router::new()
        .route(
            "/*lexicon",
            get(atproto::proxy_xrpc).post(atproto::proxy_xrpc),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Well-known routes for OAuth metadata
    let wellknown_routes = Router::new()
        .route("/oauth-client-metadata", get(oauth_client_metadata))
        .route("/jwks.json", get(jwks));

    Router::new()
        .nest("/auth", auth_routes)
        .nest("/xrpc", xrpc_routes)
        .nest("/.well-known", wellknown_routes)
}

/// OAuth Client Metadata endpoint
///
/// GET /.well-known/oauth-client-metadata
///
/// Returns the OAuth client metadata required for ATProto OAuth.
async fn oauth_client_metadata(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "client_id": state.config.oauth.client_id,
        "client_name": "Catbird",
        "client_uri": state.config.server.base_url,
        "logo_uri": format!("{}/logo.png", state.config.server.base_url),
        "tos_uri": format!("{}/terms", state.config.server.base_url),
        "policy_uri": format!("{}/privacy", state.config.server.base_url),
        "redirect_uris": [&state.config.oauth.redirect_uri],
        "scope": state.config.oauth.scopes.join(" "),
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks_uri": format!("{}/.well-known/jwks.json", state.config.server.base_url),
        "application_type": "web",
        "dpop_bound_access_tokens": true,
    }))
}

/// JWKS endpoint
///
/// GET /.well-known/jwks.json
///
/// Returns the public keys for client authentication.
async fn jwks(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
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
