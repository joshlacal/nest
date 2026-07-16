//! ATProto Routes
//!
//! Defines the routing structure for ATProto-related endpoints including:
//! - Authentication endpoints (/auth/*)
//! - XRPC proxy endpoints (/xrpc/*)
//! - OAuth metadata endpoints (/.well-known/*)

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, MatchedPath, OriginalUri},
    http::Request,
    middleware,
    response::Response,
    routing::{get, post},
    Router,
};
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::sync::Arc;

use crate::config::AppState;
use crate::error::AppError;
use crate::handlers::{atproto, push};
use crate::middleware::{
    auth_middleware, ip_rate_limit, logout_auth_middleware, session_rate_limit, RateLimitState,
};

async fn validate_proxy_lexicon_before_auth(
    request: Request<Body>,
    next: middleware::Next,
) -> Result<Response, AppError> {
    let is_wildcard_proxy = request
        .extensions()
        .get::<MatchedPath>()
        .is_some_and(|path| path.as_str().ends_with("/*lexicon"));

    if is_wildcard_proxy {
        let raw_path = request
            .extensions()
            .get::<OriginalUri>()
            .map(|uri| uri.0.path())
            .unwrap_or_else(|| request.uri().path());
        let raw_lexicon = raw_path
            .strip_prefix("/xrpc/")
            .ok_or_else(|| AppError::BadRequest("Invalid XRPC NSID".into()))?;
        atproto::ValidatedProxyLexicon::from_raw_route_tail(raw_lexicon)?;
    }

    Ok(next.run(request).await)
}

fn with_pre_auth_proxy_guard<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(middleware::from_fn(validate_proxy_lexicon_before_auth))
}

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
        .route(
            "/exchange",
            post(atproto::exchange_oauth_code)
                .layer(DefaultBodyLimit::max(1024))
                .layer(middleware::from_fn_with_state(
                    rate_limit_state.clone(),
                    ip_rate_limit,
                )),
        )
        // Protected auth routes
        .route(
            "/logout",
            post(atproto::logout).layer(middleware::from_fn_with_state(
                state.clone(),
                logout_auth_middleware,
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
    let xrpc_routes = with_pre_auth_proxy_guard(
        Router::new()
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
            )),
    );

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
    use super::with_pre_auth_proxy_guard;
    use axum::{
        body::Body,
        extract::{Path, RawQuery, State},
        http::{header::AUTHORIZATION, Request, StatusCode},
        middleware::{self, Next},
        response::{IntoResponse, Response},
        routing::{get, post},
        Extension, Router,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use tower::ServiceExt;

    #[derive(Default)]
    struct RouteSentinels {
        index_lookup: AtomicUsize,
        registry_get: AtomicUsize,
        refresh: AtomicUsize,
        body: AtomicUsize,
        metrics: AtomicUsize,
        mls: AtomicUsize,
        pds: AtomicUsize,
        dpop: AtomicUsize,
        outbound: AtomicUsize,
        named: AtomicUsize,
    }

    impl RouteSentinels {
        fn auth_counts(&self) -> [usize; 3] {
            [
                self.index_lookup.load(Ordering::SeqCst),
                self.registry_get.load(Ordering::SeqCst),
                self.refresh.load(Ordering::SeqCst),
            ]
        }

        fn downstream_counts(&self) -> [usize; 6] {
            [
                self.body.load(Ordering::SeqCst),
                self.metrics.load(Ordering::SeqCst),
                self.mls.load(Ordering::SeqCst),
                self.pds.load(Ordering::SeqCst),
                self.dpop.load(Ordering::SeqCst),
                self.outbound.load(Ordering::SeqCst),
            ]
        }

        fn record_handler_entry(&self) {
            self.body.fetch_add(1, Ordering::SeqCst);
            self.metrics.fetch_add(1, Ordering::SeqCst);
            self.mls.fetch_add(1, Ordering::SeqCst);
            self.pds.fetch_add(1, Ordering::SeqCst);
            self.dpop.fetch_add(1, Ordering::SeqCst);
            self.outbound.fetch_add(1, Ordering::SeqCst);
        }
    }

    type SeenRequests = Arc<Mutex<Vec<(String, Option<String>, String)>>>;

    #[derive(Clone, Default)]
    struct RouteProbe {
        sentinels: Arc<RouteSentinels>,
        seen: SeenRequests,
    }

    async fn expired_refreshable_auth_probe(
        Extension(probe): Extension<RouteProbe>,
        request: Request<Body>,
        next: Next,
    ) -> Response {
        let Some(session_id) = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return StatusCode::UNAUTHORIZED.into_response();
        };

        probe.sentinels.index_lookup.fetch_add(1, Ordering::SeqCst);
        probe.sentinels.registry_get.fetch_add(1, Ordering::SeqCst);
        if session_id == "expired-refreshable" {
            probe.sentinels.refresh.fetch_add(1, Ordering::SeqCst);
        }
        next.run(request).await
    }

    async fn wildcard_probe(
        State(probe): State<RouteProbe>,
        Path(lexicon): Path<String>,
        RawQuery(raw_query): RawQuery,
        request: Request<Body>,
    ) -> Response {
        probe.sentinels.record_handler_entry();
        probe
            .seen
            .lock()
            .unwrap()
            .push((lexicon.clone(), raw_query, request.method().to_string()));
        (StatusCode::OK, lexicon).into_response()
    }

    async fn named_probe(State(probe): State<RouteProbe>) -> StatusCode {
        probe.sentinels.named.fetch_add(1, Ordering::SeqCst);
        StatusCode::NO_CONTENT
    }

    fn routed_probe(probe: RouteProbe) -> Router {
        let xrpc = with_pre_auth_proxy_guard(
            Router::new()
                .route("/app.bsky.notification.registerPush", post(named_probe))
                .route("/*lexicon", get(wildcard_probe).post(wildcard_probe))
                .layer(middleware::from_fn(expired_refreshable_auth_probe)),
        );

        Router::new()
            .nest("/xrpc", xrpc)
            .layer(Extension(probe.clone()))
            .with_state(probe)
    }

    #[tokio::test]
    async fn proxy_lexicon_malformed_routes_fail_before_auth_refresh_and_downstream() {
        let authority_254 = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62),
            "method".to_string(),
        ]
        .join(".");
        assert_eq!(authority_254.rsplit_once('.').unwrap().0.len(), 254);
        assert!(authority_254.len() <= 317);
        let oversized_authority_uri = format!("/xrpc/{authority_254}");

        let malformed = [
            "/xrpc/%61pp.bsky.feed.getTimeline",
            "/xrpc/app%2Ebsky.feed.getTimeline",
            "/xrpc/app%2ebsky.feed.getTimeline",
            "/xrpc/app.bsky.feed.getTim%65line",
            "/xrpc/app.bsky.feed%2fgetTimeline",
            "/xrpc/app.bsky.feed%252fgetTimeline",
            "/xrpc/.%2e",
            "/xrpc/%2e.",
            "/xrpc/app.bsky.%2e.getTimeline",
            "/xrpc/app%E3%80%82bsky.feed.getTimeline",
            "/xrpc/%EF%BD%81pp.bsky.feed.getTimeline",
            "/xrpc/app_bsky.feed.getTimeline",
            "/xrpc/app.bsky.feed%FFgetTimeline",
        ];

        for uri in malformed
            .into_iter()
            .chain(std::iter::once(oversized_authority_uri.as_str()))
        {
            let probe = RouteProbe::default();
            let response = routed_probe(probe.clone())
                .oneshot(
                    Request::get(uri)
                        .header(AUTHORIZATION, "Bearer expired-refreshable")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "URI {uri}");
            assert_eq!(probe.sentinels.auth_counts(), [0; 3], "URI {uri}");
            assert_eq!(probe.sentinels.downstream_counts(), [0; 6], "URI {uri}");
            assert!(probe.seen.lock().unwrap().is_empty(), "URI {uri}");
        }
    }

    #[tokio::test]
    async fn proxy_lexicon_valid_get_post_and_query_reach_auth_and_handler_once() {
        for method in ["GET", "POST"] {
            let probe = RouteProbe::default();
            let response = routed_probe(probe.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/xrpc/custom.example.dynamicMethod?feed=a&feed=b")
                        .header(AUTHORIZATION, "Bearer expired-refreshable")
                        .body(Body::from("preserved-body"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(probe.sentinels.auth_counts(), [1; 3]);
            assert_eq!(probe.sentinels.downstream_counts(), [1; 6]);
            assert_eq!(
                *probe.seen.lock().unwrap(),
                [(
                    "custom.example.dynamicMethod".to_string(),
                    Some("feed=a&feed=b".to_string()),
                    method.to_string(),
                )]
            );
        }
    }

    #[tokio::test]
    async fn proxy_lexicon_named_routes_bypass_guard_and_keep_auth() {
        let probe = RouteProbe::default();
        let response = routed_probe(probe.clone())
            .oneshot(
                Request::post("/xrpc/app.bsky.notification.registerPush")
                    .header(AUTHORIZATION, "Bearer expired-refreshable")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(probe.sentinels.auth_counts(), [1; 3]);
        assert_eq!(probe.sentinels.downstream_counts(), [0; 6]);
        assert_eq!(probe.sentinels.named.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn proxy_lexicon_malformed_unauthenticated_precedes_authentication() {
        let malformed_probe = RouteProbe::default();
        let malformed = routed_probe(malformed_probe.clone())
            .oneshot(
                Request::get("/xrpc/app.bsky.feed%2fgetTimeline")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(malformed_probe.sentinels.auth_counts(), [0; 3]);
        assert_eq!(malformed_probe.sentinels.downstream_counts(), [0; 6]);

        let valid_probe = RouteProbe::default();
        let valid = routed_probe(valid_probe.clone())
            .oneshot(
                Request::get("/xrpc/custom.example.dynamicMethod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(valid.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(valid_probe.sentinels.auth_counts(), [0; 3]);
        assert_eq!(valid_probe.sentinels.downstream_counts(), [0; 6]);
    }
}
