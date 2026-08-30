//! Progressive OAuth Upgrade Integration Tests
//!
//! Thorough test suite for progressive OAuth scope upgrades covering:
//! 1. Missing/cookie-only/wrong/malformed bearer start rejected (401)
//! 2. Unknown/disallowed/excluded scope rejected (400)
//! 3. Initial login still sends core subset (no progressive upgrade scopes)
//! 4. Denial/cancellation leaves old /auth/session valid (302 to permission callback, no cookie)
//! 5. Upgrade callback sets no cookie and leaks no raw session/DID/grants in redirect URL
//! 6. Wrong nonce/origin/bearer cannot burn exchange (composite key GETDEL)
//! 7. Staged candidate gets 401 on /auth/session and /xrpc
//! 8. Commit is idempotent (receipt returned on replay)
//! 9. Old session rejected after commit (401 on /auth/session and /xrpc)
//! 10. Commit returns same DID and authoritative updated scopes
//! 11. Concurrent candidate loses without leaking winning candidate ID

use std::collections::BTreeSet;
use std::process::{Child, Command};
use std::sync::{Arc, Once};
use std::time::Duration;

use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use base64::Engine;
use chrono::Utc;
use jacquard_common::types::did::Did;
use jacquard_common::IntoStatic;
use jacquard_identity::resolver::{PlcSource, ResolverOptions};
use jacquard_identity::JacquardResolver;
use jacquard_oauth::atproto::{AtprotoClientMetadata, GrantType};
use jacquard_oauth::authstore::ClientAuthStore;
use jacquard_oauth::scopes::{IdentityScope, Scope, Scopes, TransitionScope};
use jacquard_oauth::session::{ClientData, ClientSessionData, DpopClientData};
use jacquard_oauth::types::{OAuthTokenType, TokenSet};
use serde_json::{json, Value};
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::redis::Redis;
use tokio::sync::Barrier;
use tokio::time::sleep;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request as WiremockRequest, ResponseTemplate};

use catbird::config::{AppConfig, AppState, JacquardOAuthClient};
use catbird::models::{ALLOWLISTED_UPGRADE_SCOPES, FIXED_UPGRADE_CALLBACK_URL};
use catbird::routes::atproto::create_router;
use catbird::services::{HardenedHttpClient, OAuthUpgradeService, RedisAuthStore, DEFAULT_UPGRADE_CALLBACK_URL};

/// Test encryption key for deterministic AES-256-GCM fixture storage
const TEST_ENCRYPTION_KEY: [u8; 32] = [0x42u8; 32];
static INIT_TEST_ENV: Once = Once::new();
const BROWSER_NONCE: &str = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V";
const CATBIRD_ORIGIN: &str = "https://catbird.blue";
const FIXED_TEST_DID: &str = "did:plc:upgradetestuser";

/// Deterministic ES256 PKCS#8 PEM private key for test confidential client
const TEST_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgED1AAgC7Fc9kPh5T
4i4Tn+z+tc47W1zYgzXtyjJtD92hRANCAAT80DqC+Z/JpTO7/pkPBmWqIV1IGh1P
gbGGr0pN+oSing7cZ0169JaRHTNh+0LNQXrFobInX6cj95FzEdRyT4T3
-----END PRIVATE KEY-----"#;

/// Deterministic EC P-256 JWK fixture for DPoP client data
fn deterministic_dpop_key() -> jose_jwk::Key {
    let jwk_json = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xFMTbKEBaGizdGlIUKEWx5q15odEB00stfg",
        "y": "x_daaqundbgUvJV358vRBgULGnpH7aRFZZDYyEiNg2g",
        "d": "jpsQnnGQmL-YxOmH1UmOBHg10OJ45DBTWh0n52qxzMQ"
    });
    serde_json::from_value(jwk_json).expect("valid P-256 JWK")
}

/// Create a deterministic `ClientSessionData` fixture for testing with a specified PDS URL
fn create_test_session_data_with_pds(
    session_id: &str,
    did_str: &str,
    scopes: Vec<Scope>,
    pds_url: &str,
) -> ClientSessionData {
    let did = Did::new_owned(did_str.to_string()).expect("valid DID");
    let scopes_obj = jacquard_oauth::scopes::Scopes::from_scopes(
        scopes.into_iter().map(|s| s.convert()),
    ).expect("valid scopes");

    ClientSessionData {
        account_did: did.clone(),
        session_id: session_id.to_string().into(),
        host_url: jacquard_common::deps::fluent_uri::Uri::parse(pds_url).expect("valid PDS URI").to_owned(),
        authserver_url: pds_url.to_string().into(),
        authserver_token_endpoint: "".into(),
        authserver_revocation_endpoint: None,
        scopes: scopes_obj,
        dpop_data: DpopClientData {
            dpop_key: deterministic_dpop_key(),
            dpop_authserver_nonce: "".into(),
            dpop_host_nonce: "".into(),
        },
        token_set: TokenSet {
            iss: pds_url.to_string().into(),
            sub: did.clone(),
            aud: pds_url.to_string().into(),
            scope: Some("atproto transition:generic transition:chat.bsky".into()),
            refresh_token: Some("refresh_token_xyz".into()),
            access_token: "access_token_abc".into(),
            token_type: OAuthTokenType::DPoP,
            expires_at: Some(
                jacquard_common::types::string::Datetime::try_from(
                    (Utc::now() + chrono::Duration::hours(2)).to_rfc3339(),
                )
                .expect("valid datetime"),
            ),
        },
        resolved_scopes: None,
    }
}

/// Create a deterministic `ClientSessionData` fixture for testing (default PDS)
fn create_test_session_data(
    session_id: &str,
    did_str: &str,
    scopes: Vec<Scope>,
) -> ClientSessionData {
    create_test_session_data_with_pds(session_id, did_str, scopes, "https://pds.example.com")
}

async fn seed_active_session_with_pds(
    state: &AppState,
    session_id: &str,
    did: &str,
    scopes: Vec<Scope>,
    pds_url: &str,
) {
    state
        .auth_store
        .as_ref()
        .expect("auth store")
        .upsert_session(create_test_session_data_with_pds(
            session_id, did, scopes, pds_url,
        ))
        .await
        .expect("seed active session");
}

async fn seed_active_session(
    state: &AppState,
    session_id: &str,
    did: &str,
    scopes: Vec<Scope>,
) {
    seed_active_session_with_pds(state, session_id, did, scopes, "https://pds.example.com").await;
}

fn scope_names(scopes: &[&str]) -> Vec<String> {
    scopes.iter().map(|scope| (*scope).to_string()).collect()
}

fn assert_status(response: &TestResponse, expected: StatusCode, context: &str) {
    assert_eq!(
        response.status_code(),
        expected,
        "{context}, got {}: {}",
        response.status_code(),
        response.text()
    );
}

fn granted_scopes(response: &Value) -> BTreeSet<&str> {
    response["granted_scopes"]
        .as_array()
        .expect("granted_scopes array")
        .iter()
        .map(|scope| scope.as_str().expect("scope string"))
        .collect()
}

async fn assert_session_routes_status(
    server: &TestServer,
    session_id: &str,
    expected: StatusCode,
    context: &str,
) {
    let bearer = format!("Bearer {session_id}");
    for route in [
        "/auth/session",
        "/xrpc/app.bsky.actor.getProfile?actor=test.bsky.social",
    ] {
        let response = server.get(route).add_header(AUTHORIZATION, &bearer).await;
        assert_status(&response, expected, &format!("{context} on {route}"));
    }
}

async fn commit_after_barrier(
    server: &TestServer,
    barrier: &Barrier,
    candidate_id: &str,
) -> TestResponse {
    barrier.wait().await;
    server
        .post("/auth/upgrade/commit")
        .add_header(AUTHORIZATION, format!("Bearer {candidate_id}"))
        .await
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        // SAFETY: Test execution environment variable modification for test seam.
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: Restoring prior environment variable state on test teardown.
        unsafe {
            if let Some(prev) = &self.previous {
                std::env::set_var(self.key, prev);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }
}

struct LocalRedis {
    child: Child,
}

impl Drop for LocalRedis {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

enum RedisGuard {
    Local(LocalRedis),
    Container(ContainerAsync<Redis>),
}

fn build_mock_resolver(mock: &MockServer) -> JacquardResolver<HardenedHttpClient> {
    let plc_base = jacquard_common::deps::fluent_uri::Uri::parse(format!("{}/", mock.uri()).as_str())
        .expect("valid mock plc url")
        .to_owned();
    let opts = ResolverOptions {
        plc_source: PlcSource::PlcDirectory { base: plc_base },
        ..ResolverOptions::default()
    };
    JacquardResolver::new(HardenedHttpClient::new(reqwest::Client::new()), opts)
}

/// Formats received mock requests for diagnostic assertion output.
/// Method and path are included along with safe body field names (redacting assertion/code/nonce/token).
fn format_mock_requests_diagnostics(requests: &[WiremockRequest]) -> String {
    if requests.is_empty() {
        return "<none>".to_string();
    }
    requests
        .iter()
        .map(|r| {
            let method = &r.method;
            let path = r.url.path();
            let fields = extract_safe_body_field_names(&r.body);
            if fields.is_empty() {
                format!("{method} {path}")
            } else {
                format!("{method} {path} (body fields: [{}])", fields.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Extracts safe body field names from a request body (JSON or form-urlencoded),
/// redacting sensitive field names containing assertion, code, nonce, or token.
/// Raw body values/secrets are never returned.
fn extract_safe_body_field_names(body: &[u8]) -> Vec<String> {
    if body.is_empty() {
        return Vec::new();
    }

    let is_sensitive = |name: &str| -> bool {
        let lower = name.to_ascii_lowercase();
        lower.contains("assertion")
            || lower.contains("code")
            || lower.contains("nonce")
            || lower.contains("token")
    };

    let sanitize_field = |name: &str| -> String {
        if is_sensitive(name) {
            "[redacted]".to_string()
        } else {
            name.to_string()
        }
    };

    if let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(body) {
        return map.keys().map(|k| sanitize_field(k)).collect();
    }

    if let Ok(body_str) = std::str::from_utf8(body) {
        if body_str.contains('=') {
            return url::form_urlencoded::parse(body)
                .map(|(k, _)| sanitize_field(&k))
                .collect();
        }
    }

    Vec::new()
}

async fn setup_mock_oauth_provider(mock: &MockServer, did: &str, token_scope: &str) {
    let provider_url = mock.uri();
    let supported_scopes = [
        "atproto",
        "transition:generic",
        "transition:chat.bsky",
        "identity:handle",
        "account:email",
        "account:status",
    ];
    let did_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "alsoKnownAs": [format!("at://{}.bsky.social", did.replace(':', "."))],
        "service": [
            {
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": provider_url
            }
        ]
    });
    Mock::given(method("GET"))
        .and(path(format!("/{did}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc))
        .mount(mock)
        .await;

    let protected_resource_md = json!({
        "resource": provider_url,
        "authorization_servers": [provider_url],
        "scopes_supported": supported_scopes
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(ResponseTemplate::new(200).set_body_json(protected_resource_md))
        .mount(mock)
        .await;

    let auth_server_md = json!({
        "issuer": provider_url,
        "authorization_endpoint": format!("{provider_url}/oauth/authorize"),
        "token_endpoint": format!("{provider_url}/oauth/token"),
        "pushed_authorization_request_endpoint": format!("{provider_url}/oauth/par"),
        "require_pushed_authorization_requests": true,
        "dpop_signing_alg_values_supported": ["ES256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt", "none"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "authorization_response_iss_parameter_supported": true,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": supported_scopes,
        "protected_resources": [provider_url]
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_server_md))
        .mount(mock)
        .await;

    let par_resp = json!({
        "request_uri": "urn:ietf:params:oauth:request_uri:mock-par-req-999",
        "expires_in": 300
    });
    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(ResponseTemplate::new(201).set_body_json(par_resp))
        .mount(mock)
        .await;

    let token_resp = json!({
        "access_token": "mock-access-token-token123",
        "refresh_token": "mock-refresh-token-token123",
        "token_type": "DPoP",
        "expires_in": 3600,
        "sub": did,
        "scope": token_scope
    });
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_resp))
        .mount(mock)
        .await;
}

/// Set up an isolated Redis-backed AppState and TestServer with optional custom resolver.
async fn setup_test_server_with_resolver(
    custom_resolver: Option<JacquardResolver<HardenedHttpClient>>,
) -> (Arc<AppState>, TestServer, OAuthUpgradeService, RedisGuard) {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (redis_url, redis_guard) = if let Some((url, local)) = start_local_redis().await {
        (url, RedisGuard::Local(local))
    } else {
        let redis = Redis::default()
            .start()
            .await
            .expect("test Redis container must start");
        let redis_url = format!(
            "redis://127.0.0.1:{}",
            redis
                .get_host_port_ipv4(6379)
                .await
                .expect("test Redis container must expose port 6379")
        );
        (redis_url, RedisGuard::Container(redis))
    };

    let mut config = AppConfig::load().expect("default test config must load");
    config.push.database_url = None;
    config.redis.url = redis_url;
    config.oauth.private_key_base64 =
        Some(base64::engine::general_purpose::STANDARD.encode(TEST_PRIVATE_KEY_PEM));
    config.oauth.active_key_id = "catbird-key-1".to_string();
    INIT_TEST_ENV.call_once(|| {
        std::env::set_var(
            "SESSION_ENCRYPTION_KEY",
            base64::engine::general_purpose::STANDARD.encode(TEST_ENCRYPTION_KEY),
        );
        std::env::set_var("JACQUARD_OAUTH_TEST_ALLOW_LOCAL", "1");
    });
    let mut state_obj = AppState::new(config)
        .await
        .expect("test Redis must be reachable");
    state_obj.session_encryption_key = Some(TEST_ENCRYPTION_KEY);

    let store = RedisAuthStore::new(
        state_obj.redis.clone(),
        state_obj.config.redis.key_prefix.clone(),
        state_obj.config.redis.session_ttl_seconds,
        Some(TEST_ENCRYPTION_KEY),
    )
    .expect("create RedisAuthStore");

    let upgrade_service = OAuthUpgradeService::from_auth_store(
        &store,
        Some(DEFAULT_UPGRADE_CALLBACK_URL.to_string()),
    );

    state_obj.auth_store = Some(Arc::new(store.clone()));

    let keyset = state_obj
        .key_store
        .as_ref()
        .and_then(|ks| ks.to_jacquard_keyset().ok());

    let client_id =
        jacquard_common::deps::fluent_uri::Uri::parse(state_obj.config.oauth.client_id.as_str())
            .expect("valid client_id URL")
            .to_owned();
    let redirect_uri =
        jacquard_common::deps::fluent_uri::Uri::parse(state_obj.config.oauth.redirect_uri.as_str())
            .expect("valid redirect_uri URL")
            .to_owned();
    let jwks_uri = jacquard_common::deps::fluent_uri::Uri::parse(format!(
        "{}/.well-known/jwks.json",
        state_obj.config.server.base_url.trim_end_matches('/')
    ).as_str())
    .expect("valid jwks_uri URL")
    .to_owned();

    let scopes: Vec<Scope> = state_obj
        .config
        .oauth
        .max_scopes
        .iter()
        .filter_map(|s| Scope::<smol_str::SmolStr>::parse(s).ok().map(|sc| sc.into_static()))
        .collect();
    let scopes = Scopes::from_scopes(scopes.into_iter().map(|s| s.convert())).expect("valid scopes");

    let metadata = AtprotoClientMetadata::new(
        vec![redirect_uri],
        client_id,
        Some(scopes),
    )
    .with_jwks_uri(jwks_uri);
    let client_data = ClientData::new(keyset, metadata);
    let resolver = custom_resolver.unwrap_or_else(|| {
        JacquardResolver::new(HardenedHttpClient::new(reqwest::Client::new()), ResolverOptions::default())
    });
    let jacquard_client = JacquardOAuthClient::new_from_resolver(store, resolver, client_data);
    state_obj.jacquard_client = Some(Arc::new(jacquard_client));

    let state = Arc::new(state_obj);
    let app = create_router(state.clone()).with_state(state.clone());
    let server = TestServer::new(app).expect("create TestServer");

    (state, server, upgrade_service, redis_guard)
}

/// Set up an isolated Redis-backed AppState and TestServer for every test.
async fn setup_test_server() -> (Arc<AppState>, TestServer, OAuthUpgradeService, RedisGuard) {
    setup_test_server_with_resolver(None).await
}

async fn start_local_redis() -> Option<(String, LocalRedis)> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("reserve a free loopback port for test Redis");
    let port = listener
        .local_addr()
        .expect("read reserved Redis port")
        .port();
    drop(listener);

    let candidates = std::env::var("REDIS_SERVER")
        .ok()
        .into_iter()
        .chain(["redis-server".to_string()]);

    for executable in candidates {
        let child = match Command::new(&executable)
            .args([
                "--bind",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
            ])
            .spawn()
        {
            Ok(child) => child,
            Err(_) => continue,
        };

        let redis = LocalRedis { child };
        let redis_url = format!("redis://127.0.0.1:{port}");
        let client =
            redis::Client::open(redis_url.as_str()).expect("local Redis URL must be valid");
        for _ in 0..100 {
            if let Ok(mut connection) = client.get_multiplexed_async_connection().await {
                if redis::cmd("PING")
                    .query_async::<_, String>(&mut connection)
                    .await
                    .is_ok()
                {
                    return Some((redis_url, redis));
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
        drop(redis);
        panic!("redis-server started but did not become ready");
    }

    None
}

#[tokio::test]
async fn test_upgrade_start_missing_or_cookie_only_or_wrong_bearer_rejected() {
    let (state, server, _service, _redis) = setup_test_server().await;
    let valid_session_id = Uuid::new_v4().to_string();
    seed_active_session(
        &state,
        &valid_session_id,
        "did:plc:cookieonly",
        vec![Scope::Atproto],
    )
    .await;

    let body = json!({
        "additional_scopes": ["identity:handle"],
        "browser_nonce": BROWSER_NONCE
    });
    let wrong_session_id = Uuid::new_v4().to_string();
    let cases = [
        (
            None,
            "Missing Authorization header must be rejected with 401",
        ),
        (
            Some(("cookie", format!("catbird_session={valid_session_id}"))),
            "Cookie-only authentication must be rejected with 401",
        ),
        (
            Some(("authorization", format!("Bearer {wrong_session_id}"))),
            "Non-existent bearer session must be rejected with 401",
        ),
        (
            Some(("authorization", "Bearer not-a-uuid-token".to_string())),
            "Malformed non-UUID bearer must be rejected with 401",
        ),
    ];

    for (header, context) in cases {
        let request = server.post("/auth/upgrade");
        let request = match header {
            Some((name, value)) => request.add_header(name, value),
            None => request,
        };
        let response = request.json(&body).await;
        assert_status(&response, StatusCode::UNAUTHORIZED, context);
    }
}

#[tokio::test]
async fn test_upgrade_start_unknown_or_disallowed_scope_rejected() {
    let (state, server, _service, _redis) = setup_test_server().await;
    let old_session_id = Uuid::new_v4().to_string();

    seed_active_session(
        &state,
        &old_session_id,
        "did:plc:upgradeuser123",
        vec![Scope::Atproto, Scope::Transition(TransitionScope::Generic)],
    )
    .await;

    let bearer = format!("Bearer {old_session_id}");
    let cases = [
        (
            json!({
                "additional_scopes": ["scope:not-allowed"],
                "browser_nonce": BROWSER_NONCE
            }),
            "Unknown scope must be rejected with 400",
        ),
        (
            json!({
                "additional_scopes": ["account:delete"],
                "browser_nonce": BROWSER_NONCE
            }),
            "Excluded scope must be rejected with 400",
        ),
        (
            json!({
                "additional_scopes": [],
                "browser_nonce": BROWSER_NONCE
            }),
            "Empty scopes must be rejected with 400",
        ),
        (
            json!({
                "additional_scopes": ["identity:handle"],
                "browser_nonce": "short"
            }),
            "Invalid browser nonce must be rejected with 400",
        ),
    ];

    for (body, context) in cases {
        let response = server
            .post("/auth/upgrade")
            .add_header("authorization", &bearer)
            .json(&body)
            .await;
        assert_status(&response, StatusCode::BAD_REQUEST, context);
    }
}

#[tokio::test]
async fn test_initial_login_still_sends_core_subset() {
    let mock = MockServer::start().await;
    let did = FIXED_TEST_DID;
    setup_mock_oauth_provider(
        &mock,
        did,
        "atproto transition:generic transition:chat.bsky",
    )
    .await;

    let (_state, server, _upgrade_service, _redis) =
        setup_test_server_with_resolver(Some(build_mock_resolver(&mock))).await;

    let encoded_did = urlencoding::encode(did);
    let login_resp = server
        .get(&format!(
            "/auth/login?identifier={encoded_did}&redirect_to=https://catbird.blue/oauth/callback&browser_nonce={BROWSER_NONCE}"
        ))
        .await;
    let requests = mock.received_requests().await.expect("received requests");
    assert_eq!(
        login_resp.status_code(),
        StatusCode::FOUND,
        "Expected 302 Found on /auth/login, got {}: {} | mock requests: {}",
        login_resp.status_code(),
        login_resp.text(),
        format_mock_requests_diagnostics(&requests)
    );

    let location = login_resp.header("Location");
    let location_str = location.to_str().expect("valid Location header");
    assert!(
        location_str.starts_with(&format!("{}/oauth/authorize", mock.uri())),
        "Location must redirect to mock authorization endpoint, got: {location_str}"
    );

    let par_req = requests
        .iter()
        .find(|r| r.url.path() == "/oauth/par")
        .expect("PAR request recorded by mock server");

    let par_params: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(&par_req.body)
            .into_owned()
            .collect();
    let par_scope = par_params.get("scope").expect("scope in PAR request");

    let actual_scopes: Vec<&str> = par_scope.split_whitespace().collect();
    let expected_core = &["atproto", "transition:generic", "transition:chat.bsky"];

    for scope in expected_core {
        assert!(
            actual_scopes.contains(scope),
            "PAR scope must contain core scope '{scope}', got: {par_scope}"
        );
    }
    assert_eq!(
        actual_scopes.len(),
        expected_core.len(),
        "PAR scope must contain exactly the core scopes, got: {par_scope}"
    );

    // Assert initial login excludes optional identity and account upgrade scopes
    for optional_scope in ALLOWLISTED_UPGRADE_SCOPES {
        assert!(
            !actual_scopes.contains(optional_scope),
            "PAR scope must exclude progressive upgrade scope '{optional_scope}'"
        );
    }
}

#[tokio::test]
async fn test_upgrade_callback_denial_leaves_old_session_valid() {
    let (state, server, upgrade_service, _redis) = setup_test_server().await;
    let old_session_id = Uuid::new_v4().to_string();
    let did_str = "did:plc:denialtestuser456";

    seed_active_session(
        &state,
        &old_session_id,
        did_str,
        vec![Scope::Atproto, Scope::Transition(TransitionScope::Generic)],
    )
    .await;

    // Start upgrade flow in service
    let start_result = upgrade_service
        .start_upgrade_flow(
            &old_session_id,
            did_str,
            &scope_names(&["atproto", "transition:generic"]),
            &scope_names(&["identity:handle"]),
            BROWSER_NONCE,
        )
        .await
        .expect("start upgrade flow");

    let upg_state = &start_result.state;
    assert!(upg_state.starts_with("upg_"));

    // Simulate callback denial redirect from provider
    let callback_url = format!(
        "/auth/callback?state={}&error=access_denied&error_description=User+denied+upgrade",
        upg_state
    );
    let resp = server.get(&callback_url).await;

    // Must redirect to fixed permission callback with error
    assert_status(
        &resp,
        StatusCode::FOUND,
        "Upgrade denial must return 302 Found",
    );
    let location = resp
        .headers()
        .get("location")
        .expect("location header")
        .to_str()
        .expect("valid header value");
    assert!(
        location.starts_with("https://catbird.blue/oauth/permission-callback?error="),
        "Redirect target must be fixed permission callback: got {}",
        location
    );

    // Assert NO cookie was set
    assert!(
        resp.headers().get("set-cookie").is_none(),
        "Upgrade callback denial must NOT set session cookie"
    );

    // Assert old session remains 100% valid and active
    let session_resp = server
        .get("/auth/session")
        .add_header("authorization", format!("Bearer {}", old_session_id))
        .await;
    assert_status(
        &session_resp,
        StatusCode::OK,
        "Old session must remain valid and active after upgrade denial",
    );
    let session_json: Value = session_resp.json();
    assert_eq!(session_json["did"], did_str);
}

#[tokio::test]
async fn test_upgrade_start_and_callback_flow_success() {
    let _env_guard = EnvVarGuard::set("CATBIRD_TEST_OAUTH_IDENTIFIER", FIXED_TEST_DID);
    let mock = MockServer::start().await;
    let did = FIXED_TEST_DID;
    setup_mock_oauth_provider(
        &mock,
        did,
        "atproto transition:generic transition:chat.bsky identity:handle",
    )
    .await;

    let (state, server, _upgrade_service, _redis) =
        setup_test_server_with_resolver(Some(build_mock_resolver(&mock))).await;

    let old_session_id = Uuid::new_v4().to_string();
    seed_active_session(
        &state,
        &old_session_id,
        did,
        vec![
            Scope::Atproto,
            Scope::Transition(TransitionScope::Generic),
            Scope::Transition(TransitionScope::ChatBsky),
        ],
    )
    .await;
    // 1. POST /auth/upgrade
    let start_body = json!({
        "additional_scopes": ["identity:handle"],
        "browser_nonce": BROWSER_NONCE,
    });
    let start_resp = server
        .post("/auth/upgrade")
        .add_header(AUTHORIZATION, format!("Bearer {old_session_id}"))
        .add_header("origin", CATBIRD_ORIGIN)
        .json(&start_body)
        .await;
    let requests = mock.received_requests().await.expect("received requests");
    assert_eq!(
        start_resp.status_code(),
        StatusCode::OK,
        "Expected 200 OK on /auth/upgrade, got {}: {} | mock requests: {}",
        start_resp.status_code(),
        start_resp.text(),
        format_mock_requests_diagnostics(&requests)
    );

    let start_data: Value = start_resp.json();
    let auth_url = start_data["authorization_url"]
        .as_str()
        .expect("authorization_url string");
    assert!(
        auth_url.starts_with(&format!("{}/oauth/authorize", mock.uri())),
        "Authorization URL must point to mock provider, got: {auth_url}"
    );

    // 2. Assert upgrade PAR request parameters: redirect_uri and exact target scopes
    let par_req = requests
        .iter()
        .filter(|r| r.url.path() == "/oauth/par")
        .last()
        .expect("upgrade PAR request recorded");
    let par_params: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(&par_req.body)
            .into_owned()
            .collect();

    let par_redirect_uri = par_params
        .get("redirect_uri")
        .expect("redirect_uri in PAR request");
    assert_eq!(
        par_redirect_uri, &state.config.oauth.redirect_uri,
        "Upgrade PAR redirect_uri must match registered Nest /auth/callback"
    );

    let par_scope = par_params.get("scope").expect("scope in PAR request");
    let par_scopes: Vec<&str> = par_scope.split_whitespace().collect();
    let expected_upgrade_scopes = &[
        "atproto",
        "transition:generic",
        "transition:chat.bsky",
        "identity:handle",
    ];
    for s in expected_upgrade_scopes {
        assert!(
            par_scopes.contains(s),
            "PAR scope must contain '{s}', got: {par_scope}"
        );
    }
    assert_eq!(
        par_scopes.len(),
        expected_upgrade_scopes.len(),
        "PAR scope must contain exact target scopes, got: {par_scope}"
    );

    let upgrade_state = par_params
        .get("state")
        .expect("state in PAR request")
        .clone();
    assert!(
        upgrade_state.starts_with("upg_"),
        "Upgrade state must start with upg_, got: {upgrade_state}"
    );

    // 3. Provider callback: GET /auth/callback?code=...&state=...&iss=...
    let mock_uri = mock.uri();
    let callback_resp = server
        .get(&format!(
            "/auth/callback?code=mock_upgrade_code_777&state={upgrade_state}&iss={}",
            urlencoding::encode(&mock_uri)
        ))
        .await;
    assert_status(
        &callback_resp,
        StatusCode::FOUND,
        "Expected 302 Found on /auth/callback",
    );

    // Assert actual callback sets no cookie
    assert!(
        callback_resp.maybe_header("Set-Cookie").is_none(),
        "Upgrade callback must not set Cookie"
    );

    // Assert Location points to FIXED_UPGRADE_CALLBACK_URL with one-time code only
    let location = callback_resp.header("Location");
    let location_str = location.to_str().expect("valid Location header");
    let loc_url = url::Url::parse(location_str).expect("valid Location URL");
    let loc_base = format!(
        "{}://{}{}",
        loc_url.scheme(),
        loc_url.host_str().unwrap(),
        loc_url.path()
    );
    assert_eq!(
        loc_base, FIXED_UPGRADE_CALLBACK_URL,
        "Callback redirect must point to FIXED_UPGRADE_CALLBACK_URL"
    );

    let query_pairs: Vec<(String, String)> = loc_url.query_pairs().into_owned().collect();
    assert_eq!(
        query_pairs.len(),
        1,
        "Location query must contain only 'code', got: {location_str}"
    );
    assert_eq!(
        query_pairs[0].0, "code",
        "Location query parameter must be 'code'"
    );
    let exchange_code = query_pairs[0].1.clone();
    assert!(!exchange_code.is_empty(), "Exchange code must not be empty");

    // Assert Location does not leak DID, grants, old session ID, or state
    assert!(!location_str.contains(did), "Location must not leak DID");
    assert!(
        !location_str.contains("identity:handle"),
        "Location must not leak grants"
    );
    assert!(
        !location_str.contains(&old_session_id),
        "Location must not leak old session ID"
    );
    assert!(
        !location_str.contains(&upgrade_state),
        "Location must not leak state"
    );

    // 4. Exchange one-time code to observe candidate_session_id
    let exchange_body = json!({
        "code": exchange_code,
        "browser_nonce": BROWSER_NONCE,
    });
    let exchange_resp = server
        .post("/auth/upgrade/exchange")
        .add_header(AUTHORIZATION, format!("Bearer {old_session_id}"))
        .add_header("origin", CATBIRD_ORIGIN)
        .json(&exchange_body)
        .await;
    assert_status(
        &exchange_resp,
        StatusCode::OK,
        "Expected 200 OK on /auth/upgrade/exchange",
    );
    let exchange_data: Value = exchange_resp.json();
    let candidate_id = exchange_data["candidate_session_id"]
        .as_str()
        .expect("candidate_session_id string")
        .to_string();

    let expected_scopes = [
        "atproto",
        "transition:generic",
        "transition:chat.bsky",
        "identity:handle",
    ]
    .into_iter()
    .collect();

    assert_eq!(
        exchange_data["did"].as_str(),
        Some(did),
        "Exchange response must match expected DID"
    );
    let exchange_scopes = granted_scopes(&exchange_data);
    assert_eq!(
        exchange_scopes, expected_scopes,
        "Exchange granted_scopes must match expected normalized scope set"
    );

    // Assert distinct IDs where observable
    assert_ne!(
        old_session_id, upgrade_state,
        "Old session ID and upgrade state must be distinct"
    );
    assert_ne!(
        old_session_id, candidate_id,
        "Old session ID and candidate ID must be distinct"
    );
    assert_ne!(
        upgrade_state, candidate_id,
        "Upgrade state and candidate ID must be distinct"
    );
    assert!(
        !location_str.contains(&candidate_id),
        "Location must not leak candidate session ID"
    );

    // 5. Staged candidate gets 401 on /auth/session and /xrpc before commit
    assert_session_routes_status(
        &server,
        &candidate_id,
        StatusCode::UNAUTHORIZED,
        "Staged candidate must be rejected before commit",
    )
    .await;

    // 6. Commit candidate via POST /auth/upgrade/commit
    let commit_resp = server
        .post("/auth/upgrade/commit")
        .add_header(AUTHORIZATION, format!("Bearer {candidate_id}"))
        .await;
    assert_status(
        &commit_resp,
        StatusCode::OK,
        "Expected 200 OK on /auth/upgrade/commit",
    );
    let commit_data: Value = commit_resp.json();
    assert_eq!(commit_data["status"], "committed");
    assert_eq!(
        commit_data["session_id"].as_str(),
        Some(candidate_id.as_str())
    );
    assert_eq!(
        commit_data["did"].as_str(),
        Some(did),
        "Commit response must match expected DID"
    );
    let commit_scopes = granted_scopes(&commit_data);
    assert_eq!(
        commit_scopes, expected_scopes,
        "Commit granted_scopes must match expected normalized scope set"
    );

    // 7. Final /auth/session with candidate bearer succeeds
    let session_resp = server
        .get("/auth/session")
        .add_header(AUTHORIZATION, format!("Bearer {candidate_id}"))
        .await;
    assert_status(
        &session_resp,
        StatusCode::OK,
        "Expected 200 OK on final /auth/session",
    );
    let session_data: Value = session_resp.json();
    assert_eq!(
        session_data["did"].as_str(),
        Some(did),
        "Final /auth/session must match expected DID"
    );
    let final_session_scopes = granted_scopes(&session_data);
    assert_eq!(
        final_session_scopes, expected_scopes,
        "Final session granted_scopes must match expected normalized scope set"
    );

    // 8. Old bearer rejected (401) on both /auth/session and /xrpc
    assert_session_routes_status(
        &server,
        &old_session_id,
        StatusCode::UNAUTHORIZED,
        "Old bearer must be rejected after commit",
    )
    .await;
}

#[tokio::test]
async fn test_upgrade_exchange_wrong_nonce_origin_or_bearer_cannot_burn_exchange() {
    let (state, server, upgrade_service, _redis) = setup_test_server().await;
    let old_session_id = Uuid::new_v4().to_string();
    let did_str = "did:plc:exchangeuser101";

    seed_active_session(
        &state,
        &old_session_id,
        did_str,
        vec![Scope::Atproto, Scope::Transition(TransitionScope::Generic)],
    )
    .await;
    let start_result = upgrade_service
        .start_upgrade_flow(
            &old_session_id,
            did_str,
            &scope_names(&["atproto", "transition:generic"]),
            &scope_names(&["identity:handle"]),
            BROWSER_NONCE,
        )
        .await
        .expect("start upgrade flow");

    let upgraded_session = create_test_session_data(
        &old_session_id,
        did_str,
        vec![
            Scope::Atproto,
            Scope::Transition(TransitionScope::Generic),
            Scope::Identity(IdentityScope::Handle),
        ],
    );
    let callback_res = upgrade_service
        .complete_callback(
            &start_result.state,
            upgraded_session,
            scope_names(&["atproto", "transition:generic", "identity:handle"]),
        )
        .await
        .expect("complete callback");

    let valid_code = callback_res.exchange_code;
    let old_bearer = format!("Bearer {}", old_session_id);

    let other_session_id = Uuid::new_v4().to_string();
    seed_active_session(
        &state,
        &other_session_id,
        "did:plc:otheruser999",
        vec![Scope::Atproto],
    )
    .await;

    let exchange_req = json!({"code": valid_code.clone(), "browser_nonce": BROWSER_NONCE});
    let wrong_nonce_req = json!({
        "code": valid_code,
        "browser_nonce": "WRONG2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0V"
    });
    let other_bearer = format!("Bearer {other_session_id}");
    let invalid_cases = [
        (
            &other_bearer,
            CATBIRD_ORIGIN,
            &exchange_req,
            "Wrong bearer must return 401",
        ),
        (
            &old_bearer,
            CATBIRD_ORIGIN,
            &wrong_nonce_req,
            "Wrong browser nonce must return 401",
        ),
        (
            &old_bearer,
            "https://evil.attacker.com",
            &exchange_req,
            "Wrong origin must return 401",
        ),
    ];
    for (bearer, origin, body, context) in invalid_cases {
        let response = server
            .post("/auth/upgrade/exchange")
            .add_header(AUTHORIZATION, bearer)
            .add_header("origin", origin)
            .json(body)
            .await;
        assert_status(&response, StatusCode::UNAUTHORIZED, context);
    }

    // 6d. Correct bearer + correct nonce + exact origin https://catbird.blue -> 200 OK
    let resp = server
        .post("/auth/upgrade/exchange")
        .add_header("authorization", &old_bearer)
        .add_header("origin", CATBIRD_ORIGIN)
        .json(&exchange_req)
        .await;
    assert_status(
        &resp,
        StatusCode::OK,
        "Correct exchange parameters must return 200 OK",
    );

    let exchange_resp: Value = resp.json();
    assert_eq!(
        exchange_resp["candidate_session_id"].as_str(),
        Some(callback_res.candidate_session_id.as_str())
    );
    assert_eq!(exchange_resp["did"], did_str);
    assert!(exchange_resp["granted_scopes"]
        .as_array()
        .expect("granted_scopes array")
        .iter()
        .any(|scope| scope == "identity:handle"));

    // 6e. Replay with burned exchange code -> 401
    let replay_resp = server
        .post("/auth/upgrade/exchange")
        .add_header("authorization", &old_bearer)
        .add_header("origin", CATBIRD_ORIGIN)
        .json(&exchange_req)
        .await;
    assert_status(
        &replay_resp,
        StatusCode::UNAUTHORIZED,
        "Burned exchange code must return 401 on replay",
    );
}

#[tokio::test]
async fn test_staged_candidate_gets_401_on_auth_session_and_xrpc() {
    let (state, server, upgrade_service, _redis) = setup_test_server().await;
    let old_session_id = Uuid::new_v4().to_string();
    let did_str = "did:plc:stageduser202";

    seed_active_session(&state, &old_session_id, did_str, vec![Scope::Atproto]).await;
    let start_result = upgrade_service
        .start_upgrade_flow(
            &old_session_id,
            did_str,
            &scope_names(&["atproto"]),
            &scope_names(&["identity:handle"]),
            BROWSER_NONCE,
        )
        .await
        .expect("start upgrade flow");

    let upgraded_session = create_test_session_data(
        &old_session_id,
        did_str,
        vec![Scope::Atproto, Scope::Identity(IdentityScope::Handle)],
    );
    let callback_res = upgrade_service
        .complete_callback(
            &start_result.state,
            upgraded_session,
            scope_names(&["atproto", "identity:handle"]),
        )
        .await
        .expect("complete callback");

    let candidate_id = callback_res.candidate_session_id;
    let candidate_bearer = format!("Bearer {}", candidate_id);
    // A staged candidate cannot be used to begin or exchange another upgrade.
    let start_resp = server
        .post("/auth/upgrade")
        .add_header("authorization", &candidate_bearer)
        .json(&json!({
            "additional_scopes": ["identity:handle"],
            "browser_nonce": BROWSER_NONCE
        }))
        .await;
    assert_status(
        &start_resp,
        StatusCode::UNAUTHORIZED,
        "Staged candidate must not start upgrade flow",
    );
    let exchange_resp = server
        .post("/auth/upgrade/exchange")
        .add_header("authorization", &candidate_bearer)
        .add_header("origin", CATBIRD_ORIGIN)
        .json(&json!({
            "code": "not-a-real-code",
            "browser_nonce": BROWSER_NONCE
        }))
        .await;
    assert_status(
        &exchange_resp,
        StatusCode::UNAUTHORIZED,
        "Staged candidate must not exchange code",
    );

    // 7. Staged candidate on /auth/session and /xrpc -> 401 Unauthorized
    assert_session_routes_status(
        &server,
        &candidate_id,
        StatusCode::UNAUTHORIZED,
        "Staged candidate must not be recognized before commit",
    )
    .await;
}

#[tokio::test]
async fn test_upgrade_commit_idempotent_and_lifecycle() {
    let (state, server, upgrade_service, _redis) = setup_test_server().await;
    let old_session_id = Uuid::new_v4().to_string();
    let did_str = "did:plc:committestuser303";

    seed_active_session(
        &state,
        &old_session_id,
        did_str,
        vec![Scope::Atproto, Scope::Transition(TransitionScope::Generic)],
    )
    .await;
    let start_result = upgrade_service
        .start_upgrade_flow(
            &old_session_id,
            did_str,
            &scope_names(&["atproto", "transition:generic"]),
            &scope_names(&["identity:handle"]),
            BROWSER_NONCE,
        )
        .await
        .expect("start upgrade flow");

    let upgraded_session = create_test_session_data(
        &old_session_id,
        did_str,
        vec![
            Scope::Atproto,
            Scope::Transition(TransitionScope::Generic),
            Scope::Identity(IdentityScope::Handle),
        ],
    );
    let callback_res = upgrade_service
        .complete_callback(
            &start_result.state,
            upgraded_session,
            scope_names(&["atproto", "transition:generic", "identity:handle"]),
        )
        .await
        .expect("complete callback");
    // The superseded old session is not allowed to commit the candidate.
    let old_commit = server
        .post("/auth/upgrade/commit")
        .add_header("authorization", format!("Bearer {}", old_session_id))
        .await;
    assert_status(
        &old_commit,
        StatusCode::UNAUTHORIZED,
        "Old session cannot commit candidate",
    );

    let candidate_id = callback_res.candidate_session_id;
    let candidate_bearer = format!("Bearer {}", candidate_id);

    // 8a. First commit -> 200 OK
    let resp = server
        .post("/auth/upgrade/commit")
        .add_header("authorization", &candidate_bearer)
        .await;
    assert_status(
        &resp,
        StatusCode::OK,
        "First commit must succeed with 200 OK",
    );

    let commit_resp1: Value = resp.json();
    assert_eq!(commit_resp1["status"], "committed");
    assert_eq!(
        commit_resp1["session_id"].as_str(),
        Some(candidate_id.as_str())
    );
    assert_eq!(commit_resp1["did"], did_str);
    assert!(commit_resp1["granted_scopes"]
        .as_array()
        .expect("granted_scopes array")
        .iter()
        .any(|scope| scope == "identity:handle"));

    // 8b. Idempotent commit replay with same candidate -> 200 OK with identical payload
    let replay_resp = server
        .post("/auth/upgrade/commit")
        .add_header("authorization", &candidate_bearer)
        .await;
    assert_status(
        &replay_resp,
        StatusCode::OK,
        "Commit replay must be idempotent and return 200 OK",
    );
    let commit_resp2: Value = replay_resp.json();
    assert_eq!(commit_resp1, commit_resp2);

    // 9a. Old session rejected after commit on /auth/session -> 401
    let old_session_resp = server
        .get("/auth/session")
        .add_header("authorization", format!("Bearer {}", old_session_id))
        .await;
    assert_status(
        &old_session_resp,
        StatusCode::UNAUTHORIZED,
        "Old session must be rejected with 401 after commit",
    );

    // 9b. Promoted candidate is now active on /auth/session -> 200 OK
    let candidate_session_resp = server
        .get("/auth/session")
        .add_header("authorization", &candidate_bearer)
        .await;
    assert_status(
        &candidate_session_resp,
        StatusCode::OK,
        "Promoted candidate session must be active on /auth/session",
    );

    let session_val: Value = candidate_session_resp.json();
    assert_eq!(session_val["did"], did_str);
    let scopes_arr = session_val["granted_scopes"]
        .as_array()
        .expect("granted_scopes array");
    assert!(scopes_arr
        .iter()
        .any(|s| s.as_str() == Some("identity:handle")));
}

#[tokio::test]
async fn test_concurrent_candidate_loses_without_winner_id() {
    let (state, server, upgrade_service, _redis) = setup_test_server().await;
    let old_session_id = Uuid::new_v4().to_string();
    let did_str = "did:plc:concurrentuser404";

    seed_active_session(&state, &old_session_id, did_str, vec![Scope::Atproto]).await;

    let flow_specs = [
        (
            BROWSER_NONCE,
            "identity:handle",
            Scope::Identity(IdentityScope::Handle),
        ),
        (
            "B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W",
            "account:email?action=manage",
            Scope::<smol_str::SmolStr>::parse("account:email?action=manage")
                .expect("valid account email manage scope")
                .into_static(),
        ),
    ];
    let mut candidate_ids = Vec::with_capacity(flow_specs.len());
    for (nonce, additional_scope, parsed_scope) in flow_specs {
        let start = upgrade_service
            .start_upgrade_flow(
                &old_session_id,
                did_str,
                &scope_names(&["atproto"]),
                &scope_names(&[additional_scope]),
                nonce,
            )
            .await
            .expect("start competing upgrade flow");
        let upgraded_session =
            create_test_session_data(&old_session_id, did_str, vec![Scope::Atproto, parsed_scope]);
        let callback = upgrade_service
            .complete_callback(
                &start.state,
                upgraded_session,
                scope_names(&["atproto", additional_scope]),
            )
            .await
            .expect("complete competing upgrade callback");
        candidate_ids.push(callback.candidate_session_id);
    }
    let [candidate1_id, candidate2_id]: [String; 2] = candidate_ids
        .try_into()
        .expect("exactly two competing candidates");

    // Both requests must reach the barrier before either commit is issued.
    let barrier = Barrier::new(2);
    let (resp1, resp2) = tokio::join!(
        commit_after_barrier(&server, &barrier, &candidate1_id),
        commit_after_barrier(&server, &barrier, &candidate2_id),
    );
    let status1 = resp1.status_code();
    let status2 = resp2.status_code();

    // Assert exactly one 200 OK and one 409 Conflict regardless of winner
    assert!(
        (status1 == StatusCode::OK && status2 == StatusCode::CONFLICT)
            || (status1 == StatusCode::CONFLICT && status2 == StatusCode::OK),
        "Expected exactly one 200 OK and one 409 Conflict, got status1={status1}, status2={status2}"
    );

    let (winner_id, winner_resp, loser_id, loser_resp, expected_winner_scopes) =
        if status1 == StatusCode::OK {
            (
                &candidate1_id,
                resp1,
                &candidate2_id,
                resp2,
                BTreeSet::from(["atproto", "identity:handle"]),
            )
        } else {
            (
                &candidate2_id,
                resp2,
                &candidate1_id,
                resp1,
                BTreeSet::from(["atproto", "account:email?action=manage"]),
            )
        };

    let winner_commit_data: Value = winner_resp.json();
    assert_eq!(winner_commit_data["status"], "committed");
    assert_eq!(
        winner_commit_data["session_id"].as_str(),
        Some(winner_id.as_str()),
        "Commit response session_id must match the winning candidate ID"
    );
    assert_eq!(
        winner_commit_data["did"].as_str(),
        Some(did_str),
        "Commit response DID must match expected DID"
    );
    let commit_scopes = granted_scopes(&winner_commit_data);
    assert_eq!(
        commit_scopes, expected_winner_scopes,
        "Commit granted_scopes must match expected scope set for winning candidate"
    );

    // Invariant: Loser response body and headers must NOT leak winner's candidate UUID
    let loser_text = loser_resp.text();
    assert!(
        !loser_text.contains(winner_id),
        "Error response body must NOT leak winning candidate ID"
    );

    for (hdr_name, hdr_val) in loser_resp.headers() {
        if let Ok(val_str) = hdr_val.to_str() {
            assert!(
                !val_str.contains(winner_id),
                "Header {hdr_name} must NOT leak winning candidate ID"
            );
        }
    }

    // Winner bearer is active on /auth/session with exact DID and scope set
    let winner_bearer = format!("Bearer {winner_id}");
    let winner_session_resp = server
        .get("/auth/session")
        .add_header(AUTHORIZATION, &winner_bearer)
        .await;
    assert_status(
        &winner_session_resp,
        StatusCode::OK,
        "Winning candidate session must be active on /auth/session",
    );
    let winner_session_data: Value = winner_session_resp.json();
    assert_eq!(
        winner_session_data["did"].as_str(),
        Some(did_str),
        "Winner session DID on /auth/session must match expected DID"
    );
    let winner_session_scopes = granted_scopes(&winner_session_data);
    assert_eq!(
        winner_session_scopes, expected_winner_scopes,
        "Winner session granted_scopes on /auth/session must match exact scope set"
    );

    // Winner bearer is active and authenticated on /xrpc (does not return 401 Unauthorized)
    let winner_xrpc_resp = server
        .get("/xrpc/app.bsky.actor.getProfile?actor=test.bsky.social")
        .add_header(AUTHORIZATION, &winner_bearer)
        .await;
    assert_ne!(
        winner_xrpc_resp.status_code(),
        StatusCode::UNAUTHORIZED,
        "Winning candidate must pass authentication on /xrpc"
    );

    // Loser bearer returns 401 Unauthorized on both /auth/session and /xrpc
    assert_session_routes_status(
        &server,
        loser_id,
        StatusCode::UNAUTHORIZED,
        "Losing candidate must be rejected with 401",
    )
    .await;

    // Old superseded bearer returns 401 Unauthorized on both /auth/session and /xrpc
    assert_session_routes_status(
        &server,
        &old_session_id,
        StatusCode::UNAUTHORIZED,
        "Old bearer must be rejected with 401 after commit",
    )
    .await;
}

#[tokio::test]
async fn test_upgrade_limiter_runs_before_auth_for_stable_client_ip() {
    let (_state, server, _service, _redis) = setup_test_server().await;
    let body = json!({
        "additional_scopes": ["identity:handle"],
        "browser_nonce": BROWSER_NONCE
    });

    for _ in 0..20 {
        let response = server
            .post("/auth/upgrade")
            .add_header("x-forwarded-for", "198.51.100.42")
            .json(&body)
            .await;
        assert_status(
            &response,
            StatusCode::UNAUTHORIZED,
            "Expected 401 Unauthorized before rate limit",
        );
    }

    let limited = server
        .post("/auth/upgrade")
        .add_header("x-forwarded-for", "198.51.100.42")
        .json(&body)
        .await;
    assert_status(
        &limited,
        StatusCode::TOO_MANY_REQUESTS,
        "Expected 429 Too Many Requests when rate limited",
    );
    assert!(limited
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|seconds| seconds > 0));
}
