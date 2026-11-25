//! Case C26 Paired Nest Proxy Process
//!
//! Companion process for C26 live qualification. Receives the delivery service
//! URL on stdin, boots the real Nest XRPC proxy handler on loopback, and forwards
//! client requests to the real delivery service.
//!
//! Nest mints one PDS service-auth token per proxied request (no cache) and the
//! delivery service records every `jti`, so a static fixture token is wrong for
//! more than one request. The fixture PDS therefore serves whatever single-use
//! token the driver last wrote to `tokenPath`, and records every call in
//! `callsPath`. Nest only calls getServiceAuth after ingress admission, so an
//! unchanged count across a request proves Nest rejected it before forwarding.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, Extension},
    routing::post,
    Router,
};
use catbird::config::{AppConfig, AppState};
use catbird::middleware::{JacquardDpopData, RateLimitState};
use catbird::models::CatbirdSession;
use catbird::services::DpopNonceCache;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StdinConfig {
    ds_url: String,
    ready_path: String,
    result_path: String,
    stop_path: String,
    token_path: String,
    calls_path: String,
    session_did: String,
}
struct OwnedRedis(Child);
impl Drop for OwnedRedis {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn fixture_state(service_url: &str) -> (Arc<AppState>, OwnedRedis) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let process = OwnedRedis(
        Command::new("redis-server")
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
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("local Redis fixture"),
    );
    let redis_url = format!("redis://127.0.0.1:{port}");
    let client = redis::Client::open(redis_url.as_str()).unwrap();
    for attempt in 0..100 {
        if client.get_multiplexed_async_connection().await.is_ok() {
            break;
        }
        assert!(attempt < 99, "owned Redis fixture failed to start");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let config: AppConfig = serde_json::from_value(json!({
        "server": {"base_url":"http://localhost:1"},
        "redis": {"url":redis_url,"key_prefix":"request-c26-paired:session:"},
        "oauth": {"client_id":"http://localhost:1","redirect_uri":"http://localhost:1/auth/callback"},
        "mls": {"service_url":if service_url.is_empty() { None } else { Some(service_url) },"service_did":"did:web:chat.catbird.blue"}
    })).unwrap();
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let state = Arc::new(AppState {
        config: Arc::new(config),
        http_client: http_client.clone(),
        raw_http_client: http_client,
        redis: redis::aio::ConnectionManager::new(client).await.unwrap(),
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
        rate_limit: Arc::new(RateLimitState::default()),
        session_index_ready: Arc::new(AtomicBool::new(true)),
        session_index_readiness: Arc::new(tokio::sync::Notify::new()),
    });
    (state, process)
}

fn session(pds: &MockServer, did: &str) -> CatbirdSession {
    CatbirdSession {
        id: Uuid::new_v4(),
        did: did.into(),
        handle: "c26paired.invalid".into(),
        pds_url: pds.uri().replace("127.0.0.1", "localhost"),
        access_token: "fixture-access".into(),
        refresh_token: "fixture-refresh".into(),
        scopes: vec![],
        access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
        created_at: Utc::now(),
        last_used_at: Utc::now(),
        granted_scopes: vec!["atproto".into()],
    }
}

/// The session's DPoP key material, as the OAuth session of a signed-in app
/// holds it: a fresh P-256 key and no host nonce yet.
fn session_dpop() -> JacquardDpopData {
    let secret = p256::SecretKey::random(&mut rand::thread_rng());
    JacquardDpopData {
        dpop_key: jose_jwk::Key::from(&jose_jwk::crypto::Key::from(secret)),
        dpop_host_nonce: String::new(),
    }
}

#[tokio::test]
#[ignore = "paired process invoked by e2e-tests c26_maximum_device_limits"]
async fn live_c26_nest_proxy_worker() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let mut stdin_bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut stdin_bytes)
        .expect("read config from stdin");
    let cfg: StdinConfig = serde_json::from_slice(&stdin_bytes).expect("parse StdinConfig");

    let pds = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let (token_path, calls_path, counter) = (
        cfg.token_path.clone(),
        cfg.calls_path.clone(),
        calls.clone(),
    );
    std::fs::write(&calls_path, b"0").expect("initialize call count");
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(move |_: &wiremock::Request| {
            let token = std::fs::read_to_string(&token_path).expect("driver token");
            let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
            std::fs::write(&calls_path, count.to_string()).expect("record call count");
            ResponseTemplate::new(200).set_body_json(json!({"token": token.trim()}))
        })
        .mount(&pds)
        .await;
    let (state, _redis) = fixture_state(&cfg.ds_url).await;
    let router = Router::new()
        .route(
            "/xrpc/*lexicon",
            post(catbird::handlers::atproto::proxy_xrpc)
                .get(catbird::handlers::atproto::proxy_xrpc),
        )
        // Same extractor cap as the production xrpc router; the opaque proxy
        // body is bounded by xrpc_ingress's exact per-procedure limit instead.
        .layer(DefaultBodyLimit::max(11 * 1024 * 1024))
        .layer(Extension(session(&pds, &cfg.session_did)))
        // A real app session's request carries its Jacquard DPoP key (inserted
        // by auth_middleware); the clean-chat proxy mints service auth with it.
        .layer(Extension(session_dpop()))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local tcp listener");
    let port = listener.local_addr().expect("local addr").port();

    let ready_json = json!({
        "status": "ready",
        "nestPort": port,
        "nestUrl": format!("http://127.0.0.1:{port}"),
    });
    std::fs::write(&cfg.ready_path, serde_json::to_vec(&ready_json).unwrap())
        .expect("write ready json");

    // Run server in background until stop_path appears
    let stop_path = cfg.stop_path.clone();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    while !std::path::Path::new(&stop_path).exists() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    server_handle.abort();

    let result_json = json!({
        "status": "completed",
        "nestPort": port,
        "serviceAuthCalls": calls.load(Ordering::SeqCst),
    });
    std::fs::write(&cfg.result_path, serde_json::to_vec(&result_json).unwrap())
        .expect("write result json");
}
