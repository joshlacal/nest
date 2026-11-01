//! Integration tests for authenticated Catbird Community Intelligence & Onboarding XRPC proxy routing.

use axum::http::{HeaderMap, Method, StatusCode};
use catbird::config::{AppConfig, AppState};
use catbird::error::AppError;
use catbird::models::CatbirdSession;
use catbird::services::{
    build_hardened_http_client, build_hardened_raw_http_client, DpopNonceCache,
    INTEL_APPVIEW_SERVICE_REF, INTEL_ENDPOINTS,
};
use chrono::Utc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn build_intel_test_fixture(
    pds_uri: String,
    intel_uri: String,
    enabled: bool,
) -> (
    Arc<AppState>,
    CatbirdSession,
    catbird::middleware::JacquardDpopData,
) {
    let mut config = AppConfig::test_default();
    config.intel.enabled = enabled;
    config.intel.base_url = intel_uri;
    config.intel.service_did = INTEL_APPVIEW_SERVICE_REF.to_string();
    config.intel.timeout_ms = 5000;

    let http_client = build_hardened_http_client().unwrap();
    let raw_http_client = build_hardened_raw_http_client().unwrap();
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
        did: "did:plc:synthviewer0000000000001".into(),
        handle: "viewer.test".into(),
        pds_url: pds_uri,
        access_token: "mock-oauth-access-token".into(),
        refresh_token: "mock-oauth-refresh-token".into(),
        scopes: vec!["atproto".into()],
        access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
        created_at: Utc::now(),
        last_used_at: Utc::now(),
        granted_scopes: vec!["atproto".into()],
    };

    let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
    let crypto_key = jose_jwk::crypto::Key::from(secret_key);
    let dpop_data = catbird::middleware::JacquardDpopData {
        dpop_key: jose_jwk::Key::from(&crypto_key),
        dpop_host_nonce: String::new(),
    };

    (state, session, dpop_data)
}

#[test]
fn intel_service_ref_and_endpoints_are_registered() {
    assert_eq!(
        INTEL_APPVIEW_SERVICE_REF,
        "did:web:intel.catbird.blue#catbird_intel"
    );
    assert!(INTEL_ENDPOINTS.contains(&"blue.catbird.intel.listCommunities"));
    assert!(INTEL_ENDPOINTS.contains(&"blue.catbird.intel.getCommunity"));
    assert!(INTEL_ENDPOINTS.contains(&"blue.catbird.onboarding.getCatalog"));
    assert!(INTEL_ENDPOINTS.contains(&"blue.catbird.onboarding.getCalibrationSwipes"));
    assert!(INTEL_ENDPOINTS.contains(&"blue.catbird.onboarding.previewTimeline"));
    assert!(INTEL_ENDPOINTS.contains(&"blue.catbird.onboarding.solveBundle"));
}

#[tokio::test]
async fn intel_proxy_returns_503_when_disabled() {
    let pds = MockServer::start().await;
    let intel = MockServer::start().await;
    let (state, session, dpop_data) = build_intel_test_fixture(pds.uri(), intel.uri(), false).await;

    let result = catbird::handlers::atproto::proxy_xrpc(
        axum::extract::State(state),
        axum::Extension(session),
        None,
        Some(axum::Extension(dpop_data)),
        Method::GET,
        axum::extract::Path("blue.catbird.onboarding.getCatalog".to_string()),
        axum::extract::RawQuery(None),
        HeaderMap::new(),
        axum::body::Body::empty(),
    )
    .await;

    match result {
        Err(AppError::AtprotoResponse { status, error, .. }) => {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(error, "UpstreamUnavailable");
        }
        other => panic!("Expected 503 UpstreamUnavailable when disabled, got {other:?}"),
    }

    assert_eq!(pds.received_requests().await.unwrap().len(), 0);
    assert_eq!(intel.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn intel_proxy_mints_pds_service_auth_and_forwards_get_query_with_repeated_params() {
    let pds = MockServer::start().await;
    let intel = MockServer::start().await;
    let lexicon = "blue.catbird.onboarding.getCatalog";

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .and(query_param("aud", INTEL_APPVIEW_SERVICE_REF))
        .and(query_param("lxm", lexicon))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": "intel-jwt-get-catalog-1" })),
        )
        .expect(1)
        .mount(&pds)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/blue.catbird.onboarding.getCatalog"))
        .and(header("authorization", "Bearer intel-jwt-get-catalog-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "catalogVersion": "s17_rev6_synth",
            "totalCommunities": 1016,
            "scenes": [],
            "featuredCommunities": [],
            "warmStartCommunities": []
        })))
        .expect(1)
        .mount(&intel)
        .await;

    let (state, session, dpop_data) = build_intel_test_fixture(pds.uri(), intel.uri(), true).await;

    let raw_q = "seedFollowDids=did%3Aplc%3Asynth1&seedFollowDids=did%3Aplc%3Asynth2&limit=40";
    let response = catbird::handlers::atproto::proxy_xrpc(
        axum::extract::State(state),
        axum::Extension(session),
        None,
        Some(axum::Extension(dpop_data)),
        Method::GET,
        axum::extract::Path(lexicon.to_string()),
        axum::extract::RawQuery(Some(raw_q.to_string())),
        HeaderMap::new(),
        axum::body::Body::empty(),
    )
    .await
    .expect("Intel GET catalog proxy succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["totalCommunities"], 1016);

    let reqs = intel.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    let seeds: Vec<String> = reqs[0]
        .url
        .query_pairs()
        .filter(|(k, _)| k == "seedFollowDids")
        .map(|(_, v)| v.into_owned())
        .collect();
    assert_eq!(seeds, vec!["did:plc:synth1", "did:plc:synth2"]);
}

#[tokio::test]
async fn intel_proxy_forwards_post_solve_bundle_and_mints_fresh_token_per_call() {
    let pds = MockServer::start().await;
    let intel = MockServer::start().await;
    let lexicon = "blue.catbird.onboarding.solveBundle";
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    struct MintCounterResponder(Arc<AtomicUsize>);
    impl wiremock::Respond for MintCounterResponder {
        fn respond(&self, _req: &wiremock::Request) -> ResponseTemplate {
            let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": format!("intel-jwt-solve-{n}") }))
        }
    }

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .and(query_param("aud", INTEL_APPVIEW_SERVICE_REF))
        .and(query_param("lxm", lexicon))
        .respond_with(MintCounterResponder(counter_clone))
        .expect(2)
        .mount(&pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/blue.catbird.onboarding.solveBundle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sessionId": "sess_synth",
            "catalogVersion": "s17_rev6_synth",
            "solveMs": 3,
            "summary": {
                "totalFollows": 24,
                "anchorCount": 9,
                "makerCount": 6,
                "conversationalCount": 6,
                "curatorCount": 3,
                "originalsOnlyCount": 2,
                "estimatedDailyPosts": 38,
                "coveredCommunities": 4
            },
            "follows": [],
            "feeds": [],
            "starterPacks": [],
            "harmoniousNeighbors": []
        })))
        .expect(2)
        .mount(&intel)
        .await;

    let (state, session, dpop_data) = build_intel_test_fixture(pds.uri(), intel.uri(), true).await;

    for _ in 0..2 {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            axum::http::HeaderValue::from_static("application/json"),
        );
        let payload = serde_json::to_vec(&serde_json::json!({
            "selections": [{ "communityId": 497, "weight": 2 }],
            "controls": { "pace": "balanced", "originalsOnlyForHeavyReposters": true }
        }))
        .unwrap();

        let response = catbird::handlers::atproto::proxy_xrpc(
            axum::extract::State(state.clone()),
            axum::Extension(session.clone()),
            None,
            Some(axum::Extension(dpop_data.clone())),
            Method::POST,
            axum::extract::Path(lexicon.to_string()),
            axum::extract::RawQuery(None),
            headers,
            axum::body::Body::from(payload),
        )
        .await
        .expect("Intel POST solveBundle proxy succeeds");

        assert_eq!(response.status(), StatusCode::OK);
    }

    let reqs = intel.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 2);
    let auth1 = reqs[0]
        .headers
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    let auth2 = reqs[1]
        .headers
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(auth1, "Bearer intel-jwt-solve-1");
    assert_eq!(auth2, "Bearer intel-jwt-solve-2");
}

#[tokio::test]
async fn intel_proxy_end_to_end_live_es256_jwt_verified_by_catbird_intel() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let bun_bin = ["/Users/joshlacalamito/.bun/bin/bun", "bun"]
        .into_iter()
        .find(|cand| {
            Command::new(cand)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
        .expect("bun runtime available for cross-process E2E verification");

    let intel_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catbird-intel");
    let viewer_did = "did:plc:testinteluser000000000000";

    // Spawn a real in-process catbird-intel Bun server with synthetic catalog + strict ES256 verifyServiceAuth
    let bun_script = r#"
import { P256Keypair } from "@atproto/crypto";
import { S17CatalogEngine } from "./src/intel_catalog.ts";
import { createApiHandler } from "./src/api.ts";
import { createServiceAuthenticator } from "./src/service_auth.ts";

const kp = await P256Keypair.create({ exportable: true });
const privBytes = await kp.export();
const privHex = Buffer.from(privBytes).toString("hex");
const didKey = kp.did();

const bundle = {
  catalogVersion: "s17_rev6_e2e_synth",
  generatedAt: "2026-10-31T00:00:00Z",
  sourceCardsSha256: "0000",
  totalScenes: 1,
  totalCommunities: 1,
  scenes: [{
    sceneId: 10,
    sceneSlug: "swift_apple",
    sceneTitle: "iOS & Apple Craft",
    macroCategory: "software_ai_tech",
    symbolName: "swift",
    cardCount: 1,
    totalEligibleAccounts: 2,
    topCommunityIds: [497],
  }],
  communities: [{
    communityId: 497,
    title: "SwiftUI & Apple Platform Builders",
    description: "Native iOS and macOS craft.",
    sceneId: 10,
    sceneSlug: "swift_apple",
    sceneTitle: "iOS & Apple Craft",
    macroCategory: "software_ai_tech",
    symbolName: "swift",
    eligibleCount: 2,
    postCoherenceBps: 6900,
    socialCoherenceBps: 7300,
    curatedListTags: ["swiftui", "iosdev"],
    searchTerms: ["swiftui", "xcode", "apple"],
    centPostsInt8B64: Buffer.from(new Int8Array(256).buffer).toString("base64"),
    neighborCommunityIds: [],
    samplePostUris: [
      "at://did:plc:synth1111111111111111111/app.bsky.feed.post/3laaaa1111111",
      "at://did:plc:synth2222222222222222222/app.bsky.feed.post/3laaaa2222222",
      "at://did:plc:synth1111111111111111111/app.bsky.feed.post/3laaaa3333333"
    ],
    previewPostUris: [
      "at://did:plc:synth1111111111111111111/app.bsky.feed.post/3laaaa1111111",
      "at://did:plc:synth2222222222222222222/app.bsky.feed.post/3laaaa2222222"
    ],
    sampleAccountDids: ["did:plc:synth1111111111111111111", "did:plc:synth2222222222222222222"],
    feedGeneratorUris: [],
    starterPackUris: [],
    members: [
      {
        did: "did:plc:synth1111111111111111111",
        role: "anchor_creator",
        recommendedMode: "follow_all",
        whyPicked: "Trusted voice in SwiftUI & Apple Platform Builders",
        rankScoreBps: 9100,
        repostShareBps: 900,
        mediaShareBps: 2400,
        estimatedPostsPerWeek: 8,
        followers: 4200,
        samplePostUri: "at://did:plc:synth1111111111111111111/app.bsky.feed.post/3laaaa1111111"
      },
      {
        did: "did:plc:synth2222222222222222222",
        role: "scene_curator",
        recommendedMode: "originals_only",
        whyPicked: "High-signal curator in SwiftUI & Apple Platform Builders",
        rankScoreBps: 8700,
        repostShareBps: 5400,
        mediaShareBps: 4500,
        estimatedPostsPerWeek: 14,
        followers: 3100,
        samplePostUri: "at://did:plc:synth2222222222222222222/app.bsky.feed.post/3laaaa2222222"
      }
    ]
  }],
  tasteDuels: [],
  highHostilityPairs: [],
  noUnauthDids: [],
  warmStartIndex: { "did:plc:synth1111111111111111111": [[497, 8500]] }
};

const catalog = new S17CatalogEngine(bundle as any);
const authenticator = createServiceAuthenticator({
  audience: "did:web:intel.catbird.blue#catbird_intel",
  resolveAtprotoKey: async (did: string) => {
    if (did === "did:plc:testinteluser000000000000") return didKey;
    throw new Error("unknown did");
  },
});
const fetchHandler = createApiHandler({
  authenticate: authenticator,
  catalogEngine: catalog,
  requireServiceAuth: true,
});
const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: fetchHandler });
console.log(JSON.stringify({ port: server.port, privHex }));
setInterval(() => {}, 1000);
"#;

    let mut child = Command::new(bun_bin)
        .arg("-e")
        .arg(bun_script)
        .current_dir(&intel_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn bun catbird-intel child");

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let stdout = child.stdout.take().expect("child stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout);
    let mut first_line = String::new();
    reader
        .read_line(&mut first_line)
        .expect("read bun startup line");
    let info: serde_json::Value =
        serde_json::from_str(first_line.trim()).expect("parse bun startup json");
    let intel_port = info["port"].as_u64().expect("port") as u16;
    let priv_hex = info["privHex"].as_str().expect("privHex");
    let priv_bytes: Vec<u8> = (0..priv_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&priv_hex[i..i + 2], 16).unwrap())
        .collect();
    let signing_key = SigningKey::from_slice(&priv_bytes).expect("valid P-256 signing key");

    let pds = MockServer::start().await;
    let jti_counter = Arc::new(AtomicUsize::new(0));

    struct Es256ServiceAuthResponder {
        signing_key: SigningKey,
        iss: String,
        counter: Arc<AtomicUsize>,
    }
    impl wiremock::Respond for Es256ServiceAuthResponder {
        fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
            let mut aud = String::new();
            let mut lxm = String::new();
            for (k, v) in req.url.query_pairs() {
                if k == "aud" {
                    aud = v.into_owned();
                } else if k == "lxm" {
                    lxm = v.into_owned();
                }
            }
            let seq = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
            let now = chrono::Utc::now().timestamp();
            let header_b64 = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&serde_json::json!({"alg": "ES256", "typ": "JWT"})).unwrap(),
            );
            let payload_b64 = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&serde_json::json!({
                    "iss": self.iss,
                    "aud": aud,
                    "lxm": lxm,
                    "iat": now,
                    "exp": now + 60,
                    "jti": format!("nest-e2e-jti-{seq}")
                }))
                .unwrap(),
            );
            let signing_input = format!("{header_b64}.{payload_b64}");
            let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
            let sig = sig.normalize_s().unwrap_or(sig);
            let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
            let jwt = format!("{signing_input}.{sig_b64}");
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "token": jwt }))
        }
    }

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(Es256ServiceAuthResponder {
            signing_key,
            iss: viewer_did.to_string(),
            counter: jti_counter,
        })
        .expect(2)
        .mount(&pds)
        .await;

    let (state, session, dpop_data) =
        build_intel_test_fixture(pds.uri(), format!("http://127.0.0.1:{intel_port}"), true).await;

    // 1. Live GET getCatalog with warm-start seedFollowDids
    let cat_resp = catbird::handlers::atproto::proxy_xrpc(
        axum::extract::State(state.clone()),
        axum::Extension(session.clone()),
        None,
        Some(axum::Extension(dpop_data.clone())),
        Method::GET,
        axum::extract::Path("blue.catbird.onboarding.getCatalog".to_string()),
        axum::extract::RawQuery(Some(
            "seedFollowDids=did%3Aplc%3Asynth1111111111111111111".to_string(),
        )),
        HeaderMap::new(),
        axum::body::Body::empty(),
    )
    .await
    .expect("live E2E getCatalog succeeds");
    assert_eq!(cat_resp.status(), StatusCode::OK);
    let cat_bytes = axum::body::to_bytes(cat_resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let cat_json: serde_json::Value = serde_json::from_slice(&cat_bytes).unwrap();
    assert_eq!(cat_json["catalogVersion"], "s17_rev6_e2e_synth");
    assert_eq!(cat_json["warmStartCommunities"][0]["communityId"], 497);

    // 2. Live POST solveBundle verified end-to-end
    let mut post_headers = HeaderMap::new();
    post_headers.insert(
        "content-type",
        axum::http::HeaderValue::from_static("application/json"),
    );
    let solve_body = serde_json::to_vec(&serde_json::json!({
        "selections": [{ "communityId": 497, "weight": 2 }],
        "controls": { "pace": "balanced", "originalsOnlyForHeavyReposters": true },
        "targetSize": 10
    }))
    .unwrap();
    let solve_resp = catbird::handlers::atproto::proxy_xrpc(
        axum::extract::State(state),
        axum::Extension(session),
        None,
        Some(axum::Extension(dpop_data)),
        Method::POST,
        axum::extract::Path("blue.catbird.onboarding.solveBundle".to_string()),
        axum::extract::RawQuery(None),
        post_headers,
        axum::body::Body::from(solve_body),
    )
    .await
    .expect("live E2E solveBundle succeeds");
    assert_eq!(solve_resp.status(), StatusCode::OK);
    let solve_bytes = axum::body::to_bytes(solve_resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let solve_json: serde_json::Value = serde_json::from_slice(&solve_bytes).unwrap();
    assert_eq!(solve_json["summary"]["totalFollows"], 2);
    assert_eq!(solve_json["summary"]["originalsOnlyCount"], 1);
}

#[tokio::test]
async fn intel_proxy_decompresses_gzip_upstream_and_updates_content_length() {
    const GZIPPED_CATALOG: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xab, 0x56, 0x4a, 0x4e, 0x2c,
        0x49, 0xcc, 0xc9, 0x4f, 0x0f, 0x4b, 0x2d, 0x2a, 0xce, 0xcc, 0xcf, 0x53, 0xb2, 0x52, 0x2a,
        0x36, 0x34, 0x8f, 0x4f, 0xaf, 0xca, 0x2c, 0x88, 0x2f, 0x49, 0x2d, 0x2e, 0x51, 0xd2, 0x51,
        0x2a, 0xc9, 0x07, 0x2a, 0x70, 0xce, 0xcf, 0xcd, 0x2d, 0xcd, 0xcb, 0x2c, 0xc9, 0x4c, 0x2d,
        0x56, 0xb2, 0x32, 0x34, 0x30, 0x34, 0xd3, 0x51, 0x2a, 0x4e, 0x4e, 0xcd, 0x03, 0xf1, 0xa2,
        0x63, 0x75, 0x94, 0xd2, 0x52, 0x13, 0x4b, 0x4a, 0x8b, 0x52, 0x53, 0x50, 0x94, 0x81, 0x24,
        0xca, 0x13, 0x8b, 0x72, 0x83, 0x4b, 0x12, 0x8b, 0x4a, 0xd0, 0x64, 0x6a, 0x01, 0x9f, 0x7c,
        0x84, 0x50, 0x79, 0x00, 0x00, 0x00,
    ];

    let pds = MockServer::start().await;
    let intel = MockServer::start().await;
    let lexicon = "blue.catbird.onboarding.getCatalog";

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": "intel-jwt-gzip-1" })),
        )
        .expect(1)
        .mount(&pds)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/blue.catbird.onboarding.getCatalog"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .set_body_raw(GZIPPED_CATALOG.to_vec(), "application/json"),
        )
        .expect(1)
        .mount(&intel)
        .await;

    let (state, session, dpop_data) = build_intel_test_fixture(pds.uri(), intel.uri(), true).await;
    let response = catbird::handlers::atproto::proxy_xrpc(
        axum::extract::State(state.clone()),
        axum::Extension(session),
        None,
        Some(axum::Extension(dpop_data)),
        Method::GET,
        axum::extract::Path(lexicon.to_string()),
        axum::extract::RawQuery(None),
        HeaderMap::new(),
        axum::body::Body::empty(),
    )
    .await
    .expect("gzip intel response decompresses cleanly");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("content-encoding").is_none());
    let declared_len: usize = response
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(declared_len, body_bytes.len());
    assert_eq!(declared_len, 121);
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["catalogVersion"], "s17_gzip_test");
    assert_eq!(state.active_stream_semaphore.available_permits(), 64);
}

#[tokio::test]
async fn intel_proxy_rejects_wrong_method_and_oversized_body_before_minting_service_auth() {
    let pds = MockServer::start().await;
    let intel = MockServer::start().await;
    let (state, session, dpop_data) = build_intel_test_fixture(pds.uri(), intel.uri(), true).await;

    // 1. POST to GET query lexicon -> 405 MethodNotAllowed, 0 PDS calls
    let wrong_method = catbird::handlers::atproto::proxy_xrpc(
        axum::extract::State(state.clone()),
        axum::Extension(session.clone()),
        None,
        Some(axum::Extension(dpop_data.clone())),
        Method::POST,
        axum::extract::Path("blue.catbird.onboarding.getCatalog".to_string()),
        axum::extract::RawQuery(None),
        HeaderMap::new(),
        axum::body::Body::empty(),
    )
    .await;
    match wrong_method {
        Err(AppError::AtprotoResponse { status, error, .. }) => {
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(error, "MethodNotAllowed");
        }
        other => panic!("Expected 405 MethodNotAllowed, got {other:?}"),
    }

    // 2. Oversized >64 KiB POST body on solveBundle -> 400 BadRequest, 0 PDS calls
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        axum::http::HeaderValue::from_static("application/json"),
    );
    let oversized = vec![b' '; 70_000];
    let too_big = catbird::handlers::atproto::proxy_xrpc(
        axum::extract::State(state),
        axum::Extension(session),
        None,
        Some(axum::Extension(dpop_data)),
        Method::POST,
        axum::extract::Path("blue.catbird.onboarding.solveBundle".to_string()),
        axum::extract::RawQuery(None),
        headers,
        axum::body::Body::from(oversized),
    )
    .await;
    assert!(matches!(too_big, Err(AppError::BadRequest(_))));
    assert_eq!(pds.received_requests().await.unwrap().len(), 0);
    assert_eq!(intel.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn intel_proxy_aborts_oversized_upstream_response_and_releases_stream_permit() {
    let pds = MockServer::start().await;
    let intel = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": "intel-jwt-oversize-1" })),
        )
        .expect(1)
        .mount(&pds)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/blue.catbird.intel.listCommunities"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(vec![b'a'; 2 * 1024 * 1024 + 1024], "application/json"),
        )
        .expect(1)
        .mount(&intel)
        .await;

    let (state, session, dpop_data) = build_intel_test_fixture(pds.uri(), intel.uri(), true).await;
    let res = catbird::handlers::atproto::proxy_xrpc(
        axum::extract::State(state.clone()),
        axum::Extension(session),
        None,
        Some(axum::Extension(dpop_data)),
        Method::GET,
        axum::extract::Path("blue.catbird.intel.listCommunities".to_string()),
        axum::extract::RawQuery(None),
        HeaderMap::new(),
        axum::body::Body::empty(),
    )
    .await;

    assert!(matches!(res, Err(AppError::ResponseTooLarge(_))));
    assert_eq!(state.active_stream_semaphore.available_permits(), 64);
}
