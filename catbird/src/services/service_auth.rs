//! MLS AppView Service Authentication Provider
//!
//! Obtains PDS-issued service auth tokens for MLS AppView communication.
//! Tokens are issued by the user's PDS via `com.atproto.server.getServiceAuth`
//! with `aud = MLS_APPVIEW_SERVICE_REF` and `lxm = <lexicon>`, and returned verbatim.
//!
//! DELIBERATELY NOT CACHED. mls-ds enforces single-use replay protection: it
//! records each token's `jti` in the Postgres `auth_jti_nonce` table and rejects
//! any second presentation (`auth.rs:1163-1178`, applied at `:1253` via
//! `enforce_standard_with_replay_store`). A cached token therefore yields HTTP
//! 200 on its first use and 401 on every later one. Measured in production on
//! 2026-08-22: a fresh token returned 200 with a 22KB conversation payload; the
//! same token replayed returned `{"error":"NotAuthorized"}`, byte-identical to
//! the response for a deliberately corrupted token. One `getServiceAuth` call
//! per chat request is the correct cost, not an inefficiency to optimise away.

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::JacquardDpopData;
use crate::models::CatbirdSession;
use crate::services::{AtProtoClient, ProxyResponse};
use axum::http::StatusCode;
use chrono::Utc;
use std::sync::Arc;
pub const MLS_APPVIEW_SERVICE_REF: &str = "did:web:chat.catbird.blue#atproto_mls";
pub const CIRCLE_APPVIEW_SERVICE_REF: &str = "did:web:circles.catbird.blue#atproto_circle";

pub const CIRCLE_ENDPOINTS: &[&str] = &[
    "blue.catbird.circle.getCapabilities",
    "blue.catbird.circle.createCircle",
    "blue.catbird.circle.updateMember",
    "blue.catbird.circle.deleteCircle",
    "blue.catbird.circle.updatePreferences",
    "blue.catbird.circle.reportRecord",
    "blue.catbird.circle.activateSpace",
    "blue.catbird.circle.listCircles",
    "blue.catbird.circle.getFeed",
    "blue.catbird.circle.getPostThread",
    "blue.catbird.circle.listNotifications",
    "blue.catbird.circle.getMedia",
    "blue.catbird.circle.getOperation",
    "blue.catbird.circle.retryOperation",
    "blue.catbird.circle.syncProjection",
];

pub struct ServiceAuthProvider {
    state: Arc<AppState>,
}

impl ServiceAuthProvider {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }


    /// MLS helper: delegates directly to `token_for_audience` with the MLS audience.
    /// PDS-issued service-auth JWT: `iss` is the user's own bare DID, `aud` is
    /// MLS_APPVIEW_SERVICE_REF, `lxm` is exactly `lexicon`. Returned verbatim —
    /// never re-signed or re-wrapped. Minted fresh on every call because the
    /// token is single-use; see the module comment.
    pub async fn token_for(
        &self,
        session: &CatbirdSession,
        lexicon: &str,
    ) -> AppResult<String> {
        self.token_for_audience(session, MLS_APPVIEW_SERVICE_REF, lexicon).await
    }

    /// Parameterized service-auth token fetcher for allowed audiences (MLS and Circle AppViews).
    /// Validates that `audience` is a configured service identifier and `lexicon` is an exact allowed NSID.
    pub async fn token_for_audience(
        &self,
        session: &CatbirdSession,
        audience: &str,
        lexicon: &str,
    ) -> AppResult<String> {
        self.validate_audience_and_lexicon(audience, lexicon)?;
        self.fetch_service_auth_from_pds(session, audience, lexicon).await
    }

    fn validate_audience_and_lexicon(&self, audience: &str, lexicon: &str) -> AppResult<()> {
        if audience.is_empty()
            || audience != audience.trim()
            || audience.contains('*')
            || audience.contains(char::is_whitespace)
        {
            return Err(AppError::BadRequest(format!("Invalid service auth audience: {audience:?}")));
        }
        if lexicon.is_empty()
            || lexicon != lexicon.trim()
            || lexicon.contains('*')
            || lexicon.contains(char::is_whitespace)
        {
            return Err(AppError::BadRequest(format!("Invalid service auth lexicon: {lexicon:?}")));
        }

        let is_mls_aud = audience == MLS_APPVIEW_SERVICE_REF
            || (!self.state.config.mls.service_did.is_empty() && audience == self.state.config.mls.service_did);
        let is_circle_aud = !self.state.config.circle.service_did.is_empty()
            && audience == self.state.config.circle.service_did;

        if is_mls_aud {
            let is_allowed_lxm = crate::services::CHAT_ENDPOINTS.contains(&lexicon);
            if !is_allowed_lxm {
                return Err(AppError::BadRequest(format!(
                    "Unsupported MLS service auth lexicon: {lexicon}"
                )));
            }
            return Ok(());
        }

        if is_circle_aud {
            let is_allowed_lxm = CIRCLE_ENDPOINTS.contains(&lexicon);
            if !is_allowed_lxm {
                return Err(AppError::BadRequest(format!(
                    "Unsupported Circle service auth lexicon: {lexicon}"
                )));
            }
            return Ok(());
        }

        Err(AppError::BadRequest(format!(
            "Unsupported service auth audience: {audience}"
        )))
    }
    async fn fetch_service_auth_from_pds(
        &self,
        session: &CatbirdSession,
        audience: &str,
        lexicon: &str,
    ) -> AppResult<String> {
        let client = AtProtoClient::new(self.state.clone());
        let now = Utc::now().timestamp();
        let requested_exp = now + 60;

        let query = format!(
            "aud={}&lxm={}&exp={}",
            urlencoding::encode(audience),
            urlencoding::encode(lexicon),
            requested_exp
        );
        let dpop_data = self.resolve_dpop_data(session).await;

        let response = client
            .proxy_request(
                session,
                reqwest::Method::GET,
                "/xrpc/com.atproto.server.getServiceAuth",
                Some(&query),
                None,
                None,
                None,
                "service-auth-mint",
                Some(&dpop_data),
            )
            .await?;

        let body = match response {
            ProxyResponse::Buffered { status, body, .. } => {
                if !(200..300).contains(&status) {
                    let msg = String::from_utf8_lossy(&body).into_owned();
                    let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
                    let error_code = match status {
                        401 => "AuthRequired",
                        403 => "AccessRemoved",
                        400 => "InvalidRequest",
                        _ => "UpstreamUnavailable",
                    };
                    return Err(AppError::AtprotoResponse {
                        status: status_code,
                        error: error_code.into(),
                        message: format!("com.atproto.server.getServiceAuth failed ({status}): {msg}"),
                    });
                }
                body
            }
            ProxyResponse::Streaming { status, .. } => {
                return Err(AppError::AtprotoResponse {
                    status: StatusCode::BAD_GATEWAY,
                    error: "UpstreamUnavailable".into(),
                    message: format!("Unexpected streaming response for getServiceAuth ({status})"),
                });
            }
        };
        let json: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| AppError::Internal(format!("Invalid getServiceAuth JSON response: {}", e)))?;

        let token = json
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("getServiceAuth response missing 'token' string".into()))?
            .to_string();

        Ok(token)
    }

    async fn resolve_dpop_data(&self, session: &CatbirdSession) -> JacquardDpopData {
        if let Some(jacquard_client) = &self.state.jacquard_client {
            if let Ok(did) = jacquard_common::types::did::Did::new(&session.did) {
                if let Ok(session_data) = jacquard_client.registry.get(&did, &session.id.to_string(), true).await {
                    return JacquardDpopData {
                        dpop_key: session_data.dpop_data.dpop_key.clone(),
                        dpop_host_nonce: session_data.dpop_data.dpop_host_nonce.to_string(),
                    };
                }
            }
        }

        // Ephemeral DPoP key fallback for testing or sessions without registry entries
        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::services::DpopNonceCache;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct RecordedCall {
        nsid: String,
        query: HashMap<String, String>,
    }

    impl RecordedCall {
        fn query(&self, key: &str) -> Option<&str> {
            self.query.get(key).map(|s| s.as_str())
        }
    }

    struct MockPds {
        server: MockServer,
    }

    impl MockPds {
        async fn new() -> Self {
            let server = MockServer::start().await;
            let lifetime_secs = Arc::new(AtomicI64::new(60));
            let lifetime_clone = lifetime_secs.clone();

            struct ServiceAuthResponder {
                lifetime_secs: Arc<AtomicI64>,
            }

            impl wiremock::Respond for ServiceAuthResponder {
                fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
                    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                    use base64::Engine;

                    let query: HashMap<String, String> = request.url.query_pairs().into_owned().collect();
                    let aud = query.get("aud").cloned().unwrap_or_else(|| MLS_APPVIEW_SERVICE_REF.to_string());
                    let lxm = query.get("lxm").cloned().unwrap_or_default();

                    let now = Utc::now().timestamp();
                    let lifetime = self.lifetime_secs.load(Ordering::SeqCst);
                    let exp = now + lifetime;

                    let header = serde_json::json!({
                        "alg": "ES256",
                        "typ": "JWT"
                    });
                    let payload = serde_json::json!({
                        "iss": "did:plc:alice",
                        "aud": aud,
                        "lxm": lxm,
                        "exp": exp,
                        "iat": now,
                        "jti": Uuid::new_v4().to_string()
                    });
                    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
                    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
                    let token = format!("{}.{}.mock-signature", header_b64, payload_b64);

                    let body = serde_json::json!({
                        "token": token
                    });
                    ResponseTemplate::new(200).set_body_json(body)
                }
            }

            Mock::given(method("GET"))
                .and(path("/xrpc/com.atproto.server.getServiceAuth"))
                .respond_with(ServiceAuthResponder {
                    lifetime_secs: lifetime_clone,
                })
                .mount(&server)
                .await;

            Self { server }
        }

        fn uri(&self) -> String {
            self.server.uri().replace("127.0.0.1", "localhost")
        }

        async fn call_count(&self) -> usize {
            self.server.received_requests().await.map(|r| r.len()).unwrap_or(0)
        }

        async fn single_call(&self) -> RecordedCall {
            let requests = self.server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1, "expected exactly 1 call, got {}", requests.len());
            let req = &requests[0];
            let path = req.url.path();
            let nsid = path.strip_prefix("/xrpc/").unwrap_or(path).to_string();
            let query: HashMap<String, String> = req.url.query_pairs().into_owned().collect();
            RecordedCall { nsid, query }
        }
    }

    async fn test_state() -> Arc<AppState> {
        let config = AppConfig::load().unwrap();
        let http_client = reqwest::Client::builder().build().unwrap();
        let redis_client = redis::Client::open(config.redis.url.as_str()).unwrap();
        let redis = redis::aio::ConnectionManager::new(redis_client).await.unwrap();

        Arc::new(AppState {
            config: Arc::new(config),
            http_client,
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(DpopNonceCache::new()),
            circle_capability: Arc::new(crate::services::CircleCapabilityService::new(crate::services::AtProtoCircleProbe::new())),
            circle_worker_alive: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            circle_verifying_key: None,
            session_encryption_key: None,
        })
    }

    fn test_session(did: &str, pds_url: &str) -> CatbirdSession {
        CatbirdSession {
            id: Uuid::new_v4(),
            did: did.to_string(),
            handle: format!("{}.test", did),
            pds_url: pds_url.to_string(),
            access_token: "mock-access-token".to_string(),
            refresh_token: "mock-refresh-token".to_string(),
            scopes: Vec::new(),
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
        }
    }

    /// Read the `jti` from an unverified JWT payload. mls-ds keys its replay
    /// protection on this claim, so distinctness per call is the invariant.
    fn decode_claim(token: &str, claim: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let payload = token.split('.').nth(1).expect("jwt payload segment");
        let bytes = URL_SAFE_NO_PAD.decode(payload).expect("payload decodes");
        let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("payload is json");
        claims[claim].as_str().unwrap_or_default().to_string()
    }

    fn jti_of(token: &str) -> String {
        decode_claim(token, "jti")
    }
    #[tokio::test]
    async fn requests_a_pds_token_audienced_to_the_mls_appview_and_bound_to_one_nsid() {
        let pds = MockPds::new().await;
        let provider = ServiceAuthProvider::new(test_state().await);
        let session = test_session("did:plc:alice-req", &pds.uri());

        let _ = provider
            .token_for(&session, "blue.catbird.chat.getConversations")
            .await
            .expect("token minted");

        let call = pds.single_call().await;
        assert_eq!(call.nsid, "com.atproto.server.getServiceAuth");
        assert_eq!(call.query("aud"), Some(MLS_APPVIEW_SERVICE_REF));
        assert_eq!(call.query("lxm"), Some("blue.catbird.chat.getConversations"));
        let requested_exp: i64 = call.query("exp").expect("exp requested").parse().unwrap();
        let now = Utc::now().timestamp();
        assert!(
            requested_exp - now <= 60,
            "requested lifetime {} exceeds the mls-ds ceiling of 60s",
            requested_exp - now
        );
        assert!(
            requested_exp - now > 0,
            "requested lifetime must be in the future"
        );
    }

    /// Regression test for the production defect found 2026-08-22. Tokens were
    /// cached per `(did, lexicon)` for ~50s, but mls-ds records every `jti` in
    /// the Postgres `auth_jti_nonce` table and rejects any second presentation
    /// (`auth.rs:1163-1178`, applied at `:1253`). The first poll returned 200 and
    /// every poll inside the cache window returned 401. A service-auth token is
    /// single-use: each call MUST mint a fresh one.
    #[tokio::test]
    async fn mints_a_distinct_single_use_token_on_every_call() {
        let pds = MockPds::new().await;
        let provider = ServiceAuthProvider::new(test_state().await);
        let session = test_session("did:plc:alice-single-use", &pds.uri());

        let first = provider
            .token_for(&session, "blue.catbird.chat.getConversations")
            .await
            .unwrap();
        let second = provider
            .token_for(&session, "blue.catbird.chat.getConversations")
            .await
            .unwrap();

        assert_ne!(
            first, second,
            "a replayed token is rejected by mls-ds; every call must mint a fresh token"
        );
        assert_ne!(
            jti_of(&first),
            jti_of(&second),
            "distinct jti is exactly what mls-ds replay protection keys on"
        );
        assert_eq!(
            pds.call_count().await,
            2,
            "one getServiceAuth call per chat request is the correct, required cost"
        );
    }

    #[tokio::test]
    async fn does_not_share_a_token_across_nsids_or_accounts() {
        let pds = MockPds::new().await;
        let provider = ServiceAuthProvider::new(test_state().await);
        let alice = test_session("did:plc:alice-share", &pds.uri());
        let bob = test_session("did:plc:bob-share", &pds.uri());

        provider
            .token_for(&alice, "blue.catbird.chat.getConversations")
            .await
            .unwrap();
        provider
            .token_for(&alice, "blue.catbird.chat.enrollDevice")
            .await
            .unwrap();
        provider
            .token_for(&bob, "blue.catbird.chat.getConversations")
            .await
            .unwrap();

        // lxm is single-endpoint by mls-ds contract and tokens are per-account:
        // three distinct cache keys, three distinct PDS calls.
        assert_eq!(pds.call_count().await, 3);
    }

    #[tokio::test]
    async fn circle_token_uses_exact_audience_and_lxm() {
        let pds = MockPds::new().await;
        let provider = ServiceAuthProvider::new(test_state().await);
        let session = test_session("did:plc:alice-circle", &pds.uri());

        let token = provider
            .token_for_audience(
                &session,
                "did:web:circles.catbird.blue#atproto_circle",
                "blue.catbird.circle.getFeed",
            )
            .await
            .unwrap();

        assert_eq!(decode_claim(&token, "aud"), "did:web:circles.catbird.blue#atproto_circle");
        assert_eq!(decode_claim(&token, "lxm"), "blue.catbird.circle.getFeed");

        let call = pds.single_call().await;
        assert_eq!(call.nsid, "com.atproto.server.getServiceAuth");
        assert_eq!(call.query("aud"), Some("did:web:circles.catbird.blue#atproto_circle"));
        assert_eq!(call.query("lxm"), Some("blue.catbird.circle.getFeed"));
    }

    #[tokio::test]
    async fn rejects_unsupported_audience_or_wildcards() {
        let pds = MockPds::new().await;
        let provider = ServiceAuthProvider::new(test_state().await);
        let session = test_session("did:plc:alice-reject", &pds.uri());

        // Unsupported audience
        let res = provider
            .token_for_audience(&session, "did:web:evil.com", "blue.catbird.circle.getFeed")
            .await;
        assert!(res.is_err());

        // Wildcard audience
        let res = provider
            .token_for_audience(&session, "*", "blue.catbird.circle.getFeed")
            .await;
        assert!(res.is_err());

        // Wildcard lexicon
        let res = provider
            .token_for_audience(&session, CIRCLE_APPVIEW_SERVICE_REF, "blue.catbird.circle.*")
            .await;
        assert!(res.is_err());

        // Unallowed lexicon for circle audience
        let res = provider
            .token_for_audience(&session, CIRCLE_APPVIEW_SERVICE_REF, "blue.catbird.chat.getConversations")
            .await;
        assert!(res.is_err());

        // Unallowed lexicon for MLS audience
        let res = provider
            .token_for_audience(&session, MLS_APPVIEW_SERVICE_REF, "blue.catbird.circle.getFeed")
            .await;
        assert!(res.is_err());
    }

    async fn test_state_with_circle_did(circle_did: &str) -> Arc<AppState> {
        let mut config = AppConfig::load().unwrap();
        config.circle.service_did = circle_did.to_string();
        let http_client = reqwest::Client::builder().build().unwrap();
        let redis_client = redis::Client::open(config.redis.url.as_str()).unwrap();
        let redis = redis::aio::ConnectionManager::new(redis_client).await.unwrap();

        Arc::new(AppState {
            config: Arc::new(config),
            http_client,
            redis,
            push_db: None,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(DpopNonceCache::new()),
            circle_capability: Arc::new(crate::services::CircleCapabilityService::new(crate::services::AtProtoCircleProbe::new())),
            circle_worker_alive: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            circle_verifying_key: None,
            session_encryption_key: None,
        })
    }

    #[tokio::test]
    async fn rejects_audience_or_lexicon_with_surrounding_whitespace() {
        let pds = MockPds::new().await;
        let provider = ServiceAuthProvider::new(test_state().await);
        let session = test_session("did:plc:alice-whitespace", &pds.uri());

        // Leading/trailing whitespace on circle audience
        assert!(provider
            .token_for_audience(&session, " did:web:circles.catbird.blue#atproto_circle", "blue.catbird.circle.getFeed")
            .await
            .is_err());
        assert!(provider
            .token_for_audience(&session, "did:web:circles.catbird.blue#atproto_circle ", "blue.catbird.circle.getFeed")
            .await
            .is_err());
        assert!(provider
            .token_for_audience(&session, "did:web:circles.catbird.blue#atproto_circle\n", "blue.catbird.circle.getFeed")
            .await
            .is_err());

        // Leading/trailing whitespace on MLS audience
        assert!(provider
            .token_for_audience(&session, " did:web:chat.catbird.blue#atproto_mls", "blue.catbird.chat.getConversations")
            .await
            .is_err());
        assert!(provider
            .token_for_audience(&session, "did:web:chat.catbird.blue#atproto_mls ", "blue.catbird.chat.getConversations")
            .await
            .is_err());

        // Leading/trailing whitespace on lexicon
        assert!(provider
            .token_for_audience(&session, CIRCLE_APPVIEW_SERVICE_REF, " blue.catbird.circle.getFeed")
            .await
            .is_err());
        assert!(provider
            .token_for_audience(&session, CIRCLE_APPVIEW_SERVICE_REF, "blue.catbird.circle.getFeed ")
            .await
            .is_err());
        assert!(provider
            .token_for_audience(&session, CIRCLE_APPVIEW_SERVICE_REF, "blue.catbird.circle.getFeed\r\n")
            .await
            .is_err());
        assert!(provider
            .token_for_audience(&session, MLS_APPVIEW_SERVICE_REF, " blue.catbird.chat.getConversations")
            .await
            .is_err());
        assert!(provider
            .token_for_audience(&session, MLS_APPVIEW_SERVICE_REF, "blue.catbird.chat.getConversations ")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn custom_circle_did_narrows_allowlist_and_rejects_production_default() {
        let pds = MockPds::new().await;
        let custom_did = "did:web:custom.circles.blue#atproto_circle";
        let provider = ServiceAuthProvider::new(test_state_with_circle_did(custom_did).await);
        let session = test_session("did:plc:alice-custom-did", &pds.uri());

        // Custom DID succeeds
        let res = provider
            .token_for_audience(&session, custom_did, "blue.catbird.circle.getFeed")
            .await;
        assert!(res.is_ok(), "configured custom circle did must be accepted");

        // Hard-coded production DID is now rejected because custom DID is configured and overrides it
        let res = provider
            .token_for_audience(&session, CIRCLE_APPVIEW_SERVICE_REF, "blue.catbird.circle.getFeed")
            .await;
        assert!(res.is_err(), "production default circle did must be rejected when custom did is configured");
    }
}
