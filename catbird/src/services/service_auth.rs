//! MLS AppView Service Authentication Provider
//!
//! Obtains and caches PDS-issued service auth tokens for MLS AppView communication.
//! Tokens are issued by the user's PDS via `com.atproto.server.getServiceAuth`
//! with `aud = MLS_APPVIEW_SERVICE_REF` and `lxm = <lexicon>`, and returned verbatim.

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::JacquardDpopData;
use crate::models::CatbirdSession;
use crate::services::{AtProtoClient, ProxyResponse};
use chrono::Utc;
use dashmap::DashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::Mutex;

pub const MLS_APPVIEW_SERVICE_REF: &str = "did:web:chat.catbird.blue#atproto_mls";

/// Safety margin in seconds subtracted from token exp to cover clock skew and network latency.
pub const SAFETY_MARGIN_SECS: i64 = 10;

#[derive(Clone, Debug)]
struct CachedToken {
    token: String,
    exp: i64,
}

// Global cache and per-key locks shared across all ServiceAuthProvider instances.
// ponytail: per-key mutex, single global map. If chat traffic ever makes this
// map hot, shard it — but a token per (account, endpoint) with a <60s life is
// a small working set.
static CACHE: LazyLock<DashMap<(String, String), CachedToken>> = LazyLock::new(DashMap::new);
static LOCKS: LazyLock<DashMap<(String, String), Arc<Mutex<()>>>> = LazyLock::new(DashMap::new);

pub struct ServiceAuthProvider {
    state: Arc<AppState>,
}

impl ServiceAuthProvider {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Clear all cached service auth tokens and in-flight locks.
    pub fn clear_cache() {
        CACHE.clear();
        LOCKS.clear();
    }

    /// PDS-issued service-auth JWT: `iss` is the user's own bare DID, `aud` is
    /// MLS_APPVIEW_SERVICE_REF, `lxm` is exactly `lexicon`. Returned verbatim —
    /// never re-signed or re-wrapped. Cached per `(did, lexicon)` against the
    /// token's own `exp` minus a safety margin.
    pub async fn token_for(
        &self,
        session: &CatbirdSession,
        lexicon: &str,
    ) -> AppResult<String> {
        let key = (session.did.clone(), lexicon.to_string());
        let now = Utc::now().timestamp();

        // 1. Fast path: check cache with safety margin
        if let Some(entry) = CACHE.get(&key) {
            if now + SAFETY_MARGIN_SECS < entry.exp {
                return Ok(entry.token.clone());
            }
        }

        // 2. Slow path: acquire per-key mutex to prevent concurrent miss stampede
        let lock = LOCKS
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;

        // Re-check cache under the lock
        let now = Utc::now().timestamp();
        if let Some(entry) = CACHE.get(&key) {
            if now + SAFETY_MARGIN_SECS < entry.exp {
                return Ok(entry.token.clone());
            }
        }

        // 3. Request fresh token from user's PDS
        let token = self.fetch_service_auth_from_pds(session, lexicon).await?;

        // 4. Derive TTL by decoding token's own exp claim
        let exp = extract_jwt_exp(&token).unwrap_or_else(|| now + 60);

        CACHE.insert(key, CachedToken {
            token: token.clone(),
            exp,
        });

        Ok(token)
    }

    async fn fetch_service_auth_from_pds(
        &self,
        session: &CatbirdSession,
        lexicon: &str,
    ) -> AppResult<String> {
        let client = AtProtoClient::new(self.state.clone());
        let now = Utc::now().timestamp();
        let requested_exp = now + 60;

        let query = format!(
            "aud={}&lxm={}&exp={}",
            urlencoding::encode(MLS_APPVIEW_SERVICE_REF),
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
                    return Err(AppError::Upstream {
                        status,
                        message: format!("com.atproto.server.getServiceAuth failed: {}", msg),
                    });
                }
                body
            }
            ProxyResponse::Streaming { status, .. } => {
                return Err(AppError::Upstream {
                    status,
                    message: "Unexpected streaming response for getServiceAuth".into(),
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

/// Extract the `exp` claim from an unverified JWT payload
fn extract_jwt_exp(token: &str) -> Option<i64> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    claims.get("exp").and_then(|v| v.as_i64())
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
        lifetime_secs: Arc<AtomicI64>,
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
                fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
                    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                    use base64::Engine;

                    let now = Utc::now().timestamp();
                    let lifetime = self.lifetime_secs.load(Ordering::SeqCst);
                    let exp = now + lifetime;

                    let header = serde_json::json!({
                        "alg": "ES256",
                        "typ": "JWT"
                    });
                    let payload = serde_json::json!({
                        "iss": "did:plc:alice",
                        "aud": MLS_APPVIEW_SERVICE_REF,
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

            Self {
                server,
                lifetime_secs,
            }
        }

        fn uri(&self) -> String {
            self.server.uri().replace("127.0.0.1", "localhost")
        }
        fn set_token_lifetime_secs(&self, secs: i64) {
            self.lifetime_secs.store(secs, Ordering::SeqCst);
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
            access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn requests_a_pds_token_audienced_to_the_mls_appview_and_bound_to_one_nsid() {
        ServiceAuthProvider::clear_cache();
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

    #[tokio::test]
    async fn reuses_a_live_token_for_the_same_did_and_nsid() {
        ServiceAuthProvider::clear_cache();
        let pds = MockPds::new().await;
        let provider = ServiceAuthProvider::new(test_state().await);
        let session = test_session("did:plc:alice-reuse", &pds.uri());

        let first = provider
            .token_for(&session, "blue.catbird.chat.getConversations")
            .await
            .unwrap();
        let second = provider
            .token_for(&session, "blue.catbird.chat.getConversations")
            .await
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(pds.call_count().await, 1, "a live cached token must not re-hit the PDS");
    }

    #[tokio::test]
    async fn does_not_share_a_token_across_nsids_or_accounts() {
        ServiceAuthProvider::clear_cache();
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
    async fn refreshes_before_expiry_rather_than_serving_a_dead_token() {
        ServiceAuthProvider::clear_cache();
        let pds = MockPds::new().await;
        // Mint a token that is already inside the safety margin.
        pds.set_token_lifetime_secs(5);
        let provider = ServiceAuthProvider::new(test_state().await);
        let session = test_session("did:plc:alice-refresh", &pds.uri());

        provider
            .token_for(&session, "blue.catbird.chat.getConversations")
            .await
            .unwrap();
        provider
            .token_for(&session, "blue.catbird.chat.getConversations")
            .await
            .unwrap();

        assert_eq!(
            pds.call_count().await,
            2,
            "a token inside the refresh margin must be re-minted, not served"
        );
    }
}
