//! Real Redis authentication fixtures. All keys are synthetic and isolated;
//! production guard code is exercised without a fail-open test mode.
#![allow(dead_code)]

use catbird::{models::CatbirdSession, services::RedisAuthStore};
use jacquard_oauth::authstore::ClientAuthStore;
use jacquard_oauth::session::{ClientSessionData, DpopClientData};
use jacquard_oauth::types::{OAuthTokenType, TokenSet};
use std::sync::Arc;
use uuid::Uuid;

pub const KEY: [u8; 32] = [0x24; 32];

pub fn disposable_url(name: &str, scheme: &str, forbidden_port: u16) -> String {
    assert_eq!(
        std::env::var("LITE_PUSH_DISPOSABLE").as_deref(),
        Ok("1"),
        "fixtures require explicit LITE_PUSH_DISPOSABLE=1"
    );
    let value = std::env::var(name).unwrap_or_else(|_| panic!("explicit {name} required"));
    let url = url::Url::parse(&value).expect("fixture URL");
    assert_eq!(url.scheme(), scheme);
    assert_eq!(url.host_str(), Some("127.0.0.1"), "loopback fixture only");
    assert_ne!(
        url.port().expect("explicit fixture port required"),
        forbidden_port
    );
    value
}

pub async fn store() -> Arc<RedisAuthStore> {
    store_with_prefix(&format!(
        "catbird:v2:cleanup_fixture_{}:",
        Uuid::new_v4().simple()
    ))
    .await
}

/// Reopens the exact fixture namespace in a worker subprocess. The namespace
/// must have been supplied by the owning fixture, never an application prefix.
pub async fn store_with_prefix(prefix: &str) -> Arc<RedisAuthStore> {
    let suffix = prefix
        .strip_prefix("catbird:v2:cleanup_fixture_")
        .and_then(|s| s.strip_suffix(':'))
        .expect("fixture-owned Redis prefix");
    assert!(suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    let url = disposable_url("REDIS_URL", "redis", 6379);
    let conn = redis::aio::ConnectionManager::new(redis::Client::open(url).unwrap())
        .await
        .expect("fixture Redis");
    Arc::new(RedisAuthStore::from_key(conn, prefix.into(), 3600, KEY).expect("fixture auth store"))
}

pub async fn seed(store: &RedisAuthStore, session: &CatbirdSession) {
    store
        .upsert_session(grant(
            &session.did,
            &session.id.to_string(),
            &session.pds_url,
        ))
        .await
        .expect("seed exact synthetic bearer");
}

pub fn grant(did: &str, bearer: &str, pds_url: &str) -> ClientSessionData {
    let did = jacquard_common::types::did::Did::new_owned(did.to_string()).unwrap();
    // Public synthetic test-only key, inherited from push_session_signout.rs.
    let dpop_key: jose_jwk::Key = serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-256",
        "x": "f83OJ3D2xFMTbKEBaGizdGlIUKEWx5q15odEB00stfg",
        "y": "x_daaqundbgUvJV358vRBgULGnpH7aRFZZDYyEiNg2g",
        "d": "jpsQnnGQmL-YxOmH1UmOBHg10OJ45DBTWh0n52qxzMQ"
    }))
    .unwrap();
    ClientSessionData {
        account_did: did.clone(),
        session_id: bearer.to_string().into(),
        host_url: jacquard_common::deps::fluent_uri::Uri::parse(pds_url)
            .unwrap()
            .to_owned(),
        authserver_url: pds_url.to_string().into(),
        authserver_token_endpoint: "".into(),
        authserver_revocation_endpoint: None,
        scopes: jacquard_oauth::scopes::Scopes::new(smol_str::SmolStr::new_static("atproto"))
            .unwrap(),
        dpop_data: DpopClientData {
            dpop_key,
            dpop_authserver_nonce: "".into(),
            dpop_host_nonce: "".into(),
        },
        token_set: TokenSet {
            iss: pds_url.to_string().into(),
            sub: did,
            aud: pds_url.to_string().into(),
            scope: Some("atproto".into()),
            refresh_token: Some("synthetic-fixture-refresh".into()),
            access_token: "synthetic-fixture-access".into(),
            token_type: OAuthTokenType::DPoP,
            expires_at: None,
        },
        resolved_scopes: None,
    }
}
