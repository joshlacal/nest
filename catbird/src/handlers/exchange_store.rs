//! Encrypted, opaque-keyed, single-use OAuth callback exchange records.

use base64::Engine;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::services::redis_crypto::{Keyring, RecordContext};

const EXCHANGE_TTL_SECONDS: u64 = 60;
const MAX_FUTURE_SKEW_SECONDS: i64 = 5;
const INIT_TTL_SECONDS: u64 = 600;
const ALLOWED_HTTPS_HOSTS: &[&str] = &["catbird.blue", "catmos.catbird.blue", "catmos.pages.dev"];

#[derive(Clone)]
pub struct ExchangeStore {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
    keyring: Keyring,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeInit {
    pub nonce_hash: String,
    pub redirect_origin: String,
    pub redirect_target: Option<String>,
    pub client_selector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeRecord {
    pub session_id: String,
    nonce_hash: String,
    redirect_origin: String,
    created_at: i64,
}

impl ExchangeRecord {
    #[cfg(test)]
    fn new(session_id: &str, nonce: &str, redirect_origin: &str, created_at: i64) -> Self {
        Self {
            session_id: session_id.to_string(),
            nonce_hash: nonce_hash(nonce),
            redirect_origin: redirect_origin.to_string(),
            created_at,
        }
    }

    fn validate(&self, nonce: &str, origin: &str, now: i64) -> Result<(), ExchangeError> {
        let age = now - self.created_at;
        if !(-MAX_FUTURE_SKEW_SECONDS..=EXCHANGE_TTL_SECONDS as i64).contains(&age)
            || !verify_nonce(&self.nonce_hash, nonce)
            || self.redirect_origin != origin
        {
            return Err(ExchangeError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExchangeError {
    #[error("exchange failed")]
    Unauthorized,
    #[error("exchange failed")]
    Missing,
    #[error("exchange service unavailable")]
    Unavailable,
}

impl ExchangeStore {
    pub fn new(redis: redis::aio::ConnectionManager, key_prefix: String, keyring: Keyring) -> Self {
        Self {
            redis,
            key_prefix,
            keyring,
        }
    }

    pub fn new_code(&self) -> String {
        new_code_value()
    }

    fn exchange_key(&self, code: &str) -> String {
        exchange_key_for(&self.key_prefix, &self.keyring, code)
    }

    fn init_key(&self, state: &str) -> String {
        format!(
            "{}oauth_exchange_init:{}",
            self.key_prefix,
            self.keyring.opaque_id("oauth-exchange-init", state)
        )
    }
}

fn new_code_value() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn exchange_key_for(prefix: &str, keyring: &Keyring, code: &str) -> String {
    format!(
        "{}oauth_exchange:{}",
        prefix,
        keyring.opaque_id("oauth-exchange", code)
    )
}

impl ExchangeStore {
    pub async fn store_init(
        &self,
        state: &str,
        nonce: &str,
        redirect_target: Option<&str>,
        client_selector: &str,
    ) -> Result<(), ExchangeError> {
        let redirect_origin =
            normalize_origin(redirect_target.unwrap_or("https://catbird.blue/oauth/callback"))?;
        if !matches!(client_selector, "catmos" | "default") {
            return Err(ExchangeError::Unauthorized);
        }
        let record = ExchangeInit {
            nonce_hash: nonce_hash(nonce),
            redirect_origin,
            redirect_target: redirect_target.map(str::to_string),
            client_selector: client_selector.to_string(),
        };
        self.store_encrypted(
            &self.init_key(state),
            "oauth-exchange-init",
            &record,
            INIT_TTL_SECONDS,
        )
        .await
    }

    pub async fn take_init(&self, state: &str) -> Result<ExchangeInit, ExchangeError> {
        self.take_encrypted(&self.init_key(state), "oauth-exchange-init")
            .await
    }

    pub async fn issue(
        &self,
        session_id: &str,
        init: ExchangeInit,
    ) -> Result<String, ExchangeError> {
        let code = self.new_code();
        let record = ExchangeRecord {
            session_id: session_id.to_string(),
            nonce_hash: init.nonce_hash,
            redirect_origin: init.redirect_origin,
            created_at: chrono::Utc::now().timestamp(),
        };
        self.store_encrypted(
            &self.exchange_key(&code),
            "oauth-exchange",
            &record,
            EXCHANGE_TTL_SECONDS,
        )
        .await?;
        Ok(code)
    }

    pub async fn redeem(
        &self,
        code: &str,
        nonce: &str,
        origin: &str,
    ) -> Result<String, ExchangeError> {
        let origin = normalize_origin(origin)?;
        let record: ExchangeRecord = self
            .take_encrypted(&self.exchange_key(code), "oauth-exchange")
            .await
            .map_err(|error| match error {
                ExchangeError::Missing => ExchangeError::Unauthorized,
                other => other,
            })?;
        record.validate(nonce, &origin, chrono::Utc::now().timestamp())?;
        Ok(record.session_id)
    }

    async fn store_encrypted<T: Serialize>(
        &self,
        key: &str,
        kind: &str,
        record: &T,
        ttl: u64,
    ) -> Result<(), ExchangeError> {
        let plaintext = serde_json::to_vec(record).map_err(|_| ExchangeError::Unavailable)?;
        let envelope = self
            .keyring
            .seal(&RecordContext::new(kind, key), &plaintext)
            .map_err(|_| ExchangeError::Unavailable)?;
        let mut connection = self.redis.clone();
        redis::cmd("SET")
            .arg(key)
            .arg(envelope)
            .arg("EX")
            .arg(ttl)
            .query_async::<_, ()>(&mut connection)
            .await
            .map_err(|_| ExchangeError::Unavailable)
    }

    async fn take_encrypted<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
        kind: &str,
    ) -> Result<T, ExchangeError> {
        let mut connection = self.redis.clone();
        let envelope: Option<String> = redis::cmd("GETDEL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .map_err(|_| ExchangeError::Unavailable)?;
        let envelope = envelope.ok_or(ExchangeError::Missing)?;
        let plaintext = self
            .keyring
            .open(&RecordContext::new(kind, key), &envelope)
            .map_err(|_| ExchangeError::Unauthorized)?;
        serde_json::from_slice(&plaintext).map_err(|_| ExchangeError::Unauthorized)
    }
}

pub fn normalize_origin(target: &str) -> Result<String, ExchangeError> {
    let url = url::Url::parse(target).map_err(|_| ExchangeError::Unauthorized)?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ExchangeError::Unauthorized);
    }
    let host = url.host_str().ok_or(ExchangeError::Unauthorized)?;
    match url.scheme() {
        "https"
            if url.port_or_known_default() == Some(443)
                && (ALLOWED_HTTPS_HOSTS.contains(&host) || host.ends_with(".catmos.pages.dev")) =>
        {
            Ok(format!("https://{host}"))
        }
        "http" if matches!(host, "127.0.0.1" | "::1" | "[::1]") => {
            let port = explicit_loopback_port(target).ok_or(ExchangeError::Unauthorized)?;
            Ok(format!(
                "http://{}:{}",
                if host.starts_with('[') {
                    host.to_string()
                } else if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.to_string()
                },
                port
            ))
        }
        _ => Err(ExchangeError::Unauthorized),
    }
}

fn explicit_loopback_port(target: &str) -> Option<u16> {
    let authority = target
        .strip_prefix("http://")?
        .split(['/', '?', '#'])
        .next()?;
    let port = authority
        .strip_prefix("127.0.0.1:")
        .or_else(|| authority.strip_prefix("[::1]:"))?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port = port.parse::<u32>().ok()?;
    (1..=u16::MAX as u32).contains(&port).then_some(port as u16)
}

fn nonce_hash(nonce: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(nonce.as_bytes()))
}

fn verify_nonce(expected: &str, nonce: &str) -> bool {
    let actual = nonce_hash(nonce);
    expected.len() == actual.len()
        && expected
            .bytes()
            .zip(actual.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplexed_exchange_store_contains_no_multi_exec_pipeline() {
        let forbidden = [".ato", "mic()"].concat();
        assert!(!include_str!("exchange_store.rs").contains(&forbidden));
    }

    use crate::services::redis_crypto::KeyMaterial;

    #[test]
    fn exact_origin_normalization_rejects_ambiguous_origins() {
        assert_eq!(
            normalize_origin("https://catmos.catbird.blue/callback").unwrap(),
            "https://catmos.catbird.blue"
        );
        for origin in [
            "http://catmos.catbird.blue/callback",
            "https://user@catmos.catbird.blue/callback",
            "https://catmos.catbird.blue:444/callback",
            "https://catmos.catbird.blue.evil/callback",
            "https://catmos.catbird.blue/callback#fragment",
            "http://127.0.0.1:0/callback",
            "http://[::1]:0/callback",
        ] {
            assert!(normalize_origin(origin).is_err(), "accepted {origin}");
        }
        assert_eq!(
            normalize_origin("http://127.0.0.1:43123/callback").unwrap(),
            "http://127.0.0.1:43123"
        );
        assert_eq!(
            normalize_origin("http://127.0.0.1:80/callback").unwrap(),
            "http://127.0.0.1:80"
        );
        assert_eq!(
            normalize_origin("http://[::1]:80/callback").unwrap(),
            "http://[::1]:80"
        );
    }

    #[test]
    fn nonce_binding_is_constant_shape_and_mismatch_is_generic() {
        let hash = nonce_hash("browser-secret");
        assert!(verify_nonce(&hash, "browser-secret"));
        assert!(!verify_nonce(&hash, "wrong"));
        assert_eq!(hash.len(), 43);
    }

    #[test]
    fn exchange_keys_and_codes_do_not_contain_session_credentials() {
        let keyring = Keyring::new(
            KeyMaterial::new("active", [1; 32]).unwrap(),
            vec![],
            [2; 32],
        )
        .unwrap();
        let session = "live-session-credential";
        let code = new_code_value();
        let key = exchange_key_for("test:", &keyring, &code);
        assert!(!code.contains(session));
        assert!(!key.contains(session));
        assert!(!key.contains(&code));
    }

    #[test]
    fn records_expire_after_sixty_seconds_and_fail_generically() {
        let now = 1_000;
        let record = ExchangeRecord::new("session", "nonce", "https://catmos.catbird.blue", now);
        assert!(record
            .validate("nonce", "https://catmos.catbird.blue", now + 60)
            .is_ok());
        assert_eq!(
            record.validate("nonce", "https://catmos.catbird.blue", now + 61),
            Err(ExchangeError::Unauthorized)
        );
        assert_eq!(
            record.validate("wrong", "https://catmos.catbird.blue", now),
            Err(ExchangeError::Unauthorized)
        );
        assert_eq!(
            record.validate("nonce", "https://evil.example", now),
            Err(ExchangeError::Unauthorized)
        );
        assert!(record
            .validate("nonce", "https://catmos.catbird.blue", now - 5)
            .is_ok());
        assert_eq!(
            record.validate("nonce", "https://catmos.catbird.blue", now - 6),
            Err(ExchangeError::Unauthorized)
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn redis_concurrency_ttl_and_aad_are_enforced() {
        let redis_url = std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required");
        let client = redis::Client::open(redis_url).unwrap();
        let manager = redis::aio::ConnectionManager::new(client).await.unwrap();
        let store = ExchangeStore {
            redis: manager,
            key_prefix: format!("test:oauth-exchange:{}:", uuid::Uuid::new_v4()),
            keyring: Keyring::new(
                KeyMaterial::new("active", [1; 32]).unwrap(),
                vec![],
                [2; 32],
            )
            .unwrap(),
        };
        let legacy_state = format!("legacy-{}", uuid::Uuid::new_v4());
        let legacy_client_key = format!("oauth_client:{legacy_state}");
        let legacy_redirect_key = format!("oauth_redirect:{legacy_state}");
        let mut connection = store.redis.clone();
        redis::pipe()
            .cmd("SET")
            .arg(&legacy_client_key)
            .arg("catmos")
            .ignore()
            .cmd("SET")
            .arg(&legacy_redirect_key)
            .arg("https://catmos.catbird.blue/callback")
            .ignore()
            .query_async::<_, ()>(&mut connection)
            .await
            .unwrap();
        assert!(matches!(
            store.take_init(&legacy_state).await,
            Err(ExchangeError::Missing)
        ));
        let legacy_values: (Option<String>, Option<String>) = redis::pipe()
            .cmd("GET")
            .arg(&legacy_client_key)
            .cmd("GET")
            .arg(&legacy_redirect_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            legacy_values,
            (
                Some("catmos".to_string()),
                Some("https://catmos.catbird.blue/callback".to_string())
            )
        );

        store
            .store_init(
                "cancelled-state",
                "browser-secret",
                Some("https://catmos.catbird.blue/callback"),
                "catmos",
            )
            .await
            .unwrap();
        let cancelled = store.take_init("cancelled-state").await.unwrap();
        assert_eq!(cancelled.client_selector, "catmos");
        assert!(matches!(
            store.take_init("cancelled-state").await,
            Err(ExchangeError::Missing)
        ));
        let init = ExchangeInit {
            nonce_hash: nonce_hash("browser-secret"),
            redirect_origin: "https://catmos.catbird.blue".into(),
            redirect_target: Some("https://catmos.catbird.blue/callback".into()),
            client_selector: "catmos".into(),
        };
        let code = store.issue("session", init).await.unwrap();
        let key = store.exchange_key(&code);
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!((1..=60).contains(&ttl));
        let (first, second) = tokio::join!(
            store.redeem(&code, "browser-secret", "https://catmos.catbird.blue"),
            store.redeem(&code, "browser-secret", "https://catmos.catbird.blue")
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);

        let expiring = store
            .issue(
                "expired-session",
                ExchangeInit {
                    nonce_hash: nonce_hash("browser-secret"),
                    redirect_origin: "https://catmos.catbird.blue".into(),
                    redirect_target: Some("https://catmos.catbird.blue/callback".into()),
                    client_selector: "catmos".into(),
                },
            )
            .await
            .unwrap();
        redis::cmd("PEXPIRE")
            .arg(store.exchange_key(&expiring))
            .arg(1)
            .query_async::<_, ()>(&mut connection)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(
            store
                .redeem(&expiring, "browser-secret", "https://catmos.catbird.blue")
                .await,
            Err(ExchangeError::Unauthorized)
        );

        let aad_code = store
            .issue(
                "aad-session",
                ExchangeInit {
                    nonce_hash: nonce_hash("browser-secret"),
                    redirect_origin: "https://catmos.catbird.blue".into(),
                    redirect_target: Some("https://catmos.catbird.blue/callback".into()),
                    client_selector: "catmos".into(),
                },
            )
            .await
            .unwrap();
        let original_key = store.exchange_key(&aad_code);
        let envelope: String = redis::cmd("GET")
            .arg(&original_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        let copied_key = format!("{}copied", original_key);
        redis::cmd("SET")
            .arg(&copied_key)
            .arg(envelope)
            .query_async::<_, ()>(&mut connection)
            .await
            .unwrap();
        assert!(matches!(
            store
                .take_encrypted::<ExchangeRecord>(&copied_key, "oauth-exchange")
                .await,
            Err(ExchangeError::Unauthorized)
        ));
    }
}
