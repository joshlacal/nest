use crate::access::CredentialStore;
use crate::auth::DidResolver;
use crate::oauth::OAuthService;
use crate::space_client::SpaceClient;
use sqlx::PgPool;
use std::env;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub service_did: String,
    pub plc_directory_url: String,
    pub public_appview_url: String,
    pub circle_media_base_url: url::Url,
    pub appview_base_url: String,
    pub oauth_key_id: Option<String>,
    pub oauth_signing_key_path: Option<String>,
    pub oauth_signing_key_hex: Option<String>,
    pub push_key_id: String,
    pub push_signing_key_path: Option<String>,
    pub push_signing_key_hex: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, anyhow::Error> {
        let host = env::var("CIRCLE_APPVIEW_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("CIRCLE_APPVIEW_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3002);
        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string());
        let service_did = env::var("SERVICE_DID")
            .unwrap_or_else(|_| "did:web:circles.catbird.blue#atproto_circles".to_string());
        let plc_directory_url =
            env::var("PLC_DIRECTORY_URL").unwrap_or_else(|_| "https://plc.directory".to_string());
        let public_appview_url =
            env::var("PUBLIC_APPVIEW_URL").unwrap_or_else(|_| "https://public.api.bsky.app".to_string());
        let circle_media_base_url_raw = env::var("CIRCLE_MEDIA_BASE_URL")
            .unwrap_or_else(|_| "https://media.circles.catbird.blue".to_string());
        let circle_media_base_url = url::Url::parse(&circle_media_base_url_raw)
            .map_err(|e| anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must be a valid URL: {e}"))?;
        if circle_media_base_url.scheme() != "https" {
            return Err(anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must use https scheme"));
        }
        if !circle_media_base_url.username().is_empty() || circle_media_base_url.password().is_some() {
            return Err(anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must not contain userinfo"));
        }
        if circle_media_base_url.query().is_some() {
            return Err(anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must not contain a query component"));
        }
        if circle_media_base_url.fragment().is_some() {
            return Err(anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must not contain a fragment component"));
        }
        let path = circle_media_base_url.path();
        if path != "" && path != "/" {
            return Err(anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must not contain a path component"));
        }

        let appview_base_url = env::var("APPVIEW_BASE_URL")
            .or_else(|_| env::var("PUBLIC_URL"))
            .unwrap_or_else(|_| format!("http://{host}:{port}"));

        let oauth_key_id = env::var("OAUTH_KEY_ID")
            .ok()
            .or_else(|| env::var("APPVIEW_KEY_ID").ok());
        let oauth_signing_key_path = env::var("OAUTH_SIGNING_KEY_PATH")
            .ok()
            .or_else(|| env::var("APPVIEW_SIGNING_KEY_PATH").ok());
        let oauth_signing_key_hex = env::var("OAUTH_SIGNING_KEY_HEX")
            .ok()
            .or_else(|| env::var("APPVIEW_SIGNING_KEY_HEX").ok());

        let push_key_id = env::var("PUSH_KEY_ID")
            .ok()
            .or_else(|| env::var("CIRCLE_KEY_ID").ok())
            .unwrap_or_else(|| {
                if service_did.contains('#') {
                    service_did.clone()
                } else {
                    format!("{service_did}#atproto_circles")
                }
            });
        let push_signing_key_path = env::var("PUSH_SIGNING_KEY_PATH")
            .ok()
            .or_else(|| env::var("CIRCLE_SIGNING_KEY_PATH").ok());
        let push_signing_key_hex = env::var("PUSH_SIGNING_KEY_HEX")
            .ok()
            .or_else(|| env::var("CIRCLE_SIGNING_KEY_HEX").ok());

        let session_encryption_key_raw = env::var("SESSION_ENCRYPTION_KEY").map_err(|_| {
            anyhow::anyhow!(
                "SESSION_ENCRYPTION_KEY environment variable is required (32 bytes as 64-character hex or base64)"
            )
        })?;
        let _ = parse_session_encryption_key(&session_encryption_key_raw)?;

        Ok(Self {
            host,
            port,
            database_url,
            service_did,
            plc_directory_url,
            public_appview_url,
            circle_media_base_url,
            appview_base_url,
            oauth_key_id,
            oauth_signing_key_path,
            oauth_signing_key_hex,
            push_key_id,
            push_signing_key_path,
            push_signing_key_hex,
        })
    }
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
pub fn parse_session_encryption_key(raw: &str) -> Result<[u8; 32], anyhow::Error> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("SESSION_ENCRYPTION_KEY must not be empty"));
    }
    // Try hex (64 hex characters -> 32 bytes)
    if trimmed.len() == 64 {
        if let Ok(bytes) = hex_to_bytes(trimmed) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(key);
            }
        }
    }
    // Try standard base64 and URL-safe base64 (with or without padding)
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;

    for engine in &[&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(trimmed) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(key);
            }
        }
    }

    Err(anyhow::anyhow!(
        "SESSION_ENCRYPTION_KEY is invalid: expected 32 bytes (64-character hex or base64)"
    ))
}

pub fn load_session_encryption_key_or_fail() -> [u8; 32] {
    match env::var("SESSION_ENCRYPTION_KEY") {
        Ok(raw) => match parse_session_encryption_key(&raw) {
            Ok(key) => key,
            Err(e) => {
                panic!("SESSION_ENCRYPTION_KEY is malformed: {e}. Refusing to start without valid encryption key.");
            }
        },
        Err(_) => {
            panic!("SESSION_ENCRYPTION_KEY environment variable is required (32 bytes as 64-character hex or base64). Refusing to start without encryption key.");
        }
    }
}


fn try_load_signing_key(path: Option<&str>, hex: Option<&str>) -> Option<p256::ecdsa::SigningKey> {
    if let Some(h) = hex {
        if let Ok(bytes) = hex_to_bytes(h) {
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&bytes) {
                return Some(key);
            }
        }
    }
    if let Some(p) = path {
        if let Ok(content) = std::fs::read_to_string(p) {
            let trimmed = content.trim();
            if let Ok(bytes) = hex_to_bytes(trimmed) {
                if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&bytes) {
                    return Some(key);
                }
            }
            // PKCS#8 PEM ("BEGIN PRIVATE KEY") is what `FromStr` accepts.
            if let Ok(key) = trimmed.parse::<p256::ecdsa::SigningKey>() {
                return Some(key);
            }
            // SEC1 PEM ("BEGIN EC PRIVATE KEY") is what `openssl ecparam -genkey`
            // emits by default, so accept it too rather than silently falling
            // through to an ephemeral key.
            if let Ok(secret) = p256::SecretKey::from_sec1_pem(trimmed) {
                return Some(secret.into());
            }
        }
    }
    None
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub http_client: reqwest::Client,
    pub did_resolver: Arc<DidResolver>,
    pub credential_store: Arc<CredentialStore>,
    pub space_client: Arc<SpaceClient>,
    pub space_locks: Arc<crate::access::SpaceLockManager>,
    pub profile_hydrator: Arc<crate::hydration::ProfileHydrator>,
    pub oauth_service: Arc<OAuthService>,
    pub push_client: Option<Arc<crate::push::CirclePushClient>>,
}

impl AppState {
    pub fn new(config: Config, db: PgPool) -> Self {
        let config = Arc::new(config);
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        let did_resolver = Arc::new(DidResolver::new(
            config.plc_directory_url.clone(),
            http_client.clone(),
        ));
        let credential_store = Arc::new(CredentialStore::new());
        let space_client = Arc::new(SpaceClient::new());
        let space_locks = Arc::new(crate::access::SpaceLockManager::new());
        let profile_hydrator = Arc::new(crate::hydration::ProfileHydrator::new(
            config.public_appview_url.clone(),
            http_client.clone(),
        ));

        // An ephemeral OAuth key is never acceptable for a confidential client:
        // it changes on every restart, so the published JWKS stops matching the
        // key that signs `client_assertion`, and every token exchange fails with
        // `invalid_client: signature verification failed`. That failure mode is
        // silent and remote, so a misconfigured key must stop startup instead.
        let oauth_signing_key = match try_load_signing_key(
            config.oauth_signing_key_path.as_deref(),
            config.oauth_signing_key_hex.as_deref(),
        ) {
            Some(key) => key,
            None => {
                let configured = config.oauth_signing_key_path.is_some()
                    || config.oauth_signing_key_hex.is_some();
                assert!(
                    !configured,
                    "OAuth signing key is configured but could not be parsed. Accepted forms: \
                     raw 32-byte hex, SEC1 PEM (\"BEGIN EC PRIVATE KEY\"), or PKCS#8 PEM \
                     (\"BEGIN PRIVATE KEY\"). Refusing to start with an ephemeral key."
                );
                tracing::error!(
                    "No OAuth signing key configured; using an EPHEMERAL key. OAuth cannot \
                     work: the published JWKS changes on every restart and every \
                     client_assertion will fail signature verification. Set \
                     OAUTH_SIGNING_KEY_PATH or OAUTH_SIGNING_KEY_HEX."
                );
                p256::ecdsa::SigningKey::random(&mut rand::thread_rng())
            }
        };

        let session_encryption_key = load_session_encryption_key_or_fail();

        let oauth_service = Arc::new(OAuthService::with_encryption_key(
            db.clone(),
            config.appview_base_url.clone(),
            oauth_signing_key,
            config.oauth_key_id.clone(),
            session_encryption_key,
        ));

        space_client.set_deps(crate::space_client::SpaceClientDeps {
            http_client: http_client.clone(),
            did_resolver: did_resolver.clone(),
            oauth_service: oauth_service.clone(),
        });
        let push_signing_key = try_load_signing_key(
            config.push_signing_key_path.as_deref(),
            config.push_signing_key_hex.as_deref(),
        );

        let push_client = push_signing_key.map(|key| {
            Arc::new(crate::push::CirclePushClient::new(
                env::var("PUSH_URL").ok(),
                config.service_did.clone(),
                config.push_key_id.clone(),
                env::var("PUSH_AUDIENCE").ok(),
                key,
                http_client.clone(),
            ))
        });

        Self {
            config,
            db,
            http_client,
            did_resolver,
            credential_store,
            space_client,
            space_locks,
            profile_hydrator,
            oauth_service,
            push_client,
        }
    }
    pub fn with_did_resolver(config: Config, db: PgPool, did_resolver: Arc<DidResolver>) -> Self {
        let mut state = Self::new(config, db);
        state.did_resolver = did_resolver.clone();
        state.space_client.set_deps(crate::space_client::SpaceClientDeps {
            http_client: state.http_client.clone(),
            did_resolver,
            oauth_service: state.oauth_service.clone(),
        });
        state
    }
    pub fn with_profile_hydrator(
        config: Config,
        db: PgPool,
        did_resolver: Arc<DidResolver>,
        profile_hydrator: Arc<crate::hydration::ProfileHydrator>,
    ) -> Self {
        let mut state = Self::with_did_resolver(config, db, did_resolver);
        state.profile_hydrator = profile_hydrator;
        state
    }
    pub fn with_services(
        config: Config,
        db: PgPool,
        did_resolver: Arc<DidResolver>,
        credential_store: Arc<CredentialStore>,
        space_client: Arc<SpaceClient>,
        space_locks: Arc<crate::access::SpaceLockManager>,
    ) -> Self {
        let mut state = Self::with_did_resolver(config, db, did_resolver);
        state.credential_store = credential_store;
        state.space_client = space_client;
        state.space_locks = space_locks;
        state
    }



    pub fn with_oauth_service(mut self, oauth_service: Arc<OAuthService>) -> Self {
        self.oauth_service = oauth_service;
        self
    }

    pub fn did_document(&self) -> crate::auth::DidDocument {
        let base_did = if self.config.service_did.contains('#') {
            self.config.service_did.split('#').next().unwrap().to_string()
        } else {
            self.config.service_did.clone()
        };
        let key_id_full = format!("{base_did}#{}", self.oauth_service.key_id);

        let mut verification_method = Vec::new();
        if let Some(first_key) = self.oauth_service.jwks.keys.first() {
            verification_method.push(crate::auth::VerificationMethod {
                id: key_id_full,
                r#type: "JsonWebKey2020".to_string(),
                controller: base_did.clone(),
                public_key_jwk: Some(first_key.clone()),
                public_key_multibase: None,
            });
        }

        let service = vec![crate::auth::DidService {
            id: "#atproto_circles".to_string(),
            r#type: "AtprotoCirclesAppView".to_string(),
            service_endpoint: self.oauth_service.base_url.clone(),
        }];

        crate::auth::DidDocument {
            id: base_did,
            verification_method,
            service,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::try_load_signing_key;

    /// `openssl ecparam -genkey -name prime256v1 -noout` emits SEC1, not PKCS#8.
    /// Failing to load it used to fall back to an ephemeral key, which silently
    /// broke every OAuth token exchange with `invalid_client`.
    #[test]
    fn loads_sec1_pem_key_from_file() {
        let key = p256::SecretKey::random(&mut rand::thread_rng());
        let pem = key
            .to_sec1_pem(p256::pkcs8::LineEnding::LF)
            .expect("encode sec1");
        let file = std::env::temp_dir().join(format!("circle-sec1-{}.pem", uuid::Uuid::new_v4()));
        std::fs::write(&file, pem.as_bytes()).expect("write key");

        let loaded = try_load_signing_key(Some(file.to_str().unwrap()), None)
            .expect("SEC1 PEM must load");
        assert_eq!(
            loaded.to_bytes(),
            key.to_bytes(),
            "loaded key must be the same key, not a fresh one"
        );
        std::fs::remove_file(&file).ok();
    }

    /// Raw 32-byte hex must also work, since that is the other documented form.
    #[test]
    fn loads_raw_hex_key() {
        let key = p256::SecretKey::random(&mut rand::thread_rng());
        let hex: String = key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let loaded = try_load_signing_key(None, Some(&hex)).expect("hex key must load");
        assert_eq!(loaded.to_bytes(), key.to_bytes());
    }

    /// A configured-but-garbage key must NOT yield a key; startup turns this into
    /// a hard failure rather than an ephemeral identity.
    #[test]
    fn rejects_unparseable_key() {
        assert!(try_load_signing_key(None, Some("not-a-key")).is_none());
    }

    #[test]
    fn parses_hex_session_encryption_key() {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let parsed = super::parse_session_encryption_key(hex_key).expect("hex key must parse");
        assert_eq!(parsed[0], 0x01);
        assert_eq!(parsed[31], 0xef);
    }

    #[test]
    fn parses_base64_session_encryption_key() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let raw = [42u8; 32];
        let b64 = STANDARD.encode(raw);
        let parsed = super::parse_session_encryption_key(&b64).expect("base64 key must parse");
        assert_eq!(parsed, raw);
    }

    #[test]
    fn rejects_invalid_session_encryption_keys() {
        assert!(super::parse_session_encryption_key("").is_err());
        assert!(super::parse_session_encryption_key("not-a-key").is_err());
        assert!(super::parse_session_encryption_key("0123456789abcdef").is_err()); // 8 bytes
        // 31 bytes in hex (62 hex chars)
        let short_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";
        assert!(super::parse_session_encryption_key(short_hex).is_err());
    }
}
