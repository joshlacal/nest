use crate::access::CredentialStore;
use crate::auth::DidResolver;
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
    pub nest_client_id: String,
    pub nest_jwks_url: String,
    pub nest_verifying_keys: Vec<crate::auth::ParsedVerifyingKey>,
    pub nest_push_url: Option<String>,
    pub nest_push_audience: Option<String>,
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
            .unwrap_or_else(|_| "did:web:circles.catbird.blue#atproto_circle".to_string());
        let plc_directory_url =
            env::var("PLC_DIRECTORY_URL").unwrap_or_else(|_| "https://plc.directory".to_string());
        let public_appview_url =
            env::var("PUBLIC_APPVIEW_URL").unwrap_or_else(|_| "https://public.api.bsky.app".to_string());
        let circle_media_base_url_raw = env::var("CIRCLE_MEDIA_BASE_URL")
            .map_err(|_| anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL environment variable is required"))?;
        let circle_media_base_url = url::Url::parse(&circle_media_base_url_raw)
            .map_err(|e| anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must be a valid URL: {e}"))?;
        if circle_media_base_url.scheme() != "https" {
            return Err(anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must use https scheme"));
        }
        if circle_media_base_url.host_str().is_none() {
            return Err(anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must have a valid host"));
        }
        if !circle_media_base_url.username().is_empty() || circle_media_base_url.password().is_some() {
            return Err(anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must not contain userinfo"));
        }
        if circle_media_base_url.query().is_some() {
            return Err(anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must not contain query parameters"));
        }
        if circle_media_base_url.fragment().is_some() {
            return Err(anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL must not contain a fragment"));
        }
        if circle_media_base_url.path() != "" && circle_media_base_url.path() != "/" {
            return Err(anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL path must be empty or '/'"));
        }
        let nest_client_id = env::var("NEST_CLIENT_ID")
            .map_err(|_| anyhow::anyhow!("NEST_CLIENT_ID environment variable is required"))?;
        let nest_jwks_url = env::var("NEST_JWKS_URL")
            .map_err(|_| anyhow::anyhow!("NEST_JWKS_URL environment variable is required"))?;
        let nest_push_url = env::var("NEST_PUSH_URL")
            .ok()
            .or_else(|| env::var("NEST_URL").ok().map(|u| format!("{}/internal/circle/push", u.trim_end_matches('/'))));
        let nest_push_audience = env::var("NEST_PUSH_AUDIENCE")
            .ok()
            .or_else(|| env::var("NEST_PUSH_SERVICE_DID").ok())
            .or_else(|| Some(nest_client_id.clone()));
        let push_key_id = env::var("PUSH_KEY_ID")
            .ok()
            .or_else(|| env::var("CIRCLE_KEY_ID").ok())
            .unwrap_or_else(|| {
                if service_did.contains('#') {
                    service_did.clone()
                } else {
                    format!("{service_did}#atproto_circle")
                }
            });
        let push_signing_key_path = env::var("PUSH_SIGNING_KEY_PATH")
            .ok()
            .or_else(|| env::var("CIRCLE_SIGNING_KEY_PATH").ok());
        let push_signing_key_hex = env::var("PUSH_SIGNING_KEY_HEX")
            .ok()
            .or_else(|| env::var("CIRCLE_SIGNING_KEY_HEX").ok());

        Ok(Self {
            host,
            port,
            database_url,
            service_did,
            plc_directory_url,
            public_appview_url,
            circle_media_base_url,
            nest_client_id,
            nest_jwks_url,
            nest_verifying_keys: Vec::new(),
            nest_push_url,
            nest_push_audience,
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

fn try_load_signing_key(path: Option<&str>, hex: Option<&str>) -> Option<p256::ecdsa::SigningKey> {
    if let Some(h) = hex {
        let trimmed = h.trim();
        if let Ok(bytes) = hex_to_bytes(trimmed) {
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&bytes) {
                return Some(k);
            }
        }
    }
    if let Some(p) = path {
        if let Ok(content) = std::fs::read(p) {
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&content) {
                return Some(k);
            }
            if let Ok(text) = std::str::from_utf8(&content) {
                if let Ok(bytes) = hex_to_bytes(text.trim()) {
                    if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&bytes) {
                        return Some(k);
                    }
                }
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
    pub push_client: Option<Arc<crate::push::NestPushClient>>,
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

        let push_client = if let (Some(push_url), Some(signing_key)) = (
            &config.nest_push_url,
            try_load_signing_key(
                config.push_signing_key_path.as_deref(),
                config.push_signing_key_hex.as_deref(),
            ),
        ) {
            let audience = config
                .nest_push_audience
                .clone()
                .unwrap_or_else(|| config.nest_client_id.clone());
            Some(Arc::new(crate::push::NestPushClient::new(
                push_url.clone(),
                config.service_did.clone(),
                config.push_key_id.clone(),
                audience,
                signing_key,
                http_client.clone(),
            )))
        } else {
            None
        };

        Self {
            config,
            db,
            http_client,
            did_resolver,
            credential_store,
            space_client,
            space_locks,
            profile_hydrator,
            push_client,
        }
    }

    pub fn with_push_client(mut self, push_client: Arc<crate::push::NestPushClient>) -> Self {
        self.push_client = Some(push_client);
        self
    }

    pub fn set_push_client(&mut self, push_client: Option<Arc<crate::push::NestPushClient>>) {
        self.push_client = push_client;
    }
    pub fn with_did_resolver(config: Config, db: PgPool, did_resolver: Arc<DidResolver>) -> Self {
        let config = Arc::new(config);
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        let credential_store = Arc::new(CredentialStore::new());
        let space_client = Arc::new(SpaceClient::new());
        let space_locks = Arc::new(crate::access::SpaceLockManager::new());
        let profile_hydrator = Arc::new(crate::hydration::ProfileHydrator::new(
            config.public_appview_url.clone(),
            http_client.clone(),
        ));

        Self {
            config,
            db,
            http_client,
            did_resolver,
            credential_store,
            space_client,
            space_locks,
            profile_hydrator,
            push_client: None,
        }
    }

    pub fn with_services(
        config: Config,
        db: PgPool,
        did_resolver: Arc<DidResolver>,
        credential_store: Arc<CredentialStore>,
        space_client: Arc<SpaceClient>,
        space_locks: Arc<crate::access::SpaceLockManager>,
    ) -> Self {
        let config = Arc::new(config);
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        let profile_hydrator = Arc::new(crate::hydration::ProfileHydrator::new(
            config.public_appview_url.clone(),
            http_client.clone(),
        ));

        Self {
            config,
            db,
            http_client,
            did_resolver,
            credential_store,
            space_client,
            space_locks,
            profile_hydrator,
            push_client: None,
        }
    }

    pub fn with_profile_hydrator(
        config: Config,
        db: PgPool,
        did_resolver: Arc<DidResolver>,
        profile_hydrator: Arc<crate::hydration::ProfileHydrator>,
    ) -> Self {
        let config = Arc::new(config);
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        let credential_store = Arc::new(CredentialStore::new());
        let space_client = Arc::new(SpaceClient::new());
        let space_locks = Arc::new(crate::access::SpaceLockManager::new());

        Self {
            config,
            db,
            http_client,
            did_resolver,
            credential_store,
            space_client,
            space_locks,
            profile_hydrator,
            push_client: None,
        }
    }
}
