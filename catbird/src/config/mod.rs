//! Configuration module for Catbird Nest Gateway
//!
//! Handles loading configuration from environment variables and config files.

use jacquard_common::IntoStatic;
use serde::Deserialize;
use std::sync::Arc;

/// Application configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    /// Server configuration
    pub server: ServerConfig,
    /// Redis configuration for session storage
    pub redis: RedisConfig,
    /// OAuth/ATProto configuration
    pub oauth: OAuthConfig,
    /// MLS service configuration (optional, for direct routing)
    #[serde(default)]
    pub mls: MlsConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MlsConfig {
    /// URL of the MLS service (e.g., http://127.0.0.1:3000)
    /// If set, MLS requests are routed directly instead of through PDS
    #[serde(default)]
    pub service_url: Option<String>,
    /// DID of this gateway for service auth (e.g., did:web:api.catbird.blue)
    #[serde(default)]
    pub gateway_did: Option<String>,
    /// DID of the MLS service (e.g., did:web:mls.catbird.blue)
    #[serde(default = "default_mls_service_did")]
    pub service_did: String,
}

fn default_mls_service_did() -> String {
    "did:web:mls.catbird.blue".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Host to bind to
    #[serde(default = "default_host")]
    pub host: String,
    /// Port to listen on
    #[serde(default = "default_port")]
    pub port: u16,
    /// Port for internal admin endpoints (metrics)
    #[serde(default = "default_admin_port")]
    pub admin_port: u16,
    /// Base URL for this server (used in OAuth metadata)
    pub base_url: String,
    /// Allowed CORS origins (empty = permissive in dev)
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL
    #[serde(default = "default_redis_url")]
    pub url: String,
    /// Key prefix for session storage
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,
    /// Session TTL in seconds
    #[serde(default = "default_session_ttl")]
    pub session_ttl_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig {
    /// Client ID (your domain, e.g., https://api.catbird.app)
    pub client_id: String,
    /// Path to the ES256 private key (PEM format) - for single-key backward compatibility
    pub private_key_path: Option<String>,
    /// ES256 private key as base64-encoded string (alternative to file path)
    pub private_key_base64: Option<String>,
    /// Multiple private key paths for key rotation support
    /// Each key gets a kid derived from filename (e.g., "key1.pem" -> "catbird-key1")
    #[serde(default)]
    pub private_key_paths: Vec<String>,
    /// Which key ID to use for signing new JWTs (must match a loaded key's kid)
    /// Defaults to "catbird-key-1" for backward compatibility
    #[serde(default = "default_active_key_id")]
    pub active_key_id: String,
    /// Redirect URI for OAuth callback
    pub redirect_uri: String,
    /// Scopes to request
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
}

fn default_active_key_id() -> String {
    "catbird-key-1".to_string()
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    3000
}

fn default_admin_port() -> u16 {
    9090
}

fn default_redis_url() -> String {
    "redis://127.0.0.1:6379".to_string()
}

fn default_key_prefix() -> String {
    "catbird:session:".to_string()
}

fn default_session_ttl() -> u64 {
    86400 * 30 // 30 days
}

fn default_scopes() -> Vec<String> {
    vec!["atproto".to_string(), "transition:generic".to_string(), "transition:chat.bsky".to_string()]
}

impl AppConfig {
    /// Load configuration from environment and config files
    pub fn load() -> Result<Self, config::ConfigError> {
        dotenvy::dotenv().ok();

        let config = config::Config::builder()
            // Set defaults
            .set_default("server.host", default_host())?
            .set_default("server.port", default_port())?
            .set_default("redis.url", default_redis_url())?
            .set_default("redis.key_prefix", default_key_prefix())?
            .set_default("redis.session_ttl_seconds", default_session_ttl())?
            .set_default("oauth.scopes", default_scopes())?
            // Load from config file if exists
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::File::with_name("config/local").required(false))
            // Override with environment variables (CATBIRD_ prefix)
            .add_source(
                config::Environment::with_prefix("CATBIRD")
                    .separator("__")
                    .with_list_parse_key("CATBIRD__OAUTH__SCOPES")
                    .list_separator(",")
                    .try_parsing(true),
            )
            .build()?;

        config.try_deserialize()
    }
}

/// Concrete Jacquard OAuth client type used throughout nest.
pub type JacquardOAuthClient =
    jacquard_oauth::client::OAuthClient<jacquard_identity::JacquardResolver, crate::services::RedisAuthStore>;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub http_client: reqwest::Client,
    pub redis: redis::aio::ConnectionManager,
    pub key_store: Option<Arc<crate::services::KeyStore>>,
    /// Jacquard OAuth client
    pub jacquard_client: Option<Arc<JacquardOAuthClient>>,
    /// Redis-backed auth store for Jacquard sessions
    pub auth_store: Option<Arc<crate::services::RedisAuthStore>>,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self, anyhow::Error> {
        let http_client = reqwest::Client::builder()
            .user_agent("Catbird/0.1.0")
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .build()?;

        let redis_client = redis::Client::open(config.redis.url.as_str())?;
        let redis = redis::aio::ConnectionManager::new(redis_client).await?;

        let mut state = Self {
            config: Arc::new(config),
            http_client,
            redis,
            key_store: None,
            jacquard_client: None,
            auth_store: None,
        };

        // Initialize KeyStore first (needed by OAuth client)
        match crate::services::KeyStore::from_config(&state) {
            Ok(store) => {
                state.key_store = Some(Arc::new(store));
                tracing::info!("KeyStore initialized successfully");
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to initialize KeyStore: {}. OAuth will be unavailable.",
                    e
                );
            }
        }

        // Initialize Jacquard auth store + OAuth client
        if let Some(ref key_store) = state.key_store {
            match Self::init_jacquard(&state, key_store) {
                Ok((store, client)) => {
                    state.auth_store = Some(Arc::new(store));
                    state.jacquard_client = Some(Arc::new(client));
                    tracing::info!("Jacquard OAuthClient initialized successfully");
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to initialize Jacquard OAuthClient: {}",
                        e
                    );
                }
            }
        }

        Ok(state)
    }

    /// Build the Jacquard RedisAuthStore and OAuthClient from current state.
    fn init_jacquard(
        state: &AppState,
        key_store: &crate::services::KeyStore,
    ) -> Result<(crate::services::RedisAuthStore, JacquardOAuthClient), anyhow::Error> {
        use jacquard_oauth::atproto::{AtprotoClientMetadata, GrantType};
        use jacquard_oauth::scopes::Scope;
        use jacquard_oauth::session::ClientData;

        // Parse encryption key from env (base64-encoded 32-byte key)
        let encryption_key = std::env::var("SESSION_ENCRYPTION_KEY")
            .ok()
            .and_then(|b64| {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD.decode(&b64).ok()?;
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    tracing::warn!("SESSION_ENCRYPTION_KEY must be 32 bytes (44 base64 chars)");
                    None
                }
            });

        let store = crate::services::RedisAuthStore::new(
            state.redis.clone(),
            state.config.redis.key_prefix.clone(),
            state.config.redis.session_ttl_seconds,
            encryption_key,
        );

        let keyset = key_store.to_jacquard_keyset()?;

        // Build AtprotoClientMetadata for confidential client
        let client_id = url::Url::parse(&state.config.oauth.client_id)?;
        let redirect_uri = url::Url::parse(&state.config.oauth.redirect_uri)?;
        let jwks_uri = url::Url::parse(&format!(
            "{}/.well-known/jwks.json",
            state.config.server.base_url.trim_end_matches('/')
        ))?;

        let scopes: Vec<Scope<'static>> = state
            .config
            .oauth
            .scopes
            .iter()
            .filter_map(|s| Scope::parse(s).ok().map(|sc| sc.into_static()))
            .collect();

        let metadata = AtprotoClientMetadata::new(
            client_id,
            None,
            vec![redirect_uri],
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            scopes,
            Some(jwks_uri),
        );

        let client_data = ClientData::new(Some(keyset), metadata);
        let client = JacquardOAuthClient::new(store.clone(), client_data);

        Ok((store, client))
    }
}
