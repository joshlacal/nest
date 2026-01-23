//! Configuration module for Catbird Nest Gateway
//!
//! Handles loading configuration from environment variables and config files.

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
    /// Base URL for this server (used in OAuth metadata)
    pub base_url: String,
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
    /// Path to the ES256 private key (PEM format)
    pub private_key_path: Option<String>,
    /// ES256 private key as base64-encoded string (alternative to file path)
    pub private_key_base64: Option<String>,
    /// Redirect URI for OAuth callback
    pub redirect_uri: String,
    /// Scopes to request
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    3000
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

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub http_client: reqwest::Client,
    pub redis: redis::aio::ConnectionManager,
    pub oauth_client: Option<Arc<crate::services::CatbirdOAuthClient>>,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self, anyhow::Error> {
        let http_client = reqwest::Client::builder()
            .user_agent("Catbird/0.1.0")
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let redis_client = redis::Client::open(config.redis.url.as_str())?;
        let redis = redis::aio::ConnectionManager::new(redis_client).await?;

        let mut state = Self {
            config: Arc::new(config),
            http_client,
            redis,
            oauth_client: None,
        };

        // Initialize OAuth client after state is created
        match crate::services::create_oauth_client(&state) {
            Ok(client) => {
                state.oauth_client = Some(Arc::new(client));
                tracing::info!("OAuthClient initialized successfully");
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to initialize OAuthClient: {}. OAuth will be unavailable.",
                    e
                );
            }
        }

        Ok(state)
    }
}
