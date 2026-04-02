//! Configuration module for Catbird Nest Gateway
//!
//! Handles loading configuration from environment variables and config files.

use jacquard_common::IntoStatic;
use serde::Deserialize;
use std::sync::Arc;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

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
    /// Push control-plane configuration (optional)
    #[serde(default)]
    pub push: PushConfig,
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
    "did:web:mlschat.catbird.blue".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PushConfig {
    /// Shared Postgres URL used by Nest and catbird-firehose
    #[serde(default)]
    pub database_url: Option<String>,
    /// DID that clients should send in registerPush/unregisterPush
    #[serde(default)]
    pub service_did: Option<String>,
    /// How often Nest should opportunistically refresh cached moderation state
    #[serde(default = "default_push_sync_interval_seconds")]
    pub sync_interval_seconds: u64,
    /// Background queue poll interval in milliseconds
    #[serde(default = "default_push_queue_poll_interval_ms")]
    pub queue_poll_interval_ms: u64,
    /// Max queue rows to lease per poll
    #[serde(default = "default_push_queue_batch_size")]
    pub queue_batch_size: u32,
    /// APNs delivery configuration
    #[serde(default)]
    pub apns: ApnsConfig,
    /// Enable the chat poll background service
    #[serde(default)]
    pub chat_poll_enabled: bool,
}

impl PushConfig {
    pub fn is_enabled(&self) -> bool {
        self.database_url.is_some() && self.service_did.is_some()
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ApnsConfig {
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub production: bool,
}

fn default_push_sync_interval_seconds() -> u64 {
    300
}

fn default_push_queue_poll_interval_ms() -> u64 {
    500
}

fn default_push_queue_batch_size() -> u32 {
    32
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
    vec![
        "atproto".to_string(),
        "transition:generic".to_string(),
        "transition:chat.bsky".to_string(),
    ]
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
pub type JacquardOAuthClient = jacquard_oauth::client::OAuthClient<
    jacquard_identity::JacquardResolver,
    crate::services::RedisAuthStore,
>;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub http_client: reqwest::Client,
    pub redis: redis::aio::ConnectionManager,
    pub push_db: Option<Pool<Postgres>>,
    pub key_store: Option<Arc<crate::services::KeyStore>>,
    /// Jacquard OAuth client (primary — Catbird iOS)
    pub jacquard_client: Option<Arc<JacquardOAuthClient>>,
    /// Jacquard OAuth client for catmos-web
    pub catmos_jacquard_client: Option<Arc<JacquardOAuthClient>>,
    /// Redis-backed auth store for Jacquard sessions
    pub auth_store: Option<Arc<crate::services::RedisAuthStore>>,
    /// Push subsystem managers (only present when push is configured)
    pub push: Option<Arc<crate::services::push::PushServices>>,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self, anyhow::Error> {
        let push_db = match config.push.database_url.as_deref() {
            Some(database_url) => {
                let pool = PgPoolOptions::new()
                    .max_connections(16)
                    .connect(database_url)
                    .await?;
                tracing::info!("Connected to Postgres push database");
                Some(pool)
            }
            None => None,
        };

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
            push_db,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            auth_store: None,
            push: None,
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
                    tracing::warn!("Failed to initialize Jacquard OAuthClient: {}", e);
                }
            }
        }

        // Initialize catmos-web OAuth client if CATMOS_OAUTH_CLIENT_ID is set
        if let (Some(ref key_store), Some(ref auth_store)) = (&state.key_store, &state.auth_store) {
            if let Ok(catmos_client_id) = std::env::var("CATMOS_OAUTH_CLIENT_ID") {
                let catmos_redirect = std::env::var("CATMOS_OAUTH_REDIRECT_URI")
                    .unwrap_or_else(|_| format!("{}/auth/callback", state.config.server.base_url));
                match Self::build_jacquard_client(
                    &state,
                    key_store,
                    auth_store,
                    &catmos_client_id,
                    &catmos_redirect,
                ) {
                    Ok(client) => {
                        state.catmos_jacquard_client = Some(Arc::new(client));
                        tracing::info!(
                            "Catmos Jacquard OAuthClient initialized (client_id={})",
                            catmos_client_id
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Failed to initialize catmos OAuthClient: {}", e);
                    }
                }
            }
        }

        Ok(state)
    }

    pub async fn init_push_services(&mut self) -> Result<(), anyhow::Error> {
        let Some(pool) = self.push_db.clone() else {
            return Ok(());
        };

        if !self.config.push.is_enabled() {
            tracing::warn!("Push database is configured but push service DID is missing");
            return Ok(());
        }

        let services = crate::services::push::PushServices::new(pool, self.config.push.clone())?;
        self.push = Some(Arc::new(services));
        tracing::info!("Push services initialized successfully");
        Ok(())
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
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&b64)
                    .ok()?;
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
        let resolver = Self::build_resolver();
        let client =
            JacquardOAuthClient::new_from_resolver(store.clone(), resolver, client_data);

        Ok((store, client))
    }

    /// Build a JacquardOAuthClient with a custom client_id and redirect_uri,
    /// reusing an existing RedisAuthStore. Used for catmos-web's separate OAuth identity.
    fn build_jacquard_client(
        state: &AppState,
        key_store: &crate::services::KeyStore,
        existing_store: &crate::services::RedisAuthStore,
        client_id_str: &str,
        redirect_uri_str: &str,
    ) -> Result<JacquardOAuthClient, anyhow::Error> {
        use jacquard_oauth::atproto::{AtprotoClientMetadata, GrantType};
        use jacquard_oauth::scopes::Scope;
        use jacquard_oauth::session::ClientData;

        let keyset = key_store.to_jacquard_keyset()?;

        let client_id = url::Url::parse(client_id_str)?;
        let redirect_uri = url::Url::parse(redirect_uri_str)?;
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
        let resolver = Self::build_resolver();
        let client =
            JacquardOAuthClient::new_from_resolver(existing_store.clone(), resolver, client_data);

        Ok(client)
    }

    /// Build a JacquardResolver with DNS enabled but no in-memory cache.
    ///
    /// Nest handles low-volume OAuth login flows where correctness matters more
    /// than saving a PLC directory lookup. Caching with time-to-idle TTLs caused
    /// stale identity data to persist indefinitely when users retried login.
    fn build_resolver() -> jacquard_identity::JacquardResolver {
        let resolver = jacquard_identity::JacquardResolver::new(
            reqwest::Client::new(),
            jacquard_identity::resolver::ResolverOptions::default(),
        );
        resolver.with_system_dns()
    }
}
