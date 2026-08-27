//! Configuration module for Catbird Nest Gateway
//!
//! Handles loading configuration from environment variables and config files.

use jacquard_common::IntoStatic;
use serde::Deserialize;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
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
    /// Push control-plane configuration (optional)
    #[serde(default)]
    pub push: PushConfig,
    /// Clean-chat configuration (blue.catbird.chat.*)
    #[serde(default)]
    pub chat: ChatConfig,
    /// Standalone Circle AppView direct-routing configuration.
    #[serde(default)]
    pub circle: CircleConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CircleConfig {
    #[serde(default = "default_circle_base_url")]
    pub base_url: String,
    #[serde(default = "default_circle_service_did")]
    pub service_did: String,
}

fn default_circle_base_url() -> String {
    "https://circles.catbird.blue".to_string()
}

fn default_circle_service_did() -> String {
    "did:web:circles.catbird.blue#atproto_circles".to_string()
}

impl Default for CircleConfig {
    fn default() -> Self {
        Self {
            base_url: default_circle_base_url(),
            service_did: default_circle_service_did(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChatConfig {
    /// Whether clean-chat routing/exchanger is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Token issuer (default: "https://api.catbird.blue")
    #[serde(default = "default_chat_issuer")]
    pub issuer: String,
    /// Token audience (default: "did:web:mlschat.catbird.blue")
    #[serde(default = "default_chat_audience")]
    pub audience: String,
    /// Token header kid (default: "catbird-chat-key-1")
    #[serde(default = "default_chat_key_id")]
    pub key_id: String,
    /// Private key for ES256 minting (base64 PKCS#8 DER, SEC1, or PEM)
    #[serde(default)]
    pub signing_key_base64: Option<String>,
    /// Chat instance UUID (default: "e9a27f41-d4a6-4507-8687-b921733ec41a")
    #[serde(default = "default_chat_instance_id")]
    pub instance_id: String,
    /// External base URL for DPoP htu (default: "https://mlschat.catbird.blue")
    #[serde(default = "default_chat_external_base")]
    pub external_base: String,
    /// Internal URL to reach delivery service (default: "http://127.0.0.1:3001")
    #[serde(default = "default_chat_ds_internal_url")]
    pub ds_internal_url: String,
    /// Token TTL in seconds (default: 120)
    #[serde(default = "default_chat_token_ttl_seconds")]
    pub token_ttl_seconds: i64,
}

fn default_chat_issuer() -> String {
    "https://api.catbird.blue".to_string()
}

fn default_chat_audience() -> String {
    "did:web:mlschat.catbird.blue".to_string()
}

fn default_chat_key_id() -> String {
    "catbird-chat-key-1".to_string()
}

fn default_chat_instance_id() -> String {
    "e9a27f41-d4a6-4507-8687-b921733ec41a".to_string()
}

fn default_chat_external_base() -> String {
    "https://mlschat.catbird.blue".to_string()
}

fn default_chat_ds_internal_url() -> String {
    "http://127.0.0.1:3001".to_string()
}

fn default_chat_token_ttl_seconds() -> i64 {
    120
}

impl Default for ChatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: default_chat_issuer(),
            audience: default_chat_audience(),
            key_id: default_chat_key_id(),
            signing_key_base64: None,
            instance_id: default_chat_instance_id(),
            external_base: default_chat_external_base(),
            ds_internal_url: default_chat_ds_internal_url(),
            token_ttl_seconds: default_chat_token_ttl_seconds(),
        }
    }
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
    /// Default first-try APNs environment for registrations with no known
    /// environment yet (`RegistrationRow.apns_environment` is NULL).
    /// `true` tries production first, `false` tries sandbox first.
    /// `ApnsDelivery` always maintains clients for BOTH environments and
    /// falls back to the other one on a `BadDeviceToken` rejection, so this
    /// only affects which endpoint is tried first for brand-new tokens.
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

        let mut app_config: AppConfig = config.try_deserialize()?;

        // Override chat config with direct CHAT_* environment variables if present
        if let Ok(val) = std::env::var("CHAT_ENABLED") {
            app_config.chat.enabled =
                matches!(val.to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        }
        if let Ok(val) = std::env::var("CHAT_NEST_ISSUER") {
            if !val.is_empty() {
                app_config.chat.issuer = val;
            }
        }
        if let Ok(val) = std::env::var("CHAT_NEST_AUDIENCE") {
            if !val.is_empty() {
                app_config.chat.audience = val;
            }
        }
        if let Ok(val) = std::env::var("CHAT_NEST_KEY_ID") {
            if !val.is_empty() {
                app_config.chat.key_id = val;
            }
        }
        if let Ok(val) = std::env::var("CHAT_NEST_SIGNING_KEY") {
            if !val.is_empty() {
                app_config.chat.signing_key_base64 = Some(val);
            }
        }
        if let Ok(val) = std::env::var("CHAT_INSTANCE_ID") {
            if !val.is_empty() {
                app_config.chat.instance_id = val;
            }
        }
        if let Ok(val) = std::env::var("CHAT_EXTERNAL_BASE") {
            if !val.is_empty() {
                app_config.chat.external_base = val;
            }
        }
        if let Ok(val) = std::env::var("CHAT_DS_INTERNAL_URL") {
            if !val.is_empty() {
                app_config.chat.ds_internal_url = val;
            }
        }
        if let Ok(val) = std::env::var("CHAT_TOKEN_TTL_SECONDS") {
            if let Ok(ttl) = val.parse::<i64>() {
                if ttl > 0 {
                    app_config.chat.token_ttl_seconds = ttl;
                }
            }
        }

        Ok(app_config)
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
    /// Process-wide per-origin DPoP nonce cache, shared by the XRPC proxy
    /// path and the chat poller so a nonce learned via one saves the other
    /// a guaranteed `use_dpop_nonce` round trip. See
    /// `services::DpopNonceCache` for the cache/eviction/rotation contract.
    pub dpop_nonce_cache: Arc<crate::services::DpopNonceCache>,
    /// AES-256-GCM encryption key for Redis session records
    pub session_encryption_key: Option<[u8; 32]>,
}

fn validate_configured_oauth_scopes(scopes: &[String]) -> Result<(), anyhow::Error> {
    use jacquard_oauth::scopes::Scope;

    for scope in scopes {
        Scope::parse(scope).map_err(|error| {
            anyhow::anyhow!("Invalid configured OAuth scope {scope:?}: {error:?}")
        })?;
    }
    Ok(())
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self, anyhow::Error> {
        validate_configured_oauth_scopes(&config.oauth.scopes)?;
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

        // Parse encryption key from env (base64-encoded 32-byte key)
        let session_encryption_key = std::env::var("SESSION_ENCRYPTION_KEY")
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
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key,
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

        let store = crate::services::RedisAuthStore::new(
            state.redis.clone(),
            state.config.redis.key_prefix.clone(),
            state.config.redis.session_ttl_seconds,
            state.session_encryption_key,
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
            .map(|s| {
                Scope::parse(s)
                    .map(|scope| scope.into_static())
                    .map_err(|error| {
                        anyhow::anyhow!("Invalid configured OAuth scope {s:?}: {error:?}")
                    })
            })
            .collect::<Result<_, _>>()?;

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
        let client = JacquardOAuthClient::new_from_resolver(store.clone(), resolver, client_data);

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

        // Use CATMOS_OAUTH_SCOPES if set, otherwise fall back to "atproto transition:generic"
        let scope_str = std::env::var("CATMOS_OAUTH_SCOPES")
            .unwrap_or_else(|_| "atproto transition:generic".to_string());
        let scopes: Vec<Scope<'static>> = scope_str
            .split_whitespace()
            .map(|s| {
                Scope::parse(s)
                    .map(|scope| scope.into_static())
                    .map_err(|error| {
                        anyhow::anyhow!("Invalid CATMOS_OAUTH_SCOPES value {s:?}: {error:?}")
                    })
            })
            .collect::<Result<_, _>>()?;

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
        // `reqwest::Client::new()` has NO timeout: a hung identity lookup
        // waits forever. This resolver is reached from background workers that
        // process work sequentially, so one unbounded request stalls the whole
        // pipeline behind it.
        let resolver_client = reqwest::Client::builder()
            .user_agent("Catbird/0.1.0")
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let resolver = jacquard_identity::JacquardResolver::new(
            resolver_client,
            jacquard_identity::resolver::ResolverOptions::default(),
        );
        resolver.with_system_dns()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scopes_contain_standard_scopes() {
        let scopes = default_scopes();
        assert!(scopes.contains(&"atproto".to_string()));
        assert!(scopes.contains(&"transition:generic".to_string()));
        assert!(scopes.contains(&"transition:chat.bsky".to_string()));
    }
}
