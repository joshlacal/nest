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

#[derive(Debug, Clone, Deserialize)]
pub struct PushConfig {
    /// Shared Postgres URL used by Nest and catbird-firehose
    #[serde(default)]
    pub database_url: Option<String>,
    /// DID that clients should send in registerPush/unregisterPush
    #[serde(default)]
    pub service_did: Option<String>,
    /// How long a cached per-actor moderation verdict is served before Nest
    /// re-asks the appview. Short: it exists to collapse bursts from one actor,
    /// not to be a source of truth.
    #[serde(default = "default_push_verdict_ttl_seconds")]
    pub verdict_ttl_seconds: u64,
    /// Background queue poll interval in milliseconds
    #[serde(default = "default_push_queue_poll_interval_ms")]
    pub queue_poll_interval_ms: u64,
    /// Max queue rows to lease per poll
    #[serde(default = "default_push_queue_batch_size")]
    pub queue_batch_size: u32,
    /// Max active devices per account (default: 10)
    #[serde(default = "default_max_active_devices_per_account")]
    pub max_active_devices_per_account: i64,
    /// Max inactive devices retained per account before pruning (default: 20)
    #[serde(default = "default_max_inactive_devices_per_account")]
    pub max_inactive_devices_per_account: i64,
    /// Max active devices to fan out to per notification (default: 10)
    #[serde(default = "default_max_fanout_per_notification")]
    pub max_fanout_per_notification: i64,
    /// APNs send timeout in seconds (default: 10)
    #[serde(default = "default_push_send_timeout_seconds")]
    pub send_timeout_seconds: u64,
    /// APNs delivery configuration
    #[serde(default)]
    pub apns: ApnsConfig,
    /// Enable the chat poll background service
    #[serde(default)]
    pub chat_poll_enabled: bool,
    /// When true (Phase 2), writers bind the SHA-256 fingerprint into session_id instead of raw plaintext bearer strings
    #[serde(default)]
    pub phase2_writers: bool,
}

impl PushConfig {
    pub fn is_enabled(&self) -> bool {
        self.database_url.is_some() && self.service_did.is_some()
    }

    /// Independent release gate verification for chat polling beyond config boolean default.
    ///
    /// Chat polling remains disabled by default. Even if `chat_poll_enabled` is set in config,
    /// the subsystem requires an explicit independent deployment gate confirmation via
    /// `NEST_CHAT_POLL_RELEASE_GATE="open"` or `CATBIRD_CHAT_POLL_RELEASE_GATE="open"`.
    pub fn is_chat_poll_release_gate_open(&self) -> bool {
        if !self.chat_poll_enabled {
            return false;
        }
        std::env::var("NEST_CHAT_POLL_RELEASE_GATE").as_deref() == Ok("open")
            || std::env::var("CATBIRD_CHAT_POLL_RELEASE_GATE").as_deref() == Ok("open")
    }
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            database_url: None,
            service_did: None,
            verdict_ttl_seconds: default_push_verdict_ttl_seconds(),
            queue_poll_interval_ms: default_push_queue_poll_interval_ms(),
            queue_batch_size: default_push_queue_batch_size(),
            max_active_devices_per_account: default_max_active_devices_per_account(),
            max_inactive_devices_per_account: default_max_inactive_devices_per_account(),
            max_fanout_per_notification: default_max_fanout_per_notification(),
            send_timeout_seconds: default_push_send_timeout_seconds(),
            apns: Default::default(),
            chat_poll_enabled: false,
            phase2_writers: false,
        }
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

fn default_push_verdict_ttl_seconds() -> u64 {
    60
}

fn default_push_queue_poll_interval_ms() -> u64 {
    500
}

fn default_push_queue_batch_size() -> u32 {
    32
}

fn default_max_active_devices_per_account() -> i64 {
    10
}

fn default_max_inactive_devices_per_account() -> i64 {
    20
}

fn default_max_fanout_per_notification() -> i64 {
    10
}

fn default_push_send_timeout_seconds() -> u64 {
    10
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
    /// Trusted reverse proxy CIDRs (empty = none trusted; forwarding headers ignored)
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL
    #[serde(default = "default_redis_url")]
    pub url: String,
    /// Key prefix for session storage (must contain explicit ':v2:' segment; e.g. 'catbird:v2:session:' or '<tenant>:v2:session:')
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,
    /// Session TTL in seconds
    #[serde(default = "default_session_ttl")]
    pub session_ttl_seconds: u64,
}

/// Redact userinfo and query parameters from a Redis connection URL for safe logging.
pub fn redact_redis_url(raw: &str) -> String {
    if let Ok(parsed) = url::Url::parse(raw) {
        let scheme = parsed.scheme();
        let host = match parsed.host_str() {
            Some(h) => h,
            None => return "<invalid-redis-url>".to_string(),
        };
        let port_part = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
        let path = parsed.path().trim_start_matches('/');
        let db_part = match path.parse::<u32>() {
            Ok(db) => format!("/{db}"),
            Err(_) => String::new(),
        };
        format!("{scheme}://{host}{port_part}{db_part}")
    } else {
        "<invalid-redis-url>".to_string()
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawOAuthConfig")]
pub struct OAuthConfig {
    /// Client ID (your domain, e.g., https://api.catbird.app)
    pub client_id: String,
    /// Path to the ES256 private key (PEM format) - for single-key backward compatibility
    pub private_key_path: Option<String>,
    /// ES256 private key as base64-encoded string (alternative to file path)
    pub private_key_base64: Option<String>,
    /// Multiple private key paths for key rotation support
    /// Each key gets a kid derived from filename (e.g., "key1.pem" -> "catbird-key1")
    pub private_key_paths: Vec<String>,
    /// Which key ID to use for signing new JWTs (must match a loaded key's kid)
    /// Defaults to "catbird-key-1" for backward compatibility
    pub active_key_id: String,
    /// Redirect URI for OAuth callback
    pub redirect_uri: String,
    /// Explicit initial scopes requested at login (default: atproto, transition:generic, transition:chat.bsky)
    pub initial_scopes: Vec<String>,
    /// Declared maximum scopes in client metadata (default: union of initial + optional progressive scopes)
    pub max_scopes: Vec<String>,
    /// Scopes field (maintained for backwards compatibility; synchronized to max_scopes)
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawOAuthConfig {
    client_id: String,
    #[serde(default)]
    private_key_path: Option<String>,
    #[serde(default)]
    private_key_base64: Option<String>,
    #[serde(default)]
    private_key_paths: Vec<String>,
    #[serde(default = "default_active_key_id")]
    active_key_id: String,
    redirect_uri: String,
    #[serde(default)]
    initial_scopes: Option<Vec<String>>,
    #[serde(default)]
    max_scopes: Option<Vec<String>>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
}

impl TryFrom<RawOAuthConfig> for OAuthConfig {
    type Error = String;

    fn try_from(raw: RawOAuthConfig) -> Result<Self, Self::Error> {
        let (initial_scopes, max_scopes) = match (raw.initial_scopes, raw.max_scopes, raw.scopes) {
            // Case 1: initial_scopes is explicitly provided (authoritative)
            (Some(initial), maybe_max, maybe_legacy) => {
                if initial.is_empty() {
                    return Err("OAuth initial_scopes cannot be empty".to_string());
                }
                if let Some(legacy) = &maybe_legacy {
                    if legacy.is_empty() {
                        return Err("Legacy OAuth scopes cannot be empty".to_string());
                    }
                    for s in legacy {
                        jacquard_oauth::scopes::Scope::<smol_str::SmolStr>::parse(s)
                            .map_err(|e| format!("Invalid legacy OAuth scope '{s}': {e:?}"))?;
                    }
                }
                let max = match maybe_max {
                    Some(configured_max) => derive_max_scopes(&initial, &configured_max),
                    None => derive_max_scopes(&initial, &default_optional_scopes()),
                };
                (initial, max)
            }
            // Case 2: initial_scopes absent, legacy scopes provided as backward-compatible initial input
            (None, maybe_max, Some(legacy)) => {
                if legacy.is_empty() {
                    return Err("Legacy OAuth scopes cannot be empty".to_string());
                }
                let initial = legacy.clone();
                let max = match maybe_max {
                    Some(configured_max) => derive_max_scopes(&initial, &configured_max),
                    None => {
                        // Existing deployments setting only legacy `scopes` / CATBIRD__OAUTH__SCOPES:
                        // Must NOT silently inherit optional account/identity maximum scopes.
                        initial.clone()
                    }
                };
                (initial, max)
            }
            // Case 3: Default configuration (neither initial_scopes nor legacy scopes configured)
            (None, maybe_max, None) => {
                let initial = default_initial_scopes();
                let max = match maybe_max {
                    Some(configured_max) => derive_max_scopes(&initial, &configured_max),
                    None => default_max_scopes(),
                };
                (initial, max)
            }
        };

        // Validate all initial_scopes entries
        for s in &initial_scopes {
            jacquard_oauth::scopes::Scope::<smol_str::SmolStr>::parse(s)
                .map_err(|e| format!("Invalid OAuth initial_scope '{s}': {e:?}"))?;
        }

        // Validate that normalized initial scopes contain mandatory `atproto` scope
        let normalized_initial = Self::parse_and_normalize_scopes(&initial_scopes)?;
        if !normalized_initial.iter().any(|s| s == "atproto") {
            return Err("OAuth initial_scopes must contain mandatory 'atproto' scope".to_string());
        }

        // Validate all max_scopes entries
        for s in &max_scopes {
            jacquard_oauth::scopes::Scope::<smol_str::SmolStr>::parse(s)
                .map_err(|e| format!("Invalid OAuth max_scope '{s}': {e:?}"))?;
        }

        // Validate that normalized derived max scopes contain mandatory `atproto` scope
        let normalized_max = Self::parse_and_normalize_scopes(&max_scopes)?;
        if !normalized_max.iter().any(|s| s == "atproto") {
            return Err("OAuth max_scopes must contain mandatory 'atproto' scope".to_string());
        }
        let scopes = max_scopes.clone();

        Ok(Self {
            client_id: raw.client_id,
            private_key_path: raw.private_key_path,
            private_key_base64: raw.private_key_base64,
            private_key_paths: raw.private_key_paths,
            active_key_id: raw.active_key_id,
            redirect_uri: raw.redirect_uri,
            initial_scopes,
            max_scopes,
            scopes,
        })
    }
}

impl OAuthConfig {
    /// Parse and validate a slice of scope strings into Jacquard Scope objects.
    /// Fails fast on ANY malformed scope instead of silently ignoring or truncating.
    pub fn parse_and_validate_scopes(
        scopes: &[String],
    ) -> Result<Vec<jacquard_oauth::scopes::Scope>, String> {
        scopes
            .iter()
            .map(|s| {
                jacquard_oauth::scopes::Scope::parse(s)
                    .map(|sc: jacquard_oauth::scopes::Scope<smol_str::SmolStr>| sc.into_static())
                    .map_err(|e| format!("Invalid OAuth scope '{s}': {e:?}"))
            })
            .collect()
    }

    /// Parse and return normalized scope strings.
    pub fn parse_and_normalize_scopes(scopes: &[String]) -> Result<Vec<String>, String> {
        let parsed = Self::parse_and_validate_scopes(scopes)?;
        Ok(parsed
            .into_iter()
            .map(|s| s.to_string_normalized().to_string())
            .collect())
    }

    /// Returns normalized maximum scopes as a vector of strings.
    pub fn normalized_max_scopes(&self) -> Result<Vec<String>, String> {
        Self::parse_and_normalize_scopes(&self.max_scopes)
    }

    /// Validates whether a requested scope string is allowed by declared max_scopes.
    /// Excludes app-password and account deletion scopes by design.
    pub fn is_scope_allowed(&self, scope_str: &str) -> Result<bool, String> {
        let parsed = jacquard_oauth::scopes::Scope::<smol_str::SmolStr>::parse(scope_str)
            .map_err(|e| format!("Invalid scope '{scope_str}': {e:?}"))?;
        let normalized = parsed.to_string_normalized();
        let max_normalized = self.normalized_max_scopes()?;
        Ok(max_normalized
            .iter()
            .any(|s| s.as_str() == normalized.as_str()))
    }
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
    "catbird:v2:session:".to_string()
}

fn default_session_ttl() -> u64 {
    86400 * 30 // 30 days
}

/// Default explicit initial scopes requested during sign-in.
/// Initial sign-in retains the core request for full-client compatibility.
/// Account and identity permissions are never in the initial request.
///
/// Deliberately does NOT request a chat-specific scope. Verified 2026-08-22 by
/// live call against two PDS hosts (selfhosted.social,
/// enoki.us-east.host.bsky.network): a session holding only these three scopes
/// mints com.atproto.server.getServiceAuth for
/// aud=did:web:chat.catbird.blue#atproto_mls with HTTP 200, and the returned JWT
/// satisfies every constraint in mls-ds validate_mls_service_claims. Adding an
/// unrecognised scope here would risk the OAuth authorize path for zero gain.
pub fn default_initial_scopes() -> Vec<String> {
    vec![
        "atproto".to_string(),
        "transition:generic".to_string(),
        "transition:chat.bsky".to_string(),
    ]
}

/// Default optional progressive scopes (identity and account management).
/// App-password management and account deletion are excluded by design.
pub fn default_optional_scopes() -> Vec<String> {
    vec![
        "identity:handle".to_string(),
        "account:email?action=manage".to_string(),
        "account:status?action=manage".to_string(),
    ]
}

/// Derives maximum scopes as the union of initial scopes and optional/configured max scopes,
/// preserving initial scope order, appending non-duplicate extra scopes, without overwriting operator policy.
pub fn derive_max_scopes(initial: &[String], optional_or_max: &[String]) -> Vec<String> {
    let mut derived = initial.to_vec();
    for s in optional_or_max {
        if !derived.iter().any(|existing| existing == s) {
            derived.push(s.clone());
        }
    }
    derived
}

/// Default declared maximum scopes for OAuth client metadata.
/// Defaults to union(default_initial_scopes(), default_optional_scopes()).
/// Note: App-password management and account deletion are excluded by design.
pub fn default_max_scopes() -> Vec<String> {
    derive_max_scopes(&default_initial_scopes(), &default_optional_scopes())
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
            // Load from config file if exists
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::File::with_name("config/local").required(false))
            // Override with environment variables (CATBIRD_ prefix)
            .add_source(
                config::Environment::with_prefix("CATBIRD")
                    .separator("__")
                    .with_list_parse_key("oauth.scopes")
                    .with_list_parse_key("oauth.initial_scopes")
                    .with_list_parse_key("oauth.max_scopes")
                    .list_separator(",")
                    .try_parsing(true),
            )
            .build()?;

        let mut app_config: AppConfig = config.try_deserialize()?;

        // Fail startup on invalid Redis key prefix (must contain explicit :v2: segment)
        crate::services::RedisAuthStore::validate_key_prefix(&app_config.redis.key_prefix)
            .map_err(|e| config::ConfigError::Message(e.to_string()))?;

        // Fail startup on any malformed scope in initial_scopes, max_scopes, or scopes
        for scope_str in &app_config.oauth.initial_scopes {
            jacquard_oauth::scopes::Scope::<smol_str::SmolStr>::parse(scope_str).map_err(|e| {
                config::ConfigError::Message(format!(
                    "Malformed OAuth initial_scope '{scope_str}': {e:?}"
                ))
            })?;
        }
        for scope_str in &app_config.oauth.max_scopes {
            jacquard_oauth::scopes::Scope::<smol_str::SmolStr>::parse(scope_str).map_err(|e| {
                config::ConfigError::Message(format!(
                    "Malformed OAuth max_scope '{scope_str}': {e:?}"
                ))
            })?;
        }
        for scope_str in &app_config.oauth.scopes {
            jacquard_oauth::scopes::Scope::<smol_str::SmolStr>::parse(scope_str).map_err(|e| {
                config::ConfigError::Message(format!("Malformed OAuth scope '{scope_str}': {e:?}"))
            })?;
        }

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

    /// Provide a valid default AppConfig for test environments without panicking on unset env vars.
    pub fn test_default() -> Self {
        let config = config::Config::builder()
            .set_default("server.host", default_host())
            .unwrap()
            .set_default("server.port", default_port())
            .unwrap()
            .set_default("server.base_url", "https://api.catbird.blue")
            .unwrap()
            .set_default("redis.url", default_redis_url())
            .unwrap()
            .set_default("redis.key_prefix", default_key_prefix())
            .unwrap()
            .set_default("redis.session_ttl_seconds", default_session_ttl())
            .unwrap()
            .set_default("oauth.client_id", "https://api.catbird.blue")
            .unwrap()
            .set_default("oauth.redirect_uri", "https://api.catbird.blue/callback")
            .unwrap()
            .build()
            .unwrap();
        config.try_deserialize().unwrap()
    }
}

/// Concrete Jacquard OAuth client type used throughout nest.
pub type JacquardOAuthClient = jacquard_oauth::client::OAuthClient<
    jacquard_identity::JacquardResolver<crate::services::HardenedHttpClient>,
    crate::services::RedisAuthStore,
>;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub http_client: reqwest::Client,
    pub raw_http_client: reqwest::Client,
    pub redis: redis::aio::ConnectionManager,
    pub push_db: Option<Pool<Postgres>>,
    pub key_store: Option<Arc<crate::services::KeyStore>>,
    pub jacquard_client: Option<Arc<JacquardOAuthClient>>,
    /// Jacquard OAuth client for catmos-web
    pub catmos_jacquard_client: Option<Arc<JacquardOAuthClient>>,
    /// Scopes configured for catmos-web OAuth client
    pub catmos_oauth_scopes: Vec<jacquard_oauth::scopes::Scope>,
    /// Trusted reverse proxy CIDRs (empty = none trusted; forwarding headers ignored)
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Redis-backed auth store for Jacquard sessions
    pub auth_store: Option<Arc<crate::services::RedisAuthStore>>,
    /// Push subsystem managers (only present when push is configured)
    pub push: Option<Arc<crate::services::push::PushServices>>,
    /// Process-wide per-origin DPoP nonce cache
    pub dpop_nonce_cache: Arc<crate::services::DpopNonceCache>,
    /// AES-256-GCM encryption key for Redis session records
    pub session_encryption_key: Option<[u8; 32]>,
    /// Concurrency semaphore for active outbound proxy streams
    pub active_stream_semaphore: Arc<tokio::sync::Semaphore>,
    /// Rate limit state for session, IP, and byte rate limiting
    pub rate_limit: Arc<crate::middleware::RateLimitState>,
    /// Session index readiness signal for background workers
    pub session_index_ready: Arc<std::sync::atomic::AtomicBool>,
    pub session_index_readiness: Arc<tokio::sync::Notify>,
}

fn validate_configured_oauth_scopes(scopes: &[String]) -> Result<(), anyhow::Error> {
    use jacquard_oauth::scopes::Scope;

    for scope in scopes {
        Scope::<smol_str::SmolStr>::parse(scope).map_err(|error| {
            anyhow::anyhow!("Invalid configured OAuth scope {scope:?}: {error:?}")
        })?;
    }
    Ok(())
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self, anyhow::Error> {
        validate_configured_oauth_scopes(&config.oauth.scopes)?;
        let mut parsed_trusted_proxies = Vec::new();
        for cidr_str in &config.server.trusted_proxies {
            let net: ipnet::IpNet = cidr_str
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid trusted_proxies CIDR '{cidr_str}': {e}"))?;
            parsed_trusted_proxies.push(net);
        }
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

        let http_client = crate::services::build_hardened_http_client()
            .map_err(|e| anyhow::anyhow!("Failed to build hardened HTTP client: {e}"))?;
        let raw_http_client = crate::services::build_hardened_raw_http_client()
            .map_err(|e| anyhow::anyhow!("Failed to build hardened raw HTTP client: {e}"))?;
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

        // Parse CATMOS_OAUTH_SCOPES (defaulting to "atproto transition:generic")
        let catmos_scope_str = std::env::var("CATMOS_OAUTH_SCOPES")
            .unwrap_or_else(|_| "atproto transition:generic".to_string());
        let trimmed_catmos = catmos_scope_str.trim();
        if trimmed_catmos.is_empty() {
            anyhow::bail!("CATMOS_OAUTH_SCOPES cannot be empty");
        }
        let catmos_oauth_scopes: Vec<jacquard_oauth::scopes::Scope> = trimmed_catmos
            .split_whitespace()
            .map(|s| {
                jacquard_oauth::scopes::Scope::parse(s)
                    .map(|sc: jacquard_oauth::scopes::Scope<smol_str::SmolStr>| sc.into_static())
                    .map_err(|e| anyhow::anyhow!("Invalid catmos OAuth scope '{s}': {e:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if catmos_oauth_scopes.is_empty() {
            anyhow::bail!("CATMOS_OAUTH_SCOPES cannot be empty");
        }
        if !catmos_oauth_scopes.iter().any(|s| {
            matches!(s, jacquard_oauth::scopes::Scope::Atproto)
                || s.to_string_normalized() == "atproto"
        }) {
            anyhow::bail!("CATMOS_OAUTH_SCOPES must contain mandatory 'atproto' scope");
        }

        let rate_limit = Arc::new(crate::middleware::RateLimitState::with_trusted_proxies(
            parsed_trusted_proxies.clone(),
        ));
        rate_limit.clone().start_cleanup_task();

        let mut state = Self {
            config: Arc::new(config),
            http_client,
            raw_http_client,
            redis,
            push_db,
            key_store: None,
            jacquard_client: None,
            catmos_jacquard_client: None,
            catmos_oauth_scopes,
            trusted_proxies: parsed_trusted_proxies,
            auth_store: None,
            push: None,
            dpop_nonce_cache: Arc::new(crate::services::DpopNonceCache::new()),
            session_encryption_key,
            active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            rate_limit,
            session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            session_index_readiness: Arc::new(tokio::sync::Notify::new()),
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
        if let Some(ref key_store) = state.key_store {
            match Self::init_jacquard(&state, key_store).await {
                Ok((store, client)) => {
                    state.auth_store = Some(Arc::new(store));
                    state.jacquard_client = Some(Arc::new(client));
                    tracing::info!("Jacquard OAuthClient and RedisAuthStore initialized");
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to initialize Jacquard OAuthClient: {e}"
                    ));
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
                    &state.catmos_oauth_scopes,
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
    /// Returns the active `PushRegistry` if push services or `push_db` is available,
    /// ensuring `phase2_writers` is configured from `config.push.phase2_writers`.
    pub fn push_registry(&self) -> Option<crate::services::push::registry::PushRegistry> {
        if let Some(push) = &self.push {
            return Some(push.registry.clone());
        }
        self.push_db.as_ref().map(|db| {
            crate::services::push::registry::PushRegistry::with_config(
                db.clone(),
                &self.config.push,
            )
        })
    }

    pub fn is_session_index_ready(&self) -> bool {
        self.session_index_ready
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub async fn wait_for_session_index_readiness(&self) {
        if self.is_session_index_ready() {
            return;
        }
        while !self.is_session_index_ready() {
            let notified = self.session_index_readiness.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_session_index_ready() {
                break;
            }
            notified.await;
        }
    }

    /// Reconcile pre-existing sessions at startup before background workers consume.
    /// Always releases session index readiness on completion or failure so workers are never parked forever.
    pub async fn reconcile_session_indexes(
        &self,
    ) -> Result<crate::services::ReconciliationOutcome, anyhow::Error> {
        let Some(auth_store) = self.auth_store.as_ref() else {
            self.session_index_ready
                .store(true, std::sync::atomic::Ordering::Release);
            self.session_index_readiness.notify_waiters();
            return Ok(crate::services::ReconciliationOutcome {
                reconciled: 0,
                skipped: 0,
                failed: 0,
                total_scanned: 0,
                is_complete: true,
            });
        };

        let mut attempts = 0usize;
        let max_attempts = 3usize;
        let mut last_error = None;

        while attempts < max_attempts {
            attempts += 1;
            match auth_store.reconcile_legacy_sessions().await {
                Ok(outcome) => {
                    self.session_index_ready
                        .store(true, std::sync::atomic::Ordering::Release);
                    self.session_index_readiness.notify_waiters();
                    tracing::info!(
                        reconciled = outcome.reconciled,
                        attempts = attempts,
                        is_complete = outcome.is_complete,
                        "Session index reconciliation complete; background workers unblocked"
                    );
                    return Ok(outcome);
                }
                Err(err) => {
                    tracing::warn!(
                        attempt = attempts,
                        error = %err,
                        "Session index reconciliation attempt failed"
                    );
                    last_error = Some(err);
                    if attempts < max_attempts {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            50 * (1 << (attempts - 1)),
                        ))
                        .await;
                    }
                }
            }
        }

        // Reconciliation failed after retries: always release readiness so background workers are never parked forever.
        // The background resolver has fail-closed and self-healing mechanisms for individual session lookups.
        self.session_index_ready
            .store(true, std::sync::atomic::Ordering::Release);
        self.session_index_readiness.notify_waiters();

        let final_err = last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string());
        tracing::error!(
            error = %final_err,
            "Session index reconciliation failed after max retries; background workers unblocked (resolver fails safe)"
        );
        Err(anyhow::anyhow!(
            "Session index reconciliation failed: {final_err}"
        ))
    }

    /// Build the Jacquard RedisAuthStore and OAuthClient from current state.
    async fn init_jacquard(
        state: &AppState,
        key_store: &crate::services::KeyStore,
    ) -> Result<(crate::services::RedisAuthStore, JacquardOAuthClient), anyhow::Error> {
        use jacquard_oauth::atproto::AtprotoClientMetadata;
        use jacquard_oauth::scopes::{Scope, Scopes};
        use jacquard_oauth::session::ClientData;
        let store = crate::services::RedisAuthStore::new(
            state.redis.clone(),
            state.config.redis.key_prefix.clone(),
            state.config.redis.session_ttl_seconds,
            state.session_encryption_key,
        )
        .map_err(|e| anyhow::anyhow!("Failed to initialize RedisAuthStore: {e}"))?;

        let keyset = key_store.to_jacquard_keyset()?;
        // Build AtprotoClientMetadata for confidential client
        let client_id =
            jacquard_common::deps::fluent_uri::Uri::parse(state.config.oauth.client_id.as_str())
                .map_err(|e| anyhow::anyhow!("Invalid client_id URI: {e:?}"))?
                .to_owned();
        let redirect_uri =
            jacquard_common::deps::fluent_uri::Uri::parse(state.config.oauth.redirect_uri.as_str())
                .map_err(|e| anyhow::anyhow!("Invalid redirect_uri: {e:?}"))?
                .to_owned();
        let jwks_uri = jacquard_common::deps::fluent_uri::Uri::parse(
            format!(
                "{}/.well-known/jwks.json",
                state.config.server.base_url.trim_end_matches('/')
            )
            .as_str(),
        )
        .map_err(|e| anyhow::anyhow!("Invalid jwks_uri: {e:?}"))?
        .to_owned();

        let scopes: Vec<Scope> = state
            .config
            .oauth
            .max_scopes
            .iter()
            .map(|s| {
                Scope::parse(s)
                    .map(|sc: Scope<smol_str::SmolStr>| sc.into_static())
                    .map_err(|e| anyhow::anyhow!("Invalid OAuth max_scope '{s}': {e:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let scopes = Scopes::from_scopes(scopes.into_iter().map(|s| s.convert()))
            .map_err(|e| anyhow::anyhow!("Invalid scopes: {e:?}"))?;
        let metadata = AtprotoClientMetadata::new(vec![redirect_uri], client_id, Some(scopes))
            .with_jwks_uri(jwks_uri);

        let client_data = ClientData::new(Some(keyset), metadata);
        let resolver = Self::build_resolver();
        let client = JacquardOAuthClient::new_from_resolver(store.clone(), resolver, client_data);

        Ok((store, client))
    }

    /// Build a client whose PAR requests exactly `scopes`, reusing an existing
    /// `RedisAuthStore` so a later callback resolves through any client backed by
    /// the same store.
    fn build_jacquard_client(
        state: &AppState,
        key_store: &crate::services::KeyStore,
        existing_store: &crate::services::RedisAuthStore,
        client_id_str: &str,
        redirect_uri_str: &str,
        scopes: &[jacquard_oauth::scopes::Scope],
    ) -> Result<JacquardOAuthClient, anyhow::Error> {
        use jacquard_oauth::atproto::AtprotoClientMetadata;
        use jacquard_oauth::scopes::Scopes;
        use jacquard_oauth::session::ClientData;

        let keyset = key_store.to_jacquard_keyset()?;

        let client_id = jacquard_common::deps::fluent_uri::Uri::parse(client_id_str)
            .map_err(|e| anyhow::anyhow!("Invalid client_id URI: {e:?}"))?
            .to_owned();
        let redirect_uri = jacquard_common::deps::fluent_uri::Uri::parse(redirect_uri_str)
            .map_err(|e| anyhow::anyhow!("Invalid redirect_uri: {e:?}"))?
            .to_owned();
        let jwks_uri = jacquard_common::deps::fluent_uri::Uri::parse(
            format!(
                "{}/.well-known/jwks.json",
                state.config.server.base_url.trim_end_matches('/')
            )
            .as_str(),
        )
        .map_err(|e| anyhow::anyhow!("Invalid jwks_uri: {e:?}"))?
        .to_owned();

        if scopes.is_empty() {
            return Err(anyhow::anyhow!(
                "Refusing to build an OAuth client with an empty scope set"
            ));
        }
        let scopes = Scopes::from_scopes(scopes.iter().cloned().map(|s| s.convert()))
            .map_err(|e| anyhow::anyhow!("Invalid scopes: {e:?}"))?;
        let metadata = AtprotoClientMetadata::new(vec![redirect_uri], client_id, Some(scopes))
            .with_jwks_uri(jwks_uri);

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
    fn build_resolver() -> jacquard_identity::JacquardResolver<crate::services::HardenedHttpClient>
    {
        let resolver_client = crate::services::build_hardened_http_client()
            .expect("Failed to build hardened HTTP client for identity resolver");
        let hardened_client = crate::services::HardenedHttpClient::new(resolver_client);
        let resolver = jacquard_identity::JacquardResolver::new(
            hardened_client,
            jacquard_identity::resolver::ResolverOptions::default(),
        );
        resolver.with_system_dns()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_scopes_differ_from_max_scopes() {
        let initial = default_initial_scopes();
        let max = default_max_scopes();
        assert_ne!(
            initial, max,
            "initial scopes and maximum scopes must differ"
        );
        assert!(
            max.len() > initial.len(),
            "maximum scopes must be a superset of initial scopes"
        );
    }

    #[test]
    fn optional_scopes_not_in_initial_scopes() {
        let initial = default_initial_scopes();
        assert!(!initial.contains(&"identity:handle".to_string()));
        assert!(!initial.contains(&"account:email?action=manage".to_string()));
        assert!(!initial.contains(&"account:status?action=manage".to_string()));
    }

    #[test]
    fn chat_poll_disabled_by_default_security_gate() {
        let push_config = PushConfig::default();
        assert!(
            !push_config.chat_poll_enabled,
            "chat_poll_enabled MUST be false by default until release gate opens"
        );
    }

    #[test]
    fn test_chat_poll_release_gate_environment_override() {
        let mut push_config = PushConfig::default();
        assert!(!push_config.is_chat_poll_release_gate_open());

        push_config.chat_poll_enabled = true;
        // Without env var, gate is still closed
        std::env::remove_var("NEST_CHAT_POLL_RELEASE_GATE");
        std::env::remove_var("CATBIRD_CHAT_POLL_RELEASE_GATE");
        assert!(!push_config.is_chat_poll_release_gate_open());

        // With env var open, gate is open
        std::env::set_var("NEST_CHAT_POLL_RELEASE_GATE", "open");
        assert!(push_config.is_chat_poll_release_gate_open());
        std::env::remove_var("NEST_CHAT_POLL_RELEASE_GATE");

        std::env::set_var("CATBIRD_CHAT_POLL_RELEASE_GATE", "open");
        assert!(push_config.is_chat_poll_release_gate_open());
        std::env::remove_var("CATBIRD_CHAT_POLL_RELEASE_GATE");
    }

    #[test]
    fn default_initial_and_max_scopes_contain_expected_permissions() {
        let initial = default_initial_scopes();
        assert_eq!(
            initial,
            vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
                "transition:chat.bsky".to_string(),
            ],
            "initial scopes changed; verify against parity foundation contract"
        );

        let max = default_max_scopes();
        assert!(max.contains(&"identity:handle".to_string()));
        assert!(max.contains(&"account:email?action=manage".to_string()));
        assert!(max.contains(&"account:status?action=manage".to_string()));
    }

    #[test]
    fn invalid_scope_fails_validation() {
        let bad_scopes = vec!["invalid_scope_format:::".to_string()];
        let res = OAuthConfig::parse_and_validate_scopes(&bad_scopes);
        assert!(res.is_err(), "malformed scope must fail validation");
    }

    #[test]
    fn normalized_scope_helpers_work() {
        let config = OAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: default_initial_scopes(),
            max_scopes: default_max_scopes(),
            scopes: default_max_scopes(),
        };
        assert_eq!(
            OAuthConfig::parse_and_normalize_scopes(&config.initial_scopes).unwrap(),
            vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
                "transition:chat.bsky".to_string(),
            ]
        );
        assert_eq!(
            config.normalized_max_scopes().unwrap(),
            vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
                "transition:chat.bsky".to_string(),
                "identity:handle".to_string(),
                "account:email?action=manage".to_string(),
                "account:status?action=manage".to_string(),
            ]
        );

        assert!(config.is_scope_allowed("identity:handle").unwrap());
        assert!(config.is_scope_allowed("atproto").unwrap());
        assert!(!config
            .is_scope_allowed("account:repo?action=manage")
            .unwrap());
    }

    #[test]
    fn legacy_only_scopes_does_not_inherit_optional_max_scopes() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: None,
            max_scopes: None,
            scopes: Some(vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
            ]),
        };
        let config = OAuthConfig::try_from(raw).expect("valid scopes must succeed");
        assert_eq!(
            config.initial_scopes,
            vec!["atproto".to_string(), "transition:generic".to_string()]
        );
        assert_eq!(
            config.max_scopes,
            vec!["atproto".to_string(), "transition:generic".to_string()],
            "legacy-only deployment must not inherit optional account/identity scopes"
        );
        assert_eq!(config.scopes, config.max_scopes);
    }

    #[test]
    fn initial_scopes_authoritative_over_legacy_scopes() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: Some(vec!["atproto".to_string()]),
            max_scopes: None,
            scopes: Some(vec!["transition:generic".to_string()]),
        };
        let config = OAuthConfig::try_from(raw).expect("valid scopes must succeed");
        assert_eq!(config.initial_scopes, vec!["atproto".to_string()]);
        assert_eq!(
            config.max_scopes,
            vec![
                "atproto".to_string(),
                "identity:handle".to_string(),
                "account:email?action=manage".to_string(),
                "account:status?action=manage".to_string(),
            ]
        );
        assert_eq!(config.scopes, config.max_scopes);
    }

    #[test]
    fn configured_max_scopes_derived_as_union_without_overwriting() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: Some(vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
            ]),
            max_scopes: Some(vec!["identity:handle".to_string()]),
            scopes: None,
        };
        let config = OAuthConfig::try_from(raw).expect("valid scopes must succeed");
        assert_eq!(
            config.initial_scopes,
            vec!["atproto".to_string(), "transition:generic".to_string()]
        );
        assert_eq!(
            config.max_scopes,
            vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
                "identity:handle".to_string()
            ]
        );
        assert_eq!(config.scopes, config.max_scopes);
    }

    #[test]
    fn legacy_scopes_with_configured_max_scopes() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: None,
            max_scopes: Some(vec!["identity:handle".to_string()]),
            scopes: Some(vec!["atproto".to_string()]),
        };
        let config = OAuthConfig::try_from(raw).expect("valid scopes must succeed");
        assert_eq!(config.initial_scopes, vec!["atproto".to_string()]);
        assert_eq!(
            config.max_scopes,
            vec!["atproto".to_string(), "identity:handle".to_string()]
        );
    }

    #[test]
    fn default_configuration_derives_initial_and_max() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: None,
            max_scopes: None,
            scopes: None,
        };
        let config = OAuthConfig::try_from(raw).expect("valid defaults must succeed");
        assert_eq!(config.initial_scopes, default_initial_scopes());
        assert_eq!(config.max_scopes, default_max_scopes());
        assert_eq!(config.scopes, default_max_scopes());
    }

    #[test]
    fn invalid_initial_scope_fails_try_from() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: Some(vec!["invalid:::scope".to_string()]),
            max_scopes: None,
            scopes: None,
        };
        let res = OAuthConfig::try_from(raw);
        assert!(res.is_err(), "invalid initial_scope must fail");
    }

    #[test]
    fn invalid_max_scope_fails_try_from() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: None,
            max_scopes: Some(vec!["invalid:::scope".to_string()]),
            scopes: None,
        };
        let res = OAuthConfig::try_from(raw);
        assert!(res.is_err(), "invalid max_scope must fail");
    }

    #[test]
    fn invalid_legacy_scope_fails_try_from() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: None,
            max_scopes: None,
            scopes: Some(vec!["invalid:::scope".to_string()]),
        };
        let res = OAuthConfig::try_from(raw);
        assert!(res.is_err(), "invalid legacy scope must fail");
    }

    #[test]
    fn empty_initial_scopes_fails_try_from() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: Some(vec![]),
            max_scopes: None,
            scopes: None,
        };
        let res = OAuthConfig::try_from(raw);
        assert!(res.is_err(), "empty initial_scopes must fail");
    }

    #[test]
    fn empty_legacy_scopes_fails_try_from() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: None,
            max_scopes: None,
            scopes: Some(vec![]),
        };
        let res = OAuthConfig::try_from(raw);
        assert!(res.is_err(), "empty legacy scopes must fail");
    }

    #[test]
    fn empty_legacy_scopes_with_initial_scopes_fails_try_from() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: Some(vec!["atproto".to_string()]),
            max_scopes: None,
            scopes: Some(vec![]),
        };
        let res = OAuthConfig::try_from(raw);
        assert!(
            res.is_err(),
            "empty legacy scopes alongside initial_scopes must fail"
        );
    }

    #[test]
    fn atproto_less_initial_scopes_fails_try_from() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: Some(vec!["transition:generic".to_string()]),
            max_scopes: None,
            scopes: None,
        };
        let res = OAuthConfig::try_from(raw);
        assert!(res.is_err(), "initial_scopes lacking atproto must fail");
    }

    #[test]
    fn atproto_less_legacy_scopes_fails_try_from() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: None,
            max_scopes: None,
            scopes: Some(vec!["transition:generic".to_string()]),
        };
        let res = OAuthConfig::try_from(raw);
        assert!(res.is_err(), "legacy scopes lacking atproto must fail");
    }

    #[test]
    fn empty_max_scopes_succeeds_and_contains_atproto() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: Some(vec!["atproto".to_string()]),
            max_scopes: Some(vec![]),
            scopes: None,
        };
        let config =
            OAuthConfig::try_from(raw).expect("empty max_scopes with valid initial must succeed");
        assert_eq!(config.initial_scopes, vec!["atproto".to_string()]);
        assert_eq!(config.max_scopes, vec!["atproto".to_string()]);
        assert!(config.max_scopes.contains(&"atproto".to_string()));
    }

    #[test]
    fn atproto_less_max_scopes_succeeds_and_derived_max_contains_atproto() {
        let raw = RawOAuthConfig {
            client_id: "https://example.com".to_string(),
            private_key_path: None,
            private_key_base64: None,
            private_key_paths: vec![],
            active_key_id: "key-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            initial_scopes: Some(vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
            ]),
            max_scopes: Some(vec!["identity:handle".to_string()]),
            scopes: None,
        };
        let config = OAuthConfig::try_from(raw)
            .expect("atproto-less configured max_scopes must succeed via derivation");
        assert_eq!(
            config.initial_scopes,
            vec!["atproto".to_string(), "transition:generic".to_string()]
        );
        assert_eq!(
            config.max_scopes,
            vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
                "identity:handle".to_string(),
            ]
        );
        assert!(config.max_scopes.contains(&"atproto".to_string()));
        assert!(config
            .normalized_max_scopes()
            .unwrap()
            .contains(&"atproto".to_string()));
    }

    #[test]
    fn test_catmos_scopes_defaults_and_explicit_subsets() {
        use jacquard_oauth::scopes::Scope;

        // Default Catmos scopes
        let default_scope_str = "atproto transition:generic";
        let parsed_default: Vec<Scope> = default_scope_str
            .split_whitespace()
            .map(|s| Scope::<smol_str::SmolStr>::parse(s).unwrap().into_static())
            .collect();
        assert_eq!(parsed_default.len(), 2);
        assert_eq!(
            parsed_default
                .iter()
                .map(|s| s.to_string_normalized())
                .collect::<Vec<_>>(),
            vec!["atproto", "transition:generic"]
        );

        // Default initial scopes for iOS / primary client
        let default_initial = default_initial_scopes();
        assert_eq!(
            default_initial,
            vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
                "transition:chat.bsky".to_string(),
            ]
        );

        // Catmos default is a strict subset of default initial scopes
        for scope in &parsed_default {
            assert!(default_initial.contains(&scope.to_string_normalized().to_string()));
        }
        assert!(!parsed_default
            .iter()
            .any(|s| s.to_string_normalized() == "transition:chat.bsky"));
    }
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        vars: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvGuard {
        fn set(vars: &[(&'static str, &str)]) -> Self {
            let lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            let mut saved = Vec::with_capacity(vars.len());
            for &(k, v) in vars {
                saved.push((k, std::env::var_os(k)));
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::set_var(k, v);
                }
            }
            Self {
                _lock: lock,
                vars: saved,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, orig) in &self.vars {
                #[allow(unused_unsafe)]
                unsafe {
                    match orig {
                        Some(val) => std::env::set_var(k, val),
                        None => std::env::remove_var(k),
                    }
                }
            }
        }
    }

    fn base_test_config_builder() -> config::ConfigBuilder<config::builder::DefaultState> {
        config::Config::builder()
            .set_default("server.host", default_host())
            .unwrap()
            .set_default("server.port", default_port())
            .unwrap()
            .set_default("server.base_url", "https://api.catbird.blue")
            .unwrap()
            .set_default("redis.url", default_redis_url())
            .unwrap()
            .set_default("redis.key_prefix", default_key_prefix())
            .unwrap()
            .set_default("redis.session_ttl_seconds", default_session_ttl())
            .unwrap()
            .set_default("oauth.client_id", "https://api.catbird.blue")
            .unwrap()
            .set_default("oauth.redirect_uri", "https://api.catbird.blue/callback")
            .unwrap()
    }

    #[test]
    fn test_redis_v2_key_prefix_default() {
        let default_config = base_test_config_builder().build().unwrap();
        let app_config: AppConfig = default_config.try_deserialize().unwrap();
        assert_eq!(
            app_config.redis.key_prefix, "catbird:v2:session:",
            "default key_prefix must use explicit v2 session namespace"
        );
        assert!(
            crate::services::RedisAuthStore::validate_key_prefix(&app_config.redis.key_prefix)
                .is_ok()
        );
    }

    #[test]
    fn test_redis_config_custom_tenant_v2_prefix() {
        let custom_config = base_test_config_builder()
            .set_default("redis.key_prefix", "tenant_a:v2:session:")
            .unwrap()
            .set_default("redis.session_ttl_seconds", 3600)
            .unwrap()
            .build()
            .unwrap();

        let app_config: AppConfig = custom_config.try_deserialize().unwrap();
        assert_eq!(app_config.redis.key_prefix, "tenant_a:v2:session:");
        assert_eq!(app_config.redis.session_ttl_seconds, 3600);
        assert!(
            crate::services::RedisAuthStore::validate_key_prefix(&app_config.redis.key_prefix)
                .is_ok()
        );
    }

    #[test]
    fn test_redact_redis_url() {
        assert_eq!(
            redact_redis_url("redis://127.0.0.1:6379"),
            "redis://127.0.0.1:6379"
        );
        assert_eq!(
            redact_redis_url("redis://default:secretpass@127.0.0.1:6379/2?foo=bar#frag"),
            "redis://127.0.0.1:6379/2"
        );
        assert_eq!(
            redact_redis_url("rediss://user:token@prod.redis.cache.amazonaws.com:6380/0"),
            "rediss://prod.redis.cache.amazonaws.com:6380/0"
        );
        assert_eq!(
            redact_redis_url("redis://:onlypass@localhost:6379"),
            "redis://localhost:6379"
        );
        assert_eq!(
            redact_redis_url("redis://default:secretpass@127.0.0.1:6379/0/SENTINEL_TOKEN?token=SENTINEL_QUERY#SENTINEL_FRAG"),
            "redis://127.0.0.1:6379"
        );
        assert_eq!(
            redact_redis_url("redis://:pass@localhost:6379/notanumber/SENTINEL"),
            "redis://localhost:6379"
        );
        assert_eq!(redact_redis_url("not a url"), "<invalid-redis-url>");
    }

    #[test]
    fn test_redis_key_prefix_rejects_legacy_and_unversioned() {
        // Legacy prefix
        let legacy_config = base_test_config_builder()
            .set_default("redis.key_prefix", "catbird:session:")
            .unwrap()
            .build()
            .unwrap();
        let legacy_app_config: AppConfig = legacy_config.try_deserialize().unwrap();
        let legacy_err = crate::services::RedisAuthStore::validate_key_prefix(
            &legacy_app_config.redis.key_prefix,
        )
        .unwrap_err();
        assert!(format!("{legacy_err}").contains("must contain explicit ':v2:' segment"));

        // Unversioned prefix
        let unversioned_config = base_test_config_builder()
            .set_default("redis.key_prefix", "session:")
            .unwrap()
            .build()
            .unwrap();
        let unversioned_app_config: AppConfig = unversioned_config.try_deserialize().unwrap();
        let unversioned_err = crate::services::RedisAuthStore::validate_key_prefix(
            &unversioned_app_config.redis.key_prefix,
        )
        .unwrap_err();
        assert!(format!("{unversioned_err}").contains("must contain explicit ':v2:' segment"));

        // v1 prefix
        let v1_config = base_test_config_builder()
            .set_default("redis.key_prefix", "catbird:v1:session:")
            .unwrap()
            .build()
            .unwrap();
        let v1_app_config: AppConfig = v1_config.try_deserialize().unwrap();
        let v1_err =
            crate::services::RedisAuthStore::validate_key_prefix(&v1_app_config.redis.key_prefix)
                .unwrap_err();
        assert!(format!("{v1_err}").contains("must contain explicit ':v2:' segment"));
    }

    #[test]
    fn test_catbird_oauth_scopes_env_list_parsing() {
        // Test environment parsing of comma-separated list keys
        let _guard = EnvGuard::set(&[
            ("TEST_CATBIRD__SERVER__HOST", "127.0.0.1"),
            ("TEST_CATBIRD__SERVER__PORT", "3000"),
            ("TEST_CATBIRD__SERVER__BASE_URL", "https://api.catbird.blue"),
            ("TEST_CATBIRD__OAUTH__CLIENT_ID", "https://api.catbird.blue"),
            (
                "TEST_CATBIRD__OAUTH__REDIRECT_URI",
                "https://api.catbird.blue/callback",
            ),
            (
                "TEST_CATBIRD__OAUTH__INITIAL_SCOPES",
                "atproto,transition:generic",
            ),
            (
                "TEST_CATBIRD__OAUTH__MAX_SCOPES",
                "atproto,transition:generic,identity:handle",
            ),
        ]);

        let config = base_test_config_builder()
            .add_source(
                config::Environment::with_prefix("TEST_CATBIRD")
                    .separator("__")
                    .with_list_parse_key("oauth.scopes")
                    .with_list_parse_key("oauth.initial_scopes")
                    .with_list_parse_key("oauth.max_scopes")
                    .list_separator(",")
                    .try_parsing(true),
            )
            .build()
            .unwrap();

        let app_config: AppConfig = config.try_deserialize().unwrap();
        assert_eq!(
            app_config.oauth.initial_scopes,
            vec!["atproto".to_string(), "transition:generic".to_string()]
        );
        assert_eq!(
            app_config.oauth.max_scopes,
            vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
                "identity:handle".to_string()
            ]
        );
    }

    #[test]
    fn test_catmos_oauth_scopes_validation_logic() {
        use jacquard_oauth::scopes::Scope;

        // Helper simulating the validation in AppState::new
        fn validate_catmos_scopes(scope_str: &str) -> Result<Vec<Scope>, String> {
            let trimmed = scope_str.trim();
            if trimmed.is_empty() {
                return Err("CATMOS_OAUTH_SCOPES cannot be empty".to_string());
            }
            let scopes: Vec<Scope> = trimmed
                .split_whitespace()
                .map(|s| {
                    Scope::parse(s)
                        .map(|sc: Scope<smol_str::SmolStr>| sc.into_static())
                        .map_err(|e| format!("Invalid scope '{s}': {e:?}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if scopes.is_empty() {
                return Err("CATMOS_OAUTH_SCOPES cannot be empty".to_string());
            }
            if !scopes
                .iter()
                .any(|s| matches!(s, Scope::Atproto) || s.to_string_normalized() == "atproto")
            {
                return Err(
                    "CATMOS_OAUTH_SCOPES must contain mandatory 'atproto' scope".to_string()
                );
            }
            Ok(scopes)
        }

        // Empty / whitespace fails
        assert!(validate_catmos_scopes("").is_err());
        assert!(validate_catmos_scopes("   ").is_err());

        // Missing atproto fails
        assert!(validate_catmos_scopes("transition:generic identity:handle").is_err());

        // Valid containing atproto succeeds
        let valid = validate_catmos_scopes("atproto transition:generic").unwrap();
        assert_eq!(valid.len(), 2);

        let custom = validate_catmos_scopes("atproto transition:generic identity:handle").unwrap();
        assert_eq!(custom.len(), 3);
    }

    #[tokio::test]
    async fn test_reconcile_session_indexes_releases_readiness_on_failure() {
        let session_index_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let session_index_readiness = Arc::new(tokio::sync::Notify::new());

        assert!(!session_index_ready.load(std::sync::atomic::Ordering::Acquire));

        // Spawn a background waiter using the safe pinned-enable pattern
        let waiter_ready = session_index_ready.clone();
        let waiter_notify = session_index_readiness.clone();
        let waiter = tokio::spawn(async move {
            while !waiter_ready.load(std::sync::atomic::Ordering::Acquire) {
                let notified = waiter_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if waiter_ready.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                notified.await;
            }
            true
        });

        // Simulate reconciliation failure and ensure readiness is unconditionally set
        session_index_ready.store(true, std::sync::atomic::Ordering::Release);
        session_index_readiness.notify_waiters();

        let result = tokio::time::timeout(std::time::Duration::from_millis(500), waiter).await;
        assert!(
            result.is_ok(),
            "Waiter must not be parked when reconciliation completes or fails"
        );
        assert!(
            result.unwrap().unwrap(),
            "Waiter must observe readiness as true"
        );
        assert!(session_index_ready.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn test_wait_for_session_index_readiness_no_lost_wakeup() {
        let session_index_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let session_index_readiness = Arc::new(tokio::sync::Notify::new());

        let mut handles = Vec::new();
        for _ in 0..20 {
            let ready = session_index_ready.clone();
            let notify = session_index_readiness.clone();
            handles.push(tokio::spawn(async move {
                while !ready.load(std::sync::atomic::Ordering::Acquire) {
                    let notified = notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if ready.load(std::sync::atomic::Ordering::Acquire) {
                        break;
                    }
                    notified.await;
                }
                true
            }));
        }

        tokio::task::yield_now().await;

        session_index_ready.store(true, std::sync::atomic::Ordering::Release);
        session_index_readiness.notify_waiters();

        for handle in handles {
            let res = tokio::time::timeout(std::time::Duration::from_millis(500), handle).await;
            assert!(res.is_ok(), "Waiter must not be parked due to lost wakeup");
            assert!(res.unwrap().unwrap(), "Waiter must observe readiness");
        }
    }
}
