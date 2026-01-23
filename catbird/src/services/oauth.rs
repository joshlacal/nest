//! OAuth Service using Atrium
//!
//! This module provides Redis-backed stores for atrium-oauth and initializes
//! the OAuthClient for the Catbird Nest gateway (Production Ready).

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::services::CryptoService;
use atrium_api::types::string::Did;
use atrium_common::store::Store;
use atrium_oauth::store::session::{Session, SessionStore};
use atrium_oauth::store::state::{InternalStateData, StateStore};
use atrium_oauth::{
    AtprotoClientMetadata, AuthMethod, DefaultHttpClient, GrantType, KnownScope, OAuthClient,
    OAuthClientConfig, OAuthResolverConfig, Scope,
};

use atrium_identity::handle::{
    AtprotoHandleResolver, AtprotoHandleResolverConfig, DohDnsTxtResolver, DohDnsTxtResolverConfig,
};
use jose_jwk::Jwk;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use redis::AsyncCommands;

const STATE_TTL_SECONDS: u64 = 600; // 10 minutes for OAuth state
const SESSION_TTL_SECONDS: u64 = 86400 * 30; // 30 days for sessions

// ==============================================================================
// Redis State Store (for OAuth authorization state during login)
// ==============================================================================

#[derive(Clone)]
pub struct RedisStateStore {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
}

impl RedisStateStore {
    pub fn new(redis: redis::aio::ConnectionManager, key_prefix: String) -> Self {
        Self { redis, key_prefix }
    }

    fn key_for(&self, state: &str) -> String {
        format!("{}oauth_state:{}", self.key_prefix, state)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Redis store error: {0}")]
pub struct RedisStoreError(#[from] redis::RedisError);

impl Store<String, InternalStateData> for RedisStateStore {
    type Error = RedisStoreError;

    async fn get(&self, key: &String) -> Result<Option<InternalStateData>, Self::Error> {
        let redis_key = self.key_for(key);
        let mut conn = self.redis.clone();
        let data: Option<String> = conn.get(&redis_key).await?;
        Ok(data.and_then(|s| serde_json::from_str(&s).ok()))
    }

    async fn set(&self, key: String, value: InternalStateData) -> Result<(), Self::Error> {
        let redis_key = self.key_for(&key);
        let json = serde_json::to_string(&value).expect("InternalStateData should serialize");
        let mut conn = self.redis.clone();
        conn.set_ex::<_, _, ()>(&redis_key, json, STATE_TTL_SECONDS)
            .await?;
        Ok(())
    }

    async fn del(&self, key: &String) -> Result<(), Self::Error> {
        let redis_key = self.key_for(key);
        let mut conn = self.redis.clone();
        conn.del::<_, ()>(&redis_key).await?;
        Ok(())
    }

    async fn clear(&self) -> Result<(), Self::Error> {
        // Would require SCAN + DEL, not typically needed
        Ok(())
    }
}

impl StateStore for RedisStateStore {}

// ==============================================================================
// Redis Session Store (for OAuth sessions after login)
// ==============================================================================

#[derive(Clone)]
pub struct RedisSessionStore {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
}

impl RedisSessionStore {
    pub fn new(redis: redis::aio::ConnectionManager, key_prefix: String) -> Self {
        Self { redis, key_prefix }
    }

    fn key_for(&self, did: &Did) -> String {
        format!("{}oauth_session:{}", self.key_prefix, did.as_str())
    }
}

impl Store<Did, Session> for RedisSessionStore {
    type Error = RedisStoreError;

    async fn get(&self, key: &Did) -> Result<Option<Session>, Self::Error> {
        let redis_key = self.key_for(key);
        let mut conn = self.redis.clone();
        let data: Option<String> = conn.get(&redis_key).await?;
        Ok(data.and_then(|s| serde_json::from_str(&s).ok()))
    }

    async fn set(&self, key: Did, value: Session) -> Result<(), Self::Error> {
        let redis_key = self.key_for(&key);
        let json = serde_json::to_string(&value).expect("Session should serialize");
        let mut conn = self.redis.clone();
        conn.set_ex::<_, _, ()>(&redis_key, json, SESSION_TTL_SECONDS)
            .await?;
        Ok(())
    }

    async fn del(&self, key: &Did) -> Result<(), Self::Error> {
        let redis_key = self.key_for(key);
        let mut conn = self.redis.clone();
        conn.del::<_, ()>(&redis_key).await?;
        Ok(())
    }

    async fn clear(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl SessionStore for RedisSessionStore {}

// ==============================================================================
// OAuthClient Type Aliases
// ==============================================================================

/// Production OAuthClient with Redis-backed stores
pub type CatbirdOAuthClient = OAuthClient<
    RedisStateStore,
    RedisSessionStore,
    atrium_identity::did::CommonDidResolver<DefaultHttpClient>,
    AtprotoHandleResolver<DohDnsTxtResolver<DefaultHttpClient>, DefaultHttpClient>,
>;

/// Creates the OAuthClient for Catbird Nest (Production).
///
/// Uses Redis for state and session persistence with private_key_jwt authentication.
pub fn create_oauth_client(state: &AppState) -> AppResult<CatbirdOAuthClient> {
    use atrium_identity::did::{CommonDidResolver, CommonDidResolverConfig};
    use std::sync::Arc;

    // Use atrium's default HTTP client
    let http_client = Arc::new(DefaultHttpClient::default());

    // Set up resolvers
    let did_resolver = CommonDidResolver::new(CommonDidResolverConfig {
        plc_directory_url: "https://plc.directory".into(),
        http_client: Arc::clone(&http_client),
    });

    let dns_txt_resolver = DohDnsTxtResolver::new(DohDnsTxtResolverConfig {
        // Used for _atproto.<handle> TXT lookups; HTTPS well-known remains a fallback.
        service_url: "https://cloudflare-dns.com/dns-query".into(),
        http_client: Arc::clone(&http_client),
    });

    let handle_resolver = AtprotoHandleResolver::new(AtprotoHandleResolverConfig {
        dns_txt_resolver,
        http_client: Arc::clone(&http_client),
    });

    // Convert scope strings to atrium_oauth::Scope
    let scopes: Vec<Scope> = state
        .config
        .oauth
        .scopes
        .iter()
        .map(|s| match s.as_str() {
            "atproto" => Scope::Known(KnownScope::Atproto),
            "transition:generic" => Scope::Known(KnownScope::TransitionGeneric),
            "transition:chat.bsky" => Scope::Known(KnownScope::TransitionChatBsky),
            _ => Scope::Unknown(s.clone()),
        })
        .collect();

    // Load ES256 private key and convert to JWK
    let keys = load_oauth_keys(state)?;
    if keys.is_none() {
        return Err(AppError::Config(
            "OAuth private key not configured".to_string(),
        ));
    }

    // Production client metadata with private_key_jwt
    let client_metadata = AtprotoClientMetadata {
        client_id: state.config.oauth.client_id.clone(),
        client_uri: Some(state.config.server.base_url.clone()),
        redirect_uris: vec![state.config.oauth.redirect_uri.clone()],
        token_endpoint_auth_method: AuthMethod::PrivateKeyJwt,
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        scopes,
        jwks_uri: Some(format!(
            "{}/.well-known/jwks.json",
            state.config.server.base_url
        )),
        token_endpoint_auth_signing_alg: Some("ES256".to_string()),
    };

    let resolver_config = OAuthResolverConfig {
        did_resolver,
        handle_resolver,
        authorization_server_metadata: Default::default(),
        protected_resource_metadata: Default::default(),
    };

    // Redis-backed stores for production
    let state_store =
        RedisStateStore::new(state.redis.clone(), state.config.redis.key_prefix.clone());
    let session_store =
        RedisSessionStore::new(state.redis.clone(), state.config.redis.key_prefix.clone());

    let config = OAuthClientConfig {
        client_metadata,
        keys,
        state_store,
        session_store,
        resolver: resolver_config,
    };

    OAuthClient::new(config)
        .map_err(|e| AppError::OAuth(format!("Failed to create OAuthClient: {}", e)))
}

/// Load ES256 keys from configuration and convert to JWK keyset
fn load_oauth_keys(state: &AppState) -> AppResult<Option<Vec<Jwk>>> {
    // Use KeyStore if available
    if let Some(key_store) = &state.key_store {
        let jwks = key_store
            .all_keys()
            .iter()
            .map(|key| {
                let public_key = key.secret_key.public_key();
                let ec_point = public_key.to_encoded_point(false);

                let x_bytes = ec_point.x().expect("Missing x coordinate");
                let y_bytes = ec_point.y().expect("Missing y coordinate");
                let d_bytes = key.secret_key.to_bytes();

                use base64::Engine;
                let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

                let jwk = serde_json::json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": b64.encode(x_bytes.as_slice()),
                    "y": b64.encode(y_bytes.as_slice()),
                    "d": b64.encode(d_bytes.as_slice()),
                    "alg": "ES256",
                    "use": "sig",
                    "kid": key.kid
                });

                serde_json::from_value(jwk).expect("Failed to create JWK")
            })
            .collect();

        return Ok(Some(jwks));
    }

    // Fallback to legacy single-key loading
    let crypto = CryptoService::new(std::sync::Arc::new(state.clone()));

    // Try to load the private key
    let secret_key = match crypto.load_private_key() {
        Ok(key) => key,
        Err(e) => {
            tracing::warn!(
                "No OAuth private key configured: {}. Using public client mode.",
                e
            );
            return Ok(None);
        }
    };

    // Convert p256 SecretKey to JWK using jose-jwk
    let public_key = secret_key.public_key();
    let ec_point = public_key.to_encoded_point(false);

    let x_bytes = ec_point
        .x()
        .ok_or_else(|| AppError::Crypto("Missing x coordinate".into()))?;
    let y_bytes = ec_point
        .y()
        .ok_or_else(|| AppError::Crypto("Missing y coordinate".into()))?;
    let d_bytes = secret_key.to_bytes();

    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Create the JWK structure
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64.encode(x_bytes.as_slice()),
        "y": b64.encode(y_bytes.as_slice()),
        "d": b64.encode(d_bytes.as_slice()),
        "alg": "ES256",
        "use": "sig",
        "kid": "catbird-key-1"
    });

    let jwk: Jwk = serde_json::from_value(jwk)
        .map_err(|e| AppError::Crypto(format!("Failed to create JWK: {}", e)))?;

    Ok(Some(vec![jwk]))
}
