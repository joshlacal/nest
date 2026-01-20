//! Data types for the Catbird Gateway
//!
//! Defines structures for sessions, tokens, and API responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Catbird session stored in Redis
/// Maps a Catbird session ID to ATProto tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatbirdSession {
    /// Unique session identifier
    pub id: Uuid,
    /// User's DID (decentralized identifier)
    pub did: String,
    /// User's handle (e.g., user.bsky.social)
    pub handle: String,
    /// User's PDS URL
    pub pds_url: String,
    /// ATProto access token
    pub access_token: String,
    /// ATProto refresh token
    pub refresh_token: String,
    /// When the access token expires
    pub access_token_expires_at: DateTime<Utc>,
    /// When this session was created
    pub created_at: DateTime<Utc>,
    /// When this session was last used
    pub last_used_at: DateTime<Utc>,
    /// DPoP key thumbprint (for token binding)
    pub dpop_jkt: Option<String>,
}

impl CatbirdSession {
    /// Check if the access token is expired or about to expire (within 60 seconds)
    pub fn is_access_token_expired(&self) -> bool {
        let buffer = chrono::Duration::seconds(60);
        Utc::now() + buffer >= self.access_token_expires_at
    }
}

/// OAuth authorization state stored during the OAuth flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    /// State parameter for CSRF protection
    pub state: String,
    /// PKCE code verifier
    pub code_verifier: String,
    /// The authorization server URL
    pub issuer: String,
    /// When this state was created
    pub created_at: DateTime<Utc>,
    /// DPoP private key (JWK format) for this authorization
    pub dpop_private_key_jwk: String,
}

/// Token response from ATProto OAuth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    /// The DID of the authenticated user
    pub sub: String,
}

/// User info extracted from token/session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub did: String,
    pub handle: String,
    pub pds_url: String,
}

/// Health check response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub redis_connected: bool,
}

/// Login initiation request
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// User's handle or DID
    pub identifier: String,
}

/// Login initiation response (redirect URL)
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// URL to redirect the user to for authorization
    pub authorization_url: String,
}

/// OAuth callback parameters
#[derive(Debug, Deserialize)]
pub struct OAuthCallback {
    pub code: String,
    pub state: String,
    pub iss: Option<String>,
}

/// Session info response (returned to iOS app)
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub did: String,
    pub handle: String,
    pub created_at: DateTime<Utc>,
}

/// Logout response
#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub success: bool,
    pub message: String,
}



/// DPoP key pair for token binding (RFC 9449)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPoPKeyPair {
    /// The public key in JWK format (for JWT header)
    pub public_jwk: serde_json::Value,
    /// The private key bytes (32 bytes for P-256)
    #[serde(with = "base64_bytes")]
    pub private_key_bytes: [u8; 32],
}

/// Serde helper for base64-encoded byte arrays
mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};
    
    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        serializer.serialize_str(&b64.encode(bytes))
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let bytes = b64.decode(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| serde::de::Error::custom("Invalid key length"))
    }
}