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
    /// OAuth scopes granted to this session
    #[serde(default)]
    pub scopes: Vec<String>,
    /// When the access token expires
    pub access_token_expires_at: DateTime<Utc>,
    /// When this session was created
    pub created_at: DateTime<Utc>,
    /// When this session was last used
    pub last_used_at: DateTime<Utc>,
}

impl CatbirdSession {
    /// Check if the access token is expired or about to expire (within 60 seconds)
    pub fn is_access_token_expired(&self) -> bool {
        let buffer = chrono::Duration::seconds(60);
        Utc::now() + buffer >= self.access_token_expires_at
    }
}

/// Health check response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub redis_connected: bool,
}

/// OAuth callback parameters
#[derive(Debug, Deserialize)]
pub struct OAuthCallback {
    /// Absent when the user cancels or the provider returns an error
    /// (RFC 6749 §4.1.2.1: `error` + optional `error_description` instead).
    pub code: Option<String>,
    pub state: String,
    pub iss: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
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

/// Request body for POST /auth/exchange (ADR-014 confidential gateway exchange)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeRequest {
    pub code: String,
    pub browser_nonce: String,
}

/// Response body for POST /auth/exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeResponse {
    pub session_id: String,
}
