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
    /// Authoritative granted scopes returned by PDS/OAuth server.
    /// Defaulted for legacy session deserialization, but an empty list
    /// must never be treated as successful authorization evidence.
    #[serde(default)]
    pub granted_scopes: Vec<String>,
}

impl CatbirdSession {
    /// Check if the access token is expired or about to expire (within 60 seconds)
    pub fn is_access_token_expired(&self) -> bool {
        let buffer = chrono::Duration::seconds(60);
        Utc::now() + buffer >= self.access_token_expires_at
    }

    /// Check if this session has been granted a specific scope (normalized)
    pub fn has_granted_scope(&self, scope: &str) -> bool {
        self.granted_scopes.iter().any(|s| s == scope)
    }

    /// Returns whether the session has at least the basic atproto scope
    pub fn has_atproto_scope(&self) -> bool {
        self.has_granted_scope("atproto")
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub did: String,
    pub handle: String,
    pub created_at: DateTime<Utc>,
    /// Authoritative granted scopes for this session.
    /// Defaulted for backwards compatibility during serialization/deserialization,
    /// but authoritative when populated from the session model.
    #[serde(default)]
    pub granted_scopes: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_deserialization_defaults_granted_scopes() {
        let json = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "did": "did:plc:test1234",
            "handle": "test.bsky.social",
            "pds_url": "https://pds.example.com",
            "access_token": "access_token_val",
            "refresh_token": "refresh_token_val",
            "access_token_expires_at": "2026-08-24T12:00:00Z",
            "created_at": "2026-08-24T10:00:00Z",
            "last_used_at": "2026-08-24T11:00:00Z"
        });

        let session: CatbirdSession = serde_json::from_value(json).expect("valid session json");
        assert!(session.granted_scopes.is_empty());
        assert!(!session.has_granted_scope("atproto"));
    }

    #[test]
    fn session_info_serialization_exposes_granted_scopes() {
        let info = SessionInfo {
            did: "did:plc:test1234".to_string(),
            handle: "test.bsky.social".to_string(),
            created_at: Utc::now(),
            granted_scopes: vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
                "identity:handle".to_string(),
            ],
        };

        let value = serde_json::to_value(&info).expect("serialize");
        let scopes = value
            .get("granted_scopes")
            .and_then(|v| v.as_array())
            .expect("granted_scopes array");
        assert_eq!(scopes.len(), 3);
        assert_eq!(scopes[0], "atproto");
        assert_eq!(scopes[2], "identity:handle");
    }
}
