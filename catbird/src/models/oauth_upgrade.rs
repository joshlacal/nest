//! Progressive OAuth upgrade wire DTOs and types
//!
//! Defines request/response models and status enums for the progressive OAuth
//! scope upgrade flow (`/auth/upgrade`, `/auth/upgrade/exchange`, `/auth/upgrade/commit`).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum number of additional scopes allowed in a single upgrade request
pub const MAX_ADDITIONAL_SCOPES: usize = 16;

/// Maximum length of an individual scope string
pub const MAX_SCOPE_LEN: usize = 128;

/// Minimum length of browser nonce
pub const MIN_BROWSER_NONCE_LEN: usize = 16;

/// Maximum length of browser nonce
pub const MAX_BROWSER_NONCE_LEN: usize = 256;

/// Maximum length of authorization code
pub const MAX_CODE_LEN: usize = 512;

/// Fixed server-side callback URL for progressive OAuth upgrade flows
pub const FIXED_UPGRADE_CALLBACK_URL: &str = "https://catbird.blue/oauth/permission-callback";

/// Supported allowlisted progressive upgrade scopes per binding contract
pub const ALLOWLISTED_UPGRADE_SCOPES: &[&str] = &[
    "identity:handle",
    "account:email?action=manage",
    "account:status?action=manage",
];

/// Request payload for initiating progressive OAuth upgrade (`POST /auth/upgrade`).
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeStartRequest {
    /// Additional scopes requested for upgrade (must be allowlisted).
    pub additional_scopes: Vec<String>,
    /// Cryptographically random browser challenge nonce.
    pub browser_nonce: String,
}

impl UpgradeStartRequest {
    /// Check whether all requested additional scopes and browser nonce are structurally bounded.
    pub fn is_structurally_valid(&self) -> bool {
        if self.additional_scopes.is_empty() || self.additional_scopes.len() > MAX_ADDITIONAL_SCOPES
        {
            return false;
        }
        if self.browser_nonce.len() < MIN_BROWSER_NONCE_LEN
            || self.browser_nonce.len() > MAX_BROWSER_NONCE_LEN
        {
            return false;
        }
        self.additional_scopes
            .iter()
            .all(|s| !s.is_empty() && s.len() <= MAX_SCOPE_LEN)
    }

    /// Check if all requested additional scopes belong to the allowlisted scope set.
    pub fn has_only_allowlisted_scopes(&self) -> bool {
        self.additional_scopes
            .iter()
            .all(|scope| ALLOWLISTED_UPGRADE_SCOPES.contains(&scope.as_str()))
    }
}

/// Response payload from initiating progressive OAuth upgrade (`POST /auth/upgrade`).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct UpgradeStartResponse {
    /// Authorization URL to open in browser for user consent.
    pub authorization_url: String,
}

/// Request payload for exchanging authorization code for candidate session (`POST /auth/upgrade/exchange`).
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeExchangeRequest {
    /// One-time authorization code returned via browser callback redirect.
    pub code: String,
    /// Browser challenge nonce supplied at upgrade start.
    pub browser_nonce: String,
}

impl UpgradeExchangeRequest {
    /// Check whether code and browser nonce are structurally bounded.
    pub fn is_structurally_valid(&self) -> bool {
        if self.code.is_empty() || self.code.len() > MAX_CODE_LEN {
            return false;
        }
        if self.browser_nonce.len() < MIN_BROWSER_NONCE_LEN
            || self.browser_nonce.len() > MAX_BROWSER_NONCE_LEN
        {
            return false;
        }
        true
    }
}

/// Response payload for upgrade exchange (`POST /auth/upgrade/exchange`).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct UpgradeExchangeResponse {
    /// Candidate session UUID (inactive until commit).
    pub candidate_session_id: Uuid,
    /// Decentralized identifier of the upgrading account.
    pub did: String,
    /// Authoritative granted scopes returned by PDS/OAuth server.
    pub granted_scopes: Vec<String>,
}

/// Fixed status enum for upgrade commit operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpgradeCommitStatus {
    Committed,
}

impl std::fmt::Display for UpgradeCommitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Committed => write!(f, "committed"),
        }
    }
}

/// Response payload for upgrade commit (`POST /auth/upgrade/commit`).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct UpgradeCommitResponse {
    /// Fixed commit status (`committed`).
    pub status: UpgradeCommitStatus,
    /// Active session UUID (promoted from candidate session).
    pub session_id: Uuid,
    /// Decentralized identifier of the upgraded account.
    pub did: String,
    /// Authoritative granted scopes for the active session.
    pub granted_scopes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_start_request_serde_and_validation() {
        let json_str = r#"{
            "additional_scopes": ["identity:handle"],
            "browser_nonce": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
        }"#;

        let req: UpgradeStartRequest =
            serde_json::from_str(json_str).expect("deserialize valid request");
        assert_eq!(req.additional_scopes, vec!["identity:handle"]);
        assert!(req.is_structurally_valid());
        assert!(req.has_only_allowlisted_scopes());

        // Unknown fields rejected
        let invalid_json = r#"{
            "additional_scopes": ["identity:handle"],
            "browser_nonce": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
            "extra_field": "disallowed"
        }"#;
        assert!(serde_json::from_str::<UpgradeStartRequest>(invalid_json).is_err());
    }

    #[test]
    fn upgrade_start_request_non_allowlisted_scope() {
        let req = UpgradeStartRequest {
            additional_scopes: vec!["admin:all".to_string()],
            browser_nonce: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF".to_string(),
        };
        assert!(req.is_structurally_valid());
        assert!(!req.has_only_allowlisted_scopes());
    }

    #[test]
    fn upgrade_start_response_serde() {
        let resp = UpgradeStartResponse {
            authorization_url: "https://pds.example.com/oauth/authorize?par=123".to_string(),
        };
        let json_val = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(
            json_val["authorization_url"],
            "https://pds.example.com/oauth/authorize?par=123"
        );
    }

    #[test]
    fn upgrade_exchange_request_serde() {
        let json_str = r#"{
            "code": "auth_code_12345",
            "browser_nonce": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
        }"#;
        let req: UpgradeExchangeRequest =
            serde_json::from_str(json_str).expect("deserialize exchange request");
        assert_eq!(req.code, "auth_code_12345");
        assert!(req.is_structurally_valid());

        // Unknown fields rejected
        let invalid_json = r#"{
            "code": "auth_code_12345",
            "browser_nonce": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
            "did": "did:plc:injected"
        }"#;
        assert!(serde_json::from_str::<UpgradeExchangeRequest>(invalid_json).is_err());
    }

    #[test]
    fn upgrade_exchange_response_serde() {
        let candidate_id = Uuid::new_v4();
        let resp = UpgradeExchangeResponse {
            candidate_session_id: candidate_id,
            did: "did:plc:testuser123".to_string(),
            granted_scopes: vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
                "identity:handle".to_string(),
            ],
        };

        let json_val = serde_json::to_value(&resp).expect("serialize exchange response");
        assert_eq!(json_val["candidate_session_id"], candidate_id.to_string());
        assert_eq!(json_val["did"], "did:plc:testuser123");
        assert_eq!(json_val["granted_scopes"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn upgrade_commit_status_serde() {
        let status = UpgradeCommitStatus::Committed;
        let json_val = serde_json::to_value(status).expect("serialize status");
        assert_eq!(json_val, "committed");
    }

    #[test]
    fn upgrade_commit_response_serde() {
        let session_id = Uuid::new_v4();
        let resp = UpgradeCommitResponse {
            status: UpgradeCommitStatus::Committed,
            session_id,
            did: "did:plc:testuser123".to_string(),
            granted_scopes: vec![
                "atproto".to_string(),
                "transition:generic".to_string(),
                "identity:handle".to_string(),
            ],
        };

        let json_val = serde_json::to_value(&resp).expect("serialize commit response");
        assert_eq!(json_val["status"], "committed");
        assert_eq!(json_val["session_id"], session_id.to_string());
        assert_eq!(json_val["did"], "did:plc:testuser123");
        assert_eq!(json_val["granted_scopes"].as_array().unwrap().len(), 3);
    }
}
