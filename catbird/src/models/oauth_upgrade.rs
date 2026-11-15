//! Progressive OAuth upgrade wire DTOs and types
//!
//! Defines request/response models and status enums for the progressive OAuth
//! scope upgrade flow (`/auth/upgrade`, `/auth/upgrade/exchange`, `/auth/upgrade/commit`).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum number of additional scopes allowed in a single upgrade request
pub const MAX_ADDITIONAL_SCOPES: usize = 16;

/// Maximum length of an individual scope string.
/// 512 accommodates parameterized `space:` scopes (the Labyrinth mailbox scope is ~440 chars).
pub const MAX_SCOPE_LEN: usize = 512;

/// Circle Space scope, in jacquard-normalized form (params sorted, defaults omitted).
/// Grants record read_self/create/update/delete on any collection in
/// `blue.catbird.circle` spaces under any authority, plus space
/// create/update/delete management. Requested just-in-time when the user
/// first creates or writes to a Circle.
pub const CIRCLE_SPACE_SCOPE: &str = "space:blue.catbird.circle?action=create&action=delete&action=read_self&action=update&authority=*&collection=*&manage=create&manage=delete&manage=update";

/// Encrypted Circle Space scope (`blue.catbird.circle.encrypted`), in jacquard-normalized form.
pub const CIRCLE_ENCRYPTED_SPACE_SCOPE: &str = "space:blue.catbird.circle.encrypted?action=create&action=delete&action=read_self&action=update&authority=*&collection=*&manage=create&manage=delete&manage=update";

/// Wildcard blob upload/fetch scope required for encrypted media & Space avatars.
pub const BLOB_ALL_SCOPE: &str = "blob:*/*";

/// Repository write/read scope for Labyrinth `mailboxKeys` records.
pub const LABYRINTH_MAILBOX_KEYS_REPO_SCOPE: &str = "repo:blue.catbird.labyrinth.mailboxKeys";

/// Create-only repository scope for MLS `device` key-material records (`blue.catbird.chat.device`).
pub const MLS_CHAT_DEVICE_REPO_SCOPE: &str = "repo:blue.catbird.chat.device?action=create";

/// Create-only repository scope for signed MLS `deviceRevocation` tombstones (`blue.catbird.chat.deviceRevocation`, `B4`).
pub const MLS_CHAT_DEVICE_REVOCATION_REPO_SCOPE: &str =
    "repo:blue.catbird.chat.deviceRevocation?action=create";

/// Labyrinth personal mailbox Space scope: record read/create/update/delete on the exact
/// mailbox collections plus Space create/delete management (self authority).
pub const LABYRINTH_MAILBOX_SPACE_SCOPE: &str = "space:blue.catbird.labyrinth.mailbox?action=create&action=delete&action=read&action=update&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.circleOwnerState&collection=blue.catbird.labyrinth.device&collection=blue.catbird.labyrinth.epoch&collection=blue.catbird.labyrinth.epochMember&collection=blue.catbird.labyrinth.otcSession&collection=blue.catbird.labyrinth.ownerBatch&collection=blue.catbird.labyrinth.readState&collection=blue.catbird.labyrinth.virtualDevice&manage=create&manage=delete";

/// Labyrinth conversation Space scope: record read/create/update/delete on the exact
/// conversation collections across any Space authority (`authority=*`).
pub const LABYRINTH_CONVERSATION_SPACE_SCOPE: &str = "space:blue.catbird.labyrinth.conversation?action=create&action=delete&action=read&action=update&authority=*&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.authorRedaction&collection=blue.catbird.labyrinth.batch&collection=blue.catbird.labyrinth.mek";

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
    CIRCLE_SPACE_SCOPE,
    CIRCLE_ENCRYPTED_SPACE_SCOPE,
    BLOB_ALL_SCOPE,
    LABYRINTH_MAILBOX_KEYS_REPO_SCOPE,
    MLS_CHAT_DEVICE_REPO_SCOPE,
    MLS_CHAT_DEVICE_REVOCATION_REPO_SCOPE,
    LABYRINTH_MAILBOX_SPACE_SCOPE,
    LABYRINTH_CONVERSATION_SPACE_SCOPE,
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
        self.additional_scopes.iter().all(|s| {
            !s.is_empty()
                && (s.len() <= MAX_SCOPE_LEN || ALLOWLISTED_UPGRADE_SCOPES.contains(&s.as_str()))
        })
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
    fn upgrade_start_request_accepts_exact_labyrinth_space_scopes_only() {
        let nonce = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF".to_string();
        let req = UpgradeStartRequest {
            additional_scopes: vec![
                LABYRINTH_MAILBOX_SPACE_SCOPE.to_string(),
                LABYRINTH_CONVERSATION_SPACE_SCOPE.to_string(),
            ],
            browser_nonce: nonce.clone(),
        };
        assert!(req.is_structurally_valid());
        assert!(req.has_only_allowlisted_scopes());

        for retired in [
            "space:blue.catbird.labyrinth.mailbox?manage=create&manage=delete",
            "space:blue.catbird.labyrinth.conversation?authority=*",
        ] {
            let req = UpgradeStartRequest {
                additional_scopes: vec![retired.to_string()],
                browser_nonce: nonce.clone(),
            };
            assert!(!req.has_only_allowlisted_scopes(), "{retired}");
        }
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

    #[test]
    fn max_scope_len_is_512_and_rejects_oversized_non_allowlisted_scopes() {
        assert_eq!(MAX_SCOPE_LEN, 512);
        let nonce = "a".repeat(43);

        let exact_512 = UpgradeStartRequest {
            additional_scopes: vec!["s".repeat(MAX_SCOPE_LEN)],
            browser_nonce: nonce.clone(),
        };
        assert!(exact_512.is_structurally_valid());

        let over_512 = UpgradeStartRequest {
            additional_scopes: vec!["s".repeat(MAX_SCOPE_LEN + 1)],
            browser_nonce: nonce.clone(),
        };
        assert!(!over_512.is_structurally_valid());

        let arbitrary_531 = UpgradeStartRequest {
            additional_scopes: vec!["s".repeat(LABYRINTH_MAILBOX_SPACE_SCOPE.len())],
            browser_nonce: nonce.clone(),
        };
        assert!(!arbitrary_531.is_structurally_valid());

        let allowlisted_mailbox = UpgradeStartRequest {
            additional_scopes: vec![
                LABYRINTH_MAILBOX_SPACE_SCOPE.to_string(),
                CIRCLE_ENCRYPTED_SPACE_SCOPE.to_string(),
                MLS_CHAT_DEVICE_REPO_SCOPE.to_string(),
                MLS_CHAT_DEVICE_REVOCATION_REPO_SCOPE.to_string(),
            ],
            browser_nonce: nonce.clone(),
        };
        assert!(allowlisted_mailbox.is_structurally_valid());
        assert!(allowlisted_mailbox.has_only_allowlisted_scopes());

        for bare_retired in [
            "repo:blue.catbird.chat.device",
            "repo:blue.catbird.chat.deviceRevocation",
        ] {
            let bare_req = UpgradeStartRequest {
                additional_scopes: vec![bare_retired.to_string()],
                browser_nonce: nonce.clone(),
            };
            assert!(!bare_req.has_only_allowlisted_scopes(), "{bare_retired}");
        }
    }
}
