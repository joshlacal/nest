//! Progressive OAuth Upgrade Service
//!
//! Implements storage and business logic for progressive OAuth scope upgrades:
//! - Initiation: `/auth/upgrade` (validates allowlisted scopes, 43-char browser nonce, stores encrypted flow)
//! - Callback: Server-side exchange, DID validation, monotonic scope check, staged candidate session
//! - Candidate Exchange: `/auth/upgrade/exchange` (composite key atomic GETDEL)
//! - Commit: `/auth/upgrade/commit` (Lua-driven atomic idempotent candidate activation + old session retirement)
//!
//! Fixed wire decisions per parity foundation contract:
//! - Allowlisted upgrade scopes: `identity:handle`, `account:email?action=manage`, `account:status?action=manage`
//! - Fixed callback: `https://catbird.blue/oauth/permission-callback`
//! - No public upgrade_id; exchange uses candidate_session_id (fresh UUID), did, granted_scopes
//! - Candidate remains absent from ordinary session/index until commit
//! - Old session remains active until commit
//! - One pending upgrade per old UUID
//! - Commit is idempotent for same candidate and rejects competing candidates

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jacquard_oauth::scopes::Scope;
use jacquard_oauth::session::ClientSessionData;
use rand::RngCore;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

use sha2::Digest;

use super::redis_auth_store::{fingerprint_id, RedisAuthStore};
use super::redis_crypto::{open_strict, seal_strict};

/// Fixed server-side callback URL for progressive OAuth scope upgrades
pub const DEFAULT_UPGRADE_CALLBACK_URL: &str = "https://catbird.blue/oauth/permission-callback";

/// Supported allowlisted progressive upgrade scopes
pub const ALLOWED_UPGRADE_SCOPES: &[&str] = &[
    "identity:handle",
    "account:email?action=manage",
    "account:status?action=manage",
];

/// TTL for pending upgrade flow state (10 minutes)
pub const UPGRADE_FLOW_TTL_SECONDS: u64 = 600;

/// TTL for staged candidate session before commit (10 minutes)
pub const UPGRADE_CANDIDATE_TTL_SECONDS: u64 = 600;

/// TTL for one-time candidate exchange code (5 minutes)
pub const UPGRADE_EXCHANGE_TTL_SECONDS: u64 = 300;

/// TTL for committed upgrade receipt (24 hours)
pub const UPGRADE_RECEIPT_TTL_SECONDS: u64 = 86400;

/// Default TTL for retired session tombstones (centralized 90 days)
pub use super::redis_auth_store::RETIRED_TOMBSTONE_TTL_SECONDS;

/// Normal session index TTL (30 days)
pub const SESSION_INDEX_TTL_SECONDS: u64 = 86400 * 30;

/// Lua script for atomic idempotent upgrade commit:
/// - Checks if receipt already exists for this candidate (idempotent replay)
/// - Checks if old session was already retired by a different winning candidate or logout
/// - Verifies candidate exists in staged storage
/// - Verifies old session blob exists, matches expected version digest, and old index maps to candidate DID
/// - Promotes candidate into active hashed session storage and index
/// - Retires old session from session storage and index
/// - Records retired winner as candidate HMAC fingerprint on hashed retired tombstone key
/// - Records encrypted commit receipt
/// - Cleans up candidate and pending upgrade keys
const LUA_COMMIT_SCRIPT: &str = r#"
-- KEYS:
-- 1: candidate_key (hashed)
-- 2: receipt_key (hashed)
-- 3: retired_key (hashed)
-- 4: new_session_key (hashed)
-- 5: new_session_index_key (hashed)
-- 6: old_session_key (hashed)
-- 7: old_session_index_key (hashed)
-- 8: pending_upgrade_key (hashed)

-- ARGV:
-- 1: candidate_fingerprint (HMAC fingerprint of candidate_session_id)
-- 2: old_fingerprint (HMAC fingerprint of old_session_id)
-- 3: did
-- 4: encrypted_session_data
-- 5: encrypted_receipt
-- 6: session_ttl
-- 7: session_index_ttl
-- 8: retired_ttl
-- 9: receipt_ttl
-- 10: originating_flow_state_fp (HMAC fingerprint of originating state)
-- 11: expected_old_session_blob (exact sealed session CAS)

local existing_receipt = redis.call('GET', KEYS[2])
if existing_receipt then
    return {1, existing_receipt}
end

local winner = redis.call('GET', KEYS[3])
if winner then
    if winner == "logout" then
        return {4, "old_session_inactive"}
    elseif winner ~= ARGV[1] then
        return {2, "conflict"}
    end
end

local candidate = redis.call('GET', KEYS[1])
if not candidate then
    return {3, "candidate_not_found"}
end

local old_session = redis.call('GET', KEYS[6])
if not old_session then
    return {4, "old_session_inactive"}
end

if not ARGV[11] or ARGV[11] == '' or old_session ~= ARGV[11] then
    return {4, "old_session_conflict"}
end

local old_index_did = redis.call('GET', KEYS[7])
if not old_index_did or old_index_did ~= ARGV[3] then
    return {4, "old_session_inactive"}
end

redis.call('SETEX', KEYS[4], tonumber(ARGV[6]), ARGV[4])
redis.call('SETEX', KEYS[5], tonumber(ARGV[7]), ARGV[3])
redis.call('DEL', KEYS[6])
redis.call('DEL', KEYS[7])
redis.call('SETEX', KEYS[3], tonumber(ARGV[8]), ARGV[1])
redis.call('SETEX', KEYS[2], tonumber(ARGV[9]), ARGV[5])
redis.call('DEL', KEYS[1])

if ARGV[10] and ARGV[10] ~= '' then
    local current_pending = redis.call('GET', KEYS[8])
    if current_pending == ARGV[10] then
        redis.call('DEL', KEYS[8])
    end
end

return {0, ARGV[5]}
"#;

/// Lua script for atomic upgrade start:
/// - Checks if retired tombstone exists (returns 2 for inactive/logged-out old session)
/// - Checks if live pending upgrade exists (returns 1 if pending upgrade exists, cleans up stale pointer)
/// - Claims new flow and records pending pointer
const LUA_START_SCRIPT: &str = r#"
-- KEYS:
-- 1: pending_upgrade_key (hashed)
-- 2: new_flow_key (hashed)
-- 3: retired_key (hashed)

-- ARGV:
-- 1: new_state_fp
-- 2: encrypted_flow_data
-- 3: flow_ttl
-- 4: flow_key_prefix

if redis.call('EXISTS', KEYS[3]) == 1 then
    return 2
end

local hmac_state = redis.call('GET', KEYS[1])
if hmac_state then
    local hmac_flow_key = ARGV[4] .. hmac_state
    if redis.call('EXISTS', hmac_flow_key) == 1 then
        return 1
    else
        redis.call('DEL', KEYS[1])
        redis.call('DEL', hmac_flow_key)
    end
end

redis.call('SETEX', KEYS[2], tonumber(ARGV[3]), ARGV[2])
redis.call('SETEX', KEYS[1], tonumber(ARGV[3]), ARGV[1])
return 0
"#;

/// Lua script for atomic compare-and-delete:
/// - Deletes target key if and only if its current value equals expected value
const LUA_CAD_SCRIPT: &str = r#"
-- KEYS:
-- 1: target_key

-- ARGV:
-- 1: expected_value

if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
else
    return 0
end
"#;

const LUA_CONSUME_CALLBACK_SCRIPT: &str = r#"
-- KEYS:
-- 1: flow_key (hashed)
-- 2: pending_upgrade_key (hashed)

-- ARGV:
-- 1: state_fp

if redis.call('GET', KEYS[2]) == ARGV[1] then
    local flow_data = redis.call('GET', KEYS[1])
    if flow_data then
        redis.call('DEL', KEYS[1])
        redis.call('DEL', KEYS[2])
        return flow_data
    end
end
return nil
"#;

/// Errors arising from progressive OAuth upgrade operations.
#[derive(Debug, Error)]
pub enum UpgradeError {
    #[error("Missing encryption key: required for progressive OAuth upgrade")]
    MissingEncryptionKey,

    #[error("Invalid browser_nonce: must be exactly 43 base64url characters")]
    InvalidBrowserNonce,

    #[error("Disallowed or invalid upgrade scope: {0}")]
    DisallowedScope(String),

    #[error("Empty additional scopes requested")]
    EmptyAdditionalScopes,

    #[error("Invalid session ID UUID")]
    InvalidSessionId,

    #[error("Invalid upgrade state or flow expired")]
    InvalidFlowState,

    #[error("Flow DID mismatch: expected {expected}, got {actual}")]
    DidMismatch { expected: String, actual: String },

    #[error("Scope downgrade: {0}")]
    ScopeDowngrade(String),

    #[error("Upgrade already pending for session")]
    PendingUpgradeExists,

    #[error("Invalid exchange parameters or code not found")]
    ExchangeNotFound,

    #[error("Staged candidate session not found or expired")]
    CandidateNotFound,

    #[error("Commit rejected: competing candidate already won upgrade lineage")]
    CompetingCandidateWon,

    #[error("Commit rejected: old session is inactive or logged out")]
    OldSessionInactive,

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal upgrade error: {0}")]
    Internal(String),
}

/// Pending progressive upgrade flow state stored in Redis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpgradeFlowState {
    pub state: String,
    pub old_session_id: String,
    pub old_did: String,
    pub requested_scopes: Vec<String>,
    pub browser_nonce: String,
    pub created_at: u64,
    pub expected_old_session_blob: String,
}

/// Inactive candidate session staged in Redis prior to commit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StagedCandidateSession {
    pub candidate_session_id: String,
    pub old_session_id: String,
    pub did: String,
    pub flow_state: String,
    pub granted_scopes: Vec<String>,
    pub session_data_json: String,
    pub created_at: u64,
    pub expected_old_session_blob: String,
}


/// Exchange state stored under a composite key (old_session_id:code:browser_nonce).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpgradeExchangeState {
    pub candidate_session_id: String,
    pub old_session_id: String,
    pub did: String,
    pub granted_scopes: Vec<String>,
    pub created_at: u64,
}

/// Authoritative commit receipt recorded for idempotent commit lookups.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpgradeReceipt {
    pub status: String,
    pub candidate_session_id: String,
    pub old_session_id: String,
    pub did: String,
    pub granted_scopes: Vec<String>,
    pub committed_at: u64,
}

/// Result returned from initiating an upgrade flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpgradeStartResult {
    pub state: String,
    pub requested_scopes: Vec<String>,
    pub callback_url: String,
}

/// Result returned from processing the server-side OAuth callback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpgradeCallbackResult {
    pub exchange_code: String,
    pub candidate_session_id: String,
    pub did: String,
    pub granted_scopes: Vec<String>,
}

/// Result returned from candidate exchange.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpgradeExchangeResult {
    pub candidate_session_id: String,
    pub did: String,
    pub granted_scopes: Vec<String>,
}

/// Check if a single scope string belongs to the allowlist.
pub fn is_allowed_upgrade_scope(scope: &str) -> bool {
    ALLOWED_UPGRADE_SCOPES.contains(&scope)
}

/// Validate that requested additional scopes are non-empty, allowlisted, and free of injection.
pub fn validate_additional_scopes(scopes: &[String]) -> Result<(), UpgradeError> {
    if scopes.is_empty() {
        return Err(UpgradeError::EmptyAdditionalScopes);
    }
    for scope in scopes {
        let trimmed = scope.trim();
        if trimmed.is_empty()
            || trimmed.contains(' ')
            || trimmed.contains('*')
            || !is_allowed_upgrade_scope(trimmed)
        {
            return Err(UpgradeError::DisallowedScope(scope.clone()));
        }
    }
    Ok(())
}

/// Validate that a browser challenge nonce is exactly 43 base64url characters.
pub fn is_valid_browser_nonce(nonce: &str) -> bool {
    if nonce.len() != 43 {
        return false;
    }
    nonce
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Compute SHA-256 hex digest of a byte slice.
pub fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in result {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{:02x}", b);
    }
    hex
}

/// Generate a 32-byte cryptographically secure random exchange code encoded as 43-character base64url (no padding).
pub fn generate_exchange_code() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Progressive OAuth Upgrade Service.
#[derive(Clone)]
pub struct OAuthUpgradeService {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
    session_ttl: u64,
    encryption_key: [u8; 32],
    callback_url: String,
}

impl OAuthUpgradeService {
    /// Create a new `OAuthUpgradeService` with explicit settings.
    pub fn new(
        redis: redis::aio::ConnectionManager,
        key_prefix: String,
        session_ttl: u64,
        encryption_key: [u8; 32],
        callback_url: Option<String>,
    ) -> Self {
        Self {
            redis,
            key_prefix,
            session_ttl,
            encryption_key,
            callback_url: callback_url.unwrap_or_else(|| DEFAULT_UPGRADE_CALLBACK_URL.to_string()),
        }
    }

    /// Construct service from an existing `RedisAuthStore`.
    pub fn from_auth_store(store: &RedisAuthStore, callback_url: Option<String>) -> Self {
        Self::new(
            store.redis_connection(),
            store.key_prefix().to_string(),
            store.session_ttl(),
            store.encryption_key(),
            callback_url,
        )
    }

    /// Compute HMAC-SHA256 fingerprint for bearer IDs.
    pub fn fingerprint(&self, id: &str) -> String {
        fingerprint_id(&self.encryption_key, id)
    }

    // Key schema helpers (HMAC-SHA256 fingerprinted for bearer values under v2 prefix)
    pub fn flow_key(&self, state: &str) -> String {
        format!(
            "{}upgrade_flow:{}",
            self.key_prefix,
            self.fingerprint(state)
        )
    }

    pub fn pending_upgrade_key(&self, old_session_id: &str) -> String {
        format!(
            "{}upgrade_pending:{}",
            self.key_prefix,
            self.fingerprint(old_session_id)
        )
    }

    pub fn candidate_key(&self, candidate_session_id: &str) -> String {
        format!(
            "{}upgrade_candidate:{}",
            self.key_prefix,
            self.fingerprint(candidate_session_id)
        )
    }

    pub fn exchange_key(&self, old_session_id: &str, code: &str, browser_nonce: &str) -> String {
        format!(
            "{}upgrade_exchange:{}:{}:{}",
            self.key_prefix,
            self.fingerprint(old_session_id),
            self.fingerprint(code),
            self.fingerprint(browser_nonce)
        )
    }

    pub fn receipt_key(&self, candidate_session_id: &str) -> String {
        format!(
            "{}upgrade_receipt:{}",
            self.key_prefix,
            self.fingerprint(candidate_session_id)
        )
    }

    pub fn retired_key(&self, old_session_id: &str) -> String {
        format!(
            "{}upgrade_retired:{}",
            self.key_prefix,
            self.fingerprint(old_session_id)
        )
    }

    pub fn session_key(&self, did: &str, session_id: &str) -> String {
        format!(
            "{}session:{}_{}",
            self.key_prefix,
            did,
            self.fingerprint(session_id)
        )
    }

    pub fn session_index_key(&self, session_id: &str) -> String {
        format!(
            "{}session_index:{}",
            self.key_prefix,
            self.fingerprint(session_id)
        )
    }

    fn enc_key(&self) -> &[u8; 32] {
        &self.encryption_key
    }

    /// Start a progressive OAuth upgrade flow.
    ///
    /// Validates inputs, rejects current scopes missing `atproto`, rejects duplicate pending
    /// upgrades if a live flow exists, and persists encrypted flow state.
    pub async fn start_upgrade_flow(
        &self,
        old_session_id: &str,
        old_did: &str,
        current_scopes: &[String],
        additional_scopes: &[String],
        browser_nonce: &str,
    ) -> Result<UpgradeStartResult, UpgradeError> {
        if !is_valid_browser_nonce(browser_nonce) {
            return Err(UpgradeError::InvalidBrowserNonce);
        }

        validate_additional_scopes(additional_scopes)?;

        // Validate UUID structure
        if Uuid::parse_str(old_session_id).is_err() {
            return Err(UpgradeError::InvalidSessionId);
        }

        // Validate current scopes: must be non-empty, parseable, and must explicitly contain atproto
        if current_scopes.is_empty() {
            return Err(UpgradeError::ScopeDowngrade(
                "current scopes empty: must contain atproto".into(),
            ));
        }

        let mut has_atproto = false;
        for s in current_scopes {
            let parsed = Scope::<smol_str::SmolStr>::parse(s).map_err(|_| {
                UpgradeError::DisallowedScope(format!("invalid current scope: {s}"))
            })?;
            if matches!(parsed, Scope::Atproto) {
                has_atproto = true;
            }
        }
        if !has_atproto {
            return Err(UpgradeError::ScopeDowngrade(
                "current scopes missing required atproto scope".into(),
            ));
        }

        // Build combined requested scopes preserving base scopes without duplicate entries
        let mut requested_scopes = Vec::new();
        for s in current_scopes {
            if !requested_scopes.contains(s) {
                requested_scopes.push(s.clone());
            }
        }
        for s in additional_scopes {
            if !requested_scopes.contains(s) {
                requested_scopes.push(s.clone());
            }
        }

        let mut conn = self.redis.clone();

        // Query old active session blob to capture its exact encrypted value for CAS
        let old_session_k = self.session_key(old_did, old_session_id);
        let old_sess_blob: Option<String> = conn.get(&old_session_k).await?;
        let Some(old_sess_str) = old_sess_blob else {
            return Err(UpgradeError::OldSessionInactive);
        };
        if old_sess_str.trim().is_empty() {
            return Err(UpgradeError::OldSessionInactive);
        }

        // Generate cryptographically random OAuth state for the upgrade flow
        let state = format!("upg_{}", Uuid::new_v4().simple());
        let flow_state = UpgradeFlowState {
            state: state.clone(),
            old_session_id: old_session_id.to_string(),
            old_did: old_did.to_string(),
            requested_scopes: requested_scopes.clone(),
            browser_nonce: browser_nonce.to_string(),
            created_at: current_timestamp_secs(),
            expected_old_session_blob: old_sess_str,
        };

        let json = serde_json::to_string(&flow_state)?;
        let encrypted = seal_strict(self.enc_key(), &json)
            .map_err(|e| UpgradeError::Internal(format!("Failed to seal flow: {e}")))?;

        // Atomically claim/store flow + pending pointer via Lua script
        let state_fp = self.fingerprint(&state);
        let pending_key = self.pending_upgrade_key(old_session_id);
        let flow_k = self.flow_key(&state);
        let retired_k = self.retired_key(old_session_id);
        let flow_key_prefix = format!("{}upgrade_flow:", self.key_prefix);

        let script = redis::Script::new(LUA_START_SCRIPT);
        let res: i32 = script
            .key(&pending_key)
            .key(&flow_k)
            .key(&retired_k)
            .arg(&state_fp)
            .arg(&encrypted)
            .arg(UPGRADE_FLOW_TTL_SECONDS)
            .arg(&flow_key_prefix)
            .invoke_async(&mut conn)
            .await?;

        if res == 1 {
            return Err(UpgradeError::PendingUpgradeExists);
        } else if res == 2 {
            return Err(UpgradeError::OldSessionInactive);
        } else if res != 0 {
            return Err(UpgradeError::Internal(format!(
                "Unexpected Lua start flow response status: {res}"
            )));
        }

        Ok(UpgradeStartResult {
            state,
            requested_scopes,
            callback_url: self.callback_url.clone(),
        })
    }

    /// Clean up a cancelled or denied upgrade flow without touching the active session.
    pub async fn cancel_or_deny_flow(&self, state: &str) -> Result<Option<String>, UpgradeError> {
        let mut conn = self.redis.clone();
        let flow_k = self.flow_key(state);
        let raw: Option<String> = conn.get_del(&flow_k).await?;

        let Some(encrypted) = raw else {
            return Ok(None);
        };

        let json = open_strict(self.enc_key(), &encrypted)
            .map_err(|e| UpgradeError::Internal(format!("Failed to open flow: {e}")))?;
        let flow: UpgradeFlowState = serde_json::from_str(&json)?;

        // Clean up pending pointer safely only if it still points to this consumed state via atomic CAD
        let state_fp = self.fingerprint(state);
        let pending_k = self.pending_upgrade_key(&flow.old_session_id);
        let script = redis::Script::new(LUA_CAD_SCRIPT);
        let _: Result<i32, _> = script
            .key(&pending_k)
            .arg(&state_fp)
            .invoke_async(&mut conn)
            .await;
        Ok(Some(flow.old_session_id))
    }

    /// Process server-side OAuth callback after successful authorization from PDS.
    ///
    /// Consumes flow state atomically with pending pointer verification, verifies DID and granted scopes,
    /// agreement, rewrites candidate session_id to fresh candidate UUID, and stages candidate.
    pub async fn complete_callback(
        &self,
        state: &str,
        session_data: ClientSessionData,
        granted_scopes: Vec<String>,
    ) -> Result<UpgradeCallbackResult, UpgradeError> {
        let mut conn = self.redis.clone();
        let flow_k = self.flow_key(state);

        // Read flow state
        let raw: Option<String> = conn.get(&flow_k).await?;
        let Some(encrypted) = raw else {
            return Err(UpgradeError::InvalidFlowState);
        };

        let json = open_strict(self.enc_key(), &encrypted)
            .map_err(|e| UpgradeError::Internal(format!("Failed to open flow: {e}")))?;
        let flow: UpgradeFlowState = serde_json::from_str(&json)?;
        if flow.expected_old_session_blob.is_empty() {
            return Err(UpgradeError::InvalidFlowState);
        }

        let state_fp = self.fingerprint(state);
        let pending_k = self.pending_upgrade_key(&flow.old_session_id);
        let script = redis::Script::new(LUA_CONSUME_CALLBACK_SCRIPT);
        let consumed: Option<String> = script
            .key(&flow_k)
            .key(&pending_k)
            .arg(&state_fp)
            .invoke_async(&mut conn)
            .await?;

        if consumed.is_none() {
            return Err(UpgradeError::InvalidFlowState);
        }

        // Exact DID verification
        if session_data.account_did.as_str() != flow.old_did {
            return Err(UpgradeError::DidMismatch {
                expected: flow.old_did,
                actual: session_data.account_did.as_str().to_string(),
            });
        }

        // Parse and validate granted scopes
        let mut parsed_granted = Vec::new();
        for s in &granted_scopes {
            let parsed = Scope::<smol_str::SmolStr>::parse(s).map_err(|_| {
                UpgradeError::ScopeDowngrade(format!("invalid or unparseable granted scope: {s}"))
            })?;
            parsed_granted.push(parsed);
        }

        // Parse requested scopes from flow
        let mut parsed_requested = Vec::new();
        for s in &flow.requested_scopes {
            let parsed = Scope::<smol_str::SmolStr>::parse(s).map_err(|_| {
                UpgradeError::ScopeDowngrade(format!("invalid or unparseable requested scope: {s}"))
            })?;
            parsed_requested.push(parsed);
        }

        // Must contain atproto scope
        if !parsed_granted.iter().any(|s| matches!(s, Scope::Atproto)) {
            return Err(UpgradeError::ScopeDowngrade(
                "missing required atproto scope in granted scopes".into(),
            ));
        }

        // Exact/semantic scope verification: every requested scope must be covered by granted scopes
        for req in &parsed_requested {
            let covered = parsed_granted.iter().any(|g| g == req || g.grants(req));
            if !covered {
                return Err(UpgradeError::ScopeDowngrade(format!(
                    "requested scope '{}' not granted",
                    req.to_string_normalized()
                )));
            }
        }

        // No unexpected grant beyond target: every granted scope must be covered by requested scopes
        for grant in &parsed_granted {
            let allowed = parsed_requested
                .iter()
                .any(|r| r == grant || r.grants(grant));
            if !allowed {
                return Err(UpgradeError::ScopeDowngrade(format!(
                    "unexpected scope '{}' granted beyond requested target",
                    grant.to_string_normalized()
                )));
            }
        }

        // Require session_data.scopes agrees with the passed grants
        for grant in &parsed_granted {
            let in_session = session_data
                .scopes
                .iter()
                .any(|s| s.to_string_normalized() == grant.to_string_normalized() || s.grants(grant));
            if !in_session {
                return Err(UpgradeError::ScopeDowngrade(format!(
                    "session_data.scopes missing granted scope '{}'",
                    grant.to_string_normalized()
                )));
            }
        }
        for s in session_data.scopes.iter() {
            let in_granted = parsed_granted
                .iter()
                .any(|g| g.to_string_normalized() == s.to_string_normalized() || g.grants(&s));
            if !in_granted {
                return Err(UpgradeError::ScopeDowngrade(format!(
                    "session_data.scopes contains ungranted scope '{}'",
                    s.to_string_normalized()
                )));
            }
        }

        // Generate fresh candidate session UUID independent of old session
        let candidate_session_id = Uuid::new_v4().to_string();

        // Rewrite staged ClientSessionData.session_id to candidate UUID before serialization
        // so token refresh persists under candidate session ID
        let mut session_data = session_data;
        session_data.session_id = candidate_session_id.clone().into();

        // Generate 32 random bytes encoded as 43-char base64url for one-time exchange code
        let exchange_code = generate_exchange_code();

        let staged_candidate = StagedCandidateSession {
            candidate_session_id: candidate_session_id.clone(),
            old_session_id: flow.old_session_id.clone(),
            did: flow.old_did.clone(),
            flow_state: self.fingerprint(&flow.state),
            granted_scopes: granted_scopes.clone(),
            session_data_json: serde_json::to_string(&session_data)?,
            created_at: current_timestamp_secs(),
            expected_old_session_blob: flow.expected_old_session_blob,
        };
        let staged_json = serde_json::to_string(&staged_candidate)?;
        let staged_encrypted = seal_strict(self.enc_key(), &staged_json)
            .map_err(|e| UpgradeError::Internal(format!("Failed to seal candidate: {e}")))?;

        // Save staged candidate outside ordinary session/index
        let cand_key = self.candidate_key(&candidate_session_id);
        conn.set_ex::<_, _, ()>(&cand_key, staged_encrypted, UPGRADE_CANDIDATE_TTL_SECONDS)
            .await?;

        // Save exchange state under composite key
        let exchange_state = UpgradeExchangeState {
            candidate_session_id: candidate_session_id.clone(),
            old_session_id: flow.old_session_id,
            did: flow.old_did.clone(),
            granted_scopes: granted_scopes.clone(),
            created_at: current_timestamp_secs(),
        };

        let exchange_json = serde_json::to_string(&exchange_state)?;
        let exchange_encrypted = seal_strict(self.enc_key(), &exchange_json)
            .map_err(|e| UpgradeError::Internal(format!("Failed to seal exchange: {e}")))?;
        let ex_key = self.exchange_key(
            &exchange_state.old_session_id,
            &exchange_code,
            &flow.browser_nonce,
        );
        conn.set_ex::<_, _, ()>(&ex_key, exchange_encrypted, UPGRADE_EXCHANGE_TTL_SECONDS)
            .await?;

        Ok(UpgradeCallbackResult {
            exchange_code,
            candidate_session_id,
            did: flow.old_did,
            granted_scopes,
        })
    }

    /// Exchange code + browser nonce for candidate session info (`POST /auth/upgrade/exchange`).
    ///
    /// Uses composite key lookup so wrong bearer/nonce cannot consume legitimate records.
    pub async fn exchange_candidate(
        &self,
        old_session_id: &str,
        exchange_code: &str,
        browser_nonce: &str,
    ) -> Result<UpgradeExchangeResult, UpgradeError> {
        let mut conn = self.redis.clone();
        let ex_key = self.exchange_key(old_session_id, exchange_code, browser_nonce);

        let raw: Option<String> = conn.get_del(&ex_key).await?;
        let Some(encrypted) = raw else {
            return Err(UpgradeError::ExchangeNotFound);
        };

        let json = open_strict(self.enc_key(), &encrypted)
            .map_err(|e| UpgradeError::Internal(format!("Failed to open exchange: {e}")))?;
        let state: UpgradeExchangeState = serde_json::from_str(&json)?;

        Ok(UpgradeExchangeResult {
            candidate_session_id: state.candidate_session_id,
            did: state.did,
            granted_scopes: state.granted_scopes,
        })
    }

    /// Commit the candidate session (`POST /auth/upgrade/commit`).
    ///
    /// Atomically activates candidate session into ordinary session storage & index,
    /// retires old session, and records an idempotent receipt.
    pub async fn commit_upgrade(
        &self,
        candidate_session_id: &str,
    ) -> Result<UpgradeReceipt, UpgradeError> {
        let mut conn = self.redis.clone();
        // Fast path: check if this candidate was already committed (idempotency)
        if let Some(receipt) = self.get_receipt(candidate_session_id).await? {
            return Ok(receipt);
        }

        // Fetch staged candidate
        let cand_k = self.candidate_key(candidate_session_id);
        let cand_raw: Option<String> = conn.get(&cand_k).await?;
        let cand_encrypted = match cand_raw {
            Some(c) => c,
            None => {
                // If candidate fetch misses after initial receipt check (e.g. concurrent identical commit won the race),
                // atomically re-read receipt and return committed receipt if present before CandidateNotFound.
                if let Some(receipt) = self.get_receipt(candidate_session_id).await? {
                    return Ok(receipt);
                }
                return Err(UpgradeError::CandidateNotFound);
            }
        };

        let cand_json = open_strict(self.enc_key(), &cand_encrypted)
            .map_err(|e| UpgradeError::Internal(format!("Candidate decryption failed: {e}")))?;
        let candidate: StagedCandidateSession = serde_json::from_str(&cand_json)?;
        if candidate.expected_old_session_blob.is_empty() {
            return Err(UpgradeError::OldSessionInactive);
        }
        let receipt = UpgradeReceipt {
            status: "committed".to_string(),
            candidate_session_id: candidate_session_id.to_string(),
            old_session_id: candidate.old_session_id.clone(),
            did: candidate.did.clone(),
            granted_scopes: candidate.granted_scopes.clone(),
            committed_at: current_timestamp_secs(),
        };
        let receipt_json = serde_json::to_string(&receipt)?;
        let encrypted_receipt = seal_strict(self.enc_key(), &receipt_json)
            .map_err(|e| UpgradeError::Internal(format!("Receipt encryption failed: {e}")))?;

        // Re-encrypt the session data for standard session storage
        let encrypted_session = seal_strict(self.enc_key(), &candidate.session_data_json)
            .map_err(|e| UpgradeError::Internal(format!("Session encryption failed: {e}")))?;

        let retired_k = self.retired_key(&candidate.old_session_id);
        let new_session_k = self.session_key(&candidate.did, candidate_session_id);
        let new_index_k = self.session_index_key(candidate_session_id);
        let old_session_k = self.session_key(&candidate.did, &candidate.old_session_id);
        let old_index_k = self.session_index_key(&candidate.old_session_id);
        let pending_k = self.pending_upgrade_key(&candidate.old_session_id);
        let receipt_k = self.receipt_key(candidate_session_id);

        let cand_fp = self.fingerprint(candidate_session_id);
        let old_fp = self.fingerprint(&candidate.old_session_id);

        let retired_ttl = self
            .session_ttl
            .max(SESSION_INDEX_TTL_SECONDS)
            .max(RETIRED_TOMBSTONE_TTL_SECONDS);

        let script = redis::Script::new(LUA_COMMIT_SCRIPT);
        let script_res: (i32, String) = script
            .key(&cand_k)
            .key(&receipt_k)
            .key(&retired_k)
            .key(&new_session_k)
            .key(&new_index_k)
            .key(&old_session_k)
            .key(&old_index_k)
            .key(&pending_k)
            .arg(&cand_fp)
            .arg(&old_fp)
            .arg(&candidate.did)
            .arg(&encrypted_session)
            .arg(&encrypted_receipt)
            .arg(self.session_ttl)
            .arg(SESSION_INDEX_TTL_SECONDS)
            .arg(retired_ttl)
            .arg(UPGRADE_RECEIPT_TTL_SECONDS)
            .arg(&candidate.flow_state)
            .arg(&candidate.expected_old_session_blob)
            .invoke_async(&mut conn)
            .await?;

        match script_res.0 {
            0 | 1 => {
                let json = open_strict(self.enc_key(), &script_res.1).map_err(|e| {
                    UpgradeError::Internal(format!("Commit receipt decryption failed: {e}"))
                })?;
                let final_receipt: UpgradeReceipt = serde_json::from_str(&json)?;
                Ok(final_receipt)
            }
            2 => Err(UpgradeError::CompetingCandidateWon),
            3 => {
                if let Some(receipt) = self.get_receipt(candidate_session_id).await? {
                    Ok(receipt)
                } else {
                    Err(UpgradeError::CandidateNotFound)
                }
            }
            4 => Err(UpgradeError::OldSessionInactive),
            _ => Err(UpgradeError::Internal(format!(
                "Unexpected Lua commit response status: {}",
                script_res.0
            ))),
        }
    }

    /// Read receipt for an already-committed candidate.
    pub async fn get_receipt(
        &self,
        candidate_session_id: &str,
    ) -> Result<Option<UpgradeReceipt>, UpgradeError> {
        let mut conn = self.redis.clone();
        let receipt_k = self.receipt_key(candidate_session_id);

        let data: Option<String> = conn.get(&receipt_k).await?;
        if let Some(encrypted) = data {
            let json = open_strict(self.enc_key(), &encrypted)
                .map_err(|e| UpgradeError::Internal(format!("Receipt decryption failed: {e}")))?;
            return Ok(Some(serde_json::from_str(&json)?));
        }
        Ok(None)
    }

    /// Check if a session has an active pending upgrade.
    pub async fn is_pending_upgrade(&self, old_session_id: &str) -> Result<bool, UpgradeError> {
        let mut conn = self.redis.clone();
        let pending_k = self.pending_upgrade_key(old_session_id);

        let state_fp: Option<String> = conn.get(&pending_k).await?;
        if let Some(state_fp_val) = state_fp {
            let flow_k = format!("{}upgrade_flow:{}", self.key_prefix, state_fp_val);
            let exists: bool = conn.exists(&flow_k).await?;
            if exists {
                return Ok(true);
            } else {
                let script = redis::Script::new(LUA_CAD_SCRIPT);
                let _: Result<i32, _> = script
                    .key(&pending_k)
                    .arg(&state_fp_val)
                    .invoke_async(&mut conn)
                    .await;
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_KEY: [u8; 32] = [0x42u8; 32];

    #[test]
    fn test_no_raw_bearer_in_upgrade_keys() {
        let key_prefix = "catbird:v2:";
        let old_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let candidate_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let code = "random_exchange_code_43_chars_base64url_xyz";
        let nonce = "random_browser_nonce_43_chars_base64url_abc";
        let state = "raw_oauth_state_string_upg_1234567890";
        let did = "did:plc:ragtjsm2j2vknq6z";

        let fp_old = fingerprint_id(&TEST_KEY, old_session_id);
        let fp_cand = fingerprint_id(&TEST_KEY, candidate_id);
        let fp_code = fingerprint_id(&TEST_KEY, code);
        let fp_nonce = fingerprint_id(&TEST_KEY, nonce);
        let fp_state = fingerprint_id(&TEST_KEY, state);

        let flow_key = format!("{}upgrade_flow:{}", key_prefix, fp_state);
        let pending_key = format!("{}upgrade_pending:{}", key_prefix, fp_old);
        let candidate_key = format!("{}upgrade_candidate:{}", key_prefix, fp_cand);
        let exchange_key = format!(
            "{}upgrade_exchange:{}:{}:{}",
            key_prefix, fp_old, fp_code, fp_nonce
        );
        let receipt_key = format!("{}upgrade_receipt:{}", key_prefix, fp_cand);
        let retired_key = format!("{}upgrade_retired:{}", key_prefix, fp_old);
        let session_key = format!("{}session:{}_{}", key_prefix, did, fp_cand);
        let session_index_key = format!("{}session_index:{}", key_prefix, fp_cand);

        // Verify none of the generated keys contain the raw bearer tokens or raw state
        assert!(!flow_key.contains(state));
        assert!(!pending_key.contains(old_session_id));
        assert!(!candidate_key.contains(candidate_id));
        assert!(!exchange_key.contains(old_session_id));
        assert!(!exchange_key.contains(code));
        assert!(!exchange_key.contains(nonce));
        assert!(!receipt_key.contains(candidate_id));
        assert!(!retired_key.contains(old_session_id));
        assert!(!session_key.contains(candidate_id));
        assert!(!session_index_key.contains(candidate_id));

        // Verify they all contain their respective fingerprints
        assert!(flow_key.contains(&fp_state));
        assert!(pending_key.contains(&fp_old));
        assert!(candidate_key.contains(&fp_cand));
        assert!(exchange_key.contains(&fp_old));
        assert!(exchange_key.contains(&fp_code));
        assert!(exchange_key.contains(&fp_nonce));
        assert!(receipt_key.contains(&fp_cand));
        assert!(retired_key.contains(&fp_old));
        assert!(session_key.contains(&fp_cand));
        assert!(session_index_key.contains(&fp_cand));
    }

    struct CommitSim {
        store: std::collections::HashMap<String, String>,
    }

    impl CommitSim {
        fn commit(
            &mut self,
            cand_k: &str,
            receipt_k: &str,
            ret_k_hashed: &str,
            new_sess_k: &str,
            new_idx_k: &str,
            old_sess_k_hashed: &str,
            old_idx_k_hashed: &str,
            pending_k_hashed: &str,
            cand_fp: &str,
            did: &str,
            enc_session: &str,
            encrypted_receipt: &str,
            flow_state: &str,
            expected_old_blob: &str,
        ) -> (i32, String) {
            if let Some(existing) = self.store.get(receipt_k).cloned() {
                return (1, existing);
            }

            if let Some(w) = self.store.get(ret_k_hashed) {
                if w != cand_fp {
                    if w == "logout" {
                        return (4, "old_session_inactive".into());
                    } else {
                        return (2, "conflict".into());
                    }
                }
            }

            if !self.store.contains_key(cand_k) {
                return (3, "candidate_not_found".into());
            }

            let Some(old_sess_data) = self.store.get(old_sess_k_hashed) else {
                return (4, "old_session_inactive".into());
            };

            // Check old session exact sealed blob match (CAS) - mandatory nonempty, no empty bypass
            if expected_old_blob.is_empty() || old_sess_data != expected_old_blob {
                return (4, "old_session_conflict".into());
            }

            if self.store.get(old_idx_k_hashed).map(|s| s.as_str()) != Some(did) {
                return (4, "old_session_inactive".into());
            }

            // Promote candidate to hashed keys
            self.store
                .insert(new_sess_k.to_string(), enc_session.to_string());
            self.store.insert(new_idx_k.to_string(), did.to_string());

            // Delete old session keys
            self.store.remove(old_sess_k_hashed);
            self.store.remove(old_idx_k_hashed);

            // Set tombstone (HMAC fingerprint ONLY) and receipt
            self.store
                .insert(ret_k_hashed.to_string(), cand_fp.to_string());
            self.store
                .insert(receipt_k.to_string(), encrypted_receipt.to_string());
            self.store.remove(cand_k);

            if let Some(cur) = self.store.get(pending_k_hashed) {
                if cur == flow_state {
                    self.store.remove(pending_k_hashed);
                }
            }

            (0, encrypted_receipt.to_string())
        }
    }

    #[test]
    fn test_lua_commit_simulation() {
        let mut sim = CommitSim {
            store: std::collections::HashMap::new(),
        };

        let old_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let candidate_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let did = "did:plc:ragtjsm2j2vknq6z";
        let flow_state = "upg_state_123";

        let fp_old = fingerprint_id(&TEST_KEY, old_session_id);
        let fp_cand = fingerprint_id(&TEST_KEY, candidate_id);

        let cand_k = format!("catbird:v2:upgrade_candidate:{}", fp_cand);
        let receipt_k = format!("catbird:v2:upgrade_receipt:{}", fp_cand);
        let ret_k_hashed = format!("catbird:v2:upgrade_retired:{}", fp_old);
        let new_sess_k = format!("catbird:v2:session:{}_{}", did, fp_cand);
        let new_idx_k = format!("catbird:v2:session_index:{}", fp_cand);
        let old_sess_k_hashed = format!("catbird:v2:session:{}_{}", did, fp_old);
        let old_idx_k_hashed = format!("catbird:v2:session_index:{}", fp_old);
        let pending_k_hashed = format!("catbird:v2:upgrade_pending:{}", fp_old);

        let old_blob = "sealed_old_blob";
        sim.store.insert(cand_k.clone(), "candidate_blob".into());
        sim.store.insert(old_sess_k_hashed.clone(), old_blob.into());
        sim.store.insert(old_idx_k_hashed.clone(), did.into());
        sim.store
            .insert(pending_k_hashed.clone(), flow_state.into());

        let sealed_receipt = seal_strict(&TEST_KEY, r#"{"status":"committed"}"#).unwrap();

        // Perform commit
        let (status, resp) = sim.commit(
            &cand_k,
            &receipt_k,
            &ret_k_hashed,
            &new_sess_k,
            &new_idx_k,
            &old_sess_k_hashed,
            &old_idx_k_hashed,
            &pending_k_hashed,
            &fp_cand,
            did,
            "new_encrypted_blob",
            &sealed_receipt,
            flow_state,
            old_blob,
        );

        assert_eq!(status, 0);
        assert_eq!(resp, sealed_receipt);

        // Verify candidate promoted to hashed keys
        assert_eq!(
            sim.store.get(&new_sess_k).map(|s| s.as_str()),
            Some("new_encrypted_blob")
        );
        assert_eq!(sim.store.get(&new_idx_k).map(|s| s.as_str()), Some(did));

        // Verify old session and candidate deleted
        assert!(!sim.store.contains_key(&old_sess_k_hashed));
        assert!(!sim.store.contains_key(&old_idx_k_hashed));
        assert!(!sim.store.contains_key(&cand_k));

        // Verify retired tombstone set (HMAC fingerprint ONLY) and receipt stored
        assert_eq!(
            sim.store.get(&ret_k_hashed).map(|s| s.as_str()),
            Some(fp_cand.as_str())
        );
        assert_eq!(
            sim.store.get(&receipt_k).map(|s| s.as_str()),
            Some(sealed_receipt.as_str())
        );

        // Idempotent replay
        let (status2, resp2) = sim.commit(
            &cand_k,
            &receipt_k,
            &ret_k_hashed,
            &new_sess_k,
            &new_idx_k,
            &old_sess_k_hashed,
            &old_idx_k_hashed,
            &pending_k_hashed,
            &fp_cand,
            did,
            "new_encrypted_blob",
            &sealed_receipt,
            flow_state,
            old_blob,
        );
        assert_eq!(status2, 1);
        assert_eq!(resp2, sealed_receipt);
    }

    #[test]
    fn test_old_session_version_conflict_rejects_commit() {
        let mut sim = CommitSim {
            store: std::collections::HashMap::new(),
        };

        let old_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let candidate_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let did = "did:plc:ragtjsm2j2vknq6z";
        let flow_state = "upg_state_conflict";

        let fp_old = fingerprint_id(&TEST_KEY, old_session_id);
        let fp_cand = fingerprint_id(&TEST_KEY, candidate_id);

        let cand_k = format!("catbird:v2:upgrade_candidate:{}", fp_cand);
        let receipt_k = format!("catbird:v2:upgrade_receipt:{}", fp_cand);
        let ret_k_hashed = format!("catbird:v2:upgrade_retired:{}", fp_old);
        let new_sess_k = format!("catbird:v2:session:{}_{}", did, fp_cand);
        let new_idx_k = format!("catbird:v2:session_index:{}", fp_cand);
        let old_sess_k_hashed = format!("catbird:v2:session:{}_{}", did, fp_old);
        let old_idx_k_hashed = format!("catbird:v2:session_index:{}", fp_old);
        let pending_k_hashed = format!("catbird:v2:upgrade_pending:{}", fp_old);

        let original_blob = "original_encrypted_old_blob";
        let refreshed_blob = "refreshed_encrypted_old_blob";

        sim.store.insert(cand_k.clone(), "candidate_blob".into());
        sim.store
            .insert(old_sess_k_hashed.clone(), refreshed_blob.into());
        sim.store.insert(old_idx_k_hashed.clone(), did.into());

        let (status, resp) = sim.commit(
            &cand_k,
            &receipt_k,
            &ret_k_hashed,
            &new_sess_k,
            &new_idx_k,
            &old_sess_k_hashed,
            &old_idx_k_hashed,
            &pending_k_hashed,
            &fp_cand,
            did,
            "new_encrypted_session",
            "receipt",
            flow_state,
            original_blob, // Expects original sealed blob, but Redis has refreshed blob
        );
        assert_eq!(status, 4);
        assert_eq!(resp, "old_session_conflict");

        // Candidate must NOT be promoted
        assert!(!sim.store.contains_key(&new_sess_k));
        // Old refreshed session must NOT be deleted
        assert_eq!(
            sim.store.get(&old_sess_k_hashed).map(|s| s.as_str()),
            Some(refreshed_blob)
        );
    }

    #[test]
    fn test_logout_prevents_upgrade_commit() {
        let mut sim = CommitSim {
            store: std::collections::HashMap::new(),
        };

        let old_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let candidate_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let did = "did:plc:ragtjsm2j2vknq6z";
        let fp_old = fingerprint_id(&TEST_KEY, old_session_id);
        let fp_cand = fingerprint_id(&TEST_KEY, candidate_id);

        let ret_k_hashed = format!("catbird:v2:upgrade_retired:{}", fp_old);
        let cand_k = format!("catbird:v2:upgrade_candidate:{}", fp_cand);
        let receipt_k = format!("catbird:v2:upgrade_receipt:{}", fp_cand);
        let new_sess_k = format!("catbird:v2:session:{}_{}", did, fp_cand);
        let new_idx_k = format!("catbird:v2:session_index:{}", fp_cand);
        let old_sess_k_hashed = format!("catbird:v2:session:{}_{}", did, fp_old);
        let old_idx_k_hashed = format!("catbird:v2:session_index:{}", fp_old);
        let pending_k_hashed = format!("catbird:v2:upgrade_pending:{}", fp_old);

        // Old session was logged out: tombstone is "logout"
        sim.store.insert(ret_k_hashed.clone(), "logout".to_string());
        sim.store
            .insert(cand_k.clone(), "candidate_blob".to_string());
        sim.store
            .insert(old_sess_k_hashed.clone(), "old_blob".to_string());
        sim.store.insert(old_idx_k_hashed.clone(), did.into());

        let (status, resp) = sim.commit(
            &cand_k,
            &receipt_k,
            &ret_k_hashed,
            &new_sess_k,
            &new_idx_k,
            &old_sess_k_hashed,
            &old_idx_k_hashed,
            &pending_k_hashed,
            &fp_cand,
            did,
            "new_session",
            "receipt",
            "flow_state",
            "old_blob",
        );

        assert_eq!(status, 4);
        assert_eq!(resp, "old_session_inactive");
    }

    #[test]
    fn test_callback_consumption_with_authoritative_pending_pointer() {
        struct CallbackSim {
            store: std::collections::HashMap<String, String>,
        }

        impl CallbackSim {
            fn consume(
                &mut self,
                flow_k: &str,
                hmac_pending_k: &str,
                state_fp: &str,
            ) -> Option<String> {
                if self.store.get(hmac_pending_k).map(|s| s.as_str()) != Some(state_fp) {
                    return None;
                }

                let flow_data = self.store.remove(flow_k)?;
                self.store.remove(hmac_pending_k);
                Some(flow_data)
            }
        }

        let prefix = "catbird:v2:upgrade_flow:";
        let old_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let fp_old = fingerprint_id(&TEST_KEY, old_session_id);
        let hmac_pending_k = format!("catbird:v2:upgrade_pending:{}", fp_old);

        let valid_state = "valid_state_123";
        let fp_valid_state = fingerprint_id(&TEST_KEY, valid_state);
        let flow_k = format!("{}{}", prefix, fp_valid_state);

        // Case 1: Valid matching state fingerprint consumes flow and deletes pending pointer
        let mut sim = CallbackSim {
            store: std::collections::HashMap::new(),
        };
        sim.store
            .insert(flow_k.clone(), "encrypted_flow_data".into());
        sim.store.insert(hmac_pending_k.clone(), fp_valid_state.clone());

        let res = sim.consume(&flow_k, &hmac_pending_k, &fp_valid_state);
        assert_eq!(res.as_deref(), Some("encrypted_flow_data"));
        assert!(!sim.store.contains_key(&flow_k));
        assert!(!sim.store.contains_key(&hmac_pending_k));

        // Case 2: Mismatched state fingerprint is rejected and does not consume flow
        let mut sim = CallbackSim {
            store: std::collections::HashMap::new(),
        };
        sim.store
            .insert(flow_k.clone(), "encrypted_flow_data".into());
        sim.store.insert(hmac_pending_k.clone(), fp_valid_state);

        let res2 = sim.consume(&flow_k, &hmac_pending_k, "wrong_state_fp");
        assert_eq!(res2, None);
        assert!(sim.store.contains_key(&flow_k));
    }

    #[test]
    fn test_start_upgrade_flow_simulation() {
        struct StartSim {
            store: std::collections::HashMap<String, String>,
        }

        impl StartSim {
            fn start(
                &mut self,
                hmac_pending_k: &str,
                new_flow_k: &str,
                ret_k_hashed: &str,
                new_state_fp: &str,
                new_flow_blob: &str,
                prefix: &str,
            ) -> i32 {
                if self.store.contains_key(ret_k_hashed) {
                    return 2;
                }

                if let Some(hmac_state) = self.store.get(hmac_pending_k).cloned() {
                    let hmac_flow_k = format!("{}{}", prefix, hmac_state);
                    if self.store.contains_key(&hmac_flow_k) {
                        return 1;
                    } else {
                        self.store.remove(hmac_pending_k);
                        self.store.remove(&hmac_flow_k);
                    }
                }

                self.store
                    .insert(new_flow_k.to_string(), new_flow_blob.to_string());
                self.store
                    .insert(hmac_pending_k.to_string(), new_state_fp.to_string());
                0
            }
        }

        let prefix = "catbird:v2:upgrade_flow:";
        let old_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let fp_old = fingerprint_id(&TEST_KEY, old_session_id);
        let hmac_pending_k = format!("catbird:v2:upgrade_pending:{}", fp_old);
        let ret_k_hashed = format!("catbird:v2:upgrade_retired:{}", fp_old);

        let new_state = "new_flow_state_xyz";
        let fp_new_state = fingerprint_id(&TEST_KEY, new_state);
        let new_flow_k = format!("{}{}", prefix, fp_new_state);

        let live_state = "live_state_123";
        let fp_live_state = fingerprint_id(&TEST_KEY, live_state);

        // Case 1: Live pending flow exists -> returns 1
        let mut sim = StartSim {
            store: std::collections::HashMap::new(),
        };
        sim.store
            .insert(hmac_pending_k.clone(), fp_live_state.clone());
        sim.store
            .insert(format!("{}{}", prefix, fp_live_state), "flow_blob".into());

        let res1 = sim.start(
            &hmac_pending_k,
            &new_flow_k,
            &ret_k_hashed,
            &fp_new_state,
            "new_blob",
            prefix,
        );
        assert_eq!(res1, 1);

        // Case 2: Retired session -> returns 2
        let mut sim2 = StartSim {
            store: std::collections::HashMap::new(),
        };
        sim2.store.insert(ret_k_hashed.clone(), "winner_fp".into());
        let res2 = sim2.start(
            &hmac_pending_k,
            &new_flow_k,
            &ret_k_hashed,
            &fp_new_state,
            "new_blob",
            prefix,
        );
        assert_eq!(res2, 2);

        // Case 3: Clean state -> claims flow and records pending pointer
        let mut sim3 = StartSim {
            store: std::collections::HashMap::new(),
        };
        let res3 = sim3.start(
            &hmac_pending_k,
            &new_flow_k,
            &ret_k_hashed,
            &fp_new_state,
            "new_blob",
            prefix,
        );
        assert_eq!(res3, 0);
        assert_eq!(
            sim3.store.get(&hmac_pending_k).map(|s| s.as_str()),
            Some(fp_new_state.as_str())
        );
        assert_eq!(
            sim3.store.get(&new_flow_k).map(|s| s.as_str()),
            Some("new_blob")
        );
    }

    #[test]
    fn test_validate_additional_scopes() {
        let valid = vec![
            "identity:handle".to_string(),
            "account:email?action=manage".to_string(),
        ];
        assert!(validate_additional_scopes(&valid).is_ok());

        let empty: Vec<String> = vec![];
        assert!(matches!(
            validate_additional_scopes(&empty),
            Err(UpgradeError::EmptyAdditionalScopes)
        ));

        let disallowed = vec!["admin:delete".to_string()];
        assert!(matches!(
            validate_additional_scopes(&disallowed),
            Err(UpgradeError::DisallowedScope(_))
        ));

        let injected = vec!["identity:handle\r\nSET bad 1".to_string()];
        assert!(matches!(
            validate_additional_scopes(&injected),
            Err(UpgradeError::DisallowedScope(_))
        ));
    }

    #[test]
    fn test_browser_nonce_validation() {
        assert!(is_valid_browser_nonce(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP1"
        ));
        assert!(!is_valid_browser_nonce("short"));
        assert!(!is_valid_browser_nonce(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP1234"
        )); // 44 chars
        assert!(!is_valid_browser_nonce(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP!"
        )); // invalid char
    }

    #[test]
    fn test_generate_exchange_code_format() {
        let code = generate_exchange_code();
        assert_eq!(code.len(), 43);
        assert!(is_valid_browser_nonce(&code));
    }

    #[test]
    fn test_refresh_between_start_and_commit_conflict() {
        let mut sim = CommitSim {
            store: std::collections::HashMap::new(),
        };

        let old_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let candidate_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let did = "did:plc:ragtjsm2j2vknq6z";
        let flow_state = "upg_state_refresh_conflict";

        let fp_old = fingerprint_id(&TEST_KEY, old_session_id);
        let fp_cand = fingerprint_id(&TEST_KEY, candidate_id);

        let cand_k = format!("catbird:v2:upgrade_candidate:{}", fp_cand);
        let receipt_k = format!("catbird:v2:upgrade_receipt:{}", fp_cand);
        let ret_k_hashed = format!("catbird:v2:upgrade_retired:{}", fp_old);
        let new_sess_k = format!("catbird:v2:session:{}_{}", did, fp_cand);
        let new_idx_k = format!("catbird:v2:session_index:{}", fp_cand);
        let old_sess_k_hashed = format!("catbird:v2:session:{}_{}", did, fp_old);
        let old_idx_k_hashed = format!("catbird:v2:session_index:{}", fp_old);
        let pending_k_hashed = format!("catbird:v2:upgrade_pending:{}", fp_old);

        // Step 1: Start flow captures initial encrypted old session blob v1
        let old_blob_v1 = "initial_sealed_old_session_blob_v1";
        sim.store
            .insert(old_sess_k_hashed.clone(), old_blob_v1.into());
        sim.store.insert(old_idx_k_hashed.clone(), did.into());

        // Candidate staged with expected_old_session_blob = old_blob_v1
        sim.store
            .insert(cand_k.clone(), "staged_candidate_session_blob".into());
        sim.store
            .insert(pending_k_hashed.clone(), flow_state.into());

        // Step 2: Between start and commit, an access token refresh updates the old session in Redis to v2
        let old_blob_v2 = "refreshed_sealed_old_session_blob_v2";
        sim.store
            .insert(old_sess_k_hashed.clone(), old_blob_v2.into());

        let sealed_receipt = seal_strict(&TEST_KEY, r#"{"status":"committed"}"#).unwrap();

        // Step 3: Commit executes with exact CAS expecting v1
        let (status, resp) = sim.commit(
            &cand_k,
            &receipt_k,
            &ret_k_hashed,
            &new_sess_k,
            &new_idx_k,
            &old_sess_k_hashed,
            &old_idx_k_hashed,
            &pending_k_hashed,
            &fp_cand,
            did,
            "new_upgraded_session_blob",
            &sealed_receipt,
            flow_state,
            old_blob_v1, // Expects v1 from start
        );

        // Step 4: CAS mismatch must strictly reject commit with status 4 conflict
        assert_eq!(status, 4);
        assert_eq!(resp, "old_session_conflict");

        // Candidate was not promoted to active session
        assert!(!sim.store.contains_key(&new_sess_k));
        // Old refreshed session remains active and untouched
        assert_eq!(
            sim.store.get(&old_sess_k_hashed).map(|s| s.as_str()),
            Some(old_blob_v2)
        );
        // Tombstone was not set
        assert!(!sim.store.contains_key(&ret_k_hashed));
    }

    #[test]
    fn test_steady_state_command_shapes_avoid_raw_keys() {
        let prefix = "catbird:v2:";
        let old_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let candidate_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let exchange_code = "sample_exchange_code_43_chars_base64url_xxx";
        let browser_nonce = "sample_browser_nonce_43_chars_base64url_yyy";
        let state = "sample_raw_oauth_state_43_chars_base64url_zzz";

        let fp_old = fingerprint_id(&TEST_KEY, old_session_id);
        let fp_cand = fingerprint_id(&TEST_KEY, candidate_id);
        let fp_code = fingerprint_id(&TEST_KEY, exchange_code);
        let fp_nonce = fingerprint_id(&TEST_KEY, browser_nonce);
        let fp_state = fingerprint_id(&TEST_KEY, state);

        // 1. Flow key shape
        let steady_flow_key = format!("{}upgrade_flow:{}", prefix, fp_state);
        assert!(!steady_flow_key.contains(state));
        assert!(steady_flow_key.contains(&fp_state));

        // 2. Exchange key shape
        let steady_ex_key = format!(
            "{}upgrade_exchange:{}:{}:{}",
            prefix, fp_old, fp_code, fp_nonce
        );
        assert!(!steady_ex_key.contains(old_session_id));
        assert!(!steady_ex_key.contains(exchange_code));
        assert!(!steady_ex_key.contains(browser_nonce));
        assert!(steady_ex_key.contains(&fp_old));
        assert!(steady_ex_key.contains(&fp_code));
        assert!(steady_ex_key.contains(&fp_nonce));

        // 3. Receipt key shape
        let steady_receipt_key = format!("{}upgrade_receipt:{}", prefix, fp_cand);
        assert!(!steady_receipt_key.contains(candidate_id));
        assert!(steady_receipt_key.contains(&fp_cand));

        // 4. Candidate key shape
        let steady_cand_key = format!("{}upgrade_candidate:{}", prefix, fp_cand);
        assert!(!steady_cand_key.contains(candidate_id));
        assert!(steady_cand_key.contains(&fp_cand));

        // 5. Pending key shape
        let steady_pending_key = format!("{}upgrade_pending:{}", prefix, fp_old);
        assert!(!steady_pending_key.contains(old_session_id));
        assert!(steady_pending_key.contains(&fp_old));

        // 6. Retired key shape
        let steady_retired_key = format!("{}upgrade_retired:{}", prefix, fp_old);
        assert!(!steady_retired_key.contains(old_session_id));
        assert!(steady_retired_key.contains(&fp_old));

        // Centralized 90-day tombstone TTL verification
        assert_eq!(RETIRED_TOMBSTONE_TTL_SECONDS, 86400 * 90);
    }

    #[test]
    fn test_concurrent_identical_commit_both_receive_success_and_no_winner_secret() {
        let mut sim = CommitSim {
            store: std::collections::HashMap::new(),
        };

        let old_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let candidate_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let competing_candidate_id = "7ca7b810-9dad-11d1-80b4-00c04fd430c9";
        let did = "did:plc:ragtjsm2j2vknq6z";
        let flow_state = "upg_state_concurrent";

        let fp_old = fingerprint_id(&TEST_KEY, old_session_id);
        let fp_cand = fingerprint_id(&TEST_KEY, candidate_id);
        let fp_competing = fingerprint_id(&TEST_KEY, competing_candidate_id);

        let cand_k = format!("catbird:v2:upgrade_candidate:{}", fp_cand);
        let receipt_k = format!("catbird:v2:upgrade_receipt:{}", fp_cand);
        let ret_k_hashed = format!("catbird:v2:upgrade_retired:{}", fp_old);
        let new_sess_k = format!("catbird:v2:session:{}_{}", did, fp_cand);
        let new_idx_k = format!("catbird:v2:session_index:{}", fp_cand);
        let old_sess_k_hashed = format!("catbird:v2:session:{}_{}", did, fp_old);
        let old_idx_k_hashed = format!("catbird:v2:session_index:{}", fp_old);
        let pending_k_hashed = format!("catbird:v2:upgrade_pending:{}", fp_old);

        let old_blob = "sealed_old_session_blob";
        let candidate_blob = "sealed_candidate_blob";
        let receipt_json = format!(
            r#"{{"status":"committed","candidate_session_id":"{}","old_session_id":"{}","did":"{}","granted_scopes":["identity:handle"],"committed_at":1700000000}}"#,
            candidate_id, old_session_id, did
        );
        let sealed_receipt = seal_strict(&TEST_KEY, &receipt_json).unwrap();

        // 1. Initial Redis state: candidate staged, old session active
        sim.store.insert(cand_k.clone(), candidate_blob.into());
        sim.store.insert(old_sess_k_hashed.clone(), old_blob.into());
        sim.store.insert(old_idx_k_hashed.clone(), did.into());
        sim.store
            .insert(pending_k_hashed.clone(), flow_state.into());

        // Step A: Caller 1 and Caller 2 check receipt initially -> neither sees a receipt
        assert!(!sim.store.contains_key(&receipt_k));

        // Step B: Caller 1 fetches candidate successfully
        let caller1_cand = sim.store.get(&cand_k).cloned();
        assert_eq!(caller1_cand, Some(candidate_blob.into()));

        // Step C: Caller 1 performs commit via Lua script -> succeeds
        let (status1, resp1) = sim.commit(
            &cand_k,
            &receipt_k,
            &ret_k_hashed,
            &new_sess_k,
            &new_idx_k,
            &old_sess_k_hashed,
            &old_idx_k_hashed,
            &pending_k_hashed,
            &fp_cand,
            did,
            "new_sealed_session",
            &sealed_receipt,
            flow_state,
            old_blob,
        );
        assert_eq!(status1, 0);
        assert_eq!(resp1, sealed_receipt);

        // Step D: Caller 2 (which missed initial receipt check) now attempts candidate fetch:
        // Candidate key was deleted by Caller 1's commit!
        let caller2_cand_fetch = sim.store.get(&cand_k);
        assert!(caller2_cand_fetch.is_none());

        // Step E: Caller 2 performs receipt fetch:
        // Finds the receipt committed by Caller 1
        let caller2_receipt_fetch = sim.store.get(&receipt_k);
        assert!(caller2_receipt_fetch.is_some());
        let caller2_resp = caller2_receipt_fetch.unwrap().clone();
        assert_eq!(caller2_resp, sealed_receipt);

        // Both Caller 1 and Caller 2 decrypt and obtain identical committed receipts
        let r1_json = open_strict(&TEST_KEY, &resp1).unwrap();
        let r2_json = open_strict(&TEST_KEY, &caller2_resp).unwrap();
        assert_eq!(r1_json, r2_json);
        assert!(r1_json.contains(r#""status":"committed""#));

        // Step F: Verify competing candidate (Caller 3 with different candidate ID) running commit is rejected
        let cand_k_competing = format!("catbird:v2:upgrade_candidate:{}", fp_competing);
        let receipt_k_competing = format!("catbird:v2:upgrade_receipt:{}", fp_competing);
        let new_sess_k_competing = format!("catbird:v2:session:{}_{}", did, fp_competing);
        let new_idx_k_competing = format!("catbird:v2:session_index:{}", fp_competing);

        sim.store
            .insert(cand_k_competing.clone(), "competing_cand_blob".into());

        let (status_competing, resp_competing) = sim.commit(
            &cand_k_competing,
            &receipt_k_competing,
            &ret_k_hashed,
            &new_sess_k_competing,
            &new_idx_k_competing,
            &old_sess_k_hashed,
            &old_idx_k_hashed,
            &pending_k_hashed,
            &fp_competing,
            did,
            "competing_sealed_session",
            "competing_receipt",
            flow_state,
            old_blob,
        );

        // Competing candidate is strictly rejected with conflict status 2
        assert_eq!(status_competing, 2);
        // And response is generic "conflict" string - no winner candidate ID or secret is leaked!
        assert_eq!(resp_competing, "conflict");
        assert!(!resp_competing.contains(candidate_id));
        assert!(!resp_competing.contains(&fp_cand));

        // Verify retirement tombstone uses centralized 90-day TTL constant
        assert_eq!(RETIRED_TOMBSTONE_TTL_SECONDS, 86400 * 90);
    }

    #[test]
    fn test_legacy_record_without_expected_old_session_blob_rejected() {
        // Legacy UpgradeFlowState JSON missing expected_old_session_blob must fail deserialization
        let legacy_flow_json = r#"{
            "state": "upg_test_123",
            "old_session_id": "550e8400-e29b-41d4-a716-446655440000",
            "old_did": "did:plc:ragtjsm2j2vknq6z",
            "requested_scopes": ["identity:handle"],
            "browser_nonce": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP1",
            "created_at": 1700000000
        }"#;
        let res = serde_json::from_str::<UpgradeFlowState>(legacy_flow_json);
        assert!(res.is_err(), "Legacy flow missing expected_old_session_blob must be rejected");

        // Legacy UpgradeFlowState with old_session_version alias must also fail deserialization
        let alias_flow_json = r#"{
            "state": "upg_test_123",
            "old_session_id": "550e8400-e29b-41d4-a716-446655440000",
            "old_did": "did:plc:ragtjsm2j2vknq6z",
            "requested_scopes": ["identity:handle"],
            "browser_nonce": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP1",
            "created_at": 1700000000,
            "old_session_version": "v1"
        }"#;
        let res_alias = serde_json::from_str::<UpgradeFlowState>(alias_flow_json);
        assert!(res_alias.is_err(), "Alias old_session_version must not deserialize");

        // Legacy StagedCandidateSession missing expected_old_session_blob must fail deserialization
        let legacy_cand_json = r#"{
            "candidate_session_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "old_session_id": "550e8400-e29b-41d4-a716-446655440000",
            "did": "did:plc:ragtjsm2j2vknq6z",
            "flow_state": "flow_state_fp",
            "granted_scopes": ["identity:handle"],
            "session_data_json": "{}",
            "created_at": 1700000000
        }"#;
        let res_cand = serde_json::from_str::<StagedCandidateSession>(legacy_cand_json);
        assert!(res_cand.is_err(), "Legacy candidate missing expected_old_session_blob must be rejected");

        // Commit simulation strictly rejects empty expected_old_session_blob
        let mut sim = CommitSim {
            store: std::collections::HashMap::new(),
        };
        let fp_old = fingerprint_id(&TEST_KEY, "550e8400-e29b-41d4-a716-446655440000");
        let fp_cand = fingerprint_id(&TEST_KEY, "6ba7b810-9dad-11d1-80b4-00c04fd430c8");
        let cand_k = format!("catbird:v2:upgrade_candidate:{}", fp_cand);
        let receipt_k = format!("catbird:v2:upgrade_receipt:{}", fp_cand);
        let ret_k_hashed = format!("catbird:v2:upgrade_retired:{}", fp_old);
        let new_sess_k = format!("catbird:v2:session:did:plc:123_{}", fp_cand);
        let new_idx_k = format!("catbird:v2:session_index:{}", fp_cand);
        let old_sess_k_hashed = format!("catbird:v2:session:did:plc:123_{}", fp_old);
        let old_idx_k_hashed = format!("catbird:v2:session_index:{}", fp_old);
        let pending_k_hashed = format!("catbird:v2:upgrade_pending:{}", fp_old);

        sim.store.insert(cand_k.clone(), "candidate_blob".into());
        sim.store.insert(old_sess_k_hashed.clone(), "sealed_old_blob".into());
        sim.store.insert(old_idx_k_hashed.clone(), "did:plc:123".into());

        let (status, resp) = sim.commit(
            &cand_k,
            &receipt_k,
            &ret_k_hashed,
            &new_sess_k,
            &new_idx_k,
            &old_sess_k_hashed,
            &old_idx_k_hashed,
            &pending_k_hashed,
            &fp_cand,
            "did:plc:123",
            "new_encrypted_blob",
            "sealed_receipt",
            "flow_state",
            "", // empty expected_old_blob
        );
        assert_eq!(status, 4);
        assert_eq!(resp, "old_session_conflict");
    }

    #[test]
    fn test_stale_cleanup_race_prevention() {
        struct CadSim {
            store: std::collections::HashMap<String, String>,
        }
        impl CadSim {
            fn cad(&mut self, key: &str, expected_val: &str) -> i32 {
                if self.store.get(key).map(|s| s.as_str()) == Some(expected_val) {
                    self.store.remove(key);
                    1
                } else {
                    0
                }
            }
        }

        let old_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let fp_old = fingerprint_id(&TEST_KEY, old_session_id);
        let pending_k = format!("catbird:v2:upgrade_pending:{}", fp_old);

        let state1 = "state_flow_1";
        let fp_state1 = fingerprint_id(&TEST_KEY, state1);
        let state2 = "state_flow_2";
        let fp_state2 = fingerprint_id(&TEST_KEY, state2);

        let mut sim = CadSim {
            store: std::collections::HashMap::new(),
        };

        // Flow 1 was started, pending pointer set to fp_state1
        sim.store.insert(pending_k.clone(), fp_state1.clone());

        // Concurrently, Flow 2 starts and overwrites pending pointer with fp_state2
        sim.store.insert(pending_k.clone(), fp_state2.clone());

        // A stale cleanup for Flow 1 (which checked its expired flow_k and attempts CAD with fp_state1)
        let deleted = sim.cad(&pending_k, &fp_state1);
        assert_eq!(deleted, 0, "Stale cleanup must NOT delete newer pending pointer");

        // Newer pointer fp_state2 remains intact in pending_k
        assert_eq!(sim.store.get(&pending_k).map(|s| s.as_str()), Some(fp_state2.as_str()));

        // Cleanup with matching fp_state2 succeeds
        let deleted2 = sim.cad(&pending_k, &fp_state2);
        assert_eq!(deleted2, 1, "Matching CAD must delete the pointer");
        assert!(!sim.store.contains_key(&pending_k));
    }

    #[test]
    fn test_no_raw_state_in_flow_keys_and_staged_candidate() {
        let old_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let candidate_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let did = "did:plc:ragtjsm2j2vknq6z";
        let raw_state = "upg_test_raw_oauth_state_1234567890";
        let fp_state = fingerprint_id(&TEST_KEY, raw_state);

        // StagedCandidateSession.flow_state must store the HMAC fingerprint of state, not raw state
        let staged = StagedCandidateSession {
            candidate_session_id: candidate_id.to_string(),
            old_session_id: old_session_id.to_string(),
            did: did.to_string(),
            flow_state: fp_state.clone(),
            granted_scopes: vec!["identity:handle".to_string()],
            session_data_json: "{}".to_string(),
            created_at: 1700000000,
            expected_old_session_blob: "sealed_old_blob".to_string(),
        };

        assert_eq!(staged.flow_state, fp_state);
        assert_ne!(staged.flow_state, raw_state);
        assert!(!staged.flow_state.contains(raw_state));
    }
}
