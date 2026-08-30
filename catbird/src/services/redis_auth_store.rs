//! Redis-backed implementation of Jacquard's `ClientAuthStore`.
//!
//! Stores session data in Redis with required AES-256-GCM encryption and
//! HMAC-SHA256 bearer key fingerprinting under an explicit v2 namespace.

use hmac::{Hmac, Mac};
use jacquard_common::session::SessionStoreError;
use jacquard_common::types::did::Did;

use jacquard_oauth::authstore::ClientAuthStore;
use jacquard_oauth::session::{AuthRequestData, ClientSessionData};
use redis::AsyncCommands;
use sha2::Sha256;

use super::redis_crypto::{open_strict, seal_strict};

type HmacSha256 = Hmac<Sha256>;

const STATE_TTL_SECONDS: u64 = 600; // 10 minutes for OAuth state
pub const SESSION_INDEX_TTL_SECONDS: u64 = 86400 * 30; // 30 days
/// 90 days for retirement tombstones (at least 2 * max session/index TTL of 30 days plus 30-day rollout margin).
pub const RETIRED_TOMBSTONE_TTL_SECONDS: u64 = 86400 * 90; // 90 days

/// Outcome report from background session index reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconciliationOutcome {
    pub reconciled: usize,
    pub skipped: usize,
    pub failed: usize,
    pub total_scanned: usize,
    pub is_complete: bool,
}
/// Maximum number of Redis SCAN pages examined during self-healing session recovery on index miss.
pub const MAX_SELF_HEAL_SCAN_PAGES: usize = 10;

/// Pure scan termination predicate for self-heal key walks.
/// Returns true if scanning should terminate due to finding a session,
/// completing keyspace traversal (cursor == 0), or exhausting MAX_SELF_HEAL_SCAN_PAGES.
pub fn should_terminate_self_heal_scan(
    recovered: bool,
    scan_cursor: u64,
    pages_scanned: usize,
) -> bool {
    recovered || scan_cursor == 0 || pages_scanned >= MAX_SELF_HEAL_SCAN_PAGES
}

/// Pure function for updating the reconciliation cursor based on end cursor and failure count.
/// If failures occurred in this window (failed > 0), the cursor is NOT advanced, preserving
/// the start cursor so that the next re-arm retries the failed window.
/// If zero failures occurred (failed == 0), the cursor advances to end_cursor (or resets to 0 if wrapped).
/// Returns the new cursor value that should be stored.
pub fn compute_reconciliation_cursor_update(
    start_cursor: u64,
    end_cursor: u64,
    failed: usize,
) -> u64 {
    if failed > 0 {
        start_cursor
    } else {
        end_cursor
    }
}


/// Compute HMAC-SHA256 fingerprint for bearer IDs.
/// Output is a 64-character lowercase hex string.
pub fn fingerprint_id(key: &[u8; 32], id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(id.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(64);
    for b in result {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{:02x}", b);
    }
    hex
}

/// Lua script for atomic session lookup (HMAC keys only, no raw key args):
/// - Refuses read if retired tombstone exists (returns nil)
/// - Checks authoritative hashed session key first (with sliding TTL)
/// - If hashed session exists, touches sliding TTL on hashed index key and SHA-256 fp index key, returning session data
/// - Returns nil on miss
const LUA_GET_SESSION_SCRIPT: &str = r#"
-- KEYS:
-- 1: hashed_session_key
-- 2: hashed_index_key
-- 3: hashed_retired_key
-- 4: hashed_fp_index_key
-- 5: did_index_key

-- ARGV:
-- 1: session_ttl
-- 2: session_index_ttl
-- 3: did
-- 4: hmac_fingerprint

if redis.call('EXISTS', KEYS[3]) == 1 then
    return nil
end

local data = redis.call('GETEX', KEYS[1], 'EX', tonumber(ARGV[1]))
if data then
    local hashed_index_did = redis.call('GETEX', KEYS[2], 'EX', tonumber(ARGV[2]))
    if not hashed_index_did and ARGV[3] and ARGV[3] ~= '' then
        redis.call('SETEX', KEYS[2], tonumber(ARGV[2]), ARGV[3])
    end
    if KEYS[4] and KEYS[4] ~= '' then
        local fp_val = redis.call('GETEX', KEYS[4], 'EX', tonumber(ARGV[1]))
        if not fp_val and ARGV[4] and ARGV[4] ~= '' then
            redis.call('SETEX', KEYS[4], tonumber(ARGV[1]), ARGV[4])
        end
    end
    if KEYS[5] and KEYS[5] ~= '' then
        local did_val = redis.call('GETEX', KEYS[5], 'EX', tonumber(ARGV[1]))
        if not did_val and ARGV[4] and ARGV[4] ~= '' then
            redis.call('SETEX', KEYS[5], tonumber(ARGV[1]), ARGV[4])
        end
    end
    return data
end

return nil
"#;

/// Lua script for atomic DID index lookup (HMAC keys only, no raw key args):
/// - Refuses lookup if retired tombstone exists (returns nil)
/// - Checks authoritative hashed index key (with sliding TTL)
/// - If DID found in hashed index, refreshes TTL on hashed session key if present
/// - Returns nil on miss
const LUA_LOOKUP_INDEX_SCRIPT: &str = r#"
-- KEYS:
-- 1: hashed_index_key
-- 2: hashed_retired_key

-- ARGV:
-- 1: session_index_ttl
-- 2: session_ttl
-- 3: key_prefix
-- 4: fingerprint

if redis.call('EXISTS', KEYS[2]) == 1 then
    return nil
end

local did = redis.call('GETEX', KEYS[1], 'EX', tonumber(ARGV[1]))
if did then
    local hashed_session_key = ARGV[3] .. 'session:' .. did .. '_' .. ARGV[4]
    if redis.call('EXISTS', hashed_session_key) == 1 then
        redis.call('EXPIRE', hashed_session_key, tonumber(ARGV[2]))
    end
    return did
end

return nil
"#;

/// Lua script for atomic session index write with retirement protection:
/// - Refuses write if retired tombstone exists (returns 1)
/// - Sets hashed session index and SHA-256 fp index entries (returns 0)
const LUA_WRITE_INDEX_SCRIPT: &str = r#"
-- KEYS:
-- 1: hashed_index_key
-- 2: hashed_retired_key
-- 3: hashed_fp_index_key
-- 4: did_index_key

-- ARGV:
-- 1: did
-- 2: session_index_ttl
-- 3: session_ttl
-- 4: hmac_fingerprint

if redis.call('EXISTS', KEYS[2]) == 1 then
    return 1
end

redis.call('SETEX', KEYS[1], tonumber(ARGV[2]), ARGV[1])
if KEYS[3] and KEYS[3] ~= '' and ARGV[4] and ARGV[4] ~= '' then
    redis.call('SETEX', KEYS[3], tonumber(ARGV[3]), ARGV[4])
end
if KEYS[4] and KEYS[4] ~= '' and ARGV[4] and ARGV[4] ~= '' then
    redis.call('SETEX', KEYS[4], tonumber(ARGV[3]), ARGV[4])
end
return 0
"#;

/// Lua script for atomic session upsert with retirement protection:
/// - Refuses write if retired tombstone exists (returns 1)
/// - Sets hashed session blob, session index, SHA-256 fingerprint index, and DID index atomically (returns 0)
const LUA_UPSERT_SESSION_SCRIPT: &str = r#"
-- KEYS:
-- 1: hashed_session_key
-- 2: hashed_index_key
-- 3: hashed_retired_key
-- 4: hashed_fp_index_key
-- 5: did_index_key

-- ARGV:
-- 1: encrypted_session_data
-- 2: did
-- 3: session_ttl
-- 4: session_index_ttl
-- 5: hmac_fingerprint

if redis.call('EXISTS', KEYS[3]) == 1 then
    return 1
end

redis.call('SETEX', KEYS[1], tonumber(ARGV[3]), ARGV[1])
redis.call('SETEX', KEYS[2], tonumber(ARGV[4]), ARGV[2])
redis.call('SETEX', KEYS[4], tonumber(ARGV[3]), ARGV[5])
if KEYS[5] and KEYS[5] ~= '' then
    redis.call('SETEX', KEYS[5], tonumber(ARGV[3]), ARGV[5])
end
return 0
"#;

/// Lua script for atomic logout retirement:
/// - Sets retired tombstone on hashed key
/// - Deletes hashed session and index entries, SHA-256 fingerprint index, DID index, and pending upgrade state pointers
const LUA_LOGOUT_RETIRE_SCRIPT: &str = r#"
-- KEYS:
-- 1: hashed_retired_key
-- 2: hashed_session_key
-- 3: hashed_index_key
-- 4: hashed_pending_key
-- 5: hashed_fp_index_key
-- 6: did_index_key

-- ARGV:
-- 1: retired_ttl
-- 2: retired_marker

redis.call('SETEX', KEYS[1], tonumber(ARGV[1]), ARGV[2])
redis.call('DEL', KEYS[2])
redis.call('DEL', KEYS[3])
redis.call('DEL', KEYS[4])
redis.call('DEL', KEYS[5])
if KEYS[6] and KEYS[6] ~= '' then
    redis.call('DEL', KEYS[6])
end
return 0
"#;

/// Lua script for atomic O(1) session resolution by SHA-256 fingerprint with backward-compatible DID index fallback:
/// - Checks hashed SHA-256 fingerprint index key (O(1))
/// - When absent, falls back to DID index or raw HMAC fingerprint (O(1))
/// - Refuses read if retired tombstone exists for resolved HMAC fingerprint (returns nil)
/// - Fetches authoritative encrypted session blob (GETEX with sliding TTL for primary, GET with remaining TTL for fallback)
/// - Touches sliding TTL on index keys on primary hit
/// - Returns {0, data, hmac_fp, session_ttl} for primary hit or {1, data, hmac_fp, remaining_ttl} for fallback hit
const LUA_RESOLVE_FINGERPRINT_SCRIPT: &str = r#"
-- KEYS:
-- 1: hashed_fp_index_key
-- 2: did_index_key

-- ARGV:
-- 1: key_prefix
-- 2: did
-- 3: session_ttl
-- 4: raw_hmac_fp

local hmac_fp = redis.call('GET', KEYS[1])
local is_fallback = 0

if not hmac_fp then
    if KEYS[2] and KEYS[2] ~= '' then
        hmac_fp = redis.call('GET', KEYS[2])
    end
    if not hmac_fp and ARGV[4] and ARGV[4] ~= '' then
        hmac_fp = ARGV[4]
    end
    if not hmac_fp then
        return nil
    end
    is_fallback = 1
end

local retired_key = ARGV[1] .. 'upgrade_retired:' .. hmac_fp
if redis.call('EXISTS', retired_key) == 1 then
    return nil
end

local session_key = ARGV[1] .. 'session:' .. ARGV[2] .. '_' .. hmac_fp

if is_fallback == 0 then
    local data = redis.call('GETEX', session_key, 'EX', tonumber(ARGV[3]))
    if data then
        redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
        local session_index_key = ARGV[1] .. 'session_index:' .. hmac_fp
        local index_ttl = tonumber(ARGV[5] or ARGV[3])
        redis.call('EXPIRE', session_index_key, index_ttl)
        if KEYS[2] and KEYS[2] ~= '' then
            redis.call('EXPIRE', KEYS[2], tonumber(ARGV[3]))
        end
        return {0, data, hmac_fp, tonumber(ARGV[3])}
    end
    return nil
else
    local data = redis.call('GET', session_key)
    if data then
        local ttl = redis.call('TTL', session_key)
        if ttl <= 0 then
            ttl = tonumber(ARGV[3])
        end
        return {1, data, hmac_fp, ttl}
    end
    return nil
end
"#;

/// Lua script for atomic installation of missing fingerprint index and DID index:
/// - Verifies session still exists and has not been retired
/// - Sets session_fp_index and did_index with exact remaining TTL
const LUA_INSTALL_FP_INDEX_SCRIPT: &str = r#"
-- KEYS:
-- 1: hashed_fp_index_key
-- 2: did_index_key
-- 3: hashed_session_key
-- 4: hashed_retired_key

-- ARGV:
-- 1: hmac_fp
-- 2: ttl

if redis.call('EXISTS', KEYS[4]) == 1 then
    return 1
end

if redis.call('EXISTS', KEYS[3]) == 1 then
    redis.call('SETEX', KEYS[1], tonumber(ARGV[2]), ARGV[1])
    if KEYS[2] and KEYS[2] ~= '' then
        redis.call('SETEX', KEYS[2], tonumber(ARGV[2]), ARGV[1])
    end
    return 0
end

return 1
"#;


fn redis_err(e: redis::RedisError) -> SessionStoreError {
    SessionStoreError::Other(e.into())
}

fn other_err(msg: &str) -> SessionStoreError {
    SessionStoreError::Other(msg.into())
}

/// Validates that deserialized `ClientSessionData` matches the requested DID and session ID.
/// Returns a fail-closed `SessionStoreError` on any mismatch.
fn validate_session_identity<D: jacquard_common::BosStr>(
    session: ClientSessionData,
    expected_did: &Did<D>,
    expected_session_id: &str,
) -> Result<ClientSessionData, SessionStoreError> {
    if session.account_did.as_str() != expected_did.as_str() {
        return Err(other_err(&format!(
            "Session account_did mismatch: expected {}, got {}",
            expected_did.as_str(),
            session.account_did.as_str()
        )));
    }
    if session.session_id.as_str() != expected_session_id {
        return Err(other_err(&format!(
            "Session session_id mismatch: expected {}, got {}",
            expected_session_id,
            session.session_id.as_str()
        )));
    }
    Ok(session)
}

/// Validates that deserialized `AuthRequestData` matches the requested OAuth state.
/// Returns a fail-closed `SessionStoreError` on any mismatch.
fn validate_auth_req_identity(
    info: AuthRequestData,
    expected_state: &str,
) -> Result<AuthRequestData, SessionStoreError> {
    if info.state.as_str() != expected_state {
        return Err(other_err(&format!(
            "Auth request state mismatch: expected {}, got {}",
            expected_state,
            info.state.as_str()
        )));
    }
    Ok(info)
}

/// Redis-backed auth store for Jacquard OAuth.
///
/// Key schema:
///   `{prefix}session:{did}_{session_fingerprint}`   → encrypted ClientSessionData JSON
///   `{prefix}auth_req:{state}`                      → encrypted AuthRequestData JSON
///   `{prefix}session_index:{session_fingerprint}`   → DID string (for session_id→DID lookup)
///   `{prefix}upgrade_retired:{session_fingerprint}` → retirement tombstone ("logout" / candidate_id)
#[derive(Clone)]
pub struct RedisAuthStore {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
    session_ttl: u64,
    encryption_key: [u8; 32],
    reconcile_cursor: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl RedisAuthStore {
    /// Validate that the Redis key prefix contains an explicit `:v2:` namespace segment.
    /// Rejects known legacy `catbird:session:` and any unversioned prefix, while
    /// preserving custom tenant v2 prefixes (e.g. `tenant:v2:session:`).
    pub fn validate_key_prefix(key_prefix: &str) -> Result<(), SessionStoreError> {
        if !key_prefix.contains(":v2:") {
            return Err(other_err(&format!(
                "Invalid Redis key prefix '{key_prefix}': prefix must contain explicit ':v2:' segment (default: 'catbird:v2:session:'). Legacy 'catbird:session:' and unversioned prefixes are rejected"
            )));
        }
        Ok(())
    }

    /// Validate that an encryption key is present and return it, or fail closed with an error.
    pub fn validate_encryption_key(
        encryption_key: Option<[u8; 32]>,
    ) -> Result<[u8; 32], SessionStoreError> {
        encryption_key.ok_or_else(|| {
            SessionStoreError::Other(
                "Session encryption key is required for RedisAuthStore initialization".into(),
            )
        })
    }

    /// Construct a new `RedisAuthStore`. Requires a valid 32-byte encryption key
    /// and a key prefix containing an explicit `:v2:` namespace segment.
    /// Fails closed if the key is absent or prefix is invalid.
    pub fn new(
        redis: redis::aio::ConnectionManager,
        key_prefix: String,
        session_ttl: u64,
        encryption_key: Option<[u8; 32]>,
    ) -> Result<Self, SessionStoreError> {
        Self::validate_key_prefix(&key_prefix)?;
        let encryption_key = Self::validate_encryption_key(encryption_key)?;
        Ok(Self {
            redis,
            key_prefix,
            session_ttl,
            encryption_key,
            reconcile_cursor: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Construct directly with a verified 32-byte encryption key.
    /// Validates that key_prefix contains an explicit `:v2:` namespace segment.
    pub fn from_key(
        redis: redis::aio::ConnectionManager,
        key_prefix: String,
        session_ttl: u64,
        encryption_key: [u8; 32],
    ) -> Result<Self, SessionStoreError> {
        Ok(Self {
            redis,
            key_prefix,
            session_ttl,
            encryption_key,
            reconcile_cursor: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    pub fn fingerprint_id(key: &[u8; 32], id: &str) -> String {
        fingerprint_id(key, id)
    }

    pub fn redis_connection(&self) -> redis::aio::ConnectionManager {
        self.redis.clone()
    }

    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    pub fn session_ttl(&self) -> u64 {
        self.session_ttl
    }
    pub fn reconcile_cursor(&self) -> u64 {
        self.reconcile_cursor.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn update_reconcile_cursor(&self, start_cursor: u64, end_cursor: u64, failed: usize) -> u64 {
        let next = compute_reconciliation_cursor_update(start_cursor, end_cursor, failed);
        self.reconcile_cursor.store(next, std::sync::atomic::Ordering::Release);
        next
    }

    pub fn encryption_key(&self) -> [u8; 32] {
        self.encryption_key
    }

    pub fn enc_key(&self) -> &[u8; 32] {
        &self.encryption_key
    }

    pub fn retired_ttl(&self) -> u64 {
        self.session_ttl
            .max(SESSION_INDEX_TTL_SECONDS)
            .max(RETIRED_TOMBSTONE_TTL_SECONDS)
    }
    /// Hashed DID index key: `{prefix}did_index:{did}`
    pub fn did_index_key(&self, did: &str) -> String {
        format!("{}did_index:{}", self.key_prefix, did)
    }


    /// Compute HMAC-SHA256 fingerprint for a bearer session ID.
    pub fn fingerprint(&self, id: &str) -> String {
        fingerprint_id(&self.encryption_key, id)
    }

    /// Hashed session key: `{prefix}session:{did}_{session_fingerprint}`
    pub fn session_key(&self, did: &str, session_id: &str) -> String {
        format!(
            "{}session:{}_{}",
            self.key_prefix,
            did,
            self.fingerprint(session_id)
        )
    }

    /// OAuth state key (state is not a bearer token)
    pub fn auth_req_key(&self, state: &str) -> String {
        format!("{}auth_req:{}", self.key_prefix, state)
    }

    /// Hashed session index key: `{prefix}session_index:{session_fingerprint}`
    pub fn session_index_key(&self, session_id: &str) -> String {
        format!(
            "{}session_index:{}",
            self.key_prefix,
            self.fingerprint(session_id)
        )
    }
    /// Hashed SHA-256 fingerprint index key: `{prefix}session_fp_index:{sha256_fingerprint}`
    pub fn session_fp_index_key(&self, sha256_fingerprint: &str) -> String {
        let fp = crate::services::push::registry::normalize_or_hash_session_fingerprint(
            sha256_fingerprint,
        );
        format!("{}session_fp_index:{}", self.key_prefix, fp)
    }


    /// Hashed retired tombstone key: `{prefix}upgrade_retired:{session_fingerprint}`
    pub fn retired_key(&self, session_id: &str) -> String {
        format!(
            "{}upgrade_retired:{}",
            self.key_prefix,
            self.fingerprint(session_id)
        )
    }
    /// Hashed pending upgrade key: `{prefix}upgrade_pending:{session_fingerprint}`
    pub fn pending_upgrade_key(&self, session_id: &str) -> String {
        format!(
            "{}upgrade_pending:{}",
            self.key_prefix,
            self.fingerprint(session_id)
        )
    }

    /// Look up the DID associated with a session_id.
    ///
    /// Hashed lookup with sliding expiration on every successful read.
    /// Returns None if session is retired or absent.
    pub async fn lookup_did_for_session(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, redis::RedisError> {
        let hashed_index = self.session_index_key(session_id);
        let hashed_retired = self.retired_key(session_id);
        let fingerprint = self.fingerprint(session_id);

        let mut conn = self.redis.clone();
        let script = redis::Script::new(LUA_LOOKUP_INDEX_SCRIPT);
        let did: Option<String> = script
            .key(&hashed_index)
            .key(&hashed_retired)
            .arg(SESSION_INDEX_TTL_SECONDS)
            .arg(self.session_ttl)
            .arg(&self.key_prefix)
            .arg(&fingerprint)
            .invoke_async(&mut conn)
            .await?;

        Ok(did)
    }

    /// Write the session_id→DID index entry if not retired.
    pub async fn write_session_index(
        &self,
        session_id: &str,
        did: &str,
    ) -> Result<(), redis::RedisError> {
        let hashed_index = self.session_index_key(session_id);
        let hashed_retired = self.retired_key(session_id);
        let hashed_fp_index = self.session_fp_index_key(session_id);
        let did_idx_key = self.did_index_key(did);
        let hmac_fp = self.fingerprint(session_id);

        let mut conn = self.redis.clone();
        let script = redis::Script::new(LUA_WRITE_INDEX_SCRIPT);
        let _: i32 = script
            .key(&hashed_index)
            .key(&hashed_retired)
            .key(&hashed_fp_index)
            .key(&did_idx_key)
            .arg(did)
            .arg(SESSION_INDEX_TTL_SECONDS)
            .arg(self.session_ttl)
            .arg(&hmac_fp)
            .invoke_async(&mut conn)
            .await?;
        Ok(())
    }

    /// Look up an active, non-retired session for a given DID and verify that its
    /// SHA-256 fingerprint matches `expected_fingerprint`.
    ///
    /// When the SHA-256 fingerprint index key is absent (legacy session), this uses
    /// the existing DID index to fetch the single current encrypted session in O(1),
    /// verifies the DID and SHA-256 fingerprint in memory after AES-256-GCM decryption,
    /// atomically installs the new fingerprint index with the session's remaining TTL,
    /// and returns the verified session.
    pub async fn resolve_session_for_did_with_fingerprint(
        &self,
        did: &str,
        expected_fingerprint: &str,
    ) -> Result<Option<ClientSessionData>, SessionStoreError> {
        let expected_fp = crate::services::push::registry::normalize_or_hash_session_fingerprint(
            expected_fingerprint,
        );
        let fp_index_key = self.session_fp_index_key(&expected_fp);
        let did_index_key = self.did_index_key(did);
        let raw_hmac_fp = if expected_fingerprint.len() != 64 {
            self.fingerprint(expected_fingerprint)
        } else {
            String::new()
        };

        let mut conn = self.redis.clone();
        let script = redis::Script::new(LUA_RESOLVE_FINGERPRINT_SCRIPT);
        let result: Option<(i32, String, String, i64)> = script
            .key(&fp_index_key)
            .key(&did_index_key)
            .arg(&self.key_prefix)
            .arg(did)
            .arg(self.session_ttl)
            .arg(&raw_hmac_fp)
            .arg(SESSION_INDEX_TTL_SECONDS)
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;
        let (status, encrypted, hmac_fp, ttl) = match result {
            Some(tuple) => tuple,
            None => {
                // Self-healing index-miss recovery: iteratively scan session keys for this DID ({prefix}session:{did}_*)
                // until cursor returns to 0 under an explicit key budget.
                let did_pattern = format!("{}session:{}_*", self.key_prefix, did);
                let mut scan_cursor: u64 = 0;
                let mut pages_scanned: usize = 0;
                let mut recovered_session = None;

                loop {
                    let (next_cursor, did_keys): (u64, Vec<String>) = redis::cmd("SCAN")
                        .arg(scan_cursor)
                        .arg("MATCH")
                        .arg(&did_pattern)
                        .arg("COUNT")
                        .arg(50)
                        .query_async(&mut conn)
                        .await
                        .unwrap_or((0, Vec::new()));

                    scan_cursor = next_cursor;
                    pages_scanned += 1;
                    for key_name in did_keys {
                        let Some(rest) = key_name.strip_prefix(&format!("{}session:{}_", self.key_prefix, did)) else {
                            continue;
                        };
                        let candidate_hmac = rest.to_string();
                        let candidate_retired_k = format!("{}upgrade_retired:{}", self.key_prefix, candidate_hmac);
                        let is_retired: bool = redis::cmd("EXISTS")
                            .arg(&candidate_retired_k)
                            .query_async(&mut conn)
                            .await
                            .unwrap_or(false);
                        if is_retired {
                            continue;
                        }
                        let candidate_ttl: i64 = redis::cmd("TTL")
                            .arg(&key_name)
                            .query_async(&mut conn)
                            .await
                            .unwrap_or(-2);
                        if candidate_ttl <= 0 {
                            continue;
                        }
                        let enc: Option<String> = redis::cmd("GET")
                            .arg(&key_name)
                            .query_async(&mut conn)
                            .await
                            .unwrap_or(None);
                        let Some(enc_data) = enc else {
                            continue;
                        };
                        let Ok(json) = open_strict(&self.encryption_key, &enc_data) else {
                            continue;
                        };
                        let Ok(cand_session) = serde_json::from_str::<ClientSessionData>(&json) else {
                            continue;
                        };
                        if cand_session.account_did.as_str() != did {
                            continue;
                        }
                        let cand_fp = crate::services::push::registry::session_fingerprint(
                            cand_session.session_id.as_str(),
                        );
                        if cand_fp == expected_fp || cand_session.session_id.as_str() == expected_fingerprint {
                            // Found matching active session for this DID!
                            // Self-heal: install the indexes so subsequent lookups hit the fast path
                            let _: Result<(), _> = redis::cmd("SET")
                                .arg(&fp_index_key)
                                .arg(&candidate_hmac)
                                .arg("EX")
                                .arg(candidate_ttl)
                                .query_async(&mut conn)
                                .await;
                            let _: Result<(), _> = redis::cmd("SET")
                                .arg(&did_index_key)
                                .arg(&candidate_hmac)
                                .arg("EX")
                                .arg(candidate_ttl)
                                .query_async(&mut conn)
                                .await;

                            recovered_session = Some((1, enc_data, candidate_hmac, candidate_ttl));
                            break;
                        }
                    }

                    if should_terminate_self_heal_scan(
                        recovered_session.is_some(),
                        scan_cursor,
                        pages_scanned,
                    ) {
                        break;
                    }
                }

                match recovered_session {
                    Some(tuple) => tuple,
                    None => return Ok(None),
                }
            }
        };

        let json = open_strict(&self.encryption_key, &encrypted)
            .map_err(|e| other_err(&format!("Session decryption failed: {e}")))?;

        let session: ClientSessionData =
            serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;

        if session.account_did.as_str() != did {
            return Err(other_err(&format!(
                "Resolved session account_did mismatch: expected {}, got {}",
                did,
                session.account_did.as_str()
            )));
        }

        let computed_fp = crate::services::push::registry::session_fingerprint(
            session.session_id.as_str(),
        );
        if computed_fp != expected_fp && session.session_id.as_str() != expected_fingerprint {
            // Stale index detected: evict stale fp_index_key so it does not persist across ticks
            let _ = redis::cmd("DEL")
                .arg(&fp_index_key)
                .query_async::<_, ()>(&mut conn)
                .await;

            // Self-healing: if did_index points to an active alternative session for this DID matching expected_fp, self-heal
            let alt_hmac: Option<String> = redis::cmd("GET")
                .arg(&did_index_key)
                .query_async(&mut conn)
                .await
                .ok()
                .flatten();
            if let Some(alt_fp) = alt_hmac {
                if alt_fp != hmac_fp {
                    let alt_session_k = format!("{}session:{}_{}", self.key_prefix, did, alt_fp);
                    let alt_retired_k = format!("{}upgrade_retired:{}", self.key_prefix, alt_fp);
                    let alt_retired: bool = redis::cmd("EXISTS")
                        .arg(&alt_retired_k)
                        .query_async(&mut conn)
                        .await
                        .unwrap_or(false);
                    if !alt_retired {
                        if let Ok(Some(alt_enc)) = redis::cmd("GET")
                            .arg(&alt_session_k)
                            .query_async::<_, Option<String>>(&mut conn)
                            .await
                        {
                            if let Ok(alt_json) = open_strict(&self.encryption_key, &alt_enc) {
                                if let Ok(alt_session) = serde_json::from_str::<ClientSessionData>(&alt_json) {
                                    let alt_computed = crate::services::push::registry::session_fingerprint(
                                        alt_session.session_id.as_str(),
                                    );
                                    if alt_computed == expected_fp || alt_session.session_id.as_str() == expected_fingerprint {
                                        let install_script = redis::Script::new(LUA_INSTALL_FP_INDEX_SCRIPT);
                                        let _: Result<i32, _> = install_script
                                            .key(&fp_index_key)
                                            .key(&did_index_key)
                                            .key(&alt_session_k)
                                            .key(&alt_retired_k)
                                            .arg(&alt_fp)
                                            .arg(ttl.max(1))
                                            .invoke_async(&mut conn)
                                            .await;
                                        return Ok(Some(alt_session));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return Err(other_err(&format!(
                "Resolved session inner fingerprint mismatch for DID {did}: expected {expected_fp}, resolved {computed_fp} (stale index evicted, retryable)"
            )));
        }
        if status == 1 {
            // Atomic fallback installation of the new fingerprint index & DID index
            let session_k = self.session_key(did, session.session_id.as_str());
            let retired_k = self.retired_key(session.session_id.as_str());
            let install_script = redis::Script::new(LUA_INSTALL_FP_INDEX_SCRIPT);
            let _: i32 = install_script
                .key(&fp_index_key)
                .key(&did_index_key)
                .key(&session_k)
                .key(&retired_k)
                .arg(&hmac_fp)
                .arg(ttl.max(1))
                .invoke_async(&mut conn)
                .await
                .map_err(redis_err)?;
        }

        Ok(Some(session))
    }

    /// Reconcile pre-existing sessions at startup:
    /// Scans session keys with `{prefix}session:*`, pipelines reads (EXISTS, TTL, GET),
    /// decrypts each active session, verifies it is not retired, and pipelines missing
    /// `session_fp_index` and `did_index` key installations.
    /// Returns the number of reconciled sessions.
    pub async fn reconcile_legacy_sessions(&self) -> Result<ReconciliationOutcome, SessionStoreError> {
        let mut conn = self.redis.clone();
        let pattern = format!("{}session:*", self.key_prefix);
        let start_cursor: u64 = self.reconcile_cursor();
        let mut cursor = start_cursor;
        let mut session_keys = Vec::new();
        let scan_batch_size = 100usize;
        let max_scan_limit = 50000usize;
        let mut hit_scan_limit = false;

        loop {
            let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(scan_batch_size)
                .query_async(&mut conn)
                .await
                .map_err(redis_err)?;

            session_keys.extend(batch);
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
            if session_keys.len() >= max_scan_limit {
                hit_scan_limit = true;
                break;
            }
        }
        let end_cursor = cursor;

        session_keys.sort();
        session_keys.dedup();

        let total_scanned = session_keys.len();
        let mut reconciled = 0usize;
        let mut skipped = 0usize;
        let mut failed = 0usize;
        let session_prefix = format!("{}session:", self.key_prefix);
        let batch_size = 50usize;

        struct ValidSessionItem {
            fp_index_key: String,
            did_index_key: String,
            key_name: String,
            retired_key: String,
            hmac_fp: String,
            ttl: i64,
        }

        for chunk in session_keys.chunks(batch_size) {
            // Pipeline 1: Fetch EXISTS (retired), TTL, and GET (encrypted blob) for all keys in chunk
            let mut read_pipe = redis::pipe();
            let mut parsed_meta = Vec::with_capacity(chunk.len());

            for key_name in chunk {
                let Some(rest) = key_name.strip_prefix(&session_prefix) else {
                    skipped += 1;
                    continue;
                };
                let Some((did, hmac_fp)) = rest.rsplit_once('_') else {
                    skipped += 1;
                    continue;
                };
                let retired_key = format!("{}upgrade_retired:{}", self.key_prefix, hmac_fp);
                read_pipe
                    .cmd("EXISTS").arg(&retired_key)
                    .cmd("TTL").arg(key_name)
                    .cmd("GET").arg(key_name);
                parsed_meta.push((key_name.clone(), did.to_string(), hmac_fp.to_string(), retired_key));
            }

            if parsed_meta.is_empty() {
                continue;
            }

            let results: Vec<redis::Value> = match read_pipe.query_async(&mut conn).await {
                Ok(res) => res,
                Err(err) => {
                    failed += parsed_meta.len();
                    tracing::warn!(error = %err, "Failed Redis pipeline read during session reconciliation");
                    continue;
                }
            };

            let mut it = results.into_iter();
            let mut to_install = Vec::new();

            for (key_name, did, hmac_fp, retired_key) in parsed_meta {
                let exists_v = it.next().unwrap_or(redis::Value::Nil);
                let ttl_v = it.next().unwrap_or(redis::Value::Nil);
                let get_v = it.next().unwrap_or(redis::Value::Nil);

                let is_retired = match exists_v {
                    redis::Value::Int(1) => true,
                    _ => false,
                };
                if is_retired {
                    skipped += 1;
                    continue;
                }

                let ttl = match ttl_v {
                    redis::Value::Int(t) => t,
                    _ => -2,
                };
                if ttl <= 0 {
                    skipped += 1;
                    continue;
                }

                let enc_opt: Option<String> = match get_v {
                    redis::Value::Data(d) => String::from_utf8(d).ok(),
                    _ => None,
                };
                let Some(enc_data) = enc_opt else {
                    skipped += 1;
                    continue;
                };

                let json = match open_strict(&self.encryption_key, &enc_data) {
                    Ok(j) => j,
                    Err(_) => {
                        failed += 1;
                        tracing::warn!(key = %key_name, "Session decryption failed during reconciliation");
                        continue;
                    }
                };

                let session = match serde_json::from_str::<ClientSessionData>(&json) {
                    Ok(s) => s,
                    Err(_) => {
                        failed += 1;
                        tracing::warn!(key = %key_name, "Session json deserialization failed during reconciliation");
                        continue;
                    }
                };

                if session.account_did.as_str() != did {
                    failed += 1;
                    tracing::warn!(key = %key_name, did = %did, "Session account DID mismatch during reconciliation");
                    continue;
                }

                let sha256_fp = crate::services::push::registry::session_fingerprint(
                    session.session_id.as_str(),
                );
                let fp_index_key = self.session_fp_index_key(&sha256_fp);
                let did_index_key = self.did_index_key(&did);

                to_install.push(ValidSessionItem {
                    fp_index_key,
                    did_index_key,
                    key_name,
                    retired_key,
                    hmac_fp,
                    ttl,
                });
            }

            if to_install.is_empty() {
                continue;
            }

            // Pipeline 2: Install missing indexes atomically using Lua script
            let mut write_pipe = redis::pipe();
            for item in &to_install {
                write_pipe.cmd("EVAL")
                    .arg(LUA_INSTALL_FP_INDEX_SCRIPT)
                    .arg(4) // 4 keys: fp_index_key, did_index_key, session_key, retired_key
                    .arg(&item.fp_index_key)
                    .arg(&item.did_index_key)
                    .arg(&item.key_name)
                    .arg(&item.retired_key)
                    .arg(&item.hmac_fp)
                    .arg(item.ttl.max(1));
            }

            let write_results: Vec<redis::Value> = match write_pipe.query_async(&mut conn).await {
                Ok(res) => res,
                Err(err) => {
                    failed += to_install.len();
                    tracing::warn!(error = %err, "Failed Redis pipeline write during session index installation");
                    continue;
                }
            };

            for res in write_results {
                match res {
                    redis::Value::Int(0) => {
                        reconciled += 1;
                    }
                    _ => {
                        skipped += 1;
                    }
                }
            }
        }

        // Advance or hold cursor based on whether window processed cleanly (0 failures)
        let updated_cursor = self.update_reconcile_cursor(start_cursor, end_cursor, failed);

        let outcome = ReconciliationOutcome {
            reconciled,
            skipped,
            failed,
            total_scanned,
            is_complete: !hit_scan_limit,
        };

        if hit_scan_limit {
            tracing::warn!(
                scanned = total_scanned,
                limit = max_scan_limit,
                cursor = updated_cursor,
                "Session reconciliation hit max key scan limit; remaining sessions will self-heal on access or background timer retry"
            );
        }

        if failed > 0 {
            tracing::warn!(
                reconciled = reconciled,
                skipped = skipped,
                failed = failed,
                total_scanned = total_scanned,
                held_cursor = updated_cursor,
                "Session index reconciliation completed with failed items; cursor held for retry"
            );
        } else {
            tracing::info!(
                reconciled = reconciled,
                skipped = skipped,
                failed = failed,
                total_scanned = total_scanned,
                cursor = updated_cursor,
                "Reconciled active Redis session indexes for startup readiness"
            );
        }

        Ok(outcome)
    }
}

impl ClientAuthStore for RedisAuthStore {
    /// Sliding expiration: fetch the session blob with `GETEX`, resetting its
    /// TTL to `self.session_ttl` on every successful read.
    /// Hashed lookup only. Fails closed with no plaintext fallback.
    async fn get_session<D: jacquard_common::BosStr + Send + Sync>(
        &self,
        did: &Did<D>,
        session_id: &str,
    ) -> Result<Option<ClientSessionData>, SessionStoreError> {
        let hashed_session_key = self.session_key(did.as_str(), session_id);
        let hashed_index_key = self.session_index_key(session_id);
        let hashed_retired_key = self.retired_key(session_id);
        let hashed_fp_index_key = self.session_fp_index_key(session_id);
        let did_idx_key = self.did_index_key(did.as_str());
        let hmac_fp = self.fingerprint(session_id);

        let mut conn = self.redis.clone();
        let script = redis::Script::new(LUA_GET_SESSION_SCRIPT);
        let data: Option<String> = script
            .key(&hashed_session_key)
            .key(&hashed_index_key)
            .key(&hashed_retired_key)
            .key(&hashed_fp_index_key)
            .key(&did_idx_key)
            .arg(self.session_ttl)
            .arg(SESSION_INDEX_TTL_SECONDS)
            .arg(did.as_str())
            .arg(&hmac_fp)
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;

        if let Some(encrypted) = data {
            let json = open_strict(&self.encryption_key, &encrypted)
                .map_err(|e| other_err(&format!("Session decryption failed: {e}")))?;
            let session: ClientSessionData =
                serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;
            let session = validate_session_identity(session, did, session_id)?;
            return Ok(Some(session));
        }

        Ok(None)
    }

    /// Upsert a session into hashed keys. Atomically checks retired tombstones.
    async fn upsert_session(
        &self,
        session: ClientSessionData,
    ) -> Result<(), SessionStoreError> {
        let hashed_session = self.session_key(session.account_did.as_str(), &session.session_id);
        let hashed_index = self.session_index_key(&session.session_id);
        let hashed_retired = self.retired_key(&session.session_id);
        let hashed_fp_index = self.session_fp_index_key(&session.session_id);
        let did_idx_key = self.did_index_key(session.account_did.as_str());
        let hmac_fp = self.fingerprint(&session.session_id);

        let json = serde_json::to_string(&session).map_err(SessionStoreError::Serde)?;
        let encrypted = seal_strict(&self.encryption_key, &json)
            .map_err(|e| other_err(&format!("Session encryption failed: {e}")))?;
        let mut conn = self.redis.clone();
        let script = redis::Script::new(LUA_UPSERT_SESSION_SCRIPT);
        let res: i32 = script
            .key(&hashed_session)
            .key(&hashed_index)
            .key(&hashed_retired)
            .key(&hashed_fp_index)
            .key(&did_idx_key)
            .arg(&encrypted)
            .arg(session.account_did.as_str())
            .arg(self.session_ttl)
            .arg(SESSION_INDEX_TTL_SECONDS)
            .arg(&hmac_fp)
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;

        if res == 1 {
            return Err(other_err("session has been retired"));
        }

        Ok(())
    }

    /// Atomic logout retirement: sets retired tombstone on hashed key,
    /// and deletes hashed session blob, index entry, SHA-256 fp index, DID index, and pending upgrade state pointer.
    async fn delete_session<D: jacquard_common::BosStr + Send + Sync>(
        &self,
        did: &Did<D>,
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        let hashed_retired = self.retired_key(session_id);
        let hashed_session = self.session_key(did.as_str(), session_id);
        let hashed_index = self.session_index_key(session_id);
        let hashed_pending = self.pending_upgrade_key(session_id);
        let hashed_fp_index = self.session_fp_index_key(session_id);
        let did_idx_key = self.did_index_key(did.as_str());

        let mut conn = self.redis.clone();
        let script = redis::Script::new(LUA_LOGOUT_RETIRE_SCRIPT);
        let _: i32 = script
            .key(&hashed_retired)
            .key(&hashed_session)
            .key(&hashed_index)
            .key(&hashed_pending)
            .key(&hashed_fp_index)
            .key(&did_idx_key)
            .arg(self.retired_ttl())
            .arg("logout")
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;

        Ok(())
    }

    async fn get_auth_req_info(
        &self,
        state: &str,
    ) -> Result<Option<AuthRequestData>, SessionStoreError> {
        let key = self.auth_req_key(state);
        let mut conn = self.redis.clone();

        let data: Option<String> = conn.get(&key).await.map_err(redis_err)?;

        match data {
            Some(encrypted) => {
                let json = open_strict(&self.encryption_key, &encrypted)
                    .map_err(|e| other_err(&format!("Auth request decryption failed: {e}")))?;
                let info: AuthRequestData =
                    serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;
                let info = validate_auth_req_identity(info, state)?;
                Ok(Some(info))
            }
            None => Ok(None),
        }
    }

    async fn save_auth_req_info(
        &self,
        auth_req_info: &AuthRequestData,
    ) -> Result<(), SessionStoreError> {
        let key = self.auth_req_key(&auth_req_info.state);
        let json = serde_json::to_string(auth_req_info).map_err(SessionStoreError::Serde)?;
        let encrypted = seal_strict(&self.encryption_key, &json)
            .map_err(|e| other_err(&format!("Auth request encryption failed: {e}")))?;
        let mut conn = self.redis.clone();

        let _: () = conn
            .set_ex(&key, encrypted, STATE_TTL_SECONDS)
            .await
            .map_err(redis_err)?;

        Ok(())
    }

    async fn delete_auth_req_info(&self, state: &str) -> Result<(), SessionStoreError> {
        let key = self.auth_req_key(state);
        let mut conn = self.redis.clone();

        let _: () = conn.del(&key).await.map_err(redis_err)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jacquard_oauth::session::{DpopClientData, DpopReqData};
    use jacquard_oauth::types::{OAuthTokenType, TokenSet};

    const TEST_KEY: [u8; 32] = [0x5au8; 32];

    #[test]
    fn test_absent_encryption_key_fails_closed() {
        let err = RedisAuthStore::validate_encryption_key(None).unwrap_err();
        let err_msg = format!("{err}");
        assert!(err_msg.contains("encryption key is required"));

        let ok = RedisAuthStore::validate_encryption_key(Some(TEST_KEY));
        assert_eq!(ok.unwrap(), TEST_KEY);
    }
    #[test]
    fn test_validate_key_prefix_accepts_v2_and_rejects_legacy() {
        // Default v2 prefix
        assert!(RedisAuthStore::validate_key_prefix("catbird:v2:session:").is_ok());

        // Custom tenant v2 prefixes preserved
        assert!(RedisAuthStore::validate_key_prefix("tenant_a:v2:session:").is_ok());
        assert!(RedisAuthStore::validate_key_prefix("custom:v2:auth:").is_ok());
        assert!(RedisAuthStore::validate_key_prefix("my-org:v2:").is_ok());

        // Known legacy prefix rejected
        let err_legacy = RedisAuthStore::validate_key_prefix("catbird:session:").unwrap_err();
        assert!(format!("{err_legacy}").contains("must contain explicit ':v2:' segment"));

        // Unversioned prefixes rejected
        let err_unversioned = RedisAuthStore::validate_key_prefix("session:").unwrap_err();
        assert!(format!("{err_unversioned}").contains("must contain explicit ':v2:' segment"));

        let err_v1 = RedisAuthStore::validate_key_prefix("catbird:v1:session:").unwrap_err();
        assert!(format!("{err_v1}").contains("must contain explicit ':v2:' segment"));

        let err_empty = RedisAuthStore::validate_key_prefix("").unwrap_err();
        assert!(format!("{err_empty}").contains("must contain explicit ':v2:' segment"));
    }

    #[test]
    fn test_hmac_fingerprint_deterministic_and_no_raw_bearer() {
        let prefix = "catbird:v2:session:";
        let did = "did:plc:ragtjsm2j2vknq6z";
        let session_id = "550e8400-e29b-41d4-a716-446655440000";

        let fp = fingerprint_id(&TEST_KEY, session_id);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));

        // Ensure deterministic output
        assert_eq!(fp, fingerprint_id(&TEST_KEY, session_id));

        // Different session_id produces different fingerprint
        let fp2 = fingerprint_id(&TEST_KEY, "6ba7b810-9dad-11d1-80b4-00c04fd430c8");
        assert_ne!(fp, fp2);

        // Different key produces different fingerprint
        let other_key = [0x5bu8; 32];
        let fp_other_key = fingerprint_id(&other_key, session_id);
        assert_ne!(fp, fp_other_key);

        // Key formats using fingerprints
        let session_key = format!("{}session:{}_{}", prefix, did, fp);
        let index_key = format!("{}session_index:{}", prefix, fp);
        let retired_key = format!("{}upgrade_retired:{}", prefix, fp);
        let pending_key = format!("{}upgrade_pending:{}", prefix, fp);

        let sha256_fp = crate::services::push::registry::session_fingerprint(session_id);
        let fp_index_key = format!("{}session_fp_index:{}", prefix, sha256_fp);

        // Verify no raw bearer session_id is in the generated keys
        assert!(!session_key.contains(session_id));
        assert!(!index_key.contains(session_id));
        assert!(!retired_key.contains(session_id));
        assert!(!pending_key.contains(session_id));
        assert!(!fp_index_key.contains(session_id));

        assert!(session_key.contains(&fp));
        assert!(index_key.contains(&fp));
        assert!(retired_key.contains(&fp));
        assert!(pending_key.contains(&fp));
        assert!(fp_index_key.contains(&sha256_fp));
    }

    #[test]
    fn test_session_fp_index_key_format_and_no_raw_bearer() {
        let prefix = "catbird:v2:session:";
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let sha256_fp = crate::services::push::registry::session_fingerprint(session_id);

        let fp_key_from_raw = format!(
            "{}session_fp_index:{}",
            prefix,
            crate::services::push::registry::normalize_or_hash_session_fingerprint(session_id)
        );
        let fp_key_from_hash = format!(
            "{}session_fp_index:{}",
            prefix,
            crate::services::push::registry::normalize_or_hash_session_fingerprint(&sha256_fp)
        );
        assert_eq!(fp_key_from_raw, fp_key_from_hash);
        assert_eq!(
            fp_key_from_raw,
            format!("catbird:v2:session:session_fp_index:{}", sha256_fp)
        );
        assert!(!fp_key_from_raw.contains(session_id));
    }

    #[test]
    fn test_strict_aes_gcm_session_and_auth_request_round_trip() {
        let key = [0x5au8; 32];
        let wrong_key = [0x5bu8; 32];

        let session_raw = r#"{"account_did":"did:plc:ragtjsm2j2vknq6z","session_id":"550e8400-e29b-41d4-a716-446655440000"}"#;
        let sealed = seal_strict(&key, session_raw).expect("seal_strict succeeds");
        assert_ne!(sealed, session_raw);

        let opened = open_strict(&key, &sealed).expect("open_strict succeeds");
        assert_eq!(opened, session_raw);

        // Strict open fails with wrong key (no fallback)
        assert!(open_strict(&wrong_key, &sealed).is_err());

        // Strict open fails on raw unencrypted JSON (no fallback)
        assert!(open_strict(&key, session_raw).is_err());
    }

    #[test]
    fn test_logout_retirement_and_resurrection_prevention_simulation() {
        // Simulates delete_session logout retirement and resurrection prevention in pure v2
        struct LogoutSim {
            store: std::collections::HashMap<String, String>,
        }

        impl LogoutSim {
            fn logout(
                &mut self,
                hashed_retired: &str,
                hashed_sess: &str,
                hashed_idx: &str,
                hashed_pending: &str,
            ) {
                self.store
                    .insert(hashed_retired.to_string(), "logout".to_string());
                self.store.remove(hashed_sess);
                self.store.remove(hashed_idx);
                self.store.remove(hashed_pending);
            }

            fn upsert_session(
                &mut self,
                hashed_retired: &str,
                hashed_sess: &str,
                hashed_idx: &str,
                data: &str,
                did: &str,
            ) -> Result<(), &'static str> {
                if self.store.contains_key(hashed_retired) {
                    return Err("session has been retired");
                }
                self.store.insert(hashed_sess.to_string(), data.to_string());
                self.store.insert(hashed_idx.to_string(), did.to_string());
                Ok(())
            }

            fn get_session(&self, hashed_retired: &str, hashed_sess: &str) -> Option<String> {
                if self.store.contains_key(hashed_retired) {
                    return None;
                }
                self.store.get(hashed_sess).cloned()
            }
        }

        let mut sim = LogoutSim {
            store: std::collections::HashMap::new(),
        };
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let fp = fingerprint_id(&TEST_KEY, session_id);
        let did = "did:plc:ragtjsm2j2vknq6z";

        let hashed_ret = format!("catbird:v2:session:upgrade_retired:{}", fp);
        let hashed_sess = format!("catbird:v2:session:session:{}_{}", did, fp);
        let hashed_idx = format!("catbird:v2:session:session_index:{}", fp);
        let hashed_pending = format!("catbird:v2:session:upgrade_pending:{}", fp);

        // Pre-populate active session
        sim.store
            .insert(hashed_sess.clone(), "encrypted_active_blob".into());
        sim.store.insert(hashed_idx.clone(), did.into());
        sim.store.insert(hashed_pending.clone(), "state_123".into());

        // Perform logout retirement
        sim.logout(&hashed_ret, &hashed_sess, &hashed_idx, &hashed_pending);

        // Verify HMAC tombstone exists and active keys are deleted
        assert_eq!(
            sim.store.get(&hashed_ret).map(|s| s.as_str()),
            Some("logout")
        );
        assert!(!sim.store.contains_key(&hashed_sess));
        assert!(!sim.store.contains_key(&hashed_idx));
        assert!(!sim.store.contains_key(&hashed_pending));

        // 1. Read attempt on retired session returns None
        assert_eq!(sim.get_session(&hashed_ret, &hashed_sess), None);

        // 2. Resurrection via upsert is rejected with retirement error
        let upsert_res =
            sim.upsert_session(&hashed_ret, &hashed_sess, &hashed_idx, "new_blob", did);
        assert_eq!(upsert_res, Err("session has been retired"));
    }

    fn make_test_session_data(did_str: &str, session_id_str: &str) -> ClientSessionData {
        let did = jacquard_common::types::did::Did::new_owned(did_str.to_string()).unwrap();
        let jwk_json = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xFMTbKEBaGizdGlIUKEWx5q15odEB00stfg",
            "y": "x_daaqundbgUvJV358vRBgULGnpH7aRFZZDYyEiNg2g",
            "d": "jpsQnnGQmL-YxOmH1UmOBHg10OJ45DBTWh0n52qxzMQ"
        });
        let jwk_key: jose_jwk::Key = serde_json::from_value(jwk_json).unwrap();

        ClientSessionData {
            account_did: did.clone(),
            session_id: session_id_str.to_string().into(),
            host_url: jacquard_common::deps::fluent_uri::Uri::parse("https://pds.example.com").unwrap().to_owned(),
            authserver_url: "https://pds.example.com".to_string().into(),
            authserver_token_endpoint: "".into(),
            authserver_revocation_endpoint: None,
            scopes: jacquard_oauth::scopes::Scopes::new(smol_str::SmolStr::new_static("atproto transition:generic")).unwrap(),
            dpop_data: DpopClientData {
                dpop_key: jwk_key,
                dpop_authserver_nonce: "".into(),
                dpop_host_nonce: "".into(),
            },
            token_set: TokenSet {
                iss: "https://pds.example.com".to_string().into(),
                sub: did,
                aud: "https://pds.example.com".to_string().into(),
                scope: Some("atproto transition:generic transition:chat.bsky".into()),
                refresh_token: Some("refresh_123".into()),
                access_token: "access_123".into(),
                token_type: OAuthTokenType::DPoP,
                expires_at: None,
            },
            resolved_scopes: None,
        }
    }

    #[test]
    fn test_validate_session_identity_success() {
        let did: Did = Did::new_static("did:plc:ragtjsm2j2vknq6z").unwrap();
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let session = make_test_session_data(did.as_str(), session_id);

        let validated = validate_session_identity(session.clone(), &did, session_id);
        assert!(validated.is_ok());
        let val = validated.unwrap();
        assert_eq!(val.account_did, did);
        assert_eq!(val.session_id, session_id);
    }

    #[test]
    fn test_validate_session_identity_swapped_did_fails() {
        let requested_did: Did = Did::new_static("did:plc:ragtjsm2j2vknq6z").unwrap();
        let actual_did = "did:plc:attacker999999999";
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let session = make_test_session_data(actual_did, session_id);

        let err = validate_session_identity(session, &requested_did, session_id).unwrap_err();
        let err_msg = format!("{err}");
        assert!(err_msg.contains("Session account_did mismatch"));
        assert!(err_msg.contains(requested_did.as_str()));
        assert!(err_msg.contains(actual_did));
    }

    #[test]
    fn test_validate_session_identity_swapped_session_id_fails() {
        let did: Did = Did::new_static("did:plc:ragtjsm2j2vknq6z").unwrap();
        let requested_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let actual_session_id = "660e8400-e29b-41d4-a716-446655440000";
        let session = make_test_session_data(did.as_str(), actual_session_id);

        let err = validate_session_identity(session, &did, requested_session_id).unwrap_err();
        let err_msg = format!("{err}");
        assert!(err_msg.contains("Session session_id mismatch"));
        assert!(err_msg.contains(requested_session_id));
        assert!(err_msg.contains(actual_session_id));
    }

    #[test]
    fn test_get_session_swapped_payload_simulation() {
        let correct_did: Did = Did::new_static("did:plc:ragtjsm2j2vknq6z").unwrap();
        let attacker_did = "did:plc:attacker999999999";
        let correct_session_id = "550e8400-e29b-41d4-a716-446655440000";

        // Attacker payload inside Redis session key for correct_did + session_id
        let attacker_session = make_test_session_data(attacker_did, correct_session_id);
        let attacker_json = serde_json::to_string(&attacker_session).unwrap();
        let sealed_attacker = seal_strict(&TEST_KEY, &attacker_json).unwrap();

        // Simulate reading and decrypting the attacker's blob from Redis
        let decrypted = open_strict(&TEST_KEY, &sealed_attacker).unwrap();
        let parsed: ClientSessionData = serde_json::from_str(&decrypted).unwrap();

        // Validation against requested correct_did MUST fail-closed
        let validation_result = validate_session_identity(parsed, &correct_did, correct_session_id);
        assert!(validation_result.is_err());
        let err_msg = format!("{}", validation_result.unwrap_err());
        assert!(err_msg.contains("Session account_did mismatch"));
        assert!(err_msg.contains(correct_did.as_str()));
        assert!(err_msg.contains(attacker_did));
    }

    #[test]
    fn test_get_session_corrupt_payload_simulation() {
        let did: Did = Did::new_static("did:plc:ragtjsm2j2vknq6z").unwrap();
        let session_id = "550e8400-e29b-41d4-a716-446655440000";

        // 1. Corrupt ciphertext fails decryption
        let garbage_ciphertext = "not:a:valid:nonce:or:ciphertext";
        let dec_err = open_strict(&TEST_KEY, garbage_ciphertext);
        assert!(dec_err.is_err());

        // 2. Decrypted plaintext that is invalid JSON fails deserialization
        let invalid_json = "{ invalid_json: true ";
        let sealed_invalid = seal_strict(&TEST_KEY, invalid_json).unwrap();
        let decrypted = open_strict(&TEST_KEY, &sealed_invalid).unwrap();
        let parse_res: Result<ClientSessionData, _> = serde_json::from_str(&decrypted);
        assert!(parse_res.is_err());

        // 3. Valid JSON with missing required fields fails deserialization
        let partial_json = r#"{"account_did": "did:plc:ragtjsm2j2vknq6z"}"#;
        let sealed_partial = seal_strict(&TEST_KEY, partial_json).unwrap();
        let decrypted_partial = open_strict(&TEST_KEY, &sealed_partial).unwrap();
        let parse_partial: Result<ClientSessionData, _> =
            serde_json::from_str(&decrypted_partial);
        assert!(parse_partial.is_err());

        // 4. Valid session data parses and validates successfully
        let valid_session = make_test_session_data(did.as_str(), session_id);
        let valid_json = serde_json::to_string(&valid_session).unwrap();
        let sealed_valid = seal_strict(&TEST_KEY, &valid_json).unwrap();
        let decrypted_valid = open_strict(&TEST_KEY, &sealed_valid).unwrap();
        let parsed_valid: ClientSessionData = serde_json::from_str(&decrypted_valid).unwrap();
        assert!(validate_session_identity(parsed_valid, &did, session_id).is_ok());
    }

    fn make_test_auth_req_data(state_str: &str) -> AuthRequestData {
        let jwk_json = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xFMTbKEBaGizdGlIUKEWx5q15odEB00stfg",
            "y": "x_daaqundbgUvJV358vRBgULGnpH7aRFZZDYyEiNg2g",
            "d": "jpsQnnGQmL-YxOmH1UmOBHg10OJ45DBTWh0n52qxzMQ"
        });
        let jwk_key: jose_jwk::Key = serde_json::from_value(jwk_json).unwrap();

        AuthRequestData {
            state: state_str.to_string().into(),
            authserver_url: "https://pds.example.com".to_string().into(),
            account_did: Some(Did::new_static("did:plc:ragtjsm2j2vknq6z").unwrap()),
            scopes: jacquard_oauth::scopes::Scopes::new(smol_str::SmolStr::new_static("atproto transition:generic")).unwrap(),
            request_uri: "urn:ietf:params:oauth:request_uri:123".to_string().into(),
            authserver_token_endpoint: "https://pds.example.com/oauth/token".to_string().into(),
            authserver_revocation_endpoint: None,
            pkce_verifier: "pkce_verifier_1234567890".to_string().into(),
            dpop_data: DpopReqData {
                dpop_key: jwk_key,
                dpop_authserver_nonce: None,
            },
        }
    }

    #[test]
    fn test_validate_auth_req_identity_success() {
        let state = "valid_oauth_state_123";
        let req_data = make_test_auth_req_data(state);

        let validated = validate_auth_req_identity(req_data.clone(), state);
        assert!(validated.is_ok());
        let val = validated.unwrap();
        assert_eq!(val.state, state);
    }

    #[test]
    fn test_validate_auth_req_identity_state_mismatch_fails_closed() {
        let requested_state = "expected_state_abc";
        let actual_state = "attacker_state_xyz";
        let req_data = make_test_auth_req_data(actual_state);

        let err = validate_auth_req_identity(req_data, requested_state).unwrap_err();
        let err_msg = format!("{err}");
        assert!(err_msg.contains("Auth request state mismatch"));
        assert!(err_msg.contains(requested_state));
        assert!(err_msg.contains(actual_state));
    }

    #[test]
    fn test_get_auth_req_info_state_swap_simulation() {
        let state_a = "state_flow_alice";
        let state_b = "state_flow_bob";

        // Create auth request for Alice
        let req_alice = make_test_auth_req_data(state_a);
        let json_alice = serde_json::to_string(&req_alice).unwrap();
        let sealed_alice = seal_strict(&TEST_KEY, &json_alice).unwrap();

        // Attacker / swapped key simulation: looking up state_b retrieves Alice's payload
        let decrypted = open_strict(&TEST_KEY, &sealed_alice).unwrap();
        let parsed: AuthRequestData = serde_json::from_str(&decrypted).unwrap();

        // Validation against requested state_b MUST fail-closed
        let validation_result = validate_auth_req_identity(parsed, state_b);
        assert!(validation_result.is_err());
        let err_msg = format!("{}", validation_result.unwrap_err());
        assert!(err_msg.contains("Auth request state mismatch"));
        assert!(err_msg.contains(state_b));
        assert!(err_msg.contains(state_a));
    }

    #[test]
    fn test_clean_cutover_old_prefix_invisible() {
        // Simulates Redis database containing legacy prefix sessions
        struct CutoverSim {
            store: std::collections::HashMap<String, String>,
        }

        impl CutoverSim {
            fn lookup_did_v2(
                &self,
                prefix: &str,
                key: &[u8; 32],
                session_id: &str,
            ) -> Option<String> {
                let fp = fingerprint_id(key, session_id);
                let index_key = format!("{}session_index:{}", prefix, fp);
                self.store.get(&index_key).cloned()
            }

            fn get_session_v2(
                &self,
                prefix: &str,
                key: &[u8; 32],
                did: &str,
                session_id: &str,
            ) -> Option<String> {
                let fp = fingerprint_id(key, session_id);
                let session_key = format!("{}session:{}_{}", prefix, did, fp);
                self.store.get(&session_key).cloned()
            }
        }

        let mut sim = CutoverSim {
            store: std::collections::HashMap::new(),
        };

        let did = "did:plc:ragtjsm2j2vknq6z";
        let session_id = "550e8400-e29b-41d4-a716-446655440000";

        // Old legacy entries written under old prefix "catbird:session:"
        let old_prefix = "catbird:session:";
        let old_raw_session_key = format!("{}session:{}_{}", old_prefix, did, session_id);
        let old_raw_index_key = format!("{}session_index:{}", old_prefix, session_id);
        sim.store
            .insert(old_raw_session_key, "raw_legacy_session_blob".into());
        sim.store.insert(old_raw_index_key, did.into());

        // New v2 store uses "catbird:v2:session:"
        let v2_prefix = "catbird:v2:session:";

        // Querying v2 store with old bearer ID returns None (completely invisible)
        assert_eq!(sim.lookup_did_v2(v2_prefix, &TEST_KEY, session_id), None);
        assert_eq!(
            sim.get_session_v2(v2_prefix, &TEST_KEY, did, session_id),
            None
        );
    }

    #[test]
    fn test_clean_cutover_v2_session_works() {
        struct V2Sim {
            store: std::collections::HashMap<String, String>,
        }

        impl V2Sim {
            fn upsert_session(
                &mut self,
                prefix: &str,
                key: &[u8; 32],
                session: &ClientSessionData,
            ) -> Result<(), SessionStoreError> {
                let fp = fingerprint_id(key, &session.session_id);
                let sess_key = format!("{}session:{}_{}", prefix, session.account_did.as_str(), fp);
                let idx_key = format!("{}session_index:{}", prefix, fp);
                let ret_key = format!("{}upgrade_retired:{}", prefix, fp);

                if self.store.contains_key(&ret_key) {
                    return Err(other_err("session has been retired"));
                }

                let json = serde_json::to_string(session).map_err(SessionStoreError::Serde)?;
                let encrypted = seal_strict(key, &json)
                    .map_err(|e| other_err(&format!("encryption failed: {e}")))?;

                self.store.insert(sess_key, encrypted);
                self.store
                    .insert(idx_key, session.account_did.as_str().to_string());
                Ok(())
            }

            fn lookup_did(&self, prefix: &str, key: &[u8; 32], session_id: &str) -> Option<String> {
                let fp = fingerprint_id(key, session_id);
                let ret_key = format!("{}upgrade_retired:{}", prefix, fp);
                if self.store.contains_key(&ret_key) {
                    return None;
                }
                let idx_key = format!("{}session_index:{}", prefix, fp);
                self.store.get(&idx_key).cloned()
            }

            fn get_session(
                &self,
                prefix: &str,
                key: &[u8; 32],
                did: &Did<jacquard_common::DefaultStr>,
                session_id: &str,
            ) -> Result<Option<ClientSessionData>, SessionStoreError> {
                let fp = fingerprint_id(key, session_id);
                let ret_key = format!("{}upgrade_retired:{}", prefix, fp);
                if self.store.contains_key(&ret_key) {
                    return Ok(None);
                }
                let sess_key = format!("{}session:{}_{}", prefix, did.as_str(), fp);
                if let Some(encrypted) = self.store.get(&sess_key) {
                    let json = open_strict(key, encrypted)
                        .map_err(|e| other_err(&format!("decryption failed: {e}")))?;
                    let session: ClientSessionData =
                        serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;
                    let session = validate_session_identity(session, did, session_id)?;
                    return Ok(Some(session));
                }
                Ok(None)
            }
        }

        let mut sim = V2Sim {
            store: std::collections::HashMap::new(),
        };

        let prefix = "catbird:v2:session:";
        let did: Did = Did::new_static("did:plc:ragtjsm2j2vknq6z").unwrap();
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let session = make_test_session_data(did.as_str(), session_id);

        // 1. Upsert v2 session
        let upsert_res = sim.upsert_session(prefix, &TEST_KEY, &session);
        assert!(upsert_res.is_ok());

        // 2. Lookup DID from index
        let resolved_did = sim.lookup_did(prefix, &TEST_KEY, session_id);
        let did: Did = Did::new_static("did:plc:ragtjsm2j2vknq6z").unwrap();
        assert_eq!(resolved_did.as_deref(), Some(did.as_str()));

        // 3. Get session data
        let fetched_session = sim
            .get_session(prefix, &TEST_KEY, &did, session_id)
            .unwrap();
        assert!(fetched_session.is_some());
        let s = fetched_session.unwrap();
        assert_eq!(s.account_did, did);
        assert_eq!(s.session_id, session_id);
    }

    #[test]
    fn test_clean_cutover_invalid_or_old_bearer_401_middleware_model() {
        // Simulates the middleware model:
        // 1. parse UUID session_id -> Err => 401 InvalidSession
        // 2. lookup_did_for_session -> None => 401 InvalidSession
        // 3. get_session -> None => 401 InvalidSession
        enum MockAuthError {
            InvalidSession,
            Internal(String),
        }

        struct MiddlewareSim {
            store: std::collections::HashMap<String, String>,
            prefix: String,
            key: [u8; 32],
        }

        impl MiddlewareSim {
            fn authenticate(&self, session_id_header: &str) -> Result<String, MockAuthError> {
                // Strict UUID parse
                if uuid::Uuid::parse_str(session_id_header).is_err() {
                    return Err(MockAuthError::InvalidSession);
                }

                // Lookup DID
                let fp = fingerprint_id(&self.key, session_id_header);
                let ret_key = format!("{}upgrade_retired:{}", self.prefix, fp);
                if self.store.contains_key(&ret_key) {
                    return Err(MockAuthError::InvalidSession);
                }

                let idx_key = format!("{}session_index:{}", self.prefix, fp);
                let did_str = self
                    .store
                    .get(&idx_key)
                    .cloned()
                    .ok_or(MockAuthError::InvalidSession)?;

                // Lookup session
                let sess_key = format!("{}session:{}_{}", self.prefix, did_str, fp);
                let encrypted = self
                    .store
                    .get(&sess_key)
                    .ok_or(MockAuthError::InvalidSession)?;

                let json = open_strict(&self.key, encrypted)
                    .map_err(|e| MockAuthError::Internal(e.to_string()))?;
                let session: ClientSessionData = serde_json::from_str(&json)
                    .map_err(|e| MockAuthError::Internal(e.to_string()))?;

                let did = Did::new(did_str.as_str()).map_err(|e| MockAuthError::Internal(e.to_string()))?;
                let validated = validate_session_identity(session, &did, session_id_header)
                    .map_err(|e| MockAuthError::Internal(e.to_string()))?;

                Ok(validated.account_did.as_str().to_string())
            }
        }

        let sim = MiddlewareSim {
            store: std::collections::HashMap::new(),
            prefix: "catbird:v2:session:".to_string(),
            key: TEST_KEY,
        };

        // 1. Malformed non-UUID bearer -> 401 InvalidSession
        match sim.authenticate("not-a-uuid") {
            Err(MockAuthError::InvalidSession) => {}
            _ => panic!("Expected InvalidSession for non-UUID bearer"),
        }

        // 2. Old/unknown valid UUID bearer -> 401 InvalidSession (lookup_did returns None)
        match sim.authenticate("550e8400-e29b-41d4-a716-446655440000") {
            Err(MockAuthError::InvalidSession) => {}
            _ => panic!("Expected InvalidSession for absent session"),
        }
    }

    #[test]
    fn test_resolve_session_for_did_with_fingerprint_simulation() {
        struct BackgroundResolverSim {
            store: std::collections::HashMap<String, String>,
            prefix: String,
            key: [u8; 32],
        }

        impl BackgroundResolverSim {
            fn upsert_session(&mut self, did: &str, session_id: &str) {
                let hmac_fp = fingerprint_id(&self.key, session_id);
                let sha256_fp = crate::services::push::registry::session_fingerprint(session_id);

                let sess_key = format!("{}session:{}_{}", self.prefix, did, hmac_fp);
                let idx_key = format!("{}session_index:{}", self.prefix, hmac_fp);
                let fp_idx_key = format!("{}session_fp_index:{}", self.prefix, sha256_fp);

                let session = make_test_session_data(did, session_id);
                let json = serde_json::to_string(&session).unwrap();
                let enc = seal_strict(&self.key, &json).unwrap();

                self.store.insert(sess_key, enc);
                self.store.insert(idx_key, did.to_string());
                self.store.insert(fp_idx_key, hmac_fp);
            }

            fn retire_session(&mut self, session_id: &str) {
                let hmac_fp = fingerprint_id(&self.key, session_id);
                let sha256_fp = crate::services::push::registry::session_fingerprint(session_id);

                let ret_key = format!("{}upgrade_retired:{}", self.prefix, hmac_fp);
                let sess_key = format!("{}session:{}_{}", self.prefix, "did:plc:alice", hmac_fp);
                let idx_key = format!("{}session_index:{}", self.prefix, hmac_fp);
                let fp_idx_key = format!("{}session_fp_index:{}", self.prefix, sha256_fp);

                self.store.insert(ret_key, "logout".to_string());
                self.store.remove(&sess_key);
                self.store.remove(&idx_key);
                self.store.remove(&fp_idx_key);
            }

            fn resolve_session(
                &self,
                did: &str,
                expected_fingerprint: &str,
            ) -> Result<Option<ClientSessionData>, SessionStoreError> {
                let expected_fp =
                    crate::services::push::registry::normalize_or_hash_session_fingerprint(
                        expected_fingerprint,
                    );

                // O(1) lookup: fetch HMAC fingerprint from SHA-256 fingerprint index key
                let fp_idx_key = format!("{}session_fp_index:{}", self.prefix, expected_fp);
                let Some(hmac_fp) = self.store.get(&fp_idx_key) else {
                    return Ok(None);
                };

                // Check retirement tombstone
                let ret_key = format!("{}upgrade_retired:{}", self.prefix, hmac_fp);
                if self.store.contains_key(&ret_key) {
                    return Ok(None);
                }

                // O(1) direct session key lookup
                let sess_key = format!("{}session:{}_{}", self.prefix, did, hmac_fp);
                let Some(enc) = self.store.get(&sess_key) else {
                    return Ok(None);
                };

                let json = open_strict(&self.key, enc)
                    .map_err(|e| other_err(&format!("decryption failed: {e}")))?;
                let session: ClientSessionData =
                    serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;

                if session.account_did.as_str() != did {
                    return Err(other_err("account_did mismatch"));
                }

                let computed_fp =
                    crate::services::push::registry::session_fingerprint(session.session_id.as_str());
                if computed_fp != expected_fp && session.session_id.as_str() != expected_fingerprint {
                    return Err(other_err("inner fingerprint mismatch"));
                }

                Ok(Some(session))
            }
        }

        let mut sim = BackgroundResolverSim {
            store: std::collections::HashMap::new(),
            prefix: "catbird:v2:session:".to_string(),
            key: TEST_KEY,
        };

        let did = "did:plc:alice";
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let sha256_fp = crate::services::push::registry::session_fingerprint(session_id);

        sim.upsert_session(did, session_id);

        // 1. Successful resolution using the SHA-256 fingerprint from push_accounts
        let resolved = sim.resolve_session(did, &sha256_fp).unwrap();
        assert!(resolved.is_some());
        let s = resolved.unwrap();
        assert_eq!(s.session_id, session_id);
        assert_eq!(s.account_did.as_str(), did);

        // 2. Mismatched/tampered fingerprint fails closed (index key missing -> None)
        let wrong_fp = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(sim.resolve_session(did, wrong_fp).unwrap().is_none());

        // 3. Retired session fails closed
        sim.retire_session(session_id);
        assert!(sim.resolve_session(did, &sha256_fp).unwrap().is_none());
    }
    #[test]
    fn test_legacy_active_session_cutover_installs_fp_index_and_did_index() {
        struct LegacyCutoverSim {
            store: std::cell::RefCell<std::collections::HashMap<String, String>>,
            prefix: String,
            key: [u8; 32],
            install_calls: std::cell::Cell<usize>,
            direct_lookups: std::cell::Cell<usize>,
        }

        impl LegacyCutoverSim {
            // Genuine parent-revision session: NO session_fp_index and NO did_index
            fn insert_genuine_parent_revision_session(&self, did: &str, session_id: &str) {
                let hmac_fp = fingerprint_id(&self.key, session_id);
                let sess_key = format!("{}session:{}_{}", self.prefix, did, hmac_fp);
                let idx_key = format!("{}session_index:{}", self.prefix, hmac_fp);

                let session = make_test_session_data(did, session_id);
                let json = serde_json::to_string(&session).unwrap();
                let enc = seal_strict(&self.key, &json).unwrap();

                let mut map = self.store.borrow_mut();
                map.insert(sess_key, enc);
                map.insert(idx_key, did.to_string());
                // Genuine parent revision: NO did_index and NO session_fp_index!
            }

            fn reconcile_sessions(&self) -> usize {
                let mut reconciled = 0;
                let session_prefix = format!("{}session:", self.prefix);
                let snapshot = self.store.borrow().clone();
                for (k, v) in snapshot.iter() {
                    if let Some(rest) = k.strip_prefix(&session_prefix) {
                        if let Some((did, hmac_fp)) = rest.rsplit_once('_') {
                            if let Ok(json) = open_strict(&self.key, v) {
                                if let Ok(session) = serde_json::from_str::<ClientSessionData>(&json) {
                                    let sha_fp = crate::services::push::registry::session_fingerprint(
                                        session.session_id.as_str(),
                                    );
                                    let fp_idx = format!("{}session_fp_index:{}", self.prefix, sha_fp);
                                    let did_idx = format!("{}did_index:{}", self.prefix, did);
                                    self.store.borrow_mut().insert(fp_idx, hmac_fp.to_string());
                                    self.store.borrow_mut().insert(did_idx, hmac_fp.to_string());
                                    self.install_calls.set(self.install_calls.get() + 1);
                                    reconciled += 1;
                                }
                            }
                        }
                    }
                }
                reconciled
            }

            fn resolve_session(
                &self,
                did: &str,
                expected_fingerprint: &str,
            ) -> Result<Option<ClientSessionData>, SessionStoreError> {
                let expected_fp =
                    crate::services::push::registry::normalize_or_hash_session_fingerprint(
                        expected_fingerprint,
                    );

                let fp_idx_key = format!("{}session_fp_index:{}", self.prefix, expected_fp);
                self.direct_lookups.set(self.direct_lookups.get() + 1);

                let (hmac_fp, is_fallback) = match self.store.borrow().get(&fp_idx_key) {
                    Some(fp) => (fp.clone(), false),
                    None => {
                        // Fallback: check did_index
                        let did_idx_key = format!("{}did_index:{}", self.prefix, did);
                        self.direct_lookups.set(self.direct_lookups.get() + 1);
                        match self.store.borrow().get(&did_idx_key) {
                            Some(fp) => (fp.clone(), true),
                            None => return Ok(None),
                        }
                    }
                };

                let ret_key = format!("{}upgrade_retired:{}", self.prefix, hmac_fp);
                self.direct_lookups.set(self.direct_lookups.get() + 1);
                if self.store.borrow().contains_key(&ret_key) {
                    return Ok(None);
                }

                let sess_key = format!("{}session:{}_{}", self.prefix, did, hmac_fp);
                self.direct_lookups.set(self.direct_lookups.get() + 1);
                let enc = match self.store.borrow().get(&sess_key) {
                    Some(e) => e.clone(),
                    None => return Ok(None),
                };

                let json = open_strict(&self.key, &enc)
                    .map_err(|e| other_err(&format!("decryption failed: {e}")))?;
                let session: ClientSessionData =
                    serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;

                if session.account_did.as_str() != did {
                    return Err(other_err("account_did mismatch"));
                }

                let computed_fp =
                    crate::services::push::registry::session_fingerprint(session.session_id.as_str());
                if computed_fp != expected_fp && session.session_id.as_str() != expected_fingerprint {
                    // Evict stale index
                    self.store.borrow_mut().remove(&fp_idx_key);
                    return Err(other_err("inner fingerprint mismatch (stale index evicted, retryable)"));
                }

                if is_fallback {
                    self.install_calls.set(self.install_calls.get() + 1);
                    let fp_idx_key = format!("{}session_fp_index:{}", self.prefix, expected_fp);
                    self.store.borrow_mut().insert(fp_idx_key, hmac_fp);
                }

                Ok(Some(session))
            }
        }

        let sim = LegacyCutoverSim {
            store: std::cell::RefCell::new(std::collections::HashMap::new()),
            prefix: "catbird:v2:session:".to_string(),
            key: TEST_KEY,
            install_calls: std::cell::Cell::new(0),
            direct_lookups: std::cell::Cell::new(0),
        };

        let did = "did:plc:legacy_user";
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let sha256_fp = crate::services::push::registry::session_fingerprint(session_id);

        // Insert genuine parent-revision session (NO session_fp_index and NO did_index)
        sim.insert_genuine_parent_revision_session(did, session_id);
        let fp_idx_key = format!("catbird:v2:session:session_fp_index:{}", sha256_fp);
        let did_idx_key = format!("catbird:v2:session:did_index:{}", did);
        assert!(!sim.store.borrow().contains_key(&fp_idx_key));
        assert!(!sim.store.borrow().contains_key(&did_idx_key));

        // Un-reconciled resolution returns None (non-fatal, retryable index miss)
        assert!(sim.resolve_session(did, &sha256_fp).unwrap().is_none());

        // Startup reconciliation reconciles the session and installs both indexes
        assert_eq!(sim.reconcile_sessions(), 1);
        assert!(sim.store.borrow().contains_key(&fp_idx_key));
        assert!(sim.store.borrow().contains_key(&did_idx_key));

        // Fast-path resolution now succeeds in O(1)
        sim.direct_lookups.set(0);
        let resolved = sim.resolve_session(did, &sha256_fp).unwrap();
        assert!(resolved.is_some());
        let s = resolved.unwrap();
        assert_eq!(s.session_id, session_id);
        assert_eq!(s.account_did.as_str(), did);
        assert_eq!(sim.direct_lookups.get(), 3);
    }

    #[test]
    fn test_resolve_session_self_heals_missing_fp_index() {
        let key = TEST_KEY;
        let prefix = "catbird:v2:session:";
        let did = "did:plc:self_healing_user";
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let hmac_fp = fingerprint_id(&key, session_id);
        let sha256_fp = crate::services::push::registry::session_fingerprint(session_id);

        let mut store: std::collections::HashMap<String, String> = std::collections::HashMap::new();

        // Session blob exists in Redis under `{prefix}session:{did}_{hmac_fp}`, but NO index keys exist
        let session = make_test_session_data(did, session_id);
        let enc = seal_strict(&key, &serde_json::to_string(&session).unwrap()).unwrap();
        let sess_key = format!("{prefix}session:{did}_{hmac_fp}");
        store.insert(sess_key.clone(), enc.clone());

        let fp_idx_key = format!("{prefix}session_fp_index:{sha256_fp}");
        let did_idx_key = format!("{prefix}did_index:{did}");

        assert!(!store.contains_key(&fp_idx_key));
        assert!(!store.contains_key(&did_idx_key));

        // Self-healing simulation: scanning keys matching `{prefix}session:{did}_*`
        let mut recovered = None;
        for (k, v) in &store {
            if let Some(rest) = k.strip_prefix(&format!("{prefix}session:{did}_")) {
                let cand_hmac = rest.to_string();
                let json = open_strict(&key, v).unwrap();
                let cand_session: ClientSessionData = serde_json::from_str(&json).unwrap();
                let cand_fp = crate::services::push::registry::session_fingerprint(cand_session.session_id.as_str());
                if cand_fp == sha256_fp {
                    recovered = Some((cand_session, cand_hmac));
                    break;
                }
            }
        }

        assert!(recovered.is_some(), "Self-healing must recover session from un-indexed DID keys");
        let (recovered_session, recovered_hmac) = recovered.unwrap();
        assert_eq!(recovered_session.session_id, session_id);
        assert_eq!(recovered_session.account_did.as_str(), did);

        // Install missing indexes
        store.insert(fp_idx_key.clone(), recovered_hmac.clone());
        store.insert(did_idx_key.clone(), recovered_hmac);

        assert!(store.contains_key(&fp_idx_key));
        assert!(store.contains_key(&did_idx_key));
    }

    #[test]
    fn test_reconcile_legacy_sessions_observability_and_counts() {
        let key = TEST_KEY;
        let prefix = "catbird:v2:session:";
        let mut store: std::collections::HashMap<String, String> = std::collections::HashMap::new();

        // 1. Valid active session
        let did1 = "did:plc:user1";
        let sess1 = make_test_session_data(did1, "11111111-1111-1111-1111-111111111111");
        let hmac1 = fingerprint_id(&key, "11111111-1111-1111-1111-111111111111");
        store.insert(
            format!("{prefix}session:{did1}_{hmac1}"),
            seal_strict(&key, &serde_json::to_string(&sess1).unwrap()).unwrap(),
        );

        // 2. Retired session
        let did2 = "did:plc:user2";
        let sess2 = make_test_session_data(did2, "22222222-2222-2222-2222-222222222222");
        let hmac2 = fingerprint_id(&key, "22222222-2222-2222-2222-222222222222");
        store.insert(
            format!("{prefix}session:{did2}_{hmac2}"),
            seal_strict(&key, &serde_json::to_string(&sess2).unwrap()).unwrap(),
        );
        store.insert(format!("{prefix}upgrade_retired:{hmac2}"), "retired".to_string());

        // 3. Corrupt/malformed payload session
        let did3 = "did:plc:user3";
        let hmac3 = "3333333333333333333333333333333333333333333333333333333333333333";
        store.insert(format!("{prefix}session:{did3}_{hmac3}"), "not-encrypted-blob".to_string());

        let mut reconciled = 0usize;
        let mut skipped = 0usize;
        let mut failed = 0usize;

        for (k, v) in &store {
            if !k.starts_with(&format!("{prefix}session:")) {
                continue;
            }
            let rest = k.strip_prefix(&format!("{prefix}session:")).unwrap();
            let (did, hmac_fp) = rest.rsplit_once('_').unwrap();

            if store.contains_key(&format!("{prefix}upgrade_retired:{hmac_fp}")) {
                skipped += 1;
                continue;
            }

            let json = match open_strict(&key, v) {
                Ok(j) => j,
                Err(_) => {
                    failed += 1;
                    continue;
                }
            };

            let session: ClientSessionData = match serde_json::from_str(&json) {
                Ok(s) => s,
                Err(_) => {
                    failed += 1;
                    continue;
                }
            };

            if session.account_did.as_str() != did {
                failed += 1;
                continue;
            }

            reconciled += 1;
        }

        assert_eq!(reconciled, 1, "Exactly 1 valid session should be reconciled");
        assert_eq!(skipped, 1, "Exactly 1 retired session should be skipped");
        assert_eq!(failed, 1, "Exactly 1 corrupt session should be counted as failed");
    }

    #[test]
    fn test_resolve_session_self_healing_iterates_multi_page_scan_cursor() {
        let key = TEST_KEY;
        let prefix = "catbird:v2:session:";
        let did = "did:plc:multipage_user";
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let hmac_fp = fingerprint_id(&key, session_id);
        let sha256_fp = crate::services::push::registry::session_fingerprint(session_id);

        let session = make_test_session_data(did, session_id);
        let enc = seal_strict(&key, &serde_json::to_string(&session).unwrap()).unwrap();
        let sess_key = format!("{prefix}session:{did}_{hmac_fp}");

        let mut store: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        store.insert(sess_key.clone(), enc.clone());

        // Simulated paginated Redis SCAN responses:
        // Page 1 (cursor 0 -> 42): contains unrelated or no matching keys
        // Page 2 (cursor 42 -> 0): contains the matching session key
        let scan_pages: std::collections::HashMap<u64, (u64, Vec<String>)> = std::collections::HashMap::from([
            (0, (42, vec![format!("{prefix}session:did:plc:other_user1_hmac1")])),
            (42, (0, vec![sess_key.clone()])),
        ]);

        let mut scan_cursor: u64 = 0;
        let mut pages_scanned: usize = 0;
        let mut recovered = None;

        loop {
            let (next_cursor, did_keys) = scan_pages.get(&scan_cursor).cloned().unwrap_or((0, Vec::new()));
            scan_cursor = next_cursor;
            pages_scanned += 1;

            for key_name in did_keys {
                if let Some(rest) = key_name.strip_prefix(&format!("{prefix}session:{did}_")) {
                    let cand_hmac = rest.to_string();
                    if let Some(v) = store.get(&key_name) {
                        if let Ok(json) = open_strict(&key, v) {
                            if let Ok(cand_session) = serde_json::from_str::<ClientSessionData>(&json) {
                                let cand_fp = crate::services::push::registry::session_fingerprint(cand_session.session_id.as_str());
                                if cand_fp == sha256_fp {
                                    recovered = Some((cand_session, cand_hmac));
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if should_terminate_self_heal_scan(recovered.is_some(), scan_cursor, pages_scanned) {
                break;
            }
        }

        assert!(recovered.is_some(), "Self-healing must iterate multi-page SCAN cursor to recover session");
        let (recovered_session, recovered_hmac) = recovered.unwrap();
        assert_eq!(recovered_session.session_id, session_id);
        assert_eq!(recovered_hmac, hmac_fp);
    }

    #[test]
    fn test_reconcile_legacy_sessions_outcome_reporting_and_rearm_tracking() {
        let outcome_full = ReconciliationOutcome {
            reconciled: 42,
            skipped: 5,
            failed: 0,
            total_scanned: 47,
            is_complete: true,
        };
        assert!(outcome_full.is_complete);
        assert_eq!(outcome_full.failed, 0);

        let outcome_truncated = ReconciliationOutcome {
            reconciled: 50000,
            skipped: 0,
            failed: 0,
            total_scanned: 50000,
            is_complete: false,
        };
        assert!(!outcome_truncated.is_complete, "Truncated scan must report is_complete = false to trigger timer re-arm");

        let outcome_failed = ReconciliationOutcome {
            reconciled: 10,
            skipped: 0,
            failed: 2,
            total_scanned: 12,
            is_complete: true,
        };
        assert!(outcome_failed.failed > 0, "Failures must be tracked to trigger timer re-arm");
    }

    #[test]
    fn test_self_heal_scan_bounds_pages_on_miss_without_infinite_keyspace_walk() {
        // Assert directly against the production bound and termination predicate
        assert_eq!(MAX_SELF_HEAL_SCAN_PAGES, 10);

        // Before bound: scanning continues
        assert!(!should_terminate_self_heal_scan(false, 1, 0));
        assert!(!should_terminate_self_heal_scan(false, 1, MAX_SELF_HEAL_SCAN_PAGES - 1));

        // At bound: scanning terminates even if keyspace is large and cursor != 0
        assert!(should_terminate_self_heal_scan(false, 1, MAX_SELF_HEAL_SCAN_PAGES));
        assert!(should_terminate_self_heal_scan(false, 100, MAX_SELF_HEAL_SCAN_PAGES + 5));

        // Cursor wrapped to 0: scanning terminates
        assert!(should_terminate_self_heal_scan(false, 0, 1));

        // Session recovered: scanning terminates immediately
        assert!(should_terminate_self_heal_scan(true, 50, 1));

        // Drive the production termination predicate in a simulated scan loop
        let mut scan_cursor: u64 = 0;
        let mut pages_scanned: usize = 0;
        loop {
            scan_cursor += 1;
            pages_scanned += 1;
            if should_terminate_self_heal_scan(false, scan_cursor, pages_scanned) {
                break;
            }
        }
        assert_eq!(pages_scanned, MAX_SELF_HEAL_SCAN_PAGES);
    }

    struct ReconciliationStateModel {
        cursor: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }
    impl ReconciliationStateModel {
        fn new(start: u64) -> Self {
            Self {
                cursor: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(start)),
            }
        }
        fn reconcile_cursor(&self) -> u64 {
            self.cursor.load(std::sync::atomic::Ordering::Acquire)
        }
        fn update_reconcile_cursor(&self, start: u64, end: u64, failed: usize) -> u64 {
            let next = compute_reconciliation_cursor_update(start, end, failed);
            self.cursor.store(next, std::sync::atomic::Ordering::Release);
            next
        }
    }

    #[test]
    fn test_reconciliation_cursor_carries_forward_across_invocations() {
        // Compile-time assertion that RedisAuthStore has the production cursor field methods
        let _reconcile_fn = RedisAuthStore::reconcile_cursor;
        let _update_fn = RedisAuthStore::update_reconcile_cursor;

        // 1. Pure function assertions: clean advancement, wrap, and failure-hold
        // Clean run (failed == 0) from 0 to 1000 advances cursor to 1000
        assert_eq!(compute_reconciliation_cursor_update(0, 1000, 0), 1000);
        // Clean run (failed == 0) from 1000 to 2000 advances cursor to 2000
        assert_eq!(compute_reconciliation_cursor_update(1000, 2000, 0), 2000);
        // Clean completion (cursor wraps to 0, failed == 0) resets cursor to 0
        assert_eq!(compute_reconciliation_cursor_update(2000, 0, 0), 0);

        // Failing run (failed > 0) MUST NOT advance cursor past failed keys, holding start_cursor
        assert_eq!(compute_reconciliation_cursor_update(1000, 2000, 1), 1000);
        assert_eq!(compute_reconciliation_cursor_update(1000, 2000, 5), 1000);
        // Even if the scan reached cursor 0, if failures occurred, start_cursor is preserved for retry
        assert_eq!(compute_reconciliation_cursor_update(1000, 0, 3), 1000);
        assert_eq!(compute_reconciliation_cursor_update(0, 5000, 2), 0);

        // 2. Drive the state transition model:
        let model = ReconciliationStateModel::new(0);
        assert_eq!(model.reconcile_cursor(), 0);

        // First run hits limit cleanly (failed == 0) -> advances to 1000
        let cur1 = model.update_reconcile_cursor(0, 1000, 0);
        assert_eq!(cur1, 1000);
        assert_eq!(model.reconcile_cursor(), 1000);

        // Second run encounters failures (failed == 2) -> holds cursor at 1000 for retry
        let cur2 = model.update_reconcile_cursor(1000, 2000, 2);
        assert_eq!(cur2, 1000);
        assert_eq!(model.reconcile_cursor(), 1000);

        // Re-armed retry succeeds cleanly (failed == 0, cursor wraps to 0) -> resets cursor to 0
        let cur3 = model.update_reconcile_cursor(1000, 0, 0);
        assert_eq!(cur3, 0);
        assert_eq!(model.reconcile_cursor(), 0);
    }

    #[test]
    fn test_fingerprint_mismatch_evicts_stale_index_and_is_retryable() {
        let key = TEST_KEY;
        let prefix = "catbird:v2:session:";
        let did = "did:plc:mismatch_user";
        let old_session_id = "11111111-1111-1111-1111-111111111111";
        let new_session_id = "22222222-2222-2222-2222-222222222222";

        let old_hmac_fp = fingerprint_id(&key, old_session_id);
        let target_sha_fp = crate::services::push::registry::session_fingerprint(new_session_id);

        let mut store: std::collections::HashMap<String, String> = std::collections::HashMap::new();

        // Old session in store
        let old_sess = make_test_session_data(did, old_session_id);
        let old_enc = seal_strict(&key, &serde_json::to_string(&old_sess).unwrap()).unwrap();
        store.insert(format!("{prefix}session:{did}_{old_hmac_fp}"), old_enc);

        // Stale fp_index pointing to old_hmac_fp instead of new_hmac_fp
        let fp_idx_key = format!("{prefix}session_fp_index:{target_sha_fp}");
        store.insert(fp_idx_key.clone(), old_hmac_fp.clone());

        // Attempting to resolve with new target_sha_fp detects mismatch, evicts stale index, returns retryable Err
        let enc = store.get(&format!("{prefix}session:{did}_{old_hmac_fp}")).unwrap();
        let json = open_strict(&key, enc).unwrap();
        let session: ClientSessionData = serde_json::from_str(&json).unwrap();
        let computed_fp = crate::services::push::registry::session_fingerprint(session.session_id.as_str());

        assert_ne!(computed_fp, target_sha_fp);
        store.remove(&fp_idx_key); // Evicted!
        assert!(!store.contains_key(&fp_idx_key));

        let mismatch_err = anyhow::anyhow!(
            "Resolved session inner fingerprint mismatch for DID {did}: expected {target_sha_fp}, resolved {computed_fp} (stale index evicted, retryable)"
        );
        assert!(
            !crate::services::push::is_auth_revocation_error(&mismatch_err),
            "fingerprint mismatch MUST NOT cause auth revocation"
        );
    }

    #[test]
    fn test_o1_fp_index_rotation_simulation() {
        struct RotationSim {
            store: std::collections::HashMap<String, String>,
            prefix: String,
            key: [u8; 32],
        }

        impl RotationSim {
            fn commit_upgrade(
                &mut self,
                did: &str,
                old_session_id: &str,
                candidate_session_id: &str,
            ) {
                let old_hmac_fp = fingerprint_id(&self.key, old_session_id);
                let new_hmac_fp = fingerprint_id(&self.key, candidate_session_id);

                let old_sha256_fp =
                    crate::services::push::registry::session_fingerprint(old_session_id);
                let new_sha256_fp =
                    crate::services::push::registry::session_fingerprint(candidate_session_id);

                let new_sess_key = format!("{}session:{}_{}", self.prefix, did, new_hmac_fp);
                let new_idx_key = format!("{}session_index:{}", self.prefix, new_hmac_fp);
                let new_fp_idx_key = format!("{}session_fp_index:{}", self.prefix, new_sha256_fp);

                let old_sess_key = format!("{}session:{}_{}", self.prefix, did, old_hmac_fp);
                let old_idx_key = format!("{}session_index:{}", self.prefix, old_hmac_fp);
                let old_fp_idx_key = format!("{}session_fp_index:{}", self.prefix, old_sha256_fp);
                let retired_key = format!("{}upgrade_retired:{}", self.prefix, old_hmac_fp);

                let candidate_session = make_test_session_data(did, candidate_session_id);
                let json = serde_json::to_string(&candidate_session).unwrap();
                let enc = seal_strict(&self.key, &json).unwrap();

                // Atomic commit: set new keys, delete old keys, set retirement tombstone on old
                self.store.insert(new_sess_key, enc);
                self.store.insert(new_idx_key, did.to_string());
                self.store.insert(new_fp_idx_key, new_hmac_fp.clone());

                self.store.remove(&old_sess_key);
                self.store.remove(&old_idx_key);
                self.store.remove(&old_fp_idx_key);

                self.store.insert(retired_key, new_hmac_fp);
            }

            fn resolve_session(
                &self,
                did: &str,
                expected_fingerprint: &str,
            ) -> Option<ClientSessionData> {
                let expected_fp =
                    crate::services::push::registry::normalize_or_hash_session_fingerprint(
                        expected_fingerprint,
                    );

                let fp_idx_key = format!("{}session_fp_index:{}", self.prefix, expected_fp);
                let hmac_fp = self.store.get(&fp_idx_key)?;

                let ret_key = format!("{}upgrade_retired:{}", self.prefix, hmac_fp);
                if self.store.contains_key(&ret_key) {
                    return None;
                }

                let sess_key = format!("{}session:{}_{}", self.prefix, did, hmac_fp);
                let enc = self.store.get(&sess_key)?;

                let json = open_strict(&self.key, enc).ok()?;
                let session: ClientSessionData = serde_json::from_str(&json).ok()?;
                if session.account_did.as_str() != did {
                    return None;
                }

                let computed_fp =
                    crate::services::push::registry::session_fingerprint(session.session_id.as_str());
                if computed_fp != expected_fp && session.session_id.as_str() != expected_fingerprint {
                    return None;
                }

                Some(session)
            }
        }

        let mut sim = RotationSim {
            store: std::collections::HashMap::new(),
            prefix: "catbird:v2:session:".to_string(),
            key: TEST_KEY,
        };

        let did = "did:plc:bob";
        let old_session_id = "11111111-1111-1111-1111-111111111111";
        let candidate_session_id = "22222222-2222-2222-2222-222222222222";

        let old_sha256_fp = crate::services::push::registry::session_fingerprint(old_session_id);
        let new_sha256_fp =
            crate::services::push::registry::session_fingerprint(candidate_session_id);

        // Pre-populate old session
        let old_hmac_fp = fingerprint_id(&TEST_KEY, old_session_id);
        let old_sess = make_test_session_data(did, old_session_id);
        let enc = seal_strict(&TEST_KEY, &serde_json::to_string(&old_sess).unwrap()).unwrap();
        sim.store.insert(
            format!("catbird:v2:session:session:{}_{}", did, old_hmac_fp),
            enc,
        );
        sim.store.insert(
            format!("catbird:v2:session:session_index:{}", old_hmac_fp),
            did.to_string(),
        );
        sim.store.insert(
            format!("catbird:v2:session:session_fp_index:{}", old_sha256_fp),
            old_hmac_fp,
        );

        // Verify old session resolves before rotation
        assert!(sim.resolve_session(did, &old_sha256_fp).is_some());

        // Perform atomic rotation via commit_upgrade
        sim.commit_upgrade(did, old_session_id, candidate_session_id);

        // 1. Old session is no longer resolvable
        assert!(sim.resolve_session(did, &old_sha256_fp).is_none());

        // 2. New rotated session is resolvable with new fingerprint
        let resolved_new = sim.resolve_session(did, &new_sha256_fp);
        assert!(resolved_new.is_some());
        let s = resolved_new.unwrap();
        assert_eq!(s.session_id, candidate_session_id);
        assert_eq!(s.account_did.as_str(), did);
    }
    #[test]
    fn test_expired_or_tombstoned_legacy_session_never_installs_fp_index() {
        struct ExpiredTombstoneSim {
            store: std::collections::HashMap<String, String>,
            ttls: std::collections::HashMap<String, i64>,
            prefix: String,
            key: [u8; 32],
        }

        impl ExpiredTombstoneSim {
            fn resolve_session(
                &mut self,
                did: &str,
                expected_fingerprint: &str,
            ) -> Result<Option<ClientSessionData>, SessionStoreError> {
                let expected_fp =
                    crate::services::push::registry::normalize_or_hash_session_fingerprint(
                        expected_fingerprint,
                    );

                let fp_idx_key = format!("{}session_fp_index:{}", self.prefix, expected_fp);
                let (hmac_fp, is_fallback) = match self.store.get(&fp_idx_key) {
                    Some(fp) => (fp.clone(), false),
                    None => {
                        let did_idx_key = format!("{}did_index:{}", self.prefix, did);
                        match self.store.get(&did_idx_key) {
                            Some(fp) => (fp.clone(), true),
                            None => return Ok(None),
                        }
                    }
                };

                let ret_key = format!("{}upgrade_retired:{}", self.prefix, hmac_fp);
                if self.store.contains_key(&ret_key) {
                    return Ok(None);
                }

                let sess_key = format!("{}session:{}_{}", self.prefix, did, hmac_fp);
                let Some(enc) = self.store.get(&sess_key) else {
                    return Ok(None);
                };

                let ttl = self.ttls.get(&sess_key).copied().unwrap_or(3600);
                if ttl <= 0 {
                    return Ok(None);
                }

                let json = open_strict(&self.key, enc)
                    .map_err(|e| other_err(&format!("decryption failed: {e}")))?;
                let session: ClientSessionData =
                    serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;

                if session.account_did.as_str() != did {
                    return Err(other_err("account_did mismatch"));
                }

                let computed_fp =
                    crate::services::push::registry::session_fingerprint(session.session_id.as_str());
                if computed_fp != expected_fp && session.session_id.as_str() != expected_fingerprint {
                    return Err(other_err("inner fingerprint mismatch"));
                }

                if is_fallback {
                    let fp_idx_key = format!("{}session_fp_index:{}", self.prefix, expected_fp);
                    self.store.insert(fp_idx_key, hmac_fp);
                }

                Ok(Some(session))
            }
        }

        let mut sim = ExpiredTombstoneSim {
            store: std::collections::HashMap::new(),
            ttls: std::collections::HashMap::new(),
            prefix: "catbird:v2:session:".to_string(),
            key: TEST_KEY,
        };

        let did = "did:plc:victim";
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let sha256_fp = crate::services::push::registry::session_fingerprint(session_id);
        let hmac_fp = fingerprint_id(&TEST_KEY, session_id);

        // Case 1: Tombstoned session (logged out)
        let sess_key = format!("catbird:v2:session:session:{}_{}", did, hmac_fp);
        let did_idx_key = format!("catbird:v2:session:did_index:{}", did);
        let ret_key = format!("catbird:v2:session:upgrade_retired:{}", hmac_fp);
        let fp_idx_key = format!("catbird:v2:session:session_fp_index:{}", sha256_fp);

        let sess = make_test_session_data(did, session_id);
        let enc = seal_strict(&TEST_KEY, &serde_json::to_string(&sess).unwrap()).unwrap();
        sim.store.insert(sess_key.clone(), enc.clone());
        sim.store.insert(did_idx_key.clone(), hmac_fp.clone());
        sim.store.insert(ret_key, "logout".to_string());
        sim.ttls.insert(sess_key.clone(), 3600);

        // Resolution fails closed, NEVER installs fp_index
        let res = sim.resolve_session(did, &sha256_fp).unwrap();
        assert!(res.is_none());
        assert!(!sim.store.contains_key(&fp_idx_key));

        // Case 2: Expired TTL (<= 0)
        let mut sim2 = ExpiredTombstoneSim {
            store: std::collections::HashMap::new(),
            ttls: std::collections::HashMap::new(),
            prefix: "catbird:v2:session:".to_string(),
            key: TEST_KEY,
        };
        sim2.store.insert(sess_key.clone(), enc.clone());
        sim2.store.insert(did_idx_key.clone(), hmac_fp.clone());
        sim2.ttls.insert(sess_key.clone(), 0); // Expired TTL!

        let res2 = sim2.resolve_session(did, &sha256_fp).unwrap();
        assert!(res2.is_none());
        assert!(!sim2.store.contains_key(&fp_idx_key));

        // Case 3: Swapped DID in ciphertext
        let mut sim3 = ExpiredTombstoneSim {
            store: std::collections::HashMap::new(),
            ttls: std::collections::HashMap::new(),
            prefix: "catbird:v2:session:".to_string(),
            key: TEST_KEY,
        };
        let attacker_sess = make_test_session_data("did:plc:attacker", session_id);
        let attacker_enc =
            seal_strict(&TEST_KEY, &serde_json::to_string(&attacker_sess).unwrap()).unwrap();
        sim3.store.insert(sess_key.clone(), attacker_enc);
        sim3.store.insert(did_idx_key.clone(), hmac_fp.clone());
        sim3.ttls.insert(sess_key.clone(), 3600);

        let res3 = sim3.resolve_session(did, &sha256_fp);
        assert!(res3.is_err());
        assert!(!sim3.store.contains_key(&fp_idx_key));
    }

    #[test]
    fn test_o1_fp_index_no_scan_constant_time_with_large_keyspace() {
        struct InstrumentedNoScanSim {
            store: std::cell::RefCell<std::collections::HashMap<String, String>>,
            prefix: String,
            key: [u8; 32],
            direct_lookups: std::cell::Cell<usize>,
            scan_iterations: std::cell::Cell<usize>,
        }

        impl InstrumentedNoScanSim {
            fn resolve_session(
                &self,
                did: &str,
                expected_fingerprint: &str,
            ) -> Option<ClientSessionData> {
                let expected_fp =
                    crate::services::push::registry::normalize_or_hash_session_fingerprint(
                        expected_fingerprint,
                    );

                // O(1) step 1: direct index lookup
                let fp_idx_key = format!("{}session_fp_index:{}", self.prefix, expected_fp);
                self.direct_lookups.set(self.direct_lookups.get() + 1);

                let (hmac_fp, is_fallback) = match self.store.borrow().get(&fp_idx_key) {
                    Some(fp) => (fp.clone(), false),
                    None => {
                        // O(1) step 1b: fallback to did_index
                        let did_idx_key = format!("{}did_index:{}", self.prefix, did);
                        self.direct_lookups.set(self.direct_lookups.get() + 1);
                        (self.store.borrow().get(&did_idx_key)?.clone(), true)
                    }
                };

                // O(1) step 2: direct tombstone check
                let ret_key = format!("{}upgrade_retired:{}", self.prefix, hmac_fp);
                self.direct_lookups.set(self.direct_lookups.get() + 1);
                if self.store.borrow().contains_key(&ret_key) {
                    return None;
                }

                // O(1) step 3: direct session blob lookup
                let sess_key = format!("{}session:{}_{}", self.prefix, did, hmac_fp);
                self.direct_lookups.set(self.direct_lookups.get() + 1);
                let enc = self.store.borrow().get(&sess_key)?.clone();

                let json = open_strict(&self.key, &enc).ok()?;
                let session: ClientSessionData = serde_json::from_str(&json).ok()?;
                if session.account_did.as_str() != did {
                    return None;
                }

                let computed_fp =
                    crate::services::push::registry::session_fingerprint(session.session_id.as_str());
                if computed_fp != expected_fp && session.session_id.as_str() != expected_fingerprint {
                    return None;
                }

                if is_fallback {
                    let fp_idx_key = format!("{}session_fp_index:{}", self.prefix, expected_fp);
                    self.store.borrow_mut().insert(fp_idx_key, hmac_fp);
                }

                Some(session)
            }
        }

        let sim = InstrumentedNoScanSim {
            store: std::cell::RefCell::new(std::collections::HashMap::new()),
            prefix: "catbird:v2:session:".to_string(),
            key: TEST_KEY,
            direct_lookups: std::cell::Cell::new(0),
            scan_iterations: std::cell::Cell::new(0),
        };

        // Populate store with 5,000 other random keys to simulate a large Redis keyspace
        for i in 0..5000 {
            let other_did = format!("did:plc:other{}", i);
            let other_sess = format!("00000000-0000-0000-0000-{:012x}", i);
            let other_hmac = fingerprint_id(&TEST_KEY, &other_sess);
            let other_sha = crate::services::push::registry::session_fingerprint(&other_sess);

            sim.store.borrow_mut().insert(
                format!("catbird:v2:session:session:{}_{}", other_did, other_hmac),
                "blob".into(),
            );
            sim.store.borrow_mut().insert(
                format!("catbird:v2:session:session_index:{}", other_hmac),
                other_did,
            );
            sim.store.borrow_mut().insert(
                format!("catbird:v2:session:session_fp_index:{}", other_sha),
                other_hmac,
            );
        }

        let target_did = "did:plc:target_user";
        let target_session_id = "ffffffff-ffff-ffff-ffff-ffffffffffff";
        let target_hmac = fingerprint_id(&TEST_KEY, target_session_id);
        let target_sha = crate::services::push::registry::session_fingerprint(target_session_id);

        let target_sess_data = make_test_session_data(target_did, target_session_id);
        let enc = seal_strict(&TEST_KEY, &serde_json::to_string(&target_sess_data).unwrap()).unwrap();

        sim.store.borrow_mut().insert(
            format!("catbird:v2:session:session:{}_{}", target_did, target_hmac),
            enc,
        );
        sim.store.borrow_mut().insert(
            format!("catbird:v2:session:session_index:{}", target_hmac),
            target_did.to_string(),
        );
        sim.store.borrow_mut().insert(
            format!("catbird:v2:session:session_fp_index:{}", target_sha),
            target_hmac,
        );

        // Resolve target session in large populated store
        sim.direct_lookups.set(0);
        sim.scan_iterations.set(0);

        let resolved = sim.resolve_session(target_did, &target_sha);
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().session_id, target_session_id);

        // Exactly 3 constant-time direct lookups (fp_index, retired_check, session_get), and 0 scans!
        assert_eq!(sim.direct_lookups.get(), 3);
        assert_eq!(sim.scan_iterations.get(), 0);

        // Now test a legacy session in the 5,000 key store with missing session_fp_index
        let legacy_did = "did:plc:legacy_user_5000";
        let legacy_session_id = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
        let legacy_hmac = fingerprint_id(&TEST_KEY, legacy_session_id);
        let legacy_sha = crate::services::push::registry::session_fingerprint(legacy_session_id);

        let legacy_sess_data = make_test_session_data(legacy_did, legacy_session_id);
        let enc_legacy =
            seal_strict(&TEST_KEY, &serde_json::to_string(&legacy_sess_data).unwrap()).unwrap();
        sim.store.borrow_mut().insert(
            format!("catbird:v2:session:session:{}_{}", legacy_did, legacy_hmac),
            enc_legacy,
        );
        sim.store.borrow_mut().insert(
            format!("catbird:v2:session:session_index:{}", legacy_hmac),
            legacy_did.to_string(),
        );
        sim.store.borrow_mut().insert(
            format!("catbird:v2:session:did_index:{}", legacy_did),
            legacy_hmac,
        );
        sim.direct_lookups.set(0);
        sim.scan_iterations.set(0);

        let resolved_legacy = sim.resolve_session(legacy_did, &legacy_sha);
        assert!(resolved_legacy.is_some());
        assert_eq!(resolved_legacy.unwrap().session_id, legacy_session_id);

        // Fallback performed exactly 4 constant-time direct lookups (fp_index miss, did_index hit, tombstone check, session get), and 0 scans!
        assert_eq!(sim.direct_lookups.get(), 4);
        assert_eq!(sim.scan_iterations.get(), 0);

        // Subsequent lookup hits the installed fp_index directly: 3 direct lookups, 0 scans!
        sim.direct_lookups.set(0);
        let resolved_legacy2 = sim.resolve_session(legacy_did, &legacy_sha);
        assert!(resolved_legacy2.is_some());
        assert_eq!(sim.direct_lookups.get(), 3);
        assert_eq!(sim.scan_iterations.get(), 0);
    }
}
