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
use super::redis_crypto::{
    build_aad, open_session_dual_read, open_strict_with_aad, open_v2_with_metadata,
    seal_strict_with_aad, seal_v2_with_metadata, EnvelopeMetadata,
};
type HmacSha256 = Hmac<Sha256>;

const STATE_TTL_SECONDS: u64 = 600; // 10 minutes for OAuth state
pub const SESSION_INDEX_TTL_SECONDS: u64 = 86400 * 30; // 30 days
/// 90 days for retirement tombstones (at least 2 * max session/index TTL of 30 days plus 30-day rollout margin).
pub const RETIRED_TOMBSTONE_TTL_SECONDS: u64 = 86400 * 90; // 90 days

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
/// - If hashed session exists, touches sliding TTL on hashed index key and returns session data
/// - Returns nil on miss
const LUA_GET_SESSION_SCRIPT: &str = r#"
-- KEYS:
-- 1: hashed_session_key
-- 2: hashed_index_key
-- 3: hashed_retired_key

-- ARGV:
-- 1: session_ttl
-- 2: session_index_ttl
-- 3: did

if redis.call('EXISTS', KEYS[3]) == 1 then
    return nil
end

local data = redis.call('GETEX', KEYS[1], 'EX', tonumber(ARGV[1]))
if data then
    local hashed_index_did = redis.call('GETEX', KEYS[2], 'EX', tonumber(ARGV[2]))
    if not hashed_index_did and ARGV[3] and ARGV[3] ~= '' then
        redis.call('SETEX', KEYS[2], tonumber(ARGV[2]), ARGV[3])
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
/// - Sets hashed session index entry (returns 0)
const LUA_WRITE_INDEX_SCRIPT: &str = r#"
-- KEYS:
-- 1: hashed_index_key
-- 2: hashed_retired_key

-- ARGV:
-- 1: did
-- 2: session_index_ttl

if redis.call('EXISTS', KEYS[2]) == 1 then
    return 1
end

redis.call('SETEX', KEYS[1], tonumber(ARGV[2]), ARGV[1])
return 0
"#;

/// Lua script for atomic session upsert with retirement protection:
/// - Refuses write if retired tombstone exists (returns 1)
/// - Sets hashed session blob and session index atomically (returns 0)
const LUA_UPSERT_SESSION_SCRIPT: &str = r#"
-- KEYS:
-- 1: hashed_session_key
-- 2: hashed_index_key
-- 3: hashed_retired_key

-- ARGV:
-- 1: encrypted_session_data
-- 2: did
-- 3: session_ttl
-- 4: session_index_ttl

if redis.call('EXISTS', KEYS[3]) == 1 then
    return 1
end

redis.call('SETEX', KEYS[1], tonumber(ARGV[3]), ARGV[1])
redis.call('SETEX', KEYS[2], tonumber(ARGV[4]), ARGV[2])
return 0
"#;
/// Lua script for atomic logout retirement:
/// - Checks if old session was upgraded to a winner candidate; if so, atomically revokes the winner candidate lineage
/// - Sets retired tombstone on hashed key
/// - Deletes hashed session and index entries, and pending upgrade state pointers
const LUA_LOGOUT_RETIRE_SCRIPT: &str = r#"
-- KEYS:
-- 1: hashed_retired_key
-- 2: hashed_session_key
-- 3: hashed_index_key
-- 4: hashed_pending_key

-- ARGV:
-- 1: retired_ttl
-- 2: retired_marker
-- 3: key_prefix
-- 4: did

local current_winner = redis.call('GET', KEYS[1])
if current_winner and current_winner ~= '' and current_winner ~= 'logout' then
    local prefix = ARGV[3]
    local did = ARGV[4]
    if prefix and did and prefix ~= '' and did ~= '' then
        local winner_session = prefix .. 'session:' .. did .. '_' .. current_winner
        local winner_index = prefix .. 'session_index:' .. current_winner
        local winner_retired = prefix .. 'upgrade_retired:' .. current_winner
        local winner_receipt = prefix .. 'upgrade_receipt:' .. current_winner
        local winner_candidate = prefix .. 'upgrade_candidate:' .. current_winner
        local winner_pending = prefix .. 'pending_upgrade:' .. current_winner
        
        redis.call('SETEX', winner_retired, tonumber(ARGV[1]), ARGV[2])
        redis.call('DEL', winner_session)
        redis.call('DEL', winner_index)
        redis.call('DEL', winner_receipt)
        redis.call('DEL', winner_candidate)
        redis.call('DEL', winner_pending)
    end
end

redis.call('SETEX', KEYS[1], tonumber(ARGV[1]), ARGV[2])
redis.call('DEL', KEYS[2])
redis.call('DEL', KEYS[3])
redis.call('DEL', KEYS[4])
return 0
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
        Self::validate_key_prefix(&key_prefix)?;
        Ok(Self {
            redis,
            key_prefix,
            session_ttl,
            encryption_key,
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

        let mut conn = self.redis.clone();
        let script = redis::Script::new(LUA_WRITE_INDEX_SCRIPT);
        let _: i32 = script
            .key(&hashed_index)
            .key(&hashed_retired)
            .arg(did)
            .arg(SESSION_INDEX_TTL_SECONDS)
            .invoke_async(&mut conn)
            .await?;
        Ok(())
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

        let mut conn = self.redis.clone();
        let script = redis::Script::new(LUA_GET_SESSION_SCRIPT);
        let data: Option<String> = script
            .key(&hashed_session_key)
            .key(&hashed_index_key)
            .key(&hashed_retired_key)
            .arg(self.session_ttl)
            .arg(SESSION_INDEX_TTL_SECONDS)
            .arg(did.as_str())
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;

        if let Some(encrypted) = data {
            let (json, metadata, is_v1) = open_v2_with_metadata(
                &self.encryption_key,
                &encrypted,
                "session",
                &hashed_session_key,
            )
            .map_err(|e| other_err(&format!("Session decryption failed: {e}")))?;
            let session: ClientSessionData =
                serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;
            let session = validate_session_identity(session, did, session_id)?;

            if let Some(meta_did) = metadata.did {
                if meta_did != did.as_str() {
                    return Err(other_err("Session DID mismatch with envelope metadata"));
                }
            }

            // Safe dual-read re-encrypt on access: if session was stored as legacy v1, upgrade it to v2 envelope with AAD
            if is_v1 {
                let meta = EnvelopeMetadata::new(
                    "session",
                    &hashed_session_key,
                    Some(did.as_str()),
                    None,
                );
                let v2_encrypted = seal_v2_with_metadata(&self.encryption_key, &json, &meta)
                    .map_err(|e| other_err(&format!("Session reseal failed during migration: {e}")))?;
                conn.set_ex::<_, _, ()>(&hashed_session_key, v2_encrypted, self.session_ttl)
                    .await
                    .map_err(redis_err)?;
            }

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

        let json = serde_json::to_string(&session).map_err(SessionStoreError::Serde)?;
        let meta = EnvelopeMetadata::new(
            "session",
            &hashed_session,
            Some(session.account_did.as_str()),
            None,
        );
        let encrypted = seal_v2_with_metadata(&self.encryption_key, &json, &meta)
            .map_err(|e| other_err(&format!("Session encryption failed: {e}")))?;
        let mut conn = self.redis.clone();
        let script = redis::Script::new(LUA_UPSERT_SESSION_SCRIPT);
        let res: i32 = script
            .key(&hashed_session)
            .key(&hashed_index)
            .key(&hashed_retired)
            .arg(&encrypted)
            .arg(session.account_did.as_str())
            .arg(self.session_ttl)
            .arg(SESSION_INDEX_TTL_SECONDS)
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;
        if res == 1 {
            return Err(other_err("session has been retired"));
        }

        Ok(())
    }

    /// Atomic logout retirement: sets retired tombstone on hashed key,
    /// and deletes hashed session blob, index entry, and pending upgrade state pointer.
    async fn delete_session<D: jacquard_common::BosStr + Send + Sync>(
        &self,
        did: &Did<D>,
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        let hashed_retired = self.retired_key(session_id);
        let hashed_session = self.session_key(did.as_str(), session_id);
        let hashed_index = self.session_index_key(session_id);
        let hashed_pending = self.pending_upgrade_key(session_id);

        let mut conn = self.redis.clone();
        let script = redis::Script::new(LUA_LOGOUT_RETIRE_SCRIPT);
        let _: i32 = script
            .key(&hashed_retired)
            .key(&hashed_session)
            .key(&hashed_index)
            .key(&hashed_pending)
            .arg(self.retired_ttl())
            .arg("logout")
            .arg(&self.key_prefix)
            .arg(did.as_str())
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
                let (json, _metadata, _) = open_v2_with_metadata(
                    &self.encryption_key,
                    &encrypted,
                    "auth_req_info",
                    &key,
                )
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
        let meta = EnvelopeMetadata::new("auth_req_info", &key, None, None);
        let encrypted = seal_v2_with_metadata(&self.encryption_key, &json, &meta)
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
    use crate::services::redis_crypto::{open_strict, seal_strict};
    use jacquard_oauth::session::{DpopClientData, DpopReqData};
    use jacquard_oauth::types::{OAuthTokenType, TokenSet};

    const TEST_KEY: [u8; 32] = [0x42u8; 32];
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

        // Verify no raw bearer session_id is in the generated keys
        assert!(!session_key.contains(session_id));
        assert!(!index_key.contains(session_id));
        assert!(!retired_key.contains(session_id));
        assert!(!pending_key.contains(session_id));

        assert!(session_key.contains(&fp));
        assert!(index_key.contains(&fp));
        assert!(retired_key.contains(&fp));
        assert!(pending_key.contains(&fp));
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
    fn test_logout_retire_atomically_revokes_winner_candidate_lineage_logic() {
        let old_session_id = "550e8400-e29b-41d4-a716-446655440001";
        let candidate_session_id = "550e8400-e29b-41d4-a716-446655440002";
        let did = "did:plc:alice";
        let prefix = "catbird:v2:session:";
        let key = TEST_KEY;

        let old_fp = fingerprint_id(&key, old_session_id);
        let cand_fp = fingerprint_id(&key, candidate_session_id);

        let mut store = std::collections::HashMap::new();

        // Setup state where upgrade commit won and recorded cand_fp on old retired key
        let old_retired_k = format!("{}upgrade_retired:{}", prefix, old_fp);
        let old_session_k = format!("{}session:{}_{}", prefix, did, old_fp);
        let old_index_k = format!("{}session_index:{}", prefix, old_fp);
        let old_pending_k = format!("{}pending_upgrade:{}", prefix, old_fp);

        let winner_session_k = format!("{}session:{}_{}", prefix, did, cand_fp);
        let winner_index_k = format!("{}session_index:{}", prefix, cand_fp);
        let winner_retired_k = format!("{}retired:{}", prefix, cand_fp);
        let winner_receipt_k = format!("{}upgrade_receipt:{}", prefix, cand_fp);
        let winner_candidate_k = format!("{}upgrade_candidate:{}", prefix, cand_fp);
        let winner_pending_k = format!("{}pending_upgrade:{}", prefix, cand_fp);

        store.insert(old_retired_k.clone(), cand_fp.clone());
        store.insert(winner_session_k.clone(), "sealed_candidate_session".into());
        store.insert(winner_index_k.clone(), did.into());
        store.insert(winner_receipt_k.clone(), "sealed_receipt".into());
        store.insert(winner_candidate_k.clone(), "sealed_candidate".into());
        store.insert(winner_pending_k.clone(), "pending_flow_pointer".into());
        // Simulate Lua script execution
        let current_winner = store.get(&old_retired_k).cloned();
        if let Some(winner) = current_winner {
            if !winner.is_empty() && winner != "logout" {
                let w_sess = format!("{}session:{}_{}", prefix, did, winner);
                let w_idx = format!("{}session_index:{}", prefix, winner);
                let w_ret = format!("{}retired:{}", prefix, winner);
                let w_rec = format!("{}upgrade_receipt:{}", prefix, winner);
                let w_cand = format!("{}upgrade_candidate:{}", prefix, winner);
                let w_pend = format!("{}pending_upgrade:{}", prefix, winner);

                store.insert(w_ret, "logout".into());
                store.remove(&w_sess);
                store.remove(&w_idx);
                store.remove(&w_rec);
                store.remove(&w_cand);
                store.remove(&w_pend);
            }
        }

        store.insert(old_retired_k.clone(), "logout".into());
        store.remove(&old_session_k);
        store.remove(&old_index_k);
        store.remove(&old_pending_k);

        // Verify old session is tombstoned
        assert_eq!(store.get(&old_retired_k).map(|s| s.as_str()), Some("logout"));
        assert!(!store.contains_key(&old_session_k));

        // Verify winner candidate is completely revoked and purged
        assert_eq!(store.get(&winner_retired_k).map(|s| s.as_str()), Some("logout"));
        assert!(!store.contains_key(&winner_session_k));
        assert!(!store.contains_key(&winner_receipt_k));
        assert!(!store.contains_key(&winner_candidate_k));
        assert!(!store.contains_key(&winner_pending_k));
    }
}
