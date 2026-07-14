//! Redis-backed implementation of Jacquard's `ClientAuthStore`.
//!
//! Stores authenticated, encrypted session data under opaque Redis keys.

use futures_util::{stream, StreamExt, TryStreamExt};
use jacquard_common::session::SessionStoreError;
use jacquard_common::types::did::Did;
use jacquard_common::IntoStatic;
use jacquard_oauth::authstore::{
    reauthentication_required_store_error, session_operation_active_store_error, ClientAuthStore,
    SessionOperationAcquire, SessionOperationKind, SessionOperationLease,
};
use jacquard_oauth::session::{AuthRequestData, ClientSessionData, DpopClientData};
use jacquard_oauth::types::{OAuthTokenType, TokenSet};
use redis::{AsyncCommands, Expiry};
use std::collections::{BTreeSet, HashSet};
use std::time::Duration;

use super::redis_crypto::{open_utf8_with_status, Keyring, RecordContext};

const STATE_TTL_SECONDS: u64 = 600; // 10 minutes for OAuth state
const MAX_LIFECYCLE_AUDIT_CONCURRENCY: usize = 16;

#[derive(Default)]
struct ScanCollection {
    keys: BTreeSet<String>,
    cursors: HashSet<u64>,
}

impl ScanCollection {
    /// Record one SCAN page. Returns true when cursor zero completes the scan.
    fn record_page(
        &mut self,
        next_cursor: u64,
        batch: Vec<String>,
    ) -> Result<bool, SessionStoreError> {
        self.keys.extend(batch);
        if next_cursor == 0 {
            return Ok(true);
        }
        if !self.cursors.insert(next_cursor) {
            return Err(other_err("Redis SCAN returned a repeated cursor"));
        }
        Ok(false)
    }

    fn into_keys(self) -> Vec<String> {
        self.keys.into_iter().collect()
    }
}

fn redis_err(e: redis::RedisError) -> SessionStoreError {
    SessionStoreError::Other(e.into())
}

fn other_err(msg: &str) -> SessionStoreError {
    SessionStoreError::Other(msg.into())
}

fn new_lifecycle_generation() -> String {
    use base64::Engine;
    use rand::RngCore;

    let mut generation = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut generation);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(generation)
}

fn interpret_auth_rewrap_result(result: i64) -> Result<(), SessionStoreError> {
    match result {
        1 => Ok(()),
        -2 => Err(other_err("auth request expired during rewrap")),
        -1 => Err(other_err(
            "auth request has no expiry and cannot be rewrapped",
        )),
        0 => Err(other_err("auth request changed concurrently during rewrap")),
        _ => Err(other_err("auth request rewrap returned an invalid result")),
    }
}

fn interpret_session_rewrap_result(result: i64) -> bool {
    result == 1
}

fn expiry_preserving_cas_script() -> redis::Script {
    redis::Script::new(
        r#"
        local current = redis.call('GET', KEYS[1])
        if not current then return -2 end
        if current ~= ARGV[1] then return 0 end
        local ttl = redis.call('PTTL', KEYS[1])
        if ttl <= 0 then return ttl end
        redis.call('SET', KEYS[1], ARGV[2], 'XX', 'PX', ttl)
        return 1
        "#,
    )
}

fn session_update_cas_script() -> redis::Script {
    redis::Script::new(
        r#"
        if redis.call('EXISTS', KEYS[5]) ~= 0 or redis.call('EXISTS', KEYS[6]) ~= 0 then
            return 0
        end
        local generation = redis.call('GET', KEYS[1])
        if not generation or generation ~= ARGV[1] then return 0 end
        if redis.call('EXISTS', KEYS[2]) == 0 then return 0 end
        local index_generation = redis.call('GET', KEYS[4])
        if not index_generation or index_generation ~= ARGV[1] then return 0 end
        redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[4])
        redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[4])
        redis.call('SET', KEYS[3], ARGV[3], 'EX', ARGV[4])
        redis.call('SET', KEYS[4], ARGV[1], 'EX', ARGV[4])
        return 1
        "#,
    )
}

fn session_get_cas_script() -> redis::Script {
    redis::Script::new(
        r#"
        if redis.call('EXISTS', KEYS[5]) ~= 0 then
            return {-1, '', ''}
        end
        if redis.call('EXISTS', KEYS[6]) ~= 0 then
            return {-2, '', ''}
        end
        local generation = redis.call('GET', KEYS[1])
        local index_generation = redis.call('GET', KEYS[4])
        if not generation or not index_generation or generation ~= index_generation then
            return {0, '', ''}
        end
        local session = redis.call('GET', KEYS[2])
        if not session or redis.call('EXISTS', KEYS[3]) == 0 then return {0, '', ''} end
        redis.call('EXPIRE', KEYS[1], ARGV[1])
        redis.call('EXPIRE', KEYS[2], ARGV[1])
        redis.call('EXPIRE', KEYS[3], ARGV[1])
        redis.call('EXPIRE', KEYS[4], ARGV[1])
        return {1, session, generation}
        "#,
    )
}

fn session_delete_cas_script() -> redis::Script {
    redis::Script::new(
        r#"
        if redis.call('EXISTS', KEYS[5]) ~= 0 or redis.call('EXISTS', KEYS[6]) ~= 0 then
            return 0
        end
        local generation = redis.call('GET', KEYS[1])
        if not generation or generation ~= ARGV[1] then return 0 end
        redis.call('DEL', KEYS[1], KEYS[2])
        local index_generation = redis.call('GET', KEYS[4])
        if index_generation and index_generation == ARGV[1] then
            redis.call('DEL', KEYS[3], KEYS[4])
        end
        return 1
        "#,
    )
}

fn session_operation_acquire_script() -> redis::Script {
    redis::Script::new(
        r#"
        if redis.call('EXISTS', KEYS[5]) ~= 0 then
            return {0, '', 0}
        end
        local generation = redis.call('GET', KEYS[1])
        local index_generation = redis.call('GET', KEYS[4])
        local session = redis.call('GET', KEYS[2])
        local session_index = redis.call('GET', KEYS[3])
        if not generation or not index_generation or not session or not session_index then
            return {-1, '', 0}
        end
        if generation ~= ARGV[1] or index_generation ~= ARGV[1]
            or session ~= ARGV[2] or session_index ~= ARGV[3] then
            return {0, '', 0}
        end
        local was_uncertain = redis.call('EXISTS', KEYS[6])
        redis.call('SET', KEYS[1], ARGV[4], 'EX', ARGV[7])
        redis.call('EXPIRE', KEYS[2], ARGV[7])
        redis.call('EXPIRE', KEYS[3], ARGV[7])
        redis.call('SET', KEYS[4], ARGV[4], 'EX', ARGV[7])
        redis.call('SET', KEYS[5], ARGV[5], 'PX', ARGV[6])
        if ARGV[8] == 'refresh' or was_uncertain ~= 0 then
            redis.call('SET', KEYS[6], ARGV[4], 'EX', ARGV[7])
        end
        return {1, ARGV[4], was_uncertain}
        "#,
    )
}

fn session_create_script() -> redis::Script {
    redis::Script::new(
        r#"
        redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[4])
        redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[4])
        redis.call('SET', KEYS[3], ARGV[3], 'EX', ARGV[4])
        redis.call('SET', KEYS[4], ARGV[1], 'EX', ARGV[4])
        redis.call('DEL', KEYS[5], KEYS[6])
        return 1
        "#,
    )
}

fn lifecycle_pair_read_script() -> redis::Script {
    redis::Script::new(
        r#"
        local generation = redis.call('GET', KEYS[1])
        local index_generation = redis.call('GET', KEYS[2])
        return {generation or false, index_generation or false}
        "#,
    )
}

fn session_index_lookup_script() -> redis::Script {
    redis::Script::new(
        r#"
        local encrypted = redis.call('GETEX', KEYS[1], 'EX', ARGV[1])
        local generation = redis.call('GETEX', KEYS[2], 'EX', ARGV[1])
        return {encrypted or false, generation or false}
        "#,
    )
}

fn session_operation_renew_script() -> redis::Script {
    redis::Script::new(
        r#"
        if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
        if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end
        if redis.call('GET', KEYS[3]) ~= ARGV[2] then return 0 end
        redis.call('PEXPIRE', KEYS[1], ARGV[3])
        return 1
        "#,
    )
}

fn session_refresh_commit_script() -> redis::Script {
    redis::Script::new(
        r#"
        if redis.call('GET', KEYS[5]) ~= ARGV[1] then return 0 end
        if redis.call('GET', KEYS[1]) ~= ARGV[2] then return 0 end
        if redis.call('GET', KEYS[4]) ~= ARGV[2] then return 0 end
        if redis.call('EXISTS', KEYS[2]) == 0 or redis.call('EXISTS', KEYS[3]) == 0 then
            return 0
        end
        redis.call('SET', KEYS[1], ARGV[3], 'EX', ARGV[6])
        redis.call('SET', KEYS[2], ARGV[4], 'EX', ARGV[6])
        redis.call('SET', KEYS[3], ARGV[5], 'EX', ARGV[6])
        redis.call('SET', KEYS[4], ARGV[3], 'EX', ARGV[6])
        redis.call('DEL', KEYS[5], KEYS[6])
        return 1
        "#,
    )
}

fn session_revoke_complete_script() -> redis::Script {
    redis::Script::new(
        r#"
        if redis.call('GET', KEYS[5]) ~= ARGV[1] then return 0 end
        if redis.call('GET', KEYS[1]) ~= ARGV[2] then return 0 end
        if redis.call('GET', KEYS[4]) ~= ARGV[2] then return 0 end
        redis.call('DEL', KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5], KEYS[6])
        return 1
        "#,
    )
}

fn session_operation_release_script() -> redis::Script {
    redis::Script::new(
        r#"
        if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
        if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end
        if redis.call('GET', KEYS[3]) ~= ARGV[2] then return 0 end
        redis.call('DEL', KEYS[1])
        if ARGV[3] == '0' then redis.call('DEL', KEYS[4]) end
        return 1
        "#,
    )
}

fn missing_session_index_repair_cas_script() -> redis::Script {
    redis::Script::new(
        r#"
        local generation = redis.call('GET', KEYS[1])
        local session = redis.call('GET', KEYS[2])
        if not generation or generation ~= ARGV[1] then return 0 end
        if not session or session ~= ARGV[2] then return 0 end
        if redis.call('EXISTS', KEYS[3]) ~= 0 or redis.call('EXISTS', KEYS[4]) ~= 0 then
            return -1
        end
        local generation_ttl = redis.call('PTTL', KEYS[1])
        local session_ttl = redis.call('PTTL', KEYS[2])
        if generation_ttl <= 0 or session_ttl <= 0 then return -2 end
        local ttl = math.min(generation_ttl, session_ttl)
        redis.call('PEXPIRE', KEYS[1], ttl)
        redis.call('PEXPIRE', KEYS[2], ttl)
        redis.call('SET', KEYS[3], ARGV[3], 'PX', ttl)
        redis.call('SET', KEYS[4], ARGV[1], 'PX', ttl)
        return 1
        "#,
    )
}

fn lifecycle_fence_migration_cas_script() -> redis::Script {
    redis::Script::new(
        r#"
        local session = redis.call('GET', KEYS[1])
        local session_index = redis.call('GET', KEYS[2])
        if not session or not session_index then return -2 end
        if session ~= ARGV[1] or session_index ~= ARGV[2] then return 0 end

        local generation = redis.call('GET', KEYS[3])
        local index_generation = redis.call('GET', KEYS[4])
        if generation or index_generation then
            if generation and index_generation and generation == index_generation then
                return 2
            end
            return -1
        end

        local session_ttl = redis.call('PTTL', KEYS[1])
        local index_ttl = redis.call('PTTL', KEYS[2])
        if session_ttl <= 0 or index_ttl <= 0 then return -3 end
        local ttl = math.min(session_ttl, index_ttl)
        redis.call('PEXPIRE', KEYS[1], ttl)
        redis.call('PEXPIRE', KEYS[2], ttl)
        redis.call('SET', KEYS[3], ARGV[3], 'PX', ttl)
        redis.call('SET', KEYS[4], ARGV[3], 'PX', ttl)
        return 1
        "#,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleFenceStatus {
    Required,
    Installed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleFenceMigration {
    Installed,
    AlreadyInstalled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleFenceInventoryEntry {
    pub session_key: String,
    pub index_key: String,
    pub generation_key: String,
    pub index_generation_key: String,
    pub pair_fingerprint: String,
    pub status: LifecycleFenceStatus,
}

struct ValidatedLifecyclePair {
    session_key: String,
    index_key: String,
    generation_key: String,
    index_generation_key: String,
    encrypted_session: String,
    encrypted_index: String,
}

#[derive(Default)]
struct LifecycleInventoryKeys {
    primary: Vec<String>,
    index: HashSet<String>,
    generation: HashSet<String>,
    index_generation: HashSet<String>,
}

fn partition_lifecycle_inventory_keys(
    key_prefix: &str,
    keys: Vec<String>,
) -> LifecycleInventoryKeys {
    let primary_prefix = format!("{key_prefix}session:");
    let index_prefix = format!("{key_prefix}session_index:");
    let generation_prefix = format!("{key_prefix}session_generation:");
    let index_generation_prefix = format!("{key_prefix}session_index_generation:");
    let mut inventory = LifecycleInventoryKeys::default();
    for key in keys {
        if key.starts_with(&primary_prefix) {
            inventory.primary.push(key);
        } else if key.starts_with(&index_prefix) {
            inventory.index.insert(key);
        } else if key.starts_with(&generation_prefix) {
            inventory.generation.insert(key);
        } else if key.starts_with(&index_generation_prefix) {
            inventory.index_generation.insert(key);
        }
    }
    inventory
}

fn validated_https_url(value: &str) -> Result<url::Url, SessionStoreError> {
    let parsed = url::Url::parse(value).map_err(|_| other_err("legacy endpoint is invalid"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(other_err("legacy endpoint is not an approved HTTPS URL"));
    }
    Ok(parsed)
}

fn same_origin(left: &url::Url, right: &url::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn validate_legacy_records(
    catbird: &serde_json::Value,
    dpop_pair: &serde_json::Value,
    oauth: &serde_json::Value,
) -> Result<(), SessionStoreError> {
    use base64::Engine;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let did = catbird["did"]
        .as_str()
        .ok_or_else(|| other_err("legacy session missing DID"))?;
    let pds = validated_https_url(
        catbird["pds_url"]
            .as_str()
            .ok_or_else(|| other_err("legacy session missing PDS URL"))?,
    )?;
    let tokens = oauth["token_set"]
        .as_object()
        .ok_or_else(|| other_err("legacy OAuth record missing token set"))?;
    if tokens.get("sub").and_then(|value| value.as_str()) != Some(did) {
        return Err(other_err("legacy OAuth subject does not match account DID"));
    }
    let issuer = validated_https_url(
        tokens
            .get("iss")
            .and_then(|value| value.as_str())
            .ok_or_else(|| other_err("legacy OAuth record missing issuer"))?,
    )?;
    let audience = validated_https_url(
        tokens
            .get("aud")
            .and_then(|value| value.as_str())
            .ok_or_else(|| other_err("legacy OAuth record missing audience"))?,
    )?;
    if !same_origin(&pds, &audience) {
        return Err(other_err("legacy OAuth endpoints are inconsistent"));
    }
    let _ = issuer;
    for field in ["access_token", "refresh_token"] {
        if let Some(catbird_value) = catbird.get(field).and_then(|value| value.as_str()) {
            if tokens.get(field).and_then(|value| value.as_str()) != Some(catbird_value) {
                return Err(other_err(
                    "legacy OAuth token does not match Catbird session",
                ));
            }
        } else if field == "access_token" {
            return Err(other_err("legacy Catbird session missing access token"));
        }
    }

    let public = dpop_pair["public_jwk"]
        .as_object()
        .ok_or_else(|| other_err("legacy DPoP public key is invalid"))?;
    let private = dpop_pair["private_key_bytes"]
        .as_str()
        .ok_or_else(|| other_err("legacy DPoP private key is missing"))?;
    let mut full_jwk = serde_json::Value::Object(public.clone());
    full_jwk
        .as_object_mut()
        .expect("object created above")
        .insert(
            "d".to_string(),
            serde_json::Value::String(private.to_string()),
        );
    if oauth.get("dpop_key") != Some(&full_jwk) {
        return Err(other_err("legacy DPoP records do not match"));
    }

    let scalar = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(private)
        .map_err(|_| other_err("legacy DPoP private key encoding is invalid"))?;
    let secret = p256::SecretKey::from_slice(&scalar)
        .map_err(|_| other_err("legacy DPoP private key is invalid"))?;
    let encoded = secret.public_key().to_encoded_point(false);
    let expected_x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(
            public
                .get("x")
                .and_then(|value| value.as_str())
                .ok_or_else(|| other_err("legacy DPoP x coordinate is missing"))?,
        )
        .map_err(|_| other_err("legacy DPoP x coordinate is invalid"))?;
    let expected_y = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(
            public
                .get("y")
                .and_then(|value| value.as_str())
                .ok_or_else(|| other_err("legacy DPoP y coordinate is missing"))?,
        )
        .map_err(|_| other_err("legacy DPoP y coordinate is invalid"))?;
    if encoded.x().map(|value| &value[..]) != Some(expected_x.as_slice())
        || encoded.y().map(|value| &value[..]) != Some(expected_y.as_slice())
    {
        return Err(other_err(
            "legacy DPoP private key does not match public key",
        ));
    }
    Ok(())
}

/// Redis-backed auth store for Jacquard OAuth.
///
/// This schema requires the standalone Redis/Valkey topology enforced during
/// application and migration-tool connection setup. Several lifecycle
/// transitions atomically access the primary, reverse-index, generation,
/// operation, and uncertainty keys, while inventory audits require a complete
/// server-wide SCAN. A node-local Redis Cluster connection is therefore
/// rejected before this store is constructed in production paths.
///
/// Key schema:
///   `{prefix}session:<opaque-id>`       → encrypted ClientSessionData JSON
///   `{prefix}session_generation:<opaque-id>` → opaque lifecycle generation
///   `{prefix}auth_req:<opaque-id>`      → encrypted AuthRequestData JSON
///   `{prefix}session_index:<opaque-id>` → encrypted DID string
///   `{prefix}session_index_generation:<opaque-id>` → index lifecycle generation
#[derive(Clone)]
pub struct RedisAuthStore {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
    session_ttl: u64,
    keyring: Keyring,
}

impl RedisAuthStore {
    pub(crate) fn encryption_keyring(&self) -> Keyring {
        self.keyring.clone()
    }

    pub fn from_environment(
        redis: redis::aio::ConnectionManager,
        key_prefix: String,
        session_ttl: u64,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use super::redis_crypto::{KeyMaterial, MAX_PREVIOUS_KEYS};
        use base64::Engine;

        fn decode(name: &str, encoded: &str) -> Result<[u8; 32], String> {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| format!("{name} must be valid base64"))?;
            bytes
                .try_into()
                .map_err(|_| format!("{name} must decode to exactly 32 bytes"))
        }

        let active_encoded = std::env::var("SESSION_ENCRYPTION_KEY")
            .map_err(|_| "SESSION_ENCRYPTION_KEY is required")?;
        let active = KeyMaterial::new(
            std::env::var("SESSION_ENCRYPTION_KEY_ID").unwrap_or_else(|_| "active".to_string()),
            decode("SESSION_ENCRYPTION_KEY", &active_encoded)?,
        )?;
        let mut previous = Vec::new();
        for entry in std::env::var("SESSION_ENCRYPTION_PREVIOUS_KEYS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let (kid, encoded) = entry
                .split_once('=')
                .ok_or("previous encryption keys must use kid=base64")?;
            previous.push(KeyMaterial::new(
                kid,
                decode("SESSION_ENCRYPTION_PREVIOUS_KEYS", encoded)?,
            )?);
        }
        if previous.len() > MAX_PREVIOUS_KEYS {
            return Err("too many previous encryption keys".into());
        }
        let identifier_encoded = std::env::var("SESSION_IDENTIFIER_HMAC_KEY")
            .map_err(|_| "SESSION_IDENTIFIER_HMAC_KEY is required")?;
        let keyring = Keyring::new(
            active,
            previous,
            decode("SESSION_IDENTIFIER_HMAC_KEY", &identifier_encoded)?,
        )?;
        Ok(Self::new(redis, key_prefix, session_ttl, keyring))
    }

    pub fn new(
        redis: redis::aio::ConnectionManager,
        key_prefix: String,
        session_ttl: u64,
        keyring: Keyring,
    ) -> Self {
        Self {
            redis,
            key_prefix,
            session_ttl,
            keyring,
        }
    }

    fn session_key(&self, did: &str, session_id: &str) -> String {
        let logical = format!("{did}\0{session_id}");
        format!(
            "{}session:{}",
            self.key_prefix,
            self.keyring.opaque_id("session", &logical)
        )
    }

    fn session_generation_key(&self, did: &str, session_id: &str) -> String {
        let logical = format!("{did}\0{session_id}");
        format!(
            "{}session_generation:{}",
            self.key_prefix,
            self.keyring.opaque_id("session-generation", &logical)
        )
    }

    fn session_operation_key(&self, did: &str, session_id: &str) -> String {
        let logical = format!("{did}\0{session_id}");
        format!(
            "{}session_operation:{}",
            self.key_prefix,
            self.keyring.opaque_id("session-operation", &logical)
        )
    }

    fn session_uncertain_key(&self, did: &str, session_id: &str) -> String {
        let logical = format!("{did}\0{session_id}");
        format!(
            "{}session_uncertain:{}",
            self.key_prefix,
            self.keyring.opaque_id("session-uncertain", &logical)
        )
    }

    fn session_operation_value(
        owner: &str,
        kind: SessionOperationKind,
        generation: &str,
    ) -> Result<String, SessionStoreError> {
        let kind = match kind {
            SessionOperationKind::Refresh => "refresh",
            SessionOperationKind::Revoke => "revoke",
        };
        serde_json::to_string(&(owner, kind, generation)).map_err(SessionStoreError::Serde)
    }

    fn operation_ttl_millis(ttl: Duration) -> u64 {
        ttl.as_millis().clamp(1, u64::MAX as u128) as u64
    }

    fn auth_req_key(&self, state: &str) -> String {
        format!(
            "{}auth_req:{}",
            self.key_prefix,
            self.keyring.opaque_id("auth-request", state)
        )
    }

    fn session_index_key(&self, session_id: &str) -> String {
        format!(
            "{}session_index:{}",
            self.key_prefix,
            self.keyring.opaque_id("session-index", session_id)
        )
    }

    fn session_index_generation_key(&self, session_id: &str) -> String {
        format!(
            "{}session_index_generation:{}",
            self.key_prefix,
            self.keyring
                .opaque_id("session-index-generation", session_id)
        )
    }

    async fn scan_session_keys(&self) -> Result<Vec<String>, SessionStoreError> {
        let pattern = format!("{}*", self.key_prefix);
        let mut conn = self.redis.clone();
        let mut collection = ScanCollection::default();
        let mut cursor = 0u64;
        loop {
            let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100usize)
                .query_async(&mut conn)
                .await
                .map_err(redis_err)?;
            let complete = collection.record_page(next_cursor, batch)?;
            cursor = next_cursor;
            if complete {
                break;
            }
        }
        Ok(collection.into_keys())
    }

    async fn validated_lifecycle_pair(
        &self,
        physical_session_key: &str,
    ) -> Result<ValidatedLifecyclePair, SessionStoreError> {
        let session_namespace = format!("{}session:", self.key_prefix);
        if !physical_session_key.starts_with(&session_namespace) {
            return Err(other_err(
                "session record is outside the encrypted envelope namespace",
            ));
        }
        let mut conn = self.redis.clone();
        let encrypted_session: String = conn.get(physical_session_key).await.map_err(redis_err)?;
        let session_context = RecordContext::new("session", physical_session_key);
        let session_json =
            open_utf8_with_status(&self.keyring, &session_context, &encrypted_session)
                .map_err(|error| other_err(&format!("invalid encrypted session: {error}")))?
                .0;
        let session: ClientSessionData<'_> =
            serde_json::from_str(&session_json).map_err(SessionStoreError::Serde)?;
        let expected_session_key =
            self.session_key(session.account_did.as_str(), &session.session_id);
        if expected_session_key != physical_session_key {
            return Err(other_err(
                "encrypted session key does not match its identity",
            ));
        }

        let index_key = self.session_index_key(&session.session_id);
        let encrypted_index: String = conn.get(&index_key).await.map_err(redis_err)?;
        let index_context = RecordContext::new("session_index", &index_key);
        let index_did = open_utf8_with_status(&self.keyring, &index_context, &encrypted_index)
            .map_err(|error| other_err(&format!("invalid encrypted session index: {error}")))?
            .0;
        if index_did != session.account_did.as_str() {
            return Err(other_err(
                "encrypted session index does not match its session",
            ));
        }

        Ok(ValidatedLifecyclePair {
            session_key: expected_session_key,
            index_key,
            generation_key: self
                .session_generation_key(session.account_did.as_str(), &session.session_id),
            index_generation_key: self.session_index_generation_key(&session.session_id),
            encrypted_session,
            encrypted_index,
        })
    }

    /// Inspect an authenticated encrypted-envelope pair without changing it.
    /// Mixed or mismatched fence state is an error, never a repair candidate.
    pub async fn inspect_lifecycle_fence_offline(
        &self,
        physical_session_key: &str,
    ) -> Result<LifecycleFenceStatus, SessionStoreError> {
        let pair = self.validated_lifecycle_pair(physical_session_key).await?;
        self.inspect_validated_lifecycle_fence_offline(&pair).await
    }

    async fn inspect_validated_lifecycle_fence_offline(
        &self,
        pair: &ValidatedLifecyclePair,
    ) -> Result<LifecycleFenceStatus, SessionStoreError> {
        let mut conn = self.redis.clone();
        let (generation, index_generation): (Option<String>, Option<String>) =
            lifecycle_pair_read_script()
                .key(&pair.generation_key)
                .key(&pair.index_generation_key)
                .invoke_async(&mut conn)
                .await
                .map_err(redis_err)?;
        match (generation, index_generation) {
            (None, None) => Ok(LifecycleFenceStatus::Required),
            (Some(generation), Some(index_generation))
                if !generation.is_empty() && generation == index_generation =>
            {
                Ok(LifecycleFenceStatus::Installed)
            }
            _ => Err(other_err(
                "session lifecycle fence state is mixed or invalid",
            )),
        }
    }

    /// Capture and validate the complete encrypted session inventory. Every
    /// reverse index and lifecycle fence must be derived from exactly one
    /// authenticated primary; orphaned or partial namespaces fail closed.
    pub async fn audit_lifecycle_fence_inventory_offline(
        &self,
    ) -> Result<Vec<LifecycleFenceInventoryEntry>, SessionStoreError> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        // One duplicate- and cursor-protected SCAN covers every lifecycle
        // namespace. Redis MATCH still traverses the full database, so four
        // namespace-specific scans would multiply server work by four.
        let inventory =
            partition_lifecycle_inventory_keys(&self.key_prefix, self.scan_session_keys().await?);
        let actual_index_keys = inventory.index;
        let actual_generation_keys = inventory.generation;
        let actual_index_generation_keys = inventory.index_generation;

        // Audit is read-only and fail-closed if records move underneath it.
        // Bound concurrency so a large inventory cannot create unbounded
        // connections or Redis pressure while avoiding a serial 4N latency path.
        let mut entries: Vec<LifecycleFenceInventoryEntry> = stream::iter(inventory.primary)
            .map(|session_key| async move {
                let pair = self.validated_lifecycle_pair(&session_key).await?;
                let status = self
                    .inspect_validated_lifecycle_fence_offline(&pair)
                    .await?;
                // Collapse ciphertexts into a compact authenticated fingerprint
                // before leaving the bounded future. At most 16 full pairs are
                // resident; the global collection retains metadata only.
                let mut fingerprint = Sha256::new();
                fingerprint.update((pair.encrypted_session.len() as u64).to_be_bytes());
                fingerprint.update(pair.encrypted_session.as_bytes());
                fingerprint.update((pair.encrypted_index.len() as u64).to_be_bytes());
                fingerprint.update(pair.encrypted_index.as_bytes());
                Ok::<_, SessionStoreError>(LifecycleFenceInventoryEntry {
                    session_key: pair.session_key,
                    index_key: pair.index_key,
                    generation_key: pair.generation_key,
                    index_generation_key: pair.index_generation_key,
                    pair_fingerprint: base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(fingerprint.finalize()),
                    status,
                })
            })
            .buffer_unordered(MAX_LIFECYCLE_AUDIT_CONCURRENCY)
            .try_collect()
            .await?;

        let mut expected_index_keys = HashSet::new();
        let mut expected_generation_keys = HashSet::new();
        let mut expected_index_generation_keys = HashSet::new();
        for entry in &entries {
            if !expected_index_keys.insert(entry.index_key.clone()) {
                return Err(other_err("encrypted session inventory is not one-to-one"));
            }
            if entry.status == LifecycleFenceStatus::Installed
                && (!expected_generation_keys.insert(entry.generation_key.clone())
                    || !expected_index_generation_keys.insert(entry.index_generation_key.clone()))
            {
                return Err(other_err(
                    "encrypted session fence inventory is not one-to-one",
                ));
            }
        }
        if actual_index_keys != expected_index_keys
            || actual_generation_keys != expected_generation_keys
            || actual_index_generation_keys != expected_index_generation_keys
        {
            return Err(other_err(
                "encrypted session inventory contains orphaned or missing index/fence records",
            ));
        }
        entries.sort_by(|left, right| left.session_key.cmp(&right.session_key));
        Ok(entries)
    }

    /// Install lifecycle fences for one validated encrypted-envelope pair.
    /// The compare-and-set revalidates both ciphertexts and their positive
    /// TTLs, so a concurrent refresh/create/delete causes a hard failure.
    pub async fn migrate_pre_generation_session_offline(
        &self,
        physical_session_key: &str,
    ) -> Result<LifecycleFenceMigration, SessionStoreError> {
        let pair = self.validated_lifecycle_pair(physical_session_key).await?;
        let generation = new_lifecycle_generation();
        let mut conn = self.redis.clone();
        let result: i64 = lifecycle_fence_migration_cas_script()
            .key(&pair.session_key)
            .key(&pair.index_key)
            .key(&pair.generation_key)
            .key(&pair.index_generation_key)
            .arg(&pair.encrypted_session)
            .arg(&pair.encrypted_index)
            .arg(generation)
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;
        match result {
            1 => Ok(LifecycleFenceMigration::Installed),
            2 => Ok(LifecycleFenceMigration::AlreadyInstalled),
            0 => Err(other_err(
                "session changed concurrently during lifecycle migration",
            )),
            -1 => Err(other_err(
                "session lifecycle fence state is mixed or invalid",
            )),
            -2 => Err(other_err(
                "session pair disappeared during lifecycle migration",
            )),
            -3 => Err(other_err("session pair has no bounded positive expiry")),
            _ => Err(other_err(
                "session lifecycle migration returned an invalid result",
            )),
        }
    }

    /// Look up the DID associated with a session_id.
    ///
    /// iOS sends only `session_id` (not DID), but `ClientAuthStore` needs
    /// `(did, session_id)`. This index bridges that gap.
    ///
    /// Sliding expiration: every successful lookup resets the index entry's
    /// TTL back to the configured session TTL via a single atomic read.
    /// Previously this was a plain `GET`, so the TTL only slid on token
    /// refresh (`update_session`). A device idle for
    /// longer than the TTL (no refresh) would lose its index entry and get
    /// force-logged-out on the next request even though the session was
    /// otherwise recoverable. Reading on a rolling window now keeps any
    /// actively-used session alive.
    pub async fn lookup_did_for_session(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, redis::RedisError> {
        let key = self.session_index_key(session_id);
        let index_generation_key = self.session_index_generation_key(session_id);
        let mut conn = self.redis.clone();
        let (encrypted, index_generation): (Option<String>, Option<String>) =
            session_index_lookup_script()
                .key(&key)
                .key(&index_generation_key)
                .arg(self.session_ttl)
                .invoke_async(&mut conn)
                .await?;
        let Some(value) = encrypted else {
            return Ok(None);
        };
        let index_generation = index_generation
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "session index lifecycle generation is missing",
                ))
            })?;
        let context = RecordContext::new("session_index", &key);
        let (did, needs_rewrap) =
            open_utf8_with_status(&self.keyring, &context, &value).map_err(|error| {
                redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "invalid encrypted session index",
                    error.to_string(),
                ))
            })?;
        if needs_rewrap {
            let rewrapped = self
                .keyring
                .seal(&context, did.as_bytes())
                .map_err(|error| {
                    redis::RedisError::from((
                        redis::ErrorKind::TypeError,
                        "failed to rewrap session index",
                        error.to_string(),
                    ))
                })?;
            let result: i64 = expiry_preserving_cas_script()
                .key(&key)
                .arg(&value)
                .arg(&rewrapped)
                .invoke_async(&mut conn)
                .await?;
            if interpret_session_rewrap_result(result) {
                tracing::info!(
                    record_kind = "session_index",
                    "Rewrapped Redis record with active key"
                );
            }
        }
        let primary_generation_key = self.session_generation_key(&did, session_id);
        let primary_generation: Option<String> = conn
            .get_ex(
                &primary_generation_key,
                Expiry::EX(self.session_ttl as usize),
            )
            .await?;
        match primary_generation {
            Some(primary_generation) if primary_generation == index_generation => {}
            None => return Ok(None),
            Some(_) => {
                return Err(redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "session index lifecycle generation does not match primary",
                )))
            }
        }
        Ok(Some(did))
    }

    /// Repair a fully absent reverse-index pair using an authoritative DID
    /// and session ID from a trusted background-job record. Ordinary session
    /// reads and updates remain strict: mixed or conflicting index state is
    /// corruption and cannot enter this repair path.
    pub async fn repair_missing_session_index(
        &self,
        expected_did: &Did<'_>,
        expected_session_id: &str,
    ) -> Result<bool, SessionStoreError> {
        let session_key = self.session_key(expected_did.as_str(), expected_session_id);
        let generation_key =
            self.session_generation_key(expected_did.as_str(), expected_session_id);
        let index_key = self.session_index_key(expected_session_id);
        let index_generation_key = self.session_index_generation_key(expected_session_id);
        let mut conn = self.redis.clone();
        let (generation, encrypted_session, existing_index, existing_index_generation): (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            // This is an optimistic read only. The repair Lua script revalidates
            // the exact ciphertext, generation, and absent index pair atomically.
        ) = redis::pipe()
            .get(&generation_key)
            .get(&session_key)
            .get(&index_key)
            .get(&index_generation_key)
            .query_async(&mut conn)
            .await
            .map_err(redis_err)?;

        let (generation, encrypted_session) = match (generation, encrypted_session) {
            (Some(generation), Some(encrypted_session)) => (generation, encrypted_session),
            // An expired/deleted primary is authoritative even if a stale
            // reverse-index pair has not expired yet. Report absence to the
            // background caller so it can revoke the dead registration.
            (None, None) => return Ok(false),
            _ => {
                return Err(other_err(
                    "session index repair found partial primary lifecycle state",
                ))
            }
        };
        if existing_index.is_some() || existing_index_generation.is_some() {
            return Err(other_err(
                "session index repair requires both index records to be absent",
            ));
        }
        if generation.is_empty() {
            return Err(other_err(
                "session index repair found an empty lifecycle generation",
            ));
        }

        let context = RecordContext::new("session", &session_key);
        let (json, _) = open_utf8_with_status(&self.keyring, &context, &encrypted_session)
            .map_err(|error| other_err(&format!("invalid encrypted session: {error}")))?;
        let session: ClientSessionData<'_> =
            serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;
        if session.account_did.as_str() != expected_did.as_str()
            || session.session_id.as_ref() != expected_session_id
        {
            return Err(other_err(
                "session index repair primary identity does not match expected DID and session",
            ));
        }
        let encrypted_index = self
            .keyring
            .seal(
                &RecordContext::new("session_index", &index_key),
                expected_did.as_str().as_bytes(),
            )
            .map_err(|error| other_err(&format!("failed to encrypt session index: {error}")))?;

        let result: i64 = missing_session_index_repair_cas_script()
            .key(&generation_key)
            .key(&session_key)
            .key(&index_key)
            .key(&index_generation_key)
            .arg(&generation)
            .arg(&encrypted_session)
            .arg(encrypted_index)
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;
        match result {
            1 => Ok(true),
            0 => Err(other_err(
                "session changed concurrently during index repair",
            )),
            -1 => Err(other_err(
                "session index appeared concurrently during repair",
            )),
            -2 => Err(other_err(
                "session index repair requires expiring primary records",
            )),
            _ => Err(other_err("session index repair returned an invalid result")),
        }
    }

    /// Convert one legacy plaintext three-key record. This is intentionally
    /// exposed only for the explicit offline migration binary; runtime auth
    /// never calls it.
    pub async fn migrate_legacy_session_offline(
        &self,
        session_id: &str,
    ) -> Result<bool, SessionStoreError> {
        let mut conn = self.redis.clone();
        let catbird_key = format!("{}catbird_session:{}", self.key_prefix, session_id);
        let dpop_key = format!("{}dpop_key:{}", self.key_prefix, session_id);
        let Some(catbird_json): Option<String> = conn.get(&catbird_key).await.map_err(redis_err)?
        else {
            return Ok(false);
        };
        let Some(dpop_json): Option<String> = conn.get(&dpop_key).await.map_err(redis_err)? else {
            return Err(other_err("legacy session missing DPoP record"));
        };
        let catbird: serde_json::Value =
            serde_json::from_str(&catbird_json).map_err(SessionStoreError::Serde)?;
        let did_str = catbird["did"]
            .as_str()
            .ok_or_else(|| other_err("legacy session missing DID"))?;
        let pds_url = catbird["pds_url"]
            .as_str()
            .ok_or_else(|| other_err("legacy session missing PDS URL"))?;
        let did = Did::new_owned(did_str)
            .map_err(|error| other_err(&format!("invalid legacy DID: {error}")))?;

        // The actual atrium RedisSessionStore keyed OAuth sessions by DID,
        // not by the Catbird session identifier.
        let oauth_key = format!("{}oauth_session:{}", self.key_prefix, did_str);
        let Some(oauth_json): Option<String> = conn.get(&oauth_key).await.map_err(redis_err)?
        else {
            return Err(other_err("legacy session missing OAuth record"));
        };
        let oauth: serde_json::Value =
            serde_json::from_str(&oauth_json).map_err(SessionStoreError::Serde)?;

        let pair: serde_json::Value =
            serde_json::from_str(&dpop_json).map_err(SessionStoreError::Serde)?;
        validate_legacy_records(&catbird, &pair, &oauth)?;
        let full_jwk = oauth["dpop_key"].clone();
        let dpop_jwk: jose_jwk::Key =
            serde_json::from_value(full_jwk).map_err(SessionStoreError::Serde)?;
        let token_set = &oauth["token_set"];
        let issuer = token_set["iss"]
            .as_str()
            .ok_or_else(|| other_err("legacy OAuth issuer missing"))?;
        let audience = token_set["aud"]
            .as_str()
            .ok_or_else(|| other_err("legacy OAuth audience missing"))?;
        let access_token = token_set["access_token"]
            .as_str()
            .ok_or_else(|| other_err("legacy OAuth access token missing"))?;
        let refresh_token = token_set["refresh_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .map(|token| token.to_string().into());
        let expires_at = token_set["expires_at"].as_str().and_then(|value| {
            jacquard_common::types::string::Datetime::try_from(value.to_string()).ok()
        });
        let session = ClientSessionData {
            lifecycle_generation: "".into(),
            account_did: did.clone(),
            session_id: session_id.to_string().into(),
            host_url: pds_url.to_string().into(),
            authserver_url: issuer.to_string().into(),
            authserver_token_endpoint: "".into(),
            authserver_revocation_endpoint: None,
            scopes: vec![jacquard_oauth::scopes::Scope::Atproto],
            dpop_data: DpopClientData {
                dpop_key: dpop_jwk,
                dpop_authserver_nonce: "".into(),
                dpop_host_nonce: "".into(),
            },
            token_set: TokenSet {
                iss: issuer.to_string().into(),
                sub: did.clone(),
                aud: audience.to_string().into(),
                scope: token_set["scope"]
                    .as_str()
                    .map(|value| value.to_string().into()),
                refresh_token,
                access_token: access_token.to_string().into(),
                token_type: OAuthTokenType::DPoP,
                expires_at,
            },
        };

        self.create_session(session).await?;
        let verified = self
            .get_session(&did, session_id)
            .await?
            .filter(|record| record.account_did == did && record.session_id == session_id)
            .ok_or_else(|| other_err("migrated session readback verification failed"))?;
        if verified.token_set.access_token != access_token {
            return Err(other_err("migrated token readback verification failed"));
        }
        conn.del::<_, ()>(&[catbird_key.as_str(), dpop_key.as_str(), oauth_key.as_str()])
            .await
            .map_err(redis_err)?;
        Ok(true)
    }

    /// Convert one pre-envelope Jacquard session and plaintext index. The
    /// caller must invoke this from the time-bounded offline migration CLI.
    pub async fn migrate_pre_envelope_session_offline(
        &self,
        session_id: &str,
    ) -> Result<bool, SessionStoreError> {
        let mut conn = self.redis.clone();
        let old_index_key = format!("{}session_index:{}", self.key_prefix, session_id);
        let Some(did_str): Option<String> = conn.get(&old_index_key).await.map_err(redis_err)?
        else {
            return Ok(false);
        };
        if did_str.starts_with("v1:") {
            return Ok(false);
        }
        let did = Did::new_owned(did_str.as_str())
            .map_err(|error| other_err(&format!("invalid pre-envelope DID: {error}")))?;
        let old_session_key = format!("{}session:{}_{}", self.key_prefix, did_str, session_id);
        let Some(encrypted): Option<String> =
            conn.get(&old_session_key).await.map_err(redis_err)?
        else {
            return Ok(false);
        };
        let json = if encrypted.trim_start().starts_with('{') {
            encrypted
        } else {
            String::from_utf8(
                self.keyring
                    .open_legacy_active(&encrypted)
                    .map_err(|error| other_err(&format!("invalid pre-envelope record: {error}")))?,
            )
            .map_err(|_| other_err("pre-envelope record is not UTF-8"))?
        };
        let session: ClientSessionData<'_> =
            serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;
        if session.account_did != did || session.session_id != session_id {
            return Err(other_err("pre-envelope session identity mismatch"));
        }
        self.create_session(session.into_static()).await?;
        self.get_session(&did, session_id)
            .await?
            .ok_or_else(|| other_err("pre-envelope migration readback failed"))?;
        conn.del::<_, ()>(&old_session_key)
            .await
            .map_err(redis_err)?;
        conn.del::<_, ()>(&old_index_key).await.map_err(redis_err)?;
        Ok(true)
    }
}

impl ClientAuthStore for RedisAuthStore {
    /// Sliding expiration: fetch the session blob with `GETEX`, resetting its
    /// TTL to `self.session_ttl` on every successful read so the blob slides
    /// in lockstep with the `session_index` entry (see
    /// `lookup_did_for_session`). Keeps an actively-used session from expiring
    /// on the 30-day idle window even when no token refresh occurs.
    async fn get_session(
        &self,
        did: &Did<'_>,
        session_id: &str,
    ) -> Result<Option<ClientSessionData<'_>>, SessionStoreError> {
        let key = self.session_key(did.as_str(), session_id);
        let generation_key = self.session_generation_key(did.as_str(), session_id);
        let index_key = self.session_index_key(session_id);
        let index_generation_key = self.session_index_generation_key(session_id);
        let operation_key = self.session_operation_key(did.as_str(), session_id);
        let uncertain_key = self.session_uncertain_key(did.as_str(), session_id);
        let mut conn = self.redis.clone();

        let (status, data, generation): (i64, Option<String>, Option<String>) =
            session_get_cas_script()
                .key(&generation_key)
                .key(&key)
                .key(&index_key)
                .key(&index_generation_key)
                .key(&operation_key)
                .key(&uncertain_key)
                .arg(self.session_ttl)
                .invoke_async(&mut conn)
                .await
                .map_err(redis_err)?;

        if status == -1 {
            return Err(session_operation_active_store_error());
        }
        if status == -2 {
            return Err(reauthentication_required_store_error());
        }
        if status == 0 {
            return Ok(None);
        }

        match data {
            Some(encrypted) => {
                let generation = generation
                    .filter(|generation| !generation.is_empty())
                    .ok_or_else(|| other_err("session lifecycle generation is missing"))?;
                let context = RecordContext::new("session", &key);
                let (json, needs_rewrap) =
                    open_utf8_with_status(&self.keyring, &context, &encrypted).map_err(
                        |error| other_err(&format!("invalid encrypted session: {error}")),
                    )?;
                if needs_rewrap {
                    let rewrapped =
                        self.keyring
                            .seal(&context, json.as_bytes())
                            .map_err(|error| {
                                other_err(&format!("failed to rewrap session: {error}"))
                            })?;
                    let result: i64 = expiry_preserving_cas_script()
                        .key(&key)
                        .arg(&encrypted)
                        .arg(&rewrapped)
                        .invoke_async(&mut conn)
                        .await
                        .map_err(redis_err)?;
                    if interpret_session_rewrap_result(result) {
                        tracing::info!(
                            record_kind = "session",
                            "Rewrapped Redis record with active key"
                        );
                    }
                }
                let mut session: ClientSessionData<'_> =
                    serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;
                session.lifecycle_generation = generation.into();
                Ok(Some(session.into_static()))
            }
            None => Ok(None),
        }
    }

    async fn create_session(
        &self,
        mut session: ClientSessionData<'_>,
    ) -> Result<ClientSessionData<'static>, SessionStoreError> {
        session.lifecycle_generation = new_lifecycle_generation().into();
        let key = self.session_key(session.account_did.as_str(), &session.session_id);
        let generation_key =
            self.session_generation_key(session.account_did.as_str(), &session.session_id);
        let json = serde_json::to_string(&session).map_err(SessionStoreError::Serde)?;
        let encrypted = self
            .keyring
            .seal(&RecordContext::new("session", &key), json.as_bytes())
            .map_err(|error| other_err(&format!("failed to encrypt session: {error}")))?;

        let index_key = self.session_index_key(&session.session_id);
        let index_generation_key = self.session_index_generation_key(&session.session_id);
        let operation_key =
            self.session_operation_key(session.account_did.as_str(), &session.session_id);
        let uncertain_key =
            self.session_uncertain_key(session.account_did.as_str(), &session.session_id);
        let encrypted_index = self
            .keyring
            .seal(
                &RecordContext::new("session_index", &index_key),
                session.account_did.as_str().as_bytes(),
            )
            .map_err(|error| other_err(&format!("failed to encrypt session index: {error}")))?;

        let mut conn = self.redis.clone();
        let result: i64 = session_create_script()
            .key(&generation_key)
            .key(&key)
            .key(&index_key)
            .key(&index_generation_key)
            .key(&operation_key)
            .key(&uncertain_key)
            .arg(session.lifecycle_generation.as_ref())
            .arg(encrypted)
            .arg(encrypted_index)
            .arg(self.session_ttl)
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;
        if result != 1 {
            return Err(other_err("session creation returned an invalid result"));
        }

        Ok(session.into_static())
    }

    async fn update_session(
        &self,
        session: ClientSessionData<'_>,
    ) -> Result<bool, SessionStoreError> {
        if session.lifecycle_generation.is_empty() {
            return Ok(false);
        }
        let key = self.session_key(session.account_did.as_str(), &session.session_id);
        let generation_key =
            self.session_generation_key(session.account_did.as_str(), &session.session_id);
        let json = serde_json::to_string(&session).map_err(SessionStoreError::Serde)?;
        let encrypted = self
            .keyring
            .seal(&RecordContext::new("session", &key), json.as_bytes())
            .map_err(|error| other_err(&format!("failed to encrypt session: {error}")))?;

        let index_key = self.session_index_key(&session.session_id);
        let index_generation_key = self.session_index_generation_key(&session.session_id);
        let operation_key =
            self.session_operation_key(session.account_did.as_str(), &session.session_id);
        let uncertain_key =
            self.session_uncertain_key(session.account_did.as_str(), &session.session_id);
        let encrypted_index = self
            .keyring
            .seal(
                &RecordContext::new("session_index", &index_key),
                session.account_did.as_str().as_bytes(),
            )
            .map_err(|error| other_err(&format!("failed to encrypt session index: {error}")))?;
        let mut conn = self.redis.clone();
        let result: i64 = session_update_cas_script()
            .key(&generation_key)
            .key(&key)
            .key(&index_key)
            .key(&index_generation_key)
            .key(&operation_key)
            .key(&uncertain_key)
            .arg(session.lifecycle_generation.as_ref())
            .arg(encrypted)
            .arg(encrypted_index)
            .arg(self.session_ttl)
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;
        Ok(result == 1)
    }

    async fn delete_session(
        &self,
        did: &Did<'_>,
        session_id: &str,
        lifecycle_generation: &str,
    ) -> Result<bool, SessionStoreError> {
        if lifecycle_generation.is_empty() {
            return Ok(false);
        }
        let key = self.session_key(did.as_str(), session_id);
        let generation_key = self.session_generation_key(did.as_str(), session_id);
        let index_key = self.session_index_key(session_id);
        let index_generation_key = self.session_index_generation_key(session_id);
        let operation_key = self.session_operation_key(did.as_str(), session_id);
        let uncertain_key = self.session_uncertain_key(did.as_str(), session_id);
        let mut conn = self.redis.clone();
        let result: i64 = session_delete_cas_script()
            .key(&generation_key)
            .key(&key)
            .key(&index_key)
            .key(&index_generation_key)
            .key(&operation_key)
            .key(&uncertain_key)
            .arg(lifecycle_generation)
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;
        Ok(result == 1)
    }

    async fn acquire_session_operation(
        &self,
        did: &Did<'_>,
        session_id: &str,
        kind: SessionOperationKind,
        owner: &str,
        ttl: Duration,
    ) -> Result<SessionOperationAcquire, SessionStoreError> {
        let key = self.session_key(did.as_str(), session_id);
        let generation_key = self.session_generation_key(did.as_str(), session_id);
        let index_key = self.session_index_key(session_id);
        let index_generation_key = self.session_index_generation_key(session_id);
        let operation_key = self.session_operation_key(did.as_str(), session_id);
        let uncertain_key = self.session_uncertain_key(did.as_str(), session_id);
        let mut conn = self.redis.clone();
        let (old_generation, encrypted, encrypted_index, old_index_generation): (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            // This optimistic snapshot is authenticated locally and then supplied
            // verbatim to the acquire Lua CAS. Any mixed/concurrent state loses
            // that CAS and is never returned as an acquired session.
        ) = redis::pipe()
            .get(&generation_key)
            .get(&key)
            .get(&index_key)
            .get(&index_generation_key)
            .query_async(&mut conn)
            .await
            .map_err(redis_err)?;
        let (
            Some(old_generation),
            Some(encrypted),
            Some(encrypted_index),
            Some(old_index_generation),
        ) = (
            old_generation,
            encrypted,
            encrypted_index,
            old_index_generation,
        )
        else {
            return Ok(SessionOperationAcquire::Missing);
        };
        if old_generation.is_empty() || old_generation != old_index_generation {
            return Err(other_err(
                "session lifecycle fence state is mixed or invalid",
            ));
        }
        let (json, _) = open_utf8_with_status(
            &self.keyring,
            &RecordContext::new("session", &key),
            &encrypted,
        )
        .map_err(|error| other_err(&format!("invalid encrypted session: {error}")))?;
        let (index_did, _) = open_utf8_with_status(
            &self.keyring,
            &RecordContext::new("session_index", &index_key),
            &encrypted_index,
        )
        .map_err(|error| other_err(&format!("invalid encrypted session index: {error}")))?;
        let mut session: ClientSessionData<'_> =
            serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;
        if session.account_did != *did
            || session.session_id != session_id
            || index_did != did.as_str()
        {
            return Err(other_err("session operation identity binding mismatch"));
        }
        let generation = new_lifecycle_generation();
        let operation_value = Self::session_operation_value(owner, kind, &generation)?;
        let kind_value = match kind {
            SessionOperationKind::Refresh => "refresh",
            SessionOperationKind::Revoke => "revoke",
        };
        let (status, returned_generation, was_uncertain): (i64, Option<String>, i64) =
            session_operation_acquire_script()
                .key(&generation_key)
                .key(&key)
                .key(&index_key)
                .key(&index_generation_key)
                .key(&operation_key)
                .key(&uncertain_key)
                .arg(&old_generation)
                .arg(&encrypted)
                .arg(&encrypted_index)
                .arg(&generation)
                .arg(&operation_value)
                .arg(Self::operation_ttl_millis(ttl))
                .arg(self.session_ttl)
                .arg(kind_value)
                .invoke_async(&mut conn)
                .await
                .map_err(redis_err)?;

        match status {
            0 => return Ok(SessionOperationAcquire::Busy),
            -1 => return Ok(SessionOperationAcquire::Missing),
            1 => {}
            _ => {
                return Err(other_err(
                    "session operation acquisition returned an invalid result",
                ))
            }
        }

        let returned_generation = returned_generation
            .filter(|value| value == &generation)
            .ok_or_else(|| other_err("session operation generation mismatch"))?;
        session.lifecycle_generation = returned_generation.into();
        Ok(SessionOperationAcquire::Acquired(Box::new(
            SessionOperationLease {
                session: session.into_static(),
                owner: owner.into(),
                kind,
                uncertain_refresh: was_uncertain != 0,
            },
        )))
    }

    async fn renew_session_operation(
        &self,
        lease: &SessionOperationLease,
        ttl: Duration,
    ) -> Result<bool, SessionStoreError> {
        let did = lease.session.account_did.as_str();
        let session_id = lease.session.session_id.as_ref();
        let operation_key = self.session_operation_key(did, session_id);
        let generation_key = self.session_generation_key(did, session_id);
        let index_generation_key = self.session_index_generation_key(session_id);
        let operation_value = Self::session_operation_value(
            &lease.owner,
            lease.kind,
            &lease.session.lifecycle_generation,
        )?;
        let mut conn = self.redis.clone();
        let result: i64 = session_operation_renew_script()
            .key(&operation_key)
            .key(&generation_key)
            .key(&index_generation_key)
            .arg(operation_value)
            .arg(lease.session.lifecycle_generation.as_ref())
            .arg(Self::operation_ttl_millis(ttl))
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;
        Ok(result == 1)
    }

    async fn commit_session_refresh(
        &self,
        lease: &SessionOperationLease,
        mut refreshed: ClientSessionData<'_>,
    ) -> Result<Option<ClientSessionData<'static>>, SessionStoreError> {
        if lease.kind != SessionOperationKind::Refresh
            || refreshed.account_did != lease.session.account_did
            || refreshed.session_id != lease.session.session_id
        {
            return Ok(None);
        }
        let did = lease.session.account_did.as_str();
        let session_id = lease.session.session_id.as_ref();
        let key = self.session_key(did, session_id);
        let generation_key = self.session_generation_key(did, session_id);
        let index_key = self.session_index_key(session_id);
        let index_generation_key = self.session_index_generation_key(session_id);
        let operation_key = self.session_operation_key(did, session_id);
        let uncertain_key = self.session_uncertain_key(did, session_id);
        let operation_value = Self::session_operation_value(
            &lease.owner,
            lease.kind,
            &lease.session.lifecycle_generation,
        )?;
        let generation = new_lifecycle_generation();
        refreshed.lifecycle_generation = generation.clone().into();
        let json = serde_json::to_string(&refreshed).map_err(SessionStoreError::Serde)?;
        let encrypted = self
            .keyring
            .seal(&RecordContext::new("session", &key), json.as_bytes())
            .map_err(|error| other_err(&format!("failed to encrypt session: {error}")))?;
        let encrypted_index = self
            .keyring
            .seal(
                &RecordContext::new("session_index", &index_key),
                did.as_bytes(),
            )
            .map_err(|error| other_err(&format!("failed to encrypt session index: {error}")))?;
        let mut conn = self.redis.clone();
        let result: i64 = session_refresh_commit_script()
            .key(&generation_key)
            .key(&key)
            .key(&index_key)
            .key(&index_generation_key)
            .key(&operation_key)
            .key(&uncertain_key)
            .arg(operation_value)
            .arg(lease.session.lifecycle_generation.as_ref())
            .arg(&generation)
            .arg(encrypted)
            .arg(encrypted_index)
            .arg(self.session_ttl)
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;
        Ok((result == 1).then(|| refreshed.into_static()))
    }

    async fn complete_session_revoke(
        &self,
        lease: &SessionOperationLease,
    ) -> Result<bool, SessionStoreError> {
        if lease.kind != SessionOperationKind::Revoke || lease.uncertain_refresh {
            return Ok(false);
        }
        let did = lease.session.account_did.as_str();
        let session_id = lease.session.session_id.as_ref();
        let operation_value = Self::session_operation_value(
            &lease.owner,
            lease.kind,
            &lease.session.lifecycle_generation,
        )?;
        let mut conn = self.redis.clone();
        let result: i64 = session_revoke_complete_script()
            .key(self.session_generation_key(did, session_id))
            .key(self.session_key(did, session_id))
            .key(self.session_index_key(session_id))
            .key(self.session_index_generation_key(session_id))
            .key(self.session_operation_key(did, session_id))
            .key(self.session_uncertain_key(did, session_id))
            .arg(operation_value)
            .arg(lease.session.lifecycle_generation.as_ref())
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;
        Ok(result == 1)
    }

    async fn release_session_operation(
        &self,
        lease: &SessionOperationLease,
        uncertain: bool,
    ) -> Result<bool, SessionStoreError> {
        let did = lease.session.account_did.as_str();
        let session_id = lease.session.session_id.as_ref();
        let operation_value = Self::session_operation_value(
            &lease.owner,
            lease.kind,
            &lease.session.lifecycle_generation,
        )?;
        let mut conn = self.redis.clone();
        let result: i64 = session_operation_release_script()
            .key(self.session_operation_key(did, session_id))
            .key(self.session_generation_key(did, session_id))
            .key(self.session_index_generation_key(session_id))
            .key(self.session_uncertain_key(did, session_id))
            .arg(operation_value)
            .arg(lease.session.lifecycle_generation.as_ref())
            .arg(if uncertain { 1 } else { 0 })
            .invoke_async(&mut conn)
            .await
            .map_err(redis_err)?;
        Ok(result == 1)
    }

    async fn get_auth_req_info(
        &self,
        state: &str,
    ) -> Result<Option<AuthRequestData<'_>>, SessionStoreError> {
        let key = self.auth_req_key(state);
        let mut conn = self.redis.clone();

        let data: Option<String> = conn.get(&key).await.map_err(redis_err)?;

        match data {
            Some(encrypted) => {
                let context = RecordContext::new("auth_req", &key);
                let (json, needs_rewrap) =
                    open_utf8_with_status(&self.keyring, &context, &encrypted).map_err(
                        |error| other_err(&format!("invalid encrypted auth request: {error}")),
                    )?;
                if needs_rewrap {
                    let rewrapped =
                        self.keyring
                            .seal(&context, json.as_bytes())
                            .map_err(|error| {
                                other_err(&format!("failed to rewrap auth request: {error}"))
                            })?;
                    let result: i64 = expiry_preserving_cas_script()
                        .key(&key)
                        .arg(&encrypted)
                        .arg(&rewrapped)
                        .invoke_async(&mut conn)
                        .await
                        .map_err(redis_err)?;
                    interpret_auth_rewrap_result(result)?;
                    tracing::info!(
                        record_kind = "auth_req",
                        "Rewrapped Redis record with active key"
                    );
                }
                let info: AuthRequestData<'_> =
                    serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;
                Ok(Some(info.into_static()))
            }
            None => Ok(None),
        }
    }

    async fn save_auth_req_info(
        &self,
        auth_req_info: &AuthRequestData<'_>,
    ) -> Result<(), SessionStoreError> {
        let key = self.auth_req_key(&auth_req_info.state);
        let json = serde_json::to_string(auth_req_info).map_err(SessionStoreError::Serde)?;
        let encrypted = self
            .keyring
            .seal(&RecordContext::new("auth_req", &key), json.as_bytes())
            .map_err(|error| other_err(&format!("failed to encrypt auth request: {error}")))?;

        let mut conn = self.redis.clone();
        conn.set_ex::<_, _, ()>(&key, encrypted, STATE_TTL_SECONDS)
            .await
            .map_err(redis_err)?;

        Ok(())
    }

    async fn delete_auth_req_info(&self, state: &str) -> Result<(), SessionStoreError> {
        let key = self.auth_req_key(state);
        let mut conn = self.redis.clone();
        conn.del::<_, ()>(&key).await.map_err(redis_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::redis_crypto::KeyMaterial;
    use super::*;

    #[test]
    fn multiplexed_runtime_auth_store_contains_no_multi_exec_pipeline() {
        let forbidden = [".ato", "mic()"].concat();
        assert!(!include_str!("redis_auth_store.rs").contains(&forbidden));
    }

    #[test]
    fn lifecycle_inventory_partitions_one_prefix_scan() {
        let prefix = "catbird:session:";
        let inventory = partition_lifecycle_inventory_keys(
            prefix,
            vec![
                format!("{prefix}session:primary"),
                format!("{prefix}session_index:index"),
                format!("{prefix}session_generation:generation"),
                format!("{prefix}session_index_generation:index-generation"),
                format!("{prefix}session_operation:lease"),
                format!("{prefix}session_uncertain:quarantine"),
                format!("{prefix}future:unknown"),
            ],
        );

        assert_eq!(inventory.primary, vec![format!("{prefix}session:primary")]);
        assert_eq!(
            inventory.index,
            HashSet::from([format!("{prefix}session_index:index")])
        );
        assert_eq!(
            inventory.generation,
            HashSet::from([format!("{prefix}session_generation:generation")])
        );
        assert_eq!(
            inventory.index_generation,
            HashSet::from([format!("{prefix}session_index_generation:index-generation")])
        );
        assert_eq!(MAX_LIFECYCLE_AUDIT_CONCURRENCY, 16);
    }

    fn test_keyring() -> Keyring {
        Keyring::new(
            KeyMaterial::new("test", [7u8; 32]).unwrap(),
            Vec::new(),
            [9u8; 32],
        )
        .unwrap()
    }

    fn test_session(
        did_value: &'static str,
        session_id: &'static str,
        access_token: &'static str,
    ) -> ClientSessionData<'static> {
        use base64::Engine;
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let secret = p256::SecretKey::from_slice(&[11u8; 32]).unwrap();
        let point = secret.public_key().to_encoded_point(false);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let dpop_key = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64.encode(point.x().unwrap()),
            "y": b64.encode(point.y().unwrap()),
            "d": b64.encode(secret.to_bytes()),
        }))
        .unwrap();
        let did = Did::new_static(did_value).unwrap();
        ClientSessionData {
            lifecycle_generation: "".into(),
            account_did: did.clone(),
            session_id: session_id.into(),
            host_url: "https://pds.example".into(),
            authserver_url: "https://issuer.example".into(),
            authserver_token_endpoint: "https://issuer.example/token".into(),
            authserver_revocation_endpoint: Some("https://issuer.example/revoke".into()),
            scopes: vec![],
            dpop_data: DpopClientData {
                dpop_key,
                dpop_authserver_nonce: "".into(),
                dpop_host_nonce: "".into(),
            },
            token_set: TokenSet {
                iss: "https://issuer.example".into(),
                sub: did,
                aud: "https://pds.example".into(),
                scope: None,
                refresh_token: Some("refresh".into()),
                access_token: access_token.into(),
                token_type: OAuthTokenType::DPoP,
                expires_at: None,
            },
        }
    }

    fn legacy_fixtures() -> (serde_json::Value, serde_json::Value, serde_json::Value) {
        let catbird = serde_json::json!({
            "did": "did:plc:alice",
            "pds_url": "https://pds.example",
            "access_token": "access",
            "refresh_token": "refresh"
        });
        let pair = serde_json::json!({
            "public_jwk": {"kty":"EC", "crv":"P-256", "x":"x", "y":"y"},
            "private_key_bytes": "d"
        });
        let oauth = serde_json::json!({
            "dpop_key": {"kty":"EC", "crv":"P-256", "x":"x", "y":"y", "d":"d"},
            "token_set": {
                "iss": "https://auth.example",
                "sub": "did:plc:alice",
                "aud": "https://pds.example",
                "access_token": "access",
                "refresh_token": "refresh"
            }
        });
        (catbird, pair, oauth)
    }

    #[test]
    fn legacy_validation_rejects_identity_endpoint_token_and_dpop_mismatches() {
        let (catbird, pair, oauth) = legacy_fixtures();

        let mut wrong_identity = oauth.clone();
        wrong_identity["token_set"]["sub"] = serde_json::json!("did:plc:mallory");
        assert!(validate_legacy_records(&catbird, &pair, &wrong_identity).is_err());

        let mut attacker_endpoint = catbird.clone();
        attacker_endpoint["pds_url"] = serde_json::json!("http://127.0.0.1:6379");
        assert!(validate_legacy_records(&attacker_endpoint, &pair, &oauth).is_err());

        let mut wrong_token = oauth.clone();
        wrong_token["token_set"]["access_token"] = serde_json::json!("different");
        assert!(validate_legacy_records(&catbird, &pair, &wrong_token).is_err());

        let mut wrong_dpop = oauth;
        wrong_dpop["dpop_key"]["x"] = serde_json::json!("different");
        assert!(validate_legacy_records(&catbird, &pair, &wrong_dpop).is_err());
    }

    #[test]
    fn auth_request_rewrap_rejects_expired_unbounded_and_raced_records() {
        for result in [-2, -1, 0] {
            assert!(interpret_auth_rewrap_result(result).is_err());
        }
        assert!(interpret_auth_rewrap_result(1).is_ok());
    }

    #[test]
    fn session_rewrap_only_reports_success_for_a_positive_ttl_cas() {
        assert!(interpret_session_rewrap_result(1));
        for result in [-2, -1, 0] {
            assert!(!interpret_session_rewrap_result(result));
        }
    }

    #[test]
    fn scan_page_collection_deduplicates_keys_and_rejects_repeated_cursors() {
        let mut state = ScanCollection::default();
        assert!(!state
            .record_page(17, vec!["key-b".into(), "key-a".into()])
            .unwrap());
        assert!(state
            .record_page(0, vec!["key-a".into(), "key-c".into()])
            .unwrap());
        assert_eq!(
            state.into_keys(),
            vec![
                "key-a".to_string(),
                "key-b".to_string(),
                "key-c".to_string()
            ]
        );

        let mut repeated = ScanCollection::default();
        assert!(!repeated.record_page(23, vec!["key".into()]).unwrap());
        let error = repeated.record_page(23, vec!["key".into()]).unwrap_err();
        assert!(error.to_string().contains("repeated cursor"));
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn live_redis_lifecycle_scripts_return_stable_typed_tuples() {
        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required for this test");
        let client = redis::Client::open(redis_url).expect("TEST_REDIS_URL must be valid");
        let mut conn = client
            .get_connection_manager()
            .await
            .expect("TEST_REDIS_URL must be reachable");
        let prefix = format!("test:typed-tuples:{}", uuid::Uuid::new_v4());
        let keys = (0..6)
            .map(|index| format!("{prefix}:{index}"))
            .collect::<Vec<_>>();

        let missing: (i64, String, String) = session_get_cas_script()
            .key(&keys[0])
            .key(&keys[1])
            .key(&keys[2])
            .key(&keys[3])
            .key(&keys[4])
            .key(&keys[5])
            .arg(60)
            .invoke_async(&mut conn)
            .await
            .expect("missing session tuple must decode without nil placeholders");
        assert_eq!(missing, (0, String::new(), String::new()));

        conn.set::<_, _, ()>(&keys[0], "primary-generation")
            .await
            .unwrap();
        conn.set::<_, _, ()>(&keys[1], "session").await.unwrap();
        conn.set::<_, _, ()>(&keys[2], "index").await.unwrap();
        conn.set::<_, _, ()>(&keys[3], "mismatched-index-generation")
            .await
            .unwrap();
        let mismatched: (i64, String, String) = session_get_cas_script()
            .key(&keys[0])
            .key(&keys[1])
            .key(&keys[2])
            .key(&keys[3])
            .key(&keys[4])
            .key(&keys[5])
            .arg(60)
            .invoke_async(&mut conn)
            .await
            .expect("generation-mismatch tuple must decode without nil placeholders");
        assert_eq!(mismatched, (0, String::new(), String::new()));
        conn.del::<_, ()>(&keys[..4]).await.unwrap();

        conn.set::<_, _, ()>(&keys[4], "active-owner")
            .await
            .unwrap();
        let active: (i64, String, String) = session_get_cas_script()
            .key(&keys[0])
            .key(&keys[1])
            .key(&keys[2])
            .key(&keys[3])
            .key(&keys[4])
            .key(&keys[5])
            .arg(60)
            .invoke_async(&mut conn)
            .await
            .expect("active-operation tuple must decode without nil placeholders");
        assert_eq!(active, (-1, String::new(), String::new()));
        conn.del::<_, ()>(&keys[4]).await.unwrap();
        conn.set::<_, _, ()>(&keys[5], "uncertain-generation")
            .await
            .unwrap();
        let uncertain: (i64, String, String) = session_get_cas_script()
            .key(&keys[0])
            .key(&keys[1])
            .key(&keys[2])
            .key(&keys[3])
            .key(&keys[4])
            .key(&keys[5])
            .arg(60)
            .invoke_async(&mut conn)
            .await
            .expect("uncertain-session tuple must decode without nil placeholders");
        assert_eq!(uncertain, (-2, String::new(), String::new()));
        conn.del::<_, ()>(&keys[5]).await.unwrap();

        let acquire_missing: (i64, String, i64) = session_operation_acquire_script()
            .key(&keys[0])
            .key(&keys[1])
            .key(&keys[2])
            .key(&keys[3])
            .key(&keys[4])
            .key(&keys[5])
            .arg("expected-generation")
            .arg("session")
            .arg("index")
            .arg("new-generation")
            .arg("operation")
            .arg(30_000)
            .arg(60)
            .arg("refresh")
            .invoke_async(&mut conn)
            .await
            .expect("missing acquisition tuple must decode without nil placeholders");
        assert_eq!(acquire_missing, (-1, String::new(), 0));

        conn.set::<_, _, ()>(&keys[0], "stored-generation")
            .await
            .unwrap();
        conn.set::<_, _, ()>(&keys[1], "session").await.unwrap();
        conn.set::<_, _, ()>(&keys[2], "index").await.unwrap();
        conn.set::<_, _, ()>(&keys[3], "stored-generation")
            .await
            .unwrap();
        let acquire_mismatched: (i64, String, i64) = session_operation_acquire_script()
            .key(&keys[0])
            .key(&keys[1])
            .key(&keys[2])
            .key(&keys[3])
            .key(&keys[4])
            .key(&keys[5])
            .arg("stale-generation")
            .arg("session")
            .arg("index")
            .arg("new-generation")
            .arg("operation")
            .arg(30_000)
            .arg(60)
            .arg("refresh")
            .invoke_async(&mut conn)
            .await
            .expect("acquisition mismatch tuple must decode without nil placeholders");
        assert_eq!(acquire_mismatched, (0, String::new(), 0));

        conn.set::<_, _, ()>(&keys[4], "active-owner")
            .await
            .unwrap();
        let acquire_busy: (i64, String, i64) = session_operation_acquire_script()
            .key(&keys[0])
            .key(&keys[1])
            .key(&keys[2])
            .key(&keys[3])
            .key(&keys[4])
            .key(&keys[5])
            .arg("expected-generation")
            .arg("session")
            .arg("index")
            .arg("new-generation")
            .arg("operation")
            .arg(30_000)
            .arg(60)
            .arg("refresh")
            .invoke_async(&mut conn)
            .await
            .expect("busy acquisition tuple must decode without nil placeholders");
        assert_eq!(acquire_busy, (0, String::new(), 0));

        conn.del::<_, ()>(&keys).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn multiplexed_concurrent_sessions_never_mix_responses_or_lifecycle_state() {
        use std::sync::Arc;
        use tokio::sync::Barrier;

        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required for this test");
        let client = redis::Client::open(redis_url).expect("TEST_REDIS_URL must be valid");
        let conn = client
            .get_connection_manager()
            .await
            .expect("TEST_REDIS_URL must be reachable");
        let mut cleanup = conn.clone();
        redis::cmd("FLUSHDB")
            .query_async::<_, ()>(&mut cleanup)
            .await
            .unwrap();
        let prefix = format!("test:multiplex:{}:", uuid::Uuid::new_v4());
        let store = Arc::new(RedisAuthStore::new(conn, prefix, 60, test_keyring()));
        let alice = Did::new_static("did:plc:alice").unwrap();
        let bob = Did::new_static("did:plc:bob").unwrap();

        store
            .create_session(test_session("did:plc:alice", "alice-id", "alice-initial"))
            .await
            .unwrap();
        store
            .create_session(test_session("did:plc:bob", "bob-id", "bob-initial"))
            .await
            .unwrap();

        for _ in 0..64 {
            let barrier = Arc::new(Barrier::new(4));
            let create_store = store.clone();
            let create_barrier = barrier.clone();
            let create_alice = tokio::spawn(async move {
                create_barrier.wait().await;
                create_store
                    .create_session(test_session("did:plc:alice", "alice-id", "alice-next"))
                    .await
            });
            let read_store = store.clone();
            let read_barrier = barrier.clone();
            let bob = bob.clone();
            let read_bob = tokio::spawn(async move {
                read_barrier.wait().await;
                let observed = read_store.get_session(&bob, "bob-id").await?;
                Ok::<_, SessionStoreError>(
                    observed.map(|session| session.account_did.as_str().to_string()),
                )
            });
            let lookup_store = store.clone();
            let lookup_barrier = barrier.clone();
            let lookup_alice = tokio::spawn(async move {
                lookup_barrier.wait().await;
                lookup_store.lookup_did_for_session("alice-id").await
            });
            barrier.wait().await;

            let created = create_alice.await.unwrap().unwrap();
            assert_eq!(created.account_did.as_str(), "did:plc:alice");
            let observed_bob = read_bob.await.unwrap().unwrap().unwrap();
            assert_eq!(observed_bob, "did:plc:bob");
            match lookup_alice.await.unwrap() {
                Ok(Some(observed)) => assert_eq!(observed.as_str(), "did:plc:alice"),
                Err(error) => assert!(
                    error
                        .to_string()
                        .contains("lifecycle generation does not match primary"),
                    "concurrent lookup must either return the bound DID or fail closed: {error}"
                ),
                Ok(None) => panic!("concurrent lookup must not silently lose an existing index"),
            }
        }

        let barrier = Arc::new(Barrier::new(3));
        let first_store = store.clone();
        let first_barrier = barrier.clone();
        let first = tokio::spawn(async move {
            first_barrier.wait().await;
            first_store
                .create_session(test_session("did:plc:alice", "cas-id", "first"))
                .await
        });
        let second_store = store.clone();
        let second_barrier = barrier.clone();
        let second = tokio::spawn(async move {
            second_barrier.wait().await;
            second_store
                .create_session(test_session("did:plc:alice", "cas-id", "second"))
                .await
        });
        barrier.wait().await;
        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();
        let final_session = store.get_session(&alice, "cas-id").await.unwrap().unwrap();
        let final_generation = final_session.lifecycle_generation.as_ref();
        let final_token = final_session.token_set.access_token.as_ref();
        assert!(
            (final_generation == first.lifecycle_generation.as_ref() && final_token == "first")
                || (final_generation == second.lifecycle_generation.as_ref()
                    && final_token == "second"),
            "the final generation and encrypted session must come from the same writer"
        );
        let mut conn = store.redis.clone();
        let generation: String = conn
            .get(store.session_generation_key(alice.as_str(), "cas-id"))
            .await
            .unwrap();
        let index_generation: String = conn
            .get(store.session_index_generation_key("cas-id"))
            .await
            .unwrap();
        assert_eq!(generation, index_generation);
        assert_eq!(generation, final_generation);
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn live_redis_session_and_index_rewrap_cas_never_overwrites_a_refresh() {
        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required for this test");
        let client = redis::Client::open(redis_url).expect("TEST_REDIS_URL must be valid");
        let mut conn = client
            .get_connection_manager()
            .await
            .expect("TEST_REDIS_URL must be reachable");

        for record_kind in ["session", "session_index"] {
            let key = format!("test:rewrap-cas:{record_kind}:{}", uuid::Uuid::new_v4());
            let stale_previous_key_value = format!("v1:previous:{record_kind}");
            let refreshed_active_key_value = format!("v1:active:refreshed-{record_kind}");
            let stale_rewrap_value = format!("v1:active:stale-rewrap-{record_kind}");

            let _: () = redis::cmd("SET")
                .arg(&key)
                .arg(&stale_previous_key_value)
                .arg("PX")
                .arg(60_000)
                .query_async(&mut conn)
                .await
                .unwrap();
            let stale_read: String = conn.get(&key).await.unwrap();

            // Simulate a token refresh winning after the previous-key read but
            // before lazy rewrap attempts to write its stale plaintext.
            let _: () = redis::cmd("SET")
                .arg(&key)
                .arg(&refreshed_active_key_value)
                .arg("PX")
                .arg(45_000)
                .query_async(&mut conn)
                .await
                .unwrap();
            let ttl_before: i64 = conn.pttl(&key).await.unwrap();

            let result: i64 = expiry_preserving_cas_script()
                .key(&key)
                .arg(&stale_read)
                .arg(&stale_rewrap_value)
                .invoke_async(&mut conn)
                .await
                .unwrap();
            let stored: String = conn.get(&key).await.unwrap();
            let ttl_after: i64 = conn.pttl(&key).await.unwrap();

            assert_eq!(result, 0, "{record_kind} stale CAS must lose");
            assert_eq!(stored, refreshed_active_key_value);
            assert!(ttl_before > 0);
            assert!(ttl_after > 0);
            assert!(
                ttl_after <= ttl_before,
                "CAS must not extend the refresh TTL"
            );

            conn.del::<_, ()>(&key).await.unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn independent_redis_stores_fence_stale_session_lifecycles() {
        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required for this test");
        let client = redis::Client::open(redis_url).expect("TEST_REDIS_URL must be valid");
        let conn_a = client
            .get_connection_manager()
            .await
            .expect("TEST_REDIS_URL must be reachable");
        let conn_b = client
            .get_connection_manager()
            .await
            .expect("TEST_REDIS_URL must be reachable");
        let prefix = format!("test:lifecycle-cas:{}:", uuid::Uuid::new_v4());
        let store_a = RedisAuthStore::new(conn_a, prefix.clone(), 60, test_keyring());
        let store_b = RedisAuthStore::new(conn_b, prefix, 60, test_keyring());
        let alice = Did::new_static("did:plc:alice").unwrap();
        let bob = Did::new_static("did:plc:bob").unwrap();

        let created = store_a
            .create_session(test_session("did:plc:alice", "shared-id", "access-a"))
            .await
            .unwrap();
        let mut stale = created.clone();
        stale.token_set.access_token = "stale-refresh".into();
        assert!(store_b
            .delete_session(&alice, "shared-id", &created.lifecycle_generation)
            .await
            .unwrap());
        assert!(!store_a.update_session(stale.clone()).await.unwrap());
        assert!(store_a
            .get_session(&alice, "shared-id")
            .await
            .unwrap()
            .is_none());
        assert!(store_a
            .lookup_did_for_session("shared-id")
            .await
            .unwrap()
            .is_none());

        let recreated = store_b
            .create_session(test_session("did:plc:alice", "shared-id", "access-new"))
            .await
            .unwrap();
        assert_ne!(created.lifecycle_generation, recreated.lifecycle_generation);
        assert!(!store_a.update_session(stale.clone()).await.unwrap());
        assert!(!store_a
            .delete_session(&alice, "shared-id", &created.lifecycle_generation)
            .await
            .unwrap());
        assert_eq!(
            store_a
                .get_session(&alice, "shared-id")
                .await
                .unwrap()
                .unwrap()
                .token_set
                .access_token,
            "access-new"
        );

        let bob_session = store_b
            .create_session(test_session("did:plc:bob", "shared-id", "access-b"))
            .await
            .unwrap();
        assert!(store_a
            .get_session(&alice, "shared-id")
            .await
            .unwrap()
            .is_none());
        assert!(!store_a.update_session(recreated.clone()).await.unwrap());
        assert!(store_a
            .delete_session(&alice, "shared-id", &recreated.lifecycle_generation)
            .await
            .unwrap());
        assert_eq!(
            store_a.lookup_did_for_session("shared-id").await.unwrap(),
            Some(bob.to_string())
        );
        assert_eq!(
            store_a
                .get_session(&bob, "shared-id")
                .await
                .unwrap()
                .unwrap()
                .lifecycle_generation,
            bob_session.lifecycle_generation
        );

        let mut conn = store_a.redis.clone();
        conn.del::<_, ()>(store_a.session_index_generation_key("shared-id"))
            .await
            .unwrap();
        assert!(store_a
            .get_session(&bob, "shared-id")
            .await
            .unwrap()
            .is_none());
        assert!(store_a.lookup_did_for_session("shared-id").await.is_err());
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn independent_redis_stores_enforce_operation_ownership_and_uncertain_quarantine() {
        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required for this test");
        let client = redis::Client::open(redis_url).expect("TEST_REDIS_URL must be valid");
        let conn_a = client
            .get_connection_manager()
            .await
            .expect("TEST_REDIS_URL must be reachable");
        let conn_b = client
            .get_connection_manager()
            .await
            .expect("TEST_REDIS_URL must be reachable");
        let prefix = format!("test:operation-fence:{}:", uuid::Uuid::new_v4());
        let store_a = RedisAuthStore::new(conn_a, prefix.clone(), 60, test_keyring());
        let store_b = RedisAuthStore::new(conn_b, prefix, 60, test_keyring());
        let alice = Did::new_static("did:plc:alice").unwrap();
        store_a
            .create_session(test_session("did:plc:alice", "fenced-id", "access-a"))
            .await
            .unwrap();

        let refresh = match store_a
            .acquire_session_operation(
                &alice,
                "fenced-id",
                SessionOperationKind::Refresh,
                "worker-a",
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        {
            SessionOperationAcquire::Acquired(lease) => lease,
            other => panic!("refresh lease was not acquired: {other:?}"),
        };
        let active = store_b.get_session(&alice, "fenced-id").await.unwrap_err();
        assert!(jacquard_oauth::authstore::is_session_operation_active(
            &active
        ));
        assert!(!jacquard_oauth::authstore::is_reauthentication_required(
            &active
        ));
        assert!(matches!(
            store_b
                .acquire_session_operation(
                    &alice,
                    "fenced-id",
                    SessionOperationKind::Revoke,
                    "worker-b",
                    Duration::from_secs(30),
                )
                .await
                .unwrap(),
            SessionOperationAcquire::Busy
        ));

        assert!(store_a
            .release_session_operation(&refresh, true)
            .await
            .unwrap());
        let quarantined = store_a.get_session(&alice, "fenced-id").await.unwrap_err();
        assert!(jacquard_oauth::authstore::is_reauthentication_required(
            &quarantined
        ));
        let uncertain_key = store_a.session_uncertain_key(alice.as_str(), "fenced-id");
        let mut conn = store_a.redis.clone();
        conn.expire::<_, ()>(&uncertain_key, 1).await.unwrap();
        let revoke = match store_b
            .acquire_session_operation(
                &alice,
                "fenced-id",
                SessionOperationKind::Revoke,
                "worker-b",
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        {
            SessionOperationAcquire::Acquired(lease) => lease,
            other => panic!("revoke lease was not acquired: {other:?}"),
        };
        assert!(revoke.uncertain_refresh);
        let uncertain_generation: String = conn.get(&uncertain_key).await.unwrap();
        let uncertain_ttl: i64 = conn.ttl(&uncertain_key).await.unwrap();
        assert_eq!(
            uncertain_generation,
            revoke.session.lifecycle_generation.as_ref()
        );
        assert!(
            uncertain_ttl > 50,
            "revoke acquisition must rebind and extend the existing quarantine"
        );
        let mut stale_refresh = refresh.session.clone();
        stale_refresh.token_set.access_token = "stale-issued-access".into();
        assert!(store_a
            .commit_session_refresh(&refresh, stale_refresh)
            .await
            .unwrap()
            .is_none());
        assert!(!store_b.complete_session_revoke(&revoke).await.unwrap());
        assert!(store_b
            .release_session_operation(&revoke, true)
            .await
            .unwrap());
        assert!(store_a.get_session(&alice, "fenced-id").await.is_err());

        store_a
            .create_session(test_session("did:plc:alice", "fenced-id", "access-old"))
            .await
            .unwrap();
        let refresh = match store_b
            .acquire_session_operation(
                &alice,
                "fenced-id",
                SessionOperationKind::Refresh,
                "worker-b",
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        {
            SessionOperationAcquire::Acquired(lease) => lease,
            other => panic!("second refresh lease was not acquired: {other:?}"),
        };
        let mut refreshed = refresh.session.clone();
        refreshed.token_set.access_token = "access-new".into();
        let committed = store_b
            .commit_session_refresh(&refresh, refreshed)
            .await
            .unwrap()
            .expect("live owner must commit");
        assert_ne!(
            committed.lifecycle_generation,
            refresh.session.lifecycle_generation
        );
        assert_eq!(
            store_a
                .get_session(&alice, "fenced-id")
                .await
                .unwrap()
                .unwrap()
                .token_set
                .access_token,
            "access-new"
        );
        assert!(!store_a
            .release_session_operation(&refresh, false)
            .await
            .unwrap());
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn encrypted_envelope_lifecycle_migration_is_atomic_idempotent_and_fail_closed() {
        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required for this test");
        let client = redis::Client::open(redis_url).expect("TEST_REDIS_URL must be valid");
        let conn = client
            .get_connection_manager()
            .await
            .expect("TEST_REDIS_URL must be reachable");
        let prefix = format!("test:lifecycle-migration:{}:", uuid::Uuid::new_v4());
        let store = RedisAuthStore::new(conn, prefix, 60, test_keyring());
        let did = Did::new_static("did:plc:alice").unwrap();
        let created = store
            .create_session(test_session("did:plc:alice", "legacy-id", "access"))
            .await
            .unwrap();
        let session_key = store.session_key(did.as_str(), "legacy-id");
        let generation_key = store.session_generation_key(did.as_str(), "legacy-id");
        let index_generation_key = store.session_index_generation_key("legacy-id");
        let mut conn = store.redis.clone();

        // Model the exact deployed encrypted-envelope schema: authenticated
        // primary and reverse-index values, but no lifecycle fence keys.
        conn.del::<_, ()>(&[generation_key.as_str(), index_generation_key.as_str()])
            .await
            .unwrap();
        assert!(store
            .get_session(&did, "legacy-id")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .migrate_pre_generation_session_offline(&session_key)
                .await
                .unwrap(),
            LifecycleFenceMigration::Installed
        );
        let migrated = store.get_session(&did, "legacy-id").await.unwrap().unwrap();
        assert_ne!(migrated.lifecycle_generation, created.lifecycle_generation);
        let index_key = store.session_index_key("legacy-id");
        let ttls: (i64, i64, i64, i64) = redis::pipe()
            .pttl(&session_key)
            .pttl(&index_key)
            .pttl(&generation_key)
            .pttl(&index_generation_key)
            .query_async(&mut conn)
            .await
            .unwrap();
        let ttls = [ttls.0, ttls.1, ttls.2, ttls.3];
        assert!(ttls.iter().all(|ttl| *ttl > 0));
        assert!(ttls.iter().max().unwrap() - ttls.iter().min().unwrap() < 250);
        assert_eq!(
            store
                .migrate_pre_generation_session_offline(&session_key)
                .await
                .unwrap(),
            LifecycleFenceMigration::AlreadyInstalled
        );

        // A mixed generation state is never repaired heuristically.
        conn.del::<_, ()>(&index_generation_key).await.unwrap();
        assert!(store
            .migrate_pre_generation_session_offline(&session_key)
            .await
            .is_err());
        assert!(store
            .get_session(&did, "legacy-id")
            .await
            .unwrap()
            .is_none());

        // A ciphertext change between validation and the Lua CAS loses
        // without creating either fence.
        let race = store
            .create_session(test_session("did:plc:alice", "race-id", "before"))
            .await
            .unwrap();
        let race_key = store.session_key(race.account_did.as_str(), &race.session_id);
        let pair = store.validated_lifecycle_pair(&race_key).await.unwrap();
        conn.del::<_, ()>(&[
            pair.generation_key.as_str(),
            pair.index_generation_key.as_str(),
        ])
        .await
        .unwrap();
        conn.set_ex::<_, _, ()>(&pair.session_key, "concurrent-change", 60)
            .await
            .unwrap();
        let result: i64 = lifecycle_fence_migration_cas_script()
            .key(&pair.session_key)
            .key(&pair.index_key)
            .key(&pair.generation_key)
            .key(&pair.index_generation_key)
            .arg(&pair.encrypted_session)
            .arg(&pair.encrypted_index)
            .arg(new_lifecycle_generation())
            .invoke_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(result, 0);
        assert!(!conn.exists::<_, bool>(&pair.generation_key).await.unwrap());
        assert!(!conn
            .exists::<_, bool>(&pair.index_generation_key)
            .await
            .unwrap());

        // Missing and unauthenticated pair members are rejected before CAS.
        let corrupt = store
            .create_session(test_session("did:plc:alice", "corrupt-id", "access"))
            .await
            .unwrap();
        let corrupt_key = store.session_key(corrupt.account_did.as_str(), &corrupt.session_id);
        let corrupt_index_key = store.session_index_key(&corrupt.session_id);
        let corrupt_generation_key =
            store.session_generation_key(corrupt.account_did.as_str(), &corrupt.session_id);
        let corrupt_index_generation_key = store.session_index_generation_key(&corrupt.session_id);
        conn.del::<_, ()>(&[
            corrupt_generation_key.as_str(),
            corrupt_index_generation_key.as_str(),
        ])
        .await
        .unwrap();
        conn.set_ex::<_, _, ()>(&corrupt_index_key, "not-an-envelope", 60)
            .await
            .unwrap();
        assert!(store
            .migrate_pre_generation_session_offline(&corrupt_key)
            .await
            .is_err());
        conn.del::<_, ()>(&corrupt_index_key).await.unwrap();
        assert!(store
            .migrate_pre_generation_session_offline(&corrupt_key)
            .await
            .is_err());
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn lifecycle_inventory_rejects_orphans_across_all_namespaces() {
        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required for this test");
        let client = redis::Client::open(redis_url).expect("TEST_REDIS_URL must be valid");
        let conn = client
            .get_connection_manager()
            .await
            .expect("TEST_REDIS_URL must be reachable");
        let prefix = format!("test:lifecycle-inventory:{}:", uuid::Uuid::new_v4());
        let store = RedisAuthStore::new(conn, prefix.clone(), 60, test_keyring());
        let created = store
            .create_session(test_session("did:plc:alice", "inventory-id", "access"))
            .await
            .unwrap();
        let session_key = store.session_key(created.account_did.as_str(), &created.session_id);
        let index_key = store.session_index_key(&created.session_id);
        let generation_key =
            store.session_generation_key(created.account_did.as_str(), &created.session_id);
        let index_generation_key = store.session_index_generation_key(&created.session_id);
        let mut conn = store.redis.clone();

        let installed = store
            .audit_lifecycle_fence_inventory_offline()
            .await
            .unwrap();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].status, LifecycleFenceStatus::Installed);

        conn.del::<_, ()>(&[generation_key.as_str(), index_generation_key.as_str()])
            .await
            .unwrap();
        let required = store
            .audit_lifecycle_fence_inventory_offline()
            .await
            .unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0].status, LifecycleFenceStatus::Required);

        let orphan_index = format!("{prefix}session_index:orphan");
        conn.set_ex::<_, _, ()>(&orphan_index, "orphan", 60)
            .await
            .unwrap();
        assert!(store
            .audit_lifecycle_fence_inventory_offline()
            .await
            .is_err());
        conn.del::<_, ()>(&orphan_index).await.unwrap();

        store
            .migrate_pre_generation_session_offline(&session_key)
            .await
            .unwrap();
        let orphan_generation = format!("{prefix}session_generation:orphan");
        conn.set_ex::<_, _, ()>(&orphan_generation, "orphan", 60)
            .await
            .unwrap();
        assert!(store
            .audit_lifecycle_fence_inventory_offline()
            .await
            .is_err());
        conn.del::<_, ()>(&orphan_generation).await.unwrap();

        let orphan_index_generation = format!("{prefix}session_index_generation:orphan");
        conn.set_ex::<_, _, ()>(&orphan_index_generation, "orphan", 60)
            .await
            .unwrap();
        assert!(store
            .audit_lifecycle_fence_inventory_offline()
            .await
            .is_err());
        conn.del::<_, ()>(&orphan_index_generation).await.unwrap();

        conn.del::<_, ()>(&session_key).await.unwrap();
        assert!(store
            .audit_lifecycle_fence_inventory_offline()
            .await
            .is_err());

        // The reverse index and both fences remain, proving the audit rejects
        // missing primaries rather than silently treating the inventory as empty.
        assert!(conn.exists::<_, bool>(&index_key).await.unwrap());
        assert!(conn.exists::<_, bool>(&generation_key).await.unwrap());
        assert!(conn.exists::<_, bool>(&index_generation_key).await.unwrap());
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn expected_did_repair_recreates_only_a_fully_absent_index_pair() {
        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required for this test");
        let client = redis::Client::open(redis_url).expect("TEST_REDIS_URL must be valid");
        let conn = client
            .get_connection_manager()
            .await
            .expect("TEST_REDIS_URL must be reachable");
        let prefix = format!("test:index-repair:{}:", uuid::Uuid::new_v4());
        let store = RedisAuthStore::new(conn, prefix, 60, test_keyring());
        let did = Did::new_static("did:plc:alice").unwrap();
        let created = store
            .create_session(test_session("did:plc:alice", "repair-id", "access"))
            .await
            .unwrap();
        let session_key = store.session_key(did.as_str(), "repair-id");
        let generation_key = store.session_generation_key(did.as_str(), "repair-id");
        let index_key = store.session_index_key("repair-id");
        let index_generation_key = store.session_index_generation_key("repair-id");
        let mut conn = store.redis.clone();

        conn.del::<_, ()>(&[index_key.as_str(), index_generation_key.as_str()])
            .await
            .unwrap();
        assert!(store
            .get_session(&did, "repair-id")
            .await
            .unwrap()
            .is_none());
        assert!(store
            .repair_missing_session_index(&did, "repair-id")
            .await
            .unwrap());
        assert_eq!(
            store.lookup_did_for_session("repair-id").await.unwrap(),
            Some(did.to_string())
        );
        assert_eq!(
            store
                .get_session(&did, "repair-id")
                .await
                .unwrap()
                .unwrap()
                .lifecycle_generation,
            created.lifecycle_generation
        );
        let ttls: (i64, i64, i64, i64) = redis::pipe()
            .pttl(&session_key)
            .pttl(&generation_key)
            .pttl(&index_key)
            .pttl(&index_generation_key)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!([ttls.0, ttls.1, ttls.2, ttls.3].iter().all(|ttl| *ttl > 0));

        // A partial index pair is corruption, not a repair candidate.
        conn.del::<_, ()>(&index_generation_key).await.unwrap();
        assert!(store
            .repair_missing_session_index(&did, "repair-id")
            .await
            .is_err());
        assert!(conn.exists::<_, bool>(&index_key).await.unwrap());
        assert!(!conn.exists::<_, bool>(&index_generation_key).await.unwrap());

        conn.del::<_, ()>(&index_key).await.unwrap();
        conn.set_ex::<_, _, ()>(
            &index_generation_key,
            created.lifecycle_generation.as_ref(),
            60,
        )
        .await
        .unwrap();
        assert!(store
            .repair_missing_session_index(&did, "repair-id")
            .await
            .is_err());
        assert!(!conn.exists::<_, bool>(&index_key).await.unwrap());
        conn.set_ex::<_, _, ()>(&index_key, "conflicting-index", 60)
            .await
            .unwrap();
        conn.set_ex::<_, _, ()>(&index_generation_key, "wrong-generation", 60)
            .await
            .unwrap();
        assert!(store
            .repair_missing_session_index(&did, "repair-id")
            .await
            .is_err());

        // Unauthenticated and identity-mismatched primaries fail closed.
        conn.del::<_, ()>(&[index_key.as_str(), index_generation_key.as_str()])
            .await
            .unwrap();
        conn.set_ex::<_, _, ()>(&session_key, "not-an-envelope", 60)
            .await
            .unwrap();
        assert!(store
            .repair_missing_session_index(&did, "repair-id")
            .await
            .is_err());
        let mismatched = test_session("did:plc:mallory", "repair-id", "access");
        let mismatched_json = serde_json::to_string(&mismatched).unwrap();
        let mismatched_encrypted = store
            .keyring
            .seal(
                &RecordContext::new("session", &session_key),
                mismatched_json.as_bytes(),
            )
            .unwrap();
        conn.set_ex::<_, _, ()>(&session_key, mismatched_encrypted, 60)
            .await
            .unwrap();
        assert!(store
            .repair_missing_session_index(&did, "repair-id")
            .await
            .is_err());
        let wrong_session_id = test_session("did:plc:alice", "other-id", "access");
        let wrong_session_json = serde_json::to_string(&wrong_session_id).unwrap();
        let wrong_session_encrypted = store
            .keyring
            .seal(
                &RecordContext::new("session", &session_key),
                wrong_session_json.as_bytes(),
            )
            .unwrap();
        conn.set_ex::<_, _, ()>(&session_key, wrong_session_encrypted, 60)
            .await
            .unwrap();
        assert!(store
            .repair_missing_session_index(&did, "repair-id")
            .await
            .is_err());
        let mallory = Did::new_static("did:plc:mallory").unwrap();
        assert!(!store
            .repair_missing_session_index(&mallory, "repair-id")
            .await
            .unwrap());

        // A logout/recreate between authenticated validation and Lua CAS
        // changes both generation and ciphertext, so the stale repair loses.
        let race = store
            .create_session(test_session("did:plc:alice", "repair-race", "before"))
            .await
            .unwrap();
        let race_session_key = store.session_key(did.as_str(), "repair-race");
        let race_generation_key = store.session_generation_key(did.as_str(), "repair-race");
        let race_index_key = store.session_index_key("repair-race");
        let race_index_generation_key = store.session_index_generation_key("repair-race");
        let stale_session: String = conn.get(&race_session_key).await.unwrap();
        let stale_generation = race.lifecycle_generation.to_string();
        conn.del::<_, ()>(&[
            race_session_key.as_str(),
            race_generation_key.as_str(),
            race_index_key.as_str(),
            race_index_generation_key.as_str(),
        ])
        .await
        .unwrap();
        let recreated = store
            .create_session(test_session("did:plc:alice", "repair-race", "after"))
            .await
            .unwrap();
        conn.del::<_, ()>(&[race_index_key.as_str(), race_index_generation_key.as_str()])
            .await
            .unwrap();
        let stale_index = store
            .keyring
            .seal(
                &RecordContext::new("session_index", &race_index_key),
                did.as_str().as_bytes(),
            )
            .unwrap();
        let result: i64 = missing_session_index_repair_cas_script()
            .key(&race_generation_key)
            .key(&race_session_key)
            .key(&race_index_key)
            .key(&race_index_generation_key)
            .arg(&stale_generation)
            .arg(&stale_session)
            .arg(stale_index)
            .invoke_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(result, 0);
        assert_ne!(stale_generation, recreated.lifecycle_generation.as_ref());
        assert!(!conn.exists::<_, bool>(&race_index_key).await.unwrap());
        assert!(!conn
            .exists::<_, bool>(&race_index_generation_key)
            .await
            .unwrap());
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn index_repair_reports_missing_primary_even_when_stale_reverse_index_remains() {
        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required for this test");
        let client = redis::Client::open(redis_url).expect("TEST_REDIS_URL must be valid");
        let conn = client
            .get_connection_manager()
            .await
            .expect("TEST_REDIS_URL must be reachable");
        let prefix = format!("test:stale-index:{}:", uuid::Uuid::new_v4());
        let store = RedisAuthStore::new(conn, prefix, 60, test_keyring());
        let did = Did::new_static("did:plc:alice").unwrap();
        store
            .create_session(test_session("did:plc:alice", "expired-primary", "access"))
            .await
            .unwrap();
        let session_key = store.session_key(did.as_str(), "expired-primary");
        let generation_key = store.session_generation_key(did.as_str(), "expired-primary");
        let index_key = store.session_index_key("expired-primary");
        let index_generation_key = store.session_index_generation_key("expired-primary");
        let mut conn = store.redis.clone();

        conn.del::<_, ()>(&[session_key.as_str(), generation_key.as_str()])
            .await
            .unwrap();
        assert!(conn.exists::<_, bool>(&index_key).await.unwrap());
        assert!(conn.exists::<_, bool>(&index_generation_key).await.unwrap());
        assert!(store
            .lookup_did_for_session("expired-primary")
            .await
            .unwrap()
            .is_none());
        assert!(!store
            .repair_missing_session_index(&did, "expired-primary")
            .await
            .unwrap());
    }

    #[test]
    fn legacy_validation_accepts_a_real_matching_p256_fixture() {
        use base64::Engine;
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let secret = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let point = secret.public_key().to_encoded_point(false);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let d = b64.encode(secret.to_bytes());
        let x = b64.encode(point.x().unwrap());
        let y = b64.encode(point.y().unwrap());
        let catbird = serde_json::json!({
            "did": "did:plc:alice",
            "pds_url": "https://pds.example",
            "access_token": "access",
            "refresh_token": "refresh"
        });
        let pair = serde_json::json!({
            "public_jwk": {"kty":"EC", "crv":"P-256", "x":x, "y":y},
            "private_key_bytes": d
        });
        let oauth = serde_json::json!({
            "dpop_key": {"kty":"EC", "crv":"P-256", "x":x, "y":y, "d":d},
            "token_set": {
                "iss": "https://auth.example",
                "sub": "did:plc:alice",
                "aud": "https://pds.example",
                "access_token": "access",
                "refresh_token": "refresh"
            }
        });

        validate_legacy_records(&catbird, &pair, &oauth).unwrap();
    }
}
