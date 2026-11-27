//! Per-login Redis storage for Petrel OAuth, with an atomic v2 rollback mirror.
mod legacy;
pub use legacy::{
    AuthRequestData, ClientSessionData, DpopClientData, DpopReqData, LegacySessionV2,
    OAuthTokenType, TokenSet,
};

use super::redis_auth_store::RedisAuthStore;
use super::redis_crypto::{
    build_aad, open_session_dual_read, open_v2_with_metadata, seal_v2_with_metadata, seal_with_aad,
    EnvelopeMetadata, V2_PREFIX,
};
use crate::metrics::{
    PETREL_CAS_CONFLICTS, PETREL_CONVERSIONS, PETREL_MIRROR_WRITES, PETREL_REFRESH_LEASE_READS,
};
use legacy::{corrupt, expiry};
use petrel::{
    oauth::SessionRecord,
    rt::BoxFuture,
    storage::{MemorySecretStore, SecretStore, SessionStore, StoreError},
};
use petrel_core::Did;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::Value;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct SessionBinding {
    did: Did,
    id: String,
    mirror: String,
    retired: String,
    erasure: String,
}

#[derive(Clone)]
pub struct RedisSessionSecrets {
    conn: ConnectionManager,
    namespace: String,
    hash: String,
    key: [u8; 32],
    ttl: u64,
    erasure_prefix: String,
    binding: Option<SessionBinding>,
}

fn unavailable(_: redis::RedisError) -> StoreError {
    StoreError::Unavailable("Redis operation failed".into())
}

pub(crate) fn v3_prefix(prefix: &str) -> String {
    // Reserve the short deployed spelling, while keeping all other configured
    // prefixes in an injective namespace independent of it.
    if let Some(tenant) = prefix.strip_suffix(":v2:session:") {
        format!("{tenant}:v3:")
    } else {
        format!(
            "nest-custom-v3:{}:",
            petrel::crypto::base64url(prefix.as_bytes())
        )
    }
}

// An old binary, logout, or account erasure can invalidate the v3 copy.
// Every operation by a cached client must observe those fences too.
const READ_FIELD: &str = r#"
if #KEYS == 4 then
  if redis.call('EXISTS',KEYS[3],KEYS[4]) ~= 0 then return {0} end
  local old = redis.call('GET',KEYS[2])
  if not old then return {0} end
  if old ~= redis.call('HGET',KEYS[1],'nest.mirror') then return {-1} end
end
return {1,redis.call('HGET',KEYS[1],ARGV[1])}
"#;

// Compare the exact ciphertext read and authenticated by Rust. This makes
// plaintext CAS atomic even with randomized encryption and avoids a second
// deterministic verifier for stored secrets.
const WRITE_FIELD: &str = r#"
if #KEYS == 2 and redis.call('EXISTS',KEYS[2]) ~= 0 then return -1 end
if #KEYS == 4 then
  if redis.call('EXISTS',KEYS[3],KEYS[4]) ~= 0 then return -1 end
  local old = redis.call('GET',KEYS[2])
  if not old or old ~= redis.call('HGET',KEYS[1],'nest.mirror') then return -1 end
  if ARGV[6] ~= '' and old ~= ARGV[6] then return 0 end
end
if ARGV[2] ~= '*' and (redis.call('HGET',KEYS[1],ARGV[1]) or '') ~= ARGV[2] then return 0 end
if ARGV[3] == '' then
  redis.call('HDEL',KEYS[1],ARGV[1])
else
  redis.call('HSET',KEYS[1],ARGV[1],ARGV[3])
end
if #KEYS == 4 then
  if ARGV[5] == 'delete' then
    redis.call('DEL',KEYS[1],KEYS[2])
    return 1
  elseif ARGV[5] ~= '' then
    redis.call('SET',KEYS[2],ARGV[5],'XX','KEEPTTL')
    redis.call('HSET',KEYS[1],'nest.mirror',ARGV[5])
  end
  local ttl = redis.call('PTTL',KEYS[2])
  if ttl >= 0 then redis.call('PEXPIRE',KEYS[1],ttl) else redis.call('EXPIRE',KEYS[1],ARGV[4]) end
else
  if ARGV[7] ~= '' then redis.call('HSET',KEYS[1],'nest.owner',ARGV[7]) end
  redis.call('EXPIRE',KEYS[1],ARGV[4])
end
return 1
"#;

const CONVERT: &str = r#"
if redis.call('EXISTS',KEYS[3],KEYS[4]) ~= 0 then return 0 end
local old = redis.call('GET',KEYS[2])
if not old then return 0 end
if old ~= ARGV[1] then return -1 end
if redis.call('HGET',KEYS[1],'nest.mirror') == old then return 2 end
-- A rollback may have advanced the v2 tokens. Re-import only the exact
-- authenticated v2 record just read. An uncommitted exchange needs recovery.
if redis.call('HEXISTS',KEYS[1],ARGV[4]) ~= 0 then return -2 end
redis.call('DEL',KEYS[1])
redis.call('HSET',KEYS[1],'nest.mirror',ARGV[2],unpack(ARGV,5))
redis.call('SET',KEYS[2],ARGV[2],'XX','KEEPTTL')
local ttl = redis.call('PTTL',KEYS[2])
if ttl >= 0 then redis.call('PEXPIRE',KEYS[1],ttl) else redis.call('EXPIRE',KEYS[1],ARGV[3]) end
return 1
"#;

/// Validate an encrypted v2 session without touching Redis. Returns whether
/// its access token has already expired. Errors contain only reason categories.
pub fn inspect_legacy_session(
    store: &RedisAuthStore,
    key: &str,
    envelope: &str,
    now: u64,
) -> Result<bool, StoreError> {
    let (raw, meta, _) = open_v2_with_metadata(store.enc_key(), envelope, "session", key)
        .map_err(|_| corrupt("invalid v2 session envelope"))?;
    let old: LegacySessionV2 =
        serde_json::from_str(&raw).map_err(|_| corrupt("invalid v2 session"))?;
    if meta
        .did
        .as_deref()
        .is_some_and(|d| d != old.account_did.as_str())
        || store.session_key(old.account_did.as_str(), &old.session_id) != key
    {
        return Err(corrupt("session identity mismatch"));
    }
    let (record, _) = old.to_petrel(now)?;
    Ok(record.session.expires_at() <= now)
}

impl RedisSessionSecrets {
    pub fn new(store: &RedisAuthStore, did: &Did, session_id: &str) -> Self {
        let fp = store.fingerprint(session_id);
        Self {
            conn: store.redis_connection(),
            namespace: format!("s{fp}"),
            hash: format!("{}ps:{fp}", v3_prefix(store.key_prefix())),
            key: store.encryption_key(),
            ttl: store.session_ttl(),
            erasure_prefix: format!("{}account_erasure:", store.key_prefix()),
            binding: Some(SessionBinding {
                did: did.clone(),
                id: session_id.to_owned(),
                mirror: store.session_key(did.as_str(), session_id),
                retired: store.retired_key(session_id),
                erasure: store.account_erasure_key(did.as_str()),
            }),
        }
    }

    pub fn flow_store(store: &RedisAuthStore, route: &str) -> Result<SessionStore, StoreError> {
        if route.is_empty() {
            return Err(StoreError::InvalidNamespace);
        }
        let fp = store.fingerprint(route);
        let backend = Self {
            conn: store.redis_connection(),
            namespace: format!("f{fp}"),
            hash: format!("{}flow:{fp}", v3_prefix(store.key_prefix())),
            key: store.encryption_key(),
            ttl: 600,
            erasure_prefix: format!("{}account_erasure:", store.key_prefix()),
            binding: None,
        };
        backend.typed()
    }

    fn typed(&self) -> Result<SessionStore, StoreError> {
        SessionStore::new(Arc::new(self.clone()), self.namespace.clone())
    }

    fn sealed(&self, field: &str, data: &[u8]) -> Result<String, StoreError> {
        let aad = build_aad("petrel_secret", &self.hash, None, Some(field));
        seal_with_aad(&self.key, data, &aad)
            .map_err(|_| StoreError::Unavailable("could not seal Petrel field".into()))
    }

    fn open_field(&self, field: &str, encrypted: &str) -> Result<Vec<u8>, StoreError> {
        if !encrypted.starts_with(V2_PREFIX) {
            return Err(corrupt("unbound Petrel field"));
        }
        let aad = build_aad("petrel_secret", &self.hash, None, Some(field));
        open_session_dual_read(&self.key, encrypted, &aad)
            .map(|(v, _)| v)
            .map_err(|_| corrupt("invalid encrypted Petrel field"))
    }

    fn fields<'a>(&'a self, script: &'a redis::Script) -> redis::ScriptInvocation<'a> {
        let mut invocation = script.key(&self.hash);
        if let Some(b) = &self.binding {
            invocation.key(&b.mirror).key(&b.retired).key(&b.erasure);
        }
        invocation
    }

    fn validate(&self, ns: &str, field: &str) -> Result<(), StoreError> {
        if ns != self.namespace {
            return Err(StoreError::InvalidNamespace);
        }
        if field.is_empty() || field.contains('\0') || field.starts_with("nest.") {
            return Err(StoreError::InvalidKey);
        }
        Ok(())
    }

    /// Load a live, validated session. A cached v3 copy is reusable only while
    /// the corresponding v2 grant is still current and has not been retired.
    pub async fn load_or_convert(&self) -> Result<Option<SessionStore>, StoreError> {
        Ok(self.load_with_mirror().await?.map(|(store, _)| store))
    }

    /// The encrypted mirror is the compare-and-swap token for retiring a
    /// rejected refresh without affecting a concurrent replacement grant.
    pub(super) async fn load_with_mirror(
        &self,
    ) -> Result<Option<(SessionStore, String)>, StoreError> {
        let result = self.load_or_convert_inner().await;
        if let Err(error) = &result {
            let reason = match error {
                StoreError::Corrupt(s) if s.contains("DPoP") => "invalid_key",
                StoreError::Corrupt(s) if s.contains("scope") => "invalid_scope",
                StoreError::Corrupt(s) if s.contains("issuer") || s.contains("identity") => {
                    "invalid_identity"
                }
                StoreError::Corrupt(_) => "invalid_record",
                _ => "unavailable",
            };
            PETREL_CONVERSIONS.with_label_values(&[reason]).inc();
        }
        result
    }

    async fn load_or_convert_inner(&self) -> Result<Option<(SessionStore, String)>, StoreError> {
        let b = self.binding.as_ref().ok_or(StoreError::InvalidNamespace)?;
        let mut conn = self.conn.clone();
        // Up to three retries if a concurrent reader rotated the encrypted v2 grant.
        for _ in 0..3 {
            let script = redis::Script::new(
                r#"
              if redis.call('EXISTS',KEYS[3],KEYS[4]) ~= 0 then return {0} end
              local old=redis.call('GET',KEYS[2])
              if not old then return {0} end
              if old == redis.call('HGET',KEYS[1],'nest.mirror') then return {1,old} end
              return {2,old}"#,
            );
            let (status, raw) = self.read_result(
                self.fields(&script)
                    .invoke_async(&mut conn)
                    .await
                    .map_err(unavailable)?,
            )?;
            if status == 0 {
                return Ok(None);
            }
            let raw = raw.ok_or_else(|| corrupt("missing session mirror"))?;
            if status == 1 {
                return Ok(Some((self.typed()?, raw)));
            }
            let (json, metadata, is_v1) =
                open_v2_with_metadata(&self.key, &raw, "session", &b.mirror)
                    .map_err(|_| corrupt("invalid v2 session envelope"))?;
            if metadata
                .did
                .as_deref()
                .is_some_and(|did| did != b.did.as_str())
            {
                return Err(corrupt("session envelope DID mismatch"));
            }
            let old: LegacySessionV2 =
                serde_json::from_str(&json).map_err(|_| corrupt("invalid v2 session"))?;
            if old.account_did != b.did || old.session_id != b.id {
                return Err(corrupt("session identity mismatch"));
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| StoreError::Unavailable("clock before epoch".into()))?
                .as_secs();
            let (record, scalar) = old.to_petrel(now)?;
            // Ask Petrel to encode its versioned records, including the account catalog.
            let memory = Arc::new(MemorySecretStore::new());
            let staging = SessionStore::new(memory.clone(), &self.namespace)?;
            staging.save_session(&record).await?;
            staging.save_dpop_key(&record.dpop_key_id, &scalar).await?;
            let mirror = if is_v1 {
                self.seal_mirror(b, &json)?
            } else {
                raw.clone()
            };
            let script = redis::Script::new(CONVERT);
            let mut op = self.fields(&script);
            op.arg(&raw)
                .arg(&mirror)
                .arg(self.ttl)
                .arg(format!("session.pending.{}", b.did));
            op.arg("nest.owner")
                .arg(self.sealed("nest.owner", b.did.as_str().as_bytes())?);
            for field in [
                format!("session.{}", b.did),
                format!("dpopKey.{}", record.dpop_key_id),
                "accountDIDs".into(),
            ] {
                let bytes = memory
                    .get(&self.namespace, &field)
                    .await?
                    .ok_or_else(|| corrupt("missing typed Petrel record"))?;
                op.arg(&field).arg(self.sealed(&field, &bytes)?);
            }
            let result: i64 = op.invoke_async(&mut conn).await.map_err(unavailable)?;
            match result {
                0 => return Ok(None),
                1 => {
                    PETREL_CONVERSIONS.with_label_values(&["converted"]).inc();
                    return Ok(Some((self.typed()?, mirror)));
                }
                // Another process completed conversion. Read its committed mirror.
                2 => continue,
                -2 => return Err(corrupt("mirror changed during pending refresh")),
                _ => {}
            }
        }
        Err(StoreError::Unavailable(
            "session changed during conversion".into(),
        ))
    }

    fn seal_mirror(&self, b: &SessionBinding, json: &str) -> Result<String, StoreError> {
        let metadata = EnvelopeMetadata::new("session", &b.mirror, Some(b.did.as_str()), None);
        seal_v2_with_metadata(&self.key, json, &metadata)
            .map_err(|_| StoreError::Unavailable("could not seal v2 mirror".into()))
    }

    fn read_result(&self, result: Vec<redis::Value>) -> Result<(i64, Option<String>), StoreError> {
        use redis::FromRedisValue;
        let status = result
            .first()
            .ok_or_else(|| corrupt("invalid Redis reply"))
            .and_then(|v| i64::from_redis_value(v).map_err(unavailable))?;
        let value = result
            .get(1)
            .map(Option::<String>::from_redis_value)
            .transpose()
            .map_err(unavailable)?
            .flatten();
        Ok((status, value))
    }

    async fn read(&self, field: &str) -> Result<Option<String>, StoreError> {
        let script = redis::Script::new(READ_FIELD);
        let (status, value) = self.read_result(
            self.fields(&script)
                .arg(field)
                .invoke_async(&mut self.conn.clone())
                .await
                .map_err(unavailable)?,
        )?;
        match status {
            1 => Ok(value),
            0 => Ok(None),
            _ => Err(StoreError::Unavailable("session mirror changed".into())),
        }
    }

    async fn mirror_update(
        &self,
        b: &SessionBinding,
        data: &[u8],
    ) -> Result<(String, String), StoreError> {
        #[derive(Deserialize)]
        struct Envelope {
            v: u8,
            data: SessionRecord,
        }
        let envelope: Envelope =
            serde_json::from_slice(data).map_err(|_| corrupt("invalid typed session envelope"))?;
        let record = envelope.data;
        if envelope.v != 1 || record.account.did != b.did || record.session.did != b.did {
            return Err(corrupt("invalid replacement session binding"));
        }
        let current = self
            .read("nest.mirror")
            .await?
            .ok_or_else(|| StoreError::Unavailable("session was retired".into()))?;
        let (json, _, _) = open_v2_with_metadata(&self.key, &current, "session", &b.mirror)
            .map_err(|_| corrupt("invalid v2 mirror"))?;
        let mut value: Value =
            serde_json::from_str(&json).map_err(|_| corrupt("invalid v2 session JSON"))?;
        let old: LegacySessionV2 =
            serde_json::from_value(value.clone()).map_err(|_| corrupt("invalid v2 grant"))?;
        let (bound, _) = old.to_petrel(record.session.created_at)?;
        if old.session_id != b.id
            || old.account_did != b.did
            || bound.dpop_jkt != record.dpop_jkt
            || bound.account.pds != record.account.pds
            || bound.account.expected_issuer != record.account.expected_issuer
        {
            return Err(corrupt(
                "replacement changed session authority or DPoP binding",
            ));
        }
        value["access_token"] = Value::from(record.session.access_token());
        value["refresh_token"] = Value::from(record.session.refresh_token());
        value["expires_at"] = Value::from(expiry(&record)?.as_str());
        value["scope"] = Value::from(record.session.scope());
        value["scopes"] = Value::from(record.session.scope());
        if bound.session.scope() != record.session.scope() {
            value
                .as_object_mut()
                .ok_or_else(|| corrupt("invalid session object"))?
                .remove("resolved_scopes");
        }
        if let Some(metadata) = record.account.authorization_server {
            if let Some(token) = metadata.token_endpoint {
                value["authserver_token_endpoint"] = token.into();
            }
            if let Some(revoke) = metadata.revocation_endpoint {
                value["authserver_revocation_endpoint"] = revoke.into();
            } else if let Some(obj) = value.as_object_mut() {
                obj.remove("authserver_revocation_endpoint");
            }
        }
        Ok((self.seal_mirror(b, &value.to_string())?, current))
    }

    async fn change(
        &self,
        field: &str,
        expected: Option<&str>,
        new: Option<&[u8]>,
    ) -> Result<bool, StoreError> {
        let encrypted = new
            .map(|data| self.sealed(field, data))
            .transpose()?
            .unwrap_or_default();
        let mut mirror = (String::new(), String::new());
        if let Some(b) = &self.binding {
            if field == format!("session.{}", b.did) {
                mirror = match new {
                    Some(data) => self.mirror_update(b, data).await?,
                    None => ("delete".into(), String::new()),
                };
            }
        }
        // A completed temporary authorization flow also belongs in account erasure.
        let owner = new
            .and_then(|_| field.strip_prefix("session."))
            .filter(|suffix| self.binding.is_none() && suffix.starts_with("did:"));
        let script = redis::Script::new(WRITE_FIELD);
        let mut op = self.fields(&script);
        if let Some(did) = owner {
            op.key(format!("{}{did}", self.erasure_prefix));
        }
        let mirrored = new.is_some() && !mirror.0.is_empty();
        let result: i64 = op
            .arg(field)
            .arg(expected.unwrap_or("*"))
            .arg(encrypted)
            .arg(self.ttl)
            .arg(mirror.0)
            .arg(mirror.1)
            .arg(
                owner
                    .map(|did| self.sealed("nest.owner", did.as_bytes()))
                    .transpose()?
                    .unwrap_or_default(),
            )
            .invoke_async(&mut self.conn.clone())
            .await
            .map_err(unavailable)?;
        if result == 1 && mirrored {
            PETREL_MIRROR_WRITES.inc();
        }
        match result {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(StoreError::Unavailable(
                "session retired or replaced".into(),
            )),
        }
    }
}

impl SecretStore for RedisSessionSecrets {
    fn get<'a>(
        &'a self,
        ns: &'a str,
        field: &'a str,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async move {
            self.validate(ns, field)?;
            let data = self
                .read(field)
                .await?
                .map(|s| self.open_field(field, &s))
                .transpose()?;
            if field.starts_with("session.refreshLease.") && data.is_some() {
                PETREL_REFRESH_LEASE_READS.inc();
            }
            Ok(data)
        })
    }
    fn put<'a>(
        &'a self,
        ns: &'a str,
        field: &'a str,
        value: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.validate(ns, field)?;
            if self.change(field, None, Some(value)).await? {
                Ok(())
            } else {
                Err(StoreError::Unavailable("session changed".into()))
            }
        })
    }
    fn delete<'a>(&'a self, ns: &'a str, field: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.validate(ns, field)?;
            if self.read(field).await?.is_some() {
                self.change(field, None, None).await?;
            }
            Ok(())
        })
    }
    fn take<'a>(
        &'a self,
        ns: &'a str,
        field: &'a str,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async move {
            self.validate(ns, field)?;
            for _ in 0..8 {
                let Some(cipher) = self.read(field).await? else {
                    return Ok(None);
                };
                let clear = self.open_field(field, &cipher)?;
                if self.change(field, Some(&cipher), None).await? {
                    return Ok(Some(clear));
                }
            }
            Err(StoreError::Unavailable("concurrent take".into()))
        })
    }
    fn compare_and_swap<'a>(
        &'a self,
        ns: &'a str,
        field: &'a str,
        expected: Option<&'a [u8]>,
        new: Option<&'a [u8]>,
    ) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            self.validate(ns, field)?;
            let cipher = self.read(field).await?;
            let clear = cipher
                .as_deref()
                .map(|c| self.open_field(field, c))
                .transpose()?;
            let swapped = clear.as_deref() == expected
                && self
                    .change(field, Some(cipher.as_deref().unwrap_or("")), new)
                    .await?;
            if !swapped {
                let class = if field.starts_with("session.refreshLease.") {
                    "refresh_lease"
                } else if field.starts_with("session.did:") {
                    "session"
                } else {
                    "other"
                };
                PETREL_CAS_CONFLICTS.with_label_values(&[class]).inc();
            }
            Ok(swapped)
        })
    }
    fn delete_namespace<'a>(&'a self, ns: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            if ns != self.namespace {
                return Err(StoreError::InvalidNamespace);
            }
            if let Some(b) = &self.binding {
                self.delete(ns, &format!("session.{}", b.did)).await?;
            } else {
                let _: () = self
                    .conn
                    .clone()
                    .del(&self.hash)
                    .await
                    .map_err(unavailable)?;
            }
            Ok(())
        })
    }
}
