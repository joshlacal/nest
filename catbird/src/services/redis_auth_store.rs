//! Redis-backed implementation of Jacquard's `ClientAuthStore`.
//!
//! Stores authenticated, encrypted session data under opaque Redis keys.

use jacquard_common::session::SessionStoreError;
use jacquard_common::types::did::Did;
use jacquard_common::IntoStatic;
use jacquard_oauth::authstore::ClientAuthStore;
use jacquard_oauth::session::{AuthRequestData, ClientSessionData, DpopClientData};
use jacquard_oauth::types::{OAuthTokenType, TokenSet};
use redis::{AsyncCommands, Expiry};

use super::redis_crypto::{open_utf8, Keyring, RecordContext};

const STATE_TTL_SECONDS: u64 = 600; // 10 minutes for OAuth state
const SESSION_INDEX_TTL_SECONDS: u64 = 86400 * 30; // 30 days

fn redis_err(e: redis::RedisError) -> SessionStoreError {
    SessionStoreError::Other(e.into())
}

fn other_err(msg: &str) -> SessionStoreError {
    SessionStoreError::Other(msg.into())
}

/// Redis-backed auth store for Jacquard OAuth.
///
/// Key schema:
///   `{prefix}session:<opaque-id>`       → encrypted ClientSessionData JSON
///   `{prefix}auth_req:<opaque-id>`      → encrypted AuthRequestData JSON
///   `{prefix}session_index:<opaque-id>` → encrypted DID string
#[derive(Clone)]
pub struct RedisAuthStore {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
    session_ttl: u64,
    keyring: Keyring,
}

impl RedisAuthStore {
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

    /// Look up the DID associated with a session_id.
    ///
    /// iOS sends only `session_id` (not DID), but `ClientAuthStore` needs
    /// `(did, session_id)`. This index bridges that gap.
    ///
    /// Sliding expiration: every successful lookup resets the index entry's
    /// TTL back to `SESSION_INDEX_TTL_SECONDS` via a single atomic `GETEX`.
    /// Previously this was a plain `GET`, so the TTL only slid on token
    /// refresh (`upsert_session` / `write_session_index`). A device idle for
    /// longer than the TTL (no refresh) would lose its index entry and get
    /// force-logged-out on the next request even though the session was
    /// otherwise recoverable. Reading on a rolling window now keeps any
    /// actively-used session alive.
    pub async fn lookup_did_for_session(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, redis::RedisError> {
        let key = self.session_index_key(session_id);
        let mut conn = self.redis.clone();
        let encrypted: Option<String> = conn
            .get_ex(&key, Expiry::EX(SESSION_INDEX_TTL_SECONDS as usize))
            .await?;
        encrypted
            .map(|value| {
                open_utf8(
                    &self.keyring,
                    &RecordContext::new("session_index", &key),
                    &value,
                )
                .map_err(|error| {
                    redis::RedisError::from((
                        redis::ErrorKind::TypeError,
                        "invalid encrypted session index",
                        error.to_string(),
                    ))
                })
            })
            .transpose()
    }

    /// Write the session_id→DID index entry.
    pub async fn write_session_index(
        &self,
        session_id: &str,
        did: &str,
    ) -> Result<(), redis::RedisError> {
        let key = self.session_index_key(session_id);
        let mut conn = self.redis.clone();
        let encrypted = self
            .keyring
            .seal(&RecordContext::new("session_index", &key), did.as_bytes())
            .map_err(|error| {
                redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "failed to encrypt session index",
                    error.to_string(),
                ))
            })?;
        conn.set_ex::<_, _, ()>(&key, encrypted, SESSION_INDEX_TTL_SECONDS)
            .await
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
        let oauth_key = format!("{}oauth_session:{}", self.key_prefix, session_id);
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
        let access_token = catbird["access_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .ok_or_else(|| other_err("legacy session missing access token"))?;
        let did = Did::new_owned(did_str)
            .map_err(|error| other_err(&format!("invalid legacy DID: {error}")))?;

        let pair: serde_json::Value =
            serde_json::from_str(&dpop_json).map_err(SessionStoreError::Serde)?;
        let mut full_jwk = pair["public_jwk"].clone();
        let private = pair["private_key_bytes"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| other_err("legacy DPoP record missing private key"))?;
        full_jwk
            .as_object_mut()
            .ok_or_else(|| other_err("legacy DPoP public key is invalid"))?
            .insert(
                "d".to_string(),
                serde_json::Value::String(private.to_string()),
            );
        let dpop_jwk: jose_jwk::Key =
            serde_json::from_value(full_jwk).map_err(SessionStoreError::Serde)?;
        let refresh_token = catbird["refresh_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .map(|token| token.to_string().into());
        let expires_at = catbird["access_token_expires_at"]
            .as_str()
            .and_then(|value| {
                jacquard_common::types::string::Datetime::try_from(value.to_string()).ok()
            });
        let session = ClientSessionData {
            account_did: did.clone(),
            session_id: session_id.to_string().into(),
            host_url: pds_url.to_string().into(),
            authserver_url: pds_url.to_string().into(),
            authserver_token_endpoint: "".into(),
            authserver_revocation_endpoint: None,
            scopes: vec![jacquard_oauth::scopes::Scope::Atproto],
            dpop_data: DpopClientData {
                dpop_key: dpop_jwk,
                dpop_authserver_nonce: "".into(),
                dpop_host_nonce: "".into(),
            },
            token_set: TokenSet {
                iss: pds_url.to_string().into(),
                sub: did.clone(),
                aud: pds_url.to_string().into(),
                scope: Some("atproto".into()),
                refresh_token,
                access_token: access_token.to_string().into(),
                token_type: OAuthTokenType::DPoP,
                expires_at,
            },
        };

        self.upsert_session(session).await?;
        let verified = self
            .get_session(&did, session_id)
            .await?
            .filter(|record| record.account_did == did && record.session_id == session_id)
            .ok_or_else(|| other_err("migrated session readback verification failed"))?;
        if verified.token_set.access_token != access_token {
            return Err(other_err("migrated token readback verification failed"));
        }
        conn.del::<_, ()>(&catbird_key).await.map_err(redis_err)?;
        conn.del::<_, ()>(&dpop_key).await.map_err(redis_err)?;
        conn.del::<_, ()>(&oauth_key).await.map_err(redis_err)?;
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
        let encrypted: String = conn.get(&old_session_key).await.map_err(redis_err)?;
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
        self.upsert_session(session.into_static()).await?;
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
        let mut conn = self.redis.clone();

        let data: Option<String> = conn
            .get_ex(&key, Expiry::EX(self.session_ttl as usize))
            .await
            .map_err(redis_err)?;

        match data {
            Some(encrypted) => {
                let json = open_utf8(
                    &self.keyring,
                    &RecordContext::new("session", &key),
                    &encrypted,
                )
                .map_err(|error| other_err(&format!("invalid encrypted session: {error}")))?;
                let session: ClientSessionData<'_> =
                    serde_json::from_str(&json).map_err(SessionStoreError::Serde)?;
                Ok(Some(session.into_static()))
            }
            None => Ok(None),
        }
    }

    async fn upsert_session(
        &self,
        session: ClientSessionData<'_>,
    ) -> Result<(), SessionStoreError> {
        let key = self.session_key(session.account_did.as_str(), &session.session_id);
        let json = serde_json::to_string(&session).map_err(SessionStoreError::Serde)?;
        let encrypted = self
            .keyring
            .seal(&RecordContext::new("session", &key), json.as_bytes())
            .map_err(|error| other_err(&format!("failed to encrypt session: {error}")))?;

        let mut conn = self.redis.clone();
        conn.set_ex::<_, _, ()>(&key, encrypted, self.session_ttl)
            .await
            .map_err(redis_err)?;

        // Also update the session index
        self.write_session_index(&session.session_id, session.account_did.as_str())
            .await
            .map_err(redis_err)?;

        Ok(())
    }

    async fn delete_session(
        &self,
        did: &Did<'_>,
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        let key = self.session_key(did.as_str(), session_id);
        let index_key = self.session_index_key(session_id);
        let mut conn = self.redis.clone();

        conn.del::<_, ()>(&key).await.map_err(redis_err)?;
        conn.del::<_, ()>(&index_key).await.map_err(redis_err)?;

        Ok(())
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
                let json = open_utf8(
                    &self.keyring,
                    &RecordContext::new("auth_req", &key),
                    &encrypted,
                )
                .map_err(|error| other_err(&format!("invalid encrypted auth request: {error}")))?;
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
