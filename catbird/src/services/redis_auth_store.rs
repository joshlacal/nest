//! Redis-backed implementation of Jacquard's `ClientAuthStore`.
//!
//! Stores session data in Redis with optional AES-256-GCM encryption.
//! Includes migration-on-access from the legacy 3-key atrium format.

use jacquard_common::session::SessionStoreError;
use jacquard_common::types::did::Did;
use jacquard_common::IntoStatic;
use jacquard_oauth::authstore::ClientAuthStore;
use jacquard_oauth::session::{AuthRequestData, ClientSessionData, DpopClientData};
use jacquard_oauth::types::{OAuthTokenType, TokenSet};
use redis::AsyncCommands;

use super::redis_crypto::{decrypt_from_redis, encrypt_for_redis};

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
///   `{prefix}session:{did}_{session_id}`   → encrypted ClientSessionData JSON
///   `{prefix}auth_req:{state}`             → encrypted AuthRequestData JSON
///   `{prefix}session_index:{session_id}`   → DID string (for session_id→DID lookup)
#[derive(Clone)]
pub struct RedisAuthStore {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
    session_ttl: u64,
    encryption_key: Option<[u8; 32]>,
}

impl RedisAuthStore {
    pub fn new(
        redis: redis::aio::ConnectionManager,
        key_prefix: String,
        session_ttl: u64,
        encryption_key: Option<[u8; 32]>,
    ) -> Self {
        Self {
            redis,
            key_prefix,
            session_ttl,
            encryption_key,
        }
    }

    fn session_key(&self, did: &str, session_id: &str) -> String {
        format!("{}session:{}_{}", self.key_prefix, did, session_id)
    }

    fn auth_req_key(&self, state: &str) -> String {
        format!("{}auth_req:{}", self.key_prefix, state)
    }

    fn session_index_key(&self, session_id: &str) -> String {
        format!("{}session_index:{}", self.key_prefix, session_id)
    }

    fn enc_key(&self) -> Option<&[u8; 32]> {
        self.encryption_key.as_ref()
    }

    /// Look up the DID associated with a session_id.
    ///
    /// iOS sends only `session_id` (not DID), but `ClientAuthStore` needs
    /// `(did, session_id)`. This index bridges that gap.
    pub async fn lookup_did_for_session(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, redis::RedisError> {
        let key = self.session_index_key(session_id);
        let mut conn = self.redis.clone();
        conn.get(&key).await
    }

    /// Write the session_id→DID index entry.
    pub async fn write_session_index(
        &self,
        session_id: &str,
        did: &str,
    ) -> Result<(), redis::RedisError> {
        let key = self.session_index_key(session_id);
        let mut conn = self.redis.clone();
        conn.set_ex::<_, _, ()>(&key, did, SESSION_INDEX_TTL_SECONDS)
            .await
    }

    /// Attempt to migrate a legacy (atrium) session to the new format.
    ///
    /// Legacy keys:
    ///   `{prefix}catbird_session:{session_id}` → CatbirdSession JSON
    ///   `{prefix}oauth_session:{session_id}`   → atrium Session JSON
    ///   `{prefix}dpop_key:{session_id}`        → DPoPKeyPair JSON
    ///
    /// Returns the migrated `ClientSessionData` if migration succeeded.
    pub async fn try_migrate_legacy_session(
        &self,
        session_id: &str,
    ) -> Result<Option<ClientSessionData<'static>>, SessionStoreError> {
        let mut conn = self.redis.clone();

        // Read legacy catbird session
        let catbird_key = format!("{}catbird_session:{}", self.key_prefix, session_id);
        let catbird_json: Option<String> = conn.get(&catbird_key).await.map_err(redis_err)?;

        let catbird_json = match catbird_json {
            Some(j) => j,
            None => return Ok(None),
        };

        let catbird: serde_json::Value =
            serde_json::from_str(&catbird_json).map_err(SessionStoreError::Serde)?;

        // Read legacy DPoP key
        let dpop_redis_key = format!("{}dpop_key:{}", self.key_prefix, session_id);
        let dpop_json: Option<String> = conn.get(&dpop_redis_key).await.map_err(redis_err)?;

        // We need at minimum the catbird session with tokens and DPoP key.
        let did_str = catbird["did"]
            .as_str()
            .ok_or_else(|| other_err("legacy session missing did"))?;
        let pds_url = catbird["pds_url"]
            .as_str()
            .ok_or_else(|| other_err("legacy session missing pds_url"))?;
        let access_token = catbird["access_token"]
            .as_str()
            .ok_or_else(|| other_err("legacy session missing access_token"))?;
        let refresh_token = catbird["refresh_token"].as_str().unwrap_or("");

        // Build DPoP key from legacy format
        let dpop_key: jose_jwk::Key = if let Some(ref dj) = dpop_json {
            let dpop_pair: serde_json::Value =
                serde_json::from_str(dj).map_err(SessionStoreError::Serde)?;

            // Legacy DPoPKeyPair has public_jwk (object) and private_key_bytes (base64 string)
            let pub_jwk = &dpop_pair["public_jwk"];
            let priv_b64 = dpop_pair["private_key_bytes"]
                .as_str()
                .ok_or_else(|| other_err("legacy dpop missing private_key_bytes"))?;

            // Reconstruct a full JWK with private component
            let mut full_jwk = pub_jwk.clone();
            if let Some(obj) = full_jwk.as_object_mut() {
                obj.insert(
                    "d".to_string(),
                    serde_json::Value::String(priv_b64.to_string()),
                );
            }

            serde_json::from_value(full_jwk).map_err(SessionStoreError::Serde)?
        } else {
            return Err(other_err("legacy session missing dpop_key"));
        };

        // Parse expiry
        let expires_at = catbird["access_token_expires_at"]
            .as_str()
            .and_then(|s| jacquard_common::types::string::Datetime::try_from(s.to_string()).ok());

        let did = Did::new_owned(did_str.to_string())
            .map_err(|e| other_err(&format!("invalid DID: {e}")))?;

        let session_data = ClientSessionData {
            account_did: did.clone(),
            session_id: session_id.to_string().into(),
            host_url: pds_url.to_string().into(),
            // We don't know the auth server URL in legacy format; it will be
            // resolved by Jacquard on next refresh.
            authserver_url: pds_url.to_string().into(),
            authserver_token_endpoint: "".into(),
            authserver_revocation_endpoint: None,
            scopes: vec![
                jacquard_oauth::scopes::Scope::Atproto,
                jacquard_oauth::scopes::Scope::Transition(
                    jacquard_oauth::scopes::TransitionScope::Generic,
                ),
            ],
            dpop_data: DpopClientData {
                dpop_key,
                dpop_authserver_nonce: "".into(),
                dpop_host_nonce: "".into(),
            },
            token_set: TokenSet {
                iss: pds_url.to_string().into(),
                sub: did.clone(),
                aud: pds_url.to_string().into(),
                scope: Some("atproto transition:generic transition:chat.bsky".into()),
                refresh_token: if refresh_token.is_empty() {
                    None
                } else {
                    Some(refresh_token.to_string().into())
                },
                access_token: access_token.to_string().into(),
                token_type: OAuthTokenType::DPoP,
                expires_at,
            },
        };

        // Write new-format session
        self.upsert_session(session_data.clone()).await?;

        // Write session index
        self.write_session_index(session_id, did_str)
            .await
            .map_err(redis_err)?;

        // Clean up legacy keys (best effort)
        let _: Result<(), _> = conn.del(&catbird_key).await;
        let oauth_key = format!("{}oauth_session:{}", self.key_prefix, session_id);
        let _: Result<(), _> = conn.del(&oauth_key).await;
        let _: Result<(), _> = conn.del(&dpop_redis_key).await;

        tracing::info!(
            did = %did_str,
            session_id = %session_id,
            "Migrated legacy session to new format"
        );

        Ok(Some(session_data))
    }
}

impl ClientAuthStore for RedisAuthStore {
    async fn get_session(
        &self,
        did: &Did<'_>,
        session_id: &str,
    ) -> Result<Option<ClientSessionData<'_>>, SessionStoreError> {
        let key = self.session_key(did.as_str(), session_id);
        let mut conn = self.redis.clone();

        let data: Option<String> = conn.get(&key).await.map_err(redis_err)?;

        match data {
            Some(encrypted) => {
                let json = decrypt_from_redis(self.enc_key(), &encrypted);
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
        let encrypted = encrypt_for_redis(self.enc_key(), &json);

        let mut conn = self.redis.clone();
        conn.set_ex::<_, _, ()>(&key, encrypted, self.session_ttl)
            .await
            .map_err(redis_err)?;

        // Also update the session index
        conn.set_ex::<_, _, ()>(
            &self.session_index_key(&session.session_id),
            session.account_did.as_str(),
            SESSION_INDEX_TTL_SECONDS,
        )
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
                let json = decrypt_from_redis(self.enc_key(), &encrypted);
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
        let encrypted = encrypt_for_redis(self.enc_key(), &json);

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
