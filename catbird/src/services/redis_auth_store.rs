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

use super::redis_crypto::{open_utf8_with_status, Keyring, RecordContext};

const STATE_TTL_SECONDS: u64 = 600; // 10 minutes for OAuth state
const SESSION_INDEX_TTL_SECONDS: u64 = 86400 * 30; // 30 days

fn redis_err(e: redis::RedisError) -> SessionStoreError {
    SessionStoreError::Other(e.into())
}

fn other_err(msg: &str) -> SessionStoreError {
    SessionStoreError::Other(msg.into())
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
        let Some(value) = encrypted else {
            return Ok(None);
        };
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
            conn.set_ex::<_, _, ()>(&key, rewrapped, SESSION_INDEX_TTL_SECONDS)
                .await?;
            tracing::info!(
                record_kind = "session_index",
                "Rewrapped Redis record with active key"
            );
        }
        Ok(Some(did))
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
                    conn.set_ex::<_, _, ()>(&key, rewrapped, self.session_ttl)
                        .await
                        .map_err(redis_err)?;
                    tracing::info!(
                        record_kind = "session",
                        "Rewrapped Redis record with active key"
                    );
                }
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
                let context = RecordContext::new("auth_req", &key);
                let (json, needs_rewrap) =
                    open_utf8_with_status(&self.keyring, &context, &encrypted).map_err(
                        |error| other_err(&format!("invalid encrypted auth request: {error}")),
                    )?;
                if needs_rewrap {
                    let ttl: i64 = redis::cmd("TTL")
                        .arg(&key)
                        .query_async(&mut conn)
                        .await
                        .map_err(redis_err)?;
                    let rewrapped =
                        self.keyring
                            .seal(&context, json.as_bytes())
                            .map_err(|error| {
                                other_err(&format!("failed to rewrap auth request: {error}"))
                            })?;
                    if ttl > 0 {
                        conn.set_ex::<_, _, ()>(&key, rewrapped, ttl as u64)
                            .await
                            .map_err(redis_err)?;
                    } else {
                        conn.set::<_, _, ()>(&key, rewrapped)
                            .await
                            .map_err(redis_err)?;
                    }
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
    use super::*;

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
}
