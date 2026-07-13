use crate::services::redis_crypto::{Keyring, RecordContext};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

pub(crate) const BEGIN_BINDING_NSID: &str = "blue.catbird.mlsChat.beginDeviceAuthBinding";
pub(crate) const COMPLETE_BINDING_NSID: &str = "blue.catbird.mlsChat.completeDeviceAuthBinding";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingBinding {
    pub(crate) session_binding_id: String,
    pub(crate) did: String,
    pub(crate) jkt: String,
    pub(crate) device_id: String,
    pub(crate) challenge_id: String,
    pub(crate) challenge: Vec<u8>,
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BoundDevice {
    pub(crate) session_binding_id: String,
    pub(crate) did: String,
    pub(crate) jkt: String,
    pub(crate) device_id: String,
    pub(crate) bound_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct BeginBindingInput {
    pub(crate) device_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AtprotoBytes {
    #[serde(rename = "$bytes")]
    encoded: String,
}

impl AtprotoBytes {
    fn decode(&self) -> Result<Vec<u8>, String> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.encoded)
            .map_err(|_| "invalid ATProto bytes".to_string())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CompleteBindingInput {
    pub(crate) challenge_id: String,
    signature: AtprotoBytes,
}

impl CompleteBindingInput {
    pub(crate) fn signature(&self) -> Result<Vec<u8>, String> {
        self.signature.decode()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct BeginBindingResponse {
    pub(crate) challenge_id: String,
    challenge: AtprotoBytes,
    pub(crate) expires_at: DateTime<Utc>,
    binding_version: i64,
}

impl BeginBindingResponse {
    pub(crate) fn challenge(&self) -> Result<Vec<u8>, String> {
        self.challenge.decode()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CompleteBindingResponse {
    pub(crate) device_id: String,
    pub(crate) bound_at: DateTime<Utc>,
    binding_version: i64,
}

fn valid_opaque_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn canonical_device_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .map(|uuid| uuid.hyphenated().to_string() == value)
        .unwrap_or(false)
}

pub(crate) fn parse_begin_input(body: &[u8]) -> Result<BeginBindingInput, String> {
    let input: BeginBindingInput =
        serde_json::from_slice(body).map_err(|_| "invalid begin binding input".to_string())?;
    if !canonical_device_uuid(&input.device_id) {
        return Err("invalid device ID".to_string());
    }
    Ok(input)
}

pub(crate) fn parse_complete_input(body: &[u8]) -> Result<CompleteBindingInput, String> {
    let input: CompleteBindingInput =
        serde_json::from_slice(body).map_err(|_| "invalid complete binding input".to_string())?;
    if !valid_opaque_id(&input.challenge_id, 128) || input.signature()?.len() != 64 {
        return Err("invalid complete binding input".to_string());
    }
    Ok(input)
}

pub(crate) fn parse_begin_response(
    body: &[u8],
    now: DateTime<Utc>,
) -> Result<BeginBindingResponse, String> {
    let response: BeginBindingResponse =
        serde_json::from_slice(body).map_err(|_| "invalid begin binding response".to_string())?;
    let challenge_len = response.challenge()?.len();
    if response.binding_version != 1
        || !valid_opaque_id(&response.challenge_id, 128)
        || !(1..=512).contains(&challenge_len)
        || response.expires_at <= now
        || response.expires_at > now + Duration::minutes(10)
    {
        return Err("invalid begin binding response".to_string());
    }
    Ok(response)
}

pub(crate) fn parse_complete_response(
    body: &[u8],
    expected_device_id: &str,
    now: DateTime<Utc>,
) -> Result<CompleteBindingResponse, String> {
    let response: CompleteBindingResponse = serde_json::from_slice(body)
        .map_err(|_| "invalid complete binding response".to_string())?;
    if response.binding_version != 1
        || response.device_id != expected_device_id
        || !canonical_device_uuid(&response.device_id)
        || response.bound_at < now - Duration::minutes(10)
        || response.bound_at > now + Duration::minutes(5)
    {
        return Err("invalid complete binding response".to_string());
    }
    Ok(response)
}

pub(crate) fn seal_pending(
    keyring: &Keyring,
    logical_key: &str,
    pending: &PendingBinding,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(pending).map_err(|_| "binding serialization failed")?;
    keyring
        .seal(
            &RecordContext::new("mls-device-pending", logical_key),
            &bytes,
        )
        .map_err(|_| "binding encryption failed".to_string())
}

pub(crate) fn open_pending(
    keyring: &Keyring,
    logical_key: &str,
    envelope: &str,
) -> Result<(PendingBinding, bool), String> {
    let opened = keyring
        .open_with_status(
            &RecordContext::new("mls-device-pending", logical_key),
            envelope,
        )
        .map_err(|_| "binding authentication failed".to_string())?;
    let value = serde_json::from_slice(&opened.plaintext)
        .map_err(|_| "binding record malformed".to_string())?;
    Ok((value, opened.needs_rewrap))
}

pub(crate) fn seal_bound(
    keyring: &Keyring,
    logical_key: &str,
    bound: &BoundDevice,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(bound).map_err(|_| "binding serialization failed")?;
    keyring
        .seal(&RecordContext::new("mls-device-bound", logical_key), &bytes)
        .map_err(|_| "binding encryption failed".to_string())
}

pub(crate) fn open_bound(
    keyring: &Keyring,
    logical_key: &str,
    envelope: &str,
) -> Result<(BoundDevice, bool), String> {
    let opened = keyring
        .open_with_status(
            &RecordContext::new("mls-device-bound", logical_key),
            envelope,
        )
        .map_err(|_| "binding authentication failed".to_string())?;
    let value = serde_json::from_slice(&opened.plaintext)
        .map_err(|_| "binding record malformed".to_string())?;
    Ok((value, opened.needs_rewrap))
}

pub(crate) fn authoritative_device_id<'a>(
    lexicon: &str,
    validated_begin_device: Option<&'a str>,
    pending: Option<&'a PendingBinding>,
    bound: Option<&'a BoundDevice>,
) -> Option<&'a str> {
    match lexicon {
        BEGIN_BINDING_NSID => validated_begin_device,
        COMPLETE_BINDING_NSID => pending.map(|record| record.device_id.as_str()),
        _ => bound.map(|record| record.device_id.as_str()),
    }
}

#[derive(Clone)]
pub(crate) struct MlsDeviceBindingStore {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
    session_ttl_seconds: u64,
    keyring: Keyring,
}

impl MlsDeviceBindingStore {
    pub(crate) fn new(
        redis: redis::aio::ConnectionManager,
        key_prefix: String,
        session_ttl_seconds: u64,
        keyring: Keyring,
    ) -> Self {
        Self {
            redis,
            key_prefix,
            session_ttl_seconds,
            keyring,
        }
    }

    fn session_binding_id(&self, session_id: &str) -> String {
        self.keyring.opaque_id("mls-device-session", session_id)
    }

    fn pending_key(&self, challenge_id: &str) -> String {
        format!(
            "{}mls_binding:pending:{}",
            self.key_prefix,
            self.keyring.opaque_id("mls-device-pending", challenge_id)
        )
    }

    fn bound_key_for_binding(&self, session_binding_id: &str) -> String {
        format!("{}mls_binding:bound:{session_binding_id}", self.key_prefix)
    }

    fn index_key_for_binding(&self, session_binding_id: &str) -> String {
        format!("{}mls_binding:index:{session_binding_id}", self.key_prefix)
    }

    fn device_owner_key(&self, device_id: &str) -> String {
        format!(
            "{}mls_binding:device:{}",
            self.key_prefix,
            self.keyring.opaque_id("mls-device-id", device_id)
        )
    }

    pub(crate) async fn persist_pending(
        &self,
        session_id: &str,
        did: &str,
        jkt: &str,
        device_id: &str,
        response: &BeginBindingResponse,
    ) -> crate::error::AppResult<PendingBinding> {
        let now = Utc::now();
        let challenge = response
            .challenge()
            .map_err(crate::error::AppError::BadRequest)?;
        if response.binding_version != 1
            || !canonical_device_uuid(device_id)
            || !valid_opaque_id(&response.challenge_id, 128)
            || !(1..=512).contains(&challenge.len())
            || response.expires_at <= now
        {
            return Err(crate::error::AppError::BadRequest(
                "invalid MLS device binding response".into(),
            ));
        }
        let ttl = (response.expires_at - now).num_seconds();
        if !(1..=600).contains(&ttl) {
            return Err(crate::error::AppError::BadRequest(
                "invalid MLS device binding expiry".into(),
            ));
        }
        let session_binding_id = self.session_binding_id(session_id);
        let pending = PendingBinding {
            session_binding_id: session_binding_id.clone(),
            did: did.to_string(),
            jkt: jkt.to_string(),
            device_id: device_id.to_string(),
            challenge_id: response.challenge_id.clone(),
            challenge,
            expires_at: response.expires_at,
        };
        let pending_key = self.pending_key(&pending.challenge_id);
        let index_key = self.index_key_for_binding(&session_binding_id);
        let envelope = seal_pending(&self.keyring, &pending_key, &pending)
            .map_err(crate::error::AppError::Crypto)?;
        let result: i64 = redis::Script::new(
            r#"
            if redis.call('EXISTS', KEYS[1]) ~= 0 then return 0 end
            redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2], 'NX')
            redis.call('SADD', KEYS[2], KEYS[1])
            redis.call('EXPIRE', KEYS[2], ARGV[3])
            return 1
            "#,
        )
        .key(&pending_key)
        .key(&index_key)
        .arg(&envelope)
        .arg(ttl)
        .arg(self.session_ttl_seconds)
        .invoke_async(&mut self.redis.clone())
        .await?;
        if result != 1 {
            return Err(crate::error::AppError::Unauthorized(
                "MLS device binding challenge collision".into(),
            ));
        }
        Ok(pending)
    }

    pub(crate) async fn load_pending(
        &self,
        session_id: &str,
        did: &str,
        jkt: &str,
        challenge_id: &str,
    ) -> crate::error::AppResult<PendingBinding> {
        if !valid_opaque_id(challenge_id, 128) {
            return Err(crate::error::AppError::Unauthorized(
                "invalid MLS device binding challenge".into(),
            ));
        }
        let key = self.pending_key(challenge_id);
        let envelope: Option<String> = self.redis.clone().get(&key).await?;
        let envelope = envelope.ok_or_else(|| {
            crate::error::AppError::Unauthorized("MLS device binding challenge unavailable".into())
        })?;
        let (pending, needs_rewrap) =
            open_pending(&self.keyring, &key, &envelope).map_err(crate::error::AppError::Crypto)?;
        let expected_session = self.session_binding_id(session_id);
        if pending.session_binding_id != expected_session
            || pending.did != did
            || pending.jkt != jkt
            || pending.challenge_id != challenge_id
            || pending.expires_at <= Utc::now()
        {
            return Err(crate::error::AppError::Unauthorized(
                "MLS device binding challenge mismatch".into(),
            ));
        }
        if needs_rewrap {
            let replacement = seal_pending(&self.keyring, &key, &pending)
                .map_err(crate::error::AppError::Crypto)?;
            let _: i64 = redis::Script::new(
                r#"
                if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
                local ttl = redis.call('PTTL', KEYS[1])
                if ttl <= 0 then return 0 end
                redis.call('SET', KEYS[1], ARGV[2], 'XX', 'PX', ttl)
                return 1
                "#,
            )
            .key(&key)
            .arg(&envelope)
            .arg(replacement)
            .invoke_async(&mut self.redis.clone())
            .await?;
        }
        Ok(pending)
    }

    pub(crate) async fn load_bound(
        &self,
        session_id: &str,
        did: &str,
        jkt: &str,
    ) -> crate::error::AppResult<Option<BoundDevice>> {
        let session_binding_id = self.session_binding_id(session_id);
        let key = self.bound_key_for_binding(&session_binding_id);
        let Some(envelope): Option<String> = self.redis.clone().get(&key).await? else {
            return Ok(None);
        };
        let (bound, needs_rewrap) =
            open_bound(&self.keyring, &key, &envelope).map_err(crate::error::AppError::Crypto)?;
        if bound.session_binding_id != session_binding_id || bound.did != did || bound.jkt != jkt {
            return Err(crate::error::AppError::Unauthorized(
                "MLS device binding does not match the authenticated session".into(),
            ));
        }
        let owner_key = self.device_owner_key(&bound.device_id);
        let owner_envelope: Option<String> = self.redis.clone().get(&owner_key).await?;
        let owner_envelope = owner_envelope.ok_or_else(|| {
            crate::error::AppError::Unauthorized("MLS device binding owner unavailable".into())
        })?;
        let (owner, owner_needs_rewrap) = open_bound(&self.keyring, &owner_key, &owner_envelope)
            .map_err(crate::error::AppError::Crypto)?;
        if owner != bound {
            return Err(crate::error::AppError::Unauthorized(
                "MLS device binding is no longer authoritative".into(),
            ));
        }
        let still_authoritative: i64 = redis::Script::new(
            r#"
            if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
            if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end
            return 1
            "#,
        )
        .key(&key)
        .key(&owner_key)
        .arg(&envelope)
        .arg(&owner_envelope)
        .invoke_async(&mut self.redis.clone())
        .await?;
        if still_authoritative != 1 {
            return Err(crate::error::AppError::Unauthorized(
                "MLS device binding changed during authorization".into(),
            ));
        }
        if needs_rewrap {
            let replacement =
                seal_bound(&self.keyring, &key, &bound).map_err(crate::error::AppError::Crypto)?;
            let _: i64 = redis::Script::new(
                r#"
                if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
                local ttl = redis.call('PTTL', KEYS[1])
                if ttl <= 0 then return 0 end
                redis.call('SET', KEYS[1], ARGV[2], 'XX', 'PX', ttl)
                return 1
                "#,
            )
            .key(&key)
            .arg(&envelope)
            .arg(replacement)
            .invoke_async(&mut self.redis.clone())
            .await?;
        }
        if owner_needs_rewrap {
            let replacement = seal_bound(&self.keyring, &owner_key, &owner)
                .map_err(crate::error::AppError::Crypto)?;
            let _: i64 = redis::Script::new(
                r#"
                if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
                local ttl = redis.call('PTTL', KEYS[1])
                if ttl <= 0 then return 0 end
                redis.call('SET', KEYS[1], ARGV[2], 'XX', 'PX', ttl)
                return 1
                "#,
            )
            .key(&owner_key)
            .arg(&owner_envelope)
            .arg(replacement)
            .invoke_async(&mut self.redis.clone())
            .await?;
        }
        Ok(Some(bound))
    }

    pub(crate) async fn promote(
        &self,
        session_id: &str,
        pending: &PendingBinding,
        response: &CompleteBindingResponse,
    ) -> crate::error::AppResult<BoundDevice> {
        let session_binding_id = self.session_binding_id(session_id);
        if pending.session_binding_id != session_binding_id
            || response.binding_version != 1
            || response.device_id != pending.device_id
            || !canonical_device_uuid(&response.device_id)
            || response.bound_at < Utc::now() - Duration::minutes(10)
            || response.bound_at > Utc::now() + Duration::minutes(5)
        {
            return Err(crate::error::AppError::Unauthorized(
                "MLS device binding promotion mismatch".into(),
            ));
        }
        let pending_key = self.pending_key(&pending.challenge_id);
        let pending_envelope: Option<String> = self.redis.clone().get(&pending_key).await?;
        let pending_envelope = pending_envelope.ok_or_else(|| {
            crate::error::AppError::Unauthorized("MLS device binding challenge unavailable".into())
        })?;
        let authenticated = open_pending(&self.keyring, &pending_key, &pending_envelope)
            .map_err(crate::error::AppError::Crypto)?
            .0;
        if authenticated != *pending || pending.expires_at <= Utc::now() {
            return Err(crate::error::AppError::Unauthorized(
                "MLS device binding challenge changed or expired".into(),
            ));
        }
        let bound = BoundDevice {
            session_binding_id: session_binding_id.clone(),
            did: pending.did.clone(),
            jkt: pending.jkt.clone(),
            device_id: pending.device_id.clone(),
            bound_at: response.bound_at,
        };
        let bound_key = self.bound_key_for_binding(&session_binding_id);
        let index_key = self.index_key_for_binding(&session_binding_id);
        let owner_key = self.device_owner_key(&bound.device_id);
        let target_owner_envelope: Option<String> = self.redis.clone().get(&owner_key).await?;
        let (target_old_bound_key, target_old_index_key) =
            if let Some(envelope) = target_owner_envelope.as_deref() {
                let (owner, _) = open_bound(&self.keyring, &owner_key, envelope)
                    .map_err(crate::error::AppError::Crypto)?;
                if owner.device_id != bound.device_id {
                    return Err(crate::error::AppError::Unauthorized(
                        "MLS device owner record mismatch".into(),
                    ));
                }
                (
                    self.bound_key_for_binding(&owner.session_binding_id),
                    self.index_key_for_binding(&owner.session_binding_id),
                )
            } else {
                (bound_key.clone(), index_key.clone())
            };
        let current_bound_envelope: Option<String> = self.redis.clone().get(&bound_key).await?;
        let (current_owner_key, current_owner_envelope) = if let Some(envelope) =
            current_bound_envelope.as_deref()
        {
            let (current, _) = open_bound(&self.keyring, &bound_key, envelope)
                .map_err(crate::error::AppError::Crypto)?;
            if current.session_binding_id != session_binding_id {
                return Err(crate::error::AppError::Unauthorized(
                    "MLS session binding record mismatch".into(),
                ));
            }
            let current_owner_key = self.device_owner_key(&current.device_id);
            let current_owner_envelope: Option<String> =
                self.redis.clone().get(&current_owner_key).await?;
            let current_owner_envelope = current_owner_envelope.ok_or_else(|| {
                crate::error::AppError::Unauthorized("MLS session device owner unavailable".into())
            })?;
            let (current_owner, _) =
                open_bound(&self.keyring, &current_owner_key, &current_owner_envelope)
                    .map_err(crate::error::AppError::Crypto)?;
            if current_owner != current {
                return Err(crate::error::AppError::Unauthorized(
                    "MLS session device owner mismatch".into(),
                ));
            }
            (current_owner_key, current_owner_envelope)
        } else {
            (owner_key.clone(), String::new())
        };
        let bound_envelope = seal_bound(&self.keyring, &bound_key, &bound)
            .map_err(crate::error::AppError::Crypto)?;
        let owner_envelope = seal_bound(&self.keyring, &owner_key, &bound)
            .map_err(crate::error::AppError::Crypto)?;
        let result: i64 = redis::Script::new(
            r#"
            if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
            local owner = redis.call('GET', KEYS[4])
            if ARGV[4] == 'absent' then
                if owner then return 0 end
            elseif owner ~= ARGV[5] then
                return 0
            end
            local session_bound = redis.call('GET', KEYS[2])
            if ARGV[7] == 'absent' then
                if session_bound then return 0 end
            elseif session_bound ~= ARGV[8] then
                return 0
            end
            if KEYS[7] ~= KEYS[4] and redis.call('GET', KEYS[7]) ~= ARGV[9] then
                return 0
            end
            if KEYS[5] ~= KEYS[2] then
                redis.call('DEL', KEYS[5])
                redis.call('SREM', KEYS[6], KEYS[5], KEYS[4])
            end
            if KEYS[7] ~= KEYS[4] then
                redis.call('DEL', KEYS[7])
                redis.call('SREM', KEYS[3], KEYS[7])
            end
            redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
            redis.call('SET', KEYS[4], ARGV[6], 'EX', ARGV[3])
            redis.call('DEL', KEYS[1])
            redis.call('SREM', KEYS[3], KEYS[1])
            redis.call('SADD', KEYS[3], KEYS[2], KEYS[4])
            redis.call('EXPIRE', KEYS[3], ARGV[3])
            return 1
            "#,
        )
        .key(&pending_key)
        .key(&bound_key)
        .key(&index_key)
        .key(&owner_key)
        .key(&target_old_bound_key)
        .key(&target_old_index_key)
        .key(&current_owner_key)
        .arg(&pending_envelope)
        .arg(bound_envelope)
        .arg(self.session_ttl_seconds)
        .arg(if target_owner_envelope.is_some() {
            "present"
        } else {
            "absent"
        })
        .arg(target_owner_envelope.unwrap_or_default())
        .arg(owner_envelope)
        .arg(if current_bound_envelope.is_some() {
            "present"
        } else {
            "absent"
        })
        .arg(current_bound_envelope.unwrap_or_default())
        .arg(current_owner_envelope)
        .invoke_async(&mut self.redis.clone())
        .await?;
        if result != 1 {
            return Err(crate::error::AppError::Unauthorized(
                "MLS device binding challenge was already consumed".into(),
            ));
        }
        Ok(bound)
    }

    pub(crate) async fn delete_session(&self, session_id: &str) -> crate::error::AppResult<()> {
        let session_binding_id = self.session_binding_id(session_id);
        let bound_key = self.bound_key_for_binding(&session_binding_id);
        let index_key = self.index_key_for_binding(&session_binding_id);
        let _: i64 = redis::Script::new(
            r#"
            local mappings = redis.call('SMEMBERS', KEYS[1])
            for _, key in ipairs(mappings) do redis.call('DEL', key) end
            redis.call('DEL', KEYS[1])
            redis.call('DEL', KEYS[2])
            return #mappings
            "#,
        )
        .key(index_key)
        .key(bound_key)
        .invoke_async(&mut self.redis.clone())
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::redis_crypto::{KeyMaterial, Keyring};
    use base64::Engine;
    use chrono::{Duration, Utc};

    fn keyring(active: u8, previous: Option<u8>) -> Keyring {
        Keyring::new(
            KeyMaterial::new(format!("key-{active}"), [active; 32]).unwrap(),
            previous
                .map(|byte| vec![KeyMaterial::new(format!("key-{byte}"), [byte; 32]).unwrap()])
                .unwrap_or_default(),
            [99; 32],
        )
        .unwrap()
    }

    fn pending() -> PendingBinding {
        PendingBinding {
            session_binding_id: "opaque-session".to_string(),
            did: "did:plc:alice".to_string(),
            jkt: "session-jkt".to_string(),
            device_id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            challenge_id: "challenge-1".to_string(),
            challenge: vec![1, 2, 3, 4],
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    #[test]
    fn begin_input_accepts_only_one_canonical_device_uuid() {
        let parsed =
            parse_begin_input(br#"{"deviceId":"123e4567-e89b-12d3-a456-426614174000"}"#).unwrap();
        assert_eq!(parsed.device_id, "123e4567-e89b-12d3-a456-426614174000");

        for invalid in [
            br#"{}"#.as_slice(),
            br#"{"deviceId":"victim"}"#.as_slice(),
            br#"{"deviceId":"123E4567-E89B-12D3-A456-426614174000"}"#.as_slice(),
            br#"{"deviceId":"123e4567-e89b-12d3-a456-426614174000","victim":"other"}"#.as_slice(),
        ] {
            assert!(parse_begin_input(invalid).is_err());
        }
    }

    #[test]
    fn complete_input_is_strict_and_requires_exact_ed25519_signature_size() {
        let signature = base64::engine::general_purpose::STANDARD.encode([7u8; 64]);
        let body =
            format!(r#"{{"challengeId":"challenge-1","signature":{{"$bytes":"{signature}"}}}}"#);
        let parsed = parse_complete_input(body.as_bytes()).unwrap();
        assert_eq!(parsed.challenge_id, "challenge-1");
        assert_eq!(parsed.signature().unwrap().len(), 64);

        let short = base64::engine::general_purpose::STANDARD.encode([7u8; 63]);
        let body = format!(r#"{{"challengeId":"challenge-1","signature":{{"$bytes":"{short}"}}}}"#);
        assert!(parse_complete_input(body.as_bytes()).is_err());
        assert!(parse_complete_input(
            br#"{"challengeId":"challenge-1","signature":{"$bytes":"%%%"},"deviceId":"victim"}"#
        )
        .is_err());
    }

    #[test]
    fn begin_response_must_match_the_protocol_and_be_fresh() {
        let challenge = base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        let expires = (Utc::now() + Duration::minutes(5)).to_rfc3339();
        let body = format!(
            r#"{{"challengeId":"challenge-1","challenge":{{"$bytes":"{challenge}"}},"expiresAt":"{expires}","bindingVersion":1}}"#
        );
        let parsed = parse_begin_response(body.as_bytes(), Utc::now()).unwrap();
        assert_eq!(parsed.challenge_id, "challenge-1");
        assert_eq!(parsed.challenge().unwrap(), vec![5; 32]);

        let expired = (Utc::now() - Duration::seconds(1)).to_rfc3339();
        let expired_body = format!(
            r#"{{"challengeId":"challenge-1","challenge":{{"$bytes":"{challenge}"}},"expiresAt":"{expired}","bindingVersion":1}}"#
        );
        assert!(parse_begin_response(expired_body.as_bytes(), Utc::now()).is_err());
        assert!(parse_begin_response(
            br#"{"challengeId":"challenge-1","challenge":{"$bytes":"AQ=="},"expiresAt":"2999-01-01T00:00:00Z","bindingVersion":2}"#,
            Utc::now(),
        )
        .is_err());
    }

    #[test]
    fn complete_response_must_name_the_exact_pending_device() {
        let now = Utc::now();
        let body = format!(
            r#"{{"deviceId":"123e4567-e89b-12d3-a456-426614174000","boundAt":"{}","bindingVersion":1}}"#,
            now.to_rfc3339()
        );
        let parsed =
            parse_complete_response(body.as_bytes(), "123e4567-e89b-12d3-a456-426614174000", now)
                .unwrap();
        assert_eq!(parsed.device_id, "123e4567-e89b-12d3-a456-426614174000");

        let victim = body.replace("123e4567-e89b-12d3-a456-426614174000", "victim");
        assert!(parse_complete_response(
            victim.as_bytes(),
            "123e4567-e89b-12d3-a456-426614174000",
            now,
        )
        .is_err());
    }

    #[test]
    fn pending_and_bound_records_are_opaque_aead_and_rotate_keys() {
        let old = keyring(1, None);
        let rotated = keyring(2, Some(1));
        let pending = pending();
        let challenge_key = old.opaque_id("mls-device-pending", &pending.challenge_id);
        let sealed = seal_pending(&old, &challenge_key, &pending).unwrap();

        assert!(!sealed.contains(&pending.did));
        assert!(!sealed.contains(&pending.device_id));
        assert!(!challenge_key.contains(&pending.challenge_id));

        let (opened, needs_rewrap) = open_pending(&rotated, &challenge_key, &sealed).unwrap();
        assert_eq!(opened, pending);
        assert!(needs_rewrap);
        assert!(open_pending(&keyring(3, None), &challenge_key, &sealed).is_err());

        let bound = BoundDevice {
            session_binding_id: opened.session_binding_id,
            did: opened.did,
            jkt: opened.jkt,
            device_id: opened.device_id,
            bound_at: Utc::now(),
        };
        let session_key = rotated.opaque_id("mls-device-session", "secret-session-id");
        let sealed = seal_bound(&rotated, &session_key, &bound).unwrap();
        assert_eq!(
            open_bound(&rotated, &session_key, &sealed).unwrap().0,
            bound
        );
    }

    #[test]
    fn authoritative_device_selection_never_reads_untrusted_request_fields() {
        let pending = pending();
        let bound = BoundDevice {
            session_binding_id: pending.session_binding_id.clone(),
            did: pending.did.clone(),
            jkt: pending.jkt.clone(),
            device_id: pending.device_id.clone(),
            bound_at: Utc::now(),
        };
        assert_eq!(
            authoritative_device_id(
                "blue.catbird.mlsChat.beginDeviceAuthBinding",
                Some(&pending.device_id),
                None,
                None,
            ),
            Some(pending.device_id.as_str())
        );
        assert_eq!(
            authoritative_device_id(
                "blue.catbird.mlsChat.completeDeviceAuthBinding",
                Some("victim-from-body"),
                Some(&pending),
                Some(&bound),
            ),
            Some(pending.device_id.as_str())
        );
        assert_eq!(
            authoritative_device_id(
                "blue.catbird.mlsChat.commitGroupChange",
                Some("victim-from-body-or-query-or-header"),
                None,
                Some(&bound),
            ),
            Some(bound.device_id.as_str())
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn redis_binding_lifecycle_is_atomic_session_bound_and_restart_safe() {
        let redis_url = std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL");
        let client = redis::Client::open(redis_url).unwrap();
        let manager = redis::aio::ConnectionManager::new(client).await.unwrap();
        let prefix = format!("test:mls-binding:{}:", uuid::Uuid::new_v4());
        let ring = keyring(7, None);
        let store = MlsDeviceBindingStore::new(manager.clone(), prefix.clone(), 3600, ring.clone());
        let session = "secret-session-bearer";
        let did = "did:plc:alice";
        let jkt = "session-jkt";
        let response = BeginBindingResponse {
            challenge_id: "challenge-redis".to_string(),
            challenge: AtprotoBytes {
                encoded: base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
            },
            expires_at: Utc::now() + Duration::minutes(5),
            binding_version: 1,
        };

        let pending = store
            .persist_pending(
                session,
                did,
                jkt,
                "123e4567-e89b-12d3-a456-426614174000",
                &response,
            )
            .await
            .unwrap();
        let mut conn = manager.clone();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{prefix}*"))
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(!keys.is_empty());
        assert!(keys.iter().all(|key| {
            !key.contains(session)
                && !key.contains(did)
                && !key.contains("challenge-redis")
                && !key.contains(&pending.device_id)
        }));

        assert!(store
            .load_pending("other-session", did, jkt, "challenge-redis")
            .await
            .is_err());
        assert!(store
            .load_pending(session, "did:plc:victim", jkt, "challenge-redis")
            .await
            .is_err());
        assert!(store
            .load_pending(session, did, "other-jkt", "challenge-redis")
            .await
            .is_err());
        let loaded = store
            .load_pending(session, did, jkt, "challenge-redis")
            .await
            .unwrap();

        let complete = CompleteBindingResponse {
            device_id: loaded.device_id.clone(),
            bound_at: Utc::now(),
            binding_version: 1,
        };
        let (left, right) = tokio::join!(
            store.promote(session, &loaded, &complete),
            store.promote(session, &loaded, &complete)
        );
        assert_ne!(left.is_ok(), right.is_ok());
        assert!(store
            .load_pending(session, did, jkt, "challenge-redis")
            .await
            .is_err());
        let bound = store.load_bound(session, did, jkt).await.unwrap().unwrap();
        assert_eq!(bound.device_id, loaded.device_id);

        let restarted = MlsDeviceBindingStore::new(manager.clone(), prefix.clone(), 3600, ring);
        assert_eq!(
            restarted
                .load_bound(session, did, jkt)
                .await
                .unwrap()
                .unwrap()
                .device_id,
            loaded.device_id
        );

        let replacement_device = "123e4567-e89b-12d3-a456-426614174001";
        let replacement_response = BeginBindingResponse {
            challenge_id: "challenge-device-replacement".to_string(),
            challenge: AtprotoBytes {
                encoded: base64::engine::general_purpose::STANDARD.encode([8u8; 32]),
            },
            expires_at: Utc::now() + Duration::minutes(5),
            binding_version: 1,
        };
        let replacement_pending = restarted
            .persist_pending(session, did, jkt, replacement_device, &replacement_response)
            .await
            .unwrap();
        restarted
            .promote(
                session,
                &replacement_pending,
                &CompleteBindingResponse {
                    device_id: replacement_device.to_string(),
                    bound_at: Utc::now(),
                    binding_version: 1,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            restarted
                .load_bound(session, did, jkt)
                .await
                .unwrap()
                .unwrap()
                .device_id,
            replacement_device
        );
        let old_owner: Option<String> = manager
            .clone()
            .get(restarted.device_owner_key(&loaded.device_id))
            .await
            .unwrap();
        assert!(old_owner.is_none());

        let second_session = "second-secret-session";
        let second_jkt = "second-session-jkt";
        let second_response = BeginBindingResponse {
            challenge_id: "challenge-rebind".to_string(),
            challenge: AtprotoBytes {
                encoded: base64::engine::general_purpose::STANDARD.encode([4u8; 32]),
            },
            expires_at: Utc::now() + Duration::minutes(5),
            binding_version: 1,
        };
        let second_pending = restarted
            .persist_pending(
                second_session,
                did,
                second_jkt,
                replacement_device,
                &second_response,
            )
            .await
            .unwrap();
        let second_complete = CompleteBindingResponse {
            device_id: replacement_device.to_string(),
            bound_at: Utc::now(),
            binding_version: 1,
        };
        restarted
            .promote(second_session, &second_pending, &second_complete)
            .await
            .unwrap();
        assert!(restarted
            .load_bound(session, did, jkt)
            .await
            .unwrap()
            .is_none());
        assert!(restarted
            .load_bound(second_session, did, second_jkt)
            .await
            .unwrap()
            .is_some());

        restarted.delete_session(session).await.unwrap();
        assert!(restarted
            .load_bound(second_session, did, second_jkt)
            .await
            .unwrap()
            .is_some());

        restarted.delete_session(second_session).await.unwrap();
        assert!(restarted
            .load_bound(second_session, did, second_jkt)
            .await
            .unwrap()
            .is_none());

        let race_session = "logout-promotion-race-session";
        let race_jkt = "logout-promotion-race-jkt";
        let race_response = BeginBindingResponse {
            challenge_id: "challenge-logout-race".to_string(),
            challenge: AtprotoBytes {
                encoded: base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
            },
            expires_at: Utc::now() + Duration::minutes(5),
            binding_version: 1,
        };
        let race_pending = restarted
            .persist_pending(
                race_session,
                did,
                race_jkt,
                "123e4567-e89b-12d3-a456-426614174002",
                &race_response,
            )
            .await
            .unwrap();
        let race_complete = CompleteBindingResponse {
            device_id: race_pending.device_id.clone(),
            bound_at: Utc::now(),
            binding_version: 1,
        };
        let (_promoted, logged_out) = tokio::join!(
            restarted.promote(race_session, &race_pending, &race_complete),
            restarted.delete_session(race_session)
        );
        assert!(logged_out.is_ok());
        assert!(restarted
            .load_bound(race_session, did, race_jkt)
            .await
            .unwrap()
            .is_none());
        let race_owner: Option<String> = manager
            .clone()
            .get(restarted.device_owner_key(&race_pending.device_id))
            .await
            .unwrap();
        assert!(race_owner.is_none());

        let remaining: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{prefix}*"))
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(remaining.is_empty(), "logout left MLS binding mappings");
    }
}
