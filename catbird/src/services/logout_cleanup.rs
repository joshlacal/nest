//! Locally authenticated, resumable logout. No provider refresh is used to
//! authorize retirement. Only the final locally live session requests account
//! erasure. The effects adapter must fence its SQL writers with the account lock.
//!
//! Runtime logout and its worker forbid stored retry credentials. Generic policy
//! variants remain for isolated coordinator tests, not runtime configuration.
//! Neither a receipt UUID nor a DID alone authorizes a retry; the receipt is bound
//! to the original bearer HMAC.
use async_trait::async_trait;
use jacquard_oauth::session::ClientSessionData;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::services::{
    push::registry::session_fingerprint,
    redis_crypto::{open_v2_with_metadata, seal_v2_with_metadata, EnvelopeMetadata},
    revocation::{RevokeOutcome, MAX_REVOKE_ATTEMPTS, REVOKE_JOB_TTL_SECONDS},
    RedisAuthStore,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum CredentialRetention {
    Forbidden,
    ApprovedSealedRetry { seconds: u32 },
}
impl CredentialRetention {
    pub fn validate(self) -> Result<Self, CleanupError> {
        match self {
            Self::Forbidden => Ok(self),
            Self::ApprovedSealedRetry { seconds }
                if seconds > 0 && u64::from(seconds) <= REVOKE_JOB_TTL_SECONDS =>
            {
                Ok(self)
            }
            _ => Err(CleanupError::InvalidRetentionPolicy),
        }
    }
}

/// Approved runtime policy: one bounded in-memory provider attempt, no stored
/// retry grant. Deliberately takes no setting; environment values cannot override it.
pub const fn runtime_credential_retention() -> CredentialRetention {
    CredentialRetention::Forbidden
}

fn require_runtime_retention(policy: CredentialRetention) -> Result<(), CleanupError> {
    if policy == runtime_credential_retention() {
        Ok(())
    } else {
        Err(CleanupError::InvalidRetentionPolicy)
    }
}

/// Deliberately not Debug/Serialize: this contains the client bearer.
pub struct LogoutRequest {
    pub bearer: String,
    pub retention: CredentialRetention,
}
impl LogoutRequest {
    pub fn for_runtime(bearer: String) -> Result<Self, CleanupError> {
        Self::new(bearer, runtime_credential_retention())
    }

    pub fn new(bearer: String, retention: CredentialRetention) -> Result<Self, CleanupError> {
        let id = Uuid::parse_str(&bearer).map_err(|_| CleanupError::Unauthorized)?;
        if id.to_string() != bearer {
            return Err(CleanupError::Unauthorized);
        }
        Ok(Self {
            bearer,
            retention: retention.validate()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkStatus {
    Pending,
    Complete,
    Failed,
    NotRequired,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamStatus {
    Pending,
    Revoked,
    Unconfirmed,
    Unsupported,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    Complete,
    Pending,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountCleanupStatus {
    pub required: bool,
    pub status: WorkStatus,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CleanupResponse {
    pub version: u8,
    pub receipt_id: Uuid,
    pub session_retired: bool,
    pub device_cleanup: WorkStatus,
    pub account_cleanup: AccountCleanupStatus,
    pub upstream_revocation: UpstreamStatus,
    pub completion: Completion,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanupTarget {
    pub did: String,
    pub session_hmac: String,
    pub session_fingerprint: String,
    /// A discovery snapshot, not proof of current ownership. An effects adapter
    /// must compare current ownership under its registration/retirement lock.
    pub device_ids: Vec<Uuid>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanupJournal {
    pub receipt_id: Uuid,
    pub target: CleanupTarget,
    pub retention: CredentialRetention,
    pub created_at: i64,
    pub credential_expires_at: Option<i64>,
    pub device_cleanup: WorkStatus,
    pub account_cleanup: AccountCleanupStatus,
    pub upstream_revocation: UpstreamStatus,
    pub revocation_attempts: u32,
    pub retained_credential: bool,
    pub fence_released: bool,
    pub revision: u64,
}
impl CleanupJournal {
    pub fn response(&self) -> CleanupResponse {
        let failed = self.device_cleanup == WorkStatus::Failed
            || self.account_cleanup.status == WorkStatus::Failed
            || matches!(
                self.upstream_revocation,
                UpstreamStatus::Unconfirmed | UpstreamStatus::Unsupported
            );
        let pending = self.device_cleanup == WorkStatus::Pending
            || self.account_cleanup.status == WorkStatus::Pending
            || self.upstream_revocation == UpstreamStatus::Pending
            || self.retained_credential
            || !self.fence_released;
        CleanupResponse {
            version: 1,
            receipt_id: self.receipt_id,
            session_retired: true,
            device_cleanup: self.device_cleanup,
            account_cleanup: self.account_cleanup.clone(),
            upstream_revocation: self.upstream_revocation,
            completion: if failed {
                Completion::Failed
            } else if pending {
                Completion::Pending
            } else {
                Completion::Complete
            },
        }
    }
}

/// Backend errors deliberately omit raw Redis/provider error text and credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CleanupError {
    #[error("logout bearer is not locally authenticated")]
    Unauthorized,
    #[error("an explicit bounded credential-retention policy is required")]
    InvalidRetentionPolicy,
    #[error("logout retry does not match its authenticated receipt")]
    ReceiptConflict,
    #[error("logout storage operation failed or its outcome is unknown")]
    StorageUnavailable,
    #[error("logout session changed; retry with the current session")]
    SessionChanged,
    #[error("account session inventory exceeded its bounded scan")]
    InventoryIncomplete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkFailure {
    Retryable,
    Blocked,
}

pub struct CleanupAttempt {
    pub journal: CleanupJournal,
    /// Only retained across calls when the explicit policy permits it.
    pub grant: Option<ClientSessionData>,
}

#[async_trait]
pub trait CleanupStore: Send + Sync {
    /// Must atomically persist a bearer-bound intent before/with retirement.
    /// The final-session decision and erasure fence must share that atomic boundary.
    async fn begin_or_resume(
        &self,
        request: &LogoutRequest,
        now: i64,
    ) -> Result<CleanupAttempt, CleanupError>;
    /// Compare-and-set revision; a failed acknowledgement must not be called complete.
    async fn checkpoint(&self, journal: &mut CleanupJournal) -> Result<(), CleanupError>;
    async fn delete_retained_grant(&self, target: &CleanupTarget) -> Result<(), CleanupError>;
    /// Compare-and-delete only this receipt's fence, never a newer cleanup's fence.
    async fn release_fence(&self, journal: &CleanupJournal) -> Result<(), CleanupError>;
}

#[async_trait]
pub trait CleanupEffects: Send + Sync {
    /// Must be idempotent, compare current device ownership, and preserve other sessions.
    async fn stop_devices(&self, target: &CleanupTarget) -> Result<(), WorkFailure>;
    /// Only called when the atomic local inventory found no other live session.
    /// Must verify receipt_id against account_erasure:{did} under the SQL account
    /// lock and finish the complete owned SQL/Redis inventory before returning Ok.
    async fn erase_account(
        &self,
        target: &CleanupTarget,
        receipt_id: Uuid,
    ) -> Result<(), WorkFailure>;
    async fn revoke(&self, grant: &mut ClientSessionData, receipt_id: Uuid) -> RevokeOutcome;
}

/// One bounded attempt. A pending receipt can be retried after local retirement.
/// No automatic scheduling, provider calls or credential policy are hidden here.
pub async fn run_cleanup<S: CleanupStore, E: CleanupEffects>(
    store: &S,
    effects: &E,
    request: &LogoutRequest,
    now: i64,
) -> Result<CleanupResponse, CleanupError> {
    let attempt = store.begin_or_resume(request, now).await?;
    continue_cleanup(store, effects, attempt, now).await
}

pub async fn continue_cleanup<S: CleanupStore, E: CleanupEffects>(
    store: &S,
    effects: &E,
    attempt: CleanupAttempt,
    now: i64,
) -> Result<CleanupResponse, CleanupError> {
    let CleanupAttempt {
        mut journal,
        mut grant,
    } = attempt;
    if matches!(
        journal.device_cleanup,
        WorkStatus::Pending | WorkStatus::Failed
    ) {
        journal.device_cleanup = work_status(effects.stop_devices(&journal.target).await);
        store.checkpoint(&mut journal).await?;
    }
    // Distinct gateway bearers can share the same provider grant. Until an
    // isolated grant is provable, do not revoke while any other live bearer exists.
    if journal.upstream_revocation == UpstreamStatus::Pending && !journal.account_cleanup.required {
        journal.upstream_revocation = UpstreamStatus::Unconfirmed;
        store.checkpoint(&mut journal).await?;
    }
    if journal.upstream_revocation == UpstreamStatus::Pending {
        let within_retention = journal
            .credential_expires_at
            .is_none_or(|deadline| now < deadline);
        if within_retention && journal.revocation_attempts < MAX_REVOKE_ATTEMPTS {
            journal.upstream_revocation = if let Some(grant) = grant.as_mut() {
                journal.revocation_attempts += 1;
                store.checkpoint(&mut journal).await?;
                match effects.revoke(grant, journal.receipt_id).await {
                    RevokeOutcome::Revoked => UpstreamStatus::Revoked,
                    RevokeOutcome::NoRevocationEndpoint => UpstreamStatus::Unsupported,
                    RevokeOutcome::Failed(_)
                        if journal.retained_credential
                            && journal.revocation_attempts < MAX_REVOKE_ATTEMPTS =>
                    {
                        UpstreamStatus::Pending
                    }
                    RevokeOutcome::Failed(_) => UpstreamStatus::Unconfirmed,
                }
            } else {
                UpstreamStatus::Unconfirmed
            };
        } else {
            journal.upstream_revocation = UpstreamStatus::Unconfirmed;
        }
        // Persist the remote outcome BEFORE discarding the only retry credential.
        store.checkpoint(&mut journal).await?;
    }
    if journal.upstream_revocation != UpstreamStatus::Pending && journal.retained_credential {
        store.delete_retained_grant(&journal.target).await?;
        journal.retained_credential = false;
        store.checkpoint(&mut journal).await?;
    }
    if matches!(
        journal.account_cleanup.status,
        WorkStatus::Pending | WorkStatus::Failed
    ) {
        journal.account_cleanup.status = work_status(
            effects
                .erase_account(&journal.target, journal.receipt_id)
                .await,
        );
        if journal.account_cleanup.status == WorkStatus::Complete {
            // The full owned inventory includes device routing.
            journal.device_cleanup = WorkStatus::Complete;
        }
        store.checkpoint(&mut journal).await?;
    }
    if journal.account_cleanup.status == WorkStatus::Complete
        && !journal.fence_released
        && journal.upstream_revocation != UpstreamStatus::Pending
        && !journal.retained_credential
    {
        store.release_fence(&journal).await?;
        journal.fence_released = true;
        store.checkpoint(&mut journal).await?;
    }
    Ok(journal.response())
}
fn work_status(result: Result<(), WorkFailure>) -> WorkStatus {
    match result {
        Ok(()) => WorkStatus::Complete,
        Err(WorkFailure::Retryable) => WorkStatus::Pending,
        Err(WorkFailure::Blocked) => WorkStatus::Failed,
    }
}

pub struct RedisCleanupStore<'a> {
    pub store: &'a RedisAuthStore,
}
impl RedisCleanupStore<'_> {
    pub fn journal_key(&self, session_hmac: &str) -> String {
        format!("{}logout_cleanup:{}", self.store.key_prefix(), session_hmac)
    }
    pub fn grant_key(&self, session_hmac: &str) -> String {
        format!(
            "{}logout_cleanup_grant:{}",
            self.store.key_prefix(),
            session_hmac
        )
    }
    fn seal<T: Serialize>(
        &self,
        class: &str,
        key: &str,
        did: &str,
        value: &T,
    ) -> Result<String, CleanupError> {
        let json = serde_json::to_string(value).map_err(|_| CleanupError::StorageUnavailable)?;
        seal_v2_with_metadata(
            self.store.enc_key(),
            &json,
            &EnvelopeMetadata::new(class, key, Some(did), None),
        )
        .map_err(|_| CleanupError::StorageUnavailable)
    }
    fn open<T: serde::de::DeserializeOwned>(
        &self,
        class: &str,
        key: &str,
        value: &str,
    ) -> Result<T, CleanupError> {
        let (json, _, legacy) = open_v2_with_metadata(self.store.enc_key(), value, class, key)
            .map_err(|_| CleanupError::StorageUnavailable)?;
        if legacy {
            return Err(CleanupError::StorageUnavailable);
        }
        serde_json::from_str(&json).map_err(|_| CleanupError::StorageUnavailable)
    }
    async fn load_attempt(
        &self,
        request: &LogoutRequest,
        encoded: &str,
        now: i64,
    ) -> Result<CleanupAttempt, CleanupError> {
        let hmac = self.store.fingerprint(&request.bearer);
        let journal: CleanupJournal =
            self.open("logout_cleanup", &self.journal_key(&hmac), encoded)?;
        if journal.target.session_hmac != hmac
            || journal.target.session_fingerprint != session_fingerprint(&request.bearer)
            || journal.retention != request.retention
        {
            return Err(CleanupError::ReceiptConflict);
        }
        if journal.retention == CredentialRetention::Forbidden
            && (journal.retained_credential || journal.credential_expires_at.is_some())
        {
            return Err(CleanupError::ReceiptConflict);
        }
        let mut conn = self.store.redis_connection();
        let grant = if journal.retained_credential
            && journal
                .credential_expires_at
                .is_some_and(|expiry| now < expiry)
        {
            let key = self.grant_key(&hmac);
            let encoded: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .map_err(|_| CleanupError::StorageUnavailable)?;
            encoded
                .map(|value| self.open::<ClientSessionData>("logout_cleanup_grant", &key, &value))
                .transpose()?
        } else {
            None
        };
        if let Some(grant) = &grant {
            if grant.account_did.as_str() != journal.target.did
                || grant.session_id.as_str() != request.bearer
            {
                return Err(CleanupError::ReceiptConflict);
            }
        }
        Ok(CleanupAttempt { journal, grant })
    }
}

// All reads here are non-sliding. Retirement, the complete bounded live-session
// scan, intent persistence and fence installation execute in one Redis script.
// A concurrent login either appears in the scan or is rejected by the upsert fence.
pub const RETIRE_WITH_INTENT: &str = r#"
local existing = redis.call('GET', KEYS[1])
if existing then return {1, existing} end
if redis.call('EXISTS', KEYS[4]) == 1 then return {2, ''} end
if redis.call('GET', KEYS[2]) ~= ARGV[1] or redis.call('GET', KEYS[3]) ~= ARGV[2] then return {2, ''} end
local cursor = '0'
local pages = 0
local other = false
local verified = cjson.decode(ARGV[13])
repeat
  local page = redis.call('SCAN', cursor, 'MATCH', ARGV[3], 'COUNT', 100)
  cursor = page[1]
  pages = pages + 1
  for _, key in ipairs(page[2]) do
    if key ~= KEYS[2] and string.sub(key, 1, string.len(ARGV[4])) == ARGV[4] then
      local fp = string.sub(key, string.len(ARGV[4]) + 1)
      if string.len(fp) ~= 64 or not string.match(fp, '^[0-9a-f]+$') then return {3, ''} end
      if redis.call('EXISTS', ARGV[5] .. 'upgrade_retired:' .. fp) == 0
        and redis.call('EXISTS', key) == 1 then
          if verified[key] ~= redis.call('GET', key) then return {2, ''} end
          other = true
        end
    end
  end
  if pages >= 100 and cursor ~= '0' then return {3, ''} end
until cursor == '0'
local encoded = ARGV[6]
if not other then
  if redis.call('EXISTS', KEYS[9]) == 1 then return {2, ''} end
  encoded = ARGV[7]
  redis.call('SET', KEYS[9], ARGV[8])
end
redis.call('SET', KEYS[1], encoded)
if ARGV[10] ~= '' then redis.call('SET', KEYS[8], ARGV[10], 'EX', ARGV[11]) end
redis.call('SET', KEYS[4], 'logout', 'EX', ARGV[9])
redis.call('DEL', KEYS[2], KEYS[3], KEYS[5], KEYS[7])
if redis.call('GET', KEYS[6]) == ARGV[12] then redis.call('DEL', KEYS[6]) end
return {0, encoded}
"#;

#[async_trait]
impl CleanupStore for RedisCleanupStore<'_> {
    async fn begin_or_resume(
        &self,
        request: &LogoutRequest,
        now: i64,
    ) -> Result<CleanupAttempt, CleanupError> {
        request.retention.validate()?;
        if Uuid::parse_str(&request.bearer)
            .map_err(|_| CleanupError::Unauthorized)?
            .to_string()
            != request.bearer
        {
            return Err(CleanupError::Unauthorized);
        }
        let hmac = self.store.fingerprint(&request.bearer);
        let sha = session_fingerprint(&request.bearer);
        let key = self.journal_key(&hmac);
        let mut conn = self.store.redis_connection();
        let existing: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|_| CleanupError::StorageUnavailable)?;
        if let Some(encoded) = existing {
            return self.load_attempt(request, &encoded, now).await;
        }
        let did: Option<String> = redis::cmd("GET")
            .arg(self.store.session_index_key(&request.bearer))
            .query_async(&mut conn)
            .await
            .map_err(|_| CleanupError::StorageUnavailable)?;
        let did = did.ok_or(CleanupError::Unauthorized)?;
        self.store
            .read_session_local(&did, &request.bearer)
            .await
            .map_err(|_| CleanupError::StorageUnavailable)?
            .ok_or(CleanupError::Unauthorized)?;
        let session_key = self.store.session_key(&did, &request.bearer);
        let snapshot: Option<String> = redis::cmd("GET")
            .arg(&session_key)
            .query_async(&mut conn)
            .await
            .map_err(|_| CleanupError::StorageUnavailable)?;
        let snapshot = snapshot.ok_or(CleanupError::SessionChanged)?;
        // Verify the exact CAS snapshot, not only the earlier local read.
        let (json, metadata, _) =
            open_v2_with_metadata(self.store.enc_key(), &snapshot, "session", &session_key)
                .map_err(|_| CleanupError::Unauthorized)?;
        let grant: ClientSessionData =
            serde_json::from_str(&json).map_err(|_| CleanupError::Unauthorized)?;
        if grant.account_did.as_str() != did
            || grant.session_id.as_str() != request.bearer
            || metadata.did.as_deref().is_some_and(|value| value != did)
        {
            return Err(CleanupError::Unauthorized);
        }
        let ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg(format!(
                "{}push_session_devices:{}",
                self.store.key_prefix(),
                sha
            ))
            .query_async(&mut conn)
            .await
            .map_err(|_| CleanupError::StorageUnavailable)?;
        let mut device_ids = Vec::new();
        for id in ids {
            let id = Uuid::parse_str(&id).map_err(|_| CleanupError::InventoryIncomplete)?;
            let owner: Option<String> = redis::cmd("GET")
                .arg(format!(
                    "{}push_device_session:{}",
                    self.store.key_prefix(),
                    id
                ))
                .query_async(&mut conn)
                .await
                .map_err(|_| CleanupError::StorageUnavailable)?;
            if owner.as_deref() == Some(&sha) {
                device_ids.push(id);
            }
        }
        let seconds = match request.retention {
            CredentialRetention::Forbidden => 0,
            CredentialRetention::ApprovedSealedRetry { seconds } => seconds,
        };
        let deadline = if seconds > 0 {
            Some(
                now.checked_add(i64::from(seconds))
                    .ok_or(CleanupError::InvalidRetentionPolicy)?,
            )
        } else {
            None
        };
        let journal = CleanupJournal {
            receipt_id: Uuid::new_v4(),
            target: CleanupTarget {
                did: did.clone(),
                session_hmac: hmac.clone(),
                session_fingerprint: sha,
                device_ids,
            },
            retention: request.retention,
            created_at: now,
            credential_expires_at: deadline,
            device_cleanup: WorkStatus::Pending,
            account_cleanup: AccountCleanupStatus {
                required: false,
                status: WorkStatus::NotRequired,
            },
            upstream_revocation: UpstreamStatus::Pending,
            revocation_attempts: 0,
            retained_credential: seconds > 0,
            fence_released: true,
            revision: 0,
        };
        let mut final_journal = journal.clone();
        final_journal.account_cleanup = AccountCleanupStatus {
            required: true,
            status: WorkStatus::Pending,
        };
        final_journal.fence_released = false;
        let ordinary = self.seal("logout_cleanup", &key, &did, &journal)?;
        let final_encoded = self.seal("logout_cleanup", &key, &did, &final_journal)?;
        let sealed_grant = if seconds > 0 {
            self.seal("logout_cleanup_grant", &self.grant_key(&hmac), &did, &grant)?
        } else {
            String::new()
        };
        let head = format!("{}session:{}_", self.store.key_prefix(), did);
        let pattern = format!("{}*", redis_glob_escape(&head));
        // Authenticate every candidate before calling it a locally live session.
        // The atomic census compares exact ciphertext snapshots, so concurrent
        // insertion/refresh causes a retry instead of an unverified scope decision.
        let verified = self
            .verified_session_snapshots(&did, &head, &pattern)
            .await?;
        let (status, encoded): (i32, String) = redis::Script::new(RETIRE_WITH_INTENT)
            .key(&key)
            .key(&session_key)
            .key(self.store.session_index_key(&request.bearer))
            .key(self.store.retired_key(&request.bearer))
            .key(self.store.session_fp_index_key(&request.bearer))
            .key(self.store.did_index_key(&did))
            .key(self.store.pending_upgrade_key(&request.bearer))
            .key(self.grant_key(&hmac))
            .key(self.store.account_erasure_key(&did))
            .arg(snapshot)
            .arg(&did)
            .arg(pattern)
            .arg(head)
            .arg(self.store.key_prefix())
            .arg(ordinary)
            .arg(final_encoded)
            .arg(journal.receipt_id.to_string())
            .arg(self.store.retired_ttl())
            .arg(sealed_grant)
            .arg(seconds)
            .arg(&hmac)
            .arg(verified)
            .invoke_async(&mut conn)
            .await
            .map_err(|_| CleanupError::StorageUnavailable)?;
        match status {
            0 => {
                let journal = self.open("logout_cleanup", &key, &encoded)?;
                Ok(CleanupAttempt {
                    journal,
                    grant: Some(grant),
                })
            }
            1 => self.load_attempt(request, &encoded, now).await,
            3 => Err(CleanupError::InventoryIncomplete),
            _ => Err(CleanupError::SessionChanged),
        }
    }

    async fn checkpoint(&self, journal: &mut CleanupJournal) -> Result<(), CleanupError> {
        let key = self.journal_key(&journal.target.session_hmac);
        let mut conn = self.store.redis_connection();
        let old: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|_| CleanupError::StorageUnavailable)?;
        let old = old.ok_or(CleanupError::ReceiptConflict)?;
        let stored: CleanupJournal = self.open("logout_cleanup", &key, &old)?;
        if stored.receipt_id != journal.receipt_id || stored.revision != journal.revision {
            return Err(CleanupError::ReceiptConflict);
        }
        let mut next = journal.clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(CleanupError::ReceiptConflict)?;
        let encoded = self.seal("logout_cleanup", &key, &journal.target.did, &next)?;
        let changed: i32 = redis::Script::new(
            "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end redis.call('SET', KEYS[1], ARGV[2], 'XX'); if ARGV[3] ~= '0' then redis.call('EXPIRE', KEYS[1], ARGV[3]) end; return 1",
        ).key(&key).arg(old).arg(encoded)
            .arg(if next.device_cleanup == WorkStatus::Complete && matches!(next.account_cleanup.status,WorkStatus::Complete|WorkStatus::NotRequired) && next.upstream_revocation != UpstreamStatus::Pending && next.fence_released && !next.retained_credential { 7 * 24 * 3600 } else { 0 })
            .invoke_async(&mut conn).await
            .map_err(|_| CleanupError::StorageUnavailable)?;
        if changed != 1 {
            return Err(CleanupError::ReceiptConflict);
        }
        *journal = next;
        Ok(())
    }
    async fn delete_retained_grant(&self, target: &CleanupTarget) -> Result<(), CleanupError> {
        let mut conn = self.store.redis_connection();
        redis::cmd("DEL")
            .arg(self.grant_key(&target.session_hmac))
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|_| CleanupError::StorageUnavailable)
    }
    async fn release_fence(&self, journal: &CleanupJournal) -> Result<(), CleanupError> {
        let mut conn = self.store.redis_connection();
        let _: i32 = redis::Script::new(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('DEL', KEYS[1], KEYS[2]); return 1 end return 0",
        ).key(self.store.account_erasure_key(&journal.target.did))
            .key(format!("{}account_erasure_manifest:{}",self.store.key_prefix(),journal.receipt_id))
            .arg(journal.receipt_id.to_string())
            .invoke_async(&mut conn).await.map_err(|_| CleanupError::StorageUnavailable)?;
        Ok(())
    }
}
fn redis_glob_escape(value: &str) -> String {
    let mut result = String::new();
    for character in value.chars() {
        if matches!(character, '*' | '?' | '[' | ']' | '\\') {
            result.push('\\');
        }
        result.push(character);
    }
    result
}

/// Production effects remain policy-explicit. SQL and Redis adapters use the
/// same durable nonce installed by local retirement; no DID-only public entry.
/// Includes metadata discovery and the revocation HTTP exchange. A timed-out
/// request has an unknown provider outcome; it must never be called revoked.
pub const PROVIDER_REVOKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

pub async fn with_revocation_deadline<F>(attempt: F, deadline: std::time::Duration) -> RevokeOutcome
where
    F: std::future::Future<Output = RevokeOutcome>,
{
    match tokio::time::timeout(deadline, attempt).await {
        Ok(outcome) => outcome,
        Err(_) => RevokeOutcome::Failed(
            "provider revocation deadline exceeded; outcome unconfirmed".into(),
        ),
    }
}

struct NestCleanupEffects<'a> {
    state: &'a crate::config::AppState,
    retention: CredentialRetention,
}

#[derive(Serialize, Deserialize)]
struct DiscoveryManifest {
    version: u8,
    receipt_id: Uuid,
    did: String,
    retention: CredentialRetention,
    // Fixed-family indices are validated against the schema/version on load.
    records: Vec<(usize, String)>,
    sessions: Vec<(String, String)>,
    preserved_preaccount_operational: usize,
    preserved_safety_metadata: usize,
}
impl DiscoveryManifest {
    fn capture(
        discovery: &crate::services::account_cleanup_inventory::RedisDiscovery,
        target: &CleanupTarget,
        receipt_id: Uuid,
        retention: CredentialRetention,
    ) -> Result<Self, WorkFailure> {
        use crate::services::account_cleanup_inventory::REDIS_FAMILIES;
        if discovery.unresolved_records != 0
            || REDIS_FAMILIES
                .iter()
                .any(|f| !discovery.completely_inspected.contains(f))
        {
            return Err(WorkFailure::Blocked);
        }
        let mut records = Vec::new();
        for record in &discovery.records {
            if record.owner_did != target.did {
                return Err(WorkFailure::Blocked);
            }
            let index = REDIS_FAMILIES
                .iter()
                .position(|f| *f == record.family)
                .ok_or(WorkFailure::Blocked)?;
            records.push((index, record.key.clone()));
        }
        let mut sessions = Vec::new();
        for session in &discovery.sessions {
            if session.owner_did != target.did {
                return Err(WorkFailure::Blocked);
            }
            sessions.push((
                session.hmac_fingerprint.clone(),
                session.sha256_fingerprint.clone(),
            ));
        }
        Ok(Self {
            version: 1,
            receipt_id,
            did: target.did.clone(),
            retention,
            records,
            sessions,
            preserved_preaccount_operational: discovery.preserved_preaccount_operational,
            preserved_safety_metadata: discovery.preserved_safety_metadata,
        })
    }
    fn restore(
        self,
        target: &CleanupTarget,
        receipt_id: Uuid,
        retention: CredentialRetention,
    ) -> Result<crate::services::account_cleanup_inventory::RedisDiscovery, WorkFailure> {
        use crate::services::account_cleanup_inventory::{
            RedisDiscovery, VerifiedRedisRecord, VerifiedSessionIdentity, REDIS_FAMILIES,
        };
        if self.version != 1
            || self.receipt_id != receipt_id
            || self.did != target.did
            || self.retention != retention
        {
            return Err(WorkFailure::Blocked);
        }
        let mut records = Vec::new();
        for (index, key) in self.records {
            let family = *REDIS_FAMILIES.get(index).ok_or(WorkFailure::Blocked)?;
            records.push(VerifiedRedisRecord {
                owner_did: target.did.clone(),
                family,
                key,
            });
        }
        Ok(RedisDiscovery {
            records,
            sessions: self
                .sessions
                .into_iter()
                .map(|(hmac, sha)| VerifiedSessionIdentity {
                    owner_did: target.did.clone(),
                    hmac_fingerprint: hmac,
                    sha256_fingerprint: sha,
                })
                .collect(),
            completely_inspected: REDIS_FAMILIES.iter().copied().collect(),
            unresolved_records: 0,
            preserved_preaccount_operational: self.preserved_preaccount_operational,
            preserved_safety_metadata: self.preserved_safety_metadata,
        })
    }
}

#[async_trait]
impl CleanupEffects for NestCleanupEffects<'_> {
    async fn stop_devices(&self, target: &CleanupTarget) -> Result<(), WorkFailure> {
        let registry = self.state.push_registry().ok_or(WorkFailure::Blocked)?;
        registry
            .cleanup_retired_session(&target.did, &target.session_fingerprint)
            .await
            .map(|_| ())
            .map_err(|_| WorkFailure::Retryable)
    }
    async fn erase_account(
        &self,
        target: &CleanupTarget,
        receipt_id: Uuid,
    ) -> Result<(), WorkFailure> {
        use crate::services::account_cleanup_inventory::{
            AccountCleanupPlan, AccountEraseScope, CleanupAuthorization, LockedSqlInventory,
            Quiescence, RetryCredentialPolicy,
        };
        let store = self
            .state
            .auth_store
            .as_deref()
            .ok_or(WorkFailure::Blocked)?;
        let pool = self.state.push_db.as_ref().ok_or(WorkFailure::Blocked)?;
        let locked =
            LockedSqlInventory::begin(pool, store, &target.did, &receipt_id.to_string(), "public")
                .await
                .map_err(|_| WorkFailure::Retryable)?;
        let backend = RedisCleanupStore { store };
        let manifest_key = format!(
            "{}account_erasure_manifest:{}",
            store.key_prefix(),
            receipt_id
        );
        let mut conn = store.redis_connection();
        let existing: Option<String> = redis::cmd("GET")
            .arg(&manifest_key)
            .query_async(&mut conn)
            .await
            .map_err(|_| WorkFailure::Retryable)?;
        let discovery = if let Some(encoded) = existing {
            let manifest: DiscoveryManifest = backend
                .open("account_erasure_manifest", &manifest_key, &encoded)
                .map_err(|_| WorkFailure::Blocked)?;
            manifest.restore(target, receipt_id, self.retention)?
        } else {
            let discovery = crate::services::account_cleanup_discovery::discover_account_redis(
                store,
                &locked.captured,
                target,
                receipt_id,
                self.retention,
            )
            .await
            .map_err(|_| WorkFailure::Blocked)?;
            let manifest =
                DiscoveryManifest::capture(&discovery, target, receipt_id, self.retention)?;
            let encoded = backend
                .seal(
                    "account_erasure_manifest",
                    &manifest_key,
                    &target.did,
                    &manifest,
                )
                .map_err(|_| WorkFailure::Retryable)?;
            let _: () = redis::cmd("SET")
                .arg(&manifest_key)
                .arg(encoded)
                .query_async(&mut conn)
                .await
                .map_err(|_| WorkFailure::Retryable)?;
            discovery
        };
        let retry = match self.retention {
            CredentialRetention::Forbidden => RetryCredentialPolicy::Delete,
            CredentialRetention::ApprovedSealedRetry { .. } => {
                RetryCredentialPolicy::RetainUntilExistingExpiryForUpstreamRevocation
            }
        };
        let plan = AccountCleanupPlan::prepare(
            &target.did,
            "public",
            store.key_prefix(),
            CleanupAuthorization {
                account_scope: Some(
                    AccountEraseScope::ExplicitAccountEraseAfterLastActiveSessionLogout,
                ),
                quiescence: Some(Quiescence::AllAccountWritersAndInflightWorkDrained),
                retry_credentials: Some(retry),
            },
            &locked.catalog,
            locked.captured.clone(),
            discovery,
        )
        .map_err(|_| WorkFailure::Blocked)?;
        // Preserve SQL owner joins until every exact Redis deletion is acknowledged.
        // The sealed manifest preserves opaque lineage across partial Redis deletion.
        for operation in plan.redis_operations() {
            let applied:i32 = redis::Script::new("if redis.call('GET',KEYS[1]) ~= ARGV[1] then return 0 end redis.call('DEL',KEYS[2]); return 1")
                .key(store.account_erasure_key(&target.did)).key(&operation.key).arg(receipt_id.to_string())
                .invoke_async(&mut conn).await.map_err(|_| WorkFailure::Retryable)?;
            if applied != 1 {
                return Err(WorkFailure::Blocked);
            }
        }
        let verify_script=redis::Script::new("if redis.call('GET',KEYS[1]) ~= ARGV[1] then return 0 end for i=2,#KEYS do if redis.call('EXISTS',KEYS[i]) == 1 then return 0 end end return 1");
        let mut verification = verify_script.prepare_invoke();
        verification
            .key(store.account_erasure_key(&target.did))
            .arg(receipt_id.to_string());
        for operation in plan.redis_operations() {
            verification.key(&operation.key);
        }
        let absent: i32 = verification
            .invoke_async(&mut conn)
            .await
            .map_err(|_| WorkFailure::Retryable)?;
        if absent != 1 {
            return Err(WorkFailure::Retryable);
        }
        locked
            .erase(store, &plan)
            .await
            .map_err(|_| WorkFailure::Retryable)?;
        for key in &plan.retained_retry_keys {
            let remains: bool = redis::cmd("EXISTS")
                .arg(key)
                .query_async(&mut conn)
                .await
                .map_err(|_| WorkFailure::Retryable)?;
            if remains {
                return Err(WorkFailure::Retryable);
            }
        }
        // Keep the manifest until terminal journal publication/fence release. It
        // contains only authenticated deletion identities, never provider tokens.
        Ok(())
    }
    async fn revoke(&self, grant: &mut ClientSessionData, receipt_id: Uuid) -> RevokeOutcome {
        let Some(store) = self.state.auth_store.as_deref() else {
            return RevokeOutcome::Failed("local store unavailable".into());
        };
        let mut conn = store.redis_connection();
        let fence: redis::RedisResult<Option<String>> = redis::cmd("GET")
            .arg(store.account_erasure_key(grant.account_did.as_str()))
            .query_async(&mut conn)
            .await;
        if fence.ok().flatten().as_deref() != Some(&receipt_id.to_string()) {
            return RevokeOutcome::Failed("exclusive final-session fence not confirmed".into());
        }
        let Some(client) = self.state.jacquard_client.as_deref() else {
            return RevokeOutcome::Failed("OAuth client unavailable".into());
        };
        // Evict the cached object after local retirement. It cannot refresh an
        // absent/tombstoned store entry, and no raw bearer is retained in receipt.
        if client
            .registry
            .del(&grant.account_did, grant.session_id.as_str())
            .await
            .is_err()
        {
            return RevokeOutcome::Failed("OAuth cache retirement not confirmed".into());
        }
        with_revocation_deadline(
            crate::services::revocation::revoke_upstream(client, grant),
            PROVIDER_REVOKE_DEADLINE,
        )
        .await
    }
}

impl RedisCleanupStore<'_> {
    async fn verified_session_snapshots(
        &self,
        did: &str,
        head: &str,
        pattern: &str,
    ) -> Result<String, CleanupError> {
        let mut conn = self.store.redis_connection();
        let mut cursor = 0u64;
        let mut snapshots = std::collections::BTreeMap::new();
        let mut bytes = 0usize;
        for _ in 0..100 {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await
                .map_err(|_| CleanupError::StorageUnavailable)?;
            for key in keys {
                let suffix = key
                    .strip_prefix(head)
                    .ok_or(CleanupError::InventoryIncomplete)?;
                if suffix.len() != 64
                    || !suffix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(CleanupError::InventoryIncomplete);
                }
                let value:Option<String>=redis::Script::new("if redis.call('EXISTS',KEYS[2]) == 1 then return nil end return redis.call('GET',KEYS[1])")
                    .key(&key).key(format!("{}upgrade_retired:{}",self.store.key_prefix(),suffix))
                    .invoke_async(&mut conn).await.map_err(|_|CleanupError::StorageUnavailable)?;
                let Some(value) = value else { continue };
                bytes = bytes
                    .checked_add(value.len())
                    .ok_or(CleanupError::InventoryIncomplete)?;
                if bytes > 32 * 1024 * 1024 || snapshots.len() >= 10_000 {
                    return Err(CleanupError::InventoryIncomplete);
                }
                let (json, metadata, _) =
                    open_v2_with_metadata(self.store.enc_key(), &value, "session", &key)
                        .map_err(|_| CleanupError::InventoryIncomplete)?;
                let grant: ClientSessionData =
                    serde_json::from_str(&json).map_err(|_| CleanupError::InventoryIncomplete)?;
                if grant.account_did.as_str() != did
                    || grant.token_set.sub.as_str() != did
                    || self.store.fingerprint(grant.session_id.as_str()) != suffix
                    || Uuid::parse_str(grant.session_id.as_str()).is_err()
                    || metadata.did.as_deref().is_some_and(|value| value != did)
                {
                    return Err(CleanupError::InventoryIncomplete);
                }
                snapshots.insert(key, value);
            }
            cursor = next;
            if cursor == 0 {
                return serde_json::to_string(&snapshots)
                    .map_err(|_| CleanupError::InventoryIncomplete);
            }
        }
        Err(CleanupError::InventoryIncomplete)
    }
    pub async fn response_for_request(
        &self,
        request: &LogoutRequest,
    ) -> Result<Option<CleanupResponse>, CleanupError> {
        let hmac = self.store.fingerprint(&request.bearer);
        let key = self.journal_key(&hmac);
        let mut conn = self.store.redis_connection();
        let encoded: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|_| CleanupError::StorageUnavailable)?;
        let Some(encoded) = encoded else {
            return Ok(None);
        };
        let journal: CleanupJournal = self.open("logout_cleanup", &key, &encoded)?;
        if journal.target.session_hmac != hmac
            || journal.target.session_fingerprint != session_fingerprint(&request.bearer)
            || journal.retention != request.retention
        {
            return Err(CleanupError::ReceiptConflict);
        }
        Ok(Some(journal.response()))
    }
    async fn internal_attempt(
        &self,
        key: &str,
        encoded: &str,
    ) -> Result<CleanupAttempt, CleanupError> {
        let journal: CleanupJournal = self.open("logout_cleanup", key, encoded)?;
        if self.journal_key(&journal.target.session_hmac) != key {
            return Err(CleanupError::ReceiptConflict);
        }
        // Runtime jobs resume local erasure only. Reject historical/experimental
        // retained-grant receipts before any credential lookup or provider call.
        require_runtime_retention(journal.retention)?;
        if journal.retained_credential || journal.credential_expires_at.is_some() {
            return Err(CleanupError::ReceiptConflict);
        }
        Ok(CleanupAttempt {
            journal,
            grant: None,
        })
    }
}

async fn claim_attempt(
    store: &RedisAuthStore,
    hmac: &str,
) -> Result<(String, String), CleanupError> {
    let key = format!("{}logout_cleanup_claim:{}", store.key_prefix(), hmac);
    let value = Uuid::new_v4().to_string();
    let mut conn = store.redis_connection();
    let claimed: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg(&value)
        .arg("NX")
        .arg("EX")
        .arg(300)
        .query_async(&mut conn)
        .await
        .map_err(|_| CleanupError::StorageUnavailable)?;
    if claimed.is_none() {
        return Err(CleanupError::ReceiptConflict);
    }
    Ok((key, value))
}
async fn release_claim(store: &RedisAuthStore, claim: (String, String)) {
    let mut conn = store.redis_connection();
    let _: redis::RedisResult<i32> = redis::Script::new(
        "if redis.call('GET',KEYS[1]) == ARGV[1] then redis.call('DEL',KEYS[1]); end; return 1",
    )
    .key(claim.0)
    .arg(claim.1)
    .invoke_async(&mut conn)
    .await;
}
pub async fn run_runtime_cleanup(
    state: &crate::config::AppState,
    request: &LogoutRequest,
) -> Result<CleanupResponse, CleanupError> {
    // Enforce the fixed policy before claiming, authenticating or retiring anything.
    require_runtime_retention(request.retention)?;
    let store = state
        .auth_store
        .as_deref()
        .ok_or(CleanupError::StorageUnavailable)?;
    let claim = claim_attempt(store, &store.fingerprint(&request.bearer)).await?;
    let backend = RedisCleanupStore { store };
    let result = async {
        let attempt = backend
            .begin_or_resume(request, chrono::Utc::now().timestamp())
            .await?;
        if let Some(client) = state.jacquard_client.as_deref() {
            let did = jacquard_common::types::did::Did::new(attempt.journal.target.did.as_str())
                .map_err(|_| CleanupError::ReceiptConflict)?;
            client
                .registry
                .del(&did, &request.bearer)
                .await
                .map_err(|_| CleanupError::StorageUnavailable)?;
        }
        continue_cleanup(
            &backend,
            &NestCleanupEffects {
                state,
                retention: runtime_credential_retention(),
            },
            attempt,
            chrono::Utc::now().timestamp(),
        )
        .await
    }
    .await;
    release_claim(store, claim).await;
    result
}

/// Resume authenticated sealed intents even after the client has erased its bearer.
/// No public caller can supply a DID/receipt to authorize these internal jobs.
static CLEANUP_SCAN_CURSOR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub async fn retry_cleanup_pass(state: &crate::config::AppState) -> Result<usize, CleanupError> {
    let store = state
        .auth_store
        .as_deref()
        .ok_or(CleanupError::StorageUnavailable)?;
    let policy = runtime_credential_retention();
    let backend = RedisCleanupStore { store };
    let mut conn = store.redis_connection();
    let mut cursor = CLEANUP_SCAN_CURSOR.load(std::sync::atomic::Ordering::Relaxed);
    let mut pages = 0usize;
    let started = std::time::Instant::now();
    let mut examined = 0usize;
    let mut attempted = 0;
    loop {
        let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(format!(
                "{}logout_cleanup:*",
                redis_glob_escape(store.key_prefix())
            ))
            .arg("COUNT")
            .arg(100)
            .query_async(&mut conn)
            .await
            .map_err(|_| CleanupError::StorageUnavailable)?;
        pages += 1;
        CLEANUP_SCAN_CURSOR.store(next, std::sync::atomic::Ordering::Relaxed);
        for key in keys {
            examined += 1;
            if examined > 500 || started.elapsed() > std::time::Duration::from_secs(30) {
                return Ok(attempted);
            }
            let encoded: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .map_err(|_| CleanupError::StorageUnavailable)?;
            let Some(encoded) = encoded else { continue };
            let attempt = match backend.internal_attempt(&key, &encoded).await {
                Ok(value) => value,
                Err(_) => continue,
            };
            let journal = &attempt.journal;
            if journal.retention != policy {
                continue;
            }
            let needs_work = matches!(
                journal.device_cleanup,
                WorkStatus::Pending | WorkStatus::Failed
            ) || matches!(
                journal.account_cleanup.status,
                WorkStatus::Pending | WorkStatus::Failed
            ) || journal.upstream_revocation == UpstreamStatus::Pending
                || journal.retained_credential
                || !journal.fence_released;
            if !needs_work {
                continue;
            }
            let claim = match claim_attempt(store, &journal.target.session_hmac).await {
                Ok(value) => value,
                Err(_) => continue,
            };
            // Reload after claim to avoid operating on a receipt advanced by HTTP.
            let refreshed: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .map_err(|_| CleanupError::StorageUnavailable)?;
            if let Some(refreshed) = refreshed {
                if let Ok(attempt) = backend.internal_attempt(&key, &refreshed).await {
                    attempted += 1;
                    let _ = continue_cleanup(
                        &backend,
                        &NestCleanupEffects {
                            state,
                            retention: policy,
                        },
                        attempt,
                        chrono::Utc::now().timestamp(),
                    )
                    .await;
                }
            }
            release_claim(store, claim).await;
        }
        cursor = next;
        if cursor == 0 || pages >= 128 {
            break;
        }
    }
    Ok(attempted)
}

pub fn spawn_cleanup_worker(state: std::sync::Arc<crate::config::AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let _ = retry_cleanup_pass(&state).await;
        }
    });
}
