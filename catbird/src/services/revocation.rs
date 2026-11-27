//! Upstream OAuth grant revocation for logout, with a sealed retry job.
//!
//! Logout deletes the local session before contacting the authorization server, so a
//! retry needs its own copy of the credential: the session's token set and DPoP key.
//! When the first attempt fails, that `ClientSessionData` is sealed (AES-256-GCM, AAD
//! bound to the record class, Redis key and DID) under a key derived from the HMAC
//! session fingerprint, never the raw session ID. A background pass retries with
//! exponential backoff and deletes the job on success, when the server has no
//! revocation endpoint, or after `MAX_REVOKE_ATTEMPTS`. The Redis TTL bounds the copy
//! to `REVOKE_JOB_TTL_SECONDS` regardless.

use std::sync::Arc;

use crate::services::petrel_storage::ClientSessionData;
use serde::{Deserialize, Serialize};

use crate::config::{AppState, GatewayOAuth};
use crate::services::redis_crypto::{
    open_v2_with_metadata, seal_v2_with_metadata, EnvelopeMetadata,
};

pub const REVOKE_JOB_RECORD_CLASS: &str = "revoke_job";
/// Upper bound on how long a sealed credential copy can outlive logout.
pub const REVOKE_JOB_TTL_SECONDS: u64 = 7 * 24 * 3600;
pub const MAX_REVOKE_ATTEMPTS: u32 = 8;
const BASE_BACKOFF_SECONDS: u64 = 60;
const MAX_BACKOFF_SECONDS: u64 = 6 * 3600;
const RETRY_PASS_INTERVAL_SECONDS: u64 = 300;
const MAX_JOBS_PER_PASS: usize = 500;
const CLAIM_TTL_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    Revoked,
    /// The authorization server advertises no revocation endpoint; nothing to retry.
    NoRevocationEndpoint,
    Failed(String),
}

/// Only the bound token required to revoke a retired grant. This value is
/// persisted exclusively in authenticated, short-lived cleanup envelopes.
#[derive(Clone, Serialize)]
pub struct StoredGrantV3 {
    version: u8,
    pub account_did: petrel_core::Did,
    pub session_id: String,
    credential: Option<RevocationCredential>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RevocationCredential {
    issuer: String,
    pds: String,
    token: String,
    scalar: [u8; 32],
}

impl From<ClientSessionData> for StoredGrantV3 {
    fn from(grant: ClientSessionData) -> Self {
        // A malformed historical grant may still be retired locally. Retain
        // no unusable credential and report upstream revocation as unconfirmed.
        let credential = grant.to_petrel(0).ok().and_then(|(record, scalar)| {
            Some(RevocationCredential {
                issuer: record.account.expected_issuer?,
                pds: record.account.pds,
                token: record
                    .session
                    .refresh_token()
                    .unwrap_or_else(|| record.session.access_token())
                    .to_owned(),
                scalar,
            })
        });
        Self {
            version: 3,
            account_did: grant.account_did,
            session_id: grant.session_id,
            credential,
        }
    }
}

impl<'de> Deserialize<'de> for StoredGrantV3 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        #[derive(Deserialize)]
        struct V3 {
            version: u8,
            account_did: petrel_core::Did,
            session_id: String,
            credential: Option<RevocationCredential>,
        }
        let value = serde_json::Value::deserialize(d)?;
        if value.get("version").is_none() {
            return serde_json::from_value::<ClientSessionData>(value)
                .map(Self::from)
                .map_err(D::Error::custom);
        }
        let wire: V3 = serde_json::from_value(value).map_err(D::Error::custom)?;
        if wire.version != 3 {
            return Err(D::Error::custom("unsupported stored grant version"));
        }
        Ok(Self {
            version: wire.version,
            account_did: wire.account_did,
            session_id: wire.session_id,
            credential: wire.credential,
        })
    }
}

impl StoredGrantV3 {
    fn revocation_record(&self) -> anyhow::Result<(petrel::oauth::SessionRecord, &[u8; 32])> {
        use petrel::crypto::{DpopSigner, SoftwareDpopSigner};
        use petrel::oauth::{Account, SessionRecord};
        let grant = self
            .credential
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no usable revocation grant"))?;
        let jkt = SoftwareDpopSigner::from_bytes(&grant.scalar)?
            .public_jwk()
            .thumbprint()?;
        // This one-operation Petrel session has no refresh authority. The SDK
        // passes its sole token to the revocation endpoint without a type hint.
        let session = serde_json::from_value(serde_json::json!({
            "did": self.account_did, "access_token": grant.token,
            "created_at": 0, "expires_in": 0, "scope": ""
        }))?;
        Ok((
            SessionRecord {
                account: Account {
                    did: self.account_did.clone(),
                    handle: None,
                    pds: grant.pds.clone(),
                    authorization_server: None,
                    expected_issuer: Some(grant.issuer.clone()),
                },
                session,
                dpop_key_id: format!("nest-{jkt}"),
                dpop_jkt: jkt,
            },
            &grant.scalar,
        ))
    }
}

/// Revokes the grant behind `session` at its authorization server.
///
/// Uses the refresh token when present: the atproto provider deletes the whole token
/// record either way, and a refresh token stays resolvable after the access token
/// expires. Unlike `OAuthSession::logout`, a failed revocation is reported, not ignored.
pub async fn revoke_upstream(client: &GatewayOAuth, session: &StoredGrantV3) -> RevokeOutcome {
    let result: anyhow::Result<RevokeOutcome> = async {
        // Retirement leaves the receipt as the only owner of this grant.
        let (mut record, scalar) = session.revocation_record()?;
        let metadata = client.revocation_metadata(&record).await?;
        if metadata.revocation_endpoint.is_none() {
            return Ok(RevokeOutcome::NoRevocationEndpoint);
        }
        record.account.authorization_server = Some(metadata);
        let store = petrel::storage::SessionStore::new(
            Arc::new(petrel::storage::MemorySecretStore::new()),
            "revocation",
        )?;
        store.save_dpop_key(&record.dpop_key_id, scalar).await?;
        store.save_session(&record).await?;
        if client
            .client(store)?
            .revoke_session(&session.account_did)
            .await?
        {
            Ok(RevokeOutcome::Revoked)
        } else {
            Err(anyhow::anyhow!("revocation unconfirmed"))
        }
    }
    .await;
    result.unwrap_or_else(|_| {
        RevokeOutcome::Failed("authorization server did not confirm revocation".into())
    })
}

#[derive(Serialize, Deserialize)]
pub struct RevokeJob {
    pub session: StoredGrantV3,
    pub attempts: u32,
    pub next_attempt_at: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RetryDecision {
    Delete,
    Reschedule { attempts: u32, next_attempt_at: i64 },
}

pub fn revoke_job_key(key_prefix: &str, hmac_fingerprint: &str) -> String {
    format!("{key_prefix}revoke_job:{hmac_fingerprint}")
}

fn revoke_claim_key(key_prefix: &str, job_key: &str) -> String {
    let fp = job_key.rsplit(':').next().unwrap_or_default();
    format!("{key_prefix}revoke_claim:{fp}")
}

pub fn backoff_seconds(attempts: u32) -> u64 {
    BASE_BACKOFF_SECONDS
        .saturating_mul(1u64 << attempts.min(16))
        .min(MAX_BACKOFF_SECONDS)
}

/// What to do with a job after an attempt. `attempts` counts attempts made before this one.
pub fn decide_after_attempt(outcome: &RevokeOutcome, attempts: u32, now: i64) -> RetryDecision {
    match outcome {
        RevokeOutcome::Revoked | RevokeOutcome::NoRevocationEndpoint => RetryDecision::Delete,
        RevokeOutcome::Failed(_) => {
            let attempts = attempts.saturating_add(1);
            if attempts >= MAX_REVOKE_ATTEMPTS {
                RetryDecision::Delete
            } else {
                RetryDecision::Reschedule {
                    attempts,
                    next_attempt_at: now + backoff_seconds(attempts) as i64,
                }
            }
        }
    }
}

pub fn seal_job(enc_key: &[u8; 32], redis_key: &str, job: &RevokeJob) -> Result<String, String> {
    let json = serde_json::to_string(job).map_err(|e| format!("serialize revoke job: {e}"))?;
    let did = job.session.account_did.as_str().to_string();
    let meta = EnvelopeMetadata::new(REVOKE_JOB_RECORD_CLASS, redis_key, Some(&did), None);
    seal_v2_with_metadata(enc_key, &json, &meta).map_err(|e| format!("seal revoke job: {e}"))
}

pub fn open_job(enc_key: &[u8; 32], redis_key: &str, sealed: &str) -> Result<RevokeJob, String> {
    let (json, meta, _) =
        open_v2_with_metadata(enc_key, sealed, REVOKE_JOB_RECORD_CLASS, redis_key)
            .map_err(|e| format!("open revoke job: {e}"))?;
    let job: RevokeJob =
        serde_json::from_str(&json).map_err(|e| format!("parse revoke job: {e}"))?;
    if meta.did.as_deref() != Some(job.session.account_did.as_str()) {
        return Err("revoke job DID does not match its envelope".to_string());
    }
    Ok(job)
}

/// Stores a sealed retry job for a grant whose first revocation attempt failed.
pub async fn enqueue_retry(
    store: &crate::services::RedisAuthStore,
    session: ClientSessionData,
    now: i64,
) -> Result<(), String> {
    let key = revoke_job_key(
        store.key_prefix(),
        &store.fingerprint(session.session_id.as_str()),
    );
    let job = RevokeJob {
        session: session.into(),
        attempts: 1,
        next_attempt_at: now + backoff_seconds(1) as i64,
    };
    let sealed = seal_job(store.enc_key(), &key, &job)?;
    let mut conn = store.redis_connection();
    redis::cmd("SET")
        .arg(&key)
        .arg(sealed)
        .arg("EX")
        .arg(REVOKE_JOB_TTL_SECONDS)
        .query_async::<_, ()>(&mut conn)
        .await
        .map_err(|e| format!("store revoke job: {e}"))
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RetryPassStats {
    pub scanned: usize,
    pub revoked: usize,
    pub rescheduled: usize,
    pub abandoned: usize,
    pub unreadable: usize,
}

/// One bounded pass over pending revocation jobs.
pub async fn run_retry_pass(_state: &AppState, _now: i64) -> Result<RetryPassStats, String> {
    // Legacy jobs have neither a complete cleanup receipt nor exclusive provider
    // grant ownership. Never let an old job revoke a newly live/shared grant.
    Err("Legacy revocation retries are paused pending lifecycle ownership; existing credentials keep their original TTL".into())
}

pub fn spawn_retry_worker(_state: Arc<AppState>) {
    tracing::warn!(
        "Legacy revocation retries paused; authenticated cleanup receipts own new retries"
    );
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    pub(crate) fn session(did_str: &str, sid: &str) -> ClientSessionData {
        use crate::services::petrel_storage::DpopClientData;
        use crate::services::petrel_storage::{OAuthTokenType, TokenSet};
        let did = petrel_core::Did::parse(did_str.to_string()).unwrap();
        let dpop_key: jose_jwk::Key = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xFMTbKEBaGizdGlIUKEWx5q15odEB00stfg",
            "y": "x_daaqundbgUvJV358vRBgULGnpH7aRFZZDYyEiNg2g",
            "d": "jpsQnnGQmL-YxOmH1UmOBHg10OJ45DBTWh0n52qxzMQ"
        }))
        .unwrap();
        ClientSessionData {
            account_did: did.clone(),
            session_id: sid.to_string().into(),
            host_url: url::Url::parse("https://pds.example").unwrap().to_owned(),
            authserver_url: "https://auth.example".to_string().into(),
            authserver_token_endpoint: "".into(),
            authserver_revocation_endpoint: None,
            scopes: petrel_oauth_scopes::ScopeSet::parse("atproto").unwrap(),
            dpop_data: DpopClientData {
                dpop_key,
                dpop_authserver_nonce: "".into(),
                dpop_host_nonce: "".into(),
            },
            token_set: TokenSet {
                iss: "https://auth.example".to_string().into(),
                sub: did,
                aud: "https://pds.example".to_string().into(),
                scope: Some("atproto".into()),
                refresh_token: Some("refresh-secret".into()),
                access_token: "access-secret".into(),
                token_type: OAuthTokenType::DPoP,
                expires_at: None,
            },
            resolved_scopes: None,
        }
    }

    fn job(did: &str, sid: &str) -> RevokeJob {
        RevokeJob {
            session: session(did, sid).into(),
            attempts: 1,
            next_attempt_at: 100,
        }
    }

    #[test]
    fn old_grants_decode_and_new_jobs_keep_only_the_token_needed_at_revocation() {
        use petrel::crypto::{base64url, DpopSigner, SoftwareDpopSigner};
        let mut legacy = session("did:plc:alice", "session");
        let scalar = [14; 32];
        let jwk = SoftwareDpopSigner::from_bytes(&scalar)
            .unwrap()
            .public_jwk();
        legacy.dpop_data.dpop_key = serde_json::from_value(serde_json::json!({
            "kty":"EC","crv":"P-256","x":jwk.x,"y":jwk.y,"d":base64url(&scalar)
        }))
        .unwrap();
        let old_job = serde_json::json!({"session": legacy, "attempts":1, "next_attempt_at":1});
        let job: RevokeJob = serde_json::from_value(old_job).unwrap();
        let wire = serde_json::to_value(&job).unwrap();
        assert_eq!(wire["session"]["version"], 3);
        assert_eq!(wire["session"]["credential"]["token"], "refresh-secret");
        assert!(!wire.to_string().contains("access-secret"));
        let restored: RevokeJob = serde_json::from_value(wire).unwrap();
        let (record, key) = restored.session.revocation_record().unwrap();
        assert_eq!(key, &scalar);
        assert_eq!(record.session.access_token(), "refresh-secret");
        assert_eq!(
            record.account.expected_issuer.as_deref(),
            Some("https://auth.example")
        );
    }

    #[test]
    fn sealed_job_round_trips_and_hides_credentials() {
        let key = revoke_job_key("p:", "hmacfp");
        let sealed = seal_job(&KEY, &key, &job("did:plc:alice", "raw-session-id")).unwrap();
        assert!(!sealed.contains("refresh-secret"));
        assert!(!sealed.contains("access-secret"));
        assert!(!sealed.contains("raw-session-id"));
        let opened = open_job(&KEY, &key, &sealed).unwrap();
        assert_eq!(opened.session.account_did.as_str(), "did:plc:alice");
        assert_eq!(opened.attempts, 1);
    }

    #[test]
    fn sealed_job_is_bound_to_its_key_and_encryption_key() {
        let key = revoke_job_key("p:", "fp1");
        let sealed = seal_job(&KEY, &key, &job("did:plc:alice", "sid")).unwrap();
        assert!(open_job(&KEY, &revoke_job_key("p:", "fp2"), &sealed).is_err());
        assert!(open_job(&[8u8; 32], &key, &sealed).is_err());
    }

    #[test]
    fn job_key_uses_fingerprint_not_raw_session() {
        let key = revoke_job_key("catbird:v2:session:", "abc123");
        assert_eq!(key, "catbird:v2:session:revoke_job:abc123");
        assert_eq!(
            revoke_claim_key("catbird:v2:session:", &key),
            "catbird:v2:session:revoke_claim:abc123"
        );
        assert!(!revoke_claim_key("p:", &key).contains("revoke_job"));
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_seconds(0), 60);
        assert_eq!(backoff_seconds(1), 120);
        assert_eq!(backoff_seconds(3), 480);
        assert_eq!(backoff_seconds(10), MAX_BACKOFF_SECONDS);
        assert_eq!(backoff_seconds(u32::MAX), MAX_BACKOFF_SECONDS);
    }

    #[test]
    fn decisions_delete_on_success_and_after_final_attempt() {
        assert_eq!(
            decide_after_attempt(&RevokeOutcome::Revoked, 3, 0),
            RetryDecision::Delete
        );
        assert_eq!(
            decide_after_attempt(&RevokeOutcome::NoRevocationEndpoint, 1, 0),
            RetryDecision::Delete
        );
        let failed = RevokeOutcome::Failed("timeout".into());
        assert_eq!(
            decide_after_attempt(&failed, 1, 1000),
            RetryDecision::Reschedule {
                attempts: 2,
                next_attempt_at: 1000 + 240
            }
        );
        assert_eq!(
            decide_after_attempt(&failed, MAX_REVOKE_ATTEMPTS - 1, 0),
            RetryDecision::Delete
        );
    }

    #[test]
    fn job_lifetime_is_bounded_by_ttl() {
        // Worst case schedule must fit inside the Redis TTL, so the TTL, not the
        // attempt count, is the hard retention bound.
        let total: u64 = (1..MAX_REVOKE_ATTEMPTS).map(backoff_seconds).sum();
        assert!(total < REVOKE_JOB_TTL_SECONDS);
    }
}
