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

use jacquard_oauth::request::{revoke, OAuthMetadata};
use jacquard_oauth::session::ClientSessionData;
use serde::{Deserialize, Serialize};

use crate::config::{AppState, JacquardOAuthClient};
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

/// Revokes the grant behind `session` at its authorization server.
///
/// Uses the refresh token when present: the atproto provider deletes the whole token
/// record either way, and a refresh token stays resolvable after the access token
/// expires. Unlike `OAuthSession::logout`, a failed revocation is reported, not ignored.
pub async fn revoke_upstream(
    client: &JacquardOAuthClient,
    session: &mut ClientSessionData,
) -> RevokeOutcome {
    let meta = match OAuthMetadata::new(
        client.client.as_ref(),
        &client.registry.client_data,
        session,
    )
    .await
    {
        Ok(meta) => meta,
        Err(e) => return RevokeOutcome::Failed(format!("authorization server metadata: {e}")),
    };
    if meta.server_metadata.revocation_endpoint.is_none() {
        return RevokeOutcome::NoRevocationEndpoint;
    }
    let token = session
        .token_set
        .refresh_token
        .as_ref()
        .map(|t| t.to_string())
        .unwrap_or_else(|| session.token_set.access_token.to_string());
    match revoke(
        client.client.as_ref(),
        &mut session.dpop_data,
        &token,
        &meta,
    )
    .await
    {
        Ok(()) => RevokeOutcome::Revoked,
        Err(e) => RevokeOutcome::Failed(format!("revocation request: {e}")),
    }
}

#[derive(Serialize, Deserialize)]
pub struct RevokeJob {
    pub session: ClientSessionData,
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
        session,
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
pub async fn run_retry_pass(state: &AppState, now: i64) -> Result<RetryPassStats, String> {
    let (Some(store), Some(client)) = (state.auth_store.as_ref(), state.jacquard_client.as_ref())
    else {
        return Ok(RetryPassStats::default());
    };
    let prefix = store.key_prefix().to_string();
    let mut conn = store.redis_connection();
    let pattern = format!("{prefix}revoke_job:*");
    let mut keys = Vec::new();
    let mut cursor: u64 = 0;
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(100)
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("scan revoke jobs: {e}"))?;
        keys.extend(batch);
        cursor = next;
        if cursor == 0 || keys.len() >= MAX_JOBS_PER_PASS {
            break;
        }
    }
    keys.truncate(MAX_JOBS_PER_PASS);

    let mut stats = RetryPassStats::default();
    for key in keys {
        stats.scanned += 1;
        let claim: Option<String> = redis::cmd("SET")
            .arg(revoke_claim_key(&prefix, &key))
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(CLAIM_TTL_SECONDS)
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("claim revoke job: {e}"))?;
        if claim.is_none() {
            continue;
        }
        let sealed: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("read revoke job: {e}"))?;
        let Some(sealed) = sealed else { continue };
        let mut job = match open_job(store.enc_key(), &key, &sealed) {
            Ok(job) => job,
            Err(e) => {
                tracing::warn!(error = %e, "Dropping unreadable revocation retry job");
                let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
                stats.unreadable += 1;
                continue;
            }
        };
        if job.next_attempt_at > now {
            continue;
        }
        let did = job.session.account_did.as_str().to_string();
        let outcome = revoke_upstream(client, &mut job.session).await;
        match decide_after_attempt(&outcome, job.attempts, now) {
            RetryDecision::Delete => {
                let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
                match &outcome {
                    RevokeOutcome::Failed(e) => {
                        stats.abandoned += 1;
                        tracing::warn!(%did, error = %e, attempts = MAX_REVOKE_ATTEMPTS, "Abandoning upstream grant revocation after final retry");
                    }
                    _ => {
                        stats.revoked += 1;
                        tracing::info!(%did, "Upstream grant revocation retry completed");
                    }
                }
            }
            RetryDecision::Reschedule {
                attempts,
                next_attempt_at,
            } => {
                job.attempts = attempts;
                job.next_attempt_at = next_attempt_at;
                let sealed = seal_job(store.enc_key(), &key, &job)?;
                // XX + KEEPTTL: never resurrect a deleted job or extend the retention bound.
                let _: Result<Option<String>, _> = redis::cmd("SET")
                    .arg(&key)
                    .arg(sealed)
                    .arg("XX")
                    .arg("KEEPTTL")
                    .query_async(&mut conn)
                    .await;
                stats.rescheduled += 1;
                if let RevokeOutcome::Failed(e) = &outcome {
                    tracing::warn!(%did, error = %e, attempts, "Upstream grant revocation retry failed; rescheduled");
                }
            }
        }
    }
    Ok(stats)
}

pub fn spawn_retry_worker(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(RETRY_PASS_INTERVAL_SECONDS));
        loop {
            interval.tick().await;
            match run_retry_pass(&state, chrono::Utc::now().timestamp()).await {
                Ok(stats) if stats.scanned > 0 => {
                    tracing::info!(?stats, "Revocation retry pass finished")
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Revocation retry pass failed"),
            }
        }
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    pub(crate) fn session(did_str: &str, sid: &str) -> ClientSessionData {
        use jacquard_oauth::session::DpopClientData;
        use jacquard_oauth::types::{OAuthTokenType, TokenSet};
        let did = jacquard_common::types::did::Did::new_owned(did_str.to_string()).unwrap();
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
            host_url: jacquard_common::deps::fluent_uri::Uri::parse("https://pds.example")
                .unwrap()
                .to_owned(),
            authserver_url: "https://auth.example".to_string().into(),
            authserver_token_endpoint: "".into(),
            authserver_revocation_endpoint: None,
            scopes: jacquard_oauth::scopes::Scopes::new(smol_str::SmolStr::new_static("atproto"))
                .unwrap(),
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
            session: session(did, sid),
            attempts: 1,
            next_attempt_at: 100,
        }
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
