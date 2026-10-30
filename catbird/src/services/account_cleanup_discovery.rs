//! Read-only, bounded ownership discovery for last-session account erasure.
//!
//! Run under the account erasure fence and the caller's account SQL lock, after
//! draining writers. No refresh, token use, TTL extension, or deletion occurs.
//! Do not log these values: encrypted records, keys and fingerprints are private.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use serde_json::Value;
use uuid::Uuid;

use super::account_cleanup_inventory::{
    CapturedSqlIdentities, RedisDiscovery, RedisFamily, VerifiedRedisRecord,
    VerifiedSessionIdentity, REDIS_FAMILIES,
};
use super::logout_cleanup::{CleanupJournal, CleanupTarget, CredentialRetention};
use super::push::registry::session_fingerprint;
use super::redis_crypto::{open_v2_with_metadata, EnvelopeMetadata};
use super::RedisAuthStore;

const MAX_DURATION: Duration = Duration::from_secs(30);
const MAX_SCAN_PAGES: usize = 128;
const MAX_RECORDS: usize = 10_000;
const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_SET_MEMBERS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DiscoveryError {
    #[error("account cleanup discovery has invalid or inconsistent identity evidence")]
    InvalidEvidence,
    #[error("account cleanup discovery could not verify the active erasure fence")]
    FenceMismatch,
    #[error("account cleanup discovery exceeded its bounded scan")]
    Incomplete,
    #[error("account cleanup discovery storage is unavailable")]
    StorageUnavailable,
}

// TYPE/length/TTL/value are captured together. Oversized strings and sets are
// rejected before the value is returned to the client. No Redis keys are changed.
const READ_BOUNDED: &str = r#"
local kind = redis.call('TYPE', KEYS[1]).ok
local ttl = redis.call('TTL', KEYS[1])
if kind == 'none' then return {kind, ttl, {}} end
if kind == 'string' then
  if redis.call('STRLEN', KEYS[1]) > tonumber(ARGV[1]) then return {'oversize', ttl, {}} end
  return {kind, ttl, {redis.call('GET', KEYS[1])}}
end
if kind == 'set' then
  if redis.call('SCARD', KEYS[1]) > tonumber(ARGV[2]) then return {'oversize', ttl, {}} end
  local values = redis.call('SMEMBERS', KEYS[1])
  local size = 0
  for _, value in ipairs(values) do size = size + string.len(value) end
  if size > tonumber(ARGV[1]) then return {'oversize', ttl, {}} end
  return {kind, ttl, values}
end
return {'unexpected', ttl, {}}
"#;

struct Record {
    key: String,
    kind: String,
    ttl: i64,
    values: Vec<String>,
}
impl Record {
    fn text(&self) -> Result<&str, DiscoveryError> {
        if self.kind != "string" || self.values.len() != 1 {
            return Err(DiscoveryError::InvalidEvidence);
        }
        Ok(&self.values[0])
    }
}

struct Reader {
    connection: redis::aio::ConnectionManager,
    started: Instant,
    bytes: usize,
    records: usize,
}
impl Reader {
    fn remaining(&self) -> Result<Duration, DiscoveryError> {
        MAX_DURATION
            .checked_sub(self.started.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or(DiscoveryError::Incomplete)
    }
    async fn read(&mut self, key: &str) -> Result<Option<Record>, DiscoveryError> {
        let result: (String, i64, Vec<String>) = tokio::time::timeout(
            self.remaining()?,
            redis::Script::new(READ_BOUNDED)
                .key(key)
                .arg(MAX_RECORD_BYTES)
                .arg(MAX_SET_MEMBERS)
                .invoke_async(&mut self.connection),
        )
        .await
        .map_err(|_| DiscoveryError::Incomplete)?
        .map_err(|_| DiscoveryError::StorageUnavailable)?;
        if result.0 == "none" {
            return Ok(None);
        }
        if result.0 == "oversize" {
            return Err(DiscoveryError::Incomplete);
        }
        if result.0 == "unexpected" {
            return Err(DiscoveryError::InvalidEvidence);
        }
        self.records += 1;
        self.bytes = self
            .bytes
            .saturating_add(key.len())
            .saturating_add(result.2.iter().map(String::len).sum::<usize>());
        if self.records > MAX_RECORDS || self.bytes > MAX_TOTAL_BYTES {
            return Err(DiscoveryError::Incomplete);
        }
        Ok(Some(Record {
            key: key.to_owned(),
            kind: result.0,
            ttl: result.1,
            values: result.2,
        }))
    }
    async fn scan(&mut self, pattern: &str) -> Result<Vec<Record>, DiscoveryError> {
        let mut cursor = 0_u64;
        let mut seen_keys = BTreeSet::new();
        let mut seen_cursors = BTreeSet::new();
        let mut result = Vec::new();
        for _ in 0..MAX_SCAN_PAGES {
            let (next, keys): (u64, Vec<String>) = tokio::time::timeout(
                self.remaining()?,
                redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(pattern)
                    .arg("COUNT")
                    .arg(128)
                    .query_async(&mut self.connection),
            )
            .await
            .map_err(|_| DiscoveryError::Incomplete)?
            .map_err(|_| DiscoveryError::StorageUnavailable)?;
            for key in keys {
                if !seen_keys.insert(key.clone()) {
                    continue;
                }
                if seen_keys.len() > MAX_RECORDS {
                    return Err(DiscoveryError::Incomplete);
                }
                if let Some(record) = self.read(&key).await? {
                    result.push(record);
                }
            }
            if next == 0 {
                return Ok(result);
            }
            if !seen_cursors.insert(next) {
                return Err(DiscoveryError::Incomplete);
            }
            cursor = next;
        }
        Err(DiscoveryError::Incomplete)
    }
}

#[derive(Default)]
struct Evidence {
    hmac: BTreeMap<String, String>,
    sha: BTreeMap<String, String>,
    pairs: BTreeMap<(String, String), String>,
    flows: BTreeMap<String, String>,
    preaccount_flows: BTreeSet<String>,
    target_index_hmac: BTreeSet<String>,
    target_index_sha: BTreeSet<String>,
}
impl Evidence {
    fn identity(&mut self, did: &str, hmac: &str, sha: &str) -> Result<(), DiscoveryError> {
        if !valid_did(did) || !hex(hmac) || !hex(sha) {
            return Err(DiscoveryError::InvalidEvidence);
        }
        insert_consistent(&mut self.hmac, hmac, did)?;
        insert_consistent(&mut self.sha, sha, did)?;
        if self
            .pairs
            .iter()
            .any(|((h, s), _)| (h == hmac && s != sha) || (s == sha && h != hmac))
        {
            return Err(DiscoveryError::InvalidEvidence);
        }
        self.pairs
            .insert((hmac.to_owned(), sha.to_owned()), did.to_owned());
        Ok(())
    }
    fn raw_identity(
        &mut self,
        store: &RedisAuthStore,
        did: &str,
        raw: &str,
    ) -> Result<String, DiscoveryError> {
        if raw.is_empty() || raw.len() > 4096 {
            return Err(DiscoveryError::InvalidEvidence);
        }
        let hmac = store.fingerprint(raw);
        self.identity(did, &hmac, &session_fingerprint(raw))?;
        Ok(hmac)
    }
}
fn insert_consistent(
    map: &mut BTreeMap<String, String>,
    key: &str,
    owner: &str,
) -> Result<(), DiscoveryError> {
    if map
        .insert(key.to_owned(), owner.to_owned())
        .is_some_and(|old| old != owner)
    {
        return Err(DiscoveryError::InvalidEvidence);
    }
    Ok(())
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_did(value: &str) -> bool {
    value.starts_with("did:")
        && value.len() >= 8
        && value.len() <= 2048
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":%_.-".contains(&b))
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, DiscoveryError> {
    value[key]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or(DiscoveryError::InvalidEvidence)
}
fn decode(
    store: &RedisAuthStore,
    record: &Record,
    class: &str,
) -> Result<(Value, EnvelopeMetadata), DiscoveryError> {
    decode_with_key(store.enc_key(), record, class)
}

fn decode_with_key(
    key: &[u8; 32],
    record: &Record,
    class: &str,
) -> Result<(Value, EnvelopeMetadata), DiscoveryError> {
    let (text, metadata, legacy) = open_v2_with_metadata(key, record.text()?, class, &record.key)
        .map_err(|_| DiscoveryError::InvalidEvidence)?;
    if legacy && class != "session" {
        return Err(DiscoveryError::InvalidEvidence);
    }
    let value: Value = serde_json::from_str(&text).map_err(|_| DiscoveryError::InvalidEvidence)?;
    if !value.is_object() {
        return Err(DiscoveryError::InvalidEvidence);
    }
    Ok((value, metadata))
}
fn metadata_owner(
    metadata: &EnvelopeMetadata,
    did: &str,
    lineage: Option<&str>,
) -> Result<(), DiscoveryError> {
    if metadata.did.as_deref() != Some(did) || metadata.lineage.as_deref() != lineage {
        return Err(DiscoveryError::InvalidEvidence);
    }
    Ok(())
}
fn suffix<'a>(prefix: &str, family: RedisFamily, key: &'a str) -> Result<&'a str, DiscoveryError> {
    let stem = if family == RedisFamily::Exchange {
        family.stem().to_owned()
    } else {
        format!("{prefix}{}", family.stem())
    };
    key.strip_prefix(&stem)
        .filter(|s| !s.is_empty())
        .ok_or(DiscoveryError::InvalidEvidence)
}
fn owned(
    discovery: &mut RedisDiscovery,
    target: &str,
    owner: &str,
    family: RedisFamily,
    key: &str,
) {
    if owner == target {
        discovery.records.push(VerifiedRedisRecord {
            owner_did: target.to_owned(),
            family,
            key: key.to_owned(),
        });
    }
}
fn unresolved(discovery: &mut RedisDiscovery) {
    discovery.unresolved_records += 1;
}

/// Complete scans are mandatory; an error means the caller must not erase.
/// `target` must come from an authenticated logout journal, never a client body.
/// Short-lived pre-account flow records are explicitly reported as preserved.
/// Journals, the erasure fence and global generation counter remain safety data.
pub async fn discover_account_redis(
    store: &RedisAuthStore,
    captured: &CapturedSqlIdentities,
    target: &CleanupTarget,
    receipt_id: Uuid,
    retention: CredentialRetention,
) -> Result<RedisDiscovery, DiscoveryError> {
    let prefix = store.key_prefix();
    if !captured.capture_complete
        || captured.did != target.did
        || !valid_did(&target.did)
        || !prefix.contains(":v2:")
        || prefix
            .bytes()
            .any(|b| b.is_ascii_control() || b"*?[]\\".contains(&b))
    {
        return Err(DiscoveryError::InvalidEvidence);
    }
    retention
        .validate()
        .map_err(|_| DiscoveryError::InvalidEvidence)?;
    let mut reader = Reader {
        connection: store.redis_connection(),
        started: Instant::now(),
        bytes: 0,
        records: 0,
    };
    let fence = reader
        .read(&store.account_erasure_key(&target.did))
        .await?
        .ok_or(DiscoveryError::FenceMismatch)?;
    if fence.text()? != receipt_id.to_string() || fence.ttl != -1 {
        return Err(DiscoveryError::FenceMismatch);
    }
    let mut discovery = RedisDiscovery {
        records: Vec::new(),
        sessions: Vec::new(),
        completely_inspected: BTreeSet::new(),
        unresolved_records: 0,
        preserved_preaccount_operational: 0,
        preserved_safety_metadata: 1,
    };
    let mut evidence = Evidence::default();
    evidence.identity(
        &target.did,
        &target.session_hmac,
        &target.session_fingerprint,
    )?;
    // Journals retain authenticated historical session lineage after retirement.
    let journals = reader.scan(&format!("{prefix}logout_cleanup:*")).await?;
    let mut journal_values = BTreeMap::new();
    for record in journals {
        let (value, metadata) = decode(store, &record, "logout_cleanup")?;
        let journal: CleanupJournal =
            serde_json::from_value(value).map_err(|_| DiscoveryError::InvalidEvidence)?;
        metadata_owner(&metadata, &journal.target.did, None)?;
        if record.key != format!("{prefix}logout_cleanup:{}", journal.target.session_hmac)
            || (record.ttl != -1 && !(1..=90 * 24 * 3600).contains(&record.ttl))
        {
            return Err(DiscoveryError::InvalidEvidence);
        }
        evidence.identity(
            &journal.target.did,
            &journal.target.session_hmac,
            &journal.target.session_fingerprint,
        )?;
        if journal.target.did == target.did {
            discovery.preserved_safety_metadata += 1;
        }
        journal_values.insert(journal.target.session_hmac.clone(), journal);
    }
    let current_journal = journal_values
        .get(&target.session_hmac)
        .ok_or(DiscoveryError::InvalidEvidence)?;
    if current_journal.receipt_id != receipt_id
        || current_journal.target.did != target.did
        || current_journal.retention != retention
    {
        return Err(DiscoveryError::InvalidEvidence);
    }
    let manifest_key = format!("{prefix}account_erasure_manifest:{receipt_id}");
    if let Some(manifest) = reader.read(&manifest_key).await? {
        let (_, metadata) = decode(store, &manifest, "account_erasure_manifest")?;
        metadata_owner(&metadata, &target.did, None)?;
        discovery.preserved_safety_metadata += 1;
    }
    if let Some(counter) = reader
        .read(&format!("{prefix}auth_generation_sequence"))
        .await?
    {
        if counter.text()?.parse::<u64>().is_err() {
            return Err(DiscoveryError::InvalidEvidence);
        }
        discovery.preserved_safety_metadata += 1;
    }
    let mut families = BTreeMap::new();
    for &family in REDIS_FAMILIES {
        let stem = if family == RedisFamily::Exchange {
            family.stem().to_owned()
        } else {
            format!("{prefix}{}", family.stem())
        };
        let records = reader.scan(&format!("{stem}*")).await?;
        // Only a completed cursor=0 scan can insert this family.
        discovery.completely_inspected.insert(family);
        families.insert(family, records);
    }
    // First establish authenticated session/grant and upgrade lineage globally;
    // plain pointer records are interpreted only after this evidence exists.
    for &family in &[
        RedisFamily::Session,
        RedisFamily::RevokeJob,
        RedisFamily::LogoutGrant,
    ] {
        for record in &families[&family] {
            let result = (|| {
                let class = match family {
                    RedisFamily::Session => "session",
                    RedisFamily::RevokeJob => "revoke_job",
                    _ => "logout_cleanup_grant",
                };
                let (value, meta) = decode(store, record, class)?;
                let session = if family == RedisFamily::RevokeJob {
                    &value["session"]
                } else {
                    &value
                };
                let did = field(session, "account_did")?;
                let raw = field(session, "session_id")?;
                let hmac = store.fingerprint(raw);
                let expected = if family == RedisFamily::Session {
                    format!("{prefix}session:{did}_{hmac}")
                } else {
                    format!("{prefix}{}{hmac}", family.stem())
                };
                if record.key != expected {
                    return Err(DiscoveryError::InvalidEvidence);
                }
                if family == RedisFamily::Session {
                    if meta.did.as_deref().is_some_and(|owner| owner != did)
                        || meta.lineage.is_some()
                    {
                        return Err(DiscoveryError::InvalidEvidence);
                    }
                } else {
                    metadata_owner(&meta, did, None)?;
                }
                if family == RedisFamily::RevokeJob
                    && did == target.did
                    && matches!(retention, CredentialRetention::ApprovedSealedRetry { .. })
                    && !(1..=7 * 24 * 3600).contains(&record.ttl)
                {
                    return Err(DiscoveryError::InvalidEvidence);
                }
                if family == RedisFamily::LogoutGrant
                    && did == target.did
                    && matches!(retention, CredentialRetention::ApprovedSealedRetry { .. })
                {
                    let journal = journal_values
                        .get(&hmac)
                        .ok_or(DiscoveryError::InvalidEvidence)?;
                    let expiry = journal
                        .credential_expires_at
                        .ok_or(DiscoveryError::InvalidEvidence)?;
                    let now = chrono::Utc::now().timestamp();
                    if !journal.retained_credential
                        || !matches!(
                            journal.retention,
                            CredentialRetention::ApprovedSealedRetry { .. }
                        )
                        || record.ttl <= 0
                        || record.ttl > (expiry - now).max(0) + 1
                        || expiry - journal.created_at > 7 * 24 * 3600
                    {
                        return Err(DiscoveryError::InvalidEvidence);
                    }
                }
                evidence.raw_identity(store, did, raw)?;
                owned(&mut discovery, &target.did, did, family, &record.key);
                Ok(())
            })();
            if result.is_err() {
                unresolved(&mut discovery);
            }
        }
    }
    for &family in &[
        RedisFamily::UpgradeFlow,
        RedisFamily::UpgradeCandidate,
        RedisFamily::UpgradeExchange,
        RedisFamily::UpgradeReceipt,
    ] {
        for record in &families[&family] {
            let result = (|| {
                let class = family.stem().trim_end_matches(':');
                let (value, meta) = decode(store, record, class)?;
                let did = field(
                    &value,
                    if family == RedisFamily::UpgradeFlow {
                        "old_did"
                    } else {
                        "did"
                    },
                )?;
                let old = field(&value, "old_session_id")?;
                let old_hmac = store.fingerprint(old);
                metadata_owner(&meta, did, Some(&old_hmac))?;
                let key_suffix = suffix(prefix, family, &record.key)?;
                match family {
                    RedisFamily::UpgradeFlow => {
                        let state = field(&value, "state")?;
                        let fp = store.fingerprint(state);
                        if key_suffix != fp {
                            return Err(DiscoveryError::InvalidEvidence);
                        }
                        insert_consistent(&mut evidence.flows, &fp, did)?;
                    }
                    RedisFamily::UpgradeCandidate | RedisFamily::UpgradeReceipt => {
                        let candidate = field(&value, "candidate_session_id")?;
                        if key_suffix != store.fingerprint(candidate) {
                            return Err(DiscoveryError::InvalidEvidence);
                        }
                        evidence.raw_identity(store, did, candidate)?;
                        if family == RedisFamily::UpgradeCandidate {
                            let session: Value =
                                serde_json::from_str(field(&value, "session_data_json")?)
                                    .map_err(|_| DiscoveryError::InvalidEvidence)?;
                            if field(&session, "account_did")? != did
                                || field(&session, "session_id")? != candidate
                            {
                                return Err(DiscoveryError::InvalidEvidence);
                            }
                            // Candidate storage already holds the state HMAC.
                            let flow_fingerprint = field(&value, "flow_state")?;
                            if !hex(flow_fingerprint) {
                                return Err(DiscoveryError::InvalidEvidence);
                            }
                            insert_consistent(&mut evidence.flows, flow_fingerprint, did)?;
                        }
                    }
                    RedisFamily::UpgradeExchange => {
                        let parts: Vec<_> = key_suffix.split(':').collect();
                        if parts.len() != 3
                            || parts[0] != old_hmac
                            || !parts.iter().all(|part| hex(part))
                        {
                            return Err(DiscoveryError::InvalidEvidence);
                        }
                        evidence.raw_identity(
                            store,
                            did,
                            field(&value, "candidate_session_id")?,
                        )?;
                    }
                    _ => return Err(DiscoveryError::InvalidEvidence),
                }
                evidence.raw_identity(store, did, old)?;
                owned(&mut discovery, &target.did, did, family, &record.key);
                Ok(())
            })();
            if result.is_err() {
                unresolved(&mut discovery);
            }
        }
    }
    // Exact DID values are authoritative routing metadata, not a substring
    // match. They can identify target-owned orphan pointers after session expiry.
    // They never authorize using a grant or creating a live session identity.
    for record in &families[&RedisFamily::SessionIndex] {
        if record.text().ok() == Some(target.did.as_str()) {
            match suffix(prefix, RedisFamily::SessionIndex, &record.key) {
                Ok(fp) if hex(fp) && evidence.hmac.get(fp).is_none_or(|did| did == &target.did) => {
                    evidence.target_index_hmac.insert(fp.to_owned());
                }
                _ => unresolved(&mut discovery),
            }
        }
    }
    for record in &families[&RedisFamily::SessionFingerprintIndex] {
        if record
            .text()
            .ok()
            .is_some_and(|fp| evidence.target_index_hmac.contains(fp))
        {
            match suffix(prefix, RedisFamily::SessionFingerprintIndex, &record.key) {
                Ok(fp) if hex(fp) && evidence.sha.get(fp).is_none_or(|did| did == &target.did) => {
                    evidence.target_index_sha.insert(fp.to_owned());
                }
                _ => unresolved(&mut discovery),
            }
        }
    }
    // Auth request plaintext is authenticated, but a resolved DID is only the
    // requested login identity until a grant/upgrade gives it verified lineage.
    for record in &families[&RedisFamily::AuthRequest] {
        let result = (|| {
            let (value, meta) = decode(store, record, "auth_req_info")?;
            if meta.did.is_some() || meta.lineage.is_some() {
                return Err(DiscoveryError::InvalidEvidence);
            }
            let state = field(&value, "state")?;
            if record.key != store.auth_req_key(state) {
                return Err(DiscoveryError::InvalidEvidence);
            }
            let fp = store.fingerprint(state);
            let owner = evidence.flows.get(&fp).or_else(|| evidence.hmac.get(&fp));
            if let Some(owner) = owner {
                owned(
                    &mut discovery,
                    &target.did,
                    owner,
                    RedisFamily::AuthRequest,
                    &record.key,
                );
            } else {
                verify_preaccount(
                    &value,
                    record.ttl,
                    &[
                        "state",
                        "authserver_url",
                        "account_did",
                        "scopes",
                        "request_uri",
                        "authserver_token_endpoint",
                        "authserver_revocation_endpoint",
                        "pkce_verifier",
                        "dpop_key",
                        "dpop_authserver_nonce",
                    ],
                )?;
                discovery.preserved_preaccount_operational += 1;
                evidence.preaccount_flows.insert(fp);
            }
            Ok(())
        })();
        if result.is_err() {
            unresolved(&mut discovery);
        }
    }
    for record in &families[&RedisFamily::OAuthFlow] {
        let result = (|| {
            let (value, meta) = decode(store, record, "oauth_flow")?;
            if meta.did.is_some() || meta.lineage.is_some() {
                return Err(DiscoveryError::InvalidEvidence);
            }
            let fp = suffix(prefix, RedisFamily::OAuthFlow, &record.key)?;
            if !hex(fp) {
                return Err(DiscoveryError::InvalidEvidence);
            }
            if let Some(owner) = evidence.hmac.get(fp).or_else(|| evidence.flows.get(fp)) {
                owned(
                    &mut discovery,
                    &target.did,
                    owner,
                    RedisFamily::OAuthFlow,
                    &record.key,
                );
            } else {
                verify_preaccount(
                    &value,
                    record.ttl,
                    &[
                        "version",
                        "mode",
                        "client_selector",
                        "redirect_to",
                        "browser_nonce",
                        "created_at",
                    ],
                )?;
                if value["version"].as_u64() != Some(2) || !value["client_selector"].is_string() {
                    return Err(DiscoveryError::InvalidEvidence);
                }
                evidence.preaccount_flows.insert(fp.to_owned());
                discovery.preserved_preaccount_operational += 1;
            }
            Ok(())
        })();
        if result.is_err() {
            unresolved(&mut discovery);
        }
    }
    for (&family, records) in &families {
        if matches!(
            family,
            RedisFamily::Session
                | RedisFamily::RevokeJob
                | RedisFamily::LogoutGrant
                | RedisFamily::UpgradeFlow
                | RedisFamily::UpgradeCandidate
                | RedisFamily::UpgradeExchange
                | RedisFamily::UpgradeReceipt
                | RedisFamily::AuthRequest
                | RedisFamily::OAuthFlow
        ) {
            continue;
        }
        for record in records {
            if process_pointer(
                store,
                &target.did,
                family,
                record,
                &evidence,
                &mut discovery,
            )
            .is_err()
            {
                unresolved(&mut discovery);
            }
        }
    }
    // SQL receipt history is not proof of the current device link. An absent
    // link is safe to include idempotently; a link reassigned elsewhere blocks.
    for device in captured
        .device_ids
        .union(&captured.historical_delivery_device_ids)
    {
        if Uuid::parse_str(device).is_err() {
            return Err(DiscoveryError::InvalidEvidence);
        }
        let key = format!("{prefix}push_device_session:{device}");
        match reader.read(&key).await? {
            None => owned(
                &mut discovery,
                &target.did,
                &target.did,
                RedisFamily::DeviceSession,
                &key,
            ),
            Some(record)
                if evidence
                    .sha
                    .get(record.text()?)
                    .is_some_and(|did| did == &target.did)
                    || evidence.target_index_sha.contains(record.text()?) =>
            {
                owned(
                    &mut discovery,
                    &target.did,
                    &target.did,
                    RedisFamily::DeviceSession,
                    &key,
                );
            }
            Some(_) => unresolved(&mut discovery),
        }
    }
    for ((hmac, sha), did) in evidence.pairs {
        if did == target.did {
            discovery.sessions.push(VerifiedSessionIdentity {
                owner_did: did,
                hmac_fingerprint: hmac,
                sha256_fingerprint: sha,
            });
        }
    }
    Ok(discovery)
}

fn verify_preaccount(value: &Value, ttl: i64, allowed: &[&str]) -> Result<(), DiscoveryError> {
    if !(1..=600).contains(&ttl)
        || !value
            .as_object()
            .is_some_and(|map| map.keys().all(|key| allowed.contains(&key.as_str())))
    {
        return Err(DiscoveryError::InvalidEvidence);
    }
    Ok(())
}

fn preserve_bounded_orphan(
    record: &Record,
    max_ttl: i64,
    discovery: &mut RedisDiscovery,
) -> Result<(), DiscoveryError> {
    if !(1..=max_ttl).contains(&record.ttl) {
        return Err(DiscoveryError::InvalidEvidence);
    }
    // Explicitly retained noncredential routing metadata. Never count these as
    // deleted target data, and never extend the observed expiry.
    discovery.preserved_safety_metadata += 1;
    Ok(())
}

fn process_pointer(
    store: &RedisAuthStore,
    target: &str,
    family: RedisFamily,
    record: &Record,
    evidence: &Evidence,
    discovery: &mut RedisDiscovery,
) -> Result<(), DiscoveryError> {
    let key_suffix = suffix(store.key_prefix(), family, &record.key)?;
    let owner: Option<String> = match family {
        RedisFamily::SessionIndex => {
            let did = record.text()?;
            if !hex(key_suffix) || !valid_did(did) {
                return Err(DiscoveryError::InvalidEvidence);
            }
            if let Some(owner) = evidence.hmac.get(key_suffix) {
                if owner != did {
                    return Err(DiscoveryError::InvalidEvidence);
                }
                Some(owner.clone())
            } else if did == target {
                Some(target.to_owned())
            } else {
                preserve_bounded_orphan(record, 30 * 24 * 3600, discovery)?;
                None
            }
        }
        RedisFamily::SessionFingerprintIndex => {
            let hmac = record.text()?;
            if !hex(key_suffix) || !hex(hmac) {
                return Err(DiscoveryError::InvalidEvidence);
            }
            if evidence.target_index_sha.contains(key_suffix) {
                Some(target.to_owned())
            } else if let Some(owner) = evidence.sha.get(key_suffix) {
                if evidence.hmac.get(hmac) != Some(owner)
                    || evidence
                        .pairs
                        .get(&(hmac.to_owned(), key_suffix.to_owned()))
                        != Some(owner)
                {
                    return Err(DiscoveryError::InvalidEvidence);
                }
                Some(owner.clone())
            } else {
                // A known target HMAC is still target ownership even if its old
                // SHA index has outlived the encrypted session body.
                if evidence.hmac.get(hmac).is_some_and(|did| did == target) {
                    Some(target.to_owned())
                } else {
                    preserve_bounded_orphan(record, 30 * 24 * 3600, discovery)?;
                    None
                }
            }
        }
        RedisFamily::DidIndex => {
            let hmac = record.text()?;
            if !valid_did(key_suffix) || !hex(hmac) {
                return Err(DiscoveryError::InvalidEvidence);
            }
            if let Some(owner) = evidence.hmac.get(hmac) {
                if key_suffix != owner {
                    return Err(DiscoveryError::InvalidEvidence);
                }
                Some(owner.clone())
            } else if key_suffix == target {
                Some(target.to_owned())
            } else {
                preserve_bounded_orphan(record, 30 * 24 * 3600, discovery)?;
                None
            }
        }
        RedisFamily::DeviceSession => {
            let sha = record.text()?;
            if Uuid::parse_str(key_suffix).is_err() || !hex(sha) {
                return Err(DiscoveryError::InvalidEvidence);
            }
            if evidence.target_index_sha.contains(sha) {
                Some(target.to_owned())
            } else if let Some(owner) = evidence.sha.get(sha) {
                Some(owner.clone())
            } else {
                preserve_bounded_orphan(record, 30 * 24 * 3600, discovery)?;
                None
            }
        }
        RedisFamily::SessionDevices => {
            if !hex(key_suffix)
                || record.kind != "set"
                || record.values.iter().any(|v| Uuid::parse_str(v).is_err())
            {
                return Err(DiscoveryError::InvalidEvidence);
            }
            if evidence.target_index_sha.contains(key_suffix) {
                Some(target.to_owned())
            } else if let Some(owner) = evidence.sha.get(key_suffix) {
                Some(owner.clone())
            } else {
                preserve_bounded_orphan(record, 30 * 24 * 3600, discovery)?;
                None
            }
        }
        RedisFamily::UpgradePending => {
            let flow = record.text()?;
            if !hex(key_suffix) || !hex(flow) {
                return Err(DiscoveryError::InvalidEvidence);
            }
            let owner = evidence
                .hmac
                .get(key_suffix)
                .map(String::as_str)
                .or_else(|| {
                    evidence
                        .target_index_hmac
                        .contains(key_suffix)
                        .then_some(target)
                });
            if let Some(owner) = owner {
                if evidence.flows.get(flow).is_some_and(|did| did != owner) {
                    return Err(DiscoveryError::InvalidEvidence);
                }
                Some(owner.to_owned())
            } else {
                preserve_bounded_orphan(record, 600, discovery)?;
                None
            }
        }
        RedisFamily::OAuthClaim => {
            if !hex(key_suffix) || record.text()? != "1" || !(1..=30).contains(&record.ttl) {
                return Err(DiscoveryError::InvalidEvidence);
            }
            if let Some(owner) = evidence
                .flows
                .get(key_suffix)
                .or_else(|| evidence.hmac.get(key_suffix))
            {
                Some(owner.clone())
            } else if evidence.target_index_hmac.contains(key_suffix) {
                Some(target.to_owned())
            } else {
                discovery.preserved_preaccount_operational += 1;
                None
            }
        }
        RedisFamily::Exchange => {
            if !hex(key_suffix) {
                return Err(DiscoveryError::InvalidEvidence);
            }
            let aad = super::redis_crypto::build_aad("oauth_exchange", &record.key, None, None);
            let raw =
                super::redis_crypto::open_strict_with_aad(store.enc_key(), record.text()?, &aad)
                    .map_err(|_| DiscoveryError::InvalidEvidence)?;
            let hmac = store.fingerprint(&raw);
            if evidence.target_index_hmac.contains(&hmac) {
                Some(target.to_owned())
            } else {
                Some(
                    evidence
                        .hmac
                        .get(&hmac)
                        .ok_or(DiscoveryError::InvalidEvidence)?
                        .clone(),
                )
            }
        }
        RedisFamily::RevokeClaim => {
            if !hex(key_suffix) || record.text()? != "1" || !(1..=300).contains(&record.ttl) {
                return Err(DiscoveryError::InvalidEvidence);
            }
            if let Some(owner) = evidence.hmac.get(key_suffix) {
                Some(owner.clone())
            } else if evidence.target_index_hmac.contains(key_suffix) {
                Some(target.to_owned())
            } else {
                discovery.preserved_safety_metadata += 1;
                None
            }
        }
        RedisFamily::Retired => {
            if !hex(key_suffix) || record.ttl <= 0 || record.ttl > 90 * 24 * 3600 {
                return Err(DiscoveryError::InvalidEvidence);
            }
            if let Some(owner) = evidence.hmac.get(key_suffix) {
                Some(owner.clone())
            } else if evidence.target_index_hmac.contains(key_suffix) {
                Some(target.to_owned())
            } else {
                discovery.preserved_safety_metadata += 1;
                None
            }
        }
        _ => return Err(DiscoveryError::InvalidEvidence),
    };
    if let Some(owner) = owner {
        owned(discovery, target, &owner, family, &record.key);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fingerprints_require_consistent_authenticated_lineage() {
        let mut evidence = Evidence::default();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        evidence.identity("did:plc:testaccount", &a, &b).unwrap();
        assert!(evidence.identity("did:plc:foreignaccount", &a, &b).is_err());
        let mut other = Evidence::default();
        other.identity("did:plc:testaccount", &a, &b).unwrap();
        assert!(other.identity("did:plc:testaccount", &a, &c).is_err());
        assert!(Evidence::default()
            .identity("did:plc:testaccount", "not-a-hash", &b)
            .is_err());
    }

    #[test]
    fn short_preaccount_state_does_not_hide_grants_or_indefinite_retention() {
        let allowed = ["state", "account_did", "pkce_verifier"];
        let value = json!({"state": "synthetic", "account_did": "did:plc:requested", "pkce_verifier": "synthetic"});
        assert!(verify_preaccount(&value, 600, &allowed).is_ok());
        for ttl in [-1, 0, 601] {
            assert!(verify_preaccount(&value, ttl, &allowed).is_err());
        }
        assert!(verify_preaccount(
            &json!({"state": "synthetic", "refresh_token": "synthetic"}),
            60,
            &allowed
        )
        .is_err());
        assert!(verify_preaccount(&json!([]), 60, &allowed).is_err());
    }

    #[test]
    fn metadata_did_and_lineage_must_both_match() {
        let metadata = EnvelopeMetadata::new(
            "upgrade_flow",
            "synthetic",
            Some("did:plc:owner"),
            Some("lineage"),
        );
        assert!(metadata_owner(&metadata, "did:plc:owner", Some("lineage")).is_ok());
        assert!(metadata_owner(&metadata, "did:plc:other", Some("lineage")).is_err());
        assert!(metadata_owner(&metadata, "did:plc:owner", None).is_err());
    }

    #[test]
    fn encrypted_payload_is_bound_to_class_key_and_authenticated_owner() {
        let key = [0x5a; 32];
        let meta = EnvelopeMetadata::new(
            "upgrade_flow",
            "synthetic-key",
            Some("did:plc:owner"),
            Some("lineage"),
        );
        let body = json!({"old_did": "did:plc:owner", "old_session_id": "synthetic"});
        let sealed =
            super::super::redis_crypto::seal_v2_with_metadata(&key, &body.to_string(), &meta)
                .unwrap();
        let mut record = Record {
            key: "synthetic-key".into(),
            kind: "string".into(),
            ttl: 60,
            values: vec![sealed],
        };
        let (decoded, metadata) = decode_with_key(&key, &record, "upgrade_flow").unwrap();
        assert_eq!(decoded, body);
        assert!(metadata_owner(&metadata, "did:plc:owner", Some("lineage")).is_ok());
        assert!(decode_with_key(&key, &record, "upgrade_candidate").is_err());
        record.key = "transplanted-key".into();
        assert!(decode_with_key(&key, &record, "upgrade_flow").is_err());
        record.key = "synthetic-key".into();
        assert!(decode_with_key(&[0x6b; 32], &record, "upgrade_flow").is_err());
    }

    #[test]
    fn unknown_record_types_and_identity_fields_are_not_empty_success() {
        let record = Record {
            key: "synthetic".into(),
            kind: "set".into(),
            ttl: 60,
            values: vec!["did:plc:owner".into()],
        };
        assert!(record.text().is_err());
        assert!(field(&json!({"session_id": null}), "session_id").is_err());
        assert!(field(&json!({"session_id": ""}), "session_id").is_err());
        assert!(!valid_did("did:plc:owner*"));
        assert!(!valid_did("prefix-did:plc:owner"));
    }

    #[test]
    fn ordinary_exchange_is_unprefixed_and_never_substring_attributed() {
        assert_eq!(
            suffix(
                "catbird:v2:session:",
                RedisFamily::Exchange,
                "exchange:opaque"
            )
            .unwrap(),
            "opaque"
        );
        assert!(suffix(
            "catbird:v2:session:",
            RedisFamily::Exchange,
            "catbird:v2:session:exchange:opaque"
        )
        .is_err());
        assert!(suffix(
            "catbird:v2:session:",
            RedisFamily::Session,
            "unrelated:session:did:plc:owner"
        )
        .is_err());
    }
}
