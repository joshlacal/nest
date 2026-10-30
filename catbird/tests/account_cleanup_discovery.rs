//! Disposable Redis only. Run ignored tests with LITE_PUSH_DISPOSABLE=1 and the
//! explicit TASK7_ACCOUNT_CLEANUP_FIXTURE_REDIS_URL; never default to app Redis.
#[path = "support/cleanup_auth.rs"]
mod cleanup_auth;

use catbird::services::{
    account_cleanup_discovery::{discover_account_redis, DiscoveryError},
    account_cleanup_inventory::{
        CapturedSqlIdentities, RedisDiscovery, RedisFamily, REDIS_FAMILIES,
    },
    logout_cleanup::{
        AccountCleanupStatus, CleanupJournal, CleanupTarget, CredentialRetention, UpstreamStatus,
        WorkStatus,
    },
    push::registry::session_fingerprint,
    redis_crypto::{build_aad, seal_strict_with_aad, seal_v2_with_metadata, EnvelopeMetadata},
    RedisAuthStore,
};
use serde_json::json;
use std::collections::BTreeSet;
use uuid::Uuid;

const DID: &str = "did:plc:synthetictarget";
const OTHER: &str = "did:plc:syntheticother";

struct Fixture {
    store: RedisAuthStore,
    captured: CapturedSqlIdentities,
    target: CleanupTarget,
    journal: CleanupJournal,
    bearer: String,
    keys: Vec<String>,
}
impl Fixture {
    async fn new(retention: CredentialRetention) -> Self {
        let url =
            cleanup_auth::disposable_url("TASK7_ACCOUNT_CLEANUP_FIXTURE_REDIS_URL", "redis", 6379);
        let connection = redis::aio::ConnectionManager::new(redis::Client::open(url).unwrap())
            .await
            .unwrap();
        let prefix = format!("task7:v2:discovery_{}:", Uuid::new_v4().simple());
        let store = RedisAuthStore::from_key(connection, prefix, 3600, cleanup_auth::KEY).unwrap();
        let bearer = Uuid::new_v4().to_string();
        let device = Uuid::new_v4();
        let target = CleanupTarget {
            did: DID.into(),
            session_hmac: store.fingerprint(&bearer),
            session_fingerprint: session_fingerprint(&bearer),
            device_ids: vec![device],
        };
        let now = chrono::Utc::now().timestamp();
        let expiry = match retention {
            CredentialRetention::Forbidden => None,
            CredentialRetention::ApprovedSealedRetry { seconds } => Some(now + i64::from(seconds)),
        };
        let journal = CleanupJournal {
            receipt_id: Uuid::new_v4(),
            target: target.clone(),
            retention,
            created_at: now,
            credential_expires_at: expiry,
            device_cleanup: WorkStatus::Pending,
            account_cleanup: AccountCleanupStatus {
                required: true,
                status: WorkStatus::Pending,
            },
            upstream_revocation: UpstreamStatus::Pending,
            revocation_attempts: 0,
            retained_credential: expiry.is_some(),
            fence_released: false,
            revision: 1,
        };
        let captured = CapturedSqlIdentities {
            did: DID.into(),
            device_ids: BTreeSet::from([device.to_string()]),
            receipt_keys: BTreeSet::new(),
            historical_delivery_device_ids: BTreeSet::new(),
            capture_complete: true,
        };
        let mut fixture = Self {
            store,
            captured,
            target,
            journal,
            bearer,
            keys: Vec::new(),
        };
        let journal_key = fixture.key("logout_cleanup", &fixture.target.session_hmac);
        let sealed = seal_v2_with_metadata(
            &cleanup_auth::KEY,
            &serde_json::to_string(&fixture.journal).unwrap(),
            &EnvelopeMetadata::new("logout_cleanup", &journal_key, Some(DID), None),
        )
        .unwrap();
        fixture.put(journal_key, sealed, None).await;
        fixture
            .put(
                fixture.store.account_erasure_key(DID),
                fixture.journal.receipt_id.to_string(),
                None,
            )
            .await;
        fixture
            .put(
                fixture
                    .key("auth_generation_sequence", "")
                    .trim_end_matches(':')
                    .to_owned(),
                "9".into(),
                None,
            )
            .await;
        fixture
    }
    fn key(&self, class: &str, suffix: &str) -> String {
        format!("{}{class}:{suffix}", self.store.key_prefix())
    }
    async fn put(&mut self, key: String, value: String, ttl: Option<u64>) {
        let mut command = redis::cmd("SET");
        command.arg(&key).arg(value);
        if let Some(ttl) = ttl {
            command.arg("EX").arg(ttl);
        }
        command
            .query_async::<_, ()>(&mut self.store.redis_connection())
            .await
            .unwrap();
        self.keys.push(key);
    }
    async fn sealed(
        &mut self,
        class: &str,
        suffix: &str,
        did: Option<&str>,
        lineage: Option<&str>,
        value: serde_json::Value,
        ttl: u64,
    ) {
        let key = self.key(class, suffix);
        let encoded = seal_v2_with_metadata(
            &cleanup_auth::KEY,
            &value.to_string(),
            &EnvelopeMetadata::new(class, &key, did, lineage),
        )
        .unwrap();
        self.put(key, encoded, Some(ttl)).await;
    }
    async fn discover(&self) -> Result<RedisDiscovery, DiscoveryError> {
        discover_account_redis(
            &self.store,
            &self.captured,
            &self.target,
            self.journal.receipt_id,
            self.journal.retention,
        )
        .await
    }
    async fn finish(self) {
        if !self.keys.is_empty() {
            redis::cmd("DEL")
                .arg(&self.keys)
                .query_async::<_, u64>(&mut self.store.redis_connection())
                .await
                .unwrap();
        }
    }
    async fn seed_all_families(&mut self) {
        let hmac = self.target.session_hmac.clone();
        let sha = self.target.session_fingerprint.clone();
        let grant =
            serde_json::to_value(cleanup_auth::grant(DID, &self.bearer, "http://127.0.0.1:9"))
                .unwrap();
        self.sealed(
            "session",
            &format!("{DID}_{hmac}"),
            Some(DID),
            None,
            grant.clone(),
            600,
        )
        .await;
        self.put(self.key("session_index", &hmac), DID.into(), Some(600))
            .await;
        self.put(self.key("session_fp_index", &sha), hmac.clone(), Some(600))
            .await;
        self.put(self.key("did_index", DID), hmac.clone(), Some(600))
            .await;
        let device = self.target.device_ids[0].to_string();
        self.put(
            self.key("push_device_session", &device),
            sha.clone(),
            Some(600),
        )
        .await;
        let set_key = self.key("push_session_devices", &sha);
        redis::pipe()
            .cmd("SADD")
            .arg(&set_key)
            .arg(&device)
            .ignore()
            .cmd("EXPIRE")
            .arg(&set_key)
            .arg(600)
            .ignore()
            .query_async::<_, ()>(&mut self.store.redis_connection())
            .await
            .unwrap();
        self.keys.push(set_key);
        // AuthRequest uses record class auth_req_info but the auth_req key stem.
        let auth_key = self.store.auth_req_key(&self.bearer);
        let encoded = seal_v2_with_metadata(
            &cleanup_auth::KEY,
            &json!({"state": self.bearer}).to_string(),
            &EnvelopeMetadata::new("auth_req_info", &auth_key, None, None),
        )
        .unwrap();
        self.put(auth_key, encoded, Some(600)).await;
        self.sealed(
            "oauth_flow",
            &hmac,
            None,
            None,
            json!({"version": 2, "client_selector": "synthetic", "created_at": 0}),
            600,
        )
        .await;
        self.put(self.key("oauth_claim", &hmac), "1".into(), Some(30))
            .await;
        let flow = Uuid::new_v4().to_string();
        let flow_fp = self.store.fingerprint(&flow);
        let candidate = Uuid::new_v4().to_string();
        let candidate_fp = self.store.fingerprint(&candidate);
        self.sealed(
            "upgrade_flow",
            &flow_fp,
            Some(DID),
            Some(&hmac),
            json!({"state": flow, "old_session_id": self.bearer, "old_did": DID}),
            600,
        )
        .await;
        self.put(
            self.key("upgrade_pending", &hmac),
            flow_fp.clone(),
            Some(600),
        )
        .await;
        let candidate_grant =
            serde_json::to_string(&cleanup_auth::grant(DID, &candidate, "http://127.0.0.1:9"))
                .unwrap();
        self.sealed("upgrade_candidate", &candidate_fp, Some(DID), Some(&hmac), json!({"candidate_session_id": candidate, "old_session_id": self.bearer, "did": DID, "flow_state": flow_fp, "session_data_json": candidate_grant}), 600).await;
        let exchange_suffix = format!("{hmac}:{}:{}", "a".repeat(64), "b".repeat(64));
        self.sealed(
            "upgrade_exchange",
            &exchange_suffix,
            Some(DID),
            Some(&hmac),
            json!({"candidate_session_id": candidate, "old_session_id": self.bearer, "did": DID}),
            300,
        )
        .await;
        self.sealed(
            "upgrade_receipt",
            &candidate_fp,
            Some(DID),
            Some(&hmac),
            json!({"candidate_session_id": candidate, "old_session_id": self.bearer, "did": DID}),
            600,
        )
        .await;
        let exchange_key = format!(
            "exchange:{}",
            self.store.fingerprint(&Uuid::new_v4().to_string())
        );
        let exchange = seal_strict_with_aad(
            &cleanup_auth::KEY,
            &self.bearer,
            &build_aad("oauth_exchange", &exchange_key, None, None),
        )
        .unwrap();
        self.put(exchange_key, exchange, Some(300)).await;
        self.sealed(
            "revoke_job",
            &hmac,
            Some(DID),
            None,
            json!({"session": grant, "attempts": 0, "next_attempt_at": 0}),
            300,
        )
        .await;
        self.put(self.key("revoke_claim", &hmac), "1".into(), Some(300))
            .await;
        self.put(
            self.key("upgrade_retired", &hmac),
            "logout".into(),
            Some(600),
        )
        .await;
        self.sealed("logout_cleanup_grant", &hmac, Some(DID), None, grant, 300)
            .await;
    }
}

#[tokio::test]
#[ignore = "requires explicit disposable Redis fixture"]
async fn complete_discovery_covers_every_family_and_preserves_other_account_and_preaccount() {
    let mut fixture = Fixture::new(CredentialRetention::Forbidden).await;
    fixture.seed_all_families().await;
    let other_raw = Uuid::new_v4().to_string();
    let other_fp = fixture.store.fingerprint(&other_raw);
    let other_key = fixture.key("session", &format!("{OTHER}_{other_fp}"));
    fixture
        .sealed(
            "session",
            &format!("{OTHER}_{other_fp}"),
            Some(OTHER),
            None,
            serde_json::to_value(cleanup_auth::grant(OTHER, &other_raw, "http://127.0.0.1:9"))
                .unwrap(),
            600,
        )
        .await;
    let pre_fp = fixture.store.fingerprint(&Uuid::new_v4().to_string());
    fixture
        .sealed(
            "oauth_flow",
            &pre_fp,
            None,
            None,
            json!({"version": 2, "client_selector": "synthetic", "created_at": 0}),
            600,
        )
        .await;
    fixture
        .put(fixture.key("oauth_claim", &pre_fp), "1".into(), Some(30))
        .await;
    let discovery = fixture.discover().await.unwrap();
    assert_eq!(discovery.unresolved_records, 0);
    assert_eq!(
        discovery.completely_inspected,
        REDIS_FAMILIES.iter().copied().collect()
    );
    let found: BTreeSet<_> = discovery
        .records
        .iter()
        .map(|record| record.family)
        .collect();
    assert_eq!(
        found,
        REDIS_FAMILIES.iter().copied().collect(),
        "every family must have a verified target record"
    );
    assert!(discovery
        .records
        .iter()
        .all(|record| record.owner_did == DID && record.key != other_key));
    assert_eq!(discovery.preserved_preaccount_operational, 2);
    assert!(discovery.preserved_safety_metadata >= 3);
    assert!(redis::cmd("EXISTS")
        .arg(&other_key)
        .query_async::<_, bool>(&mut fixture.store.redis_connection())
        .await
        .unwrap());
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires explicit disposable Redis fixture"]
async fn bounded_foreign_orphan_pointers_do_not_block_target_but_unbounded_orphans_do() {
    let mut fixture = Fixture::new(CredentialRetention::Forbidden).await;
    fixture.seed_all_families().await;
    let foreign_hmac = "c".repeat(64);
    let foreign_sha = "d".repeat(64);
    let target_hmac = "e".repeat(64);
    let target_sha = "f".repeat(64);
    let foreign_device = Uuid::new_v4().to_string();
    let target_device = Uuid::new_v4().to_string();
    let mut foreign_keys = Vec::new();
    let mut target_keys = Vec::new();
    for (did, hmac, sha, device, keys) in [
        (
            OTHER,
            &foreign_hmac,
            &foreign_sha,
            &foreign_device,
            &mut foreign_keys,
        ),
        (
            DID,
            &target_hmac,
            &target_sha,
            &target_device,
            &mut target_keys,
        ),
    ] {
        // These keys intentionally have no surviving encrypted session or
        // authenticated journal. Exact target DID metadata remains attributable;
        // unrelated nonsecret pointers are only preservable with bounded TTL.
        for (class, suffix, value) in [
            ("session_index", hmac.as_str(), did.to_owned()),
            ("session_fp_index", sha.as_str(), hmac.clone()),
            ("did_index", did, hmac.clone()),
            ("push_device_session", device.as_str(), sha.clone()),
            ("upgrade_pending", hmac.as_str(), "1".repeat(64)),
        ] {
            let key = fixture.key(class, suffix);
            keys.push(key.clone());
            fixture.put(key, value, Some(600)).await;
        }
        let key = fixture.key("push_session_devices", sha);
        redis::pipe()
            .cmd("SADD")
            .arg(&key)
            .arg(device)
            .ignore()
            .cmd("EXPIRE")
            .arg(&key)
            .arg(600)
            .ignore()
            .query_async::<_, ()>(&mut fixture.store.redis_connection())
            .await
            .unwrap();
        keys.push(key.clone());
        fixture.keys.push(key);
    }
    let discovery = fixture.discover().await.unwrap();
    assert_eq!(discovery.unresolved_records, 0);
    assert_eq!(
        discovery.completely_inspected,
        REDIS_FAMILIES.iter().copied().collect()
    );
    assert!(discovery.preserved_safety_metadata >= foreign_keys.len());
    for key in &target_keys {
        assert!(
            discovery
                .records
                .iter()
                .any(|record| record.key == *key && record.owner_did == DID),
            "target-owned orphan pointer must be included for deletion: {key}"
        );
    }
    for key in &foreign_keys {
        assert!(!discovery.records.iter().any(|record| record.key == *key));
        assert!(redis::cmd("EXISTS")
            .arg(key)
            .query_async::<_, bool>(&mut fixture.store.redis_connection())
            .await
            .unwrap());
    }
    assert!(
        !discovery
            .sessions
            .iter()
            .any(|identity| identity.hmac_fingerprint == target_hmac
                || identity.sha256_fingerprint == target_sha),
        "plaintext routing metadata must never become an authenticated session identity"
    );
    redis::cmd("PERSIST")
        .arg(&foreign_keys[3])
        .query_async::<_, bool>(&mut fixture.store.redis_connection())
        .await
        .unwrap();
    assert!(
        fixture.discover().await.unwrap().unresolved_records > 0,
        "an unknown pointer without a verified bounded expiry must remain unresolved"
    );
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires explicit disposable Redis fixture"]
async fn malformed_owned_envelope_and_reassigned_device_block_completeness() {
    let mut fixture = Fixture::new(CredentialRetention::Forbidden).await;
    fixture.seed_all_families().await;
    let key = fixture.key("session", &format!("{DID}_{}", fixture.target.session_hmac));
    fixture
        .put(key, "not-authenticated-ciphertext".into(), Some(600))
        .await;
    let discovery = fixture.discover().await.unwrap();
    assert!(
        discovery.unresolved_records > 0,
        "malformed payload must block the cleanup plan"
    );
    let device = fixture.target.device_ids[0].to_string();
    fixture
        .put(
            fixture.key("push_device_session", &device),
            "f".repeat(64),
            Some(600),
        )
        .await;
    let discovery = fixture.discover().await.unwrap();
    assert!(discovery.unresolved_records >= 2);
    assert!(!discovery
        .records
        .iter()
        .any(|record| record.family == RedisFamily::DeviceSession));
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires explicit disposable Redis fixture"]
async fn oversized_response_and_unfinished_scan_fail_closed() {
    let mut fixture = Fixture::new(CredentialRetention::Forbidden).await;
    let key = fixture.key("oauth_flow", &"a".repeat(64));
    fixture
        .put(key.clone(), "x".repeat(1024 * 1024 + 1), Some(600))
        .await;
    assert!(matches!(
        fixture.discover().await,
        Err(DiscoveryError::Incomplete)
    ));
    redis::cmd("DEL")
        .arg(&key)
        .query_async::<_, u64>(&mut fixture.store.redis_connection())
        .await
        .unwrap();
    // SCAN traverses the database, even when MATCH returns no records. Force
    // more than128 pages so an empty prefix cannot falsely mean complete.
    let mut pipe = redis::pipe();
    for index in 0..24_000 {
        let key = fixture.key("synthetic_scan_load", &index.to_string());
        pipe.cmd("SET")
            .arg(&key)
            .arg("synthetic")
            .arg("EX")
            .arg(300)
            .ignore();
        fixture.keys.push(key);
    }
    pipe.query_async::<_, ()>(&mut fixture.store.redis_connection())
        .await
        .unwrap();
    assert!(matches!(
        fixture.discover().await,
        Err(DiscoveryError::Incomplete)
    ));
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires explicit disposable Redis fixture"]
async fn retained_grant_requires_matching_explicit_bounded_policy() {
    let mut fixture = Fixture::new(CredentialRetention::ApprovedSealedRetry { seconds: 300 }).await;
    fixture.seed_all_families().await;
    let discovery = fixture.discover().await.unwrap();
    assert_eq!(discovery.unresolved_records, 0);
    assert!(discovery
        .records
        .iter()
        .any(|record| record.family == RedisFamily::LogoutGrant));
    assert!(matches!(
        discover_account_redis(
            &fixture.store,
            &fixture.captured,
            &fixture.target,
            fixture.journal.receipt_id,
            CredentialRetention::Forbidden
        )
        .await,
        Err(DiscoveryError::InvalidEvidence)
    ));
    let grant_key = fixture.key("logout_cleanup_grant", &fixture.target.session_hmac);
    redis::cmd("EXPIRE")
        .arg(&grant_key)
        .arg(3600)
        .query_async::<_, bool>(&mut fixture.store.redis_connection())
        .await
        .unwrap();
    assert!(fixture.discover().await.unwrap().unresolved_records > 0);
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires explicit disposable Redis fixture"]
async fn stale_or_expiring_fence_does_not_authorize_discovery() {
    let mut fixture = Fixture::new(CredentialRetention::Forbidden).await;
    let key = fixture.store.account_erasure_key(DID);
    fixture
        .put(key.clone(), Uuid::new_v4().to_string(), None)
        .await;
    assert!(matches!(
        fixture.discover().await,
        Err(DiscoveryError::FenceMismatch)
    ));
    fixture
        .put(key, fixture.journal.receipt_id.to_string(), Some(60))
        .await;
    assert!(matches!(
        fixture.discover().await,
        Err(DiscoveryError::FenceMismatch)
    ));
    fixture.finish().await;
}
