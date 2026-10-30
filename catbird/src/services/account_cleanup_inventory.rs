//! Account-erasure inventory, not a logout trigger or a background service.
//!
//! The caller must choose the account-wide policy explicitly, drain writers on
//! every instance (including callback/refresh, snapshot, poller, fanout, APNs and
//! legacy writers), capture identities, and keep that fence until verification.
//! A PostgreSQL advisory lock alone does not provide this cross-store fence.
//! Fresh login must wait: deleting auth/mute generations permits value reuse.
//!
//! Never log the plan, captured fingerprints, Redis keys, or opaque payloads.
//! Redis discovery must verify account ownership from authenticated content or
//! a verified lineage, never by scanning for a DID substring. Some OAuth flow
//! records have no DID or grant: authenticated, short-lived pre-account flow
//! state is preserved/reported separately. Unknown grant-bearing ownership or
//! malformed records must block a complete result.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountEraseScope {
    ExplicitAccountEraseAfterLastActiveSessionLogout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quiescence {
    AllAccountWritersAndInflightWorkDrained,
}

/// No Default: an unresolved product policy cannot silently erase an account.
pub struct CleanupAuthorization {
    pub account_scope: Option<AccountEraseScope>,
    pub quiescence: Option<Quiescence>,
    pub retry_credentials: Option<RetryCredentialPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryCredentialPolicy {
    /// Explicitly erase sealed provider credentials, even if revoke must stop.
    Delete,
    /// Explicit, bounded exception; the caller must report retained secrets.
    RetainUntilExistingExpiryForUpstreamRevocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryError {
    AccountScopeNotAuthorized,
    AccountNotQuiescent,
    RetryCredentialPolicyNotChosen,
    InvalidDid,
    InvalidSchema,
    MissingOrUnexpectedTable(&'static str),
    MissingOrUnexpectedColumn(&'static str, &'static str),
    IncompleteSqlCapture,
    IncompleteRedisDiscovery,
    ForeignAccountIdentity,
    InvalidRedisKey,
    InconsistentRedisIdentity,
}

#[derive(Clone, Copy)]
pub struct SqlTableSpec {
    pub table: &'static str,
    pub owner_column: &'static str,
    pub owner_type: &'static str,
    pub required: bool,
}

macro_rules! table {
    ($table:literal, $column:literal, $kind:literal, $required:literal) => {
        SqlTableSpec {
            table: $table,
            owner_column: $column,
            owner_type: $kind,
            required: $required,
        }
    };
}

/// Ordered children first; receipt/device parent rows survive until their joins
/// have been used. Optional tables are known historical schemas, not inferred.
pub const SQL_TABLES: &[SqlTableSpec] = &[
    table!("push_device_deliveries", "dedupe_key", "text", true),
    table!("notification_preferences", "user_id", "uuid", false),
    table!("push_preferences", "account_did", "text", true),
    table!("activity_subscriptions", "subscriber_did", "text", true),
    table!("thread_mutes", "user_did", "text", true),
    table!("chat_muted_convos", "account_did", "text", true),
    table!("chat_notified_watermarks", "account_did", "text", true),
    table!("chat_poll_state", "account_did", "text", true),
    table!("chat_mute_sync_generations", "account_did", "text", true),
    table!("push_event_queue", "recipient_did", "text", true),
    table!("actor_moderation_verdict", "recipient_did", "text", true),
    table!("relationship_audit_log", "user_did", "text", false),
    table!("user_blocks_encrypted", "user_did", "text", false),
    table!("user_mutes_encrypted", "user_did", "text", false),
    table!("user_blocks_hashed", "user_did", "text", false),
    table!("user_mutes_hashed", "user_did", "text", false),
    table!("user_blocks", "user_did", "text", false),
    table!("user_mutes", "user_did", "text", false),
    table!("moderation_list_subscriptions", "user_did", "text", false),
    table!("user_devices", "did", "text", true),
    table!("push_event_receipts", "recipient_did", "text", true),
    table!("push_accounts", "account_did", "text", true),
];

/// These are outside account erasure. The other-account predicates must not be
/// widened to actor_did/subject_did. Public cache expiry is a separate operation.
pub const PRESERVED_SCOPE: &[&str] = &[
    "activity_subscriptions.subject_did owned by another subscriber",
    "push_event_queue.actor_did owned by another recipient",
    "actor_moderation_verdict.actor_did owned by another recipient",
    "firehose_cursor",
    "moderation_list_members",
    "did_cache",
    "post_cache",
    "_sqlx_migrations",
    "upgrade_retired replay tombstones",
];

pub const SEPARATE_PUBLIC_CACHE_RETENTION: &[(&str, &str)] = &[
    ("did_cache", "expires_at < now()"),
    ("post_cache", "expires_at < now()"),
];

/// Catalog metadata from the explicitly selected schema. `udt_name` values are
/// used (text/uuid), and views must not be accepted as base tables.
#[derive(Default, Clone)]
pub struct SchemaInventory {
    pub base_tables: BTreeMap<String, BTreeMap<String, String>>,
    pub non_base_tables: BTreeSet<String>,
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
}

fn qualified(schema: &str, table: &str) -> String {
    // Schema is validated; table always comes from a static allowlist.
    format!("\"{schema}\".\"{table}\"")
}

fn validate_schema(schema: &str, inventory: &SchemaInventory) -> Result<(), InventoryError> {
    if !valid_identifier(schema) {
        return Err(InventoryError::InvalidSchema);
    }
    for spec in SQL_TABLES {
        if inventory.non_base_tables.contains(spec.table) {
            return Err(InventoryError::MissingOrUnexpectedTable(spec.table));
        }
        match inventory.base_tables.get(spec.table) {
            None if !spec.required => (),
            None => return Err(InventoryError::MissingOrUnexpectedTable(spec.table)),
            Some(columns)
                if columns.get(spec.owner_column).map(String::as_str) == Some(spec.owner_type) => {}
            Some(_) => {
                return Err(InventoryError::MissingOrUnexpectedColumn(
                    spec.table,
                    spec.owner_column,
                ))
            }
        }
    }
    for (table, column, kind) in [
        ("user_devices", "id", "uuid"),
        ("user_devices", "auth_session_fingerprint", "text"),
        ("push_event_receipts", "dedupe_key", "text"),
        ("push_device_deliveries", "device_id", "uuid"),
    ] {
        if inventory
            .base_tables
            .get(table)
            .and_then(|c| c.get(column))
            .map(String::as_str)
            != Some(kind)
        {
            return Err(InventoryError::MissingOrUnexpectedColumn(table, column));
        }
    }
    Ok(())
}

/// Execute these parameterized reads while fenced, before ANY destructive step.
/// Bind the exact account DID as $1. Persist retry identities securely if the
/// coordinator must survive a process exit; a later SQL requery cannot recover
/// device/receipt identities once the SQL transaction has committed.
pub fn capture_queries(schema: &str) -> Result<[String; 3], InventoryError> {
    if !valid_identifier(schema) {
        return Err(InventoryError::InvalidSchema);
    }
    let devices = qualified(schema, "user_devices");
    let receipts = qualified(schema, "push_event_receipts");
    let deliveries = qualified(schema, "push_device_deliveries");
    Ok([
        format!("SELECT id FROM {devices} WHERE did = $1 ORDER BY id FOR UPDATE"),
        format!("SELECT dedupe_key FROM {receipts} WHERE recipient_did = $1 ORDER BY dedupe_key FOR UPDATE"),
        format!("SELECT DISTINCT d.device_id FROM {deliveries} d JOIN {receipts} r USING (dedupe_key) WHERE r.recipient_did = $1"),
    ])
}

/// Captured under the same external fence as discovery; absence is a valid
/// result only after the queries have completed successfully. No raw secrets.
#[derive(Clone)]
pub struct CapturedSqlIdentities {
    pub did: String,
    pub device_ids: BTreeSet<String>,
    pub receipt_keys: BTreeSet<String>,
    pub historical_delivery_device_ids: BTreeSet<String>,
    pub capture_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RedisFamily {
    Session,
    SessionIndex,
    SessionFingerprintIndex,
    DidIndex,
    DeviceSession,
    SessionDevices,
    AuthRequest,
    OAuthFlow,
    OAuthClaim,
    UpgradeFlow,
    UpgradePending,
    UpgradeCandidate,
    UpgradeExchange,
    UpgradeReceipt,
    Exchange,
    RevokeJob,
    RevokeClaim,
    LogoutGrant,
    Retired,
}

/// Every family must have been inspected completely, even if no owned record
/// exists. Authenticated short-lived pre-account records with no DID or grant
/// are counted as preserved operational state, not silently discarded.
pub const REDIS_FAMILIES: &[RedisFamily] = &[
    RedisFamily::Session,
    RedisFamily::SessionIndex,
    RedisFamily::SessionFingerprintIndex,
    RedisFamily::DidIndex,
    RedisFamily::DeviceSession,
    RedisFamily::SessionDevices,
    RedisFamily::AuthRequest,
    RedisFamily::OAuthFlow,
    RedisFamily::OAuthClaim,
    RedisFamily::UpgradeFlow,
    RedisFamily::UpgradePending,
    RedisFamily::UpgradeCandidate,
    RedisFamily::UpgradeExchange,
    RedisFamily::UpgradeReceipt,
    RedisFamily::Exchange,
    RedisFamily::RevokeJob,
    RedisFamily::RevokeClaim,
    RedisFamily::LogoutGrant,
    RedisFamily::Retired,
];

impl RedisFamily {
    pub fn stem(self) -> &'static str {
        match self {
            Self::Session => "session:",
            Self::SessionIndex => "session_index:",
            Self::SessionFingerprintIndex => "session_fp_index:",
            Self::DidIndex => "did_index:",
            Self::DeviceSession => "push_device_session:",
            Self::SessionDevices => "push_session_devices:",
            Self::AuthRequest => "auth_req:",
            Self::OAuthFlow => "oauth_flow:",
            Self::OAuthClaim => "oauth_claim:",
            Self::UpgradeFlow => "upgrade_flow:",
            Self::UpgradePending => "upgrade_pending:",
            Self::UpgradeCandidate => "upgrade_candidate:",
            Self::UpgradeExchange => "upgrade_exchange:",
            Self::UpgradeReceipt => "upgrade_receipt:",
            Self::Exchange => "exchange:",
            Self::RevokeJob => "revoke_job:",
            Self::RevokeClaim => "revoke_claim:",
            Self::LogoutGrant => "logout_cleanup_grant:",
            Self::Retired => "upgrade_retired:",
        }
    }
}

/// Must be supplied by the auth backend after authenticated record decoding or
/// verified index/lineage traversal. A key suffix alone is not ownership proof.
pub struct VerifiedRedisRecord {
    pub owner_did: String,
    pub family: RedisFamily,
    pub key: String,
}

pub struct VerifiedSessionIdentity {
    pub owner_did: String,
    pub hmac_fingerprint: String,
    pub sha256_fingerprint: String,
}

/// No Debug/Serialize: even pseudonymous keys must not enter ordinary logs.
pub struct RedisDiscovery {
    pub records: Vec<VerifiedRedisRecord>,
    pub sessions: Vec<VerifiedSessionIdentity>,
    pub completely_inspected: BTreeSet<RedisFamily>,
    pub unresolved_records: usize,
    pub preserved_preaccount_operational: usize,
    pub preserved_safety_metadata: usize,
}

pub struct SqlDeleteOperation {
    pub table: &'static str,
    /// Bind account DID as $1. All identifiers are fixed inventory identifiers.
    pub statement: String,
    pub verification_statement: String,
}

/// Exact key only. The executor must check the quiescence fence again before
/// deletion; no wildcard deletion is ever emitted. Retired keys are not here.
pub struct RedisDeleteOperation {
    pub family: RedisFamily,
    pub key: String,
}

pub struct AccountCleanupPlan {
    did: String,
    schema: String,
    prefix: String,
    pub scope: AccountEraseScope,
    sql: Vec<SqlDeleteOperation>,
    redis: Vec<RedisDeleteOperation>,
    pub retained_retry_keys: Vec<String>,
    pub retained_replay_tombstones: Vec<String>,
    pub preserved_preaccount_operational: usize,
    pub preserved_safety_metadata: usize,
    pub captured: CapturedSqlIdentities,
}

fn hex_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn valid_did(did: &str) -> bool {
    did.starts_with("did:")
        && did.len() >= 8
        && did.len() <= 2048
        && did
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b":%_.-".contains(&c))
}

fn key_valid(prefix: &str, did: &str, record: &VerifiedRedisRecord) -> bool {
    let start = if record.family == RedisFamily::Exchange {
        record.family.stem().to_owned()
    } else {
        format!("{prefix}{}", record.family.stem())
    };
    let Some(suffix) = record.key.strip_prefix(&start) else {
        return false;
    };
    match record.family {
        RedisFamily::DidIndex => suffix == did,
        RedisFamily::Session => suffix
            .strip_prefix(&format!("{did}_"))
            .is_some_and(hex_fingerprint),
        RedisFamily::DeviceSession => uuid::Uuid::parse_str(suffix).is_ok(),
        RedisFamily::AuthRequest => {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        }
        RedisFamily::UpgradeExchange => {
            let parts: Vec<_> = suffix.split(':').collect();
            parts.len() == 3 && parts.iter().all(|p| hex_fingerprint(p))
        }
        _ => hex_fingerprint(suffix),
    }
}

impl AccountCleanupPlan {
    pub fn prepare(
        did: &str,
        schema: &str,
        prefix: &str,
        authorization: CleanupAuthorization,
        catalog: &SchemaInventory,
        captured: CapturedSqlIdentities,
        discovered: RedisDiscovery,
    ) -> Result<Self, InventoryError> {
        let scope = authorization
            .account_scope
            .ok_or(InventoryError::AccountScopeNotAuthorized)?;
        authorization
            .quiescence
            .ok_or(InventoryError::AccountNotQuiescent)?;
        let retry_policy = authorization
            .retry_credentials
            .ok_or(InventoryError::RetryCredentialPolicyNotChosen)?;
        if !valid_did(did) {
            return Err(InventoryError::InvalidDid);
        }
        if captured.did != did {
            return Err(InventoryError::ForeignAccountIdentity);
        }
        if !captured.capture_complete {
            return Err(InventoryError::IncompleteSqlCapture);
        }
        validate_schema(schema, catalog)?;
        if !prefix.contains(":v2:")
            || prefix
                .bytes()
                .any(|c| c.is_ascii_control() || b"*?[]\\".contains(&c))
        {
            return Err(InventoryError::InvalidRedisKey);
        }
        if discovered.unresolved_records != 0
            || REDIS_FAMILIES
                .iter()
                .any(|f| !discovered.completely_inspected.contains(f))
        {
            return Err(InventoryError::IncompleteRedisDiscovery);
        }
        let mut records = discovered.records;
        let preserved_preaccount_operational = discovered.preserved_preaccount_operational;
        let preserved_safety_metadata = discovered.preserved_safety_metadata;
        let mut sha_owners = BTreeMap::new();
        for session in discovered.sessions {
            if session.owner_did != did {
                return Err(InventoryError::ForeignAccountIdentity);
            }
            if !hex_fingerprint(&session.hmac_fingerprint)
                || !hex_fingerprint(&session.sha256_fingerprint)
            {
                return Err(InventoryError::InvalidRedisKey);
            }
            if sha_owners
                .insert(
                    session.sha256_fingerprint.clone(),
                    session.hmac_fingerprint.clone(),
                )
                .is_some_and(|old| old != session.hmac_fingerprint)
            {
                return Err(InventoryError::InconsistentRedisIdentity);
            }
            for (family, suffix) in [
                (
                    RedisFamily::Session,
                    format!("{did}_{}", session.hmac_fingerprint),
                ),
                (RedisFamily::SessionIndex, session.hmac_fingerprint.clone()),
                (
                    RedisFamily::SessionFingerprintIndex,
                    session.sha256_fingerprint.clone(),
                ),
                (RedisFamily::SessionDevices, session.sha256_fingerprint),
                (
                    RedisFamily::UpgradePending,
                    session.hmac_fingerprint.clone(),
                ),
                (
                    RedisFamily::UpgradeCandidate,
                    session.hmac_fingerprint.clone(),
                ),
                (
                    RedisFamily::UpgradeReceipt,
                    session.hmac_fingerprint.clone(),
                ),
                (RedisFamily::RevokeJob, session.hmac_fingerprint.clone()),
                (RedisFamily::RevokeClaim, session.hmac_fingerprint.clone()),
                (RedisFamily::Retired, session.hmac_fingerprint),
            ] {
                records.push(VerifiedRedisRecord {
                    owner_did: did.into(),
                    family,
                    key: format!("{prefix}{}{suffix}", family.stem()),
                });
            }
        }
        records.push(VerifiedRedisRecord {
            owner_did: did.into(),
            family: RedisFamily::DidIndex,
            key: format!("{prefix}did_index:{did}"),
        });
        // Device-key deletion needs verified account ownership, not merely a
        // historical receipt UUID. The auth backend resolves the current link.
        let verified_devices: BTreeSet<_> = records
            .iter()
            .filter(|r| r.family == RedisFamily::DeviceSession)
            .filter_map(|r| r.key.strip_prefix(&format!("{prefix}push_device_session:")))
            .collect();
        if captured
            .device_ids
            .union(&captured.historical_delivery_device_ids)
            .any(|id| !verified_devices.contains(id.as_str()))
        {
            // Discovery must include verified absence as an exact idempotent key
            // operation, after checking no current link belongs to another DID.
            return Err(InventoryError::IncompleteRedisDiscovery);
        }
        let mut redis = Vec::new();
        let mut retained_retry_keys = Vec::new();
        let mut retained_replay_tombstones = Vec::new();
        let mut seen = BTreeSet::new();
        for record in records {
            if record.owner_did != did {
                return Err(InventoryError::ForeignAccountIdentity);
            }
            if !key_valid(prefix, did, &record) {
                return Err(InventoryError::InvalidRedisKey);
            }
            if !seen.insert(record.key.clone()) {
                continue;
            }
            if record.family == RedisFamily::Retired {
                retained_replay_tombstones.push(record.key);
            } else if matches!(
                record.family,
                RedisFamily::RevokeJob | RedisFamily::RevokeClaim | RedisFamily::LogoutGrant
            ) && retry_policy
                == RetryCredentialPolicy::RetainUntilExistingExpiryForUpstreamRevocation
            {
                retained_retry_keys.push(record.key);
            } else {
                redis.push(RedisDeleteOperation {
                    family: record.family,
                    key: record.key,
                });
            }
        }
        let mut sql = Vec::new();
        for spec in SQL_TABLES {
            if !catalog.base_tables.contains_key(spec.table) {
                continue;
            }
            let target = qualified(schema, spec.table);
            let statement = match spec.table {
                "push_device_deliveries" => format!("DELETE FROM {target} d USING {} r WHERE d.dedupe_key = r.dedupe_key AND r.recipient_did = $1", qualified(schema, "push_event_receipts")),
                "notification_preferences" => format!("DELETE FROM {target} p USING {} d WHERE p.user_id = d.id AND d.did = $1", qualified(schema, "user_devices")),
                _ => format!("DELETE FROM {target} WHERE \"{}\" = $1", spec.owner_column),
            };
            let verification_statement = match spec.table {
                "push_device_deliveries" => format!("SELECT count(*) FROM {target} d JOIN {} r ON d.dedupe_key = r.dedupe_key WHERE r.recipient_did = $1", qualified(schema, "push_event_receipts")),
                "notification_preferences" => format!("SELECT count(*) FROM {target} p JOIN {} d ON p.user_id = d.id WHERE d.did = $1", qualified(schema, "user_devices")),
                _ => format!("SELECT count(*) FROM {target} WHERE \"{}\" = $1", spec.owner_column),
            };
            sql.push(SqlDeleteOperation {
                table: spec.table,
                statement,
                verification_statement,
            });
        }
        Ok(Self {
            did: did.into(),
            schema: schema.into(),
            prefix: prefix.into(),
            scope,
            sql,
            redis,
            retained_retry_keys,
            retained_replay_tombstones,
            preserved_preaccount_operational,
            preserved_safety_metadata,
            captured,
        })
    }

    pub fn did(&self) -> &str {
        &self.did
    }
    pub fn sql_operations(&self) -> &[SqlDeleteOperation] {
        &self.sql
    }
    pub fn redis_operations(&self) -> &[RedisDeleteOperation] {
        &self.redis
    }
}

/// Uses the caller's transaction, never COMMITs and never opens a connection.
/// Caller keeps the external fence and captured retry manifest across commit.
/// An error leaves the transaction for rollback; Redis cannot be rolled back.
async fn execute_sql_deletes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &AccountCleanupPlan,
) -> Result<Vec<(&'static str, u64)>, sqlx::Error> {
    let mut counts = Vec::new();
    for operation in &plan.sql {
        let result = sqlx::query(&operation.statement)
            .bind(plan.did())
            .execute(&mut **tx)
            .await?;
        counts.push((operation.table, result.rows_affected()));
        // Verify immediately while child ownership joins still exist.
        let remaining: i64 = sqlx::query_scalar(&operation.verification_statement)
            .bind(plan.did())
            .fetch_one(&mut **tx)
            .await?;
        if remaining != 0 {
            return Err(sqlx::Error::Protocol(format!(
                "account cleanup left rows in {}",
                operation.table
            )));
        }
    }
    Ok(counts)
}

/// Holds the same account advisory lock used by registry and APNs sends. Begin
/// only after the Redis auth coordinator has authoritatively retired the final
/// live session and installed its durable, non-expiring account-erasure nonce.
/// The caller persists `captured` before executing if restart recovery is needed.
pub struct LockedSqlInventory {
    tx: sqlx::Transaction<'static, sqlx::Postgres>,
    did: String,
    schema: String,
    fence_nonce: String,
    pub catalog: SchemaInventory,
    pub captured: CapturedSqlIdentities,
}

async fn require_account_fence(
    store: &crate::services::RedisAuthStore,
    did: &str,
    nonce: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        uuid::Uuid::parse_str(nonce).is_ok(),
        "invalid account erasure nonce"
    );
    let mut conn = store.redis_connection();
    let key = format!("{}account_erasure:{did}", store.key_prefix());
    let actual: Option<String> = redis::cmd("GET").arg(key).query_async(&mut conn).await?;
    anyhow::ensure!(
        actual.as_deref() == Some(nonce),
        "account erasure fence missing or changed"
    );
    Ok(())
}

impl LockedSqlInventory {
    pub async fn begin(
        pool: &sqlx::PgPool,
        store: &crate::services::RedisAuthStore,
        did: &str,
        fence_nonce: &str,
        schema: &str,
    ) -> anyhow::Result<Self> {
        use sqlx::Row;
        anyhow::ensure!(valid_did(did), "invalid account DID");
        anyhow::ensure!(valid_identifier(schema), "invalid account schema");
        let mut tx = pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, did).await?;
        require_account_fence(store, did, fence_nonce).await?;
        // Match the operator/mute writers' lock order as well.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('chat_muted_convos:' || $1))")
            .bind(did)
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(did)
            .execute(&mut *tx)
            .await?;
        let names: Vec<&str> = SQL_TABLES.iter().map(|s| s.table).collect();
        let rows = sqlx::query(
            "SELECT t.table_name, t.table_type, c.column_name, c.udt_name, c.udt_schema \
             FROM information_schema.tables t JOIN information_schema.columns c \
             ON c.table_schema=t.table_schema AND c.table_name=t.table_name \
             WHERE t.table_schema=$1 AND t.table_name=ANY($2)",
        )
        .bind(schema)
        .bind(names)
        .fetch_all(&mut *tx)
        .await?;
        let mut catalog = SchemaInventory::default();
        for row in rows {
            let table: String = row.try_get("table_name")?;
            let kind: String = row.try_get("table_type")?;
            if kind != "BASE TABLE" {
                catalog.non_base_tables.insert(table);
                continue;
            }
            let type_schema: String = row.try_get("udt_schema")?;
            let column_type: String = row.try_get("udt_name")?;
            let column_type = if type_schema == "pg_catalog" {
                column_type
            } else {
                format!("{type_schema}.{column_type}")
            };
            catalog
                .base_tables
                .entry(table)
                .or_default()
                .insert(row.try_get("column_name")?, column_type);
        }
        validate_schema(schema, &catalog)
            .map_err(|e| anyhow::anyhow!("cleanup inventory schema validation failed: {e:?}"))?;
        let queries =
            capture_queries(schema).map_err(|_| anyhow::anyhow!("invalid account schema"))?;
        let device_ids: Vec<uuid::Uuid> = sqlx::query_scalar(&queries[0])
            .bind(did)
            .fetch_all(&mut *tx)
            .await?;
        let receipt_keys: Vec<String> = sqlx::query_scalar(&queries[1])
            .bind(did)
            .fetch_all(&mut *tx)
            .await?;
        let historical: Vec<uuid::Uuid> = sqlx::query_scalar(&queries[2])
            .bind(did)
            .fetch_all(&mut *tx)
            .await?;
        let captured = CapturedSqlIdentities {
            did: did.into(),
            device_ids: device_ids.into_iter().map(|id| id.to_string()).collect(),
            receipt_keys: receipt_keys.into_iter().collect(),
            historical_delivery_device_ids: historical
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
            capture_complete: true,
        };
        Ok(Self {
            tx,
            did: did.into(),
            schema: schema.into(),
            fence_nonce: fence_nonce.into(),
            catalog,
            captured,
        })
    }

    /// The account fence remains installed after this returns. Success means SQL
    /// committed only; the coordinator must finish Redis and verify both stores.
    pub async fn erase(
        mut self,
        store: &crate::services::RedisAuthStore,
        plan: &AccountCleanupPlan,
    ) -> Result<Vec<(&'static str, u64)>, SqlErasureFailure> {
        let prepare = async {
            anyhow::ensure!(plan.did() == self.did, "cleanup plan account mismatch");
            // Plans must use this capture, not a stale snapshot from an old run.
            anyhow::ensure!(
                plan.captured.device_ids == self.captured.device_ids
                    && plan.captured.receipt_keys == self.captured.receipt_keys
                    && plan.captured.historical_delivery_device_ids
                        == self.captured.historical_delivery_device_ids,
                "cleanup capture changed"
            );
            anyhow::ensure!(
                plan.schema == self.schema && plan.prefix == store.key_prefix(),
                "cleanup store scope changed"
            );
            require_account_fence(store, &self.did, &self.fence_nonce).await?;
            let counts = execute_sql_deletes(&mut self.tx, plan).await?;
            require_account_fence(store, &self.did, &self.fence_nonce).await?;
            Ok::<_, anyhow::Error>(counts)
        }
        .await;
        let counts = match prepare {
            Ok(counts) => counts,
            Err(error) => {
                let outcome = if self.tx.rollback().await.is_ok() {
                    SqlOutcome::RolledBack
                } else {
                    SqlOutcome::RollbackUnknown
                };
                return Err(SqlErasureFailure { outcome, error });
            }
        };
        self.tx.commit().await.map_err(|error| SqlErasureFailure {
            outcome: SqlOutcome::CommitUnknown,
            error: error.into(),
        })?;
        Ok(counts)
    }
}

pub struct SqlErasureFailure {
    pub outcome: SqlOutcome,
    pub error: anyhow::Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlOutcome {
    NotStarted,
    RolledBack,
    RollbackUnknown,
    CommitUnknown,
    Committed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisOutcome {
    NotStarted,
    PartialOrUnknown,
    Deleted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupCompletion {
    Pending,
    ErasedWithReplayTombstones,
    ErasedWithExplicitRetryCredentialException,
}

/// Store acknowledgements alone are insufficient: verify owned rows/keys are
/// gone while still fenced. Commit-unknown must be reconciled, never replayed as
/// proof of rollback, and no partial outcome permits fresh-login activation.
pub fn completion(
    sql: SqlOutcome,
    redis: RedisOutcome,
    verified_after_delete: bool,
    retry_credentials_retained: bool,
) -> CleanupCompletion {
    if sql != SqlOutcome::Committed || redis != RedisOutcome::Deleted || !verified_after_delete {
        CleanupCompletion::Pending
    } else if retry_credentials_retained {
        CleanupCompletion::ErasedWithExplicitRetryCredentialException
    } else {
        CleanupCompletion::ErasedWithReplayTombstones
    }
}
