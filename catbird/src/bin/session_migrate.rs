//! Session migration CLI for Catbird BFF (nest/catbird).
//!
//! Exports/imports Redis sessions (still encrypted) for server migration.
//! Sessions are transferred as raw bytes — no decryption needed.
//!
//! Usage:
//!   session_migrate export --redis-url redis://old:6379 --output sessions.json
//!   session_migrate import --redis-url redis://new:6379 --input sessions.json
//!   session_migrate verify --source redis://old:6379 --target redis://new:6379
//!   session_migrate lifecycle-fence-migrate --redis-url redis://host --prefix catbird:session:
//!
//! Lifecycle-fence rollout contract: build the new migration binary, audit
//! while the old service is live, stop or fully quiesce Nest, run the guarded
//! `--apply` form with a short deadline, run the audit again until required=0,
//! verify that zero old Nest PIDs remain, and only then start the
//! refresh/revoke-lease-aware Nest binary. Generation-fenced but lease-unaware
//! binaries are old workers for this cutover and must never overlap it.
//! This tool requires standalone Redis/Valkey because SCAN is node-local in
//! Redis Cluster and the session schema uses multi-key atomic operations.

use clap::{Parser, Subcommand};
use redis::{AsyncCommands, FromRedisValue};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;

const DEFAULT_PREFIX: &str = "catbird:session:";
const DEFAULT_BATCH_SIZE: usize = 100;
const MAX_MIGRATION_PIPELINE_KEYS: usize = 100;

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "session_migrate",
    about = "Export/import Catbird BFF sessions between Redis instances",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Audit or install lifecycle fences for authenticated encrypted sessions.
    /// Stop or fully quiesce Nest before using --apply.
    LifecycleFenceMigrate {
        #[arg(long)]
        redis_url: String,
        #[arg(long, default_value = DEFAULT_PREFIX)]
        prefix: String,
        #[arg(long, default_value_t = 2_592_000)]
        session_ttl_seconds: u64,
        /// Install missing fences. Without this flag the command is read-only.
        #[arg(long)]
        apply: bool,
        /// Required with --apply to make the offline schema change explicit.
        #[arg(long)]
        allow_encrypted_session_migration: bool,
        /// Required with --apply; confirms Nest is stopped or fully quiesced.
        #[arg(long)]
        confirm_nest_quiesced: bool,
        /// Required with --apply; confirms zero lease-unaware Nest workers
        /// remain and deployment will start only lease-aware binaries.
        #[arg(long)]
        confirm_refresh_revoke_lease_cutover: bool,
        /// Required with --apply; migration refuses to run at or after this RFC3339 time.
        #[arg(long, requires = "apply")]
        deadline: Option<String>,
    },
    /// One-shot conversion of validated legacy plaintext sessions.
    LegacyConvert {
        #[arg(long)]
        redis_url: String,
        #[arg(long, default_value = DEFAULT_PREFIX)]
        prefix: String,
        #[arg(long)]
        deadline: String,
        #[arg(long, default_value_t = 2_592_000)]
        session_ttl_seconds: u64,
        #[arg(long)]
        allow_legacy_plaintext: bool,
    },
    /// Export sessions from a Redis instance to a JSON file
    Export {
        /// Redis connection URL
        #[arg(long)]
        redis_url: String,
        /// Output file path
        #[arg(long, short)]
        output: PathBuf,
        /// Key prefix (default: "catbird:session:")
        #[arg(long, default_value = DEFAULT_PREFIX)]
        prefix: String,
        /// Keys per SCAN iteration
        #[arg(long, default_value_t = DEFAULT_BATCH_SIZE)]
        batch_size: usize,
        /// Print what would be exported without writing
        #[arg(long)]
        dry_run: bool,
        /// Confirms Nest is stopped or fully quiesced for a stable snapshot.
        #[arg(long)]
        confirm_nest_quiesced: bool,
    },
    /// Import sessions from a JSON file into a Redis instance
    Import {
        /// Redis connection URL
        #[arg(long)]
        redis_url: String,
        /// Input file path
        #[arg(long, short)]
        input: PathBuf,
        /// Print what would be imported without writing
        #[arg(long)]
        dry_run: bool,
        /// Keys per pipeline batch
        #[arg(long, default_value_t = DEFAULT_BATCH_SIZE)]
        batch_size: usize,
        /// Overwrite keys that already exist on the target
        #[arg(long)]
        overwrite: bool,
    },
    /// Verify that source and target Redis have matching sessions
    Verify {
        /// Source Redis URL
        #[arg(long)]
        source: String,
        /// Target Redis URL
        #[arg(long)]
        target: String,
        /// Key prefix
        #[arg(long, default_value = DEFAULT_PREFIX)]
        prefix: String,
        /// Number of random keys to spot-check for value equality
        #[arg(long, default_value_t = 10)]
        spot_check: usize,
        /// Keys per SCAN iteration
        #[arg(long, default_value_t = DEFAULT_BATCH_SIZE)]
        batch_size: usize,
    },
}

// ── Export file format ───────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct ExportFile {
    version: u32,
    prefix: String,
    exported_at: String,
    keys: Vec<ExportedKey>,
}

#[derive(Serialize, Deserialize)]
struct ExportedKey {
    key: String,
    /// Raw value from Redis (encrypted sessions stay encrypted)
    value: String,
    /// Remaining TTL in seconds; -1 means no expiry, -2 means key disappeared
    ttl_seconds: i64,
    /// Categorisation for operator visibility. Security policy is derived from
    /// the physical key namespace, never this serialized advisory value.
    key_type: String,
}

// ── Helpers ──────────────────────────────────────────────────────────

async fn connect(url: &str) -> Result<redis::aio::ConnectionManager, anyhow::Error> {
    let client = redis::Client::open(url)?;
    let mut conn = redis::aio::ConnectionManager::new(client).await?;
    catbird::config::require_standalone_redis(&mut conn).await?;
    Ok(conn)
}

fn validate_migration_prefix(prefix: &str) -> Result<(), anyhow::Error> {
    if prefix.is_empty() {
        anyhow::bail!("session migration prefix must not be empty");
    }
    Ok(())
}

fn classify_key(key: &str, prefix: &str) -> Result<&'static str, anyhow::Error> {
    validate_migration_prefix(prefix)?;
    let suffix = key
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow::anyhow!("migration record is outside the declared key prefix"))?;
    Ok(if suffix.starts_with("session_generation:") {
        "session_generation"
    } else if suffix.starts_with("session_index_generation:") {
        "session_index_generation"
    } else if suffix.starts_with("session_uncertain:") {
        "session_uncertain"
    } else if suffix.starts_with("session_operation:") {
        "session_operation"
    } else if suffix.starts_with("session:") {
        "session"
    } else if suffix.starts_with("session_index:") {
        "session_index"
    } else if suffix.starts_with("auth_req:") {
        "auth_req"
    } else {
        "other"
    })
}

#[derive(Debug, PartialEq, Eq)]
enum ExportKeyPolicy {
    Include {
        key_type: &'static str,
        ttl_seconds: i64,
    },
    RejectActiveOperation,
    SkipExpired,
}

fn export_key_policy(
    key: &str,
    prefix: &str,
    pttl_millis: i64,
) -> Result<ExportKeyPolicy, anyhow::Error> {
    let key_type = classify_key(key, prefix)?;
    if key_type == "session_operation" {
        return Ok(ExportKeyPolicy::RejectActiveOperation);
    }
    let ttl_seconds = match pttl_millis {
        -1 => -1,
        value if value > 0 => value.saturating_add(999) / 1_000,
        _ => return Ok(ExportKeyPolicy::SkipExpired),
    };
    Ok(ExportKeyPolicy::Include {
        key_type,
        ttl_seconds,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum ImportKeyPolicy {
    Expiring(u64),
    Persistent,
    SkipTransient,
    SkipExpired,
}

fn import_key_policy(entry: &ExportedKey, prefix: &str) -> Result<ImportKeyPolicy, anyhow::Error> {
    if classify_key(&entry.key, prefix)? == "session_operation" {
        return Ok(ImportKeyPolicy::SkipTransient);
    }
    Ok(match entry.ttl_seconds {
        value if value > 0 => ImportKeyPolicy::Expiring(value as u64),
        -1 => ImportKeyPolicy::Persistent,
        _ => ImportKeyPolicy::SkipExpired,
    })
}

fn authenticated_inventory(
    entries: &[catbird::services::LifecycleFenceInventoryEntry],
) -> Vec<(String, String, String)> {
    entries
        .iter()
        .map(|entry| {
            (
                entry.session_key.clone(),
                entry.index_key.clone(),
                entry.pair_fingerprint.clone(),
            )
        })
        .collect()
}

async fn run_lifecycle_fence_migrate(
    redis_url: &str,
    prefix: &str,
    session_ttl_seconds: u64,
    apply: bool,
    allow_encrypted_session_migration: bool,
    confirm_nest_quiesced: bool,
    confirm_refresh_revoke_lease_cutover: bool,
    deadline: Option<&str>,
) -> Result<(), anyhow::Error> {
    validate_migration_prefix(prefix)?;
    if apply && !allow_encrypted_session_migration {
        anyhow::bail!("--apply requires --allow-encrypted-session-migration");
    }
    if apply && !confirm_nest_quiesced {
        anyhow::bail!("--apply requires --confirm-nest-quiesced");
    }
    if apply && !confirm_refresh_revoke_lease_cutover {
        anyhow::bail!("--apply requires --confirm-refresh-revoke-lease-cutover (zero lease-unaware Nest workers may remain)");
    }
    if apply {
        let deadline = deadline.ok_or_else(|| anyhow::anyhow!("--apply requires --deadline"))?;
        let deadline = chrono::DateTime::parse_from_rfc3339(deadline)?;
        if chrono::Utc::now() >= deadline.with_timezone(&chrono::Utc) {
            anyhow::bail!("lifecycle fence migration deadline has passed");
        }
    }
    eprintln!(
        "Connecting to {} …",
        catbird::config::sanitized_redis_endpoint(redis_url)
    );
    let conn = connect(redis_url).await?;
    let store = catbird::services::RedisAuthStore::from_environment(
        conn.clone(),
        prefix.to_string(),
        session_ttl_seconds,
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let before = store.audit_lifecycle_fence_inventory_offline().await?;
    let before_inventory = authenticated_inventory(&before);
    let mut required = 0usize;
    let mut installed = 0usize;
    let mut already_installed = 0usize;
    for entry in &before {
        match entry.status {
            catbird::services::LifecycleFenceStatus::Required if apply => {
                match store
                    .migrate_pre_generation_session_offline(&entry.session_key)
                    .await?
                {
                    catbird::services::LifecycleFenceMigration::Installed => installed += 1,
                    catbird::services::LifecycleFenceMigration::AlreadyInstalled => {
                        already_installed += 1
                    }
                }
            }
            catbird::services::LifecycleFenceStatus::Required => required += 1,
            catbird::services::LifecycleFenceStatus::Installed => already_installed += 1,
        }
    }

    if apply {
        // Re-audit all four namespaces after the CAS pass. Exact authenticated
        // ciphertext inventory equality detects replacement even when the
        // session count remains unchanged.
        let after = store.audit_lifecycle_fence_inventory_offline().await?;
        if after
            .iter()
            .any(|entry| entry.status != catbird::services::LifecycleFenceStatus::Installed)
        {
            anyhow::bail!("lifecycle fence verification found an unfenced session pair");
        }
        if authenticated_inventory(&after) != before_inventory {
            anyhow::bail!(
                "authenticated session inventory changed during lifecycle fence migration"
            );
        }
    }

    eprintln!(
        "Lifecycle fence audit: records={} required={} installed_now={} already_installed={}",
        before.len(),
        required,
        installed,
        already_installed
    );
    Ok(())
}

/// SCAN for all keys matching `{prefix}*` and return them.
async fn scan_keys(
    conn: &mut redis::aio::ConnectionManager,
    prefix: &str,
    batch_size: usize,
) -> Result<Vec<String>, anyhow::Error> {
    validate_migration_prefix(prefix)?;
    let pattern = format!("{prefix}*");
    let mut keys = BTreeSet::new();
    let mut cursors = HashSet::new();
    let mut cursor: u64 = 0;
    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(batch_size)
            .query_async(conn)
            .await?;

        keys.extend(batch);
        if next_cursor != 0 && !cursors.insert(next_cursor) {
            anyhow::bail!("Redis SCAN returned a repeated cursor");
        }
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }
    Ok(keys.into_iter().collect())
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

async fn run_legacy_convert(
    redis_url: &str,
    prefix: &str,
    deadline: &str,
    session_ttl_seconds: u64,
    allow_legacy_plaintext: bool,
) -> Result<(), anyhow::Error> {
    validate_migration_prefix(prefix)?;
    if !allow_legacy_plaintext {
        anyhow::bail!("legacy conversion requires --allow-legacy-plaintext");
    }
    let deadline = chrono::DateTime::parse_from_rfc3339(deadline)?;
    if chrono::Utc::now() >= deadline.with_timezone(&chrono::Utc) {
        anyhow::bail!("legacy conversion deadline has passed");
    }
    eprintln!(
        "Connecting to {} …",
        catbird::config::sanitized_redis_endpoint(redis_url)
    );
    let mut conn = connect(redis_url).await?;
    let store = catbird::services::RedisAuthStore::from_environment(
        conn.clone(),
        prefix.to_string(),
        session_ttl_seconds,
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let legacy_prefix = format!("{prefix}catbird_session:");
    let keys = scan_keys(&mut conn, &legacy_prefix, DEFAULT_BATCH_SIZE).await?;
    let mut migrated = 0usize;
    for key in &keys {
        let session_id = key
            .strip_prefix(&legacy_prefix)
            .ok_or_else(|| anyhow::anyhow!("legacy key did not match expected namespace"))?;
        if store.migrate_legacy_session_offline(session_id).await? {
            migrated += 1;
        }
    }
    let index_prefix = format!("{prefix}session_index:");
    let index_keys = scan_keys(&mut conn, &index_prefix, DEFAULT_BATCH_SIZE).await?;
    for key in &index_keys {
        let session_id = key
            .strip_prefix(&index_prefix)
            .ok_or_else(|| anyhow::anyhow!("session index key did not match namespace"))?;
        if store
            .migrate_pre_envelope_session_offline(session_id)
            .await?
        {
            migrated += 1;
        }
    }
    eprintln!("Converted {migrated} validated legacy or pre-envelope session records");
    Ok(())
}

// ── Subcommands ─────────────────────────────────────────────────────

async fn run_export(
    redis_url: &str,
    output: &PathBuf,
    prefix: &str,
    batch_size: usize,
    dry_run: bool,
    confirm_nest_quiesced: bool,
) -> Result<(), anyhow::Error> {
    validate_migration_prefix(prefix)?;
    if !confirm_nest_quiesced {
        anyhow::bail!("session export requires --confirm-nest-quiesced");
    }
    eprintln!(
        "Connecting to {} …",
        catbird::config::sanitized_redis_endpoint(redis_url)
    );
    let mut conn = connect(redis_url).await?;
    let export_batch_size = bounded_migration_batch_size(batch_size);

    eprintln!("Scanning for keys with prefix \"{prefix}\" …");
    let keys = scan_keys(&mut conn, prefix, export_batch_size).await?;
    eprintln!("Found {} keys", keys.len());
    require_no_session_operations(&keys, prefix)?;

    // Close the race between the inventory scan and the first snapshot read.
    // With Nest quiesced this set must be stable; any late operation lease or
    // key churn proves the precondition false and aborts the export.
    let preflight_keys = scan_keys(&mut conn, prefix, export_batch_size).await?;
    require_stable_export_keyset(&keys, &preflight_keys, prefix)?;

    let mut exported: Vec<ExportedKey> = Vec::with_capacity(keys.len());
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut skipped_expired = 0usize;
    let mut snapshot_values = BTreeMap::new();
    let total = keys.len();

    // Keep each request bounded even if an operator supplies a very large SCAN
    // count. Atomic PTTL/GET pairs give every exported value the TTL observed
    // for that same value on the supported standalone Redis topology.
    for (batch_index, keys) in keys.chunks(export_batch_size).enumerate() {
        let snapshots = fetch_export_batch(&mut conn, keys).await?;
        for (key_index, (key, (pttl, value))) in keys.iter().zip(snapshots).enumerate() {
            match export_key_policy(key, prefix, pttl)? {
                ExportKeyPolicy::RejectActiveOperation => {
                    anyhow::bail!("session export refused an active session operation lease")
                }
                ExportKeyPolicy::SkipExpired => skipped_expired += 1,
                ExportKeyPolicy::Include {
                    key_type,
                    ttl_seconds,
                } => {
                    if let Some(value) = value {
                        snapshot_values.insert(key.clone(), value.clone());
                        *counts.entry(key_type.to_string()).or_default() += 1;
                        exported.push(ExportedKey {
                            key: key.clone(),
                            value,
                            ttl_seconds,
                            key_type: key_type.to_string(),
                        });
                    } else {
                        skipped_expired += 1;
                    }
                }
            }

            let completed = batch_index * export_batch_size + key_index + 1;
            if completed % 100 == 0 || completed == total {
                eprintln!("  exported {completed}/{total}");
            }
        }
    }

    validate_export_snapshot(&mut conn, prefix, batch_size, &snapshot_values).await?;

    if dry_run {
        eprintln!("Dry-run breakdown:");
        for (key_type, count) in &counts {
            eprintln!("  {key_type}: {count}");
        }
        eprintln!("Skipped expired/disappeared={skipped_expired}");
        return Ok(());
    }

    let export = ExportFile {
        version: 1,
        prefix: prefix.to_string(),
        exported_at: now_iso(),
        keys: exported,
    };

    let json = serde_json::to_string_pretty(&export)?;
    std::fs::write(output, &json)?;
    eprintln!("Wrote {} keys to {}", export.keys.len(), output.display());
    Ok(())
}

fn require_no_session_operations(keys: &[String], prefix: &str) -> Result<(), anyhow::Error> {
    if keys
        .iter()
        .any(|key| classify_key(key, prefix).is_ok_and(|kind| kind == "session_operation"))
    {
        anyhow::bail!(
            "session export requires Nest quiescence; active session operation lease found"
        );
    }
    Ok(())
}

fn require_stable_export_keyset(
    expected: &[String],
    observed: &[String],
    prefix: &str,
) -> Result<(), anyhow::Error> {
    require_no_session_operations(observed, prefix)?;
    if expected != observed {
        anyhow::bail!("session export source inventory changed after quiescence check");
    }
    Ok(())
}

async fn validate_export_snapshot(
    conn: &mut redis::aio::ConnectionManager,
    prefix: &str,
    batch_size: usize,
    expected_values: &BTreeMap<String, String>,
) -> Result<(), anyhow::Error> {
    let observed_keys = scan_keys(conn, prefix, bounded_migration_batch_size(batch_size)).await?;
    require_no_session_operations(&observed_keys, prefix)?;
    let expected_keys: Vec<&String> = expected_values.keys().collect();
    let observed_export_keys: Vec<&String> = observed_keys.iter().collect();
    if expected_keys != observed_export_keys {
        anyhow::bail!("session export source inventory changed during snapshot");
    }

    let bounded_batch_size = bounded_migration_batch_size(batch_size);
    for keys in observed_keys.chunks(bounded_batch_size) {
        for (key, (pttl, value)) in keys.iter().zip(fetch_export_batch(conn, keys).await?) {
            if pttl == -2 || value.as_ref() != expected_values.get(key) {
                anyhow::bail!("session export source values changed during snapshot");
            }
        }
    }
    Ok(())
}

fn build_export_batch_pipeline(keys: &[String]) -> redis::Pipeline {
    let mut pipeline = redis::pipe();
    // This CLI creates one command-local ConnectionManager in run_export and
    // awaits every batch serially. The connection is never cloned or handed to
    // another task, so MULTI/EXEC cannot share a multiplexed request boundary;
    // it is retained here to snapshot each batch's PTTL/value pairs atomically.
    pipeline.atomic();
    for key in keys {
        pipeline.cmd("PTTL").arg(key).cmd("GET").arg(key);
    }
    pipeline
}

fn bounded_migration_batch_size(requested: usize) -> usize {
    requested.clamp(1, MAX_MIGRATION_PIPELINE_KEYS)
}

async fn fetch_export_batch(
    conn: &mut redis::aio::ConnectionManager,
    keys: &[String],
) -> Result<Vec<(i64, Option<String>)>, anyhow::Error> {
    let values: Vec<redis::Value> = build_export_batch_pipeline(keys).query_async(conn).await?;
    let expected = keys.len() * 2;
    if values.len() != expected {
        anyhow::bail!(
            "Redis export pipeline returned {} values for {} keys; expected {expected}",
            values.len(),
            keys.len()
        );
    }

    values
        .chunks_exact(2)
        .map(|pair| {
            Ok((
                i64::from_redis_value(&pair[0])?,
                Option::<String>::from_redis_value(&pair[1])?,
            ))
        })
        .collect()
}

async fn run_import(
    redis_url: &str,
    input: &PathBuf,
    dry_run: bool,
    batch_size: usize,
    overwrite: bool,
) -> Result<(), anyhow::Error> {
    eprintln!("Reading {} …", input.display());
    let data = std::fs::read_to_string(input)?;
    let export: ExportFile = serde_json::from_str(&data)?;

    if export.version != 1 {
        anyhow::bail!("Unsupported export version: {}", export.version);
    }
    validate_migration_prefix(&export.prefix)?;

    eprintln!(
        "Export contains {} keys (prefix \"{}\", exported at {})",
        export.keys.len(),
        export.prefix,
        export.exported_at
    );

    if dry_run {
        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut skipped_transient = 0usize;
        let mut skipped_expired = 0usize;
        for entry in &export.keys {
            match import_key_policy(entry, &export.prefix)? {
                ImportKeyPolicy::SkipTransient => skipped_transient += 1,
                ImportKeyPolicy::SkipExpired => skipped_expired += 1,
                ImportKeyPolicy::Expiring(_) | ImportKeyPolicy::Persistent => {
                    *counts.entry(entry.key_type.clone()).or_default() += 1;
                }
            }
        }
        eprintln!("Dry-run breakdown:");
        for (kt, n) in &counts {
            eprintln!("  {kt}: {n}");
        }
        eprintln!(
            "Skipped transient leases={skipped_transient}, expired/disappeared={skipped_expired}"
        );
        return Ok(());
    }

    eprintln!(
        "Connecting to {} …",
        catbird::config::sanitized_redis_endpoint(redis_url)
    );
    let mut conn = connect(redis_url).await?;

    let total = export.keys.len();
    let mut imported: usize = 0;
    let mut skipped_existing: usize = 0;
    let mut skipped_policy: usize = 0;
    let import_batch_size = bounded_migration_batch_size(batch_size);
    for chunk in export.keys.chunks(import_batch_size) {
        let mut prepared = Vec::with_capacity(chunk.len());
        for entry in chunk {
            let policy = import_key_policy(entry, &export.prefix)?;
            if matches!(
                policy,
                ImportKeyPolicy::SkipTransient | ImportKeyPolicy::SkipExpired
            ) {
                skipped_policy += 1;
                continue;
            }
            prepared.push(PreparedImport { entry, policy });
        }

        if !prepared.is_empty() {
            let results: Vec<Option<String>> = build_import_batch_pipeline(&prepared, overwrite)
                .query_async(&mut conn)
                .await?;
            if results.len() != prepared.len() {
                anyhow::bail!(
                    "Redis import pipeline returned {} values for {} records",
                    results.len(),
                    prepared.len()
                );
            }
            for result in results {
                if result.is_some() {
                    imported += 1;
                } else if overwrite {
                    anyhow::bail!("Redis import overwrite unexpectedly returned no result");
                } else {
                    skipped_existing += 1;
                }
            }
        }

        let done = imported + skipped_existing + skipped_policy;
        if done % 100 == 0 || done == total {
            eprintln!("  progress: {done}/{total}");
        }
    }

    eprintln!(
        "Done: imported {imported}, skipped_existing {skipped_existing}, skipped_transient_or_expired {skipped_policy}"
    );
    Ok(())
}

struct PreparedImport<'a> {
    entry: &'a ExportedKey,
    policy: ImportKeyPolicy,
}

fn build_import_batch_pipeline(batch: &[PreparedImport<'_>], overwrite: bool) -> redis::Pipeline {
    let mut pipeline = redis::pipe();
    // run_import owns one command-local ConnectionManager and awaits each batch
    // before building the next one. It is never cloned or used concurrently, so
    // this offline MULTI/EXEC batch cannot mix with another task's commands.
    pipeline.atomic();
    for prepared in batch {
        pipeline
            .cmd("SET")
            .arg(&prepared.entry.key)
            .arg(&prepared.entry.value);
        if let ImportKeyPolicy::Expiring(ttl_seconds) = prepared.policy {
            pipeline.arg("EX").arg(ttl_seconds);
        }
        if !overwrite {
            // SET NX combines the old EXISTS+SET pair into one race-free write.
            pipeline.arg("NX");
        }
    }
    pipeline
}

async fn run_verify(
    source_url: &str,
    target_url: &str,
    prefix: &str,
    spot_check: usize,
    batch_size: usize,
) -> Result<(), anyhow::Error> {
    eprintln!(
        "Connecting to source ({}) and target ({}) …",
        catbird::config::sanitized_redis_endpoint(source_url),
        catbird::config::sanitized_redis_endpoint(target_url)
    );
    let mut src = connect(source_url).await?;
    let mut tgt = connect(target_url).await?;

    eprintln!("Scanning source keys …");
    let src_keys = scan_keys(&mut src, prefix, batch_size).await?;
    eprintln!("Scanning target keys …");
    let tgt_keys = scan_keys(&mut tgt, prefix, batch_size).await?;

    let src_set: std::collections::HashSet<&str> = src_keys.iter().map(|s| s.as_str()).collect();
    let tgt_set: std::collections::HashSet<&str> = tgt_keys.iter().map(|s| s.as_str()).collect();

    let missing_from_target: Vec<&&str> = src_set.difference(&tgt_set).collect();
    let extra_in_target: Vec<&&str> = tgt_set.difference(&src_set).collect();

    eprintln!("Source keys: {}", src_keys.len());
    eprintln!("Target keys: {}", tgt_keys.len());

    if !missing_from_target.is_empty() {
        eprintln!(
            "⚠ {} keys in source missing from target:",
            missing_from_target.len()
        );
        if missing_from_target.len() > 20 {
            eprintln!("  … and {} more", missing_from_target.len() - 20);
        }
    }

    if !extra_in_target.is_empty() {
        eprintln!(
            "ℹ {} keys in target not in source (new sessions?):",
            extra_in_target.len()
        );
    }

    // Spot-check value equality
    let common: Vec<&&str> = src_set.intersection(&tgt_set).collect();
    let check_count = spot_check.min(common.len());

    if check_count > 0 {
        eprintln!("Spot-checking {check_count} keys for value equality …");
        // Deterministic selection: evenly spaced indices
        let step = if common.len() > check_count {
            common.len() / check_count
        } else {
            1
        };

        let mut mismatches = 0usize;
        for i in 0..check_count {
            let key = common[i * step];
            let src_val: Option<String> = src.get(*key).await?;
            let tgt_val: Option<String> = tgt.get(*key).await?;

            if src_val != tgt_val {
                eprintln!("  ✗ encrypted record mismatch");
                mismatches += 1;
            }
        }

        if mismatches == 0 {
            eprintln!("  ✓ all {check_count} spot-checked keys match");
        } else {
            eprintln!("  ⚠ {mismatches}/{check_count} keys have mismatched values");
        }
    }

    if missing_from_target.is_empty() && extra_in_target.is_empty() {
        eprintln!("✓ Source and target are in sync ({} keys)", src_keys.len());
    }

    Ok(())
}

// ── main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::LifecycleFenceMigrate {
            redis_url,
            prefix,
            session_ttl_seconds,
            apply,
            allow_encrypted_session_migration,
            confirm_nest_quiesced,
            confirm_refresh_revoke_lease_cutover,
            deadline,
        } => {
            run_lifecycle_fence_migrate(
                &redis_url,
                &prefix,
                session_ttl_seconds,
                apply,
                allow_encrypted_session_migration,
                confirm_nest_quiesced,
                confirm_refresh_revoke_lease_cutover,
                deadline.as_deref(),
            )
            .await
        }
        Command::LegacyConvert {
            redis_url,
            prefix,
            deadline,
            session_ttl_seconds,
            allow_legacy_plaintext,
        } => {
            run_legacy_convert(
                &redis_url,
                &prefix,
                &deadline,
                session_ttl_seconds,
                allow_legacy_plaintext,
            )
            .await
        }
        Command::Export {
            redis_url,
            output,
            prefix,
            batch_size,
            dry_run,
            confirm_nest_quiesced,
        } => {
            run_export(
                &redis_url,
                &output,
                &prefix,
                batch_size,
                dry_run,
                confirm_nest_quiesced,
            )
            .await
        }
        Command::Import {
            redis_url,
            input,
            dry_run,
            batch_size,
            overwrite,
        } => run_import(&redis_url, &input, dry_run, batch_size, overwrite).await,
        Command::Verify {
            source,
            target,
            prefix,
            spot_check,
            batch_size,
        } => run_verify(&source, &target, &prefix, spot_check, batch_size).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_url_display_omits_credentials_and_paths() {
        assert_eq!(
            catbird::config::sanitized_redis_endpoint(
                "rediss://user:password@redis.example:6380/4?token=secret"
            ),
            "rediss://redis.example:6380"
        );
        assert_eq!(
            catbird::config::sanitized_redis_endpoint("not a url"),
            "<invalid Redis URL>"
        );
    }

    #[test]
    fn export_classifies_lifecycle_fences_separately() {
        assert_eq!(
            classify_key("catbird:session:session_generation:opaque", DEFAULT_PREFIX).unwrap(),
            "session_generation"
        );
        assert_eq!(
            classify_key(
                "catbird:session:session_index_generation:opaque",
                DEFAULT_PREFIX
            )
            .unwrap(),
            "session_index_generation"
        );
    }

    #[test]
    fn export_batch_pipeline_pairs_pttl_and_get_for_each_key() {
        let keys = vec![
            "catbird:session:first".to_string(),
            "catbird:session:second".to_string(),
            "catbird:session:third".to_string(),
        ];

        let pipeline = build_export_batch_pipeline(&keys);

        assert_eq!(pipeline.cmd_iter().count(), keys.len() * 2);
        let packed = String::from_utf8(pipeline.get_packed_pipeline()).unwrap();
        for key in &keys {
            assert_eq!(packed.matches(key).count(), 2);
        }
        assert_eq!(packed.matches("PTTL").count(), keys.len());
        assert_eq!(packed.matches("GET").count(), keys.len());
    }

    #[test]
    fn migration_pipeline_batch_size_is_never_zero_or_unbounded() {
        assert_eq!(bounded_migration_batch_size(0), 1);
        assert_eq!(bounded_migration_batch_size(17), 17);
        assert_eq!(
            bounded_migration_batch_size(MAX_MIGRATION_PIPELINE_KEYS + 1),
            MAX_MIGRATION_PIPELINE_KEYS
        );
    }

    #[test]
    fn import_batch_pipeline_uses_one_race_free_set_per_record() {
        let expiring = ExportedKey {
            key: "catbird:session:one".into(),
            value: "ciphertext-one".into(),
            ttl_seconds: 60,
            key_type: "session".into(),
        };
        let persistent = ExportedKey {
            key: "catbird:session:two".into(),
            value: "ciphertext-two".into(),
            ttl_seconds: -1,
            key_type: "session".into(),
        };
        let batch = vec![
            PreparedImport {
                entry: &expiring,
                policy: ImportKeyPolicy::Expiring(60),
            },
            PreparedImport {
                entry: &persistent,
                policy: ImportKeyPolicy::Persistent,
            },
        ];

        let pipeline = build_import_batch_pipeline(&batch, false);
        assert_eq!(pipeline.cmd_iter().count(), batch.len());
        let commands: Vec<String> = pipeline
            .cmd_iter()
            .map(|command| String::from_utf8(command.get_packed_command()).unwrap())
            .collect();
        assert!(commands.iter().all(|command| command.contains("SET")));
        assert!(commands.iter().all(|command| command.contains("NX")));
        assert!(commands[0].contains("EX"));
        assert!(!commands[1].contains("EX"));
        assert!(commands.iter().all(|command| !command.contains("EXISTS")));

        let overwrite = build_import_batch_pipeline(&batch, true);
        assert!(overwrite.cmd_iter().all(|command| {
            !String::from_utf8(command.get_packed_command())
                .unwrap()
                .contains("NX")
        }));
    }

    #[test]
    fn migration_rejects_operation_leases_but_preserves_uncertainty() {
        assert_eq!(
            export_key_policy(
                "catbird:session:session_operation:opaque",
                DEFAULT_PREFIX,
                1,
            )
            .unwrap(),
            ExportKeyPolicy::RejectActiveOperation
        );
        assert_eq!(
            export_key_policy(
                "catbird:session:session_uncertain:opaque",
                DEFAULT_PREFIX,
                30,
            )
            .unwrap(),
            ExportKeyPolicy::Include {
                key_type: "session_uncertain",
                ttl_seconds: 1,
            }
        );
        assert_eq!(
            export_key_policy("catbird:session:future_transient:opaque", DEFAULT_PREFIX, 0,)
                .unwrap(),
            ExportKeyPolicy::SkipExpired
        );
        assert_eq!(
            export_key_policy("catbird:session:future_transient:opaque", DEFAULT_PREFIX, 1,)
                .unwrap(),
            ExportKeyPolicy::Include {
                key_type: "other",
                ttl_seconds: 1,
            }
        );
    }

    #[test]
    fn export_quiescence_gate_rejects_active_and_late_operation_leases() {
        let stable = vec!["catbird:session:session:primary".to_string()];
        let mut with_lease = stable.clone();
        with_lease.push("catbird:session:session_operation:lease".to_string());
        with_lease.sort();

        assert!(require_no_session_operations(&with_lease, DEFAULT_PREFIX).is_err());
        assert!(require_stable_export_keyset(&stable, &with_lease, DEFAULT_PREFIX).is_err());
        assert!(require_stable_export_keyset(&stable, &stable, DEFAULT_PREFIX).is_ok());
    }

    #[test]
    fn migration_rejects_empty_and_mismatched_namespaces() {
        assert!(validate_migration_prefix("").is_err());
        assert!(export_key_policy(
            "catbird:session:session_operation:opaque",
            "other-prefix:",
            1,
        )
        .is_err());

        let out_of_prefix_operation = ExportedKey {
            key: "catbird:session:session_operation:opaque".into(),
            value: "lease".into(),
            ttl_seconds: 1,
            key_type: "other".into(),
        };
        assert!(import_key_policy(&out_of_prefix_operation, "other-prefix:").is_err());
        assert!(import_key_policy(&out_of_prefix_operation, "").is_err());
    }

    #[test]
    fn import_never_turns_expiring_records_into_persistent_records() {
        let operation = ExportedKey {
            key: "catbird:session:session_operation:opaque".into(),
            value: "lease".into(),
            ttl_seconds: 1,
            key_type: "other".into(),
        };
        let near_expiry_unknown = ExportedKey {
            key: "catbird:session:future_transient:opaque".into(),
            value: "transient".into(),
            ttl_seconds: 0,
            key_type: "other".into(),
        };
        let disappeared_unknown = ExportedKey {
            ttl_seconds: -2,
            ..near_expiry_unknown
        };
        let persistent_unknown = ExportedKey {
            key: "catbird:session:future_persistent:opaque".into(),
            value: "persistent".into(),
            ttl_seconds: -1,
            key_type: "other".into(),
        };

        assert_eq!(
            import_key_policy(&operation, DEFAULT_PREFIX).unwrap(),
            ImportKeyPolicy::SkipTransient
        );
        let near_expiry_unknown = ExportedKey {
            key: "catbird:session:future_transient:opaque".into(),
            value: "transient".into(),
            ttl_seconds: 0,
            key_type: "other".into(),
        };
        assert_eq!(
            import_key_policy(&near_expiry_unknown, DEFAULT_PREFIX).unwrap(),
            ImportKeyPolicy::SkipExpired
        );
        assert_eq!(
            import_key_policy(&disappeared_unknown, DEFAULT_PREFIX).unwrap(),
            ImportKeyPolicy::SkipExpired
        );
        assert_eq!(
            import_key_policy(&persistent_unknown, DEFAULT_PREFIX).unwrap(),
            ImportKeyPolicy::Persistent
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL"]
    async fn live_redis_export_import_preserves_security_state_not_operation_leases() {
        let redis_url =
            std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required for this test");
        let mut conn = connect(&redis_url)
            .await
            .expect("TEST_REDIS_URL must be reachable");
        redis::cmd("FLUSHDB")
            .query_async::<_, ()>(&mut conn)
            .await
            .unwrap();

        let nonce = uuid::Uuid::new_v4();
        let prefix = format!("test:migrate:{nonce}:");
        let operation_key = format!("{prefix}session_operation:lease");
        let uncertainty_key = format!("{prefix}session_uncertain:quarantine");
        let persistent_key = format!("{prefix}future_persistent:record");
        redis::cmd("SET")
            .arg(&operation_key)
            .arg("lease")
            .arg("EX")
            .arg(30)
            .query_async::<_, ()>(&mut conn)
            .await
            .unwrap();
        redis::cmd("SET")
            .arg(&uncertainty_key)
            .arg("generation")
            .arg("EX")
            .arg(30)
            .query_async::<_, ()>(&mut conn)
            .await
            .unwrap();
        conn.set::<_, _, ()>(&persistent_key, "persistent")
            .await
            .unwrap();

        let output = std::env::temp_dir().join(format!("nest-session-export-{nonce}.json"));
        assert!(run_export(&redis_url, &output, &prefix, 100, false, false)
            .await
            .is_err());
        assert!(run_export(&redis_url, &output, &prefix, 100, false, true)
            .await
            .is_err());

        conn.del::<_, ()>(&operation_key).await.unwrap();
        let before_late_lease = scan_keys(&mut conn, &prefix, 100).await.unwrap();
        conn.set_ex::<_, _, ()>(&operation_key, "late-lease", 30)
            .await
            .unwrap();
        let after_late_lease = scan_keys(&mut conn, &prefix, 100).await.unwrap();
        assert!(
            require_stable_export_keyset(&before_late_lease, &after_late_lease, &prefix).is_err()
        );
        conn.del::<_, ()>(&operation_key).await.unwrap();

        // Fetch stable records in one bounded PTTL/GET pipeline.
        run_export(&redis_url, &output, &prefix, 100, false, true)
            .await
            .unwrap();
        let mut export: ExportFile =
            serde_json::from_str(&std::fs::read_to_string(&output).unwrap()).unwrap();
        assert!(!export.keys.iter().any(|entry| entry.key == operation_key));
        assert!(export
            .keys
            .iter()
            .any(|entry| entry.key == uncertainty_key && entry.ttl_seconds > 0));
        assert!(export
            .keys
            .iter()
            .any(|entry| entry.key == persistent_key && entry.ttl_seconds == -1));

        let expired_unknown_key = format!("{prefix}future_transient:expired");
        export.keys.push(ExportedKey {
            key: expired_unknown_key.clone(),
            value: "must-not-persist".into(),
            ttl_seconds: 0,
            key_type: "other".into(),
        });
        // Defend imports of older export files that captured operation leases.
        export.keys.push(ExportedKey {
            key: operation_key.clone(),
            value: "must-not-import".into(),
            ttl_seconds: 1,
            key_type: "other".into(),
        });
        std::fs::write(&output, serde_json::to_string_pretty(&export).unwrap()).unwrap();

        redis::cmd("FLUSHDB")
            .query_async::<_, ()>(&mut conn)
            .await
            .unwrap();
        conn.set::<_, _, ()>(&persistent_key, "existing-target")
            .await
            .unwrap();
        run_import(&redis_url, &output, false, 100, false)
            .await
            .unwrap();

        assert!(!conn.exists::<_, bool>(&operation_key).await.unwrap());
        assert!(!conn.exists::<_, bool>(&expired_unknown_key).await.unwrap());
        assert!(conn.exists::<_, bool>(&uncertainty_key).await.unwrap());
        assert!(conn.ttl::<_, i64>(&uncertainty_key).await.unwrap() > 0);
        assert_eq!(
            conn.get::<_, String>(&persistent_key).await.unwrap(),
            "existing-target"
        );
        assert_eq!(conn.ttl::<_, i64>(&persistent_key).await.unwrap(), -1);
    }

    #[test]
    fn authenticated_inventory_detects_same_cardinality_replacement() {
        let entry = |fingerprint: &str| catbird::services::LifecycleFenceInventoryEntry {
            session_key: "session".into(),
            index_key: "index".into(),
            generation_key: "generation".into(),
            index_generation_key: "index-generation".into(),
            pair_fingerprint: fingerprint.into(),
            status: catbird::services::LifecycleFenceStatus::Required,
        };
        assert_ne!(
            authenticated_inventory(&[entry("before")]),
            authenticated_inventory(&[entry("after")])
        );
    }

    #[tokio::test]
    async fn lifecycle_migration_apply_requires_all_explicit_guards() {
        let missing_allow = run_lifecycle_fence_migrate(
            "redis://127.0.0.1:1",
            DEFAULT_PREFIX,
            60,
            true,
            false,
            false,
            false,
            Some("2999-01-01T00:00:00Z"),
        )
        .await
        .unwrap_err();
        assert!(missing_allow
            .to_string()
            .contains("--allow-encrypted-session-migration"));

        let missing_deadline = run_lifecycle_fence_migrate(
            "redis://127.0.0.1:1",
            DEFAULT_PREFIX,
            60,
            true,
            true,
            true,
            true,
            None,
        )
        .await
        .unwrap_err();
        assert!(missing_deadline.to_string().contains("--deadline"));

        let missing_quiescence = run_lifecycle_fence_migrate(
            "redis://127.0.0.1:1",
            DEFAULT_PREFIX,
            60,
            true,
            true,
            false,
            true,
            Some("2999-01-01T00:00:00Z"),
        )
        .await
        .unwrap_err();
        assert!(missing_quiescence
            .to_string()
            .contains("--confirm-nest-quiesced"));

        let missing_lease_cutover = run_lifecycle_fence_migrate(
            "redis://127.0.0.1:1",
            DEFAULT_PREFIX,
            60,
            true,
            true,
            true,
            false,
            Some("2999-01-01T00:00:00Z"),
        )
        .await
        .unwrap_err();
        assert!(missing_lease_cutover
            .to_string()
            .contains("--confirm-refresh-revoke-lease-cutover"));
    }
}
