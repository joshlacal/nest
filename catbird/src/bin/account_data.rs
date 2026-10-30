//! Account-data operator CLI for Catbird BFF (nest/catbird).
//!
//! Reports, deletes, and ages out the data Nest holds for an account. Nothing
//! is removed unless `--apply` is passed; the default is a dry-run report of
//! row/key counts.
//!
//! Output only ever contains store/table names, counts, and the DID the
//! operator supplied. It never prints session IDs, tokens, device tokens,
//! fingerprints, or row contents.
//!
//! Usage:
//!   account_data report    --did did:plc:abc
//!   account_data delete    --did did:plc:abc [--apply]
//!   account_data retention [--apply]
//!
//! Connection settings (flag, then env):
//!   --database-url  DATABASE_URL, then CATBIRD__PUSH__DATABASE_URL
//!   --redis-url     REDIS_URL,    then CATBIRD__REDIS__URL
//!   --prefix        CATBIRD__REDIS__KEY_PREFIX (default "catbird:v2:session:")

use std::fmt::Write as _;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};

const DEFAULT_PREFIX: &str = "catbird:v2:session:";
const DEFAULT_BATCH_SIZE: usize = 500;

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "account_data",
    about = "Report, delete, and age out Nest-held account data (dry-run by default)",
    version
)]
struct Cli {
    /// Postgres URL (falls back to DATABASE_URL, then CATBIRD__PUSH__DATABASE_URL)
    #[arg(long, global = true)]
    database_url: Option<String>,
    /// Redis URL (falls back to REDIS_URL, then CATBIRD__REDIS__URL)
    #[arg(long, global = true)]
    redis_url: Option<String>,
    /// Redis session key prefix
    #[arg(long, global = true, env = "CATBIRD__REDIS__KEY_PREFIX", default_value = DEFAULT_PREFIX)]
    prefix: String,
    /// Keys per Redis SCAN iteration
    #[arg(long, global = true, default_value_t = DEFAULT_BATCH_SIZE)]
    batch_size: usize,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Count every Nest-held record tied to an account
    Report {
        /// Account DID
        #[arg(long)]
        did: String,
    },
    /// Delete an account's Nest-held data (dry-run unless --apply)
    Delete {
        /// Account DID
        #[arg(long)]
        did: String,
        /// Actually delete; without this only counts are printed
        #[arg(long)]
        apply: bool,
    },
    /// Apply age-based retention rules R1-R5 (dry-run unless --apply)
    Retention {
        /// Actually delete; without this only counts are printed
        #[arg(long)]
        apply: bool,
    },
}

// ── Table scope ──────────────────────────────────────────────────────

/// Nest-owned tables holding rows that belong to the account, with the column
/// naming the owning DID. Ordered children-first so explicit deletes never
/// trip a foreign key. `push_preferences` would also cascade from
/// `push_accounts`; it is deleted explicitly so the count is exact.
const OWNED_TABLES: &[(&str, &str)] = &[
    ("push_preferences", "account_did"),
    ("user_devices", "did"),
    ("activity_subscriptions", "subscriber_did"),
    ("thread_mutes", "user_did"),
    ("chat_muted_convos", "account_did"),
    ("chat_notified_watermarks", "account_did"),
    ("chat_poll_state", "account_did"),
    ("chat_mute_sync_generations", "account_did"),
    ("push_event_queue", "recipient_did"),
    ("push_event_receipts", "recipient_did"),
    ("actor_moderation_verdict", "recipient_did"),
    ("push_accounts", "account_did"),
];

/// Rows that mention the DID but belong to OTHER accounts. Reported, never
/// deleted by `delete --did`.
const REFERENCED_BY_OTHERS: &[(&str, &str)] = &[
    ("activity_subscriptions", "subject_did"),
    ("push_event_queue", "actor_did"),
    ("actor_moderation_verdict", "actor_did"),
];

/// Tables left behind by the retired bluesky-push-notifier. They may exist in
/// the shared production database but are not in Nest's migrations, so their
/// presence and shape are discovered at runtime.
const LEGACY_TABLES: &[&str] = &[
    "relationship_audit_log",
    "user_blocks_encrypted",
    "user_mutes_encrypted",
    "user_blocks_hashed",
    "user_mutes_hashed",
    "notification_preferences",
    "did_cache",
    "post_cache",
];

/// Column names accepted as "this row belongs to DID X" on legacy tables.
const LEGACY_DID_COLUMNS: &[&str] = &["user_did", "did"];

// ── Retention rules ──────────────────────────────────────────────────

// Receipt history is removed only by explicit account deletion. Age-based
// retention must also preserve unresolved delivery/catch-up state for review.
macro_rules! no_notification_hold {
    ($did:expr) => {
        concat!(
            "NOT EXISTS (SELECT 1 FROM chat_poll_state held_poll WHERE held_poll.account_did = ", $did,
            " AND held_poll.catch_up_required_at IS NOT NULL) AND ",
            "NOT EXISTS (SELECT 1 FROM push_event_queue held_queue WHERE held_queue.recipient_did = ", $did,
            " AND held_queue.delivery_hold_reason IS NOT NULL) AND ",
            "NOT EXISTS (SELECT 1 FROM push_event_receipts held_receipt WHERE held_receipt.recipient_did = ", $did,
            " AND (held_receipt.state = 'held' OR EXISTS (SELECT 1 FROM push_device_deliveries held_device ",
            "WHERE held_device.dedupe_key = held_receipt.dedupe_key AND held_device.state IN ('attempting', 'held'))))"
        )
    };
}

/// Accounts eligible for R1: revoked more than 180 days ago with no active device.
macro_rules! r1_doomed {
    () => {
        concat!("SELECT pa.account_did AS did FROM push_accounts pa \
         WHERE pa.auth_revoked_at < now() - interval '180 days' \
         AND NOT EXISTS (SELECT 1 FROM user_devices d WHERE d.did = pa.account_did AND d.is_active) AND ",
         no_notification_hold!("pa.account_did"))
    };
}

/// R1 (revoked accounts), dry-run: rows that R1 would remove, per table.
const R1_COUNT_SQL: &str = concat!(
    "WITH doomed AS (",
    r1_doomed!(),
    ") ",
    "SELECT 'push_accounts', count(*) FROM push_accounts WHERE account_did IN (SELECT did FROM doomed) UNION ALL ",
    "SELECT 'push_preferences', count(*) FROM push_preferences WHERE account_did IN (SELECT did FROM doomed) UNION ALL ",
    "SELECT 'user_devices', count(*) FROM user_devices WHERE did IN (SELECT did FROM doomed) UNION ALL ",
    "SELECT 'activity_subscriptions', count(*) FROM activity_subscriptions WHERE subscriber_did IN (SELECT did FROM doomed) UNION ALL ",
    "SELECT 'thread_mutes', count(*) FROM thread_mutes WHERE user_did IN (SELECT did FROM doomed) UNION ALL ",
    "SELECT 'chat_muted_convos', count(*) FROM chat_muted_convos WHERE account_did IN (SELECT did FROM doomed) UNION ALL ",
    "SELECT 'chat_notified_watermarks', count(*) FROM chat_notified_watermarks WHERE account_did IN (SELECT did FROM doomed) UNION ALL ",
    "SELECT 'chat_poll_state', count(*) FROM chat_poll_state WHERE account_did IN (SELECT did FROM doomed) UNION ALL ",
    "SELECT 'push_event_queue', count(*) FROM push_event_queue WHERE recipient_did IN (SELECT did FROM doomed) UNION ALL ",
    "SELECT 'actor_moderation_verdict', count(*) FROM actor_moderation_verdict WHERE recipient_did IN (SELECT did FROM doomed)"
);

/// R1 (revoked accounts), apply: push_accounts revoked > 180 days with no
/// active user_devices or unresolved notification holds are deleted with the
/// legacy retention scope. Receipt and mute-generation history remain intact.
/// push_preferences goes by FK cascade; its count is read from the pre-statement snapshot.
const R1_APPLY_SQL: &str = concat!(
    "WITH doomed AS (",
    r1_doomed!(),
    "), ",
    "d_dev AS (DELETE FROM user_devices WHERE did IN (SELECT did FROM doomed) RETURNING 1), ",
    "d_sub AS (DELETE FROM activity_subscriptions WHERE subscriber_did IN (SELECT did FROM doomed) RETURNING 1), ",
    "d_thr AS (DELETE FROM thread_mutes WHERE user_did IN (SELECT did FROM doomed) RETURNING 1), ",
    "d_mut AS (DELETE FROM chat_muted_convos WHERE account_did IN (SELECT did FROM doomed) RETURNING 1), ",
    "d_wm AS (DELETE FROM chat_notified_watermarks WHERE account_did IN (SELECT did FROM doomed) RETURNING 1), ",
    "d_poll AS (DELETE FROM chat_poll_state WHERE account_did IN (SELECT did FROM doomed) RETURNING 1), ",
    "d_q AS (DELETE FROM push_event_queue WHERE recipient_did IN (SELECT did FROM doomed) RETURNING 1), ",
    "d_amv AS (DELETE FROM actor_moderation_verdict WHERE recipient_did IN (SELECT did FROM doomed) RETURNING 1), ",
    "d_acc AS (DELETE FROM push_accounts WHERE account_did IN (SELECT did FROM doomed) RETURNING 1) ",
    "SELECT 'push_accounts', count(*) FROM d_acc UNION ALL ",
    "SELECT 'push_preferences', count(*) FROM push_preferences WHERE account_did IN (SELECT did FROM doomed) UNION ALL ",
    "SELECT 'user_devices', count(*) FROM d_dev UNION ALL ",
    "SELECT 'activity_subscriptions', count(*) FROM d_sub UNION ALL ",
    "SELECT 'thread_mutes', count(*) FROM d_thr UNION ALL ",
    "SELECT 'chat_muted_convos', count(*) FROM d_mut UNION ALL ",
    "SELECT 'chat_notified_watermarks', count(*) FROM d_wm UNION ALL ",
    "SELECT 'chat_poll_state', count(*) FROM d_poll UNION ALL ",
    "SELECT 'push_event_queue', count(*) FROM d_q UNION ALL ",
    "SELECT 'actor_moderation_verdict', count(*) FROM d_amv"
);

/// R2 (inactive device tokens), dry-run.
const R2_COUNT_SQL: &str = "SELECT 'user_devices', count(*) FROM user_devices \
     WHERE is_active = false AND updated_at < now() - interval '90 days'";

/// R2 (inactive device tokens), apply: user_devices rows deactivated
/// (is_active = false) and untouched for more than 90 days.
const R2_APPLY_SQL: &str = "WITH d AS (DELETE FROM user_devices \
     WHERE is_active = false AND updated_at < now() - interval '90 days' RETURNING 1) \
     SELECT 'user_devices', count(*) FROM d";

/// Predicate for R3: the chat row's account has no live push_accounts row
/// (missing entirely, or revoked more than 30 days ago).
macro_rules! r3_orphan {
    ($t:literal) => {
        concat!(
            "NOT EXISTS (SELECT 1 FROM push_accounts pa WHERE pa.account_did = ",
            $t,
            ".account_did AND (pa.auth_revoked_at IS NULL OR pa.auth_revoked_at >= now() - interval '30 days')) AND ",
            no_notification_hold!(concat!($t, ".account_did"))
        )
    };
}

/// R3 (orphaned chat state), dry-run.
const R3_COUNT_SQL: &str = concat!(
    "SELECT 'chat_notified_watermarks', count(*) FROM chat_notified_watermarks c WHERE ",
    r3_orphan!("c"),
    " UNION ALL SELECT 'chat_muted_convos', count(*) FROM chat_muted_convos c WHERE ",
    r3_orphan!("c"),
    " UNION ALL SELECT 'chat_poll_state', count(*) FROM chat_poll_state c WHERE ",
    r3_orphan!("c")
);

/// R3 (orphaned chat state), apply: chat_notified_watermarks,
/// chat_muted_convos and chat_poll_state rows whose account has no
/// push_accounts row or was revoked more than 30 days ago.
const R3_APPLY_SQL: &str = concat!(
    "WITH w AS (DELETE FROM chat_notified_watermarks c WHERE ",
    r3_orphan!("c"),
    " RETURNING 1), m AS (DELETE FROM chat_muted_convos c WHERE ",
    r3_orphan!("c"),
    " RETURNING 1), p AS (DELETE FROM chat_poll_state c WHERE ",
    r3_orphan!("c"),
    " RETURNING 1) ",
    "SELECT 'chat_notified_watermarks', count(*) FROM w UNION ALL ",
    "SELECT 'chat_muted_convos', count(*) FROM m UNION ALL ",
    "SELECT 'chat_poll_state', count(*) FROM p"
);

/// R4 (legacy audit log), dry-run. Only run when the table exists with created_at.
const R4_COUNT_SQL: &str = "SELECT 'relationship_audit_log', count(*) FROM relationship_audit_log \
     WHERE created_at < now() - interval '90 days'";

/// R4 (legacy audit log), apply: relationship_audit_log rows older than 90 days.
const R4_APPLY_SQL: &str = "WITH d AS (DELETE FROM relationship_audit_log \
     WHERE created_at < now() - interval '90 days' RETURNING 1) \
     SELECT 'relationship_audit_log', count(*) FROM d";

/// R5 (expired legacy post cache), dry-run. Only run when the table exists with expires_at.
const R5_COUNT_SQL: &str = "SELECT 'post_cache', count(*) FROM post_cache WHERE expires_at < now()";

/// R5 (expired legacy post cache), apply: post_cache rows past expires_at.
const R5_APPLY_SQL: &str =
    "WITH d AS (DELETE FROM post_cache WHERE expires_at < now() RETURNING 1) \
     SELECT 'post_cache', count(*) FROM d";

/// A retention rule: its count/apply SQL and, for legacy tables, the
/// (table, column) that must exist before the rule may run.
struct Rule {
    name: &'static str,
    count_sql: &'static str,
    apply_sql: &'static str,
    requires: Option<(&'static str, &'static str)>,
}

const RULES: &[Rule] = &[
    Rule {
        name: "R1 revoked accounts (>180d, no active device)",
        count_sql: R1_COUNT_SQL,
        apply_sql: R1_APPLY_SQL,
        requires: None,
    },
    Rule {
        name: "R2 inactive device tokens (>90d)",
        count_sql: R2_COUNT_SQL,
        apply_sql: R2_APPLY_SQL,
        requires: None,
    },
    Rule {
        name: "R3 orphaned chat state (no account / revoked >30d)",
        count_sql: R3_COUNT_SQL,
        apply_sql: R3_APPLY_SQL,
        requires: None,
    },
    Rule {
        name: "R4 legacy audit log (>90d)",
        count_sql: R4_COUNT_SQL,
        apply_sql: R4_APPLY_SQL,
        requires: Some(("relationship_audit_log", "created_at")),
    },
    Rule {
        name: "R5 expired legacy post cache",
        count_sql: R5_COUNT_SQL,
        apply_sql: R5_APPLY_SQL,
        requires: Some(("post_cache", "expires_at")),
    },
];

// ── Output model ─────────────────────────────────────────────────────

/// One output line. Deliberately holds nothing but names and a count so no
/// secret can reach stdout by construction.
#[derive(Debug, Clone, PartialEq)]
enum Entry {
    Count {
        section: String,
        name: String,
        count: i64,
    },
    Skipped {
        section: String,
        name: String,
        reason: &'static str,
    },
}

fn count(section: &str, name: impl Into<String>, count: i64) -> Entry {
    Entry::Count {
        section: section.to_string(),
        name: name.into(),
        count,
    }
}

fn skipped(section: &str, name: impl Into<String>, reason: &'static str) -> Entry {
    Entry::Skipped {
        section: section.to_string(),
        name: name.into(),
        reason,
    }
}

/// Render a report. `did` is the operator-supplied DID (validated).
fn format_report(header: &str, did: Option<&str>, entries: &[Entry], notes: &[&str]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{header}");
    if let Some(did) = did {
        let _ = writeln!(out, "did: {did}");
    }
    let mut last_section = "";
    for e in entries {
        let section = match e {
            Entry::Count { section, .. } | Entry::Skipped { section, .. } => section.as_str(),
        };
        if section != last_section {
            let _ = writeln!(out, "[{section}]");
            last_section = section;
        }
        match e {
            Entry::Count { name, count, .. } => {
                let _ = writeln!(out, "  {name:<48} {count:>10}");
            }
            Entry::Skipped { name, reason, .. } => {
                let _ = writeln!(out, "  {name:<48} skipped: {reason}");
            }
        }
    }
    for n in notes {
        let _ = writeln!(out, "note: {n}");
    }
    out
}

const REDIS_INDEX_NOTE: &str =
    "session_index / session_fp_index keys are keyed by HMAC and cannot be \
     enumerated by DID; once their session blob and did_index are gone they are dead and expire by \
     TTL within 30 days.";

// ── Validation & connection helpers ──────────────────────────────────

/// Accept only DID-shaped input so the value is safe to echo and cannot carry
/// Redis glob metacharacters.
fn validate_did(did: &str) -> Result<()> {
    let ok = did.len() <= 2048
        && did.starts_with("did:")
        && did.splitn(3, ':').count() == 3
        && !did.ends_with(':')
        && did
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'%' | b'.' | b'_' | b'-'));
    if !ok {
        bail!("--did is not a valid DID");
    }
    Ok(())
}

fn resolve(flag: Option<String>, envs: &[&str], what: &str) -> Result<String> {
    if let Some(v) = flag {
        return Ok(v);
    }
    for e in envs {
        if let Ok(v) = std::env::var(e) {
            if !v.is_empty() {
                return Ok(v);
            }
        }
    }
    bail!("{what} not set (pass the flag or set {})", envs.join(" / "))
}

async fn connect_pg(url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .map_err(|_| anyhow::anyhow!("Failed to connect to Postgres"))
}

async fn connect_redis(url: &str) -> Result<redis::aio::ConnectionManager> {
    let client =
        redis::Client::open(url).map_err(|_| anyhow::anyhow!("Failed to open Redis connection"))?;
    redis::aio::ConnectionManager::new(client)
        .await
        .map_err(|_| anyhow::anyhow!("Failed to connect to Redis"))
}

/// Columns of `table` in the current schema, or None if it does not exist.
async fn table_columns(pool: &PgPool, table: &str) -> Result<Option<Vec<String>>> {
    let cols: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = $1",
    )
    .bind(table)
    .fetch_all(pool)
    .await?;
    Ok(if cols.is_empty() { None } else { Some(cols) })
}

/// Shape of each legacy table: Ok(Some(col)) = present with a DID column,
/// Ok(None) = absent, Err(()) = present but unknown shape.
async fn legacy_shapes(
    pool: &PgPool,
) -> Result<Vec<(&'static str, std::result::Result<Option<&'static str>, ()>)>> {
    let mut out = Vec::new();
    for t in LEGACY_TABLES {
        let shape = match table_columns(pool, t).await? {
            None => Ok(None),
            Some(cols) => LEGACY_DID_COLUMNS
                .iter()
                .find(|c| cols.iter().any(|x| x == *c))
                .map(|c| Some(*c))
                .ok_or(()),
        };
        out.push((*t, shape));
    }
    Ok(out)
}

// ── Redis ────────────────────────────────────────────────────────────

/// Escape Redis glob metacharacters (validate_did already forbids them; this
/// is defence in depth).
fn glob_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\' | '^') {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

/// Session blob keys for exactly this DID: `{prefix}session:{did}_{fp}`. The
/// fingerprint never contains `_`, which excludes a longer DID that happens to
/// share this DID as a prefix.
async fn session_keys_for_did(
    conn: &mut redis::aio::ConnectionManager,
    prefix: &str,
    did: &str,
    batch_size: usize,
) -> Result<Vec<String>> {
    let head = format!("{prefix}session:{did}_");
    let pattern = format!("{}*", glob_escape(&head));
    let mut cursor: u64 = 0;
    let mut keys = Vec::new();
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(batch_size)
            .query_async(conn)
            .await
            .context("Redis SCAN failed")?;
        keys.extend(batch.into_iter().filter(|k| {
            k.strip_prefix(&head)
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('_'))
        }));
        cursor = next;
        if cursor == 0 {
            break;
        }
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

struct RedisScope {
    session_keys: Vec<String>,
    did_index_key: String,
    did_index_exists: bool,
}

async fn redis_scope(
    conn: &mut redis::aio::ConnectionManager,
    prefix: &str,
    did: &str,
    batch_size: usize,
) -> Result<RedisScope> {
    let session_keys = session_keys_for_did(conn, prefix, did, batch_size).await?;
    let did_index_key = format!("{prefix}did_index:{did}");
    let exists: i64 = redis::cmd("EXISTS")
        .arg(&did_index_key)
        .query_async(conn)
        .await
        .context("Redis EXISTS failed")?;
    Ok(RedisScope {
        session_keys,
        did_index_key,
        did_index_exists: exists > 0,
    })
}

// ── Postgres per-DID ─────────────────────────────────────────────────

async fn pg_counts_for_did(pool: &PgPool, did: &str) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let deliveries: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM push_device_deliveries d JOIN push_event_receipts r USING (dedupe_key) WHERE r.recipient_did = $1",
    )
    .bind(did)
    .fetch_one(pool)
    .await
    .context("count push_device_deliveries")?;
    entries.push(count(
        "postgres (owned by DID)",
        "push_device_deliveries.recipient_via_receipt",
        deliveries,
    ));
    for (table, col) in OWNED_TABLES {
        let n: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM \"{table}\" WHERE \"{col}\" = $1"
        ))
        .bind(did)
        .fetch_one(pool)
        .await
        .with_context(|| format!("count {table}"))?;
        entries.push(count(
            "postgres (owned by DID)",
            format!("{table}.{col}"),
            n,
        ));
    }
    for (table, col) in REFERENCED_BY_OTHERS {
        let n: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM \"{table}\" WHERE \"{col}\" = $1"
        ))
        .bind(did)
        .fetch_one(pool)
        .await
        .with_context(|| format!("count {table}"))?;
        entries.push(count(
            "postgres (other accounts' rows naming DID; kept)",
            format!("{table}.{col}"),
            n,
        ));
    }
    for (table, shape) in legacy_shapes(pool).await? {
        match shape {
            Ok(Some(col)) => {
                let n: i64 = sqlx::query_scalar(&format!(
                    "SELECT count(*) FROM \"{table}\" WHERE \"{col}\" = $1"
                ))
                .bind(did)
                .fetch_one(pool)
                .await
                .with_context(|| format!("count {table}"))?;
                entries.push(count("postgres legacy", format!("{table}.{col}"), n));
            }
            Ok(None) => entries.push(skipped("postgres legacy", table, "absent")),
            Err(()) => entries.push(skipped("postgres legacy", table, "unknown shape")),
        }
    }
    Ok(entries)
}

/// Take every lock a Nest writer for this account could hold: the push
/// registry's account lock (services::push::lock), the chat-mute quota lock,
/// and the operator lock `hashtext(did)`. Push-account lock first, matching
/// Nest's account-then-device ordering.
async fn lock_account(tx: &mut Transaction<'_, Postgres>, did: &str) -> Result<()> {
    catbird::services::push::lock::acquire_account_lock(tx, did).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('chat_muted_convos:' || $1))")
        .bind(did)
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(did)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn pg_delete_for_did(pool: &PgPool, did: &str) -> Result<Vec<Entry>> {
    let shapes = legacy_shapes(pool).await?;
    let mut tx = pool.begin().await?;
    lock_account(&mut tx, did).await?;
    let mut entries = Vec::new();
    // Delete receipt children first; a registration may already have been
    // removed, so ownership is resolved through the durable event receipt.
    let deliveries = sqlx::query(
        "DELETE FROM push_device_deliveries d USING push_event_receipts r WHERE d.dedupe_key = r.dedupe_key AND r.recipient_did = $1",
    )
    .bind(did)
    .execute(&mut *tx)
    .await
    .context("delete push_device_deliveries")?;
    entries.push(count(
        "postgres deleted",
        "push_device_deliveries.recipient_via_receipt",
        deliveries.rows_affected() as i64,
    ));
    for (table, col) in OWNED_TABLES {
        let r = sqlx::query(&format!("DELETE FROM \"{table}\" WHERE \"{col}\" = $1"))
            .bind(did)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("delete {table}"))?;
        entries.push(count(
            "postgres deleted",
            format!("{table}.{col}"),
            r.rows_affected() as i64,
        ));
    }
    for (table, shape) in shapes {
        match shape {
            Ok(Some(col)) => {
                let r = sqlx::query(&format!("DELETE FROM \"{table}\" WHERE \"{col}\" = $1"))
                    .bind(did)
                    .execute(&mut *tx)
                    .await
                    .with_context(|| format!("delete {table}"))?;
                entries.push(count(
                    "postgres legacy deleted",
                    format!("{table}.{col}"),
                    r.rows_affected() as i64,
                ));
            }
            Ok(None) => entries.push(skipped("postgres legacy deleted", table, "absent")),
            Err(()) => entries.push(skipped("postgres legacy deleted", table, "unknown shape")),
        }
    }
    tx.commit().await.context("commit")?;
    Ok(entries)
}

// ── Commands ─────────────────────────────────────────────────────────

struct Conn {
    pool: PgPool,
    redis: Option<redis::aio::ConnectionManager>,
    prefix: String,
    batch_size: usize,
}

fn redis_entries(scope: &RedisScope, section: &str) -> Vec<Entry> {
    vec![
        count(
            section,
            "session:{did}_* (session blobs)",
            scope.session_keys.len() as i64,
        ),
        count(
            section,
            "did_index:{did}",
            i64::from(scope.did_index_exists),
        ),
    ]
}

async fn run_report(c: &mut Conn, did: &str) -> Result<String> {
    let mut entries = pg_counts_for_did(&c.pool, did).await?;
    let redis = c.redis.as_mut().context("Redis connection required")?;
    let scope = redis_scope(redis, &c.prefix, did, c.batch_size).await?;
    entries.extend(redis_entries(&scope, "redis"));
    Ok(format_report(
        "account_data report",
        Some(did),
        &entries,
        &[REDIS_INDEX_NOTE],
    ))
}

async fn run_delete(c: &mut Conn, did: &str, apply: bool) -> Result<String> {
    if !apply {
        let mut entries = pg_counts_for_did(&c.pool, did).await?;
        let redis = c.redis.as_mut().context("Redis connection required")?;
        let scope = redis_scope(redis, &c.prefix, did, c.batch_size).await?;
        entries.extend(redis_entries(&scope, "redis"));
        return Ok(format_report(
            "account_data delete (DRY RUN: nothing removed; pass --apply to delete \
             the 'owned by DID', 'legacy' and 'redis' rows)",
            Some(did),
            &entries,
            &[REDIS_INDEX_NOTE],
        ));
    }

    let mut entries = pg_delete_for_did(&c.pool, did).await?;
    let redis = c.redis.as_mut().context("Redis connection required")?;
    let scope = redis_scope(redis, &c.prefix, did, c.batch_size).await?;
    let mut removed_sessions: i64 = 0;
    for chunk in scope.session_keys.chunks(c.batch_size.max(1)) {
        let n: i64 = redis::cmd("DEL")
            .arg(chunk)
            .query_async(redis)
            .await
            .context("Redis DEL failed")?;
        removed_sessions += n;
    }
    let removed_index: i64 = redis::cmd("DEL")
        .arg(&scope.did_index_key)
        .query_async(redis)
        .await
        .context("Redis DEL failed")?;
    entries.push(count(
        "redis deleted",
        "session:{did}_* (session blobs)",
        removed_sessions,
    ));
    entries.push(count("redis deleted", "did_index:{did}", removed_index));
    Ok(format_report(
        "account_data delete (APPLIED)",
        Some(did),
        &entries,
        &[
            REDIS_INDEX_NOTE,
            "other accounts' rows naming this DID (subscriptions to it, queued events it \
             authored, verdicts about it) are kept.",
            "explicit account deletion also erases delivery deduplication history and catch-up holds; \
             a future sign-in and enrollment prime a fresh cursor. Retention and rollback must retain receipt history.",
        ],
    ))
}

async fn rule_runnable(pool: &PgPool, rule: &Rule) -> Result<bool> {
    match rule.requires {
        None => Ok(true),
        Some((table, col)) => Ok(table_columns(pool, table)
            .await?
            .is_some_and(|cols| cols.iter().any(|c| c == col))),
    }
}

async fn run_retention(c: &Conn, apply: bool) -> Result<String> {
    let mut entries = Vec::new();
    if apply {
        let mut runnable = Vec::new();
        for rule in RULES {
            runnable.push(rule_runnable(&c.pool, rule).await?);
        }
        let mut tx = c.pool.begin().await?;
        for (rule, ok) in RULES.iter().zip(runnable) {
            if !ok {
                entries.push(skipped(rule.name, "-", "table absent or unknown shape"));
                continue;
            }
            let rows: Vec<(String, i64)> = sqlx::query_as(rule.apply_sql)
                .fetch_all(&mut *tx)
                .await
                .with_context(|| format!("apply {}", rule.name))?;
            for (table, n) in rows {
                entries.push(count(rule.name, table, n));
            }
        }
        tx.commit().await.context("commit")?;
        Ok(format_report(
            "account_data retention (APPLIED, one transaction)",
            None,
            &entries,
            &[],
        ))
    } else {
        for rule in RULES {
            if !rule_runnable(&c.pool, rule).await? {
                entries.push(skipped(rule.name, "-", "table absent or unknown shape"));
                continue;
            }
            let rows: Vec<(String, i64)> = sqlx::query_as(rule.count_sql)
                .fetch_all(&c.pool)
                .await
                .with_context(|| format!("count {}", rule.name))?;
            for (table, n) in rows {
                entries.push(count(rule.name, table, n));
            }
        }
        Ok(format_report(
            "account_data retention (DRY RUN: nothing removed; pass --apply)",
            None,
            &entries,
            &["counts are per rule against current data; R1 rows may overlap R2/R3."],
        ))
    }
}

async fn run(cli: Cli) -> Result<String> {
    let db_url = resolve(
        cli.database_url,
        &["DATABASE_URL", "CATBIRD__PUSH__DATABASE_URL"],
        "database URL",
    )?;
    let pool = connect_pg(&db_url).await?;
    let needs_redis = !matches!(cli.command, Command::Retention { .. });
    let redis = if needs_redis {
        let url = resolve(
            cli.redis_url,
            &["REDIS_URL", "CATBIRD__REDIS__URL"],
            "Redis URL",
        )?;
        Some(connect_redis(&url).await?)
    } else {
        None
    };
    let mut conn = Conn {
        pool,
        redis,
        prefix: cli.prefix,
        batch_size: cli.batch_size.max(1),
    };
    match cli.command {
        Command::Report { did } => {
            validate_did(&did)?;
            run_report(&mut conn, &did).await
        }
        Command::Delete { did, apply } => {
            validate_did(&did)?;
            run_delete(&mut conn, &did, apply).await
        }
        Command::Retention { apply } => run_retention(&conn, apply).await,
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(out) => print!("{out}"),
        Err(e) => {
            // sqlx/redis errors carry no row data; connection errors are
            // already reduced to a fixed message above.
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_validation() {
        assert!(validate_did("did:plc:abc234").is_ok());
        assert!(validate_did("did:web:example.com%3A8080").is_ok());
        assert!(validate_did("did:plc:*").is_err());
        assert!(validate_did("did:plc:a?b").is_err());
        assert!(validate_did("not-a-did").is_err());
        assert!(validate_did("did:plc:").is_err());
        assert!(validate_did("did:plc:a b").is_err());
    }

    #[test]
    fn glob_escape_escapes_metachars() {
        assert_eq!(glob_escape("a*b?[c]\\"), "a\\*b\\?\\[c\\]\\\\");
    }

    #[test]
    fn format_contains_only_names_counts_and_did() {
        let entries = vec![
            count("postgres", "user_devices.did", 2),
            skipped("postgres legacy", "post_cache", "unknown shape"),
        ];
        let out = format_report("hdr", Some("did:plc:x"), &entries, &["n"]);
        assert!(out.contains("did: did:plc:x"));
        assert!(out.contains("user_devices.did"));
        assert!(out.contains("skipped: unknown shape"));
    }

    #[test]
    fn rule_sql_is_consistent() {
        for r in RULES {
            assert!(r.count_sql.starts_with("SELECT") || r.count_sql.starts_with("WITH"));
            assert!(r.apply_sql.contains("DELETE FROM"));
        }
    }
}
