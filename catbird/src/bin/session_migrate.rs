//! Session migration CLI for Catbird BFF (nest/catbird).
//!
//! Exports/imports Redis sessions (still encrypted) for server migration.
//! Sessions are transferred as raw bytes — no decryption needed.
//!
//! Usage:
//!   session_migrate export --redis-url redis://old:6379 --output sessions.json
//!   session_migrate import --redis-url redis://new:6379 --input sessions.json
//!   session_migrate verify --source redis://old:6379 --target redis://new:6379

use clap::{Parser, Subcommand};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

const DEFAULT_PREFIX: &str = "catbird:session:";
const DEFAULT_BATCH_SIZE: usize = 100;

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
    /// Categorisation: "session", "session_index", "auth_req", or "other"
    key_type: String,
}

// ── Helpers ──────────────────────────────────────────────────────────

async fn connect(url: &str) -> Result<redis::aio::ConnectionManager, anyhow::Error> {
    let client = redis::Client::open(url)?;
    let conn = redis::aio::ConnectionManager::new(client).await?;
    Ok(conn)
}

fn classify_key(key: &str, prefix: &str) -> String {
    let suffix = key.strip_prefix(prefix).unwrap_or(key);
    if suffix.starts_with("session:") {
        "session".into()
    } else if suffix.starts_with("session_index:") {
        "session_index".into()
    } else if suffix.starts_with("auth_req:") {
        "auth_req".into()
    } else {
        "other".into()
    }
}

/// SCAN for all keys matching `{prefix}*` and return them.
async fn scan_keys(
    conn: &mut redis::aio::ConnectionManager,
    prefix: &str,
    batch_size: usize,
) -> Result<Vec<String>, anyhow::Error> {
    let pattern = format!("{prefix}*");
    let mut keys: Vec<String> = Vec::new();
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
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }
    Ok(keys)
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ── Subcommands ─────────────────────────────────────────────────────

async fn run_export(
    redis_url: &str,
    output: &PathBuf,
    prefix: &str,
    batch_size: usize,
    dry_run: bool,
) -> Result<(), anyhow::Error> {
    eprintln!("Connecting to {redis_url} …");
    let mut conn = connect(redis_url).await?;

    eprintln!("Scanning for keys with prefix \"{prefix}\" …");
    let keys = scan_keys(&mut conn, prefix, batch_size).await?;
    eprintln!("Found {} keys", keys.len());

    if dry_run {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for k in &keys {
            *counts.entry(classify_key(k, prefix)).or_default() += 1;
        }
        eprintln!("Dry-run breakdown:");
        for (kt, n) in &counts {
            eprintln!("  {kt}: {n}");
        }
        return Ok(());
    }

    let mut exported: Vec<ExportedKey> = Vec::with_capacity(keys.len());
    let total = keys.len();

    for (i, key) in keys.iter().enumerate() {
        let value: Option<String> = conn.get(key).await?;
        let ttl: i64 = redis::cmd("TTL").arg(key).query_async(&mut conn).await?;

        if let Some(v) = value {
            exported.push(ExportedKey {
                key: key.clone(),
                value: v,
                ttl_seconds: ttl,
                key_type: classify_key(key, prefix),
            });
        }

        if (i + 1) % 100 == 0 || i + 1 == total {
            eprintln!("  exported {}/{total}", i + 1);
        }
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

    eprintln!(
        "Export contains {} keys (prefix \"{}\", exported at {})",
        export.keys.len(),
        export.prefix,
        export.exported_at
    );

    if dry_run {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for k in &export.keys {
            *counts.entry(k.key_type.clone()).or_default() += 1;
        }
        eprintln!("Dry-run breakdown:");
        for (kt, n) in &counts {
            eprintln!("  {kt}: {n}");
        }
        return Ok(());
    }

    eprintln!("Connecting to {redis_url} …");
    let mut conn = connect(redis_url).await?;

    let total = export.keys.len();
    let mut imported: usize = 0;
    let mut skipped: usize = 0;
    let mut failed: usize = 0;

    for chunk in export.keys.chunks(batch_size) {
        for entry in chunk {
            // Check existence unless --overwrite
            if !overwrite {
                let exists: bool = conn.exists(&entry.key).await?;
                if exists {
                    skipped += 1;
                    continue;
                }
            }

            let res: Result<(), redis::RedisError> = if entry.ttl_seconds > 0 {
                conn.set_ex(&entry.key, &entry.value, entry.ttl_seconds as u64)
                    .await
            } else {
                conn.set(&entry.key, &entry.value).await
            };

            match res {
                Ok(()) => imported += 1,
                Err(e) => {
                    eprintln!("  WARN: failed to import {}: {e}", entry.key);
                    failed += 1;
                }
            }
        }

        let done = imported + skipped + failed;
        if done % 100 == 0 || done == total {
            eprintln!("  progress: {done}/{total}");
        }
    }

    eprintln!("Done: imported {imported}, skipped {skipped} (already exist), failed {failed}");
    Ok(())
}

async fn run_verify(
    source_url: &str,
    target_url: &str,
    prefix: &str,
    spot_check: usize,
    batch_size: usize,
) -> Result<(), anyhow::Error> {
    eprintln!("Connecting to source ({source_url}) and target ({target_url}) …");
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
        for k in missing_from_target.iter().take(20) {
            eprintln!("  - {k}");
        }
        if missing_from_target.len() > 20 {
            eprintln!("  … and {} more", missing_from_target.len() - 20);
        }
    }

    if !extra_in_target.is_empty() {
        eprintln!(
            "ℹ {} keys in target not in source (new sessions?):",
            extra_in_target.len()
        );
        for k in extra_in_target.iter().take(10) {
            eprintln!("  - {k}");
        }
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
                eprintln!("  ✗ mismatch: {key}");
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
        Command::Export {
            redis_url,
            output,
            prefix,
            batch_size,
            dry_run,
        } => run_export(&redis_url, &output, &prefix, batch_size, dry_run).await,
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
