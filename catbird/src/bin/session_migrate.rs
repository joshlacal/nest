//! Session migration CLI for Catbird BFF (nest/catbird).
//!
//! Exports/imports Redis sessions (still encrypted) for server migration,
//! and verifies key count and sample data consistency across instances.
//!
//! Usage:
//!   session_migrate export --redis-url redis://old:6379 --output sessions.json
//!   session_migrate import --redis-url redis://new:6379 --input sessions.json
//!   session_migrate verify --source redis://old:6379 --target redis://new:6379

use std::collections::HashSet;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

const DEFAULT_PREFIX: &str = "catbird:session:";
const DEFAULT_BATCH_SIZE: usize = 100;

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "session_migrate",
    about = "Export, import, and verify Catbird BFF sessions in Redis",
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

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct ExportFile {
    version: u32,
    prefix: String,
    exported_at: String,
    keys: Vec<ExportedKey>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
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
    let mut cursor: u64 = 0;
    let mut all_keys = Vec::new();

    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(batch_size)
            .query_async(conn)
            .await?;

        all_keys.extend(batch);
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }

    all_keys.sort();
    all_keys.dedup();
    Ok(all_keys)
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
    let mut conn = connect(redis_url).await?;
    println!("Scanning keys with prefix '{prefix}'...");
    let keys = scan_keys(&mut conn, prefix, batch_size).await?;
    println!("Found {} keys", keys.len());

    let mut exported_keys = Vec::with_capacity(keys.len());

    for chunk in keys.chunks(batch_size) {
        let mut pipe = redis::pipe();
        for key in chunk {
            pipe.get(key).ttl(key);
        }
        let results: Vec<redis::Value> = pipe.query_async(&mut conn).await?;

        let mut it = results.into_iter();
        for key in chunk {
            let val_v = it.next().unwrap_or(redis::Value::Nil);
            let ttl_v = it.next().unwrap_or(redis::Value::Nil);

            let value = match val_v {
                redis::Value::Data(bytes) => {
                    String::from_utf8(bytes).unwrap_or_else(|_| "<binary>".into())
                }
                redis::Value::Nil => continue,
                _ => "<unsupported>".into(),
            };

            let ttl_seconds = match ttl_v {
                redis::Value::Int(ttl) => ttl,
                _ => -1,
            };

            let key_type = classify_key(key, prefix);

            exported_keys.push(ExportedKey {
                key: key.clone(),
                value,
                ttl_seconds,
                key_type,
            });
        }
    }

    let export = ExportFile {
        version: 1,
        prefix: prefix.to_string(),
        exported_at: now_iso(),
        keys: exported_keys,
    };

    let count = export.keys.len();
    if dry_run {
        println!("Dry run: would write {count} keys to {}", output.display());
    } else {
        let json = serde_json::to_string_pretty(&export)?;
        tokio::fs::write(output, json).await?;
        println!("Exported {count} keys to {}", output.display());
    }

    Ok(())
}

async fn run_import(
    redis_url: &str,
    input: &PathBuf,
    dry_run: bool,
    batch_size: usize,
    overwrite: bool,
) -> Result<(), anyhow::Error> {
    let data = tokio::fs::read_to_string(input).await?;
    let export: ExportFile = serde_json::from_str(&data)?;
    println!(
        "Importing {} keys from {} (version={}, prefix='{}')",
        export.keys.len(),
        input.display(),
        export.version,
        export.prefix
    );

    if dry_run {
        println!(
            "Dry run: would import {} keys to {redis_url}",
            export.keys.len()
        );
        return Ok(());
    }

    let mut conn = connect(redis_url).await?;
    let mut imported = 0usize;
    let mut skipped = 0usize;

    for chunk in export.keys.chunks(batch_size) {
        let mut pipe = redis::pipe();
        let mut to_set = Vec::new();

        if !overwrite {
            let mut check_pipe = redis::pipe();
            for item in chunk {
                check_pipe.exists(&item.key);
            }
            let exists_res: Vec<bool> = check_pipe.query_async(&mut conn).await?;
            for (item, exists) in chunk.iter().zip(exists_res) {
                if exists {
                    skipped += 1;
                } else {
                    to_set.push(item);
                }
            }
        } else {
            to_set.extend(chunk.iter());
        }

        for item in &to_set {
            if item.ttl_seconds > 0 {
                pipe.set_ex(&item.key, &item.value, item.ttl_seconds as u64);
            } else if item.ttl_seconds == -1 {
                pipe.set(&item.key, &item.value);
            }
        }

        if !to_set.is_empty() {
            let _: () = pipe.query_async(&mut conn).await?;
            imported += to_set.len();
        }
    }

    println!("Import complete: {imported} imported, {skipped} skipped");
    Ok(())
}

async fn run_verify(
    source_url: &str,
    target_url: &str,
    prefix: &str,
    spot_check: usize,
    batch_size: usize,
) -> Result<(), anyhow::Error> {
    let mut src = connect(source_url).await?;
    let mut tgt = connect(target_url).await?;

    println!("Scanning keys on source ({source_url})...");
    let src_keys = scan_keys(&mut src, prefix, batch_size).await?;
    println!("Scanning keys on target ({target_url})...");
    let tgt_keys = scan_keys(&mut tgt, prefix, batch_size).await?;

    let src_set: HashSet<_> = src_keys.iter().collect();
    let tgt_set: HashSet<_> = tgt_keys.iter().collect();

    let missing_on_target = src_set.difference(&tgt_set).count();
    let extra_on_target = tgt_set.difference(&src_set).count();

    println!("── Key Count Summary ──");
    println!("  Source keys: {}", src_keys.len());
    println!("  Target keys: {}", tgt_keys.len());
    println!("  Missing on target: {missing_on_target}");
    println!("  Extra on target:   {extra_on_target}");

    let mut mismatches = 0usize;

    if spot_check > 0 && !src_keys.is_empty() {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let sample_keys: Vec<_> = src_keys
            .choose_multiple(&mut rng, spot_check.min(src_keys.len()))
            .cloned()
            .collect();

        println!(
            "── Spot-checking {} sampled keys for value equality ──",
            sample_keys.len()
        );
        for key in &sample_keys {
            let src_val: Option<String> = src.get(key).await?;
            let tgt_val: Option<String> = tgt.get(key).await?;

            if src_val != tgt_val {
                println!("  MISMATCH: key={key}");
                mismatches += 1;
            }
        }
        if mismatches == 0 {
            println!("  All spot-checked keys matched perfectly.");
        }
    }

    if missing_on_target == 0 && extra_on_target == 0 && mismatches == 0 {
        println!("\nVerification PASSED: Source and target Redis are consistent.");
        Ok(())
    } else {
        anyhow::bail!(
            "Verification FAILED: {missing_on_target} missing, {extra_on_target} extra, \
             {mismatches} value mismatches"
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_key() {
        assert_eq!(
            classify_key("catbird:session:session:user1", "catbird:session:"),
            "session"
        );
        assert_eq!(
            classify_key("catbird:session:session_index:idx1", "catbird:session:"),
            "session_index"
        );
        assert_eq!(
            classify_key("catbird:session:auth_req:req1", "catbird:session:"),
            "auth_req"
        );
        assert_eq!(
            classify_key("catbird:session:other_key", "catbird:session:"),
            "other"
        );
    }

    #[test]
    fn test_export_file_serde() {
        let export = ExportFile {
            version: 1,
            prefix: "catbird:session:".into(),
            exported_at: "2026-08-24T00:00:00Z".into(),
            keys: vec![ExportedKey {
                key: "catbird:session:session:1".into(),
                value: "enc_data".into(),
                ttl_seconds: 3600,
                key_type: "session".into(),
            }],
        };

        let json = serde_json::to_string(&export).unwrap();
        let deserialized: ExportFile = serde_json::from_str(&json).unwrap();
        assert_eq!(export, deserialized);
    }
}
