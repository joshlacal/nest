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
    /// Backfill session_fp_index and did_index for existing active sessions
    Backfill {
        /// Redis connection URL
        #[arg(long)]
        redis_url: String,
        /// Key prefix (default: "catbird:v2:session:")
        #[arg(long, default_value = "catbird:v2:session:")]
        prefix: String,
        /// Session encryption key (32-byte hex or base64 string)
        #[arg(long, env = "SESSION_ENCRYPTION_KEY")]
        encryption_key: Option<String>,
        /// Keys per SCAN iteration
        #[arg(long, default_value_t = DEFAULT_BATCH_SIZE)]
        batch_size: usize,
        /// Print what would be backfilled without writing
        #[arg(long)]
        dry_run: bool,
    },
    /// Rekey legacy raw-id session keys into the hashed v2 scheme (HMAC key names,
    /// v2 envelopes, session/did/fp indexes), deleting the raw-form keys afterward.
    Rekey {
        /// Redis connection URL
        #[arg(long)]
        redis_url: String,
        /// Key prefix (default: "catbird:v2:session:")
        #[arg(long, default_value = "catbird:v2:session:")]
        prefix: String,
        /// Session encryption key (32-byte hex or base64 string)
        #[arg(long, env = "SESSION_ENCRYPTION_KEY")]
        encryption_key: Option<String>,
        /// Keys per SCAN iteration
        #[arg(long, default_value_t = DEFAULT_BATCH_SIZE)]
        batch_size: usize,
        /// Print what would be rekeyed without writing
        #[arg(long)]
        dry_run: bool,
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

/// Redact userinfo and query parameters from a Redis connection URL for safe display/logging.
pub fn redact_redis_url(raw: &str) -> String {
    if let Ok(parsed) = url::Url::parse(raw) {
        let scheme = parsed.scheme();
        let host = match parsed.host_str() {
            Some(h) => h,
            None => return "<invalid-redis-url>".to_string(),
        };
        let port_part = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
        let path = parsed.path().trim_start_matches('/');
        let db_part = match path.parse::<u32>() {
            Ok(db) => format!("/{db}"),
            Err(_) => String::new(),
        };
        format!("{scheme}://{host}{port_part}{db_part}")
    } else {
        "<invalid-redis-url>".to_string()
    }
}

use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Securely writes export data to a file with owner-only permissions (mode 0600 on Unix),
/// exclusive creation semantics (no overwrite), and symlink rejection.
fn write_secure_export_file(output: &std::path::Path, data: &[u8]) -> Result<(), anyhow::Error> {
    if let Ok(meta) = std::fs::symlink_metadata(output) {
        if meta.file_type().is_symlink() {
            anyhow::bail!("Refusing to write to symlink: {}", output.display());
        }
        anyhow::bail!(
            "Export destination '{}' already exists. Overwriting is not permitted.",
            output.display()
        );
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);

    let mut file = opts.open(output).map_err(|e| {
        anyhow::anyhow!(
            "Failed to create private export file '{}': {e}",
            output.display()
        )
    })?;

    let write_res = (|| -> std::io::Result<()> {
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        drop(file);
        let _ = std::fs::remove_file(output);
        return Err(anyhow::anyhow!(
            "Failed writing export file '{}': {e}",
            output.display()
        ));
    }

    Ok(())
}

async fn connect(url: &str) -> Result<redis::aio::ConnectionManager, anyhow::Error> {
    let safe_url = redact_redis_url(url);
    let client = redis::Client::open(url)
        .map_err(|_| anyhow::anyhow!("Failed to open Redis connection at {safe_url}"))?;
    let conn = redis::aio::ConnectionManager::new(client)
        .await
        .map_err(|_| anyhow::anyhow!("Failed to connect to Redis at {safe_url}"))?;
    Ok(conn)
}

fn classify_key(key: &str, prefix: &str) -> String {
    let suffix = key.strip_prefix(prefix).unwrap_or(key);
    if suffix.starts_with("session:") {
        "session".into()
    } else if suffix.starts_with("session_index:")
        || suffix.starts_with("session_fp_index:")
        || suffix.starts_with("did_index:")
    {
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
        write_secure_export_file(output, json.as_bytes())?;
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
            "Dry run: would import {} keys to {}",
            export.keys.len(),
            redact_redis_url(redis_url)
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

    println!(
        "Scanning keys on source ({})...",
        redact_redis_url(source_url)
    );
    let src_keys = scan_keys(&mut src, prefix, batch_size).await?;
    println!(
        "Scanning keys on target ({})...",
        redact_redis_url(target_url)
    );
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
async fn run_backfill(
    redis_url: &str,
    prefix: &str,
    encryption_key: Option<&str>,
    batch_size: usize,
    dry_run: bool,
) -> Result<(), anyhow::Error> {
    let mut conn = connect(redis_url).await?;
    println!("Scanning session keys with prefix '{prefix}' for backfill...");
    let pattern = format!("{prefix}session:*");
    let mut cursor: u64 = 0;
    let mut session_keys = Vec::new();

    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(batch_size)
            .query_async(&mut conn)
            .await?;

        session_keys.extend(batch);
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }
    session_keys.sort();
    session_keys.dedup();
    println!(
        "Found {} session keys to inspect for backfill",
        session_keys.len()
    );

    let raw_key = encryption_key
        .map(|s| s.to_string())
        .or_else(|| std::env::var("SESSION_ENCRYPTION_KEY").ok())
        .or_else(|| std::env::var("CATBIRD_SESSION_ENCRYPTION_KEY").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("Encryption key is required for backfill to compute SHA-256 session fingerprints (set --encryption-key or SESSION_ENCRYPTION_KEY / CATBIRD_SESSION_ENCRYPTION_KEY)")
        })?;
    let key_bytes = parse_encryption_key(&raw_key)?;
    let mut backfilled = 0usize;
    let mut skipped = 0usize;

    for chunk in session_keys.chunks(batch_size) {
        let mut pipe = redis::pipe();
        for k in chunk {
            pipe.get(k).ttl(k);
        }
        let results: Vec<redis::Value> = pipe.query_async(&mut conn).await?;
        let mut it = results.into_iter();

        for k in chunk {
            let val_v = it.next().unwrap_or(redis::Value::Nil);
            let ttl_v = it.next().unwrap_or(redis::Value::Nil);

            let ttl_seconds = match ttl_v {
                redis::Value::Int(ttl) => ttl,
                _ => -1,
            };

            if ttl_seconds <= 0 {
                skipped += 1;
                continue;
            }

            let encrypted_data = match val_v {
                redis::Value::Data(bytes) => bytes,
                _ => {
                    skipped += 1;
                    continue;
                }
            };

            // Extract did and hmac_fp from session key: {prefix}session:{did}_{hmac_fp}
            let suffix = k.strip_prefix(prefix).unwrap_or(k);
            let rest = match suffix.strip_prefix("session:") {
                Some(r) => r,
                None => {
                    skipped += 1;
                    continue;
                }
            };

            let parts: Vec<&str> = rest.rsplitn(2, '_').collect();
            if parts.len() != 2 {
                skipped += 1;
                continue;
            }
            let hmac_fp = parts[0];
            let did = parts[1];

            // Check if retired
            let retired_key = format!("{prefix}upgrade_retired:{hmac_fp}");
            let is_retired: bool = redis::cmd("EXISTS")
                .arg(&retired_key)
                .query_async(&mut conn)
                .await
                .unwrap_or(true);

            if is_retired {
                skipped += 1;
                continue;
            }

            let enc_str = String::from_utf8_lossy(&encrypted_data);
            let json = catbird::services::redis_crypto::open_strict(&key_bytes, &enc_str)
                .map_err(|e| anyhow::anyhow!("Failed to decrypt session record '{k}': {e}"))?;
            let val = serde_json::from_str::<serde_json::Value>(&json).map_err(|e| {
                anyhow::anyhow!("Failed to parse decrypted session JSON for '{k}': {e}")
            })?;
            let sid = val
                .get("session_id")
                .and_then(|s| s.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("Session record '{k}' missing 'session_id' field in payload")
                })?;

            let sha256_fp = catbird::services::push::registry::session_fingerprint(sid);
            let did_index_key = format!("{prefix}did_index:{did}");
            let fp_index_key = format!("{prefix}session_fp_index:{sha256_fp}");

            if !dry_run {
                let mut pipe = redis::pipe();
                pipe.set_ex(&did_index_key, hmac_fp, ttl_seconds as u64);
                pipe.set_ex(&fp_index_key, hmac_fp, ttl_seconds as u64);
                let _: () = pipe.query_async(&mut conn).await?;
            }

            backfilled += 1;
        }
    }

    if !dry_run && backfilled == 0 {
        anyhow::bail!(
            "Backfill installed 0 fingerprint indexes (inspected {} keys, skipped {})",
            session_keys.len(),
            skipped
        );
    }

    if dry_run {
        println!("Dry run: would backfill {backfilled} sessions (skipped {skipped})");
    } else {
        println!("Successfully backfilled {backfilled} sessions (skipped {skipped})");
    }

    Ok(())
}

fn parse_encryption_key(raw_key: &str) -> anyhow::Result<[u8; 32]> {
    use base64::Engine;
    let trimmed = raw_key.trim();
    let bytes = if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut b = Vec::with_capacity(32);
        for i in (0..64).step_by(2) {
            let byte = u8::from_str_radix(&trimmed[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex character in encryption key: {e}"))?;
            b.push(byte);
        }
        b
    } else if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        b
    } else {
        anyhow::bail!("Encryption key must be 32 bytes (64 hex characters or base64)");
    };

    if bytes.len() != 32 {
        anyhow::bail!(
            "Encryption key must be exactly 32 bytes (got {} bytes)",
            bytes.len()
        );
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(key_bytes)
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
        Command::Backfill {
            redis_url,
            prefix,
            encryption_key,
            batch_size,
            dry_run,
        } => {
            run_backfill(
                &redis_url,
                &prefix,
                encryption_key.as_deref(),
                batch_size,
                dry_run,
            )
            .await
        }
        Command::Rekey {
            redis_url,
            prefix,
            encryption_key,
            batch_size,
            dry_run,
        } => {
            run_rekey(
                &redis_url,
                &prefix,
                encryption_key.as_deref(),
                batch_size,
                dry_run,
            )
            .await
        }
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
            classify_key("catbird:session:session_fp_index:sha1", "catbird:session:"),
            "session_index"
        );
        assert_eq!(
            classify_key("catbird:session:did_index:did1", "catbird:session:"),
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

    #[test]
    fn test_redact_redis_url() {
        assert_eq!(
            redact_redis_url("redis://127.0.0.1:6379"),
            "redis://127.0.0.1:6379"
        );
        assert_eq!(
            redact_redis_url("redis://default:secretpass@127.0.0.1:6379/2?foo=bar#frag"),
            "redis://127.0.0.1:6379/2"
        );
        assert_eq!(
            redact_redis_url("redis://default:secretpass@127.0.0.1:6379/0/SENTINEL_TOKEN?token=SENTINEL_QUERY#SENTINEL_FRAG"),
            "redis://127.0.0.1:6379"
        );
        assert_eq!(
            redact_redis_url("redis://:pass@localhost:6379/notanumber/SENTINEL"),
            "redis://localhost:6379"
        );
        assert_eq!(redact_redis_url("not a url"), "<invalid-redis-url>");
    }

    #[tokio::test]
    async fn test_connect_error_sanitizes_sentinels() {
        let sentinel_url = "redis://default:SECRET_PASSWORD@127.0.0.1:6379/0/SECRET_SENTINEL?token=SECRET_QUERY#SECRET_FRAG";
        let err = match connect(sentinel_url).await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Expected connection failure for invalid sentinel path/port"),
        };
        assert!(
            !err.contains("SECRET_PASSWORD"),
            "Error must not contain password: {err}"
        );
        assert!(
            !err.contains("SECRET_SENTINEL"),
            "Error must not contain sentinel path: {err}"
        );
        assert!(
            !err.contains("SECRET_QUERY"),
            "Error must not contain query params: {err}"
        );
        assert!(
            !err.contains("SECRET_FRAG"),
            "Error must not contain fragments: {err}"
        );
        assert!(
            err.contains("redis://127.0.0.1:6379"),
            "Error must contain safe redacted URL: {err}"
        );
    }

    #[test]
    fn test_write_secure_export_file_mode_and_create_new() {
        let temp_dir =
            std::env::temp_dir().join(format!("test_export_mode_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let export_path = temp_dir.join("sessions_export.json");
        let data = b"{\"version\":1,\"keys\":[]}";

        // First write succeeds
        let res = write_secure_export_file(&export_path, data);
        assert!(res.is_ok(), "Initial write should succeed: {:?}", res);
        assert!(export_path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::symlink_metadata(&export_path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "Export file must be created with mode 0600 (owner read/write only)"
            );
        }

        // Second write must fail because file exists and overwrite is not permitted
        let res2 = write_secure_export_file(&export_path, data);
        assert!(res2.is_err(), "Second write must fail on existing file");
        assert!(res2.unwrap_err().to_string().contains("already exists"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_write_secure_export_file_rejects_symlink() {
        let temp_dir =
            std::env::temp_dir().join(format!("test_export_symlink_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let target_file = temp_dir.join("legit_target.txt");
        std::fs::write(&target_file, b"original target").unwrap();

        let symlink_path = temp_dir.join("malicious_symlink.json");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target_file, &symlink_path).unwrap();

        #[cfg(unix)]
        {
            let res = write_secure_export_file(&symlink_path, b"malicious overwrite");
            assert!(res.is_err(), "Must reject writing to symlink");
            assert!(res.unwrap_err().to_string().contains("symlink"));
            assert_eq!(std::fs::read(&target_file).unwrap(), b"original target");
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_backfill_missing_encryption_key_fails_closed() {
        let res = run_backfill("redis://127.0.0.1:6379", "catbird:session:", None, 10, true).await;
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("Encryption key is required"),
            "Unexpected error: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_backfill_invalid_encryption_key_fails_closed() {
        let res = run_backfill(
            "redis://127.0.0.1:6379",
            "catbird:session:",
            Some("not-valid-hex-or-b64"),
            10,
            true,
        )
        .await;
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("Encryption key must be 32 bytes"),
            "Unexpected error: {err_msg}"
        );
    }

    #[test]
    fn test_parse_encryption_key_hex_and_base64() {
        use base64::Engine;
        // 32-byte hex string (64 hex characters)
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let parsed_hex =
            parse_encryption_key(hex_key).expect("64-char hex key must parse to 32 bytes");
        assert_eq!(parsed_hex[0], 0x01);
        assert_eq!(parsed_hex[15], 0xef);
        assert_eq!(parsed_hex[31], 0xef);

        // 32-byte base64 string (44 characters)
        let raw_32 = [42u8; 32];
        let b64_key = base64::engine::general_purpose::STANDARD.encode(raw_32);
        let parsed_b64 =
            parse_encryption_key(&b64_key).expect("44-char base64 key must parse to 32 bytes");
        assert_eq!(parsed_b64, raw_32);

        // Invalid length or chars fails
        assert!(parse_encryption_key("not-a-valid-key").is_err());
        assert!(parse_encryption_key("012345").is_err());
    }
}

/// Migrate legacy raw-id session keys (`{prefix}session:{did}_{uuid}`) into the
/// hashed v2 scheme the server actually reads: HMAC-fingerprint key names, v2
/// AAD envelopes, and the session/did/sha256-fp indexes. Raw-form keys and
/// their raw indexes are deleted after a successful rewrite.
async fn run_rekey(
    redis_url: &str,
    prefix: &str,
    encryption_key: Option<&str>,
    batch_size: usize,
    dry_run: bool,
) -> Result<(), anyhow::Error> {
    use catbird::services::{fingerprint_id, SESSION_INDEX_TTL_SECONDS};
    use catbird::services::redis_crypto::{
        open_session_dual_read, seal_v2_with_metadata, EnvelopeMetadata,
    };

    fn looks_like_raw_uuid(s: &str) -> bool {
        s.len() == 36
            && s.as_bytes()[8] == b'-'
            && s.as_bytes()[13] == b'-'
            && s.as_bytes()[18] == b'-'
            && s.as_bytes()[23] == b'-'
            && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    }

    /// Upgrade legacy session JSON shapes to the current jacquard schema:
    /// `scopes` was serialized as an array of strings; it is now a single
    /// space-delimited string.
    fn upgrade_session_json(mut v: serde_json::Value) -> serde_json::Value {
        if let Some(arr) = v.get("scopes").and_then(|s| s.as_array()) {
            let joined = arr
                .iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            v["scopes"] = serde_json::Value::String(joined);
        }
        v
    }

    let raw_key = encryption_key
        .map(|s| s.to_string())
        .or_else(|| std::env::var("SESSION_ENCRYPTION_KEY").ok())
        .or_else(|| std::env::var("CATBIRD_SESSION_ENCRYPTION_KEY").ok())
        .ok_or_else(|| anyhow::anyhow!("Encryption key required for rekey"))?;
    let key_bytes = parse_encryption_key(&raw_key)?;

    let mut conn = connect(redis_url).await?;
    println!("Scanning session keys with prefix '{prefix}' for rekey...");
    let pattern = format!("{prefix}session:*");
    let mut cursor: u64 = 0;
    let mut session_keys = Vec::new();
    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(batch_size)
            .query_async(&mut conn)
            .await?;
        session_keys.extend(batch);
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }
    session_keys.sort();
    session_keys.dedup();

    let mut rekeyed = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;

    for k in &session_keys {
        let suffix = k.strip_prefix(prefix).unwrap_or(k);
        let rest = match suffix.strip_prefix("session:") {
            Some(r) => r,
            None => continue,
        };
        let parts: Vec<&str> = rest.rsplitn(2, '_').collect();
        if parts.len() != 2 || !looks_like_raw_uuid(parts[0]) {
            // Hashed-form key: verify the payload parses under the current
            // schema; upgrade legacy JSON shapes in place when it does not.
            let (blob, ttl): (Option<String>, i64) = {
                let mut pipe = redis::pipe();
                pipe.get(k).ttl(k);
                let res: (Option<String>, i64) = pipe.query_async(&mut conn).await?;
                res
            };
            if let (Some(blob), ttl @ 1..) = (blob, ttl) {
                match catbird::services::redis_crypto::open_v2_with_metadata(&key_bytes, &blob, "session", k) {
                    Err(e) => {
                        eprintln!("rekey: hashed key '{k}' does not decrypt: {e}");
                        failed += 1;
                    }
                    Ok((plain, _meta, _is_v1)) => {
                        if serde_json::from_str::<jacquard_oauth::session::ClientSessionData>(&plain).is_ok() {
                            skipped += 1;
                        } else {
                            let v: serde_json::Value = match serde_json::from_str(&plain) {
                                Ok(v) => v,
                                Err(e) => {
                                    eprintln!("rekey: hashed key '{k}' payload is not JSON: {e}");
                                    failed += 1;
                                    continue;
                                }
                            };
                            let upgraded = upgrade_session_json(v);
                            let upgraded_str = serde_json::to_string(&upgraded)?;
                            match serde_json::from_str::<jacquard_oauth::session::ClientSessionData>(&upgraded_str) {
                                Ok(_) => {
                                    if dry_run {
                                        println!("would upgrade payload of {k} (ttl {ttl})");
                                    } else {
                                        let hashed_did = rest.rsplitn(2, '_').nth(1);
                                        let meta = EnvelopeMetadata::new("session", k, hashed_did, None);
                                        let v2 = seal_v2_with_metadata(&key_bytes, &upgraded_str, &meta)
                                            .map_err(|e| anyhow::anyhow!("rekey: reseal failed for '{k}': {e}"))?;
                                        let _: () = redis::cmd("SET")
                                            .arg(k)
                                            .arg(&v2)
                                            .arg("EX")
                                            .arg(ttl as u64)
                                            .query_async(&mut conn)
                                            .await?;
                                    }
                                    rekeyed += 1;
                                }
                                Err(e) => {
                                    eprintln!("rekey: hashed key '{k}' still fails typed parse after upgrade: {e}");
                                    failed += 1;
                                }
                            }
                        }
                    }
                }
            } else {
                skipped += 1;
            }
            continue;
        }
        let raw_sid = parts[0];
        let did = parts[1];

        let (blob, ttl): (Option<String>, i64) = {
            let mut pipe = redis::pipe();
            pipe.get(k).ttl(k);
            let res: (Option<String>, i64) = pipe.query_async(&mut conn).await?;
            res
        };
        let Some(blob) = blob else {
            skipped += 1;
            continue;
        };
        if ttl <= 0 {
            skipped += 1;
            continue;
        }

        let plain = if blob.starts_with('{') {
            // Pre-encryption era: session stored as plaintext JSON. Rekeying
            // seals it into the v2 envelope, removing plaintext at rest.
            blob.clone().into_bytes()
        } else {
            match open_session_dual_read(&key_bytes, &blob, &[]) {
                Ok((v, _is_v1)) => v,
                Err(e) => {
                    eprintln!("rekey: cannot decrypt '{k}': {e}");
                    failed += 1;
                    continue;
                }
            }
        };
        let json: serde_json::Value = match serde_json::from_slice(&plain) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("rekey: cannot parse session JSON for '{k}': {e}");
                failed += 1;
                continue;
            }
        };
        let sid_in_blob = json.get("session_id").and_then(|s| s.as_str()).unwrap_or("");
        let did_in_blob = json.get("account_did").and_then(|s| s.as_str()).unwrap_or("");
        if sid_in_blob != raw_sid || did_in_blob != did {
            eprintln!(
                "rekey: identity mismatch for '{k}' (payload sid/did do not match key parts); skipping"
            );
            failed += 1;
            continue;
        }

        let hmac_fp = fingerprint_id(&key_bytes, raw_sid);
        let sha256_fp = catbird::services::push::registry::session_fingerprint(raw_sid);
        let new_session_key = format!("{prefix}session:{did}_{hmac_fp}");
        let session_index_key = format!("{prefix}session_index:{hmac_fp}");
        let did_index_key = format!("{prefix}did_index:{did}");
        let fp_index_key = format!("{prefix}session_fp_index:{sha256_fp}");
        let old_raw_index = format!("{prefix}session_index:{raw_sid}");

        let upgraded = upgrade_session_json(json.clone());
        let json_str = serde_json::to_string(&upgraded)?;
        if let Err(e) = serde_json::from_str::<jacquard_oauth::session::ClientSessionData>(&json_str) {
            eprintln!("rekey: '{k}' fails typed parse even after upgrade: {e}");
            failed += 1;
            continue;
        }
        let meta = EnvelopeMetadata::new("session", &new_session_key, Some(did), None);
        let v2 = seal_v2_with_metadata(&key_bytes, &json_str, &meta)
            .map_err(|e| anyhow::anyhow!("rekey: reseal failed for '{k}': {e}"))?;

        if dry_run {
            if let Err(e) = serde_json::from_slice::<jacquard_oauth::session::ClientSessionData>(&plain) {
                eprintln!("typed-parse FAILS for {k}: {e}");
            }
            println!("would rekey {k} -> {new_session_key} (ttl {ttl})");
        } else {
            let index_ttl = (ttl as u64).max(SESSION_INDEX_TTL_SECONDS);
            let mut pipe = redis::pipe();
            pipe.set_ex(&new_session_key, &v2, ttl as u64);
            pipe.set_ex(&session_index_key, did, index_ttl);
            pipe.set_ex(&did_index_key, &hmac_fp, index_ttl);
            pipe.set_ex(&fp_index_key, &hmac_fp, index_ttl);
            pipe.del(k);
            pipe.del(&old_raw_index);
            let _: () = pipe.query_async(&mut conn).await?;
        }
        rekeyed += 1;
    }

    println!("Rekey complete: {rekeyed} rekeyed, {skipped} skipped, {failed} failed");
    if failed > 0 {
        anyhow::bail!("{failed} sessions failed to rekey");
    }
    Ok(())
}
