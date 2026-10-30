//! End-to-end tests for the `account_data` operator CLI.
//!
//! Each test creates a throwaway Postgres database (migrated with Nest's
//! migrations) and a unique Redis key prefix, runs the compiled binary
//! against them, and inspects the resulting state.
//!
//! Requires a local Postgres (`DATABASE_URL`, default
//! `postgres://localhost/postgres`, able to CREATE DATABASE) and Redis
//! (`REDIS_URL`, default `redis://127.0.0.1:6379`); ignored otherwise.

use std::collections::BTreeMap;
use std::process::Command;

use redis::AsyncCommands;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

const A: &str = "did:plc:accountdataaaaa";
const B: &str = "did:plc:accountdatabbbbb";

const SESSION_SECRET_A: &str = "SESSIONSECRET-aaaa-0001";
const SESSION_SECRET_B: &str = "SESSIONSECRET-bbbb-0002";
const FP_A1: &str = "f1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const FP_A2: &str = "f2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
const FP_B1: &str = "f3b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
const REDIS_BLOB: &str = "REDISBLOB-ciphertext-secret";

fn device_token(tag: &str) -> String {
    format!("DEVICETOKEN-{tag}-0123456789abcdef")
}

// ── Harness ──────────────────────────────────────────────────────────

struct TestEnv {
    admin_pool: Pool<Postgres>,
    db_name: String,
    db_url: String,
    pool: Pool<Postgres>,
    redis_url: String,
    redis: redis::aio::ConnectionManager,
    prefix: String,
}

impl TestEnv {
    async fn new() -> Self {
        let base_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/postgres".to_string());
        let admin_pool = Pool::<Postgres>::connect(&base_url)
            .await
            .expect("admin postgres");
        let db_name = format!("test_account_data_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&admin_pool)
            .await
            .expect("create test database");
        let mut url = url::Url::parse(&base_url).unwrap();
        url.set_path(&db_name);
        let db_url = url.to_string();
        let pool = Pool::<Postgres>::connect(&db_url)
            .await
            .expect("test database");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations");

        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let redis =
            redis::aio::ConnectionManager::new(redis::Client::open(redis_url.as_str()).unwrap())
                .await
                .expect("redis");
        let prefix = format!("catbird:v2:test_acctdata_{}:", Uuid::new_v4().simple());
        Self {
            admin_pool,
            db_name,
            db_url,
            pool,
            redis_url,
            redis,
            prefix,
        }
    }

    /// Run the binary; returns (success, stdout, stderr).
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_account_data"))
            .args(args)
            .env("DATABASE_URL", &self.db_url)
            .env("REDIS_URL", &self.redis_url)
            .env("CATBIRD__REDIS__KEY_PREFIX", &self.prefix)
            .output()
            .expect("spawn account_data");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn run_ok(&self, args: &[&str]) -> String {
        let (ok, stdout, stderr) = self.run(args);
        assert!(ok, "account_data {args:?} failed: {stderr}\n{stdout}");
        assert_no_secrets(&stdout);
        assert_no_secrets(&stderr);
        stdout
    }

    async fn redis_keys(&mut self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .redis
            .keys(format!("{}*", self.prefix))
            .await
            .expect("redis keys");
        keys.sort();
        keys
    }

    async fn cleanup(mut self) {
        let keys = self.redis_keys().await;
        if !keys.is_empty() {
            let _: i64 = self.redis.del(keys).await.unwrap_or(0);
        }
        self.pool.close().await;
        let _ = sqlx::query(&format!(
            "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
            self.db_name
        ))
        .execute(&self.admin_pool)
        .await;
    }

    async fn exec(&self, sql: &str) {
        sqlx::query(sql)
            .execute(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }

    /// Total row count of every table we care about, for no-change checks.
    async fn snapshot(&self) -> BTreeMap<String, i64> {
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT table_name::text FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' \
             AND table_name <> '_sqlx_migrations'",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap();
        let mut m = BTreeMap::new();
        for t in tables {
            let n = self.count(&format!("SELECT count(*) FROM \"{t}\"")).await;
            m.insert(t, n);
        }
        m
    }
}

fn assert_no_secrets(s: &str) {
    for needle in [
        SESSION_SECRET_A,
        SESSION_SECRET_B,
        FP_A1,
        FP_A2,
        FP_B1,
        REDIS_BLOB,
        "DEVICETOKEN",
        "SESSIONSECRET",
    ] {
        assert!(!s.contains(needle), "output leaked {needle}:\n{s}");
    }
}

/// Parse `[section]` / `  name   count` lines into (section, name) -> count.
fn parse_counts(out: &str) -> BTreeMap<(String, String), i64> {
    let mut m = BTreeMap::new();
    let mut section = String::new();
    for line in out.lines() {
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.to_string();
        } else if let Some(rest) = line.strip_prefix("  ") {
            let mut parts = rest.rsplitn(2, ' ');
            let last = parts.next().unwrap_or_default();
            let name = parts.next().unwrap_or_default().trim();
            if let Ok(n) = last.parse::<i64>() {
                m.insert((section.clone(), name.to_string()), n);
            }
        }
    }
    m
}

fn get(m: &BTreeMap<(String, String), i64>, section_prefix: &str, name: &str) -> i64 {
    m.iter()
        .find(|((s, n), _)| s.starts_with(section_prefix) && n == name)
        .map(|(_, v)| *v)
        .unwrap_or_else(|| panic!("no count for [{section_prefix}] {name} in {m:?}"))
}

// ── Seeding ──────────────────────────────────────────────────────────

/// Seeds one row (or more) for `did` in every Nest-owned table.
/// `revoked_days`: Some(n) sets auth_revoked_at = now() - n days.
/// `device`: (is_active, updated_days_ago).
async fn seed_account(
    env: &TestEnv,
    did: &str,
    session_secret: &str,
    revoked_days: Option<i32>,
    device: Option<(bool, i32)>,
    tag: &str,
) {
    let revoked = match revoked_days {
        Some(d) => format!("now() - interval '{d} days'"),
        None => "NULL".to_string(),
    };
    env.exec(&format!(
        "INSERT INTO push_accounts (account_did, session_id, pds_url, auth_revoked_at, session_fingerprint) \
         VALUES ('{did}', '{session_secret}', 'https://pds.example.com', {revoked}, encode(sha256('{session_secret}'::bytea), 'hex'))"
    ))
    .await;
    env.exec(&format!(
        "INSERT INTO push_preferences (account_did, preferences_json) VALUES ('{did}', '{{}}'::jsonb)"
    ))
    .await;
    if let Some((active, days)) = device {
        env.exec(&format!(
            "INSERT INTO user_devices (did, device_token, is_active, updated_at) \
             VALUES ('{did}', '{}', {active}, now() - interval '{days} days')",
            device_token(tag)
        ))
        .await;
    }
    seed_chat_and_misc(env, did, tag).await;
}

async fn seed_chat_and_misc(env: &TestEnv, did: &str, tag: &str) {
    env.exec(&format!(
        "INSERT INTO thread_mutes (user_did, thread_root_uri) VALUES ('{did}', 'at://{did}/app.bsky.feed.post/{tag}')"
    ))
    .await;
    seed_chat(env, did, tag).await;
    env.exec(&format!(
        "INSERT INTO push_event_queue (recipient_did, actor_did, notification_type, event_cid, event_path, \
         event_record_json, event_timestamp, dedupe_key) \
         VALUES ('{did}', 'did:plc:someactor', 'like', 'cid', 'path', '{{}}'::jsonb, 1, 'dedupe-{tag}')"
    ))
    .await;
    env.exec(&format!(
        "INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict) \
         VALUES ('{did}', 'did:plc:someactor{tag}', '{{}}'::jsonb)"
    ))
    .await;
}

async fn seed_chat(env: &TestEnv, did: &str, tag: &str) {
    env.exec(&format!(
        "INSERT INTO chat_muted_convos (account_did, convo_id) VALUES ('{did}', 'convo-{tag}')"
    ))
    .await;
    env.exec(&format!(
        "INSERT INTO chat_notified_watermarks (account_did, convo_id, last_rev) VALUES ('{did}', 'convo-{tag}', 'rev1')"
    ))
    .await;
    env.exec(&format!(
        "INSERT INTO chat_poll_state (account_did, pds_host) VALUES ('{did}', 'pds.example.com')"
    ))
    .await;
}

async fn create_legacy_tables(env: &TestEnv) {
    env.exec(
        "CREATE TABLE relationship_audit_log (id BIGSERIAL PRIMARY KEY, user_did TEXT NOT NULL, \
         device_token TEXT, action TEXT NOT NULL, details JSONB, \
         created_at TIMESTAMPTZ NOT NULL DEFAULT now(), using_hashed_dids BOOLEAN NOT NULL DEFAULT false)",
    )
    .await;
    env.exec(
        "CREATE TABLE post_cache (uri TEXT PRIMARY KEY, text TEXT, expires_at TIMESTAMPTZ NOT NULL, \
         created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())",
    )
    .await;
    // Present but with no recognised DID column: must be skipped.
    env.exec("CREATE TABLE user_blocks_hashed (user_did_hash TEXT NOT NULL, blocked_hash TEXT)")
        .await;
}

/// Two accounts, cross-subscribed, plus legacy rows and Redis sessions.
async fn seed_two_accounts(env: &mut TestEnv) {
    seed_account(env, A, SESSION_SECRET_A, None, Some((true, 0)), "a").await;
    seed_account(env, B, SESSION_SECRET_B, None, Some((true, 0)), "b").await;
    env.exec(&format!(
        "INSERT INTO user_devices (did, device_token, is_active) VALUES ('{A}', '{}', false)",
        device_token("a2")
    ))
    .await;
    env.exec(&format!(
        "INSERT INTO activity_subscriptions (subscriber_did, subject_did) VALUES ('{A}', '{B}'), ('{B}', '{A}')"
    ))
    .await;
    // B's queued event authored by A, and B's verdict about A: B's data.
    env.exec(&format!(
        "INSERT INTO push_event_queue (recipient_did, actor_did, notification_type, event_cid, event_path, \
         event_record_json, event_timestamp, dedupe_key) \
         VALUES ('{B}', '{A}', 'reply', 'cid', 'path', '{{}}'::jsonb, 2, 'dedupe-b-from-a')"
    ))
    .await;
    env.exec(&format!(
        "INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict) VALUES ('{B}', '{A}', '{{}}'::jsonb)"
    ))
    .await;

    create_legacy_tables(env).await;
    for did in [A, B] {
        env.exec(&format!(
            "INSERT INTO relationship_audit_log (user_did, device_token, action) VALUES ('{did}', '{}', 'block')",
            device_token(&format!("legacy-{did}"))
        ))
        .await;
        env.exec(&format!(
            "INSERT INTO post_cache (uri, text, expires_at) VALUES ('at://{did}/p/1', 'hi', now() + interval '1 day')"
        ))
        .await;
    }

    let p = env.prefix.clone();
    let pairs = [
        (format!("{p}session:{A}_{FP_A1}"), REDIS_BLOB),
        (format!("{p}session:{A}_{FP_A2}"), REDIS_BLOB),
        (format!("{p}did_index:{A}"), FP_A1),
        (format!("{p}session:{B}_{FP_B1}"), REDIS_BLOB),
        (format!("{p}did_index:{B}"), FP_B1),
        // A longer DID sharing A as a prefix must not be touched.
        (format!("{p}session:{A}_extra_{FP_B1}"), REDIS_BLOB),
        // HMAC index key: not enumerable by DID, must be left alone.
        (format!("{p}session_index:{FP_A1}"), REDIS_BLOB),
    ];
    for (k, v) in pairs {
        let _: () = env.redis.set_ex(k, v, 600).await.unwrap();
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires local Postgres"]
async fn report_and_dry_runs_change_nothing() {
    let mut env = TestEnv::new().await;
    seed_two_accounts(&mut env).await;
    let before = env.snapshot().await;
    let keys_before = env.redis_keys().await;

    let report = env.run_ok(&["report", "--did", A]);
    assert!(report.contains(&format!("did: {A}")));
    let m = parse_counts(&report);
    assert_eq!(get(&m, "postgres (owned", "user_devices.did"), 2);
    assert_eq!(get(&m, "postgres (owned", "push_accounts.account_did"), 1);
    assert_eq!(
        get(&m, "postgres (owned", "push_preferences.account_did"),
        1
    );
    assert_eq!(
        get(
            &m,
            "postgres (owned",
            "activity_subscriptions.subscriber_did"
        ),
        1
    );
    assert_eq!(
        get(&m, "postgres (other", "activity_subscriptions.subject_did"),
        1
    );
    assert_eq!(get(&m, "postgres (other", "push_event_queue.actor_did"), 1);
    assert_eq!(
        get(&m, "postgres legacy", "relationship_audit_log.user_did"),
        1
    );
    assert_eq!(get(&m, "redis", "session:{did}_* (session blobs)"), 2);
    assert_eq!(get(&m, "redis", "did_index:{did}"), 1);
    assert!(report.contains("user_blocks_hashed"));
    assert!(report.contains("skipped: unknown shape"));
    assert!(report.contains("expire by TTL within 30 days"));

    let dry = env.run_ok(&["delete", "--did", A]);
    assert!(dry.contains("DRY RUN"));
    let dry_ret = env.run_ok(&["retention"]);
    assert!(dry_ret.contains("DRY RUN"));

    assert_eq!(
        env.snapshot().await,
        before,
        "dry runs must not change Postgres"
    );
    assert_eq!(
        env.redis_keys().await,
        keys_before,
        "dry runs must not change Redis"
    );
    env.cleanup().await;
}

#[tokio::test]
#[ignore = "requires local Postgres"]
async fn delete_apply_removes_only_target_account() {
    let mut env = TestEnv::new().await;
    seed_two_accounts(&mut env).await;
    let b_rows_before = b_rows(&env).await;

    let out = env.run_ok(&["delete", "--did", A, "--apply"]);
    assert!(out.contains("APPLIED"));
    let m = parse_counts(&out);
    assert_eq!(get(&m, "postgres deleted", "user_devices.did"), 2);
    assert_eq!(
        get(&m, "redis deleted", "session:{did}_* (session blobs)"),
        2
    );

    for (table, col) in [
        ("push_accounts", "account_did"),
        ("push_preferences", "account_did"),
        ("user_devices", "did"),
        ("activity_subscriptions", "subscriber_did"),
        ("thread_mutes", "user_did"),
        ("chat_muted_convos", "account_did"),
        ("chat_notified_watermarks", "account_did"),
        ("chat_poll_state", "account_did"),
        ("push_event_queue", "recipient_did"),
        ("actor_moderation_verdict", "recipient_did"),
        ("relationship_audit_log", "user_did"),
    ] {
        let n = env
            .count(&format!("SELECT count(*) FROM {table} WHERE {col} = '{A}'"))
            .await;
        assert_eq!(n, 0, "{table}.{col} still has A rows");
    }
    assert_eq!(b_rows(&env).await, b_rows_before, "B's rows must be intact");
    // B's subscription to A, B's event authored by A, B's verdict about A stay.
    assert_eq!(
        env.count(&format!(
            "SELECT count(*) FROM activity_subscriptions WHERE subscriber_did = '{B}' AND subject_did = '{A}'"
        ))
        .await,
        1
    );
    assert_eq!(
        env.count(&format!(
            "SELECT count(*) FROM push_event_queue WHERE recipient_did = '{B}' AND actor_did = '{A}'"
        ))
        .await,
        1
    );
    // post_cache has no DID column: untouched.
    assert_eq!(env.count("SELECT count(*) FROM post_cache").await, 2);

    let p = env.prefix.clone();
    let keys = env.redis_keys().await;
    let expected = {
        let mut v = vec![
            format!("{p}did_index:{B}"),
            format!("{p}session:{A}_extra_{FP_B1}"),
            format!("{p}session:{B}_{FP_B1}"),
            format!("{p}session_index:{FP_A1}"),
        ];
        v.sort();
        v
    };
    assert_eq!(keys, expected);
    env.cleanup().await;
}

#[tokio::test]
#[ignore = "requires local Postgres and Redis"]
async fn notification_history_requires_explicit_account_deletion() {
    let env = TestEnv::new().await;
    let c = "did:plc:completednotification";
    for (did, tag, event_state, device_state) in [
        (A, "held-a", "held", "held"),
        (B, "held-b", "completed", "attempting"),
        (c, "completed-c", "completed", "accepted"),
    ] {
        seed_account(&env, did, "fixture-session", Some(200), None, tag).await;
        env.exec(&format!(
            "INSERT INTO push_event_receipts (dedupe_key, recipient_did, auth_generation, state) \
             VALUES ('dedupe-{tag}', '{did}', 1, '{event_state}')"
        ))
        .await;
        // Device receipts outlive registration rows; deletion must join the
        // event owner rather than relying on a surviving user_devices row.
        env.exec(&format!(
            "INSERT INTO push_device_deliveries (dedupe_key, device_id, state) \
             VALUES ('dedupe-{tag}', gen_random_uuid(), '{device_state}')"
        ))
        .await;
        env.exec(&format!(
            "INSERT INTO chat_mute_sync_generations (account_did, generation) VALUES ('{did}', 5)"
        ))
        .await;
    }
    env.exec(&format!(
        "UPDATE chat_poll_state SET chat_cursor='retained-cursor', primed_at=now(), \
         catch_up_required_at=now(), catch_up_reason='stale_fixture' WHERE account_did='{A}'"
    ))
    .await;
    env.exec(&format!(
        "UPDATE push_event_queue SET delivery_hold_reason='fixture_hold' WHERE recipient_did='{A}'"
    ))
    .await;

    let before = env.snapshot().await;
    let report = parse_counts(&env.run_ok(&["report", "--did", A]));
    for name in [
        "push_device_deliveries.recipient_via_receipt",
        "push_event_receipts.recipient_did",
        "chat_mute_sync_generations.account_did",
    ] {
        assert_eq!(get(&report, "postgres (owned", name), 1, "{name}");
    }
    env.run_ok(&["delete", "--did", A]);
    env.run_ok(&["retention"]);
    assert_eq!(
        env.snapshot().await,
        before,
        "dry runs must preserve all history"
    );

    env.run_ok(&["retention", "--apply"]);
    for did in [A, B] {
        assert_eq!(
            env.count(&format!(
                "SELECT count(*) FROM push_accounts WHERE account_did='{did}'"
            ))
            .await,
            1
        );
        assert_eq!(
            env.count(&format!(
                "SELECT count(*) FROM chat_poll_state WHERE account_did='{did}'"
            ))
            .await,
            1
        );
    }
    assert_eq!(env.count(&format!("SELECT count(*) FROM chat_poll_state WHERE account_did='{A}' AND chat_cursor='retained-cursor' AND catch_up_required_at IS NOT NULL")).await, 1);
    assert_eq!(env.count(&format!("SELECT count(*) FROM push_event_queue WHERE recipient_did='{A}' AND delivery_hold_reason='fixture_hold'")).await, 1);
    assert_eq!(
        env.count(&format!(
            "SELECT count(*) FROM push_accounts WHERE account_did='{c}'"
        ))
        .await,
        0
    );
    for table in [
        "push_event_receipts",
        "push_device_deliveries",
        "chat_mute_sync_generations",
    ] {
        assert_eq!(
            env.count(&format!("SELECT count(*) FROM {table}")).await,
            3,
            "retention pruned {table}"
        );
    }

    let deleted = env.run_ok(&["delete", "--did", A, "--apply"]);
    assert!(deleted.contains("erases delivery deduplication history"));
    let counts = parse_counts(&deleted);
    assert_eq!(
        get(
            &counts,
            "postgres deleted",
            "push_device_deliveries.recipient_via_receipt"
        ),
        1
    );
    for table in [
        "push_event_receipts",
        "push_device_deliveries",
        "chat_mute_sync_generations",
    ] {
        assert_eq!(
            env.count(&format!("SELECT count(*) FROM {table}")).await,
            2,
            "deletion scope for {table}"
        );
    }
    assert_eq!(
        env.count(&format!(
            "SELECT count(*) FROM push_event_receipts WHERE recipient_did='{A}'"
        ))
        .await,
        0
    );
    assert_eq!(env.count("SELECT count(*) FROM push_device_deliveries WHERE dedupe_key='dedupe-held-b' AND state='attempting'").await, 1);

    catbird::services::chat_poll::scheduler::ChatPollScheduler::new(env.pool.clone())
        .enroll_account(A, "pds.example.com")
        .await
        .unwrap();
    assert_eq!(env.count(&format!("SELECT count(*) FROM chat_poll_state WHERE account_did='{A}' AND chat_cursor IS NULL AND primed_at IS NULL AND catch_up_required_at IS NULL")).await, 1);
    env.cleanup().await;
}

async fn b_rows(env: &TestEnv) -> Vec<i64> {
    let mut v = Vec::new();
    for (table, col) in [
        ("push_accounts", "account_did"),
        ("push_preferences", "account_did"),
        ("user_devices", "did"),
        ("activity_subscriptions", "subscriber_did"),
        ("thread_mutes", "user_did"),
        ("chat_muted_convos", "account_did"),
        ("chat_notified_watermarks", "account_did"),
        ("chat_poll_state", "account_did"),
        ("push_event_queue", "recipient_did"),
        ("actor_moderation_verdict", "recipient_did"),
        ("relationship_audit_log", "user_did"),
    ] {
        v.push(
            env.count(&format!("SELECT count(*) FROM {table} WHERE {col} = '{B}'"))
                .await,
        );
    }
    v
}

#[tokio::test]
#[ignore = "requires local Postgres"]
async fn retention_rules_remove_exactly_aged_rows() {
    let env = TestEnv::new().await;
    // R1 target: revoked 200d, only an inactive device.
    let c = "did:plc:r1revokedold";
    seed_account(&env, c, "SESSIONSECRET-c", Some(200), Some((false, 5)), "c").await;
    // Revoked 200d but still has an active device: kept by R1 (R3 still applies).
    let d = "did:plc:r1activedevice";
    seed_account(&env, d, "SESSIONSECRET-d", Some(200), Some((true, 5)), "d").await;
    // Revoked 10d: kept by R1 and R3.
    let e = "did:plc:recentlyrevoked";
    seed_account(&env, e, "SESSIONSECRET-e", Some(10), Some((true, 1)), "e").await;
    // Live account with an old inactive device (R2), a fresh inactive device,
    // and an old active device (both kept).
    let live = "did:plc:liveaccount";
    seed_account(
        &env,
        live,
        "SESSIONSECRET-l",
        None,
        Some((false, 100)),
        "l1",
    )
    .await;
    env.exec(&format!(
        "INSERT INTO user_devices (did, device_token, is_active, updated_at) VALUES \
         ('{live}', '{}', false, now() - interval '10 days'), \
         ('{live}', '{}', true, now() - interval '400 days')",
        device_token("l2"),
        device_token("l3")
    ))
    .await;
    // R3: chat state with no account at all, and for an account revoked 40d.
    let orphan = "did:plc:noaccount";
    seed_chat(&env, orphan, "o").await;
    let g = "did:plc:revoked40days";
    seed_account(&env, g, "SESSIONSECRET-g", Some(40), Some((true, 1)), "g").await;
    // R4 / R5 legacy rows.
    create_legacy_tables(&env).await;
    env.exec(
        "INSERT INTO relationship_audit_log (user_did, action, created_at) VALUES \
         ('did:plc:x', 'block', now() - interval '100 days'), ('did:plc:x', 'block', now() - interval '10 days')",
    )
    .await;
    env.exec(
        "INSERT INTO post_cache (uri, text, expires_at) VALUES \
         ('at://old', 't', now() - interval '1 hour'), ('at://new', 't', now() + interval '1 hour')",
    )
    .await;

    let before = env.snapshot().await;
    let dry = env.run_ok(&["retention"]);
    assert_eq!(
        env.snapshot().await,
        before,
        "dry run must not change anything"
    );
    let dm = parse_counts(&dry);
    assert_eq!(get(&dm, "R1", "push_accounts"), 1);
    assert_eq!(get(&dm, "R1", "user_devices"), 1);
    assert_eq!(get(&dm, "R2", "user_devices"), 1);
    // R3 dry-run: orphan + d (revoked 200d) + c (revoked 200d) + g (revoked 40d).
    assert_eq!(get(&dm, "R3", "chat_poll_state"), 4);
    assert_eq!(get(&dm, "R4", "relationship_audit_log"), 1);
    assert_eq!(get(&dm, "R5", "post_cache"), 1);

    let out = env.run_ok(&["retention", "--apply"]);
    assert!(out.contains("APPLIED"));
    let am = parse_counts(&out);
    assert_eq!(get(&am, "R1", "push_accounts"), 1);
    assert_eq!(get(&am, "R1", "push_preferences"), 1);
    // c's rows already removed by R1, so R3 removes orphan, d and g.
    assert_eq!(get(&am, "R3", "chat_poll_state"), 3);

    let has = |t: &'static str, col: &'static str, did: &str| {
        format!("SELECT count(*) FROM {t} WHERE {col} = '{did}'")
    };
    // R1: c fully gone; d and e kept.
    for (t, col) in [
        ("push_accounts", "account_did"),
        ("push_preferences", "account_did"),
        ("user_devices", "did"),
        ("thread_mutes", "user_did"),
        ("push_event_queue", "recipient_did"),
        ("actor_moderation_verdict", "recipient_did"),
        ("chat_poll_state", "account_did"),
    ] {
        assert_eq!(env.count(&has(t, col, c)).await, 0, "R1 left {t} for c");
    }
    for did in [d, e, g, live] {
        assert_eq!(
            env.count(&has("push_accounts", "account_did", did)).await,
            1
        );
        assert_eq!(env.count(&has("thread_mutes", "user_did", did)).await, 1);
    }
    // R2: exactly the 100-day inactive device removed.
    assert_eq!(env.count(&has("user_devices", "did", live)).await, 2);
    assert_eq!(
        env.count(&format!(
            "SELECT count(*) FROM user_devices WHERE device_token = '{}'",
            device_token("l1")
        ))
        .await,
        0
    );
    // R3: chat state for orphan, d, g removed; e and live kept.
    for t in [
        "chat_muted_convos",
        "chat_notified_watermarks",
        "chat_poll_state",
    ] {
        for did in [orphan, d, g] {
            assert_eq!(env.count(&has(t, "account_did", did)).await, 0, "{t} {did}");
        }
        for did in [e, live] {
            assert_eq!(env.count(&has(t, "account_did", did)).await, 1, "{t} {did}");
        }
    }
    // R4 / R5.
    assert_eq!(
        env.count("SELECT count(*) FROM relationship_audit_log")
            .await,
        1
    );
    assert_eq!(
        env.count("SELECT count(*) FROM relationship_audit_log WHERE created_at > now() - interval '20 days'")
            .await,
        1
    );
    assert_eq!(
        env.count("SELECT count(*) FROM post_cache WHERE uri = 'at://new'")
            .await,
        1
    );
    assert_eq!(env.count("SELECT count(*) FROM post_cache").await, 1);

    // Idempotent: a second apply removes nothing.
    let again = parse_counts(&env.run_ok(&["retention", "--apply"]));
    assert!(again.values().all(|n| *n == 0), "{again:?}");
    env.cleanup().await;
}

#[tokio::test]
#[ignore = "requires local Postgres"]
async fn legacy_tables_absent_is_not_an_error() {
    let mut env = TestEnv::new().await;
    seed_account(&env, A, SESSION_SECRET_A, None, Some((true, 0)), "a").await;
    let key = format!("{}session:{A}_{FP_A1}", env.prefix);
    let _: () = env.redis.set_ex(key, REDIS_BLOB, 600).await.unwrap();

    let report = env.run_ok(&["report", "--did", A]);
    assert!(report.contains("relationship_audit_log"));
    assert!(report.contains("skipped: absent"));
    let ret = env.run_ok(&["retention"]);
    assert!(ret.contains("R4 legacy audit log"));
    assert!(ret.contains("skipped: table absent or unknown shape"));
    env.run_ok(&["retention", "--apply"]);
    env.run_ok(&["delete", "--did", A, "--apply"]);
    assert_eq!(
        env.count(&format!(
            "SELECT count(*) FROM push_accounts WHERE account_did = '{A}'"
        ))
        .await,
        0
    );
    assert!(env.redis_keys().await.is_empty());
    env.cleanup().await;
}

#[tokio::test]
#[ignore = "requires local Postgres"]
async fn rejects_non_did_input() {
    let env = TestEnv::new().await;
    let (ok, stdout, stderr) = env.run(&["delete", "--did", "did:plc:*", "--apply"]);
    assert!(!ok);
    assert!(stdout.is_empty());
    assert!(stderr.contains("not a valid DID"));
    env.cleanup().await;
}
