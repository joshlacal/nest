//! Ingestion of encrypted Circle records (Task 9): `blue.catbird.circle.key` records
//! index into `circle_keys`, `blue.catbird.circle.post` envelopes index into
//! `circle_records` with their key version and the D13 stale-key flag, and plaintext
//! posts in an encrypted Space are recorded as rejections. Every test drives the real
//! `SyncEngine` against Postgres through the mock space-host transport.
mod support;
use std::sync::Arc;
use support::encrypted::{self as enc, cid_of, envelope, envelope_reply, pds};
use support::encrypted::{b64, CIRCLE_ID, ENCRYPTED_TYPE, KEY, NOW, POST, REV};
use support::{fixture_commit, fixture_star};

use chrono::Utc;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::{json, Value};
use sqlx::PgPool;

use catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput;
use circle_appview::commit::{LtHash, RepoRecord};
use circle_appview::config::AppState;
use circle_appview::space_client::MockSpaceHostTransport;
use circle_appview::sync::{latest_key_version, SyncMode};
use circle_appview::validator::compute_uri_hash;

const OWNER_DID: &str = "did:plc:alice-enc-sync";
const BOB_DID: &str = "did:plc:bob-enc-sync";
const SPACE_URI: &str = "at:space/did:plc:alice-enc-sync/blue.catbird.circle.encrypted/enc-circle";

struct Setup {
    state: AppState,
    mock: Arc<MockSpaceHostTransport>,
}

fn key_record(kv: i64) -> Value {
    enc::key_record(OWNER_DID, kv)
}

fn serve_ops(setup: &Setup, author: &str, records: &[(&str, &str, Value)]) {
    enc::serve_ops(&setup.mock, SPACE_URI, author, records);
}

async fn sync(setup: &Setup, author: &str) -> circle_appview::sync::SyncResult {
    enc::sync(&setup.state, SPACE_URI, author).await
}

async fn insert_key_row(pool: &PgPool, kv: i64, age_secs: i64) {
    let uri = record_uri(OWNER_DID, KEY, &format!("3l7key{kv:07}"));
    enc::insert_key_row(pool, SPACE_URI, OWNER_DID, &uri, kv, age_secs).await;
}

async fn setup(pool: &PgPool) -> Setup {
    support::healthy_identity_fixture(pool, &[OWNER_DID, BOB_DID]).await;
    let service_did = "did:web:appview.catbird.blue";
    let config = enc::config(service_did, "did:web:appview.catbird.blue#atproto_circles");
    let resolver = enc::did_resolver(&config);
    enc::register_did_doc(
        &resolver,
        OWNER_DID,
        &SigningKey::random(&mut OsRng),
        vec![enc::space_host(), pds("https://pds.alice.blue")],
    );
    enc::register_did_doc(
        &resolver,
        BOB_DID,
        &SigningKey::random(&mut OsRng),
        vec![pds("https://pds.bob.blue")],
    );
    let mock = Arc::new(MockSpaceHostTransport::new());
    let credentials = enc::credential_store(&[SPACE_URI]).await;
    let state = enc::app_state(pool, config, resolver, credentials, &mock);
    enc::insert_circle(
        pool,
        SPACE_URI,
        CIRCLE_ID,
        OWNER_DID,
        &[OWNER_DID, BOB_DID],
        Some(ENCRYPTED_TYPE),
    )
    .await;
    Setup { state, mock }
}

fn record_uri(author: &str, collection: &str, rkey: &str) -> String {
    format!("{SPACE_URI}/{author}/{collection}/{rkey}")
}

fn state_bytes(lthash: &LtHash) -> [u8; 2048] {
    lthash.state().as_slice().try_into().unwrap()
}

async fn record_row(pool: &PgPool, uri: &str) -> (Option<i64>, bool, Option<String>) {
    sqlx::query_as(
        "SELECT key_version, stale_key, parent_uri FROM circle_records WHERE uri = $1 AND deleted_at IS NULL",
    )
    .bind(uri)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn key_record_is_indexed_into_circle_keys(pool: PgPool) {
    let setup = setup(&pool).await;
    let value = key_record(1);
    serve_ops(&setup, OWNER_DID, &[(KEY, "3l7keyaaaaaa1", value.clone())]);

    let result = sync(&setup, OWNER_DID).await;
    assert_eq!(result.mode, SyncMode::Incremental);
    assert_eq!((result.records_accepted, result.records_rejected), (1, 0));

    let row: (String, String, String, Value) = sqlx::query_as(
        "SELECT uri, cid, owner_did, record_json FROM circle_keys WHERE space_uri = $1 AND key_version = 1",
    )
    .bind(SPACE_URI)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, record_uri(OWNER_DID, KEY, "3l7keyaaaaaa1"));
    assert_eq!(row.1, cid_of(&value));
    assert_eq!(row.2, OWNER_DID);
    assert_eq!(row.3["keyVersion"], json!(1));

    let in_records: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM circle_records WHERE collection = $1")
            .bind(KEY)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(in_records, 0, "key records never enter circle_records");

    let latest = latest_key_version(&pool, SPACE_URI).await.unwrap();
    assert_eq!(latest.map(|(v, _)| v), Some(1));
}

#[sqlx::test(migrations = "./migrations")]
async fn key_then_first_envelope_in_same_batch_validates(pool: PgPool) {
    let setup = setup(&pool).await;
    serve_ops(
        &setup,
        OWNER_DID,
        &[
            (KEY, "3l7keyaaaaaa1", key_record(1)),
            (POST, "3l7postaaaaa1", envelope(1)),
        ],
    );

    let result = sync(&setup, OWNER_DID).await;
    assert_eq!(result.mode, SyncMode::Incremental);
    assert_eq!((result.records_accepted, result.records_rejected), (2, 0));

    let (kv, stale, parent) =
        record_row(&pool, &record_uri(OWNER_DID, POST, "3l7postaaaaa1")).await;
    assert_eq!(kv, Some(1));
    assert!(!stale);
    assert_eq!(parent, None);
}

#[sqlx::test(migrations = "./migrations")]
async fn envelope_reply_creates_notification_without_content(pool: PgPool) {
    let setup = setup(&pool).await;
    let root = envelope(1);
    let root_uri = record_uri(OWNER_DID, POST, "3l7postaaaaa1");
    serve_ops(
        &setup,
        OWNER_DID,
        &[
            (KEY, "3l7keyaaaaaa1", key_record(1)),
            (POST, "3l7postaaaaa1", root.clone()),
        ],
    );
    sync(&setup, OWNER_DID).await;

    let reply_uri = record_uri(BOB_DID, POST, "3l7replyaaaa1");
    serve_ops(
        &setup,
        BOB_DID,
        &[(
            POST,
            "3l7replyaaaa1",
            envelope_reply(1, &root_uri, &cid_of(&root)),
        )],
    );
    let result = sync(&setup, BOB_DID).await;
    assert_eq!(result.mode, SyncMode::Incremental);
    assert_eq!((result.records_accepted, result.records_rejected), (1, 0));

    let (kv, stale, parent) = record_row(&pool, &reply_uri).await;
    assert_eq!(kv, Some(1));
    assert!(!stale);
    assert_eq!(parent.as_deref(), Some(root_uri.as_str()));

    let notif: (String, String, String, Option<String>, String) = sqlx::query_as(
        "SELECT recipient_did, actor_did, reason, subject_uri, source_uri FROM circle_notifications WHERE space_uri = $1",
    )
    .bind(SPACE_URI)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(notif.0, OWNER_DID);
    assert_eq!(notif.1, BOB_DID);
    assert_eq!(notif.2, "reply");
    assert_eq!(notif.3.as_deref(), Some(reply_uri.as_str()));
    assert_eq!(notif.4, reply_uri);

    // The notification row carries no record content: no column holds a record body.
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns WHERE table_name = 'circle_notifications'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for forbidden in ["record_json", "text", "ciphertext", "content", "body"] {
        assert!(
            !columns.iter().any(|c| c == forbidden),
            "circle_notifications must not have a {forbidden} column: {columns:?}"
        );
    }
    let row_text: String = sqlx::query_scalar(
        "SELECT row_to_json(n)::text FROM circle_notifications n WHERE source_uri = $1",
    )
    .bind(&reply_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    let ciphertext = b64(100)["$bytes"].as_str().unwrap().to_string();
    assert!(!row_text.contains(&ciphertext), "no ciphertext copied");
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_envelope_within_grace_is_live(pool: PgPool) {
    let setup = setup(&pool).await;
    insert_key_row(&pool, 1, 3_600).await;
    insert_key_row(&pool, 2, 60).await;
    let uri = record_uri(OWNER_DID, POST, "3l7postaaaaa1");
    serve_ops(&setup, OWNER_DID, &[(POST, "3l7postaaaaa1", envelope(1))]);

    let result = sync(&setup, OWNER_DID).await;
    assert_eq!((result.records_accepted, result.records_rejected), (1, 0));
    let (kv, stale, _) = record_row(&pool, &uri).await;
    assert_eq!(kv, Some(1));
    assert!(
        !stale,
        "latest key is only 60 s old: still within the 600 s grace"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_envelope_after_grace_is_flagged(pool: PgPool) {
    let setup = setup(&pool).await;
    insert_key_row(&pool, 1, 3_600).await;
    insert_key_row(&pool, 2, 700).await;
    let stale_uri = record_uri(OWNER_DID, POST, "3l7postaaaaa1");
    let current_uri = record_uri(OWNER_DID, POST, "3l7postaaaaa2");
    serve_ops(
        &setup,
        OWNER_DID,
        &[
            (POST, "3l7postaaaaa1", envelope(1)),
            (POST, "3l7postaaaaa2", envelope(2)),
        ],
    );

    let result = sync(&setup, OWNER_DID).await;
    assert_eq!((result.records_accepted, result.records_rejected), (2, 0));
    let (kv, stale, _) = record_row(&pool, &stale_uri).await;
    assert_eq!(kv, Some(1));
    assert!(
        stale,
        "key 2 is 700 s old: a key-1 envelope is past the grace"
    );
    let (kv, stale, _) = record_row(&pool, &current_uri).await;
    assert_eq!(kv, Some(2));
    assert!(!stale, "an envelope at the latest key is never stale");
}

#[sqlx::test(migrations = "./migrations")]
async fn plaintext_post_in_encrypted_space_recorded_as_rejection(pool: PgPool) {
    let setup = setup(&pool).await;
    let uri = record_uri(OWNER_DID, "app.bsky.feed.post", "3l7plainaaaa1");
    serve_ops(
        &setup,
        OWNER_DID,
        &[(
            "app.bsky.feed.post",
            "3l7plainaaaa1",
            json!({"$type": "app.bsky.feed.post", "text": "plaintext", "createdAt": NOW}),
        )],
    );

    let result = sync(&setup, OWNER_DID).await;
    assert_eq!((result.records_accepted, result.records_rejected), (0, 1));

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM circle_records WHERE uri = $1")
        .bind(&uri)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let reason: String =
        sqlx::query_scalar("SELECT reason_code FROM circle_rejections WHERE uri_hash = $1")
            .bind(compute_uri_hash(&uri))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reason, "plaintext_in_encrypted_space");
}

/// The full-recovery path (getRepo after a commit mismatch) indexes keys and envelopes
/// exactly like the incremental path.
#[sqlx::test(migrations = "./migrations")]
async fn full_recovery_indexes_keys_and_envelopes(pool: PgPool) {
    let setup = setup(&pool).await;
    insert_key_row(&pool, 1, 3_600).await;

    // Incremental page with a commit that does not match its ops forces full recovery.
    let mut bad = LtHash::default();
    bad.add("app.bsky.feed.post/3l7tampered11/bafytamperedcid");
    setup.mock.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        ListRepoOpsOutput {
            commit: fixture_commit(SPACE_URI, OWNER_DID, REV, &state_bytes(&bad)),
            cursor: None,
            ops: vec![],
            extra_data: None,
        },
    );

    // Key 2 and envelopes at key 1 and key 2; key 1 is past the grace, but key 2 is
    // indexed in this very sync, so nothing is stale yet.
    let records = [
        (KEY, "3l7keyaaaaaa2", key_record(2)),
        (POST, "3l7postaaaaa1", envelope(1)),
        (POST, "3l7postaaaaa2", envelope(2)),
    ];
    let mut lthash = LtHash::default();
    let repo_records: Vec<RepoRecord> = records
        .iter()
        .map(|(collection, rkey, value)| {
            let cid = cid_of(value);
            lthash.add(&format!("{collection}/{rkey}/{cid}"));
            RepoRecord {
                collection: collection.to_string(),
                rkey: rkey.to_string(),
                cid,
                value: value.clone(),
            }
        })
        .collect();
    let commit = fixture_commit(SPACE_URI, OWNER_DID, "3l7bbbbbbbbbb", &state_bytes(&lthash));
    setup.mock.set_get_repo_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        fixture_star(&commit, &repo_records).unwrap(),
    );

    let result = sync(&setup, OWNER_DID).await;
    assert_eq!(result.mode, SyncMode::FullRecovery);
    assert_eq!((result.records_accepted, result.records_rejected), (3, 0));

    let latest = latest_key_version(&pool, SPACE_URI).await.unwrap();
    assert_eq!(latest.map(|(v, _)| v), Some(2));
    for (rkey, kv) in [("3l7postaaaaa1", 1), ("3l7postaaaaa2", 2)] {
        let (got, stale, _) = record_row(&pool, &record_uri(OWNER_DID, POST, rkey)).await;
        assert_eq!(got, Some(kv));
        assert!(!stale, "{rkey}: latest key was indexed just now");
    }
}

/// Force `author`'s next sync into full recovery at revision `rev` serving `records`.
fn serve_full_recovery(setup: &Setup, author: &str, records: &[(&str, &str, Value)], rev: &str) {
    enc::serve_full_recovery(&setup.mock, SPACE_URI, author, records, rev);
}

/// Run a single-row boolean `sql` (one text bind), e.g. an age-versus-grace check.
async fn older_than_grace(pool: &PgPool, sql: &str, bind: &str) -> bool {
    sqlx::query_scalar::<_, bool>(sql)
        .bind(bind)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Regression (review fix 1): history indexed before a rotation stays live when a later
/// full recovery re-ingests it with unchanged CIDs after the grace has elapsed.
#[sqlx::test(migrations = "./migrations")]
async fn full_recovery_after_rotation_keeps_history_live(pool: PgPool) {
    let setup = setup(&pool).await;
    let history = [
        (KEY, "3l7key0000001", key_record(1)),
        (POST, "3l7postaaaaa1", envelope(1)),
        (POST, "3l7postaaaaa2", envelope(1)),
    ];
    serve_ops(&setup, OWNER_DID, &history);
    let first = sync(&setup, OWNER_DID).await;
    assert_eq!(first.mode, SyncMode::Incremental);
    assert_eq!(first.records_accepted, 3);
    let first_seen: Vec<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT indexed_at FROM circle_records WHERE collection = $1 ORDER BY uri",
    )
    .bind(POST)
    .fetch_all(&pool)
    .await
    .unwrap();

    // Rotation: key 2 was first indexed 700 s ago, past the grace.
    insert_key_row(&pool, 2, 700).await;

    let mut recovered = history.to_vec();
    recovered.push((KEY, "3l7key0000002", key_record(2)));
    serve_full_recovery(&setup, OWNER_DID, &recovered, "3l7bbbbbbbbbb");
    let result = sync(&setup, OWNER_DID).await;
    assert_eq!(result.mode, SyncMode::FullRecovery);
    assert_eq!((result.records_accepted, result.records_rejected), (4, 0));

    for rkey in ["3l7postaaaaa1", "3l7postaaaaa2"] {
        let (kv, stale, _) = record_row(&pool, &record_uri(OWNER_DID, POST, rkey)).await;
        assert_eq!(kv, Some(1));
        assert!(!stale, "{rkey}: first seen before key 2, so it stays live");
    }
    let after: Vec<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT indexed_at FROM circle_records WHERE collection = $1 ORDER BY uri",
    )
    .bind(POST)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        after, first_seen,
        "unchanged CIDs keep their first-seen time"
    );
    assert!(
        older_than_grace(
            &pool,
            "SELECT indexed_at < now() - INTERVAL '600 seconds' FROM circle_keys WHERE uri = $1",
            &record_uri(OWNER_DID, KEY, "3l7key0000002"),
        )
        .await,
        "re-ingesting key 2 with the same CID keeps its first-seen time"
    );
}

/// D13 compares an envelope at N with key N+1, not with the latest key: key 3 indexed
/// moments ago does not reopen the grace for a key-1 envelope first seen 700 s after key 2.
#[sqlx::test(migrations = "./migrations")]
async fn late_envelope_after_grace_is_stale(pool: PgPool) {
    let setup = setup(&pool).await;
    insert_key_row(&pool, 1, 3_600).await;
    insert_key_row(&pool, 2, 700).await;
    insert_key_row(&pool, 3, 10).await;
    serve_ops(
        &setup,
        OWNER_DID,
        &[
            (POST, "3l7postaaaaa1", envelope(1)),
            (POST, "3l7postaaaaa2", envelope(2)),
        ],
    );
    let result = sync(&setup, OWNER_DID).await;
    assert_eq!((result.records_accepted, result.records_rejected), (2, 0));
    let (_, stale, _) = record_row(&pool, &record_uri(OWNER_DID, POST, "3l7postaaaaa1")).await;
    assert!(stale, "key 2 superseded key 1 700 s before this envelope");
    let (_, stale, _) = record_row(&pool, &record_uri(OWNER_DID, POST, "3l7postaaaaa2")).await;
    assert!(!stale, "key 3 superseded key 2 only 10 s ago");
}

/// A key re-synced with the same CID keeps `indexed_at`/`created_at`; a genuine rewrite
/// (new CID, D8 rule 2) takes the new `createdAt` but `indexed_at` is the version's
/// first-seen time and never moves.
#[sqlx::test(migrations = "./migrations")]
async fn key_resync_with_same_cid_keeps_indexed_at(pool: PgPool) {
    let setup = setup(&pool).await;
    insert_key_row(&pool, 1, 700).await;
    let key_uri = record_uri(OWNER_DID, KEY, "3l7key0000001");
    let stamps = |pool: PgPool| async move {
        sqlx::query_as::<_, (chrono::DateTime<Utc>, chrono::DateTime<Utc>)>(
            "SELECT indexed_at, created_at FROM circle_keys WHERE space_uri = $1 AND key_version = 1",
        )
        .bind(SPACE_URI)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let before = stamps(pool.clone()).await;

    serve_ops(&setup, OWNER_DID, &[(KEY, "3l7key0000001", key_record(1))]);
    let result = sync(&setup, OWNER_DID).await;
    assert_eq!((result.records_accepted, result.records_rejected), (1, 0));
    assert_eq!(
        stamps(pool.clone()).await,
        before,
        "same CID keeps both times"
    );

    let mut rewritten = key_record(1);
    rewritten["createdAt"] = json!("2026-11-07T01:00:00.000Z");
    serve_full_recovery(
        &setup,
        OWNER_DID,
        &[(KEY, "3l7key0000001", rewritten.clone())],
        "3l7bbbbbbbbbb",
    );
    let result = sync(&setup, OWNER_DID).await;
    assert_eq!(result.mode, SyncMode::FullRecovery);
    let after = stamps(pool.clone()).await;
    assert_eq!(
        after.0, before.0,
        "indexed_at is immutable after first insert"
    );
    assert_ne!(after.1, before.1, "a rewrite takes the new createdAt");
    let cid: String = sqlx::query_scalar("SELECT cid FROM circle_keys WHERE uri = $1")
        .bind(&key_uri)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(cid, cid_of(&rewritten));
}

/// Owners re-wrap the CURRENT version weekly; a rewrite (new CID) must not reopen the
/// D13 grace window for N-1 envelopes, so `indexed_at` stays first-seen.
#[sqlx::test(migrations = "./migrations")]
async fn key_rewrite_with_new_cid_keeps_first_seen_indexed_at(pool: PgPool) {
    let setup = setup(&pool).await;
    insert_key_row(&pool, 1, 3_600).await;
    insert_key_row(&pool, 2, 700).await;
    let key2_indexed = |pool: PgPool| async move {
        sqlx::query_scalar::<_, chrono::DateTime<Utc>>(
            "SELECT indexed_at FROM circle_keys WHERE space_uri = $1 AND key_version = 2",
        )
        .bind(SPACE_URI)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let before = key2_indexed(pool.clone()).await;

    let mut rewrapped = key_record(2);
    rewrapped["createdAt"] = json!("2026-11-07T02:00:00.000Z");
    let stale_uri = record_uri(OWNER_DID, POST, "3l7postaaaaa1");
    serve_full_recovery(
        &setup,
        OWNER_DID,
        &[
            (KEY, "3l7key0000001", key_record(1)),
            (KEY, "3l7key0000002", rewrapped.clone()),
            (POST, "3l7postaaaaa1", envelope(1)),
        ],
        "3l7bbbbbbbbbb",
    );
    let result = sync(&setup, OWNER_DID).await;
    assert_eq!(result.mode, SyncMode::FullRecovery);
    assert_eq!((result.records_accepted, result.records_rejected), (3, 0));

    let cid: String =
        sqlx::query_scalar("SELECT cid FROM circle_keys WHERE space_uri = $1 AND key_version = 2")
            .bind(SPACE_URI)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cid, cid_of(&rewrapped), "the rewrite replaced the row");
    assert_eq!(
        key2_indexed(pool.clone()).await,
        before,
        "a rewrite keeps the version's first-seen indexed_at"
    );
    let (kv, stale, _) = record_row(&pool, &stale_uri).await;
    assert_eq!(kv, Some(1));
    assert!(stale, "N-1 envelope stays stale after the weekly re-wrap");
}

/// Review minor: key vN+1 listed before vN in a recovered repo is accepted on a later pass.
#[sqlx::test(migrations = "./migrations")]
async fn full_recovery_accepts_keys_listed_out_of_order(pool: PgPool) {
    let setup = setup(&pool).await;
    // STAR lists records by collection/rkey, so key 2 ("…a1") precedes key 1 ("…a2").
    serve_full_recovery(
        &setup,
        OWNER_DID,
        &[
            (KEY, "3l7keyaaaaaa1", key_record(2)),
            (KEY, "3l7keyaaaaaa2", key_record(1)),
        ],
        "3l7bbbbbbbbbb",
    );
    let result = sync(&setup, OWNER_DID).await;
    assert_eq!(result.mode, SyncMode::FullRecovery);
    assert_eq!((result.records_accepted, result.records_rejected), (2, 0));
    let latest = latest_key_version(&pool, SPACE_URI).await.unwrap();
    assert_eq!(latest.map(|(v, _)| v), Some(2));
}
