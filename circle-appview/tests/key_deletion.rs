//! I3: `blue.catbird.circle.key` rows leave `circle_keys` when the owner deletes the
//! record (incremental DeleteRecord or absence from a full-recovery repo), and every
//! purge path (projected-data purge, Space deletion, confirmed author deletion) removes
//! them. After a key delete, `getKeys` no longer serves it and `latestKeyVersion` drops.
mod support;
use std::sync::Arc;
use support::encrypted::{self as enc, pds};
use support::encrypted::{CIRCLE_ID, ENCRYPTED_TYPE, KEY};

use axum::body::to_bytes;
use axum::extract::{Extension, Query, State};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::Value;
use sqlx::PgPool;

use catbird_atproto::generated::blue_catbird::circle::get_keys::GetKeys;
use catbird_atproto::jacquard_common::types::aturi::AtSpaceUri;
use circle_appview::auth::AuthenticatedUser;
use circle_appview::config::AppState;
use circle_appview::space_client::MockSpaceHostTransport;
use circle_appview::sync::{latest_key_version, SyncMode};

const OWNER_DID: &str = "did:plc:alice-key-delete";
const BOB_DID: &str = "did:plc:bob-key-delete";
const SPACE: &str = "at://did:plc:alice-key-delete/space/blue.catbird.circle.encrypted/kd";
const REV2: &str = "3l7bbbbbbbbbb";

struct Setup {
    state: AppState,
    mock: Arc<MockSpaceHostTransport>,
}

async fn setup(pool: &PgPool) -> Setup {
    support::healthy_identity_fixture(pool, &[OWNER_DID, BOB_DID]).await;
    let config = enc::config(
        "did:web:appview.catbird.blue",
        "did:web:appview.catbird.blue#atproto_circles",
    );
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
    let credentials = enc::credential_store(&[SPACE]).await;
    let state = enc::app_state(pool, config, resolver, credentials, &mock);
    enc::insert_circle(
        pool,
        SPACE,
        CIRCLE_ID,
        OWNER_DID,
        &[OWNER_DID, BOB_DID],
        Some(ENCRYPTED_TYPE),
    )
    .await;
    Setup { state, mock }
}

fn keys() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        (KEY, "3l7keyaaaaaa1", enc::key_record(OWNER_DID, 1)),
        (KEY, "3l7keyaaaaaa2", enc::key_record(OWNER_DID, 2)),
    ]
}

/// Index keys 1 and 2 through an incremental sync.
async fn seed_two_keys(s: &Setup) {
    enc::serve_ops(&s.mock, SPACE, OWNER_DID, &keys());
    let r = enc::sync(&s.state, SPACE, OWNER_DID).await;
    assert_eq!((r.records_accepted, r.records_rejected), (2, 0));
}

async fn key_rows(pool: &PgPool) -> Vec<i64> {
    sqlx::query_scalar("SELECT key_version FROM circle_keys ORDER BY key_version")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn get_keys(s: &Setup) -> Value {
    let query = GetKeys {
        limit: None,
        since_version: None,
        space: AtSpaceUri::new_owned(SPACE).unwrap(),
    };
    let user = AuthenticatedUser {
        did: BOB_DID.to_string(),
        lxm: "blue.catbird.circle.getKeys".to_string(),
    };
    let resp = circle_appview::handlers::keys::get_keys_handler(
        Extension(user),
        Query(query),
        State(s.state.clone()),
    )
    .await
    .unwrap();
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn versions(out: &Value) -> Vec<i64> {
    out["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["keyVersion"].as_i64().unwrap())
        .collect()
}

#[sqlx::test(migrations = "./migrations")]
async fn key_delete_record_removes_row_and_latest_drops(pool: PgPool) {
    let s = setup(&pool).await;
    seed_two_keys(&s).await;
    assert_eq!(versions(&get_keys(&s).await), vec![1, 2]);

    let all = keys();
    enc::serve_delete_ops(&s.mock, SPACE, OWNER_DID, &all, &all[1..], REV2);
    let r = enc::sync(&s.state, SPACE, OWNER_DID).await;
    assert_eq!(r.mode, SyncMode::Incremental);

    assert_eq!(key_rows(&pool).await, vec![1]);
    let latest = latest_key_version(&pool, SPACE).await.unwrap();
    assert_eq!(latest.map(|(v, _)| v), Some(1));
    let out = get_keys(&s).await;
    assert_eq!(versions(&out), vec![1]);
    assert_eq!(out["latestKeyVersion"], serde_json::json!(1));
}

#[sqlx::test(migrations = "./migrations")]
async fn full_recovery_drops_keys_absent_from_the_repo(pool: PgPool) {
    let s = setup(&pool).await;
    seed_two_keys(&s).await;
    enc::serve_full_recovery(&s.mock, SPACE, OWNER_DID, &keys()[..1], REV2);
    let r = enc::sync(&s.state, SPACE, OWNER_DID).await;
    assert_eq!(r.mode, SyncMode::FullRecovery);
    assert_eq!(key_rows(&pool).await, vec![1]);
}

#[sqlx::test(migrations = "./migrations")]
async fn purge_circle_projected_data_removes_keys(pool: PgPool) {
    let s = setup(&pool).await;
    seed_two_keys(&s).await;
    circle_appview::purge::purge_circle_projected_data(&pool, SPACE)
        .await
        .unwrap();
    assert!(key_rows(&pool).await.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_space_removes_keys(pool: PgPool) {
    let s = setup(&pool).await;
    seed_two_keys(&s).await;
    circle_appview::purge::delete_space(&pool, &s.state.credential_store, SPACE)
        .await
        .unwrap();
    assert!(key_rows(&pool).await.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn purge_deleted_author_removes_owned_keys(pool: PgPool) {
    let s = setup(&pool).await;
    seed_two_keys(&s).await;
    circle_appview::purge::purge_deleted_author(&pool, BOB_DID)
        .await
        .unwrap();
    assert_eq!(
        key_rows(&pool).await,
        vec![1, 2],
        "other authors' purge keeps keys"
    );
    circle_appview::purge::purge_deleted_author(&pool, OWNER_DID)
        .await
        .unwrap();
    assert!(key_rows(&pool).await.is_empty());
}
