//! C1: Catbird sends reply parents and like subjects in the STANDARD form
//! `at://<did>/<collection>/<rkey>` (the form the AppView serves), while sync stores and
//! keys known posts by the SPACE form `<space_uri>/<did>/<collection>/<rkey>`. Ingestion
//! must accept the standard form and store the space form, so reply counts and like
//! counts (which join on the stored form) keep matching.
mod support;
use std::sync::Arc;
use support::encrypted::{self as enc, cid_of, envelope, envelope_reply, pds};
use support::encrypted::{CIRCLE_ID, ENCRYPTED_TYPE, KEY, LATER, NOW, POST};

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::{json, Value};
use sqlx::PgPool;

use circle_appview::config::AppState;
use circle_appview::space_client::MockSpaceHostTransport;

const OWNER_DID: &str = "did:plc:alice-uri-forms";
const BOB_DID: &str = "did:plc:bob-uri-forms";
const ENC_SPACE: &str = "at://did:plc:alice-uri-forms/space/blue.catbird.circle.encrypted/enc";
const PLAIN_SPACE: &str = "at://did:plc:alice-uri-forms/space/blue.catbird.circle/plain";
const PLAIN_POST: &str = "app.bsky.feed.post";
const LIKE: &str = "app.bsky.feed.like";

struct Setup {
    state: AppState,
    mock: Arc<MockSpaceHostTransport>,
    space: &'static str,
}

async fn setup(pool: &PgPool, space: &'static str, space_type: Option<&str>) -> Setup {
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
    let credentials = enc::credential_store(&[space]).await;
    let state = enc::app_state(pool, config, resolver, credentials, &mock);
    enc::insert_circle(
        pool,
        space,
        CIRCLE_ID,
        OWNER_DID,
        &[OWNER_DID, BOB_DID],
        space_type,
    )
    .await;
    Setup { state, mock, space }
}

impl Setup {
    async fn sync(&self, author: &str, records: &[(&str, &str, Value)]) -> (usize, usize) {
        enc::serve_ops(&self.mock, self.space, author, records);
        let r = enc::sync(&self.state, self.space, author).await;
        (r.records_accepted, r.records_rejected)
    }

    fn space_uri(&self, author: &str, collection: &str, rkey: &str) -> String {
        format!("{}/{author}/{collection}/{rkey}", self.space)
    }
}

fn standard_uri(author: &str, collection: &str, rkey: &str) -> String {
    format!("at://{author}/{collection}/{rkey}")
}

async fn reply_row(pool: &PgPool, uri: &str) -> (Option<String>, Option<String>) {
    sqlx::query_as(
        "SELECT parent_uri, root_uri FROM circle_records WHERE uri = $1 AND deleted_at IS NULL",
    )
    .bind(uri)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn reply_notifications(pool: &PgPool, space: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM circle_notifications WHERE space_uri = $1 AND recipient_did = $2",
    )
    .bind(space)
    .bind(OWNER_DID)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Owner indexes key 1 and a top-level envelope; returns its (space-form uri, cid).
async fn seed_encrypted_root(s: &Setup) -> (String, String) {
    let root = envelope(1);
    let accepted = s
        .sync(
            OWNER_DID,
            &[
                (KEY, "3l7keyaaaaaa1", enc::key_record(OWNER_DID, 1)),
                (POST, "3l7postaaaaa1", root.clone()),
            ],
        )
        .await;
    assert_eq!(accepted, (2, 0));
    (s.space_uri(OWNER_DID, POST, "3l7postaaaaa1"), cid_of(&root))
}

#[sqlx::test(migrations = "./migrations")]
async fn encrypted_reply_with_standard_form_parent_is_indexed_in_space_form(pool: PgPool) {
    let s = setup(&pool, ENC_SPACE, Some(ENCRYPTED_TYPE)).await;
    let (root_uri, root_cid) = seed_encrypted_root(&s).await;

    let parent = standard_uri(OWNER_DID, POST, "3l7postaaaaa1");
    let reply = envelope_reply(1, &parent, &root_cid);
    assert_eq!(
        s.sync(BOB_DID, &[(POST, "3l7replyaaaa1", reply)]).await,
        (1, 0),
        "a standard-form parent must resolve against the space-form known post"
    );

    let reply_uri = s.space_uri(BOB_DID, POST, "3l7replyaaaa1");
    let (parent_uri, stored_root) = reply_row(&pool, &reply_uri).await;
    assert_eq!(parent_uri.as_deref(), Some(root_uri.as_str()));
    assert_eq!(stored_root.as_deref(), Some(root_uri.as_str()));
    assert_eq!(reply_notifications(&pool, ENC_SPACE).await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn encrypted_like_with_standard_form_subject_is_indexed_in_space_form(pool: PgPool) {
    let s = setup(&pool, ENC_SPACE, Some(ENCRYPTED_TYPE)).await;
    let (root_uri, root_cid) = seed_encrypted_root(&s).await;

    let like = json!({
        "$type": LIKE,
        "subject": {"uri": standard_uri(OWNER_DID, POST, "3l7postaaaaa1"), "cid": root_cid},
        "createdAt": LATER,
    });
    assert_eq!(
        s.sync(BOB_DID, &[(LIKE, "3l7likeaaaaa1", like)]).await,
        (1, 0)
    );

    let post_uri: String = sqlx::query_scalar("SELECT post_uri FROM circle_likes WHERE uri = $1")
        .bind(s.space_uri(BOB_DID, LIKE, "3l7likeaaaaa1"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(post_uri, root_uri);
    assert_eq!(reply_notifications(&pool, ENC_SPACE).await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn plaintext_reply_with_standard_form_parent_is_indexed_in_space_form(pool: PgPool) {
    let s = setup(&pool, PLAIN_SPACE, None).await;
    let root = json!({"$type": PLAIN_POST, "text": "root", "createdAt": NOW});
    let root_cid = cid_of(&root);
    assert_eq!(
        s.sync(OWNER_DID, &[(PLAIN_POST, "3l7postaaaaa1", root)])
            .await,
        (1, 0)
    );
    let root_uri = s.space_uri(OWNER_DID, PLAIN_POST, "3l7postaaaaa1");

    let parent =
        json!({"uri": standard_uri(OWNER_DID, PLAIN_POST, "3l7postaaaaa1"), "cid": root_cid});
    let reply = json!({
        "$type": PLAIN_POST,
        "text": "reply",
        "createdAt": LATER,
        "reply": {"parent": parent, "root": parent},
    });
    assert_eq!(
        s.sync(BOB_DID, &[(PLAIN_POST, "3l7replyaaaa1", reply)])
            .await,
        (1, 0)
    );

    let reply_uri = s.space_uri(BOB_DID, PLAIN_POST, "3l7replyaaaa1");
    let (parent_uri, stored_root) = reply_row(&pool, &reply_uri).await;
    assert_eq!(parent_uri.as_deref(), Some(root_uri.as_str()));
    assert_eq!(stored_root.as_deref(), Some(root_uri.as_str()));
    assert_eq!(reply_notifications(&pool, PLAIN_SPACE).await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn space_form_parent_still_resolves(pool: PgPool) {
    let s = setup(&pool, ENC_SPACE, Some(ENCRYPTED_TYPE)).await;
    let (root_uri, root_cid) = seed_encrypted_root(&s).await;
    let reply = envelope_reply(1, &root_uri, &root_cid);
    assert_eq!(
        s.sync(BOB_DID, &[(POST, "3l7replyaaaa1", reply)]).await,
        (1, 0)
    );
    let (parent_uri, _) = reply_row(&pool, &s.space_uri(BOB_DID, POST, "3l7replyaaaa1")).await;
    assert_eq!(parent_uri.as_deref(), Some(root_uri.as_str()));
}

/// Catbird's sealer encodes the reply through Petrel's `ReplyRef`, which always writes
/// `"$type": "app.bsky.feed.post#replyRef"`; that envelope must ingest.
#[sqlx::test(migrations = "./migrations")]
async fn typed_encrypted_reply_as_catbird_sends_it_is_indexed(pool: PgPool) {
    let s = setup(&pool, ENC_SPACE, Some(ENCRYPTED_TYPE)).await;
    let (root_uri, root_cid) = seed_encrypted_root(&s).await;
    let mut reply = envelope_reply(
        1,
        &standard_uri(OWNER_DID, POST, "3l7postaaaaa1"),
        &root_cid,
    );
    reply["reply"]["$type"] = json!("app.bsky.feed.post#replyRef");
    assert_eq!(
        s.sync(BOB_DID, &[(POST, "3l7replyaaaa1", reply)]).await,
        (1, 0)
    );
    let (parent_uri, _) = reply_row(&pool, &s.space_uri(BOB_DID, POST, "3l7replyaaaa1")).await;
    assert_eq!(parent_uri.as_deref(), Some(root_uri.as_str()));
}
