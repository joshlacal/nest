//! M1/M2: a `stale_key` envelope (D13: first indexed after its key's grace) is invisible
//! everywhere: its reply creates no notification or push, `listNotifications` drops
//! notifications whose subject is stale, and `getMedia` refuses blobs only a stale
//! envelope references.
mod support;
use std::sync::Arc;
use support::encrypted::{self as enc, cid_of, envelope, envelope_reply, pds};
use support::encrypted::{CIRCLE_ID, ENCRYPTED_TYPE, KEY, POST};

use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::string::{Did, Handle};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use circle_appview::auth::AuthenticatedUser;
use circle_appview::config::AppState;
use circle_appview::space_client::MockSpaceHostTransport;

const OWNER_DID: &str = "did:plc:alice-stale";
const BOB_DID: &str = "did:plc:bob-stale";
const SPACE: &str = "at:space/did:plc:alice-stale/blue.catbird.circle.encrypted/st";

struct Setup {
    state: AppState,
    mock: Arc<MockSpaceHostTransport>,
}

fn profile(did: &str, handle: &str) -> ProfileViewBasic {
    ProfileViewBasic {
        did: Did::new(SmolStr::new(did)).unwrap(),
        handle: Handle::new(SmolStr::new(handle)).unwrap(),
        display_name: None,
        avatar: None,
        associated: None,
        viewer: None,
        labels: None,
        created_at: None,
        pronouns: None,
        status: None,
        verification: None,
        debug: None,
        extra_data: None,
    }
}

/// Keys 1 (old) and 2 (700 s old, so key-1 envelopes indexed now are stale) and an
/// owner root at key 2.
async fn setup(pool: &PgPool) -> (Setup, String, String) {
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
    for (did, handle) in [(OWNER_DID, "alice.test"), (BOB_DID, "bob.test")] {
        state
            .profile_hydrator
            .set_cached_profile(did, profile(did, handle))
            .await;
    }
    enc::insert_circle(
        pool,
        SPACE,
        CIRCLE_ID,
        OWNER_DID,
        &[OWNER_DID, BOB_DID],
        Some(ENCRYPTED_TYPE),
    )
    .await;
    for (kv, age) in [(1, 3_600), (2, 700)] {
        let uri = format!("{SPACE}/{OWNER_DID}/{KEY}/3l7key{kv:07}");
        enc::insert_key_row(pool, SPACE, OWNER_DID, &uri, kv, age).await;
    }
    let s = Setup { state, mock };
    let root = envelope(2);
    assert_eq!(
        sync(&s, OWNER_DID, &[(POST, "3l7postaaaaa1", root.clone())]).await,
        (1, 0)
    );
    let root_uri = format!("{SPACE}/{OWNER_DID}/{POST}/3l7postaaaaa1");
    (s, root_uri, cid_of(&root))
}

async fn sync(s: &Setup, author: &str, records: &[(&str, &str, Value)]) -> (usize, usize) {
    enc::serve_ops(&s.mock, SPACE, author, records);
    let r = enc::sync(&s.state, SPACE, author).await;
    (r.records_accepted, r.records_rejected)
}

async fn is_stale(pool: &PgPool, uri: &str) -> bool {
    sqlx::query_scalar("SELECT stale_key FROM circle_records WHERE uri = $1")
        .bind(uri)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn notification_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM circle_notifications WHERE space_uri = $1")
        .bind(SPACE)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_reply_creates_no_notification(pool: PgPool) {
    let (s, root_uri, root_cid) = setup(&pool).await;
    let stale = envelope_reply(1, &root_uri, &root_cid);
    let live = envelope_reply(2, &root_uri, &root_cid);
    assert_eq!(
        sync(
            &s,
            BOB_DID,
            &[
                (POST, "3l7replyaaaa1", stale),
                (POST, "3l7replyaaaa2", live)
            ],
        )
        .await,
        (2, 0)
    );
    assert!(is_stale(&pool, &format!("{SPACE}/{BOB_DID}/{POST}/3l7replyaaaa1")).await);
    let sources: Vec<String> =
        sqlx::query_scalar("SELECT source_uri FROM circle_notifications WHERE space_uri = $1")
            .bind(SPACE)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        sources,
        vec![format!("{SPACE}/{BOB_DID}/{POST}/3l7replyaaaa2")],
        "only the live reply notifies"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn list_notifications_drops_stale_subjects(pool: PgPool) {
    let (s, root_uri, root_cid) = setup(&pool).await;
    let stale = envelope_reply(1, &root_uri, &root_cid);
    let live = envelope_reply(2, &root_uri, &root_cid);
    sync(
        &s,
        BOB_DID,
        &[
            (POST, "3l7replyaaaa1", stale),
            (POST, "3l7replyaaaa2", live),
        ],
    )
    .await;
    // A notification left over for the stale reply (e.g. indexed before this rule).
    let stale_uri = format!("{SPACE}/{BOB_DID}/{POST}/3l7replyaaaa1");
    sqlx::query(
        "INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at) \
         VALUES ($1, $2, $3, $4, 'reply', $5, $5, false, now()) ON CONFLICT (source_uri) DO NOTHING",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(OWNER_DID)
    .bind(SPACE)
    .bind(BOB_DID)
    .bind(&stale_uri)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(notification_count(&pool).await, 2);

    let out = circle_appview::notifications::list_notifications(&s.state, OWNER_DID, None, None)
        .await
        .unwrap();
    let text = serde_json::to_string(&out).unwrap();
    assert_eq!(out.notifications.len(), 1, "{text}");
    assert!(!text.contains("3l7replyaaaa1"), "{text}");
}

fn blob_cid(data: &[u8]) -> String {
    let mut bytes = vec![0x01, 0x55, 0x12, 0x20];
    bytes.extend_from_slice(&Sha256::digest(data));
    multibase::encode(multibase::Base::Base32Lower, &bytes)
}

fn with_attachment(mut post: Value, cid: &str, size: usize) -> Value {
    post["attachments"] = json!([{
        "$type": "blob",
        "ref": {"$link": cid},
        "mimeType": "application/octet-stream",
        "size": size,
    }]);
    post
}

#[sqlx::test(migrations = "./migrations")]
async fn media_of_a_stale_envelope_is_not_served(pool: PgPool) {
    let (s, root_uri, root_cid) = setup(&pool).await;
    let stale_blob = b"stale-ciphertext-blob".to_vec();
    let live_blob = b"live-ciphertext-blob".to_vec();
    let (stale_cid, live_cid) = (blob_cid(&stale_blob), blob_cid(&live_blob));
    let stale = with_attachment(
        envelope_reply(1, &root_uri, &root_cid),
        &stale_cid,
        stale_blob.len(),
    );
    let live = with_attachment(
        envelope_reply(2, &root_uri, &root_cid),
        &live_cid,
        live_blob.len(),
    );
    assert_eq!(
        sync(
            &s,
            BOB_DID,
            &[
                (POST, "3l7postaaaaa8", live),
                (POST, "3l7postaaaaa9", stale)
            ],
        )
        .await,
        (2, 0)
    );
    assert!(is_stale(&pool, &format!("{SPACE}/{BOB_DID}/{POST}/3l7postaaaaa9")).await);
    assert!(!is_stale(&pool, &format!("{SPACE}/{BOB_DID}/{POST}/3l7postaaaaa8")).await);
    for (cid, blob) in [(&stale_cid, &stale_blob), (&live_cid, &live_blob)] {
        s.mock.set_blob_response(
            &format!("{SPACE}:{BOB_DID}:{cid}"),
            Some("application/octet-stream".to_string()),
            blob.clone(),
        );
    }
    let user = || AuthenticatedUser {
        did: BOB_DID.into(),
        lxm: "blue.catbird.circle.getMedia".into(),
    };

    // Positive control: the identical request for a live envelope's blob is served.
    let live_res =
        circle_appview::media::get_media(&s.state, user(), SPACE, BOB_DID, &live_cid).await;
    assert_eq!(
        live_res.expect("live envelope media is served").status(),
        axum::http::StatusCode::OK
    );
    let stale_res =
        circle_appview::media::get_media(&s.state, user(), SPACE, BOB_DID, &stale_cid).await;
    assert!(
        stale_res.is_err(),
        "a blob referenced only by a stale envelope is not served"
    );
}
