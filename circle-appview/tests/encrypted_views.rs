//! Serving encrypted Circles (Task 10): `getFeed`/`getPostThread` return envelopes as
//! `encryptedPostView` items and hide stale-key envelopes, `getKeys` serves the stored
//! `blue.catbird.circle.key` records to members only, `reportRecord` persists the
//! reporter's disclosure, `getMedia` serves encrypted blobs as opaque bytes, and
//! `getCapabilities` advertises encrypted posts. Records are ingested through the real
//! `SyncEngine` (mock space-host transport) and read through the real router.
mod support;
use std::sync::Arc;
use support::encrypted::{self as enc, cid_of, envelope, envelope_reply, pds, register_did_doc};
use support::encrypted::{CIRCLE_ID, ENCRYPTED_TYPE, KEY, LATER, NOW, POST};

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use petrel_api::generated::app::bsky::actor::defs::ProfileViewBasic;
use petrel_api::generated::app::bsky::feed::defs::ThreadViewPostReplies;
use petrel_catbird::generated::blue::catbird::circle::defs::FeedItemPost;
use petrel_catbird::generated::blue::catbird::circle::get_capabilities::Output as GetCapabilitiesOutput;
use petrel_catbird::generated::blue::catbird::circle::get_feed::Output as GetFeedOutput;
use petrel_catbird::generated::blue::catbird::circle::get_post_thread::Output as GetPostThreadOutput;
use petrel_core::Did;
use petrel_core::Handle;

use circle_appview::auth::AuthenticatedUser;
use circle_appview::config::AppState;
use circle_appview::moderation::labels::AccountLabelEvent;
use circle_appview::moderation::{
    apply_label_event, is_account_restricted, prune_to_config, ModerationLabelConfig,
};
use circle_appview::routes::create_router;
use circle_appview::space_client::MockSpaceHostTransport;

const AUDIENCE: &str = "did:web:circles.catbird.blue#atproto_circles";
const OWNER_DID: &str = "did:plc:alice-enc-views";
const BOB_DID: &str = "did:plc:bob-enc-views";
const CHARLIE_DID: &str = "did:plc:charlie-enc-views";
const SPACE_URI: &str = "at:space/did:plc:alice-enc-views/blue.catbird.circle.encrypted/enc-circle";
const PLAIN_SPACE_URI: &str = "at:space/did:plc:alice-enc-views/blue.catbird.circle/plain-circle";
const LIKE: &str = "app.bsky.feed.like";
const PLAIN_CIRCLE_ID: &str = "3jzfcijpj2z2b";
const ROOT_RKEY: &str = "3l7postaaaaa1";

struct Setup {
    app: axum::Router,
    state: AppState,
    mock: Arc<MockSpaceHostTransport>,
    owner_key: SigningKey,
    bob_key: SigningKey,
    charlie_key: SigningKey,
}

fn key_record(kv: i64) -> Value {
    enc::key_record(OWNER_DID, kv)
}

fn serve_ops(setup: &Setup, space: &str, author: &str, records: &[(&str, &str, Value)]) {
    enc::serve_ops(&setup.mock, space, author, records);
}

async fn sync(setup: &Setup, space: &str, author: &str) -> (usize, usize) {
    let result = enc::sync(&setup.state, space, author).await;
    (result.records_accepted, result.records_rejected)
}

async fn insert_circle(pool: &PgPool, space: &str, circle_id: &str, space_type: Option<&str>) {
    enc::insert_circle(
        pool,
        space,
        circle_id,
        OWNER_DID,
        &[OWNER_DID, BOB_DID],
        space_type,
    )
    .await;
}

/// Insert a key row directly, as if indexed `age_secs` ago.
async fn insert_key_row(pool: &PgPool, kv: i64, age_secs: i64) {
    let uri = enc_uri(OWNER_DID, KEY, &format!("{kv:06}"));
    enc::insert_key_row(pool, SPACE_URI, OWNER_DID, &uri, kv, age_secs).await;
}

fn like(subject_uri: &str, subject_cid: &str) -> Value {
    json!({
        "$type": LIKE,
        "subject": {"uri": subject_uri, "cid": subject_cid},
        "createdAt": LATER,
    })
}

fn record_uri(space: &str, author: &str, collection: &str, rkey: &str) -> String {
    format!("{space}/{author}/{collection}/{rkey}")
}

fn enc_uri(author: &str, collection: &str, rkey: &str) -> String {
    record_uri(SPACE_URI, author, collection, rkey)
}

/// A raw-codec CIDv1 over sha2-256, as the PDS names an uploaded blob.
fn blob_cid(data: &[u8]) -> String {
    let mut bytes = vec![0x01, 0x55, 0x12, 0x20];
    bytes.extend_from_slice(&Sha256::digest(data));
    multibase::encode(multibase::Base::Base32Lower, &bytes)
}

fn profile(did: &str, handle: &str) -> ProfileViewBasic {
    ProfileViewBasic {
        did: Did::parse(did).unwrap(),
        handle: Handle::parse(handle).unwrap(),
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

async fn setup(pool: &PgPool) -> Setup {
    support::healthy_identity_fixture(pool, &[OWNER_DID, BOB_DID, CHARLIE_DID]).await;
    let config = enc::config(AUDIENCE, &format!("{AUDIENCE}#atproto_circles"));
    let did_resolver = enc::did_resolver(&config);
    let owner_key = SigningKey::random(&mut OsRng);
    let bob_key = SigningKey::random(&mut OsRng);
    let charlie_key = SigningKey::random(&mut OsRng);
    register_did_doc(
        &did_resolver,
        OWNER_DID,
        &owner_key,
        vec![enc::space_host(), pds("https://pds.alice.blue")],
    );
    register_did_doc(
        &did_resolver,
        BOB_DID,
        &bob_key,
        vec![pds("https://pds.bob.blue")],
    );
    register_did_doc(
        &did_resolver,
        CHARLIE_DID,
        &charlie_key,
        vec![pds("https://pds.charlie.blue")],
    );

    let mock = Arc::new(MockSpaceHostTransport::new());
    let credential_store = enc::credential_store(&[SPACE_URI, PLAIN_SPACE_URI]).await;
    let state = enc::app_state(pool, config, did_resolver, credential_store, &mock);
    for (did, handle) in [
        (OWNER_DID, "alice.test"),
        (BOB_DID, "bob.test"),
        (CHARLIE_DID, "charlie.test"),
    ] {
        state
            .profile_hydrator
            .set_cached_profile(did, profile(did, handle))
            .await;
    }

    insert_circle(pool, SPACE_URI, CIRCLE_ID, Some(ENCRYPTED_TYPE)).await;
    insert_circle(pool, PLAIN_SPACE_URI, PLAIN_CIRCLE_ID, None).await;

    Setup {
        app: create_router(state.clone()),
        state,
        mock,
        owner_key,
        bob_key,
        charlie_key,
    }
}

fn mint_jwt(did: &str, lxm: &str, key: &SigningKey) -> String {
    let now = Utc::now().timestamp();
    let header = json!({"typ": "JWT", "alg": "ES256", "kid": format!("{did}#atproto")});
    let claims = json!({
        "iss": did,
        "aud": AUDIENCE,
        "lxm": lxm,
        "jti": uuid::Uuid::new_v4().to_string(),
        "iat": now,
        "exp": now + 60,
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let sig: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn url_encode(input: &str) -> String {
    let mut out = String::new();
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn xrpc_get(
    setup: &Setup,
    did: &str,
    key: &SigningKey,
    method: &str,
    query: &str,
) -> (StatusCode, Vec<u8>) {
    let token = mint_jwt(did, method, key);
    let req = Request::builder()
        .uri(format!("/xrpc/{method}?{query}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 32 * 1024 * 1024).await.unwrap();
    (status, body.to_vec())
}

async fn xrpc_post(
    setup: &Setup,
    did: &str,
    key: &SigningKey,
    method: &str,
    input: &Value,
) -> (StatusCode, Vec<u8>) {
    let token = mint_jwt(did, method, key);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/xrpc/{method}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(input).unwrap()))
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (status, body.to_vec())
}

async fn get_feed(setup: &Setup, space: &str) -> (GetFeedOutput, String) {
    let (status, body) = xrpc_get(
        setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.getFeed",
        &format!("space={}&includeEncrypted=true", url_encode(space)),
    )
    .await;
    let text = String::from_utf8(body).unwrap();
    assert_eq!(status, StatusCode::OK, "getFeed failed: {text}");
    (serde_json::from_str(&text).unwrap(), text)
}

/// Owner writes key v1 and a root envelope; Bob likes it and replies to it.
async fn ingest_thread_fixture(setup: &Setup) -> (String, Value) {
    let root = envelope(1);
    let root_uri = enc_uri(OWNER_DID, POST, ROOT_RKEY);
    serve_ops(
        setup,
        SPACE_URI,
        OWNER_DID,
        &[
            (KEY, "000001", key_record(1)),
            (POST, ROOT_RKEY, root.clone()),
        ],
    );
    assert_eq!(sync(setup, SPACE_URI, OWNER_DID).await, (2, 0));
    let root_cid = cid_of(&root);
    serve_ops(
        setup,
        SPACE_URI,
        BOB_DID,
        &[
            (
                POST,
                "3l7replyaaaa1",
                envelope_reply(1, &root_uri, &root_cid),
            ),
            (LIKE, "3l7likeaaaaa1", like(&root_uri, &root_cid)),
        ],
    );
    assert_eq!(sync(setup, SPACE_URI, BOB_DID).await, (2, 0));
    (root_uri, root)
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_returns_encrypted_post_view_for_envelopes(pool: PgPool) {
    let setup = setup(&pool).await;
    let (_root_uri, root) = ingest_thread_fixture(&setup).await;

    let (feed, text) = get_feed(&setup, SPACE_URI).await;
    assert_eq!(feed.feed.len(), 1, "replies stay out of the feed");
    let item = &feed.feed[0];
    assert_eq!(item.circle.latest_key_version, Some(1));
    let FeedItemPost::EncryptedPostView(view) = &item.post else {
        panic!("an envelope must be served as encryptedPostView");
    };
    assert_eq!(
        view.uri.as_str(),
        format!("at://{OWNER_DID}/{POST}/{ROOT_RKEY}")
    );
    assert_eq!(view.cid.as_str(), cid_of(&root));
    assert_eq!(view.author.did.as_str(), OWNER_DID);
    assert_eq!(view.record.key_version, 1);
    assert_eq!(
        view.record.ciphertext.0.as_slice(),
        vec![7u8; 100].as_slice()
    );
    assert_eq!(view.record.sig.0.len(), 64);
    assert_eq!(view.like_count, Some(1));
    assert_eq!(view.reply_count, Some(1));
    let viewer_like = view.viewer.as_ref().and_then(|v| v.like.as_ref()).unwrap();
    assert_eq!(
        viewer_like.as_str(),
        format!("at://{BOB_DID}/{LIKE}/3l7likeaaaaa1")
    );

    let raw: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        raw["feed"][0]["post"]["$type"],
        json!("blue.catbird.circle.defs#encryptedPostView")
    );
    // Wire pin: served views write `$bytes` as unpadded standard base64 (Petrel's
    // encoding; the previous stack padded it). 100 bytes would carry "==" if padded.
    assert_eq!(
        raw["feed"][0]["post"]["record"]["ciphertext"]["$bytes"],
        json!(STANDARD_NO_PAD.encode([7u8; 100]))
    );
    assert!(
        !text.contains("\"text\""),
        "an encrypted feed item must carry no plaintext field: {text}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_hides_stale_key_rows(pool: PgPool) {
    let setup = setup(&pool).await;
    insert_key_row(&pool, 1, 3_600).await;
    insert_key_row(&pool, 2, 3_600).await;
    serve_ops(
        &setup,
        SPACE_URI,
        OWNER_DID,
        &[
            (POST, "3l7postaaaaa1", envelope(1)),
            (POST, "3l7postaaaaa2", envelope(2)),
        ],
    );
    assert_eq!(sync(&setup, SPACE_URI, OWNER_DID).await, (2, 0));
    let stale: bool = sqlx::query_scalar("SELECT stale_key FROM circle_records WHERE uri = $1")
        .bind(enc_uri(OWNER_DID, POST, "3l7postaaaaa1"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        stale,
        "fixture: the key-1 envelope is past the grace window"
    );

    let (feed, _) = get_feed(&setup, SPACE_URI).await;
    assert_eq!(feed.feed.len(), 1);
    assert_eq!(feed.feed[0].circle.latest_key_version, Some(2));
    let FeedItemPost::EncryptedPostView(view) = &feed.feed[0].post else {
        panic!("expected encryptedPostView");
    };
    assert_eq!(
        view.uri.as_str(),
        format!("at://{OWNER_DID}/{POST}/3l7postaaaaa2")
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn get_keys_returns_versions_after_since(pool: PgPool) {
    let setup = setup(&pool).await;
    for kv in 1..=3 {
        insert_key_row(&pool, kv, 60).await;
    }

    let (status, body) = xrpc_get(
        &setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.getKeys",
        &format!("space={}&sinceVersion=1", url_encode(SPACE_URI)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let out: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(out["latestKeyVersion"], json!(3));
    let keys = out["keys"].as_array().unwrap();
    let versions: Vec<i64> = keys
        .iter()
        .map(|k| k["keyVersion"].as_i64().unwrap())
        .collect();
    assert_eq!(versions, vec![2, 3]);
    for entry in keys {
        let kv = entry["keyVersion"].as_i64().unwrap();
        // The record is served in the lexicon wire form, byte-identical to what was indexed.
        assert_eq!(entry["record"], key_record(kv));
        assert!(entry["record"]["recipients"][0]["$bytes"].is_string());
        assert_eq!(entry["cid"], json!(cid_of(&key_record(kv))));
        assert_eq!(
            entry["uri"],
            json!(enc_uri(OWNER_DID, KEY, &format!("{kv:06}")))
        );
    }

    let (status, body) = xrpc_get(
        &setup,
        OWNER_DID,
        &setup.owner_key,
        "blue.catbird.circle.getKeys",
        &format!("space={}", url_encode(SPACE_URI)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let out: Value = serde_json::from_slice(&body).unwrap();
    let versions: Vec<i64> = out["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["keyVersion"].as_i64().unwrap())
        .collect();
    assert_eq!(versions, vec![1, 2, 3], "no sinceVersion returns every key");

    let (status, body) = xrpc_get(
        &setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.getKeys",
        &format!("space={}", url_encode(PLAIN_SPACE_URI)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let out: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(out["keys"], json!([]));
    assert_eq!(out["latestKeyVersion"], json!(0));
}

#[sqlx::test(migrations = "./migrations")]
async fn get_keys_denies_non_member(pool: PgPool) {
    let setup = setup(&pool).await;
    insert_key_row(&pool, 1, 60).await;
    let query = format!("space={}", url_encode(SPACE_URI));

    let (keys_status, keys_body) = xrpc_get(
        &setup,
        CHARLIE_DID,
        &setup.charlie_key,
        "blue.catbird.circle.getKeys",
        &query,
    )
    .await;
    let (feed_status, feed_body) = xrpc_get(
        &setup,
        CHARLIE_DID,
        &setup.charlie_key,
        "blue.catbird.circle.getFeed",
        &query,
    )
    .await;
    assert!(
        keys_status == StatusCode::FORBIDDEN,
        "non-member getKeys must be refused, got {keys_status}"
    );
    assert_eq!(keys_status, feed_status);
    let keys_err: Value = serde_json::from_slice(&keys_body).unwrap();
    let feed_err: Value = serde_json::from_slice(&feed_body).unwrap();
    assert_eq!(keys_err["error"], feed_err["error"]);
    assert!(!String::from_utf8_lossy(&keys_body).contains("recipients"));
}

#[sqlx::test(migrations = "./migrations")]
async fn report_discards_disclosed_key(pool: PgPool) {
    // Catbird's operator never gets the means to decrypt Circle content. An
    // older client that still sends a post key and media keys with a report
    // gets the report filed, and the keys are thrown away.
    let setup = setup(&pool).await;
    let (root_uri, _) = ingest_thread_fixture(&setup).await;
    let std_uri = format!("at://{OWNER_DID}/{POST}/{ROOT_RKEY}");
    let media_cid = blob_cid(b"encrypted-blob");
    let input = json!({
        "space": SPACE_URI,
        "uri": std_uri,
        "reason": "abuse",
        "disclosedPostKey": {"$bytes": STANDARD_NO_PAD.encode([9u8; 32])},
        "disclosedMedia": [{
            "cid": media_cid,
            "key": {"$bytes": STANDARD_NO_PAD.encode([5u8; 32])},
            "iv": {"$bytes": STANDARD_NO_PAD.encode([6u8; 12])},
        }],
    });
    let (status, body) = xrpc_post(
        &setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.reportRecord",
        &input,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let id: Value = serde_json::from_slice(&body).unwrap();
    let report_id = uuid::Uuid::parse_str(id["id"].as_str().unwrap()).unwrap();

    let (subject, reason): (String, String) =
        sqlx::query_as("SELECT subject_uri, reason FROM circle_reports WHERE id = $1")
            .bind(report_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(subject, root_uri);
    assert_eq!(reason, "abuse");

    // There is nowhere left to store a key.
    let key_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'circle_reports' \
            AND column_name LIKE 'disclosed%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        key_columns, 0,
        "circle_reports must not hold disclosed keys"
    );

    // Reports without disclosure are accepted as before.
    let plain = json!({"space": SPACE_URI, "uri": std_uri, "reason": "spam"});
    let (status, _) = xrpc_post(
        &setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.reportRecord",
        &plain,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM circle_reports")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 2);
}

fn takedown_event(did: &str, cts_offset_secs: i64, neg: bool) -> AccountLabelEvent {
    AccountLabelEvent {
        src: "did:plc:catbird-ozone".into(),
        did: did.into(),
        val: "!takedown".into(),
        cts: Utc::now() + chrono::Duration::seconds(cts_offset_secs),
        exp: None,
        neg,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn operator_takedown_locks_account_out_and_hides_its_content(pool: PgPool) {
    let setup = setup(&pool).await;
    let (_root_uri, _) = ingest_thread_fixture(&setup).await;
    let feed_query = format!("space={}&includeEncrypted=true", url_encode(SPACE_URI));

    // The operator takes Bob down in Ozone.
    apply_label_event(&pool, &takedown_event(BOB_DID, -60, false))
        .await
        .unwrap();

    // Bob is refused on every authenticated route.
    let (status, body) = xrpc_get(
        &setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.getFeed",
        &feed_query,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let err: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], json!("Forbidden"));
    let (status, _) = xrpc_post(
        &setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.reportRecord",
        &json!({"space": SPACE_URI, "uri": format!("at://{OWNER_DID}/{POST}/{ROOT_RKEY}"), "reason": "spam"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Bob's reply and like drop out of what the owner sees.
    let (status, body) = xrpc_get(
        &setup,
        OWNER_DID,
        &setup.owner_key,
        "blue.catbird.circle.getFeed",
        &feed_query,
    )
    .await;
    let text = String::from_utf8(body).unwrap();
    assert_eq!(status, StatusCode::OK, "owner getFeed failed: {text}");
    let feed: GetFeedOutput = serde_json::from_str(&text).unwrap();
    let FeedItemPost::EncryptedPostView(view) = &feed.feed[0].post else {
        panic!("an envelope must be served as encryptedPostView");
    };
    assert_eq!(view.like_count, Some(0));
    assert_eq!(view.reply_count, Some(0));

    // A stale reversal (older than the takedown) changes nothing.
    apply_label_event(&pool, &takedown_event(BOB_DID, -120, true))
        .await
        .unwrap();
    let (status, _) = xrpc_get(
        &setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.getFeed",
        &feed_query,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The operator reverses the takedown; Bob and his content come back.
    apply_label_event(&pool, &takedown_event(BOB_DID, 0, true))
        .await
        .unwrap();
    let (feed, _) = get_feed(&setup, SPACE_URI).await;
    let FeedItemPost::EncryptedPostView(view) = &feed.feed[0].post else {
        panic!("an envelope must be served as encryptedPostView");
    };
    assert_eq!(view.like_count, Some(1));
    assert_eq!(view.reply_count, Some(1));
}

#[sqlx::test(migrations = "./migrations")]
async fn operator_takedown_of_owner_closes_the_circle(pool: PgPool) {
    let setup = setup(&pool).await;
    ingest_thread_fixture(&setup).await;
    apply_label_event(&pool, &takedown_event(OWNER_DID, -60, false))
        .await
        .unwrap();
    let (status, _) = xrpc_get(
        &setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.getFeed",
        &format!("space={}&includeEncrypted=true", url_encode(SPACE_URI)),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a taken-down owner's Circle must not be served"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn timed_suspension_lapses(pool: PgPool) {
    let setup = setup(&pool).await;
    ingest_thread_fixture(&setup).await;
    let mut ev = takedown_event(BOB_DID, -60, false);
    ev.val = "!suspend".into();
    ev.exp = Some(Utc::now() - chrono::Duration::seconds(1));
    apply_label_event(&pool, &ev).await.unwrap();
    assert!(!is_account_restricted(&pool, BOB_DID).await.unwrap());
    let (feed, _) = get_feed(&setup, SPACE_URI).await;
    assert_eq!(feed.feed.len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn startup_prune_drops_labels_the_config_no_longer_enforces(pool: PgPool) {
    let setup = setup(&pool).await;
    ingest_thread_fixture(&setup).await;
    let ev = takedown_event(BOB_DID, -60, false);
    apply_label_event(&pool, &ev).await.unwrap();
    assert!(is_account_restricted(&pool, BOB_DID).await.unwrap());

    let cfg = ModerationLabelConfig {
        labeler_did: ev.src.clone(),
        labeler_url: "https://ozone.example".into(),
        enforced_labels: vec!["!suspend".into()],
        poll_interval: std::time::Duration::from_secs(30),
    };
    // `!takedown` is no longer enforced, so its row goes and Bob's content
    // returns to views.
    assert_eq!(prune_to_config(&pool, Some(&cfg)).await.unwrap(), 1);
    assert!(!is_account_restricted(&pool, BOB_DID).await.unwrap());
    let (feed, _) = get_feed(&setup, SPACE_URI).await;
    assert_eq!(feed.feed.len(), 1);

    // Unconfigured moderation keeps nothing.
    apply_label_event(&pool, &ev).await.unwrap();
    assert_eq!(prune_to_config(&pool, None).await.unwrap(), 1);
    assert!(!is_account_restricted(&pool, BOB_DID).await.unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn media_is_octet_stream_for_encrypted_space(pool: PgPool) {
    let setup = setup(&pool).await;
    let blob = b"\x89PNG-looking-ciphertext".to_vec();
    let cid = blob_cid(&blob);
    let mut post = envelope(1);
    post["attachments"] = json!([{
        "$type": "blob",
        "ref": {"$link": cid},
        "mimeType": "application/octet-stream",
        "size": blob.len(),
    }]);
    serve_ops(
        &setup,
        SPACE_URI,
        OWNER_DID,
        &[(KEY, "000001", key_record(1)), (POST, ROOT_RKEY, post)],
    );
    assert_eq!(sync(&setup, SPACE_URI, OWNER_DID).await, (2, 0));
    setup.mock.set_blob_response(
        &format!("{SPACE_URI}:{OWNER_DID}:{cid}"),
        Some("image/png".to_string()),
        blob.clone(),
    );

    let resp = circle_appview::media::get_media(
        &setup.state,
        AuthenticatedUser {
            did: BOB_DID.into(),
            lxm: "blue.catbird.circle.getMedia".into(),
        },
        SPACE_URI,
        OWNER_DID,
        &cid,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream",
        "upstream image/png must not leak through for an encrypted Space"
    );
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store, private"
    );
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(body.as_ref(), blob.as_slice());
}

#[sqlx::test(migrations = "./migrations")]
async fn capabilities_advertise_encrypted_posts(pool: PgPool) {
    let setup = setup(&pool).await;
    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.getCapabilities")
        .body(Body::empty())
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let out: GetCapabilitiesOutput = serde_json::from_slice(&body).unwrap();
    assert_eq!(out.supports_encrypted_posts, Some(true));
}

#[sqlx::test(migrations = "./migrations")]
async fn no_plaintext_residue_in_encrypted_rows(pool: PgPool) {
    let setup = setup(&pool).await;
    ingest_thread_fixture(&setup).await;
    // Positive control: a plaintext post in a plaintext Circle.
    serve_ops(
        &setup,
        PLAIN_SPACE_URI,
        OWNER_DID,
        &[(
            "app.bsky.feed.post",
            "3l7plainaaaa1",
            json!({"$type": "app.bsky.feed.post", "text": "plaintext control", "createdAt": NOW}),
        )],
    );
    assert_eq!(sync(&setup, PLAIN_SPACE_URI, OWNER_DID).await, (1, 0));

    let encrypted_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM circle_records WHERE collection = $1")
            .bind(POST)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        encrypted_rows, 2,
        "fixture: root and reply envelopes indexed"
    );
    let residue: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM circle_records WHERE collection = $1 AND record_json::text LIKE '%\"text\"%'",
    )
    .bind(POST)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(residue, 0, "no envelope row carries a plaintext text field");
    let control: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM circle_records WHERE collection = 'app.bsky.feed.post' AND record_json::text LIKE '%\"text\"%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        control >= 1,
        "positive control: the same grep hits plaintext"
    );

    let (_, encrypted_text) = get_feed(&setup, SPACE_URI).await;
    assert!(!encrypted_text.contains("\"text\""), "{encrypted_text}");
    let (_, plain_text) = get_feed(&setup, PLAIN_SPACE_URI).await;
    assert!(
        plain_text.contains("\"text\""),
        "positive control: the plaintext feed serializes its text"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_includes_encrypted_replies_and_excludes_stale(pool: PgPool) {
    let setup = setup(&pool).await;
    insert_key_row(&pool, 1, 3_600).await;
    insert_key_row(&pool, 2, 3_600).await;
    let root = envelope(2);
    let root_uri = enc_uri(OWNER_DID, POST, ROOT_RKEY);
    serve_ops(
        &setup,
        SPACE_URI,
        OWNER_DID,
        &[(POST, ROOT_RKEY, root.clone())],
    );
    assert_eq!(sync(&setup, SPACE_URI, OWNER_DID).await, (1, 0));
    let root_cid = cid_of(&root);
    serve_ops(
        &setup,
        SPACE_URI,
        BOB_DID,
        &[
            (
                POST,
                "3l7replyaaaa1",
                envelope_reply(2, &root_uri, &root_cid),
            ),
            (
                POST,
                "3l7replyaaaa2",
                envelope_reply(1, &root_uri, &root_cid),
            ),
        ],
    );
    assert_eq!(sync(&setup, SPACE_URI, BOB_DID).await, (2, 0));

    let std_root = format!("at://{OWNER_DID}/{POST}/{ROOT_RKEY}");
    let (status, body) = xrpc_get(
        &setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.getPostThread",
        &format!(
            "space={}&uri={}&includeEncrypted=true",
            url_encode(SPACE_URI),
            url_encode(&std_root)
        ),
    )
    .await;
    let text = String::from_utf8(body).unwrap();
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(!text.contains("\"text\""), "{text}");
    let out: GetPostThreadOutput = serde_json::from_str(&text).unwrap();
    assert_eq!(out.circle.latest_key_version, Some(2));
    assert_eq!(out.thread.post.uri.as_str(), std_root);
    assert_eq!(
        out.thread.post.reply_count,
        Some(1),
        "stale reply not counted"
    );
    let raw: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(raw["thread"]["post"]["record"]["$type"], json!(POST));
    assert!(raw["thread"]["post"]["record"]["ciphertext"]["$bytes"].is_string());

    let replies = out.thread.replies.unwrap();
    assert_eq!(replies.len(), 1, "the stale-key reply is excluded");
    let ThreadViewPostReplies::ThreadViewPost(reply) = &replies[0] else {
        panic!("expected a thread view post reply");
    };
    assert_eq!(
        reply.post.uri.as_str(),
        format!("at://{BOB_DID}/{POST}/3l7replyaaaa1")
    );
    assert_eq!(
        raw["thread"]["replies"][0]["post"]["record"]["keyVersion"],
        json!(2)
    );
}

/// Envelope thread nodes (root and replies) never carry a synthesized `embed`, even when a
/// junk `embed` key sits in the stored record (injected here past the validator).
#[sqlx::test(migrations = "./migrations")]
async fn thread_envelope_nodes_carry_no_embed(pool: PgPool) {
    let setup = setup(&pool).await;
    ingest_thread_fixture(&setup).await;
    let junk = json!({"embed": {
        "$type": "app.bsky.embed.images",
        "images": [{"alt": "x", "image": {"ref": {"$link": "bafkreihuhrvkw25tq7bote4itvajpmwnz6zeswnrntz6gb4fa4x4mtntvm"}}}],
    }});
    let touched = sqlx::query(
        "UPDATE circle_records SET record_json = record_json || $1 WHERE collection = $2",
    )
    .bind(&junk)
    .bind(POST)
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(touched, 2, "root and reply envelopes");

    let std_root = format!("at://{OWNER_DID}/{POST}/{ROOT_RKEY}");
    let (status, body) = xrpc_get(
        &setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.getPostThread",
        &format!(
            "space={}&uri={}&includeEncrypted=true",
            url_encode(SPACE_URI),
            url_encode(&std_root)
        ),
    )
    .await;
    let text = String::from_utf8(body).unwrap();
    assert_eq!(status, StatusCode::OK, "{text}");
    let raw: Value = serde_json::from_str(&text).unwrap();
    assert!(raw["thread"]["post"].get("embed").is_none(), "root: {text}");
    let reply = &raw["thread"]["replies"][0]["post"];
    assert!(reply["record"].is_object(), "a reply node exists: {text}");
    assert!(reply.get("embed").is_none(), "reply: {text}");
}

fn key_versions(out: &Value) -> Vec<i64> {
    out["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["keyVersion"].as_i64().unwrap())
        .collect()
}

/// getKeys returns at most 64 rows per call, ascending; the client pages with
/// `sinceVersion` = the last returned version and sees `latestKeyVersion` for the end.
#[sqlx::test(migrations = "./migrations")]
async fn get_keys_is_capped_and_pages_by_since_version(pool: PgPool) {
    let setup = setup(&pool).await;
    for kv in 1..=70 {
        insert_key_row(&pool, kv, 60).await;
    }
    let get = |since: Option<i64>| {
        let setup = &setup;
        async move {
            let since = since
                .map(|s| format!("&sinceVersion={s}"))
                .unwrap_or_default();
            let (status, body) = xrpc_get(
                setup,
                BOB_DID,
                &setup.bob_key,
                "blue.catbird.circle.getKeys",
                &format!("space={}{since}", url_encode(SPACE_URI)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
            serde_json::from_slice::<Value>(&body).unwrap()
        }
    };

    let first = get(None).await;
    assert_eq!(key_versions(&first), (1..=64).collect::<Vec<_>>());
    assert_eq!(first["latestKeyVersion"], json!(70), "more remain: page on");

    let second = get(Some(64)).await;
    assert_eq!(key_versions(&second), (65..=70).collect::<Vec<_>>());
    assert_eq!(second["latestKeyVersion"], json!(70));
}

/// A stored key row that no longer parses is logged and skipped, not a 500 for everyone.
#[sqlx::test(migrations = "./migrations")]
async fn get_keys_skips_corrupt_rows_and_counts_them(pool: PgPool) {
    let setup = setup(&pool).await;
    for kv in 1..=3 {
        insert_key_row(&pool, kv, 60).await;
    }
    sqlx::query("UPDATE circle_keys SET record_json = '{\"not\":\"a key\"}' WHERE key_version = 2")
        .execute(&pool)
        .await
        .unwrap();

    let (status, body) = xrpc_get(
        &setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.getKeys",
        &format!("space={}", url_encode(SPACE_URI)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let out: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(key_versions(&out), vec![1, 3]);
    assert_eq!(out["skipped"], json!(1));
    assert_eq!(out["latestKeyVersion"], json!(3));
}

/// A 512-recipient key record (the largest bucket), stored directly at `kv`.
async fn insert_large_key_row(pool: &PgPool, kv: i64) -> Value {
    let mut value = key_record(kv);
    value["recipients"] = json!(vec![enc::b64(enc::WRAP_LEN); 512]);
    sqlx::query(
        "INSERT INTO circle_keys (space_uri, key_version, uri, cid, owner_did, record_json, created_at, indexed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, now(), now() - INTERVAL '60 seconds')",
    )
    .bind(SPACE_URI)
    .bind(kv)
    .bind(enc_uri(OWNER_DID, KEY, &format!("{kv:06}")))
    .bind(cid_of(&value))
    .bind(OWNER_DID)
    .bind(&value)
    .execute(pool)
    .await
    .unwrap();
    value
}

async fn get_keys_raw(setup: &Setup, query: &str) -> (StatusCode, Vec<u8>) {
    xrpc_get(
        setup,
        BOB_DID,
        &setup.bob_key,
        "blue.catbird.circle.getKeys",
        &format!("space={}{query}", url_encode(SPACE_URI)),
    )
    .await
}

/// A page of large records stops at the 8 MiB byte cap (well under the 64-row cap); the
/// rest is reachable by paging with `sinceVersion`.
#[sqlx::test(migrations = "./migrations")]
async fn get_keys_page_stops_at_byte_cap(pool: PgPool) {
    let setup = setup(&pool).await;
    for kv in 1..=16 {
        insert_large_key_row(&pool, kv).await;
    }
    let (status, body) = get_keys_raw(&setup, "").await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(
        body.len() <= circle_appview::handlers::keys::GET_KEYS_MAX_PAGE_BYTES,
        "page is {} bytes",
        body.len()
    );
    let first: Value = serde_json::from_slice(&body).unwrap();
    let got = key_versions(&first);
    assert!(
        !got.is_empty() && got.len() < 16,
        "byte cap must cut the page: {got:?}"
    );
    assert_eq!(got, (1..=got.len() as i64).collect::<Vec<_>>());
    assert_eq!(first["latestKeyVersion"], json!(16));

    let last = *got.last().unwrap();
    let (_, body) = get_keys_raw(&setup, &format!("&sinceVersion={last}")).await;
    let second: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(key_versions(&second)[0], last + 1);
}

/// `record` is the stored JSON verbatim: its serialization appears byte-for-byte in the
/// response (recipients as `{"$bytes": ..}`, never integer arrays).
#[sqlx::test(migrations = "./migrations")]
async fn get_keys_record_is_byte_identical_to_stored_json(pool: PgPool) {
    let setup = setup(&pool).await;
    insert_large_key_row(&pool, 1).await;
    let stored: Value =
        sqlx::query_scalar("SELECT record_json FROM circle_keys WHERE key_version = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    let (status, body) = get_keys_raw(&setup, "").await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body).unwrap();
    let record_text = serde_json::to_string(&stored).unwrap();
    assert!(
        text.contains(&format!(r#""record":{record_text}"#)),
        "record must be served as stored"
    );
    assert!(
        text.len() < 2 * record_text.len(),
        "no integer-array blow-up"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn get_keys_honours_limit(pool: PgPool) {
    let setup = setup(&pool).await;
    for kv in 1..=5 {
        insert_key_row(&pool, kv, 60).await;
    }
    let (status, body) = get_keys_raw(&setup, "&limit=2&sinceVersion=1").await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let out: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(key_versions(&out), vec![2, 3]);
    let (status, _) = get_keys_raw(&setup, "&limit=65").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// `includeEncrypted` absent or false: the feed omits envelopes (plaintext Circles are
/// unaffected); true: envelopes are served.
#[sqlx::test(migrations = "./migrations")]
async fn feed_include_encrypted_gate(pool: PgPool) {
    let setup = setup(&pool).await;
    ingest_thread_fixture(&setup).await;
    let plain = json!({"$type": "app.bsky.feed.post", "text": "plain", "createdAt": NOW});
    serve_ops(
        &setup,
        PLAIN_SPACE_URI,
        OWNER_DID,
        &[("app.bsky.feed.post", ROOT_RKEY, plain)],
    );
    assert_eq!(sync(&setup, PLAIN_SPACE_URI, OWNER_DID).await, (1, 0));

    for (suffix, space, expected) in [
        ("", SPACE_URI, 0),
        ("&includeEncrypted=false", SPACE_URI, 0),
        ("&includeEncrypted=true", SPACE_URI, 1),
        ("", PLAIN_SPACE_URI, 1),
        ("&includeEncrypted=false", PLAIN_SPACE_URI, 1),
    ] {
        let (status, body) = xrpc_get(
            &setup,
            BOB_DID,
            &setup.bob_key,
            "blue.catbird.circle.getFeed",
            &format!("space={}{suffix}", url_encode(space)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let out: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            out["feed"].as_array().unwrap().len(),
            expected,
            "{space}{suffix}"
        );
    }
}

/// `includeEncrypted` absent or false: an encrypted thread is not served (every node of
/// an encrypted Space is an envelope); true: the thread with its encrypted reply.
#[sqlx::test(migrations = "./migrations")]
async fn thread_include_encrypted_gate(pool: PgPool) {
    let setup = setup(&pool).await;
    ingest_thread_fixture(&setup).await;
    let std_root = format!("at://{OWNER_DID}/{POST}/{ROOT_RKEY}");
    for (suffix, ok) in [
        ("", false),
        ("&includeEncrypted=false", false),
        ("&includeEncrypted=true", true),
    ] {
        let (status, body) = xrpc_get(
            &setup,
            BOB_DID,
            &setup.bob_key,
            "blue.catbird.circle.getPostThread",
            &format!(
                "space={}&uri={}{suffix}",
                url_encode(SPACE_URI),
                url_encode(&std_root)
            ),
        )
        .await;
        let text = String::from_utf8_lossy(&body);
        if ok {
            assert_eq!(status, StatusCode::OK, "{text}");
            let out: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(out["thread"]["replies"].as_array().unwrap().len(), 1);
        } else {
            assert_eq!(status, StatusCode::NOT_FOUND, "{suffix}: {text}");
            assert!(!text.contains("ciphertext"), "{text}");
        }
    }
}

/// Malformed rows do not produce an empty page the client cannot advance past: the page
/// scans forward past them (bounded) and counts them in `skipped`.
#[sqlx::test(migrations = "./migrations")]
async fn get_keys_scans_past_malformed_rows(pool: PgPool) {
    let setup = setup(&pool).await;
    for kv in 1..=4 {
        insert_key_row(&pool, kv, 60).await;
    }
    sqlx::query(
        "UPDATE circle_keys SET record_json = '{\"not\":\"a key\"}' WHERE key_version <= 3",
    )
    .execute(&pool)
    .await
    .unwrap();
    let (status, body) = get_keys_raw(&setup, "&limit=1").await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let out: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(key_versions(&out), vec![4]);
    assert_eq!(out["skipped"], json!(3));
}
