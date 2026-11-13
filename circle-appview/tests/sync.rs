mod support;
use std::sync::Arc;
use support::{fixture_commit, fixture_star};

use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;

use catbird_atproto::jacquard_common::types::cid::Cid;
use catbird_atproto::jacquard_common::types::nsid::Nsid;
use catbird_atproto::jacquard_common::types::recordkey::RecordKey;
use catbird_atproto::jacquard_common::types::string::Rkey;
use catbird_atproto::jacquard_common::types::tid::Tid;

use circle_appview::access::{ActiveSpaceCredential, CredentialStore, SpaceLockManager};
use circle_appview::auth::{
    DidDocument, DidResolver, DidService, PublicKeyJwk, VerificationMethod,
};
use circle_appview::commit::{compute_dagcbor_cid, LtHash as RepoLtHash, RepoRecord};
use circle_appview::config::{AppState, Config};
use circle_appview::error::AppError;
use circle_appview::space_client::{
    ListWritersOutput, MockSpaceHostTransport, RepoRemoved, RepoWrite, SpaceAppAccess, SpaceClient,
    SpaceConfig, SpacePolicy, WriterUpdate,
};

#[derive(Clone)]
struct TestLtHash {
    inner: RepoLtHash,
    state_buf: Vec<u8>,
}

impl Default for TestLtHash {
    fn default() -> Self {
        Self {
            inner: RepoLtHash::default(),
            state_buf: vec![0u8; 2048],
        }
    }
}

impl TestLtHash {
    fn new() -> Self {
        Self::default()
    }
    fn add(&mut self, collection: &str, rkey: &str, cid: &str) {
        self.inner.add(&format!("{collection}/{rkey}/{cid}"));
        self.state_buf = self.inner.state().to_vec();
    }
    fn remove(&mut self, collection: &str, rkey: &str, cid: &str) {
        self.inner.remove(&format!("{collection}/{rkey}/{cid}"));
        self.state_buf = self.inner.state().to_vec();
    }
    fn as_bytes(&self) -> &[u8; 2048] {
        self.state_buf.as_slice().try_into().unwrap()
    }
    fn digest(&self) -> [u8; 32] {
        self.inner.digest()
    }
}

type LtHash = TestLtHash;
use circle_appview::sync::{sweep_once, SyncEngine, SyncMode};
use circle_appview::validator::{
    active_members, compute_uri_hash, policy, validate, InvalidRecord, RecordCandidate,
};
const OWNER_DID: &str = "did:plc:alice-sync-test";
const BOB_DID: &str = "did:plc:bob-sync-test";
const DAVE_DID: &str = "did:plc:dave-sync-test";
const SPACE_URI: &str = "at://did:plc:alice-sync-test/space/blue.catbird.circle/test-circle";
const OWNER_POST_CID: &str = "bafyreibw72zfc6x2jwhvhk3w23vgt4i7l67v5k2k4z6w7i4j5z4w6i4j5z";
const WRONG_POST_CID: &str = "bafyreibw72zfc6x2jwhvhk3w23vgt4i7l67v5k2k4z6w7i4j5z4w6i4j5w";
const OTHER_POST_CID: &str = "bafyreibw72zfc6x2jwhvhk3w23vgt4i7l67v5k2k4z6w7i4j5z4w6i4j5y";

fn owner() -> &'static str {
    OWNER_DID
}

fn bob() -> &'static str {
    BOB_DID
}

fn space() -> &'static str {
    SPACE_URI
}

fn owner_post() -> RecordCandidate {
    RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7owner11111".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello world from circle owner!",
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    }
}

fn bob_reply_to_owner_in_same_space() -> RecordCandidate {
    RecordCandidate {
        uri: format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.post/3l7bobreply11"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7bobreply11".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello Alice, nice circle!",
            "createdAt": "2026-08-24T12:05:00.000Z",
            "reply": {
                "root": {
                    "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": OWNER_POST_CID
                },
                "parent": {
                    "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": OWNER_POST_CID
                }
            }
        }),
    }
}

fn bob_like_owner_in_same_space() -> RecordCandidate {
    RecordCandidate {
        uri: format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.like/3l7boblike111"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.like".to_string(),
        rkey: "3l7boblike111".to_string(),
        value: json!({
            "$type": "app.bsky.feed.like",
            "subject": {
                "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                "cid": OWNER_POST_CID
            },
            "createdAt": "2026-08-24T12:10:00.000Z"
        }),
    }
}

fn bob_top_level() -> RecordCandidate {
    RecordCandidate {
        uri: format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.post/3l7bobtop1111"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7bobtop1111".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Unauthorized top level post from non-owner",
            "createdAt": "2026-08-24T12:15:00.000Z"
        }),
    }
}

fn dave_reply() -> RecordCandidate {
    RecordCandidate {
        uri: format!("{SPACE_URI}/{DAVE_DID}/app.bsky.feed.post/3l7davereply1"),
        author_did: DAVE_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7davereply1".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Dave does not have an active lease",
            "createdAt": "2026-08-24T12:20:00.000Z",
            "reply": {
                "root": {
                    "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": OWNER_POST_CID
                },
                "parent": {
                    "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": OWNER_POST_CID
                }
            }
        }),
    }
}

fn cross_space_reply() -> RecordCandidate {
    RecordCandidate {
        uri: format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.post/3l7crossreply"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7crossreply".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Replying to post from another space",
            "createdAt": "2026-08-24T12:25:00.000Z",
            "reply": {
                "root": {
                    "uri": "at://did:plc:other/space/blue.catbird.circle/other/did:plc:other/app.bsky.feed.post/3l7otherpost1",
                    "cid": OTHER_POST_CID
                },
                "parent": {
                    "uri": "at://did:plc:other/space/blue.catbird.circle/other/did:plc:other/app.bsky.feed.post/3l7otherpost1",
                    "cid": OTHER_POST_CID
                }
            }
        }),
    }
}

fn quote_post() -> RecordCandidate {
    RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7quote11111"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7quote11111".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Quotes are unsupported in alpha",
            "createdAt": "2026-08-24T12:30:00.000Z",
            "embed": {
                "$type": "app.bsky.embed.record",
                "record": {
                    "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": OWNER_POST_CID
                }
            }
        }),
    }
}

fn repost_record() -> RecordCandidate {
    RecordCandidate {
        uri: format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.repost/3l7repost1111"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.repost".to_string(),
        rkey: "3l7repost1111".to_string(),
        value: json!({
            "$type": "app.bsky.feed.repost",
            "subject": {
                "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                "cid": OWNER_POST_CID
            },
            "createdAt": "2026-08-24T12:35:00.000Z"
        }),
    }
}

// ---------------------------------------------------------------------------------------
// Step 1: Validator Unit Tests
// ---------------------------------------------------------------------------------------

#[test]
fn accepts_owner_post_and_same_space_member_reply() {
    let policy = policy(owner(), active_members(&[bob()]))
        .with_space_uri(space())
        .with_known_posts([(
            format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
            OWNER_POST_CID,
        )]);

    assert!(validate(owner_post(), &policy).is_ok());
    assert!(validate(bob_reply_to_owner_in_same_space(), &policy).is_ok());
    assert!(validate(bob_like_owner_in_same_space(), &policy).is_ok());
}

#[test]
fn rejects_nonmember_top_level_cross_space_and_quote() {
    let policy = policy(owner(), active_members(&[bob()]))
        .with_space_uri(space())
        .with_known_posts([(
            format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
            OWNER_POST_CID,
        )]);

    assert_eq!(
        validate(bob_top_level(), &policy),
        Err(InvalidRecord::TopLevelAuthor)
    );
    assert_eq!(
        validate(dave_reply(), &policy),
        Err(InvalidRecord::NotMember)
    );
    assert_eq!(
        validate(cross_space_reply(), &policy),
        Err(InvalidRecord::CrossSpaceReference)
    );
    assert_eq!(
        validate(quote_post(), &policy),
        Err(InvalidRecord::UnsupportedEmbed)
    );
    assert_eq!(
        validate(repost_record(), &policy),
        Err(InvalidRecord::UnsupportedCollection(
            "app.bsky.feed.repost".into()
        ))
    );
}

// ---------------------------------------------------------------------------------------
// Step 2: LtHash accumulator tests
// ---------------------------------------------------------------------------------------

#[test]
fn lthash_additive_homomorphic_properties() {
    let mut h1 = LtHash::new();
    let mut h2 = LtHash::new();

    // Homomorphic addition is commutative: add(A), add(B) == add(B), add(A)
    h1.add("app.bsky.feed.post", "rkey1", "cid1");
    h1.add("app.bsky.feed.post", "rkey2", "cid2");

    h2.add("app.bsky.feed.post", "rkey2", "cid2");
    h2.add("app.bsky.feed.post", "rkey1", "cid1");

    assert_eq!(h1.as_bytes(), h2.as_bytes());
    assert_eq!(h1.digest(), h2.digest());

    // Homomorphic subtraction cancels addition: add(A), add(B), remove(A) == add(B)
    let mut h3 = LtHash::new();
    h3.add("app.bsky.feed.post", "rkey2", "cid2");

    h1.remove("app.bsky.feed.post", "rkey1", "cid1");
    assert_eq!(h1.as_bytes(), h3.as_bytes());
    assert_eq!(h1.digest(), h3.digest());

    // Empty state after adding and removing all items
    h1.remove("app.bsky.feed.post", "rkey2", "cid2");
    assert_eq!(h1.as_bytes(), LtHash::new().as_bytes());
}

// ---------------------------------------------------------------------------------------
// Test Infrastructure for End-to-End Sync Engine Tests
// ---------------------------------------------------------------------------------------

struct SyncTestSetup {
    state: AppState,
    mock_transport: Arc<MockSpaceHostTransport>,
}

fn register_did_doc(
    resolver: &DidResolver,
    did: &str,
    key: &SigningKey,
    services: Option<Vec<DidService>>,
) {
    let vk = key.verifying_key();
    let point = EncodedPoint::from(vk);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let p256_sec1 = vk.to_encoded_point(true);
    let mut p256_multikey_bytes = vec![0x80, 0x24];
    p256_multikey_bytes.extend_from_slice(p256_sec1.as_bytes());
    let p256_multikey = multibase::encode(multibase::Base::Base58Btc, &p256_multikey_bytes);

    let did_doc = DidDocument {
        id: did.into(),
        verification_method: vec![
            VerificationMethod {
                id: format!("{did}#atproto_space"),
                r#type: "Multikey".into(),
                controller: did.into(),
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: x.clone(),
                    y: Some(y.clone()),
                    kid: None,
                }),
                public_key_multibase: Some(p256_multikey.clone()),
            },
            VerificationMethod {
                id: format!("{did}#atproto"),
                r#type: "Multikey".into(),
                controller: did.into(),
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x,
                    y: Some(y),
                    kid: None,
                }),
                public_key_multibase: Some(p256_multikey),
            },
        ],
        service: services.unwrap_or_default(),
    };
    resolver.insert_cached(did.into(), did_doc);
}

async fn setup_sync_test(pool: PgPool) -> SyncTestSetup {
    support::healthy_identity_fixture(&pool, &[OWNER_DID, BOB_DID, DAVE_DID]).await;
    circle_appview::db::run_migrations(&pool)
        .await
        .expect("Migrations must succeed");

    let owner_key = SigningKey::random(&mut OsRng);
    let bob_key = SigningKey::random(&mut OsRng);

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: "did:web:appview.catbird.blue".into(),
        plc_directory_url: "https://plc.directory".into(),
        identity_relay_url: Some(url::Url::parse("wss://relay.fixture.example.com/").unwrap()),
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: "did:web:appview.catbird.blue#atproto_circles".into(),
        push_signing_key_path: None,
        push_signing_key_hex: None,
    };
    let did_resolver = Arc::new(DidResolver::new(
        config.plc_directory_url.clone(),
        reqwest::Client::builder().no_proxy().build().unwrap(),
    ));

    register_did_doc(
        &did_resolver,
        OWNER_DID,
        &owner_key,
        Some(vec![
            DidService {
                id: "#atproto_space_host".into(),
                r#type: "AtprotoSpaceHost".into(),
                service_endpoint: "https://space.catbird.blue".into(),
            },
            DidService {
                id: "#atproto_pds".into(),
                r#type: "AtprotoPersonalDataServer".into(),
                service_endpoint: "https://pds.alice.blue".into(),
            },
        ]),
    );

    register_did_doc(
        &did_resolver,
        BOB_DID,
        &bob_key,
        Some(vec![DidService {
            id: "#atproto_pds".into(),
            r#type: "AtprotoPersonalDataServer".into(),
            service_endpoint: "https://pds.bob.blue".into(),
        }]),
    );
    let mock_transport = Arc::new(MockSpaceHostTransport::new());
    let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
    let credential_store = Arc::new(CredentialStore::new());
    let space_locks = Arc::new(SpaceLockManager::new());

    // Pre-populate credential in store for space
    let signing_key = SigningKey::random(&mut OsRng);
    credential_store
        .insert(
            SPACE_URI.to_string(),
            ActiveSpaceCredential {
                token: "test.space.credential.jwt".to_string(),
                signing_key,
                expires_at: Utc::now() + chrono::Duration::hours(2),
            },
        )
        .await;

    let state = AppState::with_services(
        config,
        pool.clone(),
        did_resolver,
        credential_store,
        space_client,
        space_locks,
    );

    // Populate circle and member in DB with active lease
    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at) VALUES ($1, '3l7syncaaaaaa', $2, 'Test Circle', now())",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_member_cache (space_uri, member_did, cached_at) VALUES ($1, $2, now()), ($1, $3, now())",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(BOB_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count) VALUES ($1, now(), 2)",
    )
    .bind(SPACE_URI)
    .execute(&pool)
    .await
    .unwrap();

    SyncTestSetup {
        state,
        mock_transport,
    }
}
async fn callback_token(pool: &PgPool) -> String {
    circle_appview::notify::get_or_create_registration(pool, SPACE_URI, "http://127.0.0.1:3002")
        .await
        .unwrap()
        .token
}

fn repo_write_update(
    repo: &str,
    repo_rev: &str,
    data: &[u8],
    space_rev: &str,
    prev_space_rev: Option<&str>,
) -> serde_json::Value {
    serde_json::to_value(WriterUpdate::RepoWrite(RepoWrite {
        repo: repo.into(),
        repo_rev: repo_rev.into(),
        data: bytes::Bytes::copy_from_slice(data),
        space_rev: space_rev.into(),
        prev_space_rev: prev_space_rev.map(str::to_owned),
    }))
    .unwrap()
}

fn notify_body(token: &str, update: serde_json::Value) -> bytes::Bytes {
    bytes::Bytes::from(
        serde_json::to_vec(&json!({
            "space": SPACE_URI,
            "token": token,
            "update": update,
        }))
        .unwrap(),
    )
}

// ---------------------------------------------------------------------------------------
// Step 4: Incremental Sync and Hash Mismatch Recovery Tests
// ---------------------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn incremental_sync_applies_ops_and_updates_sync_state(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello first post in circle!",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7post111111", &post_cid);

    let rev = "3l7aaaaaaaaaa";
    let commit = fixture_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes());

    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(post_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7post111111"))),
        value: Some(serde_json::from_value(post_val).unwrap()),
        extra_data: None,
    };

    let list_ops_output =
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit,
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        };

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup
        .mock_transport
        .set_list_repo_ops_response(&key, list_ops_output);

    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    assert_eq!(result.mode, SyncMode::Incremental);
    assert!(result.commit_verified);
    assert_eq!(result.records_accepted, 1);
    assert_eq!(result.records_rejected, 0);

    // Verify record in circle_records table has permissioned full URI
    let record: (String, String, String) = sqlx::query_as(
        "SELECT uri, cid, collection FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        record.0,
        format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7post111111")
    );
    assert_eq!(record.1, post_cid);
    assert_eq!(record.2, "app.bsky.feed.post");

    // Verify sync state in circle_repo_sync_state table
    let sync_state: (String, Vec<u8>) = sqlx::query_as(
        "SELECT last_rev, last_hash FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(sync_state.0, rev);
    assert_eq!(sync_state.1, lthash.as_bytes().to_vec());
}

#[sqlx::test(migrations = "./migrations")]
async fn hash_mismatch_forces_full_repo_recovery(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let full_post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Full recovery restored post",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let full_post_cid = compute_dagcbor_cid(&full_post_val).unwrap();

    let inc_post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Incremental post with bad hash commit",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let inc_post_cid = compute_dagcbor_cid(&inc_post_val).unwrap();

    // 1. Setup incremental ops with an intentionally corrupted/mismatched hash in commit
    let mut bad_lthash = LtHash::new();
    bad_lthash.add("app.bsky.feed.post", "3l7tampered11", "bafytamperedcid");

    let bad_commit = fixture_commit(SPACE_URI, OWNER_DID, "3l7aaaaaaaaaa", bad_lthash.as_bytes());

    let inc_op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(inc_post_cid)),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from("3l7aaaaaaaaaa")),
        rkey: RecordKey::from(Rkey::from(String::from("3l7post111111"))),
        value: Some(serde_json::from_value(inc_post_val).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: bad_commit,
            cursor: None,
            ops: vec![inc_op_entry],
            extra_data: None,
        },
    );

    // 2. Setup full repo recovery response (valid two-root CAR)
    let mut full_lthash = LtHash::new();
    full_lthash.add("app.bsky.feed.post", "3l7fullpost11", &full_post_cid);

    let full_commit = fixture_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7bbbbbbbbbb",
        full_lthash.as_bytes(),
    );

    let repo_records = vec![RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7fullpost11".to_string(),
        cid: full_post_cid.clone(),
        value: full_post_val,
    }];

    let car_bytes = fixture_star(&full_commit, &repo_records).unwrap();
    setup.mock_transport.set_get_repo_response(&key, car_bytes);

    // 3. Run sync -> Incremental hash mismatch must transparently trigger FullRecovery!
    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    assert_eq!(result.mode, SyncMode::FullRecovery);
    assert!(result.commit_verified);
    assert_eq!(result.records_accepted, 1);

    // Verify full recovery record is in database with permissioned URI
    let record: (String, String) = sqlx::query_as(
        "SELECT uri, cid FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        record.0,
        format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7fullpost11")
    );
    assert_eq!(record.1, full_post_cid);

    // Verify sync state matches full recovery
    let sync_state: (String, Vec<u8>) = sqlx::query_as(
        "SELECT last_rev, last_hash FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(sync_state.0, "3l7bbbbbbbbbb");
    assert_eq!(sync_state.1, full_lthash.as_bytes().to_vec());
}

#[sqlx::test(migrations = "./migrations")]
async fn rejected_records_stored_only_in_circle_rejections_diagnostics(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Bob trying to author unauthorized top-level post",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();

    // Bob attempts to author an invalid top-level post
    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7bobinval11", &post_cid);

    let rev = "3l7aaaaaaaaaa";
    let commit = fixture_commit(SPACE_URI, BOB_DID, rev, lthash.as_bytes());

    let invalid_op = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(post_cid)),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7bobinval11"))),
        value: Some(serde_json::from_value(post_val).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{BOB_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit,
            cursor: None,
            ops: vec![invalid_op],
            extra_data: None,
        },
    );

    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    assert_eq!(result.mode, SyncMode::Incremental);
    assert_eq!(result.records_accepted, 0);
    assert_eq!(result.records_rejected, 1);

    // Rejected record must NOT be in circle_records
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(BOB_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 0);

    // Content-free diagnostic must be stored in circle_rejections table
    let rejected_uri = format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.post/3l7bobinval11");
    let expected_hash = compute_uri_hash(&rejected_uri);

    let rejection: (String,) =
        sqlx::query_as("SELECT reason_code FROM circle_rejections WHERE uri_hash = $1")
            .bind(&expected_hash)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(rejection.0, "top_level_author");
}

// ---------------------------------------------------------------------------------------
// Step 5: Notify Write and Sweep Revision Tests
// ---------------------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn notify_space_update_repo_write_triggers_immediate_sync(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post synced via notifySpaceUpdate",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();
    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7notifypost", &post_cid);
    let rev = "3l7aaaaaaaaaa";
    let commit = fixture_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes());
    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(post_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7notifypost"))),
        value: Some(serde_json::from_value(post_val).unwrap()),
        extra_data: None,
    };
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit,
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        },
    );

    let token = callback_token(&pool).await;
    let update = repo_write_update(OWNER_DID, rev, &lthash.digest(), "3l7spacerev2a", None);
    let app = circle_appview::routes::create_router(setup.state.clone());
    use axum::http::Request;
    use tower::ServiceExt;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.notifySpaceUpdate")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(notify_body(&token, update)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    circle_appview::sync::wait_for_notify_syncs_idle().await;
    let record: (String, String) = sqlx::query_as(
        "SELECT uri, cid FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        record.0,
        format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7notifypost")
    );
    assert_eq!(record.1, post_cid);
}
#[sqlx::test(migrations = "./migrations")]
async fn periodic_sweep_repairs_missed_notifications(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post synced via periodic sweep",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7sweeppost1", &post_cid);

    let rev = "3l7aaaaaaaaaa";
    let commit = fixture_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes());

    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(post_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7sweeppost1"))),
        value: Some(serde_json::from_value(post_val).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit,
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        },
    );

    // Space host returns listWriters with the latest writer revision and set hash.
    let repo_item = WriterUpdate::RepoWrite(RepoWrite {
        repo: OWNER_DID.into(),
        repo_rev: rev.into(),
        data: bytes::Bytes::copy_from_slice(&lthash.digest()),
        space_rev: "3l7spacerev2a".into(),
        prev_space_rev: None,
    });
    setup.mock_transport.set_list_writers_response(
        SPACE_URI,
        ListWritersOutput {
            cursor: None,
            repos: vec![repo_item],
        },
    );

    // Run sweep_once
    let summary = sweep_once(&setup.state).await.unwrap();
    assert_eq!(summary.spaces_checked, 1);
    assert_eq!(summary.repos_checked, 1);
    assert_eq!(summary.repos_synced, 1);
    assert_eq!(summary.repos_failed, 0);

    // Record is indexed!
    let record: (String, String) = sqlx::query_as(
        "SELECT uri, cid FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        record.0,
        format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7sweeppost1")
    );
    assert_eq!(record.1, post_cid);
}

// ---------------------------------------------------------------------------------------
// New Direct Tests for Reviewer Verification
// ---------------------------------------------------------------------------------------

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn dagcbor_cid_computation_and_mismatch_rejection() {
    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello world from DAG-CBOR test",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });

    let cid_str = compute_dagcbor_cid(&post_val).expect("DAG-CBOR CID computation must succeed");
    assert!(
        cid_str.starts_with("bafyre"),
        "DAG-CBOR CIDv1 base32 must start with bafyre, got {cid_str}"
    );

    // Direct serialization of Jacquard Data with link and raw bytes preserves DAG-CBOR tags
    let data_with_link: catbird_atproto::jacquard_common::types::value::Data =
        serde_json::from_value(post_val).unwrap();
    let direct_cid =
        compute_dagcbor_cid(&data_with_link).expect("Direct Data CID computation must succeed");
    assert_eq!(cid_str, direct_cid);

    // Tampering changes computed CID
    let tampered_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Tampered content",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let tampered_cid = compute_dagcbor_cid(&tampered_val).unwrap();
    assert_ne!(cid_str, tampered_cid);
}
#[test]
fn exact_fixed_lthash_vector_and_homomorphic_properties() {
    let h0 = LtHash::new();
    assert_eq!(h0.as_bytes(), &[0u8; 2048]);
    assert_eq!(
        to_hex(&h0.digest()),
        "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad"
    );

    let mut h1 = LtHash::new();
    h1.add("app.bsky.feed.post", "3l7post1", "bafyreih327owner1");
    let h1_digest = h1.digest();
    assert_ne!(h1.as_bytes(), &[0u8; 2048]);
    assert_eq!(
        to_hex(&h1_digest),
        "ded1c592c7a508e343df92cdbffa74120f51a1af508d8a21ca657238fe0e9a3d"
    );

    let mut h2 = LtHash::new();
    h2.add("app.bsky.feed.like", "3l7like1", "bafyreih327like1");
    let h2_digest = h2.digest();
    assert_ne!(h2_digest, h1_digest);
    assert_eq!(
        to_hex(&h2_digest),
        "d69fb2031356dd0662a510779dc5ba8a38c5d469cbe44c11a3b767e93cf8df12"
    );

    // Both added to h1
    h1.add("app.bsky.feed.like", "3l7like1", "bafyreih327like1");
    let combined_digest = h1.digest();
    assert_ne!(combined_digest, h1_digest);
    assert_ne!(combined_digest, h2_digest);
    assert_eq!(
        to_hex(&combined_digest),
        "6f85d6d7c5af968c298f1723dcc2c0948f9b5301942f892511a6ce3ec44bf6f4"
    );

    // Remove first item -> equals h2 exactly (homomorphic property)
    h1.remove("app.bsky.feed.post", "3l7post1", "bafyreih327owner1");
    assert_eq!(h1.as_bytes(), h2.as_bytes());
    assert_eq!(h1.digest(), h2_digest);
}

#[test]
fn dagcbor_cid_with_nested_links_and_raw_bytes() {
    let blob_cid_str = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post with embedded blob link and binary bytes",
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [{
                "image": {
                    "$type": "blob",
                    "ref": {
                        "$link": blob_cid_str
                    },
                    "mimeType": "image/jpeg",
                    "size": 12345
                },
                "alt": "an image"
            }]
        },
        "createdAt": "2026-08-24T12:00:00.000Z"
    });

    let cid_str = compute_dagcbor_cid(&post_val).expect("CID computation must succeed");
    assert!(cid_str.starts_with("bafyre"));

    let ipld = circle_appview::commit::json_to_ipld(&post_val).unwrap();
    let json_back: serde_json::Value = serde_json::to_value(&ipld).unwrap();
    assert_eq!(
        json_back["embed"]["images"][0]["image"]["ref"]["$link"],
        blob_cid_str
    );
}

#[test]
fn author_pds_resolution_requires_exact_atproto_pds_id_and_type() {
    use circle_appview::access::resolve_pds_endpoint;
    use circle_appview::auth::{DidDocument, DidService};

    // 1. Wrong id -> rejected
    let doc_wrong_id = DidDocument {
        id: BOB_DID.to_string(),
        verification_method: vec![],
        service: vec![DidService {
            id: "#custom_pds".to_string(),
            r#type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "https://pds.example.com".to_string(),
        }],
    };
    assert!(resolve_pds_endpoint(&doc_wrong_id, BOB_DID).is_err());

    // 2. Wrong type -> rejected
    let doc_wrong_type = DidDocument {
        id: BOB_DID.to_string(),
        verification_method: vec![],
        service: vec![DidService {
            id: "#atproto_pds".to_string(),
            r#type: "SomeOtherService".to_string(),
            service_endpoint: "https://pds.example.com".to_string(),
        }],
    };
    assert!(resolve_pds_endpoint(&doc_wrong_type, BOB_DID).is_err());

    // 3. Fallback to space host rejected for author
    let doc_space_host_only = DidDocument {
        id: BOB_DID.to_string(),
        verification_method: vec![],
        service: vec![DidService {
            id: "#atproto_space_host".to_string(),
            r#type: "AtprotoSpaceHost".to_string(),
            service_endpoint: "https://space.example.com".to_string(),
        }],
    };
    assert!(resolve_pds_endpoint(&doc_space_host_only, BOB_DID).is_err());

    // 4. Exact #atproto_pds and AtprotoPersonalDataServer accepted
    let doc_valid = DidDocument {
        id: BOB_DID.to_string(),
        verification_method: vec![],
        service: vec![DidService {
            id: "#atproto_pds".to_string(),
            r#type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "https://pds.bob.example.com".to_string(),
        }],
    };
    let (endpoint, id) = resolve_pds_endpoint(&doc_valid, BOB_DID).unwrap();
    assert_eq!(endpoint, "https://pds.bob.example.com");
    assert_eq!(id, "#atproto_pds");
}

#[test]
fn strong_references_require_and_verify_matching_cid() {
    let owner_post_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111");
    let correct_cid = OWNER_POST_CID;
    let wrong_cid = WRONG_POST_CID;

    let test_policy = policy(OWNER_DID, [BOB_DID])
        .with_space_uri(SPACE_URI)
        .with_known_posts([(owner_post_uri.clone(), correct_cid.to_string())]);

    // 1. Reply with matching CID -> Accepted
    let valid_reply = bob_reply_to_owner_in_same_space();
    assert!(validate(valid_reply.clone(), &test_policy).is_ok());

    // 2. Reply with wrong CID -> Rejected CrossSpaceReference
    let mut wrong_reply = valid_reply.clone();
    wrong_reply.value["reply"]["parent"]["cid"] = json!(wrong_cid);
    assert_eq!(
        validate(wrong_reply, &test_policy).unwrap_err(),
        InvalidRecord::CrossSpaceReference
    );

    // 3. Reply with missing CID -> Rejected MalformedRecord
    let mut missing_cid_reply = valid_reply.clone();
    missing_cid_reply.value["reply"]["parent"]["cid"] = json!(null);
    assert!(matches!(
        validate(missing_cid_reply, &test_policy).unwrap_err(),
        InvalidRecord::MalformedRecord(_)
    ));

    // 4. Like with matching CID -> Accepted
    let valid_like = bob_like_owner_in_same_space();
    assert!(validate(valid_like.clone(), &test_policy).is_ok());

    // 5. Like with wrong CID -> Rejected CrossSpaceReference
    let mut wrong_like = valid_like.clone();
    wrong_like.value["subject"]["cid"] = json!(wrong_cid);
    assert_eq!(
        validate(wrong_like, &test_policy).unwrap_err(),
        InvalidRecord::CrossSpaceReference
    );
}
#[sqlx::test(migrations = "./migrations")]
async fn multi_page_cursor_pagination_empty_terminal_and_same_batch_reply(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let owner_post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Owner root post on page 1",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let owner_cid = compute_dagcbor_cid(&owner_post_val).unwrap();
    let owner_post_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7page1root");

    let reply_post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Bob reply on page 2 to page 1 post in same batch",
        "createdAt": "2026-08-24T12:05:00.000Z",
        "reply": {
            "root": {
                "uri": owner_post_uri.clone(),
                "cid": owner_cid.clone()
            },
            "parent": {
                "uri": owner_post_uri.clone(),
                "cid": owner_cid.clone()
            }
        }
    });
    let reply_cid = compute_dagcbor_cid(&reply_post_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7page1root", &owner_cid);
    lthash.add("app.bsky.feed.post", "3l7page2reply", &reply_cid);

    let rev = "3l7page2termb";
    let commit = fixture_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes());

    // Page 1: owner post with cursor="page2"
    let op_page1 = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(owner_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from("3l7pageaaaaaa")),
        rkey: RecordKey::from(Rkey::from(String::from("3l7page1root"))),
        value: Some(serde_json::from_value(owner_post_val).unwrap()),
        extra_data: None,
    };

    // Page 2: reply on another full page. A full page still carries a cursor.
    let op_page2 = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(reply_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7page2reply"))),
        value: Some(serde_json::from_value(reply_post_val).unwrap()),
        extra_data: None,
    };

    let key_initial = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key_initial,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit.clone(),
            cursor: Some("page2".into()),
            ops: vec![op_page1],
            extra_data: None,
        },
    );

    let key_page2 = format!("{SPACE_URI}:{OWNER_DID}:page2");
    setup.mock_transport.set_list_repo_ops_response(
        &key_page2,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit.clone(),
            cursor: Some("page3".into()),
            ops: vec![op_page2],
            extra_data: None,
        },
    );

    // Page 3: an empty cursorless page is the terminal page whose commit is
    // authoritative for the running set hash.
    let key_page3 = format!("{SPACE_URI}:{OWNER_DID}:page3");
    setup.mock_transport.set_list_repo_ops_response(
        &key_page3,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit,
            cursor: None,
            ops: vec![],
            extra_data: None,
        },
    );

    // Run sync
    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    assert_eq!(result.mode, SyncMode::Incremental);
    assert!(result.commit_verified);
    assert_eq!(result.records_accepted, 2);
    assert_eq!(
        setup
            .mock_transport
            .recorded_credential_uses()
            .iter()
            .filter(|call| call.method == "com.atproto.space.listRepoOps")
            .count(),
        3,
        "every page, including the empty terminal page, must be fetched"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn repo_not_found_is_empty_for_never_written_and_collected_repos(pool: PgPool) {
    let setup = setup_sync_test(pool).await;
    setup
        .mock_transport
        .set_list_repo_ops_not_found(&format!("{SPACE_URI}:{OWNER_DID}"));

    let result = SyncEngine::new(&setup.state)
        .sync_repo(SPACE_URI, OWNER_DID)
        .await
        .unwrap();

    assert_eq!(result.mode, SyncMode::Incremental);
    assert!(result.commit_verified);
    assert_eq!(result.ops_applied, 0);
    assert_eq!(result.records_accepted, 0);
    assert_eq!(result.latest_rev, "");

    sqlx::query(
        "INSERT INTO circle_repo_sync_state \
         (space_uri, author_did, last_rev, last_hash, last_synced_at) \
         VALUES ($1, $2, '3l7emptygcaaa', $3, now())",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(vec![1_u8; 2048])
    .execute(&setup.state.db)
    .await
    .unwrap();
    let record_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7emptypost1");
    sqlx::query(
        "INSERT INTO circle_records \
         (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at) \
         VALUES ($1, 'bafyreicollected', $2, $3, 'app.bsky.feed.post', '3l7emptypost1', $4, now())",
    )
    .bind(&record_uri)
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "cleared"}))
    .execute(&setup.state.db)
    .await
    .unwrap();

    SyncEngine::new(&setup.state)
        .sync_repo_with_expected_commit(
            SPACE_URI,
            OWNER_DID,
            Some(&[0xAA; 32]),
            Some("3l7listedempty"),
        )
        .await
        .unwrap();
    let active_records: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM circle_records \
         WHERE space_uri = $1 AND author_did = $2 AND deleted_at IS NULL",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&setup.state.db)
    .await
    .unwrap();
    let sync_states: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM circle_repo_sync_state \
         WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&setup.state.db)
    .await
    .unwrap();
    assert_eq!(active_records, 0);
    assert_eq!(sync_states, 0);
}
#[sqlx::test(migrations = "./migrations")]
async fn star_roundtrip_and_tampered_record_rejection(pool: PgPool) {
    let _setup = setup_sync_test(pool.clone()).await;

    let post1_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post 1 in CAR recovery",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post1_cid = compute_dagcbor_cid(&post1_val).unwrap();

    let post2_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post 2 in CAR recovery",
        "createdAt": "2026-08-24T12:05:00.000Z"
    });
    let post2_cid = compute_dagcbor_cid(&post2_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7post111111", &post1_cid);
    lthash.add("app.bsky.feed.post", "3l7post222222", &post2_cid);

    let rev = "3l7carrecovbb";
    let commit = fixture_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes());

    let records = vec![
        RepoRecord {
            collection: "app.bsky.feed.post".to_string(),
            rkey: "3l7post111111".to_string(),
            cid: post1_cid.clone(),
            value: post1_val,
        },
        RepoRecord {
            collection: "app.bsky.feed.post".to_string(),
            rkey: "3l7post222222".to_string(),
            cid: post2_cid.clone(),
            value: post2_val,
        },
    ];

    // 1. STAR encoding and decoding round-trip verification
    let car_bytes = fixture_star(&commit, &records).unwrap();
    let decoded =
        circle_appview::space_star::parse_repo_star(&car_bytes, SPACE_URI, OWNER_DID).unwrap();
    assert_eq!(decoded.commit.rev.as_str(), rev);
    assert_eq!(decoded.records.len(), 2);
    assert_eq!(decoded.records[0].1, "3l7post111111");
    assert_eq!(decoded.records[1].1, "3l7post222222");

    // 2. Tampered STAR record rejection
    let mut tampered_car = car_bytes.clone();
    let last_idx = tampered_car.len() - 10;
    tampered_car[last_idx] ^= 0xff; // corrupt a record block
    assert!(
        circle_appview::space_star::parse_repo_star(&tampered_car, SPACE_URI, OWNER_DID).is_err()
    );
}
/// `notifySpaceUpdate` carries the registration token and a fully tagged update.
/// The repo revision and space sequencing fields live inside `repoWrite`.
#[test]
fn notify_space_update_body_parses_the_nov12_shape() {
    use catbird_atproto::generated::com_atproto::space::notify_space_update::NotifySpaceUpdate;

    let update = repo_write_update(OWNER_DID, "3l7rev234567a", &[9; 32], "3l7spacerev2a", None);
    let wire = json!({
        "space": SPACE_URI,
        "token": "opaque-registration-token",
        "update": update,
    });
    let parsed: NotifySpaceUpdate<String> = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(parsed.token, "opaque-registration-token");
    assert_eq!(wire["update"]["$type"], "com.atproto.space.defs#repoWrite");
    assert_eq!(wire["update"]["repoRev"], "3l7rev234567a");
    assert_eq!(wire["update"]["spaceRev"], "3l7spacerev2a");
    assert!(wire.get("repoRev").is_none());
    assert!(wire.get("spaceRev").is_none());

    let legacy = json!({
        "space": SPACE_URI,
        "repo": OWNER_DID,
        "repoRev": "3l7rev234567a",
        "data": vec![9; 32],
    });
    assert!(serde_json::from_value::<NotifySpaceUpdate<String>>(legacy).is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn notify_space_update_wrong_token_and_unknown_space_leak_same_error(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;
    let token = callback_token(&pool).await;
    let update = repo_write_update(OWNER_DID, "3l7rev234567a", &[0; 32], "3l7spacerev2a", None);
    let app = circle_appview::routes::create_router(setup.state.clone());
    use axum::body::to_bytes;
    use axum::http::Request;
    use tower::ServiceExt;

    let wrong = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.notifySpaceUpdate")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(notify_body(
                    "wrong-token",
                    update.clone(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let unknown = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.notifySpaceUpdate")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&json!({
                        "space": "at://did:plc:unknown/space/blue.catbird.circle/missing",
                        "token": token,
                        "update": update,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        to_bytes(wrong.into_body(), usize::MAX).await.unwrap(),
        to_bytes(unknown.into_body(), usize::MAX).await.unwrap(),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn full_recovery_verifies_against_authority_expected_hash_and_rejects_mismatch(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post in full recovery for expected hash check",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7hashpost1", &post_cid);

    let rev = "3l7hashrevaaa";
    let commit = fixture_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes());

    let records = vec![RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7hashpost1".to_string(),
        cid: post_cid.clone(),
        value: post_val,
    }];

    let car_bytes = fixture_star(&commit, &records).unwrap();
    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_get_repo_response(&key, car_bytes);

    // Setup list_repo_ops to fail so sync falls back to full recovery
    let sync_engine = SyncEngine::new(&setup.state);

    // 1. Full recovery with correct expected hash succeeds
    let expected_hash = commit.data.as_ref();
    let result = sync_engine
        .sync_repo_with_expected_hash(SPACE_URI, OWNER_DID, Some(expected_hash))
        .await
        .unwrap();
    assert_eq!(result.mode, SyncMode::FullRecovery);
    assert!(result.commit_verified);

    // 2. Full recovery with mismatched expected authority hash is rejected!
    let bad_expected_hash = [0x99u8; 32];
    let err_result = sync_engine
        .sync_repo_with_expected_hash(SPACE_URI, OWNER_DID, Some(&bad_expected_hash))
        .await;
    assert!(
        err_result.is_err(),
        "Must reject full recovery when authority expected hash mismatches"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn federated_repo_sync_routes_to_member_pds_endpoint(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    // Setup owner post first so Bob can reply
    let owner_post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Owner post on Alice PDS",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let owner_cid = compute_dagcbor_cid(&owner_post_val).unwrap();
    let owner_post_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7ownerroot");

    sqlx::query(
        "INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, indexed_at, created_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7ownerroot', $5, now(), now())",
    )
    .bind(&owner_post_uri)
    .bind(&owner_cid)
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(&owner_post_val)
    .execute(&pool)
    .await
    .unwrap();

    // Bob's federated reply on Bob's PDS (https://pds.bob.blue)
    let bob_reply_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Bob replying from his federated PDS",
        "createdAt": "2026-08-24T12:05:00.000Z",
        "reply": {
            "root": {
                "uri": owner_post_uri.clone(),
                "cid": owner_cid.clone()
            },
            "parent": {
                "uri": owner_post_uri.clone(),
                "cid": owner_cid.clone()
            }
        }
    });
    let bob_reply_cid = compute_dagcbor_cid(&bob_reply_val).unwrap();

    let mut bob_lthash = LtHash::new();
    bob_lthash.add("app.bsky.feed.post", "3l7bobreplyfed", &bob_reply_cid);

    let rev = "3l7bobfedreva";
    let bob_commit = fixture_commit(SPACE_URI, BOB_DID, rev, bob_lthash.as_bytes());

    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(bob_reply_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7bobreplyfed"))),
        value: Some(serde_json::from_value(bob_reply_val).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{BOB_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: bob_commit,
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        },
    );

    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    assert_eq!(result.mode, SyncMode::Incremental);
    assert!(result.commit_verified);
    assert_eq!(result.records_accepted, 1);

    // Bob's reply indexed successfully!
    let record: (String, String) = sqlx::query_as(
        "SELECT uri, cid FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(BOB_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        record.0,
        format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.post/3l7bobreplyfed")
    );
    assert_eq!(record.1, bob_reply_cid);
}

#[sqlx::test(migrations = "./migrations")]
async fn ordered_operations_preserve_delete_then_recreate_on_same_path(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let original_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Original post that will be deleted and recreated",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let original_cid = compute_dagcbor_cid(&original_val).unwrap();

    let new_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Recreated post at same rkey with new content",
        "createdAt": "2026-08-24T12:05:00.000Z"
    });
    let new_cid = compute_dagcbor_cid(&new_val).unwrap();

    let mut lthash = LtHash::new();
    // 1. Created original
    lthash.add("app.bsky.feed.post", "3l7samepath", &original_cid);
    // 2. Deleted original
    lthash.remove("app.bsky.feed.post", "3l7samepath", &original_cid);
    // 3. Recreated with new CID
    lthash.add("app.bsky.feed.post", "3l7samepath", &new_cid);

    let rev = "3l7recreateaa";
    let commit = fixture_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes());

    let op_create_1 = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(original_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from("3l7stepaaaaaa")),
        rkey: RecordKey::from(Rkey::from(String::from("3l7samepath"))),
        value: Some(serde_json::from_value(original_val).unwrap()),
        extra_data: None,
    };

    let op_delete = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: None,
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: Some(Cid::from(original_cid)),
        rev: Tid::from(String::from("3l7stepbbbbbb")),
        rkey: RecordKey::from(Rkey::from(String::from("3l7samepath"))),
        value: None,
        extra_data: None,
    };

    let op_create_2 = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(new_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7samepath"))),
        value: Some(serde_json::from_value(new_val).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit,
            cursor: None,
            ops: vec![op_create_1, op_delete, op_create_2],
            extra_data: None,
        },
    );

    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    assert_eq!(result.mode, SyncMode::Incremental);
    assert!(result.commit_verified);

    // The final state in circle_records must NOT be marked deleted!
    let record: (String, String, Option<chrono::DateTime<Utc>>) = sqlx::query_as(
        "SELECT uri, cid, deleted_at FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(record.1, new_cid);
    assert_eq!(
        record.2, None,
        "Recreated record must be active, not deleted!"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn strong_reference_validation_rejects_without_fail_open_and_ignores_non_posts(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    // 1. In an empty circle, reply to arbitrary URI is strictly rejected (no fail-open)
    let random_reply_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Reply to non-existent post",
        "createdAt": "2026-08-24T12:00:00.000Z",
        "reply": {
            "root": {
                "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/nonexistent"),
                "cid": "bafynonexistent"
            },
            "parent": {
                "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/nonexistent"),
                "cid": "bafynonexistent"
            }
        }
    });
    let random_reply_cid = compute_dagcbor_cid(&random_reply_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7randomrep", &random_reply_cid);

    let rev = "3l7failopenra";
    let commit = fixture_commit(SPACE_URI, BOB_DID, rev, lthash.as_bytes());

    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(random_reply_cid)),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7randomrep"))),
        value: Some(serde_json::from_value(random_reply_val).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{BOB_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit,
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        },
    );

    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();
    assert_eq!(result.records_accepted, 0);
    assert_eq!(result.records_rejected, 1);

    // Rejection recorded in diagnostics
    let rejections_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM circle_rejections")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rejections_count.0, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn like_reconciliation_updates_in_place_and_preserves_cross_user_likes_on_recovery(
    pool: PgPool,
) {
    let setup = setup_sync_test(pool.clone()).await;

    // 1. Owner creates post
    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Owner post to receive likes",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();
    let post_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7likedpost");

    sqlx::query(
        "INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, indexed_at, created_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7likedpost', $5, now(), now())",
    )
    .bind(&post_uri)
    .bind(&post_cid)
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(&post_val)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Bob creates a like on Owner's post
    let bob_like_uri = format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.like/3l7boblike1");
    sqlx::query(
        "INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, indexed_at, created_at) VALUES ($1, 'bafylikecid', $2, $3, 'app.bsky.feed.like', '3l7boblike1', '{}', now(), now())",
    )
    .bind(&bob_like_uri)
    .bind(SPACE_URI)
    .bind(BOB_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at) VALUES ($1, $2, $3, $4, now())",
    )
    .bind(&bob_like_uri)
    .bind(SPACE_URI)
    .bind(&post_uri)
    .bind(BOB_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 3. Owner triggers full recovery with updated post
    let mut full_lthash = LtHash::new();
    full_lthash.add("app.bsky.feed.post", "3l7likedpost", &post_cid);

    let full_commit = fixture_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7fullrecova",
        full_lthash.as_bytes(),
    );

    let records = vec![RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7likedpost".to_string(),
        cid: post_cid,
        value: post_val,
    }];

    let car_bytes = fixture_star(&full_commit, &records).unwrap();
    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_get_repo_response(&key, car_bytes);

    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine
        .sync_repo_with_expected_hash(SPACE_URI, OWNER_DID, Some(full_commit.data.as_ref()))
        .await
        .unwrap();
    assert_eq!(result.mode, SyncMode::FullRecovery);

    // 4. Bob's like on Owner's post MUST STILL EXIST in circle_likes (not cascade-deleted!)
    let bob_like_in_db: Option<(String,)> =
        sqlx::query_as("SELECT uri FROM circle_likes WHERE uri = $1")
            .bind(&bob_like_uri)
            .fetch_optional(&pool)
            .await
            .unwrap();

    assert!(
        bob_like_in_db.is_some(),
        "Bob's like on Owner's post must be preserved after Owner full recovery"
    );
}

#[tokio::test]
async fn ssrf_policy_enforced_across_all_repo_transport_methods() {
    use circle_appview::space_client::DefaultSpaceHostTransport;
    use circle_appview::space_client::SpaceHostTransport;

    let transport = DefaultSpaceHostTransport::new(); // production transport (allow_loopback = false)
    let auth = circle_appview::space_signature::credential_headers(
        &SigningKey::random(&mut OsRng),
        "cred",
        OWNER_DID,
    );

    // 1. list_writers to 127.0.0.1 -> blocked
    let loopback_url =
        url::Url::parse("https://127.0.0.1/xrpc/com.atproto.space.listWriters").unwrap();
    let res1 = transport
        .list_writers(&loopback_url, &auth, SPACE_URI, None)
        .await;
    assert!(matches!(
        res1,
        Err(circle_appview::error::AppError::Unauthorized(_))
    ));

    // 2. list_repo_ops to private IP -> blocked
    let private_url =
        url::Url::parse("https://10.0.0.1/xrpc/com.atproto.space.listRepoOps").unwrap();
    let res2 = transport
        .list_repo_ops(&private_url, &auth, SPACE_URI, OWNER_DID, None, None)
        .await;
    assert!(matches!(
        res2,
        Err(circle_appview::error::AppError::Unauthorized(_))
    ));

    // 3. get_repo to localhost -> blocked
    let localhost_url =
        url::Url::parse("https://localhost/xrpc/com.atproto.space.getRepo").unwrap();
    let res3 = transport
        .get_repo(&localhost_url, &auth, SPACE_URI, OWNER_DID, None)
        .await;
    assert!(matches!(
        res3,
        Err(circle_appview::error::AppError::Unauthorized(_))
    ));

    // 4. get_latest_commit to non-HTTPS -> blocked
    let http_url =
        url::Url::parse("http://space.example.com/xrpc/com.atproto.space.getLatestCommit").unwrap();
    let res4 = transport
        .get_latest_commit(&http_url, &auth, SPACE_URI, OWNER_DID)
        .await;
    assert!(matches!(
        res4,
        Err(circle_appview::error::AppError::InvalidRequest(_))
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn sweep_once_paginates_multiple_pages_of_repos(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post for multi-page sweep discovery",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7sweepp2", &post_cid);
    let rev = "3l7page2revbb";
    let commit = fixture_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes());

    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(post_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7sweepp2"))),
        value: Some(serde_json::from_value(post_val).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit,
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        },
    );

    // listWriters ascends by spaceRev. A full page has a cursor, and an empty
    // cursor-less page terminates the listing.
    let space_rev_1 = "3l7spacerev2a";
    let space_rev_2 = "3l7spacerev2b";
    let entry = |space_rev: &str| {
        WriterUpdate::RepoWrite(RepoWrite {
            repo: OWNER_DID.into(),
            data: bytes::Bytes::copy_from_slice(&lthash.digest()),
            repo_rev: rev.into(),
            space_rev: space_rev.into(),
            prev_space_rev: None,
        })
    };
    setup.mock_transport.set_list_writers_response(
        SPACE_URI,
        ListWritersOutput {
            cursor: Some(space_rev_1.into()),
            repos: vec![entry(space_rev_1)],
        },
    );
    setup.mock_transport.set_list_writers_response(
        &format!("{SPACE_URI}:{space_rev_1}"),
        ListWritersOutput {
            cursor: Some(space_rev_2.into()),
            repos: vec![entry(space_rev_2)],
        },
    );

    setup.mock_transport.set_list_writers_response(
        &format!("{SPACE_URI}:{space_rev_2}"),
        ListWritersOutput {
            cursor: None,
            repos: vec![],
        },
    );

    let summary = sweep_once(&setup.state).await.unwrap();
    assert_eq!(
        summary.repos_checked, 2,
        "the repeated repo is listed twice"
    );
    assert_eq!(
        summary.repos_synced, 1,
        "the repeat matches stored state and is not re-synced"
    );
    assert_eq!(summary.repos_failed, 0);
    assert_eq!(
        setup.mock_transport.recorded_list_writers_cursors(),
        vec![
            None,
            Some(space_rev_1.to_string()),
            Some(space_rev_2.to_string())
        ],
        "each returned cursor is passed back unchanged until an empty page"
    );
    let list_uses: Vec<_> = setup
        .mock_transport
        .recorded_credential_uses()
        .into_iter()
        .filter(|use_| use_.method == "com.atproto.space.listWriters")
        .collect();
    assert_eq!(list_uses.len(), 3);
    for use_ in &list_uses {
        assert_eq!(use_.auth.audience.as_deref(), Some(OWNER_DID));
        assert!(use_
            .auth
            .authorization
            .starts_with("Atproto-Space-Credential "));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn list_writers_repo_removed_then_repo_write_readds_writer(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;
    sqlx::query(
        "INSERT INTO circle_repo_sync_state \
         (space_uri, author_did, last_rev, last_hash, last_synced_at) \
         VALUES ($1, $2, '3l7oldrevaaaa', $3, now())",
    )
    .bind(SPACE_URI)
    .bind(BOB_DID)
    .bind(vec![0_u8; 2048])
    .execute(&pool)
    .await
    .unwrap();
    setup.mock_transport.set_list_writers_response(
        SPACE_URI,
        ListWritersOutput {
            cursor: None,
            repos: vec![WriterUpdate::RepoRemoved(RepoRemoved {
                repo: BOB_DID.into(),
                space_rev: "3l7removedaaa".into(),
                prev_space_rev: None,
            })],
        },
    );

    let removed = sweep_once(&setup.state).await.unwrap();
    assert_eq!(removed.repos_checked, 1);
    assert!(!sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM circle_repo_sync_state \
         WHERE space_uri = $1 AND author_did = $2)",
    )
    .bind(SPACE_URI)
    .bind(BOB_DID)
    .fetch_one(&pool)
    .await
    .unwrap());

    setup.mock_transport.set_space_config(
        SPACE_URI,
        SpaceConfig {
            authority: OWNER_DID.into(),
            space_type: "blue.catbird.circle".into(),
            skey: "3l7syncaaaaaa".into(),
            app_access: SpaceAppAccess::AllowList(vec![setup
                .state
                .oauth_service
                .client_id
                .clone()]),
            read_policy: SpacePolicy::MemberList,
            write_policy: SpacePolicy::MemberList,
            user_policy: None,
            name: Some("Test Circle".into()),
            description: None,
        },
    );
    setup
        .mock_transport
        .set_space_members(SPACE_URI, vec![OWNER_DID.into(), BOB_DID.into()]);

    let state = [0_u8; 2048];
    let repo_rev = "3l7readdaaaaa";
    let commit = fixture_commit(SPACE_URI, BOB_DID, repo_rev, &state);
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{BOB_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit.clone(),
            cursor: None,
            ops: vec![],
            extra_data: None,
        },
    );
    setup.mock_transport.set_list_writers_response(
        SPACE_URI,
        ListWritersOutput {
            cursor: None,
            repos: vec![WriterUpdate::RepoWrite(RepoWrite {
                repo: BOB_DID.into(),
                repo_rev: repo_rev.into(),
                data: commit.data,
                space_rev: "3l7readdedaaa".into(),
                prev_space_rev: Some("3l7removedaaa".into()),
            })],
        },
    );

    let readded = sweep_once(&setup.state).await.unwrap();
    assert_eq!(readded.repos_synced, 1);
    assert_eq!(readded.repos_failed, 0);
    let synced_rev: String = sqlx::query_scalar(
        "SELECT last_rev FROM circle_repo_sync_state \
         WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(BOB_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(synced_rev, repo_rev);
}

#[sqlx::test(migrations = "./migrations")]
async fn notify_space_update_verifies_expected_hash_before_advancing(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;
    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post for notifySpaceUpdate hash check",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();
    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7postnotify1", &post_cid);
    let rev = "3l7notifysync";
    let commit = fixture_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes());
    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(post_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7postnotify1"))),
        value: Some(serde_json::from_value(post_val).unwrap()),
        extra_data: None,
    };
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit,
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        },
    );
    let token = callback_token(&pool).await;

    let mismatch = circle_appview::sync::notify_space_update_handler(
        axum::extract::State(setup.state.clone()),
        notify_body(
            &token,
            repo_write_update(OWNER_DID, rev, &[0x99; 32], "3l7spacerev2a", None),
        ),
    )
    .await;
    assert!(
        mismatch.is_ok(),
        "a valid update is acknowledged before syncing"
    );
    circle_appview::sync::wait_for_notify_syncs_idle().await;
    let indexed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(indexed, 0);
    let synced: Option<String> = sqlx::query_scalar(
        "SELECT last_rev FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(synced.is_none());

    let correct = circle_appview::sync::notify_space_update_handler(
        axum::extract::State(setup.state.clone()),
        notify_body(
            &token,
            repo_write_update(OWNER_DID, rev, &lthash.digest(), "3l7spacerev2a", None),
        ),
    )
    .await;
    assert!(correct.is_ok());
    circle_appview::sync::wait_for_notify_syncs_idle().await;
    let indexed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(indexed, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn full_recovery_excludes_prior_author_posts_from_initial_policy(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    // Step 1: Owner syncs post P1
    let p1_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Initial Owner Post P1",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let p1_cid = compute_dagcbor_cid(&p1_val).unwrap();
    let p1_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7postp11111");

    let mut lthash1 = LtHash::new();
    lthash1.add("app.bsky.feed.post", "3l7postp11111", &p1_cid);
    let commit1 = fixture_commit(SPACE_URI, OWNER_DID, "3l7rev234567a", lthash1.as_bytes());

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit1,
            cursor: None,
            ops: vec![
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: Some(Cid::from(p1_cid.clone())),
                    collection: Nsid::from(String::from("app.bsky.feed.post")),
                    prev: None,
                    rev: Tid::from(String::from("3l7rev234567a")),
                    rkey: RecordKey::from(Rkey::from(String::from("3l7postp11111"))),
                    value: Some(serde_json::from_value(p1_val).unwrap()),
                    extra_data: None,
                },
            ],
            extra_data: None,
        },
    );

    let sync_engine = SyncEngine::new(&setup.state);
    let res1 = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();
    assert_eq!(res1.records_accepted, 1);

    // Step 2: Full recovery from a CAR that contains only a reply referencing P1, but CAR itself does not contain P1.
    let reply_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Reply to deleted P1",
        "createdAt": "2026-08-24T12:05:00.000Z",
        "reply": {
            "root": { "uri": p1_uri.clone(), "cid": p1_cid.clone() },
            "parent": { "uri": p1_uri.clone(), "cid": p1_cid.clone() }
        }
    });
    let reply_cid = compute_dagcbor_cid(&reply_val).unwrap();

    let mut lthash2 = LtHash::new();
    lthash2.add("app.bsky.feed.post", "3l7replyonly1", &reply_cid);
    let commit2 = fixture_commit(SPACE_URI, OWNER_DID, "3l7rev234567b", lthash2.as_bytes());

    let rec_reply = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7replyonly1".to_string(),
        cid: reply_cid,
        value: reply_val,
    };
    let car_bytes = fixture_star(&commit2, &[rec_reply]).unwrap();
    setup.mock_transport.set_get_repo_response(&key, car_bytes);

    let res2 = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();
    assert_eq!(res2.mode, SyncMode::FullRecovery);
    assert_eq!(
        res2.records_rejected, 1,
        "Reply referencing absent P1 must be rejected"
    );
    assert_eq!(res2.records_accepted, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_update_and_post_delete_cleans_derived_likes_and_notifications(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;
    let sync_engine = SyncEngine::new(&setup.state);

    // 1. Alice creates post P1
    let p1_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Target post P1 for likes",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let p1_cid = compute_dagcbor_cid(&p1_val).unwrap();
    let p1_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7targetp111");

    let mut lthash_a = LtHash::new();
    lthash_a.add("app.bsky.feed.post", "3l7targetp111", &p1_cid);
    let commit_a1 = fixture_commit(SPACE_URI, OWNER_DID, "3l7234567a234", lthash_a.as_bytes());

    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit_a1,
            cursor: None,
            ops: vec![
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: Some(Cid::from(p1_cid.clone())),
                    collection: Nsid::from(String::from("app.bsky.feed.post")),
                    prev: None,
                    rev: Tid::from(String::from("3l7234567a234")),
                    rkey: RecordKey::from(Rkey::from(String::from("3l7targetp111"))),
                    value: Some(serde_json::from_value(p1_val).unwrap()),
                    extra_data: None,
                },
            ],
            extra_data: None,
        },
    );
    sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    // 2. Bob creates like L1 pointing to P1
    let l1_val = json!({
        "$type": "app.bsky.feed.like",
        "subject": { "uri": p1_uri.clone(), "cid": p1_cid.clone() },
        "createdAt": "2026-08-24T12:05:00.000Z"
    });
    let l1_cid = compute_dagcbor_cid(&l1_val).unwrap();
    let l1_uri = format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.like/3l7like111111");

    let mut lthash_b = LtHash::new();
    lthash_b.add("app.bsky.feed.like", "3l7like111111", &l1_cid);
    let commit_b1 = fixture_commit(SPACE_URI, BOB_DID, "3l7234567b234", lthash_b.as_bytes());

    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{BOB_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit_b1,
            cursor: None,
            ops: vec![
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: Some(Cid::from(l1_cid.clone())),
                    collection: Nsid::from(String::from("app.bsky.feed.like")),
                    prev: None,
                    rev: Tid::from(String::from("3l7234567b234")),
                    rkey: RecordKey::from(Rkey::from(String::from("3l7like111111"))),
                    value: Some(serde_json::from_value(l1_val).unwrap()),
                    extra_data: None,
                },
            ],
            extra_data: None,
        },
    );
    sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    // Check like exists
    let likes_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM circle_likes WHERE post_uri = $1")
            .bind(&p1_uri)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(likes_count.0, 1);

    // 3. Bob updates like L1 to an invalid non-existent target -> Rejected mutation removes existing circle_likes row!
    let l1_invalid_val = json!({
        "$type": "app.bsky.feed.like",
        "subject": { "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7nonexistent"), "cid": "bafyreih327none1" },
        "createdAt": "2026-08-24T12:10:00.000Z"
    });
    let l1_invalid_cid = compute_dagcbor_cid(&l1_invalid_val).unwrap();

    lthash_b.remove("app.bsky.feed.like", "3l7like111111", &l1_cid);
    lthash_b.add("app.bsky.feed.like", "3l7like111111", &l1_invalid_cid);
    let commit_b2 = fixture_commit(SPACE_URI, BOB_DID, "3l7234567c234", lthash_b.as_bytes());

    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{BOB_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit_b2,
            cursor: None,
            ops: vec![
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: Some(Cid::from(l1_invalid_cid.clone())),
                    collection: Nsid::from(String::from("app.bsky.feed.like")),
                    prev: Some(Cid::from(l1_cid.clone())),
                    rev: Tid::from(String::from("3l7234567c234")),
                    rkey: RecordKey::from(Rkey::from(String::from("3l7like111111"))),
                    value: Some(serde_json::from_value(l1_invalid_val).unwrap()),
                    extra_data: None,
                },
            ],
            extra_data: None,
        },
    );
    let res_b2 = sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();
    assert_eq!(res_b2.records_rejected, 1);

    // Invalid update invalidated previous like row
    let likes_after_rejection: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM circle_likes WHERE uri = $1")
            .bind(&l1_uri)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        likes_after_rejection.0, 0,
        "Invalid update must remove prior circle_likes row"
    );

    // 4. Alice deletes post P1 -> circle_likes pointing to P1 and notifications are deleted
    let mut lthash_a2 = lthash_a.clone();
    lthash_a2.remove("app.bsky.feed.post", "3l7targetp111", &p1_cid);
    let commit_a2 = fixture_commit(SPACE_URI, OWNER_DID, "3l7234567d234", lthash_a2.as_bytes());
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit_a2,
            cursor: None,
            ops: vec![
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: None,
                    collection: Nsid::from(String::from("app.bsky.feed.post")),
                    prev: Some(Cid::from(p1_cid.clone())),
                    rev: Tid::from(String::from("3l7234567d234")),
                    rkey: RecordKey::from(Rkey::from(String::from("3l7targetp111"))),
                    value: None,
                    extra_data: None,
                },
            ],
            extra_data: None,
        },
    );
    sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    let remaining_likes: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM circle_likes WHERE post_uri = $1")
            .bind(&p1_uri)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        remaining_likes.0, 0,
        "Deleting post must remove all circle_likes pointing to it"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn incremental_sync_cursor_cycle_detected_and_enters_recovery(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;
    let sync_engine = SyncEngine::new(&setup.state);

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post recovered after cursor cycle",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7cyclepost1", &post_cid);
    let commit = fixture_commit(SPACE_URI, OWNER_DID, "3l7cyclerev22", lthash.as_bytes());

    let key = format!("{SPACE_URI}:{OWNER_DID}");

    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit.clone(),
            cursor: Some("cursor_A".into()),
            ops: vec![],
            extra_data: None,
        },
    );
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{key}:cursor_A"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit.clone(),
            cursor: Some("cursor_B".into()),
            ops: vec![],
            extra_data: None,
        },
    );
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{key}:cursor_B"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit.clone(),
            cursor: Some("cursor_A".into()), // Cycle!
            ops: vec![],
            extra_data: None,
        },
    );

    let rec = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7cyclepost1".to_string(),
        cid: post_cid,
        value: post_val,
    };
    let car_bytes = fixture_star(&commit, &[rec]).unwrap();
    setup.mock_transport.set_get_repo_response(&key, car_bytes);

    let res = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();
    assert_eq!(
        res.mode,
        SyncMode::FullRecovery,
        "Cursor cycle must enter full recovery"
    );
    assert_eq!(res.records_accepted, 1);
}

// ---------------------------------------------------------------------------------------
// Step 7: Round 4 Adversarial Unit and Integration Tests
// ---------------------------------------------------------------------------------------
#[sqlx::test(migrations = "./migrations")]
async fn notify_space_update_requires_32_byte_hash_and_non_empty_rev(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;
    let app = circle_appview::routes::create_router(setup.state.clone());
    let token = callback_token(&pool).await;
    use axum::http::Request;
    use tower::ServiceExt;

    let short = circle_appview::sync::notify_space_update_handler(
        axum::extract::State(setup.state.clone()),
        notify_body(
            &token,
            repo_write_update(
                OWNER_DID,
                "3l7234567a234",
                &[0x11; 16],
                "3l7spacerev2a",
                None,
            ),
        ),
    )
    .await;
    assert!(matches!(short, Err(AppError::InvalidRequest(_))));

    let body_with_repo_rev = |repo_rev: &str| {
        notify_body(
            &token,
            repo_write_update(DAVE_DID, repo_rev, &[0x22; 32], "3l7spacerev2a", None),
        )
    };
    let valid = circle_appview::sync::notify_space_update_handler(
        axum::extract::State(setup.state.clone()),
        body_with_repo_rev("3l7234567a234"),
    )
    .await;
    assert!(matches!(valid, Err(AppError::Forbidden(_))), "{valid:?}");

    let empty = circle_appview::sync::notify_space_update_handler(
        axum::extract::State(setup.state.clone()),
        body_with_repo_rev(""),
    )
    .await;
    assert!(
        matches!(&empty, Err(AppError::InvalidRequest(_))),
        "Empty repoRev must return InvalidRequest: {empty:?}"
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.notifySpaceUpdate")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body_with_repo_rev("")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn incremental_and_recovery_bind_and_verify_both_hash_and_rev(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;
    let sync_engine = SyncEngine::new(&setup.state);

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post for rev binding check",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7postrev1", &post_cid);
    let commit_rev = "3l7234567a234";
    let commit = fixture_commit(SPACE_URI, OWNER_DID, commit_rev, lthash.as_bytes());

    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(post_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(commit_rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7postrev1"))),
        value: Some(serde_json::from_value(post_val.clone()).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit.clone(),
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        },
    );

    let rec = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7postrev1".to_string(),
        cid: post_cid.clone(),
        value: post_val,
    };
    let car_bytes = fixture_star(&commit, &[rec]).unwrap();
    setup.mock_transport.set_get_repo_response(&key, car_bytes);

    // 1. Sync with matching hash and matching rev -> Succeeds in incremental mode
    let res = sync_engine
        .sync_repo_with_expected_commit(
            SPACE_URI,
            OWNER_DID,
            Some(commit.data.as_ref()),
            Some(commit_rev),
        )
        .await
        .unwrap();
    assert_eq!(res.mode, SyncMode::Incremental);
    assert_eq!(res.records_accepted, 1);

    // 2. Full recovery with mismatched rev -> Fails
    let err_res = sync_engine
        .sync_repo_with_expected_commit(
            SPACE_URI,
            OWNER_DID,
            Some(commit.data.as_ref()),
            Some("3l7234567b234"),
        )
        .await;
    assert!(
        err_res.is_err(),
        "Full recovery must reject CAR when expected rev does not match"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn full_recovery_retains_other_authors_when_recovering_authority(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;
    let sync_engine = SyncEngine::new(&setup.state);

    // Step 1: Owner syncs post P1
    let p1_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Owner post P1",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let p1_cid = compute_dagcbor_cid(&p1_val).unwrap();
    let mut lthash_owner = LtHash::new();
    lthash_owner.add("app.bsky.feed.post", "3l7p1owner", &p1_cid);
    let commit_owner1 = fixture_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        lthash_owner.as_bytes(),
    );
    let rec_p1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p1owner".to_string(),
        cid: p1_cid.clone(),
        value: p1_val.clone(),
    };
    let car_p1 = fixture_star(&commit_owner1, &[rec_p1]).unwrap();
    let owner_key = format!("{SPACE_URI}:{OWNER_DID}");
    setup
        .mock_transport
        .set_get_repo_response(&owner_key, car_p1);

    sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    // Step 2: Bob replies to Owner P1 with R1
    let p1_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p1owner");
    let r1_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Bob reply R1",
        "createdAt": "2026-08-24T12:10:00.000Z",
        "reply": {
            "root": { "uri": &p1_uri, "cid": &p1_cid },
            "parent": { "uri": &p1_uri, "cid": &p1_cid }
        }
    });
    let r1_cid = compute_dagcbor_cid(&r1_val).unwrap();
    let mut lthash_bob = LtHash::new();
    lthash_bob.add("app.bsky.feed.post", "3l7r1bob", &r1_cid);
    let commit_bob = fixture_commit(SPACE_URI, BOB_DID, "3l7234567b234", lthash_bob.as_bytes());
    let rec_r1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7r1bob".to_string(),
        cid: r1_cid.clone(),
        value: r1_val,
    };
    let car_bob = fixture_star(&commit_bob, &[rec_r1]).unwrap();
    let bob_key = format!("{SPACE_URI}:{BOB_DID}");
    setup
        .mock_transport
        .set_get_repo_response(&bob_key, car_bob);

    sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    // Step 3: Owner undergoes FULL RECOVERY with P1 and a new post P2
    let p2_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Owner post P2",
        "createdAt": "2026-08-24T12:20:00.000Z"
    });
    let p2_cid = compute_dagcbor_cid(&p2_val).unwrap();
    lthash_owner.add("app.bsky.feed.post", "3l7p2owner", &p2_cid);
    let commit_owner2 = fixture_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567c234",
        lthash_owner.as_bytes(),
    );
    let rec_p2 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p2owner".to_string(),
        cid: p2_cid,
        value: p2_val,
    };
    let rec_p1_renew = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p1owner".to_string(),
        cid: p1_cid,
        value: p1_val,
    };
    let car_owner_full = fixture_star(&commit_owner2, &[rec_p1_renew, rec_p2]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&owner_key, car_owner_full);

    // Force full recovery on owner
    let res_recovery = sync_engine
        .sync_repo_with_expected_hash(SPACE_URI, OWNER_DID, Some(commit_owner2.data.as_ref()))
        .await
        .unwrap();
    assert_eq!(res_recovery.mode, SyncMode::FullRecovery);

    // Verify Bob's reply R1 remains present and untouched in DB!
    let r1_uri = format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.post/3l7r1bob");
    let bob_reply_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM circle_records WHERE uri = $1 AND deleted_at IS NULL")
            .bind(&r1_uri)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        bob_reply_count.0, 1,
        "Owner recovery must NOT delete or invalidate Bob's existing reply"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn staged_rejection_removes_uri_from_policy_preventing_stale_deps(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;
    let sync_engine = SyncEngine::new(&setup.state);

    // Step 1: Owner creates valid post P1
    let p1_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Initial valid post P1",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let p1_cid = compute_dagcbor_cid(&p1_val).unwrap();
    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7p1target", &p1_cid);
    let commit1 = fixture_commit(SPACE_URI, OWNER_DID, "3l7234567a234", lthash.as_bytes());
    let rec_p1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p1target".to_string(),
        cid: p1_cid.clone(),
        value: p1_val,
    };
    let key = format!("{SPACE_URI}:{OWNER_DID}");
    let car = fixture_star(&commit1, &[rec_p1]).unwrap();
    setup.mock_transport.set_get_repo_response(&key, car);

    sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    // Step 2: Incremental sync where Owner updates P1 with an invalid embed (Quote),
    // and in the SAME batch attempts another operation depending on P1
    let p1_invalid_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Updated with illegal quote",
        "createdAt": "2026-08-24T12:05:00.000Z",
        "embed": {
            "$type": "app.bsky.embed.record",
            "record": { "uri": "at://did:plc:other/app.bsky.feed.post/123", "cid": "bafyquote" }
        }
    });
    let p1_invalid_cid = compute_dagcbor_cid(&p1_invalid_val).unwrap();

    let reply_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Reply attempting to depend on rejected P1",
        "createdAt": "2026-08-24T12:10:00.000Z",
        "reply": {
            "root": { "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p1target"), "cid": &p1_invalid_cid },
            "parent": { "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p1target"), "cid": &p1_invalid_cid }
        }
    });
    let reply_cid = compute_dagcbor_cid(&reply_val).unwrap();

    lthash.remove("app.bsky.feed.post", "3l7p1target", &p1_cid);
    lthash.add("app.bsky.feed.post", "3l7p1target", &p1_invalid_cid);
    lthash.add("app.bsky.feed.post", "3l7replyattempt", &reply_cid);

    let commit2 = fixture_commit(SPACE_URI, OWNER_DID, "3l7234567b234", lthash.as_bytes());

    let op1 = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(p1_invalid_cid)),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: Some(Cid::from(p1_cid)),
        rev: Tid::from(String::from("3l7234567b234")),
        rkey: RecordKey::from(Rkey::from(String::from("3l7p1target"))),
        value: Some(serde_json::from_value(p1_invalid_val).unwrap()),
        extra_data: None,
    };
    let op2 = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(reply_cid)),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from("3l7234567b234")),
        rkey: RecordKey::from(Rkey::from(String::from("3l7replyattempt"))),
        value: Some(serde_json::from_value(reply_val).unwrap()),
        extra_data: None,
    };

    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: commit2,
            cursor: None,
            ops: vec![op1, op2],
            extra_data: None,
        },
    );

    let res = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();
    assert_eq!(res.mode, SyncMode::Incremental);
    assert_eq!(
        res.records_rejected, 2,
        "Both the invalid update and subsequent dependent reply must be rejected"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn notification_provenance_source_uri_and_comprehensive_cleanup_on_update_delete_reject(
    pool: PgPool,
) {
    let setup = setup_sync_test(pool.clone()).await;
    let sync_engine = SyncEngine::new(&setup.state);

    // Step 1: Owner creates post P1
    let p1_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Owner post P1 for notification provenance",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let p1_cid = compute_dagcbor_cid(&p1_val).unwrap();
    let mut lthash_owner = LtHash::new();
    lthash_owner.add("app.bsky.feed.post", "3l7notifpost1", &p1_cid);
    let commit_owner = fixture_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        lthash_owner.as_bytes(),
    );
    let rec_p1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7notifpost1".to_string(),
        cid: p1_cid.clone(),
        value: p1_val,
    };
    let car_owner = fixture_star(&commit_owner, &[rec_p1]).unwrap();
    let owner_key = format!("{SPACE_URI}:{OWNER_DID}");
    setup
        .mock_transport
        .set_get_repo_response(&owner_key, car_owner);
    sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    let p1_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7notifpost1");

    // Step 2: Bob likes P1
    let like_val = json!({
        "$type": "app.bsky.feed.like",
        "subject": { "uri": &p1_uri, "cid": &p1_cid },
        "createdAt": "2026-08-24T12:05:00.000Z"
    });
    let like_cid = compute_dagcbor_cid(&like_val).unwrap();
    let mut lthash_bob = LtHash::new();
    lthash_bob.add("app.bsky.feed.like", "3l7likebob1", &like_cid);
    let commit_bob1 = fixture_commit(SPACE_URI, BOB_DID, "3l7234567b234", lthash_bob.as_bytes());
    let rec_like = RepoRecord {
        collection: "app.bsky.feed.like".to_string(),
        rkey: "3l7likebob1".to_string(),
        cid: like_cid.clone(),
        value: like_val,
    };
    let car_bob1 = fixture_star(&commit_bob1, &[rec_like]).unwrap();
    let bob_key = format!("{SPACE_URI}:{BOB_DID}");
    setup
        .mock_transport
        .set_get_repo_response(&bob_key, car_bob1);
    sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    let like_uri = format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.like/3l7likebob1");

    // Verify notification was created with source_uri = like_uri
    let notif_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM circle_notifications WHERE recipient_did = $1 AND reason = 'like' AND source_uri = $2",
    )
    .bind(OWNER_DID)
    .bind(&like_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        notif_count.0, 1,
        "Like notification must have source_uri set to like URI"
    );

    // Step 3: Bob deletes his like
    lthash_bob.remove("app.bsky.feed.like", "3l7likebob1", &like_cid);
    let commit_bob2 = fixture_commit(SPACE_URI, BOB_DID, "3l7234567c234", lthash_bob.as_bytes());
    let car_bob2 = fixture_star(&commit_bob2, &[]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&bob_key, car_bob2);
    sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    // Verify notification for deleted like was removed
    let remaining_notifs: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM circle_notifications WHERE source_uri = $1")
            .bind(&like_uri)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        remaining_notifs.0, 0,
        "Deleting like must remove its notification via source_uri"
    );
}

#[test]
fn unconditional_cid_equality_rejects_mismatched_or_empty_cids() {
    let p1_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p1");
    let real_cid = OWNER_POST_CID;
    let wrong_cid = WRONG_POST_CID;

    let pol = policy(owner(), active_members(&[bob()]))
        .with_space_uri(space())
        .with_known_posts([(p1_uri.clone(), real_cid)]);

    // 1. Like with matching CID -> Ok
    let valid_like = RecordCandidate {
        uri: format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.like/3l7l1"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.like".to_string(),
        rkey: "3l7l1".to_string(),
        value: json!({
            "$type": "app.bsky.feed.like",
            "subject": { "uri": &p1_uri, "cid": real_cid },
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };
    assert!(validate(valid_like, &pol).is_ok());

    // 2. Like with mismatched CID -> CrossSpaceReference error
    let invalid_like = RecordCandidate {
        uri: format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.like/3l7l2"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.like".to_string(),
        rkey: "3l7l2".to_string(),
        value: json!({
            "$type": "app.bsky.feed.like",
            "subject": { "uri": &p1_uri, "cid": wrong_cid },
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };
    assert_eq!(
        validate(invalid_like, &pol),
        Err(InvalidRecord::CrossSpaceReference)
    );

    // 3. Reply with mismatched root CID -> CrossSpaceReference error
    let invalid_reply = RecordCandidate {
        uri: format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.post/3l7r2"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7r2".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Reply with bad root CID",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "reply": {
                "root": { "uri": &p1_uri, "cid": wrong_cid },
                "parent": { "uri": &p1_uri, "cid": real_cid }
            }
        }),
    };
    assert_eq!(
        validate(invalid_reply, &pol),
        Err(InvalidRecord::CrossSpaceReference)
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn notification_source_identity_preserved_on_unchanged_recovery_and_replaced_on_change(
    pool: PgPool,
) {
    let setup = setup_sync_test(pool.clone()).await;
    let sync_engine = SyncEngine::new(&setup.state);

    // Step 1: Owner creates post P1
    let p1_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post 1 for notification identity test",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let p1_cid = compute_dagcbor_cid(&p1_val).unwrap();
    let mut lthash_owner = LtHash::new();
    lthash_owner.add("app.bsky.feed.post", "3l7notifp1", &p1_cid);
    let commit_owner = fixture_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        lthash_owner.as_bytes(),
    );
    let rec_p1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7notifp1".to_string(),
        cid: p1_cid.clone(),
        value: p1_val,
    };
    let car_owner = fixture_star(&commit_owner, std::slice::from_ref(&rec_p1)).unwrap();
    let owner_key = format!("{SPACE_URI}:{OWNER_DID}");
    setup
        .mock_transport
        .set_get_repo_response(&owner_key, car_owner);
    sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    let p1_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7notifp1");

    // Step 2: Bob likes P1
    let like_val = json!({
        "$type": "app.bsky.feed.like",
        "subject": { "uri": &p1_uri, "cid": &p1_cid },
        "createdAt": "2026-08-24T12:05:00.000Z"
    });
    let like_cid = compute_dagcbor_cid(&like_val).unwrap();
    let mut lthash_bob = LtHash::new();
    lthash_bob.add("app.bsky.feed.like", "3l7like1", &like_cid);
    let commit_bob = fixture_commit(SPACE_URI, BOB_DID, "3l7234567b234", lthash_bob.as_bytes());
    let rec_like = RepoRecord {
        collection: "app.bsky.feed.like".to_string(),
        rkey: "3l7like1".to_string(),
        cid: like_cid.clone(),
        value: like_val.clone(),
    };
    let car_bob = fixture_star(&commit_bob, std::slice::from_ref(&rec_like)).unwrap();
    let bob_key = format!("{SPACE_URI}:{BOB_DID}");
    setup
        .mock_transport
        .set_get_repo_response(&bob_key, car_bob.clone());
    sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    let like_uri = format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.like/3l7like1");

    // Step 3: Fetch the created notification and mark it read
    let initial_notif: (uuid::Uuid, bool, chrono::DateTime<Utc>) = sqlx::query_as(
        "SELECT id, is_read, created_at FROM circle_notifications WHERE source_uri = $1",
    )
    .bind(&like_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!initial_notif.1, "Initial notification must be unread");

    sqlx::query("UPDATE circle_notifications SET is_read = true WHERE id = $1")
        .bind(initial_notif.0)
        .execute(&pool)
        .await
        .unwrap();

    // Step 4: Perform unchanged recovery of Bob's repo
    sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    // Step 5: Verify the notification is completely preserved (same ID, is_read = true, same created_at)
    let preserved_notif: (uuid::Uuid, bool, chrono::DateTime<Utc>) = sqlx::query_as(
        "SELECT id, is_read, created_at FROM circle_notifications WHERE source_uri = $1",
    )
    .bind(&like_uri)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        preserved_notif.0, initial_notif.0,
        "Notification ID must be preserved across unchanged recovery"
    );
    assert!(
        preserved_notif.1,
        "Notification read status must remain true across unchanged recovery"
    );
    assert_eq!(
        preserved_notif.2, initial_notif.2,
        "Notification created_at timestamp must be preserved"
    );

    // Step 6: Bob updates his like to point to a different post P2
    let p2_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post 2 for notification identity test",
        "createdAt": "2026-08-24T12:10:00.000Z"
    });
    let p2_cid = compute_dagcbor_cid(&p2_val).unwrap();
    lthash_owner.add("app.bsky.feed.post", "3l7notifp2", &p2_cid);
    let commit_owner2 = fixture_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a345",
        lthash_owner.as_bytes(),
    );
    let rec_p2 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7notifp2".to_string(),
        cid: p2_cid.clone(),
        value: p2_val,
    };
    let car_owner2 = fixture_star(&commit_owner2, &[rec_p1, rec_p2]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&owner_key, car_owner2);
    sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    let p2_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7notifp2");

    let updated_like_val = json!({
        "$type": "app.bsky.feed.like",
        "subject": { "uri": &p2_uri, "cid": &p2_cid },
        "createdAt": "2026-08-24T12:15:00.000Z"
    });
    let updated_like_cid = compute_dagcbor_cid(&updated_like_val).unwrap();
    lthash_bob.remove("app.bsky.feed.like", "3l7like1", &like_cid);
    lthash_bob.add("app.bsky.feed.like", "3l7like1", &updated_like_cid);
    let commit_bob2 = fixture_commit(SPACE_URI, BOB_DID, "3l7234567b345", lthash_bob.as_bytes());
    let rec_updated_like = RepoRecord {
        collection: "app.bsky.feed.like".to_string(),
        rkey: "3l7like1".to_string(),
        cid: updated_like_cid.clone(),
        value: updated_like_val,
    };
    let car_bob2 = fixture_star(&commit_bob2, &[rec_updated_like]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&bob_key, car_bob2);
    sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    // Step 7: Verify changed like replaces notification (new ID, is_read = false, new subject)
    let replaced_notif: (uuid::Uuid, bool, String) = sqlx::query_as(
        "SELECT id, is_read, subject_uri FROM circle_notifications WHERE source_uri = $1",
    )
    .bind(&like_uri)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_ne!(
        replaced_notif.0, initial_notif.0,
        "Changed source must generate a new notification ID"
    );
    assert!(
        !replaced_notif.1,
        "Changed source must reset is_read to false"
    );
    assert_eq!(
        replaced_notif.2, p2_uri,
        "Notification subject_uri must be updated to P2"
    );
}

#[sqlx::test(migrations = false)]
async fn alpha_migration_purges_legacy_notifications_and_enforces_source_provenance_lifecycle(
    pool: PgPool,
) {
    // 1. Apply pre-000003 schema (migrations 1 and 2)
    let m1 = include_str!("../migrations/20260824000001_initial.sql");
    let m2 = include_str!("../migrations/20260824000002_generations_and_tombstones.sql");
    sqlx::raw_sql(m1).execute(&pool).await.unwrap();
    sqlx::raw_sql(m2).execute(&pool).await.unwrap();

    // Seed circle
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7syncaaaaaa', $2, 'Test Circle', now())
        "#,
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Insert pre-000003 legacy notification (without source_uri column)
    let legacy_id = uuid::Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, is_read, created_at)
        VALUES ($1, $2, $3, $4, 'like', $5, false, now())
        "#,
    )
    .bind(legacy_id)
    .bind(OWNER_DID)
    .bind(SPACE_URI)
    .bind(BOB_DID)
    .bind(format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7dummy"))
    .execute(&pool)
    .await
    .unwrap();

    let count_pre: (i64,) = sqlx::query_as("SELECT count(*) FROM circle_notifications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count_pre.0, 1,
        "Legacy notification must exist before migration 000003"
    );

    // 3. Apply migration 000003
    let m3 = include_str!("../migrations/20260824000003_notification_source_uri.sql");
    sqlx::raw_sql(m3).execute(&pool).await.unwrap();

    // 4. Verify legacy notifications were purged
    let count_post: (i64,) = sqlx::query_as("SELECT count(*) FROM circle_notifications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count_post.0, 0,
        "Legacy notifications must be purged during migration 000003"
    );

    // 5. Verify source_uri is NOT NULL
    let res_null = sqlx::query(
        r#"
        INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
        VALUES ($1, $2, $3, $4, 'like', $5, NULL, false, now())
        "#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(OWNER_DID)
    .bind(SPACE_URI)
    .bind(BOB_DID)
    .bind(format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7dummy"))
    .execute(&pool)
    .await;
    assert!(res_null.is_err(), "source_uri must not allow NULL");

    // 6. Verify source_uri UNIQUE constraint & lifecycle (insert, update, delete)
    let source1 = format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.like/3l7source1");
    let notif_id = uuid::Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
        VALUES ($1, $2, $3, $4, 'like', $5, $6, false, now())
        "#,
    )
    .bind(notif_id)
    .bind(OWNER_DID)
    .bind(SPACE_URI)
    .bind(BOB_DID)
    .bind(format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7dummy"))
    .bind(&source1)
    .execute(&pool)
    .await
    .unwrap();

    let res_dup = sqlx::query(
        r#"
        INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
        VALUES ($1, $2, $3, $4, 'like', $5, $6, false, now())
        "#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(OWNER_DID)
    .bind(SPACE_URI)
    .bind(BOB_DID)
    .bind(format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7dummy"))
    .bind(&source1)
    .execute(&pool)
    .await;
    assert!(
        res_dup.is_err(),
        "Duplicate source_uri must violate unique constraint"
    );

    // Update notification
    sqlx::query("UPDATE circle_notifications SET is_read = true WHERE source_uri = $1")
        .bind(&source1)
        .execute(&pool)
        .await
        .unwrap();

    let read_state: (bool,) =
        sqlx::query_as("SELECT is_read FROM circle_notifications WHERE source_uri = $1")
            .bind(&source1)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(read_state.0);

    // Delete notification
    sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1")
        .bind(&source1)
        .execute(&pool)
        .await
        .unwrap();

    let count_final: (i64,) = sqlx::query_as("SELECT count(*) FROM circle_notifications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count_final.0, 0);
}

#[test]
fn validator_rejects_missing_or_mismatched_type_and_unsupported_embeds() {
    let p1_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p1");
    let real_cid = compute_dagcbor_cid(&json!({"test": "p1"})).unwrap();
    let blob_cid = compute_dagcbor_cid(&json!({"test": "blob"})).unwrap();

    let pol = policy(owner(), active_members(&[bob()]))
        .with_space_uri(space())
        .with_known_posts([(p1_uri.clone(), real_cid)]);

    // 1. Missing $type -> MalformedRecord
    let no_type = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p2"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p2".to_string(),
        value: json!({
            "text": "Post without $type",
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };
    assert!(matches!(
        validate(no_type, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));

    // 2. Mismatched $type -> MalformedRecord
    let wrong_type = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p3"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p3".to_string(),
        value: json!({
            "$type": "app.bsky.feed.like",
            "text": "Post with like $type",
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };
    assert!(matches!(
        validate(wrong_type, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));

    // 3. Post with video embed -> UnsupportedEmbed
    let video_post = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p4"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p4".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with video",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "embed": {
                "$type": "app.bsky.embed.video",
                "video": { "$link": &blob_cid }
            }
        }),
    };
    assert_eq!(
        validate(video_post, &pol),
        Err(InvalidRecord::UnsupportedEmbed)
    );

    // 4. Post with external embed -> UnsupportedEmbed
    let external_post = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p5"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p5".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with external link",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "embed": {
                "$type": "app.bsky.embed.external",
                "external": {
                    "uri": "https://example.com",
                    "title": "Example",
                    "description": "Example site"
                }
            }
        }),
    };
    assert_eq!(
        validate(external_post, &pol),
        Err(InvalidRecord::UnsupportedEmbed)
    );

    // 5. Post with images embed -> Ok
    let images_post = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p6"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p6".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with images",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [{
                    "alt": "An image",
                    "image": {
                        "$type": "blob",
                        "ref": { "$link": &blob_cid },
                        "mimeType": "image/jpeg",
                        "size": 12345
                    }
                }]
            }
        }),
    };
    assert!(validate(images_post, &pol).is_ok());

    // 6. Post with float -> MalformedRecord
    let float_post = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p7"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p7".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with float",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "count": 42.5
        }),
    };
    assert!(matches!(
        validate(float_post, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));
    // 7. Post with > 4 images -> MalformedRecord
    let too_many_images = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p8"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p8".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with 5 images",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [
                    { "alt": "img1", "image": { "$type": "blob", "ref": { "$link": &blob_cid }, "mimeType": "image/jpeg", "size": 100 } },
                    { "alt": "img2", "image": { "$type": "blob", "ref": { "$link": &blob_cid }, "mimeType": "image/jpeg", "size": 100 } },
                    { "alt": "img3", "image": { "$type": "blob", "ref": { "$link": &blob_cid }, "mimeType": "image/jpeg", "size": 100 } },
                    { "alt": "img4", "image": { "$type": "blob", "ref": { "$link": &blob_cid }, "mimeType": "image/jpeg", "size": 100 } },
                    { "alt": "img5", "image": { "$type": "blob", "ref": { "$link": &blob_cid }, "mimeType": "image/jpeg", "size": 100 } }
                ]
            }
        }),
    };
    assert!(matches!(
        validate(too_many_images, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));

    // 8. Post with image > 2MB (2_000_001 bytes) -> MalformedRecord
    let oversized_image = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p9"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p9".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with oversized image",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [{
                    "alt": "oversized",
                    "image": {
                        "$type": "blob",
                        "ref": { "$link": &blob_cid },
                        "mimeType": "image/jpeg",
                        "size": 2000001
                    }
                }]
            }
        }),
    };
    assert!(matches!(
        validate(oversized_image, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));

    // 9. Post with non-image mime type -> MalformedRecord
    let bad_mime_image = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p10"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p10".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with bad mime",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [{
                    "alt": "bad mime",
                    "image": {
                        "$type": "blob",
                        "ref": { "$link": &blob_cid },
                        "mimeType": "application/pdf",
                        "size": 50000
                    }
                }]
            }
        }),
    };
    assert!(matches!(
        validate(bad_mime_image, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));

    // 10. Post with invalid facet index (byteStart < 0) -> MalformedRecord
    let bad_facet_index = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p11"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p11".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with bad facet",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "facets": [{
                "index": { "byteStart": -1, "byteEnd": 5 },
                "features": [{
                    "$type": "app.bsky.richtext.facet#tag",
                    "tag": "rust"
                }]
            }]
        }),
    };
    assert!(matches!(
        validate(bad_facet_index, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));

    // 11. Post with invalid mention DID -> MalformedRecord
    let bad_mention_did = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p12"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p12".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with bad mention",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "facets": [{
                "index": { "byteStart": 0, "byteEnd": 5 },
                "features": [{
                    "$type": "app.bsky.richtext.facet#mention",
                    "did": "not-a-valid-did"
                }]
            }]
        }),
    };
    assert!(matches!(
        validate(bad_mention_did, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));

    // 12. Post with invalid link URI -> MalformedRecord
    let bad_link_uri = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p13"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p13".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with bad link",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "facets": [{
                "index": { "byteStart": 0, "byteEnd": 5 },
                "features": [{
                    "$type": "app.bsky.richtext.facet#link",
                    "uri": "not a valid uri with spaces"
                }]
            }]
        }),
    };
    assert!(matches!(
        validate(bad_link_uri, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));
    // 13. Post with invalid aspect ratio (width < 1 or height < 1) -> MalformedRecord
    let bad_aspect_ratio = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p14"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p14".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with bad aspect ratio",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [{
                    "alt": "bad aspect",
                    "aspectRatio": { "width": 0, "height": 100 },
                    "image": {
                        "$type": "blob",
                        "ref": { "$link": &blob_cid },
                        "mimeType": "image/jpeg",
                        "size": 50000
                    }
                }]
            }
        }),
    };
    assert!(matches!(
        validate(bad_aspect_ratio, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));

    // 14. Post with SelfLabels having > 10 values -> MalformedRecord
    let too_many_labels = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p15"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p15".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with too many labels",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "labels": {
                "$type": "com.atproto.label.defs#selfLabels",
                "values": (0..11).map(|i| json!({"val": format!("label{i}")})).collect::<Vec<_>>()
            }
        }),
    };
    assert!(matches!(
        validate(too_many_labels, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));

    // 15. Post with SelfLabel having empty val -> MalformedRecord
    let empty_label = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p16"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p16".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with empty label",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "labels": {
                "$type": "com.atproto.label.defs#selfLabels",
                "values": [{ "val": "" }]
            }
        }),
    };
    assert!(matches!(
        validate(empty_label, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));

    // 16. Post with entity having negative index range -> MalformedRecord
    let bad_entity_index = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p17"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p17".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with bad entity index",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "entities": [{
                "index": { "start": 5, "end": 2 },
                "type": "mention",
                "value": "did:plc:alice"
            }]
        }),
    };
    assert!(matches!(
        validate(bad_entity_index, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));

    // 17. Post with tag having empty string -> MalformedRecord
    let empty_tag = RecordCandidate {
        uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7p18"),
        author_did: OWNER_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p18".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Post with empty tag",
            "createdAt": "2026-08-24T12:00:00.000Z",
            "tags": [""]
        }),
    };
    assert!(matches!(
        validate(empty_tag, &pol),
        Err(InvalidRecord::MalformedRecord(_))
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn scheduled_revision_sweep_task_repairs_missed_notification_and_shuts_down_cleanly(
    pool: PgPool,
) {
    let setup = setup_sync_test(pool.clone()).await;

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post synced by scheduled background revision sweep",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7sweepsch1", &post_cid);
    let rev = "3l7234567a234";
    let commit = fixture_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes());

    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(post_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7sweepsch1"))),
        value: Some(serde_json::from_value(post_val).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit,
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        },
    );

    let repo_item = WriterUpdate::RepoWrite(RepoWrite {
        repo: OWNER_DID.into(),
        data: bytes::Bytes::copy_from_slice(&lthash.digest()),
        repo_rev: rev.into(),
        space_rev: "3l7spacerev2a".into(),
        prev_space_rev: None,
    });
    setup.mock_transport.set_list_writers_response(
        SPACE_URI,
        ListWritersOutput {
            cursor: None,
            repos: vec![repo_item],
        },
    );

    let expected_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7sweepsch1");

    // Verify the record is absent before listWriters catch-up.
    let before: Option<(String,)> = sqlx::query_as("SELECT uri FROM circle_records WHERE uri = $1")
        .bind(&expected_uri)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(before.is_none(), "Record must not exist before sweep");

    // Spawn the retained background sweep task with a fast interval for test
    let (sweep_handle, shutdown_tx) = circle_appview::sync::spawn_revision_sweep_task(
        setup.state.clone(),
        std::time::Duration::from_millis(50),
    );

    // Poll database for record appearance
    let mut synced = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let after: Option<(String,)> =
            sqlx::query_as("SELECT uri FROM circle_records WHERE uri = $1")
                .bind(&expected_uri)
                .fetch_optional(&pool)
                .await
                .unwrap();
        if after.is_some() {
            synced = true;
            break;
        }
    }
    assert!(
        synced,
        "Scheduled revision sweep must repair missed notification and sync repo"
    );

    // Graceful shutdown
    shutdown_tx.send(true).unwrap();
    let join_res = tokio::time::timeout(std::time::Duration::from_secs(2), sweep_handle).await;
    assert!(join_res.is_ok(), "Sweep task must shut down cleanly");
}

#[sqlx::test(migrations = "./migrations")]
async fn server_graceful_shutdown_drains_connections_and_awaits_sweep(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    // Find an open ephemeral port
    let probe_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe_listener.local_addr().unwrap().port();
    drop(probe_listener);

    let mut config = setup.state.config.as_ref().clone();
    config.host = "127.0.0.1".into();
    config.port = port;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_handle = tokio::spawn(async move {
        circle_appview::run_server_with_shutdown(config, pool, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    // Wait briefly for server to bind and accept connections
    let client = reqwest::Client::new();
    let mut server_ready = false;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Ok(resp) = client
            .get(format!("http://127.0.0.1:{port}/_health"))
            .send()
            .await
        {
            if resp.status() == reqwest::StatusCode::OK {
                server_ready = true;
                break;
            }
        }
    }
    assert!(
        server_ready,
        "Production server must be active and serving endpoints"
    );

    // Trigger graceful shutdown signal
    shutdown_tx.send(()).unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), server_handle)
        .await
        .unwrap();
    assert!(
        result.unwrap().is_ok(),
        "run_server_with_shutdown must exit with Ok(()) on clean shutdown"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn server_graceful_shutdown_propagates_server_error_and_cleans_up_sweep(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    // Hold port open to force server bind error
    let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = blocker.local_addr().unwrap().port();

    let mut config = setup.state.config.as_ref().clone();
    config.host = "127.0.0.1".into();
    config.port = port;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Must propagate error and clean up sweep task without hanging
    let res = circle_appview::run_server_with_shutdown(config, pool, async move {
        let _ = shutdown_rx.await;
    })
    .await;

    assert!(res.is_err(), "Must propagate bind/server error");
    drop(blocker);
    let _ = shutdown_tx.send(());
}

#[cfg(unix)]
#[tokio::test]
async fn shutdown_signal_responds_to_sigterm() {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    let pid = std::process::id();

    let kill_handle = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let _ = std::process::Command::new("kill")
            .arg("-15")
            .arg(pid.to_string())
            .status();
    });

    let res = tokio::time::timeout(std::time::Duration::from_secs(2), sigterm.recv()).await;
    kill_handle.join().unwrap();
    assert!(res.is_ok(), "SIGTERM must trigger signal receiver");
}

// ---------------------------------------------------------------------------------------
// Rejected space credentials (Oct-1 alpha: CredentialRevoked, BadSpaceSignature,
// BadSpaceAudience): evict the credential and never retry it.
// ---------------------------------------------------------------------------------------

const CACHED_CREDENTIAL: &str = "test.space.credential.jwt";

fn credential_use_methods(setup: &SyncTestSetup) -> Vec<&'static str> {
    setup
        .mock_transport
        .recorded_credential_uses()
        .into_iter()
        .map(|u| {
            assert_eq!(
                u.auth.authorization,
                format!("Atproto-Space-Credential {CACHED_CREDENTIAL}"),
                "only the cached credential exists in these tests"
            );
            u.method
        })
        .collect()
}

/// Persist the stable token that authorizeSpaceSync carries on every renewal.
async fn register_notify_fresh(_setup: &SyncTestSetup, pool: &PgPool) {
    let _ = callback_token(pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn rejected_credential_stops_repo_sync_without_get_repo_fallback(pool: PgPool) {
    use circle_appview::error::AuthReason;
    let setup = setup_sync_test(pool.clone()).await;
    setup
        .mock_transport
        .reject_credential_uses(Some(AuthReason::CredentialRevoked));

    let err = SyncEngine::new(&setup.state)
        .sync_repo_with_expected_commit(SPACE_URI, OWNER_DID, None, None)
        .await
        .expect_err("a revoked credential fails the sync");
    assert!(
        matches!(err, AppError::Unauthorized(AuthReason::CredentialRevoked)),
        "{err:?}"
    );
    assert!(
        setup.state.credential_store.get(SPACE_URI).await.is_none(),
        "the rejected credential is evicted"
    );
    assert_eq!(
        credential_use_methods(&setup),
        vec!["com.atproto.space.listRepoOps"],
        "no getRepo full-recovery fallback with the rejected credential"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rejected_credential_stops_the_sweep_and_is_never_retried(pool: PgPool) {
    use circle_appview::error::AuthReason;
    let setup = setup_sync_test(pool.clone()).await;
    register_notify_fresh(&setup, &pool).await;
    setup.mock_transport.set_list_writers_response(
        SPACE_URI,
        ListWritersOutput {
            cursor: Some("3l7spacerev2a".into()),
            repos: vec![WriterUpdate::RepoWrite(RepoWrite {
                repo: OWNER_DID.into(),
                data: bytes::Bytes::copy_from_slice(&[0x11; 32]),
                repo_rev: "3l7234567a234".into(),
                space_rev: "3l7spacerev2a".into(),
                prev_space_rev: None,
            })],
        },
    );
    setup
        .mock_transport
        .reject_credential_uses(Some(AuthReason::BadSpaceSignature));

    let summary = sweep_once(&setup.state).await.unwrap();
    assert_eq!(summary.spaces_checked, 1);
    assert_eq!(summary.repos_checked, 0, "the listing was refused");
    assert!(setup.state.credential_store.get(SPACE_URI).await.is_none());
    assert_eq!(
        credential_use_methods(&setup),
        vec!["com.atproto.space.listWriters"],
        "one refused listWriters, then nothing else with that credential"
    );

    // The host would accept requests again, but the evicted credential is gone
    // and this AppView holds no OAuth session to acquire a replacement with.
    setup.mock_transport.reject_credential_uses(None);
    let summary = sweep_once(&setup.state).await.unwrap();
    assert_eq!(summary.spaces_checked, 1, "the space is still visited");
    assert_eq!(summary.repos_failed, 1, "credential acquisition failed");
    assert_eq!(
        credential_use_methods(&setup),
        vec!["com.atproto.space.listWriters"],
        "the rejected credential is never retried"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn credential_rejected_by_list_writers_is_not_used_for_repo_reads(pool: PgPool) {
    use circle_appview::error::AuthReason;
    let setup = setup_sync_test(pool.clone()).await;
    setup
        .mock_transport
        .reject_credential_uses(Some(AuthReason::BadSpaceAudience));

    let summary = sweep_once(&setup.state).await.unwrap();
    assert_eq!(summary.spaces_checked, 1);
    assert!(setup.state.credential_store.get(SPACE_URI).await.is_none());
    assert_eq!(
        credential_use_methods(&setup),
        vec!["com.atproto.space.listWriters"],
        "no repo read uses a credential listWriters rejected"
    );
}

/// A 13-character TID-alphabet spaceRev that sorts with `i`.
fn space_rev(i: usize) -> String {
    const ALPHABET: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";
    let digit = |shift: usize| ALPHABET[(i >> shift) & 31] as char;
    format!("3l7spacerv{}{}{}", digit(10), digit(5), digit(0))
}

fn writer_entry(i: usize) -> WriterUpdate {
    WriterUpdate::RepoWrite(RepoWrite {
        repo: format!("did:plc:resume-writer-{i}"),
        data: bytes::Bytes::copy_from_slice(&[0x22; 32]),
        repo_rev: "3l7234567a234".into(),
        space_rev: space_rev(i),
        prev_space_rev: None,
    })
}

/// listWriters ascends by spaceRev, so a listing the sweep budget cuts short
/// resumes after its last processed entry rather than restarting and starving
/// the most recently updated writers. A finished listing starts over.
#[sqlx::test(migrations = "./migrations")]
async fn sweep_resumes_a_budget_cut_listing_from_its_last_processed_space_rev(pool: PgPool) {
    use circle_appview::sync::MAX_REPOS_PER_SWEEP;
    let setup = setup_sync_test(pool.clone()).await;
    register_notify_fresh(&setup, &pool).await;
    let writers = MAX_REPOS_PER_SWEEP + 5;
    assert!(space_rev(0) < space_rev(1) && space_rev(1) < space_rev(writers - 1));

    setup.mock_transport.set_list_writers_response(
        SPACE_URI,
        ListWritersOutput {
            cursor: Some(space_rev(writers - 1)),
            repos: (0..writers).map(writer_entry).collect(),
        },
    );
    let cut_at = space_rev(MAX_REPOS_PER_SWEEP - 1);
    setup.mock_transport.set_list_writers_response(
        &format!("{SPACE_URI}:{cut_at}"),
        ListWritersOutput {
            cursor: Some(space_rev(writers - 1)),
            repos: (MAX_REPOS_PER_SWEEP..writers).map(writer_entry).collect(),
        },
    );
    // Past the last writer the mock answers the empty, cursor-less final page.

    let first = sweep_once(&setup.state).await.unwrap();
    assert_eq!(first.repos_checked, MAX_REPOS_PER_SWEEP, "budget cut");
    assert_eq!(
        setup.state.listing_resume.get(SPACE_URI),
        Some(cut_at.clone())
    );

    let second = sweep_once(&setup.state).await.unwrap();
    assert_eq!(second.repos_checked, 5, "the newest writers are reached");
    assert_eq!(setup.state.listing_resume.get(SPACE_URI), None);

    let third = sweep_once(&setup.state).await.unwrap();
    assert_eq!(third.repos_checked, MAX_REPOS_PER_SWEEP);

    assert_eq!(
        setup.mock_transport.recorded_list_writers_cursors(),
        vec![None, Some(cut_at), Some(space_rev(writers - 1)), None,],
        "resume after the last processed spaceRev, then start over once finished"
    );
}
