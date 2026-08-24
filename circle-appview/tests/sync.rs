use std::sync::Arc;

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
use catbird_atproto::jacquard_common::types::did::Did;
use catbird_atproto::jacquard_common::types::nsid::Nsid;
use catbird_atproto::jacquard_common::types::recordkey::RecordKey;
use catbird_atproto::jacquard_common::types::string::Rkey;
use catbird_atproto::jacquard_common::types::tid::Tid;

use circle_appview::access::{ActiveSpaceCredential, CredentialStore, SpaceLockManager};
use circle_appview::auth::{
    DidDocument, DidResolver, DidService, ParsedVerifyingKey, PublicKeyJwk, VerificationMethod,
};
use circle_appview::commit::{mint_signed_commit, verify_commit, CommitError, LtHash};
use circle_appview::config::{AppState, Config};
use circle_appview::space_client::{MockSpaceHostTransport, SpaceClient};
use circle_appview::sync::{sweep_once, SyncEngine, SyncMode};
use circle_appview::validator::{
    active_members, compute_uri_hash, policy, validate, InvalidRecord, RecordCandidate,
};

const OWNER_DID: &str = "did:plc:alice-sync-test";
const BOB_DID: &str = "did:plc:bob-sync-test";
const DAVE_DID: &str = "did:plc:dave-sync-test";
const SPACE_URI: &str = "at://did:plc:alice-sync-test/space/blue.catbird.circle/test-circle";

fn owner() -> &'static str {
    OWNER_DID
}

fn bob() -> &'static str {
    BOB_DID
}

fn dave() -> &'static str {
    DAVE_DID
}

fn space() -> &'static str {
    SPACE_URI
}

fn owner_post() -> RecordCandidate {
    RecordCandidate {
        uri: format!("at://{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
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
        uri: format!("at://{BOB_DID}/app.bsky.feed.post/3l7bobreply11"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7bobreply11".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello Alice, nice circle!",
            "createdAt": "2026-08-24T12:05:00.000Z",
            "reply": {
                "root": {
                    "uri": format!("at://{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": "bafyreih327owner1"
                },
                "parent": {
                    "uri": format!("at://{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": "bafyreih327owner1"
                }
            }
        }),
    }
}

fn bob_like_owner_in_same_space() -> RecordCandidate {
    RecordCandidate {
        uri: format!("at://{BOB_DID}/app.bsky.feed.like/3l7boblike111"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.like".to_string(),
        rkey: "3l7boblike111".to_string(),
        value: json!({
            "$type": "app.bsky.feed.like",
            "subject": {
                "uri": format!("at://{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                "cid": "bafyreih327owner1"
            },
            "createdAt": "2026-08-24T12:10:00.000Z"
        }),
    }
}

fn bob_top_level() -> RecordCandidate {
    RecordCandidate {
        uri: format!("at://{BOB_DID}/app.bsky.feed.post/3l7bobtop1111"),
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
        uri: format!("at://{DAVE_DID}/app.bsky.feed.post/3l7davereply1"),
        author_did: DAVE_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7davereply1".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Dave does not have an active lease",
            "createdAt": "2026-08-24T12:20:00.000Z",
            "reply": {
                "root": {
                    "uri": format!("at://{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": "bafyreih327owner1"
                },
                "parent": {
                    "uri": format!("at://{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": "bafyreih327owner1"
                }
            }
        }),
    }
}

fn cross_space_reply() -> RecordCandidate {
    RecordCandidate {
        uri: format!("at://{BOB_DID}/app.bsky.feed.post/3l7crossreply"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7crossreply".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Replying to post from another space",
            "createdAt": "2026-08-24T12:25:00.000Z",
            "reply": {
                "root": {
                    "uri": "at://did:plc:other/app.bsky.feed.post/3l7otherpost1",
                    "cid": "bafyreih327othercid"
                },
                "parent": {
                    "uri": "at://did:plc:other/app.bsky.feed.post/3l7otherpost1",
                    "cid": "bafyreih327othercid"
                }
            }
        }),
    }
}

fn quote_post() -> RecordCandidate {
    RecordCandidate {
        uri: format!("at://{OWNER_DID}/app.bsky.feed.post/3l7quote11111"),
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
                    "uri": format!("at://{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": "bafyreih327owner1"
                }
            }
        }),
    }
}

fn repost_record() -> RecordCandidate {
    RecordCandidate {
        uri: format!("at://{BOB_DID}/app.bsky.feed.repost/3l7repost1111"),
        author_did: BOB_DID.to_string(),
        collection: "app.bsky.feed.repost".to_string(),
        rkey: "3l7repost1111".to_string(),
        value: json!({
            "$type": "app.bsky.feed.repost",
            "subject": {
                "uri": format!("at://{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                "cid": "bafyreih327owner1"
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
        .with_known_post_uris([format!("at://{OWNER_DID}/app.bsky.feed.post/3l7owner11111")]);

    assert!(validate(owner_post(), &policy).is_ok());
    assert!(validate(bob_reply_to_owner_in_same_space(), &policy).is_ok());
    assert!(validate(bob_like_owner_in_same_space(), &policy).is_ok());
}

#[test]
fn rejects_nonmember_top_level_cross_space_and_quote() {
    let policy = policy(owner(), active_members(&[bob()]))
        .with_space_uri(space())
        .with_known_post_uris([format!("at://{OWNER_DID}/app.bsky.feed.post/3l7owner11111")]);

    assert_eq!(validate(bob_top_level(), &policy), Err(InvalidRecord::TopLevelAuthor));
    assert_eq!(validate(dave_reply(), &policy), Err(InvalidRecord::NoAccessLease));
    assert_eq!(validate(cross_space_reply(), &policy), Err(InvalidRecord::CrossSpaceReference));
    assert_eq!(validate(quote_post(), &policy), Err(InvalidRecord::UnsupportedEmbed));
    assert_eq!(
        validate(repost_record(), &policy),
        Err(InvalidRecord::UnsupportedCollection("app.bsky.feed.repost".into()))
    );
}

// ---------------------------------------------------------------------------------------
// Step 2 & 3: LtHash and Signed Commit Verification Tests
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

#[test]
fn commit_verification_succeeds_and_fails_on_tampering() {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let parsed_vk = ParsedVerifyingKey::P256(*verifying_key);

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7test111111", "bafytestcid1");

    let rev = "3l7aaaaaaaaaa";
    let signed_commit = mint_signed_commit(space(), owner(), rev, lthash.as_bytes(), &signing_key);

    // 1. Valid commit verification succeeds
    assert!(verify_commit(space(), owner(), &signed_commit, lthash.as_bytes(), &parsed_vk).is_ok());

    // 2. Tampered LtHash state -> HashMismatch
    let mut bad_lthash = LtHash::new();
    bad_lthash.add("app.bsky.feed.post", "3l7test222222", "bafytestcid2");
    assert_eq!(
        verify_commit(space(), owner(), &signed_commit, bad_lthash.as_bytes(), &parsed_vk),
        Err(CommitError::HashMismatch)
    );

    // 3. Tampered MAC -> MacMismatch
    let mut tampered_mac_commit = signed_commit.clone();
    tampered_mac_commit.mac = catbird_atproto::jacquard_common::deps::bytes::Bytes::from_static(&[0u8; 32]);
    assert_eq!(
        verify_commit(space(), owner(), &tampered_mac_commit, lthash.as_bytes(), &parsed_vk),
        Err(CommitError::MacMismatch)
    );

    // 4. Tampered Signature -> InvalidSignature
    let mut tampered_sig_commit = signed_commit.clone();
    tampered_sig_commit.sig = catbird_atproto::jacquard_common::deps::bytes::Bytes::from_static(&[1u8; 64]);
    assert!(matches!(
        verify_commit(space(), owner(), &tampered_sig_commit, lthash.as_bytes(), &parsed_vk),
        Err(CommitError::InvalidSignature(_))
    ));

    // 5. Version Mismatch -> UnsupportedVersion
    let mut bad_ver_commit = signed_commit.clone();
    bad_ver_commit.ver = 2;
    assert_eq!(
        verify_commit(space(), owner(), &bad_ver_commit, lthash.as_bytes(), &parsed_vk),
        Err(CommitError::UnsupportedVersion(2))
    );
}

// ---------------------------------------------------------------------------------------
// Test Infrastructure for End-to-End Sync Engine Tests
// ---------------------------------------------------------------------------------------

struct SyncTestSetup {
    state: AppState,
    mock_transport: Arc<MockSpaceHostTransport>,
    owner_signing_key: SigningKey,
    bob_signing_key: SigningKey,
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
        nest_client_id: "https://nest.catbird.blue/client-metadata.json".into(),
        nest_jwks_url: "https://nest.catbird.blue/.well-known/jwks.json".into(),
        nest_verifying_keys: vec![],
    };

    let did_resolver = Arc::new(DidResolver::new(
        config.plc_directory_url.clone(),
        reqwest::Client::builder().no_proxy().build().unwrap(),
    ));

    register_did_doc(
        &did_resolver,
        OWNER_DID,
        &owner_key,
        Some(vec![DidService {
            id: "#atproto_space_host".into(),
            r#type: "AtprotoSpaceHost".into(),
            service_endpoint: "https://space.catbird.blue".into(),
        }]),
    );

    register_did_doc(&did_resolver, BOB_DID, &bob_key, None);

    let mock_transport = Arc::new(MockSpaceHostTransport::new());
    let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
    let credential_store = Arc::new(CredentialStore::new());
    let space_locks = Arc::new(SpaceLockManager::new());

    // Pre-populate credential in store for space
    let dpop_key = SigningKey::random(&mut OsRng);
    credential_store
        .insert(
            SPACE_URI.to_string(),
            ActiveSpaceCredential {
                token: "test.space.credential.jwt".to_string(),
                dpop_key,
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
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Test Circle', now(), 1)",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at) VALUES ($1, $2, 'active', 1, now()), ($1, $3, 'active', 1, now())",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(BOB_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '2 hours'), ($1, $3, now() + interval '2 hours')",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(BOB_DID)
    .execute(&pool)
    .await
    .unwrap();

    SyncTestSetup {
        state,
        mock_transport,
        owner_signing_key: owner_key,
        bob_signing_key: bob_key,
    }
}

// ---------------------------------------------------------------------------------------
// Step 4: Incremental Sync and Hash Mismatch Recovery Tests
// ---------------------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn incremental_sync_applies_ops_and_updates_sync_state(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7post111111", "bafyownerpost1");

    let rev = "3l7aaaaaaaaaa";
    let commit = mint_signed_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes(), &setup.owner_signing_key);

    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(String::from("bafyownerpost1"))),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7post111111"))),
        value: Some(serde_json::from_value(json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello first post in circle!",
            "createdAt": "2026-08-24T12:00:00.000Z"
        })).unwrap()),
        extra_data: None,
    };

    let list_ops_output = catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
        commit: Some(commit),
        cursor: None,
        ops: vec![op_entry],
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(&key, list_ops_output);

    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    assert_eq!(result.mode, SyncMode::Incremental);
    assert!(result.commit_verified);
    assert_eq!(result.records_accepted, 1);
    assert_eq!(result.records_rejected, 0);

    // Verify record in circle_records table
    let record: (String, String, String) = sqlx::query_as(
        "SELECT uri, cid, collection FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(record.0, format!("at://{OWNER_DID}/app.bsky.feed.post/3l7post111111"));
    assert_eq!(record.1, "bafyownerpost1");
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

    // 1. Setup incremental ops with an intentionally corrupted/mismatched hash in commit
    let mut good_lthash = LtHash::new();
    good_lthash.add("app.bsky.feed.post", "3l7post111111", "bafyownerpost1");

    let mut bad_lthash = LtHash::new();
    bad_lthash.add("app.bsky.feed.post", "3l7tampered11", "bafytamperedcid");

    let bad_commit = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7aaaaaaaaaa", bad_lthash.as_bytes(), &setup.owner_signing_key);

    let inc_op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(String::from("bafyownerpost1"))),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from("3l7aaaaaaaaaa")),
        rkey: RecordKey::from(Rkey::from(String::from("3l7post111111"))),
        value: Some(serde_json::from_value(json!({
            "$type": "app.bsky.feed.post",
            "text": "Incremental post with bad hash commit",
            "createdAt": "2026-08-24T12:00:00.000Z"
        })).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: Some(bad_commit),
            cursor: None,
            ops: vec![inc_op_entry],
            extra_data: None,
        },
    );

    // 2. Setup full repo recovery response (valid full repo + valid latest commit)
    let mut full_lthash = LtHash::new();
    full_lthash.add("app.bsky.feed.post", "3l7fullpost11", "bafyfullcid1");

    let full_commit = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7bbbbbbbbbb", full_lthash.as_bytes(), &setup.owner_signing_key);

    let full_op = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(String::from("bafyfullcid1"))),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from("3l7bbbbbbbbbb")),
        rkey: RecordKey::from(Rkey::from(String::from("3l7fullpost11"))),
        value: Some(serde_json::from_value(json!({
            "$type": "app.bsky.feed.post",
            "text": "Full recovery restored post",
            "createdAt": "2026-08-24T12:00:00.000Z"
        })).unwrap()),
        extra_data: None,
    };

    setup.mock_transport.set_get_repo_response(&key, vec![full_op]);
    setup.mock_transport.set_latest_commit(&key, full_commit);

    // 3. Run sync -> Incremental hash mismatch must transparently trigger FullRecovery!
    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    assert_eq!(result.mode, SyncMode::FullRecovery);
    assert!(result.commit_verified);
    assert_eq!(result.records_accepted, 1);

    // Verify full recovery record is in database
    let record: (String, String) = sqlx::query_as(
        "SELECT uri, cid FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(record.0, format!("at://{OWNER_DID}/app.bsky.feed.post/3l7fullpost11"));
    assert_eq!(record.1, "bafyfullcid1");

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

    // Bob attempts to author an invalid top-level post
    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7bobinval11", "bafybobinvalidcid");

    let rev = "3l7aaaaaaaaaa";
    let commit = mint_signed_commit(SPACE_URI, BOB_DID, rev, lthash.as_bytes(), &setup.bob_signing_key);

    let invalid_op = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(String::from("bafybobinvalidcid"))),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7bobinval11"))),
        value: Some(serde_json::from_value(json!({
            "$type": "app.bsky.feed.post",
            "text": "Bob trying to author unauthorized top-level post",
            "createdAt": "2026-08-24T12:00:00.000Z"
        })).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{BOB_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: Some(commit),
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
    let rejected_uri = format!("at://{BOB_DID}/app.bsky.feed.post/3l7bobinval11");
    let expected_hash = compute_uri_hash(&rejected_uri);

    let rejection: (String,) = sqlx::query_as(
        "SELECT reason_code FROM circle_rejections WHERE uri_hash = $1",
    )
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
async fn notify_write_triggers_immediate_sync(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7notifypost", "bafynotifycid");

    let rev = "3l7aaaaaaaaaa";
    let commit = mint_signed_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes(), &setup.owner_signing_key);

    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(String::from("bafynotifycid"))),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7notifypost"))),
        value: Some(serde_json::from_value(json!({
            "$type": "app.bsky.feed.post",
            "text": "Post synced via notify_write notification",
            "createdAt": "2026-08-24T12:00:00.000Z"
        })).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: Some(commit),
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        },
    );

    let notify_input = catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite {
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&lthash.digest()),
        repo: Did::from(String::from(OWNER_DID)),
        rev: Tid::from(String::from(rev)),
        space: SPACE_URI.into(),
        extra_data: None,
    };

    let app = circle_appview::routes::create_router(setup.state.clone());
    use axum::http::Request;
    use tower::ServiceExt;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.notifyWrite")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&notify_input).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Record was immediately indexed!
    let record: (String, String) = sqlx::query_as(
        "SELECT uri, cid FROM circle_records WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(record.0, format!("at://{OWNER_DID}/app.bsky.feed.post/3l7notifypost"));
    assert_eq!(record.1, "bafynotifycid");
}

#[sqlx::test(migrations = "./migrations")]
async fn periodic_sweep_repairs_missed_notifications(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7sweeppost1", "bafysweepcid");

    let rev = "3l7aaaaaaaaaa";
    let commit = mint_signed_commit(SPACE_URI, OWNER_DID, rev, lthash.as_bytes(), &setup.owner_signing_key);

    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(String::from("bafysweepcid"))),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7sweeppost1"))),
        value: Some(serde_json::from_value(json!({
            "$type": "app.bsky.feed.post",
            "text": "Post synced via periodic sweep",
            "createdAt": "2026-08-24T12:00:00.000Z"
        })).unwrap()),
        extra_data: None,
    };

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: Some(commit),
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        },
    );

    // Space host returns listRepos with updated revision
    let repo_item = catbird_atproto::generated::com_atproto::space::list_repos::Repo {
        did: Did::from(String::from(OWNER_DID)),
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(lthash.as_bytes()),
        rev: Tid::from(String::from(rev)),
        extra_data: None,
    };

    setup.mock_transport.set_list_repos_response(
        SPACE_URI,
        catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput {
            cursor: None,
            repos: vec![repo_item],
            extra_data: None,
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

    assert_eq!(record.0, format!("at://{OWNER_DID}/app.bsky.feed.post/3l7sweeppost1"));
    assert_eq!(record.1, "bafysweepcid");
}
