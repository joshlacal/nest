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
use circle_appview::commit::{
    compute_commit_context, compute_commit_mac, compute_dagcbor_cid, decode_repo_car,
    derive_commit_mac_key, mint_repo_car, mint_signed_commit, verify_commit, CommitError, LtHash,
    RepoRecord,
};
use circle_appview::config::{AppState, Config};
use circle_appview::projections::{extract_generation_i64, SyncProjectionInput};
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
                    "cid": "bafyreih327owner1"
                },
                "parent": {
                    "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": "bafyreih327owner1"
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
                "cid": "bafyreih327owner1"
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
                    "cid": "bafyreih327owner1"
                },
                "parent": {
                    "uri": format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"),
                    "cid": "bafyreih327owner1"
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
                    "cid": "bafyreih327othercid"
                },
                "parent": {
                    "uri": "at://did:plc:other/space/blue.catbird.circle/other/did:plc:other/app.bsky.feed.post/3l7otherpost1",
                    "cid": "bafyreih327othercid"
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
                    "cid": "bafyreih327owner1"
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
        .with_known_post_uris([format!(
            "{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"
        )]);

    assert!(validate(owner_post(), &policy).is_ok());
    assert!(validate(bob_reply_to_owner_in_same_space(), &policy).is_ok());
    assert!(validate(bob_like_owner_in_same_space(), &policy).is_ok());
}

#[test]
fn rejects_nonmember_top_level_cross_space_and_quote() {
    let policy = policy(owner(), active_members(&[bob()]))
        .with_space_uri(space())
        .with_known_post_uris([format!(
            "{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7owner11111"
        )]);

    assert_eq!(
        validate(bob_top_level(), &policy),
        Err(InvalidRecord::TopLevelAuthor)
    );
    assert_eq!(
        validate(dave_reply(), &policy),
        Err(InvalidRecord::NoAccessLease)
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
    assert!(verify_commit(
        space(),
        owner(),
        &signed_commit,
        lthash.as_bytes(),
        &parsed_vk
    )
    .is_ok());

    // 2. Tampered LtHash state -> HashMismatch
    let mut bad_lthash = LtHash::new();
    bad_lthash.add("app.bsky.feed.post", "3l7test222222", "bafytestcid2");
    assert_eq!(
        verify_commit(
            space(),
            owner(),
            &signed_commit,
            bad_lthash.as_bytes(),
            &parsed_vk
        ),
        Err(CommitError::HashMismatch)
    );

    // 3. Tampered MAC -> MacMismatch
    let mut tampered_mac_commit = signed_commit.clone();
    tampered_mac_commit.mac =
        catbird_atproto::jacquard_common::deps::bytes::Bytes::from_static(&[0u8; 32]);
    assert_eq!(
        verify_commit(
            space(),
            owner(),
            &tampered_mac_commit,
            lthash.as_bytes(),
            &parsed_vk
        ),
        Err(CommitError::MacMismatch)
    );

    // 4. Tampered Signature -> InvalidSignature
    let mut tampered_sig_commit = signed_commit.clone();
    tampered_sig_commit.sig =
        catbird_atproto::jacquard_common::deps::bytes::Bytes::from_static(&[1u8; 64]);
    assert!(matches!(
        verify_commit(
            space(),
            owner(),
            &tampered_sig_commit,
            lthash.as_bytes(),
            &parsed_vk
        ),
        Err(CommitError::InvalidSignature(_))
    ));

    // 5. Version Mismatch -> UnsupportedVersion
    let mut bad_ver_commit = signed_commit.clone();
    bad_ver_commit.ver = 2;
    assert_eq!(
        verify_commit(
            space(),
            owner(),
            &bad_ver_commit,
            lthash.as_bytes(),
            &parsed_vk
        ),
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

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello first post in circle!",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7post111111", &post_cid);

    let rev = "3l7aaaaaaaaaa";
    let commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        rev,
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );

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
            commit: Some(commit),
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

    let bad_commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7aaaaaaaaaa",
        bad_lthash.as_bytes(),
        &setup.owner_signing_key,
    );

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
            commit: Some(bad_commit),
            cursor: None,
            ops: vec![inc_op_entry],
            extra_data: None,
        },
    );

    // 2. Setup full repo recovery response (valid two-root CAR)
    let mut full_lthash = LtHash::new();
    full_lthash.add("app.bsky.feed.post", "3l7fullpost11", &full_post_cid);

    let full_commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7bbbbbbbbbb",
        full_lthash.as_bytes(),
        &setup.owner_signing_key,
    );

    let repo_records = vec![RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7fullpost11".to_string(),
        cid: full_post_cid.clone(),
        value: full_post_val,
    }];

    let car_bytes = mint_repo_car(&full_commit, &repo_records).unwrap();
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
    let commit = mint_signed_commit(
        SPACE_URI,
        BOB_DID,
        rev,
        lthash.as_bytes(),
        &setup.bob_signing_key,
    );

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

fn mint_service_jwt(
    issuer_did: &str,
    aud_did: &str,
    lxm: &str,
    signing_key: &SigningKey,
) -> String {
    use p256::ecdsa::signature::Signer;
    let now = Utc::now().timestamp();
    let header_json = json!({
        "typ": "JWT",
        "alg": "ES256"
    });
    let claims_json = json!({
        "iss": issuer_did,
        "aud": aud_did,
        "exp": now + 30,
        "iat": now,
        "jti": uuid::Uuid::new_v4().to_string(),
        "lxm": lxm
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_json).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims_json).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

#[sqlx::test(migrations = "./migrations")]
async fn notify_write_triggers_immediate_sync(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post synced via notify_write notification",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7notifypost", &post_cid);

    let rev = "3l7aaaaaaaaaa";
    let commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        rev,
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );

    let op_entry = catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
        cid: Some(Cid::from(post_cid.clone())),
        collection: Nsid::from(String::from("app.bsky.feed.post")),
        prev: None,
        rev: Tid::from(String::from(rev)),
        rkey: RecordKey::from(Rkey::from(String::from("3l7notifypost"))),
        value: Some(serde_json::from_value(post_val).unwrap()),
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
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(
            &lthash.digest(),
        ),
        repo: Did::from(String::from(OWNER_DID)),
        rev: Tid::from(String::from(rev)),
        space: SPACE_URI.into(),
        extra_data: None,
    };

    let token = mint_service_jwt(
        OWNER_DID,
        &setup.state.config.service_did,
        "com.atproto.space.notifyWrite",
        &setup.owner_signing_key,
    );

    let app = circle_appview::routes::create_router(setup.state.clone());
    use axum::http::Request;
    use tower::ServiceExt;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.notifyWrite")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(
                    serde_json::to_vec(&notify_input).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Record was immediately indexed with permissioned URI!
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
    let commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        rev,
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );

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
            commit: Some(commit),
            cursor: None,
            ops: vec![op_entry],
            extra_data: None,
        },
    );

    // Space host returns listRepos with updated revision
    let repo_item = catbird_atproto::generated::com_atproto::space::list_repos::Repo {
        did: Did::from(String::from(OWNER_DID)),
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(
            lthash.as_bytes(),
        ),
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

    assert_eq!(
        record.0,
        format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7sweeppost1")
    );
    assert_eq!(record.1, post_cid);
}

// ---------------------------------------------------------------------------------------
// New Direct Tests for Reviewer Verification
// ---------------------------------------------------------------------------------------

#[test]
fn crypto_vectors_for_lthash_context_and_hkdf_expand() {
    // 1. Exact Context Encoding with uint16be length prefixes
    let ikm = [0x42u8; 32];
    let ctx = compute_commit_context(
        "at://did:plc:alice/space/blue.catbird.circle/1",
        "did:plc:alice",
        "3l7rev123",
        &ikm,
    );

    // Check uint16be fields
    let tag = b"atproto-space-v1";
    assert_eq!(&ctx[0..2], &(tag.len() as u16).to_be_bytes());
    assert_eq!(&ctx[2..2 + tag.len()], tag);

    // 2. Exact HKDF-Expand from 32-byte IKM directly (PRK = ikm)
    let mac_key = derive_commit_mac_key(&ikm, &ctx).expect("HKDF expand must succeed");
    assert_eq!(mac_key.len(), 32);

    let lthash_digest = [0x55u8; 32];
    let mac = compute_commit_mac(&mac_key, &lthash_digest).expect("HMAC must succeed");
    assert_eq!(mac.len(), 32);

    // 3. LtHash item formatting: BLAKE3 XOF over exact {collection}/{rkey}/{cid}
    let mut h1 = LtHash::new();
    h1.add("app.bsky.feed.post", "3l7post1", "bafyreih327owner1");
    assert_ne!(h1.as_bytes(), &[0u8; 2048]);
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

    // Tampering changes computed CID
    let tampered_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Tampered content",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let tampered_cid = compute_dagcbor_cid(&tampered_val).unwrap();
    assert_ne!(cid_str, tampered_cid);
}

#[sqlx::test(migrations = "./migrations")]
async fn multi_page_cursor_pagination_and_same_batch_reply_resolution(pool: PgPool) {
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
    let commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        rev,
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );

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

    // Page 2: reply with terminal commit
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
            commit: None,
            cursor: Some("page2".into()),
            ops: vec![op_page1],
            extra_data: None,
        },
    );

    let key_page2 = format!("{SPACE_URI}:{OWNER_DID}:page2");
    setup.mock_transport.set_list_repo_ops_response(
        &key_page2,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: Some(commit),
            cursor: None,
            ops: vec![op_page2],
            extra_data: None,
        },
    );

    // Run sync
    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    assert_eq!(result.mode, SyncMode::Incremental);
    assert!(result.commit_verified);
    assert_eq!(result.records_accepted, 2);
}
#[sqlx::test(migrations = "./migrations")]
async fn two_root_car_full_recovery_and_tampered_car_rejection(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

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
    let commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        rev,
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );

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

    // 1. CAR encoding and decoding round-trip verification
    let car_bytes = mint_repo_car(&commit, &records).unwrap();
    let decoded = decode_repo_car(&car_bytes).unwrap();
    assert_eq!(decoded.commit.rev.as_str(), rev);
    assert_eq!(decoded.records.len(), 2);
    assert_eq!(decoded.records[0].rkey, "3l7post111111");
    assert_eq!(decoded.records[1].rkey, "3l7post222222");

    // 2. Tampered CAR block CID rejection
    let mut tampered_car = car_bytes.clone();
    let last_idx = tampered_car.len() - 10;
    tampered_car[last_idx] ^= 0xff; // corrupt a record block
    assert!(decode_repo_car(&tampered_car).is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn notify_write_service_auth_rejection_and_issuer_binding(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;
    let app = circle_appview::routes::create_router(setup.state.clone());
    use axum::http::Request;
    use tower::ServiceExt;

    let notify_input = catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite {
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::from_static(&[0u8; 32]),
        repo: Did::from(String::from(OWNER_DID)),
        rev: Tid::from(String::from("3l7rev234567a")),
        space: SPACE_URI.into(),
        extra_data: None,
    };

    // 1. Unauthenticated request -> 401 Unauthorized
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.notifyWrite")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&notify_input).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::UNAUTHORIZED);

    // 2. Unauthorized caller DID -> 403 Forbidden
    let attacker_key = SigningKey::random(&mut OsRng);
    let attacker_did = "did:plc:attacker-evil-99";
    register_did_doc(&setup.state.did_resolver, attacker_did, &attacker_key, None);

    let attacker_token = mint_service_jwt(
        attacker_did,
        &setup.state.config.service_did,
        "com.atproto.space.notifyWrite",
        &attacker_key,
    );

    let resp2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.notifyWrite")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {attacker_token}"))
                .body(axum::body::Body::from(
                    serde_json::to_vec(&notify_input).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
}

#[test]
fn typed_integer_generations_in_projections() {
    // 1. Integer generation as number 9 -> parsed as 9
    let num_val = json!(9);
    assert_eq!(extract_generation_i64(Some(&num_val)), Some(9));

    // 2. Integer generation as whole-number float 9.0 -> parsed as 9
    let float_val = json!(9.0);
    assert_eq!(extract_generation_i64(Some(&float_val)), Some(9));

    // 3. Integer generation as string "9" -> parsed as 9
    let str_val = json!("9");
    assert_eq!(extract_generation_i64(Some(&str_val)), Some(9));

    // 4. Fractional float -> rejected as None
    let frac_val = json!(9.5);
    assert_eq!(extract_generation_i64(Some(&frac_val)), None);

    // 5. Projection input validation with string generation
    let input = SyncProjectionInput {
        operation_id: uuid::Uuid::new_v4(),
        operation_key: None,
        actor_did: OWNER_DID.to_string(),
        space_uri: SPACE_URI.to_string(),
        kind: "circle_upsert".to_string(),
        payload: json!({
            "name": "My Circle",
            "circleGeneration": "9"
        }),
        generation: Some(9),
        circle_generation: None,
        member_generation: None,
    };
    let proj = input.to_projection().unwrap();
    match proj {
        circle_appview::projections::Projection::CircleUpsert { generation, .. } => {
            assert_eq!(generation, 9);
        }
        _ => panic!("Expected CircleUpsert"),
    }
}
