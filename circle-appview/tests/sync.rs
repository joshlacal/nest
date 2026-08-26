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
    derive_commit_mac_key, mint_repo_car, mint_signed_commit, verify_commit,
    CommitError, LtHash, RepoRecord,
};
use circle_appview::config::{AppState, Config};
use circle_appview::error::AppError;
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
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        nest_client_id: "https://nest.catbird.blue/client-metadata.json".into(),
        nest_jwks_url: "https://nest.catbird.blue/.well-known/jwks.json".into(),
        nest_verifying_keys: vec![],
        nest_push_url: None,
        nest_push_audience: None,
        push_key_id: "did:web:appview.catbird.blue#atproto_circle".into(),
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

    // Space host returns listRepos with updated revision and 32-byte SHA256 digest
    let repo_item = catbird_atproto::generated::com_atproto::space::list_repos::Repo {
        did: Did::from(String::from(OWNER_DID)),
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(
            &lthash.digest(),
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

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn crypto_vectors_for_lthash_context_and_hkdf_expand() {
    // 1. Exact Context Encoding with raw protocol tag + uint16be length prefixes
    let ikm = [0x42u8; 32];
    let ctx = compute_commit_context(
        "at://did:plc:alice/space/blue.catbird.circle/1",
        "did:plc:alice",
        "3l7rev123",
        &ikm,
    );

    // Check raw protocol tag (no len prefix) and uint16be fields
    let tag = b"atproto-space-v1";
    assert_eq!(&ctx[0..tag.len()], tag);
    assert_eq!(ctx.len(), 124);
    assert_eq!(
        to_hex(&ctx),
        "617470726f746f2d73706163652d7631002e61743a2f2f6469643a706c633a616c6963652f73706163652f626c75652e636174626972642e636972636c652f31000d6469643a706c633a616c6963650009336c3772657631323300204242424242424242424242424242424242424242424242424242424242424242"
    );

    // 2. Exact HKDF-Expand from 32-byte IKM directly (PRK = ikm)
    let mac_key = derive_commit_mac_key(&ikm, &ctx).expect("HKDF expand must succeed");
    assert_eq!(mac_key.len(), 32);
    assert_eq!(
        to_hex(&mac_key),
        "ed363ae3aa4d3dbcb6413e86db3692eaf4a1713d578cd72b508b3b6ccfa5215c"
    );

    let lthash_digest = [0x55u8; 32];
    let mac = compute_commit_mac(&mac_key, &lthash_digest).expect("HMAC must succeed");
    assert_eq!(mac.len(), 32);
    assert_eq!(
        to_hex(&mac),
        "6842083d790cee0c14f392372f95dffb9fc2c2e8a37807211febca0c729cbe65"
    );
    // 3. LtHash item formatting: direct BLAKE3 XOF over exact {collection}/{rkey}/{cid}
    let mut h1 = LtHash::new();
    h1.add("app.bsky.feed.post", "3l7post1", "bafyreih327owner1");
    assert_ne!(h1.as_bytes(), &[0u8; 2048]);
    assert_eq!(h1.as_bytes().len(), 2048);
    assert_eq!(h1.digest().len(), 32);
    assert_eq!(
        to_hex(&h1.digest()),
        "ded1c592c7a508e343df92cdbffa74120f51a1af508d8a21ca657238fe0e9a3d"
    );
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
    let direct_cid = compute_dagcbor_cid(&data_with_link).expect("Direct Data CID computation must succeed");
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
    let json_back = ipld.to_json();
    assert_eq!(
        json_back["embed"]["images"][0]["image"]["ref"]["$link"],
        blob_cid_str
    );
}

#[test]
fn drisl_canonical_shortest_key_first_and_reorder_rejection() {
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    let rec_z = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "z".to_string(),
        cid: "bafyreiz11111111111111111111111111111111111111111111111".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "z",
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };
    let rec_aa = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "aa".to_string(),
        cid: "bafyreiaa1111111111111111111111111111111111111111111111".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "aa",
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };

    let rec_z_cid = compute_dagcbor_cid(&rec_z.value).unwrap();
    let rec_aa_cid = compute_dagcbor_cid(&rec_aa.value).unwrap();
    let rec_z = RepoRecord { cid: rec_z_cid, ..rec_z };
    let rec_aa = RepoRecord { cid: rec_aa_cid, ..rec_aa };

    let mut lthash = LtHash::new();
    lthash.add(&rec_z.collection, &rec_z.rkey, &rec_z.cid);
    lthash.add(&rec_aa.collection, &rec_aa.rkey, &rec_aa.cid);

    let commit = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7rev234567a", lthash.as_bytes(), &signing_key);
    let car_bytes = mint_repo_car(&commit, &[rec_aa.clone(), rec_z.clone()]).unwrap();
    let decoded = decode_repo_car(&car_bytes).unwrap();
    assert_eq!(decoded.records.len(), 2);
    assert_eq!(decoded.records[0].rkey, "z");
    assert_eq!(decoded.records[1].rkey, "aa");
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
    assert_eq!(id, format!("{BOB_DID}#atproto_pds"));
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
    let commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        rev,
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );

    let records = vec![RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7hashpost1".to_string(),
        cid: post_cid.clone(),
        value: post_val,
    }];

    let car_bytes = mint_repo_car(&commit, &records).unwrap();
    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_get_repo_response(&key, car_bytes);

    // Setup list_repo_ops to fail so sync falls back to full recovery
    let sync_engine = SyncEngine::new(&setup.state);

    // 1. Full recovery with correct expected hash succeeds
    let expected_hash = commit.hash.as_ref();
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
    assert!(err_result.is_err(), "Must reject full recovery when authority expected hash mismatches");
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
    let bob_commit = mint_signed_commit(
        SPACE_URI,
        BOB_DID,
        rev,
        bob_lthash.as_bytes(),
        &setup.bob_signing_key,
    );

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
            commit: Some(bob_commit),
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
    let commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        rev,
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );

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
            commit: Some(commit),
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
    assert_eq!(record.2, None, "Recreated record must be active, not deleted!");
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
    let commit = mint_signed_commit(
        SPACE_URI,
        BOB_DID,
        rev,
        lthash.as_bytes(),
        &setup.bob_signing_key,
    );

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
            commit: Some(commit),
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
async fn like_reconciliation_updates_in_place_and_preserves_cross_user_likes_on_recovery(pool: PgPool) {
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

    let full_commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7fullrecova",
        full_lthash.as_bytes(),
        &setup.owner_signing_key,
    );

    let records = vec![RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7likedpost".to_string(),
        cid: post_cid,
        value: post_val,
    }];

    let car_bytes = mint_repo_car(&full_commit, &records).unwrap();
    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_get_repo_response(&key, car_bytes);

    let sync_engine = SyncEngine::new(&setup.state);
    let result = sync_engine
        .sync_repo_with_expected_hash(SPACE_URI, OWNER_DID, Some(full_commit.hash.as_ref()))
        .await
        .unwrap();
    assert_eq!(result.mode, SyncMode::FullRecovery);

    // 4. Bob's like on Owner's post MUST STILL EXIST in circle_likes (not cascade-deleted!)
    let bob_like_in_db: Option<(String,)> = sqlx::query_as("SELECT uri FROM circle_likes WHERE uri = $1")
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

    // 1. list_repos to 127.0.0.1 -> blocked
    let loopback_url = url::Url::parse("https://127.0.0.1/xrpc/com.atproto.space.listRepos").unwrap();
    let res1 = transport.list_repos(&loopback_url, "cred", "dpop", SPACE_URI, None).await;
    assert!(matches!(res1, Err(circle_appview::error::AppError::Unauthorized(_))));

    // 2. list_repo_ops to private IP -> blocked
    let private_url = url::Url::parse("https://10.0.0.1/xrpc/com.atproto.space.listRepoOps").unwrap();
    let res2 = transport.list_repo_ops(&private_url, "cred", "dpop", SPACE_URI, OWNER_DID, None, None).await;
    assert!(matches!(res2, Err(circle_appview::error::AppError::Unauthorized(_))));

    // 3. get_repo to localhost -> blocked
    let localhost_url = url::Url::parse("https://localhost/xrpc/com.atproto.space.getRepo").unwrap();
    let res3 = transport.get_repo(&localhost_url, "cred", "dpop", SPACE_URI, OWNER_DID, None).await;
    assert!(matches!(res3, Err(circle_appview::error::AppError::Unauthorized(_))));

    // 4. get_latest_commit to non-HTTPS -> blocked
    let http_url = url::Url::parse("http://space.example.com/xrpc/com.atproto.space.getLatestCommit").unwrap();
    let res4 = transport.get_latest_commit(&http_url, "cred", "dpop", SPACE_URI, OWNER_DID).await;
    assert!(matches!(res4, Err(circle_appview::error::AppError::InvalidRequest(_))));
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
        rkey: RecordKey::from(Rkey::from(String::from("3l7sweepp2"))),
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

    // Page 1 of listRepos returns cursor="page2_cur" with no matching repo
    setup.mock_transport.set_list_repos_response(
        SPACE_URI,
        catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput {
            cursor: Some("page2_cur".into()),
            repos: vec![],
            extra_data: None,
        },
    );

    // Page 2 of listRepos returns OWNER_DID repo
    let page2_key = format!("{SPACE_URI}:page2_cur");
    let repo_item = catbird_atproto::generated::com_atproto::space::list_repos::Repo {
        did: Did::from(String::from(OWNER_DID)),
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(
            &lthash.digest(),
        ),
        rev: Tid::from(String::from(rev)),
        extra_data: None,
    };
    setup.mock_transport.set_list_repos_response(
        &page2_key,
        catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput {
            cursor: None,
            repos: vec![repo_item],
            extra_data: None,
        },
    );

    let summary = sweep_once(&setup.state).await.unwrap();
    assert_eq!(summary.repos_checked, 1);
    assert_eq!(summary.repos_synced, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn notify_write_verifies_against_expected_hash_and_rejects_mismatched_car(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post for notifyWrite hash check",
        "createdAt": "2026-08-24T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7postnotify1", &post_cid);
    let rev = "3l7notifysync";
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
        rkey: RecordKey::from(Rkey::from(String::from("3l7postnotify1"))),
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

    let token = mint_service_jwt(
        OWNER_DID,
        &setup.state.config.service_did,
        "com.atproto.space.notifyWrite",
        &setup.owner_signing_key,
    );

    // 1. Mismatched notify hash -> Rejected
    let wrong_hash = [0x99u8; 32];
    let notify_input_mismatched = catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite {
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&wrong_hash),
        repo: Did::from(String::from(OWNER_DID)),
        rev: Tid::from(String::from(rev)),
        space: SPACE_URI.into(),
        extra_data: None,
    };

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );

    let res_mismatch = circle_appview::routes::notify_write_handler(
        axum::extract::State(setup.state.clone()),
        headers.clone(),
        axum::Json(notify_input_mismatched),
    )
    .await;
    assert!(res_mismatch.is_err(), "Mismatched notify hash must be rejected");

    // 2. Correct notify hash -> Accepted
    let notify_input_correct = catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite {
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&lthash.digest()),
        repo: Did::from(String::from(OWNER_DID)),
        rev: Tid::from(String::from(rev)),
        space: SPACE_URI.into(),
        extra_data: None,
    };

    let token2 = mint_service_jwt(
        OWNER_DID,
        &setup.state.config.service_did,
        "com.atproto.space.notifyWrite",
        &setup.owner_signing_key,
    );
    let mut headers2 = axum::http::HeaderMap::new();
    headers2.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token2}").parse().unwrap(),
    );

    let res_correct = circle_appview::routes::notify_write_handler(
        axum::extract::State(setup.state.clone()),
        headers2,
        axum::Json(notify_input_correct),
    )
    .await;
    assert!(res_correct.is_ok(), "Matching notify hash must succeed");
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
    let commit1 = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7rev234567a",
        lthash1.as_bytes(),
        &setup.owner_signing_key,
    );

    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: Some(commit1),
            cursor: None,
            ops: vec![catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                cid: Some(Cid::from(p1_cid.clone())),
                collection: Nsid::from(String::from("app.bsky.feed.post")),
                prev: None,
                rev: Tid::from(String::from("3l7rev234567a")),
                rkey: RecordKey::from(Rkey::from(String::from("3l7postp11111"))),
                value: Some(serde_json::from_value(p1_val).unwrap()),
                extra_data: None,
            }],
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
    let commit2 = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7rev234567b",
        lthash2.as_bytes(),
        &setup.owner_signing_key,
    );

    let rec_reply = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7replyonly1".to_string(),
        cid: reply_cid,
        value: reply_val,
    };
    let car_bytes = mint_repo_car(&commit2, &[rec_reply]).unwrap();
    setup.mock_transport.set_get_repo_response(&key, car_bytes);

    let res2 = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();
    assert_eq!(res2.mode, SyncMode::FullRecovery);
    assert_eq!(res2.records_rejected, 1, "Reply referencing absent P1 must be rejected");
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
    let commit_a1 = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7234567a234", lthash_a.as_bytes(), &setup.owner_signing_key);

    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: Some(commit_a1),
            cursor: None,
            ops: vec![catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                cid: Some(Cid::from(p1_cid.clone())),
                collection: Nsid::from(String::from("app.bsky.feed.post")),
                prev: None,
                rev: Tid::from(String::from("3l7234567a234")),
                rkey: RecordKey::from(Rkey::from(String::from("3l7targetp111"))),
                value: Some(serde_json::from_value(p1_val).unwrap()),
                extra_data: None,
            }],
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
    let commit_b1 = mint_signed_commit(SPACE_URI, BOB_DID, "3l7234567b234", lthash_b.as_bytes(), &setup.bob_signing_key);

    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{BOB_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: Some(commit_b1),
            cursor: None,
            ops: vec![catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                cid: Some(Cid::from(l1_cid.clone())),
                collection: Nsid::from(String::from("app.bsky.feed.like")),
                prev: None,
                rev: Tid::from(String::from("3l7234567b234")),
                rkey: RecordKey::from(Rkey::from(String::from("3l7like111111"))),
                value: Some(serde_json::from_value(l1_val).unwrap()),
                extra_data: None,
            }],
            extra_data: None,
        },
    );
    sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    // Check like exists
    let likes_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM circle_likes WHERE post_uri = $1")
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
    let commit_b2 = mint_signed_commit(SPACE_URI, BOB_DID, "3l7234567c234", lthash_b.as_bytes(), &setup.bob_signing_key);

    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{BOB_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: Some(commit_b2),
            cursor: None,
            ops: vec![catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                cid: Some(Cid::from(l1_invalid_cid.clone())),
                collection: Nsid::from(String::from("app.bsky.feed.like")),
                prev: Some(Cid::from(l1_cid.clone())),
                rev: Tid::from(String::from("3l7234567c234")),
                rkey: RecordKey::from(Rkey::from(String::from("3l7like111111"))),
                value: Some(serde_json::from_value(l1_invalid_val).unwrap()),
                extra_data: None,
            }],
            extra_data: None,
        },
    );
    let res_b2 = sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();
    assert_eq!(res_b2.records_rejected, 1);

    // Invalid update invalidated previous like row
    let likes_after_rejection: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM circle_likes WHERE uri = $1")
        .bind(&l1_uri)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(likes_after_rejection.0, 0, "Invalid update must remove prior circle_likes row");

    // 4. Alice deletes post P1 -> circle_likes pointing to P1 and notifications are deleted
    let mut lthash_a2 = lthash_a.clone();
    lthash_a2.remove("app.bsky.feed.post", "3l7targetp111", &p1_cid);
    let commit_a2 = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7234567d234", lthash_a2.as_bytes(), &setup.owner_signing_key);
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: Some(commit_a2),
            cursor: None,
            ops: vec![catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                cid: None,
                collection: Nsid::from(String::from("app.bsky.feed.post")),
                prev: Some(Cid::from(p1_cid.clone())),
                rev: Tid::from(String::from("3l7234567d234")),
                rkey: RecordKey::from(Rkey::from(String::from("3l7targetp111"))),
                value: None,
                extra_data: None,
            }],
            extra_data: None,
        },
    );
    sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();

    let remaining_likes: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM circle_likes WHERE post_uri = $1")
        .bind(&p1_uri)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining_likes.0, 0, "Deleting post must remove all circle_likes pointing to it");
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
    let commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7cyclerev22",
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );

    let key = format!("{SPACE_URI}:{OWNER_DID}");

    setup.mock_transport.set_list_repo_ops_response(
        &key,
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: None,
            cursor: Some("cursor_A".into()),
            ops: vec![],
            extra_data: None,
        },
    );
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{key}:cursor_A"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: None,
            cursor: Some("cursor_B".into()),
            ops: vec![],
            extra_data: None,
        },
    );
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{key}:cursor_B"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            commit: None,
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
    let car_bytes = mint_repo_car(&commit, &[rec]).unwrap();
    setup.mock_transport.set_get_repo_response(&key, car_bytes);

    let res = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();
    assert_eq!(res.mode, SyncMode::FullRecovery, "Cursor cycle must enter full recovery");
    assert_eq!(res.records_accepted, 1);
}

// ---------------------------------------------------------------------------------------
// Step 7: Round 4 Adversarial Unit and Integration Tests
// ---------------------------------------------------------------------------------------

#[test]
fn strict_car_rejects_noncanonical_signed_commit_dagcbor() {
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7post1", "bafyreih327testcid1");
    let commit = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7aaaaaaaaaa", lthash.as_bytes(), &signing_key);
    let rec = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7post1".to_string(),
        cid: "bafyreih327testcid1".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Valid post",
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };

    let valid_car = mint_repo_car(&commit, &[rec]).unwrap();
    let decoded = decode_repo_car(&valid_car).unwrap();

    // Build a SignedCommit block with non-canonical key order in DAG-CBOR
    // Canonical keys (length 3 sorted, then length 4): ikm, mac, rev, sig, ver, hash
    // Encode map with reversed key order: hash, ver, sig, rev, mac, ikm
    let mut noncanonical_commit_cbor = Vec::new();
    noncanonical_commit_cbor.push(0xa6);
    noncanonical_commit_cbor.extend_from_slice(&[0x64, b'h', b'a', b's', b'h', 0x58, commit.hash.len() as u8]);
    noncanonical_commit_cbor.extend_from_slice(commit.hash.as_ref());
    noncanonical_commit_cbor.extend_from_slice(&[0x63, b'v', b'e', b'r', 0x01]);
    noncanonical_commit_cbor.extend_from_slice(&[0x63, b's', b'i', b'g', 0x58, commit.sig.len() as u8]);
    noncanonical_commit_cbor.extend_from_slice(commit.sig.as_ref());
    noncanonical_commit_cbor.extend_from_slice(&[0x63, b'r', b'e', b'v', 0x6d]);
    noncanonical_commit_cbor.extend_from_slice(commit.rev.as_bytes());
    noncanonical_commit_cbor.extend_from_slice(&[0x63, b'm', b'a', b'c', 0x58, commit.mac.len() as u8]);
    noncanonical_commit_cbor.extend_from_slice(commit.mac.as_ref());
    noncanonical_commit_cbor.extend_from_slice(&[0x63, b'i', b'k', b'm', 0x58, commit.ikm.len() as u8]);
    noncanonical_commit_cbor.extend_from_slice(commit.ikm.as_ref());

    let (nc_cid_bytes, _) = circle_appview::commit::create_cid_bytes_from_data(&noncanonical_commit_cbor);
    let nc_cid_link = circle_appview::commit::CidLink::from_bytes(nc_cid_bytes.clone());
    let drisl_cid_link = circle_appview::commit::CidLink::from_cid_str(&decoded.data_root_cid).unwrap();

    let header = circle_appview::commit::CarHeader {
        version: 1,
        roots: vec![nc_cid_link, drisl_cid_link],
    };
    let header_cbor = serde_ipld_dagcbor::to_vec(&header).unwrap();

    let mut tampered_car = Vec::new();
    circle_appview::commit::encode_varint(header_cbor.len() as u64, &mut tampered_car);
    tampered_car.extend_from_slice(&header_cbor);

    circle_appview::commit::encode_varint((nc_cid_bytes.len() + noncanonical_commit_cbor.len()) as u64, &mut tampered_car);
    tampered_car.extend_from_slice(&nc_cid_bytes);
    tampered_car.extend_from_slice(&noncanonical_commit_cbor);

    let (h_len, h_vlen) = circle_appview::commit::decode_varint(&valid_car).unwrap();
    let (b1_len, b1_vlen) = circle_appview::commit::decode_varint(&valid_car[h_vlen + h_len as usize..]).unwrap();
    let remaining_offset = h_vlen + h_len as usize + b1_vlen + b1_len as usize;
    tampered_car.extend_from_slice(&valid_car[remaining_offset..]);

    let res = decode_repo_car(&tampered_car);
    assert!(res.is_err(), "Non-canonical SignedCommit block encoding must be rejected");
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("Non-canonical DAG-CBOR SignedCommit") || err_msg.contains("strict IPLD"));
}

#[test]
fn strict_car_rejects_signed_commit_with_extra_data_float() {
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7post1", "bafyreih327testcid1");
    let commit = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7aaaaaaaaaa", lthash.as_bytes(), &signing_key);
    let rec = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7post1".to_string(),
        cid: "bafyreih327testcid1".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Valid post",
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };

    let valid_car = mint_repo_car(&commit, &[rec]).unwrap();
    let decoded = decode_repo_car(&valid_car).unwrap();

    // Encode SignedCommit with keys in canonical DAG-CBOR order (3-byte keys, then 4-byte key 'hash', then 11-byte key 'extra_float' containing CBOR float 0xfa 0x42 0x2a 0x00 0x00)
    let mut float_commit_cbor = Vec::new();
    float_commit_cbor.push(0xa7); // 7 entries
    float_commit_cbor.extend_from_slice(&[0x63, b'i', b'k', b'm', 0x58, commit.ikm.len() as u8]);
    float_commit_cbor.extend_from_slice(commit.ikm.as_ref());
    float_commit_cbor.extend_from_slice(&[0x63, b'm', b'a', b'c', 0x58, commit.mac.len() as u8]);
    float_commit_cbor.extend_from_slice(commit.mac.as_ref());
    float_commit_cbor.extend_from_slice(&[0x63, b'r', b'e', b'v', 0x6d]);
    float_commit_cbor.extend_from_slice(commit.rev.as_bytes());
    float_commit_cbor.extend_from_slice(&[0x63, b's', b'i', b'g', 0x58, commit.sig.len() as u8]);
    float_commit_cbor.extend_from_slice(commit.sig.as_ref());
    float_commit_cbor.extend_from_slice(&[0x63, b'v', b'e', b'r', 0x01]);
    float_commit_cbor.extend_from_slice(&[0x64, b'h', b'a', b's', b'h', 0x58, commit.hash.len() as u8]);
    float_commit_cbor.extend_from_slice(commit.hash.as_ref());
    float_commit_cbor.extend_from_slice(&[0x6b, b'e', b'x', b't', b'r', b'a', b'_', b'f', b'l', b'o', b'a', b't', 0xfa, 0x42, 0x2a, 0x00, 0x00]);
    let (float_cid_bytes, _) = circle_appview::commit::create_cid_bytes_from_data(&float_commit_cbor);
    let float_cid_link = circle_appview::commit::CidLink::from_bytes(float_cid_bytes.clone());
    let drisl_cid_link = circle_appview::commit::CidLink::from_cid_str(&decoded.data_root_cid).unwrap();

    let header = circle_appview::commit::CarHeader {
        version: 1,
        roots: vec![float_cid_link, drisl_cid_link],
    };
    let header_cbor = serde_ipld_dagcbor::to_vec(&header).unwrap();

    let mut tampered_car = Vec::new();
    circle_appview::commit::encode_varint(header_cbor.len() as u64, &mut tampered_car);
    tampered_car.extend_from_slice(&header_cbor);

    circle_appview::commit::encode_varint((float_cid_bytes.len() + float_commit_cbor.len()) as u64, &mut tampered_car);
    tampered_car.extend_from_slice(&float_cid_bytes);
    tampered_car.extend_from_slice(&float_commit_cbor);

    let (h_len, h_vlen) = circle_appview::commit::decode_varint(&valid_car).unwrap();
    let (b1_len, b1_vlen) = circle_appview::commit::decode_varint(&valid_car[h_vlen + h_len as usize..]).unwrap();
    let remaining_offset = h_vlen + h_len as usize + b1_vlen + b1_len as usize;
    tampered_car.extend_from_slice(&valid_car[remaining_offset..]);

    let res = decode_repo_car(&tampered_car);
    assert!(res.is_err(), "SignedCommit containing float must be rejected by strict IPLD decoding");
    assert!(res.unwrap_err().to_string().contains("Floating point numbers are forbidden"));
}
#[test]
fn strict_car_rejects_signed_commit_with_unknown_extra_data() {
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7post1", "bafyreih327testcid1");
    let commit = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7aaaaaaaaaa", lthash.as_bytes(), &signing_key);
    let rec = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7post1".to_string(),
        cid: "bafyreih327testcid1".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Valid post",
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };

    let valid_car = mint_repo_car(&commit, &[rec]).unwrap();
    let decoded = decode_repo_car(&valid_car).unwrap();

    // Canonical SignedCommit CBOR with canonical extra string field: extra_field: "value"
    let mut extra_commit_cbor = Vec::new();
    extra_commit_cbor.push(0xa7); // 7 entries
    extra_commit_cbor.extend_from_slice(&[0x63, b'i', b'k', b'm', 0x58, commit.ikm.len() as u8]);
    extra_commit_cbor.extend_from_slice(commit.ikm.as_ref());
    extra_commit_cbor.extend_from_slice(&[0x63, b'm', b'a', b'c', 0x58, commit.mac.len() as u8]);
    extra_commit_cbor.extend_from_slice(commit.mac.as_ref());
    extra_commit_cbor.extend_from_slice(&[0x63, b'r', b'e', b'v', 0x6d]);
    extra_commit_cbor.extend_from_slice(commit.rev.as_bytes());
    extra_commit_cbor.extend_from_slice(&[0x63, b's', b'i', b'g', 0x58, commit.sig.len() as u8]);
    extra_commit_cbor.extend_from_slice(commit.sig.as_ref());
    extra_commit_cbor.extend_from_slice(&[0x63, b'v', b'e', b'r', 0x01]);
    extra_commit_cbor.extend_from_slice(&[0x64, b'h', b'a', b's', b'h', 0x58, commit.hash.len() as u8]);
    extra_commit_cbor.extend_from_slice(commit.hash.as_ref());
    // 11-byte key 'extra_field', 5-byte string 'value' (0x65, b'v', b'a', b'l', b'u', b'e')
    extra_commit_cbor.extend_from_slice(&[0x6b, b'e', b'x', b't', b'r', b'a', b'_', b'f', b'i', b'e', b'l', b'd', 0x65, b'v', b'a', b'l', b'u', b'e']);

    let (extra_cid_bytes, _) = circle_appview::commit::create_cid_bytes_from_data(&extra_commit_cbor);
    let extra_cid_link = circle_appview::commit::CidLink::from_bytes(extra_cid_bytes.clone());
    let drisl_cid_link = circle_appview::commit::CidLink::from_cid_str(&decoded.data_root_cid).unwrap();

    let header = circle_appview::commit::CarHeader {
        version: 1,
        roots: vec![extra_cid_link, drisl_cid_link],
    };
    let header_cbor = serde_ipld_dagcbor::to_vec(&header).unwrap();

    let mut tampered_car = Vec::new();
    circle_appview::commit::encode_varint(header_cbor.len() as u64, &mut tampered_car);
    tampered_car.extend_from_slice(&header_cbor);

    circle_appview::commit::encode_varint((extra_cid_bytes.len() + extra_commit_cbor.len()) as u64, &mut tampered_car);
    tampered_car.extend_from_slice(&extra_cid_bytes);
    tampered_car.extend_from_slice(&extra_commit_cbor);

    let (h_len, h_vlen) = circle_appview::commit::decode_varint(&valid_car).unwrap();
    let (b1_len, b1_vlen) = circle_appview::commit::decode_varint(&valid_car[h_vlen + h_len as usize..]).unwrap();
    let remaining_offset = h_vlen + h_len as usize + b1_vlen + b1_len as usize;
    tampered_car.extend_from_slice(&valid_car[remaining_offset..]);

    let res = decode_repo_car(&tampered_car);
    assert!(res.is_err(), "SignedCommit containing unknown extra_data must be rejected");
    assert!(res.unwrap_err().to_string().contains("SignedCommit contains unknown fields"));
}

#[test]
fn strict_car_rejects_cidv0_and_unblessed_cidv1_codecs() {
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7post1", "bafyreih327testcid1");
    let commit = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7aaaaaaaaaa", lthash.as_bytes(), &signing_key);
    let rec = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7post1".to_string(),
        cid: "bafyreih327testcid1".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Valid post",
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };

    let valid_car = mint_repo_car(&commit, &[rec]).unwrap();
    let decoded = decode_repo_car(&valid_car).unwrap();
    let commit_cbor = serde_ipld_dagcbor::to_vec(&commit).unwrap();
    use sha2::Digest;
    let commit_digest = sha2::Sha256::digest(&commit_cbor);

    // 1. CAR with CIDv0 root (starts with 0x12, 0x20...) in block 1
    let mut cidv0_bytes = vec![0x12, 0x20];
    cidv0_bytes.extend_from_slice(&commit_digest);
    let cidv0_link = circle_appview::commit::CidLink::from_bytes(cidv0_bytes.clone());
    let drisl_cid_link = circle_appview::commit::CidLink::from_cid_str(&decoded.data_root_cid).unwrap();

    let header_v0 = circle_appview::commit::CarHeader {
        version: 1,
        roots: vec![cidv0_link, drisl_cid_link.clone()],
    };
    let header_v0_cbor = serde_ipld_dagcbor::to_vec(&header_v0).unwrap();
    let mut car_v0 = Vec::new();
    circle_appview::commit::encode_varint(header_v0_cbor.len() as u64, &mut car_v0);
    car_v0.extend_from_slice(&header_v0_cbor);
    circle_appview::commit::encode_varint((cidv0_bytes.len() + commit_cbor.len()) as u64, &mut car_v0);
    car_v0.extend_from_slice(&cidv0_bytes);
    car_v0.extend_from_slice(&commit_cbor);

    let (h_len, h_vlen) = circle_appview::commit::decode_varint(&valid_car).unwrap();
    let (b1_len, b1_vlen) = circle_appview::commit::decode_varint(&valid_car[h_vlen + h_len as usize..]).unwrap();
    let remaining_offset = h_vlen + h_len as usize + b1_vlen + b1_len as usize;
    car_v0.extend_from_slice(&valid_car[remaining_offset..]);

    let res_v0 = decode_repo_car(&car_v0);
    assert!(res_v0.is_err(), "CIDv0 root and block in CAR must be rejected");

    // 2. CAR with unblessed CIDv1 codec (0x55 raw binary instead of 0x71 dag-cbor)
    let mut unblessed_cidv1 = vec![0x01, 0x55, 0x12, 0x20];
    unblessed_cidv1.extend_from_slice(&commit_digest);
    let unblessed_link = circle_appview::commit::CidLink::from_bytes(unblessed_cidv1.clone());

    let header_unblessed = circle_appview::commit::CarHeader {
        version: 1,
        roots: vec![unblessed_link, drisl_cid_link],
    };
    let header_unblessed_cbor = serde_ipld_dagcbor::to_vec(&header_unblessed).unwrap();
    let mut car_unblessed = Vec::new();
    circle_appview::commit::encode_varint(header_unblessed_cbor.len() as u64, &mut car_unblessed);
    car_unblessed.extend_from_slice(&header_unblessed_cbor);
    circle_appview::commit::encode_varint((unblessed_cidv1.len() + commit_cbor.len()) as u64, &mut car_unblessed);
    car_unblessed.extend_from_slice(&unblessed_cidv1);
    car_unblessed.extend_from_slice(&commit_cbor);
    car_unblessed.extend_from_slice(&valid_car[remaining_offset..]);

    let res_unblessed = decode_repo_car(&car_unblessed);
    assert!(res_unblessed.is_err(), "Unblessed CIDv1 codec 0x55 must be rejected");
}

#[test]
fn strict_car_rejects_non_minimal_and_overflowing_varints() {
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7post1", "bafyreih327testcid1");
    let commit = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7aaaaaaaaaa", lthash.as_bytes(), &signing_key);
    let rec = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7post1".to_string(),
        cid: "bafyreih327testcid1".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Valid post",
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };

    let valid_car = mint_repo_car(&commit, &[rec]).unwrap();
    let (h_len, h_vlen) = circle_appview::commit::decode_varint(&valid_car).unwrap();

    // 1. Re-encode header varint with non-minimal overlong encoding
    let mut non_minimal_car = Vec::new();
    let val = h_len;
    non_minimal_car.push(((val & 0x7f) as u8) | 0x80);
    non_minimal_car.push((val >> 7) as u8); // extra byte
    non_minimal_car.extend_from_slice(&valid_car[h_vlen..]);

    let res_non_minimal = decode_repo_car(&non_minimal_car);
    assert!(res_non_minimal.is_err(), "Non-minimal varint encoding must be rejected");
    assert!(res_non_minimal.unwrap_err().to_string().contains("Non-minimal varint"));

    // 2. 10-byte varint where 10th byte exceeds max u64 (> 0x01)
    let mut overflow_car = Vec::new();
    overflow_car.extend_from_slice(&[0xff; 9]);
    overflow_car.push(0x02);
    overflow_car.extend_from_slice(&valid_car[h_vlen..]);

    let res_overflow = decode_repo_car(&overflow_car);
    assert!(res_overflow.is_err(), "10th varint byte exceeding max u64 must be rejected");
    assert!(res_overflow.unwrap_err().to_string().contains("10th varint byte exceeds maximum u64"));

    // 3. 10-byte varint where 10th byte has continuation bit set (0x80)
    let mut cont_car = Vec::new();
    cont_car.extend_from_slice(&[0xff; 9]);
    cont_car.push(0x80);
    cont_car.extend_from_slice(&valid_car[h_vlen..]);

    let res_cont = decode_repo_car(&cont_car);
    assert!(res_cont.is_err(), "10th varint byte with continuation bit set must be rejected");
    assert!(res_cont.unwrap_err().to_string().contains("continuation bit"));
}

#[test]
fn strict_car_rejects_duplicate_map_keys_in_ipld_and_drisl() {
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7post1", "bafyreih327testcid1");
    let commit = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7aaaaaaaaaa", lthash.as_bytes(), &signing_key);
    let rec = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7post1".to_string(),
        cid: "bafyreih327testcid1".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Valid post",
            "createdAt": "2026-08-24T12:00:00.000Z"
        }),
    };

    let valid_car = mint_repo_car(&commit, &[rec]).unwrap();
    let decoded = decode_repo_car(&valid_car).unwrap();

    // Construct DRISL map block with duplicate map key
    let (dummy_cid_bytes, _) = circle_appview::commit::create_cid_bytes_from_data(b"dummy data");
    let link = circle_appview::commit::CidLink::from_bytes(dummy_cid_bytes);
    let link_cbor = serde_ipld_dagcbor::to_vec(&link).unwrap();

    let mut dup_drisl_cbor = Vec::new();
    dup_drisl_cbor.push(0xa2); // 2 map entries
    let key = "app.bsky.feed.post/3l7post1";
    dup_drisl_cbor.push(0x78);
    dup_drisl_cbor.push(key.len() as u8);
    dup_drisl_cbor.extend_from_slice(key.as_bytes());
    dup_drisl_cbor.extend_from_slice(&link_cbor);

    dup_drisl_cbor.push(0x78);
    dup_drisl_cbor.push(key.len() as u8);
    dup_drisl_cbor.extend_from_slice(key.as_bytes());
    dup_drisl_cbor.extend_from_slice(&link_cbor);

    let (dup_drisl_cid_bytes, _) = circle_appview::commit::create_cid_bytes_from_data(&dup_drisl_cbor);
    let dup_drisl_cid_link = circle_appview::commit::CidLink::from_bytes(dup_drisl_cid_bytes.clone());
    let commit_cid_link = circle_appview::commit::CidLink::from_cid_str(&decoded.commit_cid).unwrap();

    let header = circle_appview::commit::CarHeader {
        version: 1,
        roots: vec![commit_cid_link, dup_drisl_cid_link],
    };
    let header_cbor = serde_ipld_dagcbor::to_vec(&header).unwrap();

    let mut tampered_car = Vec::new();
    circle_appview::commit::encode_varint(header_cbor.len() as u64, &mut tampered_car);
    tampered_car.extend_from_slice(&header_cbor);

    let (h_len, h_vlen) = circle_appview::commit::decode_varint(&valid_car).unwrap();
    let (b1_len, b1_vlen) = circle_appview::commit::decode_varint(&valid_car[h_vlen + h_len as usize..]).unwrap();
    let b1_start = h_vlen + h_len as usize;
    let b1_end = b1_start + b1_vlen + b1_len as usize;
    tampered_car.extend_from_slice(&valid_car[b1_start..b1_end]);

    circle_appview::commit::encode_varint((dup_drisl_cid_bytes.len() + dup_drisl_cbor.len()) as u64, &mut tampered_car);
    tampered_car.extend_from_slice(&dup_drisl_cid_bytes);
    tampered_car.extend_from_slice(&dup_drisl_cbor);

    let res = decode_repo_car(&tampered_car);
    assert!(res.is_err(), "Duplicate map keys in DRISL block must be rejected");
    assert!(res.unwrap_err().to_string().contains("Duplicate map key"));
}
#[test]
fn strict_car_rejects_duplicate_map_keys_in_record_block() {
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    // Construct a record with duplicate map keys in CBOR
    // Canonically 3 entries (with duplicate 'text' key):
    // 1. "text" (4) -> 0x64, b't', b'e', b'x', b't', 0x65, "hello" (5)
    // 2. "text" (4) -> 0x64, b't', b'e', b'x', b't', 0x69, "duplicate" (9)
    // 3. "$type" (5) -> 0x65, b'$', b't', b'y', b'p', b'e', 0x72, "app.bsky.feed.post" (18)
    let type_key = "$type";
    let type_val = "app.bsky.feed.post";
    let text_key = "text";
    let text_val1 = "hello";
    let text_val2 = "duplicate";

    let mut dup_rec_cbor = Vec::new();
    dup_rec_cbor.push(0xa3); // 3 entries (with duplicate 'text' key)
    dup_rec_cbor.push(0x60 + text_key.len() as u8);
    dup_rec_cbor.extend_from_slice(text_key.as_bytes());
    dup_rec_cbor.push(0x60 + text_val1.len() as u8);
    dup_rec_cbor.extend_from_slice(text_val1.as_bytes());

    dup_rec_cbor.push(0x60 + text_key.len() as u8);
    dup_rec_cbor.extend_from_slice(text_key.as_bytes());
    dup_rec_cbor.push(0x60 + text_val2.len() as u8);
    dup_rec_cbor.extend_from_slice(text_val2.as_bytes());

    dup_rec_cbor.push(0x60 + type_key.len() as u8);
    dup_rec_cbor.extend_from_slice(type_key.as_bytes());
    dup_rec_cbor.push(0x72); // 18 bytes
    dup_rec_cbor.extend_from_slice(type_val.as_bytes());

    let (dup_rec_cid_bytes, dup_rec_cid_str) = circle_appview::commit::create_cid_bytes_from_data(&dup_rec_cbor);
    let dup_rec_cid_link = circle_appview::commit::CidLink::from_bytes(dup_rec_cid_bytes.clone());

    let mut lthash = LtHash::new();
    lthash.add("app.bsky.feed.post", "3l7post1", &dup_rec_cid_str);
    let commit = mint_signed_commit(SPACE_URI, OWNER_DID, "3l7aaaaaaaaaa", lthash.as_bytes(), &signing_key);
    let commit_cbor = serde_ipld_dagcbor::to_vec(&commit).unwrap();
    let (commit_cid_bytes, _) = circle_appview::commit::create_cid_bytes_from_data(&commit_cbor);
    let commit_cid_link = circle_appview::commit::CidLink::from_bytes(commit_cid_bytes.clone());

    // Construct valid DRISL map pointing to dup_rec_cid_link
    let mut drisl_map = std::collections::BTreeMap::new();
    drisl_map.insert("app.bsky.feed.post/3l7post1".to_string(), dup_rec_cid_link);
    let drisl_cbor = serde_ipld_dagcbor::to_vec(&drisl_map).unwrap();
    let (drisl_cid_bytes, _) = circle_appview::commit::create_cid_bytes_from_data(&drisl_cbor);
    let drisl_cid_link = circle_appview::commit::CidLink::from_bytes(drisl_cid_bytes.clone());

    let header = circle_appview::commit::CarHeader {
        version: 1,
        roots: vec![commit_cid_link, drisl_cid_link],
    };
    let header_cbor = serde_ipld_dagcbor::to_vec(&header).unwrap();

    let mut car = Vec::new();
    // Header
    circle_appview::commit::encode_varint(header_cbor.len() as u64, &mut car);
    car.extend_from_slice(&header_cbor);
    // Commit block
    circle_appview::commit::encode_varint((commit_cid_bytes.len() + commit_cbor.len()) as u64, &mut car);
    car.extend_from_slice(&commit_cid_bytes);
    car.extend_from_slice(&commit_cbor);
    // DRISL block
    circle_appview::commit::encode_varint((drisl_cid_bytes.len() + drisl_cbor.len()) as u64, &mut car);
    car.extend_from_slice(&drisl_cid_bytes);
    car.extend_from_slice(&drisl_cbor);
    // Record block with duplicate keys
    circle_appview::commit::encode_varint((dup_rec_cid_bytes.len() + dup_rec_cbor.len()) as u64, &mut car);
    car.extend_from_slice(&dup_rec_cid_bytes);
    car.extend_from_slice(&dup_rec_cbor);

    let res = decode_repo_car(&car);
    assert!(res.is_err(), "Duplicate map keys in record block must be rejected");
    let err_str = res.unwrap_err().to_string();
    assert!(err_str.contains("Failed to decode record CBOR") || err_str.contains("Duplicate map key"));
}

#[sqlx::test(migrations = "./migrations")]
async fn notify_write_requires_32_byte_hash_and_non_empty_rev(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;
    let app = circle_appview::routes::create_router(setup.state.clone());
    use axum::http::Request;
    use tower::ServiceExt;

    let token = mint_service_jwt(
        OWNER_DID,
        &setup.state.config.service_did,
        "com.atproto.space.notifyWrite",
        &setup.owner_signing_key,
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );

    // 1. Hash is 16 bytes (not 32) -> 400 Bad Request
    let short_hash_input = catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite {
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x11u8; 16]),
        repo: Did::from(String::from(OWNER_DID)),
        rev: Tid::from(String::from("3l7234567a234")),
        space: SPACE_URI.into(),
        extra_data: None,
    };
    let res = circle_appview::routes::notify_write_handler(
        axum::extract::State(setup.state.clone()),
        headers,
        axum::Json(short_hash_input),
    )
    .await;
    assert!(matches!(res, Err(AppError::InvalidRequest(_))), "Non-32-byte hash must return InvalidRequest");

    // 2. Empty rev via HTTP router -> Client Error (400 or 422)
    let bad_json_req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.notifyWrite")
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(json!({
            "space": SPACE_URI,
            "repo": OWNER_DID,
            "rev": "",
            "hash": base64::engine::general_purpose::STANDARD.encode([0x22u8; 32])
        }).to_string()))
        .unwrap();

    let res2 = app.oneshot(bad_json_req).await.unwrap();
    assert!(res2.status().is_client_error(), "Empty rev must return client error");
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
    let commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        commit_rev,
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );

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
            commit: Some(commit.clone()),
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
    let car_bytes = mint_repo_car(&commit, &[rec]).unwrap();
    setup.mock_transport.set_get_repo_response(&key, car_bytes);

    // 1. Sync with matching hash and matching rev -> Succeeds in incremental mode
    let res = sync_engine
        .sync_repo_with_expected_commit(
            SPACE_URI,
            OWNER_DID,
            Some(commit.hash.as_ref()),
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
            Some(commit.hash.as_ref()),
            Some("3l7234567b234"),
        )
        .await;
    assert!(err_res.is_err(), "Full recovery must reject CAR when expected rev does not match");
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
    let commit_owner1 = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        lthash_owner.as_bytes(),
        &setup.owner_signing_key,
    );
    let rec_p1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p1owner".to_string(),
        cid: p1_cid.clone(),
        value: p1_val.clone(),
    };
    let car_p1 = mint_repo_car(&commit_owner1, &[rec_p1]).unwrap();
    let owner_key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_get_repo_response(&owner_key, car_p1);

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
    let commit_bob = mint_signed_commit(
        SPACE_URI,
        BOB_DID,
        "3l7234567b234",
        lthash_bob.as_bytes(),
        &setup.bob_signing_key,
    );
    let rec_r1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7r1bob".to_string(),
        cid: r1_cid.clone(),
        value: r1_val,
    };
    let car_bob = mint_repo_car(&commit_bob, &[rec_r1]).unwrap();
    let bob_key = format!("{SPACE_URI}:{BOB_DID}");
    setup.mock_transport.set_get_repo_response(&bob_key, car_bob);

    sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    // Step 3: Owner undergoes FULL RECOVERY with P1 and a new post P2
    let p2_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Owner post P2",
        "createdAt": "2026-08-24T12:20:00.000Z"
    });
    let p2_cid = compute_dagcbor_cid(&p2_val).unwrap();
    lthash_owner.add("app.bsky.feed.post", "3l7p2owner", &p2_cid);
    let commit_owner2 = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567c234",
        lthash_owner.as_bytes(),
        &setup.owner_signing_key,
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
    let car_owner_full = mint_repo_car(&commit_owner2, &[rec_p1_renew, rec_p2]).unwrap();
    setup.mock_transport.set_get_repo_response(&owner_key, car_owner_full);

    // Force full recovery on owner
    let res_recovery = sync_engine.sync_repo_with_expected_hash(SPACE_URI, OWNER_DID, Some(commit_owner2.hash.as_ref())).await.unwrap();
    assert_eq!(res_recovery.mode, SyncMode::FullRecovery);

    // Verify Bob's reply R1 remains present and untouched in DB!
    let r1_uri = format!("{SPACE_URI}/{BOB_DID}/app.bsky.feed.post/3l7r1bob");
    let bob_reply_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM circle_records WHERE uri = $1 AND deleted_at IS NULL",
    )
    .bind(&r1_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bob_reply_count.0, 1, "Owner recovery must NOT delete or invalidate Bob's existing reply");
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
    let commit1 = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );
    let rec_p1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7p1target".to_string(),
        cid: p1_cid.clone(),
        value: p1_val,
    };
    let key = format!("{SPACE_URI}:{OWNER_DID}");
    let car = mint_repo_car(&commit1, &[rec_p1]).unwrap();
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

    let commit2 = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567b234",
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );

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
            commit: Some(commit2),
            cursor: None,
            ops: vec![op1, op2],
            extra_data: None,
        },
    );

    let res = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();
    assert_eq!(res.mode, SyncMode::Incremental);
    assert_eq!(res.records_rejected, 2, "Both the invalid update and subsequent dependent reply must be rejected");
}

#[sqlx::test(migrations = "./migrations")]
async fn notification_provenance_source_uri_and_comprehensive_cleanup_on_update_delete_reject(pool: PgPool) {
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
    let commit_owner = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        lthash_owner.as_bytes(),
        &setup.owner_signing_key,
    );
    let rec_p1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7notifpost1".to_string(),
        cid: p1_cid.clone(),
        value: p1_val,
    };
    let car_owner = mint_repo_car(&commit_owner, &[rec_p1]).unwrap();
    let owner_key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_get_repo_response(&owner_key, car_owner);
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
    let commit_bob1 = mint_signed_commit(
        SPACE_URI,
        BOB_DID,
        "3l7234567b234",
        lthash_bob.as_bytes(),
        &setup.bob_signing_key,
    );
    let rec_like = RepoRecord {
        collection: "app.bsky.feed.like".to_string(),
        rkey: "3l7likebob1".to_string(),
        cid: like_cid.clone(),
        value: like_val,
    };
    let car_bob1 = mint_repo_car(&commit_bob1, &[rec_like]).unwrap();
    let bob_key = format!("{SPACE_URI}:{BOB_DID}");
    setup.mock_transport.set_get_repo_response(&bob_key, car_bob1);
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
    assert_eq!(notif_count.0, 1, "Like notification must have source_uri set to like URI");

    // Step 3: Bob deletes his like
    lthash_bob.remove("app.bsky.feed.like", "3l7likebob1", &like_cid);
    let commit_bob2 = mint_signed_commit(
        SPACE_URI,
        BOB_DID,
        "3l7234567c234",
        lthash_bob.as_bytes(),
        &setup.bob_signing_key,
    );
    let car_bob2 = mint_repo_car(&commit_bob2, &[]).unwrap();
    setup.mock_transport.set_get_repo_response(&bob_key, car_bob2);
    sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    // Verify notification for deleted like was removed
    let remaining_notifs: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM circle_notifications WHERE source_uri = $1",
    )
    .bind(&like_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remaining_notifs.0, 0, "Deleting like must remove its notification via source_uri");
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
async fn notification_source_identity_preserved_on_unchanged_recovery_and_replaced_on_change(pool: PgPool) {
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
    let commit_owner = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        lthash_owner.as_bytes(),
        &setup.owner_signing_key,
    );
    let rec_p1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7notifp1".to_string(),
        cid: p1_cid.clone(),
        value: p1_val,
    };
    let car_owner = mint_repo_car(&commit_owner, std::slice::from_ref(&rec_p1)).unwrap();
    let owner_key = format!("{SPACE_URI}:{OWNER_DID}");
    setup.mock_transport.set_get_repo_response(&owner_key, car_owner);
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
    let commit_bob = mint_signed_commit(
        SPACE_URI,
        BOB_DID,
        "3l7234567b234",
        lthash_bob.as_bytes(),
        &setup.bob_signing_key,
    );
    let rec_like = RepoRecord {
        collection: "app.bsky.feed.like".to_string(),
        rkey: "3l7like1".to_string(),
        cid: like_cid.clone(),
        value: like_val.clone(),
    };
    let car_bob = mint_repo_car(&commit_bob, std::slice::from_ref(&rec_like)).unwrap();
    let bob_key = format!("{SPACE_URI}:{BOB_DID}");
    setup.mock_transport.set_get_repo_response(&bob_key, car_bob.clone());
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

    assert_eq!(preserved_notif.0, initial_notif.0, "Notification ID must be preserved across unchanged recovery");
    assert!(preserved_notif.1, "Notification read status must remain true across unchanged recovery");
    assert_eq!(preserved_notif.2, initial_notif.2, "Notification created_at timestamp must be preserved");

    // Step 6: Bob updates his like to point to a different post P2
    let p2_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post 2 for notification identity test",
        "createdAt": "2026-08-24T12:10:00.000Z"
    });
    let p2_cid = compute_dagcbor_cid(&p2_val).unwrap();
    lthash_owner.add("app.bsky.feed.post", "3l7notifp2", &p2_cid);
    let commit_owner2 = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a345",
        lthash_owner.as_bytes(),
        &setup.owner_signing_key,
    );
    let rec_p2 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7notifp2".to_string(),
        cid: p2_cid.clone(),
        value: p2_val,
    };
    let car_owner2 = mint_repo_car(&commit_owner2, &[rec_p1, rec_p2]).unwrap();
    setup.mock_transport.set_get_repo_response(&owner_key, car_owner2);
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
    let commit_bob2 = mint_signed_commit(
        SPACE_URI,
        BOB_DID,
        "3l7234567b345",
        lthash_bob.as_bytes(),
        &setup.bob_signing_key,
    );
    let rec_updated_like = RepoRecord {
        collection: "app.bsky.feed.like".to_string(),
        rkey: "3l7like1".to_string(),
        cid: updated_like_cid.clone(),
        value: updated_like_val,
    };
    let car_bob2 = mint_repo_car(&commit_bob2, &[rec_updated_like]).unwrap();
    setup.mock_transport.set_get_repo_response(&bob_key, car_bob2);
    sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap();

    // Step 7: Verify changed like replaces notification (new ID, is_read = false, new subject)
    let replaced_notif: (uuid::Uuid, bool, String) = sqlx::query_as(
        "SELECT id, is_read, subject_uri FROM circle_notifications WHERE source_uri = $1",
    )
    .bind(&like_uri)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_ne!(replaced_notif.0, initial_notif.0, "Changed source must generate a new notification ID");
    assert!(!replaced_notif.1, "Changed source must reset is_read to false");
    assert_eq!(replaced_notif.2, p2_uri, "Notification subject_uri must be updated to P2");
}

#[sqlx::test(migrations = false)]
async fn alpha_migration_purges_legacy_notifications_and_enforces_source_provenance_lifecycle(pool: PgPool) {
    // 1. Apply pre-000003 schema (migrations 1 and 2)
    let m1 = include_str!("../migrations/20260824000001_initial.sql");
    let m2 = include_str!("../migrations/20260824000002_generations_and_tombstones.sql");
    sqlx::raw_sql(m1).execute(&pool).await.unwrap();
    sqlx::raw_sql(m2).execute(&pool).await.unwrap();

    // Seed circle
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, authority_did, display_name, created_at)
        VALUES ($1, $2, 'Test Circle', now())
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
    assert_eq!(count_pre.0, 1, "Legacy notification must exist before migration 000003");

    // 3. Apply migration 000003
    let m3 = include_str!("../migrations/20260824000003_notification_source_uri.sql");
    sqlx::raw_sql(m3).execute(&pool).await.unwrap();

    // 4. Verify legacy notifications were purged
    let count_post: (i64,) = sqlx::query_as("SELECT count(*) FROM circle_notifications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count_post.0, 0, "Legacy notifications must be purged during migration 000003");

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
    assert!(res_dup.is_err(), "Duplicate source_uri must violate unique constraint");

    // Update notification
    sqlx::query("UPDATE circle_notifications SET is_read = true WHERE source_uri = $1")
        .bind(&source1)
        .execute(&pool)
        .await
        .unwrap();

    let read_state: (bool,) = sqlx::query_as("SELECT is_read FROM circle_notifications WHERE source_uri = $1")
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
    assert!(matches!(validate(no_type, &pol), Err(InvalidRecord::MalformedRecord(_))));

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
    assert!(matches!(validate(wrong_type, &pol), Err(InvalidRecord::MalformedRecord(_))));

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
    assert_eq!(validate(video_post, &pol), Err(InvalidRecord::UnsupportedEmbed));

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
    assert_eq!(validate(external_post, &pol), Err(InvalidRecord::UnsupportedEmbed));

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
    assert!(matches!(validate(float_post, &pol), Err(InvalidRecord::MalformedRecord(_))));
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
    assert!(matches!(validate(too_many_images, &pol), Err(InvalidRecord::MalformedRecord(_))));

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
    assert!(matches!(validate(oversized_image, &pol), Err(InvalidRecord::MalformedRecord(_))));

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
    assert!(matches!(validate(bad_mime_image, &pol), Err(InvalidRecord::MalformedRecord(_))));

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
    assert!(matches!(validate(bad_facet_index, &pol), Err(InvalidRecord::MalformedRecord(_))));

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
    assert!(matches!(validate(bad_mention_did, &pol), Err(InvalidRecord::MalformedRecord(_))));

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
    assert!(matches!(validate(bad_link_uri, &pol), Err(InvalidRecord::MalformedRecord(_))));
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
    assert!(matches!(validate(bad_aspect_ratio, &pol), Err(InvalidRecord::MalformedRecord(_))));

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
    assert!(matches!(validate(too_many_labels, &pol), Err(InvalidRecord::MalformedRecord(_))));

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
    assert!(matches!(validate(empty_label, &pol), Err(InvalidRecord::MalformedRecord(_))));

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
    assert!(matches!(validate(bad_entity_index, &pol), Err(InvalidRecord::MalformedRecord(_))));

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
    assert!(matches!(validate(empty_tag, &pol), Err(InvalidRecord::MalformedRecord(_))));
}

#[sqlx::test(migrations = "./migrations")]
async fn scheduled_revision_sweep_task_repairs_missed_notification_and_shuts_down_cleanly(pool: PgPool) {
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
        rkey: RecordKey::from(Rkey::from(String::from("3l7sweepsch1"))),
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

    let repo_item = catbird_atproto::generated::com_atproto::space::list_repos::Repo {
        did: Did::from(String::from(OWNER_DID)),
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(
            &lthash.digest(),
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

    let expected_uri = format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/3l7sweepsch1");

    // Verify record is NOT yet in the database (simulating dropped notifyWrite)
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
        let after: Option<(String,)> = sqlx::query_as("SELECT uri FROM circle_records WHERE uri = $1")
            .bind(&expected_uri)
            .fetch_optional(&pool)
            .await
            .unwrap();
        if after.is_some() {
            synced = true;
            break;
        }
    }
    assert!(synced, "Scheduled revision sweep must repair missed notification and sync repo");

    // Graceful shutdown
    shutdown_tx.send(true).unwrap();
    let join_res = tokio::time::timeout(std::time::Duration::from_secs(2), sweep_handle).await;
    assert!(join_res.is_ok(), "Sweep task must shut down cleanly");
}

#[sqlx::test(migrations = "./migrations")]
async fn server_graceful_shutdown_drains_connections_and_awaits_sweep(pool: PgPool) {
    let setup = setup_sync_test(pool.clone()).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (sweep_handle, shutdown_tx) = circle_appview::sync::spawn_revision_sweep_task(
        setup.state.clone(),
        std::time::Duration::from_millis(50),
    );

    let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let app = circle_appview::routes::create_router(setup.state.clone());

    let server_task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = server_shutdown_rx.await;
            })
            .await
    });

    // Verify server is accepting connections
    let client = reqwest::Client::new();
    let resp = client.get(format!("http://{addr}/_health")).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Signal server shutdown (simulating SIGTERM/SIGINT)
    server_shutdown_tx.send(()).unwrap();
    let server_res = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await.unwrap();
    assert!(server_res.unwrap().is_ok(), "Server must shut down gracefully without error");

    // Signal and await sweep task termination
    shutdown_tx.send(true).unwrap();
    let sweep_res = tokio::time::timeout(std::time::Duration::from_secs(2), sweep_handle).await.unwrap();
    assert!(sweep_res.is_ok(), "Sweep task must join cleanly after server shutdown");
}
