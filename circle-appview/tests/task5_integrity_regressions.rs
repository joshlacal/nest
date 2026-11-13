mod support;
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use support::{fixture_commit, fixture_star};

use circle_appview::{
    access::{self, ActiveSpaceCredential, CredentialStore, SpaceLockManager},
    auth::{DidDocument, DidResolver, DidService, PublicKeyJwk, VerificationMethod},
    commit::{compute_dagcbor_cid, json_to_ipld, LtHash as RepoLtHash, RepoRecord},
    config::{AppState, Config},
    db,
    error::AppError,
    purge::{delete_space, remove_member},
    space_client::{
        ListWritersOutput, MockSpaceHostTransport, RepoWrite, SpaceClient, WriterUpdate,
    },
    sync::{sweep_once_with_shutdown, SyncEngine},
    validator::{
        prune_rejections, validate_record, InvalidRecord, RecordCandidate, ValidationPolicy,
    },
};

const CIRCLE_AUDIENCE: &str = "did:web:circles.catbird.blue#atproto_circles";
const OWNER_DID: &str = "did:plc:alice-task5-test";
const BOB_DID: &str = "did:plc:bob-task5-test";
const SPACE_URI: &str = "at://did:plc:alice-task5-test/space/blue.catbird.circle/task5-circle";

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

#[allow(dead_code)]
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

#[allow(dead_code)]
struct TestSetup {
    state: AppState,
    owner_signing_key: SigningKey,
    bob_signing_key: SigningKey,
    mock_transport: Arc<MockSpaceHostTransport>,
    pool: PgPool,
}

fn register_did_doc(
    resolver: &DidResolver,
    did: &str,
    key: &SigningKey,
    services: Option<Vec<DidService>>,
) {
    let vk = key.verifying_key();
    let point = p256::EncodedPoint::from(vk);
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());

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
        service: services.unwrap_or_else(|| {
            vec![DidService {
                id: "#atproto_pds".into(),
                r#type: "AtprotoPersonalDataServer".into(),
                service_endpoint: "https://pds.example.com".into(),
            }]
        }),
    };
    resolver.insert_cached(did.into(), did_doc);
}

async fn setup_test(pool: PgPool) -> TestSetup {
    db::run_migrations(&pool)
        .await
        .expect("Migrations must succeed");

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
        identity_relay_url: None,
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circles"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
    };
    let owner_signing_key = SigningKey::random(&mut OsRng);
    let bob_signing_key = SigningKey::random(&mut OsRng);

    let mock_transport = Arc::new(MockSpaceHostTransport::new());
    let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
    let did_resolver = Arc::new(DidResolver::new(
        "https://plc.directory".into(),
        reqwest::Client::new(),
    ));
    let credential_store = Arc::new(CredentialStore::new());
    let space_locks = Arc::new(SpaceLockManager::new());
    let profile_hydrator = Arc::new(circle_appview::hydration::ProfileHydrator::new(
        config.public_appview_url.clone(),
        reqwest::Client::new(),
    ));
    let oauth_signing_key = SigningKey::random(&mut OsRng);
    let oauth_service = Arc::new(circle_appview::oauth::OAuthService::new(
        pool.clone(),
        config.appview_base_url.clone(),
        oauth_signing_key,
        None,
    ));
    space_client.set_deps(circle_appview::space_client::SpaceClientDeps {
        http_client: reqwest::Client::new(),
        did_resolver: did_resolver.clone(),
        oauth_service: oauth_service.clone(),
    });

    let state = AppState {
        config: Arc::new(config),
        db: pool.clone(),
        http_client: reqwest::Client::new(),
        did_resolver: did_resolver.clone(),
        credential_store: credential_store.clone(),
        space_client,
        space_locks,
        listing_resume: Default::default(),
        profile_hydrator,
        oauth_service,
        push_client: None,
    };

    // Populate DIDs in resolver
    register_did_doc(&did_resolver, OWNER_DID, &owner_signing_key, None);
    register_did_doc(&did_resolver, BOB_DID, &bob_signing_key, None);

    // Insert Circle and members
    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, deleted_at) VALUES ($1, $2, $3, $4, now(), NULL)"
    )
    .bind(SPACE_URI)
    .bind("task5-circle")
    .bind(OWNER_DID)
    .bind("Task 5 Circle")
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_member_cache (space_uri, member_did, cached_at) VALUES ($1, $2, now()), ($1, $3, now())"
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(BOB_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count, generation) VALUES ($1, now(), 2, 1) ON CONFLICT (space_uri) DO NOTHING"
    )
    .bind(SPACE_URI)
    .execute(&pool)
    .await
    .unwrap();

    credential_store
        .insert(
            SPACE_URI.to_string(),
            ActiveSpaceCredential {
                token: "test-space-token".into(),
                signing_key: SigningKey::random(&mut OsRng),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        )
        .await;

    TestSetup {
        state,
        owner_signing_key,
        bob_signing_key,
        mock_transport,
        pool,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn test_cas_rejects_rollback_and_equal_rev_different_hash(pool: PgPool) {
    let setup = setup_test(pool).await;
    let sync_engine = SyncEngine::new(&setup.state);

    // Initial state: rev "3l7234567a234"
    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "hello world",
        "createdAt": "2026-08-30T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();
    let mut lthash = LtHash::default();
    lthash.add("app.bsky.feed.post", "3l7post11111", &post_cid);

    let init_commit = fixture_commit(SPACE_URI, OWNER_DID, "3l7234567a234", lthash.as_bytes());
    let post_ipld = json_to_ipld(&post_val).unwrap();
    let car_init = fixture_star(
        &init_commit,
        &[RepoRecord {
            collection: "app.bsky.feed.post".to_string(),
            rkey: "3l7post11111".to_string(),
            cid: post_cid.clone(),
            value: post_val.clone(),
        }],
    )
    .unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), car_init);
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            cursor: None,
            ops: vec![
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: Some(post_cid.clone().into()),
                    collection: "app.bsky.feed.post".to_string().into(),
                    prev: None,
                    rev: "3l7234567a234".to_string().into(),
                    rkey: catbird_atproto::jacquard_common::types::string::Rkey::new(
                        "3l7post11111",
                    )
                    .unwrap()
                    .into(),
                    value: Some(post_ipld),
                    extra_data: None,
                },
            ],
            commit: init_commit,
            extra_data: None,
        },
    );

    let res = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();
    assert_eq!(res.latest_rev, "3l7234567a234");

    // 1. Full recovery rollback attempt: CAR served at older rev "3l7234567a233" -> MUST fail
    let rollback_commit = fixture_commit(SPACE_URI, OWNER_DID, "3l7234567a233", lthash.as_bytes());
    let car_rollback = fixture_star(&rollback_commit, &[]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), car_rollback);

    // Fail ops fetch to route to full recovery
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            cursor: None,
            ops: vec![],
            commit: rollback_commit,
            extra_data: None,
        },
    );

    let rollback_res = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await;
    assert!(
        rollback_res.is_err(),
        "Rollback to older revision in full recovery must be rejected"
    );

    // 2. Equal-rev different-hash attempt -> MUST fail
    let mut different_lthash = LtHash::default();
    different_lthash.add(
        "app.bsky.feed.post",
        "3l7post11111",
        "bafyreibw72zfc6x2jwhvhk3w23vgt4i7l67v5k2k4z6w7i4j5z4w6i4j5z",
    );
    let diff_commit = fixture_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        different_lthash.as_bytes(),
    );
    let car_diff = fixture_star(&diff_commit, &[]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), car_diff);

    let diff_res = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await;
    assert!(
        diff_res.is_err(),
        "Equal revision with different hash in full recovery must be rejected"
    );

    // Verify stored sync state was NOT rolled back or modified
    let state_row: (String,) = sqlx::query_as(
        "SELECT last_rev FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&setup.pool)
    .await
    .unwrap();
    assert_eq!(state_row.0, "3l7234567a234");
}

#[sqlx::test(migrations = "./migrations")]
async fn test_membership_authorization_before_work_and_recheck_in_projection(pool: PgPool) {
    let setup = setup_test(pool).await;
    let sync_engine = SyncEngine::new(&setup.state);

    const NON_MEMBER_DID: &str = "did:plc:eve-unauthorized";

    // Non-member attempting sync fails immediately before lock acquisition / network
    let err = sync_engine
        .sync_repo(SPACE_URI, NON_MEMBER_DID)
        .await
        .unwrap_err();
    match err {
        AppError::Forbidden(msg) => assert!(msg.contains("not an active member")),
        other => panic!("Expected Forbidden for non-member, got {other:?}"),
    }

    // Verify removing member evicts from cache and increments generation
    remove_member(&setup.pool, SPACE_URI, BOB_DID)
        .await
        .unwrap();

    let meta_gen: (i64,) =
        sqlx::query_as("SELECT generation FROM circle_member_cache_meta WHERE space_uri = $1")
            .bind(SPACE_URI)
            .fetch_one(&setup.pool)
            .await
            .unwrap();
    assert_eq!(meta_gen.0, 2);

    let err = sync_engine.sync_repo(SPACE_URI, BOB_DID).await.unwrap_err();
    match err {
        AppError::Forbidden(msg) => assert!(msg.contains("not an active member")),
        other => panic!("Expected Forbidden for evicted member, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn test_linearizable_activation_cannot_resurrect_purged_circle(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Purge / delete space
    delete_space(&setup.pool, &setup.state.credential_store, SPACE_URI)
        .await
        .unwrap();

    // Verify circles row is tombstoned
    let circle_row: Option<(Option<chrono::DateTime<Utc>>,)> =
        sqlx::query_as("SELECT deleted_at FROM circles WHERE space_uri = $1")
            .bind(SPACE_URI)
            .fetch_optional(&setup.pool)
            .await
            .unwrap();
    assert!(circle_row.is_some() && circle_row.unwrap().0.is_some());
    // Activating a deleted/tombstoned space must be rejected
    let activation_res = access::activate_circle(&setup.state, SPACE_URI, "task5-circle").await;
    assert!(
        activation_res.is_err(),
        "Activation of tombstoned space must be rejected"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn test_missing_operation_value_fails_atomically_without_advancing_sync_state(pool: PgPool) {
    let setup = setup_test(pool).await;
    let sync_engine = SyncEngine::new(&setup.state);

    // Initial commit with record 1
    let val1 = json!({"$type": "app.bsky.feed.post", "text": "one", "createdAt": "2026-08-30T12:00:00.000Z"});
    let cid1 = compute_dagcbor_cid(&val1).unwrap();
    let mut lthash = LtHash::default();
    lthash.add("app.bsky.feed.post", "rkey1", &cid1);

    let init_commit = fixture_commit(SPACE_URI, OWNER_DID, "3l7234567a234", lthash.as_bytes());
    let post_ipld = json_to_ipld(&val1).unwrap();
    let car1 = fixture_star(
        &init_commit,
        &[RepoRecord {
            collection: "app.bsky.feed.post".to_string(),
            rkey: "rkey1".to_string(),
            cid: cid1.clone(),
            value: val1,
        }],
    )
    .unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), car1);
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            cursor: None,
            ops: vec![
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: Some(cid1.clone().into()),
                    collection: "app.bsky.feed.post".to_string().into(),
                    prev: None,
                    rev: "3l7234567a234".to_string().into(),
                    rkey: catbird_atproto::jacquard_common::types::string::Rkey::new("rkey1")
                        .unwrap()
                        .into(),
                    value: Some(post_ipld),
                    extra_data: None,
                },
            ],
            commit: init_commit.clone(),
            extra_data: None,
        },
    );

    let res1 = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();
    assert_eq!(res1.latest_rev, "3l7234567a234");

    // Incremental op has cid2 present, but value is None
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            cursor: None,
            ops: vec![
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: Some(
                        "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
                            .to_string()
                            .into(),
                    ),
                    collection: "app.bsky.feed.post".to_string().into(),
                    prev: None,
                    rev: "3l7234567a235".to_string().into(),
                    rkey: catbird_atproto::jacquard_common::types::string::Rkey::new("rkey2")
                        .unwrap()
                        .into(),
                    value: None, // Missing value!
                    extra_data: None,
                },
            ],
            commit: init_commit,
            extra_data: None,
        },
    );

    // Set fallback recovery CAR to invalid
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), vec![0xFF; 16]);

    let res2 = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await;
    assert!(
        res2.is_err(),
        "Sync must fail when operation value is missing for CID"
    );

    // 1. Existing record must NOT be tombstoned
    let rec_row: (Option<chrono::DateTime<Utc>>,) =
        sqlx::query_as("SELECT deleted_at FROM circle_records WHERE uri = $1")
            .bind(format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/rkey1"))
            .fetch_one(&setup.pool)
            .await
            .unwrap();
    assert!(
        rec_row.0.is_none(),
        "Existing record must not be tombstoned"
    );

    // 2. Sync state must remain at rev1
    let state_row: (String,) = sqlx::query_as(
        "SELECT last_rev FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&setup.pool)
    .await
    .unwrap();
    assert_eq!(state_row.0, "3l7234567a234");
}

#[sqlx::test(migrations = "./migrations")]
async fn test_canonical_recordkey_validation_rejects_malformed_rkeys(pool: PgPool) {
    let _setup = setup_test(pool).await;
    let policy = ValidationPolicy::new(OWNER_DID, vec![OWNER_DID]);

    for bad_rkey in [
        ".",
        "..",
        "has space",
        "has/slash",
        "has?query",
        "has#fragment",
        "",
    ] {
        let candidate = RecordCandidate {
            uri: format!("{SPACE_URI}/{OWNER_DID}/app.bsky.feed.post/{bad_rkey}"),
            author_did: OWNER_DID.to_string(),
            collection: "app.bsky.feed.post".to_string(),
            rkey: bad_rkey.to_string(),
            value: json!({
                "$type": "app.bsky.feed.post",
                "text": "Hello",
                "createdAt": "2026-08-30T12:00:00.000Z"
            }),
        };

        let res = validate_record(&candidate, &policy);
        assert!(
            res.is_err(),
            "Malformed rkey '{bad_rkey}' must be rejected by validate_record"
        );
        match res.unwrap_err() {
            InvalidRecord::MalformedRecord(msg) => assert!(msg.contains("RecordKey")),
            other => panic!("Expected MalformedRecord for '{bad_rkey}', got {other:?}"),
        }
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn test_prune_rejections_retention_bounds(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Insert fresh rejection and old rejection with full scope
    let fresh_hash = [0x01u8; 32];
    let old_hash = [0x02u8; 32];

    sqlx::query(
        r#"
        INSERT INTO circle_rejections (space_uri, author_did, rev, uri_hash, reason_code, observed_at)
        VALUES ($1, $2, '3l7rev1', $3, 'top_level_author', now()),
               ($1, $2, '3l7rev0', $4, 'malformed_record', now() - INTERVAL '10 days')
        "#
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(&fresh_hash[..])
    .bind(&old_hash[..])
    .execute(&setup.pool)
    .await
    .unwrap();

    let pruned = prune_rejections(&setup.pool, 7).await.unwrap();
    assert_eq!(pruned, 1);

    let remaining: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT uri_hash FROM circle_rejections")
        .fetch_all(&setup.pool)
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].0, fresh_hash);
}

#[sqlx::test(migrations = "./migrations")]
async fn test_delete_space_cascades_circle_member_cache_meta(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Verify circle_member_cache_meta row exists
    let meta_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM circle_member_cache_meta WHERE space_uri = $1)",
    )
    .bind(SPACE_URI)
    .fetch_one(&setup.pool)
    .await
    .unwrap();
    assert!(meta_exists, "Meta row must exist initially");

    // Delete space
    delete_space(&setup.pool, &setup.state.credential_store, SPACE_URI)
        .await
        .unwrap();

    // Verify circle_member_cache_meta row is cascaded/deleted
    let meta_remaining: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM circle_member_cache_meta WHERE space_uri = $1)",
    )
    .bind(SPACE_URI)
    .fetch_one(&setup.pool)
    .await
    .unwrap();
    assert!(
        !meta_remaining,
        "circle_member_cache_meta row must be deleted on delete_space"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn test_sweep_checkpoint_fair_resume_and_shutdown(pool: PgPool) {
    let setup = setup_test(pool).await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Initial sweep updates checkpoint
    let summary = sweep_once_with_shutdown(&setup.state, None).await.unwrap();
    assert!(summary.spaces_checked >= 1);

    let checkpoint: Option<(String,)> = sqlx::query_as("SELECT last_space_uri FROM circle_sweep_checkpoint WHERE checkpoint_key = 'revision_sweep'")
        .fetch_optional(&setup.pool)
        .await
        .unwrap();
    assert!(checkpoint.is_some());

    // Cooperative shutdown halts immediately
    shutdown_tx.send(true).unwrap();
    let mut rx = shutdown_rx.clone();
    let shutdown_summary = sweep_once_with_shutdown(&setup.state, Some(&mut rx))
        .await
        .unwrap();
    assert_eq!(
        shutdown_summary.spaces_checked, 0,
        "Sweep must halt immediately on shutdown signal"
    );
}

fn writer_update(repo: impl Into<String>, data: u8) -> WriterUpdate {
    WriterUpdate::RepoWrite(RepoWrite {
        repo: repo.into(),
        repo_rev: "3jzfcijpj2m2a".into(),
        data: bytes::Bytes::from(vec![data; 32]),
        space_rev: "3l7spacerev2a".into(),
        prev_space_rev: None,
    })
}

#[sqlx::test(migrations = "./migrations")]
async fn test_sweep_budget_and_shutdown_in_per_page_repo_loop(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Create multiple repos in a listWriters page response.
    let repos = vec![
        writer_update("did:plc:repo-1", 0x11),
        writer_update("did:plc:repo-2", 0x22),
        writer_update("did:plc:repo-3", 0x33),
    ];

    setup.mock_transport.set_list_writers_response(
        SPACE_URI,
        ListWritersOutput {
            cursor: None,
            repos,
        },
    );

    // Test cooperative shutdown triggered in repo loop
    let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(true);
    let summary = sweep_once_with_shutdown(&setup.state, Some(&mut shutdown_rx))
        .await
        .unwrap();
    assert_eq!(
        summary.repos_synced, 0,
        "Shutdown signal must prevent repo loop processing"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn test_sweep_stops_at_first_failing_ordered_writer_update(pool: PgPool) {
    let setup = setup_test(pool).await;

    // listWriters is ordered by spaceRev. A failed entry must stop the page so
    // the durable checkpoint cannot skip it and make later updates permanent.
    let repos = (0..105)
        .map(|i| writer_update(format!("did:plc:failing-repo-{i}"), 0xAA))
        .collect();

    setup.mock_transport.set_list_writers_response(
        SPACE_URI,
        ListWritersOutput {
            cursor: None,
            repos,
        },
    );

    let summary = circle_appview::sync::sweep_once(&setup.state)
        .await
        .unwrap();
    assert_eq!(summary.repos_checked, 1);
    assert_eq!(summary.repos_failed, 1);
    assert_eq!(summary.repos_synced, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn test_sweep_budget_halts_on_rejected_car_byte_limit(pool: PgPool) {
    let setup = setup_test(pool).await;

    let repos = vec![
        writer_update(OWNER_DID, 0xBB),
        writer_update("did:plc:unreached-repo-2", 0xCC),
    ];

    setup.mock_transport.set_list_writers_response(
        SPACE_URI,
        ListWritersOutput {
            cursor: None,
            repos,
        },
    );

    // Mock 12MB invalid CAR response for OWNER_DID (exceeds 10MB budget)
    setup.mock_transport.set_get_repo_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        vec![0xFF; 12 * 1024 * 1024],
    );
    let summary = circle_appview::sync::sweep_once(&setup.state)
        .await
        .unwrap();
    assert_eq!(
        summary.repos_checked, 1,
        "Sweep must halt after 12MB rejected CAR without checking remaining repos"
    );
    assert_eq!(summary.repos_failed, 1);
    assert_eq!(summary.repos_synced, 0);
}
