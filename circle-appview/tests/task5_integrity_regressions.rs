use base64::Engine;
use chrono::Utc;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use circle_appview::{
    access::{self, ActiveSpaceCredential, CredentialStore, SpaceLockManager},
    auth::{
        DidDocument, DidResolver, DidService, ParsedVerifyingKey, PublicKeyJwk, VerificationMethod,
    },
    commit::{
        compute_dagcbor_cid, extract_and_validate_car_with_policy, json_to_ipld, mint_repo_car,
        mint_signed_commit, mint_signed_commit_v2_p256, parse_permissioned_car, verify_commit_v2,
        CommitContextV2, CommitVerificationPolicy, LtHash as RepoLtHash, RepoRecord,
    },
    config::{AppState, Config},
    db,
    error::AppError,
    purge::{delete_space, remove_member},
    space_client::{MockSpaceHostTransport, SpaceClient},
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
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circles"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
        commit_verification_policy: CommitVerificationPolicy::default(),
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
                dpop_key: SigningKey::random(&mut OsRng),
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
    let sync_engine = SyncEngine::new(&setup.state)
        .with_commit_verification_policy(CommitVerificationPolicy::ExplicitMigrationPermitV1);

    // Initial state: rev "3l7234567a234"
    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "hello world",
        "createdAt": "2026-08-30T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();
    let mut lthash = LtHash::default();
    lthash.add("app.bsky.feed.post", "3l7post11111", &post_cid);

    let init_commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );
    let post_ipld = json_to_ipld(&post_val).unwrap();
    let car_init = mint_repo_car(
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
            commit: Some(init_commit),
            extra_data: None,
        },
    );

    let res = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await.unwrap();
    assert_eq!(res.latest_rev, "3l7234567a234");

    // 1. Full recovery rollback attempt: CAR served at older rev "3l7234567a233" -> MUST fail
    let rollback_commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a233",
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );
    let car_rollback = mint_repo_car(&rollback_commit, &[]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), car_rollback);

    // Fail ops fetch to route to full recovery
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            cursor: None,
            ops: vec![],
            commit: Some(rollback_commit),
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
    let diff_commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        different_lthash.as_bytes(),
        &setup.owner_signing_key,
    );
    let car_diff = mint_repo_car(&diff_commit, &[]).unwrap();
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

    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header_json).unwrap());
    let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&claims_json).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

#[sqlx::test(migrations = "./migrations")]
async fn test_notify_write_requires_active_membership_before_work(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Non-member DID
    const EVE_DID: &str = "did:plc:eve-not-member";
    let eve_key = SigningKey::random(&mut OsRng);
    register_did_doc(&setup.state.did_resolver, EVE_DID, &eve_key, None);

    let token = mint_service_jwt(
        EVE_DID,
        &setup.state.config.service_did,
        "com.atproto.space.notifyWrite",
        &eve_key,
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );

    let body = serde_json::to_vec(
        &catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite {
            hash: bytes::Bytes::copy_from_slice(&[0x42; 32]),
            repo: catbird_atproto::jacquard_common::types::string::Did::from(String::from(EVE_DID)),
            rev: catbird_atproto::jacquard_common::types::string::Tid::from(String::from(
                "3l7234567a234",
            )),
            space: catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new_owned(SPACE_URI)
                .unwrap(),
            extra_data: None,
        },
    )
    .unwrap();

    let res = circle_appview::sync::notify_write_handler(
        axum::extract::State(setup.state.clone()),
        headers,
        bytes::Bytes::from(body),
    )
    .await;

    assert!(res.is_err());
    match res.unwrap_err() {
        AppError::Forbidden(msg) => assert!(msg.contains("not an active member")),
        other => panic!("Expected Forbidden, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn test_missing_operation_value_fails_atomically_without_advancing_sync_state(pool: PgPool) {
    let setup = setup_test(pool).await;
    let sync_engine = SyncEngine::new(&setup.state)
        .with_commit_verification_policy(CommitVerificationPolicy::ExplicitMigrationPermitV1);

    // Initial commit with record 1
    let val1 = json!({"$type": "app.bsky.feed.post", "text": "one", "createdAt": "2026-08-30T12:00:00.000Z"});
    let cid1 = compute_dagcbor_cid(&val1).unwrap();
    let mut lthash = LtHash::default();
    lthash.add("app.bsky.feed.post", "rkey1", &cid1);

    let init_commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );
    let post_ipld = json_to_ipld(&val1).unwrap();
    let car1 = mint_repo_car(
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
            commit: Some(init_commit),
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
            commit: None,
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
async fn test_commit_verification_policy_production_dispatch(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Default policy is StrictV2: sending a v1 commit must be rejected
    let sync_engine_strict = SyncEngine::new(&setup.state)
        .with_commit_verification_policy(CommitVerificationPolicy::StrictV2);

    let mut lthash = LtHash::default();
    lthash.add(
        "app.bsky.feed.post",
        "3l7post11111",
        "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454",
    );
    let v1_commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );
    let car_v1 = mint_repo_car(&v1_commit, &[]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), car_v1);
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            cursor: None,
            ops: vec![],
            commit: Some(v1_commit),
            extra_data: None,
        },
    );

    let res = sync_engine_strict.sync_repo(SPACE_URI, OWNER_DID).await;
    assert!(
        res.is_err(),
        "v1 commit must be rejected under StrictV2 policy in production sync"
    );

    // DualReadWithCutoff policy: cutoff at "3l7234567a230", commit is "3l7234567a234" -> must be rejected
    let sync_engine_dual = SyncEngine::new(&setup.state).with_commit_verification_policy(
        CommitVerificationPolicy::DualReadWithCutoff {
            cutoff_rev: "3l7234567a230".to_string(),
        },
    );

    let res_dual = sync_engine_dual.sync_repo(SPACE_URI, OWNER_DID).await;
    assert!(
        res_dual.is_err(),
        "v1 commit exceeding cutoff must be rejected under DualRead policy"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn test_car_extra_unreferenced_blocks_rejected(pool: PgPool) {
    let setup = setup_test(pool).await;

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "hello",
        "createdAt": "2026-08-30T12:00:00.000Z"
    });
    let post_cid = compute_dagcbor_cid(&post_val).unwrap();
    let mut lthash = LtHash::default();
    lthash.add("app.bsky.feed.post", "3l7post1", &post_cid);

    let commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3l7234567a234",
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );
    let mut car_bytes = mint_repo_car(
        &commit,
        &[RepoRecord {
            collection: "app.bsky.feed.post".to_string(),
            rkey: "3l7post1".to_string(),
            cid: post_cid,
            value: post_val,
        }],
    )
    .unwrap();

    // Append an extra unreferenced block
    let extra_data = serde_ipld_dagcbor::to_vec(&json!({"extra": "unreferenced"})).unwrap();
    let (extra_cid_bytes, _) = circle_appview::commit::create_cid_bytes_from_data(&extra_data);
    let section_len = extra_cid_bytes.len() + extra_data.len();
    let mut extra_section = Vec::new();
    let mut val = section_len;
    while val >= 0x80 {
        extra_section.push(((val & 0x7f) | 0x80) as u8);
        val >>= 7;
    }
    extra_section.push(val as u8);
    extra_section.extend_from_slice(&extra_cid_bytes);
    extra_section.extend_from_slice(&extra_data);
    car_bytes.extend_from_slice(&extra_section);

    let parsed_car = parse_permissioned_car(&car_bytes).await.unwrap();
    let res = extract_and_validate_car_with_policy(
        &parsed_car,
        SPACE_URI,
        OWNER_DID,
        &ParsedVerifyingKey::P256(*setup.owner_signing_key.verifying_key()),
        &CommitVerificationPolicy::ExplicitMigrationPermitV1,
    );
    assert!(
        res.is_err(),
        "CAR with unreferenced extra blocks must be rejected"
    );
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

#[sqlx::test(migrations = "./migrations")]
async fn test_v2_commit_context_anchored_to_trusted_local_state(pool: PgPool) {
    let setup = setup_test(pool).await;
    let sync_engine = SyncEngine::new(&setup.state)
        .with_commit_verification_policy(CommitVerificationPolicy::StrictV2);

    // Store head at rev "3l7234567a234"
    let init_val = json!({"$type": "app.bsky.feed.post", "text": "one", "createdAt": "2026-08-30T12:00:00.000Z"});
    let init_cid = compute_dagcbor_cid(&init_val).unwrap();
    let mut lthash = LtHash::default();
    lthash.add("app.bsky.feed.post", "rkey1", &init_cid);
    let init_hash = lthash.digest();

    sqlx::query(
        "INSERT INTO circle_repo_sync_state (space_uri, author_did, last_rev, last_hash, last_synced_at) VALUES ($1, $2, '3jzfcijpj2m24', $3, now())"
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(lthash.as_bytes().as_slice())
    .execute(&setup.pool)
    .await
    .unwrap();

    // Adversary produces v2 commit for rev "3jzfcijpj2m25", but with skipped/mismatched prev_rev "3jzfcijpj2m22" (stored is 3jzfcijpj2m24)
    let val2 = json!({"$type": "app.bsky.feed.post", "text": "two", "createdAt": "2026-08-30T12:01:00.000Z"});
    let cid2 = compute_dagcbor_cid(&val2).unwrap();
    let mut lthash2 = lthash.clone();
    lthash2.add("app.bsky.feed.post", "rkey2", &cid2);

    let forged_ctx = CommitContextV2 {
        space: SPACE_URI.to_string(),
        author: OWNER_DID.to_string(),
        rev: "3jzfcijpj2m25".to_string(),
        prev_rev: "3jzfcijpj2m22".to_string(), // Mismatched predecessor (stored is 3jzfcijpj2m24)
        hash: lthash2.digest(),
        prev_hash: init_hash,
        path: "app.bsky.feed.post/rkey2".to_string(),
        action: "create".to_string(),
        cid: Some(cid2.clone()),
        prev_cid: None,
        val: bytes::Bytes::from(serde_ipld_dagcbor::to_vec(&val2).unwrap()),
    };

    let forged_commit = mint_signed_commit_v2_p256(&forged_ctx, &setup.owner_signing_key).unwrap();

    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            cursor: None,
            ops: vec![
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: Some(cid2.into()),
                    collection: "app.bsky.feed.post".to_string().into(),
                    prev: None,
                    rev: "3jzfcijpj2m25".to_string().into(),
                    rkey: catbird_atproto::jacquard_common::types::string::Rkey::new("rkey2")
                        .unwrap()
                        .into(),
                    value: Some(json_to_ipld(&val2).unwrap()),
                    extra_data: None,
                },
            ],
            commit: Some(forged_commit),
            extra_data: None,
        },
    );

    // Set fallback recovery to invalid
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), vec![0xFF; 16]);

    // Sync must fail because trusted local state anchors prev_rev = "3jzfcijpj2m24"
    let sync_res = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await;
    assert!(
        sync_res.is_err(),
        "v2 commit with mismatched predecessor must fail against trusted local state"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn test_full_recovery_rejects_forged_prev_rev_or_prev_hash(pool: PgPool) {
    let setup = setup_test(pool).await;
    let sync_engine = SyncEngine::new(&setup.state)
        .with_commit_verification_policy(CommitVerificationPolicy::StrictV2);

    // 1. Initial stored state: rev = "3jzfcijpj2m24"
    let init_val = json!({"$type": "app.bsky.feed.post", "text": "one", "createdAt": "2026-08-30T12:00:00.000Z"});
    let init_cid = compute_dagcbor_cid(&init_val).unwrap();
    let mut lthash = LtHash::default();
    lthash.add("app.bsky.feed.post", "rkey1", &init_cid);
    let init_hash = lthash.digest();

    sqlx::query(
        "INSERT INTO circle_repo_sync_state (space_uri, author_did, last_rev, last_hash, last_synced_at) VALUES ($1, $2, '3jzfcijpj2m24', $3, now())"
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(lthash.as_bytes().as_slice())
    .execute(&setup.pool)
    .await
    .unwrap();

    let val2 = json!({"$type": "app.bsky.feed.post", "text": "two", "createdAt": "2026-08-30T12:01:00.000Z"});
    let cid2 = compute_dagcbor_cid(&val2).unwrap();
    let mut lthash2 = lthash.clone();
    lthash2.add("app.bsky.feed.post", "rkey2", &cid2);
    let rec1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "rkey1".to_string(),
        cid: init_cid.clone(),
        value: init_val.clone(),
    };
    let rec2 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "rkey2".to_string(),
        cid: cid2.clone(),
        value: val2.clone(),
    };

    // Case A: CAR commit has non-monotonic prev_rev (prev_rev >= rev)
    let non_mono_ctx = CommitContextV2 {
        space: SPACE_URI.to_string(),
        author: OWNER_DID.to_string(),
        rev: "3jzfcijpj2m25".to_string(),
        prev_rev: "3jzfcijpj2m26".to_string(), // non-descending (greater than rev)!
        hash: lthash2.digest(),
        prev_hash: init_hash,
        path: "app.bsky.feed.post/rkey2".to_string(),
        action: "create".to_string(),
        cid: Some(cid2.clone()),
        prev_cid: None,
        val: bytes::Bytes::from(serde_ipld_dagcbor::to_vec(&val2).unwrap()),
    };
    let non_mono_commit =
        mint_signed_commit_v2_p256(&non_mono_ctx, &setup.owner_signing_key).unwrap();
    let car_non_mono_bytes =
        mint_repo_car(&non_mono_commit, &[rec1.clone(), rec2.clone()]).unwrap();
    let parsed_non_mono_car = parse_permissioned_car(&car_non_mono_bytes).await.unwrap();

    let res_non_mono = extract_and_validate_car_with_policy(
        &parsed_non_mono_car,
        SPACE_URI,
        OWNER_DID,
        &ParsedVerifyingKey::P256(*setup.owner_signing_key.verifying_key()),
        &CommitVerificationPolicy::StrictV2,
    );
    assert!(
        res_non_mono.is_err(),
        "Full recovery CAR with non-monotonic prev_rev must be rejected"
    );

    // Case B: CAR commit forged with mismatched commit hash vs CAR index
    let forged_hash_ctx = CommitContextV2 {
        space: SPACE_URI.to_string(),
        author: OWNER_DID.to_string(),
        rev: "3jzfcijpj2m25".to_string(),
        prev_rev: "3jzfcijpj2m24".to_string(),
        hash: [0xEE; 32], // Mismatched hash vs index!
        prev_hash: init_hash,
        path: "app.bsky.feed.post/rkey2".to_string(),
        action: "create".to_string(),
        cid: Some(cid2.clone()),
        prev_cid: None,
        val: bytes::Bytes::from(serde_ipld_dagcbor::to_vec(&val2).unwrap()),
    };
    let forged_hash_commit =
        mint_signed_commit_v2_p256(&forged_hash_ctx, &setup.owner_signing_key).unwrap();
    let car_hash_bytes = mint_repo_car(&forged_hash_commit, &[rec1.clone(), rec2.clone()]).unwrap();
    let parsed_hash_car = parse_permissioned_car(&car_hash_bytes).await.unwrap();

    let res_hash = extract_and_validate_car_with_policy(
        &parsed_hash_car,
        SPACE_URI,
        OWNER_DID,
        &ParsedVerifyingKey::P256(*setup.owner_signing_key.verifying_key()),
        &CommitVerificationPolicy::StrictV2,
    );
    assert!(
        res_hash.is_err(),
        "Full recovery CAR with mismatched hash vs index must be rejected"
    );

    // Case C: Forged prev_hash when claiming immediate descent from stored head (prev_rev == "3jzfcijpj2m24" but prev_hash != init_hash)
    // The CAR itself is self-consistent (valid signature, index matches commit hash),
    // but in full recovery, the conditional anchor detects the fork against stored last_rev and rejects it.
    let forged_prev_hash_ctx = CommitContextV2 {
        space: SPACE_URI.to_string(),
        author: OWNER_DID.to_string(),
        rev: "3jzfcijpj2m25".to_string(),
        prev_rev: "3jzfcijpj2m24".to_string(), // Claims stored head as predecessor
        hash: lthash2.digest(),
        prev_hash: [0xAA; 32], // Forged prev_hash! Does not match stored init_hash!
        path: "app.bsky.feed.post/rkey2".to_string(),
        action: "create".to_string(),
        cid: Some(cid2.clone()),
        prev_cid: None,
        val: bytes::Bytes::from(serde_ipld_dagcbor::to_vec(&val2).unwrap()),
    };
    let forged_prev_hash_commit =
        mint_signed_commit_v2_p256(&forged_prev_hash_ctx, &setup.owner_signing_key).unwrap();
    let car_forged_prev_bytes =
        mint_repo_car(&forged_prev_hash_commit, &[rec1.clone(), rec2.clone()]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), car_forged_prev_bytes);

    let res_forged_prev = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await;
    assert!(
        res_forged_prev.is_err(),
        "Full recovery must reject CAR with forged prev_hash when prev_rev matches stored last_rev"
    );

    // Case D: Valid full recovery CAR with matching prev_rev and matching prev_hash succeeds
    let valid_ctx = CommitContextV2 {
        space: SPACE_URI.to_string(),
        author: OWNER_DID.to_string(),
        rev: "3jzfcijpj2m25".to_string(),
        prev_rev: "3jzfcijpj2m24".to_string(),
        hash: lthash2.digest(),
        prev_hash: init_hash, // Correctly matches stored init_hash
        path: "app.bsky.feed.post/rkey2".to_string(),
        action: "create".to_string(),
        cid: Some(cid2.clone()),
        prev_cid: None,
        val: bytes::Bytes::from(serde_ipld_dagcbor::to_vec(&val2).unwrap()),
    };
    let valid_commit = mint_signed_commit_v2_p256(&valid_ctx, &setup.owner_signing_key).unwrap();
    let car_valid_bytes = mint_repo_car(&valid_commit, &[rec1.clone(), rec2.clone()]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), car_valid_bytes);

    let res_valid = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await;
    assert!(
        res_valid.is_ok(),
        "Valid full recovery CAR under StrictV2 must succeed: {:?}",
        res_valid.err()
    );
    let valid_out = res_valid.unwrap();
    assert_eq!(valid_out.latest_rev, "3jzfcijpj2m25");

    // Case E: Multi-commit-gap recovery succeeds without anchoring to stored head
    // Stored head is now at rev "3jzfcijpj2m25".
    // Remote Space advanced across multiple commits to rev "3jzfcijpj2m2a" (prev_rev = "3jzfcijpj2m27").
    let val3 = json!({"$type": "app.bsky.feed.post", "text": "three", "createdAt": "2026-08-30T12:02:00.000Z"});
    let cid3 = compute_dagcbor_cid(&val3).unwrap();
    let mut lthash3 = lthash2.clone();
    lthash3.add("app.bsky.feed.post", "rkey3", &cid3);

    let rec3 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "rkey3".to_string(),
        cid: cid3.clone(),
        value: val3.clone(),
    };

    let gap_ctx = CommitContextV2 {
        space: SPACE_URI.to_string(),
        author: OWNER_DID.to_string(),
        rev: "3jzfcijpj2m2a".to_string(),
        prev_rev: "3jzfcijpj2m27".to_string(), // Longer gap: prev_rev != stored last_rev ("3jzfcijpj2m25")
        hash: lthash3.digest(),
        prev_hash: [0x55; 32], // Hash of state at rev 27 (different from stored hash at rev 25)
        path: "app.bsky.feed.post/rkey3".to_string(),
        action: "create".to_string(),
        cid: Some(cid3.clone()),
        prev_cid: None,
        val: bytes::Bytes::from(serde_ipld_dagcbor::to_vec(&val3).unwrap()),
    };
    let gap_commit = mint_signed_commit_v2_p256(&gap_ctx, &setup.owner_signing_key).unwrap();
    let car_gap_bytes = mint_repo_car(&gap_commit, &[rec1, rec2, rec3]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), car_gap_bytes);

    let res_gap = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await;
    assert!(
        res_gap.is_ok(),
        "Multi-commit-gap recovery under StrictV2 must succeed: {:?}",
        res_gap.err()
    );
    let gap_out = res_gap.unwrap();
    assert_eq!(gap_out.latest_rev, "3jzfcijpj2m2a");

    // Verify stored head in database advanced to "3jzfcijpj2m2a"
    let head_row: (String, Vec<u8>) = sqlx::query_as(
        "SELECT last_rev, last_hash FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2",
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&setup.pool)
    .await
    .unwrap();
    assert_eq!(head_row.0, "3jzfcijpj2m2a");
    assert_eq!(head_row.1, lthash3.as_bytes().as_slice());
}

#[sqlx::test(migrations = "./migrations")]
async fn test_activate_circle_uses_configured_commit_verification_policy(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Create a metadata record and mint a v1 commit
    let rec_meta_val = json!({
        "$type": "blue.catbird.circle.metadata",
        "circleId": "3jzfcijpj2m2a",
        "displayName": "Policy Test Circle",
        "createdAt": "2026-08-30T12:00:00.000Z"
    });
    let cid_meta = compute_dagcbor_cid(&rec_meta_val).unwrap();
    let mut lthash = LtHash::default();
    lthash.add("blue.catbird.circle.metadata", "self", &cid_meta);

    let v1_commit = mint_signed_commit(
        SPACE_URI,
        OWNER_DID,
        "3jzfcijpj2m2a",
        lthash.as_bytes(),
        &setup.owner_signing_key,
    );

    let rec_meta = RepoRecord {
        collection: "blue.catbird.circle.metadata".to_string(),
        rkey: "self".to_string(),
        cid: cid_meta.clone(),
        value: rec_meta_val.clone(),
    };
    let car_bytes = mint_repo_car(&v1_commit, std::slice::from_ref(&rec_meta)).unwrap();
    let key = format!("{SPACE_URI}:{OWNER_DID}");
    setup
        .mock_transport
        .set_get_repo_response(&key, car_bytes.clone());
    setup
        .mock_transport
        .set_get_repo_response(SPACE_URI, car_bytes.clone());

    // Setup active space credential
    let parsed_car = parse_permissioned_car(&car_bytes).await.unwrap();
    let owner_key = ParsedVerifyingKey::P256(*setup.owner_signing_key.verifying_key());

    // 1. Under StrictV2 policy, CAR validation must reject the v1 commit
    let strict_res = extract_and_validate_car_with_policy(
        &parsed_car,
        SPACE_URI,
        OWNER_DID,
        &owner_key,
        &CommitVerificationPolicy::StrictV2,
    );
    assert!(
        strict_res.is_err(),
        "CAR validation must fail under StrictV2 policy when CAR has v1 commit"
    );

    // 2. Under ExplicitMigrationPermitV1 policy, CAR validation must accept the v1 commit
    let permit_res = extract_and_validate_car_with_policy(
        &parsed_car,
        SPACE_URI,
        OWNER_DID,
        &owner_key,
        &CommitVerificationPolicy::ExplicitMigrationPermitV1,
    );
    assert!(
        permit_res.is_ok(),
        "CAR validation must succeed under ExplicitMigrationPermitV1 policy"
    );

    // 3. Under StrictV2 policy, CAR validation succeeds when CAR has v2 commit
    let v2_ctx = CommitContextV2 {
        space: SPACE_URI.to_string(),
        author: OWNER_DID.to_string(),
        rev: "3jzfcijpj2m2b".to_string(),
        prev_rev: "3jzfcijpj2m2a".to_string(),
        hash: lthash.digest(),
        prev_hash: [0u8; 32],
        path: "blue.catbird.circle.metadata/self".to_string(),
        action: "create".to_string(),
        cid: Some(cid_meta.clone()),
        prev_cid: None,
        val: bytes::Bytes::from(serde_ipld_dagcbor::to_vec(&rec_meta_val).unwrap()),
    };
    let v2_commit = mint_signed_commit_v2_p256(&v2_ctx, &setup.owner_signing_key).unwrap();
    let v2_car_bytes = mint_repo_car(&v2_commit, &[rec_meta]).unwrap();
    let parsed_v2_car = parse_permissioned_car(&v2_car_bytes).await.unwrap();

    let v2_res = extract_and_validate_car_with_policy(
        &parsed_v2_car,
        SPACE_URI,
        OWNER_DID,
        &owner_key,
        &CommitVerificationPolicy::StrictV2,
    );
    assert!(
        v2_res.is_ok(),
        "CAR validation must succeed under StrictV2 policy when CAR has v2 commit"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn test_sweep_budget_and_shutdown_in_per_page_repo_loop(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Create multiple repos in a list_repos page response
    let repos = vec![
        catbird_atproto::generated::com_atproto::space::list_repos::Repo {
            did: "did:plc:repo-1".to_string().into(),
            rev: "3jzfcijpj2m2a".to_string().into(),
            hash: bytes::Bytes::from(vec![0x11; 32]),
            extra_data: None,
        },
        catbird_atproto::generated::com_atproto::space::list_repos::Repo {
            did: "did:plc:repo-2".to_string().into(),
            rev: "3jzfcijpj2m2a".to_string().into(),
            hash: bytes::Bytes::from(vec![0x22; 32]),
            extra_data: None,
        },
        catbird_atproto::generated::com_atproto::space::list_repos::Repo {
            did: "did:plc:repo-3".to_string().into(),
            rev: "3jzfcijpj2m2a".to_string().into(),
            hash: bytes::Bytes::from(vec![0x33; 32]),
            extra_data: None,
        },
    ];

    setup.mock_transport.set_list_repos_response(
        SPACE_URI,
        catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput {
            cursor: None,
            repos,
            extra_data: None,
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
async fn test_multi_op_batch_strict_v2_verification_and_head_advance(pool: PgPool) {
    let setup = setup_test(pool).await;
    let sync_engine = SyncEngine::new(&setup.state)
        .with_commit_verification_policy(CommitVerificationPolicy::StrictV2);

    // Initial stored state in DB: rev = "3jzfcijpj2m20" with record rkey0
    let val0 = json!({"$type": "app.bsky.feed.post", "text": "zero", "createdAt": "2026-08-30T12:00:00.000Z"});
    let cid0 = compute_dagcbor_cid(&val0).unwrap();
    let mut lthash = LtHash::default();
    lthash.add("app.bsky.feed.post", "rkey0", &cid0);

    sqlx::query(
        "INSERT INTO circle_repo_sync_state (space_uri, author_did, last_rev, last_hash, last_synced_at) VALUES ($1, $2, '3jzfcijpj2m22', $3, now())"
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .bind(lthash.as_bytes().as_slice())
    .execute(&setup.pool)
    .await
    .unwrap();

    // Op 1: rev "3jzfcijpj2m23", creates post rkey1
    let val1 = json!({"$type": "app.bsky.feed.post", "text": "one", "createdAt": "2026-08-30T12:01:00.000Z"});
    let cid1 = compute_dagcbor_cid(&val1).unwrap();
    lthash.add("app.bsky.feed.post", "rkey1", &cid1);

    // Op 2: rev "3jzfcijpj2m24", creates post rkey2
    let val2 = json!({"$type": "app.bsky.feed.post", "text": "two", "createdAt": "2026-08-30T12:02:00.000Z"});
    let cid2 = compute_dagcbor_cid(&val2).unwrap();
    lthash.add("app.bsky.feed.post", "rkey2", &cid2);
    let hash2 = lthash.digest();

    // Op 3: rev "3jzfcijpj2m25", creates post rkey3
    let val3 = json!({"$type": "app.bsky.feed.post", "text": "three", "createdAt": "2026-08-30T12:03:00.000Z"});
    let cid3 = compute_dagcbor_cid(&val3).unwrap();
    lthash.add("app.bsky.feed.post", "rkey3", &cid3);
    let hash3 = lthash.digest();

    // Terminal commit for the 3-op batch:
    // A v2 commit describes the final transition (Op 3):
    // rev = "3jzfcijpj2m25", prev_rev = "3jzfcijpj2m24" (second-to-last applied op's rev),
    // hash = hash3 (post-batch digest), prev_hash = hash2 (LtHash digest before Op 3 is folded in)
    let commit_ctx = CommitContextV2 {
        space: SPACE_URI.to_string(),
        author: OWNER_DID.to_string(),
        rev: "3jzfcijpj2m25".to_string(),
        prev_rev: "3jzfcijpj2m24".to_string(),
        hash: hash3,
        prev_hash: hash2,
        path: "app.bsky.feed.post/rkey3".to_string(),
        action: "create".to_string(),
        cid: Some(cid3.clone()),
        prev_cid: None,
        val: bytes::Bytes::from(serde_ipld_dagcbor::to_vec(&val3).unwrap()),
    };
    let signed_commit = mint_signed_commit_v2_p256(&commit_ctx, &setup.owner_signing_key).unwrap();
    setup.mock_transport.set_list_repo_ops_response(
        &format!("{SPACE_URI}:{OWNER_DID}"),
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput {
            cursor: None,
            ops: vec![
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: Some(cid1.into()),
                    collection: "app.bsky.feed.post".to_string().into(),
                    prev: None,
                    rev: "3jzfcijpj2m23".to_string().into(),
                    rkey: catbird_atproto::jacquard_common::types::string::Rkey::new("rkey1")
                        .unwrap()
                        .into(),
                    value: Some(json_to_ipld(&val1).unwrap()),
                    extra_data: None,
                },
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: Some(cid2.into()),
                    collection: "app.bsky.feed.post".to_string().into(),
                    prev: None,
                    rev: "3jzfcijpj2m24".to_string().into(),
                    rkey: catbird_atproto::jacquard_common::types::string::Rkey::new("rkey2")
                        .unwrap()
                        .into(),
                    value: Some(json_to_ipld(&val2).unwrap()),
                    extra_data: None,
                },
                catbird_atproto::generated::com_atproto::space::list_repo_ops::OpEntry {
                    cid: Some(cid3.into()),
                    collection: "app.bsky.feed.post".to_string().into(),
                    prev: None,
                    rev: "3jzfcijpj2m25".to_string().into(),
                    rkey: catbird_atproto::jacquard_common::types::string::Rkey::new("rkey3")
                        .unwrap()
                        .into(),
                    value: Some(json_to_ipld(&val3).unwrap()),
                    extra_data: None,
                },
            ],
            commit: Some(signed_commit),
            extra_data: None,
        },
    );

    // Fallback get_repo set to fail to ensure incremental sync succeeds on its own
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_URI}:{OWNER_DID}"), vec![0xFF; 16]);

    let sync_res = sync_engine.sync_repo(SPACE_URI, OWNER_DID).await;
    assert!(
        sync_res.is_ok(),
        "3-op batch under StrictV2 must verify and succeed: {:?}",
        sync_res.err()
    );
    let res = sync_res.unwrap();
    assert!(res.commit_verified);
    assert_eq!(res.latest_rev, "3jzfcijpj2m25");
    assert_eq!(res.ops_applied, 3);

    // Verify stored sync state advanced in database
    let stored_sync: (String, Vec<u8>) = sqlx::query_as(
        "SELECT last_rev, last_hash FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2"
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&setup.pool)
    .await
    .unwrap();

    assert_eq!(stored_sync.0, "3jzfcijpj2m25");
    assert_eq!(stored_sync.1.as_slice(), lthash.as_bytes().as_slice());

    // Verify all 3 records staged and present
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM circle_records WHERE space_uri = $1 AND author_did = $2 AND deleted_at IS NULL"
    )
    .bind(SPACE_URI)
    .bind(OWNER_DID)
    .fetch_one(&setup.pool)
    .await
    .unwrap();
    assert_eq!(count.0, 3);
}

#[sqlx::test(migrations = "./migrations")]
async fn test_non_descending_predecessor_rejected_under_strict_v2(pool: PgPool) {
    let setup = setup_test(pool).await;

    let val = json!({"$type": "app.bsky.feed.post", "text": "hello", "createdAt": "2026-08-30T12:00:00.000Z"});
    let cid = compute_dagcbor_cid(&val).unwrap();
    let mut lthash = LtHash::default();
    lthash.add("app.bsky.feed.post", "rkey1", &cid);

    // Case A: rev == prev_rev (equal revision, non-descending)
    let equal_rev_ctx = CommitContextV2 {
        space: SPACE_URI.to_string(),
        author: OWNER_DID.to_string(),
        rev: "3jzfcijpj2m25".to_string(),
        prev_rev: "3jzfcijpj2m25".to_string(), // equal to rev!
        hash: lthash.digest(),
        prev_hash: [0u8; 32],
        path: "app.bsky.feed.post/rkey1".to_string(),
        action: "create".to_string(),
        cid: Some(cid.clone()),
        prev_cid: None,
        val: bytes::Bytes::from(serde_ipld_dagcbor::to_vec(&val).unwrap()),
    };
    let equal_commit =
        mint_signed_commit_v2_p256(&equal_rev_ctx, &setup.owner_signing_key).unwrap();
    let ver_res = verify_commit_v2(
        &equal_commit,
        &equal_rev_ctx,
        &ParsedVerifyingKey::P256(*setup.owner_signing_key.verifying_key()),
    );
    assert!(
        ver_res.is_err(),
        "Equal rev and prev_rev must be rejected as non-monotonic"
    );

    // Case B: rev < prev_rev (prev_rev in future, non-descending)
    let inverted_rev_ctx = CommitContextV2 {
        space: SPACE_URI.to_string(),
        author: OWNER_DID.to_string(),
        rev: "3jzfcijpj2m24".to_string(),
        prev_rev: "3jzfcijpj2m25".to_string(), // greater than rev!
        hash: lthash.digest(),
        prev_hash: [0u8; 32],
        path: "app.bsky.feed.post/rkey1".to_string(),
        action: "create".to_string(),
        cid: Some(cid),
        prev_cid: None,
        val: bytes::Bytes::from(serde_ipld_dagcbor::to_vec(&val).unwrap()),
    };
    let inverted_commit =
        mint_signed_commit_v2_p256(&inverted_rev_ctx, &setup.owner_signing_key).unwrap();
    let ver_res2 = verify_commit_v2(
        &inverted_commit,
        &inverted_rev_ctx,
        &ParsedVerifyingKey::P256(*setup.owner_signing_key.verifying_key()),
    );
    assert!(
        ver_res2.is_err(),
        "prev_rev greater than rev must be rejected as non-monotonic"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn test_sweep_budget_caps_failing_repos_at_max_repos_per_sweep(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Space with 105 failing repos capped by MAX_REPOS_PER_SWEEP = 100
    let mut repos = Vec::new();
    for i in 0..105 {
        repos.push(
            catbird_atproto::generated::com_atproto::space::list_repos::Repo {
                did: format!("did:plc:failing-repo-{i}").into(),
                rev: "3jzfcijpj2m2a".to_string().into(),
                hash: bytes::Bytes::from(vec![0xAA; 32]),
                extra_data: None,
            },
        );
    }

    setup.mock_transport.set_list_repos_response(
        SPACE_URI,
        catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput {
            cursor: None,
            repos,
            extra_data: None,
        },
    );

    let summary = circle_appview::sync::sweep_once(&setup.state)
        .await
        .unwrap();
    assert_eq!(
        summary.repos_checked, 100,
        "Sweep must halt at MAX_REPOS_PER_SWEEP (100) even when all repos fail"
    );
    assert_eq!(summary.repos_failed, 100);
    assert_eq!(summary.repos_synced, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn test_sweep_budget_halts_on_rejected_car_byte_limit(pool: PgPool) {
    let setup = setup_test(pool).await;

    let repos = vec![
        catbird_atproto::generated::com_atproto::space::list_repos::Repo {
            did: OWNER_DID.to_string().into(),
            rev: "3jzfcijpj2m2a".to_string().into(),
            hash: bytes::Bytes::from(vec![0xBB; 32]),
            extra_data: None,
        },
        catbird_atproto::generated::com_atproto::space::list_repos::Repo {
            did: "did:plc:unreached-repo-2".to_string().into(),
            rev: "3jzfcijpj2m2a".to_string().into(),
            hash: bytes::Bytes::from(vec![0xCC; 32]),
            extra_data: None,
        },
    ];

    setup.mock_transport.set_list_repos_response(
        SPACE_URI,
        catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput {
            cursor: None,
            repos,
            extra_data: None,
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
