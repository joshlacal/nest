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
        compute_dagcbor_cid, extract_and_validate_car, json_to_ipld, mint_repo_car,
        mint_signed_commit, parse_permissioned_car, LtHash as RepoLtHash, RepoRecord,
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
    // The default policy must accept the upstream v1 commits this test syncs.
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

    // A forwarded notification comes from the space authority; Eve signing her
    // own is refused before any work.
    let eve_token = mint_service_jwt(
        EVE_DID,
        &setup.state.config.service_did,
        "com.atproto.space.notifyWrite",
        &eve_key,
    );
    let mut eve_headers = axum::http::HeaderMap::new();
    eve_headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {eve_token}").parse().unwrap(),
    );

    // The authority forwarding a notification for a non-member's repo.
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

    let body = serde_json::to_vec(
        &catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite {
            hash: bytes::Bytes::copy_from_slice(&[0x42; 32]),
            repo: catbird_atproto::jacquard_common::types::string::Did::from(String::from(EVE_DID)),
            repo_rev: catbird_atproto::jacquard_common::types::string::Tid::from(String::from(
                "3l7234567a234",
            )),
            space_rev: Some(catbird_atproto::jacquard_common::types::string::Tid::from(
                String::from("3l7spacerev2a"),
            )),
            prev_space_rev: None,
            space: catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new_owned(SPACE_URI)
                .unwrap(),
            extra_data: None,
        },
    )
    .unwrap();

    let res = circle_appview::sync::notify_write_handler(
        axum::extract::State(setup.state.clone()),
        eve_headers,
        bytes::Bytes::from(body.clone()),
    )
    .await;
    match res.unwrap_err() {
        AppError::Forbidden(msg) => assert!(msg.contains("not the space authority"), "{msg}"),
        other => panic!("Expected Forbidden, got {other:?}"),
    }

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
    // The default policy must accept the upstream v1 commits this test syncs.
    let sync_engine = SyncEngine::new(&setup.state);

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
    let res = extract_and_validate_car(
        &parsed_car,
        SPACE_URI,
        OWNER_DID,
        &ParsedVerifyingKey::P256(*setup.owner_signing_key.verifying_key()),
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
async fn test_car_validation_accepts_only_upstream_v1_commits(pool: PgPool) {
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

    let parsed_car = parse_permissioned_car(&car_bytes).await.unwrap();
    let owner_key = ParsedVerifyingKey::P256(*setup.owner_signing_key.verifying_key());

    // 1. An upstream v1 commit is accepted (CIRCLES-01).
    let v1_res = extract_and_validate_car(&parsed_car, SPACE_URI, OWNER_DID, &owner_key);
    assert!(
        v1_res.is_ok(),
        "CAR validation must accept an upstream v1 commit: {:?}",
        v1_res.err()
    );

    // 2. Any other commit version is rejected; v2 was a retired Catbird-only fork.
    let mut v2_commit = v1_commit.clone();
    v2_commit.ver = 2;
    let v2_car_bytes = mint_repo_car(&v2_commit, &[rec_meta]).unwrap();
    let parsed_v2_car = parse_permissioned_car(&v2_car_bytes).await.unwrap();
    let v2_err = extract_and_validate_car(&parsed_v2_car, SPACE_URI, OWNER_DID, &owner_key)
        .expect_err("a non-v1 commit must be rejected");
    assert!(
        v2_err.to_string().contains("unsupported commit version"),
        "unexpected error: {v2_err}"
    );

    // 3. A v1 commit for a different author fails signature/context verification.
    let other_key = ParsedVerifyingKey::P256(*SigningKey::random(&mut OsRng).verifying_key());
    assert!(
        extract_and_validate_car(&parsed_car, SPACE_URI, OWNER_DID, &other_key).is_err(),
        "a v1 commit must not verify under another key"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn test_sweep_budget_and_shutdown_in_per_page_repo_loop(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Create multiple repos in a list_repos page response
    let repos = vec![
        catbird_atproto::generated::com_atproto::space::list_repos::Repo {
            did: "did:plc:repo-1".to_string().into(),
            repo_rev: "3jzfcijpj2m2a".to_string().into(),
            space_rev: catbird_atproto::jacquard_common::types::string::Tid::from(String::from(
                "3l7spacerev2a",
            )),
            hash: bytes::Bytes::from(vec![0x11; 32]),
            extra_data: None,
        },
        catbird_atproto::generated::com_atproto::space::list_repos::Repo {
            did: "did:plc:repo-2".to_string().into(),
            repo_rev: "3jzfcijpj2m2a".to_string().into(),
            space_rev: catbird_atproto::jacquard_common::types::string::Tid::from(String::from(
                "3l7spacerev2a",
            )),
            hash: bytes::Bytes::from(vec![0x22; 32]),
            extra_data: None,
        },
        catbird_atproto::generated::com_atproto::space::list_repos::Repo {
            did: "did:plc:repo-3".to_string().into(),
            repo_rev: "3jzfcijpj2m2a".to_string().into(),
            space_rev: catbird_atproto::jacquard_common::types::string::Tid::from(String::from(
                "3l7spacerev2a",
            )),
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
async fn test_sweep_budget_caps_failing_repos_at_max_repos_per_sweep(pool: PgPool) {
    let setup = setup_test(pool).await;

    // Space with 105 failing repos capped by MAX_REPOS_PER_SWEEP = 100
    let mut repos = Vec::new();
    for i in 0..105 {
        repos.push(
            catbird_atproto::generated::com_atproto::space::list_repos::Repo {
                did: format!("did:plc:failing-repo-{i}").into(),
                repo_rev: "3jzfcijpj2m2a".to_string().into(),
                space_rev: catbird_atproto::jacquard_common::types::string::Tid::from(
                    String::from("3l7spacerev2a"),
                ),
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
            repo_rev: "3jzfcijpj2m2a".to_string().into(),
            space_rev: catbird_atproto::jacquard_common::types::string::Tid::from(String::from(
                "3l7spacerev2a",
            )),
            hash: bytes::Bytes::from(vec![0xBB; 32]),
            extra_data: None,
        },
        catbird_atproto::generated::com_atproto::space::list_repos::Repo {
            did: "did:plc:unreached-repo-2".to_string().into(),
            repo_rev: "3jzfcijpj2m2a".to_string().into(),
            space_rev: catbird_atproto::jacquard_common::types::string::Tid::from(String::from(
                "3l7spacerev2a",
            )),
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
