use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_atproto::generated::app_bsky::actor::get_profile::GetProfileOutput;
use catbird_atproto::generated::app_bsky::actor::{ProfileAssociated, ProfileViewBasic, ProfileViewDetailed};
use catbird_atproto::generated::app_bsky::feed::{PostViewEmbed, ThreadViewPostParent, ThreadViewPostRepliesItem};
use catbird_atproto::generated::blue_catbird::circle::get_feed::GetFeedOutput;
use catbird_atproto::generated::blue_catbird::circle::get_post_thread::GetPostThreadOutput;
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::string::{Datetime, Did, Handle, UriValue};
use chrono::{Duration, Utc};
use circle_appview::{
    auth::{DidDocument, PublicKeyJwk, VerificationMethod},
    commit::create_cid_bytes_from_data,
    config::{AppState, Config},
    db,
    hydration::ProfileHydrator,
    routes::create_router,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

use sha2::{Digest, Sha256};
use circle_appview::validator::{policy, validate_record, RecordCandidate, ValidationPolicy};
const CIRCLE_AUDIENCE: &str = "did:web:circles.catbird.blue#atproto_circle";
const ALICE_DID: &str = "did:plc:alice-circle-owner";
const BOB_DID: &str = "did:plc:bob-circle-member";
const CHARLIE_DID: &str = "did:plc:charlie-circle-nonmember";
const MEDIA_BASE: &str = "https://media.catbird.blue";
const SPACE_1: &str = "at://did:plc:alice-circle-owner/space/blue.catbird.circle/3l7space1";
const SPACE_2: &str = "at://did:plc:alice-circle-owner/space/blue.catbird.circle/3l7space2";
#[allow(dead_code)]
struct ViewTestSetup {
    app: axum::Router,
    alice_key: p256::ecdsa::SigningKey,
    bob_key: p256::ecdsa::SigningKey,
    charlie_key: p256::ecdsa::SigningKey,
}

fn compute_record_cid(val: &serde_json::Value) -> String {
    let bytes = serde_ipld_dagcbor::to_vec(val).unwrap();
    let (_, cid_str) = create_cid_bytes_from_data(&bytes);
    cid_str
}
fn compute_blob_cid(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut cid_bytes = Vec::with_capacity(4 + 32);
    cid_bytes.push(0x01); // CIDv1
    cid_bytes.push(0x55); // raw binary multicodec
    cid_bytes.push(0x12); // sha2-256
    cid_bytes.push(0x20); // 32-byte digest
    cid_bytes.extend_from_slice(&digest);
    multibase::encode(multibase::Base::Base32Lower, &cid_bytes)
}

fn validate_fixture_record(
    uri: &str,
    author_did: &str,
    collection: &str,
    rkey: &str,
    value: &serde_json::Value,
    policy: &ValidationPolicy,
) {
    let candidate = RecordCandidate {
        uri: uri.to_string(),
        author_did: author_did.to_string(),
        collection: collection.to_string(),
        rkey: rkey.to_string(),
        value: value.clone(),
    };
    validate_record(&candidate, policy)
        .expect("view test fixture record must be valid according to semantic validator");
}

async fn grant_active_member(pool: &PgPool, space_uri: &str, member_did: &str, duration: Duration) {
    sqlx::query(
        r#"
        INSERT INTO circle_members (space_uri, member_did, status, updated_at)
        VALUES ($1, $2, 'active', now())
        ON CONFLICT (space_uri, member_did)
        DO UPDATE SET status = 'active', updated_at = now()
        "#,
    )
    .bind(space_uri)
    .bind(member_did)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO access_leases (space_uri, member_did, expires_at)
        VALUES ($1, $2, now() + $3)
        ON CONFLICT (space_uri, member_did)
        DO UPDATE SET expires_at = now() + $3
        "#,
    )
    .bind(space_uri)
    .bind(member_did)
    .bind(duration)
    .execute(pool)
    .await
    .unwrap();
}

async fn setup_views_test(pool: PgPool) -> ViewTestSetup {
    db::run_migrations(&pool)
        .await
        .expect("Migrations must succeed");

    let alice_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let bob_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let charlie_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse(MEDIA_BASE).unwrap(),
        nest_client_id: "https://nest.catbird.blue".into(),
        nest_jwks_url: "https://nest.catbird.blue/.well-known/jwks.json".into(),
        nest_verifying_keys: Vec::new(),
        nest_push_url: None,
        nest_push_audience: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circle"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
    };

    let state = AppState::new(config, pool.clone());

    // Register DID documents for Alice, Bob, Charlie in mock resolver
    register_did_doc(&state.did_resolver, ALICE_DID, &alice_key);
    register_did_doc(&state.did_resolver, BOB_DID, &bob_key);
    register_did_doc(&state.did_resolver, CHARLIE_DID, &charlie_key);

    // Seed mock profile cache in hydrator
    state
        .profile_hydrator
        .set_cached_profile(
            ALICE_DID,
            ProfileViewBasic {
                did: Did::new(SmolStr::new(ALICE_DID)).unwrap(),
                handle: Handle::new(SmolStr::new("alice.test")).unwrap(),
                display_name: Some(SmolStr::new("Alice Owner")),
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
            },
        )
        .await;

    state
        .profile_hydrator
        .set_cached_profile(
            BOB_DID,
            ProfileViewBasic {
                did: Did::new(SmolStr::new(BOB_DID)).unwrap(),
                handle: Handle::new(SmolStr::new("bob.test")).unwrap(),
                display_name: Some(SmolStr::new("Bob Member")),
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
            },
        )
        .await;

    state
        .profile_hydrator
        .set_cached_profile(
            CHARLIE_DID,
            ProfileViewBasic {
                did: Did::new(SmolStr::new(CHARLIE_DID)).unwrap(),
                handle: Handle::new(SmolStr::new("charlie.test")).unwrap(),
                display_name: Some(SmolStr::new("Charlie Nonmember")),
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
            },
        )
        .await;

    let app = create_router(state.clone());

    ViewTestSetup {
        app,
        alice_key,
        bob_key,
        charlie_key,
    }
}

fn register_did_doc(
    resolver: &circle_appview::auth::DidResolver,
    did: &str,
    key: &p256::ecdsa::SigningKey,
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
        verification_method: vec![VerificationMethod {
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
        }],
        service: Vec::new(),
    };
    resolver.insert_cached(did.into(), did_doc);
}

fn mint_jwt(did: &str, lxm: &str, signing_key: &p256::ecdsa::SigningKey) -> String {
    let now = Utc::now().timestamp();
    let jti = uuid::Uuid::new_v4().to_string();

    let header = json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": format!("{did}#atproto"),
    });

    let claims = json!({
        "iss": did,
        "aud": CIRCLE_AUDIENCE,
        "lxm": lxm,
        "jti": jti,
        "iat": now,
        "exp": now + 60,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_excludes_spaces_without_active_lease(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    // 1. Create two spaces
    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())",
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 2', now())",
    )
    .bind(SPACE_2)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Grant Bob an active access lease in Space 1 ONLY
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    // 3. Insert post in Space 1 and post in Space 2 with valid canonical CIDs
    let post1_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7post1");
    let post2_uri = format!("{SPACE_2}/{ALICE_DID}/app.bsky.feed.post/3l7post2");

    let post1_json = json!({"$type": "app.bsky.feed.post", "text": "Post in Space 1", "createdAt": "2026-08-24T12:00:00.000Z"});
    let post2_json = json!({"$type": "app.bsky.feed.post", "text": "Post in Space 2", "createdAt": "2026-08-24T12:01:00.000Z"});

    let cid1 = compute_record_cid(&post1_json);
    let cid2 = compute_record_cid(&post2_json);

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7post1', $5, now(), now())
        "#,
    )
    .bind(&post1_uri)
    .bind(&cid1)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(&post1_json)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7post2', $5, now(), now())
        "#,
    )
    .bind(&post2_uri)
    .bind(&cid2)
    .bind(SPACE_2)
    .bind(ALICE_DID)
    .bind(&post2_json)
    .execute(&pool)
    .await
    .unwrap();

    // 4. Bob queries unified feed (space = None)
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri("/xrpc/blue.catbird.circle.getFeed")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let feed_output: GetFeedOutput = serde_json::from_slice(&body).unwrap();

    assert_eq!(feed_output.feed.len(), 1, "Unified feed must include only spaces with active lease");
    assert_eq!(feed_output.feed[0].circle.uri.as_str(), SPACE_1);
    assert_eq!(feed_output.feed[0].post.post.uri.as_str(), format!("at://{ALICE_DID}/app.bsky.feed.post/3l7post1"));
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_with_specific_space_requires_active_lease_and_returns_access_removed_when_lost(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    // Bob has NO active lease in Space 1
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let err_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["error"], "AccessRemoved");

    // Grant Bob active lease & active membership
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let token2 = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req2 = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();

    let resp2 = setup.app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_cursor_access_loss_returns_access_removed(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let post1_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7cursorpost1");
    let post2_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7cursorpost2");
    let post1_json = json!({"$type": "app.bsky.feed.post", "text": "Cursor post 1", "createdAt": "2026-08-24T12:00:00.000Z"});
    let post2_json = json!({"$type": "app.bsky.feed.post", "text": "Cursor post 2", "createdAt": "2026-08-24T12:01:00.000Z"});
    let cid1 = compute_record_cid(&post1_json);
    let cid2 = compute_record_cid(&post2_json);

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7cursorpost1', $5, now(), now() - interval '1 minute')
        "#,
    )
    .bind(&post1_uri)
    .bind(&cid1)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(&post1_json)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7cursorpost2', $5, now(), now())
        "#,
    )
    .bind(&post2_uri)
    .bind(&cid2)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(&post2_json)
    .execute(&pool)
    .await
    .unwrap();

    // Fetch page 1 -> get real cursor from response
    let token1 = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req1 = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}&limit=1"))
        .header(header::AUTHORIZATION, format!("Bearer {token1}"))
        .body(Body::empty())
        .unwrap();

    let resp1 = setup.app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = to_bytes(resp1.into_body(), 1024 * 1024).await.unwrap();
    let feed1: GetFeedOutput = serde_json::from_slice(&body1).unwrap();
    let real_cursor = feed1.cursor.expect("Page 1 must return a cursor");

    // Now revoke Bob's lease/access to Space 1 before page 2
    sqlx::query("DELETE FROM access_leases WHERE space_uri = $1 AND member_did = $2")
        .bind(SPACE_1)
        .bind(BOB_DID)
        .execute(&pool)
        .await
        .unwrap();

    // Bob attempts to fetch next page using the real cursor from page 1
    let cursor = real_cursor.as_str();
    let token2 = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req2 = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?cursor={cursor}"))
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();

    let resp2 = setup.app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);

    let body2 = to_bytes(resp2.into_body(), 1024 * 1024).await.unwrap();
    let err_json: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    assert_eq!(err_json["error"], "AccessRemoved");
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_stable_opaque_cursor_pagination(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let base_time = Utc::now() - Duration::hours(5);

    // Insert 5 posts
    for i in 1..=5 {
        let uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7post{i}");
        let indexed_at = base_time + Duration::minutes(i * 10);
        let post_json = json!({"$type": "app.bsky.feed.post", "text": format!("Post {i}"), "createdAt": indexed_at.to_rfc3339()});
        let cid = compute_record_cid(&post_json);
        sqlx::query(
            r#"
            INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
            VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', $5, $6, $7, $7)
            "#,
        )
        .bind(&uri)
        .bind(&cid)
        .bind(SPACE_1)
        .bind(ALICE_DID)
        .bind(format!("3l7post{i}"))
        .bind(&post_json)
        .bind(indexed_at)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Page 1: limit = 2
    let token1 = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req1 = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}&limit=2"))
        .header(header::AUTHORIZATION, format!("Bearer {token1}"))
        .body(Body::empty())
        .unwrap();

    let resp1 = setup.app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = to_bytes(resp1.into_body(), 1024 * 1024).await.unwrap();
    let page1: GetFeedOutput = serde_json::from_slice(&body1).unwrap();
    assert_eq!(page1.feed.len(), 2);
    assert_eq!(page1.feed[0].post.post.uri.as_str(), format!("at://{ALICE_DID}/app.bsky.feed.post/3l7post5"));
    assert_eq!(page1.feed[1].post.post.uri.as_str(), format!("at://{ALICE_DID}/app.bsky.feed.post/3l7post4"));
    assert!(page1.cursor.is_some());

    let cursor1 = page1.cursor.unwrap();

    // Page 2: limit = 2 with fresh token
    let token2 = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req2 = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}&limit=2&cursor={cursor1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();

    let resp2 = setup.app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = to_bytes(resp2.into_body(), 1024 * 1024).await.unwrap();
    let page2: GetFeedOutput = serde_json::from_slice(&body2).unwrap();
    assert_eq!(page2.feed.len(), 2);
    assert_eq!(page2.feed[0].post.post.uri.as_str(), format!("at://{ALICE_DID}/app.bsky.feed.post/3l7post3"));
    assert_eq!(page2.feed[1].post.post.uri.as_str(), format!("at://{ALICE_DID}/app.bsky.feed.post/3l7post2"));
    assert!(page2.cursor.is_some());

    let cursor2 = page2.cursor.unwrap();

    // Page 3: limit = 2 -> remaining 1 item with fresh token
    let token3 = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req3 = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}&limit=2&cursor={cursor2}"))
        .header(header::AUTHORIZATION, format!("Bearer {token3}"))
        .body(Body::empty())
        .unwrap();

    let resp3 = setup.app.clone().oneshot(req3).await.unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);
    let body3 = to_bytes(resp3.into_body(), 1024 * 1024).await.unwrap();
    let page3: GetFeedOutput = serde_json::from_slice(&body3).unwrap();
    assert_eq!(page3.feed.len(), 1);
    assert_eq!(page3.feed[0].post.post.uri.as_str(), format!("at://{ALICE_DID}/app.bsky.feed.post/3l7post1"));
    assert!(page3.cursor.is_none(), "Last page must have no next cursor");
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_invalid_cursor_returns_invalid_request(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}&cursor=not-a-valid-base64-json-cursor"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let err_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["error"], "InvalidRequest");
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_excludes_muted_circles_in_unified_feed_but_includes_in_specific_space(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Muted Space', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    // Bob mutes Space 1
    sqlx::query("INSERT INTO circle_preferences (space_uri, member_did, muted, updated_at) VALUES ($1, $2, true, now())")
        .bind(SPACE_1)
        .bind(BOB_DID)
        .execute(&pool)
        .await
        .unwrap();

    let post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7mutedpost");
    let post_json = json!({"$type": "app.bsky.feed.post", "text": "Post in muted space", "createdAt": "2026-08-24T12:00:00.000Z"});
    let cid = compute_record_cid(&post_json);

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7mutedpost', $5, now(), now())
        "#,
    )
    .bind(&post_uri)
    .bind(&cid)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(&post_json)
    .execute(&pool)
    .await
    .unwrap();

    // 1. Unified feed (space = None) -> excludes muted Space 1
    let token_unified = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req_unified = Request::builder()
        .method("GET")
        .uri("/xrpc/blue.catbird.circle.getFeed")
        .header(header::AUTHORIZATION, format!("Bearer {token_unified}"))
        .body(Body::empty())
        .unwrap();

    let resp_unified = setup.app.clone().oneshot(req_unified).await.unwrap();
    assert_eq!(resp_unified.status(), StatusCode::OK);
    let body_unified = to_bytes(resp_unified.into_body(), 1024 * 1024).await.unwrap();
    let feed_unified: GetFeedOutput = serde_json::from_slice(&body_unified).unwrap();
    assert_eq!(feed_unified.feed.len(), 0, "Unified feed must exclude muted circles");

    // 2. Circle-detail feed (space = SPACE_1) -> includes explicitly requested muted Space 1 with fresh token
    let token_specific = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req_specific = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token_specific}"))
        .body(Body::empty())
        .unwrap();

    let resp_specific = setup.app.clone().oneshot(req_specific).await.unwrap();
    assert_eq!(resp_specific.status(), StatusCode::OK);
    let body_specific = to_bytes(resp_specific.into_body(), 1024 * 1024).await.unwrap();
    let feed_specific: GetFeedOutput = serde_json::from_slice(&body_specific).unwrap();
    assert_eq!(feed_specific.feed.len(), 1, "Direct Circle feed must remain accessible when muted");
    assert_eq!(feed_specific.feed[0].circle.muted, Some(true));
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_excludes_removed_members_even_with_stale_lease(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    // Member status is 'removed', but stale access_leases row exists
    sqlx::query("INSERT INTO circle_members (space_uri, member_did, status, updated_at) VALUES ($1, $2, 'removed', now())")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();

    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let err_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["error"], "AccessRemoved");
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_returns_top_level_posts_only_and_omits_replies(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7root");
    let reply_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7reply");

    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Root post", "createdAt": "2026-08-24T12:00:00.000Z"});
    let root_cid = compute_record_cid(&root_json);
    let reply_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Reply post",
        "createdAt": "2026-08-24T12:01:00.000Z",
        "reply": {
            "root": {"uri": &root_uri, "cid": &root_cid},
            "parent": {"uri": &root_uri, "cid": &root_cid}
        }
    });
    let reply_cid = compute_record_cid(&reply_json);

    let mut val_policy = policy(ALICE_DID, vec![BOB_DID]).with_space_uri(SPACE_1);
    val_policy.add_post(&root_uri, &root_cid);
    validate_fixture_record(&root_uri, ALICE_DID, "app.bsky.feed.post", "3l7root", &root_json, &val_policy);
    validate_fixture_record(&reply_uri, BOB_DID, "app.bsky.feed.post", "3l7reply", &reply_json, &val_policy);

    // Root post (parent_uri IS NULL)
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7root', $5, now(), now())
        "#,
    )
    .bind(&root_uri).bind(&root_cid).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    // Reply post (parent_uri IS NOT NULL)
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7reply', $5, now(), now(), $6, $6)
        "#,
    )
    .bind(&reply_uri).bind(&reply_cid).bind(SPACE_1).bind(BOB_DID).bind(&reply_json).bind(&root_uri).execute(&pool).await.unwrap();

    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let feed: GetFeedOutput = serde_json::from_slice(&body).unwrap();

    assert_eq!(feed.feed.len(), 1, "Feed must contain only top-level posts");
    assert_eq!(feed.feed[0].post.post.uri.as_str(), format!("at://{ALICE_DID}/app.bsky.feed.post/3l7root"));
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_and_thread_space_local_counts_and_viewer_likes_isolate_cross_space_interactions(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 2', now())")
        .bind(SPACE_2).bind(ALICE_DID).execute(&pool).await.unwrap();

    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_2, BOB_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7root");
    let same_space_reply_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7reply1");
    let cross_space_reply_uri = format!("{SPACE_2}/{BOB_DID}/app.bsky.feed.post/3l7reply2");

    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Root", "createdAt": "2026-08-24T12:00:00.000Z"});
    let root_cid = compute_record_cid(&root_json);

    let same_reply_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Same space reply",
        "createdAt": "2026-08-24T12:01:00.000Z",
        "reply": {"root": {"uri": root_uri, "cid": &root_cid}, "parent": {"uri": root_uri, "cid": &root_cid}}
    });
    let cross_reply_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Cross space reply",
        "createdAt": "2026-08-24T12:02:00.000Z",
        "reply": {"root": {"uri": root_uri, "cid": &root_cid}, "parent": {"uri": root_uri, "cid": &root_cid}}
    });

    let same_reply_cid = compute_record_cid(&same_reply_json);
    let cross_reply_cid = compute_record_cid(&cross_reply_json);
    // Root in Space 1
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7root', $5, now(), now())
        "#,
    )
    .bind(&root_uri).bind(&root_cid).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    // Reply 1 in Space 1
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7reply1', $5, now(), now(), $6, $6)
        "#,
    )
    .bind(&same_space_reply_uri).bind(&same_reply_cid).bind(SPACE_1).bind(BOB_DID).bind(&same_reply_json).bind(&root_uri).execute(&pool).await.unwrap();

    // Reply 2 injected into Space 2 pointing to Space 1 root
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7reply2', $5, now(), now(), $6, $6)
        "#,
    )
    .bind(&cross_space_reply_uri).bind(&cross_reply_cid).bind(SPACE_2).bind(BOB_DID).bind(&cross_reply_json).bind(&root_uri).execute(&pool).await.unwrap();

    // Like 1 in Space 1
    let like1_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.like/3l7like1");
    let like1_json = json!({"$type": "app.bsky.feed.like", "subject": {"uri": root_uri, "cid": root_cid}, "createdAt": "2026-08-24T12:05:00.000Z"});
    let like1_cid = compute_record_cid(&like1_json);
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.like', '3l7like1', $5, now(), now())")
        .bind(&like1_uri).bind(&like1_cid).bind(SPACE_1).bind(BOB_DID).bind(&like1_json).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at) VALUES ($1, $2, $3, $4, now())")
        .bind(&like1_uri).bind(SPACE_1).bind(&root_uri).bind(BOB_DID).execute(&pool).await.unwrap();

    // Like 2 in Space 2 (cross-space like)
    let like2_uri = format!("{SPACE_2}/{BOB_DID}/app.bsky.feed.like/3l7like2");
    let like2_json = json!({"$type": "app.bsky.feed.like", "subject": {"uri": root_uri, "cid": root_cid}, "createdAt": "2026-08-24T12:06:00.000Z"});
    let like2_cid = compute_record_cid(&like2_json);
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.like', '3l7like2', $5, now(), now())")
        .bind(&like2_uri).bind(&like2_cid).bind(SPACE_2).bind(BOB_DID).bind(&like2_json).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at) VALUES ($1, $2, $3, $4, now())")
        .bind(&like2_uri).bind(SPACE_2).bind(&root_uri).bind(BOB_DID).execute(&pool).await.unwrap();

    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let feed: GetFeedOutput = serde_json::from_slice(&body).unwrap();

    let post = &feed.feed[0].post.post;
    assert_eq!(post.reply_count, Some(1), "Reply count must isolate to Space 1 (cross-space reply excluded)");
    assert_eq!(post.like_count, Some(1), "Like count must isolate to Space 1 (cross-space like excluded)");
    assert!(post.viewer.as_ref().and_then(|v| v.like.as_ref()).is_some());

    // Also assert thread counts & traversal with standard at:// URI
    let root_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/3l7root");
    let thread_token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let thread_req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {thread_token}"))
        .body(Body::empty())
        .unwrap();

    let thread_resp = setup.app.clone().oneshot(thread_req).await.unwrap();
    assert_eq!(thread_resp.status(), StatusCode::OK);
    let thread_body = to_bytes(thread_resp.into_body(), 1024 * 1024).await.unwrap();
    let thread: GetPostThreadOutput = serde_json::from_slice(&thread_body).unwrap();

    assert_eq!(thread.thread.post.reply_count, Some(1));
    assert_eq!(thread.thread.post.like_count, Some(1));
    assert_eq!(thread.thread.replies.as_ref().map(|r| r.len()), Some(1));
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_view_post_embed_images_view_construction_preserves_aspect_ratio_and_absolute_media_url(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7imagepost");

    let blob_bytes = b"jpeg test image payload 12345";
    let blob_cid = compute_blob_cid(blob_bytes);

    let post_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post with image and aspect ratio",
        "createdAt": "2026-08-24T12:00:00.000Z",
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [{
                "alt": "Test image alt",
                "aspectRatio": {
                    "width": 1200,
                    "height": 800
                },
                "image": {
                    "$type": "blob",
                    "ref": { "$link": &blob_cid },
                    "mimeType": "image/jpeg",
                    "size": blob_bytes.len()
                }
            }]
        }
    });
    let cid = compute_record_cid(&post_json);
    let val_policy = policy(ALICE_DID, vec![BOB_DID]).with_space_uri(SPACE_1);
    validate_fixture_record(&post_uri, ALICE_DID, "app.bsky.feed.post", "3l7imagepost", &post_json, &val_policy);

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7imagepost', $5, now(), now())
        "#,
    )
    .bind(&post_uri)
    .bind(&cid)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(&post_json)
    .execute(&pool)
    .await
    .unwrap();

    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let feed: GetFeedOutput = serde_json::from_slice(&body).unwrap();

    let post = &feed.feed[0].post.post;
    match &post.embed {
        Some(PostViewEmbed::ImagesView(images_view)) => {
            assert_eq!(images_view.images.len(), 1);
            assert_eq!(images_view.images[0].alt.as_str(), "Test image alt");
            assert!(images_view.images[0].fullsize.as_str().starts_with("https://media.catbird.blue/xrpc/blue.catbird.circle.getMedia"));
            assert!(images_view.images[0].fullsize.as_str().contains(&blob_cid));
            assert!(images_view.images[0].thumb.as_str().starts_with("https://media.catbird.blue/xrpc/blue.catbird.circle.getMedia"));

            let ar = images_view.images[0].aspect_ratio.as_ref().expect("Aspect ratio must be preserved");
            assert_eq!(ar.width, 1200);
            assert_eq!(ar.height, 800);
        }
        other => panic!("Expected PostViewEmbed::ImagesView, got {:?}", other),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_never_traverses_public_or_other_space_records(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 2', now())")
        .bind(SPACE_2).bind(ALICE_DID).execute(&pool).await.unwrap();

    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_2, BOB_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7root");
    let same_reply_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7same");
    let other_reply_uri = format!("{SPACE_2}/{BOB_DID}/app.bsky.feed.post/3l7other");

    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Root", "createdAt": "2026-08-24T12:00:00.000Z"});
    let root_cid = compute_record_cid(&root_json);
    let same_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Same",
        "createdAt": "2026-08-24T12:01:00.000Z",
        "reply": {"root": {"uri": root_uri, "cid": &root_cid}, "parent": {"uri": root_uri, "cid": &root_cid}}
    });
    let other_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Other",
        "createdAt": "2026-08-24T12:02:00.000Z",
        "reply": {"root": {"uri": root_uri, "cid": &root_cid}, "parent": {"uri": root_uri, "cid": &root_cid}}
    });
    let same_cid = compute_record_cid(&same_json);
    let other_cid = compute_record_cid(&other_json);

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7root', $5, now(), now())")
        .bind(&root_uri).bind(&root_cid).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7same', $5, now(), now(), $6, $6)")
        .bind(&same_reply_uri).bind(&same_cid).bind(SPACE_1).bind(BOB_DID).bind(&same_json).bind(&root_uri).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7other', $5, now(), now(), $6, $6)")
        .bind(&other_reply_uri).bind(&other_cid).bind(SPACE_2).bind(BOB_DID).bind(&other_json).bind(&root_uri).execute(&pool).await.unwrap();
    let root_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/3l7root");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let thread: GetPostThreadOutput = serde_json::from_slice(&body).unwrap();

    let replies = thread.thread.replies.expect("Replies must exist");
    assert_eq!(replies.len(), 1, "Only same-space reply must be returned");
    match &replies[0] {
        ThreadViewPostRepliesItem::ThreadViewPost(tvp) => {
            assert_eq!(tvp.post.uri.as_str(), format!("at://{BOB_DID}/app.bsky.feed.post/3l7same"));
        }
        _ => panic!("Expected ThreadViewPost"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_multi_level_parent_order_and_not_found_boundary(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let post_a = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7postA");
    let post_b = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7postB");
    let post_c = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7postC");

    let json_a = json!({"$type": "app.bsky.feed.post", "text": "Post A", "createdAt": "2026-08-24T12:00:00.000Z"});
    let cid_a = compute_record_cid(&json_a);
    let json_b = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post B",
        "createdAt": "2026-08-24T12:01:00.000Z",
        "reply": {"root": {"uri": post_a, "cid": &cid_a}, "parent": {"uri": post_a, "cid": &cid_a}}
    });
    let cid_b = compute_record_cid(&json_b);
    let json_c = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post C",
        "createdAt": "2026-08-24T12:02:00.000Z",
        "reply": {"root": {"uri": post_a, "cid": &cid_a}, "parent": {"uri": post_b, "cid": &cid_b}}
    });
    let cid_c = compute_record_cid(&json_c);

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7postA', $5, now(), now())")
        .bind(&post_a).bind(&cid_a).bind(SPACE_1).bind(ALICE_DID).bind(&json_a).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7postB', $5, now(), now(), $6, $7)")
        .bind(&post_b).bind(&cid_b).bind(SPACE_1).bind(BOB_DID).bind(&json_b).bind(&post_a).bind(&post_a).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7postC', $5, now(), now(), $6, $7)")
        .bind(&post_c).bind(&cid_c).bind(SPACE_1).bind(BOB_DID).bind(&json_c).bind(&post_b).bind(&post_a).execute(&pool).await.unwrap();
    // Query thread targeting post C with standard at:// URI
    let post_c_std = format!("at://{BOB_DID}/app.bsky.feed.post/3l7postC");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={post_c_std}&space={SPACE_1}&parentHeight=10"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let thread: GetPostThreadOutput = serde_json::from_slice(&body).unwrap();

    assert_eq!(thread.thread.post.uri.as_str(), format!("at://{BOB_DID}/app.bsky.feed.post/3l7postC"));

    // Target post C's immediate parent must be B
    let parent_b = match thread.thread.parent {
        Some(ThreadViewPostParent::ThreadViewPost(b)) => b,
        other => panic!("Expected ThreadViewPost for immediate parent B, got {:?}", other),
    };
    assert_eq!(parent_b.post.uri.as_str(), format!("at://{BOB_DID}/app.bsky.feed.post/3l7postB"));

    // B's parent must be A
    let parent_a = match parent_b.parent {
        Some(ThreadViewPostParent::ThreadViewPost(a)) => a,
        other => panic!("Expected ThreadViewPost for root parent A, got {:?}", other),
    };
    assert_eq!(parent_a.post.uri.as_str(), format!("at://{ALICE_DID}/app.bsky.feed.post/3l7postA"));
    assert!(parent_a.parent.is_none(), "Root post A must have no parent");
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_excludes_replies_whose_root_or_parent_is_deleted(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7root");
    let p1_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7p1");
    let p2_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7p2");

    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Root", "createdAt": "2026-08-24T12:00:00.000Z"});
    let root_cid = compute_record_cid(&root_json);
    let p1_json = json!({"$type": "app.bsky.feed.post", "text": "P1 deleted", "createdAt": "2026-08-24T12:01:00.000Z", "reply": {"root": {"uri": root_uri, "cid": &root_cid}, "parent": {"uri": root_uri, "cid": &root_cid}}});
    let p1_cid = compute_record_cid(&p1_json);
    let p2_json = json!({"$type": "app.bsky.feed.post", "text": "P2 child of deleted", "createdAt": "2026-08-24T12:02:00.000Z", "reply": {"root": {"uri": root_uri, "cid": &root_cid}, "parent": {"uri": p1_uri, "cid": &p1_cid}}});
    let p2_cid = compute_record_cid(&p2_json);

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7root', $5, now(), now())")
        .bind(&root_uri).bind(&root_cid).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    // P1 is soft-deleted
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri, deleted_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7p1', $5, now(), now(), $6, $6, now())")
        .bind(&p1_uri).bind(&p1_cid).bind(SPACE_1).bind(BOB_DID).bind(&p1_json).bind(&root_uri).execute(&pool).await.unwrap();

    // P2 is active child of P1
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7p2', $5, now(), now(), $6, $7)")
        .bind(&p2_uri).bind(&p2_cid).bind(SPACE_1).bind(BOB_DID).bind(&p2_json).bind(&p1_uri).bind(&root_uri).execute(&pool).await.unwrap();
    let root_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/3l7root");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let thread: GetPostThreadOutput = serde_json::from_slice(&body).unwrap();

    assert!(thread.thread.replies.is_none(), "Deleted reply tree must not be traversed");
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_not_found_when_root_post_deleted_or_missing(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let missing_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/3l7missing");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={missing_std_uri}&space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_caps_traversal_at_node_budget_and_prevents_unbounded_expansion(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7budgetroot");
    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Root", "createdAt": "2026-08-24T12:00:00.000Z"});
    let root_cid = compute_record_cid(&root_json);
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7budgetroot', $5, now(), now())")
        .bind(&root_uri).bind(&root_cid).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    // Insert 550 replies (exceeding the 500 node budget)
    for i in 1..=550 {
        let r_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7reply{i}");
        let r_json = json!({"$type": "app.bsky.feed.post", "text": format!("Reply {i}"), "createdAt": "2026-08-24T12:01:00.000Z", "reply": {"root": {"uri": root_uri, "cid": &root_cid}, "parent": {"uri": root_uri, "cid": &root_cid}}});
        let r_cid = compute_record_cid(&r_json);
        sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', $5, $6, now(), now(), $7, $7)")
            .bind(&r_uri).bind(&r_cid).bind(SPACE_1).bind(BOB_DID).bind(format!("3l7reply{i}")).bind(&r_json).bind(&root_uri).execute(&pool).await.unwrap();
    }

    let root_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/3l7budgetroot");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}&depth=10"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let thread: GetPostThreadOutput = serde_json::from_slice(&body).unwrap();

    let replies = thread.thread.replies.expect("Replies must exist");
    assert_eq!(replies.len(), 499, "Replies must be capped to budget (500 total nodes including root)");
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_authorization_race_during_hydration_returns_access_removed(pool: PgPool) {
    db::run_migrations(&pool).await.expect("Migrations must succeed");

    let (in_flight_tx, mut in_flight_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (resume_tx, resume_rx) = tokio::sync::mpsc::channel::<()>(1);
    let in_flight_tx = Arc::new(in_flight_tx);
    let resume_rx = Arc::new(tokio::sync::Mutex::new(resume_rx));

    let mock_app = Router::new().route(
        "/xrpc/app.bsky.actor.getProfile",
        get(move |req: Request<Body>| {
            let in_flight = in_flight_tx.clone();
            let resume = resume_rx.clone();
            async move {
                let query = req.uri().query().unwrap_or("");
                let actor = query.strip_prefix("actor=").unwrap_or("");
                if actor == "did:plc:alice-race-author" {
                    // Signal that hydration is in flight
                    let _ = in_flight.send(()).await;
                    // Wait for test to revoke lease/generation before resuming
                    let mut rx = resume.lock().await;
                    let _ = rx.recv().await;
                }
                let output = GetProfileOutput {
                    value: ProfileViewDetailed {
                        did: Did::new(SmolStr::new(actor)).unwrap(),
                        handle: Handle::new(SmolStr::new("race.author")).unwrap(),
                        display_name: Some(SmolStr::new("Race Author")),
                        avatar: None,
                        associated: None,
                        banner: None,
                        created_at: None,
                        debug: None,
                        description: None,
                        followers_count: None,
                        follows_count: None,
                        indexed_at: None,
                        joined_via_starter_pack: None,
                        labels: None,
                        pinned_post: None,
                        posts_count: None,
                        pronouns: None,
                        status: None,
                        verification: None,
                        viewer: None,
                        website: None,
                        extra_data: None,
                    },
                    extra_data: None,
                };
                Json(output).into_response()
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_app).await.unwrap();
    });

    let bob_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let race_author_did = "did:plc:alice-race-author";

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
        public_appview_url: format!("http://{addr}"),
        circle_media_base_url: url::Url::parse(MEDIA_BASE).unwrap(),
        nest_client_id: "https://nest.catbird.blue".into(),
        nest_jwks_url: "https://nest.catbird.blue/.well-known/jwks.json".into(),
        nest_verifying_keys: Vec::new(),
        nest_push_url: None,
        nest_push_audience: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circle"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
    };

    let hydrator = Arc::new(ProfileHydrator::new(format!("http://{addr}"), reqwest::Client::new()));
    let did_resolver = Arc::new(circle_appview::auth::DidResolver::new("https://plc.directory".into(), reqwest::Client::new()));
    register_did_doc(&did_resolver, BOB_DID, &bob_key);

    let state = AppState::with_profile_hydrator(config, pool.clone(), did_resolver, hydrator);
    let app = circle_appview::routes::create_router(state);

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Space 1', now(), 1)")
        .bind(SPACE_1).bind(race_author_did).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{race_author_did}/app.bsky.feed.post/3l7racepost");
    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Race post", "createdAt": "2026-08-24T12:00:00.000Z"});
    let root_cid = compute_record_cid(&root_json);
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7racepost', $5, now(), now())")
        .bind(&root_uri).bind(&root_cid).bind(SPACE_1).bind(race_author_did).bind(&root_json).execute(&pool).await.unwrap();

    let root_std_uri = format!("at://{race_author_did}/app.bsky.feed.post/3l7racepost");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let pool_clone = pool.clone();
    let request_handle = tokio::spawn(async move {
        app.oneshot(req).await.unwrap()
    });

    // Wait until profile hydration starts
    in_flight_rx.recv().await.expect("Hydration must start");

    // While hydration is in-flight, revoke Bob's lease
    sqlx::query("UPDATE access_leases SET expires_at = now() - interval '1 second' WHERE space_uri = $1 AND member_did = $2")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool_clone).await.unwrap();

    // Resume hydration
    resume_tx.send(()).await.unwrap();

    let resp = request_handle.await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let err_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["error"], "AccessRemoved");
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_authorization_race_during_hydration_returns_access_removed(pool: PgPool) {
    db::run_migrations(&pool).await.expect("Migrations must succeed");

    let (in_flight_tx, mut in_flight_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (resume_tx, resume_rx) = tokio::sync::mpsc::channel::<()>(1);
    let in_flight_tx = Arc::new(in_flight_tx);
    let resume_rx = Arc::new(tokio::sync::Mutex::new(resume_rx));

    let mock_app = Router::new().route(
        "/xrpc/app.bsky.actor.getProfile",
        get(move |req: Request<Body>| {
            let in_flight = in_flight_tx.clone();
            let resume = resume_rx.clone();
            async move {
                let query = req.uri().query().unwrap_or("");
                let actor = query.strip_prefix("actor=").unwrap_or("");
                if actor == "did:plc:alice-feed-race-author" {
                    let _ = in_flight.send(()).await;
                    let mut rx = resume.lock().await;
                    let _ = rx.recv().await;
                }
                let output = GetProfileOutput {
                    value: ProfileViewDetailed {
                        did: Did::new(SmolStr::new(actor)).unwrap(),
                        handle: Handle::new(SmolStr::new("feedrace.author")).unwrap(),
                        display_name: Some(SmolStr::new("Feed Race Author")),
                        avatar: None,
                        associated: None,
                        banner: None,
                        created_at: None,
                        debug: None,
                        description: None,
                        followers_count: None,
                        follows_count: None,
                        indexed_at: None,
                        joined_via_starter_pack: None,
                        labels: None,
                        pinned_post: None,
                        posts_count: None,
                        pronouns: None,
                        status: None,
                        verification: None,
                        viewer: None,
                        website: None,
                        extra_data: None,
                    },
                    extra_data: None,
                };
                Json(output).into_response()
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_app).await.unwrap();
    });

    let bob_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let race_author_did = "did:plc:alice-feed-race-author";

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
        public_appview_url: format!("http://{addr}"),
        circle_media_base_url: url::Url::parse(MEDIA_BASE).unwrap(),
        nest_client_id: "https://nest.catbird.blue".into(),
        nest_jwks_url: "https://nest.catbird.blue/.well-known/jwks.json".into(),
        nest_verifying_keys: Vec::new(),
        nest_push_url: None,
        nest_push_audience: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circle"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
    };

    let hydrator = Arc::new(ProfileHydrator::new(format!("http://{addr}"), reqwest::Client::new()));
    let did_resolver = Arc::new(circle_appview::auth::DidResolver::new("https://plc.directory".into(), reqwest::Client::new()));
    register_did_doc(&did_resolver, BOB_DID, &bob_key);

    let state = AppState::with_profile_hydrator(config, pool.clone(), did_resolver, hydrator);
    let app = circle_appview::routes::create_router(state);

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Space 1', now(), 1)")
        .bind(SPACE_1).bind(race_author_did).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{race_author_did}/app.bsky.feed.post/3l7feedrace");
    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Feed Race post", "createdAt": "2026-08-24T12:00:00.000Z"});
    let root_cid = compute_record_cid(&root_json);
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7feedrace', $5, now(), now())")
        .bind(&root_uri).bind(&root_cid).bind(SPACE_1).bind(race_author_did).bind(&root_json).execute(&pool).await.unwrap();

    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let pool_clone = pool.clone();
    let request_handle = tokio::spawn(async move {
        app.oneshot(req).await.unwrap()
    });

    // Wait until profile hydration starts
    in_flight_rx.recv().await.expect("Hydration must start");

    // While hydration is in-flight, revoke Bob's lease
    sqlx::query("UPDATE access_leases SET expires_at = now() - interval '1 second' WHERE space_uri = $1 AND member_did = $2")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool_clone).await.unwrap();

    // Resume hydration
    resume_tx.send(()).await.unwrap();

    let resp = request_handle.await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let err_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["error"], "AccessRemoved");
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_circle_epoch_generation_change_during_hydration_returns_access_removed(pool: PgPool) {
    db::run_migrations(&pool).await.expect("Migrations must succeed");

    let (in_flight_tx, mut in_flight_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (resume_tx, resume_rx) = tokio::sync::mpsc::channel::<()>(1);
    let in_flight_tx = Arc::new(in_flight_tx);
    let resume_rx = Arc::new(tokio::sync::Mutex::new(resume_rx));

    let mock_app = Router::new().route(
        "/xrpc/app.bsky.actor.getProfile",
        get(move |req: Request<Body>| {
            let in_flight = in_flight_tx.clone();
            let resume = resume_rx.clone();
            async move {
                let query = req.uri().query().unwrap_or("");
                let actor = query.strip_prefix("actor=").unwrap_or("");
                if actor == "did:plc:alice-epoch-author" {
                    let _ = in_flight.send(()).await;
                    let mut rx = resume.lock().await;
                    let _ = rx.recv().await;
                }
                let output = GetProfileOutput {
                    value: ProfileViewDetailed {
                        did: Did::new(SmolStr::new(actor)).unwrap(),
                        handle: Handle::new(SmolStr::new("epoch.author")).unwrap(),
                        display_name: Some(SmolStr::new("Epoch Author")),
                        avatar: None,
                        associated: None,
                        banner: None,
                        created_at: None,
                        debug: None,
                        description: None,
                        followers_count: None,
                        follows_count: None,
                        indexed_at: None,
                        joined_via_starter_pack: None,
                        labels: None,
                        pinned_post: None,
                        posts_count: None,
                        pronouns: None,
                        status: None,
                        verification: None,
                        viewer: None,
                        website: None,
                        extra_data: None,
                    },
                    extra_data: None,
                };
                Json(output).into_response()
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_app).await.unwrap();
    });

    let bob_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let epoch_author_did = "did:plc:alice-epoch-author";

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
        public_appview_url: format!("http://{addr}"),
        circle_media_base_url: url::Url::parse(MEDIA_BASE).unwrap(),
        nest_client_id: "https://nest.catbird.blue".into(),
        nest_jwks_url: "https://nest.catbird.blue/.well-known/jwks.json".into(),
        nest_verifying_keys: Vec::new(),
        nest_push_url: None,
        nest_push_audience: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circle"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
    };

    let hydrator = Arc::new(ProfileHydrator::new(format!("http://{addr}"), reqwest::Client::new()));
    let did_resolver = Arc::new(circle_appview::auth::DidResolver::new("https://plc.directory".into(), reqwest::Client::new()));
    register_did_doc(&did_resolver, BOB_DID, &bob_key);

    let state = AppState::with_profile_hydrator(config, pool.clone(), did_resolver, hydrator);
    let app = circle_appview::routes::create_router(state);

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Space 1', now(), 1)")
        .bind(SPACE_1).bind(epoch_author_did).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{epoch_author_did}/app.bsky.feed.post/3l7epochpost");
    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Epoch post", "createdAt": "2026-08-24T12:00:00.000Z"});
    let root_cid = compute_record_cid(&root_json);
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7epochpost', $5, now(), now())")
        .bind(&root_uri).bind(&root_cid).bind(SPACE_1).bind(epoch_author_did).bind(&root_json).execute(&pool).await.unwrap();

    let root_std_uri = format!("at://{epoch_author_did}/app.bsky.feed.post/3l7epochpost");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let pool_clone = pool.clone();
    let request_handle = tokio::spawn(async move {
        app.oneshot(req).await.unwrap()
    });

    // Wait until profile hydration starts
    in_flight_rx.recv().await.expect("Hydration must start");

    // While hydration is in-flight, change the Circle generation (delete/recreate ABA)
    sqlx::query("UPDATE circles SET generation = 2 WHERE space_uri = $1")
        .bind(SPACE_1).execute(&pool_clone).await.unwrap();

    // Resume hydration
    resume_tx.send(()).await.unwrap();

    let resp = request_handle.await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let err_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["error"], "AccessRemoved");
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_child_aggregates_isolate_parent_and_sibling_counts_and_viewer_likes(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Space 1', now(), 0)")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, CHARLIE_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7agroot");
    let reply1_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7agreply1");
    let reply2_uri = format!("{SPACE_1}/{CHARLIE_DID}/app.bsky.feed.post/3l7agreply2");

    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Root", "createdAt": "2026-08-24T12:00:00.000Z"});
    let root_cid = compute_record_cid(&root_json);

    let reply1_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Reply 1",
        "createdAt": "2026-08-24T12:01:00.000Z",
        "reply": {"root": {"uri": root_uri, "cid": &root_cid}, "parent": {"uri": root_uri, "cid": &root_cid}}
    });
    let reply1_cid = compute_record_cid(&reply1_json);

    let reply2_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Reply 2",
        "createdAt": "2026-08-24T12:02:00.000Z",
        "reply": {"root": {"uri": root_uri, "cid": &root_cid}, "parent": {"uri": reply1_uri, "cid": &reply1_cid}}
    });
    let reply2_cid = compute_record_cid(&reply2_json);

    // Insert Root
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7agroot', $5, now(), now())")
        .bind(&root_uri).bind(&root_cid).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    // Insert Reply 1
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7agreply1', $5, now(), now(), $6, $6)")
        .bind(&reply1_uri).bind(&reply1_cid).bind(SPACE_1).bind(BOB_DID).bind(&reply1_json).bind(&root_uri).execute(&pool).await.unwrap();

    // Insert Reply 2
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7agreply2', $5, now(), now(), $6, $7)")
        .bind(&reply2_uri).bind(&reply2_cid).bind(SPACE_1).bind(CHARLIE_DID).bind(&reply2_json).bind(&reply1_uri).bind(&root_uri).execute(&pool).await.unwrap();

    // Bob likes Root
    let like_bob_root_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.like/3l7likebobroot");
    let like_bob_root_json = json!({"$type": "app.bsky.feed.like", "subject": {"uri": root_uri, "cid": root_cid}, "createdAt": "2026-08-24T12:05:00.000Z"});
    let like_bob_root_cid = compute_record_cid(&like_bob_root_json);
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.like', '3l7likebobroot', $5, now(), now())")
        .bind(&like_bob_root_uri).bind(&like_bob_root_cid).bind(SPACE_1).bind(BOB_DID).bind(&like_bob_root_json).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at) VALUES ($1, $2, $3, $4, now())")
        .bind(&like_bob_root_uri).bind(SPACE_1).bind(&root_uri).bind(BOB_DID).execute(&pool).await.unwrap();

    // Bob likes Reply 1 (viewer Bob likes both parent and child!)
    let like_bob_rep1_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.like/3l7likebobrep1");
    let like_bob_rep1_json = json!({"$type": "app.bsky.feed.like", "subject": {"uri": reply1_uri, "cid": reply1_cid}, "createdAt": "2026-08-24T12:06:00.000Z"});
    let like_bob_rep1_cid = compute_record_cid(&like_bob_rep1_json);
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.like', '3l7likebobrep1', $5, now(), now())")
        .bind(&like_bob_rep1_uri).bind(&like_bob_rep1_cid).bind(SPACE_1).bind(BOB_DID).bind(&like_bob_rep1_json).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at) VALUES ($1, $2, $3, $4, now())")
        .bind(&like_bob_rep1_uri).bind(SPACE_1).bind(&reply1_uri).bind(BOB_DID).execute(&pool).await.unwrap();

    // Alice likes Reply 1
    let like_alice_rep1_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.like/3l7likealicerep1");
    let like_alice_rep1_json = json!({"$type": "app.bsky.feed.like", "subject": {"uri": reply1_uri, "cid": reply1_cid}, "createdAt": "2026-08-24T12:07:00.000Z"});
    let like_alice_rep1_cid = compute_record_cid(&like_alice_rep1_json);
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.like', '3l7likealicerep1', $5, now(), now())")
        .bind(&like_alice_rep1_uri).bind(&like_alice_rep1_cid).bind(SPACE_1).bind(ALICE_DID).bind(&like_alice_rep1_json).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at) VALUES ($1, $2, $3, $4, now())")
        .bind(&like_alice_rep1_uri).bind(SPACE_1).bind(&reply1_uri).bind(ALICE_DID).execute(&pool).await.unwrap();

    let root_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/3l7agroot");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}&depth=10"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let thread: GetPostThreadOutput = serde_json::from_slice(&body).unwrap();

    // Assert Root aggregates: 1 like (Bob), 1 reply (Reply 1)
    assert_eq!(thread.thread.post.like_count, Some(1));
    assert_eq!(thread.thread.post.reply_count, Some(1));
    assert!(thread.thread.post.viewer.as_ref().and_then(|v| v.like.as_ref()).is_some());

    // Assert Reply 1 aggregates: 2 likes (Bob, Alice), 1 reply (Reply 2)
    let replies = thread.thread.replies.expect("Replies must exist");
    assert_eq!(replies.len(), 1);
    let rep1_node = match &replies[0] {
        ThreadViewPostRepliesItem::ThreadViewPost(tvp) => tvp,
        _ => panic!("Expected ThreadViewPost"),
    };
    assert_eq!(rep1_node.post.like_count, Some(2), "Reply 1 must have exactly 2 likes (Bob + Alice, not Root's like)");
    assert_eq!(rep1_node.post.reply_count, Some(1), "Reply 1 must have exactly 1 child reply (Reply 2)");
    assert!(rep1_node.post.viewer.as_ref().and_then(|v| v.like.as_ref()).is_some(), "Viewer Bob liked Reply 1");

    // Assert Reply 2 aggregates: 0 likes, 0 replies
    let rep1_replies = rep1_node.replies.as_ref().expect("Reply 2 must exist");
    assert_eq!(rep1_replies.len(), 1);
    let rep2_node = match &rep1_replies[0] {
        ThreadViewPostRepliesItem::ThreadViewPost(tvp) => tvp,
        _ => panic!("Expected ThreadViewPost"),
    };
    assert_eq!(rep2_node.post.like_count, Some(0));
    assert_eq!(rep2_node.post.reply_count, Some(0));
    assert!(rep2_node.post.viewer.as_ref().and_then(|v| v.like.as_ref()).is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_orphan_reply_with_deleted_root_or_parent_returns_not_found(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation) VALUES ($1, $2, 'Space 1', now(), 0)")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7orphanroot");
    let reply_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7orphanreply");

    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Root deleted", "createdAt": "2026-08-24T12:00:00.000Z"});
    let root_cid = compute_record_cid(&root_json);
    let reply_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Orphan reply",
        "createdAt": "2026-08-24T12:01:00.000Z",
        "reply": {"root": {"uri": root_uri, "cid": &root_cid}, "parent": {"uri": root_uri, "cid": &root_cid}}
    });
    let reply_cid = compute_record_cid(&reply_json);

    // Root is soft-deleted
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, deleted_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7orphanroot', $5, now(), now(), now())")
        .bind(&root_uri).bind(&root_cid).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    // Reply is active row
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7orphanreply', $5, now(), now(), $6, $6)")
        .bind(&reply_uri).bind(&reply_cid).bind(SPACE_1).bind(BOB_DID).bind(&reply_json).bind(&root_uri).execute(&pool).await.unwrap();

    let reply_std_uri = format!("at://{BOB_DID}/app.bsky.feed.post/3l7orphanreply");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={reply_std_uri}&space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "Directly requesting orphan reply must return 404 NotFound");
}

#[tokio::test]
async fn profile_hydration_cached_for_five_minutes_and_fallback_unavailable_on_failure_with_controlled_mock() {
    let req_counter = Arc::new(AtomicUsize::new(0));
    let has_auth_header = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let counter_clone = req_counter.clone();
    let auth_clone = has_auth_header.clone();

    // Controlled local mock AppView HTTP server
    let mock_app = Router::new().route(
        "/xrpc/app.bsky.actor.getProfile",
        get(move |req: Request<Body>| {
            let counter = counter_clone.clone();
            let auth = auth_clone.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                if req.headers().contains_key(header::AUTHORIZATION) {
                    auth.store(true, Ordering::SeqCst);
                }

                let query = req.uri().query().unwrap_or("");
                let actor = query.strip_prefix("actor=").unwrap_or("");

                if actor == "did:plc:alice-mock" {
                    let output = GetProfileOutput {
                        value: ProfileViewDetailed {
                            did: Did::new(SmolStr::new("did:plc:alice-mock")).unwrap(),
                            handle: Handle::new(SmolStr::new("alice.mock")).unwrap(),
                            display_name: Some(SmolStr::new("Alice Mock")),
                            avatar: Some(UriValue::new(SmolStr::new("https://cdn.bsky.app/avatar.jpg")).unwrap()),
                            associated: Some(ProfileAssociated {
                                chat: None,
                                feedgens: None,
                                labeler: None,
                                lists: None,
                                starter_packs: None,
                                activity_subscription: None,
                                germ: None,
                                extra_data: None,
                            }),
                            banner: None,
                            created_at: Some(Datetime::new(Utc::now().into())),
                            debug: None,
                            description: None,
                            followers_count: None,
                            follows_count: None,
                            indexed_at: None,
                            joined_via_starter_pack: None,
                            labels: None,
                            pinned_post: None,
                            posts_count: None,
                            pronouns: Some(SmolStr::new("she/her")),
                            status: None,
                            verification: None,
                            viewer: None,
                            website: None,
                            extra_data: None,
                        },
                        extra_data: None,
                    };
                    Json(output).into_response()
                } else if actor == "did:plc:mismatched" {
                    let output = GetProfileOutput {
                        value: ProfileViewDetailed {
                            did: Did::new(SmolStr::new("did:plc:some-other-did")).unwrap(),
                            handle: Handle::new(SmolStr::new("other.mock")).unwrap(),
                            display_name: None,
                            avatar: None,
                            associated: None,
                            banner: None,
                            created_at: None,
                            debug: None,
                            description: None,
                            followers_count: None,
                            follows_count: None,
                            indexed_at: None,
                            joined_via_starter_pack: None,
                            labels: None,
                            pinned_post: None,
                            posts_count: None,
                            pronouns: None,
                            status: None,
                            verification: None,
                            viewer: None,
                            website: None,
                            extra_data: None,
                        },
                        extra_data: None,
                    };
                    Json(output).into_response()
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_app).await.unwrap();
    });

    let hydrator = ProfileHydrator::new(format!("http://{addr}"), reqwest::Client::new());

    // 1. First fetch for Alice -> hits mock server, maps all fields
    let profile1 = hydrator.get_profile("did:plc:alice-mock").await;
    assert_eq!(profile1.did.as_str(), "did:plc:alice-mock");
    assert_eq!(profile1.handle.as_str(), "alice.mock");
    assert_eq!(profile1.display_name.as_deref(), Some("Alice Mock"));
    assert_eq!(profile1.avatar.as_ref().unwrap().as_str(), "https://cdn.bsky.app/avatar.jpg");
    assert_eq!(profile1.pronouns.as_deref(), Some("she/her"));
    assert!(profile1.viewer.is_none(), "Unauthenticated viewer state must remain empty");
    assert_eq!(req_counter.load(Ordering::SeqCst), 1);
    assert!(!has_auth_header.load(Ordering::SeqCst), "Must not send private Authorization header");

    // 2. Second fetch for Alice -> cached (request count stays 1)
    let profile2 = hydrator.get_profile("did:plc:alice-mock").await;
    assert_eq!(profile2.did.as_str(), "did:plc:alice-mock");
    assert_eq!(req_counter.load(Ordering::SeqCst), 1, "Must be served from 5-minute cache");

    // 3. Batch fetch with concurrency -> Alice cached, Charlie fails (falls back), Mismatched fails (falls back)
    let batch = hydrator.get_profiles(&["did:plc:alice-mock", "did:plc:charlie-error", "did:plc:mismatched"]).await;
    assert_eq!(batch.len(), 3);
    assert_eq!(batch.get("did:plc:alice-mock").unwrap().handle.as_str(), "alice.mock");
    assert_eq!(batch.get("did:plc:charlie-error").unwrap().handle.as_str(), "handle.invalid");
    assert_eq!(batch.get("did:plc:charlie-error").unwrap().did.as_str(), "did:plc:charlie-error");
    assert_eq!(batch.get("did:plc:mismatched").unwrap().handle.as_str(), "handle.invalid");
    assert_eq!(batch.get("did:plc:mismatched").unwrap().did.as_str(), "did:plc:mismatched");

    // 4. Cache expiry after 5 minutes -> set cached_at to 305 seconds in the past and verify a new network fetch is made
    hydrator.set_cached_profile_with_time(
        "did:plc:alice-mock",
        ProfileViewBasic {
            did: Did::new(SmolStr::new("did:plc:alice-mock")).unwrap(),
            handle: Handle::new(SmolStr::new("alice.mock")).unwrap(),
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
        },
        std::time::Instant::now() - std::time::Duration::from_secs(305),
    ).await;

    let profile_after_expiry = hydrator.get_profile("did:plc:alice-mock").await;
    assert_eq!(profile_after_expiry.did.as_str(), "did:plc:alice-mock");
    assert_eq!(profile_after_expiry.display_name.as_deref(), Some("Alice Mock"));
    assert_eq!(req_counter.load(Ordering::SeqCst), 4, "Must re-fetch from server after 5-minute cache expiry");
}

#[tokio::test]
async fn profile_hydration_global_concurrency_ceiling_enforces_maximum_eight_parallel_requests() {
    let active_requests = Arc::new(AtomicUsize::new(0));
    let max_concurrent_seen = Arc::new(AtomicUsize::new(0));

    let active_clone = active_requests.clone();
    let max_clone = max_concurrent_seen.clone();

    let mock_app = Router::new().route(
        "/xrpc/app.bsky.actor.getProfile",
        get(move |req: Request<Body>| {
            let active = active_clone.clone();
            let max_seen = max_clone.clone();
            async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                // Record maximum concurrent active requests observed
                let mut prev = max_seen.load(Ordering::SeqCst);
                while current > prev {
                    match max_seen.compare_exchange_weak(prev, current, Ordering::SeqCst, Ordering::SeqCst) {
                        Ok(_) => break,
                        Err(actual) => prev = actual,
                    }
                }

                // Small delay to ensure concurrent requests overlap
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                active.fetch_sub(1, Ordering::SeqCst);

                let query = req.uri().query().unwrap_or("");
                let actor = query.strip_prefix("actor=").unwrap_or("");
                let output = GetProfileOutput {
                    value: ProfileViewDetailed {
                        did: Did::new(SmolStr::new(actor)).unwrap(),
                        handle: Handle::new(SmolStr::new("user.test")).unwrap(),
                        display_name: None,
                        avatar: None,
                        associated: None,
                        banner: None,
                        created_at: None,
                        debug: None,
                        description: None,
                        followers_count: None,
                        follows_count: None,
                        indexed_at: None,
                        joined_via_starter_pack: None,
                        labels: None,
                        pinned_post: None,
                        posts_count: None,
                        pronouns: None,
                        status: None,
                        verification: None,
                        viewer: None,
                        website: None,
                        extra_data: None,
                    },
                    extra_data: None,
                };
                Json(output).into_response()
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_app).await.unwrap();
    });

    let hydrator = Arc::new(ProfileHydrator::new(format!("http://{addr}"), reqwest::Client::new()));

    // Issue 20 parallel requests across multiple concurrent tasks sharing the same ProfileHydrator
    let mut handles = Vec::new();
    for i in 1..=20 {
        let h = hydrator.clone();
        let did = format!("did:plc:concurrency-test-{i}");
        handles.push(tokio::spawn(async move {
            h.get_profile(&did).await
        }));
    }

    for h in handles {
        let p = h.await.unwrap();
        assert!(p.did.as_str().starts_with("did:plc:concurrency-test-"));
    }

    let max_seen = max_concurrent_seen.load(Ordering::SeqCst);
    assert!(max_seen <= 8, "Global concurrency ceiling of 8 permits must never be exceeded (saw {max_seen})");
    assert!(max_seen > 1, "Must have processed requests concurrently");
}

#[test]
fn test_circle_media_base_url_strict_https_origin_validation() {
    let valid_cases = [
        "https://media.catbird.blue",
        "https://media.catbird.blue/",
        "https://media.catbird.blue:8443",
        "https://media.catbird.blue:8443/",
    ];
    for val in valid_cases {
        std::env::set_var("CIRCLE_MEDIA_BASE_URL", val);
        std::env::set_var("NEST_CLIENT_ID", "https://nest.catbird.blue");
        std::env::set_var("NEST_JWKS_URL", "https://nest.catbird.blue/.well-known/jwks.json");
        let cfg = Config::from_env().expect("Valid HTTPS origin must be accepted");
        assert_eq!(cfg.circle_media_base_url.scheme(), "https");
    }

    let invalid_cases = [
        ("https://user@media.catbird.blue/", "userinfo"),
        ("https://user:pass@media.catbird.blue", "userinfo"),
        ("https://media.catbird.blue/?upstream=wrong", "query"),
        ("https://media.catbird.blue/#fragment", "fragment"),
        ("https://media.catbird.blue/some/path", "path"),
        ("http://media.catbird.blue", "http"),
        ("ftp://media.catbird.blue", "ftp"),
        ("not-a-url", "malformed"),
    ];
    for (val, desc) in invalid_cases {
        std::env::set_var("CIRCLE_MEDIA_BASE_URL", val);
        std::env::set_var("NEST_CLIENT_ID", "https://nest.catbird.blue");
        std::env::set_var("NEST_JWKS_URL", "https://nest.catbird.blue/.well-known/jwks.json");
        let res = Config::from_env();
        assert!(res.is_err(), "Invalid CIRCLE_MEDIA_BASE_URL ({desc}: {val}) must be rejected");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_adversarial_depth_and_breadth_budget_bounded_and_preserves_direct_siblings(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7advroot");
    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Root", "createdAt": "2026-08-24T12:00:00.000Z"});
    let root_cid = compute_record_cid(&root_json);
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7advroot', $5, now(), now())")
        .bind(&root_uri).bind(&root_cid).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    // Seed a tree with >499 reachable replies within depth=10:
    // - 50 direct level-1 siblings attached to root
    // - 460 direct children attached to the first level-1 sibling (L1_1)
    let mut total_seeded = 1; // root
    let mut l1_1_uri = String::new();
    let mut l1_1_cid = String::new();

    // 1. Level 1 (50 siblings attached directly to root)
    for i in 1..=50 {
        let l1_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7adv_l1_{i}");
        let l1_json = json!({
            "$type": "app.bsky.feed.post",
            "text": format!("Level 1 - {i}"),
            "createdAt": format!("2026-08-24T12:01:{i:02}.000Z"),
            "reply": {"root": {"uri": &root_uri, "cid": &root_cid}, "parent": {"uri": &root_uri, "cid": &root_cid}}
        });
        let l1_cid = compute_record_cid(&l1_json);
        sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', $5, $6, now(), now(), $7, $7)")
            .bind(&l1_uri).bind(&l1_cid).bind(SPACE_1).bind(BOB_DID).bind(format!("3l7adv_l1_{i}")).bind(&l1_json).bind(&root_uri).execute(&pool).await.unwrap();
        if i == 1 {
            l1_1_uri = l1_uri;
            l1_1_cid = l1_cid;
        }
        total_seeded += 1;
    }

    // 2. Attach 460 direct children to the first level-1 reply (L1_1)
    // These are reachable at depth=2 (well within depth=10 limit)
    for j in 1..=460 {
        let child_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7adv_l1_1_c_{j}");
        let child_json = json!({
            "$type": "app.bsky.feed.post",
            "text": format!("L1_1 Child {j}"),
            "createdAt": format!("2026-08-24T12:05:00.{j:03}Z"),
            "reply": {"root": {"uri": &root_uri, "cid": &root_cid}, "parent": {"uri": &l1_1_uri, "cid": &l1_1_cid}}
        });
        let child_cid = compute_record_cid(&child_json);
        sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', $5, $6, now(), now(), $7, $8)")
            .bind(&child_uri).bind(&child_cid).bind(SPACE_1).bind(BOB_DID).bind(format!("3l7adv_l1_1_c_{j}")).bind(&child_json).bind(&l1_1_uri).bind(&root_uri).execute(&pool).await.unwrap();
        total_seeded += 1;
    }

    assert_eq!(total_seeded, 511, "Seeded exactly 511 nodes (1 root + 50 L1 siblings + 460 L1_1 children)");

    let root_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/3l7advroot");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}&depth=10"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 10 * 1024 * 1024).await.unwrap();
    let thread_output: GetPostThreadOutput = serde_json::from_slice(&body).unwrap();

    fn count_nodes(replies: &[ThreadViewPostRepliesItem]) -> usize {
        let mut count = 0;
        for item in replies {
            if let ThreadViewPostRepliesItem::ThreadViewPost(tvp) = item {
                count += 1;
                if let Some(child_replies) = &tvp.replies {
                    count += count_nodes(child_replies);
                }
            }
        }
        count
    }

    let thread = &thread_output.thread;

    let reply_items = thread.replies.as_ref().expect("Thread must have replies");
    let direct_replies_count = reply_items.len();
    let total_reply_nodes = count_nodes(reply_items);
    let total_thread_nodes = 1 + total_reply_nodes;

    // Strict assertions:
    // 1. Total thread nodes saturates at exactly 500 (MAX_THREAD_NODES bound, root included per implementation accounting)
    assert_eq!(total_thread_nodes, 500, "Total thread nodes must saturate at exactly MAX_THREAD_NODES (500)");
    assert_eq!(total_reply_nodes, 499, "Total reply nodes must be exactly 499 (500 max - 1 root)");
    // 2. All 50 direct level-1 siblings are retained because the direct batch was charged before recursion
    assert_eq!(direct_replies_count, 50, "All 50 direct level 1 siblings must be retained and not starved by child recursion");
    // 3. First sibling gets exactly 449 children consuming the remaining budget (499 - 50 = 449)
    if let ThreadViewPostRepliesItem::ThreadViewPost(first_sibling) = &reply_items[0] {
        let first_sibling_replies = first_sibling.replies.as_ref().expect("First sibling must have replies");
        assert_eq!(first_sibling_replies.len(), 449, "First sibling must have exactly 449 child replies (449 remaining budget)");
    } else {
        panic!("Expected first reply item to be a ThreadViewPost");
    }
}
