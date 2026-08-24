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
        circle_media_base_url: MEDIA_BASE.into(),
        nest_client_id: "https://nest.catbird.blue".into(),
        nest_jwks_url: "https://nest.catbird.blue/.well-known/jwks.json".into(),
        nest_verifying_keys: Vec::new(),
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

    let post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7cursorpost");
    let post_json = json!({"$type": "app.bsky.feed.post", "text": "Cursor post", "createdAt": "2026-08-24T12:00:00.000Z"});
    let cid = compute_record_cid(&post_json);

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', '3l7cursorpost', $5, now(), now())
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

    // Fetch page 1 -> get cursor
    let token1 = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req1 = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}&limit=1"))
        .header(header::AUTHORIZATION, format!("Bearer {token1}"))
        .body(Body::empty())
        .unwrap();

    let resp1 = setup.app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // Now revoke Bob's lease/access to Space 1 before page 2
    sqlx::query("DELETE FROM access_leases WHERE space_uri = $1 AND member_did = $2")
        .bind(SPACE_1)
        .bind(BOB_DID)
        .execute(&pool)
        .await
        .unwrap();

    // Bob attempts to fetch next page with cursor from Space 1 using fresh JWT
    let cursor = circle_appview::feed::encode_cursor(&circle_appview::feed::FeedCursor {
        indexed_at: Utc::now(),
        uri: post_uri.clone(),
    });

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
    let reply_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Reply post",
        "createdAt": "2026-08-24T12:01:00.000Z",
        "reply": {
            "root": {"uri": root_uri, "cid": "bafyreih327rootcid"},
            "parent": {"uri": root_uri, "cid": "bafyreih327rootcid"}
        }
    });

    let root_cid = compute_record_cid(&root_json);
    let reply_cid = compute_record_cid(&reply_json);

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
    let same_reply_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Same space reply",
        "createdAt": "2026-08-24T12:01:00.000Z",
        "reply": {"root": {"uri": root_uri, "cid": "c1"}, "parent": {"uri": root_uri, "cid": "c1"}}
    });
    let cross_reply_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Cross space reply",
        "createdAt": "2026-08-24T12:02:00.000Z",
        "reply": {"root": {"uri": root_uri, "cid": "c1"}, "parent": {"uri": root_uri, "cid": "c1"}}
    });

    let root_cid = compute_record_cid(&root_json);
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
                    "ref": { "$link": "bafkreiblob12345" },
                    "mimeType": "image/jpeg",
                    "size": 123456
                }
            }]
        }
    });
    let cid = compute_record_cid(&post_json);

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
            assert!(images_view.images[0].fullsize.as_str().contains("bafkreiblob12345"));
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
    let same_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Same",
        "createdAt": "2026-08-24T12:01:00.000Z",
        "reply": {"root": {"uri": root_uri, "cid": "c1"}, "parent": {"uri": root_uri, "cid": "c1"}}
    });
    let other_json = json!({
        "$type": "app.bsky.feed.post",
        "text": "Other",
        "createdAt": "2026-08-24T12:02:00.000Z",
        "reply": {"root": {"uri": root_uri, "cid": "c1"}, "parent": {"uri": root_uri, "cid": "c1"}}
    });

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, 'c1', $2, $3, 'app.bsky.feed.post', '3l7root', $4, now(), now())")
        .bind(&root_uri).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, 'c2', $2, $3, 'app.bsky.feed.post', '3l7same', $4, now(), now(), $5, $5)")
        .bind(&same_reply_uri).bind(SPACE_1).bind(BOB_DID).bind(&same_json).bind(&root_uri).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, 'c3', $2, $3, 'app.bsky.feed.post', '3l7other', $4, now(), now(), $5, $5)")
        .bind(&other_reply_uri).bind(SPACE_2).bind(BOB_DID).bind(&other_json).bind(&root_uri).execute(&pool).await.unwrap();

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
    let json_b = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post B",
        "createdAt": "2026-08-24T12:01:00.000Z",
        "reply": {"root": {"uri": post_a, "cid": "cA"}, "parent": {"uri": post_a, "cid": "cA"}}
    });
    let json_c = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post C",
        "createdAt": "2026-08-24T12:02:00.000Z",
        "reply": {"root": {"uri": post_a, "cid": "cA"}, "parent": {"uri": post_b, "cid": "cB"}}
    });

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, 'cA', $2, $3, 'app.bsky.feed.post', '3l7postA', $4, now(), now())")
        .bind(&post_a).bind(SPACE_1).bind(ALICE_DID).bind(&json_a).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, 'cB', $2, $3, 'app.bsky.feed.post', '3l7postB', $4, now(), now(), $5, $6)")
        .bind(&post_b).bind(SPACE_1).bind(BOB_DID).bind(&json_b).bind(&post_a).bind(&post_a).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, 'cC', $2, $3, 'app.bsky.feed.post', '3l7postC', $4, now(), now(), $5, $6)")
        .bind(&post_c).bind(SPACE_1).bind(BOB_DID).bind(&json_c).bind(&post_b).bind(&post_a).execute(&pool).await.unwrap();

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
    let p1_json = json!({"$type": "app.bsky.feed.post", "text": "P1 deleted", "createdAt": "2026-08-24T12:01:00.000Z", "reply": {"root": {"uri": root_uri, "cid": "c"}, "parent": {"uri": root_uri, "cid": "c"}}});
    let p2_json = json!({"$type": "app.bsky.feed.post", "text": "P2 child of deleted", "createdAt": "2026-08-24T12:02:00.000Z", "reply": {"root": {"uri": root_uri, "cid": "c"}, "parent": {"uri": p1_uri, "cid": "c"}}});

    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, 'c', $2, $3, 'app.bsky.feed.post', '3l7root', $4, now(), now())")
        .bind(&root_uri).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    // P1 is soft-deleted
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri, deleted_at) VALUES ($1, 'c', $2, $3, 'app.bsky.feed.post', '3l7p1', $4, now(), now(), $5, $5, now())")
        .bind(&p1_uri).bind(SPACE_1).bind(BOB_DID).bind(&p1_json).bind(&root_uri).execute(&pool).await.unwrap();

    // P2 is active child of P1
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, 'c', $2, $3, 'app.bsky.feed.post', '3l7p2', $4, now(), now(), $5, $6)")
        .bind(&p2_uri).bind(SPACE_1).bind(BOB_DID).bind(&p2_json).bind(&p1_uri).bind(&root_uri).execute(&pool).await.unwrap();

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
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, 'cRoot', $2, $3, 'app.bsky.feed.post', '3l7budgetroot', $4, now(), now())")
        .bind(&root_uri).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    // Insert 550 replies (exceeding the 500 node budget)
    for i in 1..=550 {
        let r_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7reply{i}");
        let r_json = json!({"$type": "app.bsky.feed.post", "text": format!("Reply {i}"), "createdAt": "2026-08-24T12:01:00.000Z", "reply": {"root": {"uri": root_uri, "cid": "cRoot"}, "parent": {"uri": root_uri, "cid": "cRoot"}}});
        sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri) VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', $5, $6, now(), now(), $7, $7)")
            .bind(&r_uri).bind(format!("c{i}")).bind(SPACE_1).bind(BOB_DID).bind(format!("3l7reply{i}")).bind(&r_json).bind(&root_uri).execute(&pool).await.unwrap();
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
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7racepost");
    let root_json = json!({"$type": "app.bsky.feed.post", "text": "Race post", "createdAt": "2026-08-24T12:00:00.000Z"});
    sqlx::query("INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at) VALUES ($1, 'cRace', $2, $3, 'app.bsky.feed.post', '3l7racepost', $4, now(), now())")
        .bind(&root_uri).bind(SPACE_1).bind(ALICE_DID).bind(&root_json).execute(&pool).await.unwrap();

    // Expire lease immediately
    sqlx::query("UPDATE access_leases SET expires_at = now() - interval '1 second' WHERE space_uri = $1 AND member_did = $2")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();

    let root_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/3l7racepost");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let err_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["error"], "AccessRemoved");
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
}
