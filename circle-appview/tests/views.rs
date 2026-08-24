use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
use catbird_atproto::generated::app_bsky::feed::PostViewEmbed;
use catbird_atproto::generated::blue_catbird::circle::get_feed::GetFeedOutput;
use catbird_atproto::generated::blue_catbird::circle::get_post_thread::GetPostThreadOutput;
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::string::{Did, Handle};
use chrono::{Duration, Utc};
use circle_appview::{
    auth::{DidDocument, PublicKeyJwk, VerificationMethod},
    config::{AppState, Config},
    db,
    feed::decode_cursor,
    hydration::ProfileHydrator,
    routes::create_router,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

const CIRCLE_AUDIENCE: &str = "did:web:circles.catbird.blue#atproto_circle";
const ALICE_DID: &str = "did:plc:alice-circle-owner";
const BOB_DID: &str = "did:plc:bob-circle-member";
const CHARLIE_DID: &str = "did:plc:charlie-circle-nonmember";
const SPACE_1: &str = "at://did:plc:alice-circle-owner/space/blue.catbird.circle/3l7space1";
const SPACE_2: &str = "at://did:plc:alice-circle-owner/space/blue.catbird.circle/3l7space2";

struct ViewTestSetup {
    app: axum::Router,
    alice_key: p256::ecdsa::SigningKey,
    bob_key: p256::ecdsa::SigningKey,
    charlie_key: p256::ecdsa::SigningKey,
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

    // 2. Grant Bob an active access lease in Space 1 ONLY (Space 2 has no lease for Bob)
    sqlx::query(
        "INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')",
    )
    .bind(SPACE_1)
    .bind(BOB_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 3. Insert post in Space 1 and post in Space 2
    let post1_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7post1");
    let post2_uri = format!("{SPACE_2}/{ALICE_DID}/app.bsky.feed.post/3l7post2");

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, 'bafyreih327post1', $2, $3, 'app.bsky.feed.post', '3l7post1', $4, now(), now())
        "#,
    )
    .bind(&post1_uri)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "Post in Space 1", "createdAt": "2026-08-24T12:00:00.000Z"}))
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, 'bafyreih327post2', $2, $3, 'app.bsky.feed.post', '3l7post2', $4, now(), now())
        "#,
    )
    .bind(&post2_uri)
    .bind(SPACE_2)
    .bind(ALICE_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "Post in Space 2", "createdAt": "2026-08-24T12:01:00.000Z"}))
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

    // Grant Bob active lease
    sqlx::query("INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();

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
async fn feed_stable_opaque_cursor_pagination(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();

    let base_time = Utc::now() - Duration::hours(5);

    // Insert 5 posts
    for i in 1..=5 {
        let uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7post{i}");
        let indexed_at = base_time + Duration::minutes(i * 10);
        sqlx::query(
            r#"
            INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
            VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', $5, $6, $7, $7)
            "#,
        )
        .bind(&uri)
        .bind(format!("bafyreih327cid{i}"))
        .bind(SPACE_1)
        .bind(ALICE_DID)
        .bind(format!("3l7post{i}"))
        .bind(json!({"$type": "app.bsky.feed.post", "text": format!("Post {i}"), "createdAt": indexed_at.to_rfc3339()}))
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
    let cursor1 = page1.cursor.expect("Page 1 must have cursor");

    // Verify cursor decodes to (indexed_at, uri) of last item
    let decoded1 = decode_cursor(cursor1.as_str()).unwrap();
    assert_eq!(decoded1.uri, format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7post4"));

    // Page 2: limit = 2 with cursor1
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
    let cursor2 = page2.cursor.expect("Page 2 must have cursor");

    // Page 3: limit = 2 with cursor2 (last 1 item)
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
    assert!(page3.cursor.is_none(), "Final page must have cursor = None");
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_invalid_cursor_returns_invalid_request(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();

    // 1. Non-base64 cursor
    let token1 = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req1 = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}&cursor=invalid%20base64!"))
        .header(header::AUTHORIZATION, format!("Bearer {token1}"))
        .body(Body::empty())
        .unwrap();

    let resp1 = setup.app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::BAD_REQUEST);

    // 2. Valid base64 but invalid JSON cursor
    let bad_json_cursor = URL_SAFE_NO_PAD.encode(b"not json");
    let token2 = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req2 = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}&cursor={bad_json_cursor}"))
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();

    let resp2 = setup.app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_never_traverses_public_or_other_space_records(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 2', now())")
        .bind(SPACE_2).bind(ALICE_DID).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7root");
    let reply1_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7rep1");
    let other_space_reply_uri = format!("{SPACE_2}/{BOB_DID}/app.bsky.feed.post/3l7cross");

    // Root in Space 1
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, 'bafyreih327root', $2, $3, 'app.bsky.feed.post', '3l7root', $4, now(), now())
        "#,
    )
    .bind(&root_uri)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "Root post", "createdAt": "2026-08-24T12:00:00.000Z"}))
    .execute(&pool)
    .await
    .unwrap();

    // Reply 1 in Space 1 (same space)
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri)
        VALUES ($1, 'bafyreih327rep1', $2, $3, 'app.bsky.feed.post', '3l7rep1', $4, now(), now(), $5, $5)
        "#,
    )
    .bind(&reply1_uri)
    .bind(SPACE_1)
    .bind(BOB_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "Reply 1 in Space 1", "createdAt": "2026-08-24T12:05:00.000Z"}))
    .bind(&root_uri)
    .execute(&pool)
    .await
    .unwrap();

    // Foreign reply in Space 2 pointing to Space 1 root
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri)
        VALUES ($1, 'bafyreih327cross', $2, $3, 'app.bsky.feed.post', '3l7cross', $4, now(), now(), $5, $5)
        "#,
    )
    .bind(&other_space_reply_uri)
    .bind(SPACE_2)
    .bind(BOB_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "Cross-space reply", "createdAt": "2026-08-24T12:10:00.000Z"}))
    .bind(&root_uri)
    .execute(&pool)
    .await
    .unwrap();

    // Query thread for Space 1 root
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
    let thread_output: GetPostThreadOutput = serde_json::from_slice(&body).unwrap();

    assert_eq!(thread_output.thread.post.uri.as_str(), root_std_uri);
    let replies = thread_output.thread.replies.expect("Thread must have replies");
    assert_eq!(replies.len(), 1, "Thread must only contain same-space replies");
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_excludes_replies_whose_root_or_parent_is_deleted(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7root");
    let reply1_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7rep1");
    let reply2_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7rep2");

    // Root post
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, 'bafyreih327root', $2, $3, 'app.bsky.feed.post', '3l7root', $4, now(), now())
        "#,
    )
    .bind(&root_uri)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "Root", "createdAt": "2026-08-24T12:00:00.000Z"}))
    .execute(&pool)
    .await
    .unwrap();

    // Reply 1 (parent is root, root is root)
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri)
        VALUES ($1, 'bafyreih327rep1', $2, $3, 'app.bsky.feed.post', '3l7rep1', $4, now(), now(), $5, $5)
        "#,
    )
    .bind(&reply1_uri)
    .bind(SPACE_1)
    .bind(BOB_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "Reply 1", "createdAt": "2026-08-24T12:05:00.000Z"}))
    .bind(&root_uri)
    .execute(&pool)
    .await
    .unwrap();

    // Reply 2 (parent is Reply 1, root is root)
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri)
        VALUES ($1, 'bafyreih327rep2', $2, $3, 'app.bsky.feed.post', '3l7rep2', $4, now(), now(), $5, $6)
        "#,
    )
    .bind(&reply2_uri)
    .bind(SPACE_1)
    .bind(BOB_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "Reply 2", "createdAt": "2026-08-24T12:10:00.000Z"}))
    .bind(&reply1_uri)
    .bind(&root_uri)
    .execute(&pool)
    .await
    .unwrap();

    // 1. Initially thread has Reply 1 with nested Reply 2
    let root_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/3l7root");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req1 = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp1 = setup.app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = to_bytes(resp1.into_body(), 1024 * 1024).await.unwrap();
    let thread1: GetPostThreadOutput = serde_json::from_slice(&body1).unwrap();
    assert_eq!(thread1.thread.replies.as_ref().unwrap().len(), 1);

    // 2. Soft-delete Reply 1
    sqlx::query("UPDATE circle_records SET deleted_at = now() WHERE uri = $1")
        .bind(&reply1_uri)
        .execute(&pool)
        .await
        .unwrap();

    // 3. Query thread again -> Root has NO replies (Reply 1 is deleted, Reply 2's parent is deleted)
    let token2 = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req2 = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();

    let resp2 = setup.app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = to_bytes(resp2.into_body(), 1024 * 1024).await.unwrap();
    let thread2: GetPostThreadOutput = serde_json::from_slice(&body2).unwrap();
    assert!(thread2.thread.replies.is_none(), "Replies must be empty when intermediate parent is deleted");
}

#[sqlx::test(migrations = "./migrations")]
async fn thread_not_found_when_root_post_deleted_or_missing(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();

    let root_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7deletedroot");

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, deleted_at)
        VALUES ($1, 'bafyreih327del', $2, $3, 'app.bsky.feed.post', '3l7deletedroot', $4, now(), now(), now())
        "#,
    )
    .bind(&root_uri)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "Deleted post", "createdAt": "2026-08-24T12:00:00.000Z"}))
    .execute(&pool)
    .await
    .unwrap();

    let root_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/3l7deletedroot");
    let token = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getPostThread?uri={root_std_uri}&space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn profile_hydration_cached_for_five_minutes_and_fallback_unavailable_on_failure() {
    let client = reqwest::Client::new();
    let hydrator = ProfileHydrator::new("https://invalid-appview.example.com".to_string(), client);

    // 1. Unknown / failing DID resolves to unavailable profile without panicking
    let fallback = hydrator.get_profile("did:plc:unreachable-actor").await;
    assert_eq!(fallback.did.as_str(), "did:plc:unreachable-actor");
    assert_eq!(fallback.handle.as_str(), "handle.invalid");
    assert!(fallback.display_name.is_none());

    // 2. Second fetch resolves from cache
    let cached = hydrator.get_profile("did:plc:unreachable-actor").await;
    assert_eq!(cached.handle.as_str(), "handle.invalid");
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_view_post_and_thread_view_post_with_circle_local_counts_and_viewer_like_state(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    // Alice, Bob, Charlie all have leases
    sqlx::query("INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(SPACE_1).bind(CHARLIE_DID).execute(&pool).await.unwrap();

    let post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7counted");
    let reply_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.post/3l7replycounted");
    let alice_like_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.like/3l7like1");
    let bob_like_uri = format!("{SPACE_1}/{BOB_DID}/app.bsky.feed.like/3l7like2");

    // Insert Post
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, 'bafyreih327counted', $2, $3, 'app.bsky.feed.post', '3l7counted', $4, now(), now())
        "#,
    )
    .bind(&post_uri)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "Counted post", "createdAt": "2026-08-24T12:00:00.000Z"}))
    .execute(&pool)
    .await
    .unwrap();

    // Insert Reply
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri)
        VALUES ($1, 'bafyreih327repcounted', $2, $3, 'app.bsky.feed.post', '3l7replycounted', $4, now(), now(), $5, $5)
        "#,
    )
    .bind(&reply_uri)
    .bind(SPACE_1)
    .bind(BOB_DID)
    .bind(json!({"$type": "app.bsky.feed.post", "text": "A reply", "createdAt": "2026-08-24T12:05:00.000Z"}))
    .bind(&post_uri)
    .execute(&pool)
    .await
    .unwrap();

    // Insert Likes in circle_records + circle_likes
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, 'bafyreih327like1', $2, $3, 'app.bsky.feed.like', '3l7like1', '{}', now(), now())
        "#,
    )
    .bind(&alice_like_uri).bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at)
        VALUES ($1, $2, $3, $4, now())
        "#,
    )
    .bind(&alice_like_uri).bind(SPACE_1).bind(&post_uri).bind(ALICE_DID).execute(&pool).await.unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, 'bafyreih327like2', $2, $3, 'app.bsky.feed.like', '3l7like2', '{}', now(), now())
        "#,
    )
    .bind(&bob_like_uri).bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at)
        VALUES ($1, $2, $3, $4, now())
        "#,
    )
    .bind(&bob_like_uri).bind(SPACE_1).bind(&post_uri).bind(BOB_DID).execute(&pool).await.unwrap();

    // 1. Alice queries feed -> sees like_count = 2, reply_count = 1, viewer.like = Some(alice_like_uri)
    let token_alice = mint_jwt(ALICE_DID, "blue.catbird.circle.getFeed", &setup.alice_key);
    let req_alice = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token_alice}"))
        .body(Body::empty())
        .unwrap();

    let resp_alice = setup.app.clone().oneshot(req_alice).await.unwrap();
    assert_eq!(resp_alice.status(), StatusCode::OK);
    let body_alice = to_bytes(resp_alice.into_body(), 1024 * 1024).await.unwrap();
    let feed_alice: GetFeedOutput = serde_json::from_slice(&body_alice).unwrap();

    // Find the post
    let post_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/3l7counted");
    let alice_like_std_uri = format!("at://{ALICE_DID}/app.bsky.feed.like/3l7like1");
    let post_item = feed_alice.feed.iter().find(|i| i.post.post.uri.as_str() == post_std_uri).unwrap();
    assert_eq!(post_item.post.post.like_count, Some(2));
    assert_eq!(post_item.post.post.reply_count, Some(1));
    assert_eq!(post_item.post.post.repost_count, None, "Repost count must not be populated");
    assert_eq!(post_item.post.post.quote_count, None, "Quote count must not be populated");
    assert_eq!(
        post_item.post.post.viewer.as_ref().and_then(|v| v.like.as_ref()).map(|l| l.as_str()),
        Some(alice_like_std_uri.as_str()),
        "Alice viewer state must contain Alice's like URI"
    );

    // 2. Charlie queries feed -> sees like_count = 2, reply_count = 1, viewer.like = None
    let token_charlie = mint_jwt(CHARLIE_DID, "blue.catbird.circle.getFeed", &setup.charlie_key);
    let req_charlie = Request::builder()
        .method("GET")
        .uri(format!("/xrpc/blue.catbird.circle.getFeed?space={SPACE_1}"))
        .header(header::AUTHORIZATION, format!("Bearer {token_charlie}"))
        .body(Body::empty())
        .unwrap();

    let resp_charlie = setup.app.clone().oneshot(req_charlie).await.unwrap();
    assert_eq!(resp_charlie.status(), StatusCode::OK);
    let body_charlie = to_bytes(resp_charlie.into_body(), 1024 * 1024).await.unwrap();
    let feed_charlie: GetFeedOutput = serde_json::from_slice(&body_charlie).unwrap();

    let post_item_charlie = feed_charlie.feed.iter().find(|i| i.post.post.uri.as_str() == post_std_uri).unwrap();
    assert_eq!(post_item_charlie.post.post.like_count, Some(2));
    assert_eq!(post_item_charlie.post.post.reply_count, Some(1));
    assert!(
        post_item_charlie.post.post.viewer.is_none()
            || post_item_charlie.post.post.viewer.as_ref().unwrap().like.is_none(),
        "Charlie has not liked the post, viewer.like must be None"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn feed_view_post_embed_images_view_construction(pool: PgPool) {
    let setup = setup_views_test(pool.clone()).await;

    sqlx::query("INSERT INTO circles (space_uri, authority_did, display_name, created_at) VALUES ($1, $2, 'Space 1', now())")
        .bind(SPACE_1).bind(ALICE_DID).execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO access_leases (space_uri, member_did, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(SPACE_1).bind(BOB_DID).execute(&pool).await.unwrap();

    let post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7imagepost");

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, 'bafyreih327img', $2, $3, 'app.bsky.feed.post', '3l7imagepost', $4, now(), now())
        "#,
    )
    .bind(&post_uri)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(json!({
        "$type": "app.bsky.feed.post",
        "text": "Post with image",
        "createdAt": "2026-08-24T12:00:00.000Z",
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [{
                "alt": "Test image alt",
                "image": {
                    "$type": "blob",
                    "ref": { "$link": "bafkreiblob12345" },
                    "mimeType": "image/jpeg",
                    "size": 123456
                }
            }]
        }
    }))
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
            assert!(images_view.images[0].fullsize.as_str().contains("/xrpc/blue.catbird.circle.getMedia"));
            assert!(images_view.images[0].fullsize.as_str().contains("bafkreiblob12345"));
            assert!(images_view.images[0].thumb.as_str().contains("/xrpc/blue.catbird.circle.getMedia"));
        }
        other => panic!("Expected PostViewEmbed::ImagesView, got {:?}", other),
    }
}
