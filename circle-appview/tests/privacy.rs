use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
use catbird_atproto::generated::blue_catbird::circle::NotificationReason;
use catbird_atproto::generated::blue_catbird::circle::list_notifications::ListNotificationsOutput;
use catbird_atproto::generated::blue_catbird::circle::report_record::ReportRecordOutput;
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::string::{Did, Handle};
use chrono::{Duration, Utc};
use circle_appview::{
    access::ActiveSpaceCredential,
    auth::{DidDocument, PublicKeyJwk, VerificationMethod},
    config::{AppState, Config},
    db,
    purge::{deactivate_author, delete_space, remove_member},
    routes::create_router,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const CIRCLE_AUDIENCE: &str = "did:web:circles.catbird.blue#atproto_circles";
const ALICE_DID: &str = "did:plc:alice-privacy-owner";
const BOB_DID: &str = "did:plc:bob-privacy-member";
const DAVE_DID: &str = "did:plc:dave-privacy-unauthorized";
const MEDIA_BASE: &str = "https://media.catbird.blue";
const SPACE_1: &str = "at://did:plc:alice-privacy-owner/space/blue.catbird.circle/3l7privacy1";
const SPACE_2: &str = "at://did:plc:dave-privacy-unauthorized/space/blue.catbird.circle/3l7privacy2";

fn url_encode(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

struct PrivacyTestSetup {
    app: axum::Router,
    state: AppState,
    mock_transport: Arc<circle_appview::space_client::MockSpaceHostTransport>,
    alice_key: p256::ecdsa::SigningKey,
    bob_key: p256::ecdsa::SigningKey,
    dave_key: p256::ecdsa::SigningKey,
}

fn register_did_doc(
    resolver: &circle_appview::auth::DidResolver,
    did: &str,
    key: &p256::ecdsa::SigningKey,
    pds_endpoint: Option<&str>,
) {
    let vk = key.verifying_key();
    let point = EncodedPoint::from(vk);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let p256_sec1 = vk.to_encoded_point(true);
    let mut p256_multikey_bytes = vec![0x80, 0x24];
    p256_multikey_bytes.extend_from_slice(p256_sec1.as_bytes());
    let p256_multikey = multibase::encode(multibase::Base::Base58Btc, &p256_multikey_bytes);

    let mut services = Vec::new();
    if let Some(endpoint) = pds_endpoint {
        services.push(circle_appview::auth::DidService {
            id: format!("{did}#atproto_pds"),
            r#type: "AtprotoPersonalDataServer".into(),
            service_endpoint: endpoint.into(),
        });
    }

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
        service: services,
    };
    resolver.insert_cached(did.into(), did_doc);
}

fn mint_jwt(did: &str, lxm: &str, signing_key: &p256::ecdsa::SigningKey) -> String {
    let now = Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();

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

async fn grant_active_member(pool: &PgPool, space_uri: &str, member_did: &str, _duration: Duration) {
    sqlx::query(
        r#"
        INSERT INTO circle_member_cache (space_uri, member_did, cached_at)
        VALUES ($1, $2, now())
        ON CONFLICT (space_uri, member_did)
        DO UPDATE SET cached_at = now()
        "#,
    )
    .bind(space_uri)
    .bind(member_did)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count)
        VALUES ($1, now(), 1)
        ON CONFLICT (space_uri)
        DO UPDATE SET last_refreshed_at = now()
        "#,
    )
    .bind(space_uri)
    .execute(pool)
    .await
    .unwrap();
}

async fn setup_privacy_test(pool: PgPool) -> PrivacyTestSetup {
    db::run_migrations(&pool)
        .await
        .expect("Migrations must succeed");

    let alice_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let bob_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let dave_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: CIRCLE_AUDIENCE.into(),
        plc_directory_url: "https://plc.directory".into(),
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse(MEDIA_BASE).unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: format!("{CIRCLE_AUDIENCE}#atproto_circles"),
        push_signing_key_path: None,
        push_signing_key_hex: None,
    };

    let mock_transport = Arc::new(circle_appview::space_client::MockSpaceHostTransport::new());
    let space_client = Arc::new(circle_appview::space_client::SpaceClient::with_transport(mock_transport.clone()));
    let did_resolver = Arc::new(circle_appview::auth::DidResolver::new("https://plc.directory".into(), reqwest::Client::new()));
    let credential_store = Arc::new(circle_appview::access::CredentialStore::new());
    let space_locks = Arc::new(circle_appview::access::SpaceLockManager::new());
    let profile_hydrator = Arc::new(circle_appview::hydration::ProfileHydrator::new(
        config.public_appview_url.clone(),
        reqwest::Client::new(),
    ));
    let oauth_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let oauth_service = Arc::new(circle_appview::oauth::OAuthService::new(
        config.appview_base_url.clone(),
        oauth_signing_key,
        None,
    ));

    let state = AppState {
        config: Arc::new(config),
        db: pool.clone(),
        http_client: reqwest::Client::new(),
        did_resolver: did_resolver.clone(),
        credential_store,
        space_client,
        space_locks,
        profile_hydrator: profile_hydrator.clone(),
        oauth_service,
        push_client: None,
    };
    register_did_doc(&state.did_resolver, ALICE_DID, &alice_key, Some("https://pds.alice.test"));
    register_did_doc(&state.did_resolver, BOB_DID, &bob_key, Some("https://pds.bob.test"));
    register_did_doc(&state.did_resolver, DAVE_DID, &dave_key, Some("https://pds.dave.test"));

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
    PrivacyTestSetup {
        app,
        state,
        mock_transport,
        alice_key,
        bob_key,
        dave_key,
    }
}

fn circle_activity_payload() -> serde_json::Value {
    json!({
        "kind": "circle_activity"
    })
}

#[sqlx::test(migrations = "./migrations")]
async fn unauthorized_user_cannot_fetch_media_or_notifications(pool: PgPool) {
    let setup = setup_privacy_test(pool.clone()).await;

    // Create private Circle owned by Alice with Bob as member
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7privacyaaa', $2, 'Alice Private Circle', now())
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    // Store active credential for SPACE_1 in state
    let cred_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    setup
        .state
        .credential_store
        .insert(
            SPACE_1.to_string(),
            ActiveSpaceCredential {
                token: "mock-space-token".into(),
                dpop_key: cred_key,
                expires_at: Utc::now() + Duration::hours(1),
            },
        )
        .await;

    // Seed private post with image blob
    let blob_cid = "bafkreifh3zkw4w2p3o2v3h";
    let post_uri = format!("{SPACE_1}/app.bsky.feed.post/3l7post1");
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, 'bafyreipost1', $2, $3, 'app.bsky.feed.post', '3l7post1', $4, now())
        "#,
    )
    .bind(&post_uri)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(json!({
        "$type": "app.bsky.feed.post",
        "text": "Top secret circle photo",
        "createdAt": Utc::now().to_rfc3339(),
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [{
                "alt": "private image",
                "image": { "$link": blob_cid }
            }]
        }
    }))
    .execute(&pool)
    .await
    .unwrap();

    // Seed notification directed to Alice
    sqlx::query(
        r#"
        INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
        VALUES ($1, $2, $3, $4, 'like', $5, $6, false, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(ALICE_DID)
    .bind(SPACE_1)
    .bind(BOB_DID)
    .bind(&post_uri)
    .bind(format!("{SPACE_1}/app.bsky.feed.like/3l7like1"))
    .execute(&pool)
    .await
    .unwrap();

    // 1. Dave (unauthorized non-member) attempts getMedia
    let dave_media_jwt = mint_jwt(DAVE_DID, "blue.catbird.circle.getMedia", &setup.dave_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
            url_encode(SPACE_1),
            url_encode(ALICE_DID),
            url_encode(blob_cid),
        ))
        .header(header::AUTHORIZATION, format!("Bearer {dave_media_jwt}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Dave (unauthorized) attempts listNotifications
    let dave_notif_jwt = mint_jwt(DAVE_DID, "blue.catbird.circle.listNotifications", &setup.dave_key);
    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.listNotifications")
        .header(header::AUTHORIZATION, format!("Bearer {dave_notif_jwt}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let notifs: ListNotificationsOutput = serde_json::from_slice(&body_bytes).unwrap();
    // Dave sees 0 notifications
    assert_eq!(notifs.notifications.len(), 0);

    // Alice (authorized) listNotifications -> sees 1 notification
    let alice_notif_jwt = mint_jwt(ALICE_DID, "blue.catbird.circle.listNotifications", &setup.alice_key);
    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.listNotifications")
        .header(header::AUTHORIZATION, format!("Bearer {alice_notif_jwt}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let notifs: ListNotificationsOutput = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(notifs.notifications.len(), 1);
    assert_eq!(notifs.notifications[0].reason, NotificationReason::Like);
}

#[test]
fn generic_push_contains_no_circle_metadata() {
    let payload = circle_activity_payload();
    let json = serde_json::to_string(&payload).unwrap();
    assert_eq!(json, r#"{"kind":"circle_activity"}"#);
}

#[sqlx::test(migrations = "./migrations")]
async fn report_requires_same_space_subject_and_stays_private(pool: PgPool) {
    let setup = setup_privacy_test(pool.clone()).await;

    // Create SPACE_1 and SPACE_2
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7privacyaaa', $2, 'Space 1', now()), ($3, '3l7privacybbb', $2, 'Space 2', now())
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(SPACE_2)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_2, ALICE_DID, Duration::hours(1)).await;

    let post_space1 = format!("{SPACE_1}/app.bsky.feed.post/3l7post1");
    let post_space2 = format!("{SPACE_2}/app.bsky.feed.post/3l7post2");
    let post_space1_std = format!("at://{BOB_DID}/app.bsky.feed.post/3l7post1");
    let post_space2_std = format!("at://{BOB_DID}/app.bsky.feed.post/3l7post2");
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES
            ($1, 'cid1', $2, $3, 'app.bsky.feed.post', '3l7post1', $4, now()),
            ($5, 'cid2', $6, $3, 'app.bsky.feed.post', '3l7post2', $4, now())
        "#,
    )
    .bind(&post_space1)
    .bind(SPACE_1)
    .bind(BOB_DID)
    .bind(json!({"text": "Hello Space 1", "createdAt": Utc::now().to_rfc3339()}))
    .bind(&post_space2)
    .bind(SPACE_2)
    .execute(&pool)
    .await
    .unwrap();

    let report_lxm = "blue.catbird.circle.reportRecord";

    // 1. Dave (unauthorized, no lease in SPACE_1) tries to report post_space1 -> FORBIDDEN
    let dave_jwt = mint_jwt(DAVE_DID, report_lxm, &setup.dave_key);
    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.reportRecord")
        .header(header::AUTHORIZATION, format!("Bearer {dave_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "space": SPACE_1,
            "uri": post_space1_std,
            "reason": "spam",
            "details": "Spam in circle"
        })).unwrap()))
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Alice reports post_space2 under SPACE_1 (cross-space mismatch) -> BAD_REQUEST
    let alice_jwt = mint_jwt(ALICE_DID, report_lxm, &setup.alice_key);
    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.reportRecord")
        .header(header::AUTHORIZATION, format!("Bearer {alice_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "space": SPACE_1,
            "uri": post_space2_std,
            "reason": "spam",
        })).unwrap()))
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 3. Alice reports post_space1 under SPACE_1 (valid same-space report) -> OK
    let alice_jwt = mint_jwt(ALICE_DID, report_lxm, &setup.alice_key);
    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.reportRecord")
        .header(header::AUTHORIZATION, format!("Bearer {alice_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "space": SPACE_1,
            "uri": post_space1_std,
            "reason": "spam",
            "details": "Private spam report"
        })).unwrap()))
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let report_output: ReportRecordOutput = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!report_output.id.as_str().is_empty());

    // 4. Verify report is stored in database
    let report_count: (i64,) = sqlx::query_as("SELECT count(*) FROM circle_reports WHERE space_uri = $1")
        .bind(SPACE_1)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(report_count.0, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn member_removal_space_deletion_and_account_deactivation_purge_exact_scopes(pool: PgPool) {
    let setup = setup_privacy_test(pool.clone()).await;

    // Create SPACE_1 with Alice and Bob
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7privacyaaa', $2, 'Purge Scope Space', now())
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let cred_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    setup
        .state
        .credential_store
        .insert(
            SPACE_1.to_string(),
            ActiveSpaceCredential {
                token: "space-cred".into(),
                dpop_key: cred_key,
                expires_at: Utc::now() + Duration::hours(1),
            },
        )
        .await;

    // Seed Alice's post, Bob's post, and notifications
    let alice_post = format!("{SPACE_1}/app.bsky.feed.post/3l7alicepost");
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, 'cidalice', $2, $3, 'app.bsky.feed.post', '3l7alicepost', $4, now())
        "#,
    )
    .bind(&alice_post)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(json!({"text": "Alice published post", "createdAt": Utc::now().to_rfc3339()}))
    .execute(&pool)
    .await
    .unwrap();

    let bob_post = format!("{SPACE_1}/app.bsky.feed.post/3l7bobpost");
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, 'cidbob', $2, $3, 'app.bsky.feed.post', '3l7bobpost', $4, now())
        "#,
    )
    .bind(&bob_post)
    .bind(SPACE_1)
    .bind(BOB_DID)
    .bind(json!({"text": "Bob published post", "createdAt": Utc::now().to_rfc3339()}))
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
        VALUES ($1, $2, $3, $4, 'reply', $5, $6, false, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(BOB_DID)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(&bob_post)
    .bind(format!("{SPACE_1}/app.bsky.feed.post/3l7alicereply"))
    .execute(&pool)
    .await
    .unwrap();

    // Insert notification where Bob is actor (Bob liked Alice's post)
    let bob_actor_notif_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
        VALUES ($1, $2, $3, $4, 'like', $5, $6, false, now())
        "#,
    )
    .bind(bob_actor_notif_id)
    .bind(ALICE_DID)
    .bind(SPACE_1)
    .bind(BOB_DID)
    .bind(&alice_post)
    .bind(format!("{SPACE_1}/app.bsky.feed.like/3l7boblike"))
    .execute(&pool)
    .await
    .unwrap();

    // 1. Remove Bob from SPACE_1
    remove_member(&pool, SPACE_1, BOB_DID).await.unwrap();

    // Verify Bob's cache is deleted
    let bob_lease: Option<(String,)> = sqlx::query_as("SELECT member_did FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2")
        .bind(SPACE_1)
        .bind(BOB_DID)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(bob_lease.is_none());

    // Verify Bob's notifications in SPACE_1 are purged
    let bob_notif: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM circle_notifications WHERE space_uri = $1 AND recipient_did = $2")
        .bind(SPACE_1)
        .bind(BOB_DID)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(bob_notif.is_none());

    // Verify Bob's published record is NOT deleted
    let bob_record: Option<(String,)> = sqlx::query_as("SELECT uri FROM circle_records WHERE uri = $1 AND deleted_at IS NULL")
        .bind(&bob_post)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(bob_record.is_some());

    // 2. Deactivate Bob's account
    deactivate_author(&pool, BOB_DID).await.unwrap();

    // Verify Bob's record is now soft-deleted (deleted_at is NOT NULL)
    let bob_record_active: Option<(String,)> = sqlx::query_as("SELECT uri FROM circle_records WHERE uri = $1 AND deleted_at IS NULL")
        .bind(&bob_post)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(bob_record_active.is_none());

    // Verify actor-sourced notifications where Bob is actor are also purged upon deactivation
    let bob_actor_notif: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM circle_notifications WHERE actor_did = $1")
        .bind(BOB_DID)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(bob_actor_notif.is_none());
    // 3. Delete SPACE_1
    delete_space(&pool, &setup.state.credential_store, SPACE_1).await.unwrap();

    // Verify Space rows cascaded
    let circle_count: (i64,) = sqlx::query_as("SELECT count(*) FROM circles WHERE space_uri = $1")
        .bind(SPACE_1)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(circle_count.0, 0);

    // Verify credential was removed
    let cred = setup.state.credential_store.get(SPACE_1).await;
    assert!(cred.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn media_streaming_enforces_20mib_cap_and_no_cache(pool: PgPool) {
    let setup = setup_privacy_test(pool.clone()).await;

    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7privacyaaa', $2, 'Media Space', now())
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let cred_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    setup
        .state
        .credential_store
        .insert(
            SPACE_1.to_string(),
            ActiveSpaceCredential {
                token: "space-cred".into(),
                dpop_key: cred_key,
                expires_at: Utc::now() + Duration::hours(1),
            },
        )
        .await;

    // Set up mock transport response for blob
    let blob_cid = "bafkreivalidblob";
    let mock_image_bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00]; // PNG header + bytes
    let mock_transport = Arc::new(circle_appview::space_client::MockSpaceHostTransport::new());
    mock_transport.set_blob_response(
        &format!("{SPACE_1}:{ALICE_DID}:{blob_cid}"),
        Some("image/png".to_string()),
        mock_image_bytes.clone(),
    );

    let space_client = Arc::new(circle_appview::space_client::SpaceClient::with_transport(mock_transport.clone()));
    let custom_state = AppState::with_services(
        setup.state.config.as_ref().clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        space_client,
        setup.state.space_locks.clone(),
    );
    let app = create_router(custom_state);

    // Bob requests Alice's blob in SPACE_1 -> 200 OK with no-cache and validated content-type
    let bob_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getMedia", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
            url_encode(SPACE_1),
            url_encode(ALICE_DID),
            url_encode(blob_cid),
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_jwt}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "image/png"
    );
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store, private"
    );
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(body_bytes.as_ref(), &mock_image_bytes);

    // Test blob exceeding 20 MiB limit is rejected
    let oversize_cid = "bafkreioversizeblob";
    let oversize_bytes = vec![0u8; 21 * 1024 * 1024]; // 21 MiB
    mock_transport.set_blob_response(
        &format!("{SPACE_1}:{ALICE_DID}:{oversize_cid}"),
        Some("image/jpeg".to_string()),
        oversize_bytes,
    );

    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
            url_encode(SPACE_1),
            url_encode(ALICE_DID),
            url_encode(oversize_cid),
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_jwt}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn media_endpoint_resolution_rejects_wrong_id_and_suffix_id(pool: PgPool) {
    let setup = setup_privacy_test(pool.clone()).await;

    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7privacyaaa', $2, 'Media Res Space', now())
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;
    let cred_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    setup
        .state
        .credential_store
        .insert(
            SPACE_1.to_string(),
            ActiveSpaceCredential {
                token: "active-cred-media-res".into(),
                dpop_key: cred_key,
                expires_at: Utc::now() + Duration::hours(1),
            },
        )
        .await;

    let blob_cid = "bafkreiblobres";
    let mock_transport = Arc::new(circle_appview::space_client::MockSpaceHostTransport::new());
    let space_client = Arc::new(circle_appview::space_client::SpaceClient::with_transport(mock_transport.clone()));

    // 1. Author DID doc with wrong service ID but right type ("#custom_pds", "AtprotoPersonalDataServer")
    let custom_pds_did = "did:plc:author-wrong-id";
    grant_active_member(&pool, SPACE_1, custom_pds_did, Duration::hours(1)).await;
    let wrong_id_doc = DidDocument {
        id: custom_pds_did.to_string(),
        verification_method: vec![],
        service: vec![circle_appview::auth::DidService {
            id: "#custom_pds".to_string(),
            r#type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "https://pds.example.com".to_string(),
        }],
    };
    setup.state.did_resolver.insert_cached(custom_pds_did.to_string(), wrong_id_doc);

    let custom_state = AppState::with_services(
        setup.state.config.as_ref().clone(),
        pool.clone(),
        setup.state.did_resolver.clone(),
        setup.state.credential_store.clone(),
        space_client.clone(),
        setup.state.space_locks.clone(),
    );
    let app = create_router(custom_state);

    let bob_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getMedia", &setup.bob_key);
    let req1 = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
            url_encode(SPACE_1),
            url_encode(custom_pds_did),
            url_encode(blob_cid),
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_jwt}"))
        .body(Body::empty())
        .unwrap();

    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::NOT_FOUND, "Wrong service ID must be rejected");

    // 2. Author DID doc with suffix ID ("#fake#atproto_pds")
    let suffix_did = "did:plc:author-suffix-id";
    grant_active_member(&pool, SPACE_1, suffix_did, Duration::hours(1)).await;
    let suffix_doc = DidDocument {
        id: suffix_did.to_string(),
        verification_method: vec![],
        service: vec![circle_appview::auth::DidService {
            id: "#fake#atproto_pds".to_string(),
            r#type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "https://pds.example.com".to_string(),
        }],
    };
    setup.state.did_resolver.insert_cached(suffix_did.to_string(), suffix_doc);

    let bob_jwt_2 = mint_jwt(BOB_DID, "blue.catbird.circle.getMedia", &setup.bob_key);
    let req2 = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
            url_encode(SPACE_1),
            url_encode(suffix_did),
            url_encode(blob_cid),
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_jwt_2}"))
        .body(Body::empty())
        .unwrap();

    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::NOT_FOUND, "Suffix service ID must be rejected");
}

#[derive(Clone)]
struct TestLogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for TestLogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TestLogBuffer {
    type Writer = TestLogBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn tracing_and_logs_contain_no_private_identifiers(pool: PgPool) {
    let log_bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let buffer_writer = TestLogBuffer(log_bytes.clone());

    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer_writer)
        .with_max_level(tracing::Level::TRACE)
        .finish();

    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::info!("Starting privacy tracing test verification run");

    let setup = setup_privacy_test(pool.clone()).await;

    // 1. Seed Space 1 and Space 2
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7privacyaaa', $2, 'Logged Space 1', now())
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7privacybbb', $2, 'Logged Space 2', now())
        "#,
    )
    .bind(SPACE_2)
    .bind(DAVE_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Grant active members/leases
    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_2, DAVE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_2, BOB_DID, Duration::hours(1)).await;

    // 3. Store active credentials in credential store for both spaces
    let cred_key_1 = p256::ecdsa::SigningKey::random(&mut OsRng);
    setup
        .state
        .credential_store
        .insert(
            SPACE_1.to_string(),
            ActiveSpaceCredential {
                token: "space-cred-1".into(),
                dpop_key: cred_key_1,
                expires_at: Utc::now() + Duration::hours(1),
            },
        )
        .await;

    let cred_key_2 = p256::ecdsa::SigningKey::random(&mut OsRng);
    setup
        .state
        .credential_store
        .insert(
            SPACE_2.to_string(),
            ActiveSpaceCredential {
                token: "space-cred-2".into(),
                dpop_key: cred_key_2,
                expires_at: Utc::now() + Duration::hours(1),
            },
        )
        .await;

    // 4. Define and seed real canary fixtures
    let canary_post_text = "Super secret private post text canary alpha";
    let canary_blob_cid = "bafkreiblobcanary123456789";
    let canary_post_rkey = "3l7canaryrkey";
    let canary_post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/{canary_post_rkey}");
    let canary_post_at_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/{canary_post_rkey}");
    let canary_report_details = "Private confidential report details canary 9876";

    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, 'bafyreicanarycid1', $2, $3, 'app.bsky.feed.post', $4, $5, now())
        "#,
    )
    .bind(&canary_post_uri)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(canary_post_rkey)
    .bind(json!({
        "$type": "app.bsky.feed.post",
        "text": canary_post_text,
        "createdAt": "2026-08-24T12:00:00Z",
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [{
                "image": {
                    "$type": "blob",
                    "ref": { "$link": canary_blob_cid },
                    "mimeType": "image/png",
                    "size": 10
                },
                "alt": "canary image alt text"
            }]
        }
    }))
    .execute(&pool)
    .await
    .unwrap();
    // Keep the standard AT-URI representation available for report/thread traversal.
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        SELECT $1, cid, space_uri, author_did, collection, rkey, record_json, created_at
        FROM circle_records WHERE uri = $2
        "#,
    )
    .bind(&canary_post_at_uri)
    .bind(&canary_post_uri)
    .execute(&pool)
    .await
    .unwrap();

    // Seed notification in SPACE_1 for Bob from Alice
    sqlx::query(
        r#"
        INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
        VALUES ($1, $2, $3, $4, 'like', $5, $6, false, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(BOB_DID)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(&canary_post_uri)
    .bind(format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.like/3l7canarylike"))
    .execute(&pool)
    .await
    .unwrap();
    // Mount mock blob response on Alice's PDS
    let mock_image_bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
    setup.mock_transport.set_blob_response(
        &format!("{SPACE_1}:{ALICE_DID}:{canary_blob_cid}"),
        Some("image/png".to_string()),
        mock_image_bytes,
    );

    // 5. Exercise all endpoints through setup.app

    // A. List Notifications with query parameters
    let bob_notif_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.listNotifications", &setup.bob_key);
    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.listNotifications?limit=10")
        .header(header::AUTHORIZATION, format!("Bearer {bob_notif_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let notif_output: ListNotificationsOutput = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(notif_output.notifications.len(), 1);

    if let Some(cursor_val) = notif_output.cursor {
        let req = Request::builder()
            .uri(format!("/xrpc/blue.catbird.circle.listNotifications?limit=10&cursor={cursor_val}"))
            .header(header::AUTHORIZATION, format!("Bearer {bob_notif_jwt}"))
            .body(Body::empty())
            .unwrap();
        let resp = setup.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    // B. Update Preferences
    let alice_pref_jwt = mint_jwt(ALICE_DID, "blue.catbird.circle.updatePreferences", &setup.alice_key);
    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.updatePreferences")
        .header(header::AUTHORIZATION, format!("Bearer {alice_pref_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "space": SPACE_1,
            "muted": true
        })).unwrap()))
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    if status != StatusCode::OK {
        let b = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        panic!("updatePreferences failed with {status}: {}", String::from_utf8_lossy(&b));
    }
    assert_eq!(status, StatusCode::OK);
    // C. Report Record
    let bob_report_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.reportRecord", &setup.bob_key);
    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.reportRecord")
        .header(header::AUTHORIZATION, format!("Bearer {bob_report_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "space": SPACE_1,
            "uri": canary_post_at_uri,
            "reason": "spam",
            "details": canary_report_details
        })).unwrap()))
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // D. Get Media
    let bob_media_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getMedia", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
            url_encode(SPACE_1),
            url_encode(ALICE_DID),
            canary_blob_cid
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_media_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // E. Get Post Thread
    let bob_thread_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getPostThread?space={}&uri={}",
            url_encode(SPACE_1),
            url_encode(&canary_post_at_uri)
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_thread_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // F. Get Feed on Space 1 and Space 2
    let bob_feed_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getFeed?space={}",
            url_encode(SPACE_1)
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_feed_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bob_feed_jwt_2 = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getFeed?space={}",
            url_encode(SPACE_2)
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_feed_jwt_2}"))
        .body(Body::empty())
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 6. Verify captured logs are non-empty, contain real trace logs, and zero private canaries
    let log_output = String::from_utf8_lossy(&log_bytes.lock().unwrap()).to_string();
    assert!(!log_output.is_empty(), "Tracing subscriber should have captured log events");
    assert!(
        log_output.lines().count() >= 5,
        "Tracing should have captured multiple server log events; actual lines: {}",
        log_output.lines().count()
    );

    let forbidden_canaries = [
        ALICE_DID,
        BOB_DID,
        DAVE_DID,
        SPACE_1,
        SPACE_2,
        canary_post_text,
        canary_blob_cid,
        &canary_post_uri,
        canary_report_details,
        "canarycursorxyz",
        "space=at%3A%2F%2F",
        "did=did%3Aplc%3A",
        "cid=bafk",
    ];

    for canary in forbidden_canaries {
        assert!(
            !log_output.contains(canary),
            "Log output leaked private identifier or text: '{canary}'. Captured logs:\n{log_output}"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn notification_hydration_deduplicates_actor_dids(pool: PgPool) {
    let setup = setup_privacy_test(pool.clone()).await;

    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7privacyaaa', $2, 'Dedupe Space', now())
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;

    // Insert 5 notifications all from BOB_DID to ALICE_DID
    for i in 0..5 {
        sqlx::query(
            r#"
            INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
            VALUES ($1, $2, $3, $4, 'like', $5, $6, false, now())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(ALICE_DID)
        .bind(SPACE_1)
        .bind(BOB_DID)
        .bind(format!("{SPACE_1}/app.bsky.feed.post/3l7post{i}"))
        .bind(format!("{SPACE_1}/app.bsky.feed.like/3l7like{i}"))
        .execute(&pool)
        .await
        .unwrap();
    }

    let alice_jwt = mint_jwt(ALICE_DID, "blue.catbird.circle.listNotifications", &setup.alice_key);
    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.listNotifications")
        .header(header::AUTHORIZATION, format!("Bearer {alice_jwt}"))
        .body(Body::empty())
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let output: ListNotificationsOutput = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(output.notifications.len(), 5);
    for notif in output.notifications {
        assert_eq!(notif.actor.did.as_str(), BOB_DID);
    }
}

#[tokio::test]
async fn push_client_logs_only_static_content_on_push_failure() {
    use circle_appview::push::CirclePushClient;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    // Push service returns 502 (delivery failed). The AppView client must surface the
    // error and emit only static log lines — never the recipient DID.
    Mock::given(method("POST"))
        .and(path("/internal/circle/push"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&mock_server)
        .await;

    let log_bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let buffer_writer = TestLogBuffer(log_bytes.clone());
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(buffer_writer)
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    );

    let client = CirclePushClient::new(
        Some(format!("{}/internal/circle/push", mock_server.uri())),
        "did:web:circles.catbird.blue".to_string(),
        "did:web:circles.catbird.blue#atproto_circles".to_string(),
        Some("https://api.catbird.blue".to_string()),
        signing_key,
        reqwest::Client::new(),
    );

    let recipient = BOB_DID;
    let result = client.deliver_circle_activity(recipient).await;
    assert!(result.is_err(), "502 response must surface as an error");

    let output = String::from_utf8_lossy(&log_bytes.lock().unwrap()).to_string();
    assert!(
        !output.contains(recipient),
        "AppView push failure log leaked the recipient DID"
    );
    assert!(
        output.contains("Push endpoint returned error")
            || output.contains("Failed to dispatch push notification trigger"),
        "AppView must log a static failure message"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn sync_mutation_dispatches_generic_push_after_commit(pool: PgPool) {
    use circle_appview::push::CirclePushClient;
    use circle_appview::sync::SyncEngine;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let mock_server = MockServer::start().await;
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);

    let service_did = "did:web:circles.catbird.blue";
    let key_id = "did:web:circles.catbird.blue#atproto_circles";
    let audience = "https://api.catbird.blue";

    Mock::given(method("POST"))
        .and(path("/internal/circle/push"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "delivered": 1
        })))
        .mount(&mock_server)
        .await;

    let push_client = Arc::new(CirclePushClient::new(
        Some(format!("{}/internal/circle/push", mock_server.uri())),
        service_did.to_string(),
        key_id.to_string(),
        Some(audience.to_string()),
        signing_key,
        reqwest::Client::new(),
    ));

    let mut setup = setup_privacy_test(pool.clone()).await;
    setup.state.push_client = Some(push_client.clone());

    // Create space owned by Alice with Bob as active member
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7privacyaaa', $2, 'Push Test Space', now())
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let cred_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    setup
        .state
        .credential_store
        .insert(
            SPACE_1.to_string(),
            ActiveSpaceCredential {
                token: "space-cred".into(),
                dpop_key: cred_key,
                expires_at: Utc::now() + Duration::hours(1),
            },
        )
        .await;

    // Alice creates post P1
    let post_rkey = "3l7postp1aaaa";
    let post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/{post_rkey}");
    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Alice post for reply test",
        "createdAt": "2026-08-24T12:00:00Z"
    });
    let post_cid = circle_appview::commit::compute_dagcbor_cid(&post_val).unwrap();
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', $5, $6, now())
        "#,
    )
    .bind(&post_uri)
    .bind(&post_cid)
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(post_rkey)
    .bind(&post_val)
    .execute(&pool)
    .await
    .unwrap();

    let reply_rkey = "3l7bbbbbbbbbb";
    let reply_value = json!({
        "$type": "app.bsky.feed.post",
        "text": "Bob reply to Alice",
        "createdAt": "2026-08-24T12:01:00Z",
        "reply": {
            "root": { "uri": post_uri.clone(), "cid": post_cid.clone() },
            "parent": { "uri": post_uri.clone(), "cid": post_cid.clone() }
        }
    });
    let reply_cid = circle_appview::commit::compute_dagcbor_cid(&reply_value).unwrap();
    let rec_reply = circle_appview::commit::RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: reply_rkey.to_string(),
        cid: reply_cid,
        value: reply_value,
    };

    let mut lthash = circle_appview::commit::LtHash::default();
    lthash.add(&circle_appview::commit::format_lthash_element(&rec_reply.collection, &rec_reply.rkey, &rec_reply.cid));

    let commit_bob = circle_appview::commit::mint_signed_commit(
        SPACE_1,
        BOB_DID,
        "3l7aaaaaaaaaa",
        &lthash.state(),
        &setup.bob_key,
    );
    let car_bob = circle_appview::commit::mint_repo_car(&commit_bob, &[rec_reply]).unwrap();
    let bob_key = format!("{SPACE_1}:{BOB_DID}");
    setup.mock_transport.set_get_repo_response(&bob_key, car_bob);

    let sync_engine = SyncEngine::new(&setup.state);
    let sync_res = sync_engine
        .sync_repo_with_expected_hash(SPACE_1, BOB_DID, Some(commit_bob.hash.as_ref()))
        .await
        .unwrap();
    assert_eq!(sync_res.records_accepted, 1);
    // Verify notification was created in DB for Alice
    let notif_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM circle_notifications WHERE recipient_did = $1 AND reason = 'reply'",
    )
    .bind(ALICE_DID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(notif_count.0, 1);

    // Verify Wiremock received the push trigger for Alice
    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["recipientDid"], ALICE_DID);

    // Privacy assertions: verify payload is content-free
    let body_str = String::from_utf8_lossy(&requests[0].body);
    assert!(!body_str.contains("Bob reply to Alice"), "Push payload leaked post text");
    assert!(!body_str.contains("Push Test Space"), "Push payload leaked Circle name");
    assert!(!body_str.contains(BOB_DID), "Push payload leaked actor DID");
    assert!(!body_str.contains(&post_uri), "Push payload leaked record URI");
}
