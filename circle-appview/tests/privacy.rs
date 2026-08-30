use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
use catbird_atproto::generated::blue_catbird::circle::list_notifications::ListNotificationsOutput;
use catbird_atproto::generated::blue_catbird::circle::report_record::ReportRecordOutput;
use catbird_atproto::generated::blue_catbird::circle::NotificationReason;
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
const SPACE_2: &str =
    "at://did:plc:dave-privacy-unauthorized/space/blue.catbird.circle/3l7privacy2";

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

async fn grant_active_member(
    pool: &PgPool,
    space_uri: &str,
    member_did: &str,
    _duration: Duration,
) {
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
        commit_verification_policy:
            circle_appview::commit::CommitVerificationPolicy::ExplicitMigrationPermitV1,
    };

    let mock_transport = Arc::new(circle_appview::space_client::MockSpaceHostTransport::new());
    let space_client = Arc::new(circle_appview::space_client::SpaceClient::with_transport(
        mock_transport.clone(),
    ));
    let did_resolver = Arc::new(circle_appview::auth::DidResolver::new(
        "https://plc.directory".into(),
        reqwest::Client::new(),
    ));
    let credential_store = Arc::new(circle_appview::access::CredentialStore::new());
    let space_locks = Arc::new(circle_appview::access::SpaceLockManager::new());
    let profile_hydrator = Arc::new(circle_appview::hydration::ProfileHydrator::new(
        config.public_appview_url.clone(),
        reqwest::Client::new(),
    ));
    let oauth_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
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

    mock_transport.set_space_members(SPACE_1, vec![ALICE_DID.to_string(), BOB_DID.to_string()]);
    mock_transport.set_space_config(
        SPACE_1,
        circle_appview::space_client::SpaceConfig {
            authority: ALICE_DID.to_string(),
            space_type: "blue.catbird.circle".to_string(),
            skey: "skey-1".to_string(),
            app_access: circle_appview::space_client::SpaceAppAccess::AllowList(vec![
                oauth_service.client_id.clone(),
                CIRCLE_AUDIENCE.to_string(),
            ]),
            user_policy: None,
            name: Some("Space 1".to_string()),
            description: Some("Test Space 1".to_string()),
        },
    );

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
    let alice_session = circle_appview::oauth::UserOAuthSession {
        user_did: ALICE_DID.to_string(),
        access_token: "alice-valid-token".to_string(),
        refresh_token: None,
        token_endpoint: "https://pds.alice.test/oauth/token".to_string(),
        auth_server_iss: "https://pds.alice.test".to_string(),
        expires_at: Some(Utc::now() + Duration::hours(1)),
        scope: "blue.catbird.circle".to_string(),
        dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
    };
    state
        .oauth_service
        .store_session(alice_session)
        .await
        .unwrap();
    mock_transport.set_authority_signing_key(ALICE_DID, alice_key.clone());

    register_did_doc(
        &state.did_resolver,
        ALICE_DID,
        &alice_key,
        Some("https://pds.alice.test"),
    );
    register_did_doc(
        &state.did_resolver,
        BOB_DID,
        &bob_key,
        Some("https://pds.bob.test"),
    );
    register_did_doc(
        &state.did_resolver,
        DAVE_DID,
        &dave_key,
        Some("https://pds.dave.test"),
    );
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
    let dave_notif_jwt = mint_jwt(
        DAVE_DID,
        "blue.catbird.circle.listNotifications",
        &setup.dave_key,
    );
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
    let alice_notif_jwt = mint_jwt(
        ALICE_DID,
        "blue.catbird.circle.listNotifications",
        &setup.alice_key,
    );
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
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": SPACE_1,
                "uri": post_space1_std,
                "reason": "spam",
                "details": "Spam in circle"
            }))
            .unwrap(),
        ))
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
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": SPACE_1,
                "uri": post_space2_std,
                "reason": "spam",
            }))
            .unwrap(),
        ))
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
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": SPACE_1,
                "uri": post_space1_std,
                "reason": "spam",
                "details": "Private spam report"
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp = setup.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let report_output: ReportRecordOutput = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!report_output.id.as_str().is_empty());

    // 4. Verify report is stored in database
    let report_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM circle_reports WHERE space_uri = $1")
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
    let bob_lease: Option<(String,)> = sqlx::query_as(
        "SELECT member_did FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(SPACE_1)
    .bind(BOB_DID)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(bob_lease.is_none());

    // Verify Bob's notifications in SPACE_1 are purged
    let bob_notif: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM circle_notifications WHERE space_uri = $1 AND recipient_did = $2",
    )
    .bind(SPACE_1)
    .bind(BOB_DID)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(bob_notif.is_none());

    // Verify Bob's published record is NOT deleted
    let bob_record: Option<(String,)> =
        sqlx::query_as("SELECT uri FROM circle_records WHERE uri = $1 AND deleted_at IS NULL")
            .bind(&bob_post)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(bob_record.is_some());

    // 2. Deactivate Bob's account
    deactivate_author(&pool, BOB_DID).await.unwrap();

    // Verify Bob's record is now soft-deleted (deleted_at is NOT NULL)
    let bob_record_active: Option<(String,)> =
        sqlx::query_as("SELECT uri FROM circle_records WHERE uri = $1 AND deleted_at IS NULL")
            .bind(&bob_post)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(bob_record_active.is_none());

    // Verify actor-sourced notifications where Bob is actor are also purged upon deactivation
    let bob_actor_notif: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM circle_notifications WHERE actor_did = $1")
            .bind(BOB_DID)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(bob_actor_notif.is_none());
    // 3. Delete SPACE_1
    delete_space(&pool, &setup.state.credential_store, SPACE_1)
        .await
        .unwrap();

    // Verify Space rows cascaded
    let circle_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM circles WHERE space_uri = $1 AND deleted_at IS NULL")
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
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7privacyaaa', $2, 'Media Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    // Insert active accepted record referencing blob_cid
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, 'bafyrec1', $2, $3, 'app.bsky.feed.post', '3l7post1', $4, now())
        "#,
    )
    .bind(format!("{SPACE_1}/app.bsky.feed.post/3l7post1"))
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(json!({
        "$type": "app.bsky.feed.post",
        "text": "Post with image",
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [
                {
                    "alt": "test image",
                    "image": {
                        "$type": "blob",
                        "ref": { "$link": "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku" },
                        "mimeType": "image/png",
                        "size": 10
                    }
                },
                {
                    "alt": "oversize image",
                    "image": {
                        "$type": "blob",
                        "ref": { "$link": "bafkreioversizeblobbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
                        "mimeType": "image/jpeg",
                        "size": 22000000
                    }
                }
            ]
        }
    }))
    .execute(&pool)
    .await
    .unwrap();
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
    let blob_cid = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
    let mock_bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00]; // PNG header + bytes
    setup.mock_transport.set_blob_response(
        &format!("{SPACE_1}:{ALICE_DID}:{blob_cid}"),
        Some("image/png".to_string()),
        mock_bytes.clone(),
    );

    let oversize_cid = "bafkreioversizeblobbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let oversize_bytes = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG header (simulated oversize)
    setup.mock_transport.set_blob_response(
        &format!("{SPACE_1}:{ALICE_DID}:{oversize_cid}"),
        Some("image/jpeg".to_string()),
        oversize_bytes,
    );
    let app = create_router(setup.state.clone());

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
    assert_eq!(body_bytes.as_ref(), &mock_bytes);

    // Test blob exceeding 20 MiB limit is rejected
    let oversize_cid = "bafkreioversizeblobbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let oversize_bytes = vec![0u8; 21 * 1024 * 1024]; // 21 MiB
    setup.mock_transport.set_blob_response(
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
    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;
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
    let space_client = Arc::new(circle_appview::space_client::SpaceClient::with_transport(
        mock_transport.clone(),
    ));

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
    setup
        .state
        .did_resolver
        .insert_cached(custom_pds_did.to_string(), wrong_id_doc);
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, 'bafyrec1', $2, $3, 'app.bsky.feed.post', '3l7post1', $4, now())
        "#,
    )
    .bind(format!("{SPACE_1}/app.bsky.feed.post/3l7post1"))
    .bind(SPACE_1)
    .bind(custom_pds_did)
    .bind(json!({
        "$type": "app.bsky.feed.post",
        "text": "Post with image",
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [{ "image": { "ref": { "$link": blob_cid } } }]
        }
    }))
    .execute(&pool)
    .await
    .unwrap();

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
    assert_eq!(
        resp1.status(),
        StatusCode::NOT_FOUND,
        "Wrong service ID must be rejected"
    );

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
    setup
        .state
        .did_resolver
        .insert_cached(suffix_did.to_string(), suffix_doc);
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, 'bafyrec2', $2, $3, 'app.bsky.feed.post', '3l7post2', $4, now())
        "#,
    )
    .bind(format!("{SPACE_1}/app.bsky.feed.post/3l7post2"))
    .bind(SPACE_1)
    .bind(suffix_did)
    .bind(json!({
        "$type": "app.bsky.feed.post",
        "text": "Post with image",
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [{ "image": { "ref": { "$link": blob_cid } } }]
        }
    }))
    .execute(&pool)
    .await
    .unwrap();

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
    assert_eq!(
        resp2.status(),
        StatusCode::NOT_FOUND,
        "Suffix service ID must be rejected"
    );
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
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7privacyaaa', $2, 'Logged Space 1', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7privacybbb', $2, 'Logged Space 2', now(), true)
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
    let canary_blob_cid = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
    let canary_post_rkey = "3l7canaryrkey";
    let canary_post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/{canary_post_rkey}");
    let canary_post_at_uri = format!("at://{ALICE_DID}/app.bsky.feed.post/{canary_post_rkey}");
    let canary_report_details = "Private confidential report details canary 9876";
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, 'bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku', $2, $3, 'app.bsky.feed.post', $4, $5, now())
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
    let bob_notif_jwt = mint_jwt(
        BOB_DID,
        "blue.catbird.circle.listNotifications",
        &setup.bob_key,
    );
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
            .uri(format!(
                "/xrpc/blue.catbird.circle.listNotifications?limit=10&cursor={cursor_val}"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {bob_notif_jwt}"))
            .body(Body::empty())
            .unwrap();
        let resp = setup.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    // B. Update Preferences
    let alice_pref_jwt = mint_jwt(
        ALICE_DID,
        "blue.catbird.circle.updatePreferences",
        &setup.alice_key,
    );
    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.updatePreferences")
        .header(header::AUTHORIZATION, format!("Bearer {alice_pref_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": SPACE_1,
                "muted": true
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = setup.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    if status != StatusCode::OK {
        let b = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        panic!(
            "updatePreferences failed with {status}: {}",
            String::from_utf8_lossy(&b)
        );
    }
    assert_eq!(status, StatusCode::OK);
    // C. Report Record
    let bob_report_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.reportRecord", &setup.bob_key);
    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.reportRecord")
        .header(header::AUTHORIZATION, format!("Bearer {bob_report_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": SPACE_1,
                "uri": canary_post_at_uri,
                "reason": "spam",
                "details": canary_report_details
            }))
            .unwrap(),
        ))
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
            url_encode(canary_blob_cid)
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
    assert!(
        !log_output.is_empty(),
        "Tracing subscriber should have captured log events"
    );
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

    let alice_jwt = mint_jwt(
        ALICE_DID,
        "blue.catbird.circle.listNotifications",
        &setup.alice_key,
    );
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
    lthash.add(&circle_appview::commit::format_lthash_element(
        &rec_reply.collection,
        &rec_reply.rkey,
        &rec_reply.cid,
    ));

    let commit_bob = circle_appview::commit::mint_signed_commit(
        SPACE_1,
        BOB_DID,
        "3l7aaaaaaaaaa",
        &lthash.state(),
        &setup.bob_key,
    );
    let car_bob = circle_appview::commit::mint_repo_car(&commit_bob, &[rec_reply]).unwrap();
    let bob_key = format!("{SPACE_1}:{BOB_DID}");
    setup
        .mock_transport
        .set_get_repo_response(&bob_key, car_bob);

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
    assert!(
        !body_str.contains("Bob reply to Alice"),
        "Push payload leaked post text"
    );
    assert!(
        !body_str.contains("Push Test Space"),
        "Push payload leaked Circle name"
    );
    assert!(!body_str.contains(BOB_DID), "Push payload leaked actor DID");
    assert!(
        !body_str.contains(&post_uri),
        "Push payload leaked record URI"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn local_active_record_cid_authorization_before_media_request_with_uniform_404(pool: PgPool) {
    let setup = setup_privacy_test(pool.clone()).await;

    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7privacymedia', $2, 'Media Auth Space', now())
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

    // Insert post referencing valid CIDv1
    let authorized_blob_cid = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
    sqlx::query(
        r#"
        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at)
        VALUES ($1, 'bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $2, $3, 'app.bsky.feed.post', '3l7authpost', $4, now())
        "#,
    )
    .bind(format!("{SPACE_1}/app.bsky.feed.post/3l7authpost"))
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .bind(json!({
        "$type": "app.bsky.feed.post",
        "text": "Post with authorized image",
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [
                {
                    "alt": "auth img",
                    "image": {
                        "$type": "blob",
                        "ref": { "$link": authorized_blob_cid },
                        "mimeType": "image/png",
                        "size": 10
                    }
                }
            ]
        }
    }))
    .execute(&pool)
    .await
    .unwrap();

    // Set mock response for authorized blob
    let mock_bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    setup.mock_transport.set_blob_response(
        &format!("{SPACE_1}:{ALICE_DID}:{authorized_blob_cid}"),
        Some("image/png".to_string()),
        mock_bytes.clone(),
    );

    let app = create_router(setup.state.clone());
    let bob_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getMedia", &setup.bob_key);

    // 1. Authorized blob -> 200 OK and streams
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
            url_encode(SPACE_1),
            url_encode(ALICE_DID),
            url_encode(authorized_blob_cid),
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(body_bytes.as_ref(), mock_bytes.as_slice());

    // 2. Wildcard injection / malformed CID syntax -> 404 NOT_FOUND without hitting upstream
    let bob_jwt_wildcard = mint_jwt(BOB_DID, "blue.catbird.circle.getMedia", &setup.bob_key);
    let req_wildcard = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid=%",
            url_encode(SPACE_1),
            url_encode(ALICE_DID),
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_jwt_wildcard}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req_wildcard).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 3. Unauthorized / unreferenced valid CID -> 404 NOT_FOUND without hitting upstream mock
    let unauthorized_blob_cid = "bafkreifzjut3w2nh5xutk7f2vr4e67r4dvyw7ojee6xedzdetojuzjevte";
    let bob_jwt_unauth = mint_jwt(BOB_DID, "blue.catbird.circle.getMedia", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
            url_encode(SPACE_1),
            url_encode(ALICE_DID),
            url_encode(unauthorized_blob_cid),
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_jwt_unauth}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 4. Soft-deleted record blob -> 404 NOT_FOUND
    sqlx::query("UPDATE circle_records SET deleted_at = now() WHERE uri = $1")
        .bind(format!("{SPACE_1}/app.bsky.feed.post/3l7authpost"))
        .execute(&pool)
        .await
        .unwrap();

    let bob_jwt_deleted = mint_jwt(BOB_DID, "blue.catbird.circle.getMedia", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
            url_encode(SPACE_1),
            url_encode(ALICE_DID),
            url_encode(authorized_blob_cid),
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_jwt_deleted}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 5. Verify upstream get_blob was invoked EXACTLY once (for the authorized request only)
    assert_eq!(
        setup.mock_transport.recorded_blob_calls().len(),
        1,
        "Zero upstream calls must be made for invalid, wildcard, unreferenced, or deleted CIDs"
    );
}
#[sqlx::test(migrations = "./migrations")]
async fn activity_push_targets_suppressed_when_author_loses_membership(pool: PgPool) {
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
    let push_client = Arc::new(circle_appview::push::CirclePushClient::new(
        Some(format!("{}/internal/circle/push", mock_server.uri())),
        service_did.to_string(),
        key_id.to_string(),
        Some(audience.to_string()),
        signing_key,
        reqwest::Client::new(),
    ));

    let mut setup = setup_privacy_test(pool.clone()).await;
    setup.state.push_client = Some(push_client.clone());

    // Create space
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
        VALUES ($1, '3l7pushsuppress', $2, 'Push Suppress Test', now())
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    // Note: BOB_DID is NOT a member (or lost membership)

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

    // Alice post P1
    let post_rkey = "3l7postp1";
    let post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/{post_rkey}");
    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Alice post",
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

    // Bob (non-member) likes Alice's post
    let like_rkey = "3l7likebob";
    let like_val = json!({
        "$type": "app.bsky.feed.like",
        "subject": { "uri": post_uri, "cid": post_cid },
        "createdAt": "2026-08-24T12:05:00Z"
    });
    let rec_like = circle_appview::commit::RepoRecord {
        collection: "app.bsky.feed.like".to_string(),
        rkey: like_rkey.to_string(),
        cid: circle_appview::commit::compute_dagcbor_cid(&like_val).unwrap(),
        value: like_val,
    };

    let mut lthash = circle_appview::commit::LtHash::default();
    lthash.add(&circle_appview::commit::format_lthash_element(
        &rec_like.collection,
        &rec_like.rkey,
        &rec_like.cid,
    ));

    let commit_bob = circle_appview::commit::mint_signed_commit(
        SPACE_1,
        BOB_DID,
        "3l7aaaaaaaaaa",
        &lthash.state(),
        &setup.bob_key,
    );
    let car_bob = circle_appview::commit::mint_repo_car(&commit_bob, &[rec_like]).unwrap();
    let bob_key = format!("{SPACE_1}:{BOB_DID}");
    setup
        .mock_transport
        .set_get_repo_response(&bob_key, car_bob);

    let sync_engine = SyncEngine::new(&setup.state);
    let _ = sync_engine
        .sync_repo_with_expected_hash(SPACE_1, BOB_DID, Some(commit_bob.hash.as_ref()))
        .await;

    // Verify NO push notification was dispatched because Bob is not a member of the space
    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        0,
        "Non-member author must not trigger activity push notifications"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn app_access_revocation_invalidates_all_private_surfaces_immediately(pool: PgPool) {
    use circle_appview::purge::revoke_app_access;

    let setup = setup_privacy_test(pool.clone()).await;

    // Create active space with Alice as owner and Bob as member
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7appaccess', $2, 'AppAccess Revoke Space', now(), true)
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
                token: "space-cred-live".into(),
                dpop_key: cred_key,
                expires_at: Utc::now() + Duration::hours(1),
            },
        )
        .await;

    let post_rkey = "3l7post1";
    let post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/{post_rkey}");
    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post for appAccess test",
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [{ "image": { "ref": { "$link": "bafkreiblob1" } } }]
        },
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

    // Insert notification
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
    .bind(&post_uri)
    .bind(format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.like/3l7like1"))
    .execute(&pool)
    .await
    .unwrap();

    let app = create_router(setup.state.clone());

    // Perform revocation of appAccess
    revoke_app_access(&pool, &setup.state.credential_store, SPACE_1)
        .await
        .unwrap();

    // 1. Verify credential was removed from CredentialStore
    assert!(setup.state.credential_store.get(SPACE_1).await.is_none());

    // 2. Test getFeed immediately excludes the revoked space
    let bob_feed_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getFeed?space={}",
            url_encode(SPACE_1)
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_feed_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::OK);

    // 3. Test getPostThread immediately denies access
    let bob_thread_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getPostThread?uri={}&space={}",
            url_encode(&post_uri),
            url_encode(SPACE_1)
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_thread_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::OK);

    // 4. Test getMedia immediately denies access
    let bob_media_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getMedia", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid=bafkreiblob1",
            url_encode(SPACE_1),
            url_encode(ALICE_DID)
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_media_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::OK);

    // 5. Test listCircles immediately excludes the space
    let bob_circles_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.listCircles", &setup.bob_key);
    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.listCircles")
        .header(header::AUTHORIZATION, format!("Bearer {bob_circles_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let circles_out: catbird_atproto::generated::blue_catbird::circle::list_circles::ListCirclesOutput =
        serde_json::from_slice(&body).unwrap();
    assert!(circles_out
        .circles
        .iter()
        .all(|c| c.uri.as_str() != SPACE_1));

    // 6. Test listNotifications immediately excludes notifications from the revoked space
    let bob_notif_jwt = mint_jwt(
        BOB_DID,
        "blue.catbird.circle.listNotifications",
        &setup.bob_key,
    );
    let req = Request::builder()
        .uri("/xrpc/blue.catbird.circle.listNotifications")
        .header(header::AUTHORIZATION, format!("Bearer {bob_notif_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let notifs_out: catbird_atproto::generated::blue_catbird::circle::list_notifications::ListNotificationsOutput =
        serde_json::from_slice(&body).unwrap();
    assert!(notifs_out
        .notifications
        .iter()
        .all(|n| n.circle.uri.as_str() != SPACE_1));
}

#[sqlx::test(migrations = "./migrations")]
async fn member_removal_revokes_private_reads_immediately(pool: PgPool) {
    use circle_appview::purge::remove_member;

    let setup = setup_privacy_test(pool.clone()).await;

    // Create space
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7memberrevoke', $2, 'Member Revoke Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    let post_rkey = "3l7postmem";
    let post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/{post_rkey}");
    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Post for member removal test",
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [{ "image": { "ref": { "$link": "bafkreiblobmem" } } }]
        },
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

    let app = create_router(setup.state.clone());

    // Remove Bob from member list in DB and mock transport
    setup
        .mock_transport
        .set_space_members(SPACE_1, vec![ALICE_DID.to_string()]);
    remove_member(&pool, SPACE_1, BOB_DID).await.unwrap();

    // 1. getFeed immediately denies Bob
    let bob_feed_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getFeed", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getFeed?space={}",
            url_encode(SPACE_1)
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_feed_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::OK);

    // 2. getPostThread immediately denies Bob
    let bob_thread_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getPostThread", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getPostThread?uri={}&space={}",
            url_encode(&post_uri),
            url_encode(SPACE_1)
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_thread_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::OK);

    // 3. getMedia immediately denies Bob
    let bob_media_jwt = mint_jwt(BOB_DID, "blue.catbird.circle.getMedia", &setup.bob_key);
    let req = Request::builder()
        .uri(format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid=bafkreiblobmem",
            url_encode(SPACE_1),
            url_encode(ALICE_DID)
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bob_media_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::OK);

    // 4. updatePreferences immediately denies Bob
    let bob_pref_jwt = mint_jwt(
        BOB_DID,
        "blue.catbird.circle.updatePreferences",
        &setup.bob_key,
    );
    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.circle.updatePreferences")
        .header(header::AUTHORIZATION, format!("Bearer {bob_pref_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": SPACE_1,
                "muted": true
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn app_access_revocation_via_refresh_and_reactivation_lifecycle(pool: PgPool) {
    use circle_appview::access::{activate_circle, refresh_member_cache};
    use circle_appview::purge::revoke_app_access;

    let setup = setup_privacy_test(pool.clone()).await;

    // 1. Initial activation of space
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7aaaaaaaabb', $2, 'Lifecycle Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;
    grant_active_member(&pool, SPACE_1, BOB_DID, Duration::hours(1)).await;

    // Verify refresh succeeds and assigns synchronized epoch
    let members = refresh_member_cache(&setup.state, SPACE_1).await.unwrap();
    assert!(members.contains(&ALICE_DID.to_string()));

    let (circle_epoch, circle_app_access): (i64, bool) =
        sqlx::query_as("SELECT access_epoch, app_access_granted FROM circles WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();

    let (meta_epoch, meta_app_access): (i64, bool) = sqlx::query_as(
        "SELECT access_epoch, app_access_granted FROM circle_member_cache_meta WHERE space_uri = $1",
    )
    .bind(SPACE_1)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(circle_epoch, meta_epoch);
    assert!(circle_app_access);
    assert!(meta_app_access);

    // 2. Revoke appAccess
    revoke_app_access(&pool, &setup.state.credential_store, SPACE_1)
        .await
        .unwrap();

    let (revoked_access, deleted_at): (bool, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT app_access_granted, deleted_at FROM circles WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!revoked_access);
    assert!(deleted_at.is_some());

    // 3. refresh_member_cache must fail-closed and NOT resurrect app_access_granted
    let refresh_res = refresh_member_cache(&setup.state, SPACE_1).await;
    assert!(
        refresh_res.is_err(),
        "refresh_member_cache must fail closed for revoked space"
    );

    let (meta_app_access_after,): (bool,) = sqlx::query_as(
        "SELECT app_access_granted FROM circle_member_cache_meta WHERE space_uri = $1",
    )
    .bind(SPACE_1)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !meta_app_access_after,
        "refresh must not resurrect meta app_access_granted"
    );

    // 4. Re-activate circle (owner re-granted appAccess)
    let meta_val = json!({
        "$type": "blue.catbird.circle.metadata",
        "circleId": "3l7aaaaaaaabb",
        "name": "Lifecycle Space Re-activated",
        "createdAt": "2026-08-24T12:00:00Z"
    });
    let meta_cid = circle_appview::commit::compute_dagcbor_cid(&meta_val).unwrap();
    let rec_meta = circle_appview::commit::RepoRecord {
        collection: "blue.catbird.circle.metadata".into(),
        rkey: "self".into(),
        cid: meta_cid,
        value: meta_val,
    };
    let mut lthash = circle_appview::commit::LtHash::default();
    lthash.add(&circle_appview::commit::format_lthash_element(
        &rec_meta.collection,
        &rec_meta.rkey,
        &rec_meta.cid,
    ));
    let commit = circle_appview::commit::mint_signed_commit(
        SPACE_1,
        ALICE_DID,
        "3l7aaaaaaaaaa",
        &lthash.state(),
        &setup.alice_key,
    );
    let car_bytes = circle_appview::commit::mint_repo_car(&commit, &[rec_meta]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_1}:{ALICE_DID}"), car_bytes);
    let reactivated = activate_circle(&setup.state, ALICE_DID, SPACE_1)
        .await
        .unwrap();
    assert_eq!(reactivated.name.as_str(), "Lifecycle Space Re-activated");

    let (restored_access, restored_deleted): (bool, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT app_access_granted, deleted_at FROM circles WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        restored_access,
        "Re-activation must restore app_access_granted = true"
    );
    assert!(
        restored_deleted.is_none(),
        "Re-activation must clear deleted_at"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn notify_write_authorizes_membership_and_app_access_before_lock(pool: PgPool) {
    use circle_appview::purge::revoke_app_access;

    let setup = setup_privacy_test(pool.clone()).await;

    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7notify', $2, 'Notify Auth Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    grant_active_member(&pool, SPACE_1, ALICE_DID, Duration::hours(1)).await;

    let app = create_router(setup.state.clone());

    // Mint service token for notifyWrite
    let alice_jwt = mint_jwt(ALICE_DID, "com.atproto.space.notifyWrite", &setup.alice_key);
    let dave_jwt = mint_jwt(DAVE_DID, "com.atproto.space.notifyWrite", &setup.dave_key);

    let notify_dave = catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite {
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0u8; 32]),
        repo: catbird_atproto::jacquard_common::types::string::Did::from(String::from(DAVE_DID)),
        rev: catbird_atproto::jacquard_common::types::string::Tid::from(String::from(
            "3l7aaaaaaaaaa",
        )),
        space: catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new_owned(SPACE_1)
            .unwrap(),
        extra_data: None,
    };
    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.notifyWrite")
        .header(header::AUTHORIZATION, format!("Bearer {dave_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&notify_dave).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Revoked appAccess rejects notifyWrite
    revoke_app_access(&pool, &setup.state.credential_store, SPACE_1)
        .await
        .unwrap();

    let notify_alice = catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite {
        hash: catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0u8; 32]),
        repo: catbird_atproto::jacquard_common::types::string::Did::from(String::from(ALICE_DID)),
        rev: catbird_atproto::jacquard_common::types::string::Tid::from(String::from(
            "3l7aaaaaaaaaa",
        )),
        space: catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new_owned(SPACE_1)
            .unwrap(),
        extra_data: None,
    };
    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.notifyWrite")
        .header(header::AUTHORIZATION, format!("Bearer {alice_jwt}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&notify_alice).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_space_transport_or_auth_error_does_not_purge_circle_data(pool: PgPool) {
    use circle_appview::access::refresh_member_cache;

    let setup = setup_privacy_test(pool.clone()).await;

    // 1. Setup active circle with a record
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7aaaaaaaabb', $2, 'Active Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (space_uri, uri, cid, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, 'bafytest', $3, 'app.bsky.feed.post', 'post1', '{"text":"hello"}'::jsonb, now(), now())
        "#,
    )
    .bind(SPACE_1)
    .bind(format!("{SPACE_1}/app.bsky.feed.post/post1"))
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Mock get_space to return an upstream auth/network error
    setup
        .mock_transport
        .set_space_config_error(SPACE_1, "OAuth token expired / PDS unavailable".into());

    // 3. refresh_member_cache should fail with Forbidden (non-destructive denial)
    let res = refresh_member_cache(&setup.state, SPACE_1).await;
    assert!(
        res.is_err(),
        "refresh_member_cache must fail when upstream is unavailable"
    );

    // 4. Circle data MUST NOT be purged
    let (app_access, deleted_at): (bool, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT app_access_granted, deleted_at FROM circles WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        app_access,
        "Circle app_access_granted must remain true on transport/auth error"
    );
    assert!(
        deleted_at.is_none(),
        "Circle deleted_at must remain NULL on transport/auth error"
    );

    let record_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM circle_records WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        record_count.0, 1,
        "circle_records must NOT be purged on upstream error"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn circle_activation_generates_notifications_for_members(pool: PgPool) {
    use circle_appview::access::activate_circle;

    let setup = setup_privacy_test(pool.clone()).await;

    use circle_appview::sync::SyncEngine;

    // 1. Alice's repo has: metadata and a root post
    let meta_val = json!({
        "$type": "blue.catbird.circle.metadata",
        "circleId": "3l7aaaaaaaabb",
        "name": "Notification Activation Space",
        "createdAt": "2026-08-24T12:00:00Z"
    });
    let meta_cid = circle_appview::commit::compute_dagcbor_cid(&meta_val).unwrap();
    let rec_meta = circle_appview::commit::RepoRecord {
        collection: "blue.catbird.circle.metadata".into(),
        rkey: "self".into(),
        cid: meta_cid,
        value: meta_val,
    };

    let post_val = json!({
        "$type": "app.bsky.feed.post",
        "text": "Alice initial post during activation",
        "createdAt": "2026-08-24T12:01:00Z"
    });
    let post_cid = circle_appview::commit::compute_dagcbor_cid(&post_val).unwrap();
    let rec_post = circle_appview::commit::RepoRecord {
        collection: "app.bsky.feed.post".into(),
        rkey: "3l7alicepost".into(),
        cid: post_cid.clone(),
        value: post_val,
    };
    let alice_post_uri = format!("{SPACE_1}/{ALICE_DID}/app.bsky.feed.post/3l7alicepost");

    let mut lthash_alice = circle_appview::commit::LtHash::default();
    lthash_alice.add(&circle_appview::commit::format_lthash_element(
        &rec_meta.collection,
        &rec_meta.rkey,
        &rec_meta.cid,
    ));
    lthash_alice.add(&circle_appview::commit::format_lthash_element(
        &rec_post.collection,
        &rec_post.rkey,
        &rec_post.cid,
    ));

    let commit_alice = circle_appview::commit::mint_signed_commit(
        SPACE_1,
        ALICE_DID,
        "3l7aaaaaaaaaa",
        &lthash_alice.state(),
        &setup.alice_key,
    );
    let car_alice =
        circle_appview::commit::mint_repo_car(&commit_alice, &[rec_meta, rec_post]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_1}:{ALICE_DID}"), car_alice);

    // 2. Activate circle (runs refresh_member_cache then sync_repo for Alice)
    activate_circle(&setup.state, ALICE_DID, SPACE_1)
        .await
        .unwrap();

    // 3. Bob (member) writes a like on Alice's post
    let like_val = json!({
        "$type": "app.bsky.feed.like",
        "subject": { "uri": &alice_post_uri, "cid": &post_cid },
        "createdAt": "2026-08-24T12:05:00Z"
    });
    let like_cid = circle_appview::commit::compute_dagcbor_cid(&like_val).unwrap();
    let rec_like = circle_appview::commit::RepoRecord {
        collection: "app.bsky.feed.like".into(),
        rkey: "3l7boblike".into(),
        cid: like_cid,
        value: like_val,
    };

    let mut lthash_bob = circle_appview::commit::LtHash::default();
    lthash_bob.add(&circle_appview::commit::format_lthash_element(
        &rec_like.collection,
        &rec_like.rkey,
        &rec_like.cid,
    ));

    let commit_bob = circle_appview::commit::mint_signed_commit(
        SPACE_1,
        BOB_DID,
        "3l7aaaaaaaaaa",
        &lthash_bob.state(),
        &setup.bob_key,
    );
    let car_bob = circle_appview::commit::mint_repo_car(&commit_bob, &[rec_like]).unwrap();
    setup
        .mock_transport
        .set_get_repo_response(&format!("{SPACE_1}:{BOB_DID}"), car_bob);

    let sync_engine = SyncEngine::new(&setup.state);
    sync_engine.sync_repo(SPACE_1, BOB_DID).await.unwrap();

    // Assert that notifications were generated for Alice
    let notif_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM circle_notifications WHERE space_uri = $1 AND recipient_did = $2",
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        notif_count.0, 1,
        "Notifications must be generated for Alice when Bob likes her post"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn app_access_open_policy_grants_access_and_preserves_projected_data(pool: PgPool) {
    use circle_appview::access::refresh_member_cache;
    use circle_appview::space_client::{SpaceAppAccess, SpaceConfig};

    let setup = setup_privacy_test(pool.clone()).await;

    // 1. Setup active circle with a record
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7openpolicy', $2, 'Open Policy Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (space_uri, uri, cid, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, 'bafyopen', $3, 'app.bsky.feed.post', 'openpost', '{"text":"open text"}'::jsonb, now(), now())
        "#,
    )
    .bind(SPACE_1)
    .bind(format!("{SPACE_1}/app.bsky.feed.post/openpost"))
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Mock get_space returning #open policy
    setup.mock_transport.set_space_config(
        SPACE_1,
        SpaceConfig {
            authority: ALICE_DID.to_string(),
            space_type: "blue.catbird.circle".to_string(),
            skey: "skey-open".to_string(),
            app_access: SpaceAppAccess::Open,
            user_policy: None,
            name: Some("Open Policy Space".to_string()),
            description: None,
        },
    );

    // 3. refresh_member_cache should succeed
    let res = refresh_member_cache(&setup.state, SPACE_1).await;
    assert!(
        res.is_ok(),
        "refresh_member_cache must succeed under #open policy: {:?}",
        res.err()
    );

    // 4. Circle data MUST NOT be purged
    let (app_access, deleted_at): (bool, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT app_access_granted, deleted_at FROM circles WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        app_access,
        "Circle app_access_granted must remain true under #open policy"
    );
    assert!(
        deleted_at.is_none(),
        "Circle deleted_at must remain NULL under #open policy"
    );

    let record_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM circle_records WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        record_count.0, 1,
        "circle_records must NOT be purged under #open policy"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn app_access_explicit_allow_list_omitting_client_revokes_and_purges_data(pool: PgPool) {
    use circle_appview::access::refresh_member_cache;
    use circle_appview::space_client::{SpaceAppAccess, SpaceConfig};

    let setup = setup_privacy_test(pool.clone()).await;

    // 1. Setup active circle with a record
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7allowomit', $2, 'AllowList Omit Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (space_uri, uri, cid, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, 'bafyomit', $3, 'app.bsky.feed.post', 'omitpost', '{"text":"omit text"}'::jsonb, now(), now())
        "#,
    )
    .bind(SPACE_1)
    .bind(format!("{SPACE_1}/app.bsky.feed.post/omitpost"))
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Mock get_space returning #allowList that explicitly omits this AppView's client_id
    setup.mock_transport.set_space_config(
        SPACE_1,
        SpaceConfig {
            authority: ALICE_DID.to_string(),
            space_type: "blue.catbird.circle".to_string(),
            skey: "skey-omit".to_string(),
            app_access: SpaceAppAccess::AllowList(vec!["did:example:other-appview".to_string()]),
            user_policy: None,
            name: Some("AllowList Omit Space".to_string()),
            description: None,
        },
    );

    // 3. refresh_member_cache should fail with Forbidden
    let res = refresh_member_cache(&setup.state, SPACE_1).await;
    assert!(
        res.is_err(),
        "refresh_member_cache must fail when allowList omits client_id"
    );

    // 4. Circle data MUST be revoked and purged
    let (app_access, deleted_at): (bool, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT app_access_granted, deleted_at FROM circles WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        !app_access,
        "Circle app_access_granted must be set to false on explicit allowList omission"
    );
    assert!(
        deleted_at.is_some(),
        "Circle deleted_at must be populated on explicit allowList omission"
    );

    let record_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM circle_records WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        record_count.0, 0,
        "circle_records MUST be purged on explicit allowList revocation"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn app_access_unrecognized_variant_denies_without_purging_data(pool: PgPool) {
    use circle_appview::access::refresh_member_cache;
    use circle_appview::space_client::{SpaceAppAccess, SpaceConfig};

    let setup = setup_privacy_test(pool.clone()).await;

    // 1. Setup active circle with a record
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7unknownpolicy', $2, 'Unknown Policy Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (space_uri, uri, cid, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, 'bafyunknown', $3, 'app.bsky.feed.post', 'unknownpost', '{"text":"unknown text"}'::jsonb, now(), now())
        "#,
    )
    .bind(SPACE_1)
    .bind(format!("{SPACE_1}/app.bsky.feed.post/unknownpost"))
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Mock get_space returning an unrecognized future union policy
    setup.mock_transport.set_space_config(
        SPACE_1,
        SpaceConfig {
            authority: ALICE_DID.to_string(),
            space_type: "blue.catbird.circle".to_string(),
            skey: "skey-unknown".to_string(),
            app_access: SpaceAppAccess::Unknown(Some("com.future.policy#customPolicy".to_string())),
            user_policy: None,
            name: Some("Unknown Policy Space".to_string()),
            description: None,
        },
    );

    // 3. refresh_member_cache should fail with Forbidden (fail-closed denial)
    let res = refresh_member_cache(&setup.state, SPACE_1).await;
    assert!(
        res.is_err(),
        "refresh_member_cache must fail closed on unrecognized policy"
    );

    // 4. Circle data MUST NOT be purged
    let (app_access, deleted_at): (bool, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT app_access_granted, deleted_at FROM circles WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        app_access,
        "Circle app_access_granted must remain true on unrecognized policy"
    );
    assert!(
        deleted_at.is_none(),
        "Circle deleted_at must remain NULL on unrecognized policy"
    );

    let record_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM circle_records WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        record_count.0, 1,
        "circle_records must NOT be purged on unrecognized policy"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn app_access_absent_allowed_array_denies_without_purging_data(pool: PgPool) {
    use circle_appview::access::refresh_member_cache;
    use circle_appview::space_client::{SpaceAppAccess, SpaceConfig};
    use serde_json::json;

    let setup = setup_privacy_test(pool.clone()).await;

    // 1. Setup active circle with a record
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7absentpolicy', $2, 'Absent Allowed Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (space_uri, uri, cid, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, 'bafyabsent', $3, 'app.bsky.feed.post', 'absentpost', '{"text":"absent text"}'::jsonb, now(), now())
        "#,
    )
    .bind(SPACE_1)
    .bind(format!("{SPACE_1}/app.bsky.feed.post/absentpost"))
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Parse wire json missing allowed array
    let wire_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList"
    });
    let parsed_access = SpaceAppAccess::parse(&wire_json);

    setup.mock_transport.set_space_config(
        SPACE_1,
        SpaceConfig {
            authority: ALICE_DID.to_string(),
            space_type: "blue.catbird.circle".to_string(),
            skey: "skey-absent".to_string(),
            app_access: parsed_access,
            user_policy: None,
            name: Some("Absent Allowed Space".to_string()),
            description: None,
        },
    );

    // 3. refresh_member_cache must fail closed
    let res = refresh_member_cache(&setup.state, SPACE_1).await;
    assert!(
        res.is_err(),
        "refresh_member_cache must fail closed on absent allowed array"
    );

    // 4. Circle data MUST NOT be purged
    let (app_access, deleted_at): (bool, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT app_access_granted, deleted_at FROM circles WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        app_access,
        "Circle app_access_granted must remain true when allowed array is absent"
    );
    assert!(
        deleted_at.is_none(),
        "Circle deleted_at must remain NULL when allowed array is absent"
    );

    let record_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM circle_records WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        record_count.0, 1,
        "circle_records must NOT be purged when allowed array is absent"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn app_access_explicit_empty_allowed_array_revokes_and_purges_data(pool: PgPool) {
    use circle_appview::access::refresh_member_cache;
    use circle_appview::space_client::{SpaceAppAccess, SpaceConfig};
    use serde_json::json;

    let setup = setup_privacy_test(pool.clone()).await;

    // 1. Setup active circle with a record
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7emptypolicy', $2, 'Empty Allowed Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (space_uri, uri, cid, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, 'bafyempty', $3, 'app.bsky.feed.post', 'emptypost', '{"text":"empty text"}'::jsonb, now(), now())
        "#,
    )
    .bind(SPACE_1)
    .bind(format!("{SPACE_1}/app.bsky.feed.post/emptypost"))
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Parse wire json with genuine empty allowed array
    let wire_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList",
        "allowed": []
    });
    let parsed_access = SpaceAppAccess::parse(&wire_json);

    setup.mock_transport.set_space_config(
        SPACE_1,
        SpaceConfig {
            authority: ALICE_DID.to_string(),
            space_type: "blue.catbird.circle".to_string(),
            skey: "skey-empty".to_string(),
            app_access: parsed_access,
            user_policy: None,
            name: Some("Empty Allowed Space".to_string()),
            description: None,
        },
    );

    // 3. refresh_member_cache must fail with Forbidden and trigger purge
    let res = refresh_member_cache(&setup.state, SPACE_1).await;
    assert!(
        res.is_err(),
        "refresh_member_cache must fail on explicit empty allowList"
    );

    // 4. Circle data MUST be revoked and purged
    let (app_access, deleted_at): (bool, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT app_access_granted, deleted_at FROM circles WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        !app_access,
        "Circle app_access_granted must be set to false on explicit empty allowList"
    );
    assert!(
        deleted_at.is_some(),
        "Circle deleted_at must be populated on explicit empty allowList"
    );

    let record_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM circle_records WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        record_count.0, 0,
        "circle_records MUST be purged on explicit empty allowList"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn app_access_object_entry_allowed_array_denies_without_purging_data(pool: PgPool) {
    use circle_appview::access::refresh_member_cache;
    use circle_appview::space_client::{SpaceAppAccess, SpaceConfig};
    use serde_json::json;

    let setup = setup_privacy_test(pool.clone()).await;

    // 1. Setup active circle with a record
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7objectentrypolicy', $2, 'Object Entry Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (space_uri, uri, cid, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, 'bafyobjectentry', $3, 'app.bsky.feed.post', 'objectentrypost', '{"text":"object entry text"}'::jsonb, now(), now())
        "#,
    )
    .bind(SPACE_1)
    .bind(format!("{SPACE_1}/app.bsky.feed.post/objectentrypost"))
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Parse wire json with object entries in allowed array
    let wire_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList",
        "allowed": [{"unreadable": true}]
    });
    let parsed_access = SpaceAppAccess::parse(&wire_json);

    setup.mock_transport.set_space_config(
        SPACE_1,
        SpaceConfig {
            authority: ALICE_DID.to_string(),
            space_type: "blue.catbird.circle".to_string(),
            skey: "skey-objectentry".to_string(),
            app_access: parsed_access,
            user_policy: None,
            name: Some("Object Entry Space".to_string()),
            description: None,
        },
    );

    // 3. refresh_member_cache must fail closed
    let res = refresh_member_cache(&setup.state, SPACE_1).await;
    assert!(
        res.is_err(),
        "refresh_member_cache must fail closed on object-entry allowed array"
    );

    // 4. Circle data MUST NOT be purged
    let (app_access, deleted_at): (bool, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT app_access_granted, deleted_at FROM circles WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        app_access,
        "Circle app_access_granted must remain true when allowed array has unreadable entries"
    );
    assert!(
        deleted_at.is_none(),
        "Circle deleted_at must remain NULL when allowed array has unreadable entries"
    );

    let record_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM circle_records WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        record_count.0, 1,
        "circle_records must NOT be purged when allowed array has unreadable entries"
    );
}

#[test]
fn app_access_wire_parsing_discriminates_open_allowlist_and_unknown() {
    use circle_appview::space_client::SpaceAppAccess;
    use serde_json::json;

    let client = "https://circles.catbird.blue/oauth/client-metadata.json";

    // Case 1: #open policy
    let open_json = json!({
        "$type": "com.atproto.simplespace.defs#open"
    });
    let parsed_open = SpaceAppAccess::parse(&open_json);
    assert_eq!(parsed_open, SpaceAppAccess::Open);
    assert!(parsed_open.grants_access(client));
    assert!(!parsed_open.is_explicit_revocation(client));

    // Case 2: #allowList with matching client
    let allow_match_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList",
        "allowed": [client, "other-client"]
    });
    let parsed_match = SpaceAppAccess::parse(&allow_match_json);
    assert_eq!(
        parsed_match,
        SpaceAppAccess::AllowList(vec![client.to_string(), "other-client".to_string()])
    );
    assert!(parsed_match.grants_access(client));
    assert!(!parsed_match.is_explicit_revocation(client));

    // Case 3: #allowList omitting client
    let allow_omit_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList",
        "allowed": ["other-client-only"]
    });
    let parsed_omit = SpaceAppAccess::parse(&allow_omit_json);
    assert_eq!(
        parsed_omit,
        SpaceAppAccess::AllowList(vec!["other-client-only".to_string()])
    );
    assert!(!parsed_omit.grants_access(client));
    assert!(parsed_omit.is_explicit_revocation(client));

    // Case 4: #allowList with genuine empty allowed array (authoritative revocation)
    let allow_empty_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList",
        "allowed": []
    });
    let parsed_empty = SpaceAppAccess::parse(&allow_empty_json);
    assert_eq!(parsed_empty, SpaceAppAccess::AllowList(vec![]));
    assert!(!parsed_empty.grants_access(client));
    assert!(parsed_empty.is_explicit_revocation(client));

    // Case 5: #allowList with absent allowed field (must degrade to Unknown, not purge)
    let allow_absent_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList"
    });
    let parsed_absent = SpaceAppAccess::parse(&allow_absent_json);
    assert_eq!(
        parsed_absent,
        SpaceAppAccess::Unknown(Some("com.atproto.simplespace.defs#allowList".to_string()))
    );
    assert!(!parsed_absent.grants_access(client));
    assert!(!parsed_absent.is_explicit_revocation(client));

    // Case 6: #allowList with null allowed field (must degrade to Unknown, not purge)
    let allow_null_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList",
        "allowed": null
    });
    let parsed_null = SpaceAppAccess::parse(&allow_null_json);
    assert_eq!(
        parsed_null,
        SpaceAppAccess::Unknown(Some("com.atproto.simplespace.defs#allowList".to_string()))
    );
    assert!(!parsed_null.grants_access(client));
    assert!(!parsed_null.is_explicit_revocation(client));

    // Case 7: #allowList with renamed allowed field (must degrade to Unknown, not purge)
    let allow_renamed_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList",
        "permitted": [client]
    });
    let parsed_renamed = SpaceAppAccess::parse(&allow_renamed_json);
    assert_eq!(
        parsed_renamed,
        SpaceAppAccess::Unknown(Some("com.atproto.simplespace.defs#allowList".to_string()))
    );
    assert!(!parsed_renamed.grants_access(client));
    assert!(!parsed_renamed.is_explicit_revocation(client));

    // Case 8: Legacy bare array [] from wire (must degrade to Unknown, not purge)
    let legacy_empty_json = json!([]);
    let parsed_legacy_empty = SpaceAppAccess::parse(&legacy_empty_json);
    assert_eq!(parsed_legacy_empty, SpaceAppAccess::Unknown(None));
    assert!(!parsed_legacy_empty.grants_access(client));
    assert!(!parsed_legacy_empty.is_explicit_revocation(client));

    // Case 9: Legacy bare array with entries
    let legacy_entries_json = json!([client, "other-client"]);
    let parsed_legacy_entries = SpaceAppAccess::parse(&legacy_entries_json);
    assert_eq!(
        parsed_legacy_entries,
        SpaceAppAccess::AllowList(vec![client.to_string(), "other-client".to_string()])
    );
    assert!(parsed_legacy_entries.grants_access(client));
    assert!(!parsed_legacy_entries.is_explicit_revocation(client));

    // Case 10: Unrecognized policy variant
    let unknown_json = json!({
        "$type": "com.custom.future#customAppAccess",
        "customField": true
    });
    let parsed_unknown = SpaceAppAccess::parse(&unknown_json);
    assert_eq!(
        parsed_unknown,
        SpaceAppAccess::Unknown(Some("com.custom.future#customAppAccess".to_string()))
    );
    assert!(!parsed_unknown.grants_access(client));
    assert!(!parsed_unknown.is_explicit_revocation(client));

    // Case 11: #allowList with non-string object entries (must degrade to Unknown, not purge)
    let allow_objects_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList",
        "allowed": [{"bad": "entry"}, {"nested": 123}]
    });
    let parsed_objects = SpaceAppAccess::parse(&allow_objects_json);
    assert_eq!(
        parsed_objects,
        SpaceAppAccess::Unknown(Some("com.atproto.simplespace.defs#allowList".to_string()))
    );
    assert!(!parsed_objects.grants_access(client));
    assert!(!parsed_objects.is_explicit_revocation(client));

    // Case 12: #allowList with partially readable array containing matching client
    let allow_partial_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList",
        "allowed": [client, {"invalid": 123}, 456]
    });
    let parsed_partial = SpaceAppAccess::parse(&allow_partial_json);
    assert_eq!(
        parsed_partial,
        SpaceAppAccess::AllowList(vec![client.to_string()])
    );
    assert!(parsed_partial.grants_access(client));
    assert!(!parsed_partial.is_explicit_revocation(client));

    // Case 13: #allowList with partially readable array omitting client
    let allow_partial_omit_json = json!({
        "$type": "com.atproto.simplespace.defs#allowList",
        "allowed": ["other-client", {"invalid": 123}]
    });
    let parsed_partial_omit = SpaceAppAccess::parse(&allow_partial_omit_json);
    assert_eq!(
        parsed_partial_omit,
        SpaceAppAccess::AllowList(vec!["other-client".to_string()])
    );
    assert!(!parsed_partial_omit.grants_access(client));
    assert!(parsed_partial_omit.is_explicit_revocation(client));

    // Case 14: Untagged object with non-string object entries (must degrade to Unknown, not purge)
    let untagged_objects_json = json!({
        "allowed": [{"bad": "entry"}]
    });
    let parsed_untagged_objects = SpaceAppAccess::parse(&untagged_objects_json);
    assert_eq!(parsed_untagged_objects, SpaceAppAccess::Unknown(None));
    assert!(!parsed_untagged_objects.grants_access(client));
    assert!(!parsed_untagged_objects.is_explicit_revocation(client));

    // Case 15: Untagged object with partially readable array
    let untagged_partial_json = json!({
        "allowed": [client, {"invalid": 123}]
    });
    let parsed_untagged_partial = SpaceAppAccess::parse(&untagged_partial_json);
    assert_eq!(
        parsed_untagged_partial,
        SpaceAppAccess::AllowList(vec![client.to_string()])
    );
    assert!(parsed_untagged_partial.grants_access(client));
    assert!(!parsed_untagged_partial.is_explicit_revocation(client));

    // Case 16: Bare array with non-string entries (must degrade to Unknown, not purge)
    let bare_non_strings_json = json!([{"bad": "entry"}, 123]);
    let parsed_bare_non_strings = SpaceAppAccess::parse(&bare_non_strings_json);
    assert_eq!(parsed_bare_non_strings, SpaceAppAccess::Unknown(None));
    assert!(!parsed_bare_non_strings.grants_access(client));
    assert!(!parsed_bare_non_strings.is_explicit_revocation(client));
}

#[sqlx::test(migrations = "./migrations")]
async fn revocation_durability_commits_state_flip_and_credentials_before_purge(pool: PgPool) {
    use circle_appview::purge::revoke_app_access;

    let setup = setup_privacy_test(pool.clone()).await;

    // 1. Setup active circle with records and in-memory credential
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, app_access_granted)
        VALUES ($1, '3l7durable', $2, 'Durable Space', now(), true)
        "#,
    )
    .bind(SPACE_1)
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO circle_records (space_uri, uri, cid, author_did, collection, rkey, record_json, created_at, indexed_at)
        VALUES ($1, $2, 'bafydurable', $3, 'app.bsky.feed.post', 'postdurable', '{"text":"durable"}'::jsonb, now(), now())
        "#,
    )
    .bind(SPACE_1)
    .bind(format!("{SPACE_1}/app.bsky.feed.post/postdurable"))
    .bind(ALICE_DID)
    .execute(&pool)
    .await
    .unwrap();

    let p256_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    setup
        .state
        .credential_store
        .insert(
            SPACE_1.to_string(),
            circle_appview::access::ActiveSpaceCredential {
                token: "dpop_token_123".into(),
                dpop_key: p256_key,
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            },
        )
        .await;
    assert!(setup.state.credential_store.get(SPACE_1).await.is_some());

    // 2. Perform durable revocation
    revoke_app_access(&pool, &setup.state.credential_store, SPACE_1)
        .await
        .unwrap();

    // 3. Verify gate flag is false, deleted_at is set, epoch is bumped
    let (app_access, deleted_at, epoch): (bool, Option<chrono::DateTime<Utc>>, i64) =
        sqlx::query_as(
            "SELECT app_access_granted, deleted_at, access_epoch FROM circles WHERE space_uri = $1",
        )
        .bind(SPACE_1)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert!(!app_access, "app_access_granted must be durably false");
    assert!(deleted_at.is_some(), "deleted_at must be populated");
    assert!(epoch >= 2, "access_epoch must be advanced");

    // 4. Verify credentials removed immediately
    assert!(
        setup.state.credential_store.get(SPACE_1).await.is_none(),
        "Credentials must be cleared from in-memory store"
    );

    // 5. Verify records purged
    let record_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM circle_records WHERE space_uri = $1")
            .bind(SPACE_1)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(record_count.0, 0, "circle_records must be purged");
}
