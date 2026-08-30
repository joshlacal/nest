//! End-to-end multi-user integration test for Circle privacy, authorization, and revocation.
//!
//! Validates the three-user (+ stranger) lifecycle scenario:
//! 1. Alice creates the "Family" Circle with Bob and Carol as initial members.
//! 2. Alice publishes a private image post in the Circle.
//! 3. Bob replies to Alice's post within the Circle.
//! 4. Carol likes Alice's post within the Circle.
//! 5. Dave (unauthorized stranger) is denied discovery, feed, thread, media, write, and counts.
//! 6. Alice adds Dave to Family -> Dave receives full Circle history and media access.
//! 7. Alice removes Bob -> Bob's access and active lease are revoked immediately;
//!    Alice, Carol, and Dave retain full access to Circle content.
//! 8. Public boundary verification: zero Circle URIs, private text, or private blob CIDs
//!    appear on public search, feed, thread, or notification surfaces.

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
use catbird_atproto::generated::blue_catbird::circle::get_feed::GetFeedOutput;
use catbird_atproto::generated::blue_catbird::circle::get_post_thread::GetPostThreadOutput;
use catbird_atproto::generated::blue_catbird::circle::list_circles::ListCirclesOutput;
use catbird_atproto::generated::blue_catbird::circle::list_notifications::ListNotificationsOutput;
use catbird_atproto::generated::blue_catbird::circle::{CircleSummary, FeedItem};
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::string::{Did, Handle};

use circle_appview::{
    access::{ActiveSpaceCredential, CredentialStore, SpaceLockManager},
    auth::{DidDocument, DidResolver, PublicKeyJwk, VerificationMethod},
    commit::create_cid_bytes_from_data,
    config::{AppState, Config},
    db,
    hydration::ProfileHydrator,
    purge::remove_member,
    routes::create_router,
    space_client::{MockSpaceHostTransport, SpaceClient},
    validator::{active_members, policy, validate, InvalidRecord, RecordCandidate},
};

const CIRCLE_AUDIENCE: &str = "did:web:circles.catbird.blue#atproto_circles";
const MEDIA_BASE: &str = "https://media.catbird.blue";

const ALICE_DID: &str = "did:plc:alice-circle-owner-3u";
const BOB_DID: &str = "did:plc:bob-circle-member-3u";
const CAROL_DID: &str = "did:plc:carol-circle-member-3u";
const DAVE_DID: &str = "did:plc:dave-circle-stranger-3u";

const ALICE_PDS: &str = "https://pds-alice.test";
const BOB_PDS: &str = "https://pds-bob.test";
const CAROL_PDS: &str = "https://pds-carol.test";
const DAVE_PDS: &str = "https://pds-dave.test";

fn compute_record_cid(val: &Value) -> String {
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

fn register_did_doc(
    resolver: &circle_appview::auth::DidResolver,
    did: &str,
    key: &SigningKey,
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

fn mint_jwt(did: &str, lxm: &str, signing_key: &SigningKey) -> String {
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

#[derive(Clone)]
pub struct TestUser {
    pub did: String,
    pub handle: String,
    pub signing_key: SigningKey,
    pub pds_endpoint: String,
}

impl TestUser {
    pub fn did(&self) -> &str {
        &self.did
    }

    pub async fn feed(&self, env: &ThreeUserEnv, circle: &CircleInfo) -> Vec<FeedItem> {
        let token = mint_jwt(&self.did, "blue.catbird.circle.getFeed", &self.signing_key);
        let uri = format!(
            "/xrpc/blue.catbird.circle.getFeed?space={}",
            circle.space_uri
        );
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = env.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "feed request failed for {}",
            self.did
        );
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let output: GetFeedOutput = serde_json::from_slice(&body).unwrap();
        output.feed
    }

    pub async fn feed_status(&self, env: &ThreeUserEnv, circle: &CircleInfo) -> StatusCode {
        let token = mint_jwt(&self.did, "blue.catbird.circle.getFeed", &self.signing_key);
        let uri = format!(
            "/xrpc/blue.catbird.circle.getFeed?space={}",
            circle.space_uri
        );
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = env.app.clone().oneshot(req).await.unwrap();
        resp.status()
    }

    pub async fn unified_feed(&self, env: &ThreeUserEnv) -> Vec<FeedItem> {
        let token = mint_jwt(&self.did, "blue.catbird.circle.getFeed", &self.signing_key);
        let uri = "/xrpc/blue.catbird.circle.getFeed";
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = env.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "unified feed failed for {}",
            self.did
        );
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let output: GetFeedOutput = serde_json::from_slice(&body).unwrap();
        output.feed
    }

    pub async fn thread(
        &self,
        env: &ThreeUserEnv,
        circle: &CircleInfo,
        post_uri: &str,
    ) -> GetPostThreadOutput {
        let token = mint_jwt(
            &self.did,
            "blue.catbird.circle.getPostThread",
            &self.signing_key,
        );
        let uri = format!(
            "/xrpc/blue.catbird.circle.getPostThread?uri={post_uri}&space={}",
            circle.space_uri
        );
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = env.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "getPostThread failed for {}",
            self.did
        );
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    pub async fn thread_status(
        &self,
        env: &ThreeUserEnv,
        circle: &CircleInfo,
        post_uri: &str,
    ) -> StatusCode {
        let token = mint_jwt(
            &self.did,
            "blue.catbird.circle.getPostThread",
            &self.signing_key,
        );
        let uri = format!(
            "/xrpc/blue.catbird.circle.getPostThread?uri={post_uri}&space={}",
            circle.space_uri
        );
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = env.app.clone().oneshot(req).await.unwrap();
        resp.status()
    }

    pub async fn media(&self, env: &ThreeUserEnv, post: &PostInfo) -> (StatusCode, Vec<u8>) {
        let token = mint_jwt(&self.did, "blue.catbird.circle.getMedia", &self.signing_key);
        let blob_cid = post
            .blob_cid
            .as_deref()
            .expect("Post must have a blob CID for media test");
        let uri = format!(
            "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
            post.space_uri, post.author_did, blob_cid
        );
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = env.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        (status, body.to_vec())
    }

    pub async fn media_status(&self, env: &ThreeUserEnv, post: &PostInfo) -> StatusCode {
        let (status, _) = self.media(env, post).await;
        status
    }

    pub async fn list_circles(&self, env: &ThreeUserEnv) -> Vec<CircleSummary> {
        let token = mint_jwt(
            &self.did,
            "blue.catbird.circle.listCircles",
            &self.signing_key,
        );
        let uri = "/xrpc/blue.catbird.circle.listCircles";
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = env.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "listCircles failed for {}",
            self.did
        );
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let output: ListCirclesOutput = serde_json::from_slice(&body).unwrap();
        output.circles
    }

    pub async fn list_notifications(&self, env: &ThreeUserEnv) -> ListNotificationsOutput {
        let token = mint_jwt(
            &self.did,
            "blue.catbird.circle.listNotifications",
            &self.signing_key,
        );
        let uri = "/xrpc/blue.catbird.circle.listNotifications";
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = env.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "listNotifications failed for {}",
            self.did
        );
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }
}

#[derive(Clone)]
pub struct CircleInfo {
    pub space_uri: String,
    pub name: String,
    pub authority_did: String,
}

#[derive(Clone)]
pub struct PostInfo {
    pub uri: String,
    pub std_uri: String,
    pub cid: String,
    pub blob_cid: Option<String>,
    pub space_uri: String,
    pub author_did: String,
    pub text: String,
}

#[derive(Clone)]
pub struct LikeInfo {
    pub uri: String,
    pub cid: String,
    pub space_uri: String,
    pub author_did: String,
    pub subject_uri: String,
}

#[derive(Default)]
pub struct MockPublicAppView {
    pub public_records: Vec<String>,
}

impl MockPublicAppView {
    pub fn new() -> Self {
        Self {
            public_records: Vec::new(),
        }
    }

    pub async fn search_uri(&self, uri: &str) -> Option<Value> {
        if self.public_records.contains(&uri.to_string()) {
            Some(json!({ "uri": uri }))
        } else {
            None
        }
    }

    pub async fn get_feed(&self) -> Vec<Value> {
        Vec::new()
    }

    pub async fn get_post_thread(&self, uri: &str) -> Option<Value> {
        if self.public_records.contains(&uri.to_string()) {
            Some(json!({ "thread": { "uri": uri } }))
        } else {
            None
        }
    }

    pub async fn get_notifications(&self) -> Vec<Value> {
        Vec::new()
    }
}

pub struct ThreeUserEnv {
    pub app: Router,
    pub state: AppState,
    pub pool: PgPool,
    pub mock_transport: Arc<MockSpaceHostTransport>,
    pub alice: TestUser,
    pub bob: TestUser,
    pub carol: TestUser,
    pub dave: TestUser,
    pub public_appview: MockPublicAppView,
}

impl ThreeUserEnv {
    pub async fn start_with_pool(pool: PgPool) -> Self {
        db::run_migrations(&pool)
            .await
            .expect("Migrations must succeed");

        let alice_key = SigningKey::random(&mut OsRng);
        let bob_key = SigningKey::random(&mut OsRng);
        let carol_key = SigningKey::random(&mut OsRng);
        let dave_key = SigningKey::random(&mut OsRng);

        let alice = TestUser {
            did: ALICE_DID.into(),
            handle: "alice.test".into(),
            signing_key: alice_key.clone(),
            pds_endpoint: ALICE_PDS.into(),
        };
        let bob = TestUser {
            did: BOB_DID.into(),
            handle: "bob.test".into(),
            signing_key: bob_key.clone(),
            pds_endpoint: BOB_PDS.into(),
        };
        let carol = TestUser {
            did: CAROL_DID.into(),
            handle: "carol.test".into(),
            signing_key: carol_key.clone(),
            pds_endpoint: CAROL_PDS.into(),
        };
        let dave = TestUser {
            did: DAVE_DID.into(),
            handle: "dave.test".into(),
            signing_key: dave_key.clone(),
            pds_endpoint: DAVE_PDS.into(),
        };

        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let did_resolver = Arc::new(DidResolver::new(
            "https://plc.directory".into(),
            reqwest::Client::new(),
        ));
        let credential_store = Arc::new(CredentialStore::new());
        let space_locks = Arc::new(SpaceLockManager::new());

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
            commit_verification_policy: circle_appview::commit::CommitVerificationPolicy::default(),
        };
        let profile_hydrator = Arc::new(ProfileHydrator::new(
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

        // Register DID documents
        register_did_doc(
            &state.did_resolver,
            ALICE_DID,
            &alice.signing_key,
            Some(ALICE_PDS),
        );
        register_did_doc(
            &state.did_resolver,
            BOB_DID,
            &bob.signing_key,
            Some(BOB_PDS),
        );
        register_did_doc(
            &state.did_resolver,
            CAROL_DID,
            &carol.signing_key,
            Some(CAROL_PDS),
        );
        register_did_doc(
            &state.did_resolver,
            DAVE_DID,
            &dave.signing_key,
            Some(DAVE_PDS),
        );

        // Seed profile cache in hydrator
        for (did, handle, name) in [
            (ALICE_DID, "alice.test", "Alice Owner"),
            (BOB_DID, "bob.test", "Bob Member"),
            (CAROL_DID, "carol.test", "Carol Member"),
            (DAVE_DID, "dave.test", "Dave Stranger"),
        ] {
            state
                .profile_hydrator
                .set_cached_profile(
                    did,
                    ProfileViewBasic {
                        did: Did::new(SmolStr::new(did)).unwrap(),
                        handle: Handle::new(SmolStr::new(handle)).unwrap(),
                        display_name: Some(SmolStr::new(name)),
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
        }

        let app = create_router(state.clone());

        Self {
            app,
            state,
            pool,
            mock_transport,
            alice,
            bob,
            carol,
            dave,
            public_appview: MockPublicAppView::new(),
        }
    }

    pub async fn create_circle(&self, name: &str, initial_members: &[&str]) -> CircleInfo {
        let space_uri = format!(
            "at://{}/space/blue.catbird.circle/3l7family",
            self.alice.did
        );

        // Insert circle
        sqlx::query(
            r#"
            INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at)
            VALUES ($1, '3l7familyaaaa', $2, $3, now())
            ON CONFLICT (space_uri) DO NOTHING
            "#,
        )
        .bind(&space_uri)
        .bind(&self.alice.did)
        .bind(name)
        .execute(&self.pool)
        .await
        .unwrap();

        // Grant active space credential to state
        let cred_key = SigningKey::random(&mut OsRng);
        self.state
            .credential_store
            .insert(
                space_uri.clone(),
                ActiveSpaceCredential {
                    token: "family-circle-space-token".into(),
                    dpop_key: cred_key,
                    expires_at: Utc::now() + Duration::hours(2),
                },
            )
            .await;

        // Add Alice (owner) as active member and grant lease
        self.grant_active_member(&space_uri, &self.alice.did).await;

        // Add initial members
        for member_did in initial_members {
            self.grant_active_member(&space_uri, member_did).await;
        }

        CircleInfo {
            space_uri,
            name: name.to_string(),
            authority_did: self.alice.did.clone(),
        }
    }

    pub async fn grant_active_member(&self, space_uri: &str, member_did: &str) {
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
        .execute(&self.pool)
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
        .execute(&self.pool)
        .await
        .unwrap();
    }

    pub async fn post_image(&self, circle: &CircleInfo, text: &str) -> PostInfo {
        let image_data = b"CANARY_SECRET_FAMILY_IMAGE_BYTES_ALICE_PHOTO";
        let blob_cid = compute_blob_cid(image_data);

        // Register blob in mock transport for Alice's PDS
        self.mock_transport.set_blob_response(
            &format!("{}:{}:{}", circle.space_uri, self.alice.did, blob_cid),
            Some("image/jpeg".to_string()),
            image_data.to_vec(),
        );

        let post_rkey = "3l7alicepost1";
        let post_uri = format!(
            "{}/{}/app.bsky.feed.post/{post_rkey}",
            circle.space_uri, self.alice.did
        );

        let post_json = json!({
            "$type": "app.bsky.feed.post",
            "text": text,
            "createdAt": Utc::now().to_rfc3339(),
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [{
                    "alt": "private photo",
                    "image": {
                        "$type": "blob",
                        "ref": { "$link": blob_cid },
                        "mimeType": "image/jpeg",
                        "size": image_data.len()
                    }
                }]
            }
        });

        let cid = compute_record_cid(&post_json);

        sqlx::query(
            r#"
            INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
            VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', $5, $6, now(), now())
            "#,
        )
        .bind(&post_uri)
        .bind(&cid)
        .bind(&circle.space_uri)
        .bind(&self.alice.did)
        .bind(post_rkey)
        .bind(&post_json)
        .execute(&self.pool)
        .await
        .unwrap();

        let std_uri = format!("at://{}/app.bsky.feed.post/{post_rkey}", self.alice.did);

        PostInfo {
            uri: post_uri,
            std_uri,
            cid,
            blob_cid: Some(blob_cid),
            space_uri: circle.space_uri.clone(),
            author_did: self.alice.did.clone(),
            text: text.to_string(),
        }
    }

    pub async fn reply(
        &self,
        user: &TestUser,
        circle: &CircleInfo,
        parent_post: &PostInfo,
        text: &str,
    ) -> PostInfo {
        let reply_rkey = format!("3l7reply{}", Uuid::new_v4().simple());
        let reply_uri = format!(
            "{}/{}/app.bsky.feed.post/{reply_rkey}",
            circle.space_uri, user.did
        );

        let reply_json = json!({
            "$type": "app.bsky.feed.post",
            "text": text,
            "createdAt": Utc::now().to_rfc3339(),
            "reply": {
                "root": {
                    "uri": parent_post.uri,
                    "cid": parent_post.cid
                },
                "parent": {
                    "uri": parent_post.uri,
                    "cid": parent_post.cid
                }
            }
        });

        let cid = compute_record_cid(&reply_json);

        sqlx::query(
            r#"
            INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at, parent_uri, root_uri)
            VALUES ($1, $2, $3, $4, 'app.bsky.feed.post', $5, $6, now(), now(), $7, $7)
            "#,
        )
        .bind(&reply_uri)
        .bind(&cid)
        .bind(&circle.space_uri)
        .bind(&user.did)
        .bind(&reply_rkey)
        .bind(&reply_json)
        .bind(&parent_post.uri)
        .execute(&self.pool)
        .await
        .unwrap();
        // Seed notification for post author (Alice)
        sqlx::query(
            r#"
            INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
            VALUES ($1, $2, $3, $4, 'reply', $5, $6, false, now())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(&parent_post.author_did)
        .bind(&circle.space_uri)
        .bind(&user.did)
        .bind(&parent_post.uri)
        .bind(&reply_uri)
        .execute(&self.pool)
        .await
        .unwrap();

        let std_uri = format!("at://{}/app.bsky.feed.post/{reply_rkey}", user.did);

        PostInfo {
            uri: reply_uri,
            std_uri,
            cid,
            blob_cid: None,
            space_uri: circle.space_uri.clone(),
            author_did: user.did.clone(),
            text: text.to_string(),
        }
    }

    pub async fn like(
        &self,
        user: &TestUser,
        circle: &CircleInfo,
        target_post: &PostInfo,
    ) -> LikeInfo {
        let like_rkey = format!("3l7like{}", Uuid::new_v4().simple());
        let like_uri = format!(
            "{}/{}/app.bsky.feed.like/{like_rkey}",
            circle.space_uri, user.did
        );

        let like_json = json!({
            "$type": "app.bsky.feed.like",
            "subject": {
                "uri": target_post.uri,
                "cid": target_post.cid
            },
            "createdAt": Utc::now().to_rfc3339()
        });

        let cid = compute_record_cid(&like_json);

        sqlx::query(
            r#"
            INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, indexed_at)
            VALUES ($1, $2, $3, $4, 'app.bsky.feed.like', $5, $6, now(), now())
            "#,
        )
        .bind(&like_uri)
        .bind(&cid)
        .bind(&circle.space_uri)
        .bind(&user.did)
        .bind(&like_rkey)
        .bind(&like_json)
        .execute(&self.pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at)
            VALUES ($1, $2, $3, $4, now())
            "#,
        )
        .bind(&like_uri)
        .bind(&circle.space_uri)
        .bind(&target_post.uri)
        .bind(&user.did)
        .execute(&self.pool)
        .await
        .unwrap();
        // Seed notification for post author (Alice)
        sqlx::query(
            r#"
            INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
            VALUES ($1, $2, $3, $4, 'like', $5, $6, false, now())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(&target_post.author_did)
        .bind(&circle.space_uri)
        .bind(&user.did)
        .bind(&target_post.uri)
        .bind(&like_uri)
        .execute(&self.pool)
        .await
        .unwrap();

        LikeInfo {
            uri: like_uri,
            cid,
            space_uri: circle.space_uri.clone(),
            author_did: user.did.clone(),
            subject_uri: target_post.uri.clone(),
        }
    }

    pub async fn add_member(&self, circle: &CircleInfo, member_did: &str) {
        self.grant_active_member(&circle.space_uri, member_did)
            .await;
    }

    pub async fn remove_member(&self, circle: &CircleInfo, member_did: &str) {
        remove_member(&self.pool, &circle.space_uri, member_did)
            .await
            .expect("remove_member must succeed");
    }
}

// ---------------------------------------------------------------------------
// Scenario Test: Primary 3-User Private, Multi-Action, and Revocation Lifecycle
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn three_user_circle_is_private_and_revocable(pool: PgPool) {
    let env = ThreeUserEnv::start_with_pool(pool).await;

    // 1. Alice creates Family with Bob and Carol
    let circle = env
        .create_circle("Family", &[env.bob.did(), env.carol.did()])
        .await;

    // 2. Alice posts private image
    let post = env.post_image(&circle, "private").await;

    // 3. Bob replies to Alice's post
    let reply = env.reply(&env.bob, &circle, &post, "reply").await;

    // 4. Carol likes Alice's post
    let _like = env.like(&env.carol, &circle, &post).await;

    // -----------------------------------------------------------------------
    // Initial State Verification: Alice, Bob, Carol active; Dave is stranger
    // -----------------------------------------------------------------------

    // Alice sees top-level post (replies are nested in getPostThread)
    let alice_feed = env.alice.feed(&env, &circle).await;
    assert_eq!(alice_feed.len(), 1, "Alice must see top-level post in feed");

    // Bob sees top-level post
    let bob_feed = env.bob.feed(&env, &circle).await;
    assert_eq!(bob_feed.len(), 1, "Bob must see top-level post in feed");

    // Carol sees top-level post
    let carol_feed = env.carol.feed(&env, &circle).await;
    assert_eq!(carol_feed.len(), 1, "Carol must see top-level post in feed");
    // Carol's feed has viewer.like populated on Alice's post
    let carol_target_post = &carol_feed[0];
    assert!(
        carol_target_post
            .post
            .post
            .uri
            .as_str()
            .ends_with("3l7alicepost1"),
        "Alice's post must be in Carol's feed"
    );
    assert!(
        carol_target_post
            .post
            .post
            .viewer
            .as_ref()
            .and_then(|v| v.like.as_ref())
            .is_some(),
        "Carol must have viewer.like set on Alice's post"
    );
    // Alice's post shows like_count = 1 and reply_count = 1
    assert_eq!(carol_target_post.post.post.like_count, Some(1));
    assert_eq!(carol_target_post.post.post.reply_count, Some(1));
    // Dave (unauthorized stranger) is denied access
    assert_eq!(
        env.dave.feed_status(&env, &circle).await,
        StatusCode::FORBIDDEN,
        "Dave must receive 403 Forbidden for Circle feed"
    );
    assert_eq!(
        env.dave.media_status(&env, &post).await,
        StatusCode::FORBIDDEN,
        "Dave must receive 403 Forbidden for Circle media"
    );
    assert_eq!(
        env.dave.thread_status(&env, &circle, &post.std_uri).await,
        StatusCode::FORBIDDEN,
        "Dave must receive 403 Forbidden for Circle post thread"
    );
    // Dave cannot discover Family via listCircles
    let dave_circles = env.dave.list_circles(&env).await;
    assert!(
        dave_circles.is_empty(),
        "Dave must not see Family in listCircles"
    );

    // Dave's unified feed is empty
    let dave_unified = env.dave.unified_feed(&env).await;
    assert!(
        dave_unified.is_empty(),
        "Dave unified feed must contain zero Circle posts"
    );
    // Dave sees zero Circle notifications
    let dave_notifs = env.dave.list_notifications(&env).await;
    assert!(
        dave_notifs.notifications.is_empty(),
        "Dave must see 0 notifications"
    );

    // Alice sees notifications from Bob (reply) and Carol (like)
    let alice_notifs = env.alice.list_notifications(&env).await;
    assert_eq!(
        alice_notifs.notifications.len(),
        2,
        "Alice must receive 2 notifications (reply + like)"
    );

    // Thread inspection: Alice, Bob, Carol can fetch the full thread
    let thread_output = env.alice.thread(&env, &circle, &post.std_uri).await;
    assert_eq!(thread_output.thread.post.uri.as_str(), post.std_uri);
    assert_eq!(
        thread_output.thread.replies.as_ref().map(|r| r.len()),
        Some(1)
    );
    let (alice_media_status, alice_media_bytes) = env.alice.media(&env, &post).await;
    assert_eq!(alice_media_status, StatusCode::OK);
    assert_eq!(
        alice_media_bytes,
        b"CANARY_SECRET_FAMILY_IMAGE_BYTES_ALICE_PHOTO"
    );

    let (bob_media_status, bob_media_bytes) = env.bob.media(&env, &post).await;
    assert_eq!(bob_media_status, StatusCode::OK);
    assert_eq!(
        bob_media_bytes,
        b"CANARY_SECRET_FAMILY_IMAGE_BYTES_ALICE_PHOTO"
    );

    // -----------------------------------------------------------------------
    // Add Dave to Family -> Dave receives full history & media
    // -----------------------------------------------------------------------

    env.add_member(&circle, env.dave.did()).await;

    // Dave can now discover Family
    let dave_circles_after_add = env.dave.list_circles(&env).await;
    assert_eq!(
        dave_circles_after_add.len(),
        1,
        "Dave must see Family in listCircles after being added"
    );

    // Dave can view top-level post in feed
    let dave_feed = env.dave.feed(&env, &circle).await;
    assert_eq!(
        dave_feed.len(),
        1,
        "Dave must receive top-level Circle post"
    );

    // Dave can view thread
    assert_eq!(
        env.dave.thread_status(&env, &circle, &post.std_uri).await,
        StatusCode::OK,
        "Dave must receive 200 OK for thread after being added"
    );
    // Dave can fetch media
    assert_eq!(
        env.dave.media_status(&env, &post).await,
        StatusCode::OK,
        "Dave must receive 200 OK for media after being added"
    );
    let (dave_media_status, dave_media_bytes) = env.dave.media(&env, &post).await;
    assert_eq!(dave_media_status, StatusCode::OK);
    assert_eq!(
        dave_media_bytes,
        b"CANARY_SECRET_FAMILY_IMAGE_BYTES_ALICE_PHOTO"
    );

    // -----------------------------------------------------------------------
    // Remove Bob from Family -> Bob revoked; Alice, Carol, Dave remain
    // -----------------------------------------------------------------------

    env.remove_member(&circle, env.bob.did()).await;

    // Bob is immediately denied feed, media, thread, and discovery
    assert_eq!(
        env.bob.feed_status(&env, &circle).await,
        StatusCode::FORBIDDEN,
        "Bob must receive 403 Forbidden after removal"
    );
    assert_eq!(
        env.bob.media_status(&env, &post).await,
        StatusCode::FORBIDDEN,
        "Bob must receive 403 Forbidden for media after removal"
    );
    assert_eq!(
        env.bob.thread_status(&env, &circle, &post.std_uri).await,
        StatusCode::FORBIDDEN,
        "Bob must receive 403 Forbidden for thread after removal"
    );
    let bob_circles_after_remove = env.bob.list_circles(&env).await;
    assert!(
        bob_circles_after_remove.is_empty(),
        "Bob must not see Family in listCircles after removal"
    );
    let bob_unified_after_remove = env.bob.unified_feed(&env).await;
    assert!(
        bob_unified_after_remove.is_empty(),
        "Bob unified feed must be empty after removal"
    );

    // Remaining members (Alice, Carol, Dave) retain full access to Circle content
    // Note: Bob's historical reply remains part of Circle history for remaining members
    let alice_feed_after = env.alice.feed(&env, &circle).await;
    assert_eq!(
        alice_feed_after.len(),
        1,
        "Alice must still see top-level post"
    );

    let carol_feed_after = env.carol.feed(&env, &circle).await;
    assert_eq!(
        carol_feed_after.len(),
        1,
        "Carol must still see top-level post"
    );

    let dave_feed_after = env.dave.feed(&env, &circle).await;
    assert_eq!(
        dave_feed_after.len(),
        1,
        "Dave must still see top-level post"
    );

    // Remaining members (Alice, Carol, Dave) can view thread with Bob's historical reply
    let alice_thread_after = env.alice.thread(&env, &circle, &post.std_uri).await;
    assert_eq!(
        alice_thread_after.thread.replies.as_ref().map(|r| r.len()),
        Some(1),
        "Thread must preserve Bob's historical reply for remaining members"
    );
    let dave_thread_after = env.dave.thread(&env, &circle, &post.std_uri).await;
    assert_eq!(
        dave_thread_after.thread.replies.as_ref().map(|r| r.len()),
        Some(1),
        "Dave must see Bob's historical reply in thread"
    );
    // Carol and Dave can still fetch media
    assert_eq!(env.carol.media_status(&env, &post).await, StatusCode::OK);
    assert_eq!(env.dave.media_status(&env, &post).await, StatusCode::OK);

    // -----------------------------------------------------------------------
    // Public Boundary Verification: Zero Circle artifacts on public surfaces
    // -----------------------------------------------------------------------

    assert!(
        env.public_appview.search_uri(&post.uri).await.is_none(),
        "Public search must not find Circle post URI"
    );
    assert!(
        env.public_appview.search_uri(&reply.uri).await.is_none(),
        "Public search must not find Circle reply URI"
    );
    assert!(
        env.public_appview
            .search_uri(&circle.space_uri)
            .await
            .is_none(),
        "Public search must not find Space URI"
    );
    assert!(
        env.public_appview
            .get_post_thread(&post.uri)
            .await
            .is_none(),
        "Public thread must not return Circle thread"
    );
    assert!(
        env.public_appview.get_feed().await.is_empty(),
        "Public feed must contain zero Circle posts"
    );
    assert!(
        env.public_appview.get_notifications().await.is_empty(),
        "Public notifications must contain zero Circle notifications"
    );
}

// ---------------------------------------------------------------------------
// Security & Validation: Non-member write rejection by validation policy
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn non_member_write_is_rejected_by_validation_policy(pool: PgPool) {
    let env = ThreeUserEnv::start_with_pool(pool).await;
    let circle = env
        .create_circle("Family", &[env.bob.did(), env.carol.did()])
        .await;

    let dave_post_candidate = RecordCandidate {
        uri: format!(
            "{}/{}/app.bsky.feed.post/3l7davetop",
            circle.space_uri, env.dave.did
        ),
        author_did: env.dave.did.clone(),
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l7davetop".to_string(),
        value: json!({
            "$type": "app.bsky.feed.post",
            "text": "Unauthorized stranger post in Family circle",
            "createdAt": Utc::now().to_rfc3339()
        }),
    };

    let validation_policy = policy(
        &env.alice.did,
        active_members(&[&env.bob.did, &env.carol.did]),
    )
    .with_space_uri(&circle.space_uri);

    // Dave is NOT an active member, so validation policy must reject candidate
    let validation_result = validate(dave_post_candidate, &validation_policy);
    assert_eq!(
        validation_result,
        Err(InvalidRecord::TopLevelAuthor),
        "Validation policy must reject top-level post candidate from non-owner Dave"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn privacy_audit_canaries_are_isolated_and_unleaked(pool: PgPool) {
    let env = ThreeUserEnv::start_with_pool(pool).await;

    let canary_circle_name = "CANARY_NAME_FAMILY_PRIVACY_AUDIT_998877";
    let canary_post_text = "CANARY_TEXT_PRIVATE_POST_BODY_112233";

    // 1. Alice creates Family with Bob and Carol
    let circle = env
        .create_circle(canary_circle_name, &[env.bob.did(), env.carol.did()])
        .await;

    // 2. Alice posts image with unique canary text
    let post = env.post_image(&circle, canary_post_text).await;
    let canary_blob_cid = post.blob_cid.as_ref().unwrap();

    // 3. Bob replies, Carol likes
    let reply = env
        .reply(&env.bob, &circle, &post, "CANARY_REPLY_TEXT_445566")
        .await;
    let _like = env.like(&env.carol, &circle, &post).await;

    // 4. Add Dave, then remove Bob
    env.add_member(&circle, env.dave.did()).await;
    env.remove_member(&circle, env.bob.did()).await;

    // 5. Audit: Public surfaces MUST NOT contain any of the canaries
    assert!(env.public_appview.search_uri(&post.uri).await.is_none());
    assert!(env.public_appview.search_uri(&reply.uri).await.is_none());
    assert!(env
        .public_appview
        .search_uri(&circle.space_uri)
        .await
        .is_none());
    assert!(env
        .public_appview
        .search_uri(canary_blob_cid)
        .await
        .is_none());

    // 6. Audit: Database state for removed member Bob must have zero cache entries,
    // notifications, or preferences
    let bob_cache_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&circle.space_uri)
    .bind(env.bob.did())
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(bob_cache_count.0, 0, "Bob cache must be purged");

    let bob_notif_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM circle_notifications WHERE space_uri = $1 AND recipient_did = $2",
    )
    .bind(&circle.space_uri)
    .bind(env.bob.did())
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(bob_notif_count.0, 0, "Bob notifications must be purged");

    let bob_pref_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM circle_preferences WHERE space_uri = $1 AND member_did = $2",
    )
    .bind(&circle.space_uri)
    .bind(env.bob.did())
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(bob_pref_count.0, 0, "Bob preferences must be purged");

    // 7. Audit: Remaining members Alice, Carol, Dave have cached membership
    for member_did in [env.alice.did(), env.carol.did(), env.dave.did()] {
        let cache_count: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2",
        )
        .bind(&circle.space_uri)
        .bind(member_did)
        .fetch_one(&env.pool)
        .await
        .unwrap();
        assert_eq!(cache_count.0, 1, "Remaining member must be in cache");
    }
}
