//! Plan 05 Task 2 (`W9`) Integration Tests:
//! 1. `/.well-known/oauth-client-metadata` & `ALLOWLISTED_UPGRADE_SCOPES` contain all 6 required
//!    Labyrinth / MLS / blob scopes (`Spec §6.7, §6.8`).
//! 2. PAR (`start_auth_with_raw_scopes`) sends the exact Labyrinth `space:` scope strings
//!    (explicit `action=` + `collection=`) on the wire, `OAuthUpgradeService::complete_callback`
//!    accepts `Swan` / `atproto#5187` `resolveSpaceSelfAuthority` grants of them, and a session
//!    holding only the retired Labyrinth scopes cannot complete an upgrade without the new ones.
//! 3. `proxy_xrpc` rejects `atproto-proxy: <did>#atproto_mls` with `403 Forbidden` while keeping
//!    `400 Bad Request` for malformed/untrusted non-MLS `atproto-proxy` headers.
//! 4. `GET /xrpc/com.atproto.server.getServiceAuth` permits `aud` matching the user's DID-resolved
//!    `#atproto_mls` service DID (e.g. `did:web:my-ds.example.org`), while rejecting arbitrary
//!    unassociated `aud` DIDs.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode},
    response::IntoResponse,
    Extension,
};
use base64::Engine;
use chrono::Utc;
use jacquard_common::types::did::Did;
use jacquard_identity::{
    resolver::{PlcSource, ResolverOptions},
    JacquardResolver,
};
use jacquard_oauth::{
    atproto::AtprotoClientMetadata,
    scopes::Scopes,
    session::{ClientData, ClientSessionData, DpopClientData},
    types::{OAuthTokenType, TokenSet},
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

use catbird::{
    config::{AppConfig, AppState, JacquardOAuthClient},
    middleware::JacquardDpopData,
    models::{CatbirdSession, ALLOWLISTED_UPGRADE_SCOPES},
    routes::atproto::create_router,
    services::{
        push::{
            gateway::{HttpMlsDsIdentityResolver, PushGatewayConfig, PushGatewayService},
            PushServices,
        },
        HardenedHttpClient, OAuthUpgradeService, RedisAuthStore, UpgradeError,
        DEFAULT_UPGRADE_CALLBACK_URL,
    },
};

const REQUIRED_CLEAN_SLATE_SCOPES: &[&str] = &[
    "atproto",
    "blob:*/*",
    "repo:blue.catbird.labyrinth.mailboxKeys",
    "repo:blue.catbird.chat.device?action=create",
    "repo:blue.catbird.chat.deviceRevocation?action=create",
    "space:blue.catbird.labyrinth.mailbox?action=create&action=delete&action=read&action=update&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.circleOwnerState&collection=blue.catbird.labyrinth.device&collection=blue.catbird.labyrinth.epoch&collection=blue.catbird.labyrinth.epochMember&collection=blue.catbird.labyrinth.otcSession&collection=blue.catbird.labyrinth.ownerBatch&collection=blue.catbird.labyrinth.readState&collection=blue.catbird.labyrinth.virtualDevice&manage=create&manage=delete",
    "space:blue.catbird.labyrinth.conversation?action=create&action=delete&action=read&action=update&authority=*&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.authorRedaction&collection=blue.catbird.labyrinth.batch&collection=blue.catbird.labyrinth.mek",
];

const RETIRED_LABYRINTH_SPACE_SCOPES: &[&str] = &[
    "space:blue.catbird.labyrinth.mailbox?manage=create&manage=delete",
    "space:blue.catbird.labyrinth.conversation?authority=*",
];

const TEST_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgED1AAgC7Fc9kPh5T
4i4Tn+z+tc47W1zYgzXtyjJtD92hRANCAAT80DqC+Z/JpTO7/pkPBmWqIV1IGh1P
gbGGr0pN+oSing7cZ0169JaRHTNh+0LNQXrFobInX6cj95FzEdRyT4T3
-----END PRIVATE KEY-----"#;

fn test_dpop_data() -> JacquardDpopData {
    let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
    let crypto_key = jose_jwk::crypto::Key::from(secret_key);
    let dpop_key = jose_jwk::Key::from(&crypto_key);
    JacquardDpopData {
        dpop_key,
        dpop_host_nonce: String::new(),
    }
}

async fn test_redis_manager() -> redis::aio::ConnectionManager {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let client = redis::Client::open(redis_url).expect("open redis client");
    redis::aio::ConnectionManager::new(client)
        .await
        .expect("connect to local redis")
}

async fn base_test_state(config: AppConfig) -> Arc<AppState> {
    let redis = test_redis_manager().await;
    Arc::new(AppState {
        config: Arc::new(config),
        http_client: reqwest::Client::new(),
        raw_http_client: reqwest::Client::new(),
        redis,
        push_db: None,
        key_store: None,
        jacquard_client: None,
        catmos_jacquard_client: None,
        catmos_oauth_scopes: vec![],
        trusted_proxies: vec![],
        auth_store: None,
        push: None,
        dpop_nonce_cache: Arc::new(catbird::services::DpopNonceCache::new()),
        session_encryption_key: Some([0x5Au8; 32]),
        active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
        session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        session_index_readiness: Arc::new(tokio::sync::Notify::new()),
    })
}

#[tokio::test]
async fn well_known_oauth_client_metadata_and_allowlist_contain_all_labyrinth_and_blob_scopes() {
    let config = AppConfig::test_default();
    let state = base_test_state(config).await;
    let router = create_router(state.clone()).with_state(state);

    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-client-metadata")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let meta: Value = serde_json::from_slice(&body_bytes).unwrap();
    let scope_str = meta["scope"]
        .as_str()
        .expect("oauth-client-metadata must expose scope string");
    let tokens: Vec<&str> = scope_str.split_whitespace().collect();

    for expected in REQUIRED_CLEAN_SLATE_SCOPES {
        assert!(
            tokens.contains(expected),
            "oauth-client-metadata scope missing '{expected}'; got: {scope_str}"
        );
    }

    for account_or_identity in &[
        "identity:handle",
        "account:email?action=manage",
        "account:status?action=manage",
    ] {
        assert!(
            tokens.contains(account_or_identity),
            "oauth-client-metadata scope missing progressive account/identity scope '{account_or_identity}'; got: {scope_str}"
        );
        assert!(
            ALLOWLISTED_UPGRADE_SCOPES.contains(account_or_identity),
            "ALLOWLISTED_UPGRADE_SCOPES missing '{account_or_identity}'"
        );
    }

    for progressive in &REQUIRED_CLEAN_SLATE_SCOPES[1..] {
        assert!(
            ALLOWLISTED_UPGRADE_SCOPES.contains(progressive),
            "ALLOWLISTED_UPGRADE_SCOPES missing '{progressive}'"
        );
    }

    for retired in RETIRED_LABYRINTH_SPACE_SCOPES.iter().chain([
        &"repo:blue.catbird.chat.device",
        &"repo:blue.catbird.chat.deviceRevocation",
    ]) {
        assert!(
            !tokens.contains(retired),
            "oauth-client-metadata must not declare retired scope '{retired}'"
        );
        assert!(
            !ALLOWLISTED_UPGRADE_SCOPES.contains(retired),
            "ALLOWLISTED_UPGRADE_SCOPES must not accept retired scope '{retired}'"
        );
    }
}

#[tokio::test]
async fn par_requests_exact_labyrinth_space_scopes_and_old_scope_sessions_must_upgrade() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    unsafe {
        std::env::set_var("JACQUARD_OAUTH_TEST_ALLOW_LOCAL", "1");
    }

    let mock_as = MockServer::start().await;
    let origin = mock_as.uri();
    let user_did = "did:plc:z72i7hdynmk6r22z27h6tvur";

    Mock::given(method("GET"))
        .and(path(format!("/{user_did}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": user_did,
            "alsoKnownAs": ["at://alice.test"],
            "verificationMethod": [],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": origin,
            }]
        })))
        .mount(&mock_as)
        .await;

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "resource": origin,
            "authorization_servers": [origin],
            "scopes_supported": ["atproto"],
        })))
        .mount(&mock_as)
        .await;

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": origin,
            "authorization_endpoint": format!("{origin}/oauth/authorize"),
            "token_endpoint": format!("{origin}/oauth/token"),
            "pushed_authorization_request_endpoint": format!("{origin}/oauth/par"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt", "none"],
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "require_pushed_authorization_requests": true,
            "client_id_metadata_document_supported": true,
            "scopes_supported": ["atproto"],
            "protected_resources": [origin],
        })))
        .mount(&mock_as)
        .await;

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("DPoP-Nonce", "nonce-1")
                .set_body_json(json!({
                    "request_uri": "urn:ietf:params:oauth:request_uri:test-par-1",
                    "expires_in": 60,
                })),
        )
        .mount(&mock_as)
        .await;

    let redis = test_redis_manager().await;
    let enc_key = [0x6Bu8; 32];
    let prefix = format!("test:v2:w9:{}:session:", Uuid::new_v4());
    let auth_store = RedisAuthStore::new(redis.clone(), prefix.clone(), 3600, Some(enc_key))
        .expect("create RedisAuthStore");

    let mut ks_cfg = AppConfig::test_default();
    ks_cfg.push.database_url = None;
    ks_cfg.oauth.private_key_base64 =
        Some(base64::engine::general_purpose::STANDARD.encode(TEST_PRIVATE_KEY_PEM));
    ks_cfg.oauth.active_key_id = "test-key-1".into();
    let ks_state = AppState::new(ks_cfg).await.expect("AppState with KeyStore");
    let keyset = ks_state
        .key_store
        .as_ref()
        .and_then(|ks| ks.to_jacquard_keyset().ok());

    let raw_requested: Vec<String> = REQUIRED_CLEAN_SLATE_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let parsed_scopes =
        catbird::config::OAuthConfig::parse_and_validate_scopes(&raw_requested).unwrap();
    let scopes_obj =
        Scopes::from_scopes(parsed_scopes.iter().cloned().map(|s| s.convert())).unwrap();

    let client_id = jacquard_common::deps::fluent_uri::Uri::parse(
        "https://api.catbird.blue/.well-known/oauth-client-metadata",
    )
    .unwrap()
    .to_owned();
    let redirect_uri = jacquard_common::deps::fluent_uri::Uri::parse(DEFAULT_UPGRADE_CALLBACK_URL)
        .unwrap()
        .to_owned();
    let jwks_uri = jacquard_common::deps::fluent_uri::Uri::parse(
        "https://api.catbird.blue/.well-known/jwks.json",
    )
    .unwrap()
    .to_owned();

    let client_meta = AtprotoClientMetadata::new(vec![redirect_uri], client_id, Some(scopes_obj))
        .with_jwks_uri(jwks_uri);
    let client_data = ClientData::new(keyset, client_meta);

    let plc_base = jacquard_common::deps::fluent_uri::Uri::parse(format!("{origin}/").as_str())
        .unwrap()
        .to_owned();
    let resolver_opts = ResolverOptions {
        plc_source: PlcSource::PlcDirectory { base: plc_base },
        ..ResolverOptions::default()
    };
    let resolver = JacquardResolver::new(
        HardenedHttpClient::new(reqwest::Client::new()),
        resolver_opts,
    );
    let oauth_client =
        JacquardOAuthClient::new_from_resolver(auth_store.clone(), resolver, client_data);

    let _auth_url = catbird::services::oauth_authorize::start_auth_with_raw_scopes(
        &oauth_client,
        user_did,
        &parsed_scopes,
        &raw_requested,
        "state_w9_par_1",
        None,
    )
    .await
    .expect("PAR start_auth_with_raw_scopes must succeed");

    let received = mock_as.received_requests().await.unwrap();
    let par_req = received
        .iter()
        .find(|r| r.url.path() == "/oauth/par")
        .expect("PAR request sent");
    let form: HashMap<String, String> = url::form_urlencoded::parse(&par_req.body)
        .into_owned()
        .collect();
    let wire_scope = form.get("scope").expect("PAR scope field");
    let wire_tokens: Vec<&str> = wire_scope.split_whitespace().collect();

    for expected in REQUIRED_CLEAN_SLATE_SCOPES {
        assert!(
            wire_tokens.contains(expected),
            "PAR wire scope must contain exact raw token '{expected}'; got: {wire_scope}"
        );
    }
    for retired in RETIRED_LABYRINTH_SPACE_SCOPES.iter().chain([
        &"repo:blue.catbird.chat.device",
        &"repo:blue.catbird.chat.deviceRevocation",
    ]) {
        assert!(
            !wire_tokens.contains(retired),
            "PAR wire scope must not request retired scope '{retired}'; got: {wire_scope}"
        );
    }

    // Verify complete_callback accepts Swan / atproto#5187 resolveSpaceSelfAuthority grants.
    let upgrade_service = OAuthUpgradeService::from_auth_store(
        &auth_store,
        Some(DEFAULT_UPGRADE_CALLBACK_URL.to_string()),
    );
    let did = Did::new_owned(user_did.to_string()).unwrap();
    let dpop_jwk: jose_jwk::Key = serde_json::from_value(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xFMTbKEBaGizdGlIUKEWx5q15odEB00stfg",
        "y": "x_daaqundbgUvJV358vRBgULGnpH7aRFZZDYyEiNg2g",
        "d": "jpsQnnGQmL-YxOmH1UmOBHg10OJ45DBTWh0n52qxzMQ"
    }))
    .unwrap();
    let session = |session_id: &str, scopes: &[String]| ClientSessionData {
        account_did: did.clone(),
        session_id: session_id.to_string().into(),
        host_url: jacquard_common::deps::fluent_uri::Uri::parse(origin.as_str())
            .unwrap()
            .to_owned(),
        authserver_url: origin.clone().into(),
        authserver_token_endpoint: format!("{origin}/oauth/token").into(),
        authserver_revocation_endpoint: None,
        scopes: Scopes::new(scopes.join(" ").into()).unwrap(),
        dpop_data: DpopClientData {
            dpop_key: dpop_jwk.clone(),
            dpop_authserver_nonce: "".into(),
            dpop_host_nonce: "".into(),
        },
        token_set: TokenSet {
            iss: origin.clone().into(),
            sub: did.clone(),
            aud: origin.clone().into(),
            scope: Some(scopes.join(" ").into()),
            refresh_token: Some("ref".into()),
            access_token: "acc".into(),
            token_type: OAuthTokenType::DPoP,
            expires_at: None,
        },
        resolved_scopes: None,
    };
    let browser_nonce = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V";

    let old_session_id = Uuid::new_v4().to_string();
    let atproto_only = vec!["atproto".to_string()];
    jacquard_oauth::authstore::ClientAuthStore::upsert_session(
        &auth_store,
        session(&old_session_id, &atproto_only),
    )
    .await
    .unwrap();
    let start_res = upgrade_service
        .start_upgrade_flow(
            &old_session_id,
            user_did,
            &atproto_only,
            &raw_requested,
            &raw_requested[1..],
            browser_nonce,
        )
        .await
        .expect("start_upgrade_flow");

    let mailbox_idx = raw_requested
        .iter()
        .position(|s| s.starts_with("space:blue.catbird.labyrinth.mailbox?"))
        .expect("mailbox space scope index");
    let mut swan_grants = raw_requested.clone();
    swan_grants[mailbox_idx] = swan_grants[mailbox_idx].replacen(
        "&collection=",
        &format!("&authority={user_did}&collection="),
        1,
    );
    let cb = upgrade_service
        .complete_callback(
            &start_res.state,
            session(&old_session_id, &swan_grants),
            swan_grants.clone(),
        )
        .await
        .expect("complete_callback must accept Swan self-authority-resolved Labyrinth grants");
    assert_eq!(cb.exchange_code.len(), 43);

    // A later unrelated upgrade must carry the registered spelling for an existing
    // self-authority grant, not retire it because Swan resolved `self` to this DID.
    let resolved_session_id = Uuid::new_v4().to_string();
    jacquard_oauth::authstore::ClientAuthStore::upsert_session(
        &auth_store,
        session(&resolved_session_id, &swan_grants),
    )
    .await
    .unwrap();
    let mut registration_with_handle = raw_requested.clone();
    registration_with_handle.push("identity:handle".to_string());
    let resolved_start = upgrade_service
        .start_upgrade_flow(
            &resolved_session_id,
            user_did,
            &swan_grants,
            &registration_with_handle,
            &["identity:handle".to_string()],
            browser_nonce,
        )
        .await
        .expect("resolved self-authority grant remains registered");
    assert!(
        resolved_start
            .requested_scopes
            .contains(&raw_requested[mailbox_idx]),
        "PAR must retain the registration's wire-exact mailbox scope"
    );
    assert!(
        !resolved_start
            .requested_scopes
            .contains(&swan_grants[mailbox_idx]),
        "resolved grant spelling must not replace the registered PAR spelling"
    );

    // A session holding only the retired Labyrinth scopes is missing the new ones: an upgrade
    // whose grants stay at the retired scopes must be rejected, never accepted as equivalent.
    let old_scope_session_id = Uuid::new_v4().to_string();
    let old_scopes: Vec<String> = REQUIRED_CLEAN_SLATE_SCOPES[..mailbox_idx]
        .iter()
        .chain(RETIRED_LABYRINTH_SPACE_SCOPES)
        .map(|s| (*s).to_string())
        .collect();
    jacquard_oauth::authstore::ClientAuthStore::upsert_session(
        &auth_store,
        session(&old_scope_session_id, &old_scopes),
    )
    .await
    .unwrap();
    let old_scope_start = upgrade_service
        .start_upgrade_flow(
            &old_scope_session_id,
            user_did,
            &old_scopes,
            &raw_requested,
            &raw_requested[mailbox_idx..],
            browser_nonce,
        )
        .await
        .expect("old-scope session must be able to start an upgrade to the new scopes");
    assert!(
        RETIRED_LABYRINTH_SPACE_SCOPES
            .iter()
            .all(|retired| !old_scope_start
                .requested_scopes
                .iter()
                .any(|scope| scope == retired)),
        "retired grants must be removed before PAR: {:?}",
        old_scope_start.requested_scopes
    );
    assert!(
        old_scope_start
            .requested_scopes
            .iter()
            .all(|scope| raw_requested.contains(scope)),
        "PAR target must remain within current registration max scopes"
    );
    let migrated_par_scopes =
        catbird::config::OAuthConfig::parse_and_validate_scopes(&old_scope_start.requested_scopes)
            .unwrap();
    catbird::services::oauth_authorize::start_auth_with_raw_scopes(
        &oauth_client,
        user_did,
        &migrated_par_scopes,
        &old_scope_start.requested_scopes,
        &old_scope_start.state,
        None,
    )
    .await
    .expect("retired-grant migration must reach PAR with registered scopes only");
    let migrated_requests = mock_as.received_requests().await.unwrap();
    let migrated_wire = migrated_requests
        .iter()
        .rev()
        .find(|request| request.url.path() == "/oauth/par")
        .map(|request| {
            url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect::<HashMap<String, String>>()
        })
        .and_then(|form| form.get("scope").cloned())
        .expect("migrated PAR scope");
    assert!(
        RETIRED_LABYRINTH_SPACE_SCOPES
            .iter()
            .all(|retired| !migrated_wire
                .split_whitespace()
                .any(|scope| scope == *retired)),
        "retired grants reached PAR: {migrated_wire}"
    );
    let err = upgrade_service
        .complete_callback(
            &old_scope_start.state,
            session(&old_scope_session_id, &old_scopes),
            old_scopes.clone(),
        )
        .await
        .expect_err("retired Labyrinth grants must not satisfy the new scopes");
    assert!(
        matches!(&err, UpgradeError::ScopeDowngrade(msg) if msg.contains(REQUIRED_CLEAN_SLATE_SCOPES[mailbox_idx])),
        "expected missing mailbox scope downgrade, got: {err}"
    );

    // A custom registration maximum drops an unrelated formerly granted
    // permission too; an upgrade never preserves it by escalating metadata.
    let custom_session_id = Uuid::new_v4().to_string();
    let custom_current = vec![
        "atproto".to_string(),
        "account:email?action=manage".to_string(),
        RETIRED_LABYRINTH_SPACE_SCOPES[0].to_string(),
    ];
    jacquard_oauth::authstore::ClientAuthStore::upsert_session(
        &auth_store,
        session(&custom_session_id, &custom_current),
    )
    .await
    .unwrap();
    let custom_max = vec!["atproto".to_string(), "identity:handle".to_string()];
    let custom = upgrade_service
        .start_upgrade_flow(
            &custom_session_id,
            user_did,
            &custom_current,
            &custom_max,
            &["identity:handle".to_string()],
            browser_nonce,
        )
        .await
        .expect("custom registration max must migrate retired grants");
    assert_eq!(custom.requested_scopes, custom_max);
}

#[tokio::test]
async fn atproto_proxy_rejects_atproto_mls_with_403_and_other_unknown_with_400() {
    let config = AppConfig::test_default();
    let state = base_test_state(config).await;
    let session = CatbirdSession {
        id: Uuid::new_v4(),
        did: "did:plc:z72i7hdynmk6r22z27h6tvur".into(),
        handle: "alice.test".into(),
        pds_url: "https://pds.example.com".into(),
        access_token: "tok".into(),
        refresh_token: "ref".into(),
        scopes: vec!["atproto".into()],
        access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
        created_at: Utc::now(),
        last_used_at: Utc::now(),
        granted_scopes: vec!["atproto".into()],
    };
    let dpop = test_dpop_data();

    for mls_proxy in [
        "did:web:chat.catbird.blue#atproto_mls",
        "did:web:my-ds.example.org#atproto_mls",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert("atproto-proxy", HeaderValue::from_static(mls_proxy));
        let err = catbird::handlers::atproto::proxy_xrpc(
            State(state.clone()),
            Extension(session.clone()),
            None,
            Some(Extension(dpop.clone())),
            Method::GET,
            Path("blue.catbird.chat.getConversations".to_string()),
            RawQuery(None),
            headers,
            Body::empty(),
        )
        .await
        .expect_err("atproto-proxy targeting #atproto_mls must be rejected");
        let resp = err.into_response();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "atproto-proxy '{mls_proxy}' must return 403 Forbidden"
        );
    }

    // Non-MLS unknown service fragment still returns 400 Bad Request.
    let mut bad_headers = HeaderMap::new();
    bad_headers.insert(
        "atproto-proxy",
        HeaderValue::from_static("did:web:evil.example#svc"),
    );
    let err = catbird::handlers::atproto::proxy_xrpc(
        State(state),
        Extension(session),
        None,
        Some(Extension(dpop)),
        Method::GET,
        Path("app.bsky.actor.getProfile".to_string()),
        RawQuery(Some("actor=alice.test".into())),
        bad_headers,
        Body::empty(),
    )
    .await
    .expect_err("unknown non-MLS atproto-proxy must be rejected");
    assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_service_auth_permits_user_declared_atproto_mls_did_and_rejects_arbitrary_aud() {
    let plc_mock = MockServer::start().await;
    let pds_mock = MockServer::start().await;
    let user_did = "did:plc:z72i7hdynmk6r22z27h6tvur";

    Mock::given(method("GET"))
        .and(path(format!("/{user_did}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": user_did,
            "verificationMethod": [],
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": pds_mock.uri(),
                },
                {
                    "id": "#atproto_mls",
                    "type": "AtprotoMLSDeliveryService",
                    "serviceEndpoint": "https://my-ds.example.org",
                }
            ]
        })))
        .mount(&plc_mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.server.getServiceAuth"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({ "token": "custom-mls-ds-jwt-123" })),
        )
        .mount(&pds_mock)
        .await;

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost:5432/postgres".to_string());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&db_url)
        .await
        .expect("connect to local postgres");

    let mut config = AppConfig::test_default();
    config.push.service_did = Some("did:web:api.catbird.blue".into());
    let resolver = Arc::new(HttpMlsDsIdentityResolver::new(
        reqwest::Client::new(),
        plc_mock.uri(),
    ));
    let gw_config =
        PushGatewayConfig::from_push_and_server_config(&config.push, "https://api.catbird.blue")
            .expect("push gateway config");
    let live_transport = Arc::new(
        catbird::services::push::gateway::LivePushGatewayTransport::from_config(
            &config.push.apns,
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let gateway = Arc::new(PushGatewayService::new(
        pool.clone(),
        gw_config,
        resolver,
        live_transport,
    ));
    let push_services = PushServices::new(pool.clone(), config.push.clone())
        .unwrap()
        .with_gateway(gateway);

    let redis = test_redis_manager().await;
    let state = Arc::new(AppState {
        config: Arc::new(config),
        http_client: reqwest::Client::new(),
        raw_http_client: reqwest::Client::new(),
        redis,
        push_db: Some(pool),
        key_store: None,
        jacquard_client: None,
        catmos_jacquard_client: None,
        catmos_oauth_scopes: vec![],
        trusted_proxies: vec![],
        auth_store: None,
        push: Some(Arc::new(push_services)),
        dpop_nonce_cache: Arc::new(catbird::services::DpopNonceCache::new()),
        session_encryption_key: Some([0x5Au8; 32]),
        active_stream_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        rate_limit: Arc::new(catbird::middleware::RateLimitState::default()),
        session_index_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        session_index_readiness: Arc::new(tokio::sync::Notify::new()),
    });

    let session = CatbirdSession {
        id: Uuid::new_v4(),
        did: user_did.into(),
        handle: "alice.test".into(),
        pds_url: pds_mock.uri(),
        access_token: "mock-access".into(),
        refresh_token: "mock-refresh".into(),
        scopes: vec!["atproto".into()],
        access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
        created_at: Utc::now(),
        last_used_at: Utc::now(),
        granted_scopes: vec!["atproto".into()],
    };
    let dpop = test_dpop_data();

    // 1. User's custom #atproto_mls DID (`did:web:my-ds.example.org`) succeeds with 200!
    let ok_resp = catbird::handlers::atproto::proxy_xrpc(
        State(state.clone()),
        Extension(session.clone()),
        None,
        Some(Extension(dpop.clone())),
        Method::GET,
        Path("com.atproto.server.getServiceAuth".to_string()),
        RawQuery(Some(
            "aud=did:web:my-ds.example.org&lxm=blue.catbird.chat.submitFrame".into(),
        )),
        HeaderMap::new(),
        Body::empty(),
    )
    .await
    .expect("getServiceAuth for user's declared #atproto_mls DID must succeed");
    assert_eq!(ok_resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(ok_resp.into_body(), 16 * 1024)
        .await
        .unwrap();
    let json_val: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json_val["token"], "custom-mls-ds-jwt-123");

    // 2. Arbitrary unassociated audience DID (`did:web:unassociated.example.org`) fails with 400!
    let err = catbird::handlers::atproto::proxy_xrpc(
        State(state),
        Extension(session),
        None,
        Some(Extension(dpop)),
        Method::GET,
        Path("com.atproto.server.getServiceAuth".to_string()),
        RawQuery(Some(
            "aud=did:web:unassociated.example.org&lxm=blue.catbird.chat.submitFrame".into(),
        )),
        HeaderMap::new(),
        Body::empty(),
    )
    .await
    .expect_err("unassociated service-auth aud must be rejected");
    assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oauth_client_config_route_serves_fail_closed_defaults_without_authentication() {
    let config = AppConfig::test_default();
    let state = base_test_state(config).await;
    let router = create_router(state.clone()).with_state(state);

    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/client-config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let payload: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        payload,
        json!({
            "mlsChatEnabled": false,
            "circlesSpacesEnabled": false,
        })
    );
}
