//! Host compatibility gate: Circles refuse a space host whose credentials are
//! not DPoP-bound (no `cnf.jkt`) with the declared `UnsupportedPDS`, instead of
//! a generic auth failure that the client reads as "sign in again".

use std::sync::Arc;

use axum::response::IntoResponse;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use sqlx::PgPool;

use circle_appview::access::{self, CredentialStore, SpaceLockManager};
use circle_appview::auth::{
    DidDocument, DidResolver, DidService, PublicKeyJwk, VerificationMethod,
};
use circle_appview::commit::CommitVerificationPolicy;
use circle_appview::config::{AppState, Config};
use circle_appview::error::{AppError, AuthReason};
use circle_appview::oauth::UserOAuthSession;
use circle_appview::space_client::{
    mint_mock_space_credential, validate_space_credential, MockSpaceHostTransport, SpaceAppAccess,
    SpaceClient, SpaceConfig, SpacePolicy,
};

const OWNER_DID: &str = "did:plc:owner-host-gate";
const SPACE_URI: &str = "at://did:plc:owner-host-gate/space/blue.catbird.circle/3l7hostgate11";

fn owner_doc(key: &SigningKey) -> DidDocument {
    let point = EncodedPoint::from(key.verifying_key());
    DidDocument {
        id: OWNER_DID.into(),
        verification_method: vec![VerificationMethod {
            id: format!("{OWNER_DID}#atproto"),
            r#type: "JsonWebKey2020".into(),
            controller: OWNER_DID.into(),
            public_key_jwk: Some(PublicKeyJwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                y: Some(URL_SAFE_NO_PAD.encode(point.y().unwrap())),
                kid: None,
            }),
            public_key_multibase: None,
        }],
        service: vec![
            DidService {
                id: "#atproto_space_host".into(),
                r#type: "AtprotoSpaceHost".into(),
                service_endpoint: "https://space.owner.example".into(),
            },
            DidService {
                id: "#atproto_pds".into(),
                r#type: "AtprotoPersonalDataServer".into(),
                service_endpoint: "https://pds.owner.example".into(),
            },
        ],
    }
}

/// A bearer space credential, as Swan profiles 2026-08-15 and 2026-09-10 mint:
/// correctly signed by the authority, but with no `cnf` claim.
fn bearer_credential(key: &SigningKey, typ: &str) -> String {
    let now = Utc::now().timestamp();
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::json!({"typ": typ, "alg": "ES256", "kid": "#atproto"})
            .to_string()
            .as_bytes(),
    );
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "iss": OWNER_DID,
            "sub": SPACE_URI,
            "iat": now,
            "exp": now + 3600,
            "jti": uuid::Uuid::new_v4().to_string(),
        })
        .to_string()
        .as_bytes(),
    );
    let input = format!("{header}.{claims}");
    let sig: p256::ecdsa::Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

#[test]
fn unbound_credential_is_refused_as_unsupported_pds() {
    let key = SigningKey::random(&mut OsRng);
    let doc = owner_doc(&key);
    for typ in ["atproto-space-credential+jwt", "at+jwt"] {
        let err = validate_space_credential(
            &bearer_credential(&key, typ),
            OWNER_DID,
            SPACE_URI,
            "expected-jkt",
            &doc,
        )
        .expect_err("a credential without cnf.jkt must be refused");
        assert!(
            matches!(err, AppError::UnsupportedPds(_)),
            "typ {typ}: expected UnsupportedPds, got {err:?}"
        );
    }
}

#[test]
fn bound_credentials_still_pass_and_wrong_binding_is_an_auth_failure() {
    let key = SigningKey::random(&mut OsRng);
    let doc = owner_doc(&key);
    let expires = Utc::now() + chrono::Duration::hours(1);
    let bound = mint_mock_space_credential(&key, OWNER_DID, SPACE_URI, "jkt-1", expires);
    assert!(validate_space_credential(&bound, OWNER_DID, SPACE_URI, "jkt-1", &doc).is_ok());
    assert!(matches!(
        validate_space_credential(&bound, OWNER_DID, SPACE_URI, "jkt-2", &doc),
        Err(AppError::Unauthorized(AuthReason::IdMismatch))
    ));
}

#[tokio::test]
async fn unsupported_pds_is_the_declared_wire_error() {
    let resp = AppError::UnsupportedPds("bearer host".into()).into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "UnsupportedPDS");
}

#[sqlx::test(migrations = "./migrations")]
async fn activation_refuses_a_bearer_space_host_without_creating_a_circle(pool: PgPool) {
    std::env::set_var(
        "SESSION_ENCRYPTION_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let owner_key = SigningKey::random(&mut OsRng);
    let config = Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: "did:web:circles.catbird.blue#atproto_circles".into(),
        plc_directory_url: "https://plc.directory".into(),
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: "did:web:circles.catbird.blue#atproto_circles".into(),
        push_signing_key_path: None,
        push_signing_key_hex: None,
        commit_verification_policy: CommitVerificationPolicy::default(),
    };
    let did_resolver = Arc::new(DidResolver::new(
        config.plc_directory_url.clone(),
        reqwest::Client::builder().no_proxy().build().unwrap(),
    ));
    did_resolver.insert_cached(OWNER_DID.into(), owner_doc(&owner_key));

    let mock = Arc::new(MockSpaceHostTransport::new());
    let state = AppState::with_services(
        config,
        pool.clone(),
        did_resolver,
        Arc::new(CredentialStore::new()),
        Arc::new(SpaceClient::with_transport(mock.clone())),
        Arc::new(SpaceLockManager::new()),
    );
    state
        .oauth_service
        .store_session(UserOAuthSession {
            user_did: OWNER_DID.into(),
            access_token: "owner-access-token".into(),
            refresh_token: None,
            token_endpoint: "https://pds.owner.example/oauth/token".into(),
            auth_server_iss: "https://pds.owner.example".into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: SigningKey::random(&mut OsRng),
        })
        .await
        .unwrap();
    mock.set_space_config(
        SPACE_URI,
        SpaceConfig {
            authority: OWNER_DID.into(),
            space_type: "blue.catbird.circle".into(),
            skey: "3l7hostgate11".into(),
            app_access: SpaceAppAccess::AllowList(vec![state.oauth_service.client_id.clone()]),
            read_policy: SpacePolicy::MemberList,
            write_policy: SpacePolicy::MemberList,
            user_policy: None,
            name: None,
            description: None,
        },
    );
    mock.set_space_members(SPACE_URI, vec![OWNER_DID.into()]);
    mock.set_credential_response(
        SPACE_URI,
        Ok(bearer_credential(
            &owner_key,
            "atproto-space-credential+jwt",
        )),
    );

    let err = access::activate_circle(&state, OWNER_DID, SPACE_URI)
        .await
        .expect_err("a bearer space host must be refused");
    assert!(
        matches!(err, AppError::UnsupportedPds(_)),
        "expected UnsupportedPds, got {err:?}"
    );
    let circles: i64 = sqlx::query_scalar("SELECT count(*) FROM circles")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(circles, 0, "no Circle is created on an unsupported host");
    assert!(state.credential_store.get(SPACE_URI).await.is_none());
}
