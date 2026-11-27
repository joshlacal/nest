//! Real Redis conversion and rollback checks with synthetic grants.
use catbird::services::{
    petrel_storage::RedisSessionSecrets,
    redis_crypto::{open_v2_with_metadata, seal_v2_with_metadata, EnvelopeMetadata},
    RedisAuthStore,
};
use petrel::crypto::{base64url, DpopSigner, SoftwareDpopSigner};
use petrel_core::Did;
use redis::AsyncCommands;
use serde_json::{json, Value};

fn grant(did: &Did, id: &str, profile: &str) -> Value {
    let scalar = [37; 32];
    let key = SoftwareDpopSigner::from_bytes(&scalar)
        .unwrap()
        .public_jwk();
    json!({
        "account_did":did.as_str(), "session_id":id, "host_url":"https://pds.example",
        "authserver_url":"https://auth.example/", "authserver_token_endpoint":"https://auth.example/token",
        "scopes":"atproto transition:generic","scope":"atproto transition:generic",
        "dpop_key":{"kty":"EC","crv":"P-256","x":key.x,"y":key.y,"d":base64url(&scalar)},
        "dpop_authserver_nonce":"as-fixture","dpop_host_nonce":"rs-fixture",
        "iss":"https://auth.example","sub":did.as_str(),"aud":"https://pds.example",
        "access_token":"test-access-one","refresh_token":"test-refresh-one","token_type":"DPoP",
        "expires_at":null,"oauth_profile":profile
    })
}

async fn install(store: &RedisAuthStore, did: &Did, id: &str, grant: &Value) -> (String, String) {
    let key = store.session_key(did.as_str(), id);
    let sealed = seal_v2_with_metadata(
        store.enc_key(),
        &grant.to_string(),
        &EnvelopeMetadata::new("session", &key, Some(did.as_str()), None),
    )
    .unwrap();
    let _: () = store
        .redis_connection()
        .set_ex(&key, &sealed, 240)
        .await
        .unwrap();
    (key, sealed)
}

#[tokio::test]
async fn petrel_storage_converts_and_mirrors_one_winning_rotation() {
    let (state, _server, _service, _redis) = super::setup_test_server().await;
    let old_store = state.auth_store.as_ref().unwrap();
    let did = Did::parse("did:plc:abcdefghijklmnopqrstuvwxyz").unwrap();
    for profile in ["catbird", "catmos"] {
        let id = uuid::Uuid::new_v4().to_string();
        let mut original = grant(&did, &id, profile);
        if profile == "catmos" {
            original["expires_at"] = "2031-10-21T17:18:19.123Z".into();
            original["authserver_revocation_endpoint"] = "https://auth.example/revoke".into();
        }
        let (v2, unchanged) = install(old_store, &did, &id, &original).await;
        let first = RedisSessionSecrets::new(old_store, &did, &id);
        let second = RedisSessionSecrets::new(old_store, &did, &id);
        let (a, b) = tokio::join!(first.load_or_convert(), second.load_or_convert());
        let a = a.unwrap().unwrap();
        let b = b.unwrap().unwrap();
        let record = a.get_session(&did).await.unwrap().unwrap();
        assert_eq!(
            **a.get_dpop_key(&record.dpop_key_id)
                .await
                .unwrap()
                .as_ref()
                .unwrap(),
            [37; 32]
        );
        assert_eq!(record.session.access_token(), "test-access-one");
        assert_eq!(
            old_store
                .redis_connection()
                .get::<_, String>(&v2)
                .await
                .unwrap(),
            unchanged
        );
        assert_eq!(
            record.account.expected_issuer.as_deref(),
            Some("https://auth.example")
        );

        let mut replacement = serde_json::to_value(&record).unwrap();
        replacement["session"]["expires_in"] = 900.into();
        replacement["session"]["access_token"] = "test-access-two".into();
        replacement["session"]["refresh_token"] = "test-refresh-two".into();
        let replacement = serde_json::from_value(replacement).unwrap();
        let (won, lost) = tokio::join!(
            a.compare_and_swap_session(&record, &replacement),
            b.compare_and_swap_session(&record, &replacement)
        );
        assert_ne!(won.unwrap(), lost.unwrap());
        let observed = old_store
            .read_session_local(did.as_str(), &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            observed.token_set.refresh_token.as_deref(),
            Some("test-refresh-two")
        );
        let ciphertext = old_store
            .redis_connection()
            .get::<_, String>(&v2)
            .await
            .unwrap();
        let (plain, _, _) =
            open_v2_with_metadata(old_store.enc_key(), &ciphertext, "session", &v2).unwrap();
        let mirrored: Value = serde_json::from_str(&plain).unwrap();
        for field in [
            "host_url",
            "authserver_url",
            "dpop_key",
            "authserver_revocation_endpoint",
            "dpop_host_nonce",
            "oauth_profile",
            "aud",
        ] {
            assert_eq!(original[field], mirrored[field], "rollback lost {field}");
        }
        // Simulate the previous binary refreshing after rollback. A later cutover
        // must import its current grant, even if an older v3 copy still exists.
        let mut rolled_back = mirrored;
        rolled_back["refresh_token"] = "test-refresh-three".into();
        install(old_store, &did, &id, &rolled_back).await;
        assert!(a.get_session(&did).await.is_err());
        let resumed = first.load_or_convert().await.unwrap().unwrap();
        assert_eq!(
            resumed
                .get_session(&did)
                .await
                .unwrap()
                .unwrap()
                .session
                .refresh_token(),
            Some("test-refresh-three")
        );
        let _: () = old_store
            .redis_connection()
            .set_ex(old_store.retired_key(&id), "logout", 60)
            .await
            .unwrap();
        assert!(resumed.get_session(&did).await.unwrap().is_none());
        assert!(resumed.save_session(&record).await.is_err());
    }
}

#[tokio::test]
async fn petrel_storage_flow_field_binding_and_one_use_state() {
    let (state, _server, _service, _redis) = super::setup_test_server().await;
    let store = state.auth_store.as_ref().unwrap();
    let route = uuid::Uuid::new_v4().to_string();
    let a = RedisSessionSecrets::flow_store(store, &route).unwrap();
    let b = RedisSessionSecrets::flow_store(store, &route).unwrap();
    let backend = a.secrets();
    backend
        .put(a.namespace(), "flow-state", b"fixture")
        .await
        .unwrap();
    let (one, two) = tokio::join!(
        backend.take(a.namespace(), "flow-state"),
        b.secrets().take(b.namespace(), "flow-state")
    );
    assert_ne!(one.unwrap().is_some(), two.unwrap().is_some());

    backend
        .put(a.namespace(), "first", b"field secret")
        .await
        .unwrap();
    let fp = store.fingerprint(&route);
    let key = format!("catbird:v3:flow:{fp}");
    let mut conn = store.redis_connection();
    let ciphertext: String = conn.hget(&key, "first").await.unwrap();
    let _: () = conn.hset(&key, "second", &ciphertext).await.unwrap();
    assert!(backend.get(a.namespace(), "second").await.is_err());
    let other_route = uuid::Uuid::new_v4().to_string();
    let other = RedisSessionSecrets::flow_store(store, &other_route).unwrap();
    let other_hash = format!("catbird:v3:flow:{}", store.fingerprint(&other_route));
    let _: () = conn.hset(&other_hash, "first", ciphertext).await.unwrap();
    assert!(other
        .secrets()
        .get(other.namespace(), "first")
        .await
        .is_err());
    backend.delete_namespace(a.namespace()).await.unwrap();
    assert!(!conn.exists::<_, bool>(key).await.unwrap());
}

#[tokio::test]
async fn petrel_storage_upgrades_legacy_v1_and_leaves_unconvertible_records_intact() {
    use aes_gcm::{
        aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
        Aes256Gcm, Nonce,
    };
    use base64::Engine;

    let (state, _server, _service, _redis) = super::setup_test_server().await;
    let store = state.auth_store.as_ref().unwrap();
    let did = Did::parse("did:plc:legacyfixture").unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let original = grant(&did, &id, "catbird");

    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = Aes256Gcm::new_from_slice(store.enc_key())
        .unwrap()
        .encrypt(&Nonce::from(nonce), original.to_string().as_bytes())
        .unwrap();
    let mut envelope = nonce.to_vec();
    envelope.extend(encrypted);
    let v1 = base64::engine::general_purpose::STANDARD.encode(envelope);
    let key = store.session_key(did.as_str(), &id);
    let mut conn = store.redis_connection();
    let _: () = conn.set_ex(&key, v1, 60).await.unwrap();
    let backend = RedisSessionSecrets::new(store, &did, &id);
    backend.load_or_convert().await.unwrap().unwrap();
    let upgraded: String = conn.get(&key).await.unwrap();
    let (json, meta, v1) =
        open_v2_with_metadata(store.enc_key(), &upgraded, "session", &key).unwrap();
    assert!(!v1);
    assert_eq!(meta.did.as_deref(), Some(did.as_str()));
    assert_eq!(serde_json::from_str::<Value>(&json).unwrap(), original);

    let mut invalid = original;
    invalid["token_type"] = "Bearer".into();
    let (_, raw) = install(store, &did, &id, &invalid).await;
    assert!(backend.load_or_convert().await.is_err());
    assert_eq!(conn.get::<_, String>(&key).await.unwrap(), raw);
}

#[tokio::test]
async fn petrel_storage_rollback_refreshes_at_the_same_single_use_provider() {
    use petrel::{
        oauth::{
            ClientAuth, OAuthClient, OAuthConfig, OAuthIdentity, OAuthIdentityError,
            OAuthIdentityResolver,
        },
        rt::BoxFuture,
    };
    use petrel_core::AtIdentifier;
    use std::sync::{Arc, Mutex};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, Request, ResponseTemplate,
    };

    struct Identity(OAuthIdentity);
    impl OAuthIdentityResolver for Identity {
        fn resolve_identity<'a>(
            &'a self,
            _: &'a AtIdentifier,
            _: bool,
        ) -> BoxFuture<'a, Result<OAuthIdentity, OAuthIdentityError>> {
            Box::pin(async { Ok(self.0.clone()) })
        }
    }
    let provider = MockServer::start().await;
    let uri = super::ISSUER;
    let did = Did::parse(super::FIXED_TEST_DID).unwrap();
    super::setup_mock_oauth_provider(&provider, did.as_str(), "atproto transition:generic").await;
    // The HTTP server consumes each fixture refresh token once, regardless of which SDK sent it.
    let accepted = Arc::new(Mutex::new(Vec::new()));
    let calls = accepted.clone();
    let sub = did.to_string();
    Mock::given(method("POST")).and(path("/oauth/token")).respond_with(move |req:&Request| {
        let token=url::form_urlencoded::parse(&req.body).find(|(k,_)|k=="refresh_token").map(|(_,v)|v.into_owned());
        let mut values=calls.lock().unwrap();
        let previous=values.len();
        if token.as_deref()!=["test-refresh-one","test-refresh-two"].get(previous).copied() {
            return ResponseTemplate::new(400).set_body_json(json!({"error":"invalid_grant"}));
        }
        values.push(token.unwrap());
        ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(150)).set_body_json(json!({
            "token_type":"DPoP","access_token":format!("test-access-{}",previous+2),
            "refresh_token":if previous==0 {"test-refresh-two"} else {"test-refresh-three"},
            "expires_in":if previous==0 {1} else {3600},"sub":sub,"scope":"atproto transition:generic"
        }))
    }).with_priority(1).mount(&provider).await;

    let (state, server, _service, _redis) =
        super::setup_test_server_with_provider(Some(&provider)).await;
    let store = state.auth_store.as_ref().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let mut original = grant(&did, &id, "catbird");
    for field in ["authserver_url", "host_url", "iss", "aud"] {
        original[field] = uri.into();
    }
    original["authserver_token_endpoint"] = format!("{uri}/oauth/token").into();
    install(store, &did, &id, &original).await;
    store.write_session_index(&id, did.as_str()).await.unwrap();

    let backend = RedisSessionSecrets::new(store, &did, &id);
    let storage = backend.load_or_convert().await.unwrap().unwrap();
    // The localhost public metadata ID is registered by definition. The old
    // gateway uses its configured confidential assertion on the rollback request.
    let cfg = OAuthConfig::new(
        "http://localhost",
        url::Url::parse("http://127.0.0.1/callback").unwrap(),
        "atproto transition:generic",
        ClientAuth::Public,
    )
    .unwrap()
    .with_loopback_development();
    let identity = Arc::new(Identity(OAuthIdentity {
        did: did.clone(),
        handle: None,
        pds: url::Url::parse(uri).unwrap(),
    }));
    let client = || {
        OAuthClient::new(
            super::petrel_fixture::transport(&provider),
            identity.clone(),
            storage.clone(),
            cfg.clone(),
        )
        .unwrap()
    };
    let a = client();
    let b = client();
    let (r1, r2) = tokio::join!(a.refresh(&did, false), b.refresh(&did, false));
    assert_eq!(r1.unwrap().refresh_token(), Some("test-refresh-two"));
    assert_eq!(r2.unwrap().refresh_token(), Some("test-refresh-two"));
    assert_eq!(accepted.lock().unwrap().len(), 1);
    // Wait for the actual one-second lifetime to expire, then use the gateway's
    // ordinary authenticated HTTP entry point against the same Redis and issuer.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let response = server
        .get("/auth/session")
        .add_header(http::header::AUTHORIZATION, format!("Bearer {id}"))
        .await;
    response.assert_status_ok();
    assert_eq!(
        *accepted.lock().unwrap(),
        ["test-refresh-one", "test-refresh-two"]
    );
    let old = store
        .read_session_local(did.as_str(), &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        old.token_set.refresh_token.as_deref(),
        Some("test-refresh-three")
    );
}
