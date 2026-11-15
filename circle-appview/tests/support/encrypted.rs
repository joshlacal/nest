//! Fixtures shared by the encrypted-Circle suites (`encrypted_sync`, `encrypted_views`):
//! record builders, a mock space-host `listRepoOps` server, DID-document registration and
//! the common `AppState` / circle rows. Each suite keeps its own DIDs and space URIs and
//! passes them in.
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::{json, Value};
use sqlx::PgPool;

use catbird_atproto::generated::com_atproto::space::list_repo_ops::{ListRepoOpsOutput, OpEntry};
use catbird_atproto::jacquard_common::types::cid::Cid;
use catbird_atproto::jacquard_common::types::nsid::Nsid;
use catbird_atproto::jacquard_common::types::recordkey::RecordKey;
use catbird_atproto::jacquard_common::types::string::Rkey;
use catbird_atproto::jacquard_common::types::tid::Tid;

use circle_appview::access::{ActiveSpaceCredential, CredentialStore};
use circle_appview::auth::{
    DidDocument, DidResolver, DidService, PublicKeyJwk, VerificationMethod,
};
use circle_appview::commit::{compute_dagcbor_cid, json_to_ipld, LtHash, RepoRecord};
use circle_appview::config::{AppState, Config};
use circle_appview::space_client::{MockSpaceHostTransport, SpaceClient};
use circle_appview::sync::{SyncEngine, SyncResult};

pub const ENCRYPTED_TYPE: &str = "blue.catbird.circle.encrypted";
pub const KEY: &str = "blue.catbird.circle.key";
pub const POST: &str = "blue.catbird.circle.post";
pub const CIRCLE_ID: &str = "3jzfcijpj2z2a";
pub const NOW: &str = "2026-11-07T00:00:00.000Z";
pub const LATER: &str = "2026-11-07T00:05:00.000Z";
pub const REV: &str = "3l7aaaaaaaaaa";
/// Hawk wrap of a 32-byte plaintext: 1 + 32 + 1088 header, 32 body, 16 tag.
pub const WRAP_LEN: usize = 1 + 32 + 1088 + 32 + 16;

pub fn b64(n: usize) -> Value {
    json!({"$bytes": STANDARD_NO_PAD.encode(vec![7u8; n])})
}

/// A conformant 8-recipient `blue.catbird.circle.key` record sent by `owner_did`.
pub fn key_record(owner_did: &str, kv: i64) -> Value {
    json!({
        "$type": KEY,
        "circleId": CIRCLE_ID,
        "createdAt": NOW,
        "keyVersion": kv,
        "reason": "created",
        "recipients": (0..8).map(|_| b64(WRAP_LEN)).collect::<Vec<_>>(),
        "sender": {
            "$type": "blue.catbird.labyrinth.mek#labyrinthSender",
            "did": owner_did,
            "senderEpoch": {
                "attestation": {"sig": b64(64), "transportPubkey": b64(32)},
                "authPubkey": b64(32),
                "encryptionPubkey": b64(1216),
                "epochHead": b64(32),
                "epochNumber": 0,
                "membersHash": b64(32),
                "selfSig": b64(64),
                "signingPubkey": b64(32),
            },
            "senderEpochHead": b64(32),
        },
    })
}

pub fn envelope(kv: i64) -> Value {
    json!({
        "$type": POST,
        "circleId": CIRCLE_ID,
        "createdAt": NOW,
        "keyVersion": kv,
        "ciphertext": b64(100),
        "sig": b64(64),
        "authorEpochHead": b64(32),
    })
}

pub fn envelope_reply(kv: i64, parent_uri: &str, parent_cid: &str) -> Value {
    let mut v = envelope(kv);
    v["createdAt"] = json!(LATER);
    let r = json!({"uri": parent_uri, "cid": parent_cid});
    v["reply"] = json!({"parent": r, "root": r});
    v
}

/// The record CID as the space host computes it: DAG-CBOR of the IPLD form, where
/// `{"$bytes": ..}` objects are CBOR byte strings.
pub fn cid_of(value: &Value) -> String {
    compute_dagcbor_cid(&json_to_ipld(value).unwrap()).unwrap()
}

/// Serve `records` (collection, rkey, value) as one verified listRepoOps page for `author`.
pub fn serve_ops(
    mock: &MockSpaceHostTransport,
    space: &str,
    author: &str,
    records: &[(&str, &str, Value)],
) {
    let mut lthash = LtHash::default();
    let mut ops = Vec::new();
    for (collection, rkey, value) in records {
        let cid = cid_of(value);
        lthash.add(&format!("{collection}/{rkey}/{cid}"));
        ops.push(OpEntry {
            cid: Some(Cid::from(cid)),
            collection: Nsid::from(collection.to_string()),
            prev: None,
            rev: Tid::from(String::from(REV)),
            rkey: RecordKey::from(Rkey::from(rkey.to_string())),
            value: Some(serde_json::from_value(value.clone()).unwrap()),
            extra_data: None,
        });
    }
    let state: [u8; 2048] = lthash.state().as_slice().try_into().unwrap();
    let commit = super::fixture_commit(space, author, REV, &state);
    mock.set_list_repo_ops_response(
        &format!("{space}:{author}"),
        ListRepoOpsOutput {
            commit,
            cursor: None,
            ops,
            extra_data: None,
        },
    );
}

/// Serve one listRepoOps page at `rev` deleting `deleted` (collection, rkey, value) from a
/// repo that previously held `before`; the commit state is the LtHash of what remains.
pub fn serve_delete_ops(
    mock: &MockSpaceHostTransport,
    space: &str,
    author: &str,
    before: &[(&str, &str, Value)],
    deleted: &[(&str, &str, Value)],
    rev: &str,
) {
    let mut lthash = LtHash::default();
    for (collection, rkey, value) in before {
        lthash.add(&format!("{collection}/{rkey}/{}", cid_of(value)));
    }
    let mut ops = Vec::new();
    for (collection, rkey, value) in deleted {
        let cid = cid_of(value);
        lthash.remove(&format!("{collection}/{rkey}/{cid}"));
        ops.push(OpEntry {
            cid: None,
            collection: Nsid::from(collection.to_string()),
            prev: Some(Cid::from(cid)),
            rev: Tid::from(rev.to_string()),
            rkey: RecordKey::from(Rkey::from(rkey.to_string())),
            value: None,
            extra_data: None,
        });
    }
    let state: [u8; 2048] = lthash.state().as_slice().try_into().unwrap();
    mock.set_list_repo_ops_response(
        &format!("{space}:{author}"),
        ListRepoOpsOutput {
            commit: super::fixture_commit(space, author, rev, &state),
            cursor: None,
            ops,
            extra_data: None,
        },
    );
}

/// Force `author`'s next sync into full recovery: the listRepoOps commit does not match
/// its (empty) ops, and getRepo serves `records` at revision `rev`.
pub fn serve_full_recovery(
    mock: &MockSpaceHostTransport,
    space: &str,
    author: &str,
    records: &[(&str, &str, Value)],
    rev: &str,
) {
    let key = format!("{space}:{author}");
    let mut bad = LtHash::default();
    bad.add("app.bsky.feed.post/3l7tampered11/bafytamperedcid");
    let bad_state: [u8; 2048] = bad.state().as_slice().try_into().unwrap();
    mock.set_list_repo_ops_response(
        &key,
        ListRepoOpsOutput {
            commit: super::fixture_commit(space, author, rev, &bad_state),
            cursor: None,
            ops: vec![],
            extra_data: None,
        },
    );
    let mut lthash = LtHash::default();
    let repo_records: Vec<RepoRecord> = records
        .iter()
        .map(|(collection, rkey, value)| {
            let cid = cid_of(value);
            lthash.add(&format!("{collection}/{rkey}/{cid}"));
            RepoRecord {
                collection: collection.to_string(),
                rkey: rkey.to_string(),
                cid,
                value: value.clone(),
            }
        })
        .collect();
    let state: [u8; 2048] = lthash.state().as_slice().try_into().unwrap();
    let commit = super::fixture_commit(space, author, rev, &state);
    mock.set_get_repo_response(&key, super::fixture_star(&commit, &repo_records).unwrap());
}

pub async fn sync(state: &AppState, space: &str, author: &str) -> SyncResult {
    SyncEngine::new(state)
        .sync_repo(space, author)
        .await
        .unwrap()
}

pub fn register_did_doc(
    resolver: &DidResolver,
    did: &str,
    key: &SigningKey,
    services: Vec<DidService>,
) {
    let point = EncodedPoint::from(key.verifying_key());
    let jwk = PublicKeyJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        y: Some(URL_SAFE_NO_PAD.encode(point.y().unwrap())),
        kid: None,
    };
    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(key.verifying_key().to_encoded_point(true).as_bytes());
    let multibase = multibase::encode(multibase::Base::Base58Btc, &multikey);
    let vm = |fragment: &str| VerificationMethod {
        id: format!("{did}#{fragment}"),
        r#type: "Multikey".into(),
        controller: did.into(),
        public_key_jwk: Some(jwk.clone()),
        public_key_multibase: Some(multibase.clone()),
    };
    resolver.insert_cached(
        did.into(),
        DidDocument {
            id: did.into(),
            verification_method: vec![vm("atproto"), vm("atproto_space")],
            service: services,
        },
    );
}

pub fn pds(endpoint: &str) -> DidService {
    DidService {
        id: "#atproto_pds".into(),
        r#type: "AtprotoPersonalDataServer".into(),
        service_endpoint: endpoint.into(),
    }
}

/// A DID service entry pointing at the space host (the owner's DID document carries it).
pub fn space_host() -> DidService {
    DidService {
        id: "#atproto_space_host".into(),
        r#type: "AtprotoSpaceHost".into(),
        service_endpoint: "https://space.catbird.blue".into(),
    }
}

pub fn config(service_did: &str, push_key_id: &str) -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: 3002,
        database_url: "postgres://localhost/postgres".into(),
        service_did: service_did.into(),
        plc_directory_url: "https://plc.directory".into(),
        identity_relay_url: Some(url::Url::parse("wss://relay.fixture.example.com/").unwrap()),
        public_appview_url: "https://public.api.bsky.app".into(),
        circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
        appview_base_url: "http://127.0.0.1:3002".into(),
        oauth_key_id: None,
        oauth_signing_key_path: None,
        oauth_signing_key_hex: None,
        push_key_id: push_key_id.into(),
        push_signing_key_path: None,
        push_signing_key_hex: None,
    }
}

pub fn did_resolver(config: &Config) -> Arc<DidResolver> {
    Arc::new(DidResolver::new(
        config.plc_directory_url.clone(),
        reqwest::Client::builder().no_proxy().build().unwrap(),
    ))
}

/// A credential store holding a live space credential for each of `spaces`.
pub async fn credential_store(spaces: &[&str]) -> Arc<CredentialStore> {
    let store = Arc::new(CredentialStore::new());
    for space in spaces {
        store
            .insert(
                space.to_string(),
                ActiveSpaceCredential {
                    token: "test.space.credential.jwt".to_string(),
                    signing_key: SigningKey::random(&mut OsRng),
                    expires_at: Utc::now() + chrono::Duration::hours(2),
                },
            )
            .await;
    }
    store
}

pub fn app_state(
    pool: &PgPool,
    config: Config,
    resolver: Arc<DidResolver>,
    credentials: Arc<CredentialStore>,
    mock: &Arc<MockSpaceHostTransport>,
) -> AppState {
    AppState::with_services(
        config,
        pool.clone(),
        resolver,
        credentials,
        Arc::new(SpaceClient::with_transport(mock.clone())),
        Arc::new(circle_appview::access::SpaceLockManager::new()),
    )
}

/// Insert a circle for `space`, its fresh member cache (`members`) and cache meta.
/// `space_type` of `None` is a plaintext Circle.
pub async fn insert_circle(
    pool: &PgPool,
    space: &str,
    circle_id: &str,
    owner_did: &str,
    members: &[&str],
    space_type: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, space_type) \
         VALUES ($1, $2, $3, 'Circle', now(), COALESCE($4, 'blue.catbird.circle'))",
    )
    .bind(space)
    .bind(circle_id)
    .bind(owner_did)
    .bind(space_type)
    .execute(pool)
    .await
    .unwrap();
    for member in members {
        sqlx::query(
            "INSERT INTO circle_member_cache (space_uri, member_did, cached_at) VALUES ($1, $2, now())",
        )
        .bind(space)
        .bind(member)
        .execute(pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count) VALUES ($1, now(), $2)",
    )
    .bind(space)
    .bind(members.len() as i32)
    .execute(pool)
    .await
    .unwrap();
}

/// Insert a key row directly at record `uri`, as if first indexed `age_secs` ago.
pub async fn insert_key_row(
    pool: &PgPool,
    space: &str,
    owner_did: &str,
    uri: &str,
    kv: i64,
    age_secs: i64,
) {
    let value = key_record(owner_did, kv);
    sqlx::query(
        "INSERT INTO circle_keys (space_uri, key_version, uri, cid, owner_did, record_json, created_at, indexed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, now(), now() - make_interval(secs => $7))",
    )
    .bind(space)
    .bind(kv)
    .bind(uri)
    .bind(cid_of(&value))
    .bind(owner_did)
    .bind(&value)
    .bind(age_secs as f64)
    .execute(pool)
    .await
    .unwrap();
}
