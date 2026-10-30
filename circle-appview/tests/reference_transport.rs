//! Opt-in protocol evidence against the real pinned local TypeScript reference hosts.
//! This test never logs fixture tokens, records, keys, or private selectors.
use circle_appview::{
    auth::DidDocument,
    space_client::{
        validate_space_credential, DefaultSpaceHostTransport, SpaceCredentialRequest,
        SpaceHostTransport,
    },
    space_mac::{encapsulate, kem_key},
    space_signature::{credential_headers, p256_did_key},
    space_star::parse_repo_star,
};
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Context {
    source_revision: String,
    space: String,
    authority: Host,
    delegation_token: String,
    repos: Vec<Host>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Host {
    did: String,
    service: String,
    document: DidDocument,
    expected_records: Option<usize>,
}
fn endpoint(host: &Host, method: &str) -> url::Url {
    let base = url::Url::parse(&host.service).expect("valid fixture origin");
    assert!(
        matches!(base.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        "reference fixture must use loopback"
    );
    base.join(&format!("/xrpc/com.atproto.space.{method}"))
        .expect("valid XRPC endpoint")
}

#[tokio::test]
#[ignore = "requires a running synthetic reference lab and a 0600 CIRCLE_REFERENCE_CONTEXT file"]
async fn actual_reference_hosts_verify_exchange_commit_ops_and_star() {
    let path =
        std::env::var("CIRCLE_REFERENCE_CONTEXT").expect("CIRCLE_REFERENCE_CONTEXT is required");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path)
                .expect("context metadata")
                .permissions()
                .mode()
                & 0o077,
            0,
            "context must be private"
        );
    }
    let context: Context =
        serde_json::from_slice(&std::fs::read(path).expect("private context exists"))
            .expect("context schema");
    assert_eq!(
        context.source_revision,
        "5d88b414a98de1ada22c94c78fa0667a7028163c"
    );
    let transport = DefaultSpaceHostTransport::with_loopback(true);
    let key = SigningKey::random(&mut OsRng);
    let kid = p256_did_key(key.verifying_key());
    let request = SpaceCredentialRequest {
        space: context.space.clone(),
        credential_kid: kid.clone(),
        delegation_token: Some(context.delegation_token),
        client_attestation: None,
    };
    let credential = transport
        .get_space_credential(
            &endpoint(&context.authority, "getSpaceCredential"),
            &request,
        )
        .await
        .expect("real body-only credential exchange");
    validate_space_credential(
        &credential,
        &context.authority.did,
        &context.space,
        &kid,
        &context.authority.document,
    )
    .expect("authority signature, exact kid and credential binding");
    let mut verified_records = 0;
    for host in &context.repos {
        let kem = kem_key(&host.document, &host.did).expect("real PLC KEM key");
        let auth = || {
            let mut headers = credential_headers(&key, &credential, &host.did);
            headers.mac = Some(encapsulate(&kem).expect("fresh DHKEM request"));
            headers
        };
        let latest = transport
            .get_latest_commit(
                &endpoint(host, "getLatestCommit"),
                &auth(),
                &context.space,
                &host.did,
            )
            .await
            .expect("real latest commit MAC");
        let ops = transport
            .list_repo_ops(
                &endpoint(host, "listRepoOps"),
                &auth(),
                &context.space,
                &host.did,
                None,
                None,
            )
            .await
            .expect("real operations MAC");
        let ops_commit = ops.commit.expect("complete operations page has commit");
        assert_eq!(ops_commit.data, latest.data);
        assert_eq!(ops_commit.rev, latest.rev);
        let bytes = transport
            .get_repo(
                &endpoint(host, "getRepo"),
                &auth(),
                &context.space,
                &host.did,
                None,
            )
            .await
            .expect("real STAR transport MAC and digest");
        let repo =
            parse_repo_star(&bytes, &context.space, &host.did).expect("complete real STAR decode");
        assert_eq!(repo.commit.data, latest.data);
        assert_eq!(repo.commit.rev, latest.rev);
        assert_eq!(
            repo.records.len(),
            host.expected_records.expect("expected count")
        );
        verified_records += repo.records.len();
    }
    println!("reference revision {}; verified authority exchange and commit/ops/STAR on {} hosts, {} records", context.source_revision, context.repos.len(), verified_records);
}
