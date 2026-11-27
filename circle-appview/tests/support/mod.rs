//! Local current-wire fixtures; injected transport tests do not qualify host interoperability.
#![allow(dead_code)]
pub mod encrypted;
use circle_appview::{
    commit::{json_to_ipld, RepoRecord},
    space_mac::Commit,
};
use sha2::{Digest, Sha256};

pub fn fixture_commit(space: &str, repo: &str, rev: &str, state: &[u8; 2048]) -> Commit {
    Commit {
        space: petrel_core::SpaceRef::parse(space).unwrap(),
        repo: petrel_core::Did::parse(repo).unwrap(),
        rev: petrel_core::Tid::parse(rev).unwrap(),
        ver: 1,
        data: petrel_core::Bytes(Sha256::digest(state).to_vec()),
        extra_data: None,
    }
}
pub fn fixture_star(commit: &Commit, records: &[RepoRecord]) -> anyhow::Result<Vec<u8>> {
    use petrel_core::Value;
    let meta = Value::Object(
        [
            ("$type", Value::String("atproto-space-repo".into())),
            ("ver", Value::Integer(commit.ver)),
            ("repo", Value::String(commit.repo.as_str().into())),
            ("space", Value::String(commit.space.as_str().into())),
            ("rev", Value::String(commit.rev.as_str().into())),
            ("data", Value::Bytes(commit.data.0.clone())),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
    );
    let mut out = circle_appview::space_star::MAGIC.to_vec();
    frame(&mut out, &petrel_core::dagcbor::try_encode(&meta)?);
    let mut records: Vec<_> = records.iter().collect();
    records.sort_by_key(|r| format!("{}/{}", r.collection, r.rkey));
    for r in records {
        out.push(0x01);
        frame(&mut out, format!("{}/{}", r.collection, r.rkey).as_bytes());
        frame(
            &mut out,
            &petrel_core::dagcbor::try_encode(&json_to_ipld(&r.value)?)?,
        );
    }
    out.push(0x00);
    Ok(out)
}
pub fn frame(out: &mut Vec<u8>, bytes: &[u8]) {
    let mut n = bytes.len();
    loop {
        let b = (n & 127) as u8;
        n >>= 7;
        out.push(if n > 0 { b | 128 } else { b });
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(bytes);
}

/// Explicit healthy local ledger state. This is a route-gate fixture, not relay qualification.
pub async fn healthy_identity_fixture(pool: &sqlx::PgPool, dids: &[&str]) {
    sqlx::query("INSERT INTO circle_identity_cursor(relay_url,cursor,last_event_at,last_received_at,reconciled_at,caught_up) VALUES('wss://relay.fixture.example.com/',1,now(),now(),now(),true) ON CONFLICT(relay_url) DO UPDATE SET last_received_at=now(),caught_up=true,reconciled_at=now(),blocked_reason=NULL,replay_invalid=false")
        .execute(pool).await.unwrap();
    for did in dids {
        sqlx::query("INSERT INTO circle_account_status(did,active,pds_url,source_seq,relay_url) VALUES($1,true,'https://pds.fixture.example.com',1,'wss://relay.fixture.example.com/') ON CONFLICT(did) DO NOTHING")
            .bind(did).execute(pool).await.unwrap();
    }
}

/// The plaintext arm of a feed item; the plaintext view suites index only plaintext posts.
pub fn plain(
    item: &petrel_catbird::generated::blue::catbird::circle::defs::FeedItem,
) -> &petrel_api::generated::app::bsky::feed::defs::FeedViewPost {
    match &item.post {
        petrel_catbird::generated::blue::catbird::circle::defs::FeedItemPost::FeedViewPost(v) => v,
        _ => {
            panic!("expected a plaintext feedViewPost")
        }
    }
}
