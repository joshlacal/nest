//! Local current-wire fixtures; injected transport tests do not qualify host interoperability.
#![allow(dead_code)]
use circle_appview::{
    commit::{json_to_ipld, RepoRecord},
    space_mac::Commit,
};
use sha2::{Digest, Sha256};

pub fn fixture_commit(space: &str, repo: &str, rev: &str, state: &[u8; 2048]) -> Commit {
    Commit {
        space: catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new_owned(space)
            .unwrap(),
        repo: repo.to_owned().into(),
        rev: rev.to_owned().into(),
        ver: 1,
        data: bytes::Bytes::copy_from_slice(&Sha256::digest(state)),
        extra_data: None,
    }
}
pub fn fixture_star(commit: &Commit, records: &[RepoRecord]) -> anyhow::Result<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct Meta<'a> {
        #[serde(rename = "$type")]
        kind: &'static str,
        ver: i64,
        repo: &'a str,
        space: &'a str,
        rev: &'a str,
        #[serde(with = "serde_bytes")]
        data: &'a [u8],
    }
    let meta = Meta {
        kind: "atproto-space-repo",
        ver: commit.ver,
        repo: commit.repo.as_str(),
        space: commit.space.as_str(),
        rev: commit.rev.as_str(),
        data: commit.data.as_ref(),
    };
    let mut out = circle_appview::space_star::MAGIC.to_vec();
    frame(&mut out, &serde_ipld_dagcbor::to_vec(&meta)?);
    let mut records: Vec<_> = records.iter().collect();
    records.sort_by_key(|r| format!("{}/{}", r.collection, r.rkey));
    for r in records {
        frame(&mut out, format!("{}/{}", r.collection, r.rkey).as_bytes());
        frame(
            &mut out,
            &serde_ipld_dagcbor::to_vec(&json_to_ipld(&r.value)?)?,
        );
    }
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
