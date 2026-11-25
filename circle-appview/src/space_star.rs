//! Strict DASL STAR v0.2 repository replacement, delegated to `atproto-spaces`.
//! No records escape before full digest validation.
use crate::{
    commit::{json_to_ipld, LtHash},
    error::AppError,
    space_mac::Commit,
};
use bytes::Bytes;
use catbird_atproto::jacquard_common::types::{
    aturi::AtSpaceUri,
    string::{Did, Tid},
    value::Data,
};

pub const MAX_STAR_BYTES: usize = 50 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = atproto_spaces::star::MAX_METADATA_BYTES;
pub const MAX_KEY_BYTES: usize = atproto_spaces::star::MAX_KEY_BYTES;
pub const MAX_RECORD_BYTES: usize = atproto_spaces::star::MAX_RECORD_BYTES;
pub const MAX_RECORDS: usize = 10_000;
pub const MAGIC: &[u8] = &atproto_spaces::star::STAR_LITE_MAGIC;
pub type RepoRecords = Vec<(String, String, String, serde_json::Value)>;

pub struct RepoSnapshot {
    pub commit: Commit,
    pub records: RepoRecords,
    pub lthash: LtHash,
}

fn invalid(message: impl std::fmt::Display) -> AppError {
    AppError::InvalidRequest(format!("Invalid STAR: {message}"))
}

fn commit_from_meta(meta: &atproto_spaces::star::StarCommitMetadata) -> Result<Commit, AppError> {
    let space =
        AtSpaceUri::new_owned(meta.space.clone()).map_err(|_| invalid("invalid space URI"))?;
    let repo = Did::new_owned(meta.repo.clone()).map_err(|_| invalid("invalid repo DID"))?;
    let rev = Tid::new(meta.rev.as_str()).map_err(|_| invalid("invalid rev TID"))?;
    Ok(Commit {
        space,
        repo,
        rev,
        data: Bytes::copy_from_slice(&meta.data),
        ver: 1,
        extra_data: None,
    })
}

/// Parse and validate ONLY the leading STAR metadata frame (`<= 64 KiB`) so the HTTP
/// transport can verify the commit MAC BEFORE any record frames are parsed.
pub fn read_commit(bytes: &[u8], space: &str, repo: &str) -> Result<Commit, AppError> {
    if bytes.len() > MAX_STAR_BYTES {
        return Err(invalid("archive exceeds limit"));
    }
    let meta = atproto_spaces::star::read_star_metadata(bytes, space, repo).map_err(invalid)?;
    commit_from_meta(&meta)
}

pub fn parse_repo_star(bytes: &[u8], space: &str, repo: &str) -> Result<RepoSnapshot, AppError> {
    if bytes.len() > MAX_STAR_BYTES {
        return Err(invalid("archive exceeds limit"));
    }
    let parsed = atproto_spaces::star::read_star_repo(bytes, space, repo).map_err(invalid)?;
    if parsed.records.len() > MAX_RECORDS {
        return Err(invalid("too many records"));
    }
    let meta = atproto_spaces::star::StarCommitMetadata {
        space: parsed.space,
        repo: parsed.repo,
        rev: parsed.rev,
        data: parsed.data,
    };
    let commit = commit_from_meta(&meta)?;

    let mut records = Vec::with_capacity(parsed.records.len());
    let mut lthash = LtHash::default();
    for rec in parsed.records {
        let value: Data<jacquard_common::SmolStr> =
            serde_ipld_dagcbor::from_slice(&rec.record_dagcbor)
                .map_err(|_| invalid("invalid DRISL"))?;
        let json = serde_json::to_value(value).map_err(|_| invalid("invalid record JSON"))?;
        json_to_ipld(&json).map_err(|_| invalid("invalid record value"))?;
        if !json.is_object() {
            return Err(invalid("record must be a map"));
        }
        let cid_str = rec.cid.to_string();
        lthash.add(&format!("{}/{cid_str}", rec.path));
        records.push((rec.collection, rec.rkey, cid_str, json));
    }
    if lthash.digest() != meta.data {
        return Err(invalid("digest mismatch"));
    }
    Ok(RepoSnapshot {
        commit,
        records,
        lthash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::create_cid_bytes_from_data;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Meta {
        #[serde(rename = "$type")]
        kind: String,
        ver: i64,
        repo: String,
        space: String,
        rev: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    }

    fn append_frame(out: &mut Vec<u8>, bytes: &[u8]) {
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

    fn archive(pairs: &[(&str, &[u8])]) -> Vec<u8> {
        let mut hash = LtHash::default();
        for (path, bytes) in pairs {
            hash.add(&format!("{path}/{}", create_cid_bytes_from_data(bytes).1));
        }
        let meta = Meta {
            kind: "atproto-space-repo".into(),
            ver: 1,
            repo: "did:plc:author".into(),
            space: "at:space/did:plc:authority/blue.catbird.circle/test".into(),
            rev: "3jzfcijpj2m2a".into(),
            data: hash.digest().to_vec(),
        };
        let mut bytes = MAGIC.to_vec();
        append_frame(&mut bytes, &serde_ipld_dagcbor::to_vec(&meta).unwrap());
        for (path, value) in pairs {
            bytes.push(0x01);
            append_frame(&mut bytes, path.as_bytes());
            append_frame(&mut bytes, value);
        }
        bytes.push(0x00);
        bytes
    }

    fn parse(bytes: &[u8]) -> Result<RepoSnapshot, AppError> {
        parse_repo_star(
            bytes,
            "at:space/did:plc:authority/blue.catbird.circle/test",
            "did:plc:author",
        )
    }

    #[test]
    fn empty_and_record_roundtrip() {
        assert!(parse(&archive(&[])).unwrap().records.is_empty());
        let value = serde_ipld_dagcbor::to_vec(&serde_json::json!({"text":"hello"})).unwrap();
        assert_eq!(
            parse(&archive(&[("app.bsky.feed.post/a", &value)]))
                .unwrap()
                .records
                .len(),
            1
        );
    }

    #[test]
    fn rejects_duplicate_order_truncation_digest() {
        let value = serde_ipld_dagcbor::to_vec(&serde_json::json!({"text":"hello"})).unwrap();
        for keys in [
            ["app.bsky.feed.post/a", "app.bsky.feed.post/a"],
            ["app.bsky.feed.post/b", "app.bsky.feed.post/a"],
        ] {
            assert!(parse(&archive(&[(keys[0], &value), (keys[1], &value)])).is_err());
        }
        let mut bytes = archive(&[("app.bsky.feed.post/a", &value)]);
        bytes.pop();
        assert!(parse(&bytes).is_err());

        let mut bytes = archive(&[]);
        bytes.push(0x80);
        bytes.push(0);
        assert!(parse(&bytes).is_err());

        let mut bytes = archive(&[("app.bsky.feed.post/a", &value)]);
        let end = bytes.len() - 1;
        bytes[end] ^= 1;
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn rejects_missing_end_bad_control_and_trailing_bytes() {
        let complete = archive(&[]);
        assert_eq!(complete.last(), Some(&0x00));

        let mut missing_end = complete.clone();
        missing_end.pop();
        assert!(parse(&missing_end).is_err());

        let mut bad_control = complete.clone();
        *bad_control.last_mut().unwrap() = 0x02;
        assert!(parse(&bad_control).is_err());

        let mut trailing = complete;
        trailing.push(0xff);
        assert!(parse(&trailing).is_err());
    }

    #[test]
    fn rejects_noncanonical_or_forbidden_records_even_with_matching_digest() {
        for record in [
            vec![0xa2, 0x62, b'a', b'a', 1, 0x61, b'b', 2], // wrong map-key order
            vec![0xa2, 0x61, b'a', 1, 0x61, b'a', 2],       // duplicate map key
            serde_ipld_dagcbor::to_vec(&serde_json::json!({"float":1.5})).unwrap(),
            serde_ipld_dagcbor::to_vec(&serde_json::json!([1, 2])).unwrap(),
        ] {
            assert!(parse(&archive(&[("app.bsky.feed.post/a", &record)])).is_err());
        }
    }

    #[test]
    fn rejects_wrong_metadata_context_and_non_utf8_paths() {
        let bytes = archive(&[]);
        assert!(parse_repo_star(
            &bytes,
            "at:space/did:plc:other/blue.catbird.circle/test",
            "did:plc:author"
        )
        .is_err());
        assert!(parse_repo_star(
            &bytes,
            "at:space/did:plc:authority/blue.catbird.circle/test",
            "did:plc:other"
        )
        .is_err());

        let invalid_meta = Meta {
            kind: "atproto-space-repo".into(),
            ver: 2,
            repo: "did:plc:author".into(),
            space: "at:space/did:plc:authority/blue.catbird.circle/test".into(),
            rev: "3jzfcijpj2m2a".into(),
            data: LtHash::default().digest().to_vec(),
        };
        let mut invalid_version = MAGIC.to_vec();
        append_frame(
            &mut invalid_version,
            &serde_ipld_dagcbor::to_vec(&invalid_meta).unwrap(),
        );
        invalid_version.push(0x00);
        assert!(parse(&invalid_version).is_err());

        let mut invalid_path = bytes;
        invalid_path.pop();
        invalid_path.push(0x01);
        append_frame(&mut invalid_path, &[0xff]);
        append_frame(&mut invalid_path, &[0xa0]);
        invalid_path.push(0x00);
        assert!(parse(&invalid_path).is_err());
    }

    #[test]
    fn rejects_oversized_record() {
        let value = vec![0; MAX_RECORD_BYTES + 1];
        assert!(parse(&archive(&[("app.bsky.feed.post/a", &value)])).is_err());
    }

    #[test]
    fn rejects_oversized_key() {
        let key = "a".repeat(MAX_KEY_BYTES + 1);
        let value = serde_ipld_dagcbor::to_vec(&serde_json::json!({})).unwrap();
        assert!(parse(&archive(&[(key.as_str(), value.as_slice())])).is_err());
    }
}
