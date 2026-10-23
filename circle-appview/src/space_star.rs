//! Strict STAR-lite v1 repository replacement. No records escape before full digest validation.
use crate::{
    commit::{create_cid_bytes_from_data, json_to_ipld, LtHash},
    error::AppError,
    space_mac::Commit,
};
use serde::{Deserialize, Serialize};

pub const MAX_STAR_BYTES: usize = 50 * 1024 * 1024;
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_RECORDS: usize = 10_000;
pub const MAGIC: &[u8] = &[0x2a, 0x6c, 0x01, 0x00];
pub type RepoRecords = Vec<(String, String, String, serde_json::Value)>;
pub struct RepoSnapshot {
    pub commit: Commit,
    pub records: RepoRecords,
    pub lthash: LtHash,
}
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
fn invalid(message: &str) -> AppError {
    AppError::InvalidRequest(format!("Invalid STAR: {message}"))
}
fn frame<'a>(input: &mut &'a [u8], max: usize) -> Result<&'a [u8], AppError> {
    let mut len = 0usize;
    let mut done = false;
    for i in 0..6 {
        let (&b, rest) = input
            .split_first()
            .ok_or_else(|| invalid("truncated varint"))?;
        *input = rest;
        len |= ((b & 127) as usize) << (7 * i);
        if b < 128 {
            if i > 0 && b == 0 {
                return Err(invalid("nonminimal varint"));
            }
            done = true;
            break;
        }
    }
    if !done || len > max {
        return Err(invalid("frame length exceeds limit"));
    }
    if input.len() < len {
        return Err(invalid("truncated frame"));
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}
fn canonical(
    bytes: &[u8],
) -> Result<jacquard_common::types::value::Data<jacquard_common::SmolStr>, AppError> {
    let value = serde_ipld_dagcbor::from_slice(bytes).map_err(|_| invalid("invalid DRISL"))?;
    if serde_ipld_dagcbor::to_vec(&value).map_err(|_| invalid("invalid DRISL"))? != bytes {
        return Err(invalid("noncanonical DRISL"));
    }
    // DRISL excludes floats even when a general CBOR decoder can round-trip them.
    let json = serde_json::to_value(&value).map_err(|_| invalid("invalid DRISL value"))?;
    json_to_ipld(&json).map_err(|_| invalid("forbidden DRISL value"))?;
    Ok(value)
}
/// MAC verification is performed by the HTTP transport before it releases these bytes.
/// The parser also checks all metadata, records, framing, canonical encoding and final digest.
pub fn read_commit(bytes: &[u8], space: &str, repo: &str) -> Result<Commit, AppError> {
    if bytes.len() > MAX_STAR_BYTES {
        return Err(invalid("archive exceeds limit"));
    }
    let mut input = bytes
        .strip_prefix(MAGIC)
        .ok_or_else(|| invalid("wrong magic"))?;
    let metadata = frame(&mut input, 64 * 1024)?;
    canonical(metadata)?;
    let meta: Meta =
        serde_ipld_dagcbor::from_slice(metadata).map_err(|_| invalid("invalid metadata"))?;
    if meta.kind != "atproto-space-repo"
        || meta.ver != 1
        || meta.space != space
        || meta.repo != repo
        || meta.data.len() != 32
    {
        return Err(invalid("metadata context mismatch"));
    }
    let commit: Commit =
        serde_ipld_dagcbor::from_slice(metadata).map_err(|_| invalid("invalid commit"))?;
    Ok(commit)
}

pub fn parse_repo_star(bytes: &[u8], space: &str, repo: &str) -> Result<RepoSnapshot, AppError> {
    if bytes.len() > MAX_STAR_BYTES {
        return Err(invalid("archive exceeds limit"));
    }
    let mut input = bytes
        .strip_prefix(MAGIC)
        .ok_or_else(|| invalid("wrong magic"))?;
    let metadata = frame(&mut input, 64 * 1024)?;
    canonical(metadata)?;
    let meta: Meta =
        serde_ipld_dagcbor::from_slice(metadata).map_err(|_| invalid("invalid metadata"))?;
    if meta.kind != "atproto-space-repo"
        || meta.ver != 1
        || meta.space != space
        || meta.repo != repo
        || meta.data.len() != 32
    {
        return Err(invalid("metadata context mismatch"));
    }
    let commit: Commit =
        serde_ipld_dagcbor::from_slice(metadata).map_err(|_| invalid("invalid commit"))?;
    let mut records = Vec::new();
    let mut last: Option<Vec<u8>> = None;
    let mut lthash = LtHash::default();
    while !input.is_empty() {
        if records.len() >= MAX_RECORDS {
            return Err(invalid("too many records"));
        }
        let path_bytes = frame(&mut input, 1024)?;
        if last
            .as_ref()
            .is_some_and(|last| last.as_slice() >= path_bytes)
        {
            return Err(invalid("duplicate or unordered path"));
        }
        let path = std::str::from_utf8(path_bytes).map_err(|_| invalid("non-UTF8 path"))?;
        let (collection, rkey) = path
            .split_once('/')
            .ok_or_else(|| invalid("invalid record path"))?;
        if collection
            .parse::<jacquard_common::types::nsid::Nsid>()
            .is_err()
            || rkey
                .parse::<jacquard_common::types::string::Rkey>()
                .is_err()
        {
            return Err(invalid("invalid collection or rkey"));
        }
        let record_bytes = frame(&mut input, MAX_RECORD_BYTES)?;
        let value = canonical(record_bytes)?;
        let json = serde_json::to_value(value).map_err(|_| invalid("invalid record JSON"))?;
        json_to_ipld(&json).map_err(|_| invalid("invalid record value"))?;
        if !json.is_object() {
            return Err(invalid("record must be a map"));
        }
        let (_, cid) = create_cid_bytes_from_data(record_bytes);
        lthash.add(&format!("{path}/{cid}"));
        records.push((collection.into(), rkey.into(), cid, json));
        last = Some(path_bytes.to_vec());
    }
    if lthash.digest().as_slice() != meta.data {
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
            space: "at://did:plc:authority/space/blue.catbird.circle/test".into(),
            rev: "3jzfcijpj2m2a".into(),
            data: hash.digest().to_vec(),
        };
        let mut bytes = MAGIC.to_vec();
        append_frame(&mut bytes, &serde_ipld_dagcbor::to_vec(&meta).unwrap());
        for (path, value) in pairs {
            append_frame(&mut bytes, path.as_bytes());
            append_frame(&mut bytes, value);
        }
        bytes
    }
    fn parse(bytes: &[u8]) -> Result<RepoSnapshot, AppError> {
        parse_repo_star(
            bytes,
            "at://did:plc:authority/space/blue.catbird.circle/test",
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
    fn rejects_noncanonical_or_forbidden_records_even_with_matching_digest() {
        // Each archive has a digest computed from the exact supplied bytes.
        // The parser must reject the representation, not merely a bad digest.
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
            "at://did:plc:other/space/blue.catbird.circle/test",
            "did:plc:author"
        )
        .is_err());
        assert!(parse_repo_star(
            &bytes,
            "at://did:plc:authority/space/blue.catbird.circle/test",
            "did:plc:other"
        )
        .is_err());
        let mut input = &bytes[MAGIC.len()..];
        let mut meta: Meta =
            serde_ipld_dagcbor::from_slice(frame(&mut input, 65536).unwrap()).unwrap();
        meta.ver = 2;
        let mut invalid_version = MAGIC.to_vec();
        append_frame(
            &mut invalid_version,
            &serde_ipld_dagcbor::to_vec(&meta).unwrap(),
        );
        assert!(parse(&invalid_version).is_err());
        let mut invalid_path = bytes;
        append_frame(&mut invalid_path, &[0xff]);
        append_frame(&mut invalid_path, &[0xa0]);
        assert!(parse(&invalid_path).is_err());
    }

    #[test]
    fn rejects_oversized_record() {
        let value = vec![0; MAX_RECORD_BYTES + 1];
        assert!(parse(&archive(&[("app.bsky.feed.post/a", &value)])).is_err());
    }
}
