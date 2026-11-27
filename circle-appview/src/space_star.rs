//! Strict DASL STAR v0.2 repository replacement, delegated to `petrel_spaces::star`.
//! No records escape before full digest validation.
use crate::{
    commit::{json_to_ipld, LtHash},
    error::AppError,
    space_mac::Commit,
};

pub const MAX_STAR_BYTES: usize = 50 * 1024 * 1024;
/// Largest STAR metadata frame.
pub const MAX_METADATA_BYTES: usize = 64 * 1024;
/// Longest STAR record path (`{collection}/{rkey}`).
pub const MAX_KEY_BYTES: usize = 4 * 1024;
/// Largest DAG-CBOR record in a STAR archive.
pub const MAX_RECORD_BYTES: usize = 1_048_576;
pub const MAX_RECORDS: usize = 10_000;
/// `*l` followed by the little-endian STAR version 1.
pub const MAGIC: &[u8] = &[
    petrel_spaces::STAR_MAGIC[0],
    petrel_spaces::STAR_MAGIC[1],
    petrel_spaces::STAR_VERSION.to_le_bytes()[0],
    petrel_spaces::STAR_VERSION.to_le_bytes()[1],
];
pub type RepoRecords = Vec<(String, String, String, serde_json::Value)>;

pub struct RepoSnapshot {
    pub commit: Commit,
    pub records: RepoRecords,
    pub lthash: LtHash,
}

fn invalid(message: impl std::fmt::Display) -> AppError {
    AppError::InvalidRequest(format!("Invalid STAR: {message}"))
}

/// Length of the metadata frame that follows the 4-byte magic. petrel-spaces bounds
/// the whole archive; the frame limit is this service's own resource bound.
fn metadata_frame_len(bytes: &[u8]) -> Result<usize, AppError> {
    let mut len: u64 = 0;
    for (index, byte) in bytes.iter().skip(MAGIC.len()).take(10).enumerate() {
        len |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return usize::try_from(len).map_err(|_| invalid("metadata frame too large"));
        }
    }
    Err(invalid("truncated metadata frame length"))
}

fn check_metadata_frame(bytes: &[u8]) -> Result<(), AppError> {
    if !bytes.starts_with(MAGIC) {
        return Err(invalid("bad magic"));
    }
    if metadata_frame_len(bytes)? > MAX_METADATA_BYTES {
        return Err(invalid("metadata frame exceeds limit"));
    }
    Ok(())
}

fn commit_from_meta(
    meta: &petrel_spaces::StarRepoMetadata,
    space: &str,
    repo: &str,
) -> Result<Commit, AppError> {
    if meta.space.as_str() != space {
        return Err(invalid("space does not match the request"));
    }
    if meta.repo.as_str() != repo {
        return Err(invalid("repo does not match the request"));
    }
    Ok(Commit {
        ver: 1,
        repo: meta.repo.clone(),
        space: meta.space.clone(),
        rev: meta.rev.clone(),
        data: petrel_core::Bytes(meta.data.to_vec()),
        extra_data: None,
    })
}

/// Parse and validate ONLY the leading STAR metadata frame (`<= 64 KiB`) so the HTTP
/// transport can verify the commit MAC BEFORE any record frames are parsed.
pub fn read_commit(bytes: &[u8], space: &str, repo: &str) -> Result<Commit, AppError> {
    if bytes.len() > MAX_STAR_BYTES {
        return Err(invalid("archive exceeds limit"));
    }
    check_metadata_frame(bytes)?;
    let meta = petrel_spaces::read_star_metadata(bytes).map_err(invalid)?;
    commit_from_meta(&meta, space, repo)
}

pub fn parse_repo_star(bytes: &[u8], space: &str, repo: &str) -> Result<RepoSnapshot, AppError> {
    if bytes.len() > MAX_STAR_BYTES {
        return Err(invalid("archive exceeds limit"));
    }
    check_metadata_frame(bytes)?;
    let parsed = petrel_spaces::read_star_repo(bytes, MAX_STAR_BYTES).map_err(invalid)?;
    let commit = commit_from_meta(&parsed.metadata, space, repo)?;
    if parsed.records.len() > MAX_RECORDS {
        return Err(invalid("too many records"));
    }

    let mut records = Vec::with_capacity(parsed.records.len());
    let mut lthash = LtHash::default();
    let mut previous: Option<&str> = None;
    for rec in &parsed.records {
        if rec.path.len() > MAX_KEY_BYTES {
            return Err(invalid("record path exceeds limit"));
        }
        if rec.cbor.len() > MAX_RECORD_BYTES {
            return Err(invalid("record exceeds limit"));
        }
        // Paths are strictly ascending by UTF-8 bytes, which also rules out duplicates.
        if previous.is_some_and(|prev| rec.path.as_bytes() <= prev.as_bytes()) {
            return Err(invalid("record paths out of order"));
        }
        previous = Some(rec.path.as_str());
        if !matches!(rec.value, petrel_core::Value::Object(_)) {
            return Err(invalid("record must be a map"));
        }
        let json = serde_json::to_value(&rec.value).map_err(|_| invalid("invalid record JSON"))?;
        json_to_ipld(&json).map_err(|_| invalid("invalid record value"))?;
        let cid_str = rec.cid.to_string();
        lthash.add_entry(&rec.path, &cid_str);
        records.push((
            rec.collection.as_str().to_owned(),
            rec.rkey.as_str().to_owned(),
            cid_str,
            json,
        ));
    }
    if lthash.digest() != parsed.metadata.data {
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
    use petrel_core::Value;
    use std::collections::BTreeMap;

    struct Meta {
        kind: String,
        ver: i64,
        repo: String,
        space: String,
        rev: String,
        data: Vec<u8>,
    }

    impl Meta {
        fn to_dagcbor(&self) -> Vec<u8> {
            let map = BTreeMap::from([
                ("$type".to_owned(), Value::String(self.kind.clone())),
                ("ver".to_owned(), Value::Integer(self.ver)),
                ("repo".to_owned(), Value::String(self.repo.clone())),
                ("space".to_owned(), Value::String(self.space.clone())),
                ("rev".to_owned(), Value::String(self.rev.clone())),
                ("data".to_owned(), Value::Bytes(self.data.clone())),
            ]);
            petrel_core::dagcbor::encode(&Value::Object(map))
        }
    }

    fn cbor(json: serde_json::Value) -> Vec<u8> {
        crate::commit::encode_dagcbor(&json_to_ipld(&json).unwrap()).unwrap()
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
            hash.add_entry(path, &create_cid_bytes_from_data(bytes).1);
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
        append_frame(&mut bytes, &meta.to_dagcbor());
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
        let value = cbor(serde_json::json!({"text":"hello"}));
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
        let value = cbor(serde_json::json!({"text":"hello"}));
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
            // {"float": 1.5}: DAG-CBOR float64
            vec![
                0xa1, 0x65, b'f', b'l', b'o', b'a', b't', 0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0,
            ],
            vec![0x82, 0x01, 0x02], // [1, 2]
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
        append_frame(&mut invalid_version, &invalid_meta.to_dagcbor());
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
        let value = cbor(serde_json::json!({}));
        assert!(parse(&archive(&[(key.as_str(), value.as_slice())])).is_err());
    }
}
