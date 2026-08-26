//! Permissioned repository commit and CAR verification primitives.
//!
//! Uses upstream `jacquard_repo::permissioned` for LtHash, commit context,
//! HMAC-over-ctx, DAG-CBOR serialization, and CAR snapshot validation.

use bytes::Bytes;
use cid::Cid as IpldCid;
use sha2::{Digest, Sha256};

pub use jacquard_repo::permissioned::{
    apply_writes, commit_from_cbor, commit_to_cbor, format_cursor, list_repo_ops, normalize_htu,
    parse_cursor, sign_commit, sign_commit_with_ikm, verify_dpop, ApplyWritesResult,
    CnfJkt, CommitContext, CredentialClaims, DpopProof, LtHash,
    OplogAction, OplogEntry, OplogPage, PermissionedCar, PermissionedError, RecordValue,
    SpaceTypeDeclaration, ValidatedRepoSnapshot, WriteOperation, WriteResult,
    WriteState, CLIENT_ATTESTATION_TYP, CLOCK_SKEW_SEC, DELEGATION_TOKEN_TYP,
    SPACE_CREDENTIAL_TYP,
};
pub use catbird_atproto::generated::com_atproto::space::SignedCommit;

use crate::auth::ParsedVerifyingKey;

pub const LTHASH_SIZE: usize = 2048;
pub const MAX_CAR_BYTES: usize = 50 * 1024 * 1024;

/// Format a record element for LtHash accumulator: `{collection}/{rkey}/{cid}`
pub fn format_lthash_element(collection: &str, rkey: &str, cid: &str) -> String {
    format!("{collection}/{rkey}/{cid}")
}

/// Compute DAG-CBOR CID (v1, raw SHA2-256, dag-cbor codec 0x71).
pub fn compute_dagcbor_cid<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<String, PermissionedError> {
    let bytes = serde_ipld_dagcbor::to_vec(value)
        .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
    let hash = Sha256::digest(&bytes);
    let mh = multihash::Multihash::wrap(0x12, &hash)
        .map_err(|e| PermissionedError::InvalidCommit(e.to_string()))?;
    let cid = IpldCid::new_v1(0x71, mh);
    Ok(cid.to_string())
}

/// Create raw CID bytes and string from DAG-CBOR block data.
pub fn create_cid_bytes_from_data(data: &[u8]) -> (Vec<u8>, String) {
    let hash = Sha256::digest(data);
    let mh = multihash::Multihash::wrap(0x12, &hash).expect("valid multihash");
    let cid = IpldCid::new_v1(0x71, mh);
    (cid.to_bytes(), cid.to_string())
}

fn check_no_floats_json(val: &serde_json::Value) -> Result<(), PermissionedError> {
    match val {
        serde_json::Value::Number(n) => {
            if !n.is_i64() && !n.is_u64() {
                return Err(PermissionedError::Serialization("Floating point numbers are forbidden in IPLD/ATProtocol".into()));
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                check_no_floats_json(v)?;
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                check_no_floats_json(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Convert JSON value to IPLD Data.
pub fn json_to_ipld(
    val: &serde_json::Value,
) -> Result<jacquard_common::types::value::Data<jacquard_common::SmolStr>, PermissionedError> {
    check_no_floats_json(val)?;
    let data: jacquard_common::types::value::Data<jacquard_common::SmolStr> = serde_json::from_value(val.clone())
        .map_err(|e| PermissionedError::Serialization(format!("Invalid IPLD/JSON format: {e}")))?;
    fn check_data_floats(d: &jacquard_common::types::value::Data<jacquard_common::SmolStr>) -> Result<(), PermissionedError> {
        match d {
            jacquard_common::types::value::Data::InvalidNumber(n) => {
                Err(PermissionedError::Serialization(format!("Floating point numbers are forbidden: {n}")))
            }
            jacquard_common::types::value::Data::Array(arr) => {
                for item in arr.iter() {
                    check_data_floats(item)?;
                }
                Ok(())
            }
            jacquard_common::types::value::Data::Object(obj) => {
                for item in obj.values() {
                    check_data_floats(item)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    check_data_floats(&data)?;
    Ok(data)
}

pub async fn parse_permissioned_car(bytes: &[u8]) -> Result<PermissionedCar, PermissionedError> {
    if bytes.len() > MAX_CAR_BYTES {
        return Err(PermissionedError::InvalidCar(
            "CAR payload exceeds maximum size limit".into(),
        ));
    }
    let decoded = decode_repo_car(bytes)?;
    let commit_cid: IpldCid = decoded.commit_cid.parse().map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;
    let data_root_cid: IpldCid = decoded.data_root_cid.parse().map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;
    let roots = [commit_cid, data_root_cid];
    let mut blocks = Vec::new();

    let mut cursor = std::io::Cursor::new(bytes);
    fn read_varint(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u64, PermissionedError> {
        use std::io::Read;
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let mut byte = [0u8; 1];
            if cursor.read_exact(&mut byte).is_err() {
                return Err(PermissionedError::InvalidCar("EOF reading varint".into()));
            }
            result |= ((byte[0] & 0x7F) as u64) << shift;
            if byte[0] & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err(PermissionedError::InvalidCar("varint overflow".into()));
            }
        }
        Ok(result)
    }

    let header_len = read_varint(&mut cursor)? as usize;
    cursor.set_position(cursor.position() + header_len as u64);
    while cursor.position() < bytes.len() as u64 {
        let section_len = read_varint(&mut cursor)? as usize;
        let mut section = vec![0u8; section_len];
        use std::io::Read;
        cursor.read_exact(&mut section)
            .map_err(|e| PermissionedError::InvalidCar(e.to_string()))?;
        let mut sec_cursor = std::io::Cursor::new(&section[..]);
        let cid = IpldCid::read_bytes(&mut sec_cursor)
            .map_err(|e| PermissionedError::InvalidCar(e.to_string()))?;
        let cid_len = sec_cursor.position() as usize;
        let data = section[cid_len..].to_vec();
        blocks.push((cid, Bytes::from(data)));
    }

    PermissionedCar::new(roots, blocks)
}

/// Verify a signed permissioned commit against a context and public verifying key.
///
/// Supports Ed25519 (upstream direct validation) as well as P-256 and Secp256k1 account keys.
pub fn verify_commit(
    commit: &catbird_atproto::generated::com_atproto::space::SignedCommit,
    context: &CommitContext,
    key: &ParsedVerifyingKey,
) -> Result<(), PermissionedError> {
    match key {
        ParsedVerifyingKey::Ed25519(vk) => {
            let upstream_commit = jacquard_repo::permissioned::SignedCommit {
                hash: commit.hash.clone(),
                ikm: commit.ikm.clone(),
                mac: commit.mac.clone(),
                rev: jacquard_common::types::tid::Tid::new(commit.rev.as_str())
                    .map_err(|e| PermissionedError::InvalidCommit(e.to_string()))?,
                sig: commit.sig.clone(),
                ver: commit.ver,
                extra_data: None,
            };
            jacquard_repo::permissioned::verify_commit(&upstream_commit, context, vk)
        }
        ParsedVerifyingKey::P256(vk) => {
            verify_commit_ecdsa_p256(commit, context, vk)
        }
        ParsedVerifyingKey::Secp256k1(vk) => {
            verify_commit_ecdsa_k256(commit, context, vk)
        }
    }
}

fn verify_commit_ecdsa_p256(
    commit: &SignedCommit,
    context: &CommitContext,
    vk: &p256::ecdsa::VerifyingKey,
) -> Result<(), PermissionedError> {
    let ikm_slice: &[u8; 32] = commit
        .ikm
        .as_ref()
        .try_into()
        .map_err(|_| PermissionedError::InvalidCommit("ikm must contain 32 bytes".into()))?;
    let hash_slice: &[u8; 32] = commit
        .hash
        .as_ref()
        .try_into()
        .map_err(|_| PermissionedError::InvalidCommit("hash must contain 32 bytes".into()))?;
    let mac_slice: &[u8; 32] = commit
        .mac
        .as_ref()
        .try_into()
        .map_err(|_| PermissionedError::InvalidCommit("mac must contain 32 bytes".into()))?;

    if commit.ver != 1 || commit.rev != context.rev {
        return Err(PermissionedError::InvalidCommit(
            "version or revision mismatch".into(),
        ));
    }

    let context_bytes = encode_commit_context_local(context, ikm_slice)?;
    if compute_mac_local(ikm_slice, &context_bytes, hash_slice) != *mac_slice {
        return Err(PermissionedError::InvalidCommit("MAC mismatch".into()));
    }

    let sig = p256::ecdsa::Signature::from_slice(commit.sig.as_ref())
        .map_err(|e| PermissionedError::InvalidCommit(format!("invalid P-256 signature: {e}")))?;
    use p256::ecdsa::signature::Verifier;
    vk.verify(&context_bytes, &sig)
        .map_err(|e| PermissionedError::InvalidCommit(format!("P-256 signature mismatch: {e}")))
}

fn verify_commit_ecdsa_k256(
    commit: &SignedCommit,
    context: &CommitContext,
    vk: &k256::ecdsa::VerifyingKey,
) -> Result<(), PermissionedError> {
    let ikm_slice: &[u8; 32] = commit
        .ikm
        .as_ref()
        .try_into()
        .map_err(|_| PermissionedError::InvalidCommit("ikm must contain 32 bytes".into()))?;
    let hash_slice: &[u8; 32] = commit
        .hash
        .as_ref()
        .try_into()
        .map_err(|_| PermissionedError::InvalidCommit("hash must contain 32 bytes".into()))?;
    let mac_slice: &[u8; 32] = commit
        .mac
        .as_ref()
        .try_into()
        .map_err(|_| PermissionedError::InvalidCommit("mac must contain 32 bytes".into()))?;

    if commit.ver != 1 || commit.rev != context.rev {
        return Err(PermissionedError::InvalidCommit(
            "version or revision mismatch".into(),
        ));
    }

    let context_bytes = encode_commit_context_local(context, ikm_slice)?;
    if compute_mac_local(ikm_slice, &context_bytes, hash_slice) != *mac_slice {
        return Err(PermissionedError::InvalidCommit("MAC mismatch".into()));
    }

    let sig = k256::ecdsa::Signature::from_slice(commit.sig.as_ref()).map_err(|e| {
        PermissionedError::InvalidCommit(format!("invalid secp256k1 signature: {e}"))
    })?;
    use k256::ecdsa::signature::Verifier;
    vk.verify(&context_bytes, &sig)
        .map_err(|e| PermissionedError::InvalidCommit(format!("secp256k1 signature mismatch: {e}")))
}

// Upstream's `encode_commit_context` is private in `jacquard_repo::permissioned`.
// This local copy exists solely because of upstream visibility, and must stay byte-identical
// to upstream's `encode_commit_context`.
fn encode_commit_context_local(context: &CommitContext, ikm: &[u8; 32]) -> Result<Vec<u8>, PermissionedError> {
    let fields = [
        context.space.as_bytes(),
        context.author.as_bytes(),
        context.rev.as_bytes(),
        ikm.as_slice(),
    ];
    let mut output = b"atproto-space-v1".to_vec();
    for field in fields {
        if field.len() > u16::MAX as usize {
            return Err(PermissionedError::InvalidCommit(
                "context field too long".into(),
            ));
        }
        output.extend_from_slice(&(field.len() as u16).to_be_bytes());
        output.extend_from_slice(field);
    }
    Ok(output)
}

fn compute_mac_local(ikm: &[u8; 32], context: &[u8], hash: &[u8; 32]) -> [u8; 32] {
    let hkdf = hkdf::Hkdf::<Sha256>::from_prk(ikm).expect("32-byte PRK is valid");
    let mut key = [0; 32];
    hkdf.expand(context, &mut key)
        .expect("fixed output length is valid");
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC accepts any key");
    mac.update(hash);
    mac.finalize().into_bytes().into()
}

/// Extract and validate a permissioned CAR file, returning the verified signed commit,
/// unpacked records as (collection, rkey, cid_str, serde_json::Value), and the verified LtHash.
pub fn extract_and_validate_car(
    car: &PermissionedCar,
    space_uri: &str,
    author_did: &str,
    key: &ParsedVerifyingKey,
) -> Result<(SignedCommit, Vec<(String, String, String, serde_json::Value)>, LtHash), PermissionedError> {
    let space_uri_parsed = jacquard_common::types::aturi::AtSpaceUri::new_owned(space_uri)
        .map_err(|_| PermissionedError::InvalidComponent {
            field: "space_uri",
            value: space_uri.to_string(),
        })?;
    let author_did_parsed = jacquard_common::types::did::Did::new_owned(author_did)
        .map_err(|_| PermissionedError::InvalidComponent {
            field: "author_did",
            value: author_did.to_string(),
        })?;

    if car.blocks.len() < 2 {
        return Err(PermissionedError::InvalidCar("CAR has fewer than 2 blocks".into()));
    }

    let upstream_commit = commit_from_cbor(&car.blocks[0].1)?;
    let commit = SignedCommit {
        hash: upstream_commit.hash.clone(),
        ikm: upstream_commit.ikm.clone(),
        mac: upstream_commit.mac.clone(),
        rev: upstream_commit.rev.to_string().into(),
        sig: upstream_commit.sig.clone(),
        ver: upstream_commit.ver,
        extra_data: None,
    };
    let context = CommitContext {
        space: space_uri_parsed,
        author: author_did_parsed,
        rev: upstream_commit.rev,
    };

    verify_commit(&commit, &context, key)?;

    let decoded_index: std::collections::BTreeMap<jacquard_common::SmolStr, jacquard_common::types::cid::CidLink<jacquard_common::SmolStr>> =
        serde_ipld_dagcbor::from_slice(&car.blocks[1].1)
            .map_err(|e| PermissionedError::InvalidCar(format!("Index decode error: {e}")))?;

    let mut index = Vec::new();
    for (path, link) in decoded_index {
        let cid = link.to_ipld().map_err(|e| PermissionedError::InvalidCar(e.to_string()))?;
        index.push((path, cid));
    }
    index.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.as_bytes().cmp(b.0.as_bytes())));

    let mut lthash = LtHash::default();
    for (path, cid) in &index {
        lthash.add(&format!("{path}/{cid}"));
    }
    if commit.hash.as_ref() != lthash.digest().as_slice() {
        return Err(PermissionedError::InvalidCar("Index does not match commit hash".into()));
    }

    let record_blocks = &car.blocks[2..];
    if record_blocks.len() != index.len() {
        return Err(PermissionedError::InvalidCar("Record block count does not match index".into()));
    }

    let mut records = Vec::with_capacity(index.len());
    for ((path, expected_cid), (actual_cid, bytes)) in index.iter().zip(record_blocks) {
        if actual_cid != expected_cid {
            return Err(PermissionedError::InvalidCar("Record block CID mismatch".into()));
        }
        let (collection, rkey) = path
            .split_once('/')
            .ok_or_else(|| PermissionedError::InvalidCar("Invalid index path".into()))?;
        let json_val: serde_json::Value = serde_ipld_dagcbor::from_slice(bytes)
            .map_err(|e| PermissionedError::InvalidCar(format!("Record decode error: {e}")))?;
        records.push((collection.to_string(), rkey.to_string(), actual_cid.to_string(), json_val));
    }

    Ok((commit, records, lthash))
}

pub type CommitError = PermissionedError;

pub use jacquard_common::types::cid::CidLink;

pub fn compute_commit_context(
    space: &str,
    author: &str,
    rev: &str,
    ikm: &[u8],
) -> Result<Vec<u8>, PermissionedError> {
    if ikm.len() != 32 {
        return Err(PermissionedError::InvalidCommit("IKM must be 32 bytes".into()));
    }
    let mut ikm_arr = [0u8; 32];
    ikm_arr.copy_from_slice(ikm);
    let space_uri = jacquard_common::types::aturi::AtSpaceUri::new_owned(space)
        .map_err(|_| PermissionedError::InvalidComponent {
            field: "space",
            value: space.to_string(),
        })?;
    let author_did = jacquard_common::types::did::Did::new_owned(author)
        .map_err(|_| PermissionedError::InvalidComponent {
            field: "author",
            value: author.to_string(),
        })?;
    let tid_rev = jacquard_common::types::tid::Tid::new(rev)
        .map_err(|_| PermissionedError::InvalidComponent {
            field: "rev",
            value: rev.to_string(),
        })?;
    let context = CommitContext {
        space: space_uri,
        author: author_did,
        rev: tid_rev,
    };
    encode_commit_context_local(&context, &ikm_arr)
}

pub fn derive_commit_mac_key(ikm: &[u8], ctx: &[u8]) -> Result<[u8; 32], PermissionedError> {
    if ikm.len() != 32 {
        return Err(PermissionedError::InvalidCommit("IKM must be 32 bytes".into()));
    }
    let mut ikm_arr = [0u8; 32];
    ikm_arr.copy_from_slice(ikm);
    let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&ikm_arr)
        .map_err(|e| PermissionedError::InvalidCommit(e.to_string()))?;
    let mut key = [0u8; 32];
    hkdf.expand(ctx, &mut key)
        .map_err(|e| PermissionedError::InvalidCommit(e.to_string()))?;
    Ok(key)
}

pub fn compute_commit_mac(mac_key: &[u8; 32], hash: &[u8]) -> Result<[u8; 32], PermissionedError> {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key)
        .map_err(|e| PermissionedError::InvalidCommit(e.to_string()))?;
    mac.update(hash);
    Ok(mac.finalize().into_bytes().into())
}

pub fn mint_signed_commit(
    space: &str,
    author: &str,
    rev: &str,
    lthash_state: &[u8; LTHASH_SIZE],
    signing_key: &p256::ecdsa::SigningKey,
) -> SignedCommit {
    let mut ikm = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ikm);

    let hash = Sha256::digest(lthash_state);
    let ctx = compute_commit_context(space, author, rev, &ikm).expect("valid commit parameters");
    let mac_key = derive_commit_mac_key(&ikm, &ctx).expect("HKDF expand must succeed");
    let mac = compute_commit_mac(&mac_key, hash.as_ref()).expect("HMAC compute must succeed");

    let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(signing_key, &ctx);

    SignedCommit {
        hash: bytes::Bytes::copy_from_slice(hash.as_ref()),
        ikm: bytes::Bytes::copy_from_slice(&ikm),
        mac: bytes::Bytes::copy_from_slice(&mac),
        rev: rev.to_string().into(),
        sig: bytes::Bytes::copy_from_slice(&sig.to_bytes()),
        ver: 1,
        extra_data: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepoRecord {
    pub collection: String,
    pub rkey: String,
    pub cid: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct DecodedRepoCar {
    pub commit: SignedCommit,
    pub commit_cid: String,
    pub data_root_cid: String,
    pub records: Vec<RepoRecord>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CarHeader {
    pub version: u64,
    pub roots: Vec<IpldCid>,
}

pub fn encode_varint(mut val: u64, buf: &mut Vec<u8>) {
    while val >= 0x80 {
        buf.push((val as u8 & 0x7F) | 0x80);
        val >>= 7;
    }
    buf.push(val as u8);
}

pub fn decode_varint(bytes: &[u8]) -> Result<(u64, usize), PermissionedError> {
    let mut result = 0u64;
    let mut shift = 0;
    let mut read = 0;
    for &b in bytes {
        read += 1;
        if read == 10 {
            if b & 0x80 != 0 {
                return Err(PermissionedError::InvalidCar(
                    "10th varint byte with continuation bit set".into(),
                ));
            }
            if b > 0x01 {
                return Err(PermissionedError::InvalidCar(
                    "10th varint byte exceeds maximum u64".into(),
                ));
            }
        }
        let val_bits = (b & 0x7F) as u64;
        result |= val_bits << shift;
        if b & 0x80 == 0 {
            if read > 1 && val_bits == 0 {
                return Err(PermissionedError::InvalidCar(
                    "Non-minimal varint encoding".into(),
                ));
            }
            return Ok((result, read));
        }
        shift += 7;
        if shift >= 70 {
            return Err(PermissionedError::InvalidCar("varint overflow".into()));
        }
    }
    Err(PermissionedError::InvalidCar("EOF reading varint".into()))
}

pub fn mint_repo_car(
    commit: &SignedCommit,
    records: &[RepoRecord],
) -> Result<Vec<u8>, PermissionedError> {
    let commit_cbor = serde_ipld_dagcbor::to_vec(commit)
        .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
    let (commit_cid_bytes, commit_cid) = create_cid_bytes_from_data(&commit_cbor);
    let commit_cid_obj: IpldCid = commit_cid.parse().map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;

    let mut index_map: std::collections::BTreeMap<jacquard_common::SmolStr, CidLink<jacquard_common::SmolStr>> = std::collections::BTreeMap::new();
    let mut record_blocks: Vec<(String, String, Vec<u8>)> = Vec::new();

    for rec in records {
        let path = format!("{}/{}", rec.collection, rec.rkey);
        let rec_cbor = serde_ipld_dagcbor::to_vec(&rec.value)
            .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
        let (_rec_cid_bytes, rec_cid) = create_cid_bytes_from_data(&rec_cbor);
        let rec_cid_obj: IpldCid = rec_cid.parse().map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;
        let link = CidLink::ipld(rec_cid_obj);
        index_map.insert(jacquard_common::SmolStr::new(path.as_str()), link);
        record_blocks.push((path, rec_cid, rec_cbor));
    }

    let index_cbor = serde_ipld_dagcbor::to_vec(&index_map)
        .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
    let (index_cid_bytes, index_cid) = create_cid_bytes_from_data(&index_cbor);
    let index_cid_obj: IpldCid = index_cid.parse().map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;

    let roots = vec![commit_cid_obj, index_cid_obj];
    let header = CarHeader { version: 1, roots };
    let header_cbor = serde_ipld_dagcbor::to_vec(&header)
        .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
    let mut output = Vec::new();
    encode_varint(header_cbor.len() as u64, &mut output);
    output.extend_from_slice(&header_cbor);

    // Commit block
    encode_varint((commit_cid_bytes.len() + commit_cbor.len()) as u64, &mut output);
    output.extend_from_slice(&commit_cid_bytes);
    output.extend_from_slice(&commit_cbor);

    // Index block
    encode_varint((index_cid_bytes.len() + index_cbor.len()) as u64, &mut output);
    output.extend_from_slice(&index_cid_bytes);
    output.extend_from_slice(&index_cbor);

    // Record blocks in DRISL index order (shortest key first)
    record_blocks.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.as_bytes().cmp(b.0.as_bytes())));
    for (_path, rec_cid, rec_cbor) in record_blocks {
        let rec_cid_obj: IpldCid = rec_cid.parse().map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;
        let rec_cid_bytes = rec_cid_obj.to_bytes();
        encode_varint((rec_cid_bytes.len() + rec_cbor.len()) as u64, &mut output);
        output.extend_from_slice(&rec_cid_bytes);
        output.extend_from_slice(&rec_cbor);
    }

    Ok(output)
}

fn validate_strict_cid(cid: &IpldCid) -> Result<(), PermissionedError> {
    if cid.version() != cid::Version::V1 {
        return Err(PermissionedError::InvalidCar("Only CIDv1 is supported".into()));
    }
    if cid.codec() != 0x71 {
        return Err(PermissionedError::InvalidCar(format!(
            "Unblessed CID codec {:#x}, only 0x71 (dag-cbor) supported",
            cid.codec()
        )));
    }
    if cid.hash().code() != 0x12 {
        return Err(PermissionedError::InvalidCar(format!(
            "Unblessed multihash {:#x}, only 0x12 (sha2-256) supported",
            cid.hash().code()
        )));
    }
    Ok(())
}

pub fn decode_repo_car(bytes: &[u8]) -> Result<DecodedRepoCar, PermissionedError> {
    if bytes.is_empty() {
        return Err(PermissionedError::InvalidCar("empty CAR".into()));
    }
    let mut offset = 0;
    let (header_len, vlen) = decode_varint(&bytes[offset..])?;
    offset += vlen;
    if offset + header_len as usize > bytes.len() {
        return Err(PermissionedError::InvalidCar("EOF reading CAR header".into()));
    }
    let header_bytes = &bytes[offset..offset + header_len as usize];
    offset += header_len as usize;

    let header: CarHeader = serde_ipld_dagcbor::from_slice(header_bytes)
        .map_err(|e| PermissionedError::InvalidCar(e.to_string()))?;
    if header.roots.len() < 2 {
        return Err(PermissionedError::InvalidCar("CAR has fewer than 2 roots".into()));
    }
    for root in &header.roots {
        validate_strict_cid(root)?;
    }
    let commit_cid = header.roots[0].to_string();
    let data_root_cid = header.roots[1].to_string();
    let mut blocks = Vec::new();

    while offset < bytes.len() {
        let (section_len, vlen) = decode_varint(&bytes[offset..])?;
        offset += vlen;
        if offset + section_len as usize > bytes.len() {
            return Err(PermissionedError::InvalidCar("EOF reading CAR section".into()));
        }
        let section = &bytes[offset..offset + section_len as usize];
        offset += section_len as usize;

        let mut sec_cursor = std::io::Cursor::new(section);
        let cid = IpldCid::read_bytes(&mut sec_cursor)
            .map_err(|e| PermissionedError::InvalidCar(e.to_string()))?;
        validate_strict_cid(&cid)?;
        let cid_len = sec_cursor.position() as usize;
        let data = section[cid_len..].to_vec();

        let (_expected_cid_bytes, expected_cid_str) = create_cid_bytes_from_data(&data);
        if cid.to_string() != expected_cid_str {
            return Err(PermissionedError::InvalidCar("block CID mismatch".into()));
        }
        blocks.push((cid.to_string(), data));
    }

    if blocks.len() < 2 {
        return Err(PermissionedError::InvalidCar("CAR has fewer than 2 blocks".into()));
    }

    // Validate SignedCommit
    let raw_commit_cbor = &blocks[0].1;
    let commit_data: jacquard_common::types::value::Data<jacquard_common::SmolStr> =
        serde_ipld_dagcbor::from_slice(raw_commit_cbor)
            .map_err(|e| PermissionedError::InvalidCar(format!("Non-canonical DAG-CBOR SignedCommit: {e}")))?;
    fn has_invalid_numbers(d: &jacquard_common::types::value::Data<jacquard_common::SmolStr>) -> bool {
        match d {
            jacquard_common::types::value::Data::InvalidNumber(_) => true,
            jacquard_common::types::value::Data::Array(a) => a.iter().any(has_invalid_numbers),
            jacquard_common::types::value::Data::Object(o) => o.values().any(has_invalid_numbers),
            _ => false,
        }
    }
    if has_invalid_numbers(&commit_data) {
        return Err(PermissionedError::InvalidCar(
            "Floating point numbers are forbidden in strict IPLD".into(),
        ));
    }
    let commit: SignedCommit = serde_ipld_dagcbor::from_slice(raw_commit_cbor)
        .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
    if let Some(extra) = &commit.extra_data {
        if !extra.is_empty() {
            return Err(PermissionedError::InvalidCar(
                "SignedCommit contains unknown fields".into(),
            ));
        }
    }
    let canonical_commit_cbor = serde_ipld_dagcbor::to_vec(&commit)
        .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
    if canonical_commit_cbor.as_slice() != raw_commit_cbor.as_slice() {
        return Err(PermissionedError::InvalidCar(
            "Non-canonical DAG-CBOR SignedCommit encoding".into(),
        ));
    }

    // Validate DRISL Index
    let raw_index_cbor = &blocks[1].1;
    let index_data: jacquard_common::types::value::Data<jacquard_common::SmolStr> =
        serde_ipld_dagcbor::from_slice(raw_index_cbor)
            .map_err(|e| PermissionedError::InvalidCar(format!("Duplicate map key or invalid DRISL CBOR: {e}")))?;
    if has_invalid_numbers(&index_data) {
        return Err(PermissionedError::InvalidCar(
            "Floating point numbers are forbidden in strict IPLD".into(),
        ));
    }
    let canonical_index_cbor = serde_ipld_dagcbor::to_vec(&index_data)
        .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
    if canonical_index_cbor.as_slice() != raw_index_cbor.as_slice() {
        return Err(PermissionedError::InvalidCar(
            "Duplicate map key or non-canonical DRISL CBOR".into(),
        ));
    }
    let index: std::collections::BTreeMap<jacquard_common::SmolStr, CidLink<jacquard_common::SmolStr>> =
        serde_ipld_dagcbor::from_slice(raw_index_cbor)
            .map_err(|e| PermissionedError::InvalidCar(format!("Duplicate map key or invalid DRISL CBOR: {e}")))?;

    // Validate Record blocks
    for (_cid_str, rec_data) in &blocks[2..] {
        let parsed_data: jacquard_common::types::value::Data<jacquard_common::SmolStr> =
            serde_ipld_dagcbor::from_slice(rec_data)
                .map_err(|e| PermissionedError::InvalidCar(format!("Failed to decode record CBOR: Duplicate map key or malformed DAG-CBOR: {e}")))?;
        if has_invalid_numbers(&parsed_data) {
            return Err(PermissionedError::InvalidCar(
                "Floating point numbers are forbidden in strict IPLD".into(),
            ));
        }
        let canonical_rec_cbor = serde_ipld_dagcbor::to_vec(&parsed_data)
            .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
        if canonical_rec_cbor.as_slice() != rec_data.as_slice() {
            return Err(PermissionedError::InvalidCar(
                "Failed to decode record CBOR: Duplicate map key or non-canonical DAG-CBOR".into(),
            ));
        }
    }

    let block_map: std::collections::HashMap<String, Vec<u8>> = blocks.into_iter().collect();

    let mut index_entries: Vec<(jacquard_common::SmolStr, CidLink<jacquard_common::SmolStr>)> = index.into_iter().collect();
    index_entries.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.as_bytes().cmp(b.0.as_bytes())));

    let mut records = Vec::new();
    for (path, link) in index_entries {
        let (collection, rkey) = path.split_once('/')
            .ok_or_else(|| PermissionedError::InvalidCar("invalid path in index".into()))?;
        let cid_str = link.as_str().to_string();
        let rec_data = block_map.get(&cid_str)
            .ok_or_else(|| PermissionedError::InvalidCar(format!("missing record block {cid_str}")))?;
        let val: serde_json::Value = serde_ipld_dagcbor::from_slice(rec_data)
            .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
        records.push(RepoRecord {
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            cid: cid_str,
            value: val,
        });
    }

    Ok(DecodedRepoCar {
        commit,
        commit_cid,
        data_root_cid,
        records,
    })
}
