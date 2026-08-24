use catbird_atproto::generated::com_atproto::space::SignedCommit;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::auth::ParsedVerifyingKey;

type HmacSha256 = Hmac<Sha256>;

pub const LTHASH_SIZE: usize = 2048;
pub const COMMIT_VERSION: i64 = 1;
pub const PROTOCOL_TAG: &str = "atproto-space-v1";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitError {
    #[error("Unsupported commit version: {0} (expected {COMMIT_VERSION})")]
    UnsupportedVersion(i64),
    #[error("LtHash digest mismatch")]
    HashMismatch,
    #[error("HMAC verification failed")]
    MacMismatch,
    #[error("Signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Invalid commit data: {0}")]
    InvalidData(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LtHash {
    pub state: [u8; LTHASH_SIZE],
}

impl Default for LtHash {
    fn default() -> Self {
        Self::new()
    }
}

impl LtHash {
    pub fn new() -> Self {
        Self {
            state: [0u8; LTHASH_SIZE],
        }
    }

    pub fn from_bytes(bytes: [u8; LTHASH_SIZE]) -> Self {
        Self { state: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; LTHASH_SIZE] {
        &self.state
    }

    pub fn into_bytes(self) -> [u8; LTHASH_SIZE] {
        self.state
    }

    fn expand_item(collection: &str, rkey: &str, cid: &str) -> [u8; LTHASH_SIZE] {
        let item_key = format!("{collection}/{rkey}/{cid}");
        let mut hasher = blake3::Hasher::new();
        hasher.update(item_key.as_bytes());
        let mut xof = hasher.finalize_xof();
        let mut expansion = [0u8; LTHASH_SIZE];
        xof.fill(&mut expansion);
        expansion
    }

    pub fn add(&mut self, collection: &str, rkey: &str, cid: &str) {
        let expansion = Self::expand_item(collection, rkey, cid);
        for i in 0..(LTHASH_SIZE / 2) {
            let offset = i * 2;
            let s = u16::from_le_bytes([self.state[offset], self.state[offset + 1]]);
            let e = u16::from_le_bytes([expansion[offset], expansion[offset + 1]]);
            let sum = s.wrapping_add(e);
            let bytes = sum.to_le_bytes();
            self.state[offset] = bytes[0];
            self.state[offset + 1] = bytes[1];
        }
    }

    pub fn remove(&mut self, collection: &str, rkey: &str, cid: &str) {
        let expansion = Self::expand_item(collection, rkey, cid);
        for i in 0..(LTHASH_SIZE / 2) {
            let offset = i * 2;
            let s = u16::from_le_bytes([self.state[offset], self.state[offset + 1]]);
            let e = u16::from_le_bytes([expansion[offset], expansion[offset + 1]]);
            let diff = s.wrapping_sub(e);
            let bytes = diff.to_le_bytes();
            self.state[offset] = bytes[0];
            self.state[offset + 1] = bytes[1];
        }
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.state);
        hasher.finalize().into()
    }
}

pub fn compute_commit_context(space: &str, author: &str, rev: &str, ikm: &[u8]) -> Vec<u8> {
    let mut ctx = Vec::new();
    for field in [
        PROTOCOL_TAG.as_bytes(),
        space.as_bytes(),
        author.as_bytes(),
        rev.as_bytes(),
        ikm,
    ] {
        let len = field.len() as u16;
        ctx.extend_from_slice(&len.to_be_bytes());
        ctx.extend_from_slice(field);
    }
    ctx
}

pub fn derive_commit_mac_key(ikm: &[u8], ctx: &[u8]) -> Result<[u8; 32], CommitError> {
    let hkdf = hkdf::Hkdf::<Sha256>::from_prk(ikm)
        .map_err(|e| CommitError::InvalidData(format!("Invalid PRK: {e}")))?;
    let mut mac_key = [0u8; 32];
    hkdf.expand(ctx, &mut mac_key)
        .map_err(|e| CommitError::InvalidData(format!("HKDF expand failed: {e}")))?;
    Ok(mac_key)
}

pub fn compute_commit_mac(mac_key: &[u8; 32], hash: &[u8]) -> Result<[u8; 32], CommitError> {
    let mut mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|e| CommitError::InvalidData(format!("Invalid HMAC key: {e}")))?;
    mac.update(hash);
    Ok(mac.finalize().into_bytes().into())
}

pub fn compute_dagcbor_cid(value: &serde_json::Value) -> Result<String, CommitError> {
    let dagcbor_bytes = serde_ipld_dagcbor::to_vec(value)
        .map_err(|e| CommitError::InvalidData(format!("DAG-CBOR serialization failed: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(&dagcbor_bytes);
    let digest = hasher.finalize();

    // CIDv1: 0x01 (cidv1) + 0x71 (dag-cbor) + 0x12 (sha2-256) + 0x20 (32 bytes) + digest
    let mut cid_bytes = Vec::with_capacity(4 + 32);
    cid_bytes.push(0x01);
    cid_bytes.push(0x71);
    cid_bytes.push(0x12);
    cid_bytes.push(0x20);
    cid_bytes.extend_from_slice(&digest);

    Ok(multibase::encode(multibase::Base::Base32Lower, &cid_bytes))
}

pub fn verify_commit(
    space: &str,
    author: &str,
    commit: &SignedCommit,
    lthash_state: &[u8; LTHASH_SIZE],
    signing_key: &ParsedVerifyingKey,
) -> Result<(), CommitError> {
    // 1. Version check
    if commit.ver != COMMIT_VERSION {
        return Err(CommitError::UnsupportedVersion(commit.ver));
    }

    // 2. LtHash state digest comparison
    let computed_hash: [u8; 32] = Sha256::digest(lthash_state).into();
    if &computed_hash[..] != commit.hash.as_ref() {
        return Err(CommitError::HashMismatch);
    }

    // 3. IKM length check
    if commit.ikm.len() != 32 {
        return Err(CommitError::InvalidData("IKM must be 32 bytes".into()));
    }

    // 4. Compute commit context: (space, author, rev, ikm)
    let ctx = compute_commit_context(space, author, commit.rev.as_str(), commit.ikm.as_ref());

    // 5. HKDF derivation of HMAC key
    let mac_key = derive_commit_mac_key(commit.ikm.as_ref(), &ctx)?;

    // 6. HMAC verification over commit.hash
    let mut mac = HmacSha256::new_from_slice(&mac_key)
        .map_err(|e| CommitError::InvalidData(format!("Invalid HMAC key: {e}")))?;
    mac.update(commit.hash.as_ref());
    if mac.verify_slice(commit.mac.as_ref()).is_err() {
        return Err(CommitError::MacMismatch);
    }

    // 7. Signature verification over ctx
    match signing_key {
        ParsedVerifyingKey::P256(vk) => {
            let sig = p256::ecdsa::Signature::from_slice(commit.sig.as_ref()).map_err(|e| {
                CommitError::InvalidSignature(format!("Invalid P-256 signature bytes: {e}"))
            })?;
            use p256::ecdsa::signature::Verifier;
            vk.verify(&ctx, &sig).map_err(|e| {
                CommitError::InvalidSignature(format!("P-256 signature verification failed: {e}"))
            })?;
        }
        ParsedVerifyingKey::Secp256k1(vk) => {
            let sig = k256::ecdsa::Signature::from_slice(commit.sig.as_ref()).map_err(|e| {
                CommitError::InvalidSignature(format!("Invalid secp256k1 signature bytes: {e}"))
            })?;
            use k256::ecdsa::signature::Verifier;
            vk.verify(&ctx, &sig).map_err(|e| {
                CommitError::InvalidSignature(format!(
                    "secp256k1 signature verification failed: {e}"
                ))
            })?;
        }
    }

    Ok(())
}

pub fn mint_signed_commit(
    space: &str,
    author: &str,
    rev: &str,
    lthash_state: &[u8; LTHASH_SIZE],
    signing_key: &p256::ecdsa::SigningKey,
) -> SignedCommit {
    let mut ikm = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ikm);

    let hash = Sha256::digest(lthash_state);
    let ctx = compute_commit_context(space, author, rev, &ikm);
    let mac_key = derive_commit_mac_key(&ikm, &ctx).expect("HKDF expand must succeed");
    let mac = compute_commit_mac(&mac_key, hash.as_ref()).expect("HMAC compute must succeed");

    let sig: p256::ecdsa::Signature = signing_key.sign(&ctx);
    let bytes_hash =
        catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(hash.as_ref());
    let bytes_ikm = catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&ikm);
    let bytes_mac = catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&mac);
    let bytes_sig =
        catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&sig.to_bytes());

    SignedCommit {
        hash: bytes_hash,
        ikm: bytes_ikm,
        mac: bytes_mac,
        rev: rev.to_string().into(),
        sig: bytes_sig,
        ver: COMMIT_VERSION,
        extra_data: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

fn encode_varint(mut val: u64, buf: &mut Vec<u8>) {
    while val >= 0x80 {
        buf.push(((val & 0x7f) as u8) | 0x80);
        val >>= 7;
    }
    buf.push(val as u8);
}

fn decode_varint(slice: &[u8]) -> Result<(u64, usize), CommitError> {
    let mut val = 0u64;
    let mut shift = 0;
    let mut bytes_read = 0;
    for &byte in slice {
        bytes_read += 1;
        val |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((val, bytes_read));
        }
        shift += 7;
        if shift >= 64 {
            return Err(CommitError::InvalidData("Varint overflow".into()));
        }
    }
    Err(CommitError::InvalidData(
        "Unexpected EOF reading varint".into(),
    ))
}

fn create_cid_bytes_from_data(data: &[u8]) -> (Vec<u8>, String) {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut cid_bytes = Vec::with_capacity(4 + 32);
    cid_bytes.push(0x01);
    cid_bytes.push(0x71); // dag-cbor
    cid_bytes.push(0x12); // sha2-256
    cid_bytes.push(0x20); // 32 bytes
    cid_bytes.extend_from_slice(&digest);
    let cid_str = multibase::encode(multibase::Base::Base32Lower, &cid_bytes);
    (cid_bytes, cid_str)
}

#[derive(Serialize, Deserialize)]
struct CarHeader {
    version: u64,
    roots: Vec<serde_bytes::ByteBuf>,
}

#[derive(Serialize, Deserialize)]
struct DrislEntry {
    k: String,
    v: String,
}

pub fn mint_repo_car(
    commit: &SignedCommit,
    records: &[RepoRecord],
) -> Result<Vec<u8>, CommitError> {
    // 1. Sort records in canonical DRISL order: collection ascending, then rkey ascending
    let mut sorted_records = records.to_vec();
    sorted_records.sort_by(|a, b| {
        a.collection
            .cmp(&b.collection)
            .then_with(|| a.rkey.cmp(&b.rkey))
    });

    // 2. Serialize SignedCommit to DAG-CBOR and compute its CID
    let commit_cbor = serde_ipld_dagcbor::to_vec(commit).map_err(|e| {
        CommitError::InvalidData(format!("SignedCommit DAG-CBOR serialization failed: {e}"))
    })?;
    let (commit_cid_bytes, _commit_cid_str) = create_cid_bytes_from_data(&commit_cbor);

    // 3. Serialize each record to DAG-CBOR and compute its CID
    let mut record_blocks = Vec::new();
    let mut drisl_entries = Vec::new();

    for rec in &sorted_records {
        let rec_cbor = serde_ipld_dagcbor::to_vec(&rec.value).map_err(|e| {
            CommitError::InvalidData(format!("Record DAG-CBOR serialization failed: {e}"))
        })?;
        let (cid_bytes, cid_str) = create_cid_bytes_from_data(&rec_cbor);
        drisl_entries.push(DrislEntry {
            k: format!("{}/{}", rec.collection, rec.rkey),
            v: cid_str,
        });
        record_blocks.push((cid_bytes, rec_cbor));
    }

    // 4. Serialize DRISL index to DAG-CBOR and compute its CID
    let drisl_cbor = serde_ipld_dagcbor::to_vec(&drisl_entries).map_err(|e| {
        CommitError::InvalidData(format!("DRISL index DAG-CBOR serialization failed: {e}"))
    })?;
    let (drisl_cid_bytes, _drisl_cid_str) = create_cid_bytes_from_data(&drisl_cbor);

    // 5. Create CAR header with two roots: [commit_cid, data_root_cid]
    let header = CarHeader {
        version: 1,
        roots: vec![
            serde_bytes::ByteBuf::from(commit_cid_bytes.clone()),
            serde_bytes::ByteBuf::from(drisl_cid_bytes.clone()),
        ],
    };
    let header_cbor = serde_ipld_dagcbor::to_vec(&header).map_err(|e| {
        CommitError::InvalidData(format!("CAR header DAG-CBOR serialization failed: {e}"))
    })?;

    // 6. Assemble CAR stream
    let mut car_bytes = Vec::new();
    encode_varint(header_cbor.len() as u64, &mut car_bytes);
    car_bytes.extend_from_slice(&header_cbor);

    // Commit block
    encode_varint(
        (commit_cid_bytes.len() + commit_cbor.len()) as u64,
        &mut car_bytes,
    );
    car_bytes.extend_from_slice(&commit_cid_bytes);
    car_bytes.extend_from_slice(&commit_cbor);

    // DRISL index block
    encode_varint(
        (drisl_cid_bytes.len() + drisl_cbor.len()) as u64,
        &mut car_bytes,
    );
    car_bytes.extend_from_slice(&drisl_cid_bytes);
    car_bytes.extend_from_slice(&drisl_cbor);

    // Record blocks
    for (cid_bytes, rec_cbor) in record_blocks {
        encode_varint((cid_bytes.len() + rec_cbor.len()) as u64, &mut car_bytes);
        car_bytes.extend_from_slice(&cid_bytes);
        car_bytes.extend_from_slice(&rec_cbor);
    }

    Ok(car_bytes)
}

pub fn decode_repo_car(car_bytes: &[u8]) -> Result<DecodedRepoCar, CommitError> {
    if car_bytes.is_empty() {
        return Err(CommitError::InvalidData("Empty CAR file".into()));
    }

    let (header_len, varint_len) = decode_varint(car_bytes)?;
    let header_start = varint_len;
    let header_end = header_start + header_len as usize;
    if car_bytes.len() < header_end {
        return Err(CommitError::InvalidData("Truncated CAR header".into()));
    }

    let header: CarHeader = serde_ipld_dagcbor::from_slice(&car_bytes[header_start..header_end])
        .map_err(|e| CommitError::InvalidData(format!("Failed to parse CAR header: {e}")))?;

    if header.version != 1 {
        return Err(CommitError::InvalidData(format!(
            "Unsupported CAR version: {} (expected 1)",
            header.version
        )));
    }

    if header.roots.len() != 2 {
        return Err(CommitError::InvalidData(format!(
            "CAR header must have exactly 2 roots (commit + DRISL), found {}",
            header.roots.len()
        )));
    }

    let commit_root_cid_str = multibase::encode(multibase::Base::Base32Lower, &header.roots[0]);
    let drisl_root_cid_str = multibase::encode(multibase::Base::Base32Lower, &header.roots[1]);

    // Stream blocks
    let mut blocks = HashMap::new();
    let mut offset = header_end;

    while offset < car_bytes.len() {
        let (block_len, v_len) = decode_varint(&car_bytes[offset..])?;
        offset += v_len;
        let block_end = offset + block_len as usize;
        if car_bytes.len() < block_end {
            return Err(CommitError::InvalidData("Truncated block in CAR".into()));
        }
        let block_slice = &car_bytes[offset..block_end];

        // Parse CID and data from block
        let (cid_str, data) = parse_cid_and_data(block_slice)?;
        blocks.insert(cid_str, data);
        offset = block_end;
    }

    // 1. Extract commit root block
    let commit_data = blocks.get(&commit_root_cid_str).ok_or_else(|| {
        CommitError::InvalidData(format!("Missing commit root block {commit_root_cid_str}"))
    })?;
    let commit: SignedCommit = serde_ipld_dagcbor::from_slice(commit_data).map_err(|e| {
        CommitError::InvalidData(format!("Failed to parse SignedCommit block: {e}"))
    })?;

    // 2. Extract DRISL index block
    let drisl_data = blocks.get(&drisl_root_cid_str).ok_or_else(|| {
        CommitError::InvalidData(format!("Missing DRISL index block {drisl_root_cid_str}"))
    })?;
    let drisl_entries: Vec<DrislEntry> = serde_ipld_dagcbor::from_slice(drisl_data)
        .map_err(|e| CommitError::InvalidData(format!("Failed to parse DRISL index block: {e}")))?;

    // 3. Verify DRISL index ordering and decode record blocks
    let mut records = Vec::new();
    let mut last_key: Option<String> = None;

    for entry in drisl_entries {
        if let Some(prev) = &last_key {
            if &entry.k <= prev {
                return Err(CommitError::InvalidData(format!(
                    "DRISL index out of canonical order: '{}' <= '{}'",
                    entry.k, prev
                )));
            }
        }
        last_key = Some(entry.k.clone());

        let parts: Vec<&str> = entry.k.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(CommitError::InvalidData(format!(
                "Invalid DRISL key format: {}",
                entry.k
            )));
        }
        let collection = parts[0].to_string();
        let rkey = parts[1].to_string();

        let rec_data = blocks
            .get(&entry.v)
            .ok_or_else(|| CommitError::InvalidData(format!("Missing record block {}", entry.v)))?;

        let val: serde_json::Value = serde_ipld_dagcbor::from_slice(rec_data)
            .map_err(|e| CommitError::InvalidData(format!("Failed to decode record CBOR: {e}")))?;

        // Verify computed DAG-CBOR CID of decoded value matches entry.v
        let computed_cid = compute_dagcbor_cid(&val)?;
        if computed_cid != entry.v {
            return Err(CommitError::InvalidData(format!(
                "Record value CID mismatch: computed {computed_cid} != DRISL index CID {}",
                entry.v
            )));
        }

        records.push(RepoRecord {
            collection,
            rkey,
            cid: entry.v,
            value: val,
        });
    }

    Ok(DecodedRepoCar {
        commit,
        commit_cid: commit_root_cid_str,
        data_root_cid: drisl_root_cid_str,
        records,
    })
}

fn parse_cid_and_data(block_slice: &[u8]) -> Result<(String, Vec<u8>), CommitError> {
    if block_slice.is_empty() {
        return Err(CommitError::InvalidData("Empty block in CAR".into()));
    }
    let (cid_len, cid_bytes) = if block_slice[0] == 0x01 {
        if block_slice.len() < 4 {
            return Err(CommitError::InvalidData("Truncated CIDv1 in block".into()));
        }
        let hash_len = block_slice[3] as usize;
        let total_cid_len = 4 + hash_len;
        if block_slice.len() < total_cid_len {
            return Err(CommitError::InvalidData(
                "Truncated CIDv1 multihash in block".into(),
            ));
        }
        (total_cid_len, &block_slice[..total_cid_len])
    } else if block_slice[0] == 0x12 && block_slice.get(1) == Some(&0x20) {
        let total_cid_len = 34;
        if block_slice.len() < total_cid_len {
            return Err(CommitError::InvalidData("Truncated CIDv0 in block".into()));
        }
        (total_cid_len, &block_slice[..total_cid_len])
    } else {
        return Err(CommitError::InvalidData(
            "Unsupported CID format in CAR block".into(),
        ));
    };

    let cid_str = multibase::encode(multibase::Base::Base32Lower, cid_bytes);
    let data = block_slice[cid_len..].to_vec();

    // Verify block SHA-256 matches CID digest
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let computed_digest = hasher.finalize();

    let digest_in_cid = &cid_bytes[cid_bytes.len() - 32..];
    if &computed_digest[..] != digest_in_cid {
        return Err(CommitError::InvalidData(format!(
            "Block CID mismatch: computed SHA256 does not match CID {cid_str}"
        )));
    }

    Ok((cid_str, data))
}
