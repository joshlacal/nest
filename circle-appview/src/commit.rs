use catbird_atproto::generated::com_atproto::space::SignedCommit;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    ctx.extend_from_slice(PROTOCOL_TAG.as_bytes());
    for field in [
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

pub fn compute_dagcbor_cid<T: Serialize + ?Sized>(value: &T) -> Result<String, CommitError> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidLink(pub Vec<u8>);

impl CidLink {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn to_cid_string(&self) -> String {
        multibase::encode(multibase::Base::Base32Lower, &self.0)
    }
}

impl Serialize for CidLink {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_newtype_struct(
            "$serde_ipld_dagcbor::cid",
            serde_bytes::Bytes::new(&self.0),
        )
    }
}

impl<'de> Deserialize<'de> for CidLink {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CidVisitor;
        impl<'de> serde::de::Visitor<'de> for CidVisitor {
            type Value = CidLink;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a DAG-CBOR CID link")
            }
            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let bytes: serde_bytes::ByteBuf = serde::Deserialize::deserialize(deserializer)?;
                Ok(CidLink(bytes.into_vec()))
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(CidLink(v.to_vec()))
            }
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(CidLink(v))
            }
        }
        deserializer.deserialize_newtype_struct("$serde_ipld_dagcbor::cid", CidVisitor)
    }
}

pub fn create_cid_bytes_from_data(data: &[u8]) -> (Vec<u8>, String) {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarHeader {
    pub version: u64,
    pub roots: Vec<CidLink>,
}

pub fn is_canonical_drisl_key_order(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        a.len() < b.len()
    } else {
        a.as_bytes() < b.as_bytes()
    }
}

pub fn mint_repo_car(
    commit: &SignedCommit,
    records: &[RepoRecord],
) -> Result<Vec<u8>, CommitError> {
    // 1. Serialize SignedCommit to DAG-CBOR and compute its CID
    let commit_cbor = serde_ipld_dagcbor::to_vec(commit).map_err(|e| {
        CommitError::InvalidData(format!("SignedCommit DAG-CBOR serialization failed: {e}"))
    })?;
    let (commit_cid_bytes, _commit_cid_str) = create_cid_bytes_from_data(&commit_cbor);
    let commit_cid_link = CidLink::from_bytes(commit_cid_bytes.clone());

    // 2. Build DRISL index map and record blocks
    let mut drisl_map = std::collections::BTreeMap::new();
    let mut record_map = std::collections::HashMap::new();

    for rec in records {
        let rec_cbor = serde_ipld_dagcbor::to_vec(&rec.value).map_err(|e| {
            CommitError::InvalidData(format!("Record DAG-CBOR serialization failed: {e}"))
        })?;
        let (cid_bytes, _cid_str) = create_cid_bytes_from_data(&rec_cbor);
        let path_key = format!("{}/{}", rec.collection, rec.rkey);
        drisl_map.insert(path_key.clone(), CidLink::from_bytes(cid_bytes.clone()));
        record_map.insert(path_key, (cid_bytes, rec_cbor));
    }

    // 3. Serialize DRISL map to DAG-CBOR and compute its CID
    let drisl_cbor = serde_ipld_dagcbor::to_vec(&drisl_map).map_err(|e| {
        CommitError::InvalidData(format!("DRISL index DAG-CBOR serialization failed: {e}"))
    })?;
    let (drisl_cid_bytes, _drisl_cid_str) = create_cid_bytes_from_data(&drisl_cbor);
    let drisl_cid_link = CidLink::from_bytes(drisl_cid_bytes.clone());

    // 4. Create CAR header with two roots: [commit_cid, drisl_cid]
    let header = CarHeader {
        version: 1,
        roots: vec![commit_cid_link, drisl_cid_link],
    };
    let header_cbor = serde_ipld_dagcbor::to_vec(&header).map_err(|e| {
        CommitError::InvalidData(format!("CAR header DAG-CBOR serialization failed: {e}"))
    })?;

    // 5. Assemble CAR stream
    let mut car_bytes = Vec::new();
    encode_varint(header_cbor.len() as u64, &mut car_bytes);
    car_bytes.extend_from_slice(&header_cbor);

    // Block 1: Commit block
    encode_varint(
        (commit_cid_bytes.len() + commit_cbor.len()) as u64,
        &mut car_bytes,
    );
    car_bytes.extend_from_slice(&commit_cid_bytes);
    car_bytes.extend_from_slice(&commit_cbor);

    // Block 2: DRISL map block
    encode_varint(
        (drisl_cid_bytes.len() + drisl_cbor.len()) as u64,
        &mut car_bytes,
    );
    car_bytes.extend_from_slice(&drisl_cid_bytes);
    car_bytes.extend_from_slice(&drisl_cbor);
    // Blocks 3..N: Record blocks in DRISL map order
    for path in drisl_map.keys() {
        if let Some((cid_bytes, rec_cbor)) = record_map.get(path) {
            encode_varint((cid_bytes.len() + rec_cbor.len()) as u64, &mut car_bytes);
            car_bytes.extend_from_slice(cid_bytes);
            car_bytes.extend_from_slice(rec_cbor);
        }
    }

    Ok(car_bytes)
}

pub const MAX_CAR_BYTES: usize = 50 * 1024 * 1024; // 50MB bounded limit

pub fn decode_repo_car(car_bytes: &[u8]) -> Result<DecodedRepoCar, CommitError> {
    if car_bytes.is_empty() {
        return Err(CommitError::InvalidData("Empty CAR file".into()));
    }
    if car_bytes.len() > MAX_CAR_BYTES {
        return Err(CommitError::InvalidData(format!(
            "CAR file exceeds maximum size limit of {MAX_CAR_BYTES} bytes"
        )));
    }

    let (header_len, varint_len) = decode_varint(car_bytes)?;
    let header_start = varint_len;
    let header_end = header_start + header_len as usize;
    if car_bytes.len() < header_end {
        return Err(CommitError::InvalidData("Truncated CAR header".into()));
    }

    let header_slice = &car_bytes[header_start..header_end];
    let header: CarHeader = serde_ipld_dagcbor::from_slice(header_slice)
        .map_err(|e| CommitError::InvalidData(format!("Failed to parse CAR header: {e}")))?;

    // Verify canonical DAG-CBOR header re-encode equality
    let re_encoded_header = serde_ipld_dagcbor::to_vec(&header).map_err(|e| {
        CommitError::InvalidData(format!("Failed to re-encode CAR header: {e}"))
    })?;
    if re_encoded_header != header_slice {
        return Err(CommitError::InvalidData(
            "Non-canonical DAG-CBOR CAR header encoding".into(),
        ));
    }

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

    let commit_root_cid = &header.roots[0].0;
    let drisl_root_cid = &header.roots[1].0;
    let commit_root_cid_str = header.roots[0].to_cid_string();
    let drisl_root_cid_str = header.roots[1].to_cid_string();

    let mut offset = header_end;

    // Stream Block 1: SignedCommit block (must match root[0])
    if offset >= car_bytes.len() {
        return Err(CommitError::InvalidData("Missing commit root block in CAR".into()));
    }
    let (b1_len, b1_vlen) = decode_varint(&car_bytes[offset..])?;
    offset += b1_vlen;
    let b1_end = offset + b1_len as usize;
    if car_bytes.len() < b1_end {
        return Err(CommitError::InvalidData("Truncated commit block in CAR".into()));
    }
    let (b1_cid_bytes, b1_cid_str, b1_data) = parse_cid_and_data_raw(&car_bytes[offset..b1_end])?;
    offset = b1_end;

    if &b1_cid_bytes != commit_root_cid {
        return Err(CommitError::InvalidData(format!(
            "First block CID {b1_cid_str} does not match commit root CID {commit_root_cid_str}"
        )));
    }
    let commit: SignedCommit = serde_ipld_dagcbor::from_slice(&b1_data)
        .map_err(|e| CommitError::InvalidData(format!("Failed to parse SignedCommit block: {e}")))?;

    // Stream Block 2: DRISL map block (must match root[1])
    if offset >= car_bytes.len() {
        return Err(CommitError::InvalidData("Missing DRISL root block in CAR".into()));
    }
    let (b2_len, b2_vlen) = decode_varint(&car_bytes[offset..])?;
    offset += b2_vlen;
    let b2_end = offset + b2_len as usize;
    if car_bytes.len() < b2_end {
        return Err(CommitError::InvalidData("Truncated DRISL block in CAR".into()));
    }
    let (b2_cid_bytes, b2_cid_str, b2_data) = parse_cid_and_data_raw(&car_bytes[offset..b2_end])?;
    offset = b2_end;

    if &b2_cid_bytes != drisl_root_cid {
        return Err(CommitError::InvalidData(format!(
            "Second block CID {b2_cid_str} does not match DRISL root CID {drisl_root_cid_str}"
        )));
    }
    let drisl_map: std::collections::BTreeMap<String, CidLink> =
        serde_ipld_dagcbor::from_slice(&b2_data).map_err(|e| {
            CommitError::InvalidData(format!("Failed to parse DRISL index map: {e}"))
        })?;

    // Verify canonical DAG-CBOR DRISL map re-encode equality
    let re_encoded_drisl = serde_ipld_dagcbor::to_vec(&drisl_map).map_err(|e| {
        CommitError::InvalidData(format!("Failed to re-encode DRISL map: {e}"))
    })?;
    if re_encoded_drisl != b2_data {
        return Err(CommitError::InvalidData(
            "Non-canonical DAG-CBOR DRISL map encoding".into(),
        ));
    }

    // Stream Blocks 3..N: Record blocks in exact DRISL map order
    let mut records = Vec::with_capacity(drisl_map.len());
    let mut prev_key: Option<&str> = None;

    for (path_key, expected_cid_link) in &drisl_map {
        // Verify canonical key ordering (length first, then bytewise)
        if let Some(pk) = prev_key {
            if !is_canonical_drisl_key_order(pk, path_key) {
                return Err(CommitError::InvalidData(format!(
                    "DRISL map key out of canonical order: '{path_key}' follows '{pk}'"
                )));
            }
        }
        prev_key = Some(path_key.as_str());

        let parts: Vec<&str> = path_key.splitn(2, '/').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(CommitError::InvalidData(format!(
                "Invalid DRISL record key format: {path_key}"
            )));
        }
        let collection = parts[0].to_string();
        let rkey = parts[1].to_string();

        if offset >= car_bytes.len() {
            return Err(CommitError::InvalidData(format!(
                "Missing record block for DRISL entry {path_key}"
            )));
        }
        let (rec_len, rec_vlen) = decode_varint(&car_bytes[offset..])?;
        offset += rec_vlen;
        let rec_end = offset + rec_len as usize;
        if car_bytes.len() < rec_end {
            return Err(CommitError::InvalidData(format!(
                "Truncated record block for {path_key}"
            )));
        }
        let (rec_cid_bytes, rec_cid_str, rec_data) =
            parse_cid_and_data_raw(&car_bytes[offset..rec_end])?;
        offset = rec_end;
        if rec_cid_bytes != expected_cid_link.0 {
            return Err(CommitError::InvalidData(format!(
                "Record block CID {rec_cid_str} does not match DRISL expected CID {}",
                expected_cid_link.to_cid_string()
            )));
        }

        let val: serde_json::Value = serde_ipld_dagcbor::from_slice(&rec_data).map_err(|e| {
            CommitError::InvalidData(format!("Failed to decode record CBOR for {path_key}: {e}"))
        })?;

        let computed_cid = compute_dagcbor_cid(&val)?;
        if computed_cid != rec_cid_str {
            return Err(CommitError::InvalidData(format!(
                "Record value CID mismatch: computed {computed_cid} != block CID {rec_cid_str}"
            )));
        }

        records.push(RepoRecord {
            collection,
            rkey,
            cid: rec_cid_str,
            value: val,
        });
    }

    if offset != car_bytes.len() {
        return Err(CommitError::InvalidData(format!(
            "Unexpected trailing data in CAR stream: {} bytes remaining",
            car_bytes.len() - offset
        )));
    }

    Ok(DecodedRepoCar {
        commit,
        commit_cid: commit_root_cid_str,
        data_root_cid: drisl_root_cid_str,
        records,
    })
}

fn parse_cid_and_data_raw(block_slice: &[u8]) -> Result<(Vec<u8>, String, Vec<u8>), CommitError> {
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

    Ok((cid_bytes.to_vec(), cid_str, data))
}
