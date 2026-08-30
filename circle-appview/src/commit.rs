//! Permissioned repository commit and CAR verification primitives.
//!
//! Implements v1 (legacy) and v2 (authenticated transition) commit and CAR verification
//! across Ed25519, P-256, and Secp256k1 curves.

use bytes::Bytes;
use cid::Cid as IpldCid;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub use catbird_atproto::generated::com_atproto::space::SignedCommit;
pub use jacquard_repo::permissioned::{
    apply_writes, commit_from_cbor, commit_to_cbor, format_cursor, list_repo_ops, normalize_htu,
    parse_cursor, sign_commit, sign_commit_with_ikm, verify_dpop, ApplyWritesResult, CnfJkt,
    CommitContext, CredentialClaims, DpopProof, LtHash, OplogAction, OplogEntry, OplogPage,
    PermissionedCar, PermissionedError, RecordValue, SpaceTypeDeclaration, ValidatedRepoSnapshot,
    WriteOperation, WriteResult, WriteState, CLIENT_ATTESTATION_TYP, CLOCK_SKEW_SEC,
    DELEGATION_TOKEN_TYP, SPACE_CREDENTIAL_TYP,
};

use crate::auth::ParsedVerifyingKey;

pub const LTHASH_SIZE: usize = 2048;
pub const MAX_CAR_BYTES: usize = 50 * 1024 * 1024;
pub const MAX_CAR_BLOCKS: usize = 10_000;

/// Verification policy controlling commit version acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CommitVerificationPolicy {
    /// Strictly accept only authenticated v2 commits (default).
    #[default]
    StrictV2,
    /// Dual-read mode accepting v1 commits only up to the specified cutoff revision.
    DualReadWithCutoff { cutoff_rev: String },
    /// Explicit migration mode accepting legacy v1 commits.
    ExplicitMigrationPermitV1,
}

/// Commit transition context for v2 authenticated commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitContextV2 {
    pub space: String,
    pub author: String,
    pub rev: String,
    pub prev_rev: String,
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub path: String,
    pub action: String,
    pub cid: Option<String>,
    pub prev_cid: Option<String>,
    pub val: Bytes,
}

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

/// Strictly validate a CID (CIDv1, dag-cbor 0x71, sha2-256 0x12).
pub fn validate_strict_cid(cid: &IpldCid) -> Result<(), PermissionedError> {
    if cid.version() != cid::Version::V1 {
        return Err(PermissionedError::InvalidCar(
            "Only CIDv1 is supported".into(),
        ));
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

/// Parse and strictly validate a CID string.
pub fn parse_and_validate_strict_cid(cid_str: &str) -> Result<IpldCid, PermissionedError> {
    let parsed: IpldCid = cid_str
        .parse()
        .map_err(|e: cid::Error| PermissionedError::InvalidCommit(format!("invalid CID: {e}")))?;
    validate_strict_cid(&parsed)?;
    Ok(parsed)
}

fn check_no_floats_json(val: &serde_json::Value) -> Result<(), PermissionedError> {
    match val {
        serde_json::Value::Number(n) => {
            if !n.is_i64() && !n.is_u64() {
                return Err(PermissionedError::Serialization(
                    "Floating point numbers are forbidden in IPLD/ATProtocol".into(),
                ));
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
    let data: jacquard_common::types::value::Data<jacquard_common::SmolStr> =
        serde_json::from_value(val.clone()).map_err(|e| {
            PermissionedError::Serialization(format!("Invalid IPLD/JSON format: {e}"))
        })?;
    fn check_data_floats(
        d: &jacquard_common::types::value::Data<jacquard_common::SmolStr>,
    ) -> Result<(), PermissionedError> {
        match d {
            jacquard_common::types::value::Data::InvalidNumber(n) => {
                Err(PermissionedError::Serialization(format!(
                    "Floating point numbers are forbidden: {n}"
                )))
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
    let commit_cid: IpldCid = decoded
        .commit_cid
        .parse()
        .map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;
    let data_root_cid: IpldCid = decoded
        .data_root_cid
        .parse()
        .map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;
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
        if blocks.len() >= MAX_CAR_BLOCKS {
            return Err(PermissionedError::InvalidCar(format!(
                "CAR exceeds maximum block count limit of {MAX_CAR_BLOCKS}"
            )));
        }
        let section_len = read_varint(&mut cursor)? as usize;
        let mut section = vec![0u8; section_len];
        use std::io::Read;
        cursor
            .read_exact(&mut section)
            .map_err(|e| PermissionedError::InvalidCar(e.to_string()))?;
        let mut sec_cursor = std::io::Cursor::new(&section[..]);
        let cid = IpldCid::read_bytes(&mut sec_cursor)
            .map_err(|e| PermissionedError::InvalidCar(e.to_string()))?;
        validate_strict_cid(&cid)?;
        let cid_len = sec_cursor.position() as usize;
        let data = section[cid_len..].to_vec();
        blocks.push((cid, Bytes::from(data)));
    }

    PermissionedCar::new(roots, blocks)
}

/// Encode v2 commit context into the canonical length-prefixed transcript.
pub fn encode_commit_context_v2(ctx: &CommitContextV2) -> Result<Vec<u8>, PermissionedError> {
    let domain = b"atproto-space-v2";
    let cid_bytes = ctx.cid.as_deref().unwrap_or("").as_bytes();
    let prev_cid_bytes = ctx.prev_cid.as_deref().unwrap_or("").as_bytes();
    let fields: [&[u8]; 11] = [
        ctx.space.as_bytes(),
        ctx.author.as_bytes(),
        ctx.rev.as_bytes(),
        ctx.prev_rev.as_bytes(),
        &ctx.hash,
        &ctx.prev_hash,
        ctx.path.as_bytes(),
        ctx.action.as_bytes(),
        cid_bytes,
        prev_cid_bytes,
        ctx.val.as_ref(),
    ];
    let mut output = domain.to_vec();
    for field in fields {
        if field.len() > u16::MAX as usize {
            return Err(PermissionedError::InvalidCommit(
                "Field length exceeds u16::MAX in commit context v2".into(),
            ));
        }
        output.extend_from_slice(&(field.len() as u16).to_be_bytes());
        output.extend_from_slice(field);
    }
    Ok(output)
}

/// Verify a v2 SignedCommit against a CommitContextV2 and verifying key.
pub fn verify_commit_v2(
    commit: &SignedCommit,
    context: &CommitContextV2,
    key: &ParsedVerifyingKey,
) -> Result<(), PermissionedError> {
    if commit.ver != 2 {
        return Err(PermissionedError::InvalidCommit(
            "commit version mismatch: expected ver 2".into(),
        ));
    }
    let commit_did = commit
        .did
        .as_ref()
        .map(|d| d.as_str())
        .ok_or_else(|| PermissionedError::InvalidCommit("v2 commit missing did".into()))?;
    if commit_did != context.author {
        return Err(PermissionedError::InvalidCommit(
            "commit author DID mismatch".into(),
        ));
    }
    let commit_space = commit
        .space
        .as_ref()
        .map(|s| s.as_str())
        .ok_or_else(|| PermissionedError::InvalidCommit("v2 commit missing space".into()))?;
    if commit_space != context.space {
        return Err(PermissionedError::InvalidCommit(
            "commit space URI mismatch".into(),
        ));
    }
    if commit.rev.as_str() != context.rev {
        return Err(PermissionedError::InvalidCommit(
            "commit rev mismatch".into(),
        ));
    }
    let commit_prev_rev = commit
        .prev_rev
        .as_ref()
        .map(|r| r.as_str())
        .ok_or_else(|| PermissionedError::InvalidCommit("v2 commit missing prev_rev".into()))?;
    if commit_prev_rev != context.prev_rev {
        return Err(PermissionedError::InvalidCommit(
            "commit prev_rev mismatch".into(),
        ));
    }
    // Monotonic check: rev > prev_rev
    if commit.rev.as_str() <= commit_prev_rev {
        return Err(PermissionedError::InvalidCommit(
            "non-monotonic revision: rev must be strictly greater than prev_rev".into(),
        ));
    }

    let commit_hash: &[u8; 32] = commit
        .hash
        .as_ref()
        .try_into()
        .map_err(|_| PermissionedError::InvalidCommit("hash must contain 32 bytes".into()))?;
    if commit_hash != &context.hash {
        return Err(PermissionedError::InvalidCommit(
            "commit hash mismatch".into(),
        ));
    }

    let prev_hash_bytes = commit
        .prev_hash
        .as_ref()
        .ok_or_else(|| PermissionedError::InvalidCommit("v2 commit missing prev_hash".into()))?;
    let commit_prev_hash: &[u8; 32] = prev_hash_bytes
        .as_ref()
        .try_into()
        .map_err(|_| PermissionedError::InvalidCommit("prev_hash must contain 32 bytes".into()))?;
    if commit_prev_hash != &context.prev_hash {
        return Err(PermissionedError::InvalidCommit(
            "commit prev_hash mismatch".into(),
        ));
    }

    let commit_path = commit
        .path
        .as_ref()
        .map(|p| p.as_str())
        .ok_or_else(|| PermissionedError::InvalidCommit("v2 commit missing path".into()))?;
    if commit_path != context.path {
        return Err(PermissionedError::InvalidCommit(
            "commit path mismatch".into(),
        ));
    }
    // Validate path format "collection/rkey"
    let (col, rkey) = commit_path
        .split_once('/')
        .ok_or_else(|| PermissionedError::InvalidCommit("invalid path format in commit".into()))?;
    if col.is_empty() || rkey.is_empty() || rkey.contains('/') {
        return Err(PermissionedError::InvalidCommit(
            "invalid path format in commit".into(),
        ));
    }
    if rkey
        .parse::<catbird_atproto::jacquard_common::types::string::Rkey>()
        .is_err()
    {
        return Err(PermissionedError::InvalidCommit(
            "invalid rkey in commit path".into(),
        ));
    }

    let commit_action = commit
        .action
        .as_ref()
        .map(|a| a.as_str())
        .ok_or_else(|| PermissionedError::InvalidCommit("v2 commit missing action".into()))?;
    if commit_action != context.action {
        return Err(PermissionedError::InvalidCommit(
            "commit action mismatch".into(),
        ));
    }

    match commit_action {
        "create" => {
            let cid_str = commit.cid.as_ref().map(|c| c.as_str()).ok_or_else(|| {
                PermissionedError::InvalidCommit("v2 create action missing cid".into())
            })?;
            parse_and_validate_strict_cid(cid_str)?;
            if commit.prev_cid.is_some() {
                return Err(PermissionedError::InvalidCommit(
                    "v2 create action must not have prev_cid".into(),
                ));
            }
            if context.cid.as_deref() != Some(cid_str) {
                return Err(PermissionedError::InvalidCommit(
                    "commit cid mismatch".into(),
                ));
            }
            if context.prev_cid.is_some() {
                return Err(PermissionedError::InvalidCommit(
                    "context create must not have prev_cid".into(),
                ));
            }
        }
        "update" => {
            let cid_str = commit.cid.as_ref().map(|c| c.as_str()).ok_or_else(|| {
                PermissionedError::InvalidCommit("v2 update action missing cid".into())
            })?;
            parse_and_validate_strict_cid(cid_str)?;
            let prev_cid_str = commit
                .prev_cid
                .as_ref()
                .map(|c| c.as_str())
                .ok_or_else(|| {
                    PermissionedError::InvalidCommit("v2 update action missing prev_cid".into())
                })?;
            parse_and_validate_strict_cid(prev_cid_str)?;
            if context.cid.as_deref() != Some(cid_str) {
                return Err(PermissionedError::InvalidCommit(
                    "commit cid mismatch".into(),
                ));
            }
            if context.prev_cid.as_deref() != Some(prev_cid_str) {
                return Err(PermissionedError::InvalidCommit(
                    "commit prev_cid mismatch".into(),
                ));
            }
        }
        "delete" => {
            if commit.cid.is_some() {
                return Err(PermissionedError::InvalidCommit(
                    "v2 delete action must not have cid".into(),
                ));
            }
            let prev_cid_str = commit
                .prev_cid
                .as_ref()
                .map(|c| c.as_str())
                .ok_or_else(|| {
                    PermissionedError::InvalidCommit("v2 delete action missing prev_cid".into())
                })?;
            parse_and_validate_strict_cid(prev_cid_str)?;
            if context.cid.is_some() {
                return Err(PermissionedError::InvalidCommit(
                    "context delete must not have cid".into(),
                ));
            }
            if context.prev_cid.as_deref() != Some(prev_cid_str) {
                return Err(PermissionedError::InvalidCommit(
                    "commit prev_cid mismatch".into(),
                ));
            }
        }
        other => {
            return Err(PermissionedError::InvalidCommit(format!(
                "unsupported commit action: {other}"
            )));
        }
    }

    let commit_val = commit
        .val
        .as_ref()
        .ok_or_else(|| PermissionedError::InvalidCommit("v2 commit missing val".into()))?;
    if commit_val.as_ref() != context.val.as_ref() {
        return Err(PermissionedError::InvalidCommit(
            "commit val mismatch".into(),
        ));
    }

    let transcript = encode_commit_context_v2(context)?;

    match key {
        ParsedVerifyingKey::Ed25519(vk) => {
            let sig = ed25519_dalek::Signature::from_slice(commit.sig.as_ref()).map_err(|e| {
                PermissionedError::InvalidCommit(format!("invalid Ed25519 signature: {e}"))
            })?;
            use ed25519_dalek::Verifier;
            vk.verify(&transcript, &sig).map_err(|e| {
                PermissionedError::InvalidCommit(format!("Ed25519 signature mismatch: {e}"))
            })?;
        }
        ParsedVerifyingKey::P256(vk) => {
            let sig = p256::ecdsa::Signature::from_slice(commit.sig.as_ref()).map_err(|e| {
                PermissionedError::InvalidCommit(format!("invalid P-256 signature: {e}"))
            })?;
            use p256::ecdsa::signature::Verifier;
            vk.verify(&transcript, &sig).map_err(|e| {
                PermissionedError::InvalidCommit(format!("P-256 signature mismatch: {e}"))
            })?;
        }
        ParsedVerifyingKey::Secp256k1(vk) => {
            let sig = k256::ecdsa::Signature::from_slice(commit.sig.as_ref()).map_err(|e| {
                PermissionedError::InvalidCommit(format!("invalid secp256k1 signature: {e}"))
            })?;
            use k256::ecdsa::signature::Verifier;
            vk.verify(&transcript, &sig).map_err(|e| {
                PermissionedError::InvalidCommit(format!("secp256k1 signature mismatch: {e}"))
            })?;
        }
    }

    Ok(())
}

/// Verify a legacy v1 SignedCommit against a CommitContext and verifying key.
pub fn verify_commit_v1(
    commit: &SignedCommit,
    context: &CommitContext,
    key: &ParsedVerifyingKey,
) -> Result<(), PermissionedError> {
    if commit.ver != 1 {
        return Err(PermissionedError::InvalidCommit(
            "expected ver 1 commit".into(),
        ));
    }
    let ikm = commit
        .ikm
        .as_ref()
        .ok_or_else(|| PermissionedError::InvalidCommit("v1 commit missing ikm".into()))?;
    let mac = commit
        .mac
        .as_ref()
        .ok_or_else(|| PermissionedError::InvalidCommit("v1 commit missing mac".into()))?;
    let ikm_slice: &[u8; 32] = ikm
        .as_ref()
        .try_into()
        .map_err(|_| PermissionedError::InvalidCommit("ikm must contain 32 bytes".into()))?;
    let hash_slice: &[u8; 32] = commit
        .hash
        .as_ref()
        .try_into()
        .map_err(|_| PermissionedError::InvalidCommit("hash must contain 32 bytes".into()))?;
    let mac_slice: &[u8; 32] = mac
        .as_ref()
        .try_into()
        .map_err(|_| PermissionedError::InvalidCommit("mac must contain 32 bytes".into()))?;

    if commit.rev.as_str() != context.rev.as_str() {
        return Err(PermissionedError::InvalidCommit("revision mismatch".into()));
    }

    let context_bytes = encode_commit_context_local(context, ikm_slice)?;
    if compute_mac_local(ikm_slice, &context_bytes, hash_slice) != *mac_slice {
        return Err(PermissionedError::InvalidCommit("MAC mismatch".into()));
    }

    match key {
        ParsedVerifyingKey::Ed25519(vk) => {
            let sig = ed25519_dalek::Signature::from_slice(commit.sig.as_ref()).map_err(|e| {
                PermissionedError::InvalidCommit(format!("invalid Ed25519 signature: {e}"))
            })?;
            use ed25519_dalek::Verifier;
            vk.verify(&context_bytes, &sig).map_err(|e| {
                PermissionedError::InvalidCommit(format!("Ed25519 signature mismatch: {e}"))
            })?;
        }
        ParsedVerifyingKey::P256(vk) => {
            let sig = p256::ecdsa::Signature::from_slice(commit.sig.as_ref()).map_err(|e| {
                PermissionedError::InvalidCommit(format!("invalid P-256 signature: {e}"))
            })?;
            use p256::ecdsa::signature::Verifier;
            vk.verify(&context_bytes, &sig).map_err(|e| {
                PermissionedError::InvalidCommit(format!("P-256 signature mismatch: {e}"))
            })?;
        }
        ParsedVerifyingKey::Secp256k1(vk) => {
            let sig = k256::ecdsa::Signature::from_slice(commit.sig.as_ref()).map_err(|e| {
                PermissionedError::InvalidCommit(format!("invalid secp256k1 signature: {e}"))
            })?;
            use k256::ecdsa::signature::Verifier;
            vk.verify(&context_bytes, &sig).map_err(|e| {
                PermissionedError::InvalidCommit(format!("secp256k1 signature mismatch: {e}"))
            })?;
        }
    }
    Ok(())
}

/// Verify a commit under an explicit CommitVerificationPolicy.
pub fn verify_commit_with_policy(
    commit: &SignedCommit,
    context_v1: Option<&CommitContext>,
    context_v2: Option<&CommitContextV2>,
    key: &ParsedVerifyingKey,
    policy: &CommitVerificationPolicy,
) -> Result<(), PermissionedError> {
    match commit.ver {
        2 => {
            let ctx = context_v2.ok_or_else(|| {
                PermissionedError::InvalidCommit(
                    "v2 commit verification requires CommitContextV2".into(),
                )
            })?;
            verify_commit_v2(commit, ctx, key)
        }
        1 => match policy {
            CommitVerificationPolicy::StrictV2 => Err(PermissionedError::InvalidCommit(
                "v1 commits rejected under StrictV2 verification policy".into(),
            )),
            CommitVerificationPolicy::DualReadWithCutoff { cutoff_rev } => {
                if commit.rev.as_str() > cutoff_rev.as_str() {
                    return Err(PermissionedError::InvalidCommit(format!(
                        "v1 commit revision {} exceeds allowed cutoff {}",
                        commit.rev, cutoff_rev
                    )));
                }
                let ctx = context_v1.ok_or_else(|| {
                    PermissionedError::InvalidCommit(
                        "v1 commit verification requires CommitContext".into(),
                    )
                })?;
                verify_commit_v1(commit, ctx, key)
            }
            CommitVerificationPolicy::ExplicitMigrationPermitV1 => {
                let ctx = context_v1.ok_or_else(|| {
                    PermissionedError::InvalidCommit(
                        "v1 commit verification requires CommitContext".into(),
                    )
                })?;
                verify_commit_v1(commit, ctx, key)
            }
        },
        other => Err(PermissionedError::InvalidCommit(format!(
            "unsupported commit version: {other}"
        ))),
    }
}

/// Verify a signed commit with default policy (StrictV2 / dual read).
pub fn verify_commit(
    commit: &SignedCommit,
    context: &CommitContext,
    key: &ParsedVerifyingKey,
) -> Result<(), PermissionedError> {
    // For legacy callers passing CommitContext, try v1 verification
    if commit.ver == 1 {
        verify_commit_v1(commit, context, key)
    } else {
        Err(PermissionedError::InvalidCommit(
            "v2 commit requires verify_commit_v2 or verify_commit_with_policy with CommitContextV2"
                .into(),
        ))
    }
}

fn encode_commit_context_local(
    context: &CommitContext,
    ikm: &[u8; 32],
) -> Result<Vec<u8>, PermissionedError> {
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
#[allow(clippy::type_complexity)]
pub fn extract_and_validate_car(
    car: &PermissionedCar,
    space_uri: &str,
    author_did: &str,
    key: &ParsedVerifyingKey,
) -> Result<
    (
        SignedCommit,
        Vec<(String, String, String, serde_json::Value)>,
        LtHash,
    ),
    PermissionedError,
> {
    extract_and_validate_car_with_policy(
        car,
        space_uri,
        author_did,
        key,
        &CommitVerificationPolicy::default(),
    )
}

/// Extract and validate a permissioned CAR file under an explicit CommitVerificationPolicy.
#[allow(clippy::type_complexity)]
pub fn extract_and_validate_car_with_policy(
    car: &PermissionedCar,
    space_uri: &str,
    author_did: &str,
    key: &ParsedVerifyingKey,
    policy: &CommitVerificationPolicy,
) -> Result<
    (
        SignedCommit,
        Vec<(String, String, String, serde_json::Value)>,
        LtHash,
    ),
    PermissionedError,
> {
    let space_uri_parsed = jacquard_common::types::aturi::AtSpaceUri::new_owned(space_uri)
        .map_err(|_| PermissionedError::InvalidComponent {
            field: "space_uri",
            value: space_uri.to_string(),
        })?;
    let author_did_parsed =
        jacquard_common::types::did::Did::new_owned(author_did).map_err(|_| {
            PermissionedError::InvalidComponent {
                field: "author_did",
                value: author_did.to_string(),
            }
        })?;

    if car.blocks.len() < 2 {
        return Err(PermissionedError::InvalidCar(
            "CAR has fewer than 2 blocks".into(),
        ));
    }

    let commit: SignedCommit = serde_ipld_dagcbor::from_slice(&car.blocks[0].1)
        .map_err(|e| PermissionedError::InvalidCar(format!("Commit decode error: {e}")))?;

    let decoded_index: std::collections::BTreeMap<
        jacquard_common::SmolStr,
        jacquard_common::types::cid::CidLink<jacquard_common::SmolStr>,
    > = serde_ipld_dagcbor::from_slice(&car.blocks[1].1)
        .map_err(|e| PermissionedError::InvalidCar(format!("Index decode error: {e}")))?;

    let mut index = Vec::new();
    for (path, link) in decoded_index {
        let cid = link
            .to_ipld()
            .map_err(|e| PermissionedError::InvalidCar(e.to_string()))?;
        validate_strict_cid(&cid)?;
        index.push((path, cid));
    }
    index.sort_by(|a, b| {
        a.0.len()
            .cmp(&b.0.len())
            .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
    });

    let mut lthash = LtHash::default();
    for (path, cid) in &index {
        lthash.add(&format!("{path}/{cid}"));
    }
    if commit.hash.as_ref() != lthash.digest().as_slice() {
        return Err(PermissionedError::InvalidCar(
            "Index does not match commit hash".into(),
        ));
    }

    let context_v1 = CommitContext {
        space: space_uri_parsed,
        author: author_did_parsed,
        rev: commit.rev.to_string().into(),
    };

    let prev_rev = commit
        .prev_rev
        .as_ref()
        .map(|r| r.to_string())
        .unwrap_or_default();
    let prev_hash = commit
        .prev_hash
        .as_ref()
        .and_then(|h| h.as_ref().try_into().ok())
        .unwrap_or([0u8; 32]);

    let hash: [u8; 32] = lthash.digest();
    let path = commit
        .path
        .as_ref()
        .map(|p| p.to_string())
        .unwrap_or_default();
    let action = commit
        .action
        .as_ref()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let cid = commit.cid.as_ref().map(|c| c.to_string());
    let prev_cid = commit.prev_cid.as_ref().map(|c| c.to_string());
    let val = commit.val.clone().unwrap_or_default();

    let context_v2 = CommitContextV2 {
        space: space_uri.to_string(),
        author: author_did.to_string(),
        rev: commit.rev.to_string(),
        prev_rev,
        hash,
        prev_hash,
        path,
        action,
        cid,
        prev_cid,
        val,
    };

    verify_commit_with_policy(&commit, Some(&context_v1), Some(&context_v2), key, policy)?;
    // Check that record_blocks.len() == index.len() to reject extra unreferenced blocks (Finding minor)
    let record_blocks = &car.blocks[2..];
    if record_blocks.len() != index.len() {
        return Err(PermissionedError::InvalidCar(format!(
            "CAR record blocks count ({}) does not match index entry count ({})",
            record_blocks.len(),
            index.len()
        )));
    }

    // Build $O(1)$ block map for linear time CAR extraction (Finding 42)
    let block_map: HashMap<IpldCid, &Bytes> = record_blocks
        .iter()
        .map(|(cid, bytes)| (*cid, bytes))
        .collect();
    let mut records = Vec::with_capacity(index.len());
    for (path, expected_cid) in &index {
        let (collection, rkey) = path
            .split_once('/')
            .ok_or_else(|| PermissionedError::InvalidCar("Invalid index path".into()))?;
        // Validate RecordKey (Finding 28)
        if rkey
            .parse::<catbird_atproto::jacquard_common::types::string::Rkey>()
            .is_err()
        {
            return Err(PermissionedError::InvalidCar(
                "invalid rkey in CAR index".into(),
            ));
        }

        let bytes = block_map.get(expected_cid).ok_or_else(|| {
            PermissionedError::InvalidCar(format!("missing block for CID {expected_cid}"))
        })?;

        let json_val: serde_json::Value = serde_ipld_dagcbor::from_slice(bytes)
            .map_err(|e| PermissionedError::InvalidCar(format!("Record decode error: {e}")))?;
        records.push((
            collection.to_string(),
            rkey.to_string(),
            expected_cid.to_string(),
            json_val,
        ));
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
        return Err(PermissionedError::InvalidCommit(
            "IKM must be 32 bytes".into(),
        ));
    }
    let mut ikm_arr = [0u8; 32];
    ikm_arr.copy_from_slice(ikm);
    let space_uri = jacquard_common::types::aturi::AtSpaceUri::new_owned(space).map_err(|_| {
        PermissionedError::InvalidComponent {
            field: "space",
            value: space.to_string(),
        }
    })?;
    let author_did = jacquard_common::types::did::Did::new_owned(author).map_err(|_| {
        PermissionedError::InvalidComponent {
            field: "author",
            value: author.to_string(),
        }
    })?;
    let tid_rev = jacquard_common::types::tid::Tid::new(rev).map_err(|_| {
        PermissionedError::InvalidComponent {
            field: "rev",
            value: rev.to_string(),
        }
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
        return Err(PermissionedError::InvalidCommit(
            "IKM must be 32 bytes".into(),
        ));
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

/// Mint a legacy v1 signed commit.
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
        ikm: Some(bytes::Bytes::copy_from_slice(&ikm)),
        mac: Some(bytes::Bytes::copy_from_slice(&mac)),
        rev: rev.to_string().into(),
        sig: bytes::Bytes::copy_from_slice(&sig.to_bytes()),
        ver: 1,
        action: None,
        cid: None,
        did: None,
        path: None,
        prev_cid: None,
        prev_hash: None,
        prev_rev: None,
        space: None,
        val: None,
        extra_data: None,
    }
}

/// Mint a v2 signed commit using P-256.
pub fn mint_signed_commit_v2_p256(
    ctx: &CommitContextV2,
    signing_key: &p256::ecdsa::SigningKey,
) -> Result<SignedCommit, PermissionedError> {
    let transcript = encode_commit_context_v2(ctx)?;
    let sig: p256::ecdsa::Signature =
        p256::ecdsa::signature::Signer::sign(signing_key, &transcript);

    Ok(SignedCommit {
        ver: 2,
        rev: ctx.rev.clone().into(),
        prev_rev: Some(ctx.prev_rev.clone().into()),
        did: Some(ctx.author.clone().into()),
        space: Some(
            catbird_atproto::jacquard_common::types::string::AtUri::new(
                jacquard_common::SmolStr::new(&ctx.space),
            )
            .map_err(|e| PermissionedError::InvalidCommit(e.to_string()))?,
        ),
        hash: Bytes::copy_from_slice(&ctx.hash),
        prev_hash: Some(Bytes::copy_from_slice(&ctx.prev_hash)),
        path: Some(ctx.path.clone().into()),
        action: Some(ctx.action.clone().into()),
        cid: ctx.cid.as_ref().map(|c| c.clone().into()),
        prev_cid: ctx.prev_cid.as_ref().map(|c| c.clone().into()),
        val: Some(ctx.val.clone()),
        sig: Bytes::copy_from_slice(&sig.to_bytes()),
        ikm: None,
        mac: None,
        extra_data: None,
    })
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
    let commit_cid_obj: IpldCid = commit_cid
        .parse()
        .map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;

    let mut index_map: std::collections::BTreeMap<
        jacquard_common::SmolStr,
        CidLink<jacquard_common::SmolStr>,
    > = std::collections::BTreeMap::new();
    let mut record_blocks: Vec<(String, String, Vec<u8>)> = Vec::new();

    for rec in records {
        let path = format!("{}/{}", rec.collection, rec.rkey);
        let rec_cbor = serde_ipld_dagcbor::to_vec(&rec.value)
            .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
        let (_rec_cid_bytes, rec_cid) = create_cid_bytes_from_data(&rec_cbor);
        let rec_cid_obj: IpldCid = rec_cid
            .parse()
            .map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;
        let link = CidLink::ipld(rec_cid_obj);
        index_map.insert(jacquard_common::SmolStr::new(path.as_str()), link);
        record_blocks.push((path, rec_cid, rec_cbor));
    }

    let index_cbor = serde_ipld_dagcbor::to_vec(&index_map)
        .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
    let (index_cid_bytes, index_cid) = create_cid_bytes_from_data(&index_cbor);
    let index_cid_obj: IpldCid = index_cid
        .parse()
        .map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;

    let roots = vec![commit_cid_obj, index_cid_obj];
    let header = CarHeader { version: 1, roots };
    let header_cbor = serde_ipld_dagcbor::to_vec(&header)
        .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
    let mut output = Vec::new();
    encode_varint(header_cbor.len() as u64, &mut output);
    output.extend_from_slice(&header_cbor);

    // Commit block
    encode_varint(
        (commit_cid_bytes.len() + commit_cbor.len()) as u64,
        &mut output,
    );
    output.extend_from_slice(&commit_cid_bytes);
    output.extend_from_slice(&commit_cbor);

    // Index block
    encode_varint(
        (index_cid_bytes.len() + index_cbor.len()) as u64,
        &mut output,
    );
    output.extend_from_slice(&index_cid_bytes);
    output.extend_from_slice(&index_cbor);

    // Record blocks in DRISL index order (shortest key first)
    record_blocks.sort_by(|a, b| {
        a.0.len()
            .cmp(&b.0.len())
            .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
    });
    for (_path, rec_cid, rec_cbor) in record_blocks {
        let rec_cid_obj: IpldCid = rec_cid
            .parse()
            .map_err(|e: cid::Error| PermissionedError::InvalidCar(e.to_string()))?;
        let rec_cid_bytes = rec_cid_obj.to_bytes();
        encode_varint((rec_cid_bytes.len() + rec_cbor.len()) as u64, &mut output);
        output.extend_from_slice(&rec_cid_bytes);
        output.extend_from_slice(&rec_cbor);
    }

    Ok(output)
}

pub fn decode_repo_car(bytes: &[u8]) -> Result<DecodedRepoCar, PermissionedError> {
    if bytes.is_empty() {
        return Err(PermissionedError::InvalidCar("empty CAR".into()));
    }
    if bytes.len() > MAX_CAR_BYTES {
        return Err(PermissionedError::InvalidCar(
            "CAR payload exceeds maximum size limit".into(),
        ));
    }
    let mut offset = 0;
    let (header_len_u64, vlen) = decode_varint(&bytes[offset..])?;
    offset += vlen;
    let header_len = usize::try_from(header_len_u64)
        .map_err(|_| PermissionedError::InvalidCar("header length overflow".into()))?;
    if offset
        .checked_add(header_len)
        .is_none_or(|end| end > bytes.len())
    {
        return Err(PermissionedError::InvalidCar(
            "EOF reading CAR header".into(),
        ));
    }
    let header_bytes = &bytes[offset..offset + header_len];
    offset += header_len;

    let header: CarHeader = serde_ipld_dagcbor::from_slice(header_bytes)
        .map_err(|e| PermissionedError::InvalidCar(e.to_string()))?;
    if header.roots.len() < 2 {
        return Err(PermissionedError::InvalidCar(
            "CAR has fewer than 2 roots".into(),
        ));
    }
    for root in &header.roots {
        validate_strict_cid(root)?;
    }
    let commit_cid = header.roots[0].to_string();
    let data_root_cid = header.roots[1].to_string();
    let mut blocks = Vec::new();

    while offset < bytes.len() {
        if blocks.len() >= MAX_CAR_BLOCKS {
            return Err(PermissionedError::InvalidCar(format!(
                "CAR exceeds maximum block count limit of {MAX_CAR_BLOCKS}"
            )));
        }
        let (section_len_u64, vlen) = decode_varint(&bytes[offset..])?;
        offset += vlen;
        let section_len = usize::try_from(section_len_u64)
            .map_err(|_| PermissionedError::InvalidCar("section length overflow".into()))?;
        if offset
            .checked_add(section_len)
            .is_none_or(|end| end > bytes.len())
        {
            return Err(PermissionedError::InvalidCar(
                "EOF reading CAR section".into(),
            ));
        }
        let section = &bytes[offset..offset + section_len];
        offset += section_len;

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
        return Err(PermissionedError::InvalidCar(
            "CAR has fewer than 2 blocks".into(),
        ));
    }

    // Validate SignedCommit
    let raw_commit_cbor = &blocks[0].1;
    let commit_data: jacquard_common::types::value::Data<jacquard_common::SmolStr> =
        serde_ipld_dagcbor::from_slice(raw_commit_cbor).map_err(|e| {
            PermissionedError::InvalidCar(format!("Non-canonical DAG-CBOR SignedCommit: {e}"))
        })?;
    fn has_invalid_numbers(
        d: &jacquard_common::types::value::Data<jacquard_common::SmolStr>,
    ) -> bool {
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
        serde_ipld_dagcbor::from_slice(raw_index_cbor).map_err(|e| {
            PermissionedError::InvalidCar(format!("Duplicate map key or invalid DRISL CBOR: {e}"))
        })?;
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
    let index: std::collections::BTreeMap<
        jacquard_common::SmolStr,
        CidLink<jacquard_common::SmolStr>,
    > = serde_ipld_dagcbor::from_slice(raw_index_cbor).map_err(|e| {
        PermissionedError::InvalidCar(format!("Duplicate map key or invalid DRISL CBOR: {e}"))
    })?;

    // Validate Record blocks
    for (_cid_str, rec_data) in &blocks[2..] {
        let parsed_data: jacquard_common::types::value::Data<jacquard_common::SmolStr> =
            serde_ipld_dagcbor::from_slice(rec_data).map_err(|e| {
                PermissionedError::InvalidCar(format!(
                    "Failed to decode record CBOR: Duplicate map key or malformed DAG-CBOR: {e}"
                ))
            })?;
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

    // Single-pass hash map index (Finding 42)
    let block_map: HashMap<String, Vec<u8>> = blocks.into_iter().collect();

    let mut index_entries: Vec<(jacquard_common::SmolStr, CidLink<jacquard_common::SmolStr>)> =
        index.into_iter().collect();
    index_entries.sort_by(|a, b| {
        a.0.len()
            .cmp(&b.0.len())
            .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
    });

    let mut records = Vec::with_capacity(index_entries.len());
    for (path, link) in index_entries {
        let (collection, rkey) = path
            .split_once('/')
            .ok_or_else(|| PermissionedError::InvalidCar("invalid path in index".into()))?;
        // Validate RecordKey (Finding 28)
        if rkey
            .parse::<catbird_atproto::jacquard_common::types::string::Rkey>()
            .is_err()
        {
            return Err(PermissionedError::InvalidCar(
                "invalid rkey in CAR index".into(),
            ));
        }
        let cid_str = link.as_str().to_string();
        let rec_data = block_map.get(&cid_str).ok_or_else(|| {
            PermissionedError::InvalidCar(format!("missing record block {cid_str}"))
        })?;
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
