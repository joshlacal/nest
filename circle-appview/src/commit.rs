use catbird_atproto::generated::com_atproto::space::SignedCommit;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use rand::RngCore;
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
        let item_key = format!("{collection}/{rkey}:{cid}");
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"lthash16\0");
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
        hasher.update(&self.state);
        hasher.finalize().into()
    }
}

pub fn compute_commit_context(space: &str, author: &str, rev: &str, ikm: &[u8]) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(32 + space.len() + author.len() + rev.len() + ikm.len());
    ctx.extend_from_slice(PROTOCOL_TAG.as_bytes());
    ctx.push(b'\0');
    ctx.extend_from_slice(space.as_bytes());
    ctx.push(b'\0');
    ctx.extend_from_slice(author.as_bytes());
    ctx.push(b'\0');
    ctx.extend_from_slice(rev.as_bytes());
    ctx.push(b'\0');
    ctx.extend_from_slice(ikm);
    ctx
}

pub fn derive_commit_mac_key(ikm: &[u8], ctx: &[u8]) -> Result<[u8; 32], CommitError> {
    let hkdf = hkdf::Hkdf::<Sha256>::new(None, ikm);
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

    // 3. Compute commit context: (space, author, rev, ikm)
    let ctx = compute_commit_context(space, author, commit.rev.as_str(), commit.ikm.as_ref());

    // 4. HKDF derivation of HMAC key
    let mac_key = derive_commit_mac_key(commit.ikm.as_ref(), &ctx)?;

    // 5. HMAC verification over commit.hash
    let mut mac = HmacSha256::new_from_slice(&mac_key)
        .map_err(|e| CommitError::InvalidData(format!("Invalid HMAC key: {e}")))?;
    mac.update(commit.hash.as_ref());
    if mac.verify_slice(commit.mac.as_ref()).is_err() {
        return Err(CommitError::MacMismatch);
    }

    // 6. Signature verification over ctx
    match signing_key {
        ParsedVerifyingKey::P256(vk) => {
            let sig = p256::ecdsa::Signature::from_slice(commit.sig.as_ref())
                .map_err(|e| CommitError::InvalidSignature(format!("Invalid P-256 signature bytes: {e}")))?;
            use p256::ecdsa::signature::Verifier;
            vk.verify(&ctx, &sig)
                .map_err(|e| CommitError::InvalidSignature(format!("P-256 signature verification failed: {e}")))?;
        }
        ParsedVerifyingKey::Secp256k1(vk) => {
            let sig = k256::ecdsa::Signature::from_slice(commit.sig.as_ref())
                .map_err(|e| CommitError::InvalidSignature(format!("Invalid secp256k1 signature bytes: {e}")))?;
            use k256::ecdsa::signature::Verifier;
            vk.verify(&ctx, &sig)
                .map_err(|e| CommitError::InvalidSignature(format!("secp256k1 signature verification failed: {e}")))?;
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
    let bytes_hash = catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(hash.as_ref());
    let bytes_ikm = catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&ikm);
    let bytes_mac = catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&mac);
    let bytes_sig = catbird_atproto::jacquard_common::deps::bytes::Bytes::copy_from_slice(&sig.to_bytes());

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
