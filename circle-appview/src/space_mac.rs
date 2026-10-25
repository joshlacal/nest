//! October 22 Spaces request authentication. Secrets are unique to each request.
use crate::{
    auth::{parse_verification_key, DidDocument, ParsedVerifyingKey},
    error::{AppError, AuthReason},
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
pub use catbird_atproto::generated::com_atproto::space::Commit;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::Generate;
use p256::{elliptic_curve::sec1::ToSec1Point, PublicKey, SecretKey};
use sha2::Sha256;

pub const WANT_MAC_HEADER: &str = "atproto-space-want-mac";
pub const MAC_HEADER: &str = "atproto-space-mac";
pub const REPO_MAC_TYPE: &str = "atproto-space-repo";
pub const RECORD_MAC_TYPE: &str = "atproto-space-record";

#[derive(Clone, PartialEq, Eq)]
pub struct MacRequest {
    pub key_share: String,
    pub shared_secret: [u8; 32],
}
impl std::fmt::Debug for MacRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacRequest")
            .field("key_share", &self.key_share)
            .finish_non_exhaustive()
    }
}
fn bad() -> AppError {
    AppError::Unauthorized(AuthReason::BadSpaceMac)
}

pub fn kem_key(doc: &DidDocument, did: &str) -> Result<PublicKey, AppError> {
    if doc.id != did {
        return Err(bad());
    }
    let id = format!("{did}#atproto_kem");
    let mut matches = doc
        .verification_method
        .iter()
        .filter(|vm| vm.id == id || vm.id == "#atproto_kem");
    let vm = matches.next().ok_or_else(|| {
        AppError::UnsupportedPds("Account has no published #atproto_kem key".into())
    })?;
    if matches.next().is_some()
        || vm.controller != did
        || vm.public_key_jwk.is_some()
        || !matches!(
            vm.r#type.as_str(),
            "Multikey" | "EcdsaSecp256r1VerificationKey2019"
        )
    {
        return Err(bad());
    }
    match parse_verification_key(vm).map_err(AppError::Unauthorized)? {
        ParsedVerifyingKey::P256(key) => {
            PublicKey::from_sec1_bytes(key.to_sec1_point(false).as_bytes()).map_err(|_| bad())
        }
        _ => Err(bad()),
    }
}
pub fn encapsulate(author: &PublicKey) -> Result<MacRequest, AppError> {
    let ephemeral = SecretKey::generate_from_rng(&mut rand::rng());
    let public = ephemeral.public_key();
    let shared_secret = derive_secret(&ephemeral, author, &public, author)?;
    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(public.to_sec1_point(true).as_bytes());
    Ok(MacRequest {
        key_share: format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, multikey)
        ),
        shared_secret,
    })
}
pub fn derive_secret(
    secret: &SecretKey,
    other: &PublicKey,
    syncer: &PublicKey,
    author: &PublicKey,
) -> Result<[u8; 32], AppError> {
    let dh = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), other.as_affine());
    let prefix = b"HPKE-v1KEM\x00\x10";
    let mut input = prefix.to_vec();
    input.extend_from_slice(b"eae_prk");
    input.extend_from_slice(dh.raw_secret_bytes());
    let mut info = vec![0, 32];
    info.extend_from_slice(prefix);
    info.extend_from_slice(b"shared_secret");
    info.extend_from_slice(syncer.to_sec1_point(false).as_bytes());
    info.extend_from_slice(author.to_sec1_point(false).as_bytes());
    let mut output = [0; 32];
    hkdf::Hkdf::<Sha256>::new(Some(&[]), &input)
        .expand(&info, &mut output)
        .map_err(|_| bad())?;
    Ok(output)
}
impl MacRequest {
    pub fn header(&self) -> String {
        format!(
            "type=\"{REPO_MAC_TYPE}\", ver=1, key_share=\"{}\"",
            self.key_share
        )
    }
}
fn length_prefixed(out: &mut Vec<u8>, value: &str) -> Result<(), AppError> {
    let len: u16 = value.len().try_into().map_err(|_| bad())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
fn commit_context(commit: &Commit) -> Result<Vec<u8>, AppError> {
    if commit.ver != 1 || commit.data.len() != 32 {
        return Err(bad());
    }
    let mut out = b"atproto-space-repo-v1".to_vec();
    length_prefixed(&mut out, commit.space.as_str())?;
    length_prefixed(&mut out, commit.repo.as_str())?;
    length_prefixed(&mut out, commit.rev.as_str())?;
    out.extend_from_slice(commit.data.as_ref());
    Ok(out)
}
pub fn compute_commit_mac(secret: &[u8; 32], commit: &Commit) -> Result<[u8; 32], AppError> {
    let mut h = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| bad())?;
    h.update(&commit_context(commit)?);
    Ok(h.finalize().into_bytes().into())
}
/// Parse the profile's Structured Field dictionary, rejecting duplicates and ambiguous fields.
pub fn parse_mac_header(header: Option<&str>, expected_type: &str) -> Result<[u8; 32], AppError> {
    let mut fields = std::collections::HashMap::new();
    for member in header.ok_or_else(bad)?.split(',') {
        let (key, value) = member.trim().split_once('=').ok_or_else(bad)?;
        if fields.insert(key, value).is_some() {
            return Err(bad());
        }
    }
    if fields.get("type").copied() != Some(format!("\"{expected_type}\"").as_str())
        || fields.get("ver").copied() != Some("1")
    {
        return Err(bad());
    }
    let mac = fields
        .get("mac")
        .and_then(|x| x.strip_prefix(':'))
        .and_then(|x| x.strip_suffix(':'))
        .ok_or_else(bad)?;
    let bytes = STANDARD
        .decode(mac)
        .or_else(|_| STANDARD_NO_PAD.decode(mac))
        .map_err(|_| bad())?;
    bytes.try_into().map_err(|_| bad())
}
pub fn verify_commit(
    commit: &Commit,
    space: &str,
    repo: &str,
    secret: &[u8; 32],
    header: Option<&str>,
) -> Result<(), AppError> {
    if commit.space.as_str() != space || commit.repo.as_str() != repo {
        return Err(bad());
    }
    let expected = parse_mac_header(header, REPO_MAC_TYPE)?;
    let mut h = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| bad())?;
    h.update(&commit_context(commit)?);
    h.verify_slice(&expected).map_err(|_| bad())
}
pub fn verify_record(
    uri: &str,
    expected_uri: &str,
    cid: &cid::Cid,
    bytes: &[u8],
    secret: &[u8; 32],
    header: Option<&str>,
) -> Result<(), AppError> {
    if uri != expected_uri || crate::commit::create_cid_bytes_from_data(bytes).0 != cid.to_bytes() {
        return Err(bad());
    }
    let mut context = b"atproto-space-record-v1".to_vec();
    length_prefixed(&mut context, uri)?;
    context.extend_from_slice(&cid.to_bytes());
    let expected = parse_mac_header(header, RECORD_MAC_TYPE)?;
    let mut h = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| bad())?;
    h.update(&context);
    h.verify_slice(&expected).map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn rfc9180_a3_vector() {
        let syncer=PublicKey::from_sec1_bytes(&hex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")).unwrap();
        let secret = SecretKey::from_slice(&hex(
            "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
        ))
        .unwrap();
        assert_eq!(
            derive_secret(&secret, &syncer, &syncer, &secret.public_key())
                .unwrap()
                .as_slice(),
            hex("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8")
        );
    }
    #[test]
    fn fresh_request_keys() {
        let author = SecretKey::generate_from_rng(&mut rand::rng()).public_key();
        assert_ne!(encapsulate(&author).unwrap(), encapsulate(&author).unwrap());
    }
    #[test]
    fn strict_mac_headers() {
        let encoded = STANDARD.encode([7; 32]);
        let good = format!("type=\"{REPO_MAC_TYPE}\", ver=1, mac=:{encoded}:");
        assert_eq!(
            parse_mac_header(Some(&good), REPO_MAC_TYPE).unwrap(),
            [7; 32]
        );
        for bad_header in [
            None,
            Some("???"),
            Some("type=\"atproto-space-repo\", ver=2, mac=:AA==:"),
        ] {
            assert!(parse_mac_header(bad_header, REPO_MAC_TYPE).is_err());
        }
        assert!(parse_mac_header(Some(&format!("{good}, ver=1")), REPO_MAC_TYPE).is_err());
        assert!(parse_mac_header(Some(&good), RECORD_MAC_TYPE).is_err());
    }
    #[test]
    fn independent_hmac_vector_and_context_binding() {
        // Computed separately with Python hmac/hashlib, using the pinned upstream context layout.
        let secret: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mut commit = Commit {
            space: catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new_owned(
                "at://did:example:space/space/app.bsky.group/test",
            )
            .unwrap(),
            repo: "did:example:alice".to_owned().into(),
            rev: "3jzfcijpj2m2a".to_owned().into(),
            data: bytes::Bytes::from_static(&[1; 32]),
            ver: 1,
            extra_data: None,
        };
        let expected = hex("3333380eab95975393287dcc08df72534b8978188da161eab9059076b3f559c1");
        assert_eq!(
            compute_commit_mac(&secret, &commit).unwrap().as_slice(),
            expected
        );
        let header = format!(
            "type=\"{REPO_MAC_TYPE}\", ver=1, mac=:{}:",
            STANDARD.encode(&expected)
        );
        let space = commit.space.to_string();
        let repo = commit.repo.to_string();
        assert!(verify_commit(&commit, &space, &repo, &secret, Some(&header)).is_ok());
        assert!(verify_commit(&commit, &space, "did:example:bob", &secret, Some(&header)).is_err());
        assert!(verify_commit(
            &commit,
            "at://did:example:other/space/app.bsky.group/test",
            &repo,
            &secret,
            Some(&header)
        )
        .is_err());
        assert!(verify_commit(&commit, &space, &repo, &[4; 32], Some(&header)).is_err());
        commit.rev = "3jzfcijpj2m2b".to_owned().into();
        assert!(verify_commit(&commit, &space, &repo, &secret, Some(&header)).is_err());
        commit.rev = "3jzfcijpj2m2a".to_owned().into();
        commit.data = bytes::Bytes::from_static(&[2; 32]);
        assert!(verify_commit(&commit, &space, &repo, &secret, Some(&header)).is_err());
    }

    #[test]
    fn record_mac_binds_uri_cid_and_body() {
        let bytes = serde_ipld_dagcbor::to_vec(&serde_json::json!({"text":"private"})).unwrap();
        let cid: cid::Cid = crate::commit::create_cid_bytes_from_data(&bytes)
            .1
            .parse()
            .unwrap();
        let uri="at://did:example:space/space/app.bsky.group/test/did:example:alice/app.bsky.feed.post/self";
        let mut context = b"atproto-space-record-v1".to_vec();
        length_prefixed(&mut context, uri).unwrap();
        context.extend_from_slice(&cid.to_bytes());
        let mut h = Hmac::<Sha256>::new_from_slice(&[7; 32]).unwrap();
        h.update(&context);
        let header = format!(
            "type=\"{RECORD_MAC_TYPE}\", ver=1, mac=:{}:",
            STANDARD.encode(h.finalize().into_bytes())
        );
        assert!(verify_record(uri, uri, &cid, &bytes, &[7; 32], Some(&header)).is_ok());
        assert!(verify_record(uri, "wrong-uri", &cid, &bytes, &[7; 32], Some(&header)).is_err());
        assert!(verify_record(uri, uri, &cid, b"other bytes", &[7; 32], Some(&header)).is_err());
        assert!(verify_record(uri, uri, &cid, &bytes, &[8; 32], Some(&header)).is_err());
    }
    #[test]
    fn real_reference_plc_document_and_strict_kem_selection() {
        // Captured by GET from the running pinned atproto PLC test host, 2026-10-23.
        // The public DID document is fixture evidence; no account token or key is stored.
        let doc: DidDocument = serde_json::from_str(include_str!(
            "../tests/fixtures/reference-plc-ac0c9f1-did.json"
        ))
        .unwrap();
        let key = kem_key(&doc, &doc.id).expect("PLC raw P-256 verification suite is supported");
        let mut multikey = vec![0x80, 0x24];
        multikey.extend_from_slice(key.to_sec1_point(true).as_bytes());
        let mut modern = doc.clone();
        let vm = modern
            .verification_method
            .iter_mut()
            .find(|vm| vm.id.ends_with("#atproto_kem"))
            .unwrap();
        vm.r#type = "Multikey".into();
        vm.public_key_multibase = Some(multibase::encode(multibase::Base::Base58Btc, multikey));
        let key_vm = vm.clone();
        assert_eq!(kem_key(&modern, &doc.id).unwrap(), key);
        modern.verification_method.push(key_vm);
        assert!(
            kem_key(&modern, &doc.id).is_err(),
            "duplicate identity must be refused"
        );
        modern.verification_method.pop();
        modern
            .verification_method
            .iter_mut()
            .find(|vm| vm.id.ends_with("#atproto_kem"))
            .unwrap()
            .controller = "did:plc:other".into();
        assert!(
            kem_key(&modern, &doc.id).is_err(),
            "controller must own the key"
        );
        let mut wrong_curve = doc.clone();
        wrong_curve
            .verification_method
            .iter_mut()
            .find(|vm| vm.id.ends_with("#atproto_kem"))
            .unwrap()
            .r#type = "EcdsaSecp256k1VerificationKey2019".into();
        assert!(kem_key(&wrong_curve, &doc.id).is_err(), "KEM is only P-256");
        assert!(kem_key(&doc, "did:plc:other").is_err());
    }
}
