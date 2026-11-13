//! November 12 Spaces response authentication: HPKE export and RFC 9421 HMAC signatures.

use std::borrow::Cow;

use crate::{
    auth::{parse_verification_key, DidDocument, ParsedVerifyingKey},
    error::{AppError, AuthReason},
};
pub use catbird_atproto::generated::com_atproto::space::Commit;
use hkdf::{Hkdf, HkdfExtract};
use hmac::{Hmac, Mac};
use p256::{
    elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint},
    PublicKey, SecretKey,
};
use sfv::{BareItem, Dictionary, FieldType, ListEntry, Parser, Version};
use sha2::Sha256;

pub const ACCEPT_SIGNATURE_HEADER: &str = "accept-signature";
pub const COMMIT_MAC_PROFILE: &str = "atproto-space-commit";
pub const RECORD_MAC_PROFILE: &str = "atproto-space-record";

const HPKE_VERSION: &[u8] = b"HPKE-v1";
const KEM_ID: &[u8] = b"KEM\x00\x10";
const SUITE_ID: &[u8] = b"HPKE\x00\x10\x00\x01\xff\xff";
const MODE_BASE: &[u8] = &[0x00];
const HPKE_INFO: &[u8] = b"atproto-mac";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacProfile {
    Commit,
    Record,
}

impl MacProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Commit => COMMIT_MAC_PROFILE,
            Self::Record => RECORD_MAC_PROFILE,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacRequest {
    pub key_share: String,
    pub shared_secret: [u8; 32],
    pub profile: MacProfile,
}

impl std::fmt::Debug for MacRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacRequest")
            .field("key_share", &self.key_share)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl MacRequest {
    pub fn header(&self) -> String {
        let profile = self.profile.as_str();
        format!(
            "mac=(\"{profile}\";sf);keyid=\"{}\";tag=\"{profile}\"",
            self.key_share
        )
    }
}

fn invalid_mac() -> AppError {
    AppError::Unauthorized(AuthReason::InvalidSpaceMac)
}

pub fn kem_key(doc: &DidDocument, did: &str) -> Result<PublicKey, AppError> {
    if doc.id != did {
        return Err(invalid_mac());
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
        return Err(invalid_mac());
    }
    match parse_verification_key(vm).map_err(AppError::Unauthorized)? {
        ParsedVerifyingKey::P256(key) => {
            PublicKey::from_sec1_bytes(key.to_encoded_point(false).as_bytes())
                .map_err(|_| invalid_mac())
        }
        _ => Err(invalid_mac()),
    }
}

pub fn encapsulate(author: &PublicKey, profile: MacProfile) -> Result<MacRequest, AppError> {
    let ephemeral = SecretKey::random(&mut OsRng);
    let public = ephemeral.public_key();
    let shared_secret = derive_secret(&ephemeral, author, &public, author)?;
    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(public.to_encoded_point(true).as_bytes());
    Ok(MacRequest {
        key_share: format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, multikey)
        ),
        shared_secret,
        profile,
    })
}

/// HPKE base-mode secret export using DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
/// Export-only AEAD, `info = "atproto-mac"`, and an empty exporter context.
pub fn derive_secret(
    secret: &SecretKey,
    other: &PublicKey,
    syncer: &PublicKey,
    author: &PublicKey,
) -> Result<[u8; 32], AppError> {
    let dh = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), other.as_affine());
    let enc = syncer.to_encoded_point(false);
    let author = author.to_encoded_point(false);

    let eae_prk = labeled_extract(KEM_ID, &[], b"eae_prk", &[dh.raw_secret_bytes()]);
    let mut kem_secret = [0; 32];
    labeled_expand(
        KEM_ID,
        &eae_prk,
        b"shared_secret",
        &[enc.as_bytes(), author.as_bytes()],
        &mut kem_secret,
    )?;

    let psk_id_hash = labeled_extract(SUITE_ID, &[], b"psk_id_hash", &[]);
    let info_hash = labeled_extract(SUITE_ID, &[], b"info_hash", &[HPKE_INFO]);
    let secret = labeled_extract(SUITE_ID, &kem_secret, b"secret", &[]);
    let mut exporter_secret = [0; 32];
    labeled_expand(
        SUITE_ID,
        &secret,
        b"exp",
        &[MODE_BASE, &psk_id_hash, &info_hash],
        &mut exporter_secret,
    )?;
    let mut shared_secret = [0; 32];
    labeled_expand(
        SUITE_ID,
        &exporter_secret,
        b"sec",
        &[],
        &mut shared_secret,
    )?;
    Ok(shared_secret)
}

fn labeled_extract(id: &[u8], salt: &[u8], label: &[u8], ikm: &[&[u8]]) -> [u8; 32] {
    let mut extract = HkdfExtract::<Sha256>::new(Some(salt));
    extract.input_ikm(HPKE_VERSION);
    extract.input_ikm(id);
    extract.input_ikm(label);
    for part in ikm {
        extract.input_ikm(part);
    }
    let (prk, _) = extract.finalize();
    prk.into()
}

fn labeled_expand(
    id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[&[u8]],
    output: &mut [u8],
) -> Result<(), AppError> {
    let length = u16::try_from(output.len())
        .map_err(|_| invalid_mac())?
        .to_be_bytes();
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| invalid_mac())?;
    let result = match info {
        [] => hkdf.expand_multi_info(&[&length, HPKE_VERSION, id, label], output),
        [a] => hkdf.expand_multi_info(&[&length, HPKE_VERSION, id, label, a], output),
        [a, b] => hkdf.expand_multi_info(&[&length, HPKE_VERSION, id, label, a, b], output),
        [a, b, c] => {
            hkdf.expand_multi_info(&[&length, HPKE_VERSION, id, label, a, b, c], output)
        }
        _ => return Err(invalid_mac()),
    };
    result.map_err(|_| invalid_mac())
}

fn combined_header<'a>(
    headers: &'a reqwest::header::HeaderMap,
    name: &str,
) -> Result<Cow<'a, str>, AppError> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .ok_or_else(invalid_mac)?
        .to_str()
        .map_err(|_| invalid_mac())?;
    let Some(second) = values.next() else {
        return Ok(Cow::Borrowed(first));
    };
    let second = second.to_str().map_err(|_| invalid_mac())?;
    let mut combined = String::with_capacity(first.len() + second.len() + 2);
    combined.push_str(first);
    combined.push_str(", ");
    combined.push_str(second);
    for value in values {
        combined.push_str(", ");
        combined.push_str(value.to_str().map_err(|_| invalid_mac())?);
    }
    Ok(Cow::Owned(combined))
}

fn parse_dictionary(value: &str) -> Result<Dictionary, AppError> {
    Parser::new(value)
        .with_version(Version::Rfc8941)
        .parse_dictionary()
        .map_err(|_| invalid_mac())
}

fn string_item(item: &BareItem) -> Option<&str> {
    match item {
        BareItem::String(value) => Some(value.as_str()),
        _ => None,
    }
}

fn bare_item<'a>(fields: &'a Dictionary, key: &str) -> Option<&'a BareItem> {
    match fields.get(key) {
        Some(ListEntry::Item(item)) => Some(&item.bare_item),
        _ => None,
    }
}

fn verify_mac(
    request: &MacRequest,
    headers: &reqwest::header::HeaderMap,
) -> Result<Dictionary, AppError> {
    let profile = request.profile.as_str();
    let input_value = combined_header(headers, "signature-input")?;
    let inputs = parse_dictionary(&input_value)?;
    let mut tagged = None;
    for (label, entry) in &inputs {
        let ListEntry::InnerList(inner) = entry else {
            continue;
        };
        if inner
            .params
            .get("tag")
            .and_then(string_item)
            .is_some_and(|tag| tag == profile)
        {
            if tagged.is_some() {
                return Err(invalid_mac());
            }
            tagged = Some((label, entry, inner));
        }
    }
    let (label, entry, inner) = tagged.ok_or_else(invalid_mac)?;
    if inner.items.len() != 1
        || string_item(&inner.items[0].bare_item) != Some(profile)
        || inner.items[0].params.len() != 1
        || !matches!(
            inner.items[0].params.get("sf"),
            Some(BareItem::Boolean(true))
        )
    {
        return Err(invalid_mac());
    }
    if let Some(alg) = inner.params.get("alg") {
        if string_item(alg) != Some("hmac-sha256") {
            return Err(invalid_mac());
        }
    }
    if let Some(key_id) = inner.params.get("keyid") {
        if string_item(key_id) != Some(request.key_share.as_str()) {
            return Err(invalid_mac());
        }
    }

    let signatures = parse_dictionary(&combined_header(headers, "signature")?)?;
    let signature = match signatures.get(label) {
        Some(ListEntry::Item(item)) if item.params.is_empty() => match &item.bare_item {
            BareItem::ByteSequence(value) => value.as_slice(),
            _ => return Err(invalid_mac()),
        },
        _ => return Err(invalid_mac()),
    };

    let mut serializer = sfv::ListSerializer::new();
    serializer.members(std::slice::from_ref(entry));
    let signature_params = serializer.finish().ok_or_else(invalid_mac)?;

    let covered_value = combined_header(headers, profile)?;
    let fields = parse_dictionary(&covered_value)?;
    let canonical = fields.serialize().ok_or_else(invalid_mac)?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(&request.shared_secret).map_err(|_| invalid_mac())?;
    hmac.update(b"\"");
    hmac.update(profile.as_bytes());
    hmac.update(b"\";sf: ");
    hmac.update(canonical.as_bytes());
    hmac.update(b"\n\"@signature-params\": ");
    hmac.update(signature_params.as_bytes());
    hmac.verify_slice(signature).map_err(|_| invalid_mac())?;
    Ok(fields)
}

pub fn verify_commit(
    commit: &Commit,
    space: &str,
    repo: &str,
    request: &MacRequest,
    headers: &reqwest::header::HeaderMap,
) -> Result<(), AppError> {
    if request.profile != MacProfile::Commit
        || commit.ver != 1
        || commit.data.len() != 32
        || commit.space.as_str() != space
        || commit.repo.as_str() != repo
    {
        return Err(invalid_mac());
    }
    let fields = verify_mac(request, headers)?;
    let matches = matches!(bare_item(&fields, "ver"), Some(BareItem::Integer(value)) if i64::from(*value) == commit.ver)
        && string_item(bare_item(&fields, "repo").ok_or_else(invalid_mac)?) == Some(commit.repo.as_str())
        && string_item(bare_item(&fields, "space").ok_or_else(invalid_mac)?) == Some(commit.space.as_str())
        && string_item(bare_item(&fields, "rev").ok_or_else(invalid_mac)?) == Some(commit.rev.as_str())
        && matches!(bare_item(&fields, "data"), Some(BareItem::ByteSequence(value)) if value.as_slice() == commit.data.as_ref());
    if matches {
        Ok(())
    } else {
        Err(invalid_mac())
    }
}

pub fn verify_record(
    uri: &str,
    expected_uri: &str,
    cid: &cid::Cid,
    bytes: &[u8],
    request: &MacRequest,
    headers: &reqwest::header::HeaderMap,
) -> Result<(), AppError> {
    if request.profile != MacProfile::Record
        || uri != expected_uri
        || crate::commit::create_cid_bytes_from_data(bytes).0 != cid.to_bytes()
    {
        return Err(invalid_mac());
    }
    let fields = verify_mac(request, headers)?;
    let cid = cid.to_string();
    if string_item(bare_item(&fields, "uri").ok_or_else(invalid_mac)?) == Some(uri)
        && string_item(bare_item(&fields, "cid").ok_or_else(invalid_mac)?) == Some(cid.as_str())
    {
        Ok(())
    } else {
        Err(invalid_mac())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use reqwest::header::{HeaderMap, HeaderValue};

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn commit() -> Commit {
        Commit {
            space: catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new_owned(
                "at://did:example:space/space/app.bsky.group/test",
            )
            .unwrap(),
            repo: "did:example:alice".to_owned().into(),
            rev: "3kbcq3p7ad4aa".to_owned().into(),
            data: bytes::Bytes::from_static(&[1; 32]),
            ver: 1,
            extra_data: None,
        }
    }

    fn signed_headers(
        request: &MacRequest,
        covered: &str,
        label: &str,
        params: Option<&str>,
    ) -> HeaderMap {
        let profile = request.profile.as_str();
        let default_params = format!(
            "(\"{profile}\";sf);keyid=\"{}\";tag=\"{profile}\"",
            request.key_share
        );
        let params = params.unwrap_or(&default_params);
        let canonical = parse_dictionary(covered).unwrap().serialize().unwrap();
        let mut hmac = Hmac::<Sha256>::new_from_slice(&request.shared_secret).unwrap();
        hmac.update(format!("\"{profile}\";sf: {canonical}\n\"@signature-params\": {params}").as_bytes());
        let signature = STANDARD.encode(hmac.finalize().into_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(profile, HeaderValue::from_str(covered).unwrap());
        headers.insert(
            "signature-input",
            HeaderValue::from_str(&format!("{label}={params}")).unwrap(),
        );
        headers.insert(
            "signature",
            HeaderValue::from_str(&format!("{label}=:{signature}:")).unwrap(),
        );
        headers
    }

    #[test]
    fn matches_hpke_export_only_p256_vector() {
        let enc = PublicKey::from_sec1_bytes(&hex(
            "04d804370b7e24b94749eb1dc8df6d4d4a5d75f9effad01739ebcad5c54a40d57aaa8b4190fc124dbde2e4f1e1d1b012a3bc4038157dc29b55533a932306d8d38d",
        ))
        .unwrap();
        let author = SecretKey::from_slice(&hex(
            "62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346",
        ))
        .unwrap();
        assert_eq!(
            derive_secret(&author, &enc, &enc, &author.public_key())
                .unwrap()
                .as_slice(),
            hex("2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d")
        );
    }

    #[test]
    fn fresh_profiled_requests() {
        let author = SecretKey::random(&mut OsRng).public_key();
        let commit = encapsulate(&author, MacProfile::Commit).unwrap();
        let other = encapsulate(&author, MacProfile::Commit).unwrap();
        assert_ne!(commit, other);
        assert_eq!(
            commit.header(),
            format!(
                "mac=(\"atproto-space-commit\";sf);keyid=\"{}\";tag=\"atproto-space-commit\"",
                commit.key_share
            )
        );
        assert!(encapsulate(&author, MacProfile::Record)
            .unwrap()
            .header()
            .contains("atproto-space-record"));
    }

    #[test]
    fn commit_profile_verifies_rfc9421_and_structured_field_canonicalization() {
        let commit = commit();
        let request = MacRequest {
            key_share: "did:key:zDnaExample".into(),
            shared_secret: std::array::from_fn(|i| i as u8),
            profile: MacProfile::Commit,
        };
        let covered = format!(
            "ver=1, repo=\"{}\", space=\"{}\", rev=\"{}\", data=:{}:",
            commit.repo,
            commit.space,
            commit.rev,
            STANDARD.encode(&commit.data)
        );
        let mut headers = signed_headers(&request, &covered, "other", None);
        headers.insert(
            COMMIT_MAC_PROFILE,
            HeaderValue::from_str(&covered.replace(", ", ",   ")).unwrap(),
        );
        assert!(verify_commit(
            &commit,
            commit.space.as_str(),
            commit.repo.as_str(),
            &request,
            &headers
        )
        .is_ok());

        let params = format!(
            "(\"atproto-space-commit\";sf);tag=\"atproto-space-commit\";created=1700000000;keyid=\"{}\";alg=\"hmac-sha256\"",
            request.key_share
        );
        let headers = signed_headers(&request, &covered, "mac", Some(&params));
        assert!(verify_commit(
            &commit,
            commit.space.as_str(),
            commit.repo.as_str(),
            &request,
            &headers
        )
        .is_ok());
    }

    #[test]
    fn commit_profile_rejects_wrong_key_profile_body_and_duplicate_tag() {
        let commit = commit();
        let request = MacRequest {
            key_share: "did:key:zDnaExample".into(),
            shared_secret: [7; 32],
            profile: MacProfile::Commit,
        };
        let covered = format!(
            "ver=1, repo=\"{}\", space=\"{}\", rev=\"{}\", data=:{}:",
            commit.repo,
            commit.space,
            commit.rev,
            STANDARD.encode(&commit.data)
        );
        for params in [
            "(\"atproto-space-commit\";sf);keyid=\"did:key:other\";tag=\"atproto-space-commit\"",
            "(\"atproto-space-commit\";sf);tag=\"atproto-space-commit\";alg=\"hmac-sha512\"",
            "(\"atproto-space-commit\");tag=\"atproto-space-commit\"",
        ] {
            assert!(verify_commit(
                &commit,
                commit.space.as_str(),
                commit.repo.as_str(),
                &request,
                &signed_headers(&request, &covered, "mac", Some(params))
            )
            .is_err());
        }

        let mut changed = commit.clone();
        changed.rev = "3kbcq3p7ad4ab".to_owned().into();
        let headers = signed_headers(&request, &covered, "mac", None);
        assert!(verify_commit(
            &changed,
            changed.space.as_str(),
            changed.repo.as_str(),
            &request,
            &headers
        )
        .is_err());

        let duplicate = headers.get("signature-input").unwrap().to_str().unwrap();
        let mut headers = headers.clone();
        headers.append(
            "signature-input",
            HeaderValue::from_str(&duplicate.replace("mac=", "other=")).unwrap(),
        );
        assert!(verify_commit(
            &commit,
            commit.space.as_str(),
            commit.repo.as_str(),
            &request,
            &headers
        )
        .is_err());

        let record_request = MacRequest {
            profile: MacProfile::Record,
            ..request
        };
        assert!(verify_commit(
            &commit,
            commit.space.as_str(),
            commit.repo.as_str(),
            &record_request,
            &headers
        )
        .is_err());
    }

    #[test]
    fn record_profile_binds_uri_cid_and_body() {
        let bytes = serde_ipld_dagcbor::to_vec(&serde_json::json!({"text":"private"})).unwrap();
        let cid: cid::Cid = crate::commit::create_cid_bytes_from_data(&bytes)
            .1
            .parse()
            .unwrap();
        let uri = "at://did:example:space/space/app.bsky.group/test/did:example:alice/app.bsky.feed.post/self";
        let request = MacRequest {
            key_share: "did:key:zDnaRecord".into(),
            shared_secret: [9; 32],
            profile: MacProfile::Record,
        };
        let covered = format!("uri=\"{uri}\", cid=\"{cid}\"");
        let headers = signed_headers(&request, &covered, "record", None);
        assert!(verify_record(uri, uri, &cid, &bytes, &request, &headers).is_ok());
        assert!(verify_record(uri, "wrong", &cid, &bytes, &request, &headers).is_err());
        assert!(verify_record(uri, uri, &cid, b"other", &request, &headers).is_err());

        let mut wrong = request.clone();
        wrong.shared_secret = [8; 32];
        assert!(verify_record(uri, uri, &cid, &bytes, &wrong, &headers).is_err());
    }

    #[test]
    fn real_reference_plc_document_and_strict_kem_selection() {
        let doc: DidDocument = serde_json::from_str(include_str!(
            "../tests/fixtures/reference-plc-ac0c9f1-did.json"
        ))
        .unwrap();
        let key = kem_key(&doc, &doc.id).expect("PLC raw P-256 verification suite is supported");
        let mut multikey = vec![0x80, 0x24];
        multikey.extend_from_slice(key.to_encoded_point(true).as_bytes());
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
        assert!(kem_key(&modern, &doc.id).is_err());
        modern.verification_method.pop();
        modern
            .verification_method
            .iter_mut()
            .find(|vm| vm.id.ends_with("#atproto_kem"))
            .unwrap()
            .controller = "did:plc:other".into();
        assert!(kem_key(&modern, &doc.id).is_err());
    }
}
