//! November 12 Spaces request authentication and RFC 9421 MAC verification,
//! delegated to `petrel_spaces` (`kem` + `mac_header`).
use crate::{
    auth::{parse_verification_key, DidDocument, ParsedVerifyingKey},
    error::{AppError, AuthReason},
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
pub use petrel_api::generated::com::atproto::space::defs::Commit;
pub use petrel_spaces::MacProfile;

/// Request header that asks a Space host for a MAC-authenticated response.
pub const ACCEPT_SIGNATURE_HEADER: &str = "accept-signature";
/// Response header (and RFC 9421 component) carrying a commit MAC's covered fields.
pub const COMMIT_MAC_PROFILE: &str = "atproto-space-commit";
/// Response header (and RFC 9421 component) carrying a record MAC's covered fields.
pub const RECORD_MAC_PROFILE: &str = "atproto-space-record";
const SIGNATURE_INPUT_HEADER: &str = "signature-input";
const SIGNATURE_HEADER: &str = "signature";

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

fn invalid_mac() -> AppError {
    AppError::Unauthorized(AuthReason::InvalidSpaceMac)
}

/// The `did:key` of a P-256 public key (compressed SEC1, multicodec `p256-pub`).
pub fn p256_did_key(key: &PublicKey) -> Result<String, AppError> {
    petrel_spaces::encode_p256_did_key(key.to_encoded_point(true).as_bytes())
        .map_err(|_| invalid_mac())
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
    let author_did_key = p256_did_key(author)?;
    let encap = petrel_spaces::encapsulate_p256(&author_did_key).map_err(|_| invalid_mac())?;
    Ok(MacRequest {
        key_share: encap.key_share.clone(),
        shared_secret: *encap.shared_secret,
        profile,
    })
}

/// HPKE base-mode secret export using DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
/// Export-only AEAD, `info = "atproto-mac"`, and an empty exporter context,
/// delegated to `petrel_spaces::kem`.
pub fn derive_secret(
    secret: &SecretKey,
    other: &PublicKey,
    syncer: &PublicKey,
    author: &PublicKey,
) -> Result<[u8; 32], AppError> {
    let own_pub = secret.public_key();
    let own_secret: zeroize::Zeroizing<[u8; 32]> =
        zeroize::Zeroizing::new(secret.to_bytes().into());
    if &own_pub == author && other == syncer {
        let syncer_did_key = p256_did_key(syncer)?;
        petrel_spaces::decapsulate_p256(&own_secret, &syncer_did_key)
            .map(|secret| *secret)
            .map_err(|_| invalid_mac())
    } else if &own_pub == syncer && other == author {
        let author_did_key = p256_did_key(author)?;
        petrel_spaces::encapsulate_p256_with_ephemeral(&author_did_key, &own_secret)
            .map(|e| *e.shared_secret)
            .map_err(|_| invalid_mac())
    } else {
        Err(invalid_mac())
    }
}

impl MacRequest {
    pub fn header(&self) -> String {
        petrel_spaces::format_accept_signature(self.profile, &self.key_share).unwrap_or_else(|_| {
            let profile = self.profile.as_str();
            format!(
                "mac=(\"{profile}\";sf);keyid=\"{}\";tag=\"{profile}\"",
                self.key_share
            )
        })
    }
}

/// The single value of a MAC response header. A repeated header is refused: a
/// host never sends two, and joining them would let an extra member slip in.
fn single_header<'h>(
    headers: &'h reqwest::header::HeaderMap,
    name: &str,
) -> Result<&'h str, AppError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or_else(invalid_mac)?;
    if values.next().is_some() {
        return Err(invalid_mac());
    }
    value.to_str().map_err(|_| invalid_mac())
}

/// The covered-fields, `Signature-Input` and `Signature` values of a MAC response.
fn mac_headers(
    headers: &reqwest::header::HeaderMap,
    profile: MacProfile,
) -> Result<(&str, &str, &str), AppError> {
    Ok((
        single_header(headers, profile.response_header())?,
        single_header(headers, SIGNATURE_INPUT_HEADER)?,
        single_header(headers, SIGNATURE_HEADER)?,
    ))
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
        || commit.space.as_str() != space
        || commit.repo.as_str() != repo
    {
        return Err(invalid_mac());
    }
    let data_32: [u8; 32] = commit
        .data
        .0
        .as_slice()
        .try_into()
        .map_err(|_| invalid_mac())?;
    let (covered, signature_input, signature) = mac_headers(headers, MacProfile::Commit)?;
    let verified = petrel_spaces::verify_commit_mac(
        &request.shared_secret,
        covered,
        signature_input,
        signature,
    )
    .map_err(|_| invalid_mac())?;
    if verified.keyid != request.key_share
        || verified.ver != 1
        || verified.space.as_str() != commit.space.as_str()
        || verified.repo.as_str() != commit.repo.as_str()
        || verified.rev.as_str() != commit.rev.as_str()
        || verified.data != data_32
    {
        return Err(invalid_mac());
    }
    Ok(())
}

pub fn verify_record(
    uri: &str,
    expected_uri: &str,
    cid: &petrel_core::Cid,
    bytes: &[u8],
    request: &MacRequest,
    headers: &reqwest::header::HeaderMap,
) -> Result<(), AppError> {
    if request.profile != MacProfile::Record || uri != expected_uri || !cid.matches_content(bytes) {
        return Err(invalid_mac());
    }
    let (covered, signature_input, signature) = mac_headers(headers, MacProfile::Record)?;
    let verified = petrel_spaces::verify_record_mac(
        &request.shared_secret,
        covered,
        signature_input,
        signature,
    )
    .map_err(|_| invalid_mac())?;
    if verified.keyid != request.key_share || verified.uri.as_str() != uri || &verified.cid != cid {
        return Err(invalid_mac());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use hmac::{Hmac, Mac};
    use p256::elliptic_curve::rand_core::OsRng;
    use reqwest::header::{HeaderMap, HeaderValue};
    use sha2::Sha256;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    /// A real P-256 `did:key`: petrel-spaces checks the MAC keyid parses as one.
    fn test_did_key() -> String {
        p256_did_key(&SecretKey::random(&mut OsRng).public_key()).unwrap()
    }

    fn commit() -> Commit {
        Commit {
            space: petrel_core::SpaceRef::parse("at:space/did:example:space/app.bsky.group/test")
                .unwrap(),
            repo: petrel_core::Did::parse("did:example:alice").unwrap(),
            rev: petrel_core::Tid::parse("3kbcq3p7ad4aa").unwrap(),
            data: petrel_core::Bytes(vec![1; 32]),
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
        let mut hmac = Hmac::<Sha256>::new_from_slice(&request.shared_secret).unwrap();
        hmac.update(
            format!("\"{profile}\";sf: {covered}\n\"@signature-params\": {params}").as_bytes(),
        );
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
            key_share: test_did_key(),
            shared_secret: std::array::from_fn(|i| i as u8),
            profile: MacProfile::Commit,
        };
        let covered = format!(
            "ver=1, repo=\"{}\", space=\"{}\", rev=\"{}\", data=:{}:",
            commit.repo,
            commit.space,
            commit.rev,
            STANDARD.encode(&commit.data.0)
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

        // Parameters may come in any order, and `alg` names the one algorithm.
        let params = format!(
            "(\"atproto-space-commit\";sf);tag=\"atproto-space-commit\";keyid=\"{}\";alg=\"hmac-sha256\"",
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

        // Wire pin: petrel-spaces refuses any parameter beyond keyid, tag and alg
        // (the previous verifier accepted `created`). Swan echoes only keyid and tag.
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
        .is_err());

        // A MAC with no keyid, or a keyid other than the request's key share, is refused.
        let params = "(\"atproto-space-commit\";sf);tag=\"atproto-space-commit\"";
        let headers = signed_headers(&request, &covered, "mac", Some(params));
        assert!(verify_commit(
            &commit,
            commit.space.as_str(),
            commit.repo.as_str(),
            &request,
            &headers
        )
        .is_err());
    }

    #[test]
    fn commit_profile_rejects_wrong_key_profile_body_and_duplicate_tag() {
        let commit = commit();
        let request = MacRequest {
            key_share: test_did_key(),
            shared_secret: [7; 32],
            profile: MacProfile::Commit,
        };
        let covered = format!(
            "ver=1, repo=\"{}\", space=\"{}\", rev=\"{}\", data=:{}:",
            commit.repo,
            commit.space,
            commit.rev,
            STANDARD.encode(&commit.data.0)
        );
        for params in [
            "(\"atproto-space-commit\";sf);keyid=\"did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169\";tag=\"atproto-space-commit\"",
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
        changed.rev = petrel_core::Tid::parse("3kbcq3p7ad4ab").unwrap();
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
        let bytes = crate::commit::encode_dagcbor(
            &crate::commit::json_to_ipld(&serde_json::json!({"text":"private"})).unwrap(),
        )
        .unwrap();
        let cid =
            petrel_core::Cid::parse(&crate::commit::create_cid_bytes_from_data(&bytes).1).unwrap();
        let uri = "at:space/did:example:space/app.bsky.group/test/did:example:alice/app.bsky.feed.post/self";
        let request = MacRequest {
            key_share: test_did_key(),
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
        use p256::elliptic_curve::sec1::ToEncodedPoint;
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
