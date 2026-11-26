//! November 12 Spaces request authentication and RFC 9421 MAC verification,
//! delegated to `atproto-spaces` (`kem` + `mac`).
use crate::{
    auth::{parse_verification_key, DidDocument, ParsedVerifyingKey},
    error::{AppError, AuthReason},
};
pub use atproto_spaces::mac::{
    MacProfile, ACCEPT_SIGNATURE_HEADER, COMMIT_MAC_PROFILE, RECORD_MAC_PROFILE,
};
pub use catbird_atproto::generated::com_atproto::space::Commit;
use p256::{PublicKey, SecretKey};

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
    let author_did_key = atproto_spaces::kem::encode_p256_did_key(author);
    let encap =
        atproto_spaces::kem::encapsulate_p256(&author_did_key).map_err(|_| invalid_mac())?;
    Ok(MacRequest {
        key_share: encap.key_share_did_key,
        shared_secret: encap.shared_secret,
        profile,
    })
}

/// HPKE base-mode secret export using DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
/// Export-only AEAD, `info = "atproto-mac"`, and an empty exporter context,
/// delegated to `atproto_spaces::kem`.
pub fn derive_secret(
    secret: &SecretKey,
    other: &PublicKey,
    syncer: &PublicKey,
    author: &PublicKey,
) -> Result<[u8; 32], AppError> {
    let own_pub = secret.public_key();
    if &own_pub == author && other == syncer {
        let syncer_did_key = atproto_spaces::kem::encode_p256_did_key(syncer);
        atproto_spaces::kem::decapsulate_p256(secret, &syncer_did_key).map_err(|_| invalid_mac())
    } else if &own_pub == syncer && other == author {
        let author_did_key = atproto_spaces::kem::encode_p256_did_key(author);
        atproto_spaces::kem::encapsulate_p256_deterministic(&author_did_key, secret)
            .map(|e| e.shared_secret)
            .map_err(|_| invalid_mac())
    } else {
        Err(invalid_mac())
    }
}

impl MacRequest {
    pub fn header(&self) -> String {
        atproto_spaces::mac::format_accept_signature(self.profile, &self.key_share).unwrap_or_else(
            |_| {
                let profile = self.profile.as_str();
                format!(
                    "mac=(\"{profile}\";sf);keyid=\"{}\";tag=\"{profile}\"",
                    self.key_share
                )
            },
        )
    }
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
    let data_32: &[u8; 32] = commit.data.as_ref().try_into().map_err(|_| invalid_mac())?;
    atproto_spaces::mac::verify_commit_mac(
        &request.shared_secret,
        &request.key_share,
        headers,
        commit.space.as_str(),
        commit.repo.as_str(),
        commit.rev.as_str(),
        data_32,
    )
    .map_err(|_| invalid_mac())
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
    let cid_str = cid.to_string();
    atproto_spaces::mac::verify_record_mac(
        &request.shared_secret,
        &request.key_share,
        headers,
        uri,
        &cid_str,
    )
    .map_err(|_| invalid_mac())
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

    fn commit() -> Commit {
        Commit {
            space: catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new_owned(
                "at:space/did:example:space/app.bsky.group/test",
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
        let uri = "at:space/did:example:space/app.bsky.group/test/did:example:alice/app.bsky.feed.post/self";
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
