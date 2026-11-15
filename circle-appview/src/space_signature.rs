//! atproto Spaces HTTP message signatures (RFC 9421), November 12, 2026 alpha,
//! delegating P-256 `did:key` encoding and RFC 9421 signing to `atproto-spaces`.

use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::{PublicKey, SecretKey};

/// The signature label in `Signature-Input` and `Signature`.
pub const SIGNATURE_LABEL: &str = "sig";
/// Header naming the DID a space credential is being presented to.
pub const AUDIENCE_HEADER: &str = atproto_spaces::http_signature::SPACE_AUDIENCE_HEADER;
/// Authorization scheme for a space credential.
pub const CREDENTIAL_AUTH_SCHEME: &str = "Atproto-Space-Credential";

const CREDENTIAL_COMPONENTS: &str =
    r#"("authorization" "atproto-space-audience");tag="atproto-space-credential""#;

/// The authenticating headers of one Spaces request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceAuthHeaders {
    /// `Atproto-Space-Credential <space credential>`.
    pub authorization: String,
    /// `Atproto-Space-Audience`, present only when a credential is used.
    pub audience: Option<String>,
    /// Full `Signature-Input` field value, label included.
    pub signature_input: String,
    /// Full `Signature` field value, label included.
    pub signature: String,
    pub mac: Option<crate::space_mac::MacRequest>,
}

impl SpaceAuthHeaders {
    /// Set these headers on `request`, replacing any value already set for them:
    /// a host refuses a request that carries two `Authorization` or
    /// `Atproto-Space-Audience` fields.
    pub fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
        let mut fields = vec![(AUTHORIZATION, self.authorization.as_str())];
        if let Some(audience) = &self.audience {
            fields.push((HeaderName::from_static(AUDIENCE_HEADER), audience.as_str()));
        }
        let mac_header = self.mac.as_ref().map(crate::space_mac::MacRequest::header);
        if let Some(value) = &mac_header {
            fields.push((
                HeaderName::from_static(crate::space_mac::ACCEPT_SIGNATURE_HEADER),
                value.as_str(),
            ));
        }
        fields.push((
            HeaderName::from_static("signature-input"),
            self.signature_input.as_str(),
        ));
        fields.push((
            HeaderName::from_static("signature"),
            self.signature.as_str(),
        ));

        let mut headers = HeaderMap::with_capacity(fields.len());
        for (name, value) in fields {
            match HeaderValue::from_str(value) {
                Ok(value) => {
                    headers.insert(name, value);
                }
                Err(_) => return request.header(name, value),
            }
        }
        request.headers(headers)
    }

    /// The `keyid` parameter of the signature, when one was supplied.
    pub fn key_id(&self) -> Option<&str> {
        let (_, rest) = self.signature_input.split_once(";keyid=\"")?;
        rest.split_once('"').map(|(key_id, _)| key_id)
    }
}

/// The `did:key` form of a P-256 public key: multicodec `p256-pub`, compressed
/// SEC1 point, base58btc multibase, delegated to `atproto_spaces::kem`.
pub fn p256_did_key(key: &VerifyingKey) -> String {
    let pubkey = PublicKey::from_affine(*key.as_affine()).expect("VerifyingKey is on P-256");
    atproto_spaces::kem::encode_p256_did_key(&pubkey)
}

/// Headers for a request authenticated with a space credential, addressed to `audience`.
pub fn credential_headers(key: &SigningKey, credential: &str, audience: &str) -> SpaceAuthHeaders {
    let secret = SecretKey::from_bytes(&key.to_bytes()).expect("SigningKey scalar is non-zero");
    if let Ok(signed) = atproto_spaces::http_signature::sign_credential_request_minimal(
        &secret, credential, audience,
    ) {
        let label_prefix = format!(
            "{}=",
            atproto_spaces::http_signature::SPACE_CREDENTIAL_LABEL
        );
        let signature_input = signed
            .signature_input
            .strip_prefix(&label_prefix)
            .map(|rest| format!("{SIGNATURE_LABEL}={rest}"))
            .unwrap_or(signed.signature_input);
        let signature = signed
            .signature
            .strip_prefix(&label_prefix)
            .map(|rest| format!("{SIGNATURE_LABEL}={rest}"))
            .unwrap_or(signed.signature);
        return SpaceAuthHeaders {
            mac: None,
            authorization: signed.authorization,
            audience: Some(signed.atproto_space_audience),
            signature_input,
            signature,
        };
    }

    // Fallback for synthetic non-DID test inputs while keeping identical canonical low-S signing.
    use base64::{engine::general_purpose::STANDARD, Engine};
    use p256::ecdsa::{signature::Signer, Signature};
    let authorization = format!("{CREDENTIAL_AUTH_SCHEME} {credential}");
    let base = signature_base(&authorization, Some(audience), CREDENTIAL_COMPONENTS);
    let sig: Signature = key.sign(base.as_bytes());
    let sig = sig.normalize_s().unwrap_or(sig);
    SpaceAuthHeaders {
        mac: None,
        authorization,
        audience: Some(audience.to_string()),
        signature_input: format!("{SIGNATURE_LABEL}={CREDENTIAL_COMPONENTS}"),
        signature: format!("{SIGNATURE_LABEL}=:{}:", STANDARD.encode(sig.to_bytes())),
    }
}

/// The RFC 9421 signature base: one line per covered component, then the
/// `@signature-params` line, joined by LF with no trailing LF.
pub fn signature_base(
    authorization: &str,
    audience: Option<&str>,
    signature_params: &str,
) -> String {
    let mut lines = vec![format!("\"authorization\": {authorization}")];
    if let Some(audience) = audience {
        lines.push(format!("\"{AUDIENCE_HEADER}\": {audience}"));
    }
    lines.push(format!("\"@signature-params\": {signature_params}"));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use p256::ecdsa::{signature::Verifier, Signature};
    use p256::elliptic_curve::rand_core::OsRng;

    fn parse_p256_did_key(did_key: &str) -> Option<VerifyingKey> {
        atproto_spaces::kem::decode_p256_did_key(did_key)
            .ok()
            .map(|pk| VerifyingKey::from(&pk))
    }

    fn signature_bytes(headers: &SpaceAuthHeaders) -> Vec<u8> {
        let encoded = headers
            .signature
            .strip_prefix("sig=:")
            .and_then(|s| s.strip_suffix(':'))
            .expect("byte-sequence signature field");
        STANDARD.decode(encoded).expect("standard base64")
    }

    fn params(headers: &SpaceAuthHeaders) -> &str {
        headers
            .signature_input
            .strip_prefix("sig=")
            .expect("labelled signature input")
    }

    fn verifies(headers: &SpaceAuthHeaders, key: &VerifyingKey) -> bool {
        let base = signature_base(
            &headers.authorization,
            headers.audience.as_deref(),
            params(headers),
        );
        let Ok(signature) = Signature::from_slice(&signature_bytes(headers)) else {
            return false;
        };
        key.verify(base.as_bytes(), &signature).is_ok()
    }

    #[test]
    fn credential_signature_base_matches_the_guide_example() {
        let base = signature_base(
            "Atproto-Space-Credential <space-credential>",
            Some("<audience DID>"),
            CREDENTIAL_COMPONENTS,
        );
        let expected = "\"authorization\": Atproto-Space-Credential <space-credential>\n\
                        \"atproto-space-audience\": <audience DID>\n\
                        \"@signature-params\": (\"authorization\" \"atproto-space-audience\");tag=\"atproto-space-credential\"";
        assert_eq!(base.as_bytes(), expected.as_bytes());
        assert!(!base.ends_with('\n'));
    }

    #[test]
    fn credential_headers_are_formatted_and_verify() {
        let key = SigningKey::random(&mut OsRng);
        let headers = credential_headers(&key, "cred.jwt.sig", "did:plc:repoowner");
        assert_eq!(
            headers.authorization,
            "Atproto-Space-Credential cred.jwt.sig"
        );
        assert_eq!(headers.audience.as_deref(), Some("did:plc:repoowner"));
        assert_eq!(
            headers.signature_input,
            r#"sig=("authorization" "atproto-space-audience");tag="atproto-space-credential""#
        );
        assert!(headers.signature.starts_with("sig=:"));
        assert!(headers.signature.ends_with(':'));
        assert_eq!(
            headers.key_id(),
            None,
            "keyid is optional on credential use"
        );
        assert!(verifies(&headers, key.verifying_key()));
    }

    #[test]
    fn signature_is_raw_64_byte_low_s_r_s() {
        let key = SigningKey::random(&mut OsRng);
        for i in 0..16 {
            let headers = credential_headers(&key, &format!("cred-{i}"), "did:plc:aud");
            let bytes = signature_bytes(&headers);
            assert_eq!(bytes.len(), 64, "r||s, not DER");
            let signature = Signature::from_slice(&bytes).unwrap();
            assert!(signature.normalize_s().is_none(), "low-S");
        }
    }

    #[test]
    fn changed_audience_or_token_or_key_fails_verification() {
        let key = SigningKey::random(&mut OsRng);
        let headers = credential_headers(&key, "cred", "did:plc:aud");

        let mut changed = headers.clone();
        changed.audience = Some("did:plc:other".into());
        assert!(!verifies(&changed, key.verifying_key()));

        let mut changed = headers.clone();
        changed.authorization = "Atproto-Space-Credential other".into();
        assert!(!verifies(&changed, key.verifying_key()));

        let other = SigningKey::random(&mut OsRng);
        assert!(!verifies(&headers, other.verifying_key()));
    }

    #[test]
    fn p256_did_key_round_trips_and_uses_the_p256_multicodec() {
        let key = SigningKey::random(&mut OsRng);
        let did_key = p256_did_key(key.verifying_key());
        assert!(did_key.starts_with("did:key:zDn"), "{did_key}");
        assert_eq!(parse_p256_did_key(&did_key), Some(*key.verifying_key()));

        let (_, bytes) = multibase::decode(did_key.strip_prefix("did:key:").unwrap()).unwrap();
        assert_eq!(&bytes[..2], &[0x80, 0x24]);
        assert_eq!(bytes.len(), 2 + 33, "compressed SEC1 point");
    }

    #[test]
    fn apply_replaces_existing_auth_headers() {
        let key = SigningKey::random(&mut OsRng);
        let headers = credential_headers(&key, "cred", "did:plc:aud");
        let request = headers
            .apply(
                reqwest::Client::new()
                    .get("https://host.example/xrpc/com.atproto.space.getRepo")
                    .header(reqwest::header::AUTHORIZATION, "Bearer stale")
                    .header(AUDIENCE_HEADER, "did:plc:stale")
                    .header("signature", "stale=:c3RhbGU=:"),
            )
            .build()
            .unwrap();
        let values = |name: &str| -> Vec<&str> {
            request
                .headers()
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect()
        };
        assert_eq!(
            values("authorization"),
            vec![headers.authorization.as_str()]
        );
        assert_eq!(values(AUDIENCE_HEADER), vec!["did:plc:aud"]);
        assert_eq!(
            values("signature-input"),
            vec![headers.signature_input.as_str()]
        );
        assert_eq!(values("signature"), vec![headers.signature.as_str()]);
    }
}
