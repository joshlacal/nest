//! atproto Spaces HTTP message signatures (RFC 9421), October 22, 2026 alpha.
//!
//! These replace the Spaces DPoP binding (atproto#5569). Ordinary AT Protocol
//! OAuth DPoP in [`crate::oauth`] is a separate mechanism and is unchanged.
//!
//! A credential client holds one fresh P-256 key per space credential:
//!
//! - The body-only exchange sends `credentialKid`; the authority binds the
//!   issued credential to that key as `cnf.kid`. No HTTP signature is sent.
//!   See [`crate::space_client::SpaceCredentialRequest`].
//! - Every use of the credential signs `authorization` and
//!   `atproto-space-audience`, in that order, with the same key. The audience is
//!   the repo owner's DID for repo reads and the space authority's bare DID for
//!   space-host operations.
//!
//! Mirrors `packages/space/src/http-signature.ts` at atproto 5d88b414a98de1ada22c94c78fa0667a7028163c.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// The signature label in `Signature-Input` and `Signature`.
pub const SIGNATURE_LABEL: &str = "atproto-space-credential";
/// Header naming the DID a space credential is being presented to.
pub const AUDIENCE_HEADER: &str = "atproto-space-audience";
/// Authorization scheme for a space credential.
pub const CREDENTIAL_AUTH_SCHEME: &str = "Atproto-Space-Credential";

/// Multicodec `p256-pub` (0x1200) as an unsigned varint.
const P256_PUB_MULTICODEC: [u8; 2] = [0x80, 0x24];

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
                HeaderName::from_static(crate::space_mac::WANT_MAC_HEADER),
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
                // Let reqwest report the invalid value when the request is sent.
                Err(_) => return request.header(name, value),
            }
        }
        // `headers` replaces existing values; `header` would append another.
        request.headers(headers)
    }

    /// The `keyid` parameter of the signature, when one was supplied.
    pub fn key_id(&self) -> Option<&str> {
        let (_, rest) = self.signature_input.split_once(";keyid=\"")?;
        rest.split_once('"').map(|(key_id, _)| key_id)
    }
}

/// The `did:key` form of a P-256 public key: multicodec `p256-pub`, compressed
/// SEC1 point, base58btc multibase.
pub fn p256_did_key(key: &VerifyingKey) -> String {
    let point = key.to_encoded_point(true);
    let mut bytes = Vec::with_capacity(P256_PUB_MULTICODEC.len() + point.len());
    bytes.extend_from_slice(&P256_PUB_MULTICODEC);
    bytes.extend_from_slice(point.as_bytes());
    format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, bytes)
    )
}

/// Headers for a request authenticated with a space credential, addressed to
/// `audience`.
pub fn credential_headers(key: &SigningKey, credential: &str, audience: &str) -> SpaceAuthHeaders {
    sign(
        key,
        format!("{CREDENTIAL_AUTH_SCHEME} {credential}"),
        Some(audience.to_string()),
        CREDENTIAL_COMPONENTS.to_string(),
    )
}

/// The RFC 9421 signature base: one line per covered component, then the
/// `@signature-params` line, joined by LF with no trailing LF.
pub fn signature_base(
    authorization: &str,
    audience: Option<&str>,
    signature_params: &str,
) -> String {
    let mut lines = vec![format!("\"authorization\": {}", authorization)];
    if let Some(audience) = audience {
        lines.push(format!("\"{AUDIENCE_HEADER}\": {}", audience));
    }
    lines.push(format!("\"@signature-params\": {signature_params}"));
    lines.join("\n")
}

fn sign(
    key: &SigningKey,
    authorization: String,
    audience: Option<String>,
    signature_params: String,
) -> SpaceAuthHeaders {
    let base = signature_base(&authorization, audience.as_deref(), &signature_params);
    let signature: Signature = key.sign(base.as_bytes());
    // Verifiers accept either S; emit low-S as the reference signer does.
    let signature = signature.normalize_s().unwrap_or(signature);
    SpaceAuthHeaders {
        mac: None,
        authorization,
        audience,
        signature_input: format!("{SIGNATURE_LABEL}={signature_params}"),
        signature: format!(
            "{SIGNATURE_LABEL}=:{}:",
            STANDARD.encode(signature.to_bytes())
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::elliptic_curve::rand_core::OsRng;

    /// Parse a P-256 `did:key` (the verifier's side of [`p256_did_key`]).
    /// `None` for any other key type or malformed input.
    fn parse_p256_did_key(did_key: &str) -> Option<VerifyingKey> {
        let multibase_key = did_key.strip_prefix("did:key:")?;
        let (base, bytes) = multibase::decode(multibase_key).ok()?;
        if base != multibase::Base::Base58Btc {
            return None;
        }
        let point = bytes.strip_prefix(&P256_PUB_MULTICODEC[..])?;
        VerifyingKey::from_sec1_bytes(point).ok()
    }

    fn signature_bytes(headers: &SpaceAuthHeaders) -> Vec<u8> {
        let encoded = headers
            .signature
            .strip_prefix("atproto-space-credential=:")
            .and_then(|s| s.strip_suffix(':'))
            .expect("byte-sequence signature field");
        STANDARD.decode(encoded).expect("standard base64")
    }

    fn params(headers: &SpaceAuthHeaders) -> &str {
        headers
            .signature_input
            .strip_prefix("atproto-space-credential=")
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

    /// The guide's minimal credential example, byte for byte.
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
            r#"atproto-space-credential=("authorization" "atproto-space-audience");tag="atproto-space-credential""#
        );
        assert!(headers.signature.starts_with("atproto-space-credential=:"));
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

    /// `apply` replaces auth headers already on the request instead of adding
    /// a second field.
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
                    .header("signature", "atproto-space-credential=:c3RhbGU=:"),
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
            vec!["Atproto-Space-Credential cred"]
        );
        assert_eq!(values(AUDIENCE_HEADER), vec!["did:plc:aud"]);
        assert_eq!(
            values("signature-input"),
            vec![headers.signature_input.as_str()]
        );
        assert_eq!(values("signature"), vec![headers.signature.as_str()]);
    }

    /// A published P-256 did:key vector (w3c-ccg did-method-key test vectors).
    #[test]
    fn parses_a_known_p256_did_key_vector() {
        let did_key = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
        let parsed = parse_p256_did_key(did_key).expect("valid P-256 did:key");
        assert_eq!(p256_did_key(&parsed), did_key);
    }

    #[test]
    fn rejects_non_p256_did_keys() {
        // secp256k1 (0xe7) did:key from the atproto docs.
        assert!(
            parse_p256_did_key("did:key:zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF")
                .is_none()
        );
        assert!(parse_p256_did_key("did:plc:abc").is_none());
        assert!(parse_p256_did_key("did:key:not-multibase").is_none());
    }
}
