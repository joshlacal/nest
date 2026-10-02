//! atproto Spaces HTTP message signatures (RFC 9421), October 1, 2026 alpha.
//!
//! These replace the Spaces DPoP binding (atproto#5569). Ordinary AT Protocol
//! OAuth DPoP in [`crate::oauth`] is a separate mechanism and is unchanged.
//!
//! A credential client holds one fresh P-256 key per space credential:
//!
//! - The exchange (`com.atproto.space.getSpaceCredential`) signs only
//!   `authorization` and names the key as a `did:key` in `keyid`. The authority
//!   binds the issued credential to that key as `cnf.kid`.
//! - Every use of the credential signs `authorization` and
//!   `atproto-space-audience`, in that order, with the same key. The audience is
//!   the repo owner's DID for repo reads and the space authority's bare DID for
//!   space-host operations.
//!
//! Mirrors `packages/space/src/http-signature.ts` at atproto 679724ad.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// The signature label in `Signature-Input` and `Signature`.
pub const SIGNATURE_LABEL: &str = "atproto-space";
/// Header naming the DID a space credential is being presented to.
pub const AUDIENCE_HEADER: &str = "atproto-space-audience";
/// Authorization scheme for a space credential.
pub const CREDENTIAL_AUTH_SCHEME: &str = "Atproto-Space";

/// Multicodec `p256-pub` (0x1200) as an unsigned varint.
const P256_PUB_MULTICODEC: [u8; 2] = [0x80, 0x24];

const EXCHANGE_COMPONENTS: &str = r#"("authorization")"#;
const CREDENTIAL_COMPONENTS: &str = r#"("authorization" "atproto-space-audience")"#;

/// The authenticating headers of one Spaces request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceAuthHeaders {
    /// `Bearer <delegation token>` or `Atproto-Space <space credential>`.
    pub authorization: String,
    /// `Atproto-Space-Audience`, present only when a credential is used.
    pub audience: Option<String>,
    /// Full `Signature-Input` field value, label included.
    pub signature_input: String,
    /// Full `Signature` field value, label included.
    pub signature: String,
}

impl SpaceAuthHeaders {
    /// Set these headers on `request`, replacing any earlier value.
    pub fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut request = request.header(reqwest::header::AUTHORIZATION, &self.authorization);
        if let Some(audience) = &self.audience {
            request = request.header(AUDIENCE_HEADER, audience);
        }
        request
            .header("signature-input", &self.signature_input)
            .header("signature", &self.signature)
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

/// Parse a P-256 `did:key`. `None` for any other key type or malformed input.
pub fn parse_p256_did_key(did_key: &str) -> Option<VerifyingKey> {
    let multibase_key = did_key.strip_prefix("did:key:")?;
    let (base, bytes) = multibase::decode(multibase_key).ok()?;
    if base != multibase::Base::Base58Btc {
        return None;
    }
    let point = bytes.strip_prefix(&P256_PUB_MULTICODEC[..])?;
    VerifyingKey::from_sec1_bytes(point).ok()
}

/// Headers for `com.atproto.space.getSpaceCredential`: the delegation token,
/// signed with the key the credential will be bound to.
pub fn exchange_headers(key: &SigningKey, delegation_token: &str) -> SpaceAuthHeaders {
    let key_id = p256_did_key(key.verifying_key());
    let params = format!("{EXCHANGE_COMPONENTS};keyid={}", sf_string(&key_id));
    sign(key, format!("Bearer {delegation_token}"), None, params)
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
    let mut lines = vec![format!("\"authorization\": {}", authorization.trim())];
    if let Some(audience) = audience {
        lines.push(format!("\"{AUDIENCE_HEADER}\": {}", audience.trim()));
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
        authorization,
        audience,
        signature_input: format!("{SIGNATURE_LABEL}={signature_params}"),
        signature: format!(
            "{SIGNATURE_LABEL}=:{}:",
            STANDARD.encode(signature.to_bytes())
        ),
    }
}

/// RFC 8941 sf-string serialization.
fn sf_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::elliptic_curve::rand_core::OsRng;

    fn signature_bytes(headers: &SpaceAuthHeaders) -> Vec<u8> {
        let encoded = headers
            .signature
            .strip_prefix("atproto-space=:")
            .and_then(|s| s.strip_suffix(':'))
            .expect("byte-sequence signature field");
        STANDARD.decode(encoded).expect("standard base64")
    }

    fn params(headers: &SpaceAuthHeaders) -> &str {
        headers
            .signature_input
            .strip_prefix("atproto-space=")
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
            "Atproto-Space <space-credential>",
            Some("<audience DID>"),
            r#"("authorization" "atproto-space-audience")"#,
        );
        let expected = "\"authorization\": Atproto-Space <space-credential>\n\
                        \"atproto-space-audience\": <audience DID>\n\
                        \"@signature-params\": (\"authorization\" \"atproto-space-audience\")";
        assert_eq!(base.as_bytes(), expected.as_bytes());
        assert!(!base.ends_with('\n'));
    }

    #[test]
    fn credential_headers_are_formatted_and_verify() {
        let key = SigningKey::random(&mut OsRng);
        let headers = credential_headers(&key, "cred.jwt.sig", "did:plc:repoowner");
        assert_eq!(headers.authorization, "Atproto-Space cred.jwt.sig");
        assert_eq!(headers.audience.as_deref(), Some("did:plc:repoowner"));
        assert_eq!(
            headers.signature_input,
            r#"atproto-space=("authorization" "atproto-space-audience")"#
        );
        assert!(headers.signature.starts_with("atproto-space=:"));
        assert!(headers.signature.ends_with(':'));
        assert_eq!(
            headers.key_id(),
            None,
            "keyid is optional on credential use"
        );
        assert!(verifies(&headers, key.verifying_key()));
    }

    #[test]
    fn exchange_headers_cover_only_authorization_and_name_the_key() {
        let key = SigningKey::random(&mut OsRng);
        let key_id = p256_did_key(key.verifying_key());
        let headers = exchange_headers(&key, "delegation.jwt.sig");
        assert_eq!(headers.authorization, "Bearer delegation.jwt.sig");
        assert_eq!(headers.audience, None);
        assert_eq!(
            headers.signature_input,
            format!(r#"atproto-space=("authorization");keyid="{key_id}""#)
        );
        assert_eq!(headers.key_id(), Some(key_id.as_str()));
        assert!(verifies(&headers, key.verifying_key()));
        assert_eq!(
            signature_base(&headers.authorization, None, params(&headers)),
            format!(
                "\"authorization\": Bearer delegation.jwt.sig\n\"@signature-params\": (\"authorization\");keyid=\"{key_id}\""
            )
        );
    }

    #[test]
    fn signature_is_raw_64_byte_low_s_r_s() {
        let key = SigningKey::random(&mut OsRng);
        for i in 0..16 {
            let headers = credential_headers(&key, &format!("cred-{i}"), "did:plc:aud");
            let bytes = signature_bytes(&headers);
            assert_eq!(bytes.len(), 64, "r||s, not DER");
            assert_ne!(bytes[0], 0x30, "never a DER SEQUENCE");
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
        changed.authorization = "Atproto-Space other".into();
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
