//! MLS Service Authentication
//!
//! Generates service auth tokens for direct Gateway → MLS server communication.
//! Uses the Gateway's signing key to create JWTs that the MLS server can verify.

use super::atproto_client::MAX_RESPONSE_SIZE;
use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::models::CatbirdSession;
use base64::Engine;
use chrono::Utc;
use futures_util::StreamExt;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MlsProofOrigin(String);

impl MlsProofOrigin {
    pub(crate) fn parse(value: &str) -> AppResult<Self> {
        let parsed = url::Url::parse(value)
            .map_err(|_| AppError::Config("mls.proof_origin must be a valid URL".into()))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(AppError::Config(
                "mls.proof_origin must be an origin-only HTTPS URL".into(),
            ));
        }
        Ok(Self(parsed.origin().ascii_serialization()))
    }

    pub(crate) fn htu(&self, lexicon: &str) -> AppResult<String> {
        if !MlsAuthService::is_mls_lexicon(lexicon)
            || lexicon
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'.'))
        {
            return Err(AppError::BadRequest("invalid MLS lexicon".into()));
        }
        Ok(format!("{}/xrpc/{lexicon}", self.0))
    }

    pub(crate) fn htu_for_routed_request(
        &self,
        lexicon: &str,
        _raw_query: Option<&str>,
    ) -> AppResult<String> {
        // RFC 9449 htu excludes query and fragment. Raw query is used only by
        // the trusted connect URL, never by proof or device authority.
        self.htu(lexicon)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DelegatedAuth {
    pub(crate) token: String,
    pub(crate) proof: String,
    pub(crate) jkt: String,
}

pub(crate) struct MlsProxyRequest<'a> {
    pub(crate) session: &'a CatbirdSession,
    pub(crate) session_dpop_key: &'a jose_jwk::Key,
    pub(crate) device_id: Option<&'a str>,
    pub(crate) method: reqwest::Method,
    pub(crate) lexicon: &'a str,
    pub(crate) query_string: Option<&'a str>,
    pub(crate) body: Option<bytes::Bytes>,
    pub(crate) content_type: Option<&'a str>,
}

struct DelegatedAuthRequest<'a> {
    gateway_signing_key: &'a SigningKey,
    gateway_kid: &'a str,
    gateway_did: &'a str,
    service_did: &'a str,
    user_did: &'a str,
    lexicon: &'a str,
    device_id: Option<&'a str>,
    session_dpop_key: &'a jose_jwk::Key,
    method: &'a str,
    proof_origin: &'a MlsProofOrigin,
}

pub(crate) fn public_p256_jwk(key: &jose_jwk::Key) -> AppResult<serde_json::Value> {
    let jose_jwk::Key::Ec(ec) = key else {
        return Err(AppError::Crypto("session DPoP key must be P-256".into()));
    };
    if ec.crv != jose_jwk::EcCurves::P256 || ec.x.len() != 32 || ec.y.len() != 32 {
        return Err(AppError::Crypto("session DPoP key must be P-256".into()));
    }
    let mut public = ec.clone();
    public.d = None;
    serde_json::to_value(jose_jwk::Key::Ec(public))
        .map_err(|_| AppError::Crypto("session DPoP public key encoding failed".into()))
}

pub(crate) fn rfc7638_public_jkt(jwk: &serde_json::Value) -> AppResult<String> {
    let object = jwk
        .as_object()
        .ok_or_else(|| AppError::Crypto("DPoP public JWK must be an object".into()))?;
    if ["d", "k", "p", "q", "dp", "dq", "qi", "oth"]
        .iter()
        .any(|field| object.contains_key(*field))
    {
        return Err(AppError::Crypto(
            "DPoP public JWK contains private material".into(),
        ));
    }
    let field = |name: &str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AppError::Crypto("DPoP public JWK is incomplete".into()))
    };
    let kty = field("kty")?;
    let crv = field("crv")?;
    let x = field("x")?;
    let y = field("y")?;
    let decode_len = |value: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .map(|bytes| bytes.len())
    };
    if kty != "EC" || crv != "P-256" || decode_len(x) != Ok(32) || decode_len(y) != Ok(32) {
        return Err(AppError::Crypto(
            "DPoP public JWK is not a valid P-256 key".into(),
        ));
    }
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(canonical)))
}

pub(crate) fn session_p256_jkt(key: &jose_jwk::Key) -> AppResult<String> {
    let jose_jwk::Key::Ec(ec) = key else {
        return Err(AppError::Crypto("session DPoP key must be P-256".into()));
    };
    if ec.d.is_none() {
        return Err(AppError::Crypto(
            "session DPoP key lacks private signing material".into(),
        ));
    }
    rfc7638_public_jkt(&public_p256_jwk(key)?)
}

fn sign_compact_jwt(
    claims: &serde_json::Value,
    signing_key: &SigningKey,
    kid: &str,
) -> AppResult<String> {
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = json!({ "alg": "ES256", "typ": "JWT", "kid": kid });
    let encoded_header =
        b64url.encode(serde_json::to_vec(&header).map_err(|e| AppError::Internal(e.to_string()))?);
    let encoded_payload =
        b64url.encode(serde_json::to_vec(claims).map_err(|e| AppError::Internal(e.to_string()))?);
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        b64url.encode(signature.to_bytes())
    ))
}

fn issue_delegated_auth(request: DelegatedAuthRequest<'_>) -> AppResult<DelegatedAuth> {
    let DelegatedAuthRequest {
        gateway_signing_key,
        gateway_kid,
        gateway_did,
        service_did,
        user_did,
        lexicon,
        device_id,
        session_dpop_key,
        method,
        proof_origin,
    } = request;
    let jkt = session_p256_jkt(session_dpop_key)?;
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": gateway_did,
        "sub": user_did,
        "aud": service_did,
        "exp": now + 120,
        "iat": now,
        "lxm": lexicon,
        "jti": Uuid::new_v4().to_string(),
        "cnf": { "jkt": jkt },
    });
    if let Some(device_id) = device_id {
        claims
            .as_object_mut()
            .expect("JSON object literal")
            .insert("device_id".into(), json!(device_id));
    }
    let token = sign_compact_jwt(&claims, gateway_signing_key, gateway_kid)?;
    let method = method.to_ascii_uppercase();
    let method = http::Method::from_bytes(method.as_bytes())
        .map_err(|_| AppError::BadRequest("invalid MLS HTTP method".into()))?
        .as_str()
        .to_string();
    let htu = proof_origin.htu(lexicon)?;
    let ath =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
    let proof = jacquard_oauth::dpop::build_dpop_proof(
        session_dpop_key,
        method.into(),
        htu.into(),
        None,
        Some(ath.into()),
    )
    .map_err(|_| AppError::Crypto("failed to build MLS DPoP proof".into()))?
    .to_string();
    Ok(DelegatedAuth { token, proof, jkt })
}

pub(crate) fn delegated_headers(auth: &DelegatedAuth) -> AppResult<HeaderMap> {
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", auth.token))
            .map_err(|_| AppError::Internal("invalid gateway token header".into()))?,
    );
    headers.insert(
        "dpop",
        HeaderValue::from_str(&auth.proof)
            .map_err(|_| AppError::Internal("invalid DPoP proof header".into()))?,
    );
    Ok(headers)
}

async fn send_authenticated_mls_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    auth: &DelegatedAuth,
    body: Option<bytes::Bytes>,
    content_type: Option<&str>,
) -> AppResult<(u16, HeaderMap, bytes::Bytes)> {
    let mut request = client
        .request(method, url)
        .headers(delegated_headers(auth)?);
    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| AppError::Internal(format!("MLS request failed: {error}")))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    if headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_RESPONSE_SIZE)
    {
        return Err(AppError::ResponseTooLarge(format!(
            "MLS response exceeds maximum allowed {MAX_RESPONSE_SIZE} bytes"
        )));
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|error| AppError::Internal(format!("Failed to read MLS response: {error}")))?;
        if body.len() + chunk.len() > MAX_RESPONSE_SIZE {
            return Err(AppError::ResponseTooLarge(format!(
                "MLS response exceeded maximum size of {MAX_RESPONSE_SIZE} bytes while reading"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, headers, bytes::Bytes::from(body)))
}

/// Service for generating MLS service auth tokens
pub struct MlsAuthService {
    state: Arc<AppState>,
}

impl MlsAuthService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Check if a lexicon is an MLS endpoint that should be routed directly
    pub fn is_mls_lexicon(lexicon: &str) -> bool {
        let prefix = Self::mls_lexicon_prefix();
        lexicon.len() > prefix.len()
            && lexicon.starts_with(prefix)
            && lexicon.as_bytes().get(prefix.len()) == Some(&b'.')
    }

    fn mls_lexicon_prefix() -> &'static str {
        catbird_atproto::catbird::mls_chat::get_convos::NSID
            .rsplit_once('.')
            .map(|(prefix, _)| prefix)
            .unwrap_or(catbird_atproto::catbird::mls_chat::get_convos::NSID)
    }

    /// Check if direct MLS routing is enabled
    pub fn is_enabled(&self) -> bool {
        self.state.config.mls.service_url.is_some() && self.state.config.mls.gateway_did.is_some()
    }

    /// Get the MLS service URL
    pub fn service_url(&self) -> Option<&str> {
        self.state.config.mls.service_url.as_deref()
    }

    /// Make an authenticated request to the MLS service
    pub(crate) async fn proxy_request(
        &self,
        request: MlsProxyRequest<'_>,
    ) -> AppResult<(u16, reqwest::header::HeaderMap, bytes::Bytes)> {
        let MlsProxyRequest {
            session,
            session_dpop_key,
            device_id,
            method,
            lexicon,
            query_string,
            body,
            content_type,
        } = request;
        let service_url = self
            .service_url()
            .ok_or_else(|| AppError::Config("MLS service_url not configured".into()))?;

        // Build the URL
        let url = if let Some(qs) = query_string {
            format!("{}/xrpc/{}?{}", service_url, lexicon, qs)
        } else {
            format!("{}/xrpc/{}", service_url, lexicon)
        };

        let proof_origin = self
            .state
            .config
            .mls
            .proof_origin
            .as_deref()
            .ok_or_else(|| AppError::Config("MLS proof_origin not configured".into()))?;
        let proof_origin = MlsProofOrigin::parse(proof_origin)?;
        // Parse the path-only public htu even though query is used below for
        // the trusted internal connection URL.
        let _htu = proof_origin.htu_for_routed_request(lexicon, query_string)?;
        let gateway_did = self
            .state
            .config
            .mls
            .gateway_did
            .as_deref()
            .ok_or_else(|| AppError::Config("MLS gateway_did not configured".into()))?;
        let key_store = self
            .state
            .key_store
            .as_ref()
            .ok_or_else(|| AppError::Config("KeyStore not configured".into()))?;
        let active_key = key_store.active_key();
        let signing_key = SigningKey::from(&active_key.secret_key);
        let delegated = issue_delegated_auth(DelegatedAuthRequest {
            gateway_signing_key: &signing_key,
            gateway_kid: &active_key.kid,
            gateway_did,
            service_did: &self.state.config.mls.service_did,
            user_did: &session.did,
            lexicon,
            device_id,
            session_dpop_key,
            method: method.as_str(),
            proof_origin: &proof_origin,
        })?;
        let (status, headers, body) = send_authenticated_mls_request(
            &self.state.http_client,
            method,
            &url,
            &delegated,
            body,
            content_type,
        )
        .await?;

        tracing::debug!(
            lexicon = %lexicon,
            status = %status,
            body_len = %body.len(),
            "MLS direct proxy response"
        );

        Ok((status, headers, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::signature::Verifier;
    use sha2::{Digest, Sha256};

    fn session_dpop_key() -> jose_jwk::Key {
        let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        jose_jwk::Key::from(&jose_jwk::crypto::Key::from(secret))
    }

    fn jwt_parts(compact: &str) -> (serde_json::Value, serde_json::Value, Vec<u8>) {
        let parts: Vec<_> = compact.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        (header, claims, signature)
    }

    #[test]
    fn test_is_mls_lexicon() {
        assert!(MlsAuthService::is_mls_lexicon(
            "blue.catbird.mlsChat.getConvos"
        ));
        assert!(MlsAuthService::is_mls_lexicon(
            "blue.catbird.mlsChat.sendMessage"
        ));
        assert!(MlsAuthService::is_mls_lexicon(
            "blue.catbird.mlsChat.publishKeyPackages"
        ));
        assert!(!MlsAuthService::is_mls_lexicon("app.bsky.feed.getTimeline"));
        assert!(!MlsAuthService::is_mls_lexicon(
            "chat.bsky.convo.listConvos"
        ));
    }

    #[test]
    fn proof_origin_is_exact_https_origin_and_htu_excludes_query() {
        let origin = MlsProofOrigin::parse("https://mlschat.catbird.blue").unwrap();
        assert_eq!(
            origin.htu("blue.catbird.mlsChat.getMessages").unwrap(),
            "https://mlschat.catbird.blue/xrpc/blue.catbird.mlsChat.getMessages"
        );
        assert_eq!(
            origin
                .htu_for_routed_request(
                    "blue.catbird.mlsChat.getMessages",
                    Some("cursor=one&cursor=two")
                )
                .unwrap(),
            "https://mlschat.catbird.blue/xrpc/blue.catbird.mlsChat.getMessages"
        );

        assert_eq!(
            MlsProofOrigin::parse("https://mlschat.catbird.blue:8443")
                .unwrap()
                .htu("blue.catbird.mlsChat.getMessages")
                .unwrap(),
            "https://mlschat.catbird.blue:8443/xrpc/blue.catbird.mlsChat.getMessages"
        );

        for invalid in [
            "http://mlschat.catbird.blue",
            "https://user@mlschat.catbird.blue",
            "https://mlschat.catbird.blue/path",
            "https://mlschat.catbird.blue?query=1",
            "https://mlschat.catbird.blue#fragment",
        ] {
            assert!(
                MlsProofOrigin::parse(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn rfc7638_thumbprint_accepts_public_metadata_but_rejects_private_material() {
        let key = session_dpop_key();
        let session_jkt = session_p256_jkt(&key).unwrap();
        let mut public = public_p256_jwk(&key).unwrap();
        public["kid"] = serde_json::json!("metadata-is-ignored");
        public["alg"] = serde_json::json!("ES256");
        public["use"] = serde_json::json!("sig");
        assert_eq!(rfc7638_public_jkt(&public).unwrap(), session_jkt);

        public["d"] = serde_json::json!("private-material");
        assert!(rfc7638_public_jkt(&public).is_err());
        let mut wrong_curve = public_p256_jwk(&key).unwrap();
        wrong_curve["crv"] = serde_json::json!("P-384");
        assert!(rfc7638_public_jkt(&wrong_curve).is_err());
    }

    #[test]
    fn delegated_token_and_dpop_are_fresh_bound_and_contain_no_private_jwk() {
        let gateway_signing = SigningKey::random(&mut rand::rngs::OsRng);
        let gateway_verifying = gateway_signing.verifying_key();
        let session_key = session_dpop_key();
        let origin = MlsProofOrigin::parse("https://mlschat.catbird.blue").unwrap();

        let first = issue_delegated_auth(DelegatedAuthRequest {
            gateway_signing_key: &gateway_signing,
            gateway_kid: "gateway-kid",
            gateway_did: "did:web:api.catbird.blue",
            service_did: "did:web:mlschat.catbird.blue",
            user_did: "did:plc:alice",
            lexicon: "blue.catbird.mlsChat.commitGroupChange",
            device_id: Some("123e4567-e89b-12d3-a456-426614174000"),
            session_dpop_key: &session_key,
            method: "post",
            proof_origin: &origin,
        })
        .unwrap();
        let second = issue_delegated_auth(DelegatedAuthRequest {
            gateway_signing_key: &gateway_signing,
            gateway_kid: "gateway-kid",
            gateway_did: "did:web:api.catbird.blue",
            service_did: "did:web:mlschat.catbird.blue",
            user_did: "did:plc:alice",
            lexicon: "blue.catbird.mlsChat.commitGroupChange",
            device_id: Some("123e4567-e89b-12d3-a456-426614174000"),
            session_dpop_key: &session_key,
            method: "POST",
            proof_origin: &origin,
        })
        .unwrap();
        assert_ne!(first.token, second.token);
        assert_ne!(first.proof, second.proof);

        let (_, claims, signature) = jwt_parts(&first.token);
        assert_eq!(claims["iss"], "did:web:api.catbird.blue");
        assert_eq!(claims["sub"], "did:plc:alice");
        assert_eq!(claims["aud"], "did:web:mlschat.catbird.blue");
        assert_eq!(claims["lxm"], "blue.catbird.mlsChat.commitGroupChange");
        assert_eq!(claims["device_id"], "123e4567-e89b-12d3-a456-426614174000");
        assert_eq!(claims["cnf"]["jkt"], first.jkt);
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            120
        );
        let (_, second_claims, _) = jwt_parts(&second.token);
        assert_ne!(claims["jti"], second_claims["jti"]);
        let token_parts: Vec<_> = first.token.split('.').collect();
        let token_signature = Signature::from_slice(&signature).unwrap();
        gateway_verifying
            .verify(
                format!("{}.{}", token_parts[0], token_parts[1]).as_bytes(),
                &token_signature,
            )
            .unwrap();
        let mut tampered_claims = claims.clone();
        tampered_claims["device_id"] = serde_json::json!("victim-device");
        let tampered_payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered_claims).unwrap());
        assert!(gateway_verifying
            .verify(
                format!("{}.{}", token_parts[0], tampered_payload).as_bytes(),
                &token_signature,
            )
            .is_err());

        let (proof_header, proof_claims, proof_signature) = jwt_parts(&first.proof);
        assert_eq!(proof_header["typ"], "dpop+jwt");
        assert!(proof_header["jwk"].get("d").is_none());
        assert_eq!(proof_claims["htm"], "POST");
        assert_eq!(
            proof_claims["htu"],
            "https://mlschat.catbird.blue/xrpc/blue.catbird.mlsChat.commitGroupChange"
        );
        let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(first.token.as_bytes()));
        assert_eq!(proof_claims["ath"], expected_ath);
        let (_, second_proof_claims, _) = jwt_parts(&second.proof);
        assert_ne!(proof_claims["jti"], second_proof_claims["jti"]);
        assert!(proof_claims["iat"].as_i64().is_some());
        let proof_ec: jose_jwk::Ec = serde_json::from_value(proof_header["jwk"].clone()).unwrap();
        let proof_public = p256::PublicKey::try_from(&proof_ec).unwrap();
        let proof_verifying = p256::ecdsa::VerifyingKey::from(proof_public);
        let proof_parts: Vec<_> = first.proof.split('.').collect();
        proof_verifying
            .verify(
                format!("{}.{}", proof_parts[0], proof_parts[1]).as_bytes(),
                &Signature::from_slice(&proof_signature).unwrap(),
            )
            .unwrap();
        let mut tampered_proof_claims = proof_claims;
        tampered_proof_claims["htu"] =
            serde_json::json!("https://evil.example/xrpc/blue.catbird.mlsChat.commitGroupChange");
        let tampered_payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered_proof_claims).unwrap());
        assert!(proof_verifying
            .verify(
                format!("{}.{}", proof_parts[0], tampered_payload).as_bytes(),
                &Signature::from_slice(&proof_signature).unwrap(),
            )
            .is_err());
    }

    #[test]
    fn unbound_sessions_remain_compatible_without_inventing_a_device() {
        let gateway_signing = SigningKey::random(&mut rand::rngs::OsRng);
        let session_key = session_dpop_key();
        let origin = MlsProofOrigin::parse("https://mlschat.catbird.blue").unwrap();
        let auth = issue_delegated_auth(DelegatedAuthRequest {
            gateway_signing_key: &gateway_signing,
            gateway_kid: "gateway-kid",
            gateway_did: "did:web:api.catbird.blue",
            service_did: "did:web:mlschat.catbird.blue",
            user_did: "did:plc:alice",
            lexicon: "blue.catbird.mlsChat.getConvos",
            device_id: None,
            session_dpop_key: &session_key,
            method: "GET",
            proof_origin: &origin,
        })
        .unwrap();
        let (_, claims, _) = jwt_parts(&auth.token);
        assert!(claims.get("device_id").is_none());
        assert!(claims["cnf"]["jkt"].is_string());
    }

    #[test]
    fn delegated_headers_are_an_explicit_two_header_boundary() {
        let auth = DelegatedAuth {
            token: "gateway-token".to_string(),
            proof: "gateway-proof".to_string(),
            jkt: "jkt".to_string(),
        };
        let headers = delegated_headers(&auth).unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers.get("authorization").unwrap(),
            "Bearer gateway-token"
        );
        assert_eq!(headers.get("dpop").unwrap(), "gateway-proof");
        for browser_secret in ["cookie", "proxy-authorization", "x-forwarded-for"] {
            assert!(headers.get(browser_secret).is_none());
        }
    }

    #[tokio::test]
    async fn live_request_capture_contains_gateway_credentials_but_no_browser_credentials() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/xrpc/blue.catbird.mlsChat.getMessages"))
            .and(query_param("cursor", "one"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"{}"))
            .mount(&server)
            .await;
        let auth = DelegatedAuth {
            token: "fresh-gateway-token".to_string(),
            proof: "fresh-gateway-proof".to_string(),
            jkt: "jkt".to_string(),
        };
        let url = format!(
            "{}/xrpc/blue.catbird.mlsChat.getMessages?cursor=one",
            server.uri()
        );
        let response = send_authenticated_mls_request(
            &reqwest::Client::new(),
            reqwest::Method::POST,
            &url,
            &auth,
            Some(bytes::Bytes::from_static(b"{}")),
            Some("application/json"),
        )
        .await
        .unwrap();
        assert_eq!(response.0, 200);

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let headers = &requests[0].headers;
        assert_eq!(
            headers.get("authorization").unwrap(),
            "Bearer fresh-gateway-token"
        );
        assert_eq!(headers.get("dpop").unwrap(), "fresh-gateway-proof");
        for forbidden in [
            "cookie",
            "proxy-authorization",
            "x-forwarded-for",
            "x-device-id",
        ] {
            assert!(headers.get(forbidden).is_none(), "forwarded {forbidden}");
        }
    }
}
