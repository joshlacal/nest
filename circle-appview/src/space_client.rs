use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::auth::{
    is_localhost_hostname, is_private_ip, parse_verification_key,
    select_authority_verification_method, DidDocument, JwtHeader,
};
use crate::error::{AppError, AuthReason};

pub trait SpaceHostTransport: Send + Sync {
    fn get_space_credential<'a>(
        &'a self,
        endpoint_url: &'a str,
        delegation_token: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        client_attestation: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>>;
}

#[derive(Clone, Default)]
pub struct DefaultSpaceHostTransport {
    test_root_cert: Option<reqwest::Certificate>,
}

impl DefaultSpaceHostTransport {
    pub fn new() -> Self {
        Self {
            test_root_cert: None,
        }
    }

    pub fn with_test_root_certificate(cert: reqwest::Certificate) -> Self {
        Self {
            test_root_cert: Some(cert),
        }
    }
}

impl SpaceHostTransport for DefaultSpaceHostTransport {
    fn get_space_credential<'a>(
        &'a self,
        endpoint_url: &'a str,
        delegation_token: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        client_attestation: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>> {
        let endpoint_url = endpoint_url.to_string();
        let delegation_token = delegation_token.to_string();
        let dpop_proof = dpop_proof.to_string();
        let space_uri = space_uri.to_string();
        let client_attestation = client_attestation.map(|s| s.to_string());
        let test_cert = self.test_root_cert.clone();

        Box::pin(async move {
            let parsed_url = url::Url::parse(&endpoint_url)
                .map_err(|e| AppError::InvalidRequest(format!("Invalid Space host URL: {e}")))?;

            if parsed_url.scheme() != "https" {
                return Err(AppError::InvalidRequest(
                    "Space host endpoint must use HTTPS".into(),
                ));
            }

            let host = parsed_url.host_str().ok_or_else(|| {
                AppError::InvalidRequest("Missing host in Space host URL".into())
            })?;

            if host.is_empty() || is_localhost_hostname(host) {
                return Err(AppError::Unauthorized(AuthReason::SsrfBlocked));
            }

            if let Ok(ip) = host.parse::<IpAddr>() {
                if is_private_ip(&ip) {
                    return Err(AppError::Unauthorized(AuthReason::SsrfBlocked));
                }
            }

            let port = parsed_url.port().unwrap_or(443);

            // DNS resolution
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| AppError::Unauthorized(AuthReason::DidResolutionFailed))?
                .collect();

            if addrs.is_empty() {
                return Err(AppError::Unauthorized(AuthReason::DidResolutionFailed));
            }

            // Reject every non-global/special-purpose address
            for addr in &addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(AppError::Unauthorized(AuthReason::SsrfBlocked));
                }
            }

            let pinned_addr = addrs[0];

            let mut builder = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(5))
                .resolve(host, pinned_addr);

            if let Some(cert) = test_cert {
                builder = builder.add_root_certificate(cert);
            }

            let client = builder
                .build()
                .map_err(|e| AppError::Internal(format!("Failed to build pinned HTTPS client: {e}")))?;

            let mut target_url = parsed_url.clone();
            target_url.set_path("/xrpc/com.atproto.space.getSpaceCredential");

            let mut req_body = serde_json::Map::new();
            req_body.insert("space".to_string(), serde_json::Value::String(space_uri));
            if let Some(attestation) = client_attestation {
                req_body.insert(
                    "clientAttestation".to_string(),
                    serde_json::Value::String(attestation),
                );
            }

            let response = client
                .post(target_url.as_str())
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {delegation_token}"))
                .header("DPoP", dpop_proof)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&serde_json::Value::Object(req_body))
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

            if !response.status().is_success() {
                let status = response.status();
                return Err(AppError::Internal(format!(
                    "Space host returned non-success status: {status}"
                )));
            }

            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| AppError::Internal(format!("Invalid JSON from Space host: {e}")))?;

            let credential = body
                .get("credential")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Internal("Missing credential in Space host response".into()))?;

            Ok(credential.to_string())
        })
    }
}

#[derive(Debug, Clone)]
pub struct RecordedSpaceHostCall {
    pub endpoint_url: String,
    pub delegation_token: String,
    pub dpop_proof: String,
    pub space_uri: String,
    pub client_attestation: Option<String>,
}

#[derive(Default)]
pub struct MockSpaceHostTransport {
    responses: Mutex<HashMap<String, Result<String, String>>>,
    calls: Mutex<Vec<RecordedSpaceHostCall>>,
}

impl MockSpaceHostTransport {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn set_credential_response(&self, space: &str, result: Result<String, String>) {
        let mut lock = self.responses.lock().unwrap();
        lock.insert(space.to_string(), result);
    }

    pub fn recorded_calls(&self) -> Vec<RecordedSpaceHostCall> {
        let lock = self.calls.lock().unwrap();
        lock.clone()
    }
}

impl SpaceHostTransport for MockSpaceHostTransport {
    fn get_space_credential<'a>(
        &'a self,
        endpoint_url: &'a str,
        delegation_token: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        client_attestation: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>> {
        let call = RecordedSpaceHostCall {
            endpoint_url: endpoint_url.to_string(),
            delegation_token: delegation_token.to_string(),
            dpop_proof: dpop_proof.to_string(),
            space_uri: space_uri.to_string(),
            client_attestation: client_attestation.map(|s| s.to_string()),
        };

        {
            let mut calls = self.calls.lock().unwrap();
            calls.push(call);
        }

        let space_uri = space_uri.to_string();
        let res = {
            let lock = self.responses.lock().unwrap();
            lock.get(&space_uri).cloned()
        };

        Box::pin(async move {
            match res {
                Some(Ok(token)) => Ok(token),
                Some(Err(err)) => Err(AppError::Internal(err)),
                None => Err(AppError::NotFound("No mock credential configured for space".into())),
            }
        })
    }
}

pub struct SpaceClient {
    transport: Arc<dyn SpaceHostTransport>,
}

impl SpaceClient {
    pub fn new() -> Self {
        Self {
            transport: Arc::new(DefaultSpaceHostTransport::new()),
        }
    }

    pub fn with_transport(transport: Arc<dyn SpaceHostTransport>) -> Self {
        Self { transport }
    }

    pub async fn exchange_credential(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        delegation_token: &str,
        client_attestation: Option<&str>,
        authority_did: &str,
        authority_doc: &DidDocument,
    ) -> Result<(String, p256::ecdsa::SigningKey, DateTime<Utc>), AppError> {
        let ephemeral_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = ephemeral_key.verifying_key();
        let expected_jkt = calculate_rfc7638_jkt(&verifying_key);

        let target_url = format!(
            "{}/xrpc/com.atproto.space.getSpaceCredential",
            service_endpoint.trim_end_matches('/')
        );

        let dpop_proof = create_dpop_proof(&ephemeral_key, "POST", &target_url);

        let credential_jwt = self
            .transport
            .get_space_credential(
                service_endpoint,
                delegation_token,
                &dpop_proof,
                space_uri,
                client_attestation,
            )
            .await?;

        // Validate returned Space credential
        let expires_at = validate_space_credential(
            &credential_jwt,
            authority_did,
            space_uri,
            &expected_jkt,
            authority_doc,
        )?;

        Ok((credential_jwt, ephemeral_key, expires_at))
    }
}

impl Default for SpaceClient {
    fn default() -> Self {
        Self::new()
    }
}

pub fn calculate_rfc7638_jkt(verifying_key: &p256::ecdsa::VerifyingKey) -> String {
    let point = EncodedPoint::from(verifying_key);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    // Canonical JSON representation for EC P-256 key per RFC 7638
    let canonical_jwk = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let mut hasher = Sha256::new();
    hasher.update(canonical_jwk.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn create_dpop_proof(
    signing_key: &p256::ecdsa::SigningKey,
    htm: &str,
    htu: &str,
) -> String {
    let now = Utc::now().timestamp();
    let verifying_key = signing_key.verifying_key();
    let point = EncodedPoint::from(verifying_key);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        }
    });

    let payload = json!({
        "jti": Uuid::new_v4().to_string(),
        "htm": htm,
        "htu": htu,
        "iat": now,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

pub fn validate_space_credential(
    credential_jwt: &str,
    expected_authority_did: &str,
    expected_space_uri: &str,
    expected_jkt: &str,
    authority_doc: &DidDocument,
) -> Result<DateTime<Utc>, AppError> {
    let parts: Vec<&str> = credential_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::InvalidRequest(
            "Invalid Space credential JWT format".into(),
        ));
    }

    // 1. Validate Header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::InvalidRequest("Invalid Space credential header encoding".into()))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid Space credential header JSON".into()))?;

    match &header.typ {
        Some(t) if t == "atproto-space-credential+jwt" => {}
        _ => return Err(AppError::Unauthorized(AuthReason::InvalidTyp)),
    }

    if header.alg != "ES256" && header.alg != "ES256K" {
        return Err(AppError::Unauthorized(AuthReason::UnsupportedAlg));
    }

    // 2. Validate Payload
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::InvalidRequest("Invalid Space credential payload encoding".into()))?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid Space credential claims JSON".into()))?;

    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRequest("Missing iss in Space credential claims".into()))?;
    if iss != expected_authority_did {
        return Err(AppError::Forbidden(
            "Space credential issuer does not match Space authority".into(),
        ));
    }

    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRequest("Missing sub in Space credential claims".into()))?;
    if sub != expected_space_uri {
        return Err(AppError::InvalidRequest(
            "Space credential subject does not match requested Space URI".into(),
        ));
    }

    // Must not have an inappropriate audience (absence of audience or matching requested space)
    if let Some(aud) = claims.get("aud").and_then(|v| v.as_str()) {
        if !aud.is_empty() && aud != expected_space_uri {
            return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
        }
    }

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::InvalidRequest("Missing exp in Space credential claims".into()))?;
    let now = Utc::now().timestamp();
    if exp <= now {
        return Err(AppError::Unauthorized(AuthReason::Expired));
    }

    let iat = claims
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::InvalidRequest("Missing iat in Space credential claims".into()))?;
    if iat > now + 300 {
        return Err(AppError::Unauthorized(AuthReason::FutureIat));
    }

    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRequest("Missing jti in Space credential claims".into()))?;
    if jti.is_empty() {
        return Err(AppError::InvalidRequest(
            "Empty jti in Space credential claims".into(),
        ));
    }

    // Validate cnf.jkt binding
    let jkt = claims
        .get("cnf")
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRequest("Missing cnf.jkt in Space credential claims".into()))?;
    if jkt != expected_jkt {
        return Err(AppError::Unauthorized(AuthReason::InvalidCoordinates));
    }

    // 3. Verify Signature against authority DID document (#atproto_space fallback to #atproto)
    let vm = select_authority_verification_method(
        authority_doc,
        expected_authority_did,
        header.kid.as_deref(),
    )
    .map_err(AppError::Unauthorized)?;
    let key = parse_verification_key(vm).map_err(AppError::Unauthorized)?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidSignatureFormat))?;

    key.verify(signing_input.as_bytes(), &sig_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::BadSignature))?;

    DateTime::from_timestamp(exp, 0).ok_or_else(|| {
        AppError::InvalidRequest("Invalid timestamp in Space credential exp".into())
    })
}
