use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use serde_json::json;
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::auth::{is_localhost_hostname, is_private_ip};
use crate::error::AppError;

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

pub struct DefaultSpaceHostTransport {
    http_client: reqwest::Client,
}

impl DefaultSpaceHostTransport {
    pub fn new(http_client: reqwest::Client) -> Self {
        Self { http_client }
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

        Box::pin(async move {
            let parsed_url = url::Url::parse(&endpoint_url)
                .map_err(|e| AppError::InvalidRequest(format!("Invalid Space host URL: {e}")))?;

            let host = parsed_url.host_str().ok_or_else(|| {
                AppError::InvalidRequest("Missing host in Space host URL".into())
            })?;

            if is_localhost_hostname(host) {
                return Err(AppError::InvalidRequest("Restricted host rejected by SSRF policy".into()));
            }

            if let Ok(ip) = host.parse::<IpAddr>() {
                if is_private_ip(&ip) {
                    return Err(AppError::InvalidRequest("Restricted IP rejected by SSRF policy".into()));
                }
            }

            let full_url = format!(
                "{}/xrpc/com.atproto.space.getSpaceCredential",
                endpoint_url.trim_end_matches('/')
            );

            let mut req_body = serde_json::Map::new();
            req_body.insert("space".to_string(), serde_json::Value::String(space_uri));
            if let Some(attestation) = client_attestation {
                req_body.insert(
                    "clientAttestation".to_string(),
                    serde_json::Value::String(attestation),
                );
            }

            let response = self
                .http_client
                .post(&full_url)
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

#[derive(Default)]
pub struct MockSpaceHostTransport {
    responses: Mutex<HashMap<String, Result<String, String>>>,
}

impl MockSpaceHostTransport {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_credential_response(&self, space: &str, result: Result<String, String>) {
        let mut lock = self.responses.lock().unwrap();
        lock.insert(space.to_string(), result);
    }
}

impl SpaceHostTransport for MockSpaceHostTransport {
    fn get_space_credential<'a>(
        &'a self,
        _endpoint_url: &'a str,
        _delegation_token: &'a str,
        _dpop_proof: &'a str,
        space_uri: &'a str,
        _client_attestation: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>> {
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
    pub fn new(http_client: reqwest::Client) -> Self {
        Self {
            transport: Arc::new(DefaultSpaceHostTransport::new(http_client)),
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
    ) -> Result<(String, p256::ecdsa::SigningKey, DateTime<Utc>), AppError> {
        let ephemeral_key = p256::ecdsa::SigningKey::random(&mut OsRng);
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

        let expires_at = parse_jwt_expiry(&credential_jwt)?;

        Ok((credential_jwt, ephemeral_key, expires_at))
    }
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

pub fn parse_jwt_expiry(token: &str) -> Result<DateTime<Utc>, AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::InvalidRequest("Invalid JWT format in credential".into()));
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::InvalidRequest("Invalid credential payload encoding".into()))?;

    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid credential claims JSON".into()))?;

    let exp = claims.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| {
        AppError::InvalidRequest("Missing exp in Space credential claims".into())
    })?;

    DateTime::from_timestamp(exp, 0).ok_or_else(|| {
        AppError::InvalidRequest("Invalid timestamp in Space credential exp".into())
    })
}
