//! MLS and Clean-Chat Service Authentication
//!
//! Handles service auth tokens for Gateway → Delivery Service communication.
//! Supports both:
//! - Clean-chat (`blue.catbird.chat.*`, all 32 endpoints): PDS-issued user service auth tokens (Bearer)
//!   and direct Delivery Service routing.
//! - Legacy MLS (`blue.catbird.mlsChat.*`): Gateway-issued ES256 service tokens (Bearer)
//!   and direct Delivery Service routing.
use super::atproto_client::MAX_RESPONSE_SIZE;
use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::models::CatbirdSession;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Utc;
use futures_util::StreamExt;
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use p256::pkcs8::DecodePrivateKey;
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

/// All 32 clean-chat endpoints defined in blue.catbird.chat.*
pub const CHAT_ENDPOINTS: &[&str] = &[
    "blue.catbird.chat.acceptConversation",
    "blue.catbird.chat.acknowledgeWelcome",
    "blue.catbird.chat.activateReset",
    "blue.catbird.chat.cancelLeafRecovery",
    "blue.catbird.chat.cancelLeave",
    "blue.catbird.chat.closeConversation",
    "blue.catbird.chat.createConversation",
    "blue.catbird.chat.deleteBlob",
    "blue.catbird.chat.enrollDevice",
    "blue.catbird.chat.getBlob",
    "blue.catbird.chat.getBlobUsage",
    "blue.catbird.chat.getConversationState",
    "blue.catbird.chat.getConversations",
    "blue.catbird.chat.getDevices",
    "blue.catbird.chat.getEntries",
    "blue.catbird.chat.getLeafRecoveryInbox",
    "blue.catbird.chat.getOwnDevices",
    "blue.catbird.chat.getPendingWelcomes",
    "blue.catbird.chat.getSubscriptionTicket",
    "blue.catbird.chat.prepareBlobUpload",
    "blue.catbird.chat.publishTyping",
    "blue.catbird.chat.rebindDeviceAuthentication",
    "blue.catbird.chat.rejectWelcome",
    "blue.catbird.chat.replenishKeyPackages",
    "blue.catbird.chat.requestLeafRecovery",
    "blue.catbird.chat.requestLeave",
    "blue.catbird.chat.requestReset",
    "blue.catbird.chat.revokeDevice",
    "blue.catbird.chat.sendMessage",
    "blue.catbird.chat.submitTransition",
    "blue.catbird.chat.subscribeEvents",
    "blue.catbird.chat.uploadBlob",
];

/// Public EC P-256 JWK embedded in DPoP proof headers (deny_unknown_fields)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicP256Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// DPoP proof JWT header (deny_unknown_fields)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopProofHeader {
    pub typ: String,
    pub alg: String,
    pub jwk: PublicP256Jwk,
}

/// Exact claims for DPoP proof JWTs (deny_unknown_fields)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopProofClaims {
    pub htm: String,
    pub htu: String,
    pub ath: String,
    pub iat: i64,
    pub jti: String,
}

/// Extract PublicP256Jwk from an EC P-256 VerifyingKey
pub fn public_p256_jwk_from_verifying_key(vk: &VerifyingKey) -> PublicP256Jwk {
    let encoded_point = vk.to_encoded_point(false);
    let x_bytes = encoded_point.x().expect("uncompressed point has x");
    let y_bytes = encoded_point.y().expect("uncompressed point has y");
    PublicP256Jwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: URL_SAFE_NO_PAD.encode(x_bytes),
        y: URL_SAFE_NO_PAD.encode(y_bytes),
    }
}

/// Extract PublicP256Jwk from an EC P-256 SigningKey
pub fn public_p256_jwk_from_signing_key(sk: &SigningKey) -> PublicP256Jwk {
    public_p256_jwk_from_verifying_key(&sk.verifying_key())
}

/// Calculate RFC 7638 SHA-256 thumbprint (base64url URL_SAFE_NO_PAD) for an EC P-256 JWK
pub fn calculate_rfc7638_jkt(jwk: &PublicP256Jwk) -> String {
    // Canonical JSON with keys in lexicographical order: crv, kty, x, y
    let canonical_json = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    let digest = Sha256::digest(canonical_json.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Calculate RFC 7638 thumbprint for a P-256 SigningKey
pub fn p256_jwk_thumbprint(sk: &SigningKey) -> String {
    let jwk = public_p256_jwk_from_signing_key(sk);
    calculate_rfc7638_jkt(&jwk)
}

/// Calculate RFC 7638 thumbprint for a P-256 VerifyingKey
pub fn p256_verifying_key_thumbprint(vk: &VerifyingKey) -> String {
    let jwk = public_p256_jwk_from_verifying_key(vk);
    calculate_rfc7638_jkt(&jwk)
}

/// Calculate access token hash (ath) for DPoP proof
pub fn calculate_ath(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// Parse a P-256 signing key from PEM, base64 SEC1, or base64 PKCS#8 DER
pub fn parse_p256_signing_key(input: &str) -> AppResult<SigningKey> {
    let trimmed = input.trim();
    if trimmed.starts_with("-----BEGIN") {
        return SigningKey::from_pkcs8_pem(trimmed)
            .map_err(|e| AppError::Crypto(format!("Failed to parse PEM signing key: {e}")));
    }
    let decoded = STANDARD
        .decode(trimmed)
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|e| AppError::Crypto(format!("Failed to decode base64 signing key: {e}")))?;

    if decoded.len() == 32 {
        SigningKey::from_slice(&decoded)
            .map_err(|e| AppError::Crypto(format!("Invalid 32-byte SEC1 signing key: {e}")))
    } else {
        SigningKey::from_pkcs8_der(&decoded)
            .map_err(|e| AppError::Crypto(format!("Failed to parse PKCS#8 DER signing key: {e}")))
    }
}

/// Generate a DPoP proof JWT for clean-chat HTTP XRPC calls
pub fn generate_dpop_proof(
    dpop_signing_key: &SigningKey,
    method: &str,
    htu: &str,
    access_token: &str,
    iat: i64,
) -> AppResult<String> {
    let jwk = public_p256_jwk_from_signing_key(dpop_signing_key);
    let header = DpopProofHeader {
        typ: "dpop+jwt".to_string(),
        alg: "ES256".to_string(),
        jwk,
    };

    let mut random_bytes = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_bytes);
    let jti = URL_SAFE_NO_PAD.encode(random_bytes);

    let claims = DpopProofClaims {
        htm: method.to_ascii_uppercase(),
        htu: htu.to_string(),
        ath: calculate_ath(access_token),
        iat,
        jti,
    };

    let encoded_header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|e| AppError::Internal(e.to_string()))?,
    );
    let encoded_payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&claims).map_err(|e| AppError::Internal(e.to_string()))?,
    );

    let signing_input = format!("{}.{}", encoded_header, encoded_payload);
    let signature: Signature = dpop_signing_key.sign(signing_input.as_bytes());
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}", signing_input, encoded_signature))
}

/// Verify a DPoP proof JWT against expected method, htu, access_token, JKT, and timestamp
pub fn verify_dpop_proof(
    proof_jwt: &str,
    expected_method: &str,
    expected_htu: &str,
    access_token: &str,
    expected_jkt: Option<&str>,
    trusted_now: i64,
) -> AppResult<DpopProofClaims> {
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::BadRequest("invalid DPoP proof JWT format".into()));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| AppError::BadRequest(format!("invalid base64url DPoP header: {e}")))?;
    let header: DpopProofHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid DPoP header JSON: {e}")))?;

    if header.typ != "dpop+jwt" || header.alg != "ES256" {
        return Err(AppError::BadRequest("unsupported DPoP proof header alg/typ".into()));
    }
    if header.jwk.kty != "EC" || header.jwk.crv != "P-256" {
        return Err(AppError::BadRequest("DPoP proof JWK must be EC P-256".into()));
    }

    let proof_jkt = calculate_rfc7638_jkt(&header.jwk);
    if let Some(expected) = expected_jkt {
        if proof_jkt != expected {
            return Err(AppError::BadRequest(format!(
                "DPoP proof JKT mismatch: got {}, expected {}",
                proof_jkt, expected
            )));
        }
    }

    let x_bytes = URL_SAFE_NO_PAD
        .decode(&header.jwk.x)
        .map_err(|e| AppError::BadRequest(format!("invalid base64url jwk.x: {e}")))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(&header.jwk.y)
        .map_err(|e| AppError::BadRequest(format!("invalid base64url jwk.y: {e}")))?;
    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err(AppError::BadRequest("invalid P-256 coordinate length".into()));
    }

    let mut point_bytes = Vec::with_capacity(65);
    point_bytes.push(0x04);
    point_bytes.extend_from_slice(&x_bytes);
    point_bytes.extend_from_slice(&y_bytes);

    let encoded_point = EncodedPoint::from_bytes(&point_bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid P-256 encoded point: {e}")))?;
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|e| AppError::BadRequest(format!("invalid P-256 verifying key: {e}")))?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| AppError::BadRequest(format!("invalid base64url signature: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid ES256 signature bytes: {e}")))?;

    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| AppError::BadRequest(format!("DPoP proof signature verification failed: {e}")))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AppError::BadRequest(format!("invalid base64url payload: {e}")))?;
    let claims: DpopProofClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid DPoP proof claims JSON: {e}")))?;

    if claims.htm != expected_method.to_ascii_uppercase() {
        return Err(AppError::BadRequest(format!(
            "DPoP htm mismatch: got {}, expected {}",
            claims.htm, expected_method
        )));
    }
    if claims.htu != expected_htu {
        return Err(AppError::BadRequest(format!(
            "DPoP htu mismatch: got {}, expected {}",
            claims.htu, expected_htu
        )));
    }
    let expected_ath = calculate_ath(access_token);
    if claims.ath != expected_ath {
        return Err(AppError::BadRequest(format!(
            "DPoP ath mismatch: got {}, expected {}",
            claims.ath, expected_ath
        )));
    }
    if (claims.iat - trusted_now).abs() > 60 {
        return Err(AppError::BadRequest(format!(
            "DPoP proof iat outside 60-second window: iat={}, now={}",
            claims.iat, trusted_now
        )));
    }

    let jti_decoded = URL_SAFE_NO_PAD
        .decode(&claims.jti)
        .map_err(|e| AppError::BadRequest(format!("invalid DPoP proof jti encoding: {e}")))?;
    if !(12..=32).contains(&jti_decoded.len()) {
        return Err(AppError::BadRequest(format!(
            "DPoP proof jti raw byte length {} outside [12, 32]",
            jti_decoded.len()
        )));
    }

    Ok(claims)
}

/// Service for generating MLS and clean-chat service auth tokens and proxying requests
pub struct MlsAuthService {
    state: Arc<AppState>,
}

impl MlsAuthService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Check if a lexicon is an MLS or clean-chat endpoint that should be routed directly
    pub fn is_mls_lexicon(lexicon: &str) -> bool {
        Self::is_clean_chat_lexicon(lexicon)
    }

    /// Check if a lexicon belongs to v1 legacy MLS (`blue.catbird.mlsChat.*`)
    pub fn is_v1_mls_lexicon(_lexicon: &str) -> bool {
        false
    }

    /// Check if a lexicon belongs to clean-chat (`blue.catbird.chat.*`, 32 endpoints)
    pub fn is_clean_chat_lexicon(lexicon: &str) -> bool {
        let prefix = "blue.catbird.chat";
        lexicon.len() > prefix.len()
            && lexicon.starts_with(prefix)
            && lexicon.as_bytes().get(prefix.len()) == Some(&b'.')
            && lexicon != "blue.catbird.chat.defs"
    }

    /// Check if direct MLS or clean-chat routing is enabled
    pub fn is_enabled(&self) -> bool {
        self.state.config.mls.service_url.is_some()
            || self.state.config.chat.enabled
            || std::env::var("CHAT_ENABLED")
                .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false)
    }

    /// Get the delivery service URL (loopback target)
    pub fn service_url(&self) -> Option<&str> {
        self.state
            .config
            .mls
            .service_url
            .as_deref()
            .or_else(|| {
                if !self.state.config.chat.ds_internal_url.is_empty() {
                    Some(self.state.config.chat.ds_internal_url.as_str())
                } else {
                    None
                }
            })
    }

    pub fn chat_issuer(&self) -> &str {
        if !self.state.config.chat.issuer.is_empty() {
            &self.state.config.chat.issuer
        } else {
            "https://api.catbird.blue"
        }
    }

    pub fn chat_audience(&self) -> &str {
        if !self.state.config.chat.audience.is_empty() {
            &self.state.config.chat.audience
        } else {
            "did:web:mlschat.catbird.blue"
        }
    }

    pub fn chat_key_id(&self) -> String {
        if !self.state.config.chat.key_id.is_empty() {
            self.state.config.chat.key_id.clone()
        } else if let Some(ref ks) = self.state.key_store {
            ks.active_key().kid.clone()
        } else {
            "catbird-chat-key-1".to_string()
        }
    }

    pub fn chat_instance_id(&self) -> &str {
        if !self.state.config.chat.instance_id.is_empty() {
            &self.state.config.chat.instance_id
        } else {
            "e9a27f41-d4a6-4507-8687-b921733ec41a"
        }
    }

    pub fn chat_external_base(&self) -> &str {
        if !self.state.config.chat.external_base.is_empty() {
            &self.state.config.chat.external_base
        } else {
            "https://mlschat.catbird.blue"
        }
    }


    /// Generate legacy v1 service auth token for MLS requests (Bearer auth)
    pub fn generate_service_token(
        &self,
        session: &CatbirdSession,
        lexicon: &str,
    ) -> AppResult<String> {
        let gateway_did = self
            .state
            .config
            .mls
            .gateway_did
            .as_ref()
            .ok_or_else(|| AppError::Config("MLS gateway_did not configured".into()))?;

        let now = Utc::now().timestamp();

        let claims = json!({
            "iss": gateway_did,
            "sub": session.did,
            "aud": self.state.config.mls.service_did,
            "exp": now + 120,
            "iat": now,
            "lxm": lexicon,
            "jti": Uuid::new_v4().hyphenated().to_string(),
        });

        let key_store = self
            .state
            .key_store
            .as_ref()
            .ok_or_else(|| AppError::Config("KeyStore not configured".into()))?;
        let active_key = key_store.active_key();
        let signing_key = SigningKey::from(&active_key.secret_key);

        self.sign_jwt_with_kid(&claims, &signing_key, &active_key.kid)
    }

    /// Sign a JWT with ES256 and include kid in header
    fn sign_jwt_with_kid(
        &self,
        claims: &serde_json::Value,
        signing_key: &SigningKey,
        kid: &str,
    ) -> AppResult<String> {
        let header = json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": kid
        });

        let encoded_header = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&header)
                .map_err(|e| AppError::Internal(e.to_string()))?
                .as_bytes(),
        );
        let encoded_payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(claims)
                .map_err(|e| AppError::Internal(e.to_string()))?
                .as_bytes(),
        );

        let signing_input = format!("{}.{}", encoded_header, encoded_payload);

        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let encoded_signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{}.{}", signing_input, encoded_signature))
    }

    /// Make an authenticated request to the MLS/Chat delivery service
    pub async fn proxy_request(
        &self,
        session: &CatbirdSession,
        method: reqwest::Method,
        lexicon: &str,
        query_string: Option<&str>,
        body: Option<bytes::Bytes>,
        content_type: Option<&str>,
    ) -> AppResult<(u16, reqwest::header::HeaderMap, bytes::Bytes)> {
        if Self::is_clean_chat_lexicon(lexicon) {
            self.proxy_clean_chat_request(
                session,
                method,
                lexicon,
                query_string,
                body,
                content_type,
                None,
                None,
            )
            .await
        } else {
            self.proxy_v1_request(
                session,
                method,
                lexicon,
                query_string,
                body,
                content_type,
            )
            .await
        }
    }

    /// Make a legacy v1 authenticated request to the MLS service (Authorization: Bearer)
    async fn proxy_v1_request(
        &self,
        session: &CatbirdSession,
        method: reqwest::Method,
        lexicon: &str,
        query_string: Option<&str>,
        body: Option<bytes::Bytes>,
        content_type: Option<&str>,
    ) -> AppResult<(u16, reqwest::header::HeaderMap, bytes::Bytes)> {
        let service_url = self
            .service_url()
            .ok_or_else(|| AppError::Config("MLS service_url not configured".into()))?;

        let url = if let Some(qs) = query_string {
            format!("{}/xrpc/{}?{}", service_url.trim_end_matches('/'), lexicon, qs)
        } else {
            format!("{}/xrpc/{}", service_url.trim_end_matches('/'), lexicon)
        };

        let token = self.generate_service_token(session, lexicon)?;

        let mut request = self
            .state
            .http_client
            .request(method, &url)
            .header("Authorization", format!("Bearer {}", token));

        if let Some(ct) = content_type {
            request = request.header("Content-Type", ct);
        }

        if let Some(b) = body {
            request = request.body(b);
        }

        let response = request
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("MLS request failed: {}", e)))?;

        let status = response.status().as_u16();
        let headers = response.headers().clone();

        let content_length = headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        if let Some(len) = content_length {
            if len > MAX_RESPONSE_SIZE {
                return Err(AppError::ResponseTooLarge(format!(
                    "MLS response size {} bytes exceeds maximum allowed {} bytes",
                    len, MAX_RESPONSE_SIZE
                )));
            }
        }

        let mut stream = response.bytes_stream();
        let mut body_vec = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| AppError::Internal(format!("Failed to read MLS response: {}", e)))?;
            if body_vec.len() + chunk.len() > MAX_RESPONSE_SIZE {
                return Err(AppError::ResponseTooLarge(format!(
                    "MLS response exceeded maximum size of {} bytes while reading",
                    MAX_RESPONSE_SIZE
                )));
            }
            body_vec.extend_from_slice(&chunk);
        }

        let body = bytes::Bytes::from(body_vec);

        tracing::debug!(
            lexicon = %lexicon,
            status = %status,
            body_len = %body.len(),
            "MLS direct proxy response"
        );

        Ok((status, headers, body))
    }

    /// Make a clean-chat authenticated request (Authorization: Bearer <token>)
    #[allow(clippy::too_many_arguments)]
    pub async fn proxy_clean_chat_request(
        &self,
        session: &CatbirdSession,
        method: reqwest::Method,
        lexicon: &str,
        query_string: Option<&str>,
        body: Option<bytes::Bytes>,
        content_type: Option<&str>,
        device_id_override: Option<&str>,
        _dpop_key_override: Option<&SigningKey>,
    ) -> AppResult<(u16, reqwest::header::HeaderMap, bytes::Bytes)> {
        let service_url = self
            .service_url()
            .ok_or_else(|| AppError::Config("Chat delivery service URL not configured".into()))?;

        let url = if let Some(qs) = query_string {
            format!("{}/xrpc/{}?{}", service_url.trim_end_matches('/'), lexicon, qs)
        } else {
            format!("{}/xrpc/{}", service_url.trim_end_matches('/'), lexicon)
        };

        // Determine device ID:
        // 1. Explicit override (e.g. from x-catbird-chat-device-id header)
        // 2. Request body (actorDeviceId / deviceId / recipientDeviceId)
        // 3. Database lookup for session.did in chat.devices (active device)
        // 4. Fallback UUIDv4
        let device_id = if let Some(id) = device_id_override {
            id.to_string()
        } else if let Some(id) = body.as_ref().and_then(|b| {
            serde_json::from_slice::<serde_json::Value>(b).ok().and_then(|v| {
                let inner = v
                    .get("signedRequest")
                    .and_then(|sr| sr.get("body"))
                    .unwrap_or_else(|| v.get("body").unwrap_or(&v));
                inner
                    .get("actorDeviceId")
                    .or_else(|| inner.get("deviceId"))
                    .or_else(|| inner.get("recipientDeviceId"))
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string())
            })
        }) {
            id
        } else if let Some(ref pool) = self.state.push_db {
            let row: Option<(Uuid,)> = sqlx::query_as(
                "SELECT device_id FROM chat.devices WHERE user_did = $1 AND status = 'active' ORDER BY updated_at DESC LIMIT 1",
            )
            .bind(&session.did)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();
            row.map(|(id,)| id.hyphenated().to_string())
                .unwrap_or_else(|| Uuid::new_v4().hyphenated().to_string())
        } else {
            Uuid::new_v4().hyphenated().to_string()
        };

        // Obtain PDS-issued user service auth token
        let token = super::service_auth::ServiceAuthProvider::new(self.state.clone())
            .token_for(session, lexicon)
            .await?;

        let mut request = self
            .state
            .http_client
            .request(method, &url)
            .header("Authorization", format!("Bearer {}", token))
            .header("x-catbird-chat-device-id", &device_id);

        if let Some(ct) = content_type {
            request = request.header("Content-Type", ct);
        }

        if let Some(b) = body {
            request = request.body(b);
        }

        let response = request
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Chat request failed: {}", e)))?;

        let status = response.status().as_u16();
        let headers = response.headers().clone();

        let content_length = headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        if let Some(len) = content_length {
            if len > MAX_RESPONSE_SIZE {
                return Err(AppError::ResponseTooLarge(format!(
                    "Chat response size {} bytes exceeds maximum allowed {} bytes",
                    len, MAX_RESPONSE_SIZE
                )));
            }
        }

        let mut stream = response.bytes_stream();
        let mut body_vec = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| AppError::Internal(format!("Failed to read chat response: {}", e)))?;
            if body_vec.len() + chunk.len() > MAX_RESPONSE_SIZE {
                return Err(AppError::ResponseTooLarge(format!(
                    "Chat response exceeded maximum size of {} bytes while reading",
                    MAX_RESPONSE_SIZE
                )));
            }
            body_vec.extend_from_slice(&chunk);
        }

        let body = bytes::Bytes::from(body_vec);

        tracing::debug!(
            lexicon = %lexicon,
            status = %status,
            body_len = %body.len(),
            "Clean-chat direct proxy response"
        );

        Ok((status, headers, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_mls_lexicon_recognition() {
        // Legacy v1 MLS endpoints must NOT be routed as active MLS endpoints
        assert!(!MlsAuthService::is_mls_lexicon("blue.catbird.mlsChat.getConvos"));
        assert!(!MlsAuthService::is_mls_lexicon("blue.catbird.mlsChat.sendMessage"));
        assert!(!MlsAuthService::is_mls_lexicon("blue.catbird.mlsChat.publishKeyPackages"));
        assert!(!MlsAuthService::is_v1_mls_lexicon("blue.catbird.mlsChat.getConvos"));
        assert!(!MlsAuthService::is_clean_chat_lexicon("blue.catbird.mlsChat.getConvos"));

        // All 32 clean-chat endpoints
        for endpoint in CHAT_ENDPOINTS {
            assert!(
                MlsAuthService::is_mls_lexicon(endpoint),
                "Endpoint {endpoint} must be recognized by is_mls_lexicon"
            );
            assert!(
                MlsAuthService::is_clean_chat_lexicon(endpoint),
                "Endpoint {endpoint} must be recognized by is_clean_chat_lexicon"
            );
            assert!(
                !MlsAuthService::is_v1_mls_lexicon(endpoint),
                "Endpoint {endpoint} must NOT be recognized by is_v1_mls_lexicon"
            );
        }

        // Non-MLS endpoints
        assert!(!MlsAuthService::is_mls_lexicon("app.bsky.feed.getTimeline"));
        assert!(!MlsAuthService::is_mls_lexicon("chat.bsky.convo.listConvos"));
        assert!(!MlsAuthService::is_mls_lexicon("com.atproto.repo.getRecord"));
        assert!(!MlsAuthService::is_mls_lexicon("blue.catbird.chat.defs"));
        assert!(!MlsAuthService::is_clean_chat_lexicon("blue.catbird.chat.defs"));
    }

    #[test]
    fn test_rfc7638_jkt_calculation() {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let jwk = public_p256_jwk_from_signing_key(&signing_key);

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(URL_SAFE_NO_PAD.decode(&jwk.x).unwrap().len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.decode(&jwk.y).unwrap().len(), 32);

        let jkt = calculate_rfc7638_jkt(&jwk);
        // Base64url without padding SHA-256 is exactly 43 characters
        assert_eq!(jkt.len(), 43);
        assert_eq!(p256_jwk_thumbprint(&signing_key), jkt);
    }

    #[test]
    fn test_dpop_proof_generation_and_verification() {
        let dpop_key = SigningKey::random(&mut rand::thread_rng());
        let dpop_jkt = p256_jwk_thumbprint(&dpop_key);

        let method = "POST";
        let htu = "https://mlschat.catbird.blue/xrpc/blue.catbird.chat.sendMessage";
        let access_token = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.test_signature";
        let now = 1700000000;

        let proof = generate_dpop_proof(&dpop_key, method, htu, access_token, now).unwrap();

        // Verify valid proof
        let claims = verify_dpop_proof(
            &proof,
            method,
            htu,
            access_token,
            Some(&dpop_jkt),
            now,
        )
        .unwrap();

        assert_eq!(claims.htm, "POST");
        assert_eq!(claims.htu, htu);
        assert_eq!(claims.ath, calculate_ath(access_token));
        assert_eq!(claims.iat, now);
        assert!(!claims.jti.is_empty());

        // Test tampering detection
        // 1. Wrong method
        assert!(verify_dpop_proof(&proof, "GET", htu, access_token, Some(&dpop_jkt), now).is_err());
        // 2. Wrong htu
        assert!(verify_dpop_proof(&proof, method, "https://mlschat.catbird.blue/xrpc/blue.catbird.chat.getEntries", access_token, Some(&dpop_jkt), now).is_err());
        // 3. Wrong access token (ath mismatch)
        assert!(verify_dpop_proof(&proof, method, htu, "tampered_token", Some(&dpop_jkt), now).is_err());
        // 4. Wrong JKT
        assert!(verify_dpop_proof(&proof, method, htu, access_token, Some("different_jkt_43_chars_long_aaaaaaaaaaaaaa"), now).is_err());
        // 5. Expired / clock skew > 60s
        assert!(verify_dpop_proof(&proof, method, htu, access_token, Some(&dpop_jkt), now + 61).is_err());
        assert!(verify_dpop_proof(&proof, method, htu, access_token, Some(&dpop_jkt), now - 61).is_err());
    }

    #[test]
    fn test_parse_p256_signing_key() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let sec1_bytes = key.to_bytes();
        let base64_sec1 = STANDARD.encode(sec1_bytes);

        let parsed = parse_p256_signing_key(&base64_sec1).unwrap();
        assert_eq!(parsed.to_bytes(), key.to_bytes());

        // Test URL_SAFE base64 as well
        let url_safe_sec1 = URL_SAFE_NO_PAD.encode(sec1_bytes);
        let parsed_url_safe = parse_p256_signing_key(&url_safe_sec1).unwrap();
        assert_eq!(parsed_url_safe.to_bytes(), key.to_bytes());
    }
}
