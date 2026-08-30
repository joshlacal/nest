use axum::{
    extract::{FromRequestParts, Request, State},
    http::{header, request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use crate::config::AppState;
use crate::db;
use crate::error::{AppError, AuthReason};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub did: String,
    pub lxm: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtHeader {
    #[serde(default)]
    pub typ: Option<String>,
    pub alg: String,
    #[serde(default)]
    pub kid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtProtoServiceAuthClaims {
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub jti: Option<String>,
    #[serde(default)]
    pub lxm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,
    #[serde(default, rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub service: Vec<DidService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidService {
    pub id: String,
    pub r#type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    #[serde(default, rename = "publicKeyJwk")]
    pub public_key_jwk: Option<PublicKeyJwk>,
    #[serde(default, rename = "publicKeyMultibase")]
    pub public_key_multibase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(default)]
    pub y: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<PublicKeyJwk>,
}

#[derive(Debug, Clone)]
pub enum ParsedVerifyingKey {
    P256(p256::ecdsa::VerifyingKey),
    Secp256k1(k256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl ParsedVerifyingKey {
    pub fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> Result<(), AuthReason> {
        match self {
            Self::P256(vk) => {
                let sig = p256::ecdsa::Signature::from_slice(sig_bytes)
                    .map_err(|_| AuthReason::InvalidSignatureFormat)?;
                vk.verify(msg, &sig).map_err(|_| AuthReason::BadSignature)?;
                Ok(())
            }
            Self::Secp256k1(vk) => {
                let sig = k256::ecdsa::Signature::from_slice(sig_bytes)
                    .map_err(|_| AuthReason::InvalidSignatureFormat)?;
                vk.verify(msg, &sig).map_err(|_| AuthReason::BadSignature)?;
                Ok(())
            }
            Self::Ed25519(vk) => {
                let sig = ed25519_dalek::Signature::from_slice(sig_bytes)
                    .map_err(|_| AuthReason::InvalidSignatureFormat)?;
                use ed25519_dalek::Verifier;
                vk.verify(msg, &sig).map_err(|_| AuthReason::BadSignature)?;
                Ok(())
            }
        }
    }
}

pub fn parse_public_key_jwk(jwk: &PublicKeyJwk) -> Result<ParsedVerifyingKey, AuthReason> {
    if jwk.kty == "OKP" && jwk.crv.eq_ignore_ascii_case("Ed25519") {
        let x = URL_SAFE_NO_PAD
            .decode(&jwk.x)
            .map_err(|_| AuthReason::InvalidCoordinates)?;
        if x.len() != 32 {
            return Err(AuthReason::InvalidCoordinates);
        }
        let bytes: &[u8; 32] = x
            .as_slice()
            .try_into()
            .map_err(|_| AuthReason::InvalidCoordinates)?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|_| AuthReason::InvalidCoordinates)?;
        return Ok(ParsedVerifyingKey::Ed25519(vk));
    }

    if jwk.kty != "EC" {
        return Err(AuthReason::InvalidKeyType);
    }

    let x = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|_| AuthReason::InvalidCoordinates)?;
    let y_str = jwk.y.as_deref().ok_or(AuthReason::InvalidCoordinates)?;
    let y = URL_SAFE_NO_PAD
        .decode(y_str)
        .map_err(|_| AuthReason::InvalidCoordinates)?;

    if x.len() != 32 || y.len() != 32 {
        return Err(AuthReason::InvalidCoordinates);
    }

    if jwk.crv.eq_ignore_ascii_case("P-256") {
        let mut x_bytes = p256::FieldBytes::default();
        x_bytes.copy_from_slice(&x);
        let mut y_bytes = p256::FieldBytes::default();
        y_bytes.copy_from_slice(&y);
        let ep = p256::EncodedPoint::from_affine_coordinates(&x_bytes, &y_bytes, false);
        let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&ep)
            .map_err(|_| AuthReason::InvalidCoordinates)?;
        return Ok(ParsedVerifyingKey::P256(vk));
    }

    if jwk.crv.eq_ignore_ascii_case("secp256k1") || jwk.crv.eq_ignore_ascii_case("P-256K") {
        let mut x_bytes = k256::FieldBytes::default();
        x_bytes.copy_from_slice(&x);
        let mut y_bytes = k256::FieldBytes::default();
        y_bytes.copy_from_slice(&y);
        let ep = k256::EncodedPoint::from_affine_coordinates(&x_bytes, &y_bytes, false);
        let vk = k256::ecdsa::VerifyingKey::from_encoded_point(&ep)
            .map_err(|_| AuthReason::InvalidCoordinates)?;
        return Ok(ParsedVerifyingKey::Secp256k1(vk));
    }

    Err(AuthReason::InvalidCurve)
}

pub fn parse_verification_key(vm: &VerificationMethod) -> Result<ParsedVerifyingKey, AuthReason> {
    if let Some(multibase_str) = &vm.public_key_multibase {
        if vm.r#type != "Multikey" {
            return Err(AuthReason::InvalidKeyType);
        }

        let (_base, decoded) =
            multibase::decode(multibase_str).map_err(|_| AuthReason::InvalidMultikey)?;

        // Ed25519 multicodec prefix: 0xed -> varint [0xed, 0x01]
        if decoded.starts_with(&[0xed, 0x01]) {
            let key_bytes = &decoded[2..];
            if key_bytes.len() != 32 {
                return Err(AuthReason::InvalidCoordinates);
            }
            let bytes: &[u8; 32] = key_bytes
                .try_into()
                .map_err(|_| AuthReason::InvalidCoordinates)?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(bytes)
                .map_err(|_| AuthReason::InvalidCoordinates)?;
            return Ok(ParsedVerifyingKey::Ed25519(vk));
        }

        // P-256 multicodec prefix: 0x1200 -> varint [0x80, 0x24]
        if decoded.starts_with(&[0x80, 0x24]) {
            let key_bytes = &decoded[2..];
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                .map_err(|_| AuthReason::InvalidCoordinates)?;
            return Ok(ParsedVerifyingKey::P256(vk));
        }

        // Secp256k1 multicodec prefix: 0xe7 -> varint [0xe7, 0x01]
        if decoded.starts_with(&[0xe7, 0x01]) {
            let key_bytes = &decoded[2..];
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                .map_err(|_| AuthReason::InvalidCoordinates)?;
            return Ok(ParsedVerifyingKey::Secp256k1(vk));
        }

        return Err(AuthReason::InvalidKeyType);
    }

    if let Some(jwk) = &vm.public_key_jwk {
        if vm.r#type != "JsonWebKey2020" {
            return Err(AuthReason::InvalidKeyType);
        }
        return parse_public_key_jwk(jwk);
    }

    Err(AuthReason::NoVerificationMethod)
}

pub trait DidWebTransport: Send + Sync {
    fn resolve_dns<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, AuthReason>> + Send + 'a>>;

    fn fetch<'a>(
        &'a self,
        url: &'a str,
        host: &'a str,
        pinned_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<DidDocument, AuthReason>> + Send + 'a>>;

    fn test_root_certificate(&self) -> Option<reqwest::Certificate> {
        None
    }

    fn allows_loopback_for_test(&self) -> bool {
        false
    }
}
#[derive(Debug, Default, Clone)]
pub struct DefaultDidWebTransport {
    test_root_cert: Option<reqwest::Certificate>,
    allow_loopback_for_test: bool,
}

impl DefaultDidWebTransport {
    pub fn new() -> Self {
        Self {
            test_root_cert: None,
            allow_loopback_for_test: false,
        }
    }

    pub fn with_test_root_certificate(cert: reqwest::Certificate) -> Self {
        Self {
            test_root_cert: Some(cert),
            allow_loopback_for_test: false,
        }
    }

    pub fn with_test_fixture(cert: reqwest::Certificate, allow_loopback: bool) -> Self {
        Self {
            test_root_cert: Some(cert),
            allow_loopback_for_test: allow_loopback,
        }
    }

    pub fn with_loopback(allow_loopback: bool) -> Self {
        Self {
            test_root_cert: None,
            allow_loopback_for_test: allow_loopback,
        }
    }
}

/// Builds the pinned reqwest client used for did:web document fetches.
/// Enforces no-proxy, redirects disabled, request timeout, and hostname pinning.
pub fn build_did_web_client(
    host: &str,
    pinned_addr: SocketAddr,
    test_root_cert: Option<reqwest::Certificate>,
) -> Result<reqwest::Client, AuthReason> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .resolve(host, pinned_addr);

    if let Some(cert) = test_root_cert {
        builder = builder.add_root_certificate(cert);
    }

    builder.build().map_err(|_| AuthReason::DidResolutionFailed)
}

impl DidWebTransport for DefaultDidWebTransport {
    fn test_root_certificate(&self) -> Option<reqwest::Certificate> {
        self.test_root_cert.clone()
    }

    fn allows_loopback_for_test(&self) -> bool {
        self.allow_loopback_for_test
    }

    fn resolve_dns<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, AuthReason>> + Send + 'a>> {
        let host = host.to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|_| AuthReason::DidResolutionFailed)?
                .collect();
            if addrs.is_empty() {
                return Err(AuthReason::DidResolutionFailed);
            }
            Ok(addrs)
        })
    }

    fn fetch<'a>(
        &'a self,
        url: &'a str,
        host: &'a str,
        pinned_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<DidDocument, AuthReason>> + Send + 'a>> {
        let url = url.to_string();
        let host = host.to_string();
        let test_cert = self.test_root_cert.clone();
        Box::pin(async move {
            let client = build_did_web_client(&host, pinned_addr, test_cert)?;

            let resp = client
                .get(&url)
                .send()
                .await
                .map_err(|_| AuthReason::DidResolutionFailed)?;

            if !resp.status().is_success() {
                return Err(AuthReason::DidResolutionFailed);
            }

            let body_bytes = read_bounded_response_bytes(resp, MAX_DID_DOC_BYTES)
                .await
                .map_err(|_| AuthReason::DidDocumentInvalid)?;

            serde_json::from_slice::<DidDocument>(&body_bytes)
                .map_err(|_| AuthReason::DidDocumentInvalid)
        })
    }
}
pub const DID_AUTH_REVOCATION_SLO_SECS: i64 = 60;
pub const FRESH_RESOLUTION_COOLDOWN_SECS: i64 = 5;
pub const MAX_DID_DOC_BYTES: usize = 512 * 1024; // 512 KiB
pub const MAX_JWKS_BYTES: usize = 512 * 1024; // 512 KiB
pub const MAX_CONCURRENT_PUBLIC_FLOWS: usize = 32;
pub const MAX_AGGREGATE_PUBLIC_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Budget class distinguishing unauthenticated public flows from authenticated Space transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteBudget {
    /// Unauthenticated public flows (OAuth metadata discovery, PAR, token exchange/refresh,
    /// DID resolution, JWKS) subject to the 16 MiB aggregate public memory budget (`MAX_AGGREGATE_PUBLIC_BYTES`).
    PublicFlow,
    /// Authenticated Space-host transfers (CAR files, blobs, space RPC responses) bounded by
    /// their own per-response limits (e.g. 50 MiB CAR, 20 MiB blob) without consuming the public budget.
    AuthenticatedSpace,
}

static PUBLIC_FLOW_SEMAPHORE: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PUBLIC_FLOWS)));
static PUBLIC_BYTE_BUDGET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub fn public_flow_semaphore() -> Arc<tokio::sync::Semaphore> {
    PUBLIC_FLOW_SEMAPHORE.clone()
}

pub fn current_aggregate_public_bytes() -> usize {
    PUBLIC_BYTE_BUDGET.load(std::sync::atomic::Ordering::Relaxed)
}

/// Drop guard for aggregate public byte budget to prevent reservation leaks on errors, early returns, or cancellation.
pub struct AggregateByteGuard(pub usize);

impl Drop for AggregateByteGuard {
    fn drop(&mut self) {
        if self.0 > 0 {
            PUBLIC_BYTE_BUDGET.fetch_sub(self.0, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Read an HTTP response body with an explicit maximum byte limit to prevent decompression/memory exhaustion.
/// For unauthenticated public flows (`ByteBudget::PublicFlow`), enforces Content-Length validation,
/// streaming chunk size checks, and aggregate public flow byte budget (`MAX_AGGREGATE_PUBLIC_BYTES`).
/// For authenticated Space transfers (`ByteBudget::AuthenticatedSpace`), enforces per-response limits
/// without consuming or being rejected by the public aggregate budget.
pub async fn read_bounded_response_bytes_with_budget(
    mut response: reqwest::Response,
    max_bytes: usize,
    budget: ByteBudget,
) -> Result<Vec<u8>, AppError> {
    if let Some(len) = response.content_length() {
        if len > max_bytes as u64 {
            return Err(AppError::InvalidRequest(format!(
                "Response Content-Length {len} exceeds limit of {max_bytes} bytes"
            )));
        }
    }
    let mut body = Vec::new();
    let mut guard = AggregateByteGuard(0);

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| AppError::Internal(format!("Failed reading response chunk: {e}")))?
    {
        let chunk_len = chunk.len();
        if body.len() + chunk_len > max_bytes {
            return Err(AppError::InvalidRequest(format!(
                "Response body exceeded maximum allowed size of {max_bytes} bytes"
            )));
        }

        if budget == ByteBudget::PublicFlow {
            let prev =
                PUBLIC_BYTE_BUDGET.fetch_add(chunk_len, std::sync::atomic::Ordering::Relaxed);
            guard.0 += chunk_len;
            if prev + chunk_len > MAX_AGGREGATE_PUBLIC_BYTES {
                return Err(AppError::InvalidRequest(format!(
                    "Aggregate public flow byte budget of {MAX_AGGREGATE_PUBLIC_BYTES} bytes exceeded"
                )));
            }
        }

        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

/// Read unauthenticated public flow response with aggregate public byte budget enforcement.
pub async fn read_bounded_public_response_bytes(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, AppError> {
    read_bounded_response_bytes_with_budget(response, max_bytes, ByteBudget::PublicFlow).await
}

/// Read authenticated Space transfer response (e.g. CAR files, blobs) with per-response size limits.
pub async fn read_bounded_authenticated_response_bytes(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, AppError> {
    read_bounded_response_bytes_with_budget(response, max_bytes, ByteBudget::AuthenticatedSpace)
        .await
}

/// Default public flow response reader (for backward compatibility).
pub async fn read_bounded_response_bytes(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, AppError> {
    read_bounded_public_response_bytes(response, max_bytes).await
}

pub const MAX_DID_CACHE_CAPACITY: usize = 10_000;
pub struct DidResolver {
    plc_directory_url: String,
    http_client: reqwest::Client,
    pub web_transport: Arc<dyn DidWebTransport>,
    capacity: usize,
    cache: RwLock<HashMap<String, (DidDocument, DateTime<Utc>)>>,
    last_fresh_resolution: RwLock<HashMap<String, std::time::Instant>>,
}

impl DidResolver {
    pub fn new(plc_directory_url: String, http_client: reqwest::Client) -> Self {
        Self::with_capacity(plc_directory_url, http_client, MAX_DID_CACHE_CAPACITY)
    }

    pub fn with_capacity(
        plc_directory_url: String,
        http_client: reqwest::Client,
        capacity: usize,
    ) -> Self {
        Self {
            plc_directory_url,
            http_client,
            web_transport: Arc::new(DefaultDidWebTransport::new()),
            capacity,
            cache: RwLock::new(HashMap::new()),
            last_fresh_resolution: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_transport(
        plc_directory_url: String,
        http_client: reqwest::Client,
        web_transport: Arc<dyn DidWebTransport>,
    ) -> Self {
        Self {
            plc_directory_url,
            http_client,
            web_transport,
            capacity: MAX_DID_CACHE_CAPACITY,
            cache: RwLock::new(HashMap::new()),
            last_fresh_resolution: RwLock::new(HashMap::new()),
        }
    }

    /// Invalidate any cached DID document for a DID.
    pub fn invalidate_cached(&self, did: &str) {
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(did);
        }
    }

    /// Return total cached entries count.
    pub fn cached_count(&self) -> usize {
        if let Ok(cache) = self.cache.read() {
            cache.len()
        } else {
            0
        }
    }

    /// Return total fresh resolution tracked entries count.
    pub fn fresh_resolution_count(&self) -> usize {
        if let Ok(last_map) = self.last_fresh_resolution.read() {
            last_map.len()
        } else {
            0
        }
    }

    /// Insert or override a DID document directly in cache (useful for testing)
    pub fn insert_cached(&self, did: String, doc: DidDocument) {
        self.insert_cached_with_ttl(
            did,
            doc,
            chrono::Duration::seconds(DID_AUTH_REVOCATION_SLO_SECS),
        );
    }

    /// Insert with explicit TTL and enforce capacity + expired eviction
    pub fn insert_cached_with_ttl(&self, did: String, doc: DidDocument, ttl: chrono::Duration) {
        if let Ok(mut cache) = self.cache.write() {
            let now = Utc::now();
            cache.retain(|_, (_, exp)| *exp > now);
            if cache.len() >= self.capacity && !cache.contains_key(&did) {
                // Evict oldest/earliest expiring entry
                if let Some(oldest_key) = cache
                    .iter()
                    .min_by_key(|(_, (_, exp))| *exp)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest_key);
                }
            }
            cache.insert(did, (doc, now + ttl));
        }
    }
    pub async fn resolve(&self, did: &str) -> Result<DidDocument, AuthReason> {
        self.resolve_internal(did, false).await
    }

    /// Force fresh resolution from network/upstream and update cache (enforces revocation SLO).
    /// Protected by a per-issuer cooldown and admission permit to prevent unauthenticated
    /// bad-signature JWT floods from forcing unbounded uncached upstream fetches.
    pub async fn resolve_fresh(&self, did: &str) -> Result<DidDocument, AuthReason> {
        // Check per-issuer cooldown: if fresh resolution was performed very recently,
        // serve cached document to mitigate flood of unauthenticated invalid-signature requests.
        if let Ok(mut last_map) = self.last_fresh_resolution.write() {
            let now = std::time::Instant::now();
            let cooldown = std::time::Duration::from_secs(FRESH_RESOLUTION_COOLDOWN_SECS as u64);
            // Prune expired cooldowns
            last_map.retain(|_, t| now.saturating_duration_since(*t) < cooldown);
            // Enforce capacity bound
            if last_map.len() >= self.capacity && !last_map.contains_key(did) {
                if let Some(oldest_key) = last_map
                    .iter()
                    .min_by_key(|(_, t)| *t)
                    .map(|(k, _)| k.clone())
                {
                    last_map.remove(&oldest_key);
                }
            }
            if let Some(last_time) = last_map.get(did) {
                if now.saturating_duration_since(*last_time) < cooldown {
                    if let Ok(cache) = self.cache.read() {
                        if let Some((doc, _)) = cache.get(did) {
                            return Ok(doc.clone());
                        }
                    }
                }
            }
            last_map.insert(did.to_string(), now);
        }

        // Acquire admission permit to bound concurrent upstream resolution calls
        let _permit = public_flow_semaphore()
            .acquire_owned()
            .await
            .map_err(|_| AuthReason::DidResolutionFailed)?;
        self.resolve_internal(did, true).await
    }

    async fn resolve_internal(
        &self,
        did: &str,
        force_fresh: bool,
    ) -> Result<DidDocument, AuthReason> {
        // Check in-memory cache if not forced fresh
        if !force_fresh {
            if let Ok(cache) = self.cache.read() {
                if let Some((doc, exp)) = cache.get(did) {
                    if *exp > Utc::now() {
                        return Ok(doc.clone());
                    }
                }
            }
        }

        let doc = if did.starts_with("did:plc:") {
            self.resolve_plc(did).await?
        } else if did.starts_with("did:web:") {
            self.resolve_web(did).await?
        } else {
            return Err(AuthReason::UnsupportedDidMethod);
        };

        // Cache resolved document with configured <= 60s revocation SLO TTL
        self.insert_cached_with_ttl(
            did.to_string(),
            doc.clone(),
            chrono::Duration::seconds(DID_AUTH_REVOCATION_SLO_SECS),
        );

        Ok(doc)
    }

    async fn resolve_plc(&self, did: &str) -> Result<DidDocument, AuthReason> {
        let url = format!("{}/{}", self.plc_directory_url.trim_end_matches('/'), did);
        let resp = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|_| AuthReason::DidResolutionFailed)?;

        if !resp.status().is_success() {
            return Err(AuthReason::DidResolutionFailed);
        }

        let body_bytes = read_bounded_response_bytes(resp, MAX_DID_DOC_BYTES)
            .await
            .map_err(|_| AuthReason::DidDocumentInvalid)?;

        serde_json::from_slice::<DidDocument>(&body_bytes)
            .map_err(|_| AuthReason::DidDocumentInvalid)
    }

    async fn resolve_web(&self, did: &str) -> Result<DidDocument, AuthReason> {
        let raw = did
            .strip_prefix("did:web:")
            .ok_or(AuthReason::UnsupportedDidMethod)?;
        if raw.is_empty() {
            return Err(AuthReason::DidResolutionFailed);
        }

        let parts: Vec<&str> = raw.split(':').collect();
        if parts.is_empty() {
            return Err(AuthReason::DidResolutionFailed);
        }

        let domain = parts[0];
        if domain.is_empty() || is_localhost_hostname(domain) {
            return Err(AuthReason::SsrfBlocked);
        }

        // Percent-decode domain (e.g. example.com%3A8443)
        let domain_decoded = urlencoding_decode(domain)?;

        // Parse host and port
        let (hostname, port) = if let Some((h, p)) = domain_decoded.split_once(':') {
            let parsed_port: u16 = p.parse().map_err(|_| AuthReason::DidResolutionFailed)?;
            (h.to_string(), parsed_port)
        } else {
            (domain_decoded, 443)
        };

        if hostname.is_empty() || is_localhost_hostname(&hostname) {
            return Err(AuthReason::SsrfBlocked);
        }

        if let Ok(ip) = hostname.parse::<IpAddr>() {
            if is_private_ip(&ip) {
                return Err(AuthReason::SsrfBlocked);
            }
        }

        // DNS resolution via injected web_transport
        let addrs = self.web_transport.resolve_dns(&hostname, port).await?;
        if addrs.is_empty() {
            return Err(AuthReason::DidResolutionFailed);
        }

        // Reject if any resolved address is non-global or special-purpose
        for addr in &addrs {
            if is_private_ip(&addr.ip()) {
                return Err(AuthReason::SsrfBlocked);
            }
        }

        let pinned_addr = addrs[0];

        let url_path = if parts.len() == 1 {
            "/.well-known/did.json".to_string()
        } else {
            let path_segments = parts[1..]
                .iter()
                .map(|seg| urlencoding_decode(seg))
                .collect::<Result<Vec<_>, _>>()?;
            format!("/{}/did.json", path_segments.join("/"))
        };

        let url = format!("https://{hostname}:{port}{url_path}");
        self.web_transport.fetch(&url, &hostname, pinned_addr).await
    }

    pub async fn resolve_pds_endpoint(&self, did: &str) -> Result<String, AuthReason> {
        let doc = self.resolve(did).await?;
        let pds_full_id = format!("{did}#atproto_pds");
        let service = doc
            .service
            .iter()
            .find(|s| {
                s.id == "#atproto_pds"
                    || s.id == pds_full_id
                    || s.r#type == "AtprotoPersonalDataServer"
            })
            .ok_or(AuthReason::NoVerificationMethod)?;
        Ok(service.service_endpoint.clone())
    }
}

pub async fn fetch_https_jwks(
    resolver: &DidResolver,
    jwks_url: &str,
) -> Result<Vec<ParsedVerifyingKey>, AuthReason> {
    let parsed = url::Url::parse(jwks_url).map_err(|_| AuthReason::DidResolutionFailed)?;
    if parsed.scheme() != "https" {
        return Err(AuthReason::SsrfBlocked);
    }
    let host = parsed.host_str().ok_or(AuthReason::DidResolutionFailed)?;
    let allow_loopback = resolver.web_transport.allows_loopback_for_test();
    if !allow_loopback {
        if host.is_empty() || is_localhost_hostname(host) {
            return Err(AuthReason::SsrfBlocked);
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_ip(&ip) {
                return Err(AuthReason::SsrfBlocked);
            }
        }
    }
    let port = parsed.port().unwrap_or(443);
    let addrs = resolver.web_transport.resolve_dns(host, port).await?;
    if addrs.is_empty() {
        return Err(AuthReason::DidResolutionFailed);
    }
    if !allow_loopback {
        for addr in &addrs {
            if is_private_ip(&addr.ip()) {
                return Err(AuthReason::SsrfBlocked);
            }
        }
    }
    let pinned_addr = addrs[0];
    let client = build_did_web_client(
        host,
        pinned_addr,
        resolver.web_transport.test_root_certificate(),
    )?;
    let resp = client
        .get(parsed.as_str())
        .send()
        .await
        .map_err(|_| AuthReason::DidResolutionFailed)?;
    if !resp.status().is_success() {
        return Err(AuthReason::DidResolutionFailed);
    }
    let body_bytes = read_bounded_response_bytes(resp, MAX_JWKS_BYTES)
        .await
        .map_err(|_| AuthReason::DidDocumentInvalid)?;
    let jwks: JwksDocument =
        serde_json::from_slice(&body_bytes).map_err(|_| AuthReason::DidDocumentInvalid)?;
    let mut parsed_keys = Vec::new();
    for jwk in &jwks.keys {
        if let Ok(k) = parse_public_key_jwk(jwk) {
            parsed_keys.push(k);
        }
    }
    if parsed_keys.is_empty() {
        return Err(AuthReason::NoVerificationMethod);
    }
    Ok(parsed_keys)
}

pub fn select_verification_method<'a>(
    doc: &'a DidDocument,
    iss: &str,
    kid: Option<&str>,
) -> Result<&'a VerificationMethod, AuthReason> {
    if doc.id != iss {
        return Err(AuthReason::IdMismatch);
    }

    if doc.verification_method.is_empty() {
        return Err(AuthReason::NoVerificationMethod);
    }

    let expected_full_id = format!("{iss}#atproto");

    if let Some(target_kid) = kid {
        if target_kid != "#atproto" && target_kid != expected_full_id {
            return Err(AuthReason::InvalidKid);
        }
    }

    for vm in &doc.verification_method {
        let id_matches = vm.id == "#atproto" || vm.id == expected_full_id;
        let controller_matches = vm.controller == iss;

        if id_matches && controller_matches {
            return Ok(vm);
        }
    }

    Err(AuthReason::NoVerificationMethod)
}

pub fn select_authority_verification_method<'a>(
    doc: &'a DidDocument,
    authority_did: &str,
    kid: Option<&str>,
) -> Result<&'a VerificationMethod, AuthReason> {
    if doc.id != authority_did {
        return Err(AuthReason::IdMismatch);
    }

    if doc.verification_method.is_empty() {
        return Err(AuthReason::NoVerificationMethod);
    }

    let expected_full_space = format!("{authority_did}#atproto_space");
    let expected_full_atproto = format!("{authority_did}#atproto");

    // Exact dedicated key #atproto_space first, fallback to #atproto
    let dedicated = doc.verification_method.iter().find(|vm| {
        (vm.id == "#atproto_space" || vm.id == expected_full_space)
            && vm.controller == authority_did
    });

    let selected = if let Some(vm) = dedicated {
        vm
    } else {
        doc.verification_method
            .iter()
            .find(|vm| {
                (vm.id == "#atproto" || vm.id == expected_full_atproto)
                    && vm.controller == authority_did
            })
            .ok_or(AuthReason::NoVerificationMethod)?
    };

    if let Some(target_kid) = kid {
        let matches = target_kid == selected.id
            || (target_kid == "#atproto_space" && selected.id == expected_full_space)
            || (target_kid == "#atproto" && selected.id == expected_full_atproto)
            || (target_kid == expected_full_space && selected.id == "#atproto_space")
            || (target_kid == expected_full_atproto && selected.id == "#atproto");

        if !matches {
            return Err(AuthReason::InvalidKid);
        }
    }

    Ok(selected)
}

pub async fn verify_service_jwt(
    state: &AppState,
    token: &str,
    expected_aud: &str,
    expected_lxm: Option<&str>,
) -> Result<AuthenticatedUser, AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized(AuthReason::InvalidJwtFormat));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderEncoding))?;
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsEncoding))?;

    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderJson))?;
    let claims: AtProtoServiceAuthClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsJson))?;

    // 1. Verify typ == "JWT"
    match &header.typ {
        Some(t) if t == "JWT" => {}
        _ => return Err(AppError::Unauthorized(AuthReason::InvalidTyp)),
    }

    // 2. Verify alg
    if header.alg != "ES256" && header.alg != "ES256K" {
        return Err(AppError::Unauthorized(AuthReason::UnsupportedAlg));
    }

    // 3. Verify iat and exp
    let iat = claims
        .iat
        .ok_or(AppError::Unauthorized(AuthReason::MissingIat))?;
    let exp = claims.exp;

    let now = Utc::now().timestamp();

    // iat <= now (strictly now or past; no future clock skew allowed)
    if iat > now {
        return Err(AppError::Unauthorized(AuthReason::FutureIat));
    }

    // now < exp (exp == now is expired!)
    if exp <= now {
        return Err(AppError::Unauthorized(AuthReason::Expired));
    }

    // Lifetime checks: exp > iat and exp - iat <= 60s
    if exp <= iat {
        return Err(AppError::Unauthorized(AuthReason::Expired));
    }
    match exp.checked_sub(iat) {
        Some(lifetime) if lifetime <= 60 => {}
        _ => return Err(AppError::Unauthorized(AuthReason::LifetimeExceeded)),
    }

    // 4. Verify audience
    if claims.aud != expected_aud {
        return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
    }

    // 5. Verify lxm
    let lxm = claims
        .lxm
        .ok_or(AppError::Unauthorized(AuthReason::MissingLxm))?;
    if let Some(expected) = expected_lxm {
        if lxm != expected {
            return Err(AppError::Unauthorized(AuthReason::LxmMismatch));
        }
    }

    // 6. Verify jti
    let jti = claims
        .jti
        .filter(|s| !s.is_empty())
        .ok_or(AppError::Unauthorized(AuthReason::MissingJti))?;

    // 7. Resolve DID and select verification method
    let did_doc = state
        .did_resolver
        .resolve(&claims.iss)
        .await
        .map_err(AppError::Unauthorized)?;

    let verify_with_doc = |doc: &DidDocument,
                           kid: Option<&str>,
                           alg: &str,
                           signing_input: &[u8],
                           sig_bytes: &[u8]|
     -> Result<(), AuthReason> {
        let vm = select_verification_method(doc, &claims.iss, kid)?;
        let key = parse_verification_key(vm)?;
        match (&key, alg) {
            (ParsedVerifyingKey::P256(_), "ES256") => {}
            (ParsedVerifyingKey::Secp256k1(_), "ES256K") => {}
            _ => return Err(AuthReason::AlgKeyMismatch),
        }
        key.verify(signing_input, sig_bytes)?;
        Ok(())
    };

    // 8. Verify cryptographic signature
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidSignatureFormat))?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    if let Err(_first_err) = verify_with_doc(
        &did_doc,
        header.kid.as_deref(),
        header.alg.as_str(),
        signing_input.as_bytes(),
        &sig_bytes,
    ) {
        // If verification fails with cached key or algorithm mismatched, try resolving fresh from upstream (enforcing <= 60s revocation SLO)
        let fresh_doc = state
            .did_resolver
            .resolve_fresh(&claims.iss)
            .await
            .map_err(AppError::Unauthorized)?;
        verify_with_doc(
            &fresh_doc,
            header.kid.as_deref(),
            header.alg.as_str(),
            signing_input.as_bytes(),
            &sig_bytes,
        )
        .map_err(AppError::Unauthorized)?;
    }
    // 9. Enforce single-use JTI replay protection
    let expires_at = DateTime::from_timestamp(claims.exp, 0)
        .ok_or(AppError::Unauthorized(AuthReason::InvalidClaimsJson))?;
    let fresh = db::consume_jti_nonce(&state.db, &jti, &claims.iss, &claims.aud, expires_at)
        .await
        .map_err(AppError::Database)?;

    if !fresh {
        return Err(AppError::Unauthorized(AuthReason::ReplayedJti));
    }

    Ok(AuthenticatedUser {
        did: claims.iss,
        lxm,
    })
}

/// Axum authentication middleware.
pub async fn authenticate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::Unauthorized(AuthReason::MissingHeader))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .ok_or(AppError::Unauthorized(AuthReason::InvalidHeader))?;

    let path = request.uri().path();
    let expected_lxm = path
        .strip_prefix("/xrpc/")
        .map(|s| s.trim_start_matches('/'));
    let user = verify_service_jwt(&state, token, &state.config.service_did, expected_lxm).await?;

    request.extensions_mut().insert(user);
    Ok(next.run(request).await)
}

// Extractor for AuthenticatedUser from request extensions
#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedUser>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "Unauthorized"))
    }
}

fn urlencoding_decode(s: &str) -> Result<String, AuthReason> {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.as_bytes().iter().copied();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next().ok_or(AuthReason::DidResolutionFailed)?;
            let h2 = chars.next().ok_or(AuthReason::DidResolutionFailed)?;
            let h1_val = (h1 as char)
                .to_digit(16)
                .ok_or(AuthReason::DidResolutionFailed)? as u8;
            let h2_val = (h2 as char)
                .to_digit(16)
                .ok_or(AuthReason::DidResolutionFailed)? as u8;
            bytes.push((h1_val << 4) | h2_val);
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).map_err(|_| AuthReason::DidResolutionFailed)
}

/// Check if an IP address is in a private, loopback, or otherwise restricted range
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

/// Check if an IPv4 address is private/restricted
pub fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();

    // 0.0.0.0/8
    if octets[0] == 0 {
        return true;
    }
    // 127.0.0.0/8
    if ip.is_loopback() || octets[0] == 127 {
        return true;
    }
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 100.64.0.0/10
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }
    // 169.254.0.0/16
    if ip.is_link_local() || (octets[0] == 169 && octets[1] == 254) {
        return true;
    }
    // IETF Protocol Assignments: 192.0.0.0/24
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        // 192.0.0.9 (PCP Anycast, RFC 7723) and 192.0.0.10 (TURN Anycast, RFC 8155) are global exceptions
        if octets[3] != 9 && octets[3] != 10 {
            return true;
        }
    }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return true;
    }
    // 192.88.99.0/24
    if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
        return true;
    }
    // 198.18.0.0/15
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return true;
    }
    // 224.0.0.0/4
    if ip.is_multicast() || (octets[0] >= 224 && octets[0] <= 239) {
        return true;
    }
    // 240.0.0.0/4
    if octets[0] >= 240 {
        return true;
    }
    if ip.is_broadcast() {
        return true;
    }

    false
}

/// Check if an IPv6 address is private/restricted
pub fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }

    if ip.is_multicast() {
        return true;
    }
    let segments = ip.segments();
    if (segments[0] & 0xff00) == 0xff00 {
        return true;
    }
    // Unique local: fc00::/7
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-local: fe80::/10
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // Deprecated Site-Local: fec0::/10
    if (segments[0] & 0xffc0) == 0xfec0 {
        return true;
    }
    // IETF Protocol Assignments: 2001::/23
    if segments[0] == 0x2001 && segments[1] <= 0x01ff {
        // Check named IANA globally reachable exceptions inside 2001::/23:
        // 1. 2001:1::1/128 (PCP Anycast, RFC 7723)
        // 2. 2001:1::2/128 (TURN Anycast, RFC 8155)
        // 3. 2001:1::3/128 (DNS-SD Anycast)
        let is_2001_1_anycast = segments[1] == 1
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0
            && segments[6] == 0
            && (segments[7] == 1 || segments[7] == 2 || segments[7] == 3);
        // 4. 2001:3::/32 (AMT, RFC 7450)
        let is_2001_3 = segments[1] == 3;
        // 5. 2001:4:112::/48 (AS112-v6, RFC 7535)
        let is_2001_4_112 = segments[1] == 4 && segments[2] == 0x0112;
        // 6. 2001:20::/28 (ORCHIDv2, RFC 7343)
        let is_2001_20 = (segments[1] & 0xfff0) == 0x0020;
        // 7. 2001:30::/28 (Drone Remote ID DETs, RFC 9374)
        let is_2001_30 = (segments[1] & 0xfff0) == 0x0030;

        if !is_2001_1_anycast && !is_2001_3 && !is_2001_4_112 && !is_2001_20 && !is_2001_30 {
            return true;
        }
    }
    // Documentation: 2001:db8::/32
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }
    // Documentation: 3fff::/20
    if segments[0] == 0x3fff && (segments[1] & 0xf000) == 0x0000 {
        return true;
    }
    // Discard / dummy: 100::/64 & 100:0:0:1::/64
    if segments[0] == 0x0100
        && segments[1] == 0
        && segments[2] == 0
        && (segments[3] == 0 || segments[3] == 1)
    {
        return true;
    }
    // Translation: 64:ff9b:1::/48
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001 {
        return true;
    }
    // Translation: 64:ff9b::/96
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        return true;
    }
    // 6to4: 2002::/16
    if segments[0] == 0x2002 {
        return true;
    }
    // SRv6: 5f00::/16
    if segments[0] == 0x5f00 {
        return true;
    }
    // IPv4-mapped: ::ffff:0:0/96
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&ipv4);
    }
    // SIIT: ::ffff:0:0:0/96
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        let octet0 = (segments[6] >> 8) as u8;
        let octet1 = (segments[6] & 0xff) as u8;
        let octet2 = (segments[7] >> 8) as u8;
        let octet3 = (segments[7] & 0xff) as u8;
        return is_private_ipv4(&Ipv4Addr::new(octet0, octet1, octet2, octet3));
    }

    false
}

pub fn is_localhost_hostname(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    let trimmed = lower.trim_end_matches('.');

    trimmed == "localhost"
        || trimmed.ends_with(".localhost")
        || trimmed.ends_with(".local")
        || trimmed.ends_with(".internal")
        || trimmed.ends_with(".lan")
        || trimmed.ends_with(".home.arpa")
        || trimmed.ends_with(".corp")
        || trimmed.ends_with(".onion")
        || trimmed.ends_with(".invalid")
        || trimmed.ends_with(".test")
        || trimmed.ends_with(".example")
}

pub fn is_loopback_or_localhost(host: &str) -> bool {
    if is_localhost_hostname(host) {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    false
}
