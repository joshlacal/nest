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
}

pub enum ParsedVerifyingKey {
    P256(p256::ecdsa::VerifyingKey),
    Secp256k1(k256::ecdsa::VerifyingKey),
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
        }
    }
}

pub fn parse_verification_key(vm: &VerificationMethod) -> Result<ParsedVerifyingKey, AuthReason> {
    if let Some(multibase_str) = &vm.public_key_multibase {
        if vm.r#type != "Multikey" {
            return Err(AuthReason::InvalidKeyType);
        }

        let (_base, decoded) =
            multibase::decode(multibase_str).map_err(|_| AuthReason::InvalidMultikey)?;

        // P-256 multicodec prefix: 0x1200 -> varint [0x80, 0x24]
        if decoded.starts_with(&[0x80, 0x24]) {
            let raw_key = &decoded[2..];
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(raw_key)
                .map_err(|_| AuthReason::InvalidCoordinates)?;
            return Ok(ParsedVerifyingKey::P256(vk));
        }

        // Secp256k1 multicodec prefix: 0xe7 -> varint [0xe7, 0x01]
        if decoded.starts_with(&[0xe7, 0x01]) {
            let raw_key = &decoded[2..];
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(raw_key)
                .map_err(|_| AuthReason::InvalidCoordinates)?;
            return Ok(ParsedVerifyingKey::Secp256k1(vk));
        }

        return Err(AuthReason::InvalidKeyType);
    }

    if let Some(jwk) = &vm.public_key_jwk {
        if vm.r#type != "JsonWebKey2020" && vm.r#type != "EcdsaSecp256k1VerificationKey2019" {
            return Err(AuthReason::InvalidKeyType);
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
            if vm.r#type != "JsonWebKey2020" {
                return Err(AuthReason::InvalidKeyType);
            }
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

        return Err(AuthReason::InvalidCurve);
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
}

#[derive(Debug, Default, Clone)]
pub struct DefaultDidWebTransport;

impl DidWebTransport for DefaultDidWebTransport {
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
        Box::pin(async move {
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(5))
                .resolve(&host, pinned_addr)
                .build()
                .map_err(|_| AuthReason::DidResolutionFailed)?;

            let resp = client
                .get(&url)
                .send()
                .await
                .map_err(|_| AuthReason::DidResolutionFailed)?;

            if !resp.status().is_success() {
                return Err(AuthReason::DidResolutionFailed);
            }

            resp.json::<DidDocument>()
                .await
                .map_err(|_| AuthReason::DidDocumentInvalid)
        })
    }
}
pub struct DidResolver {
    plc_directory_url: String,
    http_client: reqwest::Client,
    web_transport: Arc<dyn DidWebTransport>,
    cache: RwLock<HashMap<String, (DidDocument, DateTime<Utc>)>>,
}

impl DidResolver {
    pub fn new(plc_directory_url: String, http_client: reqwest::Client) -> Self {
        Self {
            plc_directory_url,
            http_client,
            web_transport: Arc::new(DefaultDidWebTransport),
            cache: RwLock::new(HashMap::new()),
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
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Insert or override a DID document directly in cache (useful for testing)
    pub fn insert_cached(&self, did: String, doc: DidDocument) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(did, (doc, Utc::now() + chrono::Duration::hours(24)));
        }
    }


    pub async fn resolve(&self, did: &str) -> Result<DidDocument, AuthReason> {
        // Check in-memory cache
        if let Ok(cache) = self.cache.read() {
            if let Some((doc, expires_at)) = cache.get(did) {
                if *expires_at > Utc::now() {
                    return Ok(doc.clone());
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

        // Cache for 1 hour
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                did.to_string(),
                (doc.clone(), Utc::now() + chrono::Duration::hours(1)),
            );
        }

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

        resp.json::<DidDocument>()
            .await
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

        self.web_transport
            .fetch(&url, &hostname, pinned_addr)
            .await
    }
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
    if (exp - iat) > 60 {
        return Err(AppError::Unauthorized(AuthReason::LifetimeExceeded));
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

    let vm = select_verification_method(&did_doc, &claims.iss, header.kid.as_deref())
        .map_err(AppError::Unauthorized)?;

    let key = parse_verification_key(vm).map_err(AppError::Unauthorized)?;

    // Verify algorithm matches key curve
    match (&key, header.alg.as_str()) {
        (ParsedVerifyingKey::P256(_), "ES256") => {}
        (ParsedVerifyingKey::Secp256k1(_), "ES256K") => {}
        _ => return Err(AppError::Unauthorized(AuthReason::AlgKeyMismatch)),
    }
    // 8. Verify cryptographic signature
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidSignatureFormat))?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    key.verify(signing_input.as_bytes(), &sig_bytes)
        .map_err(AppError::Unauthorized)?;

    // 9. Enforce single-use JTI replay protection
    let expires_at = DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(Utc::now);
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
    let expected_lxm = path.strip_prefix("/xrpc/").map(|s| s.trim_start_matches('/'));

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
    // 192.0.0.0/24
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
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
    // IETF Protocol Assignments: 2001::/23 (covers 2001::/32, 2001:2::/48, 2001:5::/32, 2001:10::/28, 2001:20::/28, etc.)
    if segments[0] == 0x2001 && segments[1] <= 0x01ff {
        return true;
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

fn is_localhost_hostname(host: &str) -> bool {
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
