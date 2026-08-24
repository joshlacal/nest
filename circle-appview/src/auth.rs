use axum::{
    extract::{FromRequestParts, Request, State},
    http::{header, request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

use crate::config::AppState;
use crate::db;
use crate::error::AppError;

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

pub struct DidResolver {
    plc_directory_url: String,
    http_client: reqwest::Client,
    cache: RwLock<HashMap<String, (DidDocument, DateTime<Utc>)>>,
}

impl DidResolver {
    pub fn new(plc_directory_url: String, http_client: reqwest::Client) -> Self {
        Self {
            plc_directory_url,
            http_client,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Insert or override a DID document directly in cache (useful for testing)
    pub fn insert_cached(&self, did: String, doc: DidDocument) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(did, (doc, Utc::now() + chrono::Duration::hours(24)));
        }
    }

    pub async fn resolve(&self, did: &str) -> Result<DidDocument, AppError> {
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
            return Err(AppError::Unauthorized(format!("Unsupported DID method: {did}")));
        };

        // Cache for 1 hour
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(did.to_string(), (doc.clone(), Utc::now() + chrono::Duration::hours(1)));
        }

        Ok(doc)
    }

    async fn resolve_plc(&self, did: &str) -> Result<DidDocument, AppError> {
        let url = format!("{}/{}", self.plc_directory_url.trim_end_matches('/'), did);
        let resp = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::Unauthorized(format!("Failed to resolve PLC DID: {e}")))?;

        if !resp.status().is_success() {
            return Err(AppError::Unauthorized(format!(
                "PLC directory returned status {}",
                resp.status()
            )));
        }

        resp.json::<DidDocument>()
            .await
            .map_err(|e| AppError::Unauthorized(format!("Failed to parse PLC DID document: {e}")))
    }

    async fn resolve_web(&self, did: &str) -> Result<DidDocument, AppError> {
        let raw = did.strip_prefix("did:web:").unwrap_or(did);
        let parts: Vec<&str> = raw.split(':').collect();
        if parts.is_empty() {
            return Err(AppError::Unauthorized("Invalid did:web format".into()));
        }

        let domain = parts[0];
        // SSRF check on hostname / IP
        if domain == "localhost" || domain.ends_with(".localhost") || domain.ends_with(".local") {
            return Err(AppError::Unauthorized("Private did:web domain not allowed".into()));
        }
        if let Ok(ip) = domain.parse::<IpAddr>() {
            if ip.is_loopback() || ip.is_unspecified() {
                return Err(AppError::Unauthorized("Private did:web IP not allowed".into()));
            }
        }

        let url = if parts.len() == 1 {
            format!("https://{}/.well-known/did.json", domain)
        } else {
            let path = parts[1..].join("/");
            format!("https://{}/{}/did.json", domain, path)
        };

        let resp = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::Unauthorized(format!("Failed to resolve web DID: {e}")))?;

        if !resp.status().is_success() {
            return Err(AppError::Unauthorized(format!(
                "did:web host returned status {}",
                resp.status()
            )));
        }

        resp.json::<DidDocument>()
            .await
            .map_err(|e| AppError::Unauthorized(format!("Failed to parse web DID document: {e}")))
    }
}

pub fn select_verification_method<'a>(
    doc: &'a DidDocument,
    kid: Option<&str>,
) -> Result<&'a VerificationMethod, AppError> {
    if doc.verification_method.is_empty() {
        return Err(AppError::Unauthorized("DID document has no verification methods".into()));
    }

    if let Some(target_kid) = kid {
        let target_trimmed = target_kid.trim_start_matches('#');
        for vm in &doc.verification_method {
            if vm.id == target_kid
                || vm.id.ends_with(target_kid)
                || vm.id.ends_with(&format!("#{target_trimmed}"))
            {
                return Ok(vm);
            }
        }
        Err(AppError::Unauthorized(format!(
            "No verification method matches kid {target_kid}"
        )))
    } else {
        // Look for #atproto verification method
        for vm in &doc.verification_method {
            if vm.id.ends_with("#atproto") {
                return Ok(vm);
            }
        }
        // Fallback to the first verification method if only one exists
        if doc.verification_method.len() == 1 {
            Ok(&doc.verification_method[0])
        } else {
            Err(AppError::Unauthorized(
                "Missing kid and no #atproto verification method found".into(),
            ))
        }
    }
}

pub async fn verify_service_jwt(
    state: &AppState,
    token: &str,
    expected_aud: &str,
    expected_lxm: Option<&str>,
) -> Result<AuthenticatedUser, AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized("Invalid JWT format".into()));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| AppError::Unauthorized(format!("Invalid base64 header: {e}")))?;
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AppError::Unauthorized(format!("Invalid base64 payload: {e}")))?;

    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| AppError::Unauthorized(format!("Invalid header JSON: {e}")))?;
    let claims: AtProtoServiceAuthClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|e| AppError::Unauthorized(format!("Invalid claims JSON: {e}")))?;

    // 1. Check expiration
    let now = Utc::now().timestamp();
    if claims.exp < now {
        return Err(AppError::Unauthorized("Token has expired".into()));
    }

    // 2. Check audience
    if claims.aud != expected_aud {
        return Err(AppError::Unauthorized(format!(
            "Audience mismatch: expected {expected_aud}, got {}",
            claims.aud
        )));
    }

    // 3. Check lxm
    let lxm = claims
        .lxm
        .ok_or_else(|| AppError::Unauthorized("Missing lxm claim in service auth token".into()))?;
    if let Some(expected) = expected_lxm {
        if lxm != expected {
            return Err(AppError::Unauthorized(format!(
                "lxm mismatch: expected {expected}, got {lxm}"
            )));
        }
    }

    // 4. Check jti presence
    let jti = claims
        .jti
        .ok_or_else(|| AppError::Unauthorized("Missing jti claim in service auth token".into()))?;

    // 5. Verify signature
    if header.alg != "ES256" {
        return Err(AppError::Unauthorized(format!(
            "Unsupported algorithm: {}",
            header.alg
        )));
    }

    let did_doc = state.did_resolver.resolve(&claims.iss).await?;
    let vm = select_verification_method(&did_doc, header.kid.as_deref())?;

    let jwk = vm
        .public_key_jwk
        .as_ref()
        .ok_or_else(|| AppError::Unauthorized("Missing publicKeyJwk in verification method".into()))?;

    if jwk.kty != "EC" || !jwk.crv.eq_ignore_ascii_case("P-256") {
        return Err(AppError::Unauthorized(format!(
            "Expected EC P-256 key, got {} {}",
            jwk.kty, jwk.crv
        )));
    }

    let x = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|e| AppError::Unauthorized(format!("Invalid JWK x coordinate: {e}")))?;
    let y_str = jwk
        .y
        .as_ref()
        .ok_or_else(|| AppError::Unauthorized("Missing JWK y coordinate".into()))?;
    let y = URL_SAFE_NO_PAD
        .decode(y_str)
        .map_err(|e| AppError::Unauthorized(format!("Invalid JWK y coordinate: {e}")))?;

    if x.len() != 32 || y.len() != 32 {
        return Err(AppError::Unauthorized("Invalid P-256 coordinate length".into()));
    }

    let mut x_bytes = p256::FieldBytes::default();
    x_bytes.copy_from_slice(&x);
    let mut y_bytes = p256::FieldBytes::default();
    y_bytes.copy_from_slice(&y);
    let ep = EncodedPoint::from_affine_coordinates(&x_bytes, &y_bytes, false);
    let vk = VerifyingKey::from_encoded_point(&ep)
        .map_err(|_| AppError::Unauthorized("Invalid P-256 curve point".into()))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| AppError::Unauthorized(format!("Invalid base64 signature: {e}")))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| AppError::Unauthorized("Invalid ES256 signature length/format".into()))?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| AppError::Unauthorized("Invalid cryptographic signature".into()))?;

    // 6. Enforce single-use JTI replay protection
    let expires_at = DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(Utc::now);
    let fresh = db::consume_jti_nonce(&state.db, &jti, &claims.iss, &claims.aud, expires_at)
        .await
        .map_err(AppError::Database)?;

    if !fresh {
        return Err(AppError::Unauthorized(
            "Replayed token (JTI nonce already consumed)".into(),
        ));
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
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".into()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .ok_or_else(|| AppError::Unauthorized("Authorization header must be Bearer token".into()))?;

    // Extract expected lxm from URI path if it is an XRPC endpoint
    let path = request.uri().path();
    let expected_lxm = path.strip_prefix("/xrpc/").map(|s| s.trim_start_matches('/'));

    let user = verify_service_jwt(
        &state,
        token,
        &state.config.service_did,
        expected_lxm,
    )
    .await?;

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
