//! Circle push notification handler
//!
//! Exposes internal push triggering for Circle AppView notifications.

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CirclePushRequest {
    #[serde(rename = "recipientDid", alias = "recipient_did")]
    pub recipient_did: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CirclePushResponse {
    pub status: &'static str,
    pub delivered: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct ServiceAuthClaims {
    iss: String,
    aud: String,
    exp: i64,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    lxm: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwtHeader {
    #[serde(default)]
    typ: Option<String>,
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

pub async fn handle_circle_push(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<CirclePushRequest>,
) -> AppResult<Json<CirclePushResponse>> {
    // 1. Extract and verify service authorization header
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".into()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header format".into()))?;

    verify_circle_service_jwt(&state, token).await?;

    let delivered = if let Some(push_services) = &state.push {
        push_services
            .deliver_circle_activity(&input.recipient_did)
            .await
            .map_err(|_e| {
                tracing::warn!("circle push delivery failed");
                AppError::Upstream {
                    status: StatusCode::BAD_GATEWAY.as_u16(),
                    message: "Circle push delivery failed".into(),
                }
            })?
    } else {
        0
    };

    Ok(Json(CirclePushResponse {
        status: "ok",
        delivered,
    }))
}

async fn verify_circle_service_jwt(state: &AppState, token: &str) -> AppResult<()> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized("Invalid JWT format".into()));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::Unauthorized("Invalid header base64".into()))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Unauthorized("Invalid header JSON".into()))?;

    if header.typ.as_deref() != Some("JWT") {
        return Err(AppError::Unauthorized("Invalid or missing typ header; must be 'JWT'".into()));
    }

    if header.alg != "ES256" {
        return Err(AppError::Unauthorized("Unsupported JWT algorithm; must be ES256".into()));
    }

    let kid = header.kid.as_deref().unwrap_or("").trim();
    if kid.is_empty() {
        return Err(AppError::Unauthorized("Missing or empty kid header".into()));
    }
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::Unauthorized("Invalid claims base64".into()))?;
    let claims: ServiceAuthClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::Unauthorized("Invalid claims JSON".into()))?;

    let now = Utc::now().timestamp();

    // Verify expiration
    if claims.exp <= now {
        return Err(AppError::Unauthorized("JWT expired".into()));
    }

    // Verify iat
    let iat = claims
        .iat
        .ok_or_else(|| AppError::Unauthorized("Missing iat claim".into()))?;
    if iat > now + 30 {
        return Err(AppError::Unauthorized("JWT iat in future".into()));
    }

    // Verify lifetime <= 300s
    if claims.exp - iat > 300 {
        return Err(AppError::Unauthorized("JWT lifetime exceeds 300s".into()));
    }

    // Verify jti
    if claims.jti.as_deref().unwrap_or("").trim().is_empty() {
        return Err(AppError::Unauthorized("Missing jti claim".into()));
    }

    // Verify lxm is blue.catbird.circle.push
    if claims.lxm.as_deref() != Some("blue.catbird.circle.push") {
        return Err(AppError::Unauthorized("Invalid or missing lxm claim".into()));
    }

    // Verify audience matches Nest's configured push service DID or client ID (never issuer DID)
    let push_did = state.config.push.service_did.as_deref();
    let client_id = &state.config.oauth.client_id;

    let aud_matches = claims.aud == *client_id
        || push_did.map(|d| d == claims.aud).unwrap_or(false);

    if !aud_matches {
        return Err(AppError::Unauthorized("Audience mismatch".into()));
    }

    // Verify exact issuer and key ID match configured Circle service DID
    let circle_service_did = &state.config.circle.service_did;
    if claims.iss != *circle_service_did {
        return Err(AppError::Unauthorized("Issuer mismatch".into()));
    }

    if kid != circle_service_did {
        return Err(AppError::Unauthorized("Key ID (kid) mismatch".into()));
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AppError::Unauthorized("Invalid signature base64".into()))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = p256::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|_| AppError::Unauthorized("Invalid signature format".into()))?;

    let verifying_key = state
        .circle_verifying_key
        .as_deref()
        .ok_or_else(|| AppError::Unauthorized("Circle verifying key not available".into()))?;

    use p256::ecdsa::signature::Verifier;
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| AppError::Unauthorized("Invalid JWT signature".into()))?;

    Ok(())
}
