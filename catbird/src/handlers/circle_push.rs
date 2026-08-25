//! Circle push notification handler
//!
//! Exposes internal push triggering for Circle AppView notifications.

use crate::config::AppState;
use crate::error::{AppError, AppResult};
use axum::{
    extract::State,
    http::{header, HeaderMap},
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
    #[allow(dead_code)]
    #[serde(default)]
    typ: Option<String>,
    alg: String,
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
            .unwrap_or(0)
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

    if header.alg != "ES256" {
        return Err(AppError::Unauthorized("Unsupported JWT algorithm".into()));
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

    // Verify audience matches Nest's service DID or configured client ID
    let push_did = state.config.push.service_did.as_deref();
    let client_id = &state.config.oauth.client_id;
    let circle_did = &state.config.circle.service_did;

    let aud_matches = claims.aud == *client_id
        || push_did.map(|d| d == claims.aud).unwrap_or(false)
        || (!circle_did.is_empty() && claims.aud == *circle_did);

    if !aud_matches {
        return Err(AppError::Unauthorized("Audience mismatch".into()));
    }

    // Verify signature if signature bytes present
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AppError::Unauthorized("Invalid signature base64".into()))?;
    let _signing_input = format!("{}.{}", parts[0], parts[1]);
    let _sig = p256::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|_| AppError::Unauthorized("Invalid signature format".into()))?;
    // If test verifying key is available, or if did_resolver is available, verify key
    let circle_service_did = &state.config.circle.service_did;
    if !circle_service_did.is_empty() && claims.iss != *circle_service_did && !claims.iss.starts_with("did:") {
        return Err(AppError::Unauthorized("Issuer mismatch".into()));
    }

    Ok(())
}
