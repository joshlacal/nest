//! Nest Push Client for Circle AppView
//!
//! Authenticates and sends generic push notification triggers to Nest's internal push endpoint.

use crate::error::AppError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CirclePushPayload {
    #[serde(rename = "recipientDid", alias = "recipient_did")]
    pub recipient_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CirclePushResponse {
    pub status: String,
    #[serde(default)]
    pub delivered: usize,
}

pub struct NestPushClient {
    push_url: String,
    service_did: String,
    audience: String,
    signing_key: SigningKey,
    http_client: reqwest::Client,
}

impl NestPushClient {
    pub fn new(
        push_url: String,
        service_did: String,
        audience: String,
        signing_key: SigningKey,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            push_url,
            service_did,
            audience,
            signing_key,
            http_client,
        }
    }

    /// Mints a signed ES256 service authorization JWT for `blue.catbird.circle.push`
    pub fn mint_service_jwt(&self) -> Result<String, AppError> {
        let now = Utc::now().timestamp();
        let jti = Uuid::new_v4().to_string();

        let header = json!({
            "alg": "ES256",
            "typ": "JWT"
        });

        let claims = json!({
            "iss": self.service_did,
            "aud": self.audience,
            "exp": now + 60,
            "iat": now,
            "jti": jti,
            "lxm": "blue.catbird.circle.push"
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|e| {
            AppError::Internal(format!("Failed to serialize JWT header: {e}"))
        })?);
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).map_err(|e| {
            AppError::Internal(format!("Failed to serialize JWT claims: {e}"))
        })?);
        let signing_input = format!("{header_b64}.{claims_b64}");

        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Delivers a generic circle_activity push trigger to Nest for the given recipient DID.
    pub async fn deliver_circle_activity(&self, recipient_did: &str) -> Result<usize, AppError> {
        let jwt = self.mint_service_jwt()?;
        let body = json!({
            "recipient_did": recipient_did
        });

        let resp = self
            .http_client
            .post(&self.push_url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {jwt}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to dispatch push to Nest: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Nest push endpoint returned {status}: {err_body}"
            )));
        }

        let push_resp: CirclePushResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid response JSON from Nest push: {e}")))?;

        Ok(push_resp.delivered)
    }
}
