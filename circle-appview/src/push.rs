//! Direct Push Client for Circle AppView
//!
//! Delivers content-free push notification triggers directly from the AppView.
//! Payloads contain only recipient DID: no post text, Circle name, actor name,
//! record URI, or blob URL.

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

#[derive(Clone)]
pub struct CirclePushClient {
    pub push_url: Option<String>,
    pub service_did: String,
    pub key_id: String,
    pub audience: Option<String>,
    signing_key: SigningKey,
    http_client: reqwest::Client,
}

impl CirclePushClient {
    pub fn new(
        push_url: Option<String>,
        service_did: String,
        key_id: String,
        audience: Option<String>,
        signing_key: SigningKey,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            push_url,
            service_did,
            key_id,
            audience,
            signing_key,
            http_client,
        }
    }

    /// Mints a signed ES256 service authorization JWT for `blue.catbird.circle.push`
    pub fn mint_service_jwt(&self) -> Result<String, AppError> {
        let aud = self.audience.as_deref().unwrap_or(&self.service_did);
        let header = json!({
            "alg": "ES256",
            "typ": "atproto-service-auth+jwt",
            "kid": self.key_id
        });

        let now = Utc::now().timestamp();
        let jti = Uuid::new_v4().to_string();
        let claims = json!({
            "iss": self.service_did,
            "aud": aud,
            "exp": now + 60,
            "iat": now,
            "jti": jti,
            "lxm": "blue.catbird.circle.push"
        });

        let header_str = serde_json::to_string(&header)
            .map_err(|e| AppError::Internal(format!("Failed to serialize JWT header: {e}")))?;
        let claims_str = serde_json::to_string(&claims)
            .map_err(|e| AppError::Internal(format!("Failed to serialize JWT claims: {e}")))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_str.as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_str.as_bytes());
        let signing_input = format!("{header_b64}.{claims_b64}");

        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_bytes = signature.to_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Delivers a generic content-free circle_activity push trigger for the given recipient DID.
    pub async fn deliver_circle_activity(&self, recipient_did: &str) -> Result<usize, AppError> {
        let push_url = match &self.push_url {
            Some(url) if !url.trim().is_empty() => url,
            _ => {
                tracing::debug!("Push URL not configured; skipping push delivery");
                return Ok(0);
            }
        };

        let token = self.mint_service_jwt()?;
        let payload = CirclePushPayload {
            recipient_did: recipient_did.to_string(),
        };

        let res = self
            .http_client
            .post(push_url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Push request failed: {e}")))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            tracing::warn!(status = %status, body = %body, "Push endpoint returned error");
            return Err(AppError::Internal(format!(
                "Push endpoint error {status}: {body}"
            )));
        }

        let push_res: CirclePushResponse = res
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid push response JSON: {e}")))?;

        Ok(push_res.delivered)
    }
}
