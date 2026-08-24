use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::auth::DidDocument;
use crate::config::AppState;
use crate::error::{AppError, AuthReason};

#[derive(Clone)]
pub struct ActiveSpaceCredential {
    pub token: String,
    pub dpop_key: p256::ecdsa::SigningKey,
    pub expires_at: DateTime<Utc>,
}

#[derive(Default)]
pub struct CredentialStore {
    values: RwLock<HashMap<String, ActiveSpaceCredential>>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self {
            values: RwLock::new(HashMap::new()),
        }
    }

    pub async fn insert(&self, space: String, cred: ActiveSpaceCredential) {
        let mut lock = self.values.write().await;
        lock.insert(space, cred);
    }

    pub async fn get(&self, space: &str) -> Option<ActiveSpaceCredential> {
        let lock = self.values.read().await;
        if let Some(cred) = lock.get(space) {
            if cred.expires_at > Utc::now() {
                return Some(cred.clone());
            }
        }
        None
    }

    pub async fn remove(&self, space: &str) {
        let mut lock = self.values.write().await;
        lock.remove(space);
    }

    pub async fn count(&self) -> usize {
        let lock = self.values.read().await;
        lock.len()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DelegationTokenClaims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub iat: Option<i64>,
}

pub fn parse_delegation_token(token: &str) -> Result<DelegationTokenClaims, AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::InvalidRequest("Invalid delegation token format".into()));
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::InvalidRequest("Invalid delegation token payload encoding".into()))?;

    let claims: DelegationTokenClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid delegation token claims JSON".into()))?;

    Ok(claims)
}

pub fn extract_authority_did(space_uri: &str) -> Result<String, AppError> {
    let stripped = space_uri
        .strip_prefix("at://")
        .ok_or_else(|| AppError::InvalidRequest("Invalid Space URI: must start with at://".into()))?;
    let did = stripped
        .split('/')
        .next()
        .ok_or_else(|| AppError::InvalidRequest("Invalid Space URI: missing authority DID".into()))?;
    if did.is_empty() {
        return Err(AppError::InvalidRequest("Invalid Space URI: empty authority DID".into()));
    }
    Ok(did.to_string())
}

pub fn resolve_space_host_endpoint(doc: &DidDocument, authority_did: &str) -> Result<String, AppError> {
    let expected_full_id = format!("{authority_did}#atproto_space_host");
    let expected_short_id = "#atproto_space_host";
    let fallback_full = format!("{authority_did}#atproto_space");
    let fallback_short = "#atproto_space";

    for svc in &doc.service {
        if svc.id == expected_short_id
            || svc.id == expected_full_id
            || svc.id == fallback_short
            || svc.id == fallback_full
            || svc.r#type == "AtprotoSpaceHost"
            || svc.r#type == "AtprotoSpace"
        {
            if !svc.service_endpoint.is_empty() {
                return Ok(svc.service_endpoint.clone());
            }
        }
    }

    Err(AppError::InvalidRequest("No AtprotoSpaceHost service found in DID document".into()))
}

pub async fn activate_space(
    state: &AppState,
    user_did: &str,
    space: &str,
    delegation_token: &str,
    client_attestation: Option<&str>,
) -> Result<DateTime<Utc>, AppError> {
    // 1. Parse and validate delegation token claims (without logging it)
    let claims = parse_delegation_token(delegation_token)?;
    if claims.iss != user_did {
        return Err(AppError::Forbidden("Delegation token issuer does not match authenticated user".into()));
    }
    if claims.sub != space {
        return Err(AppError::InvalidRequest("Delegation token subject does not match requested space".into()));
    }
    let now = Utc::now().timestamp();
    if let Some(exp) = claims.exp {
        if exp <= now {
            return Err(AppError::Unauthorized(AuthReason::Expired));
        }
    }

    // 2. Extract authority DID from space URI
    let authority_did = extract_authority_did(space)?;

    // 3. Resolve authority DID document
    let did_doc = state
        .did_resolver
        .resolve(&authority_did)
        .await
        .map_err(AppError::Unauthorized)?;

    // 4. Resolve #atproto_space_host service endpoint
    let service_endpoint = resolve_space_host_endpoint(&did_doc, &authority_did)?;

    // 5. Exchange credential with Space host via DPoP
    let (credential_jwt, dpop_key, expires_at) = state
        .space_client
        .exchange_credential(
            &service_endpoint,
            space,
            delegation_token,
            client_attestation,
        )
        .await?;

    // 6. Store credential in memory only
    let active_cred = ActiveSpaceCredential {
        token: credential_jwt,
        dpop_key,
        expires_at,
    };
    state.credential_store.insert(space.to_string(), active_cred).await;

    // 7. Ensure circle exists (to prevent foreign key failure), then persist ONLY lease expiry
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, authority_did, display_name, created_at)
        VALUES ($1, $2, 'Circle', now())
        ON CONFLICT (space_uri) DO NOTHING
        "#,
    )
    .bind(space)
    .bind(&authority_did)
    .execute(&state.db)
    .await
    .map_err(AppError::Database)?;

    sqlx::query(
        r#"
        INSERT INTO access_leases (space_uri, member_did, expires_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (space_uri, member_did)
        DO UPDATE SET expires_at = EXCLUDED.expires_at
        "#,
    )
    .bind(space)
    .bind(user_did)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(AppError::Database)?;

    Ok(expires_at)
}
