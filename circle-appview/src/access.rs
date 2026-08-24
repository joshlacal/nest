use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::auth::{
    parse_verification_key, select_verification_method, DidDocument, JwtHeader,
};
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
        if cred.expires_at <= Utc::now() {
            return;
        }

        let mut lock = self.values.write().await;
        // Prune expired credentials under write lock
        let now = Utc::now();
        lock.retain(|_, v| v.expires_at > now);

        if let Some(existing) = lock.get(&space) {
            if cred.expires_at >= existing.expires_at {
                lock.insert(space, cred);
            }
        } else {
            lock.insert(space, cred);
        }
    }

    pub async fn get(&self, space: &str) -> Option<ActiveSpaceCredential> {
        let now = Utc::now();
        {
            let lock = self.values.read().await;
            if let Some(cred) = lock.get(space) {
                if cred.expires_at > now {
                    return Some(cred.clone());
                }
            } else {
                return None;
            }
        }

        // If expired, prune it under write lock
        let mut lock = self.values.write().await;
        if let Some(cred) = lock.get(space) {
            if cred.expires_at <= now {
                lock.remove(space);
            }
        }
        None
    }

    pub async fn remove(&self, space: &str) {
        let mut lock = self.values.write().await;
        lock.remove(space);
    }

    pub async fn count(&self) -> usize {
        let mut lock = self.values.write().await;
        let now = Utc::now();
        lock.retain(|_, v| v.expires_at > now);
        lock.len()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DelegationTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
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

pub fn resolve_space_host_endpoint(
    doc: &DidDocument,
    authority_did: &str,
) -> Result<(String, String), AppError> {
    if doc.id != authority_did {
        return Err(AppError::Unauthorized(AuthReason::IdMismatch));
    }

    let expected_full_id = format!("{authority_did}#atproto_space_host");
    let expected_short_id = "#atproto_space_host";

    // 1. Try exact #atproto_space_host first
    for svc in &doc.service {
        if svc.id == expected_short_id
            || svc.id == expected_full_id
            || svc.r#type == "AtprotoSpaceHost"
        {
            if !svc.service_endpoint.is_empty() {
                return Ok((svc.service_endpoint.clone(), svc.id.clone()));
            }
        }
    }

    // 2. Fallback to exact #atproto_pds
    let pds_full_id = format!("{authority_did}#atproto_pds");
    let pds_short_id = "#atproto_pds";
    for svc in &doc.service {
        if svc.id == pds_short_id
            || svc.id == pds_full_id
            || svc.r#type == "AtprotoPersonalDataServer"
        {
            if !svc.service_endpoint.is_empty() {
                return Ok((svc.service_endpoint.clone(), svc.id.clone()));
            }
        }
    }

    Err(AppError::InvalidRequest(
        "No #atproto_space_host or #atproto_pds service found in authority DID document".into(),
    ))
}

pub fn parse_and_validate_delegation_token(
    token: &str,
    expected_user_did: &str,
    expected_space_uri: &str,
    expected_audience: &str,
    user_doc: &DidDocument,
) -> Result<DelegationTokenClaims, AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::InvalidRequest("Invalid delegation token format".into()));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::InvalidRequest("Invalid delegation token header encoding".into()))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid delegation token header JSON".into()))?;

    match &header.typ {
        Some(t) if t == "atproto-delegation+jwt" || t == "JWT" => {}
        _ => return Err(AppError::Unauthorized(AuthReason::InvalidTyp)),
    }

    if header.alg != "ES256" && header.alg != "ES256K" {
        return Err(AppError::Unauthorized(AuthReason::UnsupportedAlg));
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::InvalidRequest("Invalid delegation token payload encoding".into()))?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid delegation token claims JSON".into()))?;

    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRequest("Missing iss in delegation token claims".into()))?;
    if iss != expected_user_did {
        return Err(AppError::Forbidden(
            "Delegation token issuer does not match authenticated user".into(),
        ));
    }

    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRequest("Missing sub in delegation token claims".into()))?;
    if sub != expected_space_uri {
        return Err(AppError::InvalidRequest(
            "Delegation token subject does not match requested space".into(),
        ));
    }

    let aud = claims
        .get("aud")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized(AuthReason::AudienceMismatch))?;

    let authority_did = extract_authority_did(expected_space_uri)?;
    let space_host_full = format!("{authority_did}#atproto_space_host");
    let pds_full = format!("{authority_did}#atproto_pds");

    let aud_matches = aud == expected_audience
        || aud == authority_did
        || aud == "#atproto_space_host"
        || aud == "#atproto_pds"
        || aud == space_host_full
        || aud == pds_full;

    if !aud_matches {
        return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
    }

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::Unauthorized(AuthReason::MissingExp))?;
    let now = Utc::now().timestamp();
    if exp <= now {
        return Err(AppError::Unauthorized(AuthReason::Expired));
    }

    let iat = claims
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::Unauthorized(AuthReason::MissingIat))?;
    if iat > now + 300 {
        return Err(AppError::Unauthorized(AuthReason::FutureIat));
    }

    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized(AuthReason::MissingJti))?;
    if jti.is_empty() {
        return Err(AppError::Unauthorized(AuthReason::MissingJti));
    }

    // Verify signature using user's DID document
    let vm = select_verification_method(user_doc, expected_user_did, header.kid.as_deref())
        .map_err(AppError::Unauthorized)?;
    let key = parse_verification_key(vm).map_err(AppError::Unauthorized)?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidSignatureFormat))?;

    key.verify(signing_input.as_bytes(), &sig_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::BadSignature))?;

    Ok(DelegationTokenClaims {
        iss: iss.to_string(),
        sub: sub.to_string(),
        aud: aud.to_string(),
        exp,
        iat,
        jti: jti.to_string(),
    })
}

pub async fn activate_space(
    state: &AppState,
    user_did: &str,
    space: &str,
    delegation_token: &str,
    client_attestation: Option<&str>,
) -> Result<DateTime<Utc>, AppError> {
    // 1. Extract authority DID from space URI
    let authority_did = extract_authority_did(space)?;

    // 2. Resolve user DID document
    let user_doc = state
        .did_resolver
        .resolve(user_did)
        .await
        .map_err(AppError::Unauthorized)?;

    // 3. Resolve authority DID document
    let authority_doc = state
        .did_resolver
        .resolve(&authority_did)
        .await
        .map_err(AppError::Unauthorized)?;

    // 4. Resolve #atproto_space_host service endpoint (with #atproto_pds fallback)
    let (service_endpoint, service_id) = resolve_space_host_endpoint(&authority_doc, &authority_did)?;

    // 5. Parse and validate delegation token claims and signature
    parse_and_validate_delegation_token(
        delegation_token,
        user_did,
        space,
        &service_id,
        &user_doc,
    )?;

    // 6. Exchange credential with Space host via DPoP
    let (credential_jwt, dpop_key, expires_at) = state
        .space_client
        .exchange_credential(
            &service_endpoint,
            space,
            delegation_token,
            client_attestation,
            &authority_did,
            &authority_doc,
        )
        .await?;

    // 7. Atomic transaction for lease creation: locks and verifies circle and member state
    let mut tx = state.db.begin().await.map_err(AppError::Database)?;

    // Check if Circle was deleted (tombstone)
    let tombstone: Option<(String,)> = sqlx::query_as(
        "SELECT space_uri FROM circle_tombstones WHERE space_uri = $1",
    )
    .bind(space)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    if tombstone.is_some() {
        return Err(AppError::Forbidden("Circle is deleted".into()));
    }

    // Check member status
    let member_row: Option<(String, i64)> = sqlx::query_as(
        "SELECT status, generation FROM circle_members WHERE space_uri = $1 AND member_did = $2 FOR UPDATE",
    )
    .bind(space)
    .bind(user_did)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    match member_row {
        Some((status, _gen)) => {
            if status == "removed" {
                return Err(AppError::Forbidden(
                    "Member has been removed from Circle".into(),
                ));
            }
        }
        None => {
            if user_did == authority_did {
                sqlx::query(
                    r#"
                    INSERT INTO circles (space_uri, authority_did, display_name, created_at)
                    VALUES ($1, $2, 'Circle', now())
                    ON CONFLICT (space_uri) DO NOTHING
                    "#,
                )
                .bind(space)
                .bind(&authority_did)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;

                sqlx::query(
                    r#"
                    INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at)
                    VALUES ($1, $2, 'active', 0, now())
                    ON CONFLICT (space_uri, member_did) DO NOTHING
                    "#,
                )
                .bind(space)
                .bind(user_did)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;
            } else {
                let circle_exists: Option<(String,)> = sqlx::query_as(
                    "SELECT space_uri FROM circles WHERE space_uri = $1",
                )
                .bind(space)
                .fetch_optional(&mut *tx)
                .await
                .map_err(AppError::Database)?;

                if circle_exists.is_some() {
                    return Err(AppError::Forbidden(
                        "User is not an active member of this Circle".into(),
                    ));
                }

                // Initial circle & active member
                sqlx::query(
                    r#"
                    INSERT INTO circles (space_uri, authority_did, display_name, created_at)
                    VALUES ($1, $2, 'Circle', now())
                    ON CONFLICT (space_uri) DO NOTHING
                    "#,
                )
                .bind(space)
                .bind(&authority_did)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;

                sqlx::query(
                    r#"
                    INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at)
                    VALUES ($1, $2, 'active', 0, now())
                    ON CONFLICT (space_uri, member_did) DO NOTHING
                    "#,
                )
                .bind(space)
                .bind(user_did)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;
            }
        }
    }

    // Persist access lease
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
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    tx.commit().await.map_err(AppError::Database)?;

    // 8. Store credential in memory ONLY after successful transaction commit
    let active_cred = ActiveSpaceCredential {
        token: credential_jwt,
        dpop_key,
        expires_at,
    };
    state.credential_store.insert(space.to_string(), active_cred).await;

    Ok(expires_at)
}
