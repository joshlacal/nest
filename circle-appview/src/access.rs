use crate::auth::{
    parse_verification_key, select_verification_method, DidDocument, JwtHeader, ParsedVerifyingKey,
};
use crate::config::AppState;
use crate::error::{AppError, AuthReason};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};

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
            let cred = lock.get(space)?;
            if cred.expires_at > now {
                return Some(cred.clone());
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

#[derive(Clone)]
struct SpaceLockEntry {
    mutex: Arc<Mutex<()>>,
    waiters: Arc<std::sync::atomic::AtomicUsize>,
}

#[derive(Clone, Default)]
pub struct SpaceLockManager {
    locks: Arc<RwLock<HashMap<String, SpaceLockEntry>>>,
}

impl SpaceLockManager {
    pub fn new() -> Self {
        Self {
            locks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn acquire(&self, space: &str) -> OwnedMutexGuard<()> {
        let (mutex, waiters) = {
            let mut map = self.locks.write().await;
            let entry = map
                .entry(space.to_string())
                .or_insert_with(|| SpaceLockEntry {
                    mutex: Arc::new(Mutex::new(())),
                    waiters: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                });
            (entry.mutex.clone(), entry.waiters.clone())
        };
        waiters.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let guard = mutex.lock_owned().await;
        waiters.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        guard
    }

    pub async fn waiter_count(&self, space: &str) -> usize {
        let map = self.locks.read().await;
        if let Some(entry) = map.get(space) {
            entry.waiters.load(std::sync::atomic::Ordering::SeqCst)
        } else {
            0
        }
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
    let stripped = space_uri.strip_prefix("at://").ok_or_else(|| {
        AppError::InvalidRequest("Invalid Space URI: must start with at://".into())
    })?;
    let did = stripped.split('/').next().ok_or_else(|| {
        AppError::InvalidRequest("Invalid Space URI: missing authority DID".into())
    })?;
    if did.is_empty() {
        return Err(AppError::InvalidRequest(
            "Invalid Space URI: empty authority DID".into(),
        ));
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
        if (svc.id == expected_short_id || svc.id == expected_full_id)
            && !svc.service_endpoint.is_empty()
        {
            return Ok((svc.service_endpoint.clone(), expected_full_id));
        }
    }

    // 2. Fallback to exact #atproto_pds
    let pds_full_id = format!("{authority_did}#atproto_pds");
    let pds_short_id = "#atproto_pds";
    for svc in &doc.service {
        if (svc.id == pds_short_id || svc.id == pds_full_id) && !svc.service_endpoint.is_empty() {
            return Ok((svc.service_endpoint.clone(), pds_full_id));
        }
    }

    Err(AppError::InvalidRequest(
        "No #atproto_space_host or #atproto_pds service found in authority DID document".into(),
    ))
}

pub fn resolve_pds_endpoint(
    doc: &DidDocument,
    author_did: &str,
) -> Result<(String, String), AppError> {
    if doc.id != author_did {
        return Err(AppError::Unauthorized(AuthReason::IdMismatch));
    }

    let pds_full_id = format!("{author_did}#atproto_pds");
    let pds_short_id = "#atproto_pds";
    for svc in &doc.service {
        if (svc.id == pds_short_id || svc.id == pds_full_id)
            && svc.r#type == "AtprotoPersonalDataServer"
            && !svc.service_endpoint.is_empty()
        {
            return Ok((svc.service_endpoint.clone(), pds_full_id));
        }
    }
    Err(AppError::InvalidRequest(
        "No #atproto_pds service found in author DID document".into(),
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
        return Err(AppError::InvalidRequest(
            "Invalid delegation token format".into(),
        ));
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

    let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| {
        AppError::InvalidRequest("Invalid delegation token payload encoding".into())
    })?;
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

    if aud != expected_audience {
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

    // Verify algorithm matches key curve
    match (&key, header.alg.as_str()) {
        (ParsedVerifyingKey::P256(_), "ES256") => {}
        (ParsedVerifyingKey::Secp256k1(_), "ES256K") => {}
        _ => return Err(AppError::Unauthorized(AuthReason::AlgKeyMismatch)),
    }

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
    client_attestation: &str,
) -> Result<DateTime<Utc>, AppError> {
    if client_attestation.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "Missing or empty client attestation".into(),
        ));
    }

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
    let (service_endpoint, service_id) =
        resolve_space_host_endpoint(&authority_doc, &authority_did)?;

    // 5. Parse and validate delegation token claims and signature
    parse_and_validate_delegation_token(delegation_token, user_did, space, &service_id, &user_doc)?;

    // Acquire per-Space async lock spanning exchange, DB check, lease insertion, and credential store insertion
    let _space_lock = state.space_locks.acquire(space).await;

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
    let tombstone: Option<(i64,)> = sqlx::query_as(
        "SELECT generation FROM circle_tombstones WHERE space_uri = $1 ORDER BY generation DESC LIMIT 1",
    )
    .bind(space)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    let circle_gen: Option<(i64,)> =
        sqlx::query_as("SELECT generation FROM circles WHERE space_uri = $1 FOR UPDATE")
            .bind(space)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;

    if let Some((t_gen,)) = tombstone {
        if let Some((c_gen,)) = circle_gen {
            if t_gen >= c_gen {
                return Err(AppError::Forbidden("Circle is deleted".into()));
            }
        } else {
            return Err(AppError::Forbidden("Circle is deleted".into()));
        }
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
                    INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation)
                    VALUES ($1, $2, 'Circle', now(), 0)
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
                let circle_exists: Option<(String,)> =
                    sqlx::query_as("SELECT space_uri FROM circles WHERE space_uri = $1")
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
                    INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation)
                    VALUES ($1, $2, 'Circle', now(), 0)
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

    // Persist access lease with GREATEST monotonic expiry
    sqlx::query(
        r#"
        INSERT INTO access_leases (space_uri, member_did, expires_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (space_uri, member_did)
        DO UPDATE SET expires_at = GREATEST(access_leases.expires_at, EXCLUDED.expires_at)
        "#,
    )
    .bind(space)
    .bind(user_did)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    tx.commit().await.map_err(AppError::Database)?;

    // 8. Verify tombstone does not exist post-commit before inserting into in-memory store
    let post_tombstone: Option<(i64,)> = sqlx::query_as(
        "SELECT generation FROM circle_tombstones WHERE space_uri = $1 ORDER BY generation DESC LIMIT 1",
    )
    .bind(space)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::Database)?;

    let can_insert = match post_tombstone {
        None => true,
        Some((t_gen,)) => match circle_gen {
            Some((c_gen,)) => c_gen > t_gen,
            None => false,
        },
    };

    if can_insert {
        let active_cred = ActiveSpaceCredential {
            token: credential_jwt,
            dpop_key,
            expires_at,
        };
        state
            .credential_store
            .insert(space.to_string(), active_cred)
            .await;
    }
    Ok(expires_at)
}

pub async fn check_active_lease(
    pool: &sqlx::PgPool,
    space_uri: &str,
    user_did: &str,
) -> Result<(), AppError> {
    let circle_row: Option<(
        Option<DateTime<Utc>>,
        Option<String>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        r#"
        SELECT
            c.deleted_at,
            m.status,
            a.expires_at
        FROM circles c
        LEFT JOIN circle_members m ON m.space_uri = c.space_uri AND m.member_did = $2
        LEFT JOIN access_leases a ON a.space_uri = c.space_uri AND a.member_did = $2
        WHERE c.space_uri = $1
        "#,
    )
    .bind(space_uri)
    .bind(user_did)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;

    match circle_row {
        None => Err(AppError::NotFound("Space not found".into())),
        Some((Some(_), _, _)) => Err(AppError::NotFound("Space deleted".into())),
        Some((None, member_status, expires_at)) => {
            let is_active = member_status.as_deref() == Some("active");
            let has_lease = expires_at.is_some_and(|exp| exp > Utc::now());
            if !is_active || !has_lease {
                return Err(AppError::AccessRemoved(
                    "No active access lease for this Circle".into(),
                ));
            }
            Ok(())
        }
    }
}
