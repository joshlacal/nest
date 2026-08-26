use crate::auth::{
    parse_verification_key, select_verification_method, DidDocument, JwtHeader, ParsedVerifyingKey,
};
use crate::config::AppState;
use crate::error::{AppError, AuthReason};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_atproto::generated::blue_catbird::circle::CircleSummary;
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
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
    for service in &doc.service {
        if service.r#type == "AtprotoSpaceHost"
            && (service.id == "#atproto_space_host" || service.id == expected_full_id)
        {
            return Ok((service.service_endpoint.clone(), service.id.clone()));
        }
    }

    let expected_atproto_pds = format!("{authority_did}#atproto_pds");
    for service in &doc.service {
        if service.r#type == "AtprotoPersonalDataServer"
            && (service.id == "#atproto_pds" || service.id == expected_atproto_pds)
        {
            return Ok((service.service_endpoint.clone(), service.id.clone()));
        }
    }
    Err(AppError::NotFound(
        "Authority DID document does not declare an #atproto_space_host or #atproto_pds service"
            .into(),
    ))
}

pub fn resolve_pds_endpoint(
    doc: &DidDocument,
    author_did: &str,
) -> Result<(String, String), AppError> {
    if doc.id != author_did {
        return Err(AppError::Unauthorized(AuthReason::IdMismatch));
    }
    let expected_full_id = format!("{author_did}#atproto_pds");
    for service in &doc.service {
        if service.r#type == "AtprotoPersonalDataServer"
            && (service.id == "#atproto_pds" || service.id == expected_full_id)
        {
            return Ok((service.service_endpoint.clone(), service.id.clone()));
        }
    }

    Err(AppError::NotFound(
        "DID document does not declare an AtprotoPersonalDataServer (#atproto_pds) service".into(),
    ))
}

pub fn resolve_circles_appview_endpoint(
    doc: &DidDocument,
    appview_did: &str,
) -> Result<(String, String), AppError> {
    if doc.id != appview_did {
        return Err(AppError::Unauthorized(AuthReason::IdMismatch));
    }
    let expected_full_id = format!("{appview_did}#atproto_circles");
    for service in &doc.service {
        if service.id == "#atproto_circles" || service.id == expected_full_id {
            return Ok((service.service_endpoint.clone(), service.id.clone()));
        }
    }

    Err(AppError::NotFound(
        "AppView DID document does not declare an #atproto_circles service".into(),
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
        return Err(AppError::Unauthorized(AuthReason::InvalidJwtFormat));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderEncoding))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderJson))?;

    if header.typ.as_deref() != Some("atproto-delegation-token+jwt") {
        return Err(AppError::Unauthorized(AuthReason::InvalidTyp));
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsEncoding))?;
    let claims: DelegationTokenClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsJson))?;

    if claims.iss != expected_user_did {
        return Err(AppError::Unauthorized(AuthReason::ControllerMismatch));
    }
    if claims.sub != expected_space_uri {
        return Err(AppError::InvalidRequest(
            "Delegation token subject does not match requested Space URI".into(),
        ));
    }
    if claims.aud != expected_audience {
        return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
    }

    let now = Utc::now().timestamp();
    if claims.exp <= now {
        return Err(AppError::Unauthorized(AuthReason::Expired));
    }
    if claims.iat > now + 300 {
        return Err(AppError::Unauthorized(AuthReason::FutureIat));
    }
    if claims.jti.is_empty() {
        return Err(AppError::InvalidRequest(
            "Empty jti in delegation token claims".into(),
        ));
    }

    let vm = select_verification_method(user_doc, expected_user_did, header.kid.as_deref())
        .map_err(AppError::Unauthorized)?;
    let key = parse_verification_key(vm).map_err(AppError::Unauthorized)?;

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

    Ok(claims)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberAccessOutcome {
    Authorized,
    DeniedNotMember,
    IndeterminateDenied,
}

/// Verify service-auth subject is in the cached member list for the target Circle,
/// revalidating against the owner's PDS on cache miss, stale cache, or cached denial.
/// Returns explicit MemberAccessOutcome to distinguish authorized, removed, and indeterminate outcomes.
pub async fn verify_member_access(
    state: &AppState,
    space_uri: &str,
    user_did: &str,
) -> Result<MemberAccessOutcome, AppError> {
    // 1. Check if the circle exists and is not deleted
    let space_row: Option<(Option<DateTime<Utc>>,)> = sqlx::query_as(
        "SELECT deleted_at FROM circles WHERE space_uri = $1",
    )
    .bind(space_uri)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::Database)?;

    if let Some((Some(_),)) = space_row {
        return Err(AppError::NotFound("Circle deleted".into()));
    }

    // 2. Check cache freshness metadata (TTL: 300 seconds)
    let cache_meta: Option<(DateTime<Utc>, i32)> = sqlx::query_as(
        "SELECT last_refreshed_at, member_count FROM circle_member_cache_meta WHERE space_uri = $1",
    )
    .bind(space_uri)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::Database)?;

    let now = Utc::now();
    let is_fresh = cache_meta.as_ref().is_some_and(|(refreshed_at, _)| {
        now.signed_duration_since(*refreshed_at).num_seconds() < 300
    });

    if is_fresh {
        let is_cached: Option<(String,)> = sqlx::query_as(
            "SELECT member_did FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2",
        )
        .bind(space_uri)
        .bind(user_did)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::Database)?;

        if is_cached.is_some() {
            return Ok(MemberAccessOutcome::Authorized);
        }
        // Cached denial or miss: revalidate against PDS
    }

    // Refresh member cache from owner's PDS
    match refresh_member_cache(state, space_uri).await {
        Ok(members) => {
            if members.iter().any(|m| m == user_did) {
                Ok(MemberAccessOutcome::Authorized)
            } else {
                Ok(MemberAccessOutcome::DeniedNotMember)
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Member cache refresh failed, denying access as indeterminate");
            Ok(MemberAccessOutcome::IndeterminateDenied)
        }
    }
}

/// Verify service-auth subject is in the cached member list for the target Circle,
/// revalidating against the owner's PDS on cache miss, stale cache, or cached denial.
/// An unreadable member list MUST deny — never default-allow, never serve from unvalidated cache.
pub async fn check_member_access(
    state: &AppState,
    space_uri: &str,
    user_did: &str,
) -> Result<(), AppError> {
    match verify_member_access(state, space_uri, user_did).await? {
        MemberAccessOutcome::Authorized => Ok(()),
        MemberAccessOutcome::DeniedNotMember => Err(AppError::AccessRemoved(
            "Not authorized: user is not on the Circle member list".into(),
        )),
        MemberAccessOutcome::IndeterminateDenied => Err(AppError::Forbidden(
            "Unable to establish membership: member list unreadable from upstream".into(),
        )),
    }
}

/// Revalidates any candidate spaces for a user where the member cache is stale (> 300s).
/// For each stale space, attempts to refresh the member cache from the owner's PDS.
/// Unreadable spaces remain stale and thus excluded by the freshness gate (fail-closed).
pub async fn revalidate_stale_member_spaces(
    state: &AppState,
    user_did: &str,
) -> Result<(), AppError> {
    let stale_spaces: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT c.space_uri
        FROM circles c
        LEFT JOIN circle_member_cache m ON m.space_uri = c.space_uri AND m.member_did = $1
        LEFT JOIN circle_member_cache_meta meta ON meta.space_uri = c.space_uri
        WHERE c.deleted_at IS NULL
          AND (c.authority_did = $1 OR m.member_did IS NOT NULL)
          AND (meta.last_refreshed_at IS NULL OR meta.last_refreshed_at <= now() - INTERVAL '300 seconds')
        "#,
    )
    .bind(user_did)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    for (space_uri,) in stale_spaces {
        let _ = refresh_member_cache(state, &space_uri).await;
    }

    Ok(())
}

/// Refreshes the member list cache by calling com.atproto.simplespace.listMembers on the owner's PDS.
pub async fn refresh_member_cache(
    state: &AppState,
    space_uri: &str,
) -> Result<Vec<String>, AppError> {
    let member_dids = state
        .space_client
        .member_dids(space_uri)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to fetch member DIDs from PDS");
            AppError::Forbidden(format!("Unable to fetch member list from PDS: {e}"))
        })?;

    let mut tx = state.db.begin().await.map_err(AppError::Database)?;

    sqlx::query("DELETE FROM circle_member_cache WHERE space_uri = $1")
        .bind(space_uri)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

    for member_did in &member_dids {
        sqlx::query(
            r#"
            INSERT INTO circle_member_cache (space_uri, member_did, cached_at)
            VALUES ($1, $2, now())
            ON CONFLICT (space_uri, member_did) DO UPDATE SET cached_at = now()
            "#,
        )
        .bind(space_uri)
        .bind(member_did)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;
    }

    sqlx::query(
        r#"
        INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count)
        VALUES ($1, now(), $2)
        ON CONFLICT (space_uri) DO UPDATE
        SET last_refreshed_at = now(), member_count = EXCLUDED.member_count
        "#,
    )
    .bind(space_uri)
    .bind(member_dids.len() as i32)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(member_dids)
}

pub async fn get_cached_member_count(
    pool: &PgPool,
    space_uri: &str,
) -> Result<Option<i64>, AppError> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT member_count FROM circle_member_cache_meta WHERE space_uri = $1",
    )
    .bind(space_uri)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;

    Ok(row.map(|(count,)| count as i64))
}

/// Activates a Circle by verifying Space on PDS and returning defs#circleSummary.
pub async fn activate_circle(
    state: &AppState,
    user_did: &str,
    space_uri: &str,
) -> Result<CircleSummary, AppError> {
    let authority_did = extract_authority_did(space_uri)?;

    // 1. Independent verification via get_space on the owner's PDS
    let space_config = state
        .space_client
        .get_space(space_uri)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "get_space failed on PDS");
            AppError::NotFound(format!("Space not found or upstream unavailable: {e}"))
        })?;

    // Verify appAccess names this AppView's client_id
    let expected_client_id = &state.oauth_service.client_id;
    if !space_config.app_access.iter().any(|c| c == expected_client_id) {
        return Err(AppError::Forbidden(
            "Space appAccess does not name this Circle AppView client_id".into(),
        ));
    }

    // 2. Authorize the caller against the PDS member list WITHOUT writing yet.
    // `circle_member_cache` has a foreign key onto `circles`, so the cache can
    // only be persisted after the circle row exists (step 4). Authorization
    // still happens first: no row is created for a caller who is not a member.
    let members = state
        .space_client
        .member_dids(space_uri)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to fetch member DIDs from PDS");
            AppError::Forbidden(format!("Unable to fetch member list from PDS: {e}"))
        })?;
    if !members.iter().any(|m| m == user_did) && user_did != authority_did {
        return Err(AppError::Forbidden(
            "Caller is not a member or authority of this Space".into(),
        ));
    }

    // 3. Sync Space repos to discover metadata
    let sync_engine = crate::sync::SyncEngine::new(state);
    let _ = sync_engine.sync_repo(space_uri, &authority_did).await;
    // Fetch metadata record from circle_records
    let meta_record: Option<(serde_json::Value, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT record_json, created_at
        FROM circle_records
        WHERE space_uri = $1
          AND author_did = $2
          AND collection = 'blue.catbird.circle.metadata'
          AND deleted_at IS NULL
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(space_uri)
    .bind(&authority_did)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::Database)?;

    let (circle_id, display_name, created_at) = match meta_record {
        Some((val, created_at)) => {
            let circle_id = val
                .get("circleId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::InvalidRequest("Missing circleId in metadata record".into()))?
                .to_string();
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Circle")
                .to_string();
            (circle_id, name, created_at)
        }
        None => {
            return Err(AppError::InvalidRequest(
                "Space is not eligible: blue.catbird.circle.metadata record is absent".into(),
            ));
        }
    };

    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, deleted_at)
        VALUES ($1, $2, $3, $4, $5, NULL)
        ON CONFLICT (space_uri) DO UPDATE
        SET circle_id = EXCLUDED.circle_id,
            authority_did = EXCLUDED.authority_did,
            display_name = EXCLUDED.display_name,
            deleted_at = NULL
        "#,
    )
    .bind(space_uri)
    .bind(&circle_id)
    .bind(&authority_did)
    .bind(&display_name)
    .bind(created_at)
    .execute(&state.db)
    .await
    .map_err(AppError::Database)?;

    // 5. Now that the circle row exists, persist the member cache.
    let members = refresh_member_cache(state, space_uri).await?;

    let circle_tid = catbird_atproto::jacquard_common::types::string::Tid::new(
        SmolStr::new(&circle_id),
    ).map_err(|e| AppError::Internal(format!("Invalid circle TID: {e}")))?;

    let space_ref = catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new(
        SmolStr::new(space_uri),
    ).map_err(|e| AppError::Internal(format!("Invalid space URI: {e}")))?;

    let owner_did = catbird_atproto::jacquard_common::types::string::Did::new(
        SmolStr::new(&authority_did),
    ).map_err(|e| AppError::Internal(format!("Invalid owner DID: {e}")))?;

    Ok(CircleSummary {
        circle_id: circle_tid,
        uri: space_ref,
        name: SmolStr::new(&display_name),
        owner: owner_did,
        member_count: Some(members.len() as i64),
        muted: Some(false),
        extra_data: None,
    })
}
