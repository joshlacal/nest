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

#[derive(Debug, Clone)]
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

const DEFAULT_MAX_LOCK_ENTRIES: usize = 1000;

#[derive(Clone)]
struct SpaceLockEntry {
    mutex: Arc<Mutex<()>>,
    waiters: Arc<std::sync::atomic::AtomicUsize>,
}

pub struct SpaceLockGuard {
    _guard: OwnedMutexGuard<()>,
    space: String,
    locks: Arc<RwLock<HashMap<String, SpaceLockEntry>>>,
    waiters: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for SpaceLockGuard {
    fn drop(&mut self) {
        let remaining = self
            .waiters
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        if remaining <= 1 {
            let locks = self.locks.clone();
            let space = self.space.clone();
            let waiters = self.waiters.clone();
            tokio::spawn(async move {
                let mut map = locks.write().await;
                if waiters.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                    if let Some(entry) = map.get(&space) {
                        if Arc::ptr_eq(&entry.waiters, &waiters) {
                            map.remove(&space);
                        }
                    }
                }
            });
        }
    }
}

#[derive(Clone)]
pub struct SpaceLockManager {
    locks: Arc<RwLock<HashMap<String, SpaceLockEntry>>>,
    max_capacity: usize,
}

impl Default for SpaceLockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SpaceLockManager {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_LOCK_ENTRIES)
    }

    pub fn with_capacity(max_capacity: usize) -> Self {
        Self {
            locks: Arc::new(RwLock::new(HashMap::new())),
            max_capacity,
        }
    }

    pub async fn acquire(&self, space: &str) -> SpaceLockGuard {
        let (mutex, waiters) = {
            let mut map = self.locks.write().await;
            if map.len() >= self.max_capacity && !map.contains_key(space) {
                map.retain(|_, v| v.waiters.load(std::sync::atomic::Ordering::SeqCst) > 0);
            }
            let entry = map
                .entry(space.to_string())
                .or_insert_with(|| SpaceLockEntry {
                    mutex: Arc::new(Mutex::new(())),
                    waiters: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                });
            entry
                .waiters
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            (entry.mutex.clone(), entry.waiters.clone())
        };
        let guard = mutex.lock_owned().await;
        SpaceLockGuard {
            _guard: guard,
            space: space.to_string(),
            locks: self.locks.clone(),
            waiters,
        }
    }

    pub async fn waiter_count(&self, space: &str) -> usize {
        let map = self.locks.read().await;
        if let Some(entry) = map.get(space) {
            entry.waiters.load(std::sync::atomic::Ordering::SeqCst)
        } else {
            0
        }
    }

    pub async fn lock_count(&self) -> usize {
        let map = self.locks.read().await;
        map.len()
    }

    pub async fn clean_idle(&self) {
        let mut map = self.locks.write().await;
        map.retain(|_, v| v.waiters.load(std::sync::atomic::Ordering::SeqCst) > 0);
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

/// Resolve a Space authority's space-host endpoint, and the service identifier
/// that addresses it as an audience.
///
/// The returned identifier is always the fully-qualified
/// `{authority_did}#atproto_space_host`. Per the permissioned-data proposal, that
/// is the `aud` of both a delegation token and a client attestation, and it names
/// the space-host *role* rather than whichever DID document entry the endpoint was
/// resolved from. `#atproto_space_host` and `#atproto_space` are both optional: an
/// authority that omits them falls back to `#atproto_pds` and `#atproto` for the
/// endpoint and key, but the audience does not change with that fallback. Returning
/// the matched `service.id` here instead sent the bare relative fragment
/// `"#atproto_pds"` as an audience, which the live PDS rejected with
/// `InvalidClientAttestation`.
pub fn resolve_space_host_endpoint(
    doc: &DidDocument,
    authority_did: &str,
) -> Result<(String, String), AppError> {
    if doc.id != authority_did {
        return Err(AppError::Unauthorized(AuthReason::IdMismatch));
    }

    let space_host_service = format!("{authority_did}#atproto_space_host");

    for service in &doc.service {
        if service.r#type == "AtprotoSpaceHost"
            && (service.id == "#atproto_space_host" || service.id == space_host_service)
        {
            return Ok((service.service_endpoint.clone(), space_host_service));
        }
    }

    let expected_atproto_pds = format!("{authority_did}#atproto_pds");
    for service in &doc.service {
        if service.r#type == "AtprotoPersonalDataServer"
            && (service.id == "#atproto_pds" || service.id == expected_atproto_pds)
        {
            return Ok((service.service_endpoint.clone(), space_host_service));
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
    // 1. Check if the circle exists, is not deleted, and appAccess is granted
    let space_row: Option<(Option<DateTime<Utc>>, bool, i64)> = sqlx::query_as(
        "SELECT deleted_at, app_access_granted, access_epoch FROM circles WHERE space_uri = $1",
    )
    .bind(space_uri)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::Database)?;

    let (circle_deleted, circle_app_access, circle_epoch) = match space_row {
        None => return Err(AppError::NotFound("Circle not found".into())),
        Some((deleted_at, app_access, epoch)) => (deleted_at.is_some(), app_access, epoch),
    };

    if circle_deleted || !circle_app_access {
        return Err(AppError::NotFound(
            "Circle deleted or appAccess revoked".into(),
        ));
    }
    // 2. Check cache freshness and matching access epoch metadata (TTL: 300 seconds)
    let cache_meta: Option<(DateTime<Utc>, i32, i64, bool)> = sqlx::query_as(
        "SELECT last_refreshed_at, member_count, access_epoch, app_access_granted FROM circle_member_cache_meta WHERE space_uri = $1",
    )
    .bind(space_uri)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::Database)?;

    let now = Utc::now();
    let is_fresh =
        cache_meta
            .as_ref()
            .is_some_and(|(refreshed_at, _, meta_epoch, meta_app_access)| {
                *meta_app_access
                    && *meta_epoch == circle_epoch
                    && now.signed_duration_since(*refreshed_at).num_seconds() < 300
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
    // 1. Verify appAccess with get_space on the owner's PDS before updating any cache
    let space_config = match state.space_client.get_space(space_uri).await {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(error = %e, "get_space failed during refresh_member_cache, denying non-destructively");
            return Err(AppError::Forbidden(format!(
                "Unable to verify appAccess: {e}"
            )));
        }
    };
    let expected_client_id = &state.oauth_service.client_id;
    if space_config
        .app_access
        .is_explicit_revocation(expected_client_id)
    {
        tracing::warn!(space_uri = %space_uri, "Space appAccess explicitly omits client_id, revoking");
        if let Err(e) =
            crate::purge::revoke_app_access(&state.db, &state.credential_store, space_uri).await
        {
            tracing::error!(error = %e, space_uri = %space_uri, "Failed to revoke app access and purge circle data");
        }
        return Err(AppError::Forbidden("Space appAccess revoked".into()));
    } else if !space_config.app_access.grants_access(expected_client_id) {
        tracing::warn!(space_uri = %space_uri, "Space appAccess policy does not grant access, denying without purge");
        return Err(AppError::Forbidden(
            "Space appAccess policy denies access".into(),
        ));
    }

    // Check if the circle is deleted or appAccess is not granted in the circles table
    let circle_row: Option<(bool, Option<DateTime<Utc>>, i64)> = sqlx::query_as(
        "SELECT app_access_granted, deleted_at, access_epoch FROM circles WHERE space_uri = $1",
    )
    .bind(space_uri)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::Database)?;

    let (app_access_granted, is_deleted, current_epoch) = match circle_row {
        Some((granted, deleted, epoch)) => (granted, deleted.is_some(), epoch),
        None => return Err(AppError::NotFound("Circle not found".into())),
    };

    if !app_access_granted || is_deleted {
        return Err(AppError::Forbidden(
            "Circle is inactive or appAccess revoked".into(),
        ));
    }

    let member_dids = state
        .space_client
        .member_dids(space_uri)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to fetch member DIDs from PDS");
            AppError::Forbidden(format!("Unable to fetch member list from PDS: {e}"))
        })?;

    let mut tx = state.db.begin().await.map_err(AppError::Database)?;

    // Fetch existing cached members to detect membership mutations
    let existing_members: Vec<(String,)> =
        sqlx::query_as("SELECT member_did FROM circle_member_cache WHERE space_uri = $1")
            .bind(space_uri)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::Database)?;

    let existing_set: std::collections::HashSet<String> =
        existing_members.into_iter().map(|(d,)| d).collect();
    let new_set: std::collections::HashSet<String> = member_dids.iter().cloned().collect();

    let membership_changed = existing_set != new_set;

    let target_epoch = if membership_changed {
        let (new_epoch,): (i64,) = sqlx::query_as(
            r#"
            UPDATE circles
            SET access_epoch = access_epoch + 1
            WHERE space_uri = $1
            RETURNING access_epoch
            "#,
        )
        .bind(space_uri)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::Database)?;
        new_epoch
    } else {
        current_epoch
    };

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
        INSERT INTO circle_member_cache_meta (space_uri, last_refreshed_at, member_count, access_epoch, app_access_granted, generation)
        VALUES ($1, now(), $2, $3, true, 1)
        ON CONFLICT (space_uri) DO UPDATE
        SET last_refreshed_at = now(), member_count = EXCLUDED.member_count, access_epoch = EXCLUDED.access_epoch, app_access_granted = true, generation = circle_member_cache_meta.generation + 1
        "#,
    )
    .bind(space_uri)
    .bind(member_dids.len() as i32)
    .bind(target_epoch)
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
    let row: Option<(i32,)> =
        sqlx::query_as("SELECT member_count FROM circle_member_cache_meta WHERE space_uri = $1")
            .bind(space_uri)
            .fetch_optional(pool)
            .await
            .map_err(AppError::Database)?;

    Ok(row.map(|(count,)| count as i64))
}
/// Computes an opaque, truncated SHA-256 fingerprint for a Space URI for safe operational logging.
pub fn space_fingerprint(space_uri: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(space_uri.as_bytes());
    let hex_part: String = hash[..6].iter().map(|b| format!("{:02x}", b)).collect();
    format!("space_{hex_part}")
}

/// Activates a Circle by verifying Space on PDS and returning defs#circleSummary.
pub async fn activate_circle(
    state: &AppState,
    user_did: &str,
    space_uri: &str,
) -> Result<CircleSummary, AppError> {
    let authority_did = extract_authority_did(space_uri)?;

    // 1. Independent verification via get_space on the owner's PDS
    let space_config = state.space_client.get_space(space_uri).await.map_err(|e| {
        tracing::warn!(error = %e, "get_space failed on PDS");
        AppError::NotFound(format!("Space not found or upstream unavailable: {e}"))
    })?;

    // Verify appAccess names this AppView's client_id
    let expected_client_id = &state.oauth_service.client_id;
    if !space_config.app_access.grants_access(expected_client_id) {
        return Err(AppError::Forbidden(
            "Space appAccess does not authorize this Circle AppView client_id".into(),
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

    // 3. Acquire a Space credential under the calling user's OAuth session first.
    let cred = ensure_space_credential(state, space_uri, Some(user_did)).await.map_err(|e| {
        tracing::warn!(error = %e, space_uri = %space_uri, "Failed to acquire space credential during activation");
        e
    })?;

    // 4. Fetch and parse the authority's repo IN MEMORY to discover and validate
    // the blue.catbird.circle.metadata record before persisting the circles row.
    let authority_doc = state
        .did_resolver
        .resolve(&authority_did)
        .await
        .map_err(|e| match e {
            AuthReason::SsrfBlocked => AppError::Unauthorized(AuthReason::SsrfBlocked),
            other => AppError::Internal(format!(
                "Failed to resolve DID document for {authority_did}: {other}"
            )),
        })?;
    let (repo_service_endpoint, _) = resolve_pds_endpoint(&authority_doc, &authority_did)?;
    let author_vm = select_verification_method(&authority_doc, &authority_did, None)
        .map_err(AppError::Unauthorized)?;
    let author_signing_key = parse_verification_key(author_vm).map_err(AppError::Unauthorized)?;

    let car_bytes = state
        .space_client
        .get_repo(
            &repo_service_endpoint,
            space_uri,
            &authority_did,
            None,
            &cred.token,
            &cred.dpop_key,
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, space_uri = %space_uri, "Failed to fetch authority repo during activation");
            AppError::Internal(format!("Could not read the Space: repo fetch failed ({e})"))
        })?;

    let car = crate::commit::parse_permissioned_car(&car_bytes)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, space_uri = %space_uri, "CAR decoding failed during activation");
            AppError::Internal(format!("Could not read the Space: CAR decoding failed ({e})"))
        })?;

    let (_commit, records, _lthash) = crate::commit::extract_and_validate_car_with_policy(
        &car,
        space_uri,
        &authority_did,
        &author_signing_key,
        &state.config.commit_verification_policy,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, space_uri = %space_uri, "CAR validation failed during activation");
        AppError::Internal(format!("Could not read the Space: CAR validation failed ({e})"))
    })?;

    let meta_records: Vec<_> = records
        .into_iter()
        .filter(|(col, _, _, _)| col == "blue.catbird.circle.metadata")
        .collect();

    if meta_records.is_empty() {
        return Err(AppError::InvalidRequest(
            "Space is not eligible: blue.catbird.circle.metadata record is absent".into(),
        ));
    }

    let mut parsed_meta = Vec::new();
    for (_col, _rkey, _cid, val) in meta_records {
        let circle_id = val
            .get("circleId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InvalidRequest("Missing circleId in metadata record".into()))?
            .to_string();
        let name = val
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s.chars().count() <= 64)
            .unwrap_or("Circle")
            .to_string();
        let created_at = val
            .get("createdAt")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<DateTime<Utc>>().ok())
            .unwrap_or_else(Utc::now);
        parsed_meta.push((circle_id, name, created_at));
    }
    parsed_meta.sort_by_key(|(_, _, created_at)| *created_at);
    let (circle_id, display_name, created_at) = parsed_meta.pop().unwrap();

    // 5. INSERT the circles parent row.
    sqlx::query(
        r#"
        INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at, deleted_at, app_access_granted, app_access_revoked_at, access_epoch)
        VALUES ($1, $2, $3, $4, $5, NULL, true, NULL, 1)
        ON CONFLICT (space_uri) DO UPDATE
        SET circle_id = EXCLUDED.circle_id,
            authority_did = EXCLUDED.authority_did,
            display_name = EXCLUDED.display_name,
            deleted_at = NULL,
            app_access_granted = true,
            app_access_revoked_at = NULL,
            access_epoch = circles.access_epoch + 1
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
    // 6. Now that the circle row exists, persist the member cache before syncing repo records
    // so notification triggers correctly detect active members.
    let members = refresh_member_cache(state, space_uri).await?;

    // 7. Sync the repo so children (circle_records, etc.) have their FK parent and notifications are generated.
    let sync_engine = crate::sync::SyncEngine::new(state);
    if let Err(e) = sync_engine.sync_repo(space_uri, &authority_did).await {
        tracing::warn!(error = %e, space_uri = %space_uri, "Space repo sync failed during activation");
    }

    let circle_tid =
        catbird_atproto::jacquard_common::types::string::Tid::new(SmolStr::new(&circle_id))
            .map_err(|e| AppError::Internal(format!("Invalid circle TID: {e}")))?;

    let space_ref =
        catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new(SmolStr::new(space_uri))
            .map_err(|e| AppError::Internal(format!("Invalid space URI: {e}")))?;

    let owner_did =
        catbird_atproto::jacquard_common::types::string::Did::new(SmolStr::new(&authority_did))
            .map_err(|e| AppError::Internal(format!("Invalid owner DID: {e}")))?;

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
/// Ensure an active Space credential is available in the CredentialStore for the given space_uri.
///
/// If already cached and valid, returns it immediately.
/// Otherwise, selects an active OAuth session (preferred_user_did, or a space member with an active session,
/// or the space authority), obtains a delegation token from the user's PDS, signs a client attestation,
/// exchanges for a space credential with the Space host, and inserts it into the credential store.
pub async fn ensure_space_credential(
    state: &AppState,
    space_uri: &str,
    preferred_user_did: Option<&str>,
) -> Result<ActiveSpaceCredential, AppError> {
    if let Some(cred) = state.credential_store.get(space_uri).await {
        return Ok(cred);
    }

    let _lock_guard = state.space_locks.acquire(space_uri).await;

    ensure_space_credential_from_parts(
        &state.db,
        &state.space_client,
        &state.credential_store,
        &state.did_resolver,
        &state.oauth_service,
        &state.http_client,
        space_uri,
        preferred_user_did,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn ensure_space_credential_from_parts(
    db: &PgPool,
    space_client: &crate::space_client::SpaceClient,
    credential_store: &CredentialStore,
    did_resolver: &crate::auth::DidResolver,
    oauth_service: &crate::oauth::OAuthService,
    http_client: &reqwest::Client,
    space_uri: &str,
    preferred_user_did: Option<&str>,
) -> Result<ActiveSpaceCredential, AppError> {
    // 1. Return early if credential store already holds an active, unexpired credential
    if let Some(cred) = credential_store.get(space_uri).await {
        return Ok(cred);
    }

    let authority_did = extract_authority_did(space_uri)?;

    // 2. Choose whose OAuth session to act under:
    // - preferred_user_did if we hold a session for them
    // - otherwise a member of that Space for whom we DO hold a session
    //   (intersect circle_member_cache with oauth_service.list_sessions())
    // - otherwise the Space authority
    let mut acting_user_did: Option<String> = None;

    if let Some(preferred) = preferred_user_did {
        if oauth_service.get_session(preferred).await?.is_some() {
            acting_user_did = Some(preferred.to_string());
        }
    }

    if acting_user_did.is_none() {
        let member_rows: Vec<(String,)> =
            sqlx::query_as("SELECT member_did FROM circle_member_cache WHERE space_uri = $1")
                .bind(space_uri)
                .fetch_all(db)
                .await?;

        if !member_rows.is_empty() {
            let sessions = oauth_service.list_sessions().await?;
            for (member_did,) in member_rows {
                if sessions.iter().any(|s| s.user_did == member_did) {
                    acting_user_did = Some(member_did);
                    break;
                }
            }
        }
    }

    if acting_user_did.is_none() && oauth_service.get_session(&authority_did).await?.is_some() {
        acting_user_did = Some(authority_did.clone());
    }

    let user_did = acting_user_did.ok_or_else(|| {
        AppError::Forbidden(
            "Circle authorization required: no active OAuth session for user, members, or space authority".into(),
        )
    })?;

    // 3. Obtain valid token and DPoP signing key for the chosen user
    let (access_token, dpop_key) = oauth_service
        .get_valid_token(&user_did, http_client)
        .await?;

    // 4. Resolve that user's PDS endpoint from their DID document
    let user_doc = did_resolver.resolve(&user_did).await.map_err(|e| match e {
        AuthReason::SsrfBlocked => AppError::Unauthorized(AuthReason::SsrfBlocked),
        other => AppError::Internal(format!(
            "Failed to resolve DID document for {user_did}: {other}"
        )),
    })?;
    let (user_pds_endpoint, _) = resolve_pds_endpoint(&user_doc, &user_did)?;

    // 5. Step 1: Mint delegation token from user's PDS
    let delegation_token = space_client
        .get_delegation_token(&user_pds_endpoint, space_uri, &access_token, &dpop_key)
        .await?;

    // 6. Resolve space host endpoint and authority DID document
    let authority_doc = did_resolver
        .resolve(&authority_did)
        .await
        .map_err(|e| match e {
            AuthReason::SsrfBlocked => AppError::Unauthorized(AuthReason::SsrfBlocked),
            other => AppError::Internal(format!(
                "Failed to resolve DID document for {authority_did}: {other}"
            )),
        })?;
    let (space_host_endpoint, space_host_service) =
        resolve_space_host_endpoint(&authority_doc, &authority_did)?;

    // 7. Step 2: Sign client attestation and exchange for Space credential
    let client_attestation = oauth_service.sign_client_attestation(&space_host_service)?;

    let (credential_jwt, ephemeral_dpop_key, expires_at) = space_client
        .exchange_credential(
            &space_host_endpoint,
            space_uri,
            &delegation_token,
            &client_attestation,
            &authority_did,
            &authority_doc,
        )
        .await?;

    let cred = ActiveSpaceCredential {
        token: credential_jwt,
        dpop_key: ephemeral_dpop_key,
        expires_at,
    };

    // 8. Store in CredentialStore
    credential_store
        .insert(space_uri.to_string(), cred.clone())
        .await;

    Ok(cred)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{DidDocument, DidResolver, DidService, PublicKeyJwk, VerificationMethod};
    use crate::oauth::{OAuthService, UserOAuthSession};
    use crate::space_client::{MockSpaceHostTransport, SpaceClient};
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::EncodedPoint;
    use std::sync::Arc;
    fn setup_test_key() {
        std::env::set_var(
            "SESSION_ENCRYPTION_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
    }

    const TEST_SPACE_URI: &str =
        "at://did:plc:authority-space-owner/space/blue.catbird.circle/3k2space1";
    const TEST_USER_DID: &str = "did:plc:alice-member-user";
    const TEST_AUTHORITY_DID: &str = "did:plc:authority-space-owner";
    const TEST_SPACE_HOST: &str = "https://space-host.example.com";
    const TEST_USER_PDS: &str = "https://pds.alice.example.com";

    /// The `aud` of a client attestation and of a delegation token is the
    /// space-host *role* identifier, always fully qualified, even when the
    /// endpoint was resolved from the `#atproto_pds` fallback. Returning the
    /// matched service's own relative id here sent `"#atproto_pds"` as an
    /// audience and the live PDS answered `InvalidClientAttestation`.
    #[test]
    fn space_host_audience_is_always_the_qualified_space_host_service() {
        let declared = DidDocument {
            id: TEST_AUTHORITY_DID.into(),
            verification_method: vec![],
            service: vec![DidService {
                id: "#atproto_space_host".into(),
                r#type: "AtprotoSpaceHost".into(),
                service_endpoint: TEST_SPACE_HOST.into(),
            }],
        };
        let (endpoint, service) =
            resolve_space_host_endpoint(&declared, TEST_AUTHORITY_DID).unwrap();
        assert_eq!(endpoint, TEST_SPACE_HOST);
        assert_eq!(service, format!("{TEST_AUTHORITY_DID}#atproto_space_host"));

        // An authority that declares no space host falls back to its PDS for the
        // endpoint, but the audience must not fall back with it.
        let fallback = DidDocument {
            id: TEST_AUTHORITY_DID.into(),
            verification_method: vec![],
            service: vec![DidService {
                id: "#atproto_pds".into(),
                r#type: "AtprotoPersonalDataServer".into(),
                service_endpoint: TEST_USER_PDS.into(),
            }],
        };
        let (endpoint, service) =
            resolve_space_host_endpoint(&fallback, TEST_AUTHORITY_DID).unwrap();
        assert_eq!(endpoint, TEST_USER_PDS);
        assert_eq!(service, format!("{TEST_AUTHORITY_DID}#atproto_space_host"));
        assert!(
            !service.starts_with('#'),
            "audience must be fully qualified"
        );
    }

    fn register_test_did_doc(
        resolver: &DidResolver,
        did: &str,
        signing_key: &p256::ecdsa::SigningKey,
        services: Vec<DidService>,
    ) {
        let ep = EncodedPoint::from(signing_key.verifying_key());
        let x = URL_SAFE_NO_PAD.encode(ep.x().expect("x"));
        let y = URL_SAFE_NO_PAD.encode(ep.y().expect("y"));
        let jwk = PublicKeyJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x,
            y: Some(y),
            kid: Some(format!("{did}#atproto")),
        };
        let vm = VerificationMethod {
            id: format!("{did}#atproto"),
            r#type: "JsonWebKey2020".into(),
            controller: did.into(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        };
        let doc = DidDocument {
            id: did.into(),
            verification_method: vec![vm],
            service: services,
        };
        resolver.insert_cached(did.into(), doc);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_ensure_space_credential_success_populates_store(pool: PgPool) {
        setup_test_key();
        let user_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let auth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);

        let did_resolver = Arc::new(DidResolver::new(
            "https://plc.directory".into(),
            reqwest::Client::new(),
        ));
        register_test_did_doc(
            &did_resolver,
            TEST_USER_DID,
            &user_key,
            vec![DidService {
                id: "#atproto_pds".into(),
                r#type: "AtprotoPersonalDataServer".into(),
                service_endpoint: TEST_USER_PDS.into(),
            }],
        );
        register_test_did_doc(
            &did_resolver,
            TEST_AUTHORITY_DID,
            &auth_key,
            vec![DidService {
                id: "#atproto_space_host".into(),
                r#type: "AtprotoSpaceHost".into(),
                service_endpoint: TEST_SPACE_HOST.into(),
            }],
        );

        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        mock_transport.set_authority_signing_key(TEST_AUTHORITY_DID, auth_key.clone());
        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());

        let oauth_service = Arc::new(OAuthService::new(
            pool.clone(),
            "https://circles.catbird.blue".into(),
            oauth_key,
            None,
        ));

        // Store active session for user
        let user_session = UserOAuthSession {
            user_did: TEST_USER_DID.into(),
            access_token: "test_access_token".into(),
            refresh_token: None,
            token_endpoint: format!("{TEST_USER_PDS}/oauth/token"),
            auth_server_iss: TEST_USER_PDS.into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        };
        oauth_service.store_session(user_session).await.unwrap();

        let http_client = reqwest::Client::new();
        let cred = ensure_space_credential_from_parts(
            &pool,
            &space_client,
            &credential_store,
            &did_resolver,
            &oauth_service,
            &http_client,
            TEST_SPACE_URI,
            Some(TEST_USER_DID),
        )
        .await
        .expect("ensure_space_credential should succeed");

        assert!(!cred.token.is_empty());
        assert!(cred.expires_at > Utc::now());

        // Credential store must now hold the credential
        let cached = credential_store.get(TEST_SPACE_URI).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().token, cred.token);

        // Mock transport must have recorded delegation token and credential exchange calls
        let dt_calls = mock_transport.recorded_delegation_token_calls();
        assert_eq!(dt_calls.len(), 1);
        assert_eq!(dt_calls[0].space_uri, TEST_SPACE_URI);

        let cred_calls = mock_transport.recorded_calls();
        assert_eq!(cred_calls.len(), 1);
        assert_eq!(cred_calls[0].space_uri, TEST_SPACE_URI);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_ensure_space_credential_cached_does_not_rerun_chain(pool: PgPool) {
        setup_test_key();
        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        let did_resolver = Arc::new(DidResolver::new(
            "https://plc.directory".into(),
            reqwest::Client::new(),
        ));
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_service = Arc::new(OAuthService::new(
            pool.clone(),
            "https://circles.catbird.blue".into(),
            oauth_key,
            None,
        ));

        // Pre-populate credential store with unexpired credential
        let existing_cred = ActiveSpaceCredential {
            token: "already_cached_token".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
            expires_at: Utc::now() + chrono::Duration::hours(2),
        };
        credential_store
            .insert(TEST_SPACE_URI.to_string(), existing_cred.clone())
            .await;

        let http_client = reqwest::Client::new();
        let cred = ensure_space_credential_from_parts(
            &pool,
            &space_client,
            &credential_store,
            &did_resolver,
            &oauth_service,
            &http_client,
            TEST_SPACE_URI,
            Some(TEST_USER_DID),
        )
        .await
        .expect("Cached credential should return without network calls");

        assert_eq!(cred.token, "already_cached_token");
        assert_eq!(mock_transport.recorded_delegation_token_calls().len(), 0);
        assert_eq!(mock_transport.recorded_calls().len(), 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_ensure_space_credential_app_not_authorized_surfaced(pool: PgPool) {
        setup_test_key();
        let user_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let auth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);

        let did_resolver = Arc::new(DidResolver::new(
            "https://plc.directory".into(),
            reqwest::Client::new(),
        ));
        register_test_did_doc(
            &did_resolver,
            TEST_USER_DID,
            &user_key,
            vec![DidService {
                id: "#atproto_pds".into(),
                r#type: "AtprotoPersonalDataServer".into(),
                service_endpoint: TEST_USER_PDS.into(),
            }],
        );
        register_test_did_doc(
            &did_resolver,
            TEST_AUTHORITY_DID,
            &auth_key,
            vec![DidService {
                id: "#atproto_space_host".into(),
                r#type: "AtprotoSpaceHost".into(),
                service_endpoint: TEST_SPACE_HOST.into(),
            }],
        );

        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        // Set AppNotAuthorized error response from authority
        mock_transport.set_credential_response(
            TEST_SPACE_URI,
            Err(serde_json::json!({
                "error": "AppNotAuthorized",
                "message": "Client AppView not permitted to read Space"
            })
            .to_string()),
        );

        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        let oauth_service = Arc::new(OAuthService::new(
            pool.clone(),
            "https://circles.catbird.blue".into(),
            oauth_key,
            None,
        ));

        let user_session = UserOAuthSession {
            user_did: TEST_USER_DID.into(),
            access_token: "test_access_token".into(),
            refresh_token: None,
            token_endpoint: format!("{TEST_USER_PDS}/oauth/token"),
            auth_server_iss: TEST_USER_PDS.into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        };
        oauth_service.store_session(user_session).await.unwrap();

        let http_client = reqwest::Client::new();
        let err = ensure_space_credential_from_parts(
            &pool,
            &space_client,
            &credential_store,
            &did_resolver,
            &oauth_service,
            &http_client,
            TEST_SPACE_URI,
            Some(TEST_USER_DID),
        )
        .await
        .expect_err("Must fail when AppNotAuthorized returned by authority");

        match err {
            AppError::Forbidden(msg) => {
                assert!(
                    msg.contains("AppNotAuthorized"),
                    "Error message must clearly identify AppNotAuthorized, got: {msg}"
                );
            }
            other => panic!(
                "Expected AppError::Forbidden for AppNotAuthorized, got: {:?}",
                other
            ),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_ensure_space_credential_no_usable_session_fails(pool: PgPool) {
        setup_test_key();
        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        let did_resolver = Arc::new(DidResolver::new(
            "https://plc.directory".into(),
            reqwest::Client::new(),
        ));
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_service = Arc::new(OAuthService::new(
            pool.clone(),
            "https://circles.catbird.blue".into(),
            oauth_key,
            None,
        ));

        let http_client = reqwest::Client::new();
        let err = ensure_space_credential_from_parts(
            &pool,
            &space_client,
            &credential_store,
            &did_resolver,
            &oauth_service,
            &http_client,
            TEST_SPACE_URI,
            None,
        )
        .await
        .expect_err("Must fail when no session is held for user/member/authority");

        match err {
            AppError::Forbidden(msg) => {
                assert!(
                    msg.contains("Circle authorization required")
                        || msg.contains("no active OAuth session"),
                    "Error must indicate authorization is needed, got: {msg}"
                );
            }
            other => panic!(
                "Expected AppError::Forbidden for missing session, got: {:?}",
                other
            ),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_ensure_space_credential_db_failure_propagates_database_error(pool: PgPool) {
        setup_test_key();
        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        let did_resolver = Arc::new(DidResolver::new(
            "https://plc.directory".into(),
            reqwest::Client::new(),
        ));
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_service = Arc::new(OAuthService::new(
            pool.clone(),
            "https://circles.catbird.blue".into(),
            oauth_key,
            None,
        ));

        // Close the pool to force a database error on member cache lookup
        pool.close().await;

        let http_client = reqwest::Client::new();
        let err = ensure_space_credential_from_parts(
            &pool,
            &space_client,
            &credential_store,
            &did_resolver,
            &oauth_service,
            &http_client,
            TEST_SPACE_URI,
            None,
        )
        .await
        .expect_err("DB failure must propagate as an error");

        match err {
            AppError::Database(_) => {}
            other => panic!(
                "Expected AppError::Database for DB failure, got: {:?}",
                other
            ),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_ensure_space_credential_did_resolver_failure_surfaces_as_internal(pool: PgPool) {
        setup_test_key();
        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        // Unmocked DID resolver pointing to unreachable endpoint to simulate PLC outage
        let did_resolver = Arc::new(DidResolver::new(
            "http://127.0.0.1:1".into(),
            reqwest::Client::new(),
        ));
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_service = Arc::new(OAuthService::new(
            pool.clone(),
            "https://circles.catbird.blue".into(),
            oauth_key,
            None,
        ));

        let user_session = UserOAuthSession {
            user_did: TEST_USER_DID.into(),
            access_token: "test_access_token".into(),
            refresh_token: None,
            token_endpoint: format!("{TEST_USER_PDS}/oauth/token"),
            auth_server_iss: TEST_USER_PDS.into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        };
        oauth_service.store_session(user_session).await.unwrap();

        let http_client = reqwest::Client::new();
        let err = ensure_space_credential_from_parts(
            &pool,
            &space_client,
            &credential_store,
            &did_resolver,
            &oauth_service,
            &http_client,
            TEST_SPACE_URI,
            Some(TEST_USER_DID),
        )
        .await
        .expect_err("DID resolution outage must fail");

        match err {
            AppError::Internal(msg) => {
                assert!(
                    msg.contains("Failed to resolve DID document"),
                    "Error must indicate DID resolution failure as internal error, got: {msg}"
                );
            }
            other => panic!(
                "Expected AppError::Internal for DID resolution outage, got: {:?}",
                other
            ),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_ensure_space_credential_concurrent_runs_chain_once(pool: PgPool) {
        setup_test_key();
        let user_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let auth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);

        let did_resolver = Arc::new(DidResolver::new(
            "https://plc.directory".into(),
            reqwest::Client::new(),
        ));
        register_test_did_doc(
            &did_resolver,
            TEST_USER_DID,
            &user_key,
            vec![DidService {
                id: "#atproto_pds".into(),
                r#type: "AtprotoPersonalDataServer".into(),
                service_endpoint: TEST_USER_PDS.into(),
            }],
        );
        register_test_did_doc(
            &did_resolver,
            TEST_AUTHORITY_DID,
            &auth_key,
            vec![DidService {
                id: "#atproto_space_host".into(),
                r#type: "AtprotoSpaceHost".into(),
                service_endpoint: TEST_SPACE_HOST.into(),
            }],
        );

        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        mock_transport.set_authority_signing_key(TEST_AUTHORITY_DID, auth_key.clone());

        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        let oauth_service = Arc::new(OAuthService::new(
            pool.clone(),
            "https://circles.catbird.blue".into(),
            oauth_key,
            None,
        ));

        let user_session = UserOAuthSession {
            user_did: TEST_USER_DID.into(),
            access_token: "test_access_token".into(),
            refresh_token: None,
            token_endpoint: format!("{TEST_USER_PDS}/oauth/token"),
            auth_server_iss: TEST_USER_PDS.into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        };
        oauth_service.store_session(user_session).await.unwrap();

        let config = Arc::new(crate::config::Config {
            host: "127.0.0.1".into(),
            port: 3002,
            database_url: "postgres://localhost/postgres".into(),
            service_did: "did:web:circles.catbird.blue#atproto_circles".into(),
            plc_directory_url: "https://plc.directory".into(),
            public_appview_url: "https://public.api.bsky.app".into(),
            circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
            appview_base_url: "http://127.0.0.1:3002".into(),
            oauth_key_id: None,
            oauth_signing_key_path: None,
            oauth_signing_key_hex: None,
            push_key_id: "did:web:circles.catbird.blue#atproto_circles".into(),
            push_signing_key_path: None,
            push_signing_key_hex: None,
            commit_verification_policy: crate::commit::CommitVerificationPolicy::default(),
        });

        let http_client = reqwest::Client::new();
        let profile_hydrator = Arc::new(crate::hydration::ProfileHydrator::new(
            config.public_appview_url.clone(),
            http_client.clone(),
        ));

        let state = AppState {
            config,
            db: pool,
            http_client,
            did_resolver,
            credential_store: credential_store.clone(),
            space_client,
            space_locks: Arc::new(SpaceLockManager::new()),
            profile_hydrator,
            oauth_service,
            push_client: None,
        };

        // Spawn 5 concurrent tasks requesting the same space credential
        let mut handles = Vec::new();
        for _ in 0..5 {
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                ensure_space_credential(&state, TEST_SPACE_URI, Some(TEST_USER_DID)).await
            }));
        }

        for handle in handles {
            let res = handle.await.unwrap();
            assert!(
                res.is_ok(),
                "Concurrent ensure_space_credential must succeed: {:?}",
                res.err()
            );
        }

        // The chain must have run exactly once due to the per-space lock and double-checked caching
        assert_eq!(mock_transport.recorded_delegation_token_calls().len(), 1);
        assert_eq!(mock_transport.recorded_calls().len(), 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_sync_lock_with_ensure_space_credential_from_parts_no_deadlock(pool: PgPool) {
        setup_test_key();
        let user_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let auth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);

        let did_resolver = Arc::new(DidResolver::new(
            "https://plc.directory".into(),
            reqwest::Client::new(),
        ));
        register_test_did_doc(
            &did_resolver,
            TEST_USER_DID,
            &user_key,
            vec![DidService {
                id: "#atproto_pds".into(),
                r#type: "AtprotoPersonalDataServer".into(),
                service_endpoint: TEST_USER_PDS.into(),
            }],
        );
        register_test_did_doc(
            &did_resolver,
            TEST_AUTHORITY_DID,
            &auth_key,
            vec![DidService {
                id: "#atproto_space_host".into(),
                r#type: "AtprotoSpaceHost".into(),
                service_endpoint: TEST_SPACE_HOST.into(),
            }],
        );

        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        mock_transport.set_authority_signing_key(TEST_AUTHORITY_DID, auth_key.clone());

        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        let space_locks = Arc::new(SpaceLockManager::new());
        let oauth_service = Arc::new(OAuthService::new(
            pool.clone(),
            "https://circles.catbird.blue".into(),
            oauth_key,
            None,
        ));

        let user_session = UserOAuthSession {
            user_did: TEST_USER_DID.into(),
            access_token: "test_access_token".into(),
            refresh_token: None,
            token_endpoint: format!("{TEST_USER_PDS}/oauth/token"),
            auth_server_iss: TEST_USER_PDS.into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        };
        oauth_service.store_session(user_session).await.unwrap();

        // Simulate SyncEngine holding the space lock
        let _sync_guard = space_locks.acquire(TEST_SPACE_URI).await;

        let http_client = reqwest::Client::new();
        let cred = ensure_space_credential_from_parts(
            &pool,
            &space_client,
            &credential_store,
            &did_resolver,
            &oauth_service,
            &http_client,
            TEST_SPACE_URI,
            Some(TEST_USER_DID),
        )
        .await
        .expect("ensure_space_credential_from_parts must succeed while caller holds space lock");

        assert!(!cred.token.is_empty());
    }

    async fn start_mock_pds_tls_server() -> (String, tokio::task::JoinHandle<()>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
                .unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        let rustls_cert = rustls::pki_types::CertificateDer::from(cert_der);
        let rustls_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
        );
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![rustls_cert], rustls_key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let pds_endpoint = format!("https://127.0.0.1:{port}");

        let handle = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = [0u8; 4096];
                    let Ok(n) = tls_stream.read(&mut buf).await else {
                        return;
                    };
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    if req_str.starts_with("GET /xrpc/com.atproto.simplespace.getSpace") {
                        let body = serde_json::json!({
                            "authority": TEST_AUTHORITY_DID,
                            "spaceType": "blue.catbird.circle",
                            "skey": "3k2space1",
                            "appAccess": {
                                "$type": "com.atproto.space.defs#allowList",
                                "allowed": ["https://circles.catbird.blue/oauth/client-metadata.json"]
                            },
                            "name": "Test Circle Space"
                        }).to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = tls_stream.write_all(response.as_bytes()).await;
                    } else if req_str.starts_with("GET /xrpc/com.atproto.simplespace.listMembers") {
                        let body = serde_json::json!({
                            "members": [
                                { "did": TEST_USER_DID },
                                { "did": TEST_AUTHORITY_DID }
                            ]
                        })
                        .to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = tls_stream.write_all(response.as_bytes()).await;
                    }
                });
            }
        });

        (pds_endpoint, handle)
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_activate_circle_success_creates_circle_and_synced_records(pool: PgPool) {
        setup_test_key();
        use crate::commit::{mint_repo_car, mint_signed_commit, LtHash, RepoRecord};

        let (pds_endpoint, _mock_pds_handle) = start_mock_pds_tls_server().await;

        let user_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let auth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);

        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let did_resolver = Arc::new(DidResolver::with_transport(
            "https://plc.directory".into(),
            http_client.clone(),
            Arc::new(crate::auth::DefaultDidWebTransport::with_loopback(true)),
        ));
        register_test_did_doc(
            &did_resolver,
            TEST_USER_DID,
            &user_key,
            vec![DidService {
                id: "#atproto_pds".into(),
                r#type: "AtprotoPersonalDataServer".into(),
                service_endpoint: pds_endpoint.clone(),
            }],
        );
        register_test_did_doc(
            &did_resolver,
            TEST_AUTHORITY_DID,
            &auth_key,
            vec![
                DidService {
                    id: "#atproto_pds".into(),
                    r#type: "AtprotoPersonalDataServer".into(),
                    service_endpoint: pds_endpoint.clone(),
                },
                DidService {
                    id: "#atproto_space_host".into(),
                    r#type: "AtprotoSpaceHost".into(),
                    service_endpoint: TEST_SPACE_HOST.into(),
                },
            ],
        );

        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        mock_transport.set_authority_signing_key(TEST_AUTHORITY_DID, auth_key.clone());

        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        let oauth_service = Arc::new(OAuthService::with_transport(
            pool.clone(),
            "https://circles.catbird.blue".into(),
            oauth_key,
            None,
            Arc::new(crate::space_client::DefaultSpaceHostTransport::with_loopback(true)),
        ));

        space_client.set_deps(crate::space_client::SpaceClientDeps {
            http_client: http_client.clone(),
            did_resolver: did_resolver.clone(),
            oauth_service: oauth_service.clone(),
        });

        // Store active sessions for user and authority
        let user_session = UserOAuthSession {
            user_did: TEST_USER_DID.into(),
            access_token: "test_user_access_token".into(),
            refresh_token: None,
            token_endpoint: format!("{pds_endpoint}/oauth/token"),
            auth_server_iss: pds_endpoint.clone(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        };
        oauth_service.store_session(user_session).await.unwrap();

        let auth_session = UserOAuthSession {
            user_did: TEST_AUTHORITY_DID.into(),
            access_token: "test_auth_access_token".into(),
            refresh_token: None,
            token_endpoint: format!("{pds_endpoint}/oauth/token"),
            auth_server_iss: pds_endpoint.clone(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        };
        oauth_service.store_session(auth_session).await.unwrap();

        // Build valid CAR containing blue.catbird.circle.metadata and a post
        let meta_json = serde_json::json!({
            "$type": "blue.catbird.circle.metadata",
            "circleId": "3l7aaaaaaaaaa",
            "name": "My Test Circle",
            "createdAt": Utc::now().to_rfc3339()
        });
        let post_json = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello world from circle space!",
            "createdAt": Utc::now().to_rfc3339()
        });

        let rec_meta = RepoRecord {
            collection: "blue.catbird.circle.metadata".into(),
            rkey: "self".into(),
            cid: crate::commit::compute_dagcbor_cid(&meta_json).unwrap(),
            value: meta_json,
        };
        let rec_post = RepoRecord {
            collection: "app.bsky.feed.post".into(),
            rkey: "3l7post222222".into(),
            cid: crate::commit::compute_dagcbor_cid(&post_json).unwrap(),
            value: post_json,
        };

        let mut lthash = LtHash::default();
        lthash.add(&format!(
            "{}/{}/{}",
            rec_meta.collection, rec_meta.rkey, rec_meta.cid
        ));
        lthash.add(&format!(
            "{}/{}/{}",
            rec_post.collection, rec_post.rkey, rec_post.cid
        ));

        let commit = mint_signed_commit(
            TEST_SPACE_URI,
            TEST_AUTHORITY_DID,
            "3l7rev234567a",
            &lthash.state(),
            &auth_key,
        );

        let car_bytes = mint_repo_car(&commit, &[rec_meta, rec_post]).unwrap();
        let key = format!("{TEST_SPACE_URI}:{TEST_AUTHORITY_DID}");
        mock_transport.set_get_repo_response(&key, car_bytes.clone());
        mock_transport.set_get_repo_response(TEST_SPACE_URI, car_bytes);

        let config = Arc::new(crate::config::Config {
            host: "127.0.0.1".into(),
            port: 3002,
            database_url: "postgres://localhost/postgres".into(),
            service_did: "did:web:circles.catbird.blue#atproto_circles".into(),
            plc_directory_url: "https://plc.directory".into(),
            public_appview_url: "https://public.api.bsky.app".into(),
            circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
            appview_base_url: "http://127.0.0.1:3002".into(),
            oauth_key_id: None,
            oauth_signing_key_path: None,
            oauth_signing_key_hex: None,
            push_key_id: "did:web:circles.catbird.blue#atproto_circles".into(),
            push_signing_key_path: None,
            push_signing_key_hex: None,
            commit_verification_policy:
                crate::commit::CommitVerificationPolicy::ExplicitMigrationPermitV1,
        });

        let profile_hydrator = Arc::new(crate::hydration::ProfileHydrator::new(
            config.public_appview_url.clone(),
            http_client.clone(),
        ));

        let state = AppState {
            config,
            db: pool.clone(),
            http_client,
            did_resolver,
            credential_store: credential_store.clone(),
            space_client,
            space_locks: Arc::new(SpaceLockManager::new()),
            profile_hydrator,
            oauth_service,
            push_client: None,
        };

        let summary = activate_circle(&state, TEST_USER_DID, TEST_SPACE_URI)
            .await
            .expect("activate_circle must succeed when metadata is present");

        assert_eq!(summary.circle_id.as_str(), "3l7aaaaaaaaaa");
        assert_eq!(summary.name.as_str(), "My Test Circle");
        assert_eq!(summary.owner.as_str(), TEST_AUTHORITY_DID);
        assert_eq!(summary.member_count, Some(2));

        // Verify circles row is in DB
        let circle_row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT circle_id, display_name, authority_did FROM circles WHERE space_uri = $1",
        )
        .bind(TEST_SPACE_URI)
        .fetch_optional(&pool)
        .await
        .unwrap();

        assert!(circle_row.is_some(), "circles row must exist");
        let (cid, name, auth) = circle_row.unwrap();
        assert_eq!(cid, "3l7aaaaaaaaaa");
        assert_eq!(name, "My Test Circle");
        assert_eq!(auth, TEST_AUTHORITY_DID);

        // Verify circle_records has the post record synced from repo
        let post_record: Option<(String,)> = sqlx::query_as(
            "SELECT rkey FROM circle_records WHERE space_uri = $1 AND collection = 'app.bsky.feed.post'",
        )
        .bind(TEST_SPACE_URI)
        .fetch_optional(&pool)
        .await
        .unwrap();

        assert!(
            post_record.is_some(),
            "Synced post record must exist in circle_records"
        );
        assert_eq!(post_record.unwrap().0, "3l7post222222");

        // Verify circle_member_cache has members
        let member_rows: Vec<(String,)> = sqlx::query_as(
            "SELECT member_did FROM circle_member_cache WHERE space_uri = $1 ORDER BY member_did",
        )
        .bind(TEST_SPACE_URI)
        .fetch_all(&pool)
        .await
        .unwrap();

        assert_eq!(member_rows.len(), 2);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_activate_circle_ineligible_when_metadata_absent_leaves_no_circle_row(
        pool: PgPool,
    ) {
        setup_test_key();
        use crate::commit::{mint_repo_car, mint_signed_commit, LtHash, RepoRecord};

        let (pds_endpoint, _mock_pds_handle) = start_mock_pds_tls_server().await;

        let user_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let auth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);

        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let did_resolver = Arc::new(DidResolver::with_transport(
            "https://plc.directory".into(),
            http_client.clone(),
            Arc::new(crate::auth::DefaultDidWebTransport::with_loopback(true)),
        ));
        register_test_did_doc(
            &did_resolver,
            TEST_USER_DID,
            &user_key,
            vec![DidService {
                id: "#atproto_pds".into(),
                r#type: "AtprotoPersonalDataServer".into(),
                service_endpoint: pds_endpoint.clone(),
            }],
        );
        register_test_did_doc(
            &did_resolver,
            TEST_AUTHORITY_DID,
            &auth_key,
            vec![
                DidService {
                    id: "#atproto_pds".into(),
                    r#type: "AtprotoPersonalDataServer".into(),
                    service_endpoint: pds_endpoint.clone(),
                },
                DidService {
                    id: "#atproto_space_host".into(),
                    r#type: "AtprotoSpaceHost".into(),
                    service_endpoint: TEST_SPACE_HOST.into(),
                },
            ],
        );

        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        mock_transport.set_authority_signing_key(TEST_AUTHORITY_DID, auth_key.clone());

        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        let oauth_service = Arc::new(OAuthService::with_transport(
            pool.clone(),
            "https://circles.catbird.blue".into(),
            oauth_key,
            None,
            Arc::new(crate::space_client::DefaultSpaceHostTransport::with_loopback(true)),
        ));

        space_client.set_deps(crate::space_client::SpaceClientDeps {
            http_client: http_client.clone(),
            did_resolver: did_resolver.clone(),
            oauth_service: oauth_service.clone(),
        });

        // Store active sessions for user and authority
        let user_session = UserOAuthSession {
            user_did: TEST_USER_DID.into(),
            access_token: "test_user_access_token".into(),
            refresh_token: None,
            token_endpoint: format!("{pds_endpoint}/oauth/token"),
            auth_server_iss: pds_endpoint.clone(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        };
        oauth_service.store_session(user_session).await.unwrap();

        let auth_session = UserOAuthSession {
            user_did: TEST_AUTHORITY_DID.into(),
            access_token: "test_auth_access_token".into(),
            refresh_token: None,
            token_endpoint: format!("{pds_endpoint}/oauth/token"),
            auth_server_iss: pds_endpoint.clone(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: "atproto".into(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        };
        oauth_service.store_session(auth_session).await.unwrap();

        // Build valid CAR with ONLY a post record (NO metadata record)
        let post_json = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello world with no metadata record",
            "createdAt": Utc::now().to_rfc3339()
        });

        let rec_post = RepoRecord {
            collection: "app.bsky.feed.post".into(),
            rkey: "3l7post222222".into(),
            cid: crate::commit::compute_dagcbor_cid(&post_json).unwrap(),
            value: post_json,
        };

        let mut lthash = LtHash::default();
        lthash.add(&format!(
            "{}/{}/{}",
            rec_post.collection, rec_post.rkey, rec_post.cid
        ));

        let commit = mint_signed_commit(
            TEST_SPACE_URI,
            TEST_AUTHORITY_DID,
            "3l7rev234567a",
            &lthash.state(),
            &auth_key,
        );

        let car_bytes = mint_repo_car(&commit, &[rec_post]).unwrap();
        let key = format!("{TEST_SPACE_URI}:{TEST_AUTHORITY_DID}");
        mock_transport.set_get_repo_response(&key, car_bytes.clone());
        mock_transport.set_get_repo_response(TEST_SPACE_URI, car_bytes);

        let config = Arc::new(crate::config::Config {
            host: "127.0.0.1".into(),
            port: 3002,
            database_url: "postgres://localhost/postgres".into(),
            service_did: "did:web:circles.catbird.blue#atproto_circles".into(),
            plc_directory_url: "https://plc.directory".into(),
            public_appview_url: "https://public.api.bsky.app".into(),
            circle_media_base_url: url::Url::parse("https://media.catbird.blue").unwrap(),
            appview_base_url: "http://127.0.0.1:3002".into(),
            oauth_key_id: None,
            oauth_signing_key_path: None,
            oauth_signing_key_hex: None,
            push_key_id: "did:web:circles.catbird.blue#atproto_circles".into(),
            push_signing_key_path: None,
            push_signing_key_hex: None,
            commit_verification_policy:
                crate::commit::CommitVerificationPolicy::ExplicitMigrationPermitV1,
        });

        let profile_hydrator = Arc::new(crate::hydration::ProfileHydrator::new(
            config.public_appview_url.clone(),
            http_client.clone(),
        ));

        let state = AppState {
            config,
            db: pool.clone(),
            http_client,
            did_resolver,
            credential_store: credential_store.clone(),
            space_client,
            space_locks: Arc::new(SpaceLockManager::new()),
            profile_hydrator,
            oauth_service,
            push_client: None,
        };

        let err = activate_circle(&state, TEST_USER_DID, TEST_SPACE_URI)
            .await
            .expect_err("activate_circle must fail when metadata is absent");

        match err {
            AppError::InvalidRequest(msg) => {
                assert!(
                    msg.contains(
                        "Space is not eligible: blue.catbird.circle.metadata record is absent"
                    ),
                    "Error message must indicate space ineligibility, got: {msg}"
                );
            }
            other => panic!("Expected AppError::InvalidRequest, got: {:?}", other),
        }

        // Verify NO circles row exists in DB
        let circle_row: Option<(String,)> =
            sqlx::query_as("SELECT circle_id FROM circles WHERE space_uri = $1")
                .bind(TEST_SPACE_URI)
                .fetch_optional(&pool)
                .await
                .unwrap();

        assert!(circle_row.is_none(), "NO circles row must exist in DB");
    }
}
