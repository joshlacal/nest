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

    // 3. Sync Space repos to discover metadata.
    // Acquire a Space credential under the calling user's OAuth session first.
    if let Err(e) = ensure_space_credential(state, space_uri, Some(user_did)).await {
        tracing::warn!(error = %e, space_uri = %space_uri, "Failed to acquire space credential during activation");
        return Err(e);
    }

    let sync_engine = crate::sync::SyncEngine::new(state);
    let sync_error = match sync_engine.sync_repo(space_uri, &authority_did).await {
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(error = %e, space_uri = %space_uri, "Space repo sync failed during activation");
            Some(e.to_string())
        }
    };
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
            return Err(match sync_error {
                // Sync failed, so we never had a chance to see the record.
                // Reporting it as "absent" would blame the user's Space for an
                // AppView-side failure.
                Some(err) => AppError::Internal(format!(
                    "Could not read the Space: repo sync failed ({err})"
                )),
                None => AppError::InvalidRequest(
                    "Space is not eligible: blue.catbird.circle.metadata record is absent".into(),
                ),
            });
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
        let member_rows: Vec<(String,)> = sqlx::query_as(
            "SELECT member_did FROM circle_member_cache WHERE space_uri = $1",
        )
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
    let user_doc = did_resolver
        .resolve(&user_did)
        .await
        .map_err(|e| match e {
            AuthReason::SsrfBlocked => AppError::Unauthorized(AuthReason::SsrfBlocked),
            other => AppError::Internal(format!("Failed to resolve DID document for {user_did}: {other}")),
        })?;
    let (user_pds_endpoint, _) = resolve_pds_endpoint(&user_doc, &user_did)?;

    // 5. Step 1: Mint delegation token from user's PDS
    let delegation_token = space_client
        .get_delegation_token(
            &user_pds_endpoint,
            space_uri,
            &access_token,
            &dpop_key,
        )
        .await?;

    // 6. Resolve space host endpoint and authority DID document
    let authority_doc = did_resolver
        .resolve(&authority_did)
        .await
        .map_err(|e| match e {
            AuthReason::SsrfBlocked => AppError::Unauthorized(AuthReason::SsrfBlocked),
            other => AppError::Internal(format!("Failed to resolve DID document for {authority_did}: {other}")),
        })?;
    let (space_host_endpoint, space_host_service) =
        resolve_space_host_endpoint(&authority_doc, &authority_did)?;

    // 7. Step 2: Sign client attestation and exchange for Space credential
    let client_attestation = oauth_service
        .sign_client_attestation(&space_host_service)?;

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
    credential_store.insert(space_uri.to_string(), cred.clone()).await;

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

    const TEST_SPACE_URI: &str = "at://did:plc:authority-space-owner/space/blue.catbird.circle/3k2space1";
    const TEST_USER_DID: &str = "did:plc:alice-member-user";
    const TEST_AUTHORITY_DID: &str = "did:plc:authority-space-owner";
    const TEST_SPACE_HOST: &str = "https://space-host.example.com";
    const TEST_USER_PDS: &str = "https://pds.alice.example.com";

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
        let user_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let auth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);

        let did_resolver = Arc::new(DidResolver::new("https://plc.directory".into(), reqwest::Client::new()));
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
        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        let did_resolver = Arc::new(DidResolver::new("https://plc.directory".into(), reqwest::Client::new()));
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
        credential_store.insert(TEST_SPACE_URI.to_string(), existing_cred.clone()).await;

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
        let user_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let auth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);

        let did_resolver = Arc::new(DidResolver::new("https://plc.directory".into(), reqwest::Client::new()));
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
            }).to_string()),
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
            other => panic!("Expected AppError::Forbidden for AppNotAuthorized, got: {:?}", other),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_ensure_space_credential_no_usable_session_fails(pool: PgPool) {
        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        let did_resolver = Arc::new(DidResolver::new("https://plc.directory".into(), reqwest::Client::new()));
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
                    msg.contains("Circle authorization required") || msg.contains("no active OAuth session"),
                    "Error must indicate authorization is needed, got: {msg}"
                );
            }
            other => panic!("Expected AppError::Forbidden for missing session, got: {:?}", other),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_ensure_space_credential_db_failure_propagates_database_error(pool: PgPool) {
        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        let did_resolver = Arc::new(DidResolver::new("https://plc.directory".into(), reqwest::Client::new()));
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
            other => panic!("Expected AppError::Database for DB failure, got: {:?}", other),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_ensure_space_credential_did_resolver_failure_surfaces_as_internal(pool: PgPool) {
        let mock_transport = Arc::new(MockSpaceHostTransport::new());
        let space_client = Arc::new(SpaceClient::with_transport(mock_transport.clone()));
        let credential_store = Arc::new(CredentialStore::new());
        // Unmocked DID resolver pointing to unreachable endpoint to simulate PLC outage
        let did_resolver = Arc::new(DidResolver::new("http://127.0.0.1:1".into(), reqwest::Client::new()));
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
            other => panic!("Expected AppError::Internal for DID resolution outage, got: {:?}", other),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_ensure_space_credential_concurrent_runs_chain_once(pool: PgPool) {
        let user_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let auth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);

        let did_resolver = Arc::new(DidResolver::new("https://plc.directory".into(), reqwest::Client::new()));
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
            assert!(res.is_ok(), "Concurrent ensure_space_credential must succeed: {:?}", res.err());
        }

        // The chain must have run exactly once due to the per-space lock and double-checked caching
        assert_eq!(mock_transport.recorded_delegation_token_calls().len(), 1);
        assert_eq!(mock_transport.recorded_calls().len(), 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_sync_lock_with_ensure_space_credential_from_parts_no_deadlock(pool: PgPool) {
        let user_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let auth_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let oauth_key = p256::ecdsa::SigningKey::random(&mut OsRng);

        let did_resolver = Arc::new(DidResolver::new("https://plc.directory".into(), reqwest::Client::new()));
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
}
