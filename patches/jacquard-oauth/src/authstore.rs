use std::future::Future;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use jacquard_common::{
    IntoStatic,
    session::{SessionStore, SessionStoreError},
    types::did::Did,
};
use smol_str::{SmolStr, ToSmolStr, format_smolstr};

use crate::{
    session::{AuthRequestData, ClientSessionData},
    utils::generate_verifier,
};

/// Durable refresh uncertainty is an authentication state, not a transient
/// backend failure. The encrypted session remains stored, but it must not be
/// used again until a fresh login supersedes its lifecycle.
#[derive(Debug, thiserror::Error)]
#[error("session refresh outcome is uncertain; reauthentication is required")]
pub struct ReauthenticationRequired;

/// A live refresh or revoke lease temporarily prevents session reads. This is
/// retryable and distinct from durable refresh uncertainty.
#[derive(Debug, thiserror::Error)]
#[error("session operation is active")]
pub struct SessionOperationActive;

pub fn reauthentication_required_store_error() -> SessionStoreError {
    SessionStoreError::Other(Box::new(ReauthenticationRequired))
}

pub fn is_reauthentication_required(error: &SessionStoreError) -> bool {
    matches!(error, SessionStoreError::Other(source) if source.is::<ReauthenticationRequired>())
}

pub fn session_operation_active_store_error() -> SessionStoreError {
    SessionStoreError::Other(Box::new(SessionOperationActive))
}

pub fn is_session_operation_active(error: &SessionStoreError) -> bool {
    matches!(error, SessionStoreError::Other(source) if source.is::<SessionOperationActive>())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOperationKind {
    Refresh,
    Revoke,
}

#[derive(Clone, Debug)]
pub struct SessionOperationLease {
    pub session: ClientSessionData<'static>,
    pub owner: SmolStr,
    pub kind: SessionOperationKind,
    pub uncertain_refresh: bool,
}

#[derive(Clone, Debug)]
pub enum SessionOperationAcquire {
    Acquired(Box<SessionOperationLease>),
    Busy,
    Missing,
}

#[cfg_attr(not(target_arch = "wasm32"), trait_variant::make(Send))]
pub trait ClientAuthStore {
    fn get_session(
        &self,
        did: &Did<'_>,
        session_id: &str,
    ) -> impl Future<Output = Result<Option<ClientSessionData<'_>>, SessionStoreError>>;

    /// Start a fresh lifecycle, superseding any previous generation for this
    /// exact account and session identifier.
    fn create_session(
        &self,
        session: ClientSessionData<'_>,
    ) -> impl Future<Output = Result<ClientSessionData<'static>, SessionStoreError>>;

    /// Update only if the stored lifecycle generation still matches.
    fn update_session(
        &self,
        session: ClientSessionData<'_>,
    ) -> impl Future<Output = Result<bool, SessionStoreError>>;

    fn delete_session(
        &self,
        did: &Did<'_>,
        session_id: &str,
        lifecycle_generation: &str,
    ) -> impl Future<Output = Result<bool, SessionStoreError>>;

    /// Acquire the store-authoritative fence for refresh or revocation. The
    /// returned session is reloaded atomically with acquisition and carries a
    /// newly rotated lifecycle generation.
    fn acquire_session_operation(
        &self,
        did: &Did<'_>,
        session_id: &str,
        kind: SessionOperationKind,
        owner: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<SessionOperationAcquire, SessionStoreError>>;

    fn renew_session_operation(
        &self,
        lease: &SessionOperationLease,
        ttl: Duration,
    ) -> impl Future<Output = Result<bool, SessionStoreError>>;

    /// Install refreshed credentials only for the live refresh-fence owner.
    fn commit_session_refresh(
        &self,
        lease: &SessionOperationLease,
        refreshed: ClientSessionData<'_>,
    ) -> impl Future<Output = Result<Option<ClientSessionData<'static>>, SessionStoreError>>;

    /// Delete the session only for the live revoke-fence owner.
    fn complete_session_revoke(
        &self,
        lease: &SessionOperationLease,
    ) -> impl Future<Output = Result<bool, SessionStoreError>>;

    /// Compare-owner release. Refresh releases retain a durable uncertain
    /// marker unless a successful commit cleared it.
    fn release_session_operation(
        &self,
        lease: &SessionOperationLease,
        uncertain: bool,
    ) -> impl Future<Output = Result<bool, SessionStoreError>>;

    fn get_auth_req_info(
        &self,
        state: &str,
    ) -> impl Future<Output = Result<Option<AuthRequestData<'_>>, SessionStoreError>>;

    fn save_auth_req_info(
        &self,
        auth_req_info: &AuthRequestData<'_>,
    ) -> impl Future<Output = Result<(), SessionStoreError>>;

    fn delete_auth_req_info(
        &self,
        state: &str,
    ) -> impl Future<Output = Result<(), SessionStoreError>>;
}

struct MemoryOperation {
    owner: SmolStr,
    kind: SessionOperationKind,
    generation: SmolStr,
    expires_at: Instant,
}

#[derive(Default)]
struct MemoryState {
    sessions: HashMap<SmolStr, ClientSessionData<'static>>,
    operations: HashMap<SmolStr, MemoryOperation>,
    uncertain: HashMap<SmolStr, SmolStr>,
}

pub struct MemoryAuthStore {
    state: Mutex<MemoryState>,
    auth_reqs: DashMap<SmolStr, AuthRequestData<'static>>,
}

impl MemoryAuthStore {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MemoryState::default()),
            auth_reqs: DashMap::new(),
        }
    }
}

impl Default for MemoryAuthStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientAuthStore for MemoryAuthStore {
    async fn get_session(
        &self,
        did: &Did<'_>,
        session_id: &str,
    ) -> Result<Option<ClientSessionData<'_>>, SessionStoreError> {
        let key = format_smolstr!("{}_{}", did, session_id);
        let mut state = self.state.lock().expect("memory auth store poisoned");
        if state
            .operations
            .get(&key)
            .is_some_and(|operation| operation.expires_at <= Instant::now())
        {
            state.operations.remove(&key);
        }
        if state.operations.contains_key(&key) {
            return Err(session_operation_active_store_error());
        }
        if state.uncertain.contains_key(&key) {
            return Err(reauthentication_required_store_error());
        }
        Ok(state.sessions.get(&key).cloned())
    }

    async fn create_session(
        &self,
        mut session: ClientSessionData<'_>,
    ) -> Result<ClientSessionData<'static>, SessionStoreError> {
        session.lifecycle_generation = generate_verifier();
        let key = format_smolstr!("{}_{}", session.account_did, session.session_id);
        let session = session.into_static();
        let mut state = self.state.lock().expect("memory auth store poisoned");
        state.operations.remove(&key);
        state.uncertain.remove(&key);
        state.sessions.insert(key, session.clone());
        Ok(session)
    }

    async fn update_session(
        &self,
        session: ClientSessionData<'_>,
    ) -> Result<bool, SessionStoreError> {
        let key = format_smolstr!("{}_{}", session.account_did, session.session_id);
        let mut state = self.state.lock().expect("memory auth store poisoned");
        if state.operations.contains_key(&key) || state.uncertain.contains_key(&key) {
            return Ok(false);
        }
        let Some(current) = state.sessions.get_mut(&key) else {
            return Ok(false);
        };
        if session.lifecycle_generation.is_empty()
            || current.lifecycle_generation != session.lifecycle_generation
        {
            return Ok(false);
        }
        *current = session.into_static();
        Ok(true)
    }

    async fn delete_session(
        &self,
        did: &Did<'_>,
        session_id: &str,
        lifecycle_generation: &str,
    ) -> Result<bool, SessionStoreError> {
        let key = format_smolstr!("{}_{}", did, session_id);
        let mut state = self.state.lock().expect("memory auth store poisoned");
        if state.operations.contains_key(&key) || state.uncertain.contains_key(&key) {
            return Ok(false);
        }
        let matches = state.sessions.get(&key).is_some_and(|current| {
            !lifecycle_generation.is_empty() && current.lifecycle_generation == lifecycle_generation
        });
        if matches {
            state.sessions.remove(&key);
        }
        Ok(matches)
    }

    async fn acquire_session_operation(
        &self,
        did: &Did<'_>,
        session_id: &str,
        kind: SessionOperationKind,
        owner: &str,
        ttl: Duration,
    ) -> Result<SessionOperationAcquire, SessionStoreError> {
        let key = format_smolstr!("{}_{}", did, session_id);
        let mut state = self.state.lock().expect("memory auth store poisoned");
        let now = Instant::now();
        if state
            .operations
            .get(&key)
            .is_some_and(|op| op.expires_at > now)
        {
            return Ok(SessionOperationAcquire::Busy);
        }
        state.operations.remove(&key);
        let uncertain_refresh = state.uncertain.contains_key(&key);
        let Some(current) = state.sessions.get_mut(&key) else {
            return Ok(SessionOperationAcquire::Missing);
        };
        let generation = generate_verifier();
        current.lifecycle_generation = generation.clone();
        let session = current.clone();
        state.operations.insert(
            key.clone(),
            MemoryOperation {
                owner: owner.into(),
                kind,
                generation: generation.clone().into(),
                expires_at: now + ttl,
            },
        );
        if kind == SessionOperationKind::Refresh {
            state.uncertain.insert(key, generation.into());
        }
        Ok(SessionOperationAcquire::Acquired(Box::new(
            SessionOperationLease {
                session,
                owner: owner.into(),
                kind,
                uncertain_refresh,
            },
        )))
    }

    async fn renew_session_operation(
        &self,
        lease: &SessionOperationLease,
        ttl: Duration,
    ) -> Result<bool, SessionStoreError> {
        let key = format_smolstr!("{}_{}", lease.session.account_did, lease.session.session_id);
        let mut state = self.state.lock().expect("memory auth store poisoned");
        let Some(op) = state.operations.get_mut(&key) else {
            return Ok(false);
        };
        if op.owner != lease.owner
            || op.kind != lease.kind
            || op.generation.as_str() != lease.session.lifecycle_generation.as_ref()
            || op.expires_at <= Instant::now()
        {
            return Ok(false);
        }
        op.expires_at = Instant::now() + ttl;
        Ok(true)
    }

    async fn commit_session_refresh(
        &self,
        lease: &SessionOperationLease,
        mut refreshed: ClientSessionData<'_>,
    ) -> Result<Option<ClientSessionData<'static>>, SessionStoreError> {
        let key = format_smolstr!("{}_{}", lease.session.account_did, lease.session.session_id);
        let mut state = self.state.lock().expect("memory auth store poisoned");
        let valid = state.operations.get(&key).is_some_and(|op| {
            op.owner == lease.owner
                && op.kind == SessionOperationKind::Refresh
                && op.generation.as_str() == lease.session.lifecycle_generation.as_ref()
                && op.expires_at > Instant::now()
        });
        if !valid {
            return Ok(None);
        }
        let generation = generate_verifier();
        refreshed.lifecycle_generation = generation;
        let refreshed = refreshed.into_static();
        state.sessions.insert(key.clone(), refreshed.clone());
        state.operations.remove(&key);
        state.uncertain.remove(&key);
        Ok(Some(refreshed))
    }

    async fn complete_session_revoke(
        &self,
        lease: &SessionOperationLease,
    ) -> Result<bool, SessionStoreError> {
        if lease.uncertain_refresh {
            return Ok(false);
        }
        let key = format_smolstr!("{}_{}", lease.session.account_did, lease.session.session_id);
        let mut state = self.state.lock().expect("memory auth store poisoned");
        let valid = state.operations.get(&key).is_some_and(|op| {
            op.owner == lease.owner
                && op.kind == SessionOperationKind::Revoke
                && op.generation.as_str() == lease.session.lifecycle_generation.as_ref()
                && op.expires_at > Instant::now()
        });
        if !valid {
            return Ok(false);
        }
        state.sessions.remove(&key);
        state.operations.remove(&key);
        state.uncertain.remove(&key);
        Ok(true)
    }

    async fn release_session_operation(
        &self,
        lease: &SessionOperationLease,
        uncertain: bool,
    ) -> Result<bool, SessionStoreError> {
        let key = format_smolstr!("{}_{}", lease.session.account_did, lease.session.session_id);
        let mut state = self.state.lock().expect("memory auth store poisoned");
        let valid = state.operations.get(&key).is_some_and(|op| {
            op.owner == lease.owner
                && op.kind == lease.kind
                && op.generation.as_str() == lease.session.lifecycle_generation.as_ref()
        });
        if !valid {
            return Ok(false);
        }
        state.operations.remove(&key);
        if !uncertain {
            state.uncertain.remove(&key);
        }
        Ok(true)
    }

    async fn get_auth_req_info(
        &self,
        state: &str,
    ) -> Result<Option<AuthRequestData<'_>>, SessionStoreError> {
        Ok(self.auth_reqs.get(state).map(|v| v.clone()))
    }

    async fn save_auth_req_info(
        &self,
        auth_req_info: &AuthRequestData<'_>,
    ) -> Result<(), SessionStoreError> {
        self.auth_reqs.insert(
            auth_req_info.state.clone().to_smolstr(),
            auth_req_info.clone().into_static(),
        );
        Ok(())
    }

    async fn delete_auth_req_info(&self, state: &str) -> Result<(), SessionStoreError> {
        self.auth_reqs.remove(state);
        Ok(())
    }
}

impl<T: ClientAuthStore + Send + Sync>
    SessionStore<(Did<'static>, SmolStr), ClientSessionData<'static>> for Arc<T>
{
    /// Get the current session if present.
    async fn get(&self, key: &(Did<'static>, SmolStr)) -> Option<ClientSessionData<'static>> {
        let (did, session_id) = key;
        self.as_ref()
            .get_session(did, session_id)
            .await
            .ok()
            .flatten()
            .into_static()
    }
    /// Persist the given session.
    async fn set(
        &self,
        _key: (Did<'static>, SmolStr),
        session: ClientSessionData<'static>,
    ) -> Result<(), SessionStoreError> {
        if session.lifecycle_generation.is_empty() {
            self.as_ref().create_session(session).await.map(|_| ())
        } else if self.as_ref().update_session(session).await? {
            Ok(())
        } else {
            Err(SessionStoreError::Other("session lifecycle changed".into()))
        }
    }
    /// Delete the given session.
    async fn del(&self, key: &(Did<'static>, SmolStr)) -> Result<(), SessionStoreError> {
        let (did, session_id) = key;
        let Some(session) = self.as_ref().get_session(did, session_id).await? else {
            return Ok(());
        };
        if self
            .as_ref()
            .delete_session(did, session_id, &session.lifecycle_generation)
            .await?
        {
            Ok(())
        } else {
            Err(SessionStoreError::Other("session lifecycle changed".into()))
        }
    }
}
