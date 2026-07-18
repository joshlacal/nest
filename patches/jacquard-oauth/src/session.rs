use std::{sync::Arc, time::Duration};

use chrono::TimeDelta;

use crate::{
    atproto::{AtprotoClientMetadata, atproto_client_metadata},
    authstore::{
        ClientAuthStore, SessionOperationAcquire, SessionOperationKind, SessionOperationLease,
    },
    dpop::DpopExt,
    keyset::Keyset,
    request::{OAuthMetadata, refresh},
    resolver::OAuthResolver,
    scopes::Scope,
    types::TokenSet,
    utils::generate_verifier,
};

use dashmap::DashMap;
use jacquard_common::{
    CowStr, IntoStatic,
    http_client::HttpClient,
    session::SessionStoreError,
    types::{did::Did, string::Datetime},
};
use jose_jwk::Key;
use serde::{Deserialize, Serialize};
use smol_str::{SmolStr, format_smolstr};
use tokio::sync::{Mutex, OwnedMutexGuard};

pub trait DpopDataSource {
    fn key(&self) -> &Key;
    fn authserver_nonce(&self) -> Option<CowStr<'_>>;
    fn set_authserver_nonce(&mut self, nonce: CowStr<'_>);
    fn host_nonce(&self) -> Option<CowStr<'_>>;
    fn set_host_nonce(&mut self, nonce: CowStr<'_>);
}

async fn compensate_uncommitted_refresh<T>(
    client: &T,
    mut refreshed: ClientSessionData<'_>,
    metadata: &OAuthMetadata,
) where
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
{
    let token = refreshed
        .token_set
        .refresh_token
        .clone()
        .unwrap_or_else(|| refreshed.token_set.access_token.clone());
    let _ = crate::request::revoke(client, &mut refreshed.dpop_data, &token, metadata).await;
}

/// Persisted information about an OAuth session. Used to resume an active session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSessionData<'s> {
    /// Opaque storage lifecycle generation. Stores populate this on reads and
    /// fresh creation; existing-session writes must present the same value.
    /// It is transport-local metadata and is never serialized into OAuth
    /// session records or exposed to providers.
    #[serde(skip)]
    pub lifecycle_generation: CowStr<'s>,

    // Account DID for this session. Assuming only one active session per account, this can be used as "primary key" for storing and retrieving this information.
    #[serde(borrow)]
    pub account_did: Did<'s>,

    // Independent opaque credential generated only after the OAuth token,
    // subject, issuer, and returned scopes have been validated. It must never
    // reuse provider-visible OAuth state.
    pub session_id: CowStr<'s>,

    // Base URL of the "resource server" (eg, PDS). Should include scheme, hostname, port; no path or auth info.
    pub host_url: CowStr<'s>,

    // Base URL of the "auth server" (eg, PDS or entryway). Should include scheme, hostname, port; no path or auth info.
    pub authserver_url: CowStr<'s>,

    // Full token endpoint
    pub authserver_token_endpoint: CowStr<'s>,

    // Full revocation endpoint, if it exists
    #[serde(skip_serializing_if = "std::option::Option::is_none")]
    pub authserver_revocation_endpoint: Option<CowStr<'s>>,

    // The set of scopes approved for this session (returned in the initial token request)
    pub scopes: Vec<Scope<'s>>,

    #[serde(flatten)]
    pub dpop_data: DpopClientData<'s>,

    #[serde(flatten)]
    pub token_set: TokenSet<'s>,
}

impl IntoStatic for ClientSessionData<'_> {
    type Output = ClientSessionData<'static>;

    fn into_static(self) -> Self::Output {
        ClientSessionData {
            lifecycle_generation: self.lifecycle_generation.into_static(),
            authserver_url: self.authserver_url.into_static(),
            authserver_token_endpoint: self.authserver_token_endpoint.into_static(),
            authserver_revocation_endpoint: self
                .authserver_revocation_endpoint
                .map(IntoStatic::into_static),
            scopes: self.scopes.into_static(),
            dpop_data: self.dpop_data.into_static(),
            token_set: self.token_set.into_static(),
            account_did: self.account_did.into_static(),
            session_id: self.session_id.into_static(),
            host_url: self.host_url.into_static(),
        }
    }
}

impl ClientSessionData<'_> {
    pub fn update_with_tokens(&mut self, token_set: TokenSet<'_>) {
        if let Some(Ok(scopes)) = token_set
            .scope
            .as_ref()
            .map(|scope| Scope::parse_multiple_reduced(&scope).map(IntoStatic::into_static))
        {
            self.scopes = scopes;
        }
        self.token_set = token_set.into_static();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DpopClientData<'s> {
    pub dpop_key: Key,
    // Current auth server DPoP nonce
    #[serde(borrow)]
    pub dpop_authserver_nonce: CowStr<'s>,
    // Current host ("resource server", eg PDS) DPoP nonce
    pub dpop_host_nonce: CowStr<'s>,
}

impl IntoStatic for DpopClientData<'_> {
    type Output = DpopClientData<'static>;

    fn into_static(self) -> Self::Output {
        DpopClientData {
            dpop_key: self.dpop_key,
            dpop_authserver_nonce: self.dpop_authserver_nonce.into_static(),
            dpop_host_nonce: self.dpop_host_nonce.into_static(),
        }
    }
}

impl DpopDataSource for DpopClientData<'_> {
    fn key(&self) -> &Key {
        &self.dpop_key
    }
    fn authserver_nonce(&self) -> Option<CowStr<'_>> {
        Some(self.dpop_authserver_nonce.clone())
    }

    fn host_nonce(&self) -> Option<CowStr<'_>> {
        Some(self.dpop_host_nonce.clone())
    }

    fn set_authserver_nonce(&mut self, nonce: CowStr<'_>) {
        self.dpop_authserver_nonce = nonce.into_static();
    }

    fn set_host_nonce(&mut self, nonce: CowStr<'_>) {
        self.dpop_host_nonce = nonce.into_static();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequestData<'s> {
    // The random identifier generated by the client for the auth request flow. Can be used as "primary key" for storing and retrieving this information.
    #[serde(borrow)]
    pub state: CowStr<'s>,

    // URL of the auth server (eg, PDS or entryway)
    pub authserver_url: CowStr<'s>,

    // If the flow started with an account identifier (DID or handle), it should be persisted, to verify against the initial token response.
    #[serde(skip_serializing_if = "std::option::Option::is_none")]
    pub account_did: Option<Did<'s>>,

    // OAuth scope strings
    pub scopes: Vec<Scope<'s>>,

    // unique token in URI format, which will be used by the client in the auth flow redirect
    pub request_uri: CowStr<'s>,

    // Full token endpoint URL
    pub authserver_token_endpoint: CowStr<'s>,

    // Full revocation endpoint, if it exists
    #[serde(skip_serializing_if = "std::option::Option::is_none")]
    pub authserver_revocation_endpoint: Option<CowStr<'s>>,

    // The secret token/nonce which a code challenge was generated from
    pub pkce_verifier: CowStr<'s>,

    #[serde(flatten)]
    pub dpop_data: DpopReqData<'s>,
}

impl IntoStatic for AuthRequestData<'_> {
    type Output = AuthRequestData<'static>;
    fn into_static(self) -> AuthRequestData<'static> {
        AuthRequestData {
            request_uri: self.request_uri.into_static(),
            authserver_token_endpoint: self.authserver_token_endpoint.into_static(),
            authserver_revocation_endpoint: self
                .authserver_revocation_endpoint
                .map(|s| s.into_static()),
            pkce_verifier: self.pkce_verifier.into_static(),
            dpop_data: self.dpop_data.into_static(),
            state: self.state.into_static(),
            authserver_url: self.authserver_url.into_static(),
            account_did: self.account_did.into_static(),
            scopes: self.scopes.into_static(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DpopReqData<'s> {
    // The secret cryptographic key generated by the client for this specific OAuth session
    pub dpop_key: Key,
    // Server-provided DPoP nonce from auth request (PAR)
    #[serde(borrow)]
    pub dpop_authserver_nonce: Option<CowStr<'s>>,
}

impl IntoStatic for DpopReqData<'_> {
    type Output = DpopReqData<'static>;
    fn into_static(self) -> DpopReqData<'static> {
        DpopReqData {
            dpop_key: self.dpop_key,
            dpop_authserver_nonce: self.dpop_authserver_nonce.into_static(),
        }
    }
}

impl DpopDataSource for DpopReqData<'_> {
    fn key(&self) -> &Key {
        &self.dpop_key
    }
    fn authserver_nonce(&self) -> Option<CowStr<'_>> {
        self.dpop_authserver_nonce.clone()
    }

    fn host_nonce(&self) -> Option<CowStr<'_>> {
        None
    }

    fn set_authserver_nonce(&mut self, nonce: CowStr<'_>) {
        self.dpop_authserver_nonce = Some(nonce.into_static());
    }

    fn set_host_nonce(&mut self, _nonce: CowStr<'_>) {}
}

#[derive(Clone, Debug)]
pub struct ClientData<'s> {
    pub keyset: Option<Keyset>,
    pub config: AtprotoClientMetadata<'s>,
}

impl<'s> ClientData<'s> {
    pub fn new(keyset: Option<Keyset>, config: AtprotoClientMetadata<'s>) -> Self {
        Self { keyset, config }
    }

    pub fn new_public(config: AtprotoClientMetadata<'s>) -> Self {
        Self {
            keyset: None,
            config,
        }
    }
}

pub struct ClientSession<'s> {
    pub keyset: Option<Keyset>,
    pub config: AtprotoClientMetadata<'s>,
    pub session_data: ClientSessionData<'s>,
}

impl<'s> ClientSession<'s> {
    pub fn new(
        ClientData { keyset, config }: ClientData<'s>,
        session_data: ClientSessionData<'s>,
    ) -> Self {
        Self {
            keyset,
            config,
            session_data,
        }
    }

    pub async fn metadata<T: HttpClient + OAuthResolver + Send + Sync>(
        &self,
        client: &T,
    ) -> Result<OAuthMetadata, Error> {
        Ok(OAuthMetadata {
            server_metadata: client
                .get_authorization_server_metadata(&self.session_data.authserver_url)
                .await
                .map_err(|e| Error::ServerAgent(crate::request::RequestError::resolver(e)))?,
            client_metadata: atproto_client_metadata(self.config.clone(), &self.keyset)
                .unwrap()
                .into_static(),
            keyset: self.keyset.clone(),
        })
    }
}

#[derive(thiserror::Error, Debug, miette::Diagnostic)]
pub enum Error {
    #[error(transparent)]
    #[diagnostic(code(jacquard_oauth::session::request))]
    ServerAgent(#[from] crate::request::RequestError),
    #[error(transparent)]
    #[diagnostic(code(jacquard_oauth::session::storage))]
    Store(SessionStoreError),
    #[error("session requires reauthentication")]
    #[diagnostic(
        code(jacquard_oauth::session::reauthentication_required),
        help("start a new login; quarantined credentials were retained but cannot be reused")
    )]
    ReauthenticationRequired,
    #[error("session operation is active")]
    #[diagnostic(
        code(jacquard_oauth::session::operation_in_progress),
        help("retry after the active session refresh or revocation completes")
    )]
    OperationInProgress,
    #[error("session does not exist")]
    #[diagnostic(code(jacquard_oauth::session::not_found))]
    SessionNotFound,
    #[error("session refresh failed permanently")]
    #[diagnostic(
        code(jacquard_oauth::session::refresh_failed),
        help("the session has been cleared - user must re-authenticate")
    )]
    RefreshFailed(#[source] crate::request::RequestError),
}

impl Error {
    /// Returns true if this error indicates a permanent auth failure
    /// where the user needs to re-authenticate.
    pub fn is_permanent(&self) -> bool {
        match self {
            Error::RefreshFailed(_) => true,
            Error::SessionNotFound => true,
            Error::ReauthenticationRequired => true,
            Error::OperationInProgress => false,
            Error::ServerAgent(e) => e.is_permanent(),
            Error::Store(_) => false,
        }
    }
}

impl From<SessionStoreError> for Error {
    fn from(error: SessionStoreError) -> Self {
        if crate::authstore::is_reauthentication_required(&error) {
            Self::ReauthenticationRequired
        } else if crate::authstore::is_session_operation_active(&error) {
            Self::OperationInProgress
        } else {
            Self::Store(error)
        }
    }
}

pub struct SessionRegistry<T, S>
where
    T: OAuthResolver,
    S: ClientAuthStore,
{
    pub store: Arc<S>,
    pub client: Arc<T>,
    pub client_data: ClientData<'static>,
    pending: DashMap<SmolStr, Arc<Mutex<()>>>,
}

impl<T, S> SessionRegistry<T, S>
where
    S: ClientAuthStore,
    T: OAuthResolver,
{
    const EXPIRY_BUFFER_SECS: i64 = 60;
    const OPERATION_LEASE_TTL: Duration = Duration::from_secs(120);

    fn session_is_fresh(session: &ClientSessionData<'_>) -> bool {
        session
            .token_set
            .expires_at
            .as_ref()
            .is_some_and(|expires_at| {
                let now_with_buffer = Datetime::now()
                    .as_ref()
                    .checked_add_signed(TimeDelta::seconds(Self::EXPIRY_BUFFER_SECS))
                    .map(Datetime::new)
                    .unwrap_or_else(Datetime::now);
                expires_at > &now_with_buffer
            })
    }

    pub fn new(store: S, client: Arc<T>, client_data: ClientData<'static>) -> Self {
        let store = Arc::new(store);
        Self {
            store: Arc::clone(&store),
            client,
            client_data,
            pending: DashMap::new(),
        }
    }

    pub fn new_shared(store: Arc<S>, client: Arc<T>, client_data: ClientData<'static>) -> Self {
        Self {
            store,
            client,
            client_data,
            pending: DashMap::new(),
        }
    }
}

impl<T, S> SessionRegistry<T, S>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
{
    fn lifecycle_key(did: &Did<'_>, session_id: &str) -> SmolStr {
        format_smolstr!("{}\0{}", did, session_id)
    }

    pub(crate) async fn lock_session(
        &self,
        did: &Did<'_>,
        session_id: &str,
    ) -> OwnedMutexGuard<()> {
        self.pending
            .entry(Self::lifecycle_key(did, session_id))
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
            .lock_owned()
            .await
    }

    pub(crate) async fn acquire_operation(
        &self,
        did: &Did<'_>,
        session_id: &str,
        kind: SessionOperationKind,
    ) -> Result<SessionOperationLease, Error> {
        let owner = generate_verifier();
        for _ in 0..100 {
            match self
                .store
                .acquire_session_operation(did, session_id, kind, &owner, Self::OPERATION_LEASE_TTL)
                .await?
            {
                SessionOperationAcquire::Acquired(lease) => return Ok(*lease),
                SessionOperationAcquire::Missing => return Err(Error::SessionNotFound),
                SessionOperationAcquire::Busy => {
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
            }
        }
        Err(SessionStoreError::Other("session operation is busy".into()).into())
    }

    async fn get_refreshed(
        &self,
        did: &Did<'_>,
        session_id: &str,
    ) -> Result<ClientSessionData<'_>, Error> {
        let _guard = self.lock_session(did, session_id).await;

        let initial = self
            .store
            .get_session(did, session_id)
            .await?
            .ok_or(Error::SessionNotFound)?;

        // Check if token is still valid with a 60-second buffer before expiry.
        // This triggers proactive refresh before the token actually expires,
        // avoiding the race condition where a token expires mid-request.
        if Self::session_is_fresh(&initial) {
            return Ok(initial);
        }
        let lease = self
            .acquire_operation(did, session_id, SessionOperationKind::Refresh)
            .await?;
        if lease.uncertain_refresh {
            // Another worker may have quarantined this refresh family after
            // our initial read but before this lease was acquired. Durable
            // uncertainty dominates the stale snapshot: release only the
            // operation fence while preserving quarantine, and never send the
            // retained refresh token again.
            let _ = self.store.release_session_operation(&lease, true).await;
            return Err(Error::ReauthenticationRequired);
        }
        if Self::session_is_fresh(&lease.session) {
            return if self.store.release_session_operation(&lease, false).await? {
                Ok(lease.session)
            } else {
                Err(Error::SessionNotFound)
            };
        }
        let session = lease.session.clone();
        let metadata =
            match OAuthMetadata::new(self.client.as_ref(), &self.client_data, &session).await {
                Ok(metadata) => metadata,
                Err(error) => {
                    let _ = self.store.release_session_operation(&lease, false).await;
                    return Err(error.into());
                }
            };
        if !self
            .store
            .renew_session_operation(&lease, Self::OPERATION_LEASE_TTL)
            .await?
        {
            return Err(Error::SessionNotFound);
        }
        let (stop_renewal, mut renewal_stopped) = tokio::sync::oneshot::channel::<()>();
        let renewal_store = Arc::clone(&self.store);
        let renewal_lease = lease.clone();
        let renewal = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut renewal_stopped => return true,
                    _ = tokio::time::sleep(Duration::from_secs(40)) => {
                        match renewal_store.renew_session_operation(&renewal_lease, Self::OPERATION_LEASE_TTL).await {
                            Ok(true) => {}
                            _ => return false,
                        }
                    }
                }
            }
        });
        let refresh_result = refresh(self.client.as_ref(), session, &metadata).await;
        let _ = stop_renewal.send(());
        let renewal_live = renewal.await.unwrap_or(false);
        match refresh_result {
            Ok(refreshed) => {
                let renewed = if renewal_live {
                    self.store
                        .renew_session_operation(&lease, Self::OPERATION_LEASE_TTL)
                        .await
                        .unwrap_or(false)
                } else {
                    false
                };
                if !renewed {
                    compensate_uncommitted_refresh(self.client.as_ref(), refreshed, &metadata)
                        .await;
                    return Err(Error::SessionNotFound);
                }
                match self
                    .store
                    .commit_session_refresh(&lease, refreshed.clone())
                    .await
                {
                    Ok(Some(installed)) => Ok(installed),
                    Ok(None) => {
                        compensate_uncommitted_refresh(self.client.as_ref(), refreshed, &metadata)
                            .await;
                        Err(Error::SessionNotFound)
                    }
                    Err(error) => {
                        compensate_uncommitted_refresh(self.client.as_ref(), refreshed, &metadata)
                            .await;
                        Err(error.into())
                    }
                }
            }
            Err(e) if e.is_permanent() => {
                let _ = self.store.release_session_operation(&lease, false).await;
                let _ = self
                    .store
                    .delete_session(did, session_id, &lease.session.lifecycle_generation)
                    .await;
                Err(Error::RefreshFailed(e))
            }
            Err(e) => {
                // Quarantine only when the token endpoint may have issued
                // credentials without a trustworthy response reaching us.
                // Resolver/preflight failures and explicit OAuth errors are
                // safe to retry with the existing refresh token.
                let uncertain = e.refresh_outcome_is_ambiguous();
                let _ = self
                    .store
                    .release_session_operation(&lease, uncertain)
                    .await;
                Err(Error::ServerAgent(e))
            }
        }
    }
    pub async fn get(
        &self,
        did: &Did<'_>,
        session_id: &str,
        refresh: bool,
    ) -> Result<ClientSessionData<'_>, Error> {
        if refresh {
            self.get_refreshed(did, session_id).await
        } else {
            // TODO: cached?
            self.store
                .get_session(did, session_id)
                .await?
                .ok_or(Error::SessionNotFound)
        }
    }
    pub async fn set(&self, value: ClientSessionData<'_>) -> Result<(), Error> {
        let _guard = self
            .lock_session(&value.account_did, &value.session_id)
            .await;
        if !self.store.update_session(value).await? {
            return Err(Error::SessionNotFound);
        }
        Ok(())
    }

    /// Explicitly create a new lifecycle for a freshly-authorized session.
    /// Existing-session update paths must use [`Self::set`] or [`Self::update`]
    /// so data captured before logout cannot resurrect a deleted session.
    pub async fn create(
        &self,
        value: ClientSessionData<'_>,
    ) -> Result<ClientSessionData<'static>, Error> {
        let _guard = self
            .lock_session(&value.account_did, &value.session_id)
            .await;
        Ok(self.store.create_session(value).await?)
    }

    /// Atomically load and mutate an existing session under its lifecycle
    /// fence. The closure is synchronous by design so no untrusted work is
    /// performed while the fence is held.
    pub async fn update<F>(
        &self,
        did: &Did<'_>,
        session_id: &str,
        update: F,
    ) -> Result<ClientSessionData<'static>, Error>
    where
        F: FnOnce(&mut ClientSessionData<'static>),
    {
        let _guard = self.lock_session(did, session_id).await;
        let mut current = self
            .store
            .get_session(did, session_id)
            .await?
            .ok_or(Error::SessionNotFound)?
            .into_static();
        update(&mut current);
        if self.store.update_session(current.clone()).await? {
            Ok(current)
        } else {
            Err(Error::SessionNotFound)
        }
    }

    /// Rewrite the latest primary session and its secondary index without
    /// accepting caller-captured session data.
    pub async fn touch(
        &self,
        did: &Did<'_>,
        session_id: &str,
    ) -> Result<ClientSessionData<'static>, Error> {
        self.update(did, session_id, |_| {}).await
    }

    pub async fn del(&self, did: &Did<'_>, session_id: &str) -> Result<(), Error> {
        let _guard = self.lock_session(did, session_id).await;
        let current = self
            .store
            .get_session(did, session_id)
            .await?
            .ok_or(Error::SessionNotFound)?;
        self.delete_locked(did, session_id, &current.lifecycle_generation)
            .await
    }

    pub(crate) async fn delete_locked(
        &self,
        did: &Did<'_>,
        session_id: &str,
        lifecycle_generation: &str,
    ) -> Result<(), Error> {
        if self
            .store
            .delete_session(did, session_id, lifecycle_generation)
            .await?
        {
            Ok(())
        } else {
            Err(Error::SessionNotFound)
        }
    }
}
