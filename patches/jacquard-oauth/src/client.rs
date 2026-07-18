use crate::{
    atproto::atproto_client_metadata,
    authstore::ClientAuthStore,
    dpop::DpopExt,
    error::{CallbackError, Result},
    request::{OAuthMetadata, RequestError, exchange_code, par},
    resolver::OAuthResolver,
    scopes::Scope,
    session::{ClientData, ClientSessionData, DpopClientData, SessionRegistry},
    types::{AuthorizeOptions, CallbackParams},
    utils::generate_verifier,
};
use http::HeaderValue;
use jacquard_common::{
    AuthorizationToken, CowStr, IntoStatic,
    cowstr::ToCowStr,
    error::{AuthError, ClientError, XrpcResult},
    http_client::HttpClient,
    types::{did::Did, string::Handle},
    xrpc::{
        CallOptions, Response, XrpcClient, XrpcError, XrpcExt, XrpcRequest, XrpcResp, XrpcResponse,
        build_http_request, process_response,
    },
};

#[cfg(feature = "websocket")]
use jacquard_common::websocket::{WebSocketClient, WebSocketConnection};
#[cfg(feature = "websocket")]
use jacquard_common::xrpc::XrpcSubscription;
use jacquard_identity::{
    JacquardResolver,
    resolver::{DidDocResponse, IdentityError, IdentityResolver, ResolverOptions},
};
use jose_jwk::JwkSet;
use smol_str::ToSmolStr;
use std::{future::Future, sync::Arc};
use tokio::sync::RwLock;
use url::Url;

fn validate_authorization_location(value: &str) -> Result<()> {
    HeaderValue::from_str(value)
        .map(|_| ())
        .map_err(|error| RequestError::http_build(error).into())
}

fn parse_returned_scopes(scope: Option<&str>) -> Result<Vec<Scope<'static>>> {
    scope
        .map(Scope::parse_multiple_reduced)
        .transpose()
        .map(|scopes| scopes.unwrap_or_default().into_static())
        .map_err(|_| RequestError::token_verification().into())
}

fn fresh_session_id() -> CowStr<'static> {
    generate_verifier()
}

pub struct OAuthClient<T, S>
where
    T: OAuthResolver,
    S: ClientAuthStore,
{
    pub registry: Arc<SessionRegistry<T, S>>,
    pub options: RwLock<CallOptions<'static>>,
    pub endpoint: RwLock<Option<CowStr<'static>>>,
    pub client: Arc<T>,
}

impl<S: ClientAuthStore> OAuthClient<JacquardResolver, S> {
    pub fn new(store: S, client_data: ClientData<'static>) -> Self {
        let client = JacquardResolver::default();
        Self::new_from_resolver(store, client, client_data)
    }

    /// Create an OAuth client with the provided store and default localhost client metadata.
    ///
    /// This is a convenience constructor for quickly setting up an OAuth client
    /// with default localhost redirect URIs and "atproto transition:generic" scopes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use jacquard_oauth::client::OAuthClient;
    /// # use jacquard_oauth::authstore::MemoryAuthStore;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let store = MemoryAuthStore::new();
    /// let oauth = OAuthClient::with_default_config(store);
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_default_config(store: S) -> Self {
        let client_data = ClientData {
            keyset: None,
            config: crate::atproto::AtprotoClientMetadata::default_localhost(),
        };
        Self::new(store, client_data)
    }
}

impl OAuthClient<JacquardResolver, crate::authstore::MemoryAuthStore> {
    /// Create an OAuth client with an in-memory auth store and default localhost client metadata.
    ///
    /// This is a convenience constructor for simple testing and development.
    /// The session will not persist across restarts.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use jacquard_oauth::client::OAuthClient;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let oauth = OAuthClient::with_memory_store();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_memory_store() -> Self {
        Self::with_default_config(crate::authstore::MemoryAuthStore::new())
    }
}

impl<T, S> OAuthClient<T, S>
where
    T: OAuthResolver,
    S: ClientAuthStore,
{
    pub fn new_from_resolver(store: S, client: T, client_data: ClientData<'static>) -> Self {
        // #[cfg(feature = "tracing")]
        // tracing::info!(
        //     redirect_uris = ?client_data.config.redirect_uris,
        //     scopes = ?client_data.config.scopes,
        //     has_keyset = client_data.keyset.is_some(),
        //     "oauth client created:"
        // );

        let client = Arc::new(client);
        let registry = Arc::new(SessionRegistry::new(store, client.clone(), client_data));
        Self {
            registry,
            client,
            options: RwLock::new(CallOptions::default()),
            endpoint: RwLock::new(None),
        }
    }

    pub fn new_with_shared(
        store: Arc<S>,
        client: Arc<T>,
        client_data: ClientData<'static>,
    ) -> Self {
        let registry = Arc::new(SessionRegistry::new_shared(
            store,
            client.clone(),
            client_data,
        ));
        Self {
            registry,
            client,
            options: RwLock::new(CallOptions::default()),
            endpoint: RwLock::new(None),
        }
    }
}

#[cfg(test)]
mod revocation_security_tests {
    use super::{
        complete_logout_after_revocation, fresh_session_id, parse_returned_scopes,
        validate_authorization_location,
    };
    use crate::types::OAuthAuthorizationServerMetadata;
    use crate::{
        atproto::AtprotoClientMetadata,
        authstore::{
            ClientAuthStore, MemoryAuthStore, SessionOperationAcquire, SessionOperationKind,
            is_reauthentication_required, is_session_operation_active,
        },
        dpop::DpopExt,
        request::{RequestError, Result as RequestResult},
        resolver::OAuthResolver,
        session::{ClientData, ClientSessionData, DpopClientData, SessionRegistry},
        types::{OAuthTokenType, TokenSet},
    };
    use dashmap::DashMap;
    use http::{Request, Response, StatusCode};
    use jacquard_common::{
        CowStr, IntoStatic,
        http_client::HttpClient,
        types::{did::Did, string::Handle},
    };
    use jacquard_identity::resolver::{
        DidDocResponse, IdentityError, IdentityResolver, ResolverOptions,
    };
    use std::{
        convert::Infallible,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::{Barrier, Notify};
    use url::Url;

    #[derive(Clone)]
    struct NoopResolver;

    impl HttpClient for NoopResolver {
        type Error = Infallible;

        async fn send_http(
            &self,
            _request: Request<Vec<u8>>,
        ) -> core::result::Result<Response<Vec<u8>>, Self::Error> {
            unreachable!("logout decision tests do not perform HTTP")
        }
    }

    impl IdentityResolver for NoopResolver {
        fn options(&self) -> &ResolverOptions {
            use std::sync::LazyLock;
            static OPTIONS: LazyLock<ResolverOptions> = LazyLock::new(ResolverOptions::default);
            &OPTIONS
        }

        async fn resolve_handle(
            &self,
            _handle: &Handle<'_>,
        ) -> core::result::Result<Did<'static>, IdentityError> {
            unreachable!("logout decision tests do not resolve handles")
        }

        async fn resolve_did_doc(
            &self,
            _did: &Did<'_>,
        ) -> core::result::Result<DidDocResponse, IdentityError> {
            unreachable!("logout decision tests do not resolve DID documents")
        }
    }

    impl OAuthResolver for NoopResolver {}
    impl DpopExt for NoopResolver {}

    #[derive(Clone)]
    struct BlockingRefreshResolver {
        refresh_entered: Arc<Notify>,
        release_refresh: Arc<Notify>,
        revocation_started: Arc<AtomicBool>,
        revocation_bodies: Arc<Mutex<Vec<String>>>,
        fail_refresh: Arc<AtomicBool>,
        fail_issuer: Arc<AtomicBool>,
        malformed_refresh_sub: Arc<AtomicBool>,
        malformed_refresh_error: Arc<AtomicBool>,
        revoke_as_inactive: Arc<AtomicBool>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("simulated transport timeout")]
    struct SimulatedTransportTimeout;

    impl HttpClient for BlockingRefreshResolver {
        type Error = SimulatedTransportTimeout;

        async fn send_http(
            &self,
            request: Request<Vec<u8>>,
        ) -> core::result::Result<Response<Vec<u8>>, Self::Error> {
            match request.uri().path() {
                "/token" => {
                    self.refresh_entered.notify_one();
                    self.release_refresh.notified().await;
                    if self.fail_refresh.load(Ordering::SeqCst) {
                        return Err(SimulatedTransportTimeout);
                    }
                    if self.malformed_refresh_error.load(Ordering::SeqCst) {
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(b"not-json".to_vec())
                            .unwrap());
                    }
                    let mut body = serde_json::json!({
                        "access_token": "refreshed-access",
                        "refresh_token": "refreshed-refresh",
                        "token_type": "DPoP",
                        "expires_in": 3600
                    });
                    if self.malformed_refresh_sub.load(Ordering::SeqCst) {
                        body["sub"] = serde_json::Value::String("not-a-did".into());
                    }
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(serde_json::to_vec(&body).unwrap())
                        .unwrap())
                }
                "/revoke" => {
                    self.revocation_started.store(true, Ordering::SeqCst);
                    self.revocation_bodies
                        .lock()
                        .unwrap()
                        .push(String::from_utf8(request.body().clone()).unwrap());
                    if self.revoke_as_inactive.load(Ordering::SeqCst) {
                        Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .header("content-type", "application/json")
                            .body(br#"{"error":"invalid_grant"}"#.to_vec())
                            .unwrap())
                    } else {
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(Vec::new())
                            .unwrap())
                    }
                }
                path => panic!("unexpected OAuth endpoint: {path}"),
            }
        }
    }

    impl IdentityResolver for BlockingRefreshResolver {
        fn options(&self) -> &ResolverOptions {
            use std::sync::LazyLock;
            static OPTIONS: LazyLock<ResolverOptions> = LazyLock::new(ResolverOptions::default);
            &OPTIONS
        }

        async fn resolve_handle(
            &self,
            _handle: &Handle<'_>,
        ) -> core::result::Result<Did<'static>, IdentityError> {
            unreachable!("refresh race test does not resolve handles")
        }

        async fn resolve_did_doc(
            &self,
            _did: &Did<'_>,
        ) -> core::result::Result<DidDocResponse, IdentityError> {
            unreachable!("refresh race test overrides issuer verification")
        }
    }

    impl OAuthResolver for BlockingRefreshResolver {
        async fn verify_issuer(
            &self,
            _server_metadata: &OAuthAuthorizationServerMetadata<'_>,
            _sub: &Did<'_>,
        ) -> crate::resolver::Result<Url> {
            if self.fail_issuer.load(Ordering::SeqCst) {
                return Err(crate::resolver::ResolverError::transport(
                    SimulatedTransportTimeout,
                ));
            }
            Ok(Url::parse("https://pds.example").unwrap())
        }

        async fn get_authorization_server_metadata(
            &self,
            _issuer: &CowStr<'_>,
        ) -> crate::resolver::Result<OAuthAuthorizationServerMetadata<'static>> {
            let mut metadata = OAuthAuthorizationServerMetadata::default();
            metadata.issuer = CowStr::new_static("https://issuer.example");
            metadata.token_endpoint = CowStr::new_static("https://issuer.example/token");
            metadata.revocation_endpoint =
                Some(CowStr::new_static("https://issuer.example/revoke"));
            metadata.token_endpoint_auth_methods_supported = Some(vec![CowStr::new_static("none")]);
            Ok(metadata)
        }
    }
    impl DpopExt for BlockingRefreshResolver {}

    #[derive(Clone)]
    struct RefreshResponseResolver {
        status: StatusCode,
        refresh_dispatches: Arc<AtomicUsize>,
        block_next_dispatch: Arc<AtomicBool>,
        dispatch_entered: Arc<Notify>,
        release_dispatch: Arc<Notify>,
    }

    impl RefreshResponseResolver {
        fn new(status: StatusCode, refresh_dispatches: Arc<AtomicUsize>) -> Self {
            Self {
                status,
                refresh_dispatches,
                block_next_dispatch: Arc::new(AtomicBool::new(false)),
                dispatch_entered: Arc::new(Notify::new()),
                release_dispatch: Arc::new(Notify::new()),
            }
        }

        fn block_one_dispatch(&self) {
            self.block_next_dispatch.store(true, Ordering::SeqCst);
        }
    }

    impl HttpClient for RefreshResponseResolver {
        type Error = Infallible;

        async fn send_http(
            &self,
            request: Request<Vec<u8>>,
        ) -> core::result::Result<Response<Vec<u8>>, Self::Error> {
            assert_eq!(request.uri().path(), "/token");
            self.refresh_dispatches.fetch_add(1, Ordering::SeqCst);
            if self.block_next_dispatch.swap(false, Ordering::SeqCst) {
                self.dispatch_entered.notify_one();
                self.release_dispatch.notified().await;
            }
            let body = if self.status == StatusCode::OK {
                serde_json::to_vec(&serde_json::json!({
                    "access_token": "refreshed-access",
                    "refresh_token": "refreshed-refresh",
                    "token_type": "DPoP",
                    "expires_in": 3600
                }))
                .unwrap()
            } else {
                Vec::new()
            };
            Ok(Response::builder()
                .status(self.status)
                .header("content-type", "application/json")
                .body(body)
                .unwrap())
        }
    }

    impl IdentityResolver for RefreshResponseResolver {
        fn options(&self) -> &ResolverOptions {
            use std::sync::LazyLock;
            static OPTIONS: LazyLock<ResolverOptions> = LazyLock::new(ResolverOptions::default);
            &OPTIONS
        }

        async fn resolve_handle(
            &self,
            _handle: &Handle<'_>,
        ) -> core::result::Result<Did<'static>, IdentityError> {
            unreachable!("refresh tests do not resolve handles")
        }

        async fn resolve_did_doc(
            &self,
            _did: &Did<'_>,
        ) -> core::result::Result<DidDocResponse, IdentityError> {
            unreachable!("refresh tests override issuer verification")
        }
    }

    impl OAuthResolver for RefreshResponseResolver {
        async fn verify_issuer(
            &self,
            _server_metadata: &OAuthAuthorizationServerMetadata<'_>,
            _sub: &Did<'_>,
        ) -> crate::resolver::Result<Url> {
            Ok(Url::parse("https://pds.example").unwrap())
        }

        async fn get_authorization_server_metadata(
            &self,
            _issuer: &CowStr<'_>,
        ) -> crate::resolver::Result<OAuthAuthorizationServerMetadata<'static>> {
            let mut metadata = OAuthAuthorizationServerMetadata::default();
            metadata.issuer = CowStr::new_static("https://issuer.example");
            metadata.token_endpoint = CowStr::new_static("https://issuer.example/token");
            metadata.token_endpoint_auth_methods_supported = Some(vec![CowStr::new_static("none")]);
            Ok(metadata)
        }
    }

    impl DpopExt for RefreshResponseResolver {}

    struct IndexedMemoryAuthStore {
        inner: MemoryAuthStore,
        index: DashMap<String, String>,
        block_next_update: AtomicBool,
        update_entered: Notify,
        release_update: Notify,
        fail_renew_countdown: AtomicUsize,
        coordinated_initial_reads: AtomicUsize,
        initial_read_barrier: Barrier,
        busy_acquisitions: AtomicUsize,
        busy_acquisition_seen: Notify,
        fail_next_release: AtomicBool,
    }

    impl IndexedMemoryAuthStore {
        fn new() -> Self {
            Self {
                inner: MemoryAuthStore::new(),
                index: DashMap::new(),
                block_next_update: AtomicBool::new(false),
                update_entered: Notify::new(),
                release_update: Notify::new(),
                fail_renew_countdown: AtomicUsize::new(0),
                coordinated_initial_reads: AtomicUsize::new(0),
                initial_read_barrier: Barrier::new(2),
                busy_acquisitions: AtomicUsize::new(0),
                busy_acquisition_seen: Notify::new(),
                fail_next_release: AtomicBool::new(false),
            }
        }

        fn has_index(&self, session_id: &str) -> bool {
            self.index.contains_key(session_id)
        }

        fn block_one_update(&self) {
            self.block_next_update.store(true, Ordering::SeqCst);
        }

        fn coordinate_two_initial_reads(&self) {
            self.coordinated_initial_reads.store(2, Ordering::SeqCst);
        }

        fn fail_one_release(&self) {
            self.fail_next_release.store(true, Ordering::SeqCst);
        }
    }

    impl ClientAuthStore for IndexedMemoryAuthStore {
        async fn get_session(
            &self,
            did: &Did<'_>,
            session_id: &str,
        ) -> core::result::Result<
            Option<ClientSessionData<'_>>,
            jacquard_common::session::SessionStoreError,
        > {
            let coordinate = self
                .coordinated_initial_reads
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok();
            if coordinate {
                let snapshot = self.inner.get_session(did, session_id).await;
                self.initial_read_barrier.wait().await;
                return snapshot;
            }
            self.inner.get_session(did, session_id).await
        }

        async fn create_session(
            &self,
            session: ClientSessionData<'_>,
        ) -> core::result::Result<
            ClientSessionData<'static>,
            jacquard_common::session::SessionStoreError,
        > {
            let session = self.inner.create_session(session).await?;
            self.index.insert(
                session.session_id.to_string(),
                session.account_did.to_string(),
            );
            Ok(session)
        }

        async fn update_session(
            &self,
            session: ClientSessionData<'_>,
        ) -> core::result::Result<bool, jacquard_common::session::SessionStoreError> {
            if self.block_next_update.swap(false, Ordering::SeqCst) {
                self.update_entered.notify_one();
                self.release_update.notified().await;
            }
            let session_id = session.session_id.to_string();
            let did = session.account_did.to_string();
            let updated = self.inner.update_session(session).await?;
            if updated {
                self.index.insert(session_id, did);
            }
            Ok(updated)
        }

        async fn delete_session(
            &self,
            did: &Did<'_>,
            session_id: &str,
            lifecycle_generation: &str,
        ) -> core::result::Result<bool, jacquard_common::session::SessionStoreError> {
            let deleted = self
                .inner
                .delete_session(did, session_id, lifecycle_generation)
                .await?;
            if deleted {
                self.index.remove(session_id);
            }
            Ok(deleted)
        }

        async fn acquire_session_operation(
            &self,
            did: &Did<'_>,
            session_id: &str,
            kind: crate::authstore::SessionOperationKind,
            owner: &str,
            ttl: std::time::Duration,
        ) -> core::result::Result<
            crate::authstore::SessionOperationAcquire,
            jacquard_common::session::SessionStoreError,
        > {
            let acquired = self
                .inner
                .acquire_session_operation(did, session_id, kind, owner, ttl)
                .await?;
            if matches!(acquired, crate::authstore::SessionOperationAcquire::Busy) {
                self.busy_acquisitions.fetch_add(1, Ordering::SeqCst);
                self.busy_acquisition_seen.notify_one();
            }
            Ok(acquired)
        }

        async fn renew_session_operation(
            &self,
            lease: &crate::authstore::SessionOperationLease,
            ttl: std::time::Duration,
        ) -> core::result::Result<bool, jacquard_common::session::SessionStoreError> {
            let countdown = self.fail_renew_countdown.load(Ordering::SeqCst);
            if countdown > 0 {
                let previous = self.fail_renew_countdown.fetch_sub(1, Ordering::SeqCst);
                if previous == 1 {
                    return Ok(false);
                }
            }
            self.inner.renew_session_operation(lease, ttl).await
        }

        async fn commit_session_refresh(
            &self,
            lease: &crate::authstore::SessionOperationLease,
            refreshed: ClientSessionData<'_>,
        ) -> core::result::Result<
            Option<ClientSessionData<'static>>,
            jacquard_common::session::SessionStoreError,
        > {
            if self.block_next_update.swap(false, Ordering::SeqCst) {
                self.update_entered.notify_one();
                self.release_update.notified().await;
            }
            let installed = self.inner.commit_session_refresh(lease, refreshed).await?;
            if let Some(session) = &installed {
                self.index.insert(
                    session.session_id.to_string(),
                    session.account_did.to_string(),
                );
            }
            Ok(installed)
        }

        async fn complete_session_revoke(
            &self,
            lease: &crate::authstore::SessionOperationLease,
        ) -> core::result::Result<bool, jacquard_common::session::SessionStoreError> {
            let completed = self.inner.complete_session_revoke(lease).await?;
            if completed {
                self.index.remove(lease.session.session_id.as_ref());
            }
            Ok(completed)
        }

        async fn release_session_operation(
            &self,
            lease: &crate::authstore::SessionOperationLease,
            uncertain: bool,
        ) -> core::result::Result<bool, jacquard_common::session::SessionStoreError> {
            if self.fail_next_release.swap(false, Ordering::SeqCst) {
                return Ok(false);
            }
            self.inner.release_session_operation(lease, uncertain).await
        }

        async fn get_auth_req_info(
            &self,
            state: &str,
        ) -> core::result::Result<
            Option<crate::session::AuthRequestData<'_>>,
            jacquard_common::session::SessionStoreError,
        > {
            self.inner.get_auth_req_info(state).await
        }

        async fn save_auth_req_info(
            &self,
            auth_req_info: &crate::session::AuthRequestData<'_>,
        ) -> core::result::Result<(), jacquard_common::session::SessionStoreError> {
            self.inner.save_auth_req_info(auth_req_info).await
        }

        async fn delete_auth_req_info(
            &self,
            state: &str,
        ) -> core::result::Result<(), jacquard_common::session::SessionStoreError> {
            self.inner.delete_auth_req_info(state).await
        }
    }

    fn test_session() -> ClientSessionData<'static> {
        let did = Did::new_static("did:plc:alice").unwrap();
        ClientSessionData {
            lifecycle_generation: CowStr::default(),
            account_did: did.clone(),
            session_id: CowStr::new_static("session-a"),
            host_url: CowStr::new_static("https://pds.example"),
            authserver_url: CowStr::new_static("https://issuer.example"),
            authserver_token_endpoint: CowStr::new_static("https://issuer.example/token"),
            authserver_revocation_endpoint: Some(CowStr::new_static(
                "https://issuer.example/revoke",
            )),
            scopes: vec![],
            dpop_data: DpopClientData {
                dpop_key: crate::utils::generate_key(&[CowStr::new_static("ES256")]).unwrap(),
                dpop_authserver_nonce: CowStr::new_static(""),
                dpop_host_nonce: CowStr::new_static(""),
            },
            token_set: TokenSet {
                iss: CowStr::new_static("https://issuer.example"),
                sub: did,
                aud: CowStr::new_static("https://pds.example"),
                scope: None,
                refresh_token: Some(CowStr::new_static("refresh")),
                access_token: CowStr::new_static("access"),
                token_type: OAuthTokenType::DPoP,
                expires_at: None,
            },
        }
    }

    #[test]
    fn completed_session_credential_is_fresh_and_provider_state_independent() {
        let provider_visible_state = "provider-visible-oauth-state";
        let first = fresh_session_id();
        let second = fresh_session_id();

        assert_ne!(first.as_str(), provider_visible_state);
        assert_ne!(second.as_str(), provider_visible_state);
        assert_ne!(first, second);
        assert!(first.len() >= 43);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }

    #[test]
    fn returned_scopes_and_authorization_locations_fail_typed() {
        assert!(parse_returned_scopes(Some("atproto")).is_ok());
        assert!(parse_returned_scopes(Some("unknown:scope")).is_err());
        assert!(validate_authorization_location("https://issuer.example/authorize").is_ok());
        assert!(
            validate_authorization_location("https://issuer.example/authorize\ninvalid").is_err()
        );
    }

    #[tokio::test]
    async fn durable_uncertainty_is_typed_reauthentication_without_session_deletion() {
        let store = Arc::new(MemoryAuthStore::new());
        let session = store.create_session(test_session()).await.unwrap();
        let refresh_lease = match store
            .acquire_session_operation(
                &session.account_did,
                &session.session_id,
                SessionOperationKind::Refresh,
                "refresh-owner",
                Duration::from_millis(50),
            )
            .await
            .unwrap()
        {
            SessionOperationAcquire::Acquired(lease) => lease,
            other => panic!("expected acquired refresh lease, got {other:?}"),
        };

        let active = store
            .get_session(&session.account_did, &session.session_id)
            .await
            .unwrap_err();
        assert!(!is_reauthentication_required(&active));
        assert!(is_session_operation_active(&active));

        let registry = SessionRegistry::new_shared(
            Arc::clone(&store),
            Arc::new(NoopResolver),
            ClientData {
                keyset: None,
                config: AtprotoClientMetadata::default_localhost(),
            },
        );
        assert!(matches!(
            registry
                .get(&session.account_did, &session.session_id, false)
                .await,
            Err(crate::session::Error::OperationInProgress)
        ));

        tokio::time::sleep(Duration::from_millis(75)).await;

        let quarantined = store
            .get_session(&session.account_did, &session.session_id)
            .await
            .unwrap_err();
        assert!(is_reauthentication_required(&quarantined));

        assert!(matches!(
            registry
                .get(&session.account_did, &session.session_id, false)
                .await,
            Err(crate::session::Error::ReauthenticationRequired)
        ));

        let retained = store
            .acquire_session_operation(
                &session.account_did,
                &session.session_id,
                SessionOperationKind::Revoke,
                "revoke-owner",
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert!(matches!(
            retained,
            SessionOperationAcquire::Acquired(ref lease)
                if lease.uncertain_refresh
                    && lease.session.session_id == session.session_id
                    && lease.session.token_set.refresh_token
                        == refresh_lease.session.token_set.refresh_token
        ));

        let session = store.create_session(test_session()).await.unwrap();
        let revoke_lease = match store
            .acquire_session_operation(
                &session.account_did,
                &session.session_id,
                SessionOperationKind::Revoke,
                "expiring-revoke-owner",
                Duration::from_millis(50),
            )
            .await
            .unwrap()
        {
            SessionOperationAcquire::Acquired(lease) => lease,
            other => panic!("expected acquired revoke lease, got {other:?}"),
        };
        let active = store
            .get_session(&session.account_did, &session.session_id)
            .await
            .unwrap_err();
        assert!(!is_reauthentication_required(&active));

        tokio::time::sleep(Duration::from_millis(75)).await;
        let readable = store
            .get_session(&session.account_did, &session.session_id)
            .await
            .unwrap()
            .expect("expired revoke lease must not hide the retained session");
        assert_eq!(
            readable.lifecycle_generation,
            revoke_lease.session.lifecycle_generation
        );
    }

    async fn assert_logout_result(revocation: RequestResult<()>, should_delete: bool) {
        let store = Arc::new(IndexedMemoryAuthStore::new());
        let registry = SessionRegistry::new_shared(
            Arc::clone(&store),
            Arc::new(NoopResolver),
            ClientData {
                keyset: None,
                config: AtprotoClientMetadata::default_localhost(),
            },
        );
        let session = test_session();
        registry.create(session.clone()).await.unwrap();

        let result = complete_logout_after_revocation(
            &registry,
            &session.account_did,
            &session.session_id,
            revocation,
        )
        .await;
        assert_eq!(result.is_ok(), should_delete);
        assert_eq!(
            store
                .get_session(&session.account_did, &session.session_id)
                .await
                .unwrap()
                .is_none(),
            should_delete
        );
        assert_eq!(!store.has_index(&session.session_id), should_delete);
    }

    #[test]
    fn logout_requires_revocation_endpoint_and_prefers_refresh_grant_token() {
        assert!(super::required_revocation_token(false, Some("refresh"), "access").is_err());
        assert_eq!(
            super::required_revocation_token(true, Some("refresh"), "access").unwrap(),
            "refresh"
        );
        assert_eq!(
            super::required_revocation_token(true, None, "access").unwrap(),
            "access"
        );
    }

    #[tokio::test]
    async fn local_session_deletion_requires_success_or_status_bound_inactive_grant() {
        assert_logout_result(Ok(()), true).await;
        for code in ["invalid_token", "invalid_grant"] {
            assert_logout_result(
                Err(RequestError::http_status_with_body(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({ "error": code }),
                )),
                true,
            )
            .await;
        }

        for (status, code) in [
            (StatusCode::BAD_REQUEST, "access_denied"),
            (StatusCode::BAD_REQUEST, "invalid_client"),
            (StatusCode::BAD_REQUEST, "temporarily_unavailable"),
            (StatusCode::UNAUTHORIZED, "invalid_token"),
            (StatusCode::TOO_MANY_REQUESTS, "invalid_grant"),
        ] {
            assert_logout_result(
                Err(RequestError::http_status_with_body(
                    status,
                    serde_json::json!({ "error": code }),
                )),
                false,
            )
            .await;
        }
        assert_logout_result(
            Err(RequestError::http_status(StatusCode::SERVICE_UNAVAILABLE)),
            false,
        )
        .await;
        assert_logout_result(Err(RequestError::token_verification()), false).await;
    }

    #[tokio::test]
    async fn blocked_refresh_finishes_before_logout_deletes_session() {
        let store = Arc::new(MemoryAuthStore::new());
        let refresh_entered = Arc::new(Notify::new());
        let release_refresh = Arc::new(Notify::new());
        let resolver = Arc::new(BlockingRefreshResolver {
            refresh_entered: Arc::clone(&refresh_entered),
            release_refresh: Arc::clone(&release_refresh),
            revocation_started: Arc::new(AtomicBool::new(false)),
            revocation_bodies: Arc::new(Mutex::new(Vec::new())),
            fail_refresh: Arc::new(AtomicBool::new(false)),
            fail_issuer: Arc::new(AtomicBool::new(false)),
            malformed_refresh_sub: Arc::new(AtomicBool::new(false)),
            malformed_refresh_error: Arc::new(AtomicBool::new(false)),
            revoke_as_inactive: Arc::new(AtomicBool::new(false)),
        });
        let registry = Arc::new(SessionRegistry::new_shared(
            Arc::clone(&store),
            resolver,
            ClientData {
                keyset: None,
                config: AtprotoClientMetadata::default_localhost(),
            },
        ));
        let session = test_session();
        registry.create(session.clone()).await.unwrap();

        let refresh_registry = Arc::clone(&registry);
        let did = session.account_did.clone();
        let session_id = session.session_id.clone();
        let refresh_task = tokio::spawn(async move {
            refresh_registry
                .get(&did, &session_id, true)
                .await
                .map(IntoStatic::into_static)
        });
        refresh_entered.notified().await;

        let logout_registry = Arc::clone(&registry);
        let did = session.account_did.clone();
        let session_id = session.session_id.clone();
        let logout_task = tokio::spawn(async move {
            complete_logout_after_revocation(logout_registry.as_ref(), &did, &session_id, Ok(()))
                .await
        });

        release_refresh.notify_one();
        assert_eq!(
            refresh_task.await.unwrap().unwrap().token_set.access_token,
            "refreshed-access"
        );
        logout_task.await.unwrap().unwrap();
        assert!(
            store
                .get_session(&session.account_did, &session.session_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn same_object_logout_waits_for_refresh_and_revokes_refreshed_credentials() {
        let store = Arc::new(MemoryAuthStore::new());
        let refresh_entered = Arc::new(Notify::new());
        let release_refresh = Arc::new(Notify::new());
        let revocation_started = Arc::new(AtomicBool::new(false));
        let revocation_bodies = Arc::new(Mutex::new(Vec::new()));
        let resolver = Arc::new(BlockingRefreshResolver {
            refresh_entered: Arc::clone(&refresh_entered),
            release_refresh: Arc::clone(&release_refresh),
            revocation_started: Arc::clone(&revocation_started),
            revocation_bodies: Arc::clone(&revocation_bodies),
            fail_refresh: Arc::new(AtomicBool::new(false)),
            fail_issuer: Arc::new(AtomicBool::new(false)),
            malformed_refresh_sub: Arc::new(AtomicBool::new(false)),
            malformed_refresh_error: Arc::new(AtomicBool::new(false)),
            revoke_as_inactive: Arc::new(AtomicBool::new(false)),
        });
        let registry = Arc::new(SessionRegistry::new_shared(
            Arc::clone(&store),
            Arc::clone(&resolver),
            ClientData {
                keyset: None,
                config: AtprotoClientMetadata::default_localhost(),
            },
        ));
        let original = test_session();
        let created = registry.create(original.clone()).await.unwrap();
        let session = Arc::new(super::OAuthSession::new(
            Arc::clone(&registry),
            resolver,
            created,
        ));

        let refreshing = Arc::clone(&session);
        let refresh_task = tokio::spawn(async move {
            refreshing.refresh().await.map(|token| match token {
                jacquard_common::AuthorizationToken::Dpop(token) => token.to_string(),
                _ => panic!("refresh returned the wrong authorization scheme"),
            })
        });
        refresh_entered.notified().await;
        let logging_out = Arc::clone(&session);
        let logout_task = tokio::spawn(async move { logging_out.logout().await });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(
            !revocation_started.load(Ordering::SeqCst),
            "logout must not revoke stale credentials while refresh owns the object fence"
        );

        release_refresh.notify_one();
        assert_eq!(refresh_task.await.unwrap().unwrap(), "refreshed-access");
        logout_task.await.unwrap().unwrap();
        assert!(revocation_started.load(Ordering::SeqCst));
        assert!(
            revocation_bodies
                .lock()
                .unwrap()
                .iter()
                .any(|body| body.contains("token=refreshed-refresh")),
            "logout must revoke the refreshed token, not the pre-refresh token"
        );
        assert!(
            store
                .get_session(&original.account_did, &original.session_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            session.refresh().await.is_err(),
            "refresh must not publish credentials after logout completes"
        );
    }

    #[tokio::test]
    async fn cross_registry_logout_revokes_a_concurrently_issued_refresh_grant() {
        let store = Arc::new(IndexedMemoryAuthStore::new());
        let refresh_entered = Arc::new(Notify::new());
        let release_refresh = Arc::new(Notify::new());
        let revocation_started = Arc::new(AtomicBool::new(false));
        let revocation_bodies = Arc::new(Mutex::new(Vec::new()));
        let resolver = Arc::new(BlockingRefreshResolver {
            refresh_entered: Arc::clone(&refresh_entered),
            release_refresh: Arc::clone(&release_refresh),
            revocation_started,
            revocation_bodies: Arc::clone(&revocation_bodies),
            fail_refresh: Arc::new(AtomicBool::new(false)),
            fail_issuer: Arc::new(AtomicBool::new(false)),
            malformed_refresh_sub: Arc::new(AtomicBool::new(false)),
            malformed_refresh_error: Arc::new(AtomicBool::new(false)),
            revoke_as_inactive: Arc::new(AtomicBool::new(false)),
        });
        let client_data = ClientData {
            keyset: None,
            config: AtprotoClientMetadata::default_localhost(),
        };
        let refresh_client = Arc::new(super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            Arc::clone(&resolver),
            client_data.clone(),
        ));
        let logout_client = Arc::new(super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            resolver,
            client_data,
        ));
        let session = refresh_client
            .registry
            .create(test_session())
            .await
            .unwrap();
        let refreshing = Arc::clone(&refresh_client);
        let did = session.account_did.clone();
        let session_id = session.session_id.clone();
        let refresh_task = tokio::spawn(async move {
            refreshing
                .registry
                .get(&did, &session_id, true)
                .await
                .map(IntoStatic::into_static)
        });
        refresh_entered.notified().await;
        let logging_out = Arc::clone(&logout_client);
        let logout_did = session.account_did.clone();
        let logout_session_id = session.session_id.clone();
        let logout_task =
            tokio::spawn(async move { logging_out.revoke(&logout_did, &logout_session_id).await });
        tokio::task::yield_now().await;
        assert!(
            !logout_client
                .client
                .revocation_started
                .load(Ordering::SeqCst)
        );
        release_refresh.notify_one();
        assert!(refresh_task.await.unwrap().is_ok());
        logout_task.await.unwrap().unwrap();
        assert!(
            store
                .get_session(&session.account_did, &session.session_id)
                .await
                .unwrap()
                .is_none()
        );

        let bodies = revocation_bodies.lock().unwrap();
        assert!(
            bodies
                .iter()
                .any(|body| body.contains("token=refreshed-refresh")),
            "logout must reload and revoke the grant committed by the lease holder"
        );
    }

    #[tokio::test]
    async fn cross_registry_waiter_rechecks_fresh_session_after_acquiring_lease() {
        let store = Arc::new(IndexedMemoryAuthStore::new());
        store.coordinate_two_initial_reads();
        let refresh_dispatches = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(RefreshResponseResolver::new(
            StatusCode::OK,
            Arc::clone(&refresh_dispatches),
        ));
        resolver.block_one_dispatch();
        let client_data = ClientData {
            keyset: None,
            config: AtprotoClientMetadata::default_localhost(),
        };
        let first = Arc::new(super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            Arc::clone(&resolver),
            client_data.clone(),
        ));
        let second = Arc::new(super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            Arc::clone(&resolver),
            client_data,
        ));
        let session = first.registry.create(test_session()).await.unwrap();

        let first_did = session.account_did.clone();
        let first_session_id = session.session_id.clone();
        let first_task = tokio::spawn(async move {
            first
                .registry
                .get(&first_did, &first_session_id, true)
                .await
                .map(IntoStatic::into_static)
        });
        let second_did = session.account_did.clone();
        let second_session_id = session.session_id.clone();
        let second_task = tokio::spawn(async move {
            second
                .registry
                .get(&second_did, &second_session_id, true)
                .await
                .map(IntoStatic::into_static)
        });

        resolver.dispatch_entered.notified().await;
        store.busy_acquisition_seen.notified().await;
        assert!(store.busy_acquisitions.load(Ordering::SeqCst) > 0);
        resolver.release_dispatch.notify_one();

        let (first_result, second_result) = tokio::join!(first_task, second_task);
        assert_eq!(
            first_result.unwrap().unwrap().token_set.access_token,
            "refreshed-access"
        );
        assert_eq!(
            second_result.unwrap().unwrap().token_set.access_token,
            "refreshed-access"
        );
        assert_eq!(
            refresh_dispatches.load(Ordering::SeqCst),
            1,
            "a waiter must not rotate a grant that became fresh before lease acquisition"
        );
        assert!(
            store
                .get_session(&session.account_did, &session.session_id)
                .await
                .unwrap()
                .is_some(),
            "the redundant lease must be released without quarantining the fresh session"
        );
    }

    #[tokio::test]
    async fn cross_registry_waiter_never_refreshes_an_uncertain_lease() {
        let store = Arc::new(IndexedMemoryAuthStore::new());
        store.coordinate_two_initial_reads();
        let refresh_dispatches = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(RefreshResponseResolver::new(
            StatusCode::SERVICE_UNAVAILABLE,
            Arc::clone(&refresh_dispatches),
        ));
        resolver.block_one_dispatch();
        let client_data = ClientData {
            keyset: None,
            config: AtprotoClientMetadata::default_localhost(),
        };
        let first = Arc::new(super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            Arc::clone(&resolver),
            client_data.clone(),
        ));
        let second = Arc::new(super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            Arc::clone(&resolver),
            client_data,
        ));
        let session = first.registry.create(test_session()).await.unwrap();

        let first_did = session.account_did.clone();
        let first_session_id = session.session_id.clone();
        let first_task = tokio::spawn(async move {
            first
                .registry
                .get(&first_did, &first_session_id, true)
                .await
                .map(IntoStatic::into_static)
        });
        let second_did = session.account_did.clone();
        let second_session_id = session.session_id.clone();
        let second_task = tokio::spawn(async move {
            second
                .registry
                .get(&second_did, &second_session_id, true)
                .await
                .map(IntoStatic::into_static)
        });

        resolver.dispatch_entered.notified().await;
        store.busy_acquisition_seen.notified().await;
        resolver.release_dispatch.notify_one();

        let (first_result, second_result) = tokio::join!(first_task, second_task);
        let results = [first_result.unwrap(), second_result.unwrap()];
        assert!(
            results.iter().any(|result| matches!(
                result,
                Err(crate::session::Error::ReauthenticationRequired)
            ))
        );
        assert_eq!(
            refresh_dispatches.load(Ordering::SeqCst),
            1,
            "a waiter must not dispatch a quarantined refresh token"
        );
        assert!(is_reauthentication_required(
            &store
                .get_session(&session.account_did, &session.session_id)
                .await
                .unwrap_err()
        ));
    }

    #[tokio::test]
    async fn fresh_session_release_owner_mismatch_fails_closed() {
        let store = Arc::new(IndexedMemoryAuthStore::new());
        store.coordinate_two_initial_reads();
        let refresh_dispatches = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(RefreshResponseResolver::new(
            StatusCode::OK,
            Arc::clone(&refresh_dispatches),
        ));
        resolver.block_one_dispatch();
        let client_data = ClientData {
            keyset: None,
            config: AtprotoClientMetadata::default_localhost(),
        };
        let first = Arc::new(super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            Arc::clone(&resolver),
            client_data.clone(),
        ));
        let second = Arc::new(super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            Arc::clone(&resolver),
            client_data,
        ));
        let session = first.registry.create(test_session()).await.unwrap();

        let first_did = session.account_did.clone();
        let first_session_id = session.session_id.clone();
        let first_task = tokio::spawn(async move {
            first
                .registry
                .get(&first_did, &first_session_id, true)
                .await
                .map(IntoStatic::into_static)
        });
        let second_did = session.account_did.clone();
        let second_session_id = session.session_id.clone();
        let second_task = tokio::spawn(async move {
            second
                .registry
                .get(&second_did, &second_session_id, true)
                .await
                .map(IntoStatic::into_static)
        });

        resolver.dispatch_entered.notified().await;
        store.busy_acquisition_seen.notified().await;
        store.fail_one_release();
        resolver.release_dispatch.notify_one();

        let (first_result, second_result) = tokio::join!(first_task, second_task);
        let results = [first_result.unwrap(), second_result.unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .any(|result| matches!(result, Err(crate::session::Error::SessionNotFound)))
        );
        assert_eq!(store.busy_acquisitions.load(Ordering::SeqCst), 1);
        assert_eq!(refresh_dispatches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn postdispatch_server_error_quarantines_refresh_family() {
        let store = Arc::new(MemoryAuthStore::new());
        let refresh_dispatches = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(RefreshResponseResolver::new(
            StatusCode::SERVICE_UNAVAILABLE,
            Arc::clone(&refresh_dispatches),
        ));
        let client = super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            resolver,
            ClientData {
                keyset: None,
                config: AtprotoClientMetadata::default_localhost(),
            },
        );
        let session = client.registry.create(test_session()).await.unwrap();

        assert!(
            client
                .registry
                .get(&session.account_did, &session.session_id, true)
                .await
                .is_err()
        );
        assert_eq!(refresh_dispatches.load(Ordering::SeqCst), 1);
        let quarantined = store
            .get_session(&session.account_did, &session.session_id)
            .await
            .expect_err("post-dispatch 5xx must retain durable refresh uncertainty");
        assert!(is_reauthentication_required(&quarantined));
    }

    #[tokio::test]
    async fn lost_refresh_fence_revokes_the_uncommitted_grant() {
        let store = Arc::new(IndexedMemoryAuthStore::new());
        store.fail_renew_countdown.store(2, Ordering::SeqCst);
        let refresh_entered = Arc::new(Notify::new());
        let release_refresh = Arc::new(Notify::new());
        let revocation_bodies = Arc::new(Mutex::new(Vec::new()));
        let resolver = Arc::new(BlockingRefreshResolver {
            refresh_entered: Arc::clone(&refresh_entered),
            release_refresh: Arc::clone(&release_refresh),
            revocation_started: Arc::new(AtomicBool::new(false)),
            revocation_bodies: Arc::clone(&revocation_bodies),
            fail_refresh: Arc::new(AtomicBool::new(false)),
            fail_issuer: Arc::new(AtomicBool::new(false)),
            malformed_refresh_sub: Arc::new(AtomicBool::new(false)),
            malformed_refresh_error: Arc::new(AtomicBool::new(false)),
            revoke_as_inactive: Arc::new(AtomicBool::new(false)),
        });
        let client = super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            resolver,
            ClientData {
                keyset: None,
                config: AtprotoClientMetadata::default_localhost(),
            },
        );
        let session = client.registry.create(test_session()).await.unwrap();
        let did = session.account_did.clone();
        let session_id = session.session_id.clone();
        let refresh_task = tokio::spawn(async move {
            client
                .registry
                .get(&did, &session_id, true)
                .await
                .map(IntoStatic::into_static)
        });
        refresh_entered.notified().await;
        release_refresh.notify_one();
        assert!(refresh_task.await.unwrap().is_err());
        assert!(
            revocation_bodies
                .lock()
                .unwrap()
                .iter()
                .any(|body| body.contains("token=refreshed-refresh"))
        );
    }

    #[tokio::test]
    async fn predispatch_issuer_failure_releases_quarantine_and_remains_refreshable() {
        let store = Arc::new(MemoryAuthStore::new());
        let refresh_entered = Arc::new(Notify::new());
        let release_refresh = Arc::new(Notify::new());
        let fail_issuer = Arc::new(AtomicBool::new(true));
        let resolver = Arc::new(BlockingRefreshResolver {
            refresh_entered: Arc::clone(&refresh_entered),
            release_refresh: Arc::clone(&release_refresh),
            revocation_started: Arc::new(AtomicBool::new(false)),
            revocation_bodies: Arc::new(Mutex::new(Vec::new())),
            fail_refresh: Arc::new(AtomicBool::new(false)),
            fail_issuer: Arc::clone(&fail_issuer),
            malformed_refresh_sub: Arc::new(AtomicBool::new(false)),
            malformed_refresh_error: Arc::new(AtomicBool::new(false)),
            revoke_as_inactive: Arc::new(AtomicBool::new(false)),
        });
        let client = Arc::new(super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            resolver,
            ClientData {
                keyset: None,
                config: AtprotoClientMetadata::default_localhost(),
            },
        ));
        let session = client.registry.create(test_session()).await.unwrap();

        assert!(
            client
                .registry
                .get(&session.account_did, &session.session_id, true)
                .await
                .is_err()
        );
        assert!(
            store
                .get_session(&session.account_did, &session.session_id)
                .await
                .unwrap()
                .is_some(),
            "issuer preflight failure must clear the temporary uncertainty marker"
        );

        fail_issuer.store(false, Ordering::SeqCst);
        let retrying = Arc::clone(&client);
        let did = session.account_did.clone();
        let session_id = session.session_id.clone();
        let retry = tokio::spawn(async move {
            retrying
                .registry
                .get(&did, &session_id, true)
                .await
                .map(IntoStatic::into_static)
        });
        refresh_entered.notified().await;
        release_refresh.notify_one();
        assert_eq!(
            retry.await.unwrap().unwrap().token_set.access_token,
            "refreshed-access"
        );
    }

    #[tokio::test]
    async fn refresh_response_stage_controls_uncertainty() {
        for (malformed_sub, malformed_error, expect_quarantined) in
            [(true, false, true), (false, true, false)]
        {
            let store = Arc::new(MemoryAuthStore::new());
            let release_refresh = Arc::new(Notify::new());
            let resolver = Arc::new(BlockingRefreshResolver {
                refresh_entered: Arc::new(Notify::new()),
                release_refresh: Arc::clone(&release_refresh),
                revocation_started: Arc::new(AtomicBool::new(false)),
                revocation_bodies: Arc::new(Mutex::new(Vec::new())),
                fail_refresh: Arc::new(AtomicBool::new(false)),
                fail_issuer: Arc::new(AtomicBool::new(false)),
                malformed_refresh_sub: Arc::new(AtomicBool::new(malformed_sub)),
                malformed_refresh_error: Arc::new(AtomicBool::new(malformed_error)),
                revoke_as_inactive: Arc::new(AtomicBool::new(false)),
            });
            let client = super::OAuthClient::new_with_shared(
                Arc::clone(&store),
                resolver,
                ClientData {
                    keyset: None,
                    config: AtprotoClientMetadata::default_localhost(),
                },
            );
            let session = client.registry.create(test_session()).await.unwrap();

            release_refresh.notify_one();
            assert!(
                client
                    .registry
                    .get(&session.account_did, &session.session_id, true)
                    .await
                    .is_err()
            );
            let stored = store
                .get_session(&session.account_did, &session.session_id)
                .await;
            assert_eq!(
                stored.is_err(),
                expect_quarantined,
                "malformed accepted success must quarantine; malformed explicit error must not"
            );
            if !expect_quarantined {
                assert!(stored.unwrap().is_some());
            }
        }
    }

    #[tokio::test]
    async fn ambiguous_refresh_quarantine_rejects_old_token_inactive_as_logout_proof() {
        let store = Arc::new(MemoryAuthStore::new());
        let refresh_entered = Arc::new(Notify::new());
        let release_refresh = Arc::new(Notify::new());
        let fail_refresh = Arc::new(AtomicBool::new(true));
        let revoke_as_inactive = Arc::new(AtomicBool::new(true));
        let revocation_bodies = Arc::new(Mutex::new(Vec::new()));
        let resolver = Arc::new(BlockingRefreshResolver {
            refresh_entered: Arc::clone(&refresh_entered),
            release_refresh: Arc::clone(&release_refresh),
            revocation_started: Arc::new(AtomicBool::new(false)),
            revocation_bodies: Arc::clone(&revocation_bodies),
            fail_refresh,
            fail_issuer: Arc::new(AtomicBool::new(false)),
            malformed_refresh_sub: Arc::new(AtomicBool::new(false)),
            malformed_refresh_error: Arc::new(AtomicBool::new(false)),
            revoke_as_inactive: Arc::clone(&revoke_as_inactive),
        });
        let client = Arc::new(super::OAuthClient::new_with_shared(
            Arc::clone(&store),
            resolver,
            ClientData {
                keyset: None,
                config: AtprotoClientMetadata::default_localhost(),
            },
        ));
        let session = client.registry.create(test_session()).await.unwrap();
        let refreshing = Arc::clone(&client);
        let did = session.account_did.clone();
        let session_id = session.session_id.clone();
        let refresh_task = tokio::spawn(async move {
            refreshing
                .registry
                .get(&did, &session_id, true)
                .await
                .map(IntoStatic::into_static)
        });
        refresh_entered.notified().await;
        release_refresh.notify_one();
        assert!(refresh_task.await.unwrap().is_err());
        assert!(
            store
                .get_session(&session.account_did, &session.session_id)
                .await
                .is_err(),
            "ambiguous refresh must quarantine ordinary reads"
        );
        assert!(
            client
                .revoke(&session.account_did, &session.session_id)
                .await
                .is_err(),
            "invalid_grant for the pre-refresh token cannot close an uncertain token family"
        );
        assert!(
            store
                .get_session(&session.account_did, &session.session_id)
                .await
                .is_err(),
            "failed logout must preserve quarantine"
        );
        revoke_as_inactive.store(false, Ordering::SeqCst);
        assert!(
            client
                .revoke(&session.account_did, &session.session_id)
                .await
                .is_err(),
            "RFC 7009 success for the old token cannot prove an uncertain descendant inactive"
        );
        assert!(
            store
                .get_session(&session.account_did, &session.session_id)
                .await
                .is_err(),
            "successful old-token revocation must preserve uncertainty quarantine"
        );
        assert!(
            revocation_bodies.lock().unwrap().is_empty(),
            "quarantined sessions must fail before sending a stale revocation token"
        );
    }

    #[tokio::test]
    async fn revoke_fence_blocks_nonce_writer_and_rejects_stolen_owner() {
        use crate::authstore::{SessionOperationAcquire, SessionOperationKind};
        let store = MemoryAuthStore::new();
        let created = store.create_session(test_session()).await.unwrap();
        let lease = match store
            .acquire_session_operation(
                &created.account_did,
                &created.session_id,
                SessionOperationKind::Revoke,
                "owner-a",
                std::time::Duration::from_secs(30),
            )
            .await
            .unwrap()
        {
            SessionOperationAcquire::Acquired(lease) => lease,
            other => panic!("unexpected acquisition result: {other:?}"),
        };
        let mut stale_nonce_write = created;
        stale_nonce_write.dpop_data.dpop_host_nonce = CowStr::new_static("stale-nonce");
        assert!(!store.update_session(stale_nonce_write).await.unwrap());

        let mut stolen = lease.clone();
        stolen.owner = "owner-b".into();
        assert!(
            !store
                .renew_session_operation(&stolen, std::time::Duration::from_secs(30))
                .await
                .unwrap()
        );
        assert!(
            !store
                .release_session_operation(&stolen, false)
                .await
                .unwrap()
        );
        assert!(store.complete_session_revoke(&lease).await.unwrap());
    }

    #[tokio::test]
    async fn stale_background_set_after_logout_cannot_recreate_session_or_identity() {
        let store = Arc::new(IndexedMemoryAuthStore::new());
        let registry = SessionRegistry::new_shared(
            Arc::clone(&store),
            Arc::new(NoopResolver),
            ClientData {
                keyset: None,
                config: AtprotoClientMetadata::default_localhost(),
            },
        );
        let mut stale = registry.create(test_session()).await.unwrap();
        stale.dpop_data.dpop_host_nonce = CowStr::new_static("stale-nonce");

        // Model logout after it has acquired the lifecycle fence but before
        // it deletes. The background write is already queued at that point.
        let lifecycle = registry
            .lock_session(&stale.account_did, &stale.session_id)
            .await;
        let registry = Arc::new(registry);
        let stale_writer = Arc::clone(&registry);
        let stale_value = stale.clone();
        let stale_task = tokio::spawn(async move { stale_writer.set(stale_value).await });
        tokio::task::yield_now().await;
        registry
            .delete_locked(
                &stale.account_did,
                &stale.session_id,
                &stale.lifecycle_generation,
            )
            .await
            .unwrap();
        drop(lifecycle);

        assert!(stale_task.await.unwrap().is_err());
        assert!(
            store
                .get_session(&stale.account_did, &stale.session_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!store.has_index(&stale.session_id));
    }

    #[tokio::test]
    async fn store_clones_share_logout_fence_across_independent_registries() {
        let store = Arc::new(IndexedMemoryAuthStore::new());
        let client_data = ClientData {
            keyset: None,
            config: AtprotoClientMetadata::default_localhost(),
        };
        let first = Arc::new(SessionRegistry::new_shared(
            Arc::clone(&store),
            Arc::new(NoopResolver),
            client_data.clone(),
        ));
        let second = Arc::new(SessionRegistry::new_shared(
            Arc::clone(&store),
            Arc::new(NoopResolver),
            client_data,
        ));
        let mut stale = first.create(test_session()).await.unwrap();
        stale.dpop_data.dpop_host_nonce = CowStr::new_static("other-registry-stale");
        store.block_one_update();

        let lifecycle = first
            .lock_session(&stale.account_did, &stale.session_id)
            .await;
        let stale_writer = Arc::clone(&second);
        let stale_value = stale.clone();
        let stale_task = tokio::spawn(async move { stale_writer.set(stale_value).await });
        store.update_entered.notified().await;
        first
            .delete_locked(
                &stale.account_did,
                &stale.session_id,
                &stale.lifecycle_generation,
            )
            .await
            .unwrap();
        drop(lifecycle);
        store.release_update.notify_one();

        assert!(stale_task.await.unwrap().is_err());
        assert!(
            store
                .get_session(&stale.account_did, &stale.session_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!store.has_index(&stale.session_id));
    }

    #[tokio::test]
    async fn explicit_create_and_atomic_existing_update_preserve_normal_session_flow() {
        let store = Arc::new(MemoryAuthStore::new());
        let registry = SessionRegistry::new_shared(
            Arc::clone(&store),
            Arc::new(NoopResolver),
            ClientData {
                keyset: None,
                config: AtprotoClientMetadata::default_localhost(),
            },
        );
        let session = registry.create(test_session()).await.unwrap();
        registry
            .update(&session.account_did, &session.session_id, |current| {
                current.dpop_data.dpop_host_nonce = CowStr::new_static("fresh-nonce");
            })
            .await
            .unwrap();

        let stored = store
            .get_session(&session.account_did, &session.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.dpop_data.dpop_host_nonce, "fresh-nonce");
    }
}

impl<T, S> OAuthClient<T, S>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
{
    pub fn jwks(&self) -> JwkSet {
        self.registry
            .client_data
            .keyset
            .as_ref()
            .map(|keyset| keyset.public_jwks())
            .unwrap_or_default()
    }
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip(self, input), fields(input = input.as_ref())))]
    pub async fn start_auth(
        &self,
        input: impl AsRef<str>,
        options: AuthorizeOptions<'_>,
    ) -> Result<String> {
        let client_metadata = atproto_client_metadata(
            self.registry.client_data.config.clone(),
            &self.registry.client_data.keyset,
        )?;
        let (server_metadata, identity) = self.client.resolve_oauth(input.as_ref()).await?;
        let login_hint = if identity.is_some() {
            Some(input.as_ref().into())
        } else {
            None
        };
        let resolved_account_did = identity.as_ref().map(|document| document.id.clone());
        let metadata = OAuthMetadata {
            server_metadata,
            client_metadata,
            keyset: self.registry.client_data.keyset.clone(),
        };

        // Reject metadata that cannot be represented as a single HTTP Location
        // value before PAR work or callback state is persisted.
        validate_authorization_location(metadata.server_metadata.authorization_endpoint.as_str())?;

        let mut auth_req_info = par(
            self.client.as_ref(),
            login_hint,
            options.prompt,
            &metadata,
            options.state,
        )
        .await?;
        auth_req_info.account_did = resolved_account_did;

        // Persist state for callback handling
        self.registry
            .store
            .save_auth_req_info(&auth_req_info)
            .await?;

        #[derive(serde::Serialize)]
        struct Parameters<'s> {
            client_id: CowStr<'s>,
            request_uri: CowStr<'s>,
        }
        let parameters = serde_html_form::to_string(Parameters {
            client_id: metadata.client_metadata.client_id,
            request_uri: auth_req_info.request_uri,
        })?;
        let authorization_location =
            metadata.server_metadata.authorization_endpoint.to_string() + "?" + &parameters;
        validate_authorization_location(&authorization_location)?;
        Ok(authorization_location)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "info", skip_all, fields(state = params.state.as_ref().map(|s| s.as_ref()))))]
    pub async fn callback(&self, params: CallbackParams<'_>) -> Result<OAuthSession<T, S>> {
        let Some(state_key) = params.state else {
            return Err(CallbackError::MissingState.into());
        };

        let Some(auth_req_info) = self.registry.store.get_auth_req_info(&state_key).await? else {
            return Err(CallbackError::MissingState.into());
        };

        self.registry.store.delete_auth_req_info(&state_key).await?;

        let metadata = self
            .client
            .get_authorization_server_metadata(&auth_req_info.authserver_url.to_cowstr())
            .await?;

        if let Some(iss) = params.iss {
            if !crate::resolver::issuer_equivalent(&iss, &metadata.issuer) {
                return Err(CallbackError::IssuerMismatch {
                    expected: metadata.issuer.to_string(),
                    got: iss.to_string(),
                }
                .into());
            }
        } else if metadata.authorization_response_iss_parameter_supported == Some(true) {
            return Err(CallbackError::MissingIssuer.into());
        }
        let metadata = OAuthMetadata {
            server_metadata: metadata,
            client_metadata: atproto_client_metadata(
                self.registry.client_data.config.clone(),
                &self.registry.client_data.keyset,
            )?,
            keyset: self.registry.client_data.keyset.clone(),
        };
        let authserver_nonce = auth_req_info.dpop_data.dpop_authserver_nonce.clone();

        match exchange_code(
            self.client.as_ref(),
            &mut auth_req_info.dpop_data.clone(),
            &params.code,
            &auth_req_info.pkce_verifier,
            &metadata,
            auth_req_info.account_did.as_ref(),
        )
        .await
        {
            Ok(token_set) => {
                let scopes = parse_returned_scopes(token_set.scope.as_deref())?;
                // OAuth state is provider-visible protocol correlation data. A
                // completed Nest session receives a new independent capability
                // only after the token, subject, issuer, and scopes are valid.
                let session_id = fresh_session_id();
                let client_data = ClientSessionData {
                    lifecycle_generation: CowStr::default(),
                    account_did: token_set.sub.clone(),
                    session_id,
                    host_url: token_set.aud.clone(),
                    authserver_url: auth_req_info.authserver_url.to_cowstr(),
                    authserver_token_endpoint: auth_req_info.authserver_token_endpoint,
                    authserver_revocation_endpoint: auth_req_info.authserver_revocation_endpoint,
                    scopes,
                    dpop_data: DpopClientData {
                        dpop_key: auth_req_info.dpop_data.dpop_key.clone(),
                        dpop_authserver_nonce: authserver_nonce.unwrap_or(CowStr::default()),
                        dpop_host_nonce: auth_req_info
                            .dpop_data
                            .dpop_authserver_nonce
                            .unwrap_or(CowStr::default()),
                    },
                    token_set,
                };

                self.create_session(client_data).await
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn create_session(&self, data: ClientSessionData<'_>) -> Result<OAuthSession<T, S>> {
        let data = self.registry.create(data).await?;
        Ok(OAuthSession::new(
            self.registry.clone(),
            self.client.clone(),
            data,
        ))
    }

    pub async fn restore(&self, did: &Did<'_>, session_id: &str) -> Result<OAuthSession<T, S>> {
        let data = self.registry.get(did, session_id, true).await?;
        Ok(OAuthSession::new(
            self.registry.clone(),
            self.client.clone(),
            data.into_static(),
        ))
    }

    pub async fn revoke(&self, did: &Did<'_>, session_id: &str) -> Result<()> {
        revoke_stored_session(&self.registry, self.client.as_ref(), did, session_id).await
    }
}

impl<T, S> HttpClient for OAuthClient<T, S>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
{
    type Error = T::Error;

    async fn send_http(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> core::result::Result<http::Response<Vec<u8>>, Self::Error> {
        self.client.send_http(request).await
    }
}

impl<T, S> IdentityResolver for OAuthClient<T, S>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
{
    fn options(&self) -> &ResolverOptions {
        self.client.options()
    }

    async fn resolve_handle(
        &self,
        handle: &Handle<'_>,
    ) -> jacquard_identity::resolver::Result<Did<'static>> {
        self.client.resolve_handle(handle).await
    }

    async fn resolve_did_doc(
        &self,
        did: &Did<'_>,
    ) -> jacquard_identity::resolver::Result<DidDocResponse> {
        self.client.resolve_did_doc(did).await
    }
}

impl<T, S> XrpcClient for OAuthClient<T, S>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
{
    async fn base_uri(&self) -> CowStr<'static> {
        self.endpoint
            .read()
            .await
            .clone()
            .unwrap_or(CowStr::new_static("https://public.api.bsky.app"))
    }

    async fn opts(&self) -> CallOptions<'_> {
        self.options.read().await.clone()
    }

    async fn set_opts(&self, opts: CallOptions<'_>) {
        let mut guard = self.options.write().await;
        *guard = opts.into_static();
    }

    async fn set_base_uri(&self, url: Url) {
        let mut guard = self.endpoint.write().await;
        *guard = Some(url.to_cowstr().into_static());
    }

    async fn send<R>(&self, request: R) -> XrpcResult<XrpcResponse<R>>
    where
        R: XrpcRequest + Send + Sync,
        <R as XrpcRequest>::Response: Send + Sync,
    {
        let opts = self.options.read().await.clone();
        self.send_with_opts(request, opts).await
    }

    async fn send_with_opts<R>(
        &self,
        request: R,
        opts: CallOptions<'_>,
    ) -> XrpcResult<XrpcResponse<R>>
    where
        R: XrpcRequest + Send + Sync,
        <R as XrpcRequest>::Response: Send + Sync,
    {
        let base_uri = self.base_uri().await;
        self.client
            .xrpc(Url::parse(&base_uri).map_err(|e| ClientError::encode(e.to_smolstr()))?)
            .with_options(opts.clone())
            .send(&request)
            .await
    }
}

pub struct OAuthSession<T, S, W = ()>
where
    T: OAuthResolver,
    S: ClientAuthStore,
{
    pub registry: Arc<SessionRegistry<T, S>>,
    pub client: Arc<T>,
    pub ws_client: W,
    pub data: RwLock<ClientSessionData<'static>>,
    pub options: RwLock<CallOptions<'static>>,
}

impl<T, S> OAuthSession<T, S, ()>
where
    T: OAuthResolver,
    S: ClientAuthStore,
{
    pub fn new(
        registry: Arc<SessionRegistry<T, S>>,
        client: Arc<T>,
        data: ClientSessionData<'static>,
    ) -> Self {
        Self {
            registry,
            client,
            ws_client: (),
            data: RwLock::new(data),
            options: RwLock::new(CallOptions::default()),
        }
    }
}

impl<T, S, W> OAuthSession<T, S, W>
where
    T: OAuthResolver,
    S: ClientAuthStore,
{
    pub fn new_with_ws(
        registry: Arc<SessionRegistry<T, S>>,
        client: Arc<T>,
        ws_client: W,
        data: ClientSessionData<'static>,
    ) -> Self {
        Self {
            registry,
            client,
            ws_client,
            data: RwLock::new(data),
            options: RwLock::new(CallOptions::default()),
        }
    }

    pub fn with_options(self, options: CallOptions<'_>) -> Self {
        Self {
            registry: self.registry,
            client: self.client,
            ws_client: self.ws_client,
            data: self.data,
            options: RwLock::new(options.into_static()),
        }
    }

    /// Get a reference to the WebSocket client.
    pub fn ws_client(&self) -> &W {
        &self.ws_client
    }

    pub async fn set_options(&self, options: CallOptions<'_>) {
        *self.options.write().await = options.into_static();
    }

    pub async fn session_info(&self) -> (Did<'_>, CowStr<'_>) {
        let data = self.data.read().await;
        (data.account_did.clone(), data.session_id.clone())
    }

    pub async fn endpoint(&self) -> CowStr<'static> {
        self.data.read().await.host_url.clone()
    }

    pub async fn access_token(&self) -> AuthorizationToken<'_> {
        AuthorizationToken::Dpop(self.data.read().await.token_set.access_token.clone())
    }

    pub async fn refresh_token(&self) -> Option<AuthorizationToken<'_>> {
        self.data
            .read()
            .await
            .token_set
            .refresh_token
            .as_ref()
            .map(|t| AuthorizationToken::Dpop(t.clone()))
    }

    pub fn to_client(&self) -> OAuthClient<T, S> {
        OAuthClient::from_session(self)
    }
}
impl<T, S, W> OAuthSession<T, S, W>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
{
    pub async fn logout(&self) -> Result<()> {
        let mut data = self.data.write().await;
        let did = data.account_did.clone();
        let session_id = data.session_id.clone();
        revoke_stored_session(&self.registry, self.client.as_ref(), &did, &session_id).await?;
        data.lifecycle_generation = CowStr::default();
        Ok(())
    }
}

async fn revoke_stored_session<T, S>(
    registry: &SessionRegistry<T, S>,
    client: &T,
    did: &Did<'_>,
    session_id: &str,
) -> Result<()>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
{
    use crate::{
        authstore::SessionOperationKind,
        request::{OAuthMetadata, revoke},
    };
    let _local = registry.lock_session(did, session_id).await;
    let lease = registry
        .acquire_operation(did, session_id, SessionOperationKind::Revoke)
        .await?;
    if lease.uncertain_refresh {
        let _ = registry.store.release_session_operation(&lease, true).await;
        return Err(crate::session::Error::Store(
            jacquard_common::session::SessionStoreError::Other(
                "session has an unresolved refresh outcome; reauthentication is required".into(),
            ),
        )
        .into());
    }
    let mut latest = lease.session.clone();
    let meta = match OAuthMetadata::new(client, &registry.client_data, &latest).await {
        Ok(meta) => meta,
        Err(error) => {
            let _ = registry
                .store
                .release_session_operation(&lease, lease.uncertain_refresh)
                .await;
            return Err(error.into());
        }
    };
    let token = match required_revocation_token(
        meta.server_metadata.revocation_endpoint.is_some(),
        latest.token_set.refresh_token.as_deref(),
        latest.token_set.access_token.as_ref(),
    ) {
        Ok(token) => token.to_owned(),
        Err(error) => {
            let _ = registry
                .store
                .release_session_operation(&lease, lease.uncertain_refresh)
                .await;
            return Err(error);
        }
    };
    if !registry
        .store
        .renew_session_operation(&lease, std::time::Duration::from_secs(120))
        .await?
    {
        return Err(crate::session::Error::SessionNotFound.into());
    }
    let (stop_renewal, mut renewal_stopped) = tokio::sync::oneshot::channel::<()>();
    let renewal_store = Arc::clone(&registry.store);
    let renewal_lease = lease.clone();
    let renewal = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut renewal_stopped => return true,
                _ = tokio::time::sleep(std::time::Duration::from_secs(40)) => {
                    match renewal_store.renew_session_operation(
                        &renewal_lease,
                        std::time::Duration::from_secs(120),
                    ).await {
                        Ok(true) => {}
                        _ => return false,
                    }
                }
            }
        }
    });
    let revocation = revoke(client, &mut latest.dpop_data, &token, &meta).await;
    let _ = stop_renewal.send(());
    let renewal_live = renewal.await.unwrap_or(false);
    if !renewal_live
        || !registry
            .store
            .renew_session_operation(&lease, std::time::Duration::from_secs(120))
            .await
            .unwrap_or(false)
    {
        return Err(crate::session::Error::SessionNotFound.into());
    }
    let proven = match revocation {
        Ok(()) => true,
        Err(error) if !lease.uncertain_refresh && error.proves_token_inactive() => true,
        Err(error) => {
            let _ = registry
                .store
                .release_session_operation(&lease, lease.uncertain_refresh)
                .await;
            return Err(error.into());
        }
    };
    debug_assert!(proven);
    if registry.store.complete_session_revoke(&lease).await? {
        Ok(())
    } else {
        Err(crate::session::Error::SessionNotFound.into())
    }
}

#[cfg(test)]
fn require_local_delete_after_revocation(revocation: crate::request::Result<()>) -> Result<()> {
    match revocation {
        Ok(()) => Ok(()),
        Err(error) if error.proves_token_inactive() => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
async fn complete_logout_after_revocation<T, S>(
    registry: &SessionRegistry<T, S>,
    did: &Did<'_>,
    session_id: &str,
    revocation: crate::request::Result<()>,
) -> Result<()>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
{
    require_local_delete_after_revocation(revocation)?;
    registry.del(did, session_id).await?;
    Ok(())
}

fn required_revocation_token<'a>(
    has_revocation_endpoint: bool,
    refresh_token: Option<&'a str>,
    access_token: &'a str,
) -> Result<&'a str> {
    if !has_revocation_endpoint {
        return Err(crate::request::RequestError::no_endpoint("revocation").into());
    }
    Ok(refresh_token.unwrap_or(access_token))
}

impl<T, S> OAuthClient<T, S>
where
    T: OAuthResolver,
    S: ClientAuthStore,
{
    pub fn from_session<W>(session: &OAuthSession<T, S, W>) -> Self {
        Self {
            registry: session.registry.clone(),
            client: session.client.clone(),
            options: RwLock::new(CallOptions::default()),
            endpoint: RwLock::new(None),
        }
    }
}
impl<T, S, W> OAuthSession<T, S, W>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
{
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all))]
    pub async fn refresh(&self) -> Result<AuthorizationToken<'_>> {
        // Keep this session object's write fence for the whole refresh so a
        // same-object logout cannot revoke and delete while refresh is using
        // and replacing its credentials.
        let mut data = self.data.write().await;
        let did = data.account_did.clone();
        let sid = data.session_id.clone();
        let refreshed = self.registry.as_ref().get(&did, &sid, true).await?;
        let token = AuthorizationToken::Dpop(refreshed.token_set.access_token.clone());
        *data = refreshed.into_static();
        Ok(token)
    }
}

impl<T, S, W> HttpClient for OAuthSession<T, S, W>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
    W: Send + Sync,
{
    type Error = T::Error;

    async fn send_http(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> core::result::Result<http::Response<Vec<u8>>, Self::Error> {
        self.client.send_http(request).await
    }
}

impl<T, S, W> XrpcClient for OAuthSession<T, S, W>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + DpopExt + XrpcExt + Send + Sync + 'static,
    W: Send + Sync,
{
    async fn base_uri(&self) -> CowStr<'static> {
        self.data.read().await.host_url.clone()
    }

    async fn opts(&self) -> CallOptions<'_> {
        self.options.read().await.clone()
    }

    async fn set_opts(&self, opts: CallOptions<'_>) {
        let mut guard = self.options.write().await;
        *guard = opts.into_static();
    }

    async fn set_base_uri(&self, url: Url) {
        let mut guard = self.data.write().await;
        guard.host_url = url.as_str().trim_end_matches("/").to_cowstr().into_static();
    }

    async fn send<R>(&self, request: R) -> XrpcResult<XrpcResponse<R>>
    where
        R: XrpcRequest + Send + Sync,
        <R as XrpcRequest>::Response: Send + Sync,
    {
        let opts = self.options.read().await.clone();
        self.send_with_opts(request, opts).await
    }

    async fn send_with_opts<R>(
        &self,
        request: R,
        mut opts: CallOptions<'_>,
    ) -> XrpcResult<XrpcResponse<R>>
    where
        R: XrpcRequest + Send + Sync,
        <R as XrpcRequest>::Response: Send + Sync,
    {
        let base_uri = self.base_uri().await;
        let original_token = self.access_token().await;
        opts.auth = Some(original_token.clone());
        // Clone dpop_data and release read lock before the await point
        let mut dpop = self.data.read().await.dpop_data.clone();
        let base_uri = Url::parse(&base_uri).map_err(|e| ClientError::transport(e))?;
        let http_response = self
            .client
            .dpop_call(&mut dpop)
            .send(build_http_request(&base_uri, &request, &opts)?)
            .await
            .map_err(|e| ClientError::transport(e))?;
        let resp = process_response(http_response);

        // Write back updated nonce to session data (dpop_call may have updated it)
        {
            let mut guard = self.data.write().await;
            guard.dpop_data.dpop_host_nonce = dpop.dpop_host_nonce.clone();
        }

        if is_invalid_token_response(&resp) {
            // Optimistic refresh: check if another request already refreshed the token
            let current_token = self.access_token().await;
            if current_token != original_token {
                // Token was already refreshed by another concurrent request, use it
                opts.auth = Some(current_token);
            } else {
                // We need to refresh - this will be serialized by the registry's Mutex
                opts.auth = Some(
                    self.refresh()
                        .await
                        .map_err(|e| ClientError::transport(e))?,
                );
            }
            // Re-read dpop_data after refresh (refresh may have updated it)
            let mut dpop = self.data.read().await.dpop_data.clone();
            let http_response = self
                .client
                .dpop_call(&mut dpop)
                .send(build_http_request(&base_uri, &request, &opts)?)
                .await
                .map_err(|e| ClientError::transport(e))?;
            let resp = process_response(http_response);

            // Write back updated nonce after retry
            {
                let mut guard = self.data.write().await;
                guard.dpop_data.dpop_host_nonce = dpop.dpop_host_nonce.clone();
            }

            resp
        } else {
            resp
        }
    }
}

#[cfg(feature = "streaming")]
impl<T, S, W> jacquard_common::http_client::HttpClientExt for OAuthSession<T, S, W>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver
        + DpopExt
        + XrpcExt
        + jacquard_common::http_client::HttpClientExt
        + Send
        + Sync
        + 'static,
    W: Send + Sync,
{
    async fn send_http_streaming(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> core::result::Result<http::Response<jacquard_common::stream::ByteStream>, Self::Error>
    {
        self.client.send_http_streaming(request).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn send_http_bidirectional<Str>(
        &self,
        parts: http::request::Parts,
        body: Str,
    ) -> core::result::Result<http::Response<jacquard_common::stream::ByteStream>, Self::Error>
    where
        Str: n0_future::Stream<
                Item = core::result::Result<bytes::Bytes, jacquard_common::StreamError>,
            > + Send
            + 'static,
    {
        self.client.send_http_bidirectional(parts, body).await
    }

    #[cfg(target_arch = "wasm32")]
    async fn send_http_bidirectional<Str>(
        &self,
        parts: http::request::Parts,
        body: Str,
    ) -> core::result::Result<http::Response<jacquard_common::stream::ByteStream>, Self::Error>
    where
        Str: n0_future::Stream<
                Item = core::result::Result<bytes::Bytes, jacquard_common::StreamError>,
            > + 'static,
    {
        self.client.send_http_bidirectional(parts, body).await
    }
}

#[cfg(feature = "streaming")]
impl<T, S, W> jacquard_common::xrpc::XrpcStreamingClient for OAuthSession<T, S, W>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver
        + DpopExt
        + XrpcExt
        + jacquard_common::http_client::HttpClientExt
        + Send
        + Sync
        + 'static,
    W: Send + Sync,
{
    async fn download<R>(
        &self,
        request: R,
    ) -> core::result::Result<jacquard_common::xrpc::StreamingResponse, jacquard_common::StreamError>
    where
        R: XrpcRequest + Send + Sync,
        <R as XrpcRequest>::Response: Send + Sync,
    {
        use jacquard_common::StreamError;

        let base_uri = <Self as XrpcClient>::base_uri(self).await;
        let base_uri = Url::parse(&base_uri).map_err(|e| StreamError::protocol(e.to_string()))?;
        let mut opts = self.options.read().await.clone();
        opts.auth = Some(self.access_token().await);
        let http_request = build_http_request(&base_uri, &request, &opts)
            .map_err(|e| StreamError::protocol(e.to_string()))?;
        let guard = self.data.read().await;
        let mut dpop = guard.dpop_data.clone();
        let result = self
            .client
            .dpop_call(&mut dpop)
            .send_streaming(http_request)
            .await;
        drop(guard);

        match result {
            Ok(response) => Ok(response),
            Err(_e) => {
                // Check if it's an auth error and retry
                opts.auth = Some(
                    self.refresh()
                        .await
                        .map_err(|e| StreamError::transport(e))?,
                );
                let http_request = build_http_request(&base_uri, &request, &opts)
                    .map_err(|e| StreamError::protocol(e.to_string()))?;
                let guard = self.data.read().await;
                let mut dpop = guard.dpop_data.clone();
                self.client
                    .dpop_call(&mut dpop)
                    .send_streaming(http_request)
                    .await
                    .map_err(StreamError::transport)
            }
        }
    }

    async fn stream<Str>(
        &self,
        stream: jacquard_common::xrpc::streaming::XrpcProcedureSend<Str::Frame<'static>>,
    ) -> core::result::Result<
        jacquard_common::xrpc::streaming::XrpcResponseStream<
            <<Str as jacquard_common::xrpc::streaming::XrpcProcedureStream>::Response as jacquard_common::xrpc::streaming::XrpcStreamResp>::Frame<'static>,
        >,
        jacquard_common::StreamError,
    >
    where
        Str: jacquard_common::xrpc::streaming::XrpcProcedureStream + 'static,
        <<Str as jacquard_common::xrpc::streaming::XrpcProcedureStream>::Response as jacquard_common::xrpc::streaming::XrpcStreamResp>::Frame<'static>: jacquard_common::xrpc::streaming::XrpcStreamResp,
    {
        use jacquard_common::StreamError;
        use n0_future::TryStreamExt;

        let base_uri = self.base_uri().await;
        let mut opts = self.options.read().await.clone();
        opts.auth = Some(self.access_token().await);

        let mut url = Url::parse(&base_uri).map_err(|e| StreamError::encode(e))?;
        let mut path = url.path().trim_end_matches('/').to_owned();
        path.push_str("/xrpc/");
        path.push_str(<Str::Request as jacquard_common::xrpc::XrpcRequest>::NSID);
        url.set_path(&path);

        let mut builder = http::Request::post(url.to_string());

        if let Some(token) = &opts.auth {
            use jacquard_common::AuthorizationToken;
            let hv = match token {
                AuthorizationToken::Bearer(t) => {
                    http::HeaderValue::from_str(&format!("Bearer {}", t.as_ref()))
                }
                AuthorizationToken::Dpop(t) => {
                    http::HeaderValue::from_str(&format!("DPoP {}", t.as_ref()))
                }
            }
            .map_err(|e| StreamError::protocol(format!("Invalid authorization token: {}", e)))?;
            builder = builder.header(http::header::AUTHORIZATION, hv);
        }

        if let Some(proxy) = &opts.atproto_proxy {
            builder = builder.header("atproto-proxy", proxy.as_ref());
        }
        if let Some(labelers) = &opts.atproto_accept_labelers {
            if !labelers.is_empty() {
                let joined = labelers
                    .iter()
                    .map(|s| s.as_ref())
                    .collect::<Vec<_>>()
                    .join(", ");
                builder = builder.header("atproto-accept-labelers", joined);
            }
        }
        for (name, value) in &opts.extra_headers {
            builder = builder.header(name, value);
        }

        let (parts, _) = builder
            .body(())
            .map_err(|e| StreamError::protocol(e.to_string()))?
            .into_parts();

        let body_stream =
            jacquard_common::stream::ByteStream::new(Box::pin(stream.0.map_ok(|f| f.buffer)));

        let guard = self.data.read().await;
        let mut dpop = guard.dpop_data.clone();
        let result = self
            .client
            .dpop_call(&mut dpop)
            .send_bidirectional(parts, body_stream)
            .await;
        drop(guard);

        match result {
            Ok(response) => {
                let (resp_parts, resp_body) = response.into_parts();
                Ok(
                    jacquard_common::xrpc::streaming::XrpcResponseStream::from_typed_parts(
                        resp_parts, resp_body,
                    ),
                )
            }
            Err(e) => {
                // OAuth token refresh and retry is handled by dpop wrapper
                // If we get here, it's a real error
                Err(StreamError::transport(e))
            }
        }
    }
}

fn is_invalid_token_response<R: XrpcResp>(response: &XrpcResult<Response<R>>) -> bool {
    use jacquard_common::error::ClientErrorKind;

    match response {
        Err(e) => match e.kind() {
            ClientErrorKind::Auth(AuthError::InvalidToken) => true,
            ClientErrorKind::Auth(AuthError::Other(value)) => value
                .to_str()
                .is_ok_and(|s| s.starts_with("DPoP ") && s.contains("error=\"invalid_token\"")),
            _ => false,
        },
        Ok(resp) => match resp.parse() {
            Err(XrpcError::Auth(AuthError::InvalidToken)) => true,
            _ => false,
        },
    }
}

impl<T, S, W> IdentityResolver for OAuthSession<T, S, W>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + IdentityResolver + XrpcExt + Send + Sync + 'static,
    W: Send + Sync,
{
    fn options(&self) -> &ResolverOptions {
        self.client.options()
    }

    fn resolve_handle(
        &self,
        handle: &Handle<'_>,
    ) -> impl Future<Output = std::result::Result<Did<'static>, IdentityError>> {
        async { self.client.resolve_handle(handle).await }
    }

    fn resolve_did_doc(
        &self,
        did: &Did<'_>,
    ) -> impl Future<Output = std::result::Result<DidDocResponse, IdentityError>> {
        async { self.client.resolve_did_doc(did).await }
    }
}

#[cfg(feature = "websocket")]
impl<T, S, W> WebSocketClient for OAuthSession<T, S, W>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + Send + Sync + 'static,
    W: WebSocketClient + Send + Sync,
{
    type Error = W::Error;

    async fn connect(&self, url: Url) -> std::result::Result<WebSocketConnection, Self::Error> {
        self.ws_client.connect(url).await
    }

    async fn connect_with_headers(
        &self,
        url: Url,
        headers: Vec<(CowStr<'_>, CowStr<'_>)>,
    ) -> std::result::Result<WebSocketConnection, Self::Error> {
        self.ws_client.connect_with_headers(url, headers).await
    }
}

#[cfg(feature = "websocket")]
impl<T, S, W> jacquard_common::xrpc::SubscriptionClient for OAuthSession<T, S, W>
where
    S: ClientAuthStore + Send + Sync + 'static,
    T: OAuthResolver + Send + Sync + 'static,
    W: WebSocketClient + Send + Sync,
{
    async fn base_uri(&self) -> CowStr<'static> {
        self.data.read().await.host_url.clone()
    }

    async fn subscription_opts(&self) -> jacquard_common::xrpc::SubscriptionOptions<'_> {
        let mut opts = jacquard_common::xrpc::SubscriptionOptions::default();
        let token = self.access_token().await;
        let auth_value = match token {
            AuthorizationToken::Bearer(t) => format!("Bearer {}", t.as_ref()),
            AuthorizationToken::Dpop(t) => format!("DPoP {}", t.as_ref()),
        };
        opts.headers
            .push((CowStr::from("Authorization"), CowStr::from(auth_value)));
        opts
    }

    async fn subscribe<Sub>(
        &self,
        params: &Sub,
    ) -> std::result::Result<jacquard_common::xrpc::SubscriptionStream<Sub::Stream>, Self::Error>
    where
        Sub: XrpcSubscription + Send + Sync,
    {
        let opts = self.subscription_opts().await;
        self.subscribe_with_opts(params, opts).await
    }

    async fn subscribe_with_opts<Sub>(
        &self,
        params: &Sub,
        opts: jacquard_common::xrpc::SubscriptionOptions<'_>,
    ) -> std::result::Result<jacquard_common::xrpc::SubscriptionStream<Sub::Stream>, Self::Error>
    where
        Sub: XrpcSubscription + Send + Sync,
    {
        use jacquard_common::xrpc::SubscriptionExt;
        let base = self.base_uri().await;
        let base = Url::parse(&base).expect("Failed to parse base URL");
        self.subscription(base)
            .with_options(opts)
            .subscribe(params)
            .await
    }
}
