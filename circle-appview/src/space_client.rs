use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::rand_core::OsRng;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::auth::{
    is_localhost_hostname, is_private_ip, parse_verification_key,
    select_authority_verification_method, DidDocument, DidResolver, JwtHeader,
};
use crate::error::{AppError, AuthReason};
use crate::oauth::OAuthService;
pub use crate::space_signature::SpaceAuthHeaders;
use crate::space_signature::{credential_headers, p256_did_key};

/// Body for the Nov-12 `authorizeSpaceSync` credential exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeSpaceSyncRequest {
    pub space: String,
    pub credential_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_attestation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify: Option<crate::notify::NotifyRegistration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeSpaceSyncOutput {
    pub credential: String,
    #[serde(default)]
    pub space_rev: Option<String>,
}
#[derive(Debug, Clone)]
pub struct AuthorizedSpaceSync {
    pub credential: String,
    pub signing_key: p256::ecdsa::SigningKey,
    pub expires_at: DateTime<Utc>,
    pub space_rev: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpaceAppAccess {
    Open,
    AllowList(Vec<String>),
    Unknown(Option<String>),
}

impl SpaceAppAccess {
    /// Maps a memberspace policy's `allowedApps` (October 29 Spaces alpha).
    /// Absent means any app may read (`Open`). An array is an allow-list, and an
    /// empty array is an authoritative revocation. Anything else, including an
    /// array with no readable entries, degrades to `Unknown`, which denies
    /// without purging.
    pub fn from_allowed_apps(val: Option<&serde_json::Value>) -> Self {
        let Some(val) = val else {
            return SpaceAppAccess::Open;
        };
        let Some(arr) = val.as_array() else {
            return SpaceAppAccess::Unknown(Some("allowedApps".to_string()));
        };
        if arr.is_empty() {
            return SpaceAppAccess::AllowList(Vec::new());
        }
        let list: Vec<String> = arr
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect();
        if list.is_empty() {
            return SpaceAppAccess::Unknown(Some("allowedApps".to_string()));
        }
        SpaceAppAccess::AllowList(list)
    }

    pub fn grants_access(&self, client_id: &str) -> bool {
        match self {
            SpaceAppAccess::Open => true,
            SpaceAppAccess::AllowList(list) => list.iter().any(|c| c == client_id),
            SpaceAppAccess::Unknown(_) => false,
        }
    }

    pub fn is_explicit_revocation(&self, client_id: &str) -> bool {
        match self {
            SpaceAppAccess::AllowList(list) => !list.iter().any(|c| c == client_id),
            SpaceAppAccess::Open | SpaceAppAccess::Unknown(_) => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpacePolicy {
    Public,
    MemberList,
    ManagingApp,
    Unknown(Option<String>),
}

pub const MEMBERSPACE_POLICY_TYPE: &str = "com.atproto.memberspace.policy";
pub const MANAGEDSPACE_POLICY_TYPE: &str = "com.atproto.managedspace.policy";

/// Circle-relevant view of a space `policy` union from `com.atproto.space.getSpace`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSpacePolicy {
    pub app_access: SpaceAppAccess,
    pub read_policy: SpacePolicy,
    pub write_policy: SpacePolicy,
}

impl SpacePolicy {
    fn from_public_flag(val: Option<&serde_json::Value>, field: &str) -> Self {
        match val {
            None | Some(serde_json::Value::Bool(false)) => Self::MemberList,
            Some(serde_json::Value::Bool(true)) => Self::Public,
            Some(_) => Self::Unknown(Some(format!("{MEMBERSPACE_POLICY_TYPE}#{field}"))),
        }
    }

    /// Maps the October 29 policy union onto the read/write/app-access model the
    /// Circle AppView already enforces. Only a memberspace without public read or
    /// write is supported; managedspace, personalspace and unknown `$type`s are
    /// refused without purging, as unsupported Oct 22 policies were.
    pub fn parse_policy(policy: &serde_json::Value) -> ParsedSpacePolicy {
        let type_str = policy.get("$type").and_then(serde_json::Value::as_str);
        match type_str {
            Some(MEMBERSPACE_POLICY_TYPE) => ParsedSpacePolicy {
                app_access: SpaceAppAccess::from_allowed_apps(policy.get("allowedApps")),
                read_policy: Self::from_public_flag(policy.get("publicRead"), "publicRead"),
                write_policy: Self::from_public_flag(policy.get("publicWrite"), "publicWrite"),
            },
            // managedspace has no app allow-list; the policy itself is refused.
            Some(MANAGEDSPACE_POLICY_TYPE) => ParsedSpacePolicy {
                app_access: SpaceAppAccess::Open,
                read_policy: Self::ManagingApp,
                write_policy: Self::ManagingApp,
            },
            other => {
                let other = other.map(str::to_owned);
                ParsedSpacePolicy {
                    app_access: SpaceAppAccess::Unknown(other.clone()),
                    read_policy: Self::Unknown(other.clone()),
                    write_policy: Self::Unknown(other),
                }
            }
        }
    }

    pub fn is_supported(&self) -> bool {
        // Circles authorize from the member cache; public and managing-app
        // policies cannot be represented by that cache.
        matches!(self, SpacePolicy::MemberList)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceMember {
    pub did: String,
    pub read: bool,
    pub write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum WriterUpdate {
    #[serde(rename = "com.atproto.space.defs#repoWrite")]
    RepoWrite(RepoWrite),
    #[serde(rename = "com.atproto.space.defs#repoRemoved")]
    RepoRemoved(RepoRemoved),
}

impl WriterUpdate {
    pub fn space_rev(&self) -> &str {
        match self {
            Self::RepoWrite(update) => &update.space_rev,
            Self::RepoRemoved(update) => &update.space_rev,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepoWrite {
    pub repo: String,
    pub repo_rev: String,
    #[serde(with = "catbird_atproto::jacquard_common::serde_bytes_helper")]
    pub data: bytes::Bytes,
    pub space_rev: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_space_rev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepoRemoved {
    pub repo: String,
    pub space_rev: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_space_rev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListWritersOutput {
    pub repos: Vec<WriterUpdate>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceConfig {
    pub authority: String,
    pub space_type: String,
    pub skey: String,
    pub app_access: SpaceAppAccess,
    pub read_policy: SpacePolicy,
    pub write_policy: SpacePolicy,
    pub user_policy: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
}

pub const MAX_SPACE_RESPONSE_BYTES: usize = 1024 * 1024; // 1 MiB
pub const MAX_SPACE_CREDENTIAL_BYTES: usize = 256 * 1024; // 256 KiB
pub const MAX_LIST_MEMBERS_PAGES: usize = 50;
pub const MAX_LIST_MEMBERS_TOTAL: usize = 10_000;
pub const MAX_LIST_MEMBERS_TOTAL_BYTES: usize = 5 * 1024 * 1024; // 5 MiB
pub const MAX_CURSOR_LEN: usize = 512;
pub const MAX_LIST_MEMBERS_DURATION: std::time::Duration = std::time::Duration::from_secs(30);
pub const MAX_CONCURRENT_HYDRATIONS: usize = 10;

static HYDRATION_SEMAPHORE: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_HYDRATIONS)));
#[derive(Clone)]
pub struct SpaceClientDeps {
    pub http_client: reqwest::Client,
    pub did_resolver: Arc<DidResolver>,
    pub oauth_service: Arc<OAuthService>,
}

pub trait SpaceHostTransport: Send + Sync {
    /// Only fixture transports supply an in-process KEM identity.
    fn fixture_kem_key(&self) -> Option<p256::PublicKey> {
        None
    }

    fn get_delegation_token<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_uri: &'a str,
        _access_token: &'a str,
        _dpop_key: &'a p256::ecdsa::SigningKey,
    ) -> Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>> {
        Box::pin(async move {
            Err(AppError::NotFound(
                "get_delegation_token not implemented on transport".into(),
            ))
        })
    }

    fn authorize_space_sync<'a>(
        &'a self,
        target_url: &'a url::Url,
        request: &'a AuthorizeSpaceSyncRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizeSpaceSyncOutput, AppError>> + Send + 'a>>;

    fn list_writers<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _auth: &'a SpaceAuthHeaders,
        _space_uri: &'a str,
        _cursor: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<ListWritersOutput, AppError>> + Send + 'a>> {
        Box::pin(async move {
            Err(AppError::NotFound(
                "list_writers not implemented on transport".into(),
            ))
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn list_repo_ops<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _auth: &'a SpaceAuthHeaders,
        _space_uri: &'a str,
        _repo_did: &'a str,
        _since: Option<&'a str>,
        _cursor: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput, AppError>> + Send + 'a>>{
        Box::pin(async move {
            Err(AppError::NotFound(
                "list_repo_ops not implemented on transport".into(),
            ))
        })
    }

    #[allow(clippy::type_complexity)]
    fn list_members<'a>(
        &'a self,
        _space_uri: &'a str,
    ) -> Option<Pin<Box<dyn Future<Output = Result<Vec<SpaceMember>, AppError>> + Send + 'a>>> {
        None
    }

    #[allow(clippy::type_complexity)]
    fn get_space<'a>(
        &'a self,
        _space_uri: &'a str,
    ) -> Option<Pin<Box<dyn Future<Output = Result<SpaceConfig, AppError>> + Send + 'a>>> {
        None
    }
    fn get_repo<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _auth: &'a SpaceAuthHeaders,
        _space_uri: &'a str,
        _repo_did: &'a str,
        _since: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AppError>> + Send + 'a>> {
        Box::pin(async move {
            Err(AppError::NotFound(
                "get_repo not implemented on transport".into(),
            ))
        })
    }

    fn get_latest_commit<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _auth: &'a SpaceAuthHeaders,
        _space_uri: &'a str,
        _repo_did: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        catbird_atproto::generated::com_atproto::space::Commit,
                        AppError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Err(AppError::NotFound(
                "get_latest_commit not implemented on transport".into(),
            ))
        })
    }

    #[allow(clippy::type_complexity)]
    fn get_blob<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _auth: &'a SpaceAuthHeaders,
        _space_uri: &'a str,
        _repo: &'a str,
        _cid: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(Option<String>, Vec<u8>), AppError>> + Send + 'a>>
    {
        Box::pin(async move {
            Err(AppError::NotFound(
                "get_blob not implemented on transport".into(),
            ))
        })
    }
    fn build_pinned_client<'a>(
        &'a self,
        target_url: &'a url::Url,
    ) -> Pin<Box<dyn Future<Output = Result<reqwest::Client, AppError>> + Send + 'a>> {
        let target_url = target_url.clone();
        Box::pin(async move {
            DefaultSpaceHostTransport::new()
                .build_pinned_client(&target_url)
                .await
        })
    }
}

pub trait SpaceHostDnsResolver: Send + Sync {
    fn resolve_dns<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, AuthReason>> + Send + 'a>>;
}

#[derive(Default, Clone)]
pub struct DefaultSpaceHostDnsResolver;

impl SpaceHostDnsResolver for DefaultSpaceHostDnsResolver {
    fn resolve_dns<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, AuthReason>> + Send + 'a>> {
        let host = host.to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|_| AuthReason::DidResolutionFailed)?
                .collect();
            if addrs.is_empty() {
                return Err(AuthReason::DidResolutionFailed);
            }
            Ok(addrs)
        })
    }
}

#[derive(Clone)]
pub struct DefaultSpaceHostTransport {
    test_root_cert: Option<reqwest::Certificate>,
    dns_resolver: Arc<dyn SpaceHostDnsResolver>,
    allow_loopback_for_test: bool,
}

impl Default for DefaultSpaceHostTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultSpaceHostTransport {
    pub fn new() -> Self {
        Self {
            test_root_cert: None,
            dns_resolver: Arc::new(DefaultSpaceHostDnsResolver),
            allow_loopback_for_test: false,
        }
    }

    pub fn with_dns_resolver(dns_resolver: Arc<dyn SpaceHostDnsResolver>) -> Self {
        Self {
            test_root_cert: None,
            dns_resolver,
            allow_loopback_for_test: false,
        }
    }

    pub fn with_resolver_and_cert(
        dns_resolver: Arc<dyn SpaceHostDnsResolver>,
        cert: Option<reqwest::Certificate>,
    ) -> Self {
        Self {
            test_root_cert: cert,
            dns_resolver,
            allow_loopback_for_test: false,
        }
    }

    pub fn with_test_fixture(
        dns_resolver: Arc<dyn SpaceHostDnsResolver>,
        cert: Option<reqwest::Certificate>,
        allow_loopback: bool,
    ) -> Self {
        Self {
            test_root_cert: cert,
            dns_resolver,
            allow_loopback_for_test: allow_loopback,
        }
    }

    pub fn with_loopback(allow_loopback: bool) -> Self {
        Self {
            test_root_cert: None,
            dns_resolver: Arc::new(DefaultSpaceHostDnsResolver),
            allow_loopback_for_test: allow_loopback,
        }
    }

    pub fn allows_loopback_for_test(&self) -> bool {
        self.allow_loopback_for_test
    }

    pub async fn build_pinned_client(
        &self,
        target_url: &url::Url,
    ) -> Result<reqwest::Client, AppError> {
        if target_url.scheme() != "https"
            && (!self.allow_loopback_for_test || target_url.scheme() != "http")
        {
            return Err(AppError::InvalidRequest(
                "Space host endpoint must use HTTPS".into(),
            ));
        }

        let host = target_url
            .host_str()
            .ok_or_else(|| AppError::InvalidRequest("Missing host in Space host URL".into()))?;

        if !self.allow_loopback_for_test {
            if host.is_empty() || is_localhost_hostname(host) {
                return Err(AppError::Unauthorized(AuthReason::SsrfBlocked));
            }

            if let Ok(ip) = host.parse::<IpAddr>() {
                if is_private_ip(&ip) {
                    return Err(AppError::Unauthorized(AuthReason::SsrfBlocked));
                }
            }
        }

        let port = target_url.port().unwrap_or(443);

        let addrs = self
            .dns_resolver
            .resolve_dns(host, port)
            .await
            .map_err(|e| match e {
                AuthReason::SsrfBlocked => AppError::Unauthorized(AuthReason::SsrfBlocked),
                other => {
                    AppError::Internal(format!("DNS resolution failed for {host}:{port}: {other}"))
                }
            })?;

        if addrs.is_empty() {
            return Err(AppError::Internal(format!(
                "DNS resolution returned no addresses for {host}"
            )));
        }

        if !self.allow_loopback_for_test {
            for addr in &addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(AppError::Unauthorized(AuthReason::SsrfBlocked));
                }
            }
        }
        let pinned_addr = addrs[0];

        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .resolve(host, pinned_addr);

        if let Some(cert) = &self.test_root_cert {
            builder = builder.add_root_certificate(cert.clone());
        } else if self.allow_loopback_for_test {
            builder = builder.danger_accept_invalid_certs(true);
        }

        builder
            .build()
            .map_err(|e| AppError::Internal(format!("Failed to build pinned HTTPS client: {e}")))
    }
}

impl SpaceHostTransport for DefaultSpaceHostTransport {
    fn build_pinned_client<'a>(
        &'a self,
        target_url: &'a url::Url,
    ) -> Pin<Box<dyn Future<Output = Result<reqwest::Client, AppError>> + Send + 'a>> {
        let target_url = target_url.clone();
        Box::pin(async move { self.build_pinned_client(&target_url).await })
    }

    fn get_delegation_token<'a>(
        &'a self,
        target_url: &'a url::Url,
        space_uri: &'a str,
        access_token: &'a str,
        dpop_key: &'a p256::ecdsa::SigningKey,
    ) -> Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>> {
        let target_url = target_url.clone();
        let space_uri = space_uri.to_string();
        let access_token = access_token.to_string();
        let dpop_key = dpop_key.clone();

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let mut req_url = target_url.clone();
            req_url.query_pairs_mut().append_pair("space", &space_uri);

            let response =
                crate::oauth::get_with_dpop(&client, &dpop_key, req_url.as_str(), &access_token)
                    .await
                    .map_err(|e| {
                        AppError::Internal(format!("Failed to get delegation token: {e}"))
                    })?;

            if !response.status().is_success() {
                let status = response.status();
                let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                    response,
                    MAX_SPACE_CREDENTIAL_BYTES,
                )
                .await
                .unwrap_or_default();
                let body = String::from_utf8_lossy(&body_bytes);
                return Err(parse_xrpc_error(status, &body));
            }

            #[derive(Deserialize)]
            struct DelegationTokenResponse {
                token: String,
            }

            let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                response,
                MAX_SPACE_CREDENTIAL_BYTES,
            )
            .await?;
            let body: DelegationTokenResponse =
                serde_json::from_slice(&body_bytes).map_err(|e| {
                    AppError::Internal(format!("Invalid delegation token response JSON: {e}"))
                })?;

            if body.token.is_empty() {
                return Err(AppError::Internal("Empty delegation token received".into()));
            }

            Ok(body.token)
        })
    }

    fn authorize_space_sync<'a>(
        &'a self,
        target_url: &'a url::Url,
        request: &'a AuthorizeSpaceSyncRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizeSpaceSyncOutput, AppError>> + Send + 'a>> {
        let target_url = target_url.clone();
        let request = request.clone();
        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;
            let response = client
                .post(target_url.as_str())
                .json(&request)
                .send()
                .await
                .map_err(|e| {
                    AppError::Internal(format!("Failed to call authorizeSpaceSync: {e}"))
                })?;

            if !response.status().is_success() {
                let status = response.status();
                let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                    response,
                    MAX_SPACE_CREDENTIAL_BYTES,
                )
                .await
                .unwrap_or_default();
                return Err(parse_xrpc_error(
                    status,
                    &String::from_utf8_lossy(&body_bytes),
                ));
            }

            let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                response,
                MAX_SPACE_CREDENTIAL_BYTES,
            )
            .await?;
            let body: AuthorizeSpaceSyncOutput = serde_json::from_slice(&body_bytes)
                .map_err(|e| AppError::Internal(format!("Invalid authorizeSpaceSync response: {e}")))?;
            if body.credential.is_empty() {
                return Err(AppError::Internal(
                    "Empty credential in authorizeSpaceSync response".into(),
                ));
            }
            Ok(body)
        })
    }

    fn list_writers<'a>(
        &'a self,
        target_url: &'a url::Url,
        auth: &'a SpaceAuthHeaders,
        space_uri: &'a str,
        cursor: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<ListWritersOutput, AppError>> + Send + 'a>> {
        let target_url = target_url.clone();
        let auth = auth.clone();
        let space_uri = space_uri.to_string();
        let cursor = cursor.map(|c| c.to_string());

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let req_url = xrpc_query::list_writers(&target_url, &space_uri, cursor.as_deref())?;

            let response = auth
                .apply(client.get(req_url.as_str()))
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

            if !response.status().is_success() {
                return Err(credential_use_error(response, "listWriters").await);
            }
            let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                response,
                MAX_SPACE_RESPONSE_BYTES,
            )
            .await?;
            let output = serde_json::from_slice(&body_bytes)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            Ok(output)
        })
    }

    fn list_repo_ops<'a>(
        &'a self,
        target_url: &'a url::Url,
        auth: &'a SpaceAuthHeaders,
        space_uri: &'a str,
        repo_did: &'a str,
        since: Option<&'a str>,
        cursor: Option<&'a str>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput,
                        AppError,
                    >,
                > + Send
                + 'a,
        >,
    >{
        let target_url = target_url.clone();
        let auth = auth.clone();
        let space_uri = space_uri.to_string();
        let repo_did = repo_did.to_string();
        let since = since.map(|s| s.to_string());
        let cursor = cursor.map(|c| c.to_string());

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let req_url = xrpc_query::list_repo_ops(
                &target_url,
                &space_uri,
                &repo_did,
                since.as_deref(),
                cursor.as_deref(),
            )?;

            let response = auth
                .apply(client.get(req_url.as_str()))
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

            if !response.status().is_success() {
                return Err(credential_use_error(response, "listRepoOps").await);
            }
            let response_headers = response.headers().clone();
            let mac_request = auth
                .mac
                .as_ref()
                .ok_or(AppError::Unauthorized(AuthReason::InvalidSpaceMac))?;
            let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                response,
                MAX_SPACE_RESPONSE_BYTES,
            )
            .await?;
            let output: catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput = serde_json::from_slice(&body_bytes)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            crate::space_mac::verify_commit(
                &output.commit,
                &space_uri,
                &repo_did,
                mac_request,
                &response_headers,
            )?;
            Ok(output)
        })
    }

    fn get_repo<'a>(
        &'a self,
        target_url: &'a url::Url,
        auth: &'a SpaceAuthHeaders,
        space_uri: &'a str,
        repo_did: &'a str,
        since: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AppError>> + Send + 'a>> {
        let target_url = target_url.clone();
        let auth = auth.clone();
        let space_uri = space_uri.to_string();
        let repo_did = repo_did.to_string();
        let since = since.map(|s| s.to_string());

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            // getRepo has no `since` parameter upstream; the full repo is returned.
            let _ = since;
            let req_url = xrpc_query::get_repo(&target_url, &space_uri, &repo_did)?;

            let response = auth
                .apply(
                    client
                        .get(req_url.as_str())
                        .header(reqwest::header::ACCEPT, "application/vnd.dasl.star"),
                )
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

            if !response.status().is_success() {
                return Err(credential_use_error(response, "getRepo").await);
            }
            if response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                .is_none_or(|value| {
                    !value
                        .trim()
                        .eq_ignore_ascii_case("application/vnd.dasl.star")
                })
            {
                return Err(AppError::InvalidRequest(
                    "getRepo must return STAR application/vnd.dasl.star".into(),
                ));
            }

            let response_headers = response.headers().clone();
            let mac_request = auth
                .mac
                .as_ref()
                .ok_or(AppError::Unauthorized(AuthReason::InvalidSpaceMac))?;
            let max_car_bytes = crate::space_star::MAX_STAR_BYTES;
            let bytes =
                crate::auth::read_bounded_authenticated_response_bytes(response, max_car_bytes)
                    .await?;
            let commit = crate::space_star::read_commit(&bytes, &space_uri, &repo_did)?;
            crate::space_mac::verify_commit(
                &commit,
                &space_uri,
                &repo_did,
                mac_request,
                &response_headers,
            )?;
            crate::space_star::parse_repo_star(&bytes, &space_uri, &repo_did)?;
            Ok(bytes)
        })
    }

    fn get_latest_commit<'a>(
        &'a self,
        target_url: &'a url::Url,
        auth: &'a SpaceAuthHeaders,
        space_uri: &'a str,
        repo_did: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        catbird_atproto::generated::com_atproto::space::Commit,
                        AppError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let target_url = target_url.clone();
        let auth = auth.clone();
        let space_uri = space_uri.to_string();
        let repo_did = repo_did.to_string();

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let req_url = xrpc_query::get_latest_commit(&target_url, &space_uri, &repo_did)?;

            let response = auth
                .apply(client.get(req_url.as_str()))
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

            if !response.status().is_success() {
                return Err(credential_use_error(response, "getLatestCommit").await);
            }
            let response_headers = response.headers().clone();
            let mac_request = auth
                .mac
                .as_ref()
                .ok_or(AppError::Unauthorized(AuthReason::InvalidSpaceMac))?;
            let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                response,
                MAX_SPACE_RESPONSE_BYTES,
            )
            .await?;
            let output: catbird_atproto::generated::com_atproto::space::get_latest_commit::GetLatestCommitOutput = serde_json::from_slice(&body_bytes).map_err(|e| AppError::Internal(e.to_string()))?;
            crate::space_mac::verify_commit(
                &output.commit,
                &space_uri,
                &repo_did,
                mac_request,
                &response_headers,
            )?;
            Ok(output.commit)
        })
    }

    fn get_blob<'a>(
        &'a self,
        target_url: &'a url::Url,
        auth: &'a SpaceAuthHeaders,
        space_uri: &'a str,
        repo: &'a str,
        cid: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(Option<String>, Vec<u8>), AppError>> + Send + 'a>>
    {
        let target_url = target_url.clone();
        let auth = auth.clone();
        let space_uri = space_uri.to_string();
        let repo = repo.to_string();
        let cid = cid.to_string();

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let req_url = xrpc_query::get_blob(&target_url, &space_uri, &repo, &cid)?;

            let response = auth
                .apply(client.get(req_url.as_str()))
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

            if !response.status().is_success() {
                return Err(credential_use_error(response, "getBlob").await);
            }

            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let max_bytes: usize = 20 * 1024 * 1024; // 20 MiB streaming cap
            let bytes =
                crate::auth::read_bounded_authenticated_response_bytes(response, max_bytes).await?;
            Ok((content_type, bytes))
        })
    }
}

#[derive(Debug, Clone)]
pub struct RecordedSpaceHostCall {
    pub endpoint_url: String,
    pub request: AuthorizeSpaceSyncRequest,
}

/// One request the mock received with a space credential.
#[derive(Debug, Clone)]
pub struct RecordedCredentialUse {
    /// The XRPC method, e.g. `com.atproto.space.getRepo`.
    pub method: &'static str,
    pub space_uri: String,
    pub auth: SpaceAuthHeaders,
}


#[derive(Debug, Clone)]
pub struct RecordedDelegationTokenCall {
    pub endpoint_url: String,
    pub space_uri: String,
    pub access_token: String,
}

pub struct MockSpaceHostTransport {
    responses: Mutex<HashMap<String, Result<String, String>>>,
    delegation_token_responses: Mutex<HashMap<String, Result<String, String>>>,
    delegation_token_calls: Mutex<Vec<RecordedDelegationTokenCall>>,
    authority_keys: Mutex<HashMap<String, p256::ecdsa::SigningKey>>,
    authorize_space_revs: Mutex<HashMap<String, Option<String>>>,
    list_writers_responses: Mutex<HashMap<String, ListWritersOutput>>,
    list_repo_ops_responses: Mutex<
        HashMap<
            String,
            catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput,
        >,
    >,
    list_repo_ops_not_found: Mutex<HashSet<String>>,
    get_repo_responses: Mutex<HashMap<String, Vec<u8>>>,
    latest_commits: Mutex<HashMap<String, catbird_atproto::generated::com_atproto::space::Commit>>,
    calls: Mutex<Vec<RecordedSpaceHostCall>>,
    #[allow(clippy::type_complexity)]
    blob_responses: Mutex<HashMap<String, (Option<String>, Vec<u8>)>>,
    blob_calls: Mutex<Vec<String>>,
    space_members: Mutex<HashMap<String, Result<Vec<SpaceMember>, String>>>,
    space_configs: Mutex<HashMap<String, Result<SpaceConfig, String>>>,
    credential_uses: Mutex<Vec<RecordedCredentialUse>>,
    list_writers_cursors: Mutex<Vec<Option<String>>>,
    credential_rejection: Mutex<Option<AuthReason>>,
}

impl Default for MockSpaceHostTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSpaceHostTransport {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(HashMap::new()),
            delegation_token_responses: Mutex::new(HashMap::new()),
            delegation_token_calls: Mutex::new(Vec::new()),
            authority_keys: Mutex::new(HashMap::new()),
            authorize_space_revs: Mutex::new(HashMap::new()),
            list_writers_responses: Mutex::new(HashMap::new()),
            list_repo_ops_responses: Mutex::new(HashMap::new()),
            list_repo_ops_not_found: Mutex::new(HashSet::new()),
            get_repo_responses: Mutex::new(HashMap::new()),
            latest_commits: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            blob_responses: Mutex::new(HashMap::new()),
            blob_calls: Mutex::new(Vec::new()),
            space_members: Mutex::new(HashMap::new()),
            space_configs: Mutex::new(HashMap::new()),
            credential_uses: Mutex::new(Vec::new()),
            list_writers_cursors: Mutex::new(Vec::new()),
            credential_rejection: Mutex::new(None),
        }
    }

    /// Every request made with a space credential, in order.
    pub fn recorded_credential_uses(&self) -> Vec<RecordedCredentialUse> {
        self.credential_uses.lock().unwrap().clone()
    }

    /// The `cursor` of each listWriters request, in order.
    pub fn recorded_list_writers_cursors(&self) -> Vec<Option<String>> {
        self.list_writers_cursors.lock().unwrap().clone()
    }

    /// Reject every later request made with a space credential, as a host does
    /// for a revoked credential or a refused signature or audience.
    pub fn reject_credential_uses(&self, reason: Option<AuthReason>) {
        *self.credential_rejection.lock().unwrap() = reason;
    }

    /// Record a credential use; `Err` when uses are being rejected.
    fn use_credential(
        &self,
        method: &'static str,
        space_uri: &str,
        auth: &SpaceAuthHeaders,
    ) -> Result<(), AppError> {
        self.credential_uses
            .lock()
            .unwrap()
            .push(RecordedCredentialUse {
                method,
                space_uri: space_uri.to_string(),
                auth: auth.clone(),
            });
        match *self.credential_rejection.lock().unwrap() {
            Some(reason) => Err(AppError::Unauthorized(reason)),
            None => Ok(()),
        }
    }

    pub fn set_credential_response(&self, space: &str, result: Result<String, String>) {
        let mut lock = self.responses.lock().unwrap();
        lock.insert(space.to_string(), result);
    }

    pub fn set_delegation_token_response(&self, space: &str, result: Result<String, String>) {
        let mut lock = self.delegation_token_responses.lock().unwrap();
        lock.insert(space.to_string(), result);
    }

    pub fn set_authority_signing_key(&self, authority_did: &str, key: p256::ecdsa::SigningKey) {
        let mut lock = self.authority_keys.lock().unwrap();
        lock.insert(authority_did.to_string(), key);
    }

    pub fn set_authorize_space_rev(&self, space: &str, space_rev: Option<String>) {
        self.authorize_space_revs
            .lock()
            .unwrap()
            .insert(space.to_owned(), space_rev);
    }

    pub fn recorded_delegation_token_calls(&self) -> Vec<RecordedDelegationTokenCall> {
        let lock = self.delegation_token_calls.lock().unwrap();
        lock.clone()
    }

    pub fn set_list_writers_response(
        &self,
        space: &str,
        output: ListWritersOutput,
    ) {
        self.list_writers_responses
            .lock()
            .unwrap()
            .insert(space.to_string(), output);
    }

    pub fn set_list_repo_ops_response(
        &self,
        space_and_repo: &str,
        output: catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput,
    ) {
        let mut lock = self.list_repo_ops_responses.lock().unwrap();
        lock.insert(space_and_repo.to_string(), output);
    }

    pub fn set_list_repo_ops_not_found(&self, space_and_repo: &str) {
        self.list_repo_ops_not_found
            .lock()
            .unwrap()
            .insert(space_and_repo.to_string());
    }

    pub fn set_get_repo_response(&self, space_and_repo: &str, output: Vec<u8>) {
        let mut lock = self.get_repo_responses.lock().unwrap();
        lock.insert(space_and_repo.to_string(), output);
    }

    pub fn set_latest_commit(
        &self,
        space_and_repo: &str,
        commit: catbird_atproto::generated::com_atproto::space::Commit,
    ) {
        let mut lock = self.latest_commits.lock().unwrap();
        lock.insert(space_and_repo.to_string(), commit);
    }

    pub fn set_blob_response(&self, key: &str, content_type: Option<String>, data: Vec<u8>) {
        let mut lock = self.blob_responses.lock().unwrap();
        lock.insert(key.to_string(), (content_type, data));
    }


    pub fn recorded_calls(&self) -> Vec<RecordedSpaceHostCall> {
        let lock = self.calls.lock().unwrap();
        lock.clone()
    }

    pub fn recorded_blob_calls(&self) -> Vec<String> {
        let lock = self.blob_calls.lock().unwrap();
        lock.clone()
    }

    pub fn set_space_members(&self, space: &str, members: Vec<String>) {
        let mut lock = self.space_members.lock().unwrap();
        let detailed: Vec<SpaceMember> = members
            .into_iter()
            .map(|did| SpaceMember {
                did,
                read: true,
                write: true,
            })
            .collect();
        lock.insert(space.to_string(), Ok(detailed));
    }

    pub fn set_space_members_detailed(&self, space: &str, members: Vec<SpaceMember>) {
        let mut lock = self.space_members.lock().unwrap();
        lock.insert(space.to_string(), Ok(members));
    }

    pub fn set_space_members_error(&self, space: &str, error: String) {
        let mut lock = self.space_members.lock().unwrap();
        lock.insert(space.to_string(), Err(error));
    }

    pub fn set_space_config(&self, space: &str, config: SpaceConfig) {
        let mut lock = self.space_configs.lock().unwrap();
        lock.insert(space.to_string(), Ok(config));
    }

    pub fn set_space_config_error(&self, space: &str, error: String) {
        let mut lock = self.space_configs.lock().unwrap();
        lock.insert(space.to_string(), Err(error));
    }
}

impl SpaceHostTransport for MockSpaceHostTransport {
    fn fixture_kem_key(&self) -> Option<p256::PublicKey> {
        Some(
            p256::SecretKey::from_slice(&[1; 32])
                .expect("fixture key")
                .public_key(),
        )
    }

    fn get_delegation_token<'a>(
        &'a self,
        target_url: &'a url::Url,
        space_uri: &'a str,
        access_token: &'a str,
        _dpop_key: &'a p256::ecdsa::SigningKey,
    ) -> Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>> {
        {
            let mut calls = self.delegation_token_calls.lock().unwrap();
            calls.push(RecordedDelegationTokenCall {
                endpoint_url: target_url.to_string(),
                space_uri: space_uri.to_string(),
                access_token: access_token.to_string(),
            });
        }
        let lock = self.delegation_token_responses.lock().unwrap();
        let res = lock.get(space_uri).cloned();
        Box::pin(async move {
            match res {
                Some(Ok(token)) => Ok(token),
                Some(Err(e)) => Err(parse_xrpc_error(reqwest::StatusCode::BAD_REQUEST, &e)),
                None => Ok(format!("mock_delegation_token_{space_uri}")),
            }
        })
    }

    fn authorize_space_sync<'a>(
        &'a self,
        target_url: &'a url::Url,
        request: &'a AuthorizeSpaceSyncRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizeSpaceSyncOutput, AppError>> + Send + 'a>> {
        let space_uri = request.space.as_str();
        self.calls.lock().unwrap().push(RecordedSpaceHostCall {
            endpoint_url: target_url.to_string(),
            request: request.clone(),
        });
        let authority_did = extract_authority_from_space_uri(space_uri).unwrap_or_default();
        let authority_key = self
            .authority_keys
            .lock()
            .unwrap()
            .get(&authority_did)
            .cloned();
        let space_rev = self
            .authorize_space_revs
            .lock()
            .unwrap()
            .get(space_uri)
            .cloned()
            .flatten();
        let res = self.responses.lock().unwrap().get(space_uri).cloned();
        Box::pin(async move {
            let credential = match res {
                Some(Ok(credential)) => credential,
                Some(Err(e)) => {
                    return Err(parse_xrpc_error(reqwest::StatusCode::BAD_REQUEST, &e))
                }
                None => {
                    let key = authority_key.ok_or_else(|| {
                        AppError::NotFound(format!("No mock response for {space_uri}"))
                    })?;
                    mint_mock_space_credential(
                        &key,
                        &authority_did,
                        space_uri,
                        request.credential_key.as_str(),
                        Utc::now()
                            + chrono::Duration::seconds(DEFAULT_CREDENTIAL_LIFETIME_SECS),
                    )
                }
            };
            Ok(AuthorizeSpaceSyncOutput {
                credential,
                space_rev,
            })
        })
    }

    fn list_writers<'a>(
        &'a self,
        _target_url: &'a url::Url,
        auth: &'a SpaceAuthHeaders,
        space_uri: &'a str,
        cursor: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<ListWritersOutput, AppError>> + Send + 'a>> {
        if let Err(e) = self.use_credential("com.atproto.space.listWriters", space_uri, auth) {
            return Box::pin(async move { Err(e) });
        }
        self.list_writers_cursors
            .lock()
            .unwrap()
            .push(cursor.map(str::to_string));
        let lock = self.list_writers_responses.lock().unwrap();
        let res = match cursor {
            Some(c) => Some(
                lock.get(&format!("{space_uri}:{c}"))
                    .cloned()
                    .unwrap_or(ListWritersOutput {
                        cursor: None,
                        repos: Vec::new(),
                    }),
            ),
            None => lock.get(space_uri).cloned(),
        };
        let lookup_key = match cursor {
            Some(c) => format!("{space_uri}:{c}"),
            None => space_uri.to_string(),
        };
        Box::pin(async move {
            res.ok_or_else(|| {
                AppError::NotFound(format!("No mock list_writers configured for {lookup_key}"))
            })
        })
    }

    fn list_repo_ops<'a>(
        &'a self,
        _target_url: &'a url::Url,
        auth: &'a SpaceAuthHeaders,
        space_uri: &'a str,
        repo_did: &'a str,
        _since: Option<&'a str>,
        cursor: Option<&'a str>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput,
                        AppError,
                    >,
                > + Send
                + 'a,
        >,
    >{
        if let Err(e) = self.use_credential("com.atproto.space.listRepoOps", space_uri, auth) {
            return Box::pin(async move { Err(e) });
        }
        let base_key = format!("{space_uri}:{repo_did}");
        let repo_not_found = self
            .list_repo_ops_not_found
            .lock()
            .unwrap()
            .contains(&base_key);
        let lock = self.list_repo_ops_responses.lock().unwrap();
        let res = match cursor {
            Some(c) => lock
                .get(&format!("{base_key}:{c}"))
                .or_else(|| lock.get(&base_key))
                .or_else(|| lock.get(space_uri))
                .cloned(),
            None => lock.get(&base_key).or_else(|| lock.get(space_uri)).cloned(),
        };
        let lookup_key = match cursor {
            Some(c) => format!("{base_key}:{c}"),
            None => base_key,
        };
        Box::pin(async move {
            if repo_not_found {
                return Err(AppError::NotFound("RepoNotFound".into()));
            }
            res.ok_or_else(|| {
                AppError::NotFound(format!("No mock list_repo_ops configured for {lookup_key}"))
            })
        })
    }

    fn get_repo<'a>(
        &'a self,
        _target_url: &'a url::Url,
        auth: &'a SpaceAuthHeaders,
        space_uri: &'a str,
        repo_did: &'a str,
        _since: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AppError>> + Send + 'a>> {
        if let Err(e) = self.use_credential("com.atproto.space.getRepo", space_uri, auth) {
            return Box::pin(async move { Err(e) });
        }
        let key = format!("{space_uri}:{repo_did}");
        let lock = self.get_repo_responses.lock().unwrap();
        let res = lock.get(&key).or_else(|| lock.get(space_uri)).cloned();
        Box::pin(async move {
            res.ok_or_else(|| AppError::NotFound(format!("No mock get_repo configured for {key}")))
        })
    }

    fn get_latest_commit<'a>(
        &'a self,
        _target_url: &'a url::Url,
        auth: &'a SpaceAuthHeaders,
        space_uri: &'a str,
        repo_did: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        catbird_atproto::generated::com_atproto::space::Commit,
                        AppError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        if let Err(e) = self.use_credential("com.atproto.space.getLatestCommit", space_uri, auth) {
            return Box::pin(async move { Err(e) });
        }
        let key = format!("{space_uri}:{repo_did}");
        let lock = self.latest_commits.lock().unwrap();
        let res = lock.get(&key).or_else(|| lock.get(space_uri)).cloned();
        Box::pin(async move {
            res.ok_or_else(|| {
                AppError::NotFound(format!("No mock get_latest_commit configured for {key}"))
            })
        })
    }

    fn get_blob<'a>(
        &'a self,
        _target_url: &'a url::Url,
        auth: &'a SpaceAuthHeaders,
        space_uri: &'a str,
        did: &'a str,
        cid: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(Option<String>, Vec<u8>), AppError>> + Send + 'a>>
    {
        if let Err(e) = self.use_credential("com.atproto.space.getBlob", space_uri, auth) {
            return Box::pin(async move { Err(e) });
        }
        let key = format!("{space_uri}:{did}:{cid}");
        let alt_key = format!("{did}:{cid}");
        {
            let mut calls = self.blob_calls.lock().unwrap();
            calls.push(key.clone());
        }
        let lock = self.blob_responses.lock().unwrap();
        let res = lock.get(&key).or_else(|| lock.get(&alt_key)).cloned();
        Box::pin(async move {
            let (content_type, bytes) = res.ok_or_else(|| {
                AppError::NotFound(format!("No mock get_blob configured for {key}"))
            })?;
            let max_bytes: usize = 20 * 1024 * 1024;
            if bytes.len() > max_bytes {
                return Err(AppError::InvalidRequest(format!(
                    "Blob stream exceeds maximum size limit of {max_bytes} bytes"
                )));
            }
            Ok((content_type, bytes))
        })
    }
    fn list_members<'a>(
        &'a self,
        space_uri: &'a str,
    ) -> Option<Pin<Box<dyn Future<Output = Result<Vec<SpaceMember>, AppError>> + Send + 'a>>> {
        let lock = self.space_members.lock().unwrap();
        if let Some(res) = lock.get(space_uri).cloned() {
            Some(Box::pin(async move { res.map_err(AppError::Forbidden) }))
        } else {
            None
        }
    }

    fn get_space<'a>(
        &'a self,
        space_uri: &'a str,
    ) -> Option<Pin<Box<dyn Future<Output = Result<SpaceConfig, AppError>> + Send + 'a>>> {
        let lock = self.space_configs.lock().unwrap();
        if let Some(res) = lock.get(space_uri).cloned() {
            Some(Box::pin(async move {
                match res {
                    Ok(cfg) => Ok(cfg),
                    Err(e) => {
                        if e.starts_with('{') {
                            Err(parse_xrpc_error(reqwest::StatusCode::BAD_REQUEST, &e))
                        } else if e == "NotFound" || e == "SpaceNotFound" {
                            Err(AppError::NotFound(e))
                        } else if e.starts_with("Internal") || e.starts_with("Upstream") {
                            Err(AppError::Internal(e))
                        } else {
                            Err(AppError::Forbidden(e))
                        }
                    }
                }
            }))
        } else {
            None
        }
    }
    fn build_pinned_client<'a>(
        &'a self,
        target_url: &'a url::Url,
    ) -> Pin<Box<dyn Future<Output = Result<reqwest::Client, AppError>> + Send + 'a>> {
        let target_url = target_url.clone();
        Box::pin(async move {
            DefaultSpaceHostTransport::with_loopback(true)
                .build_pinned_client(&target_url)
                .await
        })
    }
}

pub struct SpaceClient {
    transport: Arc<dyn SpaceHostTransport>,
    deps: RwLock<Option<SpaceClientDeps>>,
}

impl SpaceClient {
    pub fn new() -> Self {
        Self {
            transport: Arc::new(DefaultSpaceHostTransport::new()),
            deps: RwLock::new(None),
        }
    }

    pub fn with_transport(transport: Arc<dyn SpaceHostTransport>) -> Self {
        Self {
            transport,
            deps: RwLock::new(None),
        }
    }

    pub fn set_deps(&self, deps: SpaceClientDeps) {
        let mut lock = self.deps.write();
        *lock = Some(deps);
    }

    /// Mint a delegation token from the user's PDS using AppView's OAuth access token.
    pub async fn get_delegation_token(
        &self,
        user_pds_endpoint: &str,
        space_uri: &str,
        access_token: &str,
        dpop_key: &p256::ecdsa::SigningKey,
    ) -> Result<String, AppError> {
        let xrpc_url =
            construct_xrpc_url(user_pds_endpoint, "com.atproto.space.getDelegationToken")?;
        self.transport
            .get_delegation_token(&xrpc_url, space_uri, access_token, dpop_key)
            .await
    }

    /// Fetch member DIDs and their read/write flags via `com.atproto.memberspace.listMembers` from the owner's PDS using AppView's OAuth session.
    /// Enforces bounds on pages, total members, bytes, cursor length, duration, concurrency, and repeated cursor detection.
    /// Stages all results and only returns when completely fetched without truncation (fails closed).
    pub async fn list_members(&self, space: &str) -> Result<Vec<SpaceMember>, AppError> {
        if let Some(fut) = self.transport.list_members(space) {
            return fut.await;
        }

        let _permit = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            HYDRATION_SEMAPHORE.acquire(),
        )
        .await
        .map_err(|_| AppError::TooManyRequests("Concurrent member hydration limit reached".into()))?
        .map_err(|_| AppError::Internal("Member hydration semaphore closed".into()))?;

        let deps = {
            let lock = self.deps.read();
            lock.clone()
                .ok_or_else(|| AppError::Internal("SpaceClient deps not configured".into()))?
        };

        let authority = extract_authority_from_space_uri(space)?;
        let pds_endpoint = deps
            .did_resolver
            .resolve_pds_endpoint(&authority)
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to resolve PDS endpoint for {authority}: {e:?}"
                ))
            })?;

        let (token, dpop_key) = deps
            .oauth_service
            .get_valid_token(&authority, &deps.http_client)
            .await?;

        let mut staged_members = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::HashSet::new();
        let start_time = std::time::Instant::now();
        let mut page_count = 0;
        let mut total_bytes_read = 0;

        loop {
            if start_time.elapsed() > MAX_LIST_MEMBERS_DURATION {
                return Err(AppError::InvalidRequest(
                    "listMembers timeout exceeded".into(),
                ));
            }

            page_count += 1;
            if page_count > MAX_LIST_MEMBERS_PAGES {
                return Err(AppError::InvalidRequest(
                    "listMembers page limit exceeded".into(),
                ));
            }

            if let Some(c) = &cursor {
                if c.len() > MAX_CURSOR_LEN {
                    return Err(AppError::InvalidRequest(
                        "listMembers cursor length exceeded".into(),
                    ));
                }
            }

            let req_url = xrpc_query::list_members(
                &construct_xrpc_url(&pds_endpoint, "com.atproto.memberspace.listMembers")?,
                space,
                cursor.as_deref(),
            )?;

            let client = self.transport.build_pinned_client(&req_url).await?;
            let resp = crate::oauth::get_with_dpop(&client, &dpop_key, req_url.as_str(), &token)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to fetch listMembers: {e}")))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                    resp,
                    crate::oauth::MAX_OAUTH_RESPONSE_BYTES,
                )
                .await
                .unwrap_or_default();
                return Err(parse_xrpc_error(
                    status,
                    &String::from_utf8_lossy(&body_bytes),
                ));
            }

            let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                resp,
                crate::oauth::MAX_OAUTH_RESPONSE_BYTES,
            )
            .await?;
            total_bytes_read += body_bytes.len();
            if total_bytes_read > MAX_LIST_MEMBERS_TOTAL_BYTES {
                return Err(AppError::InvalidRequest(
                    "listMembers aggregate byte limit exceeded".into(),
                ));
            }
            let data: catbird_atproto::generated::com_atproto::memberspace::list_members::ListMembersOutput<String> =
                serde_json::from_slice(&body_bytes).map_err(|e| {
                    AppError::Internal(format!("Failed to parse listMembers output: {e}"))
                })?;
            for member in data.members {
                staged_members.push(SpaceMember {
                    did: member.did.as_str().to_owned(),
                    read: member.read,
                    write: member.write,
                });
            }

            if staged_members.len() > MAX_LIST_MEMBERS_TOTAL {
                return Err(AppError::InvalidRequest(
                    "listMembers total members limit exceeded".into(),
                ));
            }

            if let Some(next) = data.cursor {
                if !seen_cursors.insert(next.clone()) {
                    return Err(AppError::InvalidRequest(
                        "Repeated pagination cursor detected in listMembers".into(),
                    ));
                }
                cursor = Some(next);
            } else {
                break;
            }
        }

        Ok(staged_members)
    }

    /// Fetch member DIDs authorized for read via `com.atproto.memberspace.listMembers`.
    /// Filters out members with `read = false` to prevent unauthorized read access.
    pub async fn member_dids(&self, space: &str) -> Result<Vec<String>, AppError> {
        let members = self.list_members(space).await?;
        Ok(members
            .into_iter()
            .filter(|m| m.read)
            .map(|m| m.did)
            .collect())
    }

    /// Fetch the space policy via `com.atproto.space.getSpace` from the owner's PDS using AppView's OAuth session.
    pub async fn get_space(&self, space: &str) -> Result<SpaceConfig, AppError> {
        if let Some(fut) = self.transport.get_space(space) {
            return fut.await;
        }

        let deps = {
            let lock = self.deps.read();
            lock.clone()
                .ok_or_else(|| AppError::Internal("SpaceClient deps not configured".into()))?
        };
        let authority = extract_authority_from_space_uri(space)?;
        let pds_endpoint = deps
            .did_resolver
            .resolve_pds_endpoint(&authority)
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to resolve PDS endpoint for {authority}: {e:?}"
                ))
            })?;

        let (token, dpop_key) = deps
            .oauth_service
            .get_valid_token(&authority, &deps.http_client)
            .await?;

        let req_url = xrpc_query::get_space(
            &construct_xrpc_url(&pds_endpoint, "com.atproto.space.getSpace")?,
            space,
        )?;
        let client = self.transport.build_pinned_client(&req_url).await?;
        let resp = crate::oauth::get_with_dpop(&client, &dpop_key, req_url.as_str(), &token)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch getSpace: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                resp,
                crate::oauth::MAX_OAUTH_RESPONSE_BYTES,
            )
            .await
            .unwrap_or_default();
            let body = String::from_utf8_lossy(&body_bytes);
            return Err(parse_xrpc_error(status, &body));
        }

        // Nov-12 renamed the returned identifier to `space`. Bind it so a
        // misrouted response cannot authorize a different Space's policy.
        #[derive(Deserialize)]
        struct RawSpaceView {
            space: String,
            #[serde(default)]
            policy: Option<serde_json::Value>,
        }

        let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
            resp,
            crate::oauth::MAX_OAUTH_RESPONSE_BYTES,
        )
        .await?;
        let raw: RawSpaceView = serde_json::from_slice(&body_bytes)
            .map_err(|e| AppError::Internal(format!("Failed to parse getSpace output: {e}")))?;
        if raw.space != space {
            return Err(AppError::InvalidRequest(
                "getSpace response did not match the requested space".into(),
            ));
        }

        let parsed = match raw.policy.as_ref() {
            Some(policy) => SpacePolicy::parse_policy(policy),
            None => ParsedSpacePolicy {
                app_access: SpaceAppAccess::Unknown(None),
                read_policy: SpacePolicy::Unknown(None),
                write_policy: SpacePolicy::Unknown(None),
            },
        };

        let (authority, space_type, skey) = parse_space_uri_parts(space)?;

        Ok(SpaceConfig {
            authority,
            space_type,
            skey,
            app_access: parsed.app_access,
            read_policy: parsed.read_policy,
            write_policy: parsed.write_policy,
            user_policy: None,
            name: None,
            description: None,
        })
    }

    pub async fn authorize_space_sync(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        delegation_token: &str,
        client_attestation: &str,
        notify: Option<crate::notify::NotifyRegistration>,
        authority_did: &str,
        authority_doc: &DidDocument,
    ) -> Result<AuthorizedSpaceSync, AppError> {
        let parsed_endpoint = url::Url::parse(service_endpoint)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid service endpoint URL: {e}")))?;

        if parsed_endpoint.scheme() != "https" {
            return Err(AppError::InvalidRequest(
                "Service endpoint must use HTTPS".into(),
            ));
        }
        if !parsed_endpoint.username().is_empty() || parsed_endpoint.password().is_some() {
            return Err(AppError::InvalidRequest(
                "Service endpoint must not contain userinfo".into(),
            ));
        }
        if parsed_endpoint.query().is_some() || parsed_endpoint.fragment().is_some() {
            return Err(AppError::InvalidRequest(
                "Service endpoint must not contain query or fragment".into(),
            ));
        }

        let path = parsed_endpoint.path().trim_end_matches('/');
        let xrpc_path = if path.is_empty() {
            "/xrpc/com.atproto.space.authorizeSpaceSync".to_string()
        } else {
            format!("{path}/xrpc/com.atproto.space.authorizeSpaceSync")
        };
        let mut xrpc_url = parsed_endpoint;
        xrpc_url.set_path(&xrpc_path);

        let ephemeral_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let key_id = p256_did_key(ephemeral_key.verifying_key());
        let request = AuthorizeSpaceSyncRequest {
            space: space_uri.into(),
            credential_key: key_id.clone(),
            delegation_token: Some(delegation_token.into()),
            client_attestation: Some(client_attestation.into()),
            notify,
        };

        let output = self
            .transport
            .authorize_space_sync(&xrpc_url, &request)
            .await?;
        let expires_at = validate_space_credential(
            &output.credential,
            authority_did,
            space_uri,
            &key_id,
            authority_doc,
        )?;

        Ok(AuthorizedSpaceSync {
            credential: output.credential,
            signing_key: ephemeral_key,
            expires_at,
            space_rev: output.space_rev,
        })
    }

    /// Best-effort `com.atproto.server.describeServer` on a space host, reduced to
    /// the fields that identify its implementation profile, for operator logs.
    pub async fn describe_space_host(&self, service_endpoint: &str) -> Option<serde_json::Value> {
        let url = construct_xrpc_url(service_endpoint, "com.atproto.server.describeServer").ok()?;
        let client = self.transport.build_pinned_client(&url).await.ok()?;
        let response = client.get(url.as_str()).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        let bytes = crate::auth::read_bounded_authenticated_response_bytes(
            response,
            MAX_SPACE_RESPONSE_BYTES,
        )
        .await
        .ok()?;
        let body: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let mut profile = serde_json::Map::new();
        for key in ["did", "swanProfile", "version"] {
            if let Some(value) = body.get(key) {
                profile.insert(key.to_string(), value.clone());
            }
        }
        Some(serde_json::Value::Object(profile))
    }


    /// `com.atproto.space.listWriters` on the space host; audience is the
    /// authority's bare DID. `cursor` is an exclusive spaceRev checkpoint.
    pub async fn list_writers(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        cursor: Option<&str>,
        space_credential: &str,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> Result<ListWritersOutput, AppError> {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.listWriters")?;
        let auth = credential_headers(
            signing_key,
            space_credential,
            &extract_authority_from_space_uri(space_uri)?,
        );
        self.transport
            .list_writers(&xrpc_url, &auth, space_uri, cursor)
            .await
    }

    async fn mac_auth(
        &self,
        signing_key: &p256::ecdsa::SigningKey,
        credential: &str,
        repo: &str,
        refresh: bool,
    ) -> Result<SpaceAuthHeaders, AppError> {
        let kem = if let Some(key) = self.transport.fixture_kem_key() {
            key
        } else {
            let deps =
                self.deps.read().clone().ok_or_else(|| {
                    AppError::Internal("Space client resolver not configured".into())
                })?;
            let doc = if refresh {
                deps.did_resolver.resolve_identity_event(repo).await
            } else {
                deps.did_resolver.resolve(repo).await
            }
            .map_err(AppError::Unauthorized)?;
            crate::space_mac::kem_key(&doc, repo)?
        };
        let mut auth = credential_headers(signing_key, credential, repo);
        auth.mac = Some(crate::space_mac::encapsulate(
            &kem,
            crate::space_mac::MacProfile::Commit,
        )?);
        Ok(auth)
    }

    /// `com.atproto.space.listRepoOps` on the repo's host; audience is the repo
    /// owner's DID.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_repo_ops(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        repo_did: &str,
        since: Option<&str>,
        cursor: Option<&str>,
        space_credential: &str,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> Result<
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput,
        AppError,
    > {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.listRepoOps")?;
        for retry in 0..2 {
            let auth = self
                .mac_auth(signing_key, space_credential, repo_did, retry > 0)
                .await?;
            let result = self
                .transport
                .list_repo_ops(&xrpc_url, &auth, space_uri, repo_did, since, cursor)
                .await;
            if retry == 0
                && matches!(
                    &result,
                    Err(AppError::Unauthorized(AuthReason::InvalidSpaceMac))
                )
            {
                continue;
            }
            return result;
        }
        Err(AppError::Unauthorized(AuthReason::InvalidSpaceMac))
    }

    /// `com.atproto.space.getRepo` on the repo's host; audience is the repo
    /// owner's DID.
    pub async fn get_repo(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        repo_did: &str,
        since: Option<&str>,
        space_credential: &str,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> Result<Vec<u8>, AppError> {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.getRepo")?;
        for retry in 0..2 {
            let auth = self
                .mac_auth(signing_key, space_credential, repo_did, retry > 0)
                .await?;
            let result = self
                .transport
                .get_repo(&xrpc_url, &auth, space_uri, repo_did, since)
                .await;
            if retry == 0
                && matches!(
                    &result,
                    Err(AppError::Unauthorized(AuthReason::InvalidSpaceMac))
                )
            {
                continue;
            }
            return result;
        }
        Err(AppError::Unauthorized(AuthReason::InvalidSpaceMac))
    }

    /// `com.atproto.space.getLatestCommit` on the repo's host; audience is the
    /// repo owner's DID.
    pub async fn get_latest_commit(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        repo_did: &str,
        space_credential: &str,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> Result<catbird_atproto::generated::com_atproto::space::Commit, AppError> {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.getLatestCommit")?;
        for retry in 0..2 {
            let auth = self
                .mac_auth(signing_key, space_credential, repo_did, retry > 0)
                .await?;
            let result = self
                .transport
                .get_latest_commit(&xrpc_url, &auth, space_uri, repo_did)
                .await;
            if retry == 0
                && matches!(
                    &result,
                    Err(AppError::Unauthorized(AuthReason::InvalidSpaceMac))
                )
            {
                continue;
            }
            return result;
        }
        Err(AppError::Unauthorized(AuthReason::InvalidSpaceMac))
    }

    /// `com.atproto.space.getBlob` on the repo's host; audience is the repo
    /// owner's DID.
    pub async fn get_blob(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        repo: &str,
        cid: &str,
        space_credential: &str,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> Result<(Option<String>, Vec<u8>), AppError> {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.getBlob")?;
        let auth = credential_headers(signing_key, space_credential, repo);
        self.transport
            .get_blob(&xrpc_url, &auth, space_uri, repo, cid)
            .await
    }
}

impl Default for SpaceClient {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_authority_from_space_uri(space: &str) -> Result<String, AppError> {
    let (auth, _, _) = parse_space_uri_parts(space)?;
    Ok(auth)
}

fn parse_space_uri_parts(space: &str) -> Result<(String, String, String), AppError> {
    let without_prefix = space
        .strip_prefix("at://")
        .ok_or_else(|| AppError::InvalidRequest("Space URI must start with at://".into()))?;
    let segments: Vec<&str> = without_prefix.split('/').collect();
    if segments.len() < 4 || segments[1] != "space" {
        return Err(AppError::InvalidRequest(
            "Invalid Space URI format (expected at://{authority}/space/{spaceType}/{skey})".into(),
        ));
    }
    Ok((
        segments[0].to_string(),
        segments[2].to_string(),
        segments[3].to_string(),
    ))
}

/// Query URLs for the space-host, getSpace and memberspace reads, built from the
/// lexicon-generated `catbird_atproto` params structs so the wire keys come from
/// the lexicon rather than hand-typed strings. A hand-typed `did` in place of
/// getBlob's `repo` once made every Circle image request fail upstream.
pub mod xrpc_query {
    use super::AppError;
    use catbird_atproto::generated::com_atproto::{memberspace, space};
    use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
    use catbird_atproto::jacquard_common::types::aturi::AtSpaceUri;
    use catbird_atproto::jacquard_common::types::string::{Cid, Did, Tid};

    fn space_ref(space: &str) -> Result<AtSpaceUri<SmolStr>, AppError> {
        AtSpaceUri::new(SmolStr::new(space))
            .map_err(|e| AppError::InvalidRequest(format!("Invalid space reference: {e}")))
    }

    fn did(value: &str) -> Result<Did<SmolStr>, AppError> {
        Did::new(SmolStr::new(value))
            .map_err(|e| AppError::InvalidRequest(format!("Invalid repo DID: {e}")))
    }

    fn with_params<P: serde::Serialize>(
        target_url: &url::Url,
        params: &P,
    ) -> Result<url::Url, AppError> {
        let value = serde_json::to_value(params)
            .map_err(|e| AppError::Internal(format!("Failed to encode XRPC params: {e}")))?;
        let serde_json::Value::Object(map) = value else {
            return Err(AppError::Internal(
                "XRPC params must encode as an object".into(),
            ));
        };
        let mut url = target_url.clone();
        {
            let mut query = url.query_pairs_mut();
            for (key, value) in map {
                match value {
                    serde_json::Value::Null => {}
                    serde_json::Value::String(s) => {
                        query.append_pair(&key, &s);
                    }
                    serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
                        query.append_pair(&key, &value.to_string());
                    }
                    other => {
                        return Err(AppError::Internal(format!(
                            "Unsupported XRPC param value for {key}: {other}"
                        )));
                    }
                }
            }
        }
        Ok(url)
    }

    pub fn get_blob(
        target_url: &url::Url,
        space_uri: &str,
        repo: &str,
        cid: &str,
    ) -> Result<url::Url, AppError> {
        with_params(
            target_url,
            &space::get_blob::GetBlob::<SmolStr> {
                space: space_ref(space_uri)?,
                repo: did(repo)?,
                cid: Cid::Str(SmolStr::new(cid)),
            },
        )
    }

    pub fn list_repo_ops(
        target_url: &url::Url,
        space_uri: &str,
        repo: &str,
        since: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<url::Url, AppError> {
        let since = since
            .map(|s| {
                Tid::new(s).map_err(|e| {
                    AppError::Internal(format!("listRepoOps since is not a TID rev: {e}"))
                })
            })
            .transpose()?;
        with_params(
            target_url,
            &space::list_repo_ops::ListRepoOps::<SmolStr> {
                cursor: cursor.map(SmolStr::new),
                exclude_values: None,
                limit: None,
                repo: did(repo)?,
                since,
                space: space_ref(space_uri)?,
            },
        )
    }

    pub fn get_repo(
        target_url: &url::Url,
        space_uri: &str,
        repo: &str,
    ) -> Result<url::Url, AppError> {
        with_params(
            target_url,
            &space::get_repo::GetRepo::<SmolStr> {
                repo: did(repo)?,
                space: space_ref(space_uri)?,
            },
        )
    }

    pub fn get_latest_commit(
        target_url: &url::Url,
        space_uri: &str,
        repo: &str,
    ) -> Result<url::Url, AppError> {
        with_params(
            target_url,
            &space::get_latest_commit::GetLatestCommit::<SmolStr> {
                repo: did(repo)?,
                space: space_ref(space_uri)?,
            },
        )
    }

    pub fn list_writers(
        target_url: &url::Url,
        space_uri: &str,
        cursor: Option<&str>,
    ) -> Result<url::Url, AppError> {
        let mut url = target_url.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("space", space_uri);
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
        }
        Ok(url)
    }

    pub fn get_space(target_url: &url::Url, space_uri: &str) -> Result<url::Url, AppError> {
        with_params(
            target_url,
            &space::get_space::GetSpace::<SmolStr> {
                space: space_ref(space_uri)?,
            },
        )
    }

    pub fn list_members(
        target_url: &url::Url,
        space_uri: &str,
        cursor: Option<&str>,
    ) -> Result<url::Url, AppError> {
        with_params(
            target_url,
            &memberspace::list_members::ListMembers::<SmolStr> {
                cursor: cursor.map(SmolStr::new),
                limit: None,
                space: space_ref(space_uri)?,
            },
        )
    }
}

pub fn construct_xrpc_url(service_endpoint: &str, method: &str) -> Result<url::Url, AppError> {
    let parsed = url::Url::parse(service_endpoint)
        .map_err(|e| AppError::InvalidRequest(format!("Invalid service endpoint URL: {e}")))?;

    if parsed.scheme() != "https" {
        return Err(AppError::InvalidRequest(
            "Service endpoint must use HTTPS".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::InvalidRequest(
            "Service endpoint must not contain userinfo".into(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(AppError::InvalidRequest(
            "Service endpoint must not contain query or fragment".into(),
        ));
    }

    let path = parsed.path().trim_end_matches('/');
    let xrpc_path = if path.is_empty() {
        format!("/xrpc/{method}")
    } else {
        format!("{path}/xrpc/{method}")
    };

    let mut xrpc_url = parsed;
    xrpc_url.set_path(&xrpc_path);
    Ok(xrpc_url)
}

pub const UNBOUND_CREDENTIAL_MESSAGE: &str =
    "Space host issues credentials without an HTTP message signature key binding (cnf.kid); Circles require a space host on the atproto Spaces 2026-10-22 alpha";

/// Lifetime the reference authority gives a space credential, and the mock's.
pub const DEFAULT_CREDENTIAL_LIFETIME_SECS: i64 = 600;
/// Longest space credential lifetime (exp - iat) that issuers and verifiers accept.
pub const MAX_CREDENTIAL_LIFETIME_SECS: i64 = 3600;

/// Validate a space credential this client just received for `expected_key_id`
/// (the `did:key` of the key that signed the exchange). Returns its expiry.
pub fn validate_space_credential(
    credential_jwt: &str,
    expected_iss: &str,
    expected_sub: &str,
    expected_key_id: &str,
    authority_doc: &DidDocument,
) -> Result<DateTime<Utc>, AppError> {
    let parts: Vec<&str> = credential_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized(AuthReason::InvalidJwtFormat));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderEncoding))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderJson))?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsEncoding))?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsJson))?;

    // Host compatibility gate, checked before anything else so the declared
    // error surfaces whatever else differs: space credentials must be bound to
    // the exchange's HTTP signature key (cnf.kid, atproto 2026-10-22 alpha).
    // Bearer credentials (Swan 2026-08-15 / 2026-09-10) and DPoP-bound ones
    // (cnf.jkt: the reference before 2026-10-01, Swan 2026-09-19) are refused.
    let cnf_kid = claims
        .get("cnf")
        .and_then(|cnf| cnf.get("kid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::UnsupportedPds(UNBOUND_CREDENTIAL_MESSAGE.into()))?;

    match &header.typ {
        Some(t) if t == "atproto-space-credential+jwt" => {}
        _ => return Err(AppError::Unauthorized(AuthReason::InvalidTyp)),
    }

    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Unauthorized(AuthReason::InvalidClaimsJson))?;
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Unauthorized(AuthReason::InvalidClaimsJson))?;
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or(AppError::Unauthorized(AuthReason::MissingExp))?;
    let iat = claims
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or(AppError::Unauthorized(AuthReason::MissingIat))?;
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Unauthorized(AuthReason::MissingJti))?;

    if jti.is_empty() {
        return Err(AppError::Unauthorized(AuthReason::MissingJti));
    }

    if iss != expected_iss {
        return Err(AppError::Unauthorized(AuthReason::IdMismatch));
    }
    if sub != expected_sub {
        return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
    }

    if cnf_kid != expected_key_id {
        return Err(AppError::Unauthorized(AuthReason::IdMismatch));
    }

    let now = Utc::now().timestamp();
    if iat > now + 300 {
        return Err(AppError::Unauthorized(AuthReason::FutureIat));
    }
    if exp <= now {
        return Err(AppError::Unauthorized(AuthReason::Expired));
    }
    if exp <= iat || exp - iat > MAX_CREDENTIAL_LIFETIME_SECS {
        return Err(AppError::Unauthorized(AuthReason::LifetimeExceeded));
    }

    let vm =
        select_authority_verification_method(authority_doc, expected_iss, header.kid.as_deref())
            .map_err(AppError::Unauthorized)?;
    let key = parse_verification_key(vm).map_err(AppError::Unauthorized)?;
    if !matches!(
        (&key, header.alg.as_str()),
        (crate::auth::ParsedVerifyingKey::P256(_), "ES256")
            | (crate::auth::ParsedVerifyingKey::Secp256k1(_), "ES256K")
            | (crate::auth::ParsedVerifyingKey::Ed25519(_), "EdDSA")
    ) {
        return Err(AppError::Unauthorized(AuthReason::AlgKeyMismatch));
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidSignatureFormat))?;

    key.verify(signing_input.as_bytes(), &sig_bytes)
        .map_err(AppError::Unauthorized)?;

    let expires_at = DateTime::from_timestamp(exp, 0)
        .ok_or(AppError::Unauthorized(AuthReason::InvalidClaimsJson))?;

    Ok(expires_at)
}

#[derive(Deserialize)]
struct XrpcErrorPayload {
    error: Option<String>,
    #[allow(dead_code)]
    message: Option<String>,
}

/// The [`AuthReason`] for an XRPC error code that rejects the space credential
/// itself. Retrying with that credential cannot succeed: the caller evicts it and
/// reacquires one only through a still-authorized session.
pub fn credential_rejection_reason(code: &str) -> Option<AuthReason> {
    match code {
        "CredentialRevoked" => Some(AuthReason::CredentialRevoked),
        "BadSpaceSignature" => Some(AuthReason::BadSpaceSignature),
        "BadSpaceAudience" => Some(AuthReason::BadSpaceAudience),
        "InvalidSpaceMac" => Some(AuthReason::InvalidSpaceMac),
        _ => None,
    }
}

/// Map every declared XRPC error, while retaining the credential-specific
/// reasons callers use to evict a rejected credential.
async fn credential_use_error(response: reqwest::Response, _op: &str) -> AppError {
    let status = response.status();
    let body = crate::auth::read_bounded_authenticated_response_bytes(
        response,
        MAX_SPACE_CREDENTIAL_BYTES,
    )
    .await
    .unwrap_or_default();
    parse_xrpc_error(status, &String::from_utf8_lossy(&body))
}


pub fn parse_xrpc_error(status: reqwest::StatusCode, body: &str) -> AppError {
    if status.is_server_error() {
        return AppError::Internal(format!("Upstream server error ({status})"));
    }

    let payload: XrpcErrorPayload = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(_) => {
            return AppError::Internal(format!("Failed to parse XRPC error payload ({status})"));
        }
    };

    let error_code = match payload.error.as_deref() {
        Some(code) => code,
        None => {
            return AppError::Internal(format!(
                "XRPC error response missing error field ({status})"
            ));
        }
    };

    match error_code {
        "AppNotAuthorized" => AppError::Forbidden("AppNotAuthorized".into()),
        "AccountNotAuthorized" => AppError::Forbidden("AccountNotAuthorized".into()),
        "NotAuthorized" => AppError::Forbidden("NotAuthorized".into()),
        "InvalidDelegationToken" => AppError::InvalidRequest("InvalidDelegationToken".into()),
        "InvalidClientAttestation" => AppError::Forbidden("InvalidClientAttestation".into()),
        "SpaceNotFound" => AppError::NotFound("SpaceNotFound".into()),
        "SpaceDeleted" => AppError::AccessRemoved("SpaceDeleted".into()),
        "RepoTakendown" => AppError::Forbidden("RepoTakendown".into()),
        "RepoDeactivated" => AppError::Forbidden("RepoDeactivated".into()),
        "RepoSuspended" => AppError::Forbidden("RepoSuspended".into()),
        "RepoNotFound" => AppError::NotFound("RepoNotFound".into()),
        "InvalidCursor" => AppError::InvalidRequest("InvalidCursor".into()),
        "UpstreamFailure" => AppError::Internal("UpstreamFailure".into()),
        "RegistrationNotConfirmed" => AppError::Internal(
            "RegistrationNotConfirmed: check APPVIEW_BASE_URL public reachability".into(),
        ),
        "AuthRequired" => AppError::Unauthorized(AuthReason::MissingHeader),
        "CredentialRevoked" => AppError::Unauthorized(AuthReason::CredentialRevoked),
        "BadSpaceSignature" => AppError::Unauthorized(AuthReason::BadSpaceSignature),
        "BadSpaceAudience" => AppError::Unauthorized(AuthReason::BadSpaceAudience),
        "InvalidSpaceMac" => AppError::Unauthorized(AuthReason::InvalidSpaceMac),
        _ => match status {
            reqwest::StatusCode::NOT_FOUND => AppError::NotFound("NotFound".into()),
            reqwest::StatusCode::FORBIDDEN => AppError::Forbidden("Forbidden".into()),
            reqwest::StatusCode::UNAUTHORIZED => AppError::Unauthorized(AuthReason::MissingHeader),
            reqwest::StatusCode::BAD_REQUEST => AppError::InvalidRequest("InvalidRequest".into()),
            _ => AppError::Internal(format!("Upstream error ({status})")),
        },
    }
}

/// A space credential as the authority mints it: bound to `key_id` (`cnf.kid`),
/// issued now, no JWT `aud`.
pub fn mint_mock_space_credential(
    authority_key: &p256::ecdsa::SigningKey,
    authority_did: &str,
    space_uri: &str,
    key_id: &str,
    expires_at: DateTime<Utc>,
) -> String {
    let header = json!({
        "typ": "atproto-space-credential+jwt",
        "alg": "ES256",
        "kid": "#atproto"
    });
    let claims = json!({
        "iss": authority_did,
        "sub": space_uri,
        "cnf": {
            "kid": key_id
        },
        "exp": expires_at.timestamp(),
        "iat": Utc::now().timestamp(),
        "jti": Uuid::new_v4().to_string()
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig: p256::ecdsa::Signature = authority_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn test_parse_xrpc_error_5xx_with_semantic_code_is_internal() {
        let err = parse_xrpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"SpaceNotFound","message":"database failed"}"#,
        );
        match err {
            AppError::Internal(msg) => {
                assert!(
                    msg.contains("Upstream server error (500"),
                    "500 with SpaceNotFound must be internal error, got: {msg}"
                );
            }
            other => panic!(
                "Expected AppError::Internal for 500 error, got: {:?}",
                other
            ),
        }

        let err2 = parse_xrpc_error(
            StatusCode::BAD_GATEWAY,
            r#"{"error":"AppNotAuthorized","message":"gateway bad"}"#,
        );
        match err2 {
            AppError::Internal(msg) => {
                assert!(
                    msg.contains("Upstream server error (502"),
                    "502 with AppNotAuthorized must be internal error, got: {msg}"
                );
            }
            other => panic!(
                "Expected AppError::Internal for 502 error, got: {:?}",
                other
            ),
        }

        let err3 = parse_xrpc_error(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"SpaceDeleted","message":"server overloaded"}"#,
        );
        match err3 {
            AppError::Internal(msg) => {
                assert!(
                    msg.contains("Upstream server error (503"),
                    "503 with SpaceDeleted must be internal error, got: {msg}"
                );
            }
            other => panic!(
                "Expected AppError::Internal for 503 error, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_parse_xrpc_error_unread_or_invalid_body_is_internal() {
        // Truncated/HTML 404 should NOT become NotFound
        let err = parse_xrpc_error(
            StatusCode::NOT_FOUND,
            "<html>404 Not Found from proxy</html>",
        );
        match err {
            AppError::Internal(msg) => {
                assert!(
                    msg.contains("Failed to parse XRPC error payload"),
                    "Unparsed 404 must be internal error, got: {msg}"
                );
            }
            other => panic!(
                "Expected AppError::Internal for unparsed 404, got: {:?}",
                other
            ),
        }

        // Truncated/HTML 403 should NOT become Forbidden
        let err2 = parse_xrpc_error(
            StatusCode::FORBIDDEN,
            "<html>403 Forbidden Cloudflare</html>",
        );
        match err2 {
            AppError::Internal(msg) => {
                assert!(
                    msg.contains("Failed to parse XRPC error payload"),
                    "Unparsed 403 must be internal error, got: {msg}"
                );
            }
            other => panic!(
                "Expected AppError::Internal for unparsed 403, got: {:?}",
                other
            ),
        }

        // Broken JSON body
        let err3 = parse_xrpc_error(StatusCode::BAD_REQUEST, "{\"error\": \"InvalidReq");
        match err3 {
            AppError::Internal(msg) => {
                assert!(
                    msg.contains("Failed to parse XRPC error payload"),
                    "Malformed JSON must be internal error, got: {msg}"
                );
            }
            other => panic!(
                "Expected AppError::Internal for malformed JSON, got: {:?}",
                other
            ),
        }

        // JSON without "error" field
        let err4 = parse_xrpc_error(
            StatusCode::BAD_REQUEST,
            r#"{"message":"something went wrong"}"#,
        );
        match err4 {
            AppError::Internal(msg) => {
                assert!(
                    msg.contains("missing error field"),
                    "JSON without error field must be internal error, got: {msg}"
                );
            }
            other => panic!(
                "Expected AppError::Internal for missing error field, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_parse_xrpc_error_valid_semantic_codes() {
        let err = parse_xrpc_error(
            StatusCode::NOT_FOUND,
            r#"{"error":"SpaceNotFound","message":"Space not found on PDS"}"#,
        );
        match err {
            AppError::NotFound(msg) => {
                assert!(
                    msg.contains("SpaceNotFound"),
                    "Expected SpaceNotFound, got: {msg}"
                );
            }
            other => panic!("Expected AppError::NotFound, got: {:?}", other),
        }

        let err2 = parse_xrpc_error(
            StatusCode::FORBIDDEN,
            r#"{"error":"AppNotAuthorized","message":"Client not allowed"}"#,
        );
        match err2 {
            AppError::Forbidden(msg) => {
                assert!(
                    msg.contains("AppNotAuthorized"),
                    "Expected AppNotAuthorized, got: {msg}"
                );
            }
            other => panic!("Expected AppError::Forbidden, got: {:?}", other),
        }

        let err3 = parse_xrpc_error(
            StatusCode::FORBIDDEN,
            r#"{"error":"AccountNotAuthorized","message":"User not member"}"#,
        );
        match err3 {
            AppError::Forbidden(msg) => {
                assert!(
                    msg.contains("AccountNotAuthorized"),
                    "Expected AccountNotAuthorized, got: {msg}"
                );
            }
            other => panic!("Expected AppError::Forbidden, got: {:?}", other),
        }

        let err4 = parse_xrpc_error(
            StatusCode::FORBIDDEN,
            r#"{"error":"SpaceDeleted","message":"Space has been deleted"}"#,
        );
        match err4 {
            AppError::AccessRemoved(msg) => {
                assert!(
                    msg.contains("SpaceDeleted"),
                    "Expected SpaceDeleted, got: {msg}"
                );
            }
            other => panic!("Expected AppError::AccessRemoved, got: {:?}", other),
        }
    }

    struct FailingDnsResolver;
    impl SpaceHostDnsResolver for FailingDnsResolver {
        fn resolve_dns<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, AuthReason>> + Send + 'a>>
        {
            Box::pin(async move { Err(AuthReason::DidResolutionFailed) })
        }
    }

    #[tokio::test]
    async fn test_dns_transport_failure_is_internal_not_unauthorized() {
        let transport = DefaultSpaceHostTransport::with_dns_resolver(Arc::new(FailingDnsResolver));
        let url = url::Url::parse("https://space.example.com/xrpc/endpoint").unwrap();
        let err = transport
            .build_pinned_client(&url)
            .await
            .expect_err("DNS failure must fail");

        match err {
            AppError::Internal(msg) => {
                assert!(
                    msg.contains("DNS resolution failed"),
                    "DNS failure must be internal error, got: {msg}"
                );
            }
            other => panic!(
                "Expected AppError::Internal for DNS failure, got: {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn test_ssrf_rejection_remains_unauthorized() {
        let transport = DefaultSpaceHostTransport::new();
        let url = url::Url::parse("https://127.0.0.1/xrpc/endpoint").unwrap();
        let err = transport
            .build_pinned_client(&url)
            .await
            .expect_err("SSRF must fail");

        match err {
            AppError::Unauthorized(AuthReason::SsrfBlocked) => {}
            other => panic!(
                "Expected AppError::Unauthorized(SsrfBlocked), got: {:?}",
                other
            ),
        }
    }

    const SPACE: &str = "at://did:plc:authority123/space/blue.catbird.circle/3kabcdefghi22";
    const REPO: &str = "did:plc:author456";
    const CID: &str = "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy";
    const REV: &str = "3kabcdefghi22";

    fn query_keys(url: &url::Url) -> std::collections::BTreeSet<String> {
        url.query_pairs().map(|(k, _)| k.into_owned()).collect()
    }

    fn keys(expected: &[&str]) -> std::collections::BTreeSet<String> {
        expected.iter().map(|k| k.to_string()).collect()
    }

    /// Every space-host, getSpace and memberspace read must carry exactly the lexicon's
    /// parameter names. getBlob once sent `did` where the lexicon requires `repo`.
    #[test]
    fn xrpc_query_keys_match_the_lexicon_params() {
        let base = url::Url::parse("https://host.example/xrpc/m").unwrap();

        let blob = xrpc_query::get_blob(&base, SPACE, REPO, CID).unwrap();
        assert_eq!(query_keys(&blob), keys(&["space", "repo", "cid"]));
        assert!(blob.query_pairs().any(|(k, v)| k == "repo" && v == REPO));
        assert!(!blob.query_pairs().any(|(k, _)| k == "did"));

        let ops = xrpc_query::list_repo_ops(&base, SPACE, REPO, None, None).unwrap();
        assert_eq!(query_keys(&ops), keys(&["space", "repo"]));
        let ops = xrpc_query::list_repo_ops(&base, SPACE, REPO, Some(REV), Some("c1")).unwrap();
        assert_eq!(
            query_keys(&ops),
            keys(&["space", "repo", "since", "cursor"])
        );

        let repo = xrpc_query::get_repo(&base, SPACE, REPO).unwrap();
        assert_eq!(query_keys(&repo), keys(&["space", "repo"]));

        let latest = xrpc_query::get_latest_commit(&base, SPACE, REPO).unwrap();
        assert_eq!(query_keys(&latest), keys(&["space", "repo"]));

        let writers = xrpc_query::list_writers(&base, SPACE, None).unwrap();
        assert_eq!(query_keys(&writers), keys(&["space"]));
        let writers = xrpc_query::list_writers(&base, SPACE, Some("c1")).unwrap();
        assert_eq!(query_keys(&writers), keys(&["space", "cursor"]));

        let space = xrpc_query::get_space(&base, SPACE).unwrap();
        assert_eq!(query_keys(&space), keys(&["space"]));

        let members = xrpc_query::list_members(&base, SPACE, None).unwrap();
        assert_eq!(query_keys(&members), keys(&["space"]));
        let members = xrpc_query::list_members(&base, SPACE, Some("c1")).unwrap();
        assert_eq!(query_keys(&members), keys(&["space", "cursor"]));
    }

    #[test]
    fn xrpc_query_rejects_malformed_repo_and_space() {
        let base = url::Url::parse("https://host.example/xrpc/m").unwrap();
        assert!(matches!(
            xrpc_query::get_blob(&base, SPACE, "not-a-did", CID),
            Err(AppError::InvalidRequest(_))
        ));
        assert!(matches!(
            xrpc_query::get_blob(&base, "https://not-a-space", REPO, CID),
            Err(AppError::InvalidRequest(_))
        ));
    }

    /// The real transport must put `repo` on the wire for getBlob. A capturing
    /// HTTP server records the exact query the Space host receives.
    #[tokio::test]
    async fn default_transport_get_blob_sends_repo_on_the_wire() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.space.getBlob"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "image/png")
                    .set_body_bytes(b"png-bytes".to_vec()),
            )
            .mount(&server)
            .await;

        let transport = DefaultSpaceHostTransport::with_loopback(true);
        let target =
            url::Url::parse(&format!("{}/xrpc/com.atproto.space.getBlob", server.uri())).unwrap();
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let auth = credential_headers(&key, "cred", REPO);
        let (content_type, bytes) = transport
            .get_blob(&target, &auth, SPACE, REPO, CID)
            .await
            .expect("getBlob succeeds against the capturing host");
        assert_eq!(content_type.as_deref(), Some("image/png"));
        assert_eq!(bytes, b"png-bytes");

        let received = server.received_requests().await.expect("recording on");
        assert_eq!(received.len(), 1);
        let pairs: std::collections::BTreeMap<String, String> = received[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            keys(&["space", "repo", "cid"])
        );
        assert_eq!(pairs["repo"], REPO);
        assert_eq!(pairs["space"], SPACE);
        assert_eq!(pairs["cid"], CID);

        // The credential travels as `Atproto-Space`, signed for the repo owner.
        let headers = &received[0].headers;
        let header = |name: &str| -> Vec<String> {
            headers
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(
            header("authorization"),
            vec!["Atproto-Space-Credential cred"]
        );
        assert_eq!(header("atproto-space-audience"), vec![REPO]);
        assert_eq!(
            header("signature-input"),
            vec![
                r#"sig=("authorization" "atproto-space-audience");tag="atproto-space-credential""#
            ]
        );
        assert_eq!(header("signature"), vec![auth.signature.clone()]);
        assert!(header("dpop").is_empty(), "no Spaces DPoP proof");
    }

    /// authorizeSpaceSync sends its credential-binding data only in the JSON
    /// body; the exchange itself has no credential-use signature.
    #[tokio::test]
    async fn default_transport_exchange_sends_body_without_auth_headers() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.space.authorizeSpaceSync"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"credential": "c"})),
            )
            .mount(&server)
            .await;

        let transport = DefaultSpaceHostTransport::with_loopback(true);
        let target = url::Url::parse(&format!(
            "{}/xrpc/com.atproto.space.authorizeSpaceSync",
            server.uri()
        ))
        .unwrap();
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let request = AuthorizeSpaceSyncRequest {
            space: SPACE.into(),
            credential_key: p256_did_key(key.verifying_key()),
            delegation_token: Some("delegation".into()),
            client_attestation: Some("attestation".into()),
            notify: None,
        };
        let output = transport
            .authorize_space_sync(&target, &request)
            .await
            .unwrap();
        assert_eq!(output.credential, "c");

        let received = server.received_requests().await.expect("recording on");
        let headers = &received[0].headers;
        let key_id = p256_did_key(key.verifying_key());
        for name in [
            "authorization",
            "signature-input",
            "signature",
            "dpop",
            "atproto-space-audience",
        ] {
            assert!(headers.get(name).is_none(), "unexpected {name}");
        }
        let body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert_eq!(body["space"], SPACE);
        assert_eq!(body["credentialKey"], key_id);
        assert_eq!(body["delegationToken"], "delegation");
        assert_eq!(body["clientAttestation"], "attestation");
    }

    /// CredentialRevoked, BadSpaceSignature and BadSpaceAudience from a repo or
    /// space host surface as credential rejections; other failures do not.
    #[tokio::test]
    async fn credential_use_rejections_are_distinguished() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let cases = [
            (
                401,
                "CredentialRevoked",
                Some(AuthReason::CredentialRevoked),
            ),
            (
                401,
                "BadSpaceSignature",
                Some(AuthReason::BadSpaceSignature),
            ),
            (401, "BadSpaceAudience", Some(AuthReason::BadSpaceAudience)),
            (401, "BadJwt", None),
            (400, "InvalidRequest", None),
        ];
        for (status, code, expected) in cases {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/xrpc/com.atproto.space.getRepo"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_json(serde_json::json!({"error": code, "message": "m"})),
                )
                .mount(&server)
                .await;
            let transport = DefaultSpaceHostTransport::with_loopback(true);
            let target =
                url::Url::parse(&format!("{}/xrpc/com.atproto.space.getRepo", server.uri()))
                    .unwrap();
            let key = p256::ecdsa::SigningKey::random(&mut OsRng);
            let err = transport
                .get_repo(
                    &target,
                    &credential_headers(&key, "cred", REPO),
                    SPACE,
                    REPO,
                    None,
                )
                .await
                .expect_err("host rejected the request");
            match expected {
                Some(reason) => assert!(
                    matches!(&err, AppError::Unauthorized(r) if *r == reason),
                    "{code}: expected {reason:?}, got {err:?}"
                ),
                None if status == 401 => assert!(
                    matches!(&err, AppError::Unauthorized(AuthReason::MissingHeader)),
                    "{code}: expected the declared 401 mapping, got {err:?}"
                ),
                None => assert!(
                    matches!(&err, AppError::InvalidRequest(_)),
                    "{code}: expected the declared 400 mapping, got {err:?}"
                ),
            }
        }

        assert!(matches!(
            parse_xrpc_error(
                StatusCode::UNAUTHORIZED,
                r#"{"error":"CredentialRevoked","message":"revoked"}"#
            ),
            AppError::Unauthorized(AuthReason::CredentialRevoked)
        ));
    }

    fn authority_doc(key: &p256::ecdsa::SigningKey) -> DidDocument {
        let point = key.verifying_key().to_encoded_point(false);
        DidDocument {
            id: AUTHORITY.into(),
            verification_method: vec![crate::auth::VerificationMethod {
                id: format!("{AUTHORITY}#atproto"),
                r#type: "JsonWebKey2020".into(),
                controller: AUTHORITY.into(),
                public_key_jwk: Some(crate::auth::PublicKeyJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    y: Some(URL_SAFE_NO_PAD.encode(point.y().unwrap())),
                    kid: None,
                }),
                public_key_multibase: None,
            }],
            service: vec![],
        }
    }

    fn credential_with_claims(key: &p256::ecdsa::SigningKey, claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            json!({"typ": "atproto-space-credential+jwt", "alg": "ES256", "kid": "#atproto"})
                .to_string(),
        );
        let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        let sig: p256::ecdsa::Signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    const AUTHORITY: &str = "did:plc:authority123";

    /// Repo reads are signed for the repo owner's DID; space-host operations for
    /// the authority's bare DID (never a hostname or `#atproto_space_host`).
    #[tokio::test]
    async fn audience_is_derived_from_the_operation() {
        let mock = Arc::new(MockSpaceHostTransport::new());
        let client = SpaceClient::with_transport(mock.clone());
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let ep = "https://host.example";
        let _ = client.list_writers(ep, SPACE, None, "cred", &key).await;
        let _ = client.get_repo(ep, SPACE, REPO, None, "cred", &key).await;
        let _ = client
            .list_repo_ops(ep, SPACE, REPO, None, None, "cred", &key)
            .await;
        let _ = client
            .get_latest_commit(ep, SPACE, REPO, "cred", &key)
            .await;
        let _ = client.get_blob(ep, SPACE, REPO, CID, "cred", &key).await;

        let audiences: Vec<(&str, Option<String>)> = mock
            .recorded_credential_uses()
            .into_iter()
            .map(|u| {
                assert_eq!(u.auth.authorization, "Atproto-Space-Credential cred");
                assert_eq!(
                    u.auth.signature_input,
                    r#"sig=("authorization" "atproto-space-audience");tag="atproto-space-credential""#
                );
                (u.method, u.auth.audience)
            })
            .collect();
        let authority = Some(AUTHORITY.to_string());
        let repo = Some(REPO.to_string());
        assert_eq!(
            audiences,
            vec![
                ("com.atproto.space.listWriters", authority),
                ("com.atproto.space.getRepo", repo.clone()),
                ("com.atproto.space.listRepoOps", repo.clone()),
                ("com.atproto.space.getLatestCommit", repo.clone()),
                ("com.atproto.space.getBlob", repo),
            ]
        );
    }

    /// The exchange signs with a fresh key per credential, and the credential
    /// returned is bound to exactly that key.
    #[tokio::test]
    async fn exchange_binds_each_credential_to_a_fresh_key() {
        let authority_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let doc = authority_doc(&authority_key);
        let mock = Arc::new(MockSpaceHostTransport::new());
        mock.set_authority_signing_key(AUTHORITY, authority_key);
        let client = SpaceClient::with_transport(mock.clone());

        let first = client
            .authorize_space_sync(
                "https://host.example",
                SPACE,
                "d1",
                "a1",
                None,
                AUTHORITY,
                &doc,
            )
            .await
            .expect("first exchange");
        let second = client
            .authorize_space_sync(
                "https://host.example",
                SPACE,
                "d2",
                "a2",
                None,
                AUTHORITY,
                &doc,
            )
            .await
            .expect("second exchange");
        let key_1 = first.signing_key;
        let exp_1 = first.expires_at;
        let key_2 = second.signing_key;
        assert_ne!(key_1.verifying_key(), key_2.verifying_key());
        let lifetime = exp_1.timestamp() - Utc::now().timestamp();
        assert!(
            (DEFAULT_CREDENTIAL_LIFETIME_SECS - 5..=DEFAULT_CREDENTIAL_LIFETIME_SECS)
                .contains(&lifetime),
            "expiry is the credential's own exp, got {lifetime}s"
        );

        let calls = mock.recorded_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].request.delegation_token.as_deref(), Some("d1"));
        assert_eq!(
            Some(calls[0].request.credential_key.as_str()),
            Some(p256_did_key(key_1.verifying_key()).as_str())
        );
    }

    /// The binding gate: cnf.kid must name the exchange key. A cnf.jkt (DPoP)
    /// credential from a host on an older alpha is the declared UnsupportedPDS.
    #[test]
    fn credential_must_be_bound_to_our_key_id() {
        let authority_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let doc = authority_doc(&authority_key);
        let ours = p256_did_key(p256::ecdsa::SigningKey::random(&mut OsRng).verifying_key());
        let theirs = p256_did_key(p256::ecdsa::SigningKey::random(&mut OsRng).verifying_key());
        let expires = Utc::now() + chrono::Duration::seconds(DEFAULT_CREDENTIAL_LIFETIME_SECS);

        let bound = mint_mock_space_credential(&authority_key, AUTHORITY, SPACE, &ours, expires);
        let exp = validate_space_credential(&bound, AUTHORITY, SPACE, &ours, &doc).unwrap();
        assert_eq!(
            exp.timestamp(),
            expires.timestamp(),
            "refresh follows the actual exp"
        );

        let other = mint_mock_space_credential(&authority_key, AUTHORITY, SPACE, &theirs, expires);
        assert!(matches!(
            validate_space_credential(&other, AUTHORITY, SPACE, &ours, &doc),
            Err(AppError::Unauthorized(AuthReason::IdMismatch))
        ));

        let now = Utc::now().timestamp();
        let jkt_bound = credential_with_claims(
            &authority_key,
            json!({"iss": AUTHORITY, "sub": SPACE, "iat": now, "exp": now + 600,
                   "jti": "j1", "cnf": {"jkt": "thumbprint"}}),
        );
        assert!(matches!(
            validate_space_credential(&jkt_bound, AUTHORITY, SPACE, &ours, &doc),
            Err(AppError::UnsupportedPds(_))
        ));
    }

    #[test]
    fn credential_lifetime_is_bounded_at_3600_seconds() {
        let authority_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let doc = authority_doc(&authority_key);
        let ours = p256_did_key(p256::ecdsa::SigningKey::random(&mut OsRng).verifying_key());
        let now = Utc::now().timestamp();
        let claims = |iat: i64, exp: i64| {
            json!({"iss": AUTHORITY, "sub": SPACE, "iat": iat, "exp": exp,
                   "jti": "j1", "cnf": {"kid": ours}})
        };

        let at_limit = credential_with_claims(&authority_key, claims(now, now + 3600));
        assert!(validate_space_credential(&at_limit, AUTHORITY, SPACE, &ours, &doc).is_ok());

        let over = credential_with_claims(&authority_key, claims(now, now + 3601));
        assert!(matches!(
            validate_space_credential(&over, AUTHORITY, SPACE, &ours, &doc),
            Err(AppError::Unauthorized(AuthReason::LifetimeExceeded))
        ));
    }
    #[tokio::test]
    async fn repository_reads_verify_wire_mac_before_returning_payload() {
        use crate::space_mac::{
            MacProfile, MacRequest, ACCEPT_SIGNATURE_HEADER, COMMIT_MAC_PROFILE,
        };
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let commit = crate::test_support::fixture_commit(SPACE, REPO, "3jzfcijpj2m2a", &[0; 2048]);
        let star = crate::test_support::fixture_star(&commit, &[]).unwrap();
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        for endpoint in ["getLatestCommit", "getRepo", "listRepoOps"] {
            for mode in ["good", "missing", "wrong", "duplicate", "keyid", "type", "version"] {
                let server = MockServer::start().await;
                let mut auth = credential_headers(&key, "cred", REPO);
                auth.mac = Some(MacRequest {
                    key_share: "did:key:fixture".into(),
                    shared_secret: [7; 32],
                    profile: MacProfile::Commit,
                });
                let mut covered = format!(
                    "ver=1, repo=\"{}\", space=\"{}\", rev=\"{}\", data=:{}:",
                    commit.repo,
                    commit.space,
                    commit.rev,
                    base64::engine::general_purpose::STANDARD.encode(&commit.data)
                );
                if mode == "version" {
                    covered = covered.replacen("ver=1", "ver=2", 1);
                }
                let tag = if mode == "type" {
                    "atproto-space-record"
                } else {
                    COMMIT_MAC_PROFILE
                };
                let keyid = if mode == "keyid" {
                    "did:key:zDnaOther"
                } else {
                    "did:key:fixture"
                };
                let params = format!(
                    "(\"{COMMIT_MAC_PROFILE}\";sf);keyid=\"{keyid}\";tag=\"{tag}\""
                );
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(if mode == "wrong" { &[8; 32] } else { &[7; 32] })
                        .unwrap();
                mac.update(
                    format!(
                        "\"{COMMIT_MAC_PROFILE}\";sf: {covered}\n\"@signature-params\": {params}"
                    )
                    .as_bytes(),
                );
                let signature =
                    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
                let mut signature_input = format!("mac={params}");
                let mut signature_header = format!("mac=:{signature}:");
                if mode == "duplicate" {
                    signature_input.push_str(&format!(", other={params}"));
                    signature_header.push_str(&format!(", other=:{signature}:"));
                }

                let mut template = ResponseTemplate::new(200);
                template = match endpoint {
                    "getRepo" => template
                        .set_body_bytes(star.clone())
                        .insert_header("content-type", "application/vnd.dasl.star"),
                    "listRepoOps" => template.set_body_json(json!({"commit":commit,"ops":[]})),
                    _ => template.set_body_json(json!({"commit":commit})),
                };
                if mode != "missing" {
                    template = template
                        .insert_header(COMMIT_MAC_PROFILE, covered)
                        .insert_header("signature-input", signature_input)
                        .insert_header("signature", signature_header);
                }
                let endpoint_path = format!("/xrpc/com.atproto.space.{endpoint}");
                Mock::given(method("GET"))
                    .and(path(endpoint_path.clone()))
                    .respond_with(template)
                    .mount(&server)
                    .await;
                let url = url::Url::parse(&format!("{}{endpoint_path}", server.uri())).unwrap();
                let transport = DefaultSpaceHostTransport::with_loopback(true);
                let result = match endpoint {
                    "getRepo" => transport
                        .get_repo(&url, &auth, SPACE, REPO, None)
                        .await
                        .map(|_| ()),
                    "listRepoOps" => transport
                        .list_repo_ops(&url, &auth, SPACE, REPO, None, None)
                        .await
                        .map(|_| ()),
                    _ => transport
                        .get_latest_commit(&url, &auth, SPACE, REPO)
                        .await
                        .map(|_| ()),
                };
                assert_eq!(
                    result.is_ok(),
                    mode == "good",
                    "{endpoint}/{mode}: {result:?}"
                );
                let requests = server.received_requests().await.unwrap();
                assert!(requests[0].headers.contains_key(ACCEPT_SIGNATURE_HEADER));
            }
        }
    }

    #[tokio::test]
    async fn every_page_and_bounded_bad_mac_retry_gets_a_fresh_key() {
        let mock = Arc::new(MockSpaceHostTransport::new());
        let client = SpaceClient::with_transport(mock.clone());
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        for cursor in [None, Some("next")] {
            let _ = client
                .list_repo_ops(
                    "https://host.example",
                    SPACE,
                    REPO,
                    None,
                    cursor,
                    "cred",
                    &key,
                )
                .await;
        }
        mock.reject_credential_uses(Some(AuthReason::InvalidSpaceMac));
        assert!(matches!(
            client
                .get_latest_commit("https://host.example", SPACE, REPO, "cred", &key)
                .await,
            Err(AppError::Unauthorized(AuthReason::InvalidSpaceMac))
        ));
        let calls = mock.recorded_credential_uses();
        assert_eq!(
            calls.len(),
            4,
            "two pages plus one bounded two-attempt retry"
        );
        let shares: std::collections::HashSet<_> = calls
            .iter()
            .map(|c| c.auth.mac.as_ref().unwrap().key_share.clone())
            .collect();
        assert_eq!(shares.len(), 4);
    }
}
