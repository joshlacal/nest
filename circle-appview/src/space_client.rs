use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpaceAppAccess {
    Open,
    AllowList(Vec<String>),
    Unknown(Option<String>),
}

impl SpaceAppAccess {
    pub fn parse(val: &serde_json::Value) -> Self {
        if let Some(arr) = val.as_array() {
            if arr.is_empty() {
                return SpaceAppAccess::Unknown(None);
            }
            let mut list = Vec::new();
            for item in arr {
                if let Some(s) = item.as_str() {
                    list.push(s.to_string());
                }
            }
            if list.is_empty() {
                return SpaceAppAccess::Unknown(None);
            }
            return SpaceAppAccess::AllowList(list);
        }
        if let Some(s) = val.as_str() {
            if s == "com.atproto.simplespace.defs#open" || s == "#open" || s == "open" {
                return SpaceAppAccess::Open;
            }
            return SpaceAppAccess::Unknown(Some(s.to_string()));
        }
        if let Some(obj) = val.as_object() {
            let type_str = obj.get("$type").and_then(|v| v.as_str());
            if let Some(t) = type_str {
                if t == "com.atproto.simplespace.defs#open" || t.ends_with("#open") || t == "open" {
                    return SpaceAppAccess::Open;
                }
                if t == "com.atproto.simplespace.defs#allowList"
                    || t.ends_with("#allowList")
                    || t == "allowList"
                {
                    let allowed = obj
                        .get("allowed")
                        .or_else(|| obj.get("allowList"))
                        .and_then(|v| v.as_array());
                    if let Some(arr) = allowed {
                        if arr.is_empty() {
                            return SpaceAppAccess::AllowList(Vec::new());
                        }
                        let mut list = Vec::new();
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                list.push(s.to_string());
                            }
                        }
                        if list.is_empty() {
                            return SpaceAppAccess::Unknown(Some(t.to_string()));
                        }
                        return SpaceAppAccess::AllowList(list);
                    } else {
                        return SpaceAppAccess::Unknown(Some(t.to_string()));
                    }
                }
                return SpaceAppAccess::Unknown(Some(t.to_string()));
            } else {
                let allowed = obj
                    .get("allowed")
                    .or_else(|| obj.get("allowList"))
                    .and_then(|v| v.as_array());
                if let Some(arr) = allowed {
                    if arr.is_empty() {
                        return SpaceAppAccess::Unknown(None);
                    }
                    let mut list = Vec::new();
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            list.push(s.to_string());
                        }
                    }
                    if list.is_empty() {
                        return SpaceAppAccess::Unknown(None);
                    }
                    return SpaceAppAccess::AllowList(list);
                }
                return SpaceAppAccess::Unknown(None);
            }
        }
        SpaceAppAccess::Unknown(None)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceConfig {
    pub authority: String,
    pub space_type: String,
    pub skey: String,
    pub app_access: SpaceAppAccess,
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

    fn get_space_credential<'a>(
        &'a self,
        target_url: &'a url::Url,
        delegation_token: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        client_attestation: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>>;

    fn register_notify<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        _service_identifier: &'a str,
        _space_uri: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<DateTime<Utc>, AppError>> + Send + 'a>> {
        Box::pin(async move {
            Err(AppError::NotFound(
                "register_notify not implemented on transport".into(),
            ))
        })
    }

    fn list_repos<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        _space_uri: &'a str,
        _cursor: Option<&'a str>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput,
                        AppError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Err(AppError::NotFound(
                "list_repos not implemented on transport".into(),
            ))
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn list_repo_ops<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
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
    ) -> Option<Pin<Box<dyn Future<Output = Result<Vec<String>, AppError>> + Send + 'a>>> {
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
        _space_credential: &'a str,
        _dpop_proof: &'a str,
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
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        _space_uri: &'a str,
        _repo_did: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        catbird_atproto::generated::com_atproto::space::SignedCommit,
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
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        _space_uri: &'a str,
        _did: &'a str,
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

    fn get_space_credential<'a>(
        &'a self,
        target_url: &'a url::Url,
        delegation_token: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        client_attestation: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>> {
        let target_url = target_url.clone();
        let delegation_token = delegation_token.to_string();
        let dpop_proof = dpop_proof.to_string();
        let space_uri = space_uri.to_string();
        let client_attestation = client_attestation.to_string();

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let req_body = serde_json::json!({
                "space": space_uri,
                "clientAttestation": client_attestation,
            });

            let response = client
                .post(target_url.as_str())
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {delegation_token}"),
                )
                .header("DPoP", dpop_proof)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&req_body)
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

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

            let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                response,
                MAX_SPACE_CREDENTIAL_BYTES,
            )
            .await?;
            let body: serde_json::Value = serde_json::from_slice(&body_bytes)
                .map_err(|e| AppError::Internal(format!("Invalid JSON from Space host: {e}")))?;
            let credential = body
                .get("credential")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AppError::Internal("Missing credential in Space host response".into())
                })?;

            Ok(credential.to_string())
        })
    }

    fn register_notify<'a>(
        &'a self,
        target_url: &'a url::Url,
        space_credential: &'a str,
        dpop_proof: &'a str,
        service_identifier: &'a str,
        space_uri: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<DateTime<Utc>, AppError>> + Send + 'a>> {
        let target_url = target_url.clone();
        let space_credential = space_credential.to_string();
        let dpop_proof = dpop_proof.to_string();
        let service_identifier = service_identifier.to_string();
        let space_uri = space_uri.to_string();

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let req_body = serde_json::json!({
                "service": service_identifier,
                "space": space_uri,
            });

            let response = client
                .post(target_url.as_str())
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("DPoP {space_credential}"),
                )
                .header("DPoP", dpop_proof)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&req_body)
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to call registerNotify: {e}")))?;

            if !response.status().is_success() {
                let status = response.status();
                return Err(AppError::Internal(format!(
                    "registerNotify returned status {status}"
                )));
            }

            #[derive(Deserialize)]
            struct RegisterNotifyOutput {
                #[serde(rename = "expiresAt")]
                expires_at: String,
            }

            let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                response,
                MAX_SPACE_CREDENTIAL_BYTES,
            )
            .await?;
            let body: RegisterNotifyOutput = serde_json::from_slice(&body_bytes)
                .map_err(|e| AppError::Internal(format!("Invalid registerNotify response: {e}")))?;

            let expires_at = DateTime::parse_from_rfc3339(&body.expires_at)
                .map_err(|e| AppError::Internal(format!("Invalid expiresAt timestamp: {e}")))?
                .with_timezone(&Utc);

            Ok(expires_at)
        })
    }

    fn list_repos<'a>(
        &'a self,
        target_url: &'a url::Url,
        space_credential: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        cursor: Option<&'a str>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput,
                        AppError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let target_url = target_url.clone();
        let space_credential = space_credential.to_string();
        let dpop_proof = dpop_proof.to_string();
        let space_uri = space_uri.to_string();
        let cursor = cursor.map(|c| c.to_string());

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let mut req_url = target_url.clone();
            {
                let mut query = req_url.query_pairs_mut();
                query.append_pair("space", &space_uri);
                if let Some(c) = &cursor {
                    query.append_pair("cursor", c);
                }
            }

            let response = client
                .get(req_url.as_str())
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("DPoP {space_credential}"),
                )
                .header("DPoP", dpop_proof)
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

            if !response.status().is_success() {
                let status = response.status();
                return Err(AppError::Internal(format!(
                    "Space host listRepos returned status {status}"
                )));
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
        space_credential: &'a str,
        dpop_proof: &'a str,
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
        let space_credential = space_credential.to_string();
        let dpop_proof = dpop_proof.to_string();
        let space_uri = space_uri.to_string();
        let repo_did = repo_did.to_string();
        let since = since.map(|s| s.to_string());
        let cursor = cursor.map(|c| c.to_string());

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let mut req_url = target_url.clone();
            {
                let mut query = req_url.query_pairs_mut();
                query.append_pair("space", &space_uri);
                query.append_pair("repo", &repo_did);
                if let Some(s) = &since {
                    query.append_pair("since", s);
                }
                if let Some(c) = &cursor {
                    query.append_pair("cursor", c);
                }
            }

            let response = client
                .get(req_url.as_str())
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("DPoP {space_credential}"),
                )
                .header("DPoP", dpop_proof)
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

            if !response.status().is_success() {
                let status = response.status();
                return Err(AppError::Internal(format!(
                    "Space host listRepoOps returned status {status}"
                )));
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

    fn get_repo<'a>(
        &'a self,
        target_url: &'a url::Url,
        space_credential: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        repo_did: &'a str,
        since: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AppError>> + Send + 'a>> {
        let target_url = target_url.clone();
        let space_credential = space_credential.to_string();
        let dpop_proof = dpop_proof.to_string();
        let space_uri = space_uri.to_string();
        let repo_did = repo_did.to_string();
        let since = since.map(|s| s.to_string());

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let mut req_url = target_url.clone();
            {
                let mut query = req_url.query_pairs_mut();
                query.append_pair("space", &space_uri);
                query.append_pair("repo", &repo_did);
                if let Some(s) = &since {
                    query.append_pair("since", s);
                }
            }

            let response = client
                .get(req_url.as_str())
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("DPoP {space_credential}"),
                )
                .header("DPoP", dpop_proof)
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

            if !response.status().is_success() {
                return Err(AppError::Internal(format!(
                    "Space host getRepo returned status {}",
                    response.status()
                )));
            }

            let max_car_bytes = crate::commit::MAX_CAR_BYTES;
            let bytes =
                crate::auth::read_bounded_authenticated_response_bytes(response, max_car_bytes)
                    .await?;
            Ok(bytes)
        })
    }

    fn get_latest_commit<'a>(
        &'a self,
        target_url: &'a url::Url,
        space_credential: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        repo_did: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        catbird_atproto::generated::com_atproto::space::SignedCommit,
                        AppError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let target_url = target_url.clone();
        let space_credential = space_credential.to_string();
        let dpop_proof = dpop_proof.to_string();
        let space_uri = space_uri.to_string();
        let repo_did = repo_did.to_string();

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let mut req_url = target_url.clone();
            {
                let mut query = req_url.query_pairs_mut();
                query.append_pair("space", &space_uri);
                query.append_pair("repo", &repo_did);
            }

            let response = client
                .get(req_url.as_str())
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("DPoP {space_credential}"),
                )
                .header("DPoP", dpop_proof)
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

            if !response.status().is_success() {
                let status = response.status();
                return Err(AppError::Internal(format!(
                    "Space host getLatestCommit returned status {status}"
                )));
            }
            let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
                response,
                MAX_SPACE_RESPONSE_BYTES,
            )
            .await?;
            let output: catbird_atproto::generated::com_atproto::space::get_latest_commit::GetLatestCommitOutput = serde_json::from_slice(&body_bytes).map_err(|e| AppError::Internal(e.to_string()))?;
            Ok(output.commit)
        })
    }

    fn get_blob<'a>(
        &'a self,
        target_url: &'a url::Url,
        space_credential: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        did: &'a str,
        cid: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(Option<String>, Vec<u8>), AppError>> + Send + 'a>>
    {
        let target_url = target_url.clone();
        let space_credential = space_credential.to_string();
        let dpop_proof = dpop_proof.to_string();
        let space_uri = space_uri.to_string();
        let did = did.to_string();
        let cid = cid.to_string();

        Box::pin(async move {
            let client = self.build_pinned_client(&target_url).await?;

            let mut req_url = target_url.clone();
            {
                let mut query = req_url.query_pairs_mut();
                query.append_pair("space", &space_uri);
                query.append_pair("did", &did);
                query.append_pair("cid", &cid);
            }

            let response = client
                .get(req_url.as_str())
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("DPoP {space_credential}"),
                )
                .header("DPoP", dpop_proof)
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to connect to Space host: {e}")))?;

            if !response.status().is_success() {
                return Err(AppError::Internal(format!(
                    "Space host getBlob returned status {}",
                    response.status()
                )));
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
    pub delegation_token: String,
    pub dpop_proof: String,
    pub space_uri: String,
    pub client_attestation: String,
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
    list_repos_responses: Mutex<
        HashMap<
            String,
            catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput,
        >,
    >,
    list_repo_ops_responses: Mutex<
        HashMap<
            String,
            catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput,
        >,
    >,
    get_repo_responses: Mutex<HashMap<String, Vec<u8>>>,
    latest_commits:
        Mutex<HashMap<String, catbird_atproto::generated::com_atproto::space::SignedCommit>>,
    calls: Mutex<Vec<RecordedSpaceHostCall>>,
    #[allow(clippy::type_complexity)]
    blob_responses: Mutex<HashMap<String, (Option<String>, Vec<u8>)>>,
    blob_calls: Mutex<Vec<String>>,
    register_notify_responses: Mutex<HashMap<String, DateTime<Utc>>>,
    space_members: Mutex<HashMap<String, Result<Vec<String>, String>>>,
    space_configs: Mutex<HashMap<String, Result<SpaceConfig, String>>>,
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
            list_repos_responses: Mutex::new(HashMap::new()),
            list_repo_ops_responses: Mutex::new(HashMap::new()),
            get_repo_responses: Mutex::new(HashMap::new()),
            latest_commits: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            blob_responses: Mutex::new(HashMap::new()),
            blob_calls: Mutex::new(Vec::new()),
            register_notify_responses: Mutex::new(HashMap::new()),
            space_members: Mutex::new(HashMap::new()),
            space_configs: Mutex::new(HashMap::new()),
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

    pub fn recorded_delegation_token_calls(&self) -> Vec<RecordedDelegationTokenCall> {
        let lock = self.delegation_token_calls.lock().unwrap();
        lock.clone()
    }

    pub fn set_list_repos_response(
        &self,
        space: &str,
        output: catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput,
    ) {
        let mut lock = self.list_repos_responses.lock().unwrap();
        lock.insert(space.to_string(), output);
    }

    pub fn set_list_repo_ops_response(
        &self,
        space_and_repo: &str,
        output: catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput,
    ) {
        let mut lock = self.list_repo_ops_responses.lock().unwrap();
        lock.insert(space_and_repo.to_string(), output);
    }

    pub fn set_get_repo_response(&self, space_and_repo: &str, output: Vec<u8>) {
        let mut lock = self.get_repo_responses.lock().unwrap();
        lock.insert(space_and_repo.to_string(), output);
    }

    pub fn set_latest_commit(
        &self,
        space_and_repo: &str,
        commit: catbird_atproto::generated::com_atproto::space::SignedCommit,
    ) {
        let mut lock = self.latest_commits.lock().unwrap();
        lock.insert(space_and_repo.to_string(), commit);
    }

    pub fn set_blob_response(&self, key: &str, content_type: Option<String>, data: Vec<u8>) {
        let mut lock = self.blob_responses.lock().unwrap();
        lock.insert(key.to_string(), (content_type, data));
    }

    pub fn set_register_notify_response(&self, space: &str, expires_at: DateTime<Utc>) {
        let mut lock = self.register_notify_responses.lock().unwrap();
        lock.insert(space.to_string(), expires_at);
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

    fn get_space_credential<'a>(
        &'a self,
        target_url: &'a url::Url,
        delegation_token: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        client_attestation: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>> {
        {
            let mut calls = self.calls.lock().unwrap();
            calls.push(RecordedSpaceHostCall {
                endpoint_url: target_url.to_string(),
                delegation_token: delegation_token.to_string(),
                dpop_proof: dpop_proof.to_string(),
                space_uri: space_uri.to_string(),
                client_attestation: client_attestation.to_string(),
            });
        }
        let authority_did = extract_authority_from_space_uri(space_uri).unwrap_or_default();
        let authority_key = {
            let keys = self.authority_keys.lock().unwrap();
            keys.get(&authority_did).cloned()
        };
        let res = {
            let lock = self.responses.lock().unwrap();
            lock.get(space_uri).cloned()
        };
        Box::pin(async move {
            match res {
                Some(Ok(cred)) => Ok(cred),
                Some(Err(e)) => Err(parse_xrpc_error(reqwest::StatusCode::BAD_REQUEST, &e)),
                None => {
                    if let Some(key) = authority_key {
                        let jkt = extract_jkt_from_dpop_proof(dpop_proof)
                            .unwrap_or_else(|_| "mock_jkt".into());
                        let cred = mint_mock_space_credential(
                            &key,
                            &authority_did,
                            space_uri,
                            &jkt,
                            Utc::now() + chrono::Duration::hours(2),
                        );
                        Ok(cred)
                    } else {
                        Err(AppError::NotFound(format!(
                            "No mock response for {space_uri}"
                        )))
                    }
                }
            }
        })
    }

    fn register_notify<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        _service_identifier: &'a str,
        space_uri: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<DateTime<Utc>, AppError>> + Send + 'a>> {
        let lock = self.register_notify_responses.lock().unwrap();
        let expires_at = lock
            .get(space_uri)
            .cloned()
            .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(24));
        Box::pin(async move { Ok(expires_at) })
    }

    fn list_repos<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        space_uri: &'a str,
        cursor: Option<&'a str>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput,
                        AppError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let lock = self.list_repos_responses.lock().unwrap();
        let res = match cursor {
            Some(c) => lock
                .get(&format!("{space_uri}:{c}"))
                .or_else(|| lock.get(space_uri))
                .cloned(),
            None => lock.get(space_uri).cloned(),
        };
        let lookup_key = match cursor {
            Some(c) => format!("{space_uri}:{c}"),
            None => space_uri.to_string(),
        };
        Box::pin(async move {
            res.ok_or_else(|| {
                AppError::NotFound(format!("No mock list_repos configured for {lookup_key}"))
            })
        })
    }

    fn list_repo_ops<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
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
        let base_key = format!("{space_uri}:{repo_did}");
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
            res.ok_or_else(|| {
                AppError::NotFound(format!("No mock list_repo_ops configured for {lookup_key}"))
            })
        })
    }

    fn get_repo<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        space_uri: &'a str,
        repo_did: &'a str,
        _since: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AppError>> + Send + 'a>> {
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
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        space_uri: &'a str,
        repo_did: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        catbird_atproto::generated::com_atproto::space::SignedCommit,
                        AppError,
                    >,
                > + Send
                + 'a,
        >,
    > {
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
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        space_uri: &'a str,
        did: &'a str,
        cid: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(Option<String>, Vec<u8>), AppError>> + Send + 'a>>
    {
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
    ) -> Option<Pin<Box<dyn Future<Output = Result<Vec<String>, AppError>> + Send + 'a>>> {
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
            Some(Box::pin(async move { res.map_err(AppError::Forbidden) }))
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

    /// Fetch member DIDs via `com.atproto.simplespace.listMembers` from the owner's PDS using AppView's OAuth session.
    /// Enforces bounds on pages, total members, bytes, cursor length, duration, concurrency, and repeated cursor detection.
    /// Stages all results and only returns when completely fetched without truncation (fails closed).
    pub async fn member_dids(&self, space: &str) -> Result<Vec<String>, AppError> {
        if let Some(fut) = self.transport.list_members(space) {
            return fut.await;
        }

        let _permit = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            HYDRATION_SEMAPHORE.acquire(),
        )
        .await
        .map_err(|_| AppError::InvalidRequest("Concurrent member hydration limit reached".into()))?
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

            let mut req_url =
                construct_xrpc_url(&pds_endpoint, "com.atproto.simplespace.listMembers")?;
            {
                let mut q = req_url.query_pairs_mut();
                q.append_pair("space", space);
                if let Some(c) = &cursor {
                    q.append_pair("cursor", c);
                }
            }

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
                let body = String::from_utf8_lossy(&body_bytes);
                return Err(AppError::Internal(format!(
                    "listMembers returned {status}: {body}"
                )));
            }

            #[derive(Deserialize)]
            struct MemberItem {
                did: String,
            }
            #[derive(Deserialize)]
            struct ListMembersResponse {
                members: Vec<MemberItem>,
                cursor: Option<String>,
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
            let data: ListMembersResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
                AppError::Internal(format!("Failed to parse listMembers output: {e}"))
            })?;
            for m in data.members {
                staged_members.push(m.did);
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

    /// Fetch space config via `com.atproto.simplespace.getSpace` from the owner's PDS using AppView's OAuth session.
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

        let mut req_url = construct_xrpc_url(&pds_endpoint, "com.atproto.simplespace.getSpace")?;
        req_url.query_pairs_mut().append_pair("space", space);
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
            return Err(AppError::Internal(format!(
                "getSpace returned {status}: {body}"
            )));
        }

        #[derive(Deserialize)]
        struct RawSpaceConfig {
            #[serde(default)]
            authority: Option<String>,
            #[serde(default, rename = "spaceType")]
            space_type: Option<String>,
            #[serde(default)]
            skey: Option<String>,
            #[serde(default, rename = "appAccess")]
            app_access: Option<serde_json::Value>,
            #[serde(default, rename = "userPolicy")]
            user_policy: Option<serde_json::Value>,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            description: Option<String>,
        }

        let body_bytes = crate::auth::read_bounded_authenticated_response_bytes(
            resp,
            crate::oauth::MAX_OAUTH_RESPONSE_BYTES,
        )
        .await?;
        let raw: RawSpaceConfig = serde_json::from_slice(&body_bytes)
            .map_err(|e| AppError::Internal(format!("Failed to parse getSpace output: {e}")))?;

        let app_access = raw
            .app_access
            .as_ref()
            .map(SpaceAppAccess::parse)
            .unwrap_or(SpaceAppAccess::Unknown(None));

        let (auth, st, sk) = parse_space_uri_parts(space)?;

        Ok(SpaceConfig {
            authority: raw.authority.unwrap_or(auth),
            space_type: raw.space_type.unwrap_or(st),
            skey: raw.skey.unwrap_or(sk),
            app_access,
            user_policy: raw.user_policy.map(|v| v.to_string()),
            name: raw.name,
            description: raw.description,
        })
    }

    pub async fn exchange_credential(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        delegation_token: &str,
        client_attestation: &str,
        authority_did: &str,
        authority_doc: &DidDocument,
    ) -> Result<(String, p256::ecdsa::SigningKey, DateTime<Utc>), AppError> {
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
            "/xrpc/com.atproto.space.getSpaceCredential".to_string()
        } else {
            format!("{path}/xrpc/com.atproto.space.getSpaceCredential")
        };
        let mut xrpc_url = parsed_endpoint;
        xrpc_url.set_path(&xrpc_path);

        let ephemeral_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = ephemeral_key.verifying_key();
        let expected_jkt = calculate_rfc7638_jkt(verifying_key);

        let dpop_proof = create_dpop_proof(&ephemeral_key, "POST", xrpc_url.as_str());

        let credential_jwt = self
            .transport
            .get_space_credential(
                &xrpc_url,
                delegation_token,
                &dpop_proof,
                space_uri,
                client_attestation,
            )
            .await?;

        let expires_at = validate_space_credential(
            &credential_jwt,
            authority_did,
            space_uri,
            &expected_jkt,
            authority_doc,
        )?;

        Ok((credential_jwt, ephemeral_key, expires_at))
    }

    pub async fn register_notify(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        space_credential: &str,
        dpop_key: &p256::ecdsa::SigningKey,
        service_identifier: &str,
    ) -> Result<DateTime<Utc>, AppError> {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.registerNotify")?;
        let dpop_proof =
            create_dpop_proof_with_ath(dpop_key, "POST", xrpc_url.as_str(), Some(space_credential));
        self.transport
            .register_notify(
                &xrpc_url,
                space_credential,
                &dpop_proof,
                service_identifier,
                space_uri,
            )
            .await
    }

    pub async fn list_repos(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        cursor: Option<&str>,
        space_credential: &str,
        dpop_key: &p256::ecdsa::SigningKey,
    ) -> Result<catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput, AppError>
    {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.listRepos")?;
        let dpop_proof =
            create_dpop_proof_with_ath(dpop_key, "GET", xrpc_url.as_str(), Some(space_credential));
        self.transport
            .list_repos(&xrpc_url, space_credential, &dpop_proof, space_uri, cursor)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_repo_ops(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        repo_did: &str,
        since: Option<&str>,
        cursor: Option<&str>,
        space_credential: &str,
        dpop_key: &p256::ecdsa::SigningKey,
    ) -> Result<
        catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput,
        AppError,
    > {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.listRepoOps")?;
        let dpop_proof =
            create_dpop_proof_with_ath(dpop_key, "GET", xrpc_url.as_str(), Some(space_credential));
        self.transport
            .list_repo_ops(
                &xrpc_url,
                space_credential,
                &dpop_proof,
                space_uri,
                repo_did,
                since,
                cursor,
            )
            .await
    }

    pub async fn get_repo(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        repo_did: &str,
        since: Option<&str>,
        space_credential: &str,
        dpop_key: &p256::ecdsa::SigningKey,
    ) -> Result<Vec<u8>, AppError> {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.getRepo")?;
        let dpop_proof =
            create_dpop_proof_with_ath(dpop_key, "GET", xrpc_url.as_str(), Some(space_credential));
        self.transport
            .get_repo(
                &xrpc_url,
                space_credential,
                &dpop_proof,
                space_uri,
                repo_did,
                since,
            )
            .await
    }

    pub async fn get_latest_commit(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        repo_did: &str,
        space_credential: &str,
        dpop_key: &p256::ecdsa::SigningKey,
    ) -> Result<catbird_atproto::generated::com_atproto::space::SignedCommit, AppError> {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.getLatestCommit")?;
        let dpop_proof =
            create_dpop_proof_with_ath(dpop_key, "GET", xrpc_url.as_str(), Some(space_credential));
        self.transport
            .get_latest_commit(
                &xrpc_url,
                space_credential,
                &dpop_proof,
                space_uri,
                repo_did,
            )
            .await
    }

    pub async fn get_blob(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        did: &str,
        cid: &str,
        space_credential: &str,
        dpop_key: &p256::ecdsa::SigningKey,
    ) -> Result<(Option<String>, Vec<u8>), AppError> {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.getBlob")?;
        let dpop_proof =
            create_dpop_proof_with_ath(dpop_key, "GET", xrpc_url.as_str(), Some(space_credential));
        self.transport
            .get_blob(
                &xrpc_url,
                space_credential,
                &dpop_proof,
                space_uri,
                did,
                cid,
            )
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

pub fn calculate_rfc7638_jkt(verifying_key: &p256::ecdsa::VerifyingKey) -> String {
    let point = EncodedPoint::from(verifying_key);
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("x coord"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("y coord"));
    let canonical_json = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let hash = Sha256::digest(canonical_json.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

pub fn create_dpop_proof(key: &p256::ecdsa::SigningKey, method: &str, target_url: &str) -> String {
    create_dpop_proof_with_ath(key, method, target_url, None)
}

pub fn create_dpop_proof_with_ath(
    key: &p256::ecdsa::SigningKey,
    method: &str,
    target_url: &str,
    access_token: Option<&str>,
) -> String {
    let verifying_key = key.verifying_key();
    let point = EncodedPoint::from(verifying_key);
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("x coord"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("y coord"));

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }
    });

    let mut claims = json!({
        "jti": Uuid::new_v4().to_string(),
        "htm": method,
        "htu": target_url,
        "iat": Utc::now().timestamp()
    });

    if let Some(token) = access_token {
        let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
        claims["ath"] = serde_json::Value::String(ath);
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
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

pub fn validate_space_credential(
    credential_jwt: &str,
    expected_iss: &str,
    expected_sub: &str,
    expected_jkt: &str,
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

    match &header.typ {
        Some(t) if t == "atproto-space-credential+jwt" || t == "JWT" => {}
        _ => return Err(AppError::Unauthorized(AuthReason::InvalidTyp)),
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsEncoding))?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsJson))?;

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

    let cnf_jkt = claims
        .get("cnf")
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(|v| v.as_str())
        .ok_or(AppError::Unauthorized(AuthReason::InvalidClaimsJson))?;

    if cnf_jkt != expected_jkt {
        return Err(AppError::Unauthorized(AuthReason::IdMismatch));
    }

    let now = Utc::now().timestamp();
    if iat > now + 300 {
        return Err(AppError::Unauthorized(AuthReason::FutureIat));
    }
    if exp <= now {
        return Err(AppError::Unauthorized(AuthReason::Expired));
    }

    let vm =
        select_authority_verification_method(authority_doc, expected_iss, header.kid.as_deref())
            .map_err(AppError::Unauthorized)?;
    let key = parse_verification_key(vm).map_err(AppError::Unauthorized)?;

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
        "UserNotAuthorized" => AppError::Forbidden("UserNotAuthorized".into()),
        "NotAuthorized" => AppError::Forbidden("NotAuthorized".into()),
        "InvalidDelegationToken" => AppError::Forbidden("InvalidDelegationToken".into()),
        "InvalidClientAttestation" => AppError::Forbidden("InvalidClientAttestation".into()),
        "SpaceNotFound" => AppError::NotFound("SpaceNotFound".into()),
        "SpaceDeleted" => AppError::AccessRemoved("SpaceDeleted".into()),
        _ => match status {
            reqwest::StatusCode::NOT_FOUND => AppError::NotFound("NotFound".into()),
            reqwest::StatusCode::FORBIDDEN => AppError::Forbidden("Forbidden".into()),
            reqwest::StatusCode::BAD_REQUEST => AppError::InvalidRequest("InvalidRequest".into()),
            _ => AppError::Internal(format!("Upstream error ({status})")),
        },
    }
}

pub fn extract_jkt_from_dpop_proof(dpop_proof: &str) -> Result<String, AppError> {
    let parts: Vec<&str> = dpop_proof.split('.').collect();
    if parts.is_empty() {
        return Err(AppError::InvalidRequest("Invalid DPoP proof format".into()));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderEncoding))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderJson))?;
    let jwk = header
        .get("jwk")
        .ok_or_else(|| AppError::Unauthorized(AuthReason::MissingKid))?;
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized(AuthReason::InvalidCoordinates))?;
    let y = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized(AuthReason::InvalidCoordinates))?;
    let canonical_json = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let hash = Sha256::digest(canonical_json.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

pub fn mint_mock_space_credential(
    authority_key: &p256::ecdsa::SigningKey,
    authority_did: &str,
    space_uri: &str,
    jkt: &str,
    expires_at: DateTime<Utc>,
) -> String {
    let header = json!({
        "typ": "atproto-space-credential+jwt",
        "alg": "ES256"
    });
    let claims = json!({
        "iss": authority_did,
        "sub": space_uri,
        "cnf": {
            "jkt": jkt
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
            r#"{"error":"UserNotAuthorized","message":"User not member"}"#,
        );
        match err3 {
            AppError::Forbidden(msg) => {
                assert!(
                    msg.contains("UserNotAuthorized"),
                    "Expected UserNotAuthorized, got: {msg}"
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
}
