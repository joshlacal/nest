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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceConfig {
    pub authority: String,
    pub space_type: String,
    pub skey: String,
    pub app_access: Vec<String>,
    pub user_policy: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone)]
pub struct SpaceClientDeps {
    pub http_client: reqwest::Client,
    pub did_resolver: Arc<DidResolver>,
    pub oauth_service: Arc<OAuthService>,
}

pub trait SpaceHostTransport: Send + Sync {
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

    fn get_blob<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        _space_uri: &'a str,
        _did: &'a str,
        _cid: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(Option<String>, Vec<u8>), AppError>> + Send + 'a>> {
        Box::pin(async move {
            Err(AppError::NotFound(
                "get_blob not implemented on transport".into(),
            ))
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

    pub async fn build_pinned_client(&self, target_url: &url::Url) -> Result<reqwest::Client, AppError> {
        if target_url.scheme() != "https" {
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
            .map_err(AppError::Unauthorized)?;

        if addrs.is_empty() {
            return Err(AppError::Unauthorized(AuthReason::SsrfBlocked));
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
        }

        builder.build().map_err(|e| {
            AppError::Internal(format!("Failed to build pinned HTTPS client: {e}"))
        })
    }
}

impl SpaceHostTransport for DefaultSpaceHostTransport {
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
                return Err(AppError::Internal(format!(
                    "Space host returned non-success status: {status}"
                )));
            }

            let body: serde_json::Value = response
                .json()
                .await
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

            let body: RegisterNotifyOutput = response
                .json()
                .await
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
                return Err(AppError::Internal(format!(
                    "Space host listRepos returned {}",
                    response.status()
                )));
            }
            let output = response
                .json()
                .await
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
    > {
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
                return Err(AppError::Internal(format!(
                    "Space host listRepoOps returned {}",
                    response.status()
                )));
            }
            let output = response
                .json()
                .await
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

            let mut response = client
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
                    "Space host getRepo returned {}",
                    response.status()
                )));
            }

            let max_car_bytes = crate::commit::MAX_CAR_BYTES;
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to read chunk from Space host: {e}")))?
            {
                if bytes.len() + chunk.len() > max_car_bytes {
                    return Err(AppError::InvalidRequest(format!(
                        "CAR file exceeds maximum size limit of {max_car_bytes} bytes"
                    )));
                }
                bytes.extend_from_slice(&chunk);
            }

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
                return Err(AppError::Internal(format!(
                    "Space host getLatestCommit returned {}",
                    response.status()
                )));
            }
            let output: catbird_atproto::generated::com_atproto::space::get_latest_commit::GetLatestCommitOutput = response.json().await.map_err(|e| AppError::Internal(e.to_string()))?;
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
    ) -> Pin<Box<dyn Future<Output = Result<(Option<String>, Vec<u8>), AppError>> + Send + 'a>> {
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

            let mut response = client
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
                    "Space host getBlob returned {}",
                    response.status()
                )));
            }

            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let max_bytes: usize = 20 * 1024 * 1024; // 20 MiB streaming cap
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to read chunk from Space host: {e}")))?
            {
                if bytes.len() + chunk.len() > max_bytes {
                    return Err(AppError::InvalidRequest(format!(
                        "Blob stream exceeds maximum size limit of {max_bytes} bytes"
                    )));
                }
                bytes.extend_from_slice(&chunk);
            }

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

pub struct MockSpaceHostTransport {
    responses: Mutex<HashMap<String, Result<String, String>>>,
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
    blob_responses: Mutex<HashMap<String, (Option<String>, Vec<u8>)>>,
    register_notify_responses: Mutex<HashMap<String, DateTime<Utc>>>,
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
            list_repos_responses: Mutex::new(HashMap::new()),
            list_repo_ops_responses: Mutex::new(HashMap::new()),
            get_repo_responses: Mutex::new(HashMap::new()),
            latest_commits: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            blob_responses: Mutex::new(HashMap::new()),
            register_notify_responses: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_credential_response(&self, space: &str, result: Result<String, String>) {
        let mut lock = self.responses.lock().unwrap();
        lock.insert(space.to_string(), result);
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

    pub fn set_blob_response(
        &self,
        key: &str,
        content_type: Option<String>,
        data: Vec<u8>,
    ) {
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
}

impl SpaceHostTransport for MockSpaceHostTransport {
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
        let lock = self.responses.lock().unwrap();
        let res = lock.get(space_uri).cloned();
        Box::pin(async move {
            match res {
                Some(Ok(cred)) => Ok(cred),
                Some(Err(e)) => Err(AppError::Internal(e)),
                None => Err(AppError::NotFound(format!("No mock response for {space_uri}"))),
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
        let expires_at = lock.get(space_uri).cloned().unwrap_or_else(|| Utc::now() + chrono::Duration::hours(24));
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
            Some(c) => lock.get(&format!("{space_uri}:{c}")).or_else(|| lock.get(space_uri)).cloned(),
            None => lock.get(space_uri).cloned(),
        };
        let lookup_key = match cursor {
            Some(c) => format!("{space_uri}:{c}"),
            None => space_uri.to_string(),
        };
        Box::pin(async move {
            res.ok_or_else(|| AppError::NotFound(format!("No mock list_repos configured for {lookup_key}")))
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
    > {
        let base_key = format!("{space_uri}:{repo_did}");
        let lock = self.list_repo_ops_responses.lock().unwrap();
        let res = match cursor {
            Some(c) => lock.get(&format!("{base_key}:{c}")).or_else(|| lock.get(&base_key)).or_else(|| lock.get(space_uri)).cloned(),
            None => lock.get(&base_key).or_else(|| lock.get(space_uri)).cloned(),
        };
        let lookup_key = match cursor {
            Some(c) => format!("{base_key}:{c}"),
            None => base_key,
        };
        Box::pin(async move {
            res.ok_or_else(|| AppError::NotFound(format!("No mock list_repo_ops configured for {lookup_key}")))
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
            res.ok_or_else(|| AppError::NotFound(format!("No mock get_latest_commit configured for {key}")))
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
    ) -> Pin<Box<dyn Future<Output = Result<(Option<String>, Vec<u8>), AppError>> + Send + 'a>> {
        let key = format!("{space_uri}:{did}:{cid}");
        let alt_key = format!("{did}:{cid}");
        let lock = self.blob_responses.lock().unwrap();
        let res = lock.get(&key).or_else(|| lock.get(&alt_key)).cloned();
        Box::pin(async move {
            let (content_type, bytes) =
                res.ok_or_else(|| AppError::NotFound(format!("No mock get_blob configured for {key}")))?;
            let max_bytes: usize = 20 * 1024 * 1024;
            if bytes.len() > max_bytes {
                return Err(AppError::InvalidRequest(format!(
                    "Blob stream exceeds maximum size limit of {max_bytes} bytes"
                )));
            }
            Ok((content_type, bytes))
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

    /// Fetch member DIDs via `com.atproto.simplespace.listMembers` from the owner's PDS using AppView's OAuth session.
    pub async fn member_dids(&self, space: &str) -> Result<Vec<String>, AppError> {
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
            .map_err(|e| AppError::Internal(format!("Failed to resolve PDS endpoint for {authority}: {e:?}")))?;

        let (token, dpop_key) = deps
            .oauth_service
            .get_valid_token(&authority, &deps.http_client)
            .await?;

        let mut members = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::HashSet::new();

        let base_url = pds_endpoint.trim_end_matches('/');
        let xrpc_url = format!("{base_url}/xrpc/com.atproto.simplespace.listMembers");

        loop {
            let mut req_url = url::Url::parse(&xrpc_url)
                .map_err(|e| AppError::InvalidRequest(format!("Invalid XRPC URL: {e}")))?;
            {
                let mut q = req_url.query_pairs_mut();
                q.append_pair("space", space);
                if let Some(c) = &cursor {
                    q.append_pair("cursor", c);
                }
            }

            let resp = crate::oauth::get_with_dpop(
                &deps.http_client,
                &dpop_key,
                req_url.as_str(),
                &token,
            )
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch listMembers: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(AppError::Internal(format!("listMembers returned {status}: {body}")));
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

            let data: ListMembersResponse = resp
                .json()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to parse listMembers output: {e}")))?;

            for m in data.members {
                members.push(m.did);
            }

            if let Some(next) = data.cursor {
                if !seen_cursors.insert(next.clone()) {
                    break;
                }
                cursor = Some(next);
            } else {
                break;
            }
        }

        Ok(members)
    }

    /// Fetch space config via `com.atproto.simplespace.getSpace` from the owner's PDS using AppView's OAuth session.
    pub async fn get_space(&self, space: &str) -> Result<SpaceConfig, AppError> {
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
            .map_err(|e| AppError::Internal(format!("Failed to resolve PDS endpoint for {authority}: {e:?}")))?;

        let (token, dpop_key) = deps
            .oauth_service
            .get_valid_token(&authority, &deps.http_client)
            .await?;

        let base_url = pds_endpoint.trim_end_matches('/');
        let xrpc_url = format!("{base_url}/xrpc/com.atproto.simplespace.getSpace");
        let mut req_url = url::Url::parse(&xrpc_url)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid XRPC URL: {e}")))?;
        req_url.query_pairs_mut().append_pair("space", space);

        let resp = crate::oauth::get_with_dpop(
            &deps.http_client,
            &dpop_key,
            req_url.as_str(),
            &token,
        )
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch getSpace: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!("getSpace returned {status}: {body}")));
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

        let raw: RawSpaceConfig = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse getSpace output: {e}")))?;

        let mut app_access_list = Vec::new();
        if let Some(val) = raw.app_access {
            if let Some(arr) = val.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        app_access_list.push(s.to_string());
                    }
                }
            } else if let Some(obj) = val.as_object() {
                // Real wire shape from com.atproto.simplespace.getSpace:
                //   "appAccess": { "$type": "...defs#allowList", "allowed": [client_id, ...] }
                // The array lives under `allowed`; `$type` is only the union tag.
                // A `#open` policy has no list at all and therefore never names
                // this AppView, which is the fail-closed reading we want.
                let allowed = obj
                    .get("allowed")
                    .or_else(|| obj.get("allowList"))
                    .and_then(|v| v.as_array());
                if let Some(apps) = allowed {
                    for item in apps {
                        if let Some(s) = item.as_str() {
                            app_access_list.push(s.to_string());
                        }
                    }
                }
            }
        }

        let (auth, st, sk) = parse_space_uri_parts(space)?;

        Ok(SpaceConfig {
            authority: raw.authority.unwrap_or(auth),
            space_type: raw.space_type.unwrap_or(st),
            skey: raw.skey.unwrap_or(sk),
            app_access: app_access_list,
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

    let vm = select_authority_verification_method(authority_doc, expected_iss, header.kid.as_deref())
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
