use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::rand_core::OsRng;
use p256::EncodedPoint;
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
    select_authority_verification_method, DidDocument, JwtHeader, ParsedVerifyingKey,
};
use crate::error::{AppError, AuthReason};

pub trait SpaceHostTransport: Send + Sync {
    fn get_space_credential<'a>(
        &'a self,
        target_url: &'a url::Url,
        delegation_token: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
        client_attestation: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>>;

    fn list_repos<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        _space_uri: &'a str,
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

    fn list_repo_ops<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        _space_uri: &'a str,
        _repo_did: &'a str,
        _since: Option<&'a str>,
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

    pub fn with_test_root_certificate(cert: reqwest::Certificate) -> Self {
        Self {
            test_root_cert: Some(cert),
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
        let test_cert = self.test_root_cert.clone();

        Box::pin(async move {
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

            // DNS resolution
            let addrs = self
                .dns_resolver
                .resolve_dns(host, port)
                .await
                .map_err(AppError::Unauthorized)?;

            if !self.allow_loopback_for_test {
                // Reject every non-global/special-purpose address
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

            if let Some(cert) = test_cert {
                builder = builder.add_root_certificate(cert);
            }

            let client = builder.build().map_err(|e| {
                AppError::Internal(format!("Failed to build pinned HTTPS client: {e}"))
            })?;

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

    fn list_repos<'a>(
        &'a self,
        target_url: &'a url::Url,
        space_credential: &'a str,
        dpop_proof: &'a str,
        space_uri: &'a str,
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
        let test_cert = self.test_root_cert.clone();

        Box::pin(async move {
            let host = target_url
                .host_str()
                .ok_or_else(|| AppError::InvalidRequest("Missing host in URL".into()))?;
            let port = target_url.port().unwrap_or(443);
            let addrs = self
                .dns_resolver
                .resolve_dns(host, port)
                .await
                .map_err(AppError::Unauthorized)?;
            let pinned_addr = addrs[0];

            let mut builder = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(5))
                .resolve(host, pinned_addr);
            if let Some(cert) = test_cert {
                builder = builder.add_root_certificate(cert);
            }
            let client = builder
                .build()
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let mut req_url = target_url.clone();
            req_url.query_pairs_mut().append_pair("space", &space_uri);

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
    ) -> Pin<Box<dyn Future<Output = Result<catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput, AppError>> + Send + 'a>>{
        let target_url = target_url.clone();
        let space_credential = space_credential.to_string();
        let dpop_proof = dpop_proof.to_string();
        let space_uri = space_uri.to_string();
        let repo_did = repo_did.to_string();
        let since = since.map(|s| s.to_string());
        let test_cert = self.test_root_cert.clone();

        Box::pin(async move {
            let host = target_url
                .host_str()
                .ok_or_else(|| AppError::InvalidRequest("Missing host in URL".into()))?;
            let port = target_url.port().unwrap_or(443);
            let addrs = self
                .dns_resolver
                .resolve_dns(host, port)
                .await
                .map_err(AppError::Unauthorized)?;
            let pinned_addr = addrs[0];

            let mut builder = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(5))
                .resolve(host, pinned_addr);
            if let Some(cert) = test_cert {
                builder = builder.add_root_certificate(cert);
            }
            let client = builder
                .build()
                .map_err(|e| AppError::Internal(e.to_string()))?;

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
        let test_cert = self.test_root_cert.clone();

        Box::pin(async move {
            let host = target_url
                .host_str()
                .ok_or_else(|| AppError::InvalidRequest("Missing host in URL".into()))?;
            let port = target_url.port().unwrap_or(443);
            let addrs = self
                .dns_resolver
                .resolve_dns(host, port)
                .await
                .map_err(AppError::Unauthorized)?;
            let pinned_addr = addrs[0];

            let mut builder = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(5))
                .resolve(host, pinned_addr);
            if let Some(cert) = test_cert {
                builder = builder.add_root_certificate(cert);
            }
            let client = builder
                .build()
                .map_err(|e| AppError::Internal(e.to_string()))?;

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
                    "Space host getRepo returned {}",
                    response.status()
                )));
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;
            Ok(bytes.to_vec())
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
        let test_cert = self.test_root_cert.clone();

        Box::pin(async move {
            let host = target_url
                .host_str()
                .ok_or_else(|| AppError::InvalidRequest("Missing host in URL".into()))?;
            let port = target_url.port().unwrap_or(443);
            let addrs = self
                .dns_resolver
                .resolve_dns(host, port)
                .await
                .map_err(AppError::Unauthorized)?;
            let pinned_addr = addrs[0];

            let mut builder = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(5))
                .resolve(host, pinned_addr);
            if let Some(cert) = test_cert {
                builder = builder.add_root_certificate(cert);
            }
            let client = builder
                .build()
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let mut req_url = target_url.clone();
            req_url
                .query_pairs_mut()
                .append_pair("space", &space_uri)
                .append_pair("repo", &repo_did);

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
        let call = RecordedSpaceHostCall {
            endpoint_url: target_url.to_string(),
            delegation_token: delegation_token.to_string(),
            dpop_proof: dpop_proof.to_string(),
            space_uri: space_uri.to_string(),
            client_attestation: client_attestation.to_string(),
        };
        self.calls.lock().unwrap().push(call);

        let res = self.responses.lock().unwrap().get(space_uri).cloned();
        Box::pin(async move {
            match res {
                Some(Ok(token)) => Ok(token),
                Some(Err(err)) => Err(AppError::Internal(err)),
                None => Err(AppError::NotFound(
                    "No mock credential configured for space".into(),
                )),
            }
        })
    }

    fn list_repos<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        space_uri: &'a str,
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
        let res = self
            .list_repos_responses
            .lock()
            .unwrap()
            .get(space_uri)
            .cloned();
        Box::pin(async move {
            res.ok_or_else(|| AppError::NotFound("No mock list_repos configured for space".into()))
        })
    }

    fn list_repo_ops<'a>(
        &'a self,
        _target_url: &'a url::Url,
        _space_credential: &'a str,
        _dpop_proof: &'a str,
        space_uri: &'a str,
        repo_did: &'a str,
        since: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<catbird_atproto::generated::com_atproto::space::list_repo_ops::ListRepoOpsOutput, AppError>> + Send + 'a>>{
        let key_with_since = match since {
            Some(s) => format!("{space_uri}:{repo_did}:{s}"),
            None => format!("{space_uri}:{repo_did}"),
        };
        let key_base = format!("{space_uri}:{repo_did}");
        let lock = self.list_repo_ops_responses.lock().unwrap();
        let res = lock
            .get(&key_with_since)
            .or_else(|| lock.get(&key_base))
            .cloned();
        Box::pin(async move {
            res.ok_or_else(|| {
                AppError::NotFound(format!("No mock list_repo_ops configured for {key_base}"))
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
        let res = self.get_repo_responses.lock().unwrap().get(&key).cloned();
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
        let res = self.latest_commits.lock().unwrap().get(&key).cloned();
        Box::pin(async move {
            res.ok_or_else(|| {
                AppError::NotFound(format!("No mock get_latest_commit configured for {key}"))
            })
        })
    }
}

pub struct SpaceClient {
    transport: Arc<dyn SpaceHostTransport>,
}

impl SpaceClient {
    pub fn new() -> Self {
        Self {
            transport: Arc::new(DefaultSpaceHostTransport::new()),
        }
    }

    pub fn with_transport(transport: Arc<dyn SpaceHostTransport>) -> Self {
        Self { transport }
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
        let expected_jkt = calculate_rfc7638_jkt(&verifying_key);

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

        // Validate returned Space credential
        let expires_at = validate_space_credential(
            &credential_jwt,
            authority_did,
            space_uri,
            &expected_jkt,
            authority_doc,
        )?;

        Ok((credential_jwt, ephemeral_key, expires_at))
    }

    pub async fn list_repos(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        space_credential: &str,
        dpop_key: &p256::ecdsa::SigningKey,
    ) -> Result<catbird_atproto::generated::com_atproto::space::list_repos::ListReposOutput, AppError>
    {
        let xrpc_url = construct_xrpc_url(service_endpoint, "com.atproto.space.listRepos")?;
        let dpop_proof =
            create_dpop_proof_with_ath(dpop_key, "GET", xrpc_url.as_str(), Some(space_credential));
        self.transport
            .list_repos(&xrpc_url, space_credential, &dpop_proof, space_uri)
            .await
    }

    pub async fn list_repo_ops(
        &self,
        service_endpoint: &str,
        space_uri: &str,
        repo_did: &str,
        since: Option<&str>,
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
}

impl Default for SpaceClient {
    fn default() -> Self {
        Self::new()
    }
}

pub fn calculate_rfc7638_jkt(verifying_key: &p256::ecdsa::VerifyingKey) -> String {
    let point = EncodedPoint::from(verifying_key);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    // Canonical JSON representation for EC P-256 key per RFC 7638
    let canonical_jwk = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let mut hasher = Sha256::new();
    hasher.update(canonical_jwk.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn create_dpop_proof(signing_key: &p256::ecdsa::SigningKey, htm: &str, htu: &str) -> String {
    let now = Utc::now().timestamp();
    let verifying_key = signing_key.verifying_key();
    let point = EncodedPoint::from(verifying_key);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        }
    });

    let payload = json!({
        "jti": Uuid::new_v4().to_string(),
        "htm": htm,
        "htu": htu,
        "iat": now,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

pub fn create_dpop_proof_with_ath(
    signing_key: &p256::ecdsa::SigningKey,
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
) -> String {
    let now = Utc::now().timestamp();
    let verifying_key = signing_key.verifying_key();
    let point = EncodedPoint::from(verifying_key);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        }
    });

    let mut payload = json!({
        "jti": Uuid::new_v4().to_string(),
        "htm": htm,
        "htu": htu,
        "iat": now,
    });

    if let Some(token) = access_token {
        let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
        payload["ath"] = json!(ath);
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

pub fn construct_xrpc_url(service_endpoint: &str, method_nsid: &str) -> Result<url::Url, AppError> {
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
        format!("/xrpc/{method_nsid}")
    } else {
        format!("{path}/xrpc/{method_nsid}")
    };
    let mut xrpc_url = parsed_endpoint;
    xrpc_url.set_path(&xrpc_path);
    Ok(xrpc_url)
}
pub fn validate_space_credential(
    credential_jwt: &str,
    expected_authority_did: &str,
    expected_space_uri: &str,
    expected_jkt: &str,
    authority_doc: &DidDocument,
) -> Result<DateTime<Utc>, AppError> {
    let parts: Vec<&str> = credential_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::InvalidRequest(
            "Invalid Space credential JWT format".into(),
        ));
    }

    // 1. Validate Header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::InvalidRequest("Invalid Space credential header encoding".into()))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid Space credential header JSON".into()))?;

    match &header.typ {
        Some(t) if t == "atproto-space-credential+jwt" => {}
        _ => return Err(AppError::Unauthorized(AuthReason::InvalidTyp)),
    }

    if header.alg != "ES256" && header.alg != "ES256K" {
        return Err(AppError::Unauthorized(AuthReason::UnsupportedAlg));
    }

    // 2. Validate Payload
    let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| {
        AppError::InvalidRequest("Invalid Space credential payload encoding".into())
    })?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid Space credential claims JSON".into()))?;

    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRequest("Missing iss in Space credential claims".into()))?;
    if iss != expected_authority_did {
        return Err(AppError::Forbidden(
            "Space credential issuer does not match Space authority".into(),
        ));
    }

    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRequest("Missing sub in Space credential claims".into()))?;
    if sub != expected_space_uri {
        return Err(AppError::InvalidRequest(
            "Space credential subject does not match requested Space URI".into(),
        ));
    }

    // Must not have an inappropriate audience (absence of audience or matching requested space)
    if let Some(aud) = claims.get("aud").and_then(|v| v.as_str()) {
        if !aud.is_empty() && aud != expected_space_uri {
            return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
        }
    }

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::InvalidRequest("Missing exp in Space credential claims".into()))?;
    let now = Utc::now().timestamp();
    if exp <= now {
        return Err(AppError::Unauthorized(AuthReason::Expired));
    }

    let iat = claims
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::InvalidRequest("Missing iat in Space credential claims".into()))?;
    if iat > now + 300 {
        return Err(AppError::Unauthorized(AuthReason::FutureIat));
    }

    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRequest("Missing jti in Space credential claims".into()))?;
    if jti.is_empty() {
        return Err(AppError::InvalidRequest(
            "Empty jti in Space credential claims".into(),
        ));
    }

    // Validate cnf.jkt binding
    let jkt = claims
        .get("cnf")
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AppError::InvalidRequest("Missing cnf.jkt in Space credential claims".into())
        })?;
    if jkt != expected_jkt {
        return Err(AppError::Unauthorized(AuthReason::InvalidCoordinates));
    }

    // 3. Verify Signature against authority DID document (#atproto_space fallback to #atproto)
    let vm = select_authority_verification_method(
        authority_doc,
        expected_authority_did,
        header.kid.as_deref(),
    )
    .map_err(AppError::Unauthorized)?;
    let key = parse_verification_key(vm).map_err(AppError::Unauthorized)?;

    // Match header algorithm to parsed verification key curve
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

    DateTime::from_timestamp(exp, 0)
        .ok_or_else(|| AppError::InvalidRequest("Invalid timestamp in Space credential exp".into()))
}
