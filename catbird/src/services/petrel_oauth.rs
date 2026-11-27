//! A confidential Petrel client profile. Each gateway session gets its own
//! Petrel namespace, including simultaneous sessions belonging to the same DID.

use super::petrel_storage::{ClientSessionData, RedisSessionSecrets};
use super::{KeyStore, RedisAuthStore};
use anyhow::{anyhow, Context};
use bytes::Bytes;
use petrel::{
    identity::{CachePolicy, HickoryResolver, IdentityOptions, IdentityResolver},
    net::{HttpTransport, ReqwestTransport, SendOptions, SharedTransport, TransportError},
    oauth::{
        AuthorizationServerMetadata, ClientAuth, OAuthClient, OAuthConfig, OAuthError,
        OAuthIdentityAdapter, OAuthIdentityResolver, OAuthStartOptions, OAuthTarget,
    },
    storage::{SessionStore, StoreError},
};
use petrel_core::{AtIdentifier, Did};
use std::sync::{Arc, Mutex};
use url::Url;

/// Retain Nest's issuer-origin policy in addition to Petrel's native transport
/// policy. A public issuer cannot delegate credentials to another origin.
struct GatewayTransport(SharedTransport);

impl HttpTransport for GatewayTransport {
    async fn send(
        &self,
        req: http::Request<Bytes>,
        opts: &SendOptions,
    ) -> Result<http::Response<Bytes>, TransportError> {
        super::validate_pds_url(&req.uri().to_string())
            .map_err(|_| TransportError::PolicyViolation("invalid OAuth destination".into()))?;
        let metadata = req.uri().path() == "/.well-known/oauth-authorization-server";
        let mut options = opts.clone();
        options.max_response_bytes = Some(
            options
                .max_response_bytes
                .unwrap_or(u64::MAX)
                .min(super::MAX_OAUTH_RESPONSE_SIZE as u64),
        );
        let refresh = req.method() == http::Method::POST
            && req
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"))
            && url::form_urlencoded::parse(req.body())
                .any(|(k, v)| k == "grant_type" && v == "refresh_token");
        let result = self.0.send_dyn(req, &options).await;
        if refresh {
            let outcome = match &result {
                Err(_) => "transport_failure",
                Ok(response) if response.status().is_success() => "success",
                Ok(response) => {
                    #[derive(serde::Deserialize)]
                    struct Rejection<'a> {
                        error: &'a str,
                    }
                    match serde_json::from_slice::<Rejection>(response.body())
                        .ok()
                        .map(|e| e.error)
                    {
                        Some("invalid_grant") => "invalid_grant",
                        Some("use_dpop_nonce") => "nonce_challenge",
                        _ => "server_error",
                    }
                }
            };
            crate::metrics::record_token_refresh(outcome == "success");
            crate::metrics::PETREL_REFRESH_OUTCOMES
                .with_label_values(&[outcome])
                .inc();
        }
        let res = result?;
        if metadata && res.status().is_success() {
            let doc: AuthorizationServerMetadata = serde_json::from_slice(res.body())
                .map_err(|_| TransportError::PolicyViolation("invalid issuer metadata".into()))?;
            super::oauth_authorize::validate_oauth_server_endpoints(
                &doc.issuer,
                doc.authorization_endpoint.as_deref().unwrap_or_default(),
                doc.token_endpoint.as_deref().unwrap_or_default(),
                doc.pushed_authorization_request_endpoint.as_deref(),
                doc.revocation_endpoint.as_deref(),
            )
            .map_err(|_| TransportError::PolicyViolation("invalid issuer endpoints".into()))?;
        }
        Ok(res)
    }
}

pub struct GatewayOAuth {
    pub store: RedisAuthStore,
    pub redirect: Url,
    config: OAuthConfig,
    transport: SharedTransport,
    resolver: Arc<dyn OAuthIdentityResolver>,
    clients: Mutex<std::collections::VecDeque<(String, Arc<OAuthClient>)>>,
}

impl GatewayOAuth {
    pub fn new(
        store: RedisAuthStore,
        key_store: &KeyStore,
        client_id: &str,
        redirect: &str,
        scope: &str,
    ) -> anyhow::Result<Self> {
        Self::with_transport(
            store,
            key_store,
            client_id,
            redirect,
            scope,
            Arc::new(ReqwestTransport::new()?),
            IdentityOptions::default().plc_directory,
        )
    }

    /// Supply a transport and PLC directory while retaining the gateway's endpoint policy.
    pub fn with_transport(
        store: RedisAuthStore,
        key_store: &KeyStore,
        client_id: &str,
        redirect: &str,
        scope: &str,
        transport: SharedTransport,
        plc_directory: Url,
    ) -> anyhow::Result<Self> {
        let redirect = Url::parse(redirect)?;
        let config = OAuthConfig::new(
            client_id,
            redirect.clone(),
            scope,
            ClientAuth::PrivateKeyJwt(Arc::new(key_store.active_key())),
        )?;
        let transport: SharedTransport = Arc::new(GatewayTransport(transport));
        let options = IdentityOptions {
            cache_policy: CachePolicy::disabled(),
            plc_directory,
            ..Default::default()
        };
        let resolver = Arc::new(OAuthIdentityAdapter::new(IdentityResolver::new(
            transport.clone(),
            HickoryResolver::system()?,
            options,
        )));
        Ok(Self {
            store,
            redirect,
            config,
            transport,
            resolver,
            clients: Mutex::new(Default::default()),
        })
    }

    pub fn client(&self, storage: SessionStore) -> Result<OAuthClient, OAuthError> {
        OAuthClient::new(
            self.transport.clone(),
            self.resolver.clone(),
            storage,
            self.config.clone(),
        )
    }

    pub async fn start(
        &self,
        identifier: &str,
        scope: &str,
        route: &str,
    ) -> anyhow::Result<String> {
        let target = if identifier.starts_with("https://") || identifier.starts_with("http://") {
            super::validate_pds_url(identifier)?;
            OAuthTarget::Server(Url::parse(identifier)?)
        } else {
            OAuthTarget::Identifier(AtIdentifier::parse(identifier)?)
        };
        let storage = RedisSessionSecrets::flow_store(&self.store, route)?;
        let client = self.client(storage)?;
        let flow = client
            .start_authorization_with_options(
                target,
                OAuthStartOptions {
                    scope: Some(scope),
                    state_prefix: Some(route),
                },
            )
            .await?;

        // The UI's login or upgrade state and Petrel's full, single-use state
        // must both match on callback, including after process restart.
        let key = flow_route_key(&self.store, &flow.state);
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(route)
            .arg("EX")
            .arg(600)
            .query_async(&mut self.store.redis_connection())
            .await?;
        Ok(flow.authorize_url.to_string())
    }

    pub async fn complete(
        &self,
        route: &str,
        wire_state: &str,
        code: &str,
        issuer: Option<&str>,
    ) -> anyhow::Result<ClientSessionData> {
        let storage = RedisSessionSecrets::flow_store(&self.store, route)?;
        let client = self.client(storage.clone())?;
        let mut callback = self.redirect.clone();
        {
            let mut query = callback.query_pairs_mut();
            query
                .append_pair("state", wire_state)
                .append_pair("code", code);
            if let Some(issuer) = issuer {
                query.append_pair("iss", issuer);
            }
        }
        let session = client.complete_authorization(&callback).await?;
        let record = storage
            .get_session(&session.did)
            .await?
            .context("missing new session")?;
        let key = storage
            .get_dpop_key(&record.dpop_key_id)
            .await?
            .context("missing new session key")?;
        // The bearer given to the app is independent of the public authorization state.
        let id = uuid::Uuid::new_v4().to_string();
        let data = ClientSessionData::from_petrel(&record, &key, &id)?;
        if !route.starts_with("upg_") {
            if let Err(error) = self.store.upsert_session(data.clone()).await {
                let _ = client.revoke_session(&session.did).await;
                let _ = storage
                    .secrets()
                    .delete_namespace(storage.namespace())
                    .await;
                return Err(error.into());
            }
        }
        // The cache expires after ten minutes even if the caller disconnects here.
        let _ = storage
            .secrets()
            .delete_namespace(storage.namespace())
            .await;
        Ok(data)
    }

    pub fn evict_session(&self, id: &str) {
        let key = format!("s{}", self.store.fingerprint(id));
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(k, _)| k != &key);
    }

    pub(super) async fn refreshed(
        &self,
        did: &Did,
        id: &str,
    ) -> Result<ClientSessionData, OAuthError> {
        let (storage, observed_mirror) = RedisSessionSecrets::new(&self.store, did, id)
            .load_with_mirror()
            .await?
            .ok_or(OAuthError::MissingSession)?;
        let client = {
            let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
            let key = storage.namespace().to_owned();
            if let Some(i) = clients.iter().position(|(k, _)| k == &key) {
                let pair = clients.remove(i).expect("cache entry present");
                let client = pair.1.clone();
                clients.push_back(pair);
                client
            } else {
                let client = Arc::new(self.client(storage)?);
                if clients.len() == 128 {
                    clients.pop_front();
                }
                clients.push_back((key, client.clone()));
                client
            }
        };
        let session = match client.refresh(did, false).await {
            Err(OAuthError::InvalidGrant) => {
                self.evict_session(id);
                let retired = self
                    .store
                    .retire_session(did, id, &observed_mirror)
                    .await
                    .map_err(|_| StoreError::Unavailable("session retirement".into()))?;
                return Err(if retired {
                    OAuthError::InvalidGrant
                } else {
                    OAuthError::RefreshPersistencePending
                });
            }
            other => other?,
        };
        let mirror = self
            .store
            .get_session(did, id)
            .await
            .map_err(|_| StoreError::Unavailable("read current session".into()))?
            .ok_or(OAuthError::MissingSession)?;
        if mirror.token_set.access_token != session.access_token()
            || mirror.token_set.refresh_token.as_deref() != session.refresh_token()
        {
            return Err(OAuthError::RefreshPersistencePending);
        }
        Ok(mirror)
    }

    /// Discover the current revocation endpoint before using a receipt-owned
    /// grant. Read-only discovery is bound to the resource and original issuer.
    pub(super) async fn revocation_metadata(
        &self,
        record: &petrel::oauth::SessionRecord,
    ) -> anyhow::Result<AuthorizationServerMetadata> {
        use petrel::oauth::{ClientAuthenticationMethod, ProtectedResourceMetadata};
        let pds = &record.account.pds;
        let expected = record
            .account
            .expected_issuer
            .as_deref()
            .context("missing bound issuer")?;
        let resource: ProtectedResourceMetadata =
            self.metadata(pds, "oauth-protected-resource").await?;
        if resource.validate(pds)? != expected {
            return Err(anyhow!("authorization server changed"));
        }
        let doc: AuthorizationServerMetadata = self
            .metadata(expected, "oauth-authorization-server")
            .await?;
        let server = doc
            .clone()
            .validate(expected, ClientAuthenticationMethod::PrivateKeyJwt)?;
        server.validates_resource(pds)?;
        Ok(doc)
    }

    async fn metadata<T: serde::de::DeserializeOwned>(
        &self,
        origin: &str,
        name: &str,
    ) -> anyhow::Result<T> {
        super::validate_pds_url(origin)?;
        let request = http::Request::get(format!("{origin}/.well-known/{name}"))
            .header(http::header::ACCEPT, "application/json")
            .body(Bytes::new())?;
        let mut options = SendOptions::new();
        options.anonymous = true;
        let response = self.transport.send_dyn(request, &options).await?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "OAuth metadata endpoint returned {}",
                response.status()
            ));
        }
        Ok(serde_json::from_slice(response.body())?)
    }

    pub async fn revoke(&self, did: &Did, id: &str) -> anyhow::Result<()> {
        let storage = RedisSessionSecrets::new(&self.store, did, id)
            .load_or_convert()
            .await?
            .context("session missing")?;
        if self.client(storage)?.revoke_session(did).await? {
            Ok(())
        } else {
            Err(anyhow!("authorization server did not confirm revocation"))
        }
    }
}

fn flow_route_key(store: &RedisAuthStore, state: &str) -> String {
    format!(
        "{}petrel_flow_route:{}",
        store.key_prefix(),
        store.fingerprint(state)
    )
}

pub async fn callback_route(store: &RedisAuthStore, state: &str) -> anyhow::Result<Option<String>> {
    let route = redis::cmd("GET")
        .arg(flow_route_key(store, state))
        .query_async(&mut store.redis_connection())
        .await?;
    Ok(route)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gateway_transport_refuses_disallowed_url_before_connecting() {
        let transport = GatewayTransport(Arc::new(ReqwestTransport::new().unwrap()));
        for url in ["http://10.0.0.1/resource", "http://example.com/oauth"] {
            let req = http::Request::get(url).body(Bytes::new()).unwrap();
            let err = transport.send(req, &SendOptions::new()).await.unwrap_err();
            assert!(matches!(err, TransportError::PolicyViolation(_)));
        }
    }
}
