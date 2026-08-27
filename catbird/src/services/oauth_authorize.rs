//! Starting an authorization with an explicit, per-request scope set.
//!
//! `OAuthClient::start_auth` accepts `AuthorizeOptions::scopes` but never reads
//! it: only `prompt` and `state` reach `par()`, and the pushed authorization
//! request takes its scope straight from the client metadata. Progressive scopes
//! need the opposite of that. The metadata Nest publishes has to keep declaring
//! `max_scopes`, so the authorization server knows this client is registered for
//! the account and identity permissions a later just-in-time upgrade will ask
//! for — while each individual authorization must request only the subset it
//! actually needs. Sign-in asks for `initial_scopes`; an upgrade asks for those
//! plus the one permission it is elevating.
//!
//! So derive the client metadata per request and drive `par` directly. The
//! long-lived client's resolver and auth store are reused rather than rebuilt:
//! the callback looks the request up through that same store, and a fresh
//! resolver would drop whatever identity configuration the caller established.

use anyhow::{anyhow, Result};
use jacquard_oauth::atproto::atproto_client_metadata;
use jacquard_oauth::authstore::ClientAuthStore;
use jacquard_oauth::request::{par, OAuthMetadata};
use jacquard_oauth::resolver::OAuthResolver;
use jacquard_oauth::scopes::{Scope, Scopes};
use smol_str::{SmolStr, ToSmolStr};

use crate::config::JacquardOAuthClient;

/// Push an authorization request that asks for exactly `scopes`, returning the
/// authorization URL to redirect the user to.
///
/// `redirect_uri` overrides the client's first registered redirect URI, which is
/// the one `par` sends; pass `None` to use it as registered.
pub async fn start_auth_with_scopes(
    client: &JacquardOAuthClient,
    identifier: &str,
    scopes: &[Scope],
    state_token: &str,
    redirect_uri: Option<jacquard_common::deps::fluent_uri::Uri<String>>,
) -> Result<String> {
    // An empty set would let the authorization server apply its own defaults,
    // which is how a request ends up broader than intended.
    if scopes.is_empty() {
        return Err(anyhow!(
            "refusing to start an authorization with an empty scope set"
        ));
    }

    let client_data = &client.registry.client_data;

    let mut config = client_data.config.clone();
    config.scopes = Scopes::from_scopes(scopes.iter().cloned().map(|s| s.convert()))
        .map_err(|e| anyhow!("invalid authorization scopes: {e:?}"))?;
    if let Some(redirect_uri) = redirect_uri {
        config.redirect_uris = vec![redirect_uri];
    }

    let client_metadata = atproto_client_metadata(&config, &client_data.keyset)
        .map_err(|e| anyhow!("failed to derive client metadata: {e:?}"))?;

    let (server_metadata, identity) = client
        .client
        .resolve_oauth(identifier)
        .await
        .map_err(|e| anyhow!("identity resolution failed: {e:?}"))?;

    // Matches `start_auth`: a login hint is only sent when the identifier
    // actually resolved to an identity, never for a bare PDS host.
    let login_hint: Option<SmolStr> = identity.is_some().then(|| identifier.to_smolstr());

    let mut metadata = OAuthMetadata {
        server_metadata,
        client_metadata,
        keyset: client_data.keyset.clone(),
    };

    let auth_req_info = par(
        client.client.as_ref(),
        login_hint,
        None,
        &mut metadata,
        Some(state_token.to_smolstr()),
    )
    .await
    .map_err(|e| anyhow!("pushed authorization request failed: {e:?}"))?;

    // The callback resolves the flow out of this store, so persisting is not
    // optional: a lost record turns into an unusable authorization.
    client
        .registry
        .store
        .save_auth_req_info(&auth_req_info)
        .await
        .map_err(|e| anyhow!("failed to persist authorization request: {e:?}"))?;

    Ok(format!(
        "{}?client_id={}&request_uri={}",
        metadata.server_metadata.authorization_endpoint,
        urlencoding::encode(metadata.client_metadata.client_id.as_str()),
        urlencoding::encode(auth_req_info.request_uri.as_str()),
    ))
}
