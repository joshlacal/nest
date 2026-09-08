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
use url::Url;

use crate::config::JacquardOAuthClient;
use crate::services::validate_pds_url;

/// Validates that an OAuth server's discovered endpoints are valid public HTTPS URLs
/// and strictly bound to the issuer's origin to prevent SSRF and proof exfiltration.
pub fn validate_oauth_server_endpoints(
    issuer: &str,
    auth_endpoint: &str,
    token_endpoint: &str,
    par_endpoint: Option<&str>,
    revocation_endpoint: Option<&str>,
) -> Result<()> {
    validate_pds_url(issuer).map_err(|e| anyhow!("Invalid OAuth issuer URL: {e}"))?;
    validate_pds_url(auth_endpoint)
        .map_err(|e| anyhow!("Invalid OAuth authorization endpoint: {e}"))?;
    validate_pds_url(token_endpoint).map_err(|e| anyhow!("Invalid OAuth token endpoint: {e}"))?;

    let issuer_url = Url::parse(issuer).map_err(|e| anyhow!("Failed to parse issuer URL: {e}"))?;
    let auth_url =
        Url::parse(auth_endpoint).map_err(|e| anyhow!("Failed to parse auth endpoint: {e}"))?;
    let token_url =
        Url::parse(token_endpoint).map_err(|e| anyhow!("Failed to parse token endpoint: {e}"))?;

    if auth_url.origin() != issuer_url.origin() {
        return Err(anyhow!(
            "OAuth authorization endpoint origin ({}) does not match issuer origin ({})",
            auth_url.origin().ascii_serialization(),
            issuer_url.origin().ascii_serialization()
        ));
    }

    if token_url.origin() != issuer_url.origin() {
        return Err(anyhow!(
            "OAuth token endpoint origin ({}) does not match issuer origin ({})",
            token_url.origin().ascii_serialization(),
            issuer_url.origin().ascii_serialization()
        ));
    }

    if let Some(par) = par_endpoint {
        validate_pds_url(par).map_err(|e| anyhow!("Invalid OAuth PAR endpoint: {e}"))?;
        let par_url = Url::parse(par).map_err(|e| anyhow!("Failed to parse PAR endpoint: {e}"))?;
        if par_url.origin() != issuer_url.origin() {
            return Err(anyhow!(
                "OAuth PAR endpoint origin ({}) does not match issuer origin ({})",
                par_url.origin().ascii_serialization(),
                issuer_url.origin().ascii_serialization()
            ));
        }
    }

    if let Some(rev) = revocation_endpoint {
        validate_pds_url(rev).map_err(|e| anyhow!("Invalid OAuth revocation endpoint: {e}"))?;
        let rev_url =
            Url::parse(rev).map_err(|e| anyhow!("Failed to parse revocation endpoint: {e}"))?;
        if rev_url.origin() != issuer_url.origin() {
            return Err(anyhow!(
                "OAuth revocation endpoint origin ({}) does not match issuer origin ({})",
                rev_url.origin().ascii_serialization(),
                issuer_url.origin().ascii_serialization()
            ));
        }
    }

    Ok(())
}

/// Normalize only a service URL's empty root path for OAuth discovery.
/// Stored session URLs and the resolver's exact issuer checks remain unchanged.
fn oauth_discovery_identifier(identifier: &str) -> Result<&str> {
    if identifier.starts_with("http://") || identifier.starts_with("https://") {
        validate_pds_url(identifier).map_err(|e| anyhow!("Invalid PDS identifier URL: {e}"))?;
        let uri = jacquard_common::deps::fluent_uri::Uri::parse(identifier)
            .map_err(|e| anyhow!("Invalid PDS identifier URI: {e}"))?;
        if uri.path().as_str() == "/" && uri.query().is_none() && uri.fragment().is_none() {
            return Ok(identifier.trim_end_matches('/'));
        }
    }
    Ok(identifier)
}

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

    let identifier = oauth_discovery_identifier(identifier)?;

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

    // SSRF protection & endpoint-origin binding on discovered OAuth server metadata
    validate_oauth_server_endpoints(
        server_metadata.issuer.as_str(),
        server_metadata.authorization_endpoint.as_str(),
        server_metadata.token_endpoint.as_str(),
        server_metadata
            .pushed_authorization_request_endpoint
            .as_ref()
            .map(|s| s.as_str()),
        server_metadata
            .revocation_endpoint
            .as_ref()
            .map(|s| s.as_str()),
    )?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn discovery_accepts_session_root_slash_but_rejects_wrong_issuer() {
        use jacquard_identity::{resolver::ResolverOptions, JacquardResolver};
        use serde_json::json;
        use wiremock::{matchers::path, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let origin = server.uri();
        Mock::given(path("/.well-known/oauth-protected-resource"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resource": origin,
                "authorization_servers": [origin],
                "scopes_supported": ["atproto"],
            })))
            .mount(&server)
            .await;
        Mock::given(path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": origin,
                "authorization_endpoint": format!("{origin}/oauth/authorize"),
                "token_endpoint": format!("{origin}/oauth/token"),
                "response_types_supported": ["code"],
                "scopes_supported": ["atproto"],
            })))
            .mount(&server)
            .await;

        let resolver = JacquardResolver::new(reqwest::Client::new(), ResolverOptions::default());
        let session_url = format!("{origin}/");
        let metadata = resolver
            .resolve_from_service(oauth_discovery_identifier(&session_url).unwrap())
            .await
            .expect("a session root slash must not prevent OAuth discovery");
        assert_eq!(metadata.issuer.as_str(), origin);

        server.reset().await;
        Mock::given(path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": "https://other.example.com",
                "authorization_endpoint": "https://other.example.com/oauth/authorize",
                "token_endpoint": "https://other.example.com/oauth/token",
                "response_types_supported": ["code"],
                "scopes_supported": ["atproto"],
            })))
            .mount(&server)
            .await;
        assert!(resolver
            .resolve_from_service(oauth_discovery_identifier(&session_url).unwrap())
            .await
            .is_err());
    }

    #[test]
    fn discovery_preserves_non_root_identifiers() {
        for identifier in [
            "did:plc:upgradetestuser",
            "alice.bsky.social",
            "https://pds.example.com",
            "https://pds.example.com/tenant/",
            "https://pds.example.com/?value=/",
            "https://pds.example.com/#fragment/",
        ] {
            assert_eq!(oauth_discovery_identifier(identifier).unwrap(), identifier);
        }
        assert!(oauth_discovery_identifier("https://10.0.0.1/").is_err());
        assert!(oauth_discovery_identifier("http://pds.example.com/").is_err());
    }

    #[test]
    fn test_validate_oauth_server_endpoints_success() {
        let res = validate_oauth_server_endpoints(
            "https://bsky.social",
            "https://bsky.social/oauth/authorize",
            "https://bsky.social/oauth/token",
            Some("https://bsky.social/oauth/par"),
            Some("https://bsky.social/oauth/revoke"),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_validate_oauth_server_endpoints_rejects_private_or_invalid_endpoints() {
        // Private IP in issuer
        assert!(validate_oauth_server_endpoints(
            "https://10.0.0.1",
            "https://10.0.0.1/oauth/authorize",
            "https://10.0.0.1/oauth/token",
            None,
            None,
        )
        .is_err());

        // Private IP in auth endpoint
        assert!(validate_oauth_server_endpoints(
            "https://bsky.social",
            "https://192.168.1.1/oauth/authorize",
            "https://bsky.social/oauth/token",
            None,
            None,
        )
        .is_err());

        // HTTP endpoint
        assert!(validate_oauth_server_endpoints(
            "http://bsky.social",
            "http://bsky.social/oauth/authorize",
            "http://bsky.social/oauth/token",
            None,
            None,
        )
        .is_err());

        // Private IP in revocation endpoint
        assert!(validate_oauth_server_endpoints(
            "https://bsky.social",
            "https://bsky.social/oauth/authorize",
            "https://bsky.social/oauth/token",
            None,
            Some("https://127.0.0.1/oauth/revoke"),
        )
        .is_err());
    }

    #[test]
    fn test_validate_oauth_server_endpoints_rejects_origin_mismatch() {
        // Mismatched token endpoint origin
        let err = validate_oauth_server_endpoints(
            "https://bsky.social",
            "https://bsky.social/oauth/authorize",
            "https://evil.attacker.com/oauth/token",
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match issuer origin"));

        // Mismatched PAR endpoint origin
        let err = validate_oauth_server_endpoints(
            "https://bsky.social",
            "https://bsky.social/oauth/authorize",
            "https://bsky.social/oauth/token",
            Some("https://evil.attacker.com/oauth/par"),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match issuer origin"));

        // Mismatched revocation endpoint origin
        let err = validate_oauth_server_endpoints(
            "https://bsky.social",
            "https://bsky.social/oauth/authorize",
            "https://bsky.social/oauth/token",
            None,
            Some("https://evil.attacker.com/oauth/revoke"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match issuer origin"));
    }
}
