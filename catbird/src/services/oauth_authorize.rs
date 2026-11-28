//! Enforce Nest’s confidential client endpoint policy and choose per-request scopes.

use crate::services::gateway_scope::Scope;
use crate::{config::GatewayOAuth, services::validate_pds_url};
use anyhow::{anyhow, Result};
use url::Url;

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

pub async fn start_auth_with_scopes(
    client: &GatewayOAuth,
    identifier: &str,
    scopes: &[Scope],
    route: &str,
    redirect: Option<Url>,
) -> Result<String> {
    start_auth_with_raw_scopes(client, identifier, scopes, &[], route, redirect).await
}

pub async fn start_auth_with_raw_scopes(
    client: &GatewayOAuth,
    identifier: &str,
    scopes: &[Scope],
    raw: &[String],
    route: &str,
    redirect: Option<Url>,
) -> Result<String> {
    if redirect.as_ref().is_some_and(|url| url != &client.redirect) {
        return Err(anyhow!("callback must match configured OAuth profile"));
    }
    if scopes.is_empty() {
        return Err(anyhow!("empty authorization scope set"));
    }
    let scope = if raw.is_empty() {
        scopes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        raw.join(" ")
    };
    client.start(identifier, &scope, route).await
}

#[cfg(test)]
mod tests {
    use super::*;

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
