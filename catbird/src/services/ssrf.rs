//! SSRF Protection
//!
//! Validates URLs to prevent Server-Side Request Forgery attacks by blocking
//! requests to private networks, loopback addresses, and other potentially
//! dangerous destinations.

use crate::{
    config::outbound_policy::is_global,
    error::{AppError, AppResult},
};
use std::net::IpAddr;
use url::{Host, Url};

/// Validates a PDS URL to prevent SSRF attacks.
///
/// This function checks that:
/// 1. The URL is valid and parseable
/// 2. The scheme is HTTPS (HTTP only allowed for localhost in debug mode)
/// 3. A literal IP host is allowed by the shared public-address policy
///
/// # Arguments
/// * `url` - The URL string to validate
///
/// # Returns
/// * `Ok(())` if the URL is safe to use
/// * `Err(AppError::BadRequest)` if the URL is blocked
pub fn validate_pds_url(url: &str) -> AppResult<()> {
    let parsed = Url::parse(url).map_err(|e| {
        tracing::warn!(url = %url, error = %e, "SSRF: Invalid URL format");
        AppError::BadRequest(format!("Invalid PDS URL: {}", e))
    })?;

    // Check scheme
    let scheme = parsed.scheme();
    let is_http = scheme == "http";
    let is_https = scheme == "https";

    if !is_http && !is_https {
        tracing::warn!(url = %url, scheme = %scheme, "SSRF: Blocked non-HTTP(S) scheme");
        return Err(AppError::BadRequest(format!(
            "Invalid PDS URL: scheme '{}' not allowed",
            scheme
        )));
    }

    // Get host using url crate's proper host parsing (handles IPv4, IPv6, and domains)
    let host = parsed.host().ok_or_else(|| {
        tracing::warn!(url = %url, "SSRF: URL has no host");
        AppError::BadRequest("Invalid PDS URL: no host specified".to_string())
    })?;

    match host {
        Host::Ipv4(ipv4) => {
            if !is_global(IpAddr::V4(ipv4)) {
                tracing::warn!(url = %url, ip = %ipv4, "SSRF: Blocked non-public IPv4");
                return Err(AppError::BadRequest(
                    "Invalid PDS URL: private network not allowed".to_string(),
                ));
            }
        }
        Host::Ipv6(ipv6) => {
            if !is_global(IpAddr::V6(ipv6)) {
                tracing::warn!(url = %url, ip = %ipv6, "SSRF: Blocked non-public IPv6");
                return Err(AppError::BadRequest(
                    "Invalid PDS URL: private network not allowed".to_string(),
                ));
            }
        }
        Host::Domain(domain) => {
            // Check for localhost variants
            let domain_lower = domain.to_lowercase();
            if is_localhost_hostname(&domain_lower) {
                // Allow localhost only in debug mode with HTTP
                #[cfg(debug_assertions)]
                {
                    if is_http {
                        tracing::debug!(url = %url, "SSRF: Allowing localhost in debug mode");
                        return Ok(());
                    }
                }

                // In release mode, block localhost entirely
                #[cfg(not(debug_assertions))]
                {
                    tracing::warn!(url = %url, "SSRF: Blocked localhost in release mode");
                    return Err(AppError::BadRequest(
                        "Invalid PDS URL: localhost not allowed".to_string(),
                    ));
                }
            }
        }
    }

    // HTTP is only allowed for localhost (handled above for Domain case)
    if is_http {
        tracing::warn!(url = %url, "SSRF: HTTP not allowed for non-localhost");
        return Err(AppError::BadRequest(
            "Invalid PDS URL: HTTPS required".to_string(),
        ));
    }

    Ok(())
}

/// Check if a hostname is a localhost variant
fn is_localhost_hostname(host: &str) -> bool {
    host == "localhost"
        || host == "localhost.localdomain"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_https_url() {
        assert!(validate_pds_url("https://bsky.social").is_ok());
        assert!(validate_pds_url("https://pds.example.com/xrpc/something").is_ok());
    }

    #[test]
    fn test_blocks_private_ipv4() {
        // Loopback
        assert!(validate_pds_url("https://127.0.0.1").is_err());
        assert!(validate_pds_url("https://127.0.0.2").is_err());

        // Private ranges
        assert!(validate_pds_url("https://10.0.0.1").is_err());
        assert!(validate_pds_url("https://10.255.255.255").is_err());
        assert!(validate_pds_url("https://172.16.0.1").is_err());
        assert!(validate_pds_url("https://172.31.255.255").is_err());
        assert!(validate_pds_url("https://192.168.0.1").is_err());
        assert!(validate_pds_url("https://192.168.255.255").is_err());

        // Link-local
        assert!(validate_pds_url("https://169.254.0.1").is_err());
    }

    #[test]
    fn test_blocks_private_ipv6() {
        // Loopback
        assert!(validate_pds_url("https://[::1]").is_err());

        // Unique local
        assert!(validate_pds_url("https://[fc00::1]").is_err());
        assert!(validate_pds_url("https://[fd00::1]").is_err());

        // Link-local
        assert!(validate_pds_url("https://[fe80::1]").is_err());
    }

    #[test]
    fn test_blocks_non_public_ipv6_literals() {
        for ip in [
            "64:ff9b::1",
            "100::1",
            "2001:2::1",
            "2002::1",
            "3fff::1",
            "4000::1",
            "5f00::1",
            "fec0::1",
        ] {
            let url = format!("https://[{ip}]");
            assert!(validate_pds_url(&url).is_err(), "accepted {ip}");
        }
    }

    #[test]
    fn test_blocks_http_for_public_urls() {
        assert!(validate_pds_url("http://bsky.social").is_err());
        assert!(validate_pds_url("http://example.com").is_err());
    }

    #[test]
    fn test_blocks_non_http_schemes() {
        assert!(validate_pds_url("file:///etc/passwd").is_err());
        assert!(validate_pds_url("ftp://example.com").is_err());
        assert!(validate_pds_url("gopher://example.com").is_err());
    }

    #[test]
    fn test_blocks_localhost_variants() {
        // In release mode, all localhost should be blocked
        // In debug mode, HTTP localhost is allowed
        #[cfg(not(debug_assertions))]
        {
            assert!(validate_pds_url("https://localhost").is_err());
            assert!(validate_pds_url("http://localhost").is_err());
            assert!(validate_pds_url("https://test.localhost").is_err());
        }
    }

    #[test]
    fn test_invalid_urls() {
        assert!(validate_pds_url("not-a-url").is_err());
        assert!(validate_pds_url("").is_err());
        assert!(validate_pds_url("https://").is_err());
    }

    #[test]
    fn test_valid_public_ips() {
        // Public IPs should be allowed
        assert!(validate_pds_url("https://8.8.8.8").is_ok());
        assert!(validate_pds_url("https://1.1.1.1").is_ok());
        assert!(validate_pds_url("https://[2606:4700:4700::1111]").is_ok());
    }

    #[test]
    fn test_172_non_private_range() {
        // 172.0.0.0 - 172.15.255.255 is NOT private
        assert!(validate_pds_url("https://172.15.255.255").is_ok());
        // 172.32.0.0+ is NOT private
        assert!(validate_pds_url("https://172.32.0.1").is_ok());
    }
}
