//! SSRF Protection
//!
//! Validates URLs to prevent Server-Side Request Forgery attacks by blocking
//! requests to private networks, loopback addresses, and other potentially
//! dangerous destinations.

use crate::error::{AppError, AppResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

/// Validates a PDS URL to prevent SSRF attacks.
///
/// This function checks that:
/// 1. The URL is valid and parseable
/// 2. The scheme is HTTPS (HTTP only allowed for localhost in debug mode)
/// 3. The host is not a private/loopback IP address
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
            if is_private_ipv4(&ipv4) {
                tracing::warn!(url = %url, ip = %ipv4, "SSRF: Blocked private/loopback IPv4");
                return Err(AppError::BadRequest(
                    "Invalid PDS URL: private network not allowed".to_string(),
                ));
            }
        }
        Host::Ipv6(ipv6) => {
            if is_private_ipv6(&ipv6) {
                tracing::warn!(url = %url, ip = %ipv6, "SSRF: Blocked private/loopback IPv6");
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

/// Check if an IP address is in a private, loopback, or otherwise restricted range
#[allow(dead_code)]
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

/// Check if an IPv4 address is private/restricted
fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    // Loopback: 127.0.0.0/8
    if ip.is_loopback() {
        return true;
    }

    // Private ranges
    // 10.0.0.0/8
    if ip.octets()[0] == 10 {
        return true;
    }

    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if ip.octets()[0] == 172 && (ip.octets()[1] >= 16 && ip.octets()[1] <= 31) {
        return true;
    }

    // 192.168.0.0/16
    if ip.octets()[0] == 192 && ip.octets()[1] == 168 {
        return true;
    }

    // Link-local: 169.254.0.0/16
    if ip.is_link_local() {
        return true;
    }

    // Broadcast: 255.255.255.255
    if ip.is_broadcast() {
        return true;
    }

    // Unspecified: 0.0.0.0
    if ip.is_unspecified() {
        return true;
    }

    // Documentation ranges (TEST-NET)
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 2)
        || (ip.octets()[0] == 198 && ip.octets()[1] == 51 && ip.octets()[2] == 100)
        || (ip.octets()[0] == 203 && ip.octets()[1] == 0 && ip.octets()[2] == 113)
    {
        return true;
    }

    // Carrier-grade NAT: 100.64.0.0/10
    if ip.octets()[0] == 100 && (ip.octets()[1] >= 64 && ip.octets()[1] <= 127) {
        return true;
    }

    false
}

/// Check if an IPv6 address is private/restricted
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // Loopback: ::1
    if ip.is_loopback() {
        return true;
    }

    // Unspecified: ::
    if ip.is_unspecified() {
        return true;
    }

    // Unique local addresses: fc00::/7 (fc00:: - fdff::)
    let segments = ip.segments();
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // Link-local: fe80::/10
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    // IPv4-mapped addresses: ::ffff:0:0/96
    // Check the underlying IPv4 address
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&ipv4);
    }

    false
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
    }

    #[test]
    fn test_172_non_private_range() {
        // 172.0.0.0 - 172.15.255.255 is NOT private
        assert!(validate_pds_url("https://172.15.255.255").is_ok());
        // 172.32.0.0+ is NOT private
        assert!(validate_pds_url("https://172.32.0.1").is_ok());
    }
}
