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
        tracing::warn!(error = %e, "SSRF: Invalid URL format");
        AppError::BadRequest(format!("Invalid PDS URL: {}", e))
    })?;

    // Check scheme
    let scheme = parsed.scheme();
    let is_http = scheme == "http";
    let is_https = scheme == "https";

    if !is_http && !is_https {
        tracing::warn!(scheme = %scheme, "SSRF: Blocked non-HTTP(S) scheme");
        return Err(AppError::BadRequest(format!(
            "Invalid PDS URL: scheme '{}' not allowed",
            scheme
        )));
    }

    // Get host using url crate's proper host parsing (handles IPv4, IPv6, and domains)
    let host = parsed.host().ok_or_else(|| {
        tracing::warn!(scheme = %scheme, "SSRF: URL has no host");
        AppError::BadRequest("Invalid PDS URL: no host specified".to_string())
    })?;

    let host_str = host.to_string();

    match host {
        Host::Ipv4(ipv4) => {
            #[cfg(debug_assertions)]
            if ipv4.is_loopback() {
                tracing::debug!(scheme = %scheme, host = %host_str, "SSRF: Allowing loopback in debug mode");
                return Ok(());
            }
            if is_private_ipv4(&ipv4) {
                tracing::warn!(scheme = %scheme, ip = %ipv4, "SSRF: Blocked private/loopback IPv4");
                return Err(AppError::BadRequest(
                    "Invalid PDS URL: private network not allowed".to_string(),
                ));
            }
        }
        Host::Ipv6(ipv6) => {
            if is_private_ipv6(&ipv6) {
                tracing::warn!(scheme = %scheme, ip = %ipv6, "SSRF: Blocked private/loopback IPv6");
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
                    tracing::debug!(scheme = %scheme, host = %host_str, "SSRF: Allowing localhost in debug mode");
                    return Ok(());
                }

                // In release mode, block localhost entirely
                #[cfg(not(debug_assertions))]
                {
                    tracing::warn!(scheme = %scheme, host = %host_str, "SSRF: Blocked localhost in release mode");
                    return Err(AppError::BadRequest(
                        "Invalid PDS URL: localhost not allowed".to_string(),
                    ));
                }
            }
        }
    }

    // HTTP is only allowed for localhost (handled above for Domain case)
    if is_http {
        tracing::warn!(scheme = %scheme, host = %host_str, "SSRF: HTTP not allowed for non-localhost");
        return Err(AppError::BadRequest(
            "Invalid PDS URL: HTTPS required".to_string(),
        ));
    }

    Ok(())
}

/// Check if an IP address is in a private, loopback, or otherwise restricted range
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

/// Check if an IPv4 address is private/restricted
pub fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();

    // Current network ("this host"): 0.0.0.0/8
    if octets[0] == 0 {
        return true;
    }

    // Loopback: 127.0.0.0/8
    if ip.is_loopback() || octets[0] == 127 {
        return true;
    }

    // Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if octets[0] == 10 {
        return true;
    }
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return true;
    }
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    // Carrier-grade NAT / Shared address space: 100.64.0.0/10
    if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
        return true;
    }

    // Link-local: 169.254.0.0/16
    if ip.is_link_local() || (octets[0] == 169 && octets[1] == 254) {
        return true;
    }

    // IETF Protocol Assignments: 192.0.0.0/24
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }

    // Documentation ranges: 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return true;
    }

    // 6to4 relay anycast: 192.88.99.0/24
    if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
        return true;
    }

    // RFC 2544 Benchmarking: 198.18.0.0/15 (198.18.0.0 - 198.19.255.255)
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return true;
    }

    // Multicast: 224.0.0.0/4 (224.0.0.0 - 239.255.255.255)
    if ip.is_multicast() || (octets[0] >= 224 && octets[0] <= 239) {
        return true;
    }

    // Reserved for future use / Broadcast: 240.0.0.0/4 (240.0.0.0 - 255.255.255.255)
    if octets[0] >= 240 {
        return true;
    }

    // Broadcast
    if ip.is_broadcast() {
        return true;
    }

    false
}

/// Check if an IPv6 address is private/restricted
pub fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // Loopback: ::1
    if ip.is_loopback() {
        return true;
    }

    // Unspecified: ::
    if ip.is_unspecified() {
        return true;
    }

    // Multicast: ff00::/8
    if ip.is_multicast() {
        return true;
    }
    let segments = ip.segments();
    if (segments[0] & 0xff00) == 0xff00 {
        return true;
    }

    // Unique local addresses: fc00::/7 (fc00:: - fdff::)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // Link-local: fe80::/10 (fe80:: - febf::)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    // Deprecated Site-Local: fec0::/10 (fec0:: - feff::, RFC 3879)
    if (segments[0] & 0xffc0) == 0xfec0 {
        return true;
    }

    // Documentation: 2001:db8::/32 (RFC 3849)
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }

    // Benchmarking: 2001:2::/48 (RFC 5180, RFC 8218)
    if segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0x0000 {
        return true;
    }

    // Documentation: 3fff::/20 (RFC 9637)
    if segments[0] == 0x3fff && (segments[1] & 0xf000) == 0x0000 {
        return true;
    }

    // Discard-Only Address Block: 100::/64 (RFC 6666) and Dummy IPv6 Prefix: 100:0:0:1::/64 (RFC 8504)
    if segments[0] == 0x0100
        && segments[1] == 0
        && segments[2] == 0
        && (segments[3] == 0 || segments[3] == 1)
    {
        return true;
    }

    // Local-Use IPv4/IPv6 Translation: 64:ff9b:1::/48 (RFC 8215)
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001 {
        return true;
    }

    // IPv4/IPv6 translation: 64:ff9b::/96 (RFC 6052)
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        return true;
    }

    // 6to4: 2002::/16
    if segments[0] == 0x2002 {
        return true;
    }

    // Segment Routing over IPv6 (SRv6) SIDs: 5f00::/16 (RFC 9602)
    if segments[0] == 0x5f00 {
        return true;
    }

    // IPv4-mapped addresses: ::ffff:0:0/96
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&ipv4);
    }

    // IPv4-translated (SIIT): ::ffff:0:0:0/96
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        let octet0 = (segments[6] >> 8) as u8;
        let octet1 = (segments[6] & 0xff) as u8;
        let octet2 = (segments[7] >> 8) as u8;
        let octet3 = (segments[7] & 0xff) as u8;
        return is_private_ipv4(&Ipv4Addr::new(octet0, octet1, octet2, octet3));
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
        // Loopback is checked via is_private_ipv4 (allowed in debug mode for WireMock)
        assert!(is_private_ipv4(&std::net::Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ipv4(&std::net::Ipv4Addr::new(127, 0, 0, 2)));

        #[cfg(not(debug_assertions))]
        {
            assert!(validate_pds_url("https://127.0.0.1").is_err());
            assert!(validate_pds_url("https://127.0.0.2").is_err());
        }
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
    fn test_blocks_special_and_non_global_ranges() {
        // RFC 2544 benchmarking: 198.18.0.0/15
        assert!(validate_pds_url("https://198.18.0.1").is_err());
        assert!(validate_pds_url("https://198.19.255.254").is_err());

        // IPv4 Multicast: 224.0.0.0/4
        assert!(validate_pds_url("https://224.0.0.1").is_err());
        assert!(validate_pds_url("https://239.255.255.250").is_err());

        // IPv4 Reserved: 240.0.0.0/4
        assert!(validate_pds_url("https://240.0.0.1").is_err());
        assert!(validate_pds_url("https://255.255.255.255").is_err());

        // IPv6 Multicast: ff00::/8
        assert!(validate_pds_url("https://[ff00::1]").is_err());
        assert!(validate_pds_url("https://[ff02::1]").is_err());
        assert!(validate_pds_url("https://[ff0e::1]").is_err());

        // IPv6 Documentation: 2001:db8::/32
        assert!(validate_pds_url("https://[2001:db8::1]").is_err());

        // IPv6 Discard prefix: 100::/64 and Dummy IPv6 prefix: 100:0:0:1::/64
        assert!(validate_pds_url("https://[100::1]").is_err());
        assert!(validate_pds_url("https://[100:0:0:1::1]").is_err());
        assert!(validate_pds_url("https://[100:0:0:2::1]").is_ok());
        // IPv6 IPv4-translated: 64:ff9b::/96
        assert!(validate_pds_url("https://[64:ff9b::1]").is_err());

        // IPv6 Local-Use IPv4/IPv6 Translation: 64:ff9b:1::/48 (RFC 8215)
        assert!(validate_pds_url("https://[64:ff9b:1::]").is_err()); // start
        assert!(validate_pds_url("https://[64:ff9b:1:ffff:ffff:ffff:ffff:ffff]").is_err()); // end
        assert!(validate_pds_url("https://[64:ff9b:0:1::]").is_ok()); // outside
        assert!(validate_pds_url("https://[64:ff9b:2::]").is_ok()); // outside

        // IPv6 Benchmarking: 2001:2::/48 (RFC 5180)
        assert!(validate_pds_url("https://[2001:2::]").is_err()); // start
        assert!(validate_pds_url("https://[2001:2:0:ffff:ffff:ffff:ffff:ffff]").is_err()); // end
        assert!(validate_pds_url("https://[2001:2:1::]").is_ok()); // outside
        assert!(validate_pds_url("https://[2001:1:ffff:ffff:ffff:ffff:ffff:ffff]").is_ok()); // outside
        assert!(validate_pds_url("https://[2001:3::]").is_ok()); // outside

        // IPv6 SRv6 SIDs: 5f00::/16 (RFC 9602)
        assert!(validate_pds_url("https://[5f00::1]").is_err());
        assert!(validate_pds_url("https://[5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff]").is_err());
        assert!(validate_pds_url("https://[5f01::1]").is_ok());
        // IPv6 Deprecated Site-Local: fec0::/10 (RFC 3879)
        assert!(validate_pds_url("https://[fec0::]").is_err()); // start
        assert!(validate_pds_url("https://[feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]").is_err()); // end
        assert!(validate_pds_url("https://[fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff]").is_ok()); // outside

        // IPv6 Documentation: 3fff::/20 (RFC 9637)
        assert!(validate_pds_url("https://[3fff::]").is_err()); // start
        assert!(validate_pds_url("https://[3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff]").is_err()); // end
        assert!(validate_pds_url("https://[3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff]").is_ok()); // outside
        assert!(validate_pds_url("https://[3fff:1000::]").is_ok()); // outside
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
