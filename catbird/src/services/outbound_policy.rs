//! Validated, DNS-pinned transport for requests to attacker-selected hosts.

use jacquard_common::http_client::HttpClient;
use jacquard_common::types::{did::Did, string::Handle};
use jacquard_identity::resolver::{DidDocResponse, IdentityResolver, ResolverOptions};
use reqwest::{header::HeaderMap, Method, Response, Url};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECT_HOPS: usize = 3;

#[derive(Debug, Clone)]
pub struct PolicyError(String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for PolicyError {}

#[derive(Clone, Debug)]
pub struct ValidatedUrl {
    url: Url,
    addresses: Vec<IpAddr>,
}

impl ValidatedUrl {
    pub fn parse(input: &str) -> Result<Self, PolicyError> {
        let url = Url::parse(input).map_err(|e| PolicyError(format!("invalid URL: {e}")))?;
        if url.scheme() != "https" || url.host_str().is_none() {
            return Err(PolicyError(
                "outbound URL must use HTTPS and have a host".into(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(PolicyError(
                "outbound URL cannot contain userinfo or a fragment".into(),
            ));
        }
        Ok(Self {
            url,
            addresses: Vec::new(),
        })
    }

    pub fn require_same_origin(&self, candidate: &str) -> Result<Url, PolicyError> {
        let candidate = Self::parse(candidate)?.url;
        if origin(&self.url) != origin(&candidate) {
            return Err(PolicyError(
                "credential endpoint must have the issuer's exact origin".into(),
            ));
        }
        Ok(candidate)
    }

    pub fn with_addresses(mut self, addresses: Vec<IpAddr>) -> Result<Self, PolicyError> {
        if addresses.is_empty() || addresses.iter().any(|ip| !is_global(*ip)) {
            return Err(PolicyError(
                "DNS result contains a non-global address".into(),
            ));
        }
        addresses.iter().for_each(|ip| {
            if !self.addresses.contains(ip) {
                self.addresses.push(*ip);
            }
        });
        Ok(self)
    }

    #[cfg(test)]
    fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
}

fn origin(url: &Url) -> (&str, &str, u16) {
    (
        url.scheme(),
        url.host_str().expect("validated host"),
        url.port_or_known_default().expect("https port"),
    )
}

#[derive(Clone, Default)]
pub struct OutboundPolicy;

impl OutboundPolicy {
    pub async fn validate(&self, input: &str) -> Result<ValidatedUrl, PolicyError> {
        self.validate_before(input, tokio::time::Instant::now() + REQUEST_TIMEOUT)
            .await
    }

    async fn validate_before(
        &self,
        input: &str,
        deadline: tokio::time::Instant,
    ) -> Result<ValidatedUrl, PolicyError> {
        let parsed = ValidatedUrl::parse(input)?;
        let host = parsed.url.host_str().expect("validated host").to_owned();
        let port = parsed.url.port_or_known_default().expect("https port");
        let answers =
            tokio::time::timeout_at(deadline, tokio::net::lookup_host((host.as_str(), port)))
                .await
                .map_err(|_| PolicyError("outbound request deadline exceeded during DNS".into()))?
                .map_err(|e| PolicyError(format!("DNS resolution failed: {e}")))?
                .map(|address| address.ip())
                .collect();
        parsed.with_addresses(answers)
    }

    pub async fn send(
        &self,
        method: Method,
        input: &str,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
    ) -> Result<Response, PolicyError> {
        self.send_bounded(method, input, headers, body, REQUEST_TIMEOUT)
            .await
            .map(|(response, _)| response)
    }

    pub(crate) async fn send_before(
        &self,
        method: Method,
        input: &str,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
        deadline: tokio::time::Instant,
    ) -> Result<Response, PolicyError> {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| PolicyError("outbound request deadline exceeded".into()))?;
        self.send_bounded(method, input, headers, body, remaining)
            .await
            .map(|(response, _)| response)
    }

    async fn send_bounded(
        &self,
        mut method: Method,
        input: &str,
        headers: HeaderMap,
        mut body: Option<bytes::Bytes>,
        budget: Duration,
    ) -> Result<(Response, tokio::time::Instant), PolicyError> {
        let deadline = tokio::time::Instant::now() + budget;
        let original = ValidatedUrl::parse(input)?;
        let mut current = original.url.clone();
        for hop in 0..=MAX_REDIRECT_HOPS {
            let target = self.validate_before(current.as_str(), deadline).await?;
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .ok_or_else(|| PolicyError("outbound request deadline exceeded".into()))?;
            let response = self
                .send_once(
                    method.clone(),
                    &target,
                    headers.clone(),
                    body.clone(),
                    remaining,
                )
                .await?;
            if !is_followed_redirect(response.status()) {
                return Ok((response, deadline));
            }
            if hop == MAX_REDIRECT_HOPS {
                return Err(PolicyError("outbound redirect limit exceeded".into()));
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| PolicyError("redirect missing valid Location".into()))?;
            let next = current
                .join(location)
                .map_err(|e| PolicyError(format!("invalid redirect Location: {e}")))?;
            original.require_same_origin(next.as_str())?;
            if matches!(response.status().as_u16(), 301..=303) {
                method = Method::GET;
                body = None;
            }
            current = next;
        }
        unreachable!("bounded redirect loop returns")
    }

    async fn send_once(
        &self,
        method: Method,
        target: &ValidatedUrl,
        headers: HeaderMap,
        body: Option<bytes::Bytes>,
        remaining: Duration,
    ) -> Result<Response, PolicyError> {
        let host = target.url.host_str().expect("validated host");
        let port = target.url.port_or_known_default().expect("https port");
        let pinned: Vec<_> = target
            .addresses
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT.min(remaining))
            .timeout(remaining)
            .resolve_to_addrs(host, &pinned)
            .build()
            .map_err(|e| PolicyError(format!("HTTP client setup failed: {e}")))?;
        let mut request = client.request(method, target.url.clone()).headers(headers);
        if let Some(body) = body {
            request = request.body(body);
        }
        request
            .send()
            .await
            .map_err(|e| PolicyError(format!("outbound request failed: {e}")))
    }
}

impl HttpClient for OutboundPolicy {
    type Error = PolicyError;

    async fn send_http(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, Self::Error> {
        let (parts, body) = request.into_parts();
        let method = Method::from_bytes(parts.method.as_str().as_bytes())
            .map_err(|e| PolicyError(format!("invalid method: {e}")))?;
        let (response, deadline) = self
            .send_bounded(
                method,
                &parts.uri.to_string(),
                parts.headers,
                Some(body.into()),
                REQUEST_TIMEOUT,
            )
            .await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = tokio::time::timeout_at(deadline, response.bytes())
            .await
            .map_err(|_| PolicyError("outbound request deadline exceeded reading body".into()))?
            .map_err(|e| PolicyError(format!("response read failed: {e}")))?;
        let mut builder = http::Response::builder().status(status);
        *builder.headers_mut().expect("response builder headers") = headers;
        builder
            .body(bytes.to_vec())
            .map_err(|e| PolicyError(format!("response build failed: {e}")))
    }
}

#[derive(Clone)]
pub struct PolicyOAuthResolver {
    identity: jacquard_identity::JacquardResolver<OutboundPolicy>,
    policy: OutboundPolicy,
}

impl PolicyOAuthResolver {
    pub fn new(identity: jacquard_identity::JacquardResolver<OutboundPolicy>) -> Self {
        Self {
            identity,
            policy: OutboundPolicy,
        }
    }
}

impl HttpClient for PolicyOAuthResolver {
    type Error = PolicyError;
    async fn send_http(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, Self::Error> {
        self.policy.send_http(request).await
    }
}

impl IdentityResolver for PolicyOAuthResolver {
    fn options(&self) -> &ResolverOptions {
        self.identity.options()
    }
    async fn resolve_handle(
        &self,
        handle: &Handle<'_>,
    ) -> jacquard_identity::resolver::Result<Did<'static>> {
        self.identity.resolve_handle(handle).await
    }
    async fn resolve_did_doc(
        &self,
        did: &Did<'_>,
    ) -> jacquard_identity::resolver::Result<DidDocResponse> {
        self.identity.resolve_did_doc(did).await
    }
}

impl jacquard_oauth::resolver::OAuthResolver for PolicyOAuthResolver {}
impl jacquard_oauth::dpop::DpopExt for PolicyOAuthResolver {}

pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_v4(ip),
        IpAddr::V6(ip) => is_global_v6(ip),
    }
}

fn is_followed_redirect(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 224
        || ip.is_broadcast()
        || ip.is_documentation())
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_global_v4(v4);
    }
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] == 0
            && segments[1] == 0
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0)
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)
        || (segments[0] == 0x0100 && segments[1] == 0)
        || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
        || segments[0] == 0x2002
        || (segments[0] & 0xfff0) == 0x3ff0
        || segments[0] == 0x5f00
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn rejects_non_https_and_ambiguous_urls() {
        for url in [
            "http://example.com/x",
            "https://user@example.com/x",
            "https://example.com/x#fragment",
            "file:///etc/passwd",
        ] {
            assert!(ValidatedUrl::parse(url).is_err(), "accepted {url}");
        }
    }

    #[test]
    fn rejects_private_and_mixed_dns_answers() {
        let url = ValidatedUrl::parse("https://pds.example/x").unwrap();
        assert!(url
            .clone()
            .with_addresses(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))])
            .is_err());
        assert!(url
            .with_addresses(vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ])
            .is_err());
    }

    #[test]
    fn accepts_only_global_dns_answers_and_retains_them_for_pinning() {
        let addresses = vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
        ];
        let pinned = ValidatedUrl::parse("https://example.com/x")
            .unwrap()
            .with_addresses(addresses.clone())
            .unwrap();
        assert_eq!(pinned.addresses(), addresses.as_slice());
    }

    #[test]
    fn exact_origin_binding_rejects_lookalikes_and_cross_origin_secrets() {
        let issuer = ValidatedUrl::parse("https://auth.example/issuer").unwrap();
        assert!(issuer
            .require_same_origin("https://auth.example/token")
            .is_ok());
        assert!(issuer
            .require_same_origin("https://auth.example.evil/token")
            .is_err());
        assert!(issuer
            .require_same_origin("https://auth.example:444/token")
            .is_err());
    }

    #[test]
    fn global_address_classifier_covers_special_ranges() {
        for ip in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
            "2001:db8::1",
        ] {
            assert!(!is_global(ip.parse().unwrap()), "classified {ip} global");
        }
        assert!(is_global("93.184.216.34".parse().unwrap()));
        assert!(is_global("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn globally_routable_neighbors_of_special_ipv4_ranges_remain_allowed() {
        assert!(is_global("192.0.1.1".parse().unwrap()));
        assert!(is_global("192.88.1.1".parse().unwrap()));
        assert!(!is_global("192.0.0.1".parse().unwrap()));
        assert!(!is_global("192.88.99.1".parse().unwrap()));
    }

    #[test]
    fn only_true_redirect_statuses_are_followed() {
        for status in [301, 302, 303, 307, 308] {
            assert!(is_followed_redirect(StatusCode::from_u16(status).unwrap()));
        }
        for status in [300, 304, 305, 306] {
            assert!(!is_followed_redirect(StatusCode::from_u16(status).unwrap()));
        }
    }

    #[test]
    fn rejects_all_reviewed_special_use_and_compatible_forms() {
        for ip in [
            "192.0.0.1",
            "192.88.99.1",
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "100::1",
            "2001:2::1",
            "2001:20::1",
            "2002:7f00:1::1",
            "3fff::1",
            "5f00::1",
        ] {
            assert!(!is_global(ip.parse().unwrap()), "classified {ip} global");
        }
    }

    #[tokio::test]
    async fn zero_remaining_budget_opens_no_socket() {
        let error = OutboundPolicy
            .send_bounded(
                Method::GET,
                "https://example.com/",
                HeaderMap::new(),
                None,
                Duration::ZERO,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("deadline exceeded"));
    }

    #[tokio::test(start_paused = true)]
    async fn cumulative_deadline_is_not_reset_for_a_retry() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        tokio::time::advance(Duration::from_secs(31)).await;
        let error = OutboundPolicy
            .send_before(
                Method::GET,
                "https://example.com/",
                HeaderMap::new(),
                None,
                deadline,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("deadline exceeded"));
    }

    #[tokio::test]
    async fn did_web_identity_fetch_uses_policy_and_rejects_loopback() {
        let resolver =
            jacquard_identity::JacquardResolver::new(OutboundPolicy, ResolverOptions::default());
        let did = Did::new("did:web:127.0.0.1").unwrap();
        assert!(resolver.resolve_did_doc(&did).await.is_err());
    }
}
