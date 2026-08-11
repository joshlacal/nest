//! Per-origin DPoP nonce cache
//!
//! Every upstream XRPC request nest makes is DPoP-bound, and per RFC 9449 a
//! fresh server-issued nonce must be embedded in the proof once the server
//! starts requiring one. Historically nest always sent attempt 1 with no
//! nonce, ate the guaranteed `use_dpop_nonce` 401, then retried with the
//! nonce from that challenge — two round trips for every single upstream
//! call. This cache remembers the most recently observed nonce per upstream
//! *origin* (scheme+host+port) so attempt 1 can supply it directly.
//!
//! Nonces are strictly origin-scoped (RFC 9449 §8: a client MUST NOT use a
//! nonce received from one resource server when making a request to a
//! different one) — the cache key is the request's RFC 6454 origin, never
//! the full URL or just the host, so two different ports/schemes on the
//! same hostname never share a nonce.
use dashmap::DashMap;

/// Maximum number of distinct origins tracked at once. Bounds memory growth
/// if nest ends up talking to a large or hostile set of distinct upstream
/// hosts (e.g. many self-hosted PDSes) — without a cap an attacker could
/// grow this map without limit simply by causing requests to many distinct
/// origins.
const MAX_ORIGINS: usize = 4096;

/// Process-wide, concurrency-safe cache of the most recently observed DPoP
/// nonce per upstream origin. Shared across the XRPC proxy path
/// (`AtProtoClient::proxy_request`) and the chat poller
/// (`chat_poll::poller`) so a nonce learned via one path can save a round
/// trip on the other the next time either talks to the same origin.
///
/// Locking: backed by `dashmap::DashMap`, which shards its internal
/// `RwLock`s so concurrent reads/writes to different origins don't
/// contend — appropriate here since every upstream request (hundreds of
/// thousands/day) touches this cache at least once.
#[derive(Default)]
pub struct DpopNonceCache {
    entries: DashMap<String, String>,
}

impl DpopNonceCache {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Derive the RFC 6454 origin (scheme://host[:port]) cache key for a
    /// request URL. Returns `None` if the URL doesn't parse (shouldn't
    /// happen for URLs built from an already SSRF-validated PDS URL, but
    /// callers must treat `None` as "don't use the cache" rather than
    /// falling back to a coarser key).
    pub fn origin_key(url: &str) -> Option<String> {
        let parsed = url::Url::parse(url).ok()?;
        let origin = parsed.origin();
        if origin.is_tuple() {
            Some(origin.ascii_serialization())
        } else {
            None
        }
    }

    /// Look up the cached nonce for `origin`, if any.
    pub fn get(&self, origin: &str) -> Option<String> {
        self.entries.get(origin).map(|entry| entry.value().clone())
    }

    /// Record the latest nonce advertised by `origin`. Call this for every
    /// response that carries a `DPoP-Nonce` header — including successful
    /// (2xx) responses, not just `use_dpop_nonce` challenges, since servers
    /// commonly rotate nonces and hand out the next one on success too.
    /// Always overwrites: the newest nonce observed for an origin wins,
    /// which is exactly what rotation requires.
    pub fn set(&self, origin: String, nonce: String) {
        if nonce.is_empty() {
            return;
        }
        if !self.entries.contains_key(&origin) && self.entries.len() >= MAX_ORIGINS {
            // Bound growth. DashMap has no LRU/insertion ordering, so this
            // is a coarse "evict something" rather than a true LRU evict —
            // acceptable because eviction only ever costs the evicted
            // origin one extra round trip on its next request (it just
            // falls back to the old always-two-round-trips behavior), it
            // never causes incorrect nonce reuse.
            //
            // The victim key MUST be bound to a local before `remove`. In an
            // `if let`, temporaries in the scrutinee live until the end of the
            // block, so `self.entries.iter()`'s shard *read* guard would still
            // be held when `remove` asks for a *write* lock on that same shard
            // — a self-deadlock that hangs the calling thread forever once the
            // map reaches MAX_ORIGINS. Binding first drops the iterator at the
            // end of this statement.
            let evict_key = self.entries.iter().next().map(|e| e.key().clone());
            if let Some(evict_key) = evict_key {
                self.entries.remove(&evict_key);
            }
        }
        self.entries.insert(origin, nonce);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_key_ignores_path_and_query() {
        let a = DpopNonceCache::origin_key("https://pds.example.com/xrpc/foo?x=1").unwrap();
        let b = DpopNonceCache::origin_key("https://pds.example.com/xrpc/bar").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn origin_key_distinguishes_scheme_and_port() {
        let https = DpopNonceCache::origin_key("https://pds.example.com/xrpc/foo").unwrap();
        let http = DpopNonceCache::origin_key("http://pds.example.com/xrpc/foo").unwrap();
        let alt_port = DpopNonceCache::origin_key("https://pds.example.com:8443/xrpc/foo").unwrap();
        assert_ne!(https, http);
        assert_ne!(https, alt_port);
    }

    #[test]
    fn get_set_roundtrip_and_overwrite() {
        let cache = DpopNonceCache::new();
        let origin = "https://pds.example.com".to_string();
        assert_eq!(cache.get(&origin), None);

        cache.set(origin.clone(), "nonce-1".to_string());
        assert_eq!(cache.get(&origin), Some("nonce-1".to_string()));

        // Rotation: newest nonce wins.
        cache.set(origin.clone(), "nonce-2".to_string());
        assert_eq!(cache.get(&origin), Some("nonce-2".to_string()));
    }

    #[test]
    fn different_origins_never_share_a_nonce() {
        let cache = DpopNonceCache::new();
        cache.set("https://a.example.com".to_string(), "nonce-a".to_string());
        cache.set("https://b.example.com".to_string(), "nonce-b".to_string());
        assert_eq!(
            cache.get("https://a.example.com"),
            Some("nonce-a".to_string())
        );
        assert_eq!(
            cache.get("https://b.example.com"),
            Some("nonce-b".to_string())
        );
    }

    #[test]
    fn empty_nonce_is_not_stored() {
        let cache = DpopNonceCache::new();
        cache.set("https://a.example.com".to_string(), String::new());
        assert_eq!(cache.get("https://a.example.com"), None);
    }

    #[test]
    fn bounded_size_evicts_under_pressure() {
        let cache = DpopNonceCache::new();
        for i in 0..(MAX_ORIGINS + 10) {
            cache.set(format!("https://host{i}.example.com"), "n".to_string());
        }
        assert!(cache.entries.len() <= MAX_ORIGINS);
    }
}
