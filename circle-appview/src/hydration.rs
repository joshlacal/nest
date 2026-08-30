use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::string::{Did, Handle};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes
pub const MAX_PROFILE_CACHE_CAPACITY: usize = 10_000;
#[derive(Clone)]
pub struct CachedProfile {
    pub profile: ProfileViewBasic,
    pub cached_at: Instant,
}

#[derive(Clone)]
pub struct ProfileHydrator {
    cache: Arc<RwLock<HashMap<String, CachedProfile>>>,
    http_client: reqwest::Client,
    public_appview_url: String,
    capacity: usize,
    semaphore: Arc<tokio::sync::Semaphore>,
}

impl ProfileHydrator {
    pub fn new(public_appview_url: String, http_client: reqwest::Client) -> Self {
        Self::with_capacity(public_appview_url, http_client, MAX_PROFILE_CACHE_CAPACITY)
    }

    pub fn with_capacity(
        public_appview_url: String,
        http_client: reqwest::Client,
        capacity: usize,
    ) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            http_client,
            public_appview_url: public_appview_url.trim_end_matches('/').to_string(),
            capacity,
            semaphore: Arc::new(tokio::sync::Semaphore::new(8)),
        }
    }

    pub fn unavailable_profile(did: &str) -> ProfileViewBasic {
        let did_val = Did::new(SmolStr::new(did)).unwrap_or_else(|_| {
            panic!("Invalid DID format: {did}");
        });
        ProfileViewBasic {
            did: did_val,
            handle: Handle::new(SmolStr::new("handle.invalid")).unwrap(),
            display_name: None,
            avatar: None,
            associated: None,
            viewer: None,
            labels: None,
            created_at: None,
            pronouns: None,
            status: None,
            verification: None,
            debug: None,
            extra_data: None,
        }
    }

    async fn fetch_remote_profile(&self, did: &str) -> ProfileViewBasic {
        let _permit = match self.semaphore.acquire().await {
            Ok(permit) => permit,
            Err(_) => return Self::unavailable_profile(did),
        };
        let url = format!(
            "{}/xrpc/app.bsky.actor.getProfile?actor={}",
            self.public_appview_url, did
        );
        match self.http_client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<catbird_atproto::generated::app_bsky::actor::get_profile::GetProfileOutput>().await {
                    Ok(output) => {
                        let detailed = output.value;
                        // Verify requested DID matches returned DID exactly
                        if detailed.did.as_str() != did {
                            return Self::unavailable_profile(did);
                        }
                        ProfileViewBasic {
                            did: detailed.did,
                            handle: detailed.handle,
                            display_name: detailed.display_name,
                            avatar: detailed.avatar,
                            associated: detailed.associated,
                            viewer: None,
                            labels: detailed.labels,
                            created_at: detailed.created_at,
                            pronouns: detailed.pronouns,
                            status: detailed.status,
                            verification: detailed.verification,
                            debug: detailed.debug,
                            extra_data: detailed.extra_data,
                        }
                    }
                    Err(_) => Self::unavailable_profile(did),
                }
            }
            _ => Self::unavailable_profile(did),
        }
    }

    pub async fn get_profile(&self, did: &str) -> ProfileViewBasic {
        // 1. Check in-memory cache
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(did) {
                if cached.cached_at.elapsed() < CACHE_TTL {
                    return cached.profile.clone();
                }
            }
        }

        // 2. Fetch from public AppView without leaking any private tokens or data
        let fetched_profile = self.fetch_remote_profile(did).await;

        // 3. Store in cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                did.to_string(),
                CachedProfile {
                    profile: fetched_profile.clone(),
                    cached_at: Instant::now(),
                },
            );
        }

        fetched_profile
    }

    pub async fn get_profiles(&self, dids: &[&str]) -> HashMap<String, ProfileViewBasic> {
        let unique_dids: Vec<String> = dids
            .iter()
            .map(|d| d.to_string())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let mut results = HashMap::with_capacity(unique_dids.len());
        let mut to_fetch = Vec::new();

        // 1. Check cache
        {
            let cache = self.cache.read().await;
            for did in &unique_dids {
                if let Some(cached) = cache.get(did) {
                    if cached.cached_at.elapsed() < CACHE_TTL {
                        results.insert(did.clone(), cached.profile.clone());
                        continue;
                    }
                }
                to_fetch.push(did.clone());
            }
        }

        if to_fetch.is_empty() {
            return results;
        }
        // 2. Fetch uncached with bounded concurrency 8 using shared service semaphore
        let mut handles = Vec::with_capacity(to_fetch.len());

        for did in to_fetch {
            let this = self.clone();
            handles.push(tokio::spawn(async move {
                let profile = this.fetch_remote_profile(&did).await;
                (did, profile)
            }));
        }
        let mut cache_entries = Vec::with_capacity(handles.len());
        for handle in handles {
            if let Ok((did, profile)) = handle.await {
                results.insert(did.clone(), profile.clone());
                cache_entries.push((did, profile));
            }
        }

        // 3. Store newly fetched profiles in cache
        {
            let mut cache = self.cache.write().await;
            let now = Instant::now();
            cache.retain(|_, v| now.duration_since(v.cached_at) < CACHE_TTL);
            for (did, profile) in cache_entries {
                if cache.len() >= self.capacity && !cache.contains_key(&did) {
                    if let Some(oldest_key) = cache
                        .iter()
                        .min_by_key(|(_, v)| v.cached_at)
                        .map(|(k, _)| k.clone())
                    {
                        cache.remove(&oldest_key);
                    }
                }
                cache.insert(
                    did,
                    CachedProfile {
                        profile,
                        cached_at: now,
                    },
                );
            }
        }

        results
    }

    pub async fn set_cached_profile(&self, did: &str, profile: ProfileViewBasic) {
        self.set_cached_profile_with_time(did, profile, Instant::now())
            .await;
    }

    pub async fn set_cached_profile_with_time(
        &self,
        did: &str,
        profile: ProfileViewBasic,
        cached_at: Instant,
    ) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        cache.retain(|_, v| now.duration_since(v.cached_at) < CACHE_TTL);
        if cache.len() >= self.capacity && !cache.contains_key(did) {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, v)| v.cached_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }
        cache.insert(did.to_string(), CachedProfile { profile, cached_at });
    }

    pub async fn cached_count(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }
}
