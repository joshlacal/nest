use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::string::{Did, Handle, UriValue};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

#[derive(Clone)]
pub struct CachedProfile {
    pub profile: ProfileViewBasic,
    pub cached_at: Instant,
}

pub struct ProfileHydrator {
    cache: Arc<RwLock<HashMap<String, CachedProfile>>>,
    http_client: reqwest::Client,
    public_appview_url: String,
}

impl ProfileHydrator {
    pub fn new(public_appview_url: String, http_client: reqwest::Client) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            http_client,
            public_appview_url: public_appview_url.trim_end_matches('/').to_string(),
        }
    }

    pub fn unavailable_profile(did: &str) -> ProfileViewBasic {
        ProfileViewBasic {
            did: Did::new(SmolStr::new(did)).unwrap_or_else(|_| {
                Did::new(SmolStr::new("did:plc:unknown")).unwrap()
            }),
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
        let url = format!("{}/xrpc/app.bsky.actor.getProfile?actor={}", self.public_appview_url, did);
        let fetched_profile = match self.http_client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(val) => {
                        let did_val = val.get("did").and_then(|v| v.as_str()).unwrap_or(did);
                        let handle_val = val.get("handle").and_then(|v| v.as_str()).unwrap_or("handle.invalid");
                        let display_name = val.get("displayName").and_then(|v| v.as_str()).map(SmolStr::new);
                        let avatar = val.get("avatar").and_then(|v| v.as_str()).and_then(|s| UriValue::new(SmolStr::new(s)).ok());

                        ProfileViewBasic {
                            did: Did::new(SmolStr::new(did_val)).unwrap_or_else(|_| {
                                Did::new(SmolStr::new(did)).unwrap_or_else(|_| Did::new(SmolStr::new("did:plc:unknown")).unwrap())
                            }),
                            handle: Handle::new(SmolStr::new(handle_val)).unwrap_or_else(|_| Handle::new(SmolStr::new("handle.invalid")).unwrap()),
                            display_name,
                            avatar,
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
                    Err(_) => Self::unavailable_profile(did),
                }
            }
            _ => Self::unavailable_profile(did),
        };

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

    pub async fn set_cached_profile(&self, did: &str, profile: ProfileViewBasic) {
        let mut cache = self.cache.write().await;
        cache.insert(
            did.to_string(),
            CachedProfile {
                profile,
                cached_at: Instant::now(),
            },
        );
    }
}
