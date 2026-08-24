use crate::{error::AppError, models::{require_circle_scopes, CatbirdSession, CIRCLE_PROTOCOL_REVISION}};
use dashmap::DashMap;
use serde::Serialize;
use std::{future::Future, pin::Pin, sync::Arc, time::{Duration, Instant}};

#[derive(Debug, Clone, Serialize)]
pub struct CircleCapability {
    pub enabled: bool,
    #[serde(rename = "protocolRevision")]
    pub protocol_revision: &'static str,
    #[serde(rename = "supportsImages")]
    pub supports_images: bool,
}

pub trait CircleProbe: Send + Sync {
    fn probe<'a>(&'a self, session: &'a CatbirdSession) -> Pin<Box<dyn Future<Output = Result<bool, AppError>> + Send + 'a>>;
}

struct CachedCapability {
    checked_at: Instant,
    capability: CircleCapability,
}

pub struct CircleCapabilityService<P> {
    probe: P,
    cache: Arc<DashMap<String, CachedCapability>>,
}

impl<P: CircleProbe> CircleCapabilityService<P> {
    pub fn new(probe: P) -> Self {
        Self { probe, cache: Arc::new(DashMap::new()) }
    }

    pub async fn get(&self, session: &CatbirdSession) -> Result<CircleCapability, AppError> {
        require_circle_scopes(session)?;
        let key = format!("{}:{CIRCLE_PROTOCOL_REVISION}", session.pds_url);
        if let Some(cached) = self.cache.get(&key) {
            if cached.checked_at.elapsed() < Duration::from_secs(300) {
                return Ok(cached.capability.clone());
            }
        }

        let supports_images = self.probe.probe(session).await.unwrap_or(false);
        let capability = CircleCapability {
            enabled: supports_images,
            protocol_revision: CIRCLE_PROTOCOL_REVISION,
            supports_images,
        };
        self.cache.insert(key, CachedCapability { checked_at: Instant::now(), capability: capability.clone() });
        Ok(capability)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    struct StubProbe;

    impl CircleProbe for StubProbe {
        fn probe<'a>(&'a self, _session: &'a CatbirdSession) -> Pin<Box<dyn Future<Output = Result<bool, AppError>> + Send + 'a>> {
            Box::pin(async { Ok(false) })
        }
    }

    fn session() -> CatbirdSession {
        let now = Utc::now();
        CatbirdSession {
            id: Uuid::new_v4(),
            did: "did:plc:test".into(),
            handle: "test.example".into(),
            pds_url: "https://pds.example".into(),
            access_token: "token".into(),
            refresh_token: "refresh".into(),
            scopes: vec![crate::models::CIRCLE_MEMBER_SCOPE.into(), crate::models::CIRCLE_OWNER_SCOPE.into()],
            access_token_expires_at: now + chrono::Duration::hours(1),
            created_at: now,
            last_used_at: now,
        }
    }

    #[tokio::test]
    async fn unsupported_pds_disables_capability() {
        let result = CircleCapabilityService::new(StubProbe).get(&session()).await.unwrap();
        assert!(!result.enabled);
    }
}
