use crate::{error::AppError, models::{require_circle_scopes, CatbirdSession, CIRCLE_PROTOCOL_REVISION}};
use dashmap::DashMap;
use serde::Serialize;
use std::{future::Future, pin::Pin, sync::Arc, time::{Duration, Instant}};
use crate::config::AppState;
use crate::services::{AtProtoClient, ProxyResponse};
use std::sync::{OnceLock, Weak};

pub struct AtProtoCircleProbe {
    state: Arc<OnceLock<Weak<AppState>>>,
}

impl AtProtoCircleProbe {
    pub fn new() -> Self {
        Self { state: Arc::new(OnceLock::new()) }
    }

    pub fn set_state(&self, state: Weak<AppState>) {
        let _ = self.state.set(state);
    }
}

impl CircleProbe for AtProtoCircleProbe {
    fn set_state(&self, state: Weak<AppState>) {
        let _ = self.state.set(state);
    }

    fn probe<'a>(&'a self, session: &'a CatbirdSession) -> Pin<Box<dyn Future<Output = Result<CircleProbeResult, AppError>> + Send + 'a>> {
        self.probe_with(session, None, "circle-capability")
    }
    fn probe_with<'a>(
        &'a self,
        session: &'a CatbirdSession,
        dpop: Option<&'a crate::middleware::JacquardDpopData>,
        request_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<CircleProbeResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let state = self.state.get().and_then(Weak::upgrade)
                .ok_or_else(|| AppError::Internal("Circle capability probe unavailable".into()))?;
            let response = AtProtoClient::new(state).proxy_request(
                session, reqwest::Method::GET, "/xrpc/com.atproto.space.listSpaces",
                None, None, None, None, request_id, dpop,
            ).await?;
            match response {
                ProxyResponse::Buffered { status, body, .. } if (200..300).contains(&status) => {
                    let value: serde_json::Value = serde_json::from_slice(&body)?;
                    Ok(CircleProbeResult::Supported {
                        supports_images: value.get("supportsImages").and_then(|v| v.as_bool()).unwrap_or(false),
                    })
                }
                ProxyResponse::Buffered { status, body, .. } if status == 404 || status == 501 => {
                    let error = serde_json::from_slice::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned));
                    match error.as_deref() {
                        Some("MethodNotFound" | "UnknownMethod") => Ok(CircleProbeResult::Unsupported),
                        _ => Err(AppError::Upstream { status, message: "Malformed capability probe response".into() }),
                    }
                }
                ProxyResponse::Buffered { status, .. } => Err(AppError::Upstream { status, message: "Capability probe failed".into() }),
                ProxyResponse::Streaming { status, .. } => Err(AppError::Upstream { status, message: "Unexpected capability response".into() }),
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircleProbeResult {
    Supported { supports_images: bool },
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
pub struct CircleCapability {
    pub enabled: bool,
    #[serde(rename = "protocolRevision")]
    pub protocol_revision: &'static str,
    #[serde(rename = "supportsImages")]
    pub supports_images: bool,
}

pub trait CircleProbe: Send + Sync {
    fn probe<'a>(&'a self, session: &'a CatbirdSession) -> Pin<Box<dyn Future<Output = Result<CircleProbeResult, AppError>> + Send + 'a>>;
    fn set_state(&self, _state: Weak<AppState>) {}

    fn probe_with<'a>(
        &'a self,
        session: &'a CatbirdSession,
        _dpop: Option<&'a crate::middleware::JacquardDpopData>,
        _request_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<CircleProbeResult, AppError>> + Send + 'a>> {
        self.probe(session)
    }
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
    pub fn set_state(&self, state: Weak<AppState>) {
        self.probe.set_state(state);
    }

    pub async fn get(&self, session: &CatbirdSession) -> Result<CircleCapability, AppError> {
        self.get_with_request(session, None, "circle-capability").await
    }

    pub async fn get_with_request(
        &self,
        session: &CatbirdSession,
        dpop: Option<&crate::middleware::JacquardDpopData>,
        request_id: &str,
    ) -> Result<CircleCapability, AppError> {
        require_circle_scopes(session)?;
        let key = format!("{}:{CIRCLE_PROTOCOL_REVISION}", session.pds_url);
        if let Some(cached) = self.cache.get(&key) {
            if cached.checked_at.elapsed() < Duration::from_secs(300) {
                return Ok(cached.capability.clone());
            }
        }
        let probe_result = self.probe.probe_with(session, dpop, request_id).await?;
        let (enabled, supports_images) = match probe_result {
            CircleProbeResult::Supported { supports_images } => (true, supports_images),
            CircleProbeResult::Unsupported => (false, false),
        };
        let capability = CircleCapability { enabled, protocol_revision: CIRCLE_PROTOCOL_REVISION, supports_images };
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
        fn probe<'a>(&'a self, _session: &'a CatbirdSession) -> Pin<Box<dyn Future<Output = Result<CircleProbeResult, AppError>> + Send + 'a>> {
            Box::pin(async { Ok(CircleProbeResult::Unsupported) })
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
