pub mod apns;
pub mod decision;
pub mod moderation_cache;
pub mod preferences;
pub mod queue;
pub mod registry;
pub mod subscriptions;
pub mod types;

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use chrono::Utc;
use sqlx::{Pool, Postgres};

use crate::{
    config::{AppState, PushConfig},
    error::AppError,
    middleware::JacquardDpopData,
    models::CatbirdSession,
};

use self::{
    apns::ApnsDelivery,
    decision::{PushDecisionEngine, QueueDisposition},
    moderation_cache::ModerationCache,
    preferences::PushPreferences,
    queue::PushQueue,
    registry::PushRegistry,
    subscriptions::PushSubscriptions,
};

#[derive(Clone)]
pub struct PushServices {
    pub config: PushConfig,
    pub registry: PushRegistry,
    pub preferences: PushPreferences,
    pub subscriptions: PushSubscriptions,
    pub moderation_cache: ModerationCache,
    pub queue: PushQueue,
    pub decision: PushDecisionEngine,
    pub apns: Option<ApnsDelivery>,
}

impl PushServices {
    pub fn new(db_pool: Pool<Postgres>, config: PushConfig) -> Result<Self> {
        let service_did = config
            .service_did
            .clone()
            .ok_or_else(|| anyhow!("push.service_did must be configured when push is enabled"))?;

        Ok(Self {
            registry: PushRegistry::new(db_pool.clone(), service_did),
            preferences: PushPreferences::new(db_pool.clone()),
            subscriptions: PushSubscriptions::new(db_pool.clone()),
            moderation_cache: ModerationCache::new(db_pool.clone(), config.sync_interval_seconds),
            queue: PushQueue::new(db_pool),
            decision: PushDecisionEngine::new(),
            apns: ApnsDelivery::new(&config.apns)?,
            config,
        })
    }

    pub fn spawn_worker(self: Arc<Self>, state: Arc<AppState>) {
        if self.apns.is_none() {
            tracing::warn!("Skipping push worker startup because APNs is not configured");
            return;
        }

        tokio::spawn(async move {
            self.run_worker_loop(state).await;
        });
    }

    async fn run_worker_loop(self: Arc<Self>, state: Arc<AppState>) {
        let Some(apns) = self.apns.clone() else {
            return;
        };

        let batch_size = i64::from(self.config.queue_batch_size.max(1));
        let poll_interval = std::time::Duration::from_millis(self.config.queue_poll_interval_ms);

        tracing::info!("Push queue worker started");

        // Purge lingering queue rows for revoked accounts every ~60s
        let purge_interval = std::time::Duration::from_secs(60);
        let mut last_purge = tokio::time::Instant::now();

        loop {
            if last_purge.elapsed() >= purge_interval {
                last_purge = tokio::time::Instant::now();
                match self.queue.purge_revoked_accounts().await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(count = n, "Purged push queue rows for revoked accounts"),
                    Err(err) => tracing::warn!(error = %err, "Failed to purge revoked account queue rows"),
                }
            }

            match self.queue.claim_ready(batch_size).await {
                Ok(rows) if rows.is_empty() => {
                    tokio::time::sleep(poll_interval).await;
                }
                Ok(rows) => {
                    // Track DIDs discovered to be revoked mid-batch so we can
                    // skip remaining rows without hitting the decision engine
                    let mut revoked_dids: HashSet<String> = HashSet::new();

                    for row in rows {
                        // Fast-path: skip rows for DIDs already known revoked in this batch
                        if revoked_dids.contains(&row.recipient_did) {
                            tracing::debug!(
                                recipient = %row.recipient_did,
                                notification_type = %row.notification_type,
                                "Skipping push event for revoked account (batch cache)"
                            );
                            if let Err(err) = self.queue.delete(row.id).await {
                                tracing::error!(error = %err, "Failed to delete revoked-account push event");
                            }
                            continue;
                        }

                        match self.decision.evaluate(&state, &self, &row).await {
                            Ok(QueueDisposition::Drop(reason)) => {
                                tracing::debug!(
                                    recipient = %row.recipient_did,
                                    notification_type = %row.notification_type,
                                    reason = reason,
                                    "Dropping queued push event"
                                );
                                if let Err(err) = self.queue.delete(row.id).await {
                                    tracing::error!(error = %err, "Failed to delete dropped push event");
                                }
                            }
                            Ok(QueueDisposition::Deliver(deliveries)) => {
                                let mut transient_error = None;

                                for (registration, notification) in deliveries {
                                    match apns.send(&registration, &notification).await {
                                        Ok(()) => {}
                                        Err(err) if is_invalid_token(&err) => {
                                            tracing::info!(
                                                did = %registration.did,
                                                token = %registration.device_token,
                                                "Deactivating invalid APNs token"
                                            );
                                            if let Err(update_err) = self
                                                .registry
                                                .deactivate_invalid_token(
                                                    &registration.did,
                                                    &registration.device_token,
                                                    "apns_unregistered",
                                                )
                                                .await
                                            {
                                                tracing::error!(error = %update_err, "Failed to deactivate invalid APNs token");
                                            }
                                        }
                                        Err(err) if is_auth_revocation_error(&err) => {
                                            tracing::info!(
                                                recipient = %row.recipient_did,
                                                error = %err,
                                                "Auth revoked during delivery; skipping remaining events for account"
                                            );
                                            revoked_dids.insert(row.recipient_did.clone());
                                            break;
                                        }
                                        Err(err) => {
                                            transient_error = Some(err);
                                            break;
                                        }
                                    }
                                }

                                if revoked_dids.contains(&row.recipient_did) {
                                    // Auth was revoked during delivery — delete, don't retry
                                    if let Err(err) = self.queue.delete(row.id).await {
                                        tracing::error!(error = %err, "Failed to delete revoked-account push event");
                                    }
                                } else if let Some(err) = transient_error {
                                    tracing::warn!(
                                        recipient = %row.recipient_did,
                                        notification_type = %row.notification_type,
                                        error = %err,
                                        "Transient push delivery failure; scheduling retry"
                                    );
                                    if let Err(update_err) = self
                                        .queue
                                        .retry_later(row.id, row.attempts, &err.to_string())
                                        .await
                                    {
                                        tracing::error!(error = %update_err, "Failed to schedule push retry");
                                    }
                                } else if let Err(err) = self.queue.delete(row.id).await {
                                    tracing::error!(error = %err, "Failed to delete delivered push event");
                                }
                            }
                            Err(err) if is_auth_revocation_error(&err) => {
                                tracing::info!(
                                    recipient = %row.recipient_did,
                                    error = %err,
                                    "Auth revoked during decision evaluation; skipping remaining events for account"
                                );
                                revoked_dids.insert(row.recipient_did.clone());
                                if let Err(del_err) = self.queue.delete(row.id).await {
                                    tracing::error!(error = %del_err, "Failed to delete revoked-account push event");
                                }
                            }
                            Err(err) => {
                                tracing::warn!(
                                    recipient = %row.recipient_did,
                                    notification_type = %row.notification_type,
                                    error = %err,
                                    "Push decision pipeline failed; scheduling retry"
                                );
                                if let Err(update_err) = self
                                    .queue
                                    .retry_later(row.id, row.attempts, &err.to_string())
                                    .await
                                {
                                    tracing::error!(error = %update_err, "Failed to schedule push retry");
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    tracing::error!(error = %err, "Push queue lease failed");
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }
}

fn is_invalid_token(err: &anyhow::Error) -> bool {
    if let Some(a2_err) = err.downcast_ref::<a2::Error>() {
        if let a2::Error::ResponseError(response) = a2_err {
            return response.code == 410;
        }
    }

    let message = err.to_string().to_ascii_lowercase();
    message.contains("unregistered")
}

pub(crate) async fn resolve_background_session(
    state: &Arc<AppState>,
    account_did: &str,
    session_id: &str,
    pds_url: &str,
) -> Result<(CatbirdSession, JacquardDpopData)> {
    use jacquard_common::types::did::Did;

    let auth_store = state
        .auth_store
        .as_ref()
        .ok_or_else(|| anyhow!("Auth store not configured"))?;
    let jacquard_client = state
        .jacquard_client
        .as_ref()
        .ok_or_else(|| anyhow!("Jacquard client not configured"))?;

    if let Some(mapped_did) = auth_store.lookup_did_for_session(session_id).await? {
        if mapped_did != account_did {
            tracing::warn!(
                mapped_did = %mapped_did,
                requested_did = %account_did,
                "Push background session lookup resolved a different DID than expected"
            );
        }
    }

    let did = Did::new(account_did)
        .map_err(|err| anyhow!("Invalid DID in push background session: {}", err))?;
    let session_data = jacquard_client
        .registry
        .get(&did, session_id, true)
        .await
        .map_err(|err| anyhow!("Jacquard session lookup failed: {}", err))?;

    let expires_at = session_data
        .token_set
        .expires_at
        .as_ref()
        .and_then(|dt| chrono::DateTime::parse_from_rfc3339(dt.as_str()).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(3600));

    let dpop = JacquardDpopData {
        dpop_key: session_data.dpop_data.dpop_key.clone(),
        dpop_host_nonce: session_data.dpop_data.dpop_host_nonce.to_string(),
    };

    let session = CatbirdSession {
        id: uuid::Uuid::parse_str(session_id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
        did: account_did.to_string(),
        handle: account_did.to_string(),
        pds_url: if session_data.host_url.as_str().is_empty() {
            pds_url.to_string()
        } else {
            session_data.host_url.to_string()
        },
        access_token: session_data.token_set.access_token.to_string(),
        refresh_token: session_data
            .token_set
            .refresh_token
            .as_ref()
            .map(|token| token.to_string())
            .unwrap_or_default(),
        access_token_expires_at: expires_at,
        created_at: Utc::now(),
        last_used_at: Utc::now(),
    };

    Ok((session, dpop))
}

pub(crate) fn is_auth_revocation_error(err: &anyhow::Error) -> bool {
    let message = err.to_string().to_ascii_lowercase();
    message.contains("invalid_grant")
        || message.contains("invalid_token")
        || message.contains("no refresh token")
        || message.contains("no per-session oauth data")
        || message.contains("session not found")
        || message.contains("session expired")
}

pub(crate) fn push_unavailable_error() -> AppError {
    AppError::Config("Push control plane is not configured".into())
}
