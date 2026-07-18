pub mod apns;
pub mod decision;
pub mod moderation_cache;
pub mod preferences;
pub mod queue;
pub mod registry;
pub mod subscriptions;
pub mod types;

use std::collections::HashSet;
use std::future::Future;
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
    decision::{PushDecisionEngine, QueueDisposition, AUTH_REVOKED_DROP_REASON},
    moderation_cache::ModerationCache,
    preferences::PushPreferences,
    queue::PushQueue,
    registry::PushRegistry,
    subscriptions::PushSubscriptions,
    types::QueueRow,
};

#[derive(Debug, PartialEq, Eq)]
enum FencedDelivery<T> {
    Revoked,
    LeaseLost,
    Sent(T),
}

/// Keep the authorization and ownership checks adjacent to the external send.
/// Making the send a callback prevents call sites from accidentally performing
/// the side effect before either fence succeeds.
async fn send_with_delivery_fences<
    T,
    CheckRevoked,
    CheckRevokedFuture,
    Renew,
    RenewFuture,
    Send,
    SendFuture,
>(
    check_revoked: CheckRevoked,
    renew: Renew,
    send: Send,
) -> Result<FencedDelivery<T>>
where
    CheckRevoked: FnOnce() -> CheckRevokedFuture,
    CheckRevokedFuture: Future<Output = Result<bool>>,
    Renew: FnOnce() -> RenewFuture,
    RenewFuture: Future<Output = Result<bool>>,
    Send: FnOnce() -> SendFuture,
    SendFuture: Future<Output = Result<T>>,
{
    if check_revoked().await? {
        return Ok(FencedDelivery::Revoked);
    }
    if !renew().await? {
        return Ok(FencedDelivery::LeaseLost);
    }
    Ok(FencedDelivery::Sent(send().await?))
}

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

        let self_clone = self.clone();
        let state_clone = state.clone();
        tokio::spawn(async move {
            self_clone.run_worker_loop(state_clone).await;
        });

        let self_clone = self.clone();
        let state_clone = state.clone();
        tokio::spawn(async move {
            self_clone.run_chat_push_subscriber(state_clone).await;
        });
    }

    async fn delete_claimed_row(&self, row: &QueueRow, action: &'static str) {
        match self.queue.delete(row.id, row.lease_owner).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    queue_id = row.id,
                    action,
                    "Lost push lease before row deletion; current owner will finish it"
                );
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    queue_id = row.id,
                    action,
                    "Failed to delete claimed push event"
                );
            }
        }
    }

    async fn retry_claimed_row(&self, row: &QueueRow, error: &str) {
        match self
            .queue
            .retry_later(row.id, row.lease_owner, row.attempts, error)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    queue_id = row.id,
                    "Lost push lease before retry scheduling; current owner will finish it"
                );
            }
            Err(update_err) => {
                tracing::error!(
                    error = %update_err,
                    queue_id = row.id,
                    "Failed to schedule push retry"
                );
            }
        }
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
                    Ok(n) => {
                        tracing::info!(count = n, "Purged push queue rows for revoked accounts")
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "Failed to purge revoked account queue rows")
                    }
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
                            self.delete_claimed_row(&row, "drop_revoked_batch").await;
                            continue;
                        }

                        // Staleness guard: drop events that sat in the queue
                        // past this age instead of delivering a long-dead
                        // notification. Protects against any future dormant
                        // producer/pipeline reactivation spraying weeks-old
                        // backlog (e.g. the 383k-row incident), independent of
                        // notification_type.
                        let age = time::OffsetDateTime::now_utc() - row.created_at;
                        if age > time::Duration::hours(24) {
                            tracing::debug!(
                                recipient = %row.recipient_did,
                                notification_type = %row.notification_type,
                                age_secs = age.whole_seconds(),
                                "Dropping stale queued push event"
                            );
                            self.delete_claimed_row(&row, "drop_stale").await;
                            continue;
                        }

                        match self.decision.evaluate(&state, &self, &row).await {
                            Ok(QueueDisposition::Drop(reason)) => {
                                if reason == AUTH_REVOKED_DROP_REASON {
                                    revoked_dids.insert(row.recipient_did.clone());
                                }
                                tracing::debug!(
                                    recipient = %row.recipient_did,
                                    notification_type = %row.notification_type,
                                    reason = reason,
                                    "Dropping queued push event"
                                );
                                self.delete_claimed_row(&row, "drop_decision").await;
                            }
                            Ok(QueueDisposition::Deliver(deliveries)) => {
                                let mut transient_error = None;
                                let mut lease_lost = false;

                                for (registration, notification) in deliveries {
                                    match send_with_delivery_fences(
                                        || self.registry.is_auth_revoked(&row.recipient_did),
                                        || self.queue.renew(row.id, row.lease_owner),
                                        || apns.send(&registration, &notification),
                                    )
                                    .await
                                    {
                                        Ok(FencedDelivery::Revoked) => {
                                            tracing::info!(
                                                recipient = %row.recipient_did,
                                                "Auth revoked before APNs delivery; skipping remaining events for account"
                                            );
                                            revoked_dids.insert(row.recipient_did.clone());
                                            break;
                                        }
                                        Ok(FencedDelivery::LeaseLost) => {
                                            tracing::warn!(
                                                queue_id = row.id,
                                                "Lost push lease before APNs delivery; suppressing stale side effect"
                                            );
                                            lease_lost = true;
                                            break;
                                        }
                                        Ok(FencedDelivery::Sent(delivered_env)) => {
                                            if registration.apns_environment.as_deref()
                                                != Some(delivered_env)
                                            {
                                                tracing::info!(
                                                    did = %registration.did,
                                                    env = delivered_env,
                                                    "Learned APNs environment"
                                                );
                                                if let Err(err) = self
                                                    .registry
                                                    .set_apns_environment(
                                                        &registration.did,
                                                        &registration.device_token,
                                                        delivered_env,
                                                    )
                                                    .await
                                                {
                                                    tracing::warn!(error = %err, "Failed to persist learned APNs environment");
                                                }
                                            }
                                        }
                                        Err(err) => match classify_apns_failure(&err) {
                                            ApnsFailureKind::InvalidToken => {
                                                tracing::info!(
                                                    did = %registration.did,
                                                    "Deactivating invalid APNs token"
                                                );
                                                if let Err(update_err) = self
                                                    .registry
                                                    .deactivate_invalid_token(
                                                        &registration.did,
                                                        &registration.device_token,
                                                        "apns_invalid_token",
                                                    )
                                                    .await
                                                {
                                                    tracing::error!(error = %update_err, "Failed to deactivate invalid APNs token");
                                                } else if let Some(push_db) = state.push_db.as_ref()
                                                {
                                                    let scheduler = crate::services::chat_poll::scheduler::ChatPollScheduler::new(push_db.clone());
                                                    if let Err(err) = scheduler
                                                        .unenroll_account_if_no_active_devices(
                                                            &registration.did,
                                                        )
                                                        .await
                                                    {
                                                        tracing::warn!(did = %registration.did, error = %err, "Chat poll unenroll (APNs token death) failed");
                                                    }
                                                }
                                            }
                                            ApnsFailureKind::Permanent => {
                                                tracing::warn!(
                                                    error = %err,
                                                    did = %registration.did,
                                                    "Permanent APNs rejection; dropping delivery without retry"
                                                );
                                            }
                                            ApnsFailureKind::Transient => {
                                                transient_error = Some(err);
                                                break;
                                            }
                                        },
                                    }
                                }

                                if lease_lost {
                                    // A newer claimant owns completion and retry state.
                                    continue;
                                } else if revoked_dids.contains(&row.recipient_did) {
                                    // Auth was revoked during delivery — delete, don't retry
                                    self.delete_claimed_row(&row, "drop_revoked_delivery").await;
                                } else if let Some(err) = transient_error {
                                    // Known limitation: retrying the row re-sends to
                                    // registrations that already succeeded this attempt.
                                    // Acceptable for rare, genuinely transient errors
                                    // (network/5xx) — deterministic failures like
                                    // BadDeviceToken must never reach this arm (they're
                                    // classified invalid and deactivate the token instead).
                                    tracing::warn!(
                                        recipient = %row.recipient_did,
                                        notification_type = %row.notification_type,
                                        error = %err,
                                        "Transient push delivery failure; scheduling retry"
                                    );
                                    self.retry_claimed_row(&row, &err.to_string()).await;
                                } else {
                                    self.delete_claimed_row(&row, "complete_delivery").await;
                                }
                            }
                            Err(err) if is_auth_revocation_error(&err) => {
                                tracing::info!(
                                    recipient = %row.recipient_did,
                                    error = %err,
                                    "Auth revoked during decision evaluation; skipping remaining events for account"
                                );
                                revoked_dids.insert(row.recipient_did.clone());
                                self.delete_claimed_row(&row, "drop_revoked_decision").await;
                            }
                            Err(err) => {
                                tracing::warn!(
                                    recipient = %row.recipient_did,
                                    notification_type = %row.notification_type,
                                    error = %err,
                                    "Push decision pipeline failed; scheduling retry"
                                );
                                self.retry_claimed_row(&row, &err.to_string()).await;
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

    async fn run_chat_push_subscriber(self: Arc<Self>, state: Arc<AppState>) {
        use futures_util::StreamExt;

        let Some(apns) = self.apns.clone() else {
            return;
        };

        tracing::info!("Chat push Redis subscriber starting");

        loop {
            let client = match redis::Client::open(state.config.redis.url.as_str()) {
                Ok(c) => c,
                Err(err) => {
                    tracing::error!(error = %err, "Failed to create Redis client for chat push subscriber");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut pubsub = match client.get_async_pubsub().await {
                Ok(ps) => ps,
                Err(err) => {
                    tracing::error!(error = %err, "Failed to get Redis pubsub connection for chat push subscriber");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            if let Err(err) = pubsub.subscribe("chat_push").await {
                tracing::error!(error = %err, "Failed to subscribe to chat_push channel");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            tracing::info!("Subscribed to chat_push Redis channel");

            let mut stream = pubsub.on_message();

            while let Some(msg) = stream.next().await {
                let payload: String = match msg.get_payload() {
                    Ok(p) => p,
                    Err(err) => {
                        tracing::warn!(error = %err, "Failed to get chat_push message payload");
                        continue;
                    }
                };

                let event: crate::services::chat_poll::types::ChatPushEvent =
                    match serde_json::from_str(&payload) {
                        Ok(e) => e,
                        Err(err) => {
                            tracing::warn!(error = %err, "Failed to deserialize ChatPushEvent");
                            continue;
                        }
                    };

                // Claim the queue row before doing anything else. Only a
                // never-leased row for an account that is still active can be
                // deleted here; durable attempts remain under lease fencing.
                let dedupe_key = event.dedupe_key();
                match self.queue.claim_by_dedupe_key(&dedupe_key).await {
                    Ok(true) => {}
                    Ok(false) => {
                        // Durable worker owns it (or it was already delivered).
                        continue;
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "Chat push claim failed; leaving to durable path");
                        continue;
                    }
                }

                // Account state can change immediately after the atomic claim.
                // Recheck before any policy work; a lookup outage requeues to
                // preserve at-least-once delivery.
                match self.registry.is_auth_revoked(&event.recipient_did).await {
                    Ok(false) => {}
                    Ok(true) => {
                        tracing::debug!(
                            did = %event.recipient_did,
                            "Chat push fast-path dropped: auth_revoked"
                        );
                        continue;
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            did = %event.recipient_did,
                            "Chat push fast-path revocation lookup failed; requeuing"
                        );
                        if let Err(err) = crate::services::chat_poll::poller::enqueue_push(
                            self.queue.pool(),
                            &event,
                            0,
                        )
                        .await
                        {
                            tracing::error!(error = %err, "Failed to requeue chat push after revocation lookup failure");
                        }
                        continue;
                    }
                }

                // Mirror decision.rs's preferences + moderation checks: the
                // claim already consumed the row, so on either "drop" or
                // check-error we must not silently swallow the event —
                // check-errors requeue (delay 0) so the durable path can
                // decide fail-closed, matching the durable worker's own
                // error handling.
                let prefs = match self.preferences.get_or_create(&event.recipient_did).await {
                    Ok(prefs) => prefs,
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            did = %event.recipient_did,
                            "Chat push fast-path preferences lookup failed; requeuing"
                        );
                        if let Err(err) = crate::services::chat_poll::poller::enqueue_push(
                            self.queue.pool(),
                            &event,
                            0,
                        )
                        .await
                        {
                            tracing::error!(error = %err, "Failed to requeue chat push after preferences lookup failure");
                        }
                        continue;
                    }
                };
                if !prefs.is_push_enabled_for("chat_message") {
                    tracing::debug!(
                        did = %event.recipient_did,
                        "Chat push fast-path dropped: preferences_disabled"
                    );
                    continue;
                }

                match self
                    .moderation_cache
                    .is_actor_muted_or_blocked(&event.recipient_did, &event.sender_did)
                    .await
                {
                    Ok(false) => {}
                    Ok(true) => {
                        tracing::debug!(
                            did = %event.recipient_did,
                            actor = %event.sender_did,
                            "Chat push fast-path dropped: actor_muted_or_blocked"
                        );
                        continue;
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            did = %event.recipient_did,
                            "Chat push fast-path moderation lookup failed; requeuing"
                        );
                        if let Err(err) = crate::services::chat_poll::poller::enqueue_push(
                            self.queue.pool(),
                            &event,
                            0,
                        )
                        .await
                        {
                            tracing::error!(error = %err, "Failed to requeue chat push after moderation lookup failure");
                        }
                        continue;
                    }
                }

                // Look up active registrations for recipient
                let registrations = match self
                    .registry
                    .list_active_registrations(&event.recipient_did)
                    .await
                {
                    Ok(r) => r,
                    Err(err) => {
                        tracing::warn!(error = %err, "Failed to look up registrations for chat push");
                        continue;
                    }
                };

                if registrations.is_empty() {
                    // No device to deliver to — the claim already consumed
                    // the event, matching the durable path's Drop disposition.
                    continue;
                }

                // Build notification
                let mut custom_data = std::collections::HashMap::new();
                custom_data.insert("type".to_string(), "chat_message".to_string());
                custom_data.insert("recipientDid".to_string(), event.recipient_did.clone());
                custom_data.insert("convoId".to_string(), event.convo_id.clone());
                custom_data.insert("messageId".to_string(), event.message_id.clone());
                custom_data.insert("senderDid".to_string(), event.sender_did.clone());
                let truncated_text: String = event.message_text.chars().take(200).collect();
                custom_data.insert("messageText".to_string(), truncated_text);

                let notification = apns::ApnsNotification {
                    title: "New Message".to_string(),
                    body: "You have a new message".to_string(),
                    user_did: event.recipient_did.clone(),
                    custom_data,
                    mutable_content: true,
                    thread_id: Some(format!("chat:{}", event.convo_id)),
                };

                // Fan out to all devices. Revocation is checked immediately
                // before every APNs side effect; the successful atomic delete
                // above is the fast path's ownership claim.
                let mut retryable_failure = false;
                let mut revoked = false;
                for registration in &registrations {
                    match self.registry.is_auth_revoked(&event.recipient_did).await {
                        Ok(false) => {}
                        Ok(true) => {
                            revoked = true;
                            tracing::info!(
                                recipient = %event.recipient_did,
                                "Auth revoked before chat fast-path APNs delivery"
                            );
                            break;
                        }
                        Err(err) => {
                            retryable_failure = true;
                            tracing::warn!(
                                error = %err,
                                did = %event.recipient_did,
                                "Chat fast-path revocation check failed before APNs delivery"
                            );
                            break;
                        }
                    }

                    match apns.send(registration, &notification).await {
                        Ok(delivered_env) => {
                            if registration.apns_environment.as_deref() != Some(delivered_env) {
                                tracing::info!(
                                    did = %registration.did,
                                    env = delivered_env,
                                    "Learned APNs environment (chat push fast-path)"
                                );
                                if let Err(err) = self
                                    .registry
                                    .set_apns_environment(
                                        &registration.did,
                                        &registration.device_token,
                                        delivered_env,
                                    )
                                    .await
                                {
                                    tracing::warn!(error = %err, "Failed to persist learned APNs environment (chat push fast-path)");
                                }
                            }
                        }
                        Err(err) => match classify_apns_failure(&err) {
                            ApnsFailureKind::InvalidToken => {
                                tracing::info!(
                                    did = %registration.did,
                                    "Deactivating invalid APNs token (chat push fast-path)"
                                );
                                if let Err(update_err) = self
                                    .registry
                                    .deactivate_invalid_token(
                                        &registration.did,
                                        &registration.device_token,
                                        "apns_invalid_token",
                                    )
                                    .await
                                {
                                    tracing::error!(error = %update_err, "Failed to deactivate invalid APNs token");
                                } else if let Some(push_db) = state.push_db.as_ref() {
                                    let scheduler =
                                        crate::services::chat_poll::scheduler::ChatPollScheduler::new(
                                            push_db.clone(),
                                        );
                                    if let Err(err) = scheduler
                                        .unenroll_account_if_no_active_devices(&registration.did)
                                        .await
                                    {
                                        tracing::warn!(did = %registration.did, error = %err, "Chat poll unenroll (APNs token death) failed");
                                    }
                                }
                            }
                            ApnsFailureKind::Permanent => {
                                tracing::warn!(
                                    error = %err,
                                    did = %event.recipient_did,
                                    "Permanent chat fast-path APNs rejection; not requeuing"
                                );
                            }
                            ApnsFailureKind::Transient => {
                                retryable_failure = true;
                                tracing::warn!(
                                    error = %err,
                                    did = %event.recipient_did,
                                    "Transient chat push fast-path delivery failure"
                                );
                                break;
                            }
                        },
                    }
                }

                // Requeue every genuinely transient failure, including partial
                // fanout. This can duplicate an earlier successful send but
                // preserves the queue's at-least-once contract.
                if retryable_failure && !revoked {
                    if let Err(err) = crate::services::chat_poll::poller::enqueue_push(
                        self.queue.pool(),
                        &event,
                        0,
                    )
                    .await
                    {
                        tracing::error!(error = %err, "Failed to requeue chat push after fast-path failure");
                    }
                }
            }

            // Stream ended — reconnect
            tracing::warn!("Chat push Redis subscription stream ended; reconnecting...");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApnsFailureKind {
    InvalidToken,
    Permanent,
    Transient,
}

fn classify_apns_failure(err: &anyhow::Error) -> ApnsFailureKind {
    if let Some(a2::Error::ResponseError(response)) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<a2::Error>())
    {
        if response.code == 410 {
            return ApnsFailureKind::InvalidToken;
        }
        if let Some(body) = response.error.as_ref() {
            use a2::ErrorReason;
            return match &body.reason {
                ErrorReason::BadDeviceToken
                | ErrorReason::DeviceTokenNotForTopic
                | ErrorReason::Unregistered => ApnsFailureKind::InvalidToken,
                ErrorReason::IdleTimeout
                | ErrorReason::ExpiredProviderToken
                | ErrorReason::TooManyProviderTokenUpdates
                | ErrorReason::TooManyRequests
                | ErrorReason::InternalServerError
                | ErrorReason::ServiceUnavailable
                | ErrorReason::Shutdown => ApnsFailureKind::Transient,
                _ => ApnsFailureKind::Permanent,
            };
        }
        return match response.code {
            429 | 500 | 503 => ApnsFailureKind::Transient,
            400 | 403 | 405 | 413 => ApnsFailureKind::Permanent,
            _ => ApnsFailureKind::Transient,
        };
    }

    let message = err.to_string().to_ascii_lowercase();
    if message.contains("unregistered")
        || message.contains("bad device token")
        || message.contains("device token does not match")
    {
        ApnsFailureKind::InvalidToken
    } else {
        // Transport, database-fence, and unknown failures retain at-least-once
        // retry semantics.
        ApnsFailureKind::Transient
    }
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

    let mapped_did = auth_store.lookup_did_for_session(session_id).await?;
    let repair_index = validate_background_session_mapping(mapped_did.as_deref(), account_did)?;

    let did =
        Did::new(account_did).map_err(|_| BackgroundSessionValidationError::InvalidAccountDid)?;
    if repair_index {
        require_background_index_repair(
            auth_store
                .repair_missing_session_index(&did, session_id)
                .await,
        )?;
    }
    let session_data = jacquard_client
        .registry
        .get(&did, session_id, true)
        .await
        .map_err(background_session_lookup_error)?;
    validate_background_session_record(
        session_data.account_did.as_str(),
        &session_data.session_id,
        account_did,
        session_id,
    )?;
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

fn background_session_lookup_error(error: jacquard_oauth::session::Error) -> anyhow::Error {
    // Keep the concrete Jacquard error in anyhow's source chain. Background
    // workers use that type to distinguish durable credential quarantine from
    // a retryable operation lease or store outage.
    anyhow::Error::new(error).context("Jacquard session lookup failed")
}

#[derive(Debug, thiserror::Error)]
enum BackgroundSessionValidationError {
    #[error("Background OAuth session is not bound to the requested account")]
    MappingMismatch,
    #[error("Background OAuth session record is not bound to the requested account")]
    RecordMismatch,
    #[error("Background OAuth session not found: primary record is missing")]
    MissingPrimary,
    #[error("Invalid DID in push background session")]
    InvalidAccountDid,
}

fn require_background_index_repair(
    result: std::result::Result<bool, jacquard_common::session::SessionStoreError>,
) -> Result<()> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(BackgroundSessionValidationError::MissingPrimary.into()),
        // Preserve typed store failures so infrastructure outages remain
        // retryable instead of being misclassified as credential revocation.
        Err(error) => Err(anyhow::Error::new(error)),
    }
}

fn validate_background_session_mapping(
    mapped_did: Option<&str>,
    expected_did: &str,
) -> Result<bool> {
    match mapped_did {
        Some(mapped_did) if mapped_did == expected_did => Ok(false),
        Some(_) => Err(BackgroundSessionValidationError::MappingMismatch.into()),
        // Background jobs already carry an authoritative account DID from
        // their database row. A missing secondary index may be repaired only
        // after the primary session record is loaded by that DID and its
        // embedded principal and session ID are verified below.
        None => Ok(true),
    }
}

fn validate_background_session_record(
    stored_did: &str,
    stored_session_id: &str,
    expected_did: &str,
    expected_session_id: &str,
) -> Result<()> {
    if stored_did == expected_did && stored_session_id == expected_session_id {
        Ok(())
    } else {
        Err(BackgroundSessionValidationError::RecordMismatch.into())
    }
}

pub(crate) fn is_auth_revocation_error(err: &anyhow::Error) -> bool {
    if err.chain().any(|cause| {
        cause
            .downcast_ref::<jacquard_oauth::session::Error>()
            .is_some_and(jacquard_oauth::session::Error::is_permanent)
            || cause
                .downcast_ref::<BackgroundSessionValidationError>()
                .is_some()
    }) {
        return true;
    }

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

#[cfg(test)]
mod delivery_fencing_tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    use super::*;

    fn apns_error(reason: a2::ErrorReason, code: u16) -> anyhow::Error {
        anyhow::Error::new(a2::Error::ResponseError(a2::Response {
            error: Some(a2::ErrorBody {
                reason,
                timestamp: None,
            }),
            apns_id: None,
            code,
        }))
    }

    #[tokio::test]
    async fn delivery_fence_renews_immediately_before_send() {
        let steps = Arc::new(Mutex::new(Vec::new()));
        let check_steps = steps.clone();
        let renew_steps = steps.clone();
        let send_steps = steps.clone();

        let outcome = send_with_delivery_fences(
            move || async move {
                check_steps.lock().unwrap().push("revocation");
                Ok(false)
            },
            move || async move {
                renew_steps.lock().unwrap().push("renew");
                Ok(true)
            },
            move || async move {
                send_steps.lock().unwrap().push("send");
                Ok("production")
            },
        )
        .await
        .unwrap();

        assert_eq!(outcome, FencedDelivery::Sent("production"));
        assert_eq!(
            steps.lock().unwrap().as_slice(),
            ["revocation", "renew", "send"]
        );
    }

    #[tokio::test]
    async fn lost_lease_suppresses_external_send() {
        let sent = Arc::new(AtomicBool::new(false));
        let send_state = sent.clone();

        let outcome = send_with_delivery_fences(
            || async { Ok(false) },
            || async { Ok(false) },
            move || async move {
                send_state.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap();

        assert_eq!(outcome, FencedDelivery::LeaseLost);
        assert!(!sent.load(Ordering::SeqCst));
    }

    #[test]
    fn permanent_apns_rejections_never_enter_transient_retry() {
        assert_eq!(
            classify_apns_failure(&apns_error(a2::ErrorReason::DeviceTokenNotForTopic, 400)),
            ApnsFailureKind::InvalidToken
        );
        assert_eq!(
            classify_apns_failure(&apns_error(a2::ErrorReason::Unregistered, 410)),
            ApnsFailureKind::InvalidToken
        );
        assert_eq!(
            classify_apns_failure(&apns_error(a2::ErrorReason::PayloadTooLarge, 413)),
            ApnsFailureKind::Permanent
        );
        assert_eq!(
            classify_apns_failure(&apns_error(a2::ErrorReason::ServiceUnavailable, 503)),
            ApnsFailureKind::Transient
        );
    }

    #[test]
    fn operational_push_logs_do_not_emit_device_tokens() {
        let sources = [include_str!("mod.rs"), include_str!("apns.rs")];
        let forbidden = [
            ["token", " = %registration.device_token"].concat(),
            ["device_", "token ="].concat(),
            ["token_", "hash"].concat(),
            ["token_", "prefix"].concat(),
        ];

        for source in sources {
            for value in &forbidden {
                assert!(
                    !source.contains(value),
                    "push source contains forbidden token log field"
                );
            }
        }
    }
}

#[cfg(test)]
mod session_binding_tests {
    #[test]
    fn missing_background_session_is_classified_as_revoked() {
        let error =
            anyhow::anyhow!("Background OAuth session not found: primary record is missing");
        assert!(super::is_auth_revocation_error(&error));
    }

    #[test]
    fn typed_reauthentication_survives_background_context_and_is_revoked() {
        let error = super::background_session_lookup_error(
            jacquard_oauth::session::Error::ReauthenticationRequired,
        );

        assert!(error.chain().any(|cause| cause
            .downcast_ref::<jacquard_oauth::session::Error>()
            .is_some_and(|error| matches!(
                error,
                jacquard_oauth::session::Error::ReauthenticationRequired
            ))));
        assert!(super::is_auth_revocation_error(&error));
    }

    #[test]
    fn every_typed_permanent_session_error_is_revoked() {
        for session_error in [
            jacquard_oauth::session::Error::SessionNotFound,
            jacquard_oauth::session::Error::RefreshFailed(
                jacquard_oauth::request::RequestError::no_refresh_token(),
            ),
            jacquard_oauth::session::Error::ServerAgent(
                jacquard_oauth::request::RequestError::no_refresh_token(),
            ),
        ] {
            let error = super::background_session_lookup_error(session_error);
            assert!(super::is_auth_revocation_error(&error));
        }
    }

    #[test]
    fn typed_active_operation_remains_transient_for_background_workers() {
        for session_error in [
            jacquard_oauth::session::Error::OperationInProgress,
            jacquard_oauth::session::Error::Store(
                jacquard_common::session::SessionStoreError::Other("temporary Redis outage".into()),
            ),
            jacquard_oauth::session::Error::ServerAgent(
                jacquard_oauth::request::RequestError::token_verification(),
            ),
        ] {
            let error = super::background_session_lookup_error(session_error);
            assert!(!super::is_auth_revocation_error(&error));
        }

        assert!(!super::is_auth_revocation_error(&anyhow::anyhow!(
            "temporary network failure"
        )));
    }

    #[test]
    fn every_typed_local_validation_failure_is_revoked() {
        for error in [
            super::BackgroundSessionValidationError::MissingPrimary,
            super::BackgroundSessionValidationError::InvalidAccountDid,
        ] {
            assert!(super::is_auth_revocation_error(&anyhow::Error::new(error)));
        }
    }

    #[test]
    fn background_index_repair_distinguishes_missing_primary_from_store_outage() {
        let missing = super::require_background_index_repair(Ok(false)).unwrap_err();
        assert!(missing.chain().any(|cause| matches!(
            cause.downcast_ref::<super::BackgroundSessionValidationError>(),
            Some(super::BackgroundSessionValidationError::MissingPrimary)
        )));
        assert!(super::is_auth_revocation_error(&missing));

        let outage = super::require_background_index_repair(Err(
            jacquard_common::session::SessionStoreError::Other("temporary Redis outage".into()),
        ))
        .unwrap_err();
        assert!(outage.chain().any(|cause| cause
            .downcast_ref::<jacquard_common::session::SessionStoreError>()
            .is_some()));
        assert!(!super::is_auth_revocation_error(&outage));
    }

    #[test]
    fn background_session_mapping_requires_exact_expected_did() {
        assert!(
            super::validate_background_session_mapping(Some("did:plc:alice"), "did:plc:alice")
                .is_ok_and(|repair_index| !repair_index)
        );
        let mapping_error =
            super::validate_background_session_mapping(Some("did:plc:mallory"), "did:plc:alice")
                .unwrap_err();
        assert!(super::is_auth_revocation_error(&mapping_error));
        assert!(
            super::validate_background_session_mapping(None, "did:plc:alice")
                .is_ok_and(|repair_index| repair_index)
        );

        assert!(super::validate_background_session_record(
            "did:plc:alice",
            "session-a",
            "did:plc:alice",
            "session-a"
        )
        .is_ok());
        let principal_error = super::validate_background_session_record(
            "did:plc:mallory",
            "session-a",
            "did:plc:alice",
            "session-a",
        )
        .unwrap_err();
        assert!(super::is_auth_revocation_error(&principal_error));
        let session_error = super::validate_background_session_record(
            "did:plc:alice",
            "session-b",
            "did:plc:alice",
            "session-a",
        )
        .unwrap_err();
        assert!(super::is_auth_revocation_error(&session_error));
    }
}
