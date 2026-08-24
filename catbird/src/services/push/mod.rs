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
                            if let Err(err) = self.queue.delete(row.id).await {
                                tracing::error!(error = %err, "Failed to delete revoked-account push event");
                            }
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
                            if let Err(err) = self.queue.delete(row.id).await {
                                tracing::error!(error = %err, "Failed to delete stale push event");
                            }
                            continue;
                        }

                        // Bound the whole decision. Nothing inside this path
                        // carries a timeout of its own, and it performs network
                        // work (session refresh, moderation sync) while the
                        // worker processes rows strictly sequentially — so one
                        // hung upstream connection stops ALL push delivery
                        // indefinitely, with no error logged because nothing
                        // ever returns. That is how the queue reached 2000+
                        // events with the worker silent.
                        let evaluated = tokio::time::timeout(
                            DECISION_TIMEOUT,
                            self.decision.evaluate(&state, &self, &row),
                        )
                        .await;
                        let evaluated = match evaluated {
                            Ok(result) => result,
                            Err(_elapsed) => {
                                // Requeue rather than drop: a timeout may be
                                // transient, and dropping would silently lose a
                                // deliverable notification.
                                tracing::warn!(
                                    recipient = %row.recipient_did,
                                    notification_type = %row.notification_type,
                                    timeout_secs = DECISION_TIMEOUT.as_secs(),
                                    "Push decision timed out; scheduling retry and moving on"
                                );
                                if let Err(update_err) = self
                                    .queue
                                    .retry_later(row.id, row.attempts, "decision_timeout")
                                    .await
                                {
                                    tracing::error!(error = %update_err, "Failed to schedule push retry after timeout");
                                }
                                continue;
                            }
                        };
                        match evaluated {
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
                                        Ok(delivered_env) => {
                                            if registration.apns_environment.as_deref()
                                                != Some(delivered_env)
                                            {
                                                tracing::info!(
                                                    did = %registration.did,
                                                    token = %registration.device_token,
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
                                            } else if let Some(push_db) = state.push_db.as_ref() {
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
                            Err(err) if is_unregistered_account_error(&err) => {
                                // Terminal, not transient: without a
                                // push_accounts row this event fails the same
                                // way on every attempt.
                                tracing::info!(
                                    recipient = %row.recipient_did,
                                    notification_type = %row.notification_type,
                                    "Recipient has no push account; dropping undeliverable event"
                                );
                                if let Err(del_err) = self.queue.delete(row.id).await {
                                    tracing::error!(error = %del_err, "Failed to delete undeliverable push event");
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

                // Claim the queue row before doing anything else: only an
                // UNLEASED row (one the durable worker hasn't picked up) is
                // deleted here, so at most one path ever delivers this event.
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

                // Fan out to all devices
                let mut delivered_count = 0usize;
                for registration in &registrations {
                    match apns.send(registration, &notification).await {
                        Ok(delivered_env) => {
                            delivered_count += 1;
                            if registration.apns_environment.as_deref() != Some(delivered_env) {
                                tracing::info!(
                                    did = %registration.did,
                                    token = %registration.device_token,
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
                        Err(err) if is_invalid_token(&err) => {
                            tracing::info!(
                                did = %registration.did,
                                token = %registration.device_token,
                                "Deactivating invalid APNs token (chat push fast-path)"
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
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                did = %event.recipient_did,
                                token = %registration.device_token,
                                "Chat push fast-path delivery failed"
                            );
                        }
                    }
                }

                // We claimed the row; if NOTHING was delivered, hand it back
                // to the durable path so the notification isn't lost.
                if delivered_count == 0 {
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

fn is_invalid_token(err: &anyhow::Error) -> bool {
    if let Some(a2_err) = err.downcast_ref::<a2::Error>() {
        if let a2::Error::ResponseError(response) = a2_err {
            if response.code == 410 {
                return true;
            }
            // ApnsDelivery::send already retries BadDeviceToken once against
            // the other environment, so a BadDeviceToken reaching here means
            // both endpoints rejected the token — it's genuinely invalid,
            // not just aimed at the wrong environment.
            if let Some(body) = response.error.as_ref() {
                if body.reason == a2::ErrorReason::BadDeviceToken {
                    return true;
                }
            }
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
        scopes: session_data.scopes.iter().map(|scope| scope.to_string()).collect(),
        access_token_expires_at: expires_at,
        created_at: Utc::now(),
        last_used_at: Utc::now(),
    };

    Ok((session, dpop))
}

/// Upper bound on evaluating one queued event. The decision path performs
/// network work with no internal timeout, and the worker is sequential, so an
/// unbounded hang wedges every pending notification behind it.
const DECISION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) fn is_auth_revocation_error(err: &anyhow::Error) -> bool {
    let message = err.to_string().to_ascii_lowercase();
    message.contains("invalid_grant")
        || message.contains("invalid_token")
        || message.contains("no refresh token")
        || message.contains("no per-session oauth data")
        || message.contains("session not found")
        || message.contains("session expired")
        // Jacquard phrases a missing session as "session does not exist".
        // Without this the event is rescheduled forever, because the session
        // is never coming back.
        || message.contains("session does not exist")
}

/// True when the recipient has no `push_accounts` row.
///
/// `push_preferences.account_did` is a foreign key onto `push_accounts`, so
/// building preferences for such a recipient fails identically on every
/// attempt — the event can never be delivered. Retrying is not merely
/// wasteful: in production 842 of 2048 queued events were in this state,
/// averaging ~90 attempts each, crowding out deliverable ones and keeping the
/// queue permanently backlogged.
pub(crate) fn is_unregistered_account_error(err: &anyhow::Error) -> bool {
    err.to_string()
        .contains("push_preferences_account_did_fkey")
}

pub(crate) fn push_unavailable_error() -> AppError {
    AppError::Config("Push control plane is not configured".into())
}

#[cfg(test)]
mod terminal_failure_tests {
    use super::*;

    #[test]
    fn session_does_not_exist_is_auth_revocation() {
        // Observed verbatim in production: 57 occurrences in six minutes,
        // each one rescheduled forever because this phrasing was not matched.
        let err = anyhow::anyhow!("Jacquard session lookup failed: session does not exist");
        assert!(is_auth_revocation_error(&err));
    }

    #[test]
    fn existing_auth_revocation_phrasings_still_match() {
        for message in [
            "invalid_grant",
            "invalid_token",
            "no refresh token",
            "no per-session oauth data",
            "session not found",
            "session expired",
        ] {
            assert!(
                is_auth_revocation_error(&anyhow::anyhow!("{message}")),
                "regressed on {message}"
            );
        }
    }

    #[test]
    fn missing_push_account_is_terminal() {
        // The recipient has no push_accounts row, so building preferences
        // violates the foreign key on every single attempt.
        let err = anyhow::anyhow!(
            "error returned from database: insert or update on table \"push_preferences\" violates foreign key constraint \"push_preferences_account_did_fkey\""
        );
        assert!(is_unregistered_account_error(&err));
    }

    #[test]
    fn ordinary_failures_stay_retryable() {
        for message in [
            "connection reset by peer",
            "timed out",
            "error returned from database: deadlock detected",
        ] {
            let err = anyhow::anyhow!("{message}");
            assert!(!is_auth_revocation_error(&err), "misclassified {message}");
            assert!(
                !is_unregistered_account_error(&err),
                "misclassified {message}"
            );
        }
    }
}
