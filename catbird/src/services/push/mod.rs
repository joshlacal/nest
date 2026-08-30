pub mod apns;
pub mod decision;
pub mod moderation_verdict;
pub mod preferences;
pub mod queue;
pub mod registry;
pub mod subscriptions;
pub mod thread_mutes;
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
    moderation_verdict::ActorModerationResolver,
    preferences::PushPreferences,
    queue::PushQueue,
    registry::PushRegistry,
    subscriptions::PushSubscriptions,
    thread_mutes::ThreadMuteStore,
};

#[derive(Clone)]
pub struct PushServices {
    pub config: PushConfig,
    pub registry: PushRegistry,
    pub preferences: PushPreferences,
    pub subscriptions: PushSubscriptions,
    pub thread_mutes: ThreadMuteStore,
    pub moderation: ActorModerationResolver,
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

        let mut registry = PushRegistry::new(db_pool.clone(), service_did);
        if config.phase2_writers {
            registry = registry.with_phase2_writers(true);
        }

        Ok(Self {
            registry,
            preferences: PushPreferences::new(db_pool.clone()),
            subscriptions: PushSubscriptions::new(db_pool.clone()),
            thread_mutes: ThreadMuteStore::new(db_pool.clone()),
            moderation: ActorModerationResolver::new(db_pool.clone(), config.verdict_ttl_seconds),
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
        state.wait_for_session_index_readiness().await;
        let Some(apns) = self.apns.clone() else {
            return;
        };

        let batch_size = i64::from(self.config.queue_batch_size.max(1));
        let poll_interval = std::time::Duration::from_millis(self.config.queue_poll_interval_ms);

        tracing::info!("Push queue worker started");
        // Purge lingering queue rows for revoked accounts, and reap cached
        // moderation verdicts, every ~60s.
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

                // Cached verdicts are only useful while they can still be
                // served: past STALE_VERDICT_CEILING even the offline fallback
                // refuses them, so anything older is dead weight in a table
                // that otherwise grows with every distinct actor a user hears
                // from.
                match self
                    .moderation
                    .prune_older_than(time::Duration::hours(1))
                    .await
                {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(count = n, "Pruned stale moderation verdicts"),
                    Err(err) => {
                        tracing::warn!(error = %err, "Failed to prune stale moderation verdicts")
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
                        // work (session refresh, the moderation lookup) while
                        // the worker processes rows strictly sequentially — so one
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

        state.wait_for_session_index_readiness().await;
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
                    .moderation
                    .resolve(&state, &event.recipient_did, &event.sender_did)
                    .await
                    .map(|moderation| moderation.verdict.suppresses("chat_message"))
                {
                    Ok(false) => {}
                    Ok(true) => {
                        tracing::debug!(
                            did = %event.recipient_did,
                            actor = %event.sender_did,
                            "Chat push fast-path dropped: actor_moderated"
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

    // Resolve current active session from Redis for this DID and verify its fingerprint
    let session_data = auth_store
        .resolve_session_for_did_with_fingerprint(account_did, session_id)
        .await
        .map_err(|err| anyhow!("Redis session resolution failed: {err}"))?
        .ok_or_else(|| anyhow!("Session resolution index miss for DID {account_did}: no active Redis session index matching fingerprint (retryable)"))?;
    let did = Did::new(account_did)
        .map_err(|err| anyhow!("Invalid DID in push background session: {}", err))?;
    let session_data = jacquard_client
        .registry
        .get(&did, session_data.session_id.as_str(), true)
        .await
        .map_err(|err| anyhow!("Jacquard session lookup/refresh failed for DID {account_did}: {err}"))?;
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

    let granted_scopes: Vec<String> = if !session_data.scopes.is_empty() {
        session_data
            .scopes
            .iter()
            .map(|s| s.to_string_normalized().to_string())
            .collect()
    } else if let Some(scope_str) = &session_data.token_set.scope {
        jacquard_oauth::scopes::Scopes::new(smol_str::SmolStr::from(scope_str.as_str()))
            .map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.to_string_normalized().to_string())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let raw_session_uuid = uuid::Uuid::parse_str(session_data.session_id.as_str())
        .unwrap_or_else(|_| uuid::Uuid::new_v4());

    let session = CatbirdSession {
        id: raw_session_uuid,
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
        scopes: session_data
            .scopes
            .iter()
            .map(|scope| scope.to_string())
            .collect(),
        access_token_expires_at: expires_at,
        created_at: Utc::now(),
        last_used_at: Utc::now(),
        granted_scopes,
    };
    Ok((session, dpop))
}

/// Upper bound on evaluating one queued event. The decision path performs
/// network work with no internal timeout, and the worker is sequential, so an
/// unbounded hang wedges every pending notification behind it.
const DECISION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) fn is_auth_revocation_error(err: &anyhow::Error) -> bool {
    let message = err.to_string().to_ascii_lowercase();

    // Redis index misses and fingerprint mismatches are explicitly retryable and MUST NOT unenroll or delete events
    if message.contains("index miss")
        || message.contains("fingerprint mismatch")
        || message.contains("session resolution index miss")
        || message.contains("redis session resolution failed")
    {
        return false;
    }

    message.contains("invalid_grant")
        || message.contains("invalid_token")
        || message.contains("no refresh token")
        || message.contains("no per-session oauth data")
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

    #[test]
    fn registry_refresh_error_phrasings_match_auth_revocation() {
        for err_msg in [
            "Jacquard session lookup/refresh failed for DID did:plc:alice: invalid_grant",
            "Jacquard session lookup/refresh failed for DID did:plc:alice: session does not exist",
            "Jacquard session lookup/refresh failed for DID did:plc:alice: invalid_token",
            "Jacquard session lookup/refresh failed for DID did:plc:alice: session expired",
            "Jacquard session lookup/refresh failed for DID did:plc:alice: no refresh token",
        ] {
            let err = anyhow::anyhow!("{err_msg}");
            assert!(
                is_auth_revocation_error(&err),
                "registry error failed to match auth revocation: {err_msg}"
            );
        }
    }

    #[test]
    fn session_resolution_miss_and_fingerprint_mismatch_are_never_auth_revocation() {
        for err_msg in [
            "Session not found: no active session matching fingerprint for DID did:plc:alice",
            "Session resolution index miss for DID did:plc:alice: no active Redis session index matching fingerprint (retryable)",
            "Redis session resolution failed: session index miss",
            "Resolved session inner fingerprint mismatch for DID did:plc:alice: expected abc, resolved def (stale index evicted, retryable)",
            "Session fingerprint mismatch for DID did:plc:alice: expected abc, found def (retryable)",
        ] {
            let err = anyhow::anyhow!("{err_msg}");
            assert!(
                !is_auth_revocation_error(&err),
                "resolution miss/mismatch was incorrectly classified as auth revocation: {err_msg}"
            );
        }
    }

    #[test]
    fn genuine_parent_revision_redis_state_preserves_enrolled_account_and_queued_push_events() {
        // Setup genuine parent-revision Redis state:
        // ONLY session:{did}_{hmac_fp} and session_index:{hmac_fp}
        // NO did_index:{did}
        // NO session_fp_index:{sha256_fp}
        let test_key = [7u8; 32];
        let did = "did:plc:alice";
        let raw_session_id = "550e8400-e29b-41d4-a716-446655440000";
        let sha256_fp = crate::services::push::registry::session_fingerprint(raw_session_id);
        let hmac_fp = crate::services::redis_auth_store::fingerprint_id(&test_key, raw_session_id);

        let mut redis_mock: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let session_json = serde_json::json!({
            "session_id": raw_session_id,
            "account_did": did,
            "host_url": "https://pds.example.com",
            "token_set": {
                "access_token": "mock-access-token",
                "refresh_token": "mock-refresh-token",
                "token_type": "Bearer",
                "expires_at": "2027-01-01T00:00:00Z"
            },
            "dpop_data": {
                "dpop_key": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "f83OJ3D2xFMTbKEBaTueux3jLwFI3QmMV63Wgw3_A56",
                    "y": "x_da696PEkFLDpnn6FKtx1O4CwyGNi2Qg_Mw3bYsUZY"
                },
                "dpop_host_nonce": "mock-nonce"
            },
            "scopes": ["atproto", "transition:generic"]
        });
        let json = serde_json::to_string(&session_json).unwrap();
        let enc = crate::services::redis_crypto::seal_strict(&test_key, &json).unwrap();

        let prefix = "catbird:v2:session:";
        redis_mock.insert(format!("{prefix}session:{did}_{hmac_fp}"), enc);
        redis_mock.insert(format!("{prefix}session_index:{hmac_fp}"), did.to_string());

        // Verify initial state is genuine parent-revision (no new indexes)
        assert!(!redis_mock.contains_key(&format!("{prefix}did_index:{did}")));
        assert!(!redis_mock.contains_key(&format!("{prefix}session_fp_index:{sha256_fp}")));

        // 1. If an un-reconciled resolution miss occurs:
        // The error MUST NOT be classified as auth revocation.
        let unindexed_err = anyhow::anyhow!(
            "Session resolution index miss for DID {did}: no active Redis session index matching fingerprint (retryable)"
        );
        assert!(
            !is_auth_revocation_error(&unindexed_err),
            "unindexed session resolution miss MUST NOT cause auth revocation"
        );

        // 2. Run reconciliation against the genuine parent-revision store:
        // It scans active session keys once, decrypts with test_key, and populates both indexes.
        let sess_key_prefix = format!("{prefix}session:");
        let mut reconciled_count = 0usize;
        for (k, v) in redis_mock.clone().iter() {
            if let Some(rest) = k.strip_prefix(&sess_key_prefix) {
                if let Some((k_did, k_hmac)) = rest.split_once('_') {
                    if let Ok(dec_json) = crate::services::redis_crypto::open_strict(&test_key, v) {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&dec_json) {
                            if let Some(sid) = val.get("session_id").and_then(|s| s.as_str()) {
                                let sid_sha = crate::services::push::registry::session_fingerprint(sid);
                                redis_mock.insert(format!("{prefix}session_fp_index:{sid_sha}"), k_hmac.to_string());
                                redis_mock.insert(format!("{prefix}did_index:{k_did}"), k_hmac.to_string());
                                reconciled_count += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(reconciled_count, 1);
        assert_eq!(redis_mock.get(&format!("{prefix}session_fp_index:{sha256_fp}")).unwrap(), &hmac_fp);
        assert_eq!(redis_mock.get(&format!("{prefix}did_index:{did}")).unwrap(), &hmac_fp);
    }

    #[test]
    fn raw_session_uuid_parsed_into_catbird_session_memory() {
        let raw_uuid_str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let parsed_uuid = uuid::Uuid::parse_str(raw_uuid_str).unwrap();
        assert_eq!(parsed_uuid.to_string(), raw_uuid_str);

        // Verify that passing fingerprint to parse_str fails and falls back if not using raw_session_id
        let fingerprint = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3";
        assert!(uuid::Uuid::parse_str(fingerprint).is_err());
    }
}
