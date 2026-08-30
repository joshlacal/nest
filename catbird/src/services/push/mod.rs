pub mod apns;
pub mod decision;
pub mod lock;
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
use sqlx::{Pool, Postgres, Row};

use crate::{
    config::{AppState, PushConfig},
    error::AppError,
    middleware::JacquardDpopData,
    models::CatbirdSession,
};

use self::{
    apns::{ApnsDelivery, ApnsSender},
    decision::{PushDecisionEngine, QueueDisposition},
    lock::{acquire_account_and_device_lock, acquire_account_lock},
    moderation_verdict::ActorModerationResolver,
    preferences::PushPreferences,
    queue::PushQueue,
    registry::PushRegistry,
    subscriptions::PushSubscriptions,
    thread_mutes::ThreadMuteStore,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreSendFenceOutcome {
    Authorized,
    Revoked,
    DeviceInactive,
    LeaseLost,
    PreferencesDisabled,
    ThreadMuted,
    ModerationSuppressed,
}

pub struct HeartbeatLease {
    id: i64,
    lease_token: uuid::Uuid,
    version: Arc<std::sync::atomic::AtomicI64>,
    cancel_tx: Option<tokio::sync::oneshot::Sender<()>>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl HeartbeatLease {
    /// Starts lease heartbeat by immediately renewing the lease from claim time.
    /// Returns `Ok(Some(HeartbeatLease))` if renewal succeeded, or `Ok(None)` if the lease was lost/expired.
    pub async fn start(
        queue: PushQueue,
        id: i64,
        lease_token: uuid::Uuid,
        initial_version: i64,
    ) -> Result<Option<Self>> {
        // Immediate renewal from claim time ensures full lease budget before beginning processing
        let renewed_version = match queue.extend_lease(id, lease_token, initial_version, 30).await? {
            Some(v) => v,
            None => {
                tracing::warn!(id, "Heartbeat initial lease extension failed: lease expired or lost");
                return Ok(None);
            }
        };

        let version = Arc::new(std::sync::atomic::AtomicI64::new(renewed_version));
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();

        let q = queue.clone();
        let v = version.clone();
        let join_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            // First interval tick is immediate, so discard it to wait 5 seconds for next renewal
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => {
                        break;
                    }
                    _ = interval.tick() => {
                        let cur_v = v.load(std::sync::atomic::Ordering::SeqCst);
                        match q.extend_lease(id, lease_token, cur_v, 30).await {
                            Ok(Some(new_v)) => {
                                v.store(new_v, std::sync::atomic::Ordering::SeqCst);
                            }
                            Ok(None) => {
                                tracing::warn!(id, "Heartbeat lease extension failed: lease lost or reclaimed");
                                break;
                            }
                            Err(err) => {
                                tracing::warn!(id, error = %err, "Heartbeat lease extension error");
                            }
                        }
                    }
                }
            }
        });

        Ok(Some(Self {
            id,
            lease_token,
            version,
            cancel_tx: Some(cancel_tx),
            join_handle: Some(join_handle),
        }))
    }

    pub fn current_version(&self) -> i64 {
        self.version.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn lease_token(&self) -> uuid::Uuid {
        self.lease_token
    }

    /// Stops and joins the background renewal task before final CAS acknowledgment.
    /// Returns `(lease_token, final_lease_version)` guaranteed to have no background races.
    pub async fn stop(mut self) -> (uuid::Uuid, i64) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.await;
        }
        let final_v = self.version.load(std::sync::atomic::Ordering::SeqCst);
        (self.lease_token, final_v)
    }
}

impl Drop for HeartbeatLease {
    fn drop(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
    }
}

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
    pub apns: Option<Arc<dyn ApnsSender>>,
}

impl PushServices {
    pub fn new(db_pool: Pool<Postgres>, config: PushConfig) -> Result<Self> {
        let service_did = config
            .service_did
            .clone()
            .ok_or_else(|| anyhow!("push.service_did must be configured when push is enabled"))?;

        let apns = ApnsDelivery::new(&config.apns)?.map(|d| Arc::new(d) as Arc<dyn ApnsSender>);

        Ok(Self {
            registry: PushRegistry::with_limits(
                db_pool.clone(),
                service_did,
                config.max_active_devices_per_account,
                config.max_inactive_devices_per_account,
                config.max_fanout_per_notification,
            ),
            preferences: PushPreferences::new(db_pool.clone()),
            subscriptions: PushSubscriptions::new(db_pool.clone()),
            thread_mutes: ThreadMuteStore::new(db_pool.clone()),
            moderation: ActorModerationResolver::new(db_pool.clone(), config.verdict_ttl_seconds),
            queue: PushQueue::new(db_pool),
            decision: PushDecisionEngine::new(),
            apns,
            config,
        })
    }

    pub fn with_apns_sender(mut self, sender: Arc<dyn ApnsSender>) -> Self {
        self.apns = Some(sender);
        self
    }
    pub async fn verify_pre_send_fence(
        &self,
        recipient_did: &str,
        actor_did: &str,
        device_token: &str,
        notification_type: &str,
        thread_root_uri: Option<&str>,
        queue_fence: Option<(i64, uuid::Uuid, i64)>, // (id, lease_token, auth_generation)
        expected_auth_generation: Option<i64>,
    ) -> Result<PreSendFenceOutcome> {
        let mut tx = self.queue.pool().begin().await?;
        acquire_account_and_device_lock(&mut tx, recipient_did, device_token).await?;
        let outcome = self
            .verify_pre_send_fence_tx(
                &mut tx,
                recipient_did,
                actor_did,
                device_token,
                notification_type,
                thread_root_uri,
                queue_fence,
                expected_auth_generation,
            )
            .await?;
        tx.commit().await?;
        Ok(outcome)
    }

    pub async fn verify_pre_send_fence_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        recipient_did: &str,
        actor_did: &str,
        device_token: &str,
        notification_type: &str,
        thread_root_uri: Option<&str>,
        queue_fence: Option<(i64, uuid::Uuid, i64)>, // (id, lease_token, auth_generation)
        expected_auth_generation: Option<i64>,
    ) -> Result<PreSendFenceOutcome> {
        let queue_id = queue_fence.map(|(id, _, _)| id);

        let row = sqlx::query(
            r#"
            SELECT
                pa.account_did,
                pa.auth_revoked_at,
                pa.auth_generation,
                ud.is_active AS device_is_active,
                (
                    SELECT COUNT(*)
                    FROM user_devices ud_other
                    WHERE ud_other.device_token = $2
                      AND ud_other.did != param.did
                      AND ud_other.is_active = TRUE
                ) AS other_active_device_count,
                q.lease_token,
                q.lease_version,
                q.leased_until,
                q.auth_generation AS queue_auth_generation,
                pa.moderation_generation,
                pp.preferences_json,
                (
                    SELECT EXISTS (
                        SELECT 1 FROM activity_subscriptions sub
                        WHERE sub.subscriber_did = param.did
                          AND sub.subject_did = $5
                          AND (
                              CASE 
                                  WHEN $4 = 'activity_post' THEN sub.include_posts = TRUE
                                  WHEN $4 = 'activity_reply' THEN sub.include_replies = TRUE
                                  ELSE (sub.include_posts = TRUE OR sub.include_replies = TRUE)
                              END
                          )
                    )
                ) AS activity_sub_active,
                (tm.user_did IS NOT NULL) AS thread_is_muted,
                amv.verdict AS cached_moderation_verdict
            FROM (SELECT $1::text AS did) param
            LEFT JOIN push_accounts pa ON pa.account_did = param.did
            LEFT JOIN user_devices ud ON ud.did = param.did AND ud.device_token = $2
            LEFT JOIN push_event_queue q ON q.id = $3
            LEFT JOIN push_preferences pp ON pp.account_did = param.did
            LEFT JOIN thread_mutes tm ON tm.user_did = param.did AND tm.thread_root_uri = $6
            LEFT JOIN actor_moderation_verdict amv ON amv.recipient_did = param.did AND amv.actor_did = $5
              AND amv.generation = pa.moderation_generation
            "#,
        )
        .bind(recipient_did)
        .bind(device_token)
        .bind(queue_id)
        .bind(notification_type)
        .bind(actor_did)
        .bind(thread_root_uri)
        .fetch_one(&mut **tx)
        .await?;

        // 1. Account status: must exist and not be revoked
        let account_did: Option<String> = row.try_get("account_did")?;
        let auth_revoked_at: Option<time::OffsetDateTime> = row.try_get("auth_revoked_at")?;
        let current_auth_generation: Option<i64> = row.try_get("auth_generation")?;
        let current_gen = current_auth_generation.unwrap_or(0);
        if account_did.is_none() || auth_revoked_at.is_some() || current_gen <= 0 {
            return Ok(PreSendFenceOutcome::Revoked);
        }
        if let Some(expected_gen) = expected_auth_generation {
            if expected_gen <= 0 || current_gen != expected_gen {
                return Ok(PreSendFenceOutcome::Revoked);
            }
        }

        // 2. Device status: must exist and be active, with no active ownership by another DID
        let device_is_active: Option<bool> = row.try_get("device_is_active")?;
        let other_active_count: i64 = row.try_get("other_active_device_count")?;
        if device_is_active != Some(true) || other_active_count > 0 {
            return Ok(PreSendFenceOutcome::DeviceInactive);
        }

        // 3. Queue lease validity & auth generation consistency (if queue worker)
        if let Some((_id, expected_token, expected_queue_auth_gen)) = queue_fence {
            let lease_token: Option<uuid::Uuid> = row.try_get("lease_token")?;
            let leased_until: Option<time::OffsetDateTime> = row.try_get("leased_until")?;
            let queue_auth_gen: Option<i64> = row.try_get("queue_auth_generation")?;
            let now = time::OffsetDateTime::now_utc();

            let is_valid = lease_token == Some(expected_token)
                && leased_until.map(|u| u >= now).unwrap_or(false);

            if !is_valid {
                return Ok(PreSendFenceOutcome::LeaseLost);
            }

            if expected_queue_auth_gen <= 0 || current_gen != expected_queue_auth_gen {
                return Ok(PreSendFenceOutcome::Revoked);
            }
            if let Some(q_gen) = queue_auth_gen {
                if q_gen <= 0 || current_gen != q_gen {
                    return Ok(PreSendFenceOutcome::Revoked);
                }
            } else {
                return Ok(PreSendFenceOutcome::Revoked);
            }
        }

        // 4. Push preferences
        let prefs_json: Option<serde_json::Value> = row.try_get("preferences_json")?;
        if let Some(json_val) = prefs_json {
            if let Ok(prefs) = serde_json::from_value::<types::PushPreferencesDocument>(json_val) {
                if !prefs.is_push_enabled_for(notification_type) {
                    return Ok(PreSendFenceOutcome::PreferencesDisabled);
                }
            }
        }

        // 5. Activity subscriptions: verify active subscription for activity notifications
        if notification_type.starts_with("activity_") || notification_type == "activitySubscription" {
            let activity_sub_active: bool = row.try_get("activity_sub_active")?;
            if !activity_sub_active {
                return Ok(PreSendFenceOutcome::PreferencesDisabled);
            }
        }

        // 6. Thread mute
        let thread_is_muted: bool = row.try_get("thread_is_muted")?;
        if thread_is_muted {
            return Ok(PreSendFenceOutcome::ThreadMuted);
        }

        // 7. Moderation verdict: fail closed / suppress on missing or suppressing verdict
        let cached_verdict: Option<serde_json::Value> = row.try_get("cached_moderation_verdict")?;
        match cached_verdict {
            None => {
                // Missing moderation verdict in fence suppresses/defers delivery (e.g. after invalidation/mute)
                return Ok(PreSendFenceOutcome::ModerationSuppressed);
            }
            Some(verdict_val) => {
                match serde_json::from_value::<moderation_verdict::ModerationVerdict>(verdict_val) {
                    Ok(verdict) => {
                        if verdict.suppresses(notification_type) {
                            return Ok(PreSendFenceOutcome::ModerationSuppressed);
                        }
                    }
                    Err(_) => {
                        return Ok(PreSendFenceOutcome::ModerationSuppressed);
                    }
                }
            }
        }

        Ok(PreSendFenceOutcome::Authorized)
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

    pub async fn process_queue_batch(self: &Arc<Self>, state: &Arc<AppState>) -> Result<usize> {
        let Some(apns) = self.apns.clone() else {
            return Ok(0);
        };

        let batch_size = i64::from(self.config.queue_batch_size.max(1));
        let rows = self.queue.claim_ready(batch_size).await?;
        if rows.is_empty() {
            return Ok(0);
        }

        let count = rows.len();
        let mut revoked_dids: HashSet<String> = HashSet::new();
        let send_timeout = std::time::Duration::from_secs(self.config.send_timeout_seconds.max(1));

        for row in rows {
            let Some(lease_token) = row.lease_token else {
                tracing::warn!(id = row.id, "Skipping claimed queue row without lease token");
                continue;
            };
            let heartbeat = match HeartbeatLease::start(self.queue.clone(), row.id, lease_token, row.lease_version).await {
                Ok(Some(h)) => h,
                Ok(None) => {
                    tracing::warn!(id = row.id, "Queue lease expired or was lost before processing; skipping");
                    continue;
                }
                Err(err) => {
                    tracing::warn!(id = row.id, error = %err, "Failed to initialize heartbeat lease; skipping");
                    continue;
                }
            };

            // Fast-path: skip rows for DIDs already known revoked in this batch
            if revoked_dids.contains(&row.recipient_did) {
                tracing::debug!(
                    recipient = %row.recipient_did,
                    notification_type = %row.notification_type,
                    "Skipping push event for revoked account (batch cache)"
                );
                let (token, version) = heartbeat.stop().await;
                let _ = self.queue.delete_fenced(row.id, token, version).await;
                continue;
            }

            // Staleness guard: drop events that sat in the queue past 24h
            let age = time::OffsetDateTime::now_utc() - row.created_at;
            if age > time::Duration::hours(24) {
                tracing::debug!(
                    recipient = %row.recipient_did,
                    notification_type = %row.notification_type,
                    age_secs = age.whole_seconds(),
                    "Dropping stale queued push event"
                );
                let (token, version) = heartbeat.stop().await;
                let _ = self.queue.delete_fenced(row.id, token, version).await;
                continue;
            }

            let evaluated = tokio::time::timeout(
                DECISION_TIMEOUT,
                self.decision.evaluate(state, self, &row),
            )
            .await;
            let evaluated = match evaluated {
                Ok(result) => result,
                Err(_elapsed) => {
                    tracing::warn!(
                        recipient = %row.recipient_did,
                        notification_type = %row.notification_type,
                        timeout_secs = DECISION_TIMEOUT.as_secs(),
                        "Push decision timed out; scheduling retry and moving on"
                    );
                    let (token, version) = heartbeat.stop().await;
                    if let Err(update_err) = self
                        .queue
                        .retry_later_fenced(
                            row.id,
                            token,
                            version,
                            row.attempts,
                            "decision_timeout",
                        )
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
                    let (token, version) = heartbeat.stop().await;
                    if let Err(err) = self.queue.delete_fenced(row.id, token, version).await {
                        tracing::error!(error = %err, "Failed to delete dropped push event");
                    }
                }
                Ok(QueueDisposition::Deliver(deliveries)) => {
                    let mut transient_error = None;
                    let mut is_revoked = false;
                    let mut is_lease_lost = false;

                    for (registration, notification) in deliveries {
                        let mut tx = match self.queue.pool().begin().await {
                            Ok(t) => t,
                            Err(err) => {
                                transient_error = Some(err.into());
                                break;
                            }
                        };
                        if let Err(err) = acquire_account_and_device_lock(&mut tx, &registration.did, &registration.device_token).await {
                            let _ = tx.rollback().await;
                            transient_error = Some(err);
                            break;
                        }
                        let fence_outcome = match self
                            .verify_pre_send_fence_tx(
                                &mut tx,
                                &registration.did,
                                &row.actor_did,
                                &registration.device_token,
                                &row.notification_type,
                                row.thread_root_uri.as_deref(),
                                Some((row.id, lease_token, row.auth_generation)),
                                Some(row.auth_generation),
                            )
                            .await
                        {
                            Ok(outcome) => outcome,
                            Err(err) => {
                                let _ = tx.rollback().await;
                                tracing::error!(error = %err, "Pre-send fence check failed closed");
                                transient_error = Some(err);
                                break;
                            }
                        };

                        match fence_outcome {
                            PreSendFenceOutcome::Authorized => {}
                            PreSendFenceOutcome::Revoked => {
                                let _ = tx.commit().await;
                                tracing::info!(
                                    recipient = %row.recipient_did,
                                    "Auth revoked immediately before APNs send; cancelling remaining deliveries"
                                );
                                revoked_dids.insert(row.recipient_did.clone());
                                is_revoked = true;
                                break;
                            }
                            PreSendFenceOutcome::LeaseLost => {
                                let _ = tx.commit().await;
                                tracing::warn!(
                                    id = row.id,
                                    recipient = %row.recipient_did,
                                    "Queue lease expired or was reclaimed by another worker; aborting delivery"
                                );
                                is_lease_lost = true;
                                break;
                            }
                            PreSendFenceOutcome::DeviceInactive => {
                                let _ = tx.commit().await;
                                tracing::info!(
                                    did = %registration.did,
                                    token = %registration.device_token,
                                    "Device is no longer active for recipient; skipping"
                                );
                                continue;
                            }
                            PreSendFenceOutcome::PreferencesDisabled
                            | PreSendFenceOutcome::ThreadMuted
                            | PreSendFenceOutcome::ModerationSuppressed => {
                                let _ = tx.commit().await;
                                tracing::info!(
                                    recipient = %row.recipient_did,
                                    outcome = ?fence_outcome,
                                    "Delivery suppressed by preference/mute/moderation fence; skipping device"
                                );
                                continue;
                            }
                        }

                        let send_fut = apns.send(&registration, &notification);
                        let send_res = match tokio::time::timeout(send_timeout, send_fut).await {
                            Ok(res) => res,
                            Err(_elapsed) => {
                                let _ = tx.commit().await;
                                tracing::warn!(
                                    did = %registration.did,
                                    token = %registration.device_token,
                                    "APNs send timed out; scheduling retry"
                                );
                                transient_error = Some(anyhow!("APNs send timed out"));
                                break;
                            }
                        };
                        let _ = tx.commit().await;

                        match send_res {
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
                                        tracing::warn!(
                                            did = %registration.did,
                                            token = %registration.device_token,
                                            env = delivered_env,
                                            error = %err,
                                            "Failed to persist learned APNs environment"
                                        );
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
                                is_revoked = true;
                                break;
                            }
                            Err(err) => {
                                transient_error = Some(err);
                                break;
                            }
                        }
                    }

                    let (token, final_version) = heartbeat.stop().await;

                    if is_lease_lost {
                        // Lease lost to another worker — neither acknowledge nor delete
                        tracing::warn!(id = row.id, "Queue lease lost; skipping acknowledgement");
                    } else if is_revoked || revoked_dids.contains(&row.recipient_did) {
                        // Auth was revoked during delivery — terminal deletion
                        match self.queue.delete_fenced(row.id, token, final_version).await {
                            Ok(true) => {}
                            Ok(false) => {
                                tracing::warn!(id = row.id, "delete_fenced CAS returned false (lease lost) on revoked delete");
                            }
                            Err(err) => {
                                tracing::error!(error = %err, "Failed to delete revoked-account push event");
                            }
                        }
                    } else if let Some(err) = transient_error {
                        tracing::warn!(
                            recipient = %row.recipient_did,
                            notification_type = %row.notification_type,
                            error = %err,
                            "Transient push delivery failure; scheduling retry"
                        );
                        match self
                            .queue
                            .retry_later_fenced(row.id, token, final_version, row.attempts, &err.to_string())
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                tracing::warn!(id = row.id, "retry_later_fenced CAS returned false (lease lost)");
                            }
                            Err(update_err) => {
                                tracing::error!(error = %update_err, "Failed to schedule push retry");
                            }
                        }
                    } else {
                        match self.queue.delete_fenced(row.id, token, final_version).await {
                            Ok(true) => {}
                            Ok(false) => {
                                tracing::warn!(id = row.id, "delete_fenced CAS returned false (lease lost) on delivery acknowledgment");
                            }
                            Err(err) => {
                                tracing::error!(error = %err, "Failed to delete delivered push event");
                            }
                        }
                    }
                }
                Err(err) if is_auth_revocation_error(&err) => {
                    tracing::info!(
                        recipient = %row.recipient_did,
                        error = %err,
                        "Auth revoked during decision evaluation; skipping remaining events for account"
                    );
                    revoked_dids.insert(row.recipient_did.clone());
                    let (token, version) = heartbeat.stop().await;
                    if let Err(del_err) = self.queue.delete_fenced(row.id, token, version).await {
                        tracing::error!(error = %del_err, "Failed to delete revoked-account push event");
                    }
                }
                Err(err) if is_unregistered_account_error(&err) => {
                    tracing::info!(
                        recipient = %row.recipient_did,
                        notification_type = %row.notification_type,
                        "Recipient has no push account; dropping undeliverable event"
                    );
                    let (token, version) = heartbeat.stop().await;
                    if let Err(del_err) = self.queue.delete_fenced(row.id, token, version).await {
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
                    let (token, version) = heartbeat.stop().await;
                    if let Err(update_err) = self
                        .queue
                        .retry_later_fenced(row.id, token, version, row.attempts, &err.to_string())
                        .await
                    {
                        tracing::error!(error = %update_err, "Failed to schedule push retry");
                    }
                }
            }
        }
        Ok(count)
    }

    async fn run_worker_loop(self: Arc<Self>, state: Arc<AppState>) {
        if self.apns.is_none() {
            return;
        }

        let poll_interval = std::time::Duration::from_millis(self.config.queue_poll_interval_ms);
        tracing::info!("Push queue worker started");

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

            match self.process_queue_batch(&state).await {
                Ok(0) => {
                    tokio::time::sleep(poll_interval).await;
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::error!(error = %err, "Push queue processing failed");
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
                let send_timeout = std::time::Duration::from_secs(self.config.send_timeout_seconds.max(1));
                let mut delivered_count = 0usize;
                let mut is_revoked = false;
                let mut had_transient_error = false;
                for registration in &registrations {
                    let mut tx = match self.queue.pool().begin().await {
                        Ok(t) => t,
                        Err(err) => {
                            tracing::error!(error = %err, "Failed to begin transaction for chat fast-path");
                            had_transient_error = true;
                            break;
                        }
                    };
                    if let Err(err) = acquire_account_and_device_lock(&mut tx, &event.recipient_did, &registration.device_token).await {
                        let _ = tx.rollback().await;
                        tracing::error!(error = %err, "Failed to acquire advisory lock for chat fast-path");
                        had_transient_error = true;
                        break;
                    }

                    let fence_outcome = match self
                        .verify_pre_send_fence_tx(
                            &mut tx,
                            &event.recipient_did,
                            &event.sender_did,
                            &registration.device_token,
                            "chat_message",
                            None,
                            None,
                            Some(event.auth_generation),
                        )
                        .await
                    {
                        Ok(outcome) => outcome,
                        Err(err) => {
                            let _ = tx.rollback().await;
                            tracing::error!(error = %err, "Chat fast-path pre-send fence failed closed");
                            had_transient_error = true;
                            break;
                        }
                    };

                    match fence_outcome {
                        PreSendFenceOutcome::Authorized => {}
                        PreSendFenceOutcome::Revoked => {
                            let _ = tx.commit().await;
                            tracing::info!(
                                recipient = %event.recipient_did,
                                "Auth revoked before chat fast-path APNs send; cancelling remaining deliveries"
                            );
                            is_revoked = true;
                            break;
                        }
                        PreSendFenceOutcome::DeviceInactive => {
                            let _ = tx.commit().await;
                            tracing::info!(
                                did = %registration.did,
                                token = %registration.device_token,
                                "Device is no longer active for recipient (chat fast-path); skipping"
                            );
                            continue;
                        }
                        PreSendFenceOutcome::PreferencesDisabled
                        | PreSendFenceOutcome::ThreadMuted
                        | PreSendFenceOutcome::ModerationSuppressed
                        | PreSendFenceOutcome::LeaseLost => {
                            let _ = tx.commit().await;
                            tracing::info!(
                                recipient = %event.recipient_did,
                                outcome = ?fence_outcome,
                                "Chat fast-path delivery suppressed by fence; skipping device"
                            );
                            continue;
                        }
                    }

                    let send_fut = apns.send(registration, &notification);
                    let send_res = match tokio::time::timeout(send_timeout, send_fut).await {
                        Ok(res) => res,
                        Err(_elapsed) => {
                            let _ = tx.commit().await;
                            tracing::warn!(
                                did = %registration.did,
                                token = %registration.device_token,
                                "Chat fast-path APNs send timed out"
                            );
                            had_transient_error = true;
                            break;
                        }
                    };
                    let _ = tx.commit().await;
                    match send_res {
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
                        Err(err) if is_auth_revocation_error(&err) => {
                            tracing::info!(
                                recipient = %event.recipient_did,
                                error = %err,
                                "Auth revoked during chat fast-path send; cancelling"
                            );
                            is_revoked = true;
                            break;
                        }
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                did = %event.recipient_did,
                                token = %registration.device_token,
                                "Chat push fast-path delivery failed"
                            );
                            had_transient_error = true;
                        }
                    }
                }

                // If auth was revoked, drop terminally — NEVER requeue revoked events
                if is_revoked {
                    tracing::info!(
                        recipient = %event.recipient_did,
                        "Dropping chat push event terminally due to auth revocation"
                    );
                } else if delivered_count == 0 && had_transient_error {
                    // Only hand back to durable queue if nothing was delivered due to transient failures
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
