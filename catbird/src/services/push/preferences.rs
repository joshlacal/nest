use anyhow::Result;
use serde_json::Value;
use sqlx::{Pool, Postgres, Row};

use super::types::{PushPreferencesDocument, PutPreferencesInput};

pub const RESTORE_METADATA_KEY: &str = "_catbirdRestore";

/// An explicit choice permits only events whose independent safety requirements
/// are supported. The provider's push preferences are never consulted.
pub(super) struct DeliveryPolicy {
    pub preferences: PushPreferencesDocument,
    consent_source_time: Option<i64>,
    pub chat_ready: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum EventReadiness {
    Ready,
    BeforeConsent,
    NotFollowing,
    Hold(&'static str),
}

impl DeliveryPolicy {
    pub fn event_readiness(
        &self,
        notification_type: &str,
        source_timestamp: Option<i64>,
        _thread_root_uri: Option<&str>,
    ) -> EventReadiness {
        let Some(cutoff) = self.consent_source_time else {
            // Existing local settings retain the historical delivery contract.
            return EventReadiness::Ready;
        };
        let Some(timestamp) = source_timestamp else {
            return EventReadiness::Hold("source_timestamp_unavailable");
        };
        if timestamp < cutoff {
            return EventReadiness::BeforeConsent;
        }
        let include = match notification_type {
            "chat_message" => self.preferences.chat.include.as_str(),
            "follow" => self.preferences.follow.include.as_str(),
            "like" => self.preferences.like.include.as_str(),
            "repost" => self.preferences.repost.include.as_str(),
            "via_like" => self.preferences.like_via_repost.include.as_str(),
            "via_repost" => self.preferences.repost_via_repost.include.as_str(),
            "mention" => self.preferences.mention.include.as_str(),
            "reply" => self.preferences.reply.include.as_str(),
            "quote" => self.preferences.quote.include.as_str(),
            "activity_post" | "activity_reply" => "all",
            _ => return EventReadiness::Hold("notification_type_unqualified"),
        };
        if !matches!(include, "all" | "follows") {
            return EventReadiness::Hold("notification_include_invalid");
        }
        EventReadiness::Ready
    }

    pub fn requires_following(&self, notification_type: &str) -> bool {
        if self.consent_source_time.is_none() {
            return false;
        }
        let include = match notification_type {
            "chat_message" => &self.preferences.chat.include,
            "follow" => &self.preferences.follow.include,
            "like" => &self.preferences.like.include,
            "repost" => &self.preferences.repost.include,
            "via_like" => &self.preferences.like_via_repost.include,
            "via_repost" => &self.preferences.repost_via_repost.include,
            "mention" => &self.preferences.mention.include,
            "reply" => &self.preferences.reply.include,
            "quote" => &self.preferences.quote.include,
            _ => return false,
        };
        include == "follows"
    }

    pub fn requires_thread_evidence(&self, notification_type: &str) -> bool {
        self.consent_source_time.is_some()
            && !matches!(notification_type, "follow" | "chat_message")
    }

    pub fn suppression_readiness(
        &self,
        notification_type: &str,
        following: Option<bool>,
        thread_proven: bool,
    ) -> EventReadiness {
        if self.consent_source_time.is_none() {
            return EventReadiness::Ready;
        }
        if notification_type == "chat_message" && !self.chat_ready {
            return EventReadiness::Hold("chat_bootstrap_pending");
        }
        if self.requires_following(notification_type) {
            match following {
                Some(true) => {}
                Some(false) => return EventReadiness::NotFollowing,
                None => return EventReadiness::Hold("following_relationship_evidence_required"),
            }
        }
        if self.requires_thread_evidence(notification_type) && !thread_proven {
            return EventReadiness::Hold("upstream_thread_mute_evidence_required");
        }
        EventReadiness::Ready
    }
}

/// Complete empty and nonempty snapshots use the same server-only receipt.
/// A mutation counter on its own never establishes snapshot completeness.
pub(crate) fn chat_snapshot_matches(
    payload: &Value,
    auth_generation: i64,
    mute_generation: i64,
) -> bool {
    let snapshot = &payload[RESTORE_METADATA_KEY]["chatMuteSnapshot"];
    auth_generation > 0
        && mute_generation > 0
        && snapshot["authGeneration"].as_i64() == Some(auth_generation)
        && snapshot["muteGeneration"].as_i64() == Some(mute_generation)
        && snapshot["completedAt"].as_i64().is_some_and(|at| at > 0)
}

pub(super) fn delivery_policy(payload: &Value, auth_generation: i64) -> Option<DeliveryPolicy> {
    let object = payload.as_object()?;
    let consent_source_time = match object.get(RESTORE_METADATA_KEY) {
        None => None,
        Some(metadata) => {
            if metadata["version"] != 1
                || metadata["source"] != "catbird_local"
                || metadata["localConsent"] != "Configured"
                || auth_generation <= 0
                // Consent belongs to the retained account preferences, not the
                // currently selected background session. This field records
                // provenance only; queue/device generations are fenced later.
                || metadata["authGeneration"].as_i64().is_none_or(|generation| generation <= 0)
                || metadata["automaticPushReady"] != false
            {
                return None;
            }
            Some(
                metadata["consentSourceTime"]
                    .as_i64()
                    .filter(|cutoff| *cutoff > 0)?,
            )
        }
    };
    Some(DeliveryPolicy {
        preferences: serde_json::from_value(payload.clone()).ok()?,
        consent_source_time,
        chat_ready: false,
    })
}

#[derive(Clone)]
pub struct PushPreferences {
    db_pool: Pool<Postgres>,
}

impl PushPreferences {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self { db_pool }
    }

    pub async fn get_or_create(&self, did: &str) -> Result<PushPreferencesDocument> {
        if let Some(existing) = self.get(did).await? {
            return Ok(existing);
        }

        let prefs = PushPreferencesDocument::default();
        self.put(did, &prefs).await?;
        Ok(prefs)
    }

    /// Validate the original request bearer inside the same lock as any write.
    /// Callers must not turn a pre-logout HTTP authentication into fresh state.
    pub async fn get_or_create_authenticated(
        &self,
        store: &crate::services::RedisAuthStore,
        did: &str,
        session_id: &str,
    ) -> Result<PushPreferencesDocument> {
        self.patch_authenticated(store, did, session_id, None).await
    }

    pub async fn put_authenticated(
        &self,
        store: &crate::services::RedisAuthStore,
        did: &str,
        session_id: &str,
        prefs: &PushPreferencesDocument,
    ) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, did).await?;
        store.validate_live_session_local(did, session_id).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM push_preferences WHERE account_did=$1)",
        )
        .bind(did)
        .fetch_one(&mut *tx)
        .await?;
        anyhow::ensure!(exists, "Notification preferences have not been restored");
        Self::put_in_transaction(&mut tx, did, prefs).await?;
        tx.commit().await?;
        Ok(())
    }

    /// `None` is a guarded read. A supplied patch preserves omitted local values
    /// and records explicit Catbird choices under the lifecycle account lock.
    pub async fn patch_authenticated(
        &self,
        store: &crate::services::RedisAuthStore,
        did: &str,
        session_id: &str,
        input: Option<PutPreferencesInput>,
    ) -> Result<PushPreferencesDocument> {
        if let Some(choice) = input.as_ref() {
            choice
                .validate()
                .map_err(|message| anyhow::anyhow!(message))?;
        }
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, did).await?;
        store.validate_live_session_local(did, session_id).await?;
        let current: Option<Value> = sqlx::query_scalar(
            "SELECT preferences_json FROM push_preferences WHERE account_did = $1",
        )
        .bind(did)
        .fetch_optional(&mut *tx)
        .await?;
        let payload = current.ok_or_else(|| {
            anyhow::anyhow!("Catbird notification settings have not been initialized")
        })?;
        let mut local_setup = payload
            .get(RESTORE_METADATA_KEY)
            .cloned()
            .filter(|metadata| {
                metadata["version"] == 1
                    && metadata["source"] == "catbird_local"
                    && matches!(
                        metadata["localConsent"].as_str(),
                        Some("Required" | "Configured")
                    )
            });
        let prefs = serde_json::from_value(payload)?;
        let (prefs, write) = match input {
            Some(input) => (input.apply_to(prefs), true),
            None => (prefs, false),
        };
        if write {
            Self::put_in_transaction(&mut tx, did, &prefs).await?;
            if let Some(metadata) = local_setup.as_mut() {
                let generation: Option<i64> = sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did=$1 AND auth_revoked_at IS NULL AND auth_generation>0")
                    .bind(did).fetch_optional(&mut *tx).await?;
                let generation = generation
                    .ok_or_else(|| anyhow::anyhow!("Catbird notification session changed"))?;
                // Queue timestamps have second precision. Rounding upward
                // excludes same-second events which may predate this choice.
                // Preserve the cutoff for the retained account lifetime, across
                // legitimate second-session activation, handover and upgrade.
                if metadata["localConsent"] != "Configured"
                    || metadata["consentSourceTime"]
                        .as_i64()
                        .is_none_or(|value| value <= 0)
                {
                    let cutoff: i64 = sqlx::query_scalar(
                        "SELECT CEIL(EXTRACT(EPOCH FROM clock_timestamp()))::bigint",
                    )
                    .fetch_one(&mut *tx)
                    .await?;
                    metadata["consentSourceTime"] = serde_json::json!(cutoff);
                }
                metadata["localConsent"] = serde_json::json!("Configured");
                metadata["authGeneration"] = serde_json::json!(generation);
                // Whole-account readiness is not asserted: event-specific proof
                // gates remain. Clients cannot supply this reserved metadata.
                metadata["automaticPushReady"] = serde_json::json!(false);
                sqlx::query("UPDATE push_preferences SET preferences_json=jsonb_set(preferences_json,'{_catbirdRestore}',$2::jsonb) WHERE account_did=$1")
                    .bind(did).bind(metadata.clone()).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
        Ok(prefs)
    }

    pub async fn get(&self, did: &str) -> Result<Option<PushPreferencesDocument>> {
        let row =
            sqlx::query("SELECT preferences_json FROM push_preferences WHERE account_did = $1")
                .bind(did)
                .fetch_optional(&self.db_pool)
                .await?;

        let prefs = row
            .map(|row| row.try_get::<Value, _>("preferences_json"))
            .transpose()?
            .map(serde_json::from_value)
            .transpose()?;

        Ok(prefs)
    }

    /// A missing, malformed, or restore-gated document must hold queued work.
    /// Database errors propagate separately rather than masquerading as readiness.
    pub async fn get_for_delivery(&self, did: &str) -> Result<Option<PushPreferencesDocument>> {
        Ok(self
            .get_delivery_policy(did)
            .await?
            .map(|policy| policy.preferences))
    }

    pub(super) async fn get_delivery_policy(&self, did: &str) -> Result<Option<DeliveryPolicy>> {
        let row: Option<(Value, i64, i64, bool)> = sqlx::query_as(
            "SELECT pp.preferences_json,pa.auth_generation,COALESCE(mg.generation,0),COALESCE(cp.primed_at IS NOT NULL AND cp.catch_up_required_at IS NULL,false) FROM push_preferences pp JOIN push_accounts pa USING(account_did) LEFT JOIN chat_mute_sync_generations mg USING(account_did) LEFT JOIN chat_poll_state cp USING(account_did) WHERE pp.account_did=$1 AND pa.auth_revoked_at IS NULL",
        )
        .bind(did)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row
            .as_ref()
            .and_then(|(payload, generation, mute_generation, primed)| {
                let mut policy = delivery_policy(payload, *generation)?;
                policy.chat_ready =
                    *primed && chat_snapshot_matches(payload, *generation, *mute_generation);
                Some(policy)
            }))
    }

    pub async fn put(&self, did: &str, prefs: &PushPreferencesDocument) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, did).await?;
        Self::put_in_transaction(&mut tx, did, prefs).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn put_in_transaction(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        did: &str,
        prefs: &PushPreferencesDocument,
    ) -> Result<()> {
        let payload = serde_json::to_value(prefs)?;
        sqlx::query(
            r#"
            INSERT INTO push_preferences (account_did, preferences_json, created_at, updated_at)
            VALUES ($1, $2::jsonb, NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE
            SET preferences_json = EXCLUDED.preferences_json ||
                CASE WHEN push_preferences.preferences_json ? '_catbirdRestore'
                    THEN jsonb_build_object('_catbirdRestore', push_preferences.preferences_json -> '_catbirdRestore')
                    ELSE '{}'::jsonb END,
                updated_at = NOW()
            "#,
        )
        .bind(did)
        .bind(payload)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    pub async fn patch(
        &self,
        did: &str,
        input: PutPreferencesInput,
    ) -> Result<PushPreferencesDocument> {
        let current = self.get_or_create(did).await?;
        let updated = input.apply_to(current);
        self.put(did, &updated).await?;
        Ok(updated)
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn local_readiness_requires_server_consent_cutoff_and_preserves_event_holds() {
        let mut payload = serde_json::to_value(PushPreferencesDocument::default()).unwrap();
        payload[RESTORE_METADATA_KEY] = json!({"version":1,"source":"catbird_local",
            "localConsent":"Configured","authGeneration":7,"automaticPushReady":false,"consentSourceTime":100});
        let policy = delivery_policy(&payload, 7).unwrap();
        assert_eq!(
            policy.event_readiness("follow", Some(100), None),
            EventReadiness::Ready
        );
        assert_eq!(
            policy.event_readiness("follow", Some(99), None),
            EventReadiness::BeforeConsent
        );
        assert_eq!(
            policy.event_readiness("follow", None, None),
            EventReadiness::Hold("source_timestamp_unavailable")
        );
        assert_eq!(
            policy.suppression_readiness("like", None, false),
            EventReadiness::Hold("upstream_thread_mute_evidence_required")
        );
        assert_eq!(
            policy.suppression_readiness("reply", None, false),
            EventReadiness::Hold("upstream_thread_mute_evidence_required")
        );
        assert_eq!(
            policy.suppression_readiness("chat_message", None, false),
            EventReadiness::Hold("chat_bootstrap_pending")
        );
        assert_eq!(
            policy.event_readiness("unknown", Some(100), None),
            EventReadiness::Hold("notification_type_unqualified")
        );
        payload["follow"]["include"] = json!("follows");
        assert_eq!(
            delivery_policy(&payload, 7)
                .unwrap()
                .suppression_readiness("follow", None, false),
            EventReadiness::Hold("following_relationship_evidence_required")
        );
        assert!(
            delivery_policy(&payload, 8).is_some(),
            "live session handover does not revoke account consent"
        );
        assert!(delivery_policy(&payload, 0).is_none());
        let following_policy = delivery_policy(&payload, 7).unwrap();
        assert_eq!(
            following_policy.suppression_readiness("follow", Some(true), false),
            EventReadiness::Ready
        );
        assert_eq!(
            following_policy.suppression_readiness("follow", Some(false), false),
            EventReadiness::NotFollowing
        );
        assert_eq!(
            following_policy.suppression_readiness("reply", None, true),
            EventReadiness::Ready
        );
        payload[RESTORE_METADATA_KEY]["chatMuteSnapshot"] =
            json!({"authGeneration":7,"muteGeneration":3,"completedAt":99});
        assert!(chat_snapshot_matches(&payload, 7, 3));
        assert!(!chat_snapshot_matches(&payload, 8, 3));
        assert!(!chat_snapshot_matches(&payload, 7, 4));
        assert!(!chat_snapshot_matches(&payload, 7, 0));
        for marker in [
            json!(null),
            json!({"automaticPushReady":true}),
            json!({"version":1,"source":"catbird_local","localConsent":"Required","authGeneration":7,"automaticPushReady":false,"consentSourceTime":100}),
            json!({"version":1,"source":"catbird_local","localConsent":"Configured","authGeneration":7,"automaticPushReady":true,"consentSourceTime":100}),
            json!({"version":1,"source":"catbird_local","localConsent":"Configured","authGeneration":7,"automaticPushReady":false}),
            json!({"version":1,"source":"catbird_local","localConsent":"Configured","authGeneration":0,"automaticPushReady":false,"consentSourceTime":100}),
        ] {
            payload[RESTORE_METADATA_KEY] = marker;
            assert!(delivery_policy(&payload, 7).is_none());
        }
        payload
            .as_object_mut()
            .unwrap()
            .remove(RESTORE_METADATA_KEY);
        assert_eq!(
            delivery_policy(&payload, 7)
                .unwrap()
                .event_readiness("chat_message", None, None),
            EventReadiness::Ready,
            "legacy event gates are unchanged"
        );
    }
}
