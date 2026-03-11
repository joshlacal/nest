use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::AppState;

use super::{
    apns::ApnsNotification,
    types::{PushPreferencesDocument, QueueRow, RegistrationRow},
    PushServices,
};

#[derive(Clone, Default)]
pub struct PushDecisionEngine;

pub enum QueueDisposition {
    Drop(&'static str),
    Deliver(Vec<(RegistrationRow, ApnsNotification)>),
}

impl PushDecisionEngine {
    pub fn new() -> Self {
        Self
    }

    pub async fn evaluate(
        &self,
        state: &Arc<AppState>,
        services: &PushServices,
        row: &QueueRow,
    ) -> Result<QueueDisposition> {
        let registrations = services
            .registry
            .list_active_registrations(&row.recipient_did)
            .await?;
        if registrations.is_empty() {
            return Ok(QueueDisposition::Drop("no_active_registrations"));
        }

        services
            .moderation_cache
            .ensure_fresh(state, &row.recipient_did)
            .await?;

        let prefs = services
            .preferences
            .get_or_create(&row.recipient_did)
            .await?;
        if !prefs.is_push_enabled_for(&row.notification_type) {
            return Ok(QueueDisposition::Drop("preferences_disabled"));
        }

        if services
            .moderation_cache
            .is_actor_muted_or_blocked(&row.recipient_did, &row.actor_did)
            .await?
        {
            return Ok(QueueDisposition::Drop("actor_muted_or_blocked"));
        }

        if services
            .moderation_cache
            .is_actor_list_filtered(&row.recipient_did, &row.actor_did)
            .await?
        {
            return Ok(QueueDisposition::Drop("list_filtered"));
        }

        if let Some(thread_root_uri) = row.thread_root_uri.as_deref() {
            if services
                .moderation_cache
                .is_thread_muted(&row.recipient_did, thread_root_uri)
                .await?
            {
                return Ok(QueueDisposition::Drop("thread_muted"));
            }
        }

        let notification = build_notification(row, &prefs);
        let deliveries = registrations
            .into_iter()
            .map(|registration| (registration, notification.clone()))
            .collect();

        Ok(QueueDisposition::Deliver(deliveries))
    }
}

fn build_notification(row: &QueueRow, _prefs: &PushPreferencesDocument) -> ApnsNotification {
    let title = match row.notification_type.as_str() {
        "mention" => "New mention",
        "reply" => "New reply",
        "like" => "New like",
        "follow" => "New follower",
        "repost" => "New repost",
        "quote" => "New quote",
        "via_like" => "New like via repost",
        "via_repost" => "New repost via repost",
        "activity_post" => "New post",
        "activity_reply" => "New reply",
        _ => "New notification",
    }
    .to_string();

    let body = match row.notification_type.as_str() {
        "follow" => format!("{} followed you", row.actor_did),
        "like" => format!("{} liked your post", row.actor_did),
        "repost" => format!("{} reposted your post", row.actor_did),
        "via_like" => format!("{} liked a reposted post", row.actor_did),
        "via_repost" => format!("{} reposted a reposted post", row.actor_did),
        _ => {
            let text = row
                .event_record_json
                .get("text")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();

            if text.is_empty() {
                format!("From {}", row.actor_did)
            } else {
                format!("{}: {}", row.actor_did, truncate(&text, 160))
            }
        }
    };

    let mut custom_data = HashMap::new();
    custom_data.insert("reason".to_string(), row.notification_type.clone());
    custom_data.insert("actorDid".to_string(), row.actor_did.clone());
    custom_data.insert("eventCid".to_string(), row.event_cid.clone());
    custom_data.insert("eventPath".to_string(), row.event_path.clone());
    custom_data.insert(
        "eventTimestamp".to_string(),
        row.event_timestamp.to_string(),
    );
    if let Some(subject_uri) = &row.subject_uri {
        custom_data.insert("subjectUri".to_string(), subject_uri.clone());
    }
    if let Some(thread_root_uri) = &row.thread_root_uri {
        custom_data.insert("threadRootUri".to_string(), thread_root_uri.clone());
    }

    ApnsNotification {
        title,
        body,
        user_did: row.recipient_did.clone(),
        custom_data,
    }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }
    value.chars().take(max_len).collect::<String>()
}
