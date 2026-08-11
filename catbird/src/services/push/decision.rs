use anyhow::Result;
use reqwest::Url;
use serde_json::Value;
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

        let actor_label = if row.notification_type == "chat_message" {
            None
        } else {
            Some(resolve_actor_label(&state.http_client, &row.actor_did).await)
        };

        let notification = build_notification(row, &prefs, actor_label.as_deref());
        let deliveries = registrations
            .into_iter()
            .map(|registration| (registration, notification.clone()))
            .collect();

        Ok(QueueDisposition::Deliver(deliveries))
    }
}

async fn resolve_actor_label(http_client: &reqwest::Client, actor_did: &str) -> String {
    match fetch_actor_label(http_client, actor_did).await {
        Ok(Some(label)) => label,
        Ok(None) => fallback_actor_label(actor_did),
        Err(err) => {
            tracing::debug!(
                actor = %actor_did,
                error = %err,
                "Failed to hydrate push notification actor profile"
            );
            fallback_actor_label(actor_did)
        }
    }
}

async fn fetch_actor_label(
    http_client: &reqwest::Client,
    actor_did: &str,
) -> Result<Option<String>> {
    let mut url = Url::parse("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile")?;
    url.query_pairs_mut().append_pair("actor", actor_did);

    let response = http_client.get(url).send().await?;
    if !response.status().is_success() {
        tracing::debug!(
            actor = %actor_did,
            status = %response.status(),
            "Public AppView profile lookup failed for push notification actor"
        );
        return Ok(None);
    }

    let payload: Value = response.json().await?;
    Ok(actor_label_from_profile_json(&payload))
}

fn actor_label_from_profile_json(profile: &Value) -> Option<String> {
    profile
        .get("displayName")
        .and_then(Value::as_str)
        .and_then(clean_profile_label)
        .or_else(|| {
            profile
                .get("handle")
                .and_then(Value::as_str)
                .and_then(clean_profile_label)
                .map(|handle| {
                    if handle.starts_with('@') {
                        handle
                    } else {
                        format!("@{handle}")
                    }
                })
        })
}

fn clean_profile_label(value: &str) -> Option<String> {
    let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(truncate(&collapsed, 80))
    }
}

fn build_chat_notification(row: &QueueRow) -> ApnsNotification {
    let convo_id = row
        .event_record_json
        .get("convoId")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let message_id = row
        .event_record_json
        .get("messageId")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    // messageText is stripped before the event is persisted (see
    // `enqueue_push`), so this durable/fallback path never has a preview to
    // show — only the fast Redis pub/sub path (mod.rs) carries the real text,
    // and only for its single immediate delivery attempt.
    let mut custom_data = HashMap::new();
    custom_data.insert("type".to_string(), "chat_message".to_string());
    custom_data.insert("recipientDid".to_string(), row.recipient_did.clone());
    custom_data.insert("convoId".to_string(), convo_id.to_string());
    custom_data.insert("messageId".to_string(), message_id.to_string());
    custom_data.insert("senderDid".to_string(), row.actor_did.clone());

    ApnsNotification {
        title: "New Message".to_string(),
        body: "You have a new message".to_string(),
        user_did: row.recipient_did.clone(),
        custom_data,
        mutable_content: true,
        thread_id: Some(format!("chat:{}", convo_id)),
    }
}

fn build_notification(
    row: &QueueRow,
    _prefs: &PushPreferencesDocument,
    actor_label: Option<&str>,
) -> ApnsNotification {
    if row.notification_type == "chat_message" {
        return build_chat_notification(row);
    }
    let actor_label = actor_label
        .map(str::to_string)
        .unwrap_or_else(|| fallback_actor_label(&row.actor_did));

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
        "follow" => format!("{} followed you", actor_label),
        "like" => format!("{} liked your post", actor_label),
        "repost" => format!("{} reposted your post", actor_label),
        "via_like" => format!("{} liked a reposted post", actor_label),
        "via_repost" => format!("{} reposted a reposted post", actor_label),
        _ => {
            let text = row
                .event_record_json
                .get("text")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();

            if text.is_empty() {
                format!("From {}", actor_label)
            } else {
                format!("{}: {}", actor_label, truncate(&text, 160))
            }
        }
    };

    let mut custom_data = HashMap::new();
    custom_data.insert("reason".to_string(), row.notification_type.clone());
    custom_data.insert("actorDid".to_string(), row.actor_did.clone());
    custom_data.insert("actorLabel".to_string(), actor_label);
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
        mutable_content: false,
        thread_id: None,
    }
}

fn fallback_actor_label(actor_did: &str) -> String {
    if actor_did.starts_with("did:") {
        "Someone".to_string()
    } else {
        truncate(actor_did, 80)
    }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }
    value.chars().take(max_len).collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::OffsetDateTime;

    fn queue_row(notification_type: &str) -> QueueRow {
        QueueRow {
            id: 1,
            recipient_did: "did:plc:recipient".to_string(),
            actor_did: "did:plc:alice123".to_string(),
            notification_type: notification_type.to_string(),
            event_cid: "bafy-cid".to_string(),
            event_path: "app.bsky.feed.like/3abc".to_string(),
            subject_uri: None,
            thread_root_uri: None,
            event_record_json: json!({ "text": "hello from the post" }),
            event_timestamp: 1_771_234_567,
            created_at: OffsetDateTime::now_utc(),
            attempts: 0,
        }
    }

    #[test]
    fn profile_label_prefers_display_name_over_handle() {
        let profile = json!({
            "did": "did:plc:alice123",
            "handle": "alice.example",
            "displayName": "Alice Example"
        });

        assert_eq!(
            actor_label_from_profile_json(&profile).as_deref(),
            Some("Alice Example")
        );
    }

    #[test]
    fn profile_label_falls_back_to_handle_when_display_name_is_blank() {
        let profile = json!({
            "did": "did:plc:alice123",
            "handle": "alice.example",
            "displayName": "   "
        });

        assert_eq!(
            actor_label_from_profile_json(&profile).as_deref(),
            Some("@alice.example")
        );
    }

    #[test]
    fn social_notification_body_uses_hydrated_actor_label() {
        let row = queue_row("like");

        let notification = build_notification(
            &row,
            &PushPreferencesDocument::default(),
            Some("Alice Example"),
        );

        assert_eq!(notification.body, "Alice Example liked your post");
        assert!(!notification.body.contains("did:plc"));
    }

    #[test]
    fn social_notification_body_avoids_raw_did_when_label_missing() {
        let row = queue_row("repost");

        let notification = build_notification(&row, &PushPreferencesDocument::default(), None);

        assert_eq!(notification.body, "Someone reposted your post");
        assert!(!notification.body.contains("did:plc"));
    }
}
