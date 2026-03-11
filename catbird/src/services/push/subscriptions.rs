use anyhow::Result;
use reqwest::Url;
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use std::collections::HashMap;

use super::types::{ActivitySubscriptionPreference, ActivitySubscriptionRow};

#[derive(Clone)]
pub struct PushSubscriptions {
    db_pool: Pool<Postgres>,
}

impl PushSubscriptions {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self { db_pool }
    }

    pub async fn list(&self, subscriber_did: &str) -> Result<Vec<ActivitySubscriptionRow>> {
        let rows = sqlx::query_as::<_, ActivitySubscriptionRow>(
            r#"
            SELECT subject_did, include_posts, include_replies
            FROM activity_subscriptions
            WHERE subscriber_did = $1
            ORDER BY subject_did
            "#,
        )
        .bind(subscriber_did)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows)
    }

    pub async fn put(
        &self,
        subscriber_did: &str,
        subject_did: &str,
        subscription: &ActivitySubscriptionPreference,
    ) -> Result<Option<ActivitySubscriptionPreference>> {
        if !subscription.post && !subscription.reply {
            sqlx::query(
                "DELETE FROM activity_subscriptions WHERE subscriber_did = $1 AND subject_did = $2",
            )
            .bind(subscriber_did)
            .bind(subject_did)
            .execute(&self.db_pool)
            .await?;
            return Ok(None);
        }

        sqlx::query(
            r#"
            INSERT INTO activity_subscriptions (
                subscriber_did,
                subject_did,
                include_posts,
                include_replies,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, NOW(), NOW())
            ON CONFLICT (subscriber_did, subject_did)
            DO UPDATE
            SET include_posts = EXCLUDED.include_posts,
                include_replies = EXCLUDED.include_replies,
                updated_at = NOW()
            "#,
        )
        .bind(subscriber_did)
        .bind(subject_did)
        .bind(subscription.post)
        .bind(subscription.reply)
        .execute(&self.db_pool)
        .await?;

        Ok(Some(subscription.clone()))
    }

    pub async fn list_profiles_json(
        &self,
        http_client: &reqwest::Client,
        subscriber_did: &str,
    ) -> Result<Vec<Value>> {
        let subscriptions = self.list(subscriber_did).await?;
        if subscriptions.is_empty() {
            return Ok(Vec::new());
        }

        let mut lookup = HashMap::new();
        let actor_ids: Vec<String> = subscriptions
            .iter()
            .map(|row| {
                lookup.insert(
                    row.subject_did.clone(),
                    json!({
                        "post": row.include_posts,
                        "reply": row.include_replies,
                    }),
                );
                row.subject_did.clone()
            })
            .collect();

        let mut profiles = Vec::new();
        for chunk in actor_ids.chunks(25) {
            let mut url =
                Url::parse("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfiles")?;
            {
                let mut qp = url.query_pairs_mut();
                for actor in chunk {
                    qp.append_pair("actors", actor);
                }
            }

            let response = http_client.get(url).send().await?;
            if !response.status().is_success() {
                tracing::warn!(
                    status = %response.status(),
                    "Failed to fetch activity subscription profile batch from public appview"
                );
                continue;
            }

            let payload: Value = response.json().await?;
            if let Some(items) = payload.get("profiles").and_then(|value| value.as_array()) {
                for item in items {
                    let mut profile = item.clone();
                    if let Some(did) = profile.get("did").and_then(|value| value.as_str()) {
                        if let Some(subscription) = lookup.get(did) {
                            let viewer = profile
                                .get("viewer")
                                .cloned()
                                .unwrap_or_else(|| json!({}));
                            let mut viewer_obj = viewer.as_object().cloned().unwrap_or_default();
                            viewer_obj.insert(
                                "activitySubscription".to_string(),
                                subscription.clone(),
                            );

                            if let Some(profile_obj) = profile.as_object_mut() {
                                profile_obj.insert("viewer".to_string(), Value::Object(viewer_obj));
                            }
                        }
                    }
                    profiles.push(profile);
                }
            }
        }

        Ok(profiles)
    }
}
