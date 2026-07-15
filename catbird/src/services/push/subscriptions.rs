use anyhow::Result;
use reqwest::{header::HeaderMap, Method, StatusCode, Url};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use std::{collections::HashMap, future::Future, pin::Pin};

use crate::config::outbound_policy::OutboundPolicy;

use super::types::{ActivitySubscriptionPreference, ActivitySubscriptionRow};

const DEFAULT_PAGE_LIMIT: usize = 50;
const MAX_PAGE_LIMIT: usize = 50;
const PROFILE_BATCH_SIZE: usize = 25;

type DiscoveryResponse = Result<(StatusCode, bytes::Bytes)>;
type DiscoveryFuture<'a> = Pin<Box<dyn Future<Output = DiscoveryResponse> + Send + 'a>>;

pub(crate) fn bounded_page_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(DEFAULT_PAGE_LIMIT).clamp(1, MAX_PAGE_LIMIT)
}

pub(crate) fn bounded_page_offset(cursor: Option<&str>) -> i64 {
    cursor
        .and_then(|cursor| cursor.parse::<i64>().ok())
        .filter(|offset| *offset >= 0)
        .unwrap_or(0)
}

fn next_page_cursor(offset: i64, limit: usize, has_more: bool) -> Option<String> {
    has_more.then(|| offset.saturating_add(limit as i64).to_string())
}

trait ProfileDiscovery: Send + Sync {
    fn get<'a>(&'a self, url: &'a str) -> DiscoveryFuture<'a>;
}

impl ProfileDiscovery for OutboundPolicy {
    fn get<'a>(&'a self, url: &'a str) -> DiscoveryFuture<'a> {
        Box::pin(async move {
            let (status, _headers, body) = self
                .send_discovery(Method::GET, url, HeaderMap::new(), None)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            Ok((status, body))
        })
    }
}

pub(crate) struct ActivitySubscriptionsPage {
    pub profiles: Vec<Value>,
    pub cursor: Option<String>,
}

#[derive(Clone)]
pub struct PushSubscriptions {
    db_pool: Pool<Postgres>,
}

impl PushSubscriptions {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self { db_pool }
    }

    /// Source-compatible bounded list for existing callers.
    #[allow(dead_code)] // Public library compatibility; the Nest binary uses the paged API below.
    pub async fn list(&self, subscriber_did: &str) -> Result<Vec<ActivitySubscriptionRow>> {
        let mut rows = self
            .list_page_rows(subscriber_did, 0, DEFAULT_PAGE_LIMIT)
            .await?;
        rows.truncate(DEFAULT_PAGE_LIMIT);
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

    async fn list_page_rows(
        &self,
        subscriber_did: &str,
        offset: i64,
        limit: usize,
    ) -> Result<Vec<ActivitySubscriptionRow>> {
        let limit = bounded_page_limit(Some(limit));
        let database_limit = i64::try_from(limit.saturating_add(1))?;
        let rows = sqlx::query_as::<_, ActivitySubscriptionRow>(
            r#"
            SELECT subject_did, include_posts, include_replies
            FROM activity_subscriptions
            WHERE subscriber_did = $1
            ORDER BY subject_did
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(subscriber_did)
        .bind(database_limit)
        .bind(offset.max(0))
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows)
    }

    /// Source-compatible bounded hydration for existing callers. The supplied
    /// client is retained in the signature, while fixed-AppView traffic now
    /// uses the shared validated discovery transport and response budget.
    #[allow(dead_code)] // Public library compatibility; the Nest binary uses the paged API below.
    pub async fn list_profiles_json(
        &self,
        _http_client: &reqwest::Client,
        subscriber_did: &str,
    ) -> Result<Vec<Value>> {
        Ok(self
            .list_profiles_json_with(&OutboundPolicy, subscriber_did, 0, DEFAULT_PAGE_LIMIT)
            .await?
            .profiles)
    }

    pub(crate) async fn list_profiles_page_json(
        &self,
        outbound_policy: &OutboundPolicy,
        subscriber_did: &str,
        offset: i64,
        limit: usize,
    ) -> Result<ActivitySubscriptionsPage> {
        self.list_profiles_json_with(outbound_policy, subscriber_did, offset, limit)
            .await
    }

    async fn list_profiles_json_with<D: ProfileDiscovery>(
        &self,
        discovery: &D,
        subscriber_did: &str,
        offset: i64,
        limit: usize,
    ) -> Result<ActivitySubscriptionsPage> {
        let limit = bounded_page_limit(Some(limit));
        let mut rows = self.list_page_rows(subscriber_did, offset, limit).await?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let profiles = hydrate_rows(discovery, rows).await?;
        let cursor = next_page_cursor(offset, limit, has_more);

        Ok(ActivitySubscriptionsPage { profiles, cursor })
    }
}

async fn hydrate_rows<D: ProfileDiscovery>(
    discovery: &D,
    subscriptions: Vec<ActivitySubscriptionRow>,
) -> Result<Vec<Value>> {
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
    for chunk in actor_ids.chunks(PROFILE_BATCH_SIZE) {
        let mut url = Url::parse("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfiles")?;
        {
            let mut qp = url.query_pairs_mut();
            for actor in chunk {
                qp.append_pair("actors", actor);
            }
        }

        let (status, body) = discovery.get(url.as_str()).await?;
        if !status.is_success() {
            tracing::warn!(
                status = %status,
                "Failed to fetch activity subscription profile batch from public appview"
            );
            continue;
        }

        let payload: Value = serde_json::from_slice(&body)?;
        if let Some(items) = payload.get("profiles").and_then(|value| value.as_array()) {
            for item in items {
                let mut profile = item.clone();
                if let Some(did) = profile.get("did").and_then(|value| value.as_str()) {
                    if let Some(subscription) = lookup.get(did) {
                        let viewer = profile.get("viewer").cloned().unwrap_or_else(|| json!({}));
                        let mut viewer_obj = viewer.as_object().cloned().unwrap_or_default();
                        viewer_obj.insert("activitySubscription".to_string(), subscription.clone());

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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct RecordingDiscovery {
        batch_sizes: Arc<Mutex<Vec<usize>>>,
        rejection: Option<&'static str>,
    }

    impl RecordingDiscovery {
        fn rejecting(message: &'static str) -> Self {
            Self {
                rejection: Some(message),
                ..Self::default()
            }
        }

        fn batch_sizes(&self) -> Vec<usize> {
            self.batch_sizes.lock().expect("batch lock").clone()
        }
    }

    impl ProfileDiscovery for RecordingDiscovery {
        fn get<'a>(&'a self, url: &'a str) -> DiscoveryFuture<'a> {
            Box::pin(async move {
                let actors = Url::parse(url)?
                    .query_pairs()
                    .filter_map(|(key, value)| (key == "actors").then(|| value.into_owned()))
                    .collect::<Vec<_>>();
                self.batch_sizes
                    .lock()
                    .expect("batch lock")
                    .push(actors.len());

                if let Some(message) = self.rejection {
                    anyhow::bail!(message);
                }

                let profiles = actors
                    .into_iter()
                    .map(|did| json!({ "did": did }))
                    .collect::<Vec<_>>();
                Ok((
                    StatusCode::OK,
                    serde_json::to_vec(&json!({ "profiles": profiles }))?.into(),
                ))
            })
        }
    }

    fn subscription_rows(count: usize) -> Vec<ActivitySubscriptionRow> {
        (0..count)
            .map(|index| ActivitySubscriptionRow {
                subject_did: format!("did:plc:subject{index:05}"),
                include_posts: true,
                include_replies: index % 2 == 0,
            })
            .collect()
    }

    #[tokio::test]
    async fn legacy_public_call_shapes_remain_source_compatible() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/nest_compile_only")
            .expect("lazy pool");
        let service = PushSubscriptions::new(pool);
        let client = reqwest::Client::new();

        if std::hint::black_box(false) {
            let _: Result<Vec<ActivitySubscriptionRow>> = service.list("did:plc:test").await;
            let _: Result<Vec<Value>> = service.list_profiles_json(&client, "did:plc:test").await;
        }
    }

    #[test]
    fn request_limit_and_cursor_are_bounded_before_database_access() {
        assert_eq!(bounded_page_limit(None), 50);
        assert_eq!(bounded_page_limit(Some(0)), 1);
        assert_eq!(bounded_page_limit(Some(50)), 50);
        assert_eq!(bounded_page_limit(Some(usize::MAX)), 50);

        assert_eq!(bounded_page_offset(None), 0);
        assert_eq!(bounded_page_offset(Some("not-a-cursor")), 0);
        assert_eq!(bounded_page_offset(Some("-1")), 0);
        assert_eq!(bounded_page_offset(Some(&u128::MAX.to_string())), 0);
        assert_eq!(bounded_page_offset(Some("50")), 50);
    }

    #[test]
    fn page_cursor_advances_only_when_limit_plus_one_exists() {
        assert_eq!(next_page_cursor(0, 50, true).as_deref(), Some("50"));
        assert_eq!(next_page_cursor(50, 50, true).as_deref(), Some("100"));
        assert_eq!(next_page_cursor(50, 50, false), None);
    }

    #[tokio::test]
    async fn fifty_rows_hydrate_in_at_most_two_bounded_batches() {
        let discovery = RecordingDiscovery::default();
        let profiles = hydrate_rows(&discovery, subscription_rows(50))
            .await
            .expect("hydrate bounded page");

        assert_eq!(profiles.len(), 50);
        assert_eq!(discovery.batch_sizes(), vec![25, 25]);
    }

    #[tokio::test]
    async fn discovery_budget_rejection_happens_before_json_decode() {
        for message in [
            "response Content-Length exceeds 1048576-byte limit",
            "response byte limit exceeded (1048576 bytes)",
        ] {
            let discovery = RecordingDiscovery::rejecting(message);
            let error = hydrate_rows(&discovery, subscription_rows(1))
                .await
                .expect_err("oversized discovery response must fail closed");
            assert!(error.to_string().contains("1048576"));
            assert_eq!(discovery.batch_sizes(), vec![1]);
        }
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_ten_thousand_rows_load_only_limit_plus_one() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored Postgres suite");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect test Postgres");
        let subscriber = format!("did:plc:subscriptions-test-{}", uuid::Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO activity_subscriptions (
                subscriber_did, subject_did, include_posts, include_replies
            )
            SELECT $1, 'did:plc:subject' || LPAD(value::text, 10, '0'), TRUE, TRUE
            FROM generate_series(1, 10000) AS value
            "#,
        )
        .bind(&subscriber)
        .execute(&pool)
        .await
        .expect("seed subscriptions");

        let service = PushSubscriptions::new(pool.clone());
        let loaded = service
            .list_page_rows(&subscriber, 0, 50)
            .await
            .expect("load bounded page");
        assert_eq!(loaded.len(), 51);

        let discovery = RecordingDiscovery::default();
        let page = service
            .list_profiles_json_with(&discovery, &subscriber, 0, 50)
            .await
            .expect("hydrate first page");
        assert_eq!(page.profiles.len(), 50);
        assert_eq!(page.cursor.as_deref(), Some("50"));
        assert_eq!(discovery.batch_sizes(), vec![25, 25]);

        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber)
            .execute(&pool)
            .await
            .expect("clean subscriptions fixture");
    }
}
