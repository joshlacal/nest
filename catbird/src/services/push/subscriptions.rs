use anyhow::Result;
use jacquard_common::types::did::Did;
use reqwest::{header::HeaderMap, Method, StatusCode, Url};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres, Transaction};
use std::{collections::HashMap, future::Future, pin::Pin};

use crate::config::outbound_policy::OutboundPolicy;

use super::types::{ActivitySubscriptionPreference, ActivitySubscriptionRow};

const DEFAULT_PAGE_LIMIT: usize = 50;
const MAX_PAGE_LIMIT: usize = 50;
const PROFILE_BATCH_SIZE: usize = 25;

/// Per-subscriber storage and pagination ceiling. Existing rows may be updated
/// or deleted at the ceiling; only creation of a distinct active subscription
/// consumes capacity.
const MAX_ACTIVE_SUBSCRIPTIONS_PER_DID: i64 = 10_000;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ActivitySubscriptionWriteError {
    #[error("invalid authenticated subscriber DID")]
    InvalidSubscriberDid,
    #[error("invalid activity subscription subject DID")]
    InvalidSubjectDid,
    #[error("activity subscription limit reached")]
    QuotaExceeded,
}

impl ActivitySubscriptionWriteError {
    pub(crate) fn client_message(&self) -> &'static str {
        match self {
            Self::InvalidSubscriberDid => "Invalid authenticated subscriber DID.",
            Self::InvalidSubjectDid => "Subject must be a canonical DID.",
            Self::QuotaExceeded => "Activity subscription limit reached.",
        }
    }
}

type DiscoveryResponse = Result<(StatusCode, bytes::Bytes)>;
type DiscoveryFuture<'a> = Pin<Box<dyn Future<Output = DiscoveryResponse> + Send + 'a>>;

pub(crate) fn bounded_page_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(DEFAULT_PAGE_LIMIT).clamp(1, MAX_PAGE_LIMIT)
}

pub(crate) fn bounded_page_offset(cursor: Option<&str>) -> i64 {
    cursor
        .and_then(|cursor| cursor.parse::<i64>().ok())
        .map(bounded_offset)
        .unwrap_or(0)
}

fn bounded_offset(offset: i64) -> i64 {
    offset.clamp(0, MAX_ACTIVE_SUBSCRIPTIONS_PER_DID)
}

fn next_page_cursor(offset: i64, limit: usize, has_more: bool) -> Option<String> {
    let next_offset = bounded_offset(offset).saturating_add(limit as i64);
    (has_more && next_offset <= MAX_ACTIVE_SUBSCRIPTIONS_PER_DID).then(|| next_offset.to_string())
}

fn is_canonical_did(value: &str) -> bool {
    Did::new(value)
        .map(|parsed| parsed.as_str() == value)
        .unwrap_or(false)
}

async fn acquire_subscription_did_lock(
    transaction: &mut Transaction<'_, Postgres>,
    subscriber_did: &str,
) -> Result<()> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('activity-subscriptions:' || $1, 0))",
    )
    .bind(subscriber_did)
    .execute(&mut **transaction)
    .await?;
    Ok(())
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
        if !is_canonical_did(subscriber_did) {
            return Err(ActivitySubscriptionWriteError::InvalidSubscriberDid.into());
        }
        if !is_canonical_did(subject_did) {
            return Err(ActivitySubscriptionWriteError::InvalidSubjectDid.into());
        }

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

        let mut transaction = self.db_pool.begin().await?;

        // Existing subscriptions do not consume new capacity and must remain
        // mutable while the subscriber is at quota. Avoid the advisory lock on
        // this common update path.
        let updated = sqlx::query(
            r#"
            UPDATE activity_subscriptions
            SET include_posts = $3,
                include_replies = $4,
                updated_at = clock_timestamp()
            WHERE subscriber_did = $1 AND subject_did = $2
            "#,
        )
        .bind(subscriber_did)
        .bind(subject_did)
        .bind(subscription.post)
        .bind(subscription.reply)
        .execute(&mut *transaction)
        .await?;

        if updated.rows_affected() > 0 {
            transaction.commit().await?;
            return Ok(Some(subscription.clone()));
        }

        // Serialize only creation of distinct rows for this subscriber. The
        // post-lock UPDATE closes the race where another request inserts this
        // same subject after the optimistic update above.
        acquire_subscription_did_lock(&mut transaction, subscriber_did).await?;
        let concurrently_inserted = sqlx::query(
            r#"
            UPDATE activity_subscriptions
            SET include_posts = $3,
                include_replies = $4,
                updated_at = clock_timestamp()
            WHERE subscriber_did = $1 AND subject_did = $2
            "#,
        )
        .bind(subscriber_did)
        .bind(subject_did)
        .bind(subscription.post)
        .bind(subscription.reply)
        .execute(&mut *transaction)
        .await?;

        if concurrently_inserted.rows_affected() > 0 {
            transaction.commit().await?;
            return Ok(Some(subscription.clone()));
        }

        let active_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM activity_subscriptions WHERE subscriber_did = $1",
        )
        .bind(subscriber_did)
        .fetch_one(&mut *transaction)
        .await?;
        if active_count >= MAX_ACTIVE_SUBSCRIPTIONS_PER_DID {
            return Err(ActivitySubscriptionWriteError::QuotaExceeded.into());
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
            "#,
        )
        .bind(subscriber_did)
        .bind(subject_did)
        .bind(subscription.post)
        .bind(subscription.reply)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;

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
        .bind(bounded_offset(offset))
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
        let offset = bounded_offset(offset);
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
    use sqlx::{Connection, PgConnection, PgPool};
    use std::sync::{Arc, Mutex};
    use tokio::sync::Barrier;
    use uuid::Uuid;

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

    fn preference(post: bool, reply: bool) -> ActivitySubscriptionPreference {
        ActivitySubscriptionPreference { post, reply }
    }

    async fn live_pool() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored Postgres suite");
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await
            .expect("connect test Postgres")
    }

    fn test_subscriber(label: &str) -> String {
        format!("did:plc:subscriptions-{label}-{}", Uuid::new_v4())
    }

    fn quota_subject(index: i64) -> String {
        format!("did:plc:quota{index:010}")
    }

    async fn seed_subscriptions(pool: &PgPool, subscriber: &str, count: i64) {
        sqlx::query(
            r#"
            INSERT INTO activity_subscriptions (
                subscriber_did, subject_did, include_posts, include_replies
            )
            SELECT $1, 'did:plc:quota' || LPAD(value::text, 10, '0'), TRUE, TRUE
            FROM generate_series(1, $2) AS value
            "#,
        )
        .bind(subscriber)
        .bind(count)
        .execute(pool)
        .await
        .expect("seed subscriptions");
    }

    async fn subscription_count(pool: &PgPool, subscriber: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM activity_subscriptions WHERE subscriber_did = $1",
        )
        .bind(subscriber)
        .fetch_one(pool)
        .await
        .expect("count subscriptions")
    }

    async fn cleanup_subscriptions(pool: &PgPool, subscriber: &str) {
        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(subscriber)
            .execute(pool)
            .await
            .expect("clean subscriptions fixture");
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
        assert_eq!(
            bounded_page_offset(Some(&i64::MAX.to_string())),
            MAX_ACTIVE_SUBSCRIPTIONS_PER_DID
        );
        assert_eq!(
            bounded_page_offset(Some("10001")),
            MAX_ACTIVE_SUBSCRIPTIONS_PER_DID
        );
    }

    #[test]
    fn page_cursor_advances_only_when_limit_plus_one_exists() {
        assert_eq!(next_page_cursor(0, 50, true).as_deref(), Some("50"));
        assert_eq!(next_page_cursor(50, 50, true).as_deref(), Some("100"));
        assert_eq!(next_page_cursor(50, 50, false), None);
        assert_eq!(
            next_page_cursor(MAX_ACTIVE_SUBSCRIPTIONS_PER_DID, 50, true),
            None
        );
        assert_eq!(next_page_cursor(i64::MAX, 50, true), None);
    }

    #[test]
    fn canonical_did_validation_rejects_aliases_malformed_and_oversized_values() {
        assert!(is_canonical_did("did:plc:valid"));
        assert!(!is_canonical_did("at://did:plc:alias"));
        assert!(!is_canonical_did("not-a-did"));

        let maximum = format!("did:plc:{}", "a".repeat(2040));
        assert_eq!(maximum.len(), 2048);
        assert!(is_canonical_did(&maximum));

        let oversized = format!("{maximum}a");
        assert!(!is_canonical_did(&oversized));
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
        let pool = live_pool().await;
        let subscriber = test_subscriber("page");

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

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_quota_allows_boundary_and_updates_existing_at_capacity() {
        let pool = live_pool().await;
        let subscriber = test_subscriber("boundary");
        seed_subscriptions(&pool, &subscriber, MAX_ACTIVE_SUBSCRIPTIONS_PER_DID - 1).await;
        let service = PushSubscriptions::new(pool.clone());

        let boundary_subject = quota_subject(MAX_ACTIVE_SUBSCRIPTIONS_PER_DID);
        service
            .put(&subscriber, &boundary_subject, &preference(true, false))
            .await
            .expect("the ten-thousandth distinct subscription remains allowed");
        assert_eq!(
            subscription_count(&pool, &subscriber).await,
            MAX_ACTIVE_SUBSCRIPTIONS_PER_DID
        );

        let existing_subject = quota_subject(1);
        service
            .put(&subscriber, &existing_subject, &preference(false, true))
            .await
            .expect("an existing subscription remains mutable at quota");
        let flags = sqlx::query_as::<_, (bool, bool)>(
            r#"
            SELECT include_posts, include_replies
            FROM activity_subscriptions
            WHERE subscriber_did = $1 AND subject_did = $2
            "#,
        )
        .bind(&subscriber)
        .bind(&existing_subject)
        .fetch_one(&pool)
        .await
        .expect("load updated subscription");
        assert_eq!(flags, (false, true));

        let error = service
            .put(
                &subscriber,
                "did:plc:quota-over-capacity",
                &preference(true, true),
            )
            .await
            .expect_err("a distinct subscription above quota must be rejected");
        assert!(matches!(
            error.downcast_ref::<ActivitySubscriptionWriteError>(),
            Some(ActivitySubscriptionWriteError::QuotaExceeded)
        ));
        assert_eq!(
            subscription_count(&pool, &subscriber).await,
            MAX_ACTIVE_SUBSCRIPTIONS_PER_DID
        );

        cleanup_subscriptions(&pool, &subscriber).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with migration privileges"]
    async fn live_postgres_migration_quarantines_invalid_legacy_rows_only() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored Postgres suite");
        let mut connection = PgConnection::connect(&database_url)
            .await
            .expect("connect test Postgres");
        let schema = format!("activity_subscription_bounds_{}", Uuid::new_v4().simple());

        sqlx::raw_sql(&format!(
            r#"
            CREATE SCHEMA {schema};
            SET search_path TO {schema}, public;
            CREATE TABLE activity_subscriptions (
                id UUID PRIMARY KEY,
                subscriber_did TEXT NOT NULL,
                subject_did TEXT NOT NULL,
                include_posts BOOLEAN NOT NULL,
                include_replies BOOLEAN NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                UNIQUE (subscriber_did, subject_did)
            );
            INSERT INTO activity_subscriptions (
                id, subscriber_did, subject_did, include_posts, include_replies,
                created_at, updated_at
            )
            VALUES
                (
                    '00000000-0000-0000-0000-000000000001',
                    'did:plc:valid-subscriber',
                    'did:plc:valid-subject',
                    TRUE,
                    FALSE,
                    TIMESTAMPTZ '2026-01-01 00:00:00+00',
                    TIMESTAMPTZ '2026-01-02 00:00:00+00'
                ),
                (
                    '00000000-0000-0000-0000-000000000002',
                    'did:plc:valid-subscriber',
                    'not-a-did',
                    TRUE,
                    TRUE,
                    TIMESTAMPTZ '2026-02-01 00:00:00+00',
                    TIMESTAMPTZ '2026-02-02 00:00:00+00'
                ),
                (
                    '00000000-0000-0000-0000-000000000003',
                    'did:plc:valid-subscriber',
                    'did:plc:' || repeat('a', 2041),
                    FALSE,
                    TRUE,
                    TIMESTAMPTZ '2026-03-01 00:00:00+00',
                    TIMESTAMPTZ '2026-03-02 00:00:00+00'
                ),
                (
                    '00000000-0000-0000-0000-000000000004',
                    'at://did:plc:alias-subscriber',
                    'did:plc:valid-subject',
                    TRUE,
                    FALSE,
                    TIMESTAMPTZ '2026-04-01 00:00:00+00',
                    TIMESTAMPTZ '2026-04-02 00:00:00+00'
                ),
                (
                    '00000000-0000-0000-0000-000000000005',
                    'invalid-subscriber',
                    'invalid-subject',
                    TRUE,
                    TRUE,
                    TIMESTAMPTZ '2026-05-01 00:00:00+00',
                    TIMESTAMPTZ '2026-05-02 00:00:00+00'
                );
            "#
        ))
        .execute(&mut connection)
        .await
        .expect("seed isolated legacy subscription schema");

        sqlx::raw_sql(include_str!(
            "../../../migrations/20260718050000_activity_subscription_bounds.up.sql"
        ))
        .execute(&mut connection)
        .await
        .expect("apply activity subscription bounds migration");
        sqlx::raw_sql(include_str!(
            "../../../migrations/20260718050000_activity_subscription_bounds.up.sql"
        ))
        .execute(&mut connection)
        .await
        .expect("activity subscription bounds migration remains idempotent");

        let live_rows = sqlx::query_as::<_, (Uuid, String, String, bool, bool, bool)>(
            r#"
            SELECT
                id,
                subscriber_did,
                subject_did,
                include_posts,
                include_replies,
                created_at = TIMESTAMPTZ '2026-01-01 00:00:00+00'
                    AND updated_at = TIMESTAMPTZ '2026-01-02 00:00:00+00'
            FROM activity_subscriptions
            ORDER BY id
            "#,
        )
        .fetch_all(&mut connection)
        .await
        .expect("load live rows after quarantine");
        assert_eq!(
            live_rows,
            vec![(
                Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("valid UUID"),
                "did:plc:valid-subscriber".to_owned(),
                "did:plc:valid-subject".to_owned(),
                true,
                false,
                true,
            )]
        );

        let quarantined = sqlx::query_as::<_, (Uuid, String)>(
            r#"
            SELECT source_id, quarantine_reason
            FROM activity_subscriptions_invalid_quarantine
            ORDER BY source_id
            "#,
        )
        .fetch_all(&mut connection)
        .await
        .expect("load quarantined legacy rows");
        assert_eq!(
            quarantined
                .iter()
                .map(|(id, reason)| (id.to_string(), reason.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (
                    "00000000-0000-0000-0000-000000000002".to_owned(),
                    "invalid_subject_did"
                ),
                (
                    "00000000-0000-0000-0000-000000000003".to_owned(),
                    "invalid_subject_did"
                ),
                (
                    "00000000-0000-0000-0000-000000000004".to_owned(),
                    "invalid_subscriber_did"
                ),
                (
                    "00000000-0000-0000-0000-000000000005".to_owned(),
                    "invalid_subscriber_and_subject_did"
                ),
            ]
        );

        let validated = sqlx::query_as::<_, (String, bool)>(
            r#"
            SELECT conname, convalidated
            FROM pg_constraint
            WHERE conrelid = 'activity_subscriptions'::regclass
              AND conname IN (
                  'activity_subscriptions_subscriber_did_canonical',
                  'activity_subscriptions_subject_did_canonical'
              )
            ORDER BY conname
            "#,
        )
        .fetch_all(&mut connection)
        .await
        .expect("load DID constraints");
        assert_eq!(validated.len(), 2);
        assert!(validated.iter().all(|(_, is_validated)| *is_validated));

        let invalid_insert = sqlx::query(
            r#"
            INSERT INTO activity_subscriptions (
                id, subscriber_did, subject_did, include_posts, include_replies,
                created_at, updated_at
            )
            VALUES (
                '00000000-0000-0000-0000-000000000006',
                'did:plc:valid-subscriber',
                'not-a-did',
                TRUE,
                TRUE,
                NOW(),
                NOW()
            )
            "#,
        )
        .execute(&mut connection)
        .await
        .expect_err("validated constraint must reject a new malformed DID");
        assert_eq!(
            invalid_insert
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );

        sqlx::raw_sql(include_str!(
            "../../../migrations/20260718050000_activity_subscription_bounds.down.sql"
        ))
        .execute(&mut connection)
        .await
        .expect("apply activity subscription bounds down migration");
        let retained_quarantine = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM activity_subscriptions_invalid_quarantine",
        )
        .fetch_one(&mut connection)
        .await
        .expect("count retained quarantine after down migration");
        assert_eq!(retained_quarantine, 4);
        let restored_invalid = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM activity_subscriptions WHERE id <> '00000000-0000-0000-0000-000000000001'",
        )
        .fetch_one(&mut connection)
        .await
        .expect("check down migration did not restore invalid live rows");
        assert_eq!(restored_invalid, 0);

        sqlx::raw_sql(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE;"
        ))
        .execute(&mut connection)
        .await
        .expect("clean isolated subscription migration schema");
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_concurrent_inserts_cannot_cross_quota() {
        let pool = live_pool().await;
        let subscriber = test_subscriber("concurrent");
        seed_subscriptions(&pool, &subscriber, MAX_ACTIVE_SUBSCRIPTIONS_PER_DID - 1).await;
        let service = PushSubscriptions::new(pool.clone());
        let barrier = Arc::new(Barrier::new(3));

        let first_service = service.clone();
        let first_subscriber = subscriber.clone();
        let first_barrier = barrier.clone();
        let first = tokio::spawn(async move {
            first_barrier.wait().await;
            first_service
                .put(
                    &first_subscriber,
                    "did:plc:concurrent-a",
                    &preference(true, true),
                )
                .await
        });

        let second_service = service.clone();
        let second_subscriber = subscriber.clone();
        let second_barrier = barrier.clone();
        let second = tokio::spawn(async move {
            second_barrier.wait().await;
            second_service
                .put(
                    &second_subscriber,
                    "did:plc:concurrent-b",
                    &preference(true, true),
                )
                .await
        });

        barrier.wait().await;
        let first_result = first.await.expect("first insert task did not panic");
        let second_result = second.await.expect("second insert task did not panic");
        assert_eq!(
            usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()),
            1
        );
        assert_eq!(
            subscription_count(&pool, &subscriber).await,
            MAX_ACTIVE_SUBSCRIPTIONS_PER_DID
        );

        cleanup_subscriptions(&pool, &subscriber).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_delete_remains_available_at_quota() {
        let pool = live_pool().await;
        let subscriber = test_subscriber("delete");
        seed_subscriptions(&pool, &subscriber, MAX_ACTIVE_SUBSCRIPTIONS_PER_DID).await;
        let service = PushSubscriptions::new(pool.clone());

        let deleted = service
            .put(&subscriber, &quota_subject(1), &preference(false, false))
            .await
            .expect("deletion remains available at quota");
        assert!(deleted.is_none());
        assert_eq!(
            subscription_count(&pool, &subscriber).await,
            MAX_ACTIVE_SUBSCRIPTIONS_PER_DID - 1
        );

        service
            .put(
                &subscriber,
                "did:plc:replacement-after-delete",
                &preference(true, false),
            )
            .await
            .expect("deletion releases one subscription slot");
        assert_eq!(
            subscription_count(&pool, &subscriber).await,
            MAX_ACTIVE_SUBSCRIPTIONS_PER_DID
        );

        cleanup_subscriptions(&pool, &subscriber).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_invalid_subject_did_is_rejected_by_service_and_schema() {
        let pool = live_pool().await;
        let subscriber = test_subscriber("invalid-did");
        let service = PushSubscriptions::new(pool.clone());

        service
            .put(&subscriber, "at://did:plc:alias", &preference(true, true))
            .await
            .expect_err("non-canonical DID aliases must fail before persistence");
        assert_eq!(subscription_count(&pool, &subscriber).await, 0);

        let database_error = sqlx::query(
            r#"
            INSERT INTO activity_subscriptions (
                subscriber_did, subject_did, include_posts, include_replies
            )
            VALUES ($1, 'not-a-did', TRUE, TRUE)
            "#,
        )
        .bind(&subscriber)
        .execute(&pool)
        .await
        .expect_err("database constraint must reject malformed subject DIDs");
        assert!(database_error
            .to_string()
            .contains("activity_subscriptions_subject_did_canonical"));

        cleanup_subscriptions(&pool, &subscriber).await;
    }
}
