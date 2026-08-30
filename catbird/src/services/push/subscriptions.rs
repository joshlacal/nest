use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use url::Url;

use super::types::{ActivitySubscriptionPreference, ActivitySubscriptionRow};

/// Maximum number of activity subscriptions allowed per subscriber account.
pub const MAX_ACTIVITY_SUBSCRIPTIONS_PER_ACCOUNT: usize = 1000;

/// Maximum length in bytes for a subject DID string.
pub const MAX_SUBJECT_DID_LEN: usize = 256;

/// Maximum page size for listActivitySubscriptions.
pub const MAX_ACTIVITY_SUBSCRIPTION_PAGE_LIMIT: usize = 100;

/// Default page size for listActivitySubscriptions.
pub const DEFAULT_ACTIVITY_SUBSCRIPTION_PAGE_LIMIT: usize = 50;

/// Maximum cumulative response byte budget for activity subscription profile hydration (2MB).
pub const MAX_ACTIVITY_HYDRATION_BYTES: usize = 2 * 1024 * 1024;

/// Maximum aggregate duration budget for activity subscription profile hydration (30s).
pub const MAX_ACTIVITY_HYDRATION_DURATION: std::time::Duration = std::time::Duration::from_secs(30);

/// Validate subject DID format and length.
pub fn is_valid_subject_did(subject: &str) -> bool {
    subject.starts_with("did:")
        && subject.len() >= 8
        && subject.len() <= MAX_SUBJECT_DID_LEN
        && subject
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '%' | '_' | '-' | '.'))
}

/// Clamp requested subscription page limit to [1, MAX_ACTIVITY_SUBSCRIPTION_PAGE_LIMIT].
pub fn clamp_subscription_limit(limit: usize) -> usize {
    limit.clamp(1, MAX_ACTIVITY_SUBSCRIPTION_PAGE_LIMIT)
}

/// Specific typed errors that can occur during activity subscription profile hydration.
#[derive(Debug, thiserror::Error)]
pub enum ActivityHydrationError {
    #[error("Active stream concurrency limit reached (64 max)")]
    ConcurrencyExhausted,

    #[error("Rate limit exceeded: retry after {retry_after}s")]
    RateLimitExceeded { retry_after: u64 },

    #[error("Activity subscription profile hydration cumulative byte budget exceeded limit of {0} bytes")]
    ByteBudgetExceeded(usize),

    #[error("Activity subscription profile hydration duration budget exhausted ({0:?})")]
    DurationExhausted(std::time::Duration),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Hydration error: {0}")]
    Other(#[from] anyhow::Error),
}

impl From<ActivityHydrationError> for crate::error::AppError {
    fn from(err: ActivityHydrationError) -> Self {
        match err {
            ActivityHydrationError::ConcurrencyExhausted => {
                crate::error::AppError::ServiceUnavailable(
                    "Active stream concurrency limit reached. Please retry.".to_string(),
                )
            }
            ActivityHydrationError::RateLimitExceeded { retry_after } => {
                crate::error::AppError::RateLimitExceeded { retry_after }
            }
            ActivityHydrationError::ByteBudgetExceeded(_) => {
                crate::error::AppError::RateLimitExceeded { retry_after: 5 }
            }
            ActivityHydrationError::Database(e) => crate::error::AppError::Sqlx(e),
            ActivityHydrationError::Http(e) => crate::error::AppError::HttpClient(e),
            ActivityHydrationError::DurationExhausted(d) => {
                crate::error::AppError::ServiceUnavailable(format!(
                    "Activity hydration timed out ({d:?})"
                ))
            }
            ActivityHydrationError::Other(e) => crate::error::AppError::Internal(e.to_string()),
        }
    }
}

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
        // Allow delete/unmute of legacy invalid rows regardless of creation-time syntax
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, subscriber_did).await?;

        if !subscription.post && !subscription.reply {
            sqlx::query(
                "DELETE FROM activity_subscriptions WHERE subscriber_did = $1 AND subject_did = $2",
            )
            .bind(subscriber_did)
            .bind(subject_did)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(None);
        }

        if !is_valid_subject_did(subject_did) {
            anyhow::bail!("Invalid subject DID format or length");
        }

        // Serialize quota cardinality with shared account advisory transaction lock across all writers
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('activity_subscriptions:' || $1))")
            .bind(subscriber_did)
            .execute(&mut *tx)
            .await?;

        let already_exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM activity_subscriptions
                WHERE subscriber_did = $1 AND subject_did = $2
            )
            "#,
        )
        .bind(subscriber_did)
        .bind(subject_did)
        .fetch_one(&mut *tx)
        .await?;

        if !already_exists {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM activity_subscriptions WHERE subscriber_did = $1",
            )
            .bind(subscriber_did)
            .fetch_one(&mut *tx)
            .await?;

            if count as usize >= MAX_ACTIVITY_SUBSCRIPTIONS_PER_ACCOUNT {
                anyhow::bail!(
                    "Activity subscription quota exceeded: account already has {} subscriptions (max {})",
                    count,
                    MAX_ACTIVITY_SUBSCRIPTIONS_PER_ACCOUNT
                );
            }
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
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(subscription.clone()))
    }

    /// Paginate activity subscriptions directly in SQL with a stable keyset cursor on `subject_did`
    /// before hydrating only returned subjects.
    /// Returns (hydrated_profiles_json, next_cursor).
    pub async fn list_paginated_profiles(
        &self,
        http_client: &reqwest::Client,
        subscriber_did: &str,
        limit: usize,
        cursor: Option<&str>,
        semaphore: Option<Arc<tokio::sync::Semaphore>>,
        rate_limit: Option<Arc<crate::middleware::RateLimitState>>,
        session_id: Option<String>,
    ) -> Result<(Vec<Value>, Option<String>), ActivityHydrationError> {
        self.list_paginated_profiles_with_endpoint(
            http_client,
            subscriber_did,
            limit,
            cursor,
            "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfiles",
            semaphore,
            rate_limit,
            session_id,
        )
        .await
    }

    pub async fn list_paginated_profiles_with_endpoint(
        &self,
        http_client: &reqwest::Client,
        subscriber_did: &str,
        limit: usize,
        cursor: Option<&str>,
        endpoint_url: &str,
        semaphore: Option<Arc<tokio::sync::Semaphore>>,
        rate_limit: Option<Arc<crate::middleware::RateLimitState>>,
        session_id: Option<String>,
    ) -> Result<(Vec<Value>, Option<String>), ActivityHydrationError> {
        let page_limit = clamp_subscription_limit(limit);

        // Keyset pagination using subject_did cursor
        let rows = match cursor {
            Some(cur) => {
                sqlx::query_as::<_, ActivitySubscriptionRow>(
                    r#"
                    SELECT subject_did, include_posts, include_replies
                    FROM activity_subscriptions
                    WHERE subscriber_did = $1 AND subject_did > $2
                    ORDER BY subject_did ASC
                    LIMIT $3
                    "#,
                )
                .bind(subscriber_did)
                .bind(cur)
                .bind((page_limit + 1) as i64)
                .fetch_all(&self.db_pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, ActivitySubscriptionRow>(
                    r#"
                    SELECT subject_did, include_posts, include_replies
                    FROM activity_subscriptions
                    WHERE subscriber_did = $1
                    ORDER BY subject_did ASC
                    LIMIT $2
                    "#,
                )
                .bind(subscriber_did)
                .bind((page_limit + 1) as i64)
                .fetch_all(&self.db_pool)
                .await?
            }
        };

        let has_more = rows.len() > page_limit;
        let paged_rows = if has_more {
            &rows[..rows.len() - 1]
        } else {
            &rows[..]
        };

        if paged_rows.is_empty() {
            return Ok((Vec::new(), None));
        }

        let mut lookup = HashMap::new();
        let actor_ids: Vec<String> = paged_rows
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
        let mut hydrated_dids = HashSet::new();
        let start_time = std::time::Instant::now();
        let mut total_bytes = 0usize;

        // Acquire stream-admission permit before issuing any upstream HTTP request and hold across entire hydration
        let _permit = match semaphore.as_ref() {
            Some(sem) => Some(
                sem.clone()
                    .try_acquire_owned()
                    .map_err(|_| ActivityHydrationError::ConcurrencyExhausted)?,
            ),
            None => None,
        };

        for chunk in actor_ids.chunks(25) {
            let elapsed = start_time.elapsed();
            let remaining_time = match MAX_ACTIVITY_HYDRATION_DURATION.checked_sub(elapsed) {
                Some(t) if !t.is_zero() => t,
                _ => {
                    return Err(ActivityHydrationError::DurationExhausted(
                        MAX_ACTIVITY_HYDRATION_DURATION,
                    ));
                }
            };

            let remaining_bytes = MAX_ACTIVITY_HYDRATION_BYTES.saturating_sub(total_bytes);
            if remaining_bytes == 0 {
                return Err(ActivityHydrationError::ByteBudgetExceeded(
                    MAX_ACTIVITY_HYDRATION_BYTES,
                ));
            }

            let mut url =
                Url::parse(endpoint_url).map_err(|e| ActivityHydrationError::Other(e.into()))?;
            {
                let mut qp = url.query_pairs_mut();
                for actor in chunk {
                    qp.append_pair("actors", actor);
                }
            }

            let request_fut = http_client.get(url).send();
            let response = match tokio::time::timeout(remaining_time, request_fut).await {
                Ok(res) => res?,
                Err(_) => {
                    return Err(ActivityHydrationError::DurationExhausted(
                        MAX_ACTIVITY_HYDRATION_DURATION,
                    ));
                }
            };

            if !response.status().is_success() {
                // Fail page hydration atomically without advancing or returning partial profiles
                return Err(ActivityHydrationError::Other(anyhow!(
                    "Failed to fetch activity subscription profile batch from public appview: HTTP {}",
                    response.status()
                )));
            }

            // Early Content-Length check
            if let Some(content_length) = response
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok())
            {
                if content_length > remaining_bytes {
                    return Err(ActivityHydrationError::ByteBudgetExceeded(
                        MAX_ACTIVITY_HYDRATION_BYTES,
                    ));
                }
            }

            // Stream batch through Task 1 bounded reader with remaining byte budget, semaphore permit (held in outer scope), and live rate limit accounting
            use futures_util::StreamExt;
            let stream = crate::services::bounded_byte_stream_with_accounting(
                response.bytes_stream(),
                remaining_bytes,
                None, // _permit is already held for the entire hydration by enclosing scope
                rate_limit.clone(),
                session_id.clone(),
            );
            let mut stream = std::pin::pin!(stream);
            let mut body_bytes = Vec::new();

            let stream_remaining_time =
                match MAX_ACTIVITY_HYDRATION_DURATION.checked_sub(start_time.elapsed()) {
                    Some(t) if !t.is_zero() => t,
                    _ => {
                        return Err(ActivityHydrationError::DurationExhausted(
                            MAX_ACTIVITY_HYDRATION_DURATION,
                        ));
                    }
                };

            let stream_fut = async {
                while let Some(chunk_res) = stream.next().await {
                    match chunk_res {
                        Ok(chunk) => body_bytes.extend_from_slice(&chunk),
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::PermissionDenied {
                                let msg = e.to_string();
                                let retry_after = msg
                                    .split("retry after ")
                                    .nth(1)
                                    .and_then(|s| s.strip_suffix('s'))
                                    .and_then(|s| s.parse::<u64>().ok())
                                    .unwrap_or(5);
                                return Err(ActivityHydrationError::RateLimitExceeded {
                                    retry_after,
                                });
                            } else if e.kind() == std::io::ErrorKind::InvalidData {
                                return Err(ActivityHydrationError::ByteBudgetExceeded(
                                    MAX_ACTIVITY_HYDRATION_BYTES,
                                ));
                            } else {
                                return Err(ActivityHydrationError::Other(anyhow!(
                                    "Hydration stream error: {e}"
                                )));
                            }
                        }
                    }
                }
                Ok::<_, ActivityHydrationError>(())
            };

            match tokio::time::timeout(stream_remaining_time, stream_fut).await {
                Ok(res) => res?,
                Err(_) => {
                    return Err(ActivityHydrationError::DurationExhausted(
                        MAX_ACTIVITY_HYDRATION_DURATION,
                    ));
                }
            }

            total_bytes = total_bytes.saturating_add(body_bytes.len());
            if total_bytes > MAX_ACTIVITY_HYDRATION_BYTES {
                return Err(ActivityHydrationError::ByteBudgetExceeded(
                    MAX_ACTIVITY_HYDRATION_BYTES,
                ));
            }

            let payload: Value = serde_json::from_slice(&body_bytes)
                .map_err(|e| ActivityHydrationError::Other(e.into()))?;
            let items = payload
                .get("profiles")
                .and_then(|value| value.as_array())
                .ok_or_else(|| {
                    ActivityHydrationError::Other(anyhow!(
                        "AppView getProfiles response missing 'profiles' array"
                    ))
                })?;

            let mut chunk_map = HashMap::new();
            for item in items {
                let did = item
                    .get("did")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        ActivityHydrationError::Other(anyhow!(
                            "AppView profile missing 'did' field"
                        ))
                    })?;

                if !chunk.iter().any(|d| d == did) {
                    return Err(ActivityHydrationError::Other(anyhow!(
                        "AppView getProfiles returned unexpected extra DID: {}",
                        did
                    )));
                }
                if chunk_map.insert(did.to_string(), item.clone()).is_some() {
                    return Err(ActivityHydrationError::Other(anyhow!(
                        "AppView getProfiles returned duplicate DID: {}",
                        did
                    )));
                }
            }

            for did in chunk {
                let item = chunk_map.get(did).ok_or_else(|| {
                    ActivityHydrationError::Other(anyhow!(
                        "Incomplete profile hydration: missing profile for requested DID {}",
                        did
                    ))
                })?;

                let mut profile = item.clone();
                if let Some(subscription) = lookup.get(did) {
                    let viewer = profile.get("viewer").cloned().unwrap_or_else(|| json!({}));
                    let mut viewer_obj = viewer.as_object().cloned().unwrap_or_default();
                    viewer_obj.insert("activitySubscription".to_string(), subscription.clone());

                    if let Some(profile_obj) = profile.as_object_mut() {
                        profile_obj.insert("viewer".to_string(), Value::Object(viewer_obj));
                    }
                }
                profiles.push(profile);
                hydrated_dids.insert(did.clone());
            }
        }

        // Verify every selected row in paged_rows is represented
        for row in paged_rows {
            if !hydrated_dids.contains(&row.subject_did) {
                return Err(ActivityHydrationError::Other(anyhow!(
                    "Hydration incomplete: selected row {} was not hydrated",
                    row.subject_did
                )));
            }
        }

        let next_cursor = if has_more {
            paged_rows.last().map(|row| row.subject_did.clone())
        } else {
            None
        };

        Ok((profiles, next_cursor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[test]
    fn test_is_valid_subject_did() {
        assert!(is_valid_subject_did("did:plc:ragtjsm2j2vknq6z"));
        assert!(is_valid_subject_did("did:web:example.com"));
        assert!(!is_valid_subject_did("")); // empty
        assert!(!is_valid_subject_did("not-a-did")); // missing did: prefix
        assert!(!is_valid_subject_did("did:")); // too short
        assert!(!is_valid_subject_did("did:plc:has space")); // space
        assert!(!is_valid_subject_did("did:plc:null\0byte")); // null byte
        let long_did = format!("did:plc:{}", "a".repeat(MAX_SUBJECT_DID_LEN));
        assert!(!is_valid_subject_did(&long_did)); // oversized
        let exact_limit = format!("did:{}", "a".repeat(MAX_SUBJECT_DID_LEN - 4));
        assert!(is_valid_subject_did(&exact_limit)); // exact limit
    }

    #[test]
    fn test_pagination_limit_clamping() {
        assert_eq!(clamp_subscription_limit(0), 1);
        assert_eq!(clamp_subscription_limit(1), 1);
        assert_eq!(clamp_subscription_limit(50), 50);
        assert_eq!(clamp_subscription_limit(100), 100);
        assert_eq!(clamp_subscription_limit(101), 100);
        assert_eq!(clamp_subscription_limit(10000), 100);
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_sql_subscription_quota_and_legacy_delete() {
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let subs = PushSubscriptions::new(pool.clone());
        let subscriber_did = format!("did:plc:sub_quota_{}", uuid::Uuid::new_v4());

        // Clean up
        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();

        // Seed legacy invalid row directly in DB (e.g. subject is not a valid DID)
        let legacy_invalid_subject = "legacy-invalid-subject-not-a-did";
        sqlx::query(
            r#"
            INSERT INTO activity_subscriptions (subscriber_did, subject_did, include_posts, include_replies, created_at, updated_at)
            VALUES ($1, $2, TRUE, TRUE, NOW(), NOW())
            "#,
        )
        .bind(&subscriber_did)
        .bind(legacy_invalid_subject)
        .execute(&pool)
        .await
        .unwrap();

        let list = subs.list(&subscriber_did).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].subject_did, legacy_invalid_subject);

        // Deleting the legacy invalid row must SUCCEED
        let pref_delete = ActivitySubscriptionPreference {
            post: false,
            reply: false,
        };
        subs.put(&subscriber_did, legacy_invalid_subject, &pref_delete)
            .await
            .expect("Deleting legacy invalid subject row must succeed");

        let list_after = subs.list(&subscriber_did).await.unwrap();
        assert_eq!(list_after.len(), 0);

        // Creating with an invalid DID must FAIL
        let pref_create = ActivitySubscriptionPreference {
            post: true,
            reply: true,
        };
        let res = subs
            .put(&subscriber_did, legacy_invalid_subject, &pref_create)
            .await;
        assert!(res.is_err());

        // Clean up
        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_sql_concurrent_subscription_advisory_lock_race() {
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");
        let subs = PushSubscriptions::new(pool.clone());
        let subscriber_did = format!("did:plc:sub_race_{}", uuid::Uuid::new_v4());

        // Clean up
        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();

        // Seed MAX_ACTIVITY_SUBSCRIPTIONS_PER_ACCOUNT - 1 rows (999)
        let mut query_builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO activity_subscriptions (subscriber_did, subject_did, include_posts, include_replies, created_at, updated_at) "
        );
        let entries: Vec<(String, String)> = (0..(MAX_ACTIVITY_SUBSCRIPTIONS_PER_ACCOUNT - 1))
            .map(|i| (subscriber_did.clone(), format!("did:plc:seed_{:04}", i)))
            .collect();
        query_builder.push_values(entries, |mut b, (sub, subj)| {
            b.push_bind(sub)
                .push_bind(subj)
                .push_bind(true)
                .push_bind(true)
                .push("NOW()")
                .push("NOW()");
        });
        query_builder.build().execute(&pool).await.unwrap();

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM activity_subscriptions WHERE subscriber_did = $1",
        )
        .bind(&subscriber_did)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count as usize, MAX_ACTIVITY_SUBSCRIPTIONS_PER_ACCOUNT - 1);

        // Spawn 2 concurrent tasks trying to take the final slot
        let s1 = subs.clone();
        let s2 = subs.clone();
        let sub1 = subscriber_did.clone();
        let sub2 = subscriber_did.clone();
        let pref = ActivitySubscriptionPreference {
            post: true,
            reply: true,
        };
        let p1 = pref.clone();
        let p2 = pref.clone();

        let t1 = tokio::spawn(async move { s1.put(&sub1, "did:plc:final_slot_1", &p1).await });
        let t2 = tokio::spawn(async move { s2.put(&sub2, "did:plc:final_slot_2", &p2).await });

        let (r1, r2) = tokio::join!(t1, t2);
        let res1 = r1.unwrap();
        let res2 = r2.unwrap();

        let successes = [res1.is_ok(), res2.is_ok()]
            .iter()
            .filter(|&&ok| ok)
            .count();
        let failures = [res1.is_err(), res2.is_err()]
            .iter()
            .filter(|&&err| err)
            .count();
        assert_eq!(
            successes, 1,
            "Exactly one writer should succeed into the final subscription slot"
        );
        assert_eq!(failures, 1, "The second writer must fail on quota exceeded");

        let final_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM activity_subscriptions WHERE subscriber_did = $1",
        )
        .bind(&subscriber_did)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(final_count as usize, MAX_ACTIVITY_SUBSCRIPTIONS_PER_ACCOUNT);

        // Clean up
        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_sql_keyset_pagination_stability() {
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let subs = PushSubscriptions::new(pool.clone());
        let subscriber_did = format!("did:plc:sub_keyset_{}", uuid::Uuid::new_v4());

        // Clean up
        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();

        // Seed 10 sorted subjects: did:plc:item00 through did:plc:item09
        for i in 0..10 {
            let subject = format!("did:plc:item{:02}", i);
            let pref = ActivitySubscriptionPreference {
                post: true,
                reply: true,
            };
            subs.put(&subscriber_did, &subject, &pref).await.unwrap();
        }

        // Fetch Page 1 (limit 3, cursor: None) directly via SQL query to test keyset stability
        let page1 = sqlx::query_as::<_, ActivitySubscriptionRow>(
            r#"
            SELECT subject_did, include_posts, include_replies
            FROM activity_subscriptions
            WHERE subscriber_did = $1
            ORDER BY subject_did ASC
            LIMIT 4
            "#,
        )
        .bind(&subscriber_did)
        .fetch_all(&pool)
        .await
        .unwrap();

        assert_eq!(page1.len(), 4); // limit + 1
        let cursor1 = page1[2].subject_did.clone();
        assert_eq!(cursor1, "did:plc:item02");

        // Mutate before cursor: delete item01 and insert item00_before
        subs.put(
            &subscriber_did,
            "did:plc:item01",
            &ActivitySubscriptionPreference {
                post: false,
                reply: false,
            },
        )
        .await
        .unwrap();
        subs.put(
            &subscriber_did,
            "did:plc:item00_before",
            &ActivitySubscriptionPreference {
                post: true,
                reply: true,
            },
        )
        .await
        .unwrap();

        // Fetch Page 2 with keyset cursor = "did:plc:item02"
        let page2 = sqlx::query_as::<_, ActivitySubscriptionRow>(
            r#"
            SELECT subject_did, include_posts, include_replies
            FROM activity_subscriptions
            WHERE subscriber_did = $1 AND subject_did > $2
            ORDER BY subject_did ASC
            LIMIT 4
            "#,
        )
        .bind(&subscriber_did)
        .bind(&cursor1)
        .fetch_all(&pool)
        .await
        .unwrap();

        // Must get item03, item04, item05 without skipping or duplicating despite offset shifts!
        assert_eq!(page2[0].subject_did, "did:plc:item03");
        assert_eq!(page2[1].subject_did, "did:plc:item04");
        assert_eq!(page2[2].subject_did, "did:plc:item05");

        // Clean up
        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_hydration_rejects_missing_or_malformed_profiles_array() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.actor.getProfiles"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "invalid": "structure"
            })))
            .mount(&server)
            .await;

        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let subs = PushSubscriptions::new(pool.clone());
        let subscriber_did = format!("did:plc:sub_hyd_malformed_{}", uuid::Uuid::new_v4());
        subs.put(
            &subscriber_did,
            "did:plc:target1",
            &ActivitySubscriptionPreference {
                post: true,
                reply: true,
            },
        )
        .await
        .unwrap();

        let http_client = reqwest::Client::new();
        let endpoint = format!("{}/xrpc/app.bsky.actor.getProfiles", server.uri());
        let res = subs
            .list_paginated_profiles_with_endpoint(
                &http_client,
                &subscriber_did,
                10,
                None,
                &endpoint,
                None,
                None,
                None,
            )
            .await;
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("missing 'profiles' array"));

        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_hydration_rejects_incomplete_profiles_did_coverage() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // AppView returns 200 OK but only 1 of the 2 requested profiles (e.g. unresolved actor filtered)
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.actor.getProfiles"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "profiles": [
                    { "did": "did:plc:target_alice", "handle": "alice.test" }
                ]
            })))
            .mount(&server)
            .await;

        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let subs = PushSubscriptions::new(pool.clone());
        let subscriber_did = format!("did:plc:sub_hyd_incomp_{}", uuid::Uuid::new_v4());
        subs.put(
            &subscriber_did,
            "did:plc:target_alice",
            &ActivitySubscriptionPreference {
                post: true,
                reply: true,
            },
        )
        .await
        .unwrap();
        subs.put(
            &subscriber_did,
            "did:plc:target_bob",
            &ActivitySubscriptionPreference {
                post: true,
                reply: true,
            },
        )
        .await
        .unwrap();

        let http_client = reqwest::Client::new();
        let endpoint = format!("{}/xrpc/app.bsky.actor.getProfiles", server.uri());
        let res = subs
            .list_paginated_profiles_with_endpoint(
                &http_client,
                &subscriber_did,
                10,
                None,
                &endpoint,
                None,
                None,
                None,
            )
            .await;
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("Incomplete profile hydration")
                || err_msg.contains("missing profile for requested DID")
        );

        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_hydration_rejects_extra_unrequested_did() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.actor.getProfiles"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "profiles": [
                    { "did": "did:plc:target_alice", "handle": "alice.test" },
                    { "did": "did:plc:unrequested_extra", "handle": "extra.test" }
                ]
            })))
            .mount(&server)
            .await;

        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let subs = PushSubscriptions::new(pool.clone());
        let subscriber_did = format!("did:plc:sub_hyd_extra_{}", uuid::Uuid::new_v4());
        subs.put(
            &subscriber_did,
            "did:plc:target_alice",
            &ActivitySubscriptionPreference {
                post: true,
                reply: true,
            },
        )
        .await
        .unwrap();

        let http_client = reqwest::Client::new();
        let endpoint = format!("{}/xrpc/app.bsky.actor.getProfiles", server.uri());
        let res = subs
            .list_paginated_profiles_with_endpoint(
                &http_client,
                &subscriber_did,
                10,
                None,
                &endpoint,
                None,
                None,
                None,
            )
            .await;
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("unexpected extra DID"));

        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_hydration_succeeds_with_complete_coverage_and_publishes_keyset_cursor() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.actor.getProfiles"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "profiles": [
                    { "did": "did:plc:target_a", "handle": "a.test" },
                    { "did": "did:plc:target_b", "handle": "b.test" }
                ]
            })))
            .mount(&server)
            .await;

        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let subs = PushSubscriptions::new(pool.clone());
        let subscriber_did = format!("did:plc:sub_hyd_success_{}", uuid::Uuid::new_v4());
        subs.put(
            &subscriber_did,
            "did:plc:target_a",
            &ActivitySubscriptionPreference {
                post: true,
                reply: false,
            },
        )
        .await
        .unwrap();
        subs.put(
            &subscriber_did,
            "did:plc:target_b",
            &ActivitySubscriptionPreference {
                post: false,
                reply: true,
            },
        )
        .await
        .unwrap();
        subs.put(
            &subscriber_did,
            "did:plc:target_c",
            &ActivitySubscriptionPreference {
                post: true,
                reply: true,
            },
        )
        .await
        .unwrap();

        let http_client = reqwest::Client::new();
        let endpoint = format!("{}/xrpc/app.bsky.actor.getProfiles", server.uri());
        // Fetch limit 2 -> page contains target_a, target_b, has_more = true, next_cursor = target_b
        let (profiles, next_cursor) = subs
            .list_paginated_profiles_with_endpoint(
                &http_client,
                &subscriber_did,
                2,
                None,
                &endpoint,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(next_cursor, Some("did:plc:target_b".to_string()));
        assert_eq!(profiles[0]["did"], "did:plc:target_a");
        assert_eq!(profiles[0]["viewer"]["activitySubscription"]["post"], true);
        assert_eq!(
            profiles[0]["viewer"]["activitySubscription"]["reply"],
            false
        );
        assert_eq!(profiles[1]["did"], "did:plc:target_b");
        assert_eq!(profiles[1]["viewer"]["activitySubscription"]["post"], false);
        assert_eq!(profiles[1]["viewer"]["activitySubscription"]["reply"], true);

        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn test_hydration_constants_and_limits() {
        assert_eq!(MAX_ACTIVITY_HYDRATION_BYTES, 2 * 1024 * 1024);
        assert_eq!(
            MAX_ACTIVITY_HYDRATION_DURATION,
            std::time::Duration::from_secs(30)
        );
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_hydration_enforces_active_stream_semaphore_fail_closed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.actor.getProfiles"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "profiles": [
                    { "did": "did:plc:target_sem", "handle": "sem.test" }
                ]
            })))
            .mount(&server)
            .await;

        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let subs = PushSubscriptions::new(pool.clone());
        let subscriber_did = format!("did:plc:sub_hyd_sem_{}", uuid::Uuid::new_v4());
        subs.put(
            &subscriber_did,
            "did:plc:target_sem",
            &ActivitySubscriptionPreference {
                post: true,
                reply: false,
            },
        )
        .await
        .unwrap();

        let http_client = reqwest::Client::new();
        let endpoint = format!("{}/xrpc/app.bsky.actor.getProfiles", server.uri());

        // Semaphore with 1 permit, pre-acquired so 0 are available
        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        let _held_permit = sem.clone().try_acquire_owned().unwrap();

        let res = subs
            .list_paginated_profiles_with_endpoint(
                &http_client,
                &subscriber_did,
                10,
                None,
                &endpoint,
                Some(sem),
                None,
                None,
            )
            .await;

        assert!(res.is_err(), "Must fail when stream semaphore is exhausted");
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("Active stream concurrency limit reached"),
            "Error was: {err}"
        );

        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_hydration_enforces_session_byte_rate_limit() {
        use std::time::Duration;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.actor.getProfiles"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "profiles": [
                    { "did": "did:plc:target_rl", "handle": "rl.test", "displayName": "A".repeat(200) }
                ]
            })))
            .mount(&server)
            .await;

        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");
        let subs = PushSubscriptions::new(pool.clone());
        let subscriber_did = format!("did:plc:sub_hyd_rl_{}", uuid::Uuid::new_v4());
        subs.put(
            &subscriber_did,
            "did:plc:target_rl",
            &ActivitySubscriptionPreference {
                post: true,
                reply: false,
            },
        )
        .await
        .unwrap();
        let http_client = reqwest::Client::new();
        let endpoint = format!("{}/xrpc/app.bsky.actor.getProfiles", server.uri());

        let session_id = "test-hydration-sess-123".to_string();
        let rate_limit = Arc::new(crate::middleware::RateLimitState {
            session_limiter: Arc::new(crate::middleware::RateLimiter::new()),
            ip_limiter: Arc::new(crate::middleware::RateLimiter::new()),
            session_byte_limiter: Arc::new(crate::middleware::ByteRateLimiter::new()),
            global_byte_limiter: Arc::new(crate::middleware::ByteRateLimiter::new()),
            session_config: crate::middleware::RateLimitConfig::default(),
            ip_config: crate::middleware::RateLimitConfig::default(),
            session_byte_config: crate::middleware::ByteRateLimitConfig {
                max_bytes: 50,
                window: Duration::from_secs(60),
            },
            global_byte_config: crate::middleware::ByteRateLimitConfig {
                max_bytes: 1000,
                window: Duration::from_secs(60),
            },
            trusted_proxies: Vec::new(),
        });

        let res = subs
            .list_paginated_profiles_with_endpoint(
                &http_client,
                &subscriber_did,
                10,
                None,
                &endpoint,
                None,
                Some(rate_limit),
                Some(session_id),
            )
            .await;

        assert!(
            res.is_err(),
            "Must fail when session byte rate limit is exceeded"
        );
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("Rate limit exceeded") || err.contains("PermissionDenied"),
            "Error was: {err}"
        );

        sqlx::query("DELETE FROM activity_subscriptions WHERE subscriber_did = $1")
            .bind(&subscriber_did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_hydration_error_concurrency_maps_to_503() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;

        let err: crate::error::AppError = ActivityHydrationError::ConcurrencyExhausted.into();
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["error"], "TemporarilyUnavailable");
    }

    #[tokio::test]
    async fn test_hydration_error_rate_limit_maps_to_429_with_retry_after() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;

        let err: crate::error::AppError =
            ActivityHydrationError::RateLimitExceeded { retry_after: 15 }.into();
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get(axum::http::header::RETRY_AFTER).unwrap(),
            "15"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["error"], "rate_limit_exceeded");
    }

    #[tokio::test]
    async fn test_hydration_error_byte_budget_maps_to_429() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;

        let err: crate::error::AppError =
            ActivityHydrationError::ByteBudgetExceeded(2 * 1024 * 1024).into();
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(axum::http::header::RETRY_AFTER));
    }
}
