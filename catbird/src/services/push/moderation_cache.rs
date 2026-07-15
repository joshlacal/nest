use anyhow::{anyhow, Result};
use bytes::Bytes;
use reqwest::Method;
use serde_json::Value;
use sqlx::{Pool, Postgres, Row};
use std::{collections::HashSet, future::Future, sync::Arc, time::Duration as StdDuration};
use time::{Duration, OffsetDateTime};

use crate::{
    config::AppState,
    middleware::JacquardDpopData,
    models::CatbirdSession,
    services::{AtProtoClient, ProxyResponse},
};

#[derive(Clone)]
pub struct ModerationCache {
    db_pool: Pool<Postgres>,
    sync_interval: Duration,
}

#[derive(Debug, Clone)]
struct ListSubscription {
    uri: String,
    purpose: String,
    name: Option<String>,
}

const MODERATION_SYNC_TIMEOUT: StdDuration = StdDuration::from_secs(30);
const MODERATION_MAX_PAGES: usize = 100;
const MODERATION_MAX_ITEMS_PER_COLLECTION: usize = 10_000;
const MODERATION_MAX_OPERATION_WORK: usize = 50_000;
const MODERATION_MAX_CURSOR_BYTES: usize = 1_024;
const MODERATION_MAX_CUMULATIVE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MODERATION_MAX_RETAINED_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
struct PaginationLimits {
    max_pages: usize,
    max_items: usize,
    max_response_bytes: usize,
    max_retained_bytes: usize,
}

impl PaginationLimits {
    const fn new(max_pages: usize, max_items: usize) -> Self {
        Self {
            max_pages,
            max_items,
            max_response_bytes: MODERATION_MAX_CUMULATIVE_RESPONSE_BYTES,
            max_retained_bytes: MODERATION_MAX_RETAINED_BYTES,
        }
    }

    #[cfg(test)]
    const fn with_byte_limits(
        mut self,
        max_response_bytes: usize,
        max_retained_bytes: usize,
    ) -> Self {
        self.max_response_bytes = max_response_bytes;
        self.max_retained_bytes = max_retained_bytes;
        self
    }
}

struct AggregateWorkBudget {
    used: usize,
    limit: usize,
    response_bytes: usize,
    retained_bytes: usize,
    transient_retained_bytes: usize,
}

struct ModerationSyncContext {
    deadline: tokio::time::Instant,
    work_budget: AggregateWorkBudget,
}

impl ModerationSyncContext {
    fn new() -> Self {
        Self {
            deadline: tokio::time::Instant::now() + MODERATION_SYNC_TIMEOUT,
            work_budget: AggregateWorkBudget::new(MODERATION_MAX_OPERATION_WORK),
        }
    }
}

struct ExtractedPage<T> {
    work: usize,
    retained_bytes: usize,
    items: Vec<T>,
}

#[derive(Debug)]
struct FetchedJson {
    payload: Value,
    response_bytes: usize,
}

fn extract_required_array<T, Measure, Parse>(
    payload: &Value,
    key: &str,
    max_items: usize,
    max_retained_bytes: usize,
    mut measure: Measure,
    mut parse: Parse,
) -> Result<ExtractedPage<T>>
where
    Measure: FnMut(&Value) -> Result<usize>,
    Parse: FnMut(&Value) -> Result<T>,
{
    let Some(value) = payload.get(key) else {
        return Err(anyhow!("moderation response missing required array {key}"));
    };
    let Some(array) = value.as_array() else {
        return Err(anyhow!(
            "moderation response required array {key} has wrong type"
        ));
    };
    if array.len() > max_items {
        return Err(anyhow!("moderation pagination item limit exceeded"));
    }

    let mut retained_bytes = 0usize;
    for item in array {
        let item_bytes = measure(item)
            .map_err(|error| anyhow!("moderation required array {key} item invalid: {error}"))?;
        retained_bytes = retained_bytes
            .checked_add(item_bytes)
            .ok_or_else(|| anyhow!("moderation retained byte limit exceeded"))?;
        if retained_bytes > max_retained_bytes {
            return Err(anyhow!("moderation retained byte limit exceeded"));
        }
    }

    let mut items = Vec::with_capacity(array.len());
    for item in array {
        items.push(
            parse(item).map_err(|error| {
                anyhow!("moderation required array {key} item invalid: {error}")
            })?,
        );
    }
    Ok(ExtractedPage {
        work: array.len(),
        retained_bytes,
        items,
    })
}

impl AggregateWorkBudget {
    const fn new(limit: usize) -> Self {
        Self {
            used: 0,
            limit,
            response_bytes: 0,
            retained_bytes: 0,
            transient_retained_bytes: 0,
        }
    }

    fn reserve(&mut self, count: usize) -> Result<()> {
        let next = self
            .used
            .checked_add(count)
            .ok_or_else(|| anyhow!("moderation operation work limit exceeded"))?;
        if next > self.limit {
            return Err(anyhow!("moderation operation work limit exceeded"));
        }
        self.used = next;
        Ok(())
    }

    fn reserve_response_bytes(&mut self, count: usize, limit: usize) -> Result<()> {
        let next = self
            .response_bytes
            .checked_add(count)
            .ok_or_else(|| anyhow!("moderation response byte limit exceeded"))?;
        if next > limit {
            return Err(anyhow!("moderation response byte limit exceeded"));
        }
        self.response_bytes = next;
        Ok(())
    }

    fn reserve_retained_bytes(&mut self, count: usize, limit: usize) -> Result<()> {
        let next = self
            .retained_bytes
            .checked_add(count)
            .ok_or_else(|| anyhow!("moderation retained byte limit exceeded"))?;
        let total = next
            .checked_add(self.transient_retained_bytes)
            .ok_or_else(|| anyhow!("moderation retained byte limit exceeded"))?;
        if total > limit {
            return Err(anyhow!("moderation retained byte limit exceeded"));
        }
        self.retained_bytes = next;
        Ok(())
    }

    fn reserve_transient_retained_bytes(&mut self, count: usize, limit: usize) -> Result<()> {
        let next = self
            .transient_retained_bytes
            .checked_add(count)
            .ok_or_else(|| anyhow!("moderation retained byte limit exceeded"))?;
        let total = self
            .retained_bytes
            .checked_add(next)
            .ok_or_else(|| anyhow!("moderation retained byte limit exceeded"))?;
        if total > limit {
            return Err(anyhow!("moderation retained byte limit exceeded"));
        }
        self.transient_retained_bytes = next;
        Ok(())
    }

    fn release_transient_retained_bytes(&mut self, count: usize) -> Result<()> {
        self.transient_retained_bytes = self
            .transient_retained_bytes
            .checked_sub(count)
            .ok_or_else(|| anyhow!("moderation transient retained byte accounting underflow"))?;
        Ok(())
    }

    fn remaining_retained_bytes(&self, limit: usize) -> usize {
        limit.saturating_sub(
            self.retained_bytes
                .saturating_add(self.transient_retained_bytes),
        )
    }

    #[cfg(test)]
    const fn used(&self) -> usize {
        self.used
    }
}

async fn collect_paginated<T, Fetch, FetchFuture, Extract>(
    deadline: tokio::time::Instant,
    limits: PaginationLimits,
    work_budget: &mut AggregateWorkBudget,
    mut fetch: Fetch,
    mut extract: Extract,
) -> Result<Vec<T>>
where
    Fetch: FnMut(Option<String>) -> FetchFuture,
    FetchFuture: Future<Output = Result<FetchedJson>>,
    Extract: FnMut(&Value, usize, usize) -> Result<ExtractedPage<T>>,
{
    let mut cursor = None::<String>;
    let mut seen_cursors = HashSet::new();
    let mut items = Vec::new();
    let mut item_work = 0usize;

    for page_number in 1..=limits.max_pages {
        // Count a request before dispatch so empty pages cannot evade operation work caps.
        work_budget.reserve(1)?;
        let request_cursor = cursor.take();
        let transient_cursor_bytes = request_cursor.as_ref().map_or(0, String::len);
        let fetched = tokio::time::timeout_at(deadline, fetch(request_cursor)).await;
        work_budget.release_transient_retained_bytes(transient_cursor_bytes)?;
        let fetched = fetched.map_err(|_| anyhow!("moderation pagination deadline exceeded"))??;
        work_budget.reserve_response_bytes(fetched.response_bytes, limits.max_response_bytes)?;
        let remaining_items = limits.max_items.saturating_sub(item_work);
        let remaining_retained_bytes =
            work_budget.remaining_retained_bytes(limits.max_retained_bytes);
        let page = extract(&fetched.payload, remaining_items, remaining_retained_bytes)?;
        let next_work = item_work
            .checked_add(page.work)
            .ok_or_else(|| anyhow!("moderation pagination item limit exceeded"))?;
        if next_work > limits.max_items {
            return Err(anyhow!("moderation pagination item limit exceeded"));
        }
        work_budget.reserve_retained_bytes(page.retained_bytes, limits.max_retained_bytes)?;

        // Reserve both limits before extending the aggregate collection.
        work_budget.reserve(page.work)?;
        item_work = next_work;
        items.extend(page.items);

        let cursor_value = fetched.payload.get("cursor");
        let next_cursor = match cursor_value {
            None | Some(Value::Null) => None,
            Some(Value::String(cursor)) => {
                if cursor.len() > MODERATION_MAX_CURSOR_BYTES {
                    return Err(anyhow!("moderation pagination cursor length exceeded"));
                }
                Some(cursor.as_str())
            }
            Some(_) => return Err(anyhow!("moderation pagination cursor type invalid")),
        };
        let Some(next_cursor) = next_cursor else {
            return Ok(items);
        };
        if next_cursor.is_empty() {
            return Err(anyhow!("moderation pagination non-progress cursor"));
        }
        if seen_cursors.contains(next_cursor) {
            return Err(anyhow!("moderation pagination repeated or cyclic cursor"));
        }
        if page_number == limits.max_pages {
            return Err(anyhow!("moderation pagination page limit exceeded"));
        }
        work_budget.reserve_retained_bytes(next_cursor.len(), limits.max_retained_bytes)?;
        work_budget
            .reserve_transient_retained_bytes(next_cursor.len(), limits.max_retained_bytes)?;
        let next_cursor = next_cursor.to_owned();
        seen_cursors.insert(next_cursor.clone());
        cursor = Some(next_cursor);
    }

    Err(anyhow!("moderation pagination page limit exceeded"))
}

async fn replace_after_complete_snapshot<Snapshot, Load, Replace, ReplaceFuture>(
    load: Load,
    replace: Replace,
) -> Result<()>
where
    Load: Future<Output = Result<Snapshot>>,
    Replace: FnOnce(Snapshot) -> ReplaceFuture,
    ReplaceFuture: Future<Output = Result<()>>,
{
    let snapshot = load.await?;
    replace(snapshot).await
}

const MODERATION_PAGINATION_LIMITS: PaginationLimits =
    PaginationLimits::new(MODERATION_MAX_PAGES, MODERATION_MAX_ITEMS_PER_COLLECTION);

impl ModerationCache {
    pub fn new(db_pool: Pool<Postgres>, sync_interval_seconds: u64) -> Self {
        Self {
            db_pool,
            sync_interval: Duration::seconds(sync_interval_seconds as i64),
        }
    }

    pub async fn ensure_fresh(&self, state: &Arc<AppState>, user_did: &str) -> Result<()> {
        let account = sqlx::query(
            r#"
            SELECT session_id, pds_url, last_actor_sync_at, last_list_sync_at, auth_revoked_at
            FROM push_accounts
            WHERE account_did = $1
            "#,
        )
        .bind(user_did)
        .fetch_optional(&self.db_pool)
        .await?;

        let Some(account) = account else {
            return Ok(());
        };

        // Skip sync for accounts with revoked auth sessions
        if account
            .try_get::<Option<OffsetDateTime>, _>("auth_revoked_at")?
            .is_some()
        {
            tracing::debug!(
                user_did = %user_did,
                "Skipping moderation sync for account with revoked auth"
            );
            return Ok(());
        }

        let now = OffsetDateTime::now_utc();
        let actor_stale = account
            .try_get::<Option<OffsetDateTime>, _>("last_actor_sync_at")?
            .map(|ts| now - ts >= self.sync_interval)
            .unwrap_or(true);
        let list_stale = account
            .try_get::<Option<OffsetDateTime>, _>("last_list_sync_at")?
            .map(|ts| now - ts >= self.sync_interval)
            .unwrap_or(true);

        if !actor_stale && !list_stale {
            return Ok(());
        }

        let session_id = account.try_get::<String, _>("session_id")?;
        let pds_url = account.try_get::<String, _>("pds_url")?;
        let (session, dpop) = match super::resolve_background_session(
            state,
            user_did,
            &session_id,
            &pds_url,
        )
        .await
        {
            Ok(result) => result,
            Err(err) if super::is_auth_revocation_error(&err) => {
                tracing::warn!(
                    user_did = %user_did,
                    error = %err,
                    "Auth revoked for push account; marking revoked"
                );
                sqlx::query(
                    "UPDATE push_accounts SET auth_revoked_at = NOW(), updated_at = NOW() WHERE account_did = $1",
                )
                .bind(user_did)
                .execute(&self.db_pool)
                .await?;
                return Ok(());
            }
            Err(err) => return Err(err),
        };

        if actor_stale {
            self.sync_actor_relationships(state, &session, &dpop)
                .await?;
            sqlx::query(
                "UPDATE push_accounts SET last_actor_sync_at = NOW(), updated_at = NOW() WHERE account_did = $1",
            )
            .bind(user_did)
            .execute(&self.db_pool)
            .await?;
        }

        if list_stale {
            self.sync_list_relationships(state, &session, &dpop).await?;
            sqlx::query(
                "UPDATE push_accounts SET last_list_sync_at = NOW(), updated_at = NOW() WHERE account_did = $1",
            )
            .bind(user_did)
            .execute(&self.db_pool)
            .await?;
        }

        Ok(())
    }

    pub async fn refresh_actor_relationships_for_session(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
    ) -> Result<()> {
        self.sync_actor_relationships(state, session, dpop).await?;
        sqlx::query(
            "UPDATE push_accounts SET last_actor_sync_at = NOW(), updated_at = NOW() WHERE account_did = $1",
        )
        .bind(&session.did)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn refresh_list_relationships_for_session(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
    ) -> Result<()> {
        self.sync_list_relationships(state, session, dpop).await?;
        sqlx::query(
            "UPDATE push_accounts SET last_list_sync_at = NOW(), updated_at = NOW() WHERE account_did = $1",
        )
        .bind(&session.did)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_actor_mute(&self, user_did: &str, muted_did: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO user_mutes (user_did, muted_did)
            VALUES ($1, $2)
            ON CONFLICT (user_did, muted_did) DO NOTHING
            "#,
        )
        .bind(user_did)
        .bind(muted_did)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn remove_actor_mute(&self, user_did: &str, muted_did: &str) -> Result<()> {
        sqlx::query("DELETE FROM user_mutes WHERE user_did = $1 AND muted_did = $2")
            .bind(user_did)
            .bind(muted_did)
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }

    pub async fn upsert_actor_block(&self, user_did: &str, blocked_did: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO user_blocks (user_did, blocked_did)
            VALUES ($1, $2)
            ON CONFLICT (user_did, blocked_did) DO NOTHING
            "#,
        )
        .bind(user_did)
        .bind(blocked_did)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn remove_actor_block(&self, user_did: &str, blocked_did: &str) -> Result<()> {
        sqlx::query("DELETE FROM user_blocks WHERE user_did = $1 AND blocked_did = $2")
            .bind(user_did)
            .bind(blocked_did)
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }

    pub async fn mute_thread(&self, user_did: &str, thread_root_uri: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO thread_mutes (user_did, thread_root_uri)
            VALUES ($1, $2)
            ON CONFLICT (user_did, thread_root_uri) DO NOTHING
            "#,
        )
        .bind(user_did)
        .bind(thread_root_uri)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn unmute_thread(&self, user_did: &str, thread_root_uri: &str) -> Result<()> {
        sqlx::query("DELETE FROM thread_mutes WHERE user_did = $1 AND thread_root_uri = $2")
            .bind(user_did)
            .bind(thread_root_uri)
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }

    pub async fn sync_list_subscription(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        list_uri: &str,
        purpose: &str,
    ) -> Result<()> {
        replace_after_complete_snapshot(
            async {
                let mut sync = ModerationSyncContext::new();
                let list_name = self
                    .fetch_list_name(state, session, dpop, list_uri, &mut sync)
                    .await?;
                let members = self
                    .fetch_list_members(state, session, dpop, list_uri, &mut sync)
                    .await?;
                Ok((list_name, members))
            },
            |(list_name, members)| async move {
                let mut tx = self.db_pool.begin().await?;
                sqlx::query(
                    r#"
            INSERT INTO moderation_list_subscriptions (
                user_did,
                list_uri,
                list_purpose,
                list_name,
                last_synced_at,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, NOW(), NOW(), NOW())
            ON CONFLICT (user_did, list_uri)
            DO UPDATE
            SET list_purpose = EXCLUDED.list_purpose,
                list_name = EXCLUDED.list_name,
                last_synced_at = NOW(),
                updated_at = NOW()
            "#,
                )
                .bind(&session.did)
                .bind(list_uri)
                .bind(purpose)
                .bind(list_name)
                .execute(&mut *tx)
                .await?;

                sqlx::query("DELETE FROM moderation_list_members WHERE list_uri = $1")
                    .bind(list_uri)
                    .execute(&mut *tx)
                    .await?;

                for subject_did in members {
                    sqlx::query(
                        r#"
                INSERT INTO moderation_list_members (list_uri, subject_did)
                VALUES ($1, $2)
                ON CONFLICT (list_uri, subject_did) DO NOTHING
                "#,
                    )
                    .bind(list_uri)
                    .bind(subject_did)
                    .execute(&mut *tx)
                    .await?;
                }

                tx.commit().await?;
                Ok(())
            },
        )
        .await
    }

    pub async fn remove_list_subscription(&self, user_did: &str, list_uri: &str) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        sqlx::query(
            "DELETE FROM moderation_list_subscriptions WHERE user_did = $1 AND list_uri = $2",
        )
        .bind(user_did)
        .bind(list_uri)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            DELETE FROM moderation_list_members m
            WHERE m.list_uri = $1
              AND NOT EXISTS (
                  SELECT 1
                  FROM moderation_list_subscriptions s
                  WHERE s.list_uri = m.list_uri
              )
            "#,
        )
        .bind(list_uri)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn is_actor_muted_or_blocked(&self, user_did: &str, actor_did: &str) -> Result<bool> {
        let row = sqlx::query(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM user_mutes WHERE user_did = $1 AND muted_did = $2
            ) OR EXISTS (
                SELECT 1 FROM user_blocks WHERE user_did = $1 AND blocked_did = $2
            ) AS blocked
            "#,
        )
        .bind(user_did)
        .bind(actor_did)
        .fetch_one(&self.db_pool)
        .await?;

        Ok(row.try_get::<bool, _>("blocked")?)
    }

    pub async fn is_actor_list_filtered(&self, user_did: &str, actor_did: &str) -> Result<bool> {
        let row = sqlx::query(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM moderation_list_members m
                INNER JOIN moderation_list_subscriptions s ON s.list_uri = m.list_uri
                WHERE s.user_did = $1
                  AND m.subject_did = $2
            ) AS filtered
            "#,
        )
        .bind(user_did)
        .bind(actor_did)
        .fetch_one(&self.db_pool)
        .await?;

        Ok(row.try_get::<bool, _>("filtered")?)
    }

    pub async fn is_thread_muted(&self, user_did: &str, thread_root_uri: &str) -> Result<bool> {
        let row = sqlx::query(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM thread_mutes WHERE user_did = $1 AND thread_root_uri = $2
            ) AS muted
            "#,
        )
        .bind(user_did)
        .bind(thread_root_uri)
        .fetch_one(&self.db_pool)
        .await?;

        Ok(row.try_get::<bool, _>("muted")?)
    }

    async fn sync_actor_relationships(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
    ) -> Result<()> {
        replace_after_complete_snapshot(
            async {
                let mut sync = ModerationSyncContext::new();
                let muted_dids = self
                    .fetch_paginated_profile_dids(
                        state,
                        session,
                        dpop,
                        "app.bsky.graph.getMutes",
                        "mutes",
                        &mut sync,
                    )
                    .await?;
                let blocked_dids = self
                    .fetch_paginated_profile_dids(
                        state,
                        session,
                        dpop,
                        "app.bsky.graph.getBlocks",
                        "blocks",
                        &mut sync,
                    )
                    .await?;
                Ok((muted_dids, blocked_dids))
            },
            |(muted_dids, blocked_dids)| async move {
                let mut tx = self.db_pool.begin().await?;
                sqlx::query("DELETE FROM user_mutes WHERE user_did = $1")
                    .bind(&session.did)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM user_blocks WHERE user_did = $1")
                    .bind(&session.did)
                    .execute(&mut *tx)
                    .await?;

                for muted_did in muted_dids {
                    sqlx::query(
                "INSERT INTO user_mutes (user_did, muted_did) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    )
                    .bind(&session.did)
                    .bind(muted_did)
                    .execute(&mut *tx)
                    .await?;
                }

                for blocked_did in blocked_dids {
                    sqlx::query(
                "INSERT INTO user_blocks (user_did, blocked_did) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    )
                    .bind(&session.did)
                    .bind(blocked_did)
                    .execute(&mut *tx)
                    .await?;
                }

                tx.commit().await?;
                Ok(())
            },
        )
        .await
    }

    async fn sync_list_relationships(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
    ) -> Result<()> {
        replace_after_complete_snapshot(
            async {
                let mut sync = ModerationSyncContext::new();
                let mut lists = self
                    .fetch_paginated_lists(
                        state,
                        session,
                        dpop,
                        "app.bsky.graph.getListMutes",
                        "curatelist",
                        &mut sync,
                    )
                    .await?;
                lists.extend(
                    self.fetch_paginated_lists(
                        state,
                        session,
                        dpop,
                        "app.bsky.graph.getListBlocks",
                        "modlist",
                        &mut sync,
                    )
                    .await?,
                );

                let mut member_map = Vec::with_capacity(lists.len());
                for list in &lists {
                    let members = self
                        .fetch_list_members(state, session, dpop, &list.uri, &mut sync)
                        .await?;
                    member_map.push((list.clone(), members));
                }
                Ok(member_map)
            },
            |member_map| async move {
                let mut tx = self.db_pool.begin().await?;
                sqlx::query("DELETE FROM moderation_list_subscriptions WHERE user_did = $1")
                    .bind(&session.did)
                    .execute(&mut *tx)
                    .await?;

                for (list, members) in member_map {
                    sqlx::query(
                        r#"
                INSERT INTO moderation_list_subscriptions (
                    user_did,
                    list_uri,
                    list_purpose,
                    list_name,
                    last_synced_at,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, $3, $4, NOW(), NOW(), NOW())
                "#,
                    )
                    .bind(&session.did)
                    .bind(&list.uri)
                    .bind(&list.purpose)
                    .bind(&list.name)
                    .execute(&mut *tx)
                    .await?;

                    sqlx::query("DELETE FROM moderation_list_members WHERE list_uri = $1")
                        .bind(&list.uri)
                        .execute(&mut *tx)
                        .await?;

                    for member in members {
                        sqlx::query(
                            r#"
                    INSERT INTO moderation_list_members (list_uri, subject_did)
                    VALUES ($1, $2)
                    ON CONFLICT (list_uri, subject_did) DO NOTHING
                    "#,
                        )
                        .bind(&list.uri)
                        .bind(member)
                        .execute(&mut *tx)
                        .await?;
                    }
                }

                sqlx::query(
                    r#"
            DELETE FROM moderation_list_members m
            WHERE NOT EXISTS (
                SELECT 1
                FROM moderation_list_subscriptions s
                WHERE s.list_uri = m.list_uri
            )
            "#,
                )
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;
                Ok(())
            },
        )
        .await
    }

    async fn fetch_paginated_profile_dids(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        lexicon: &str,
        array_key: &str,
        sync: &mut ModerationSyncContext,
    ) -> Result<Vec<String>> {
        let deadline = sync.deadline;
        collect_paginated(
            deadline,
            MODERATION_PAGINATION_LIMITS,
            &mut sync.work_budget,
            |cursor| async move {
                let query = match cursor.as_deref() {
                    Some(cursor) => format!("limit=100&cursor={}", urlencoding::encode(cursor)),
                    None => "limit=100".to_string(),
                };
                self.fetch_xrpc_json_before(state, session, dpop, lexicon, Some(&query), deadline)
                    .await
            },
            |payload, max_items, max_retained_bytes| {
                extract_required_array(
                    payload,
                    array_key,
                    max_items,
                    max_retained_bytes,
                    |item| {
                        let did = item
                            .get("did")
                            .and_then(Value::as_str)
                            .ok_or_else(|| anyhow!("profile did missing or invalid"))?;
                        Ok(did.len())
                    },
                    |item| {
                        let did = item
                            .get("did")
                            .and_then(Value::as_str)
                            .ok_or_else(|| anyhow!("profile did missing or invalid"))?;
                        Ok(did.to_owned())
                    },
                )
            },
        )
        .await
    }

    async fn fetch_paginated_lists(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        lexicon: &str,
        purpose: &str,
        sync: &mut ModerationSyncContext,
    ) -> Result<Vec<ListSubscription>> {
        let deadline = sync.deadline;
        collect_paginated(
            deadline,
            MODERATION_PAGINATION_LIMITS,
            &mut sync.work_budget,
            |cursor| async move {
                let query = match cursor.as_deref() {
                    Some(cursor) => format!("limit=100&cursor={}", urlencoding::encode(cursor)),
                    None => "limit=100".to_string(),
                };
                self.fetch_xrpc_json_before(state, session, dpop, lexicon, Some(&query), deadline)
                    .await
            },
            |payload, max_items, max_retained_bytes| {
                extract_required_array(
                    payload,
                    "lists",
                    max_items,
                    max_retained_bytes,
                    |item| {
                        let uri = item
                            .get("uri")
                            .and_then(Value::as_str)
                            .ok_or_else(|| anyhow!("list uri missing or invalid"))?;
                        let name_len = match item.get("name") {
                            None | Some(Value::Null) => 0,
                            Some(Value::String(name)) => name.len(),
                            Some(_) => return Err(anyhow!("list name has invalid type")),
                        };
                        uri.len()
                            .checked_add(purpose.len())
                            .and_then(|bytes| bytes.checked_add(name_len))
                            .ok_or_else(|| anyhow!("list retained size overflow"))
                    },
                    |item| {
                        let uri = item
                            .get("uri")
                            .and_then(Value::as_str)
                            .ok_or_else(|| anyhow!("list uri missing or invalid"))?;
                        let name = match item.get("name") {
                            None | Some(Value::Null) => None,
                            Some(Value::String(name)) => Some(name.to_owned()),
                            Some(_) => return Err(anyhow!("list name has invalid type")),
                        };
                        Ok(ListSubscription {
                            uri: uri.to_owned(),
                            purpose: purpose.to_owned(),
                            name,
                        })
                    },
                )
            },
        )
        .await
    }

    async fn fetch_list_name(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        list_uri: &str,
        sync: &mut ModerationSyncContext,
    ) -> Result<Option<String>> {
        let deadline = sync.deadline;
        sync.work_budget.reserve(1)?;
        let query = format!("list={}", urlencoding::encode(list_uri));
        let payload = self
            .fetch_xrpc_json_before(
                state,
                session,
                dpop,
                "app.bsky.graph.getList",
                Some(&query),
                deadline,
            )
            .await?;
        sync.work_budget.reserve_response_bytes(
            payload.response_bytes,
            MODERATION_MAX_CUMULATIVE_RESPONSE_BYTES,
        )?;

        let name = match payload
            .payload
            .get("list")
            .and_then(|value| value.get("name"))
        {
            None | Some(Value::Null) => None,
            Some(Value::String(name)) => {
                sync.work_budget
                    .reserve_retained_bytes(name.len(), MODERATION_MAX_RETAINED_BYTES)?;
                Some(name.to_owned())
            }
            Some(_) => return Err(anyhow!("moderation list name has invalid type")),
        };
        Ok(name)
    }

    async fn fetch_list_members(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        list_uri: &str,
        sync: &mut ModerationSyncContext,
    ) -> Result<Vec<String>> {
        let deadline = sync.deadline;
        collect_paginated(
            deadline,
            MODERATION_PAGINATION_LIMITS,
            &mut sync.work_budget,
            |cursor| async move {
                let mut query = format!("list={}&limit=100", urlencoding::encode(list_uri));
                if let Some(cursor_value) = cursor.as_deref() {
                    query.push_str("&cursor=");
                    query.push_str(&urlencoding::encode(cursor_value));
                }
                self.fetch_xrpc_json_before(
                    state,
                    session,
                    dpop,
                    "app.bsky.graph.getList",
                    Some(&query),
                    deadline,
                )
                .await
            },
            |payload, max_items, max_retained_bytes| {
                extract_required_array(
                    payload,
                    "items",
                    max_items,
                    max_retained_bytes,
                    |item| {
                        let did = item
                            .get("subject")
                            .and_then(|value| value.get("did"))
                            .and_then(Value::as_str)
                            .ok_or_else(|| anyhow!("list member did missing or invalid"))?;
                        Ok(did.len())
                    },
                    |item| {
                        let did = item
                            .get("subject")
                            .and_then(|value| value.get("did"))
                            .and_then(Value::as_str)
                            .ok_or_else(|| anyhow!("list member did missing or invalid"))?;
                        Ok(did.to_owned())
                    },
                )
            },
        )
        .await
    }

    async fn fetch_xrpc_json_before(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        lexicon: &str,
        query: Option<&str>,
        deadline: tokio::time::Instant,
    ) -> Result<FetchedJson> {
        tokio::time::timeout_at(
            deadline,
            self.fetch_xrpc_json(state, session, dpop, lexicon, query),
        )
        .await
        .map_err(|_| anyhow!("moderation pagination deadline exceeded"))?
    }

    async fn fetch_xrpc_json(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        lexicon: &str,
        query: Option<&str>,
    ) -> Result<FetchedJson> {
        let client = AtProtoClient::new(state.clone());
        let path = format!("/xrpc/{}", lexicon);
        let response = client
            .proxy_request(
                session,
                Method::GET,
                &path,
                query,
                None,
                None,
                None,
                "push-sync",
                Some(dpop),
            )
            .await?;

        // AtProtoClient's public contract buffers the first DPoP attempt before returning.
        // This layer cannot lower that transport cap, so it records the exact returned body
        // length and rejects it against the smaller cumulative moderation budget before any
        // parsed state can reach a replacement transaction.
        let body = match response {
            ProxyResponse::Buffered { status, body, .. } => {
                if !(200..300).contains(&status) {
                    return Err(anyhow!("{} returned HTTP {}", lexicon, status));
                }
                body
            }
            ProxyResponse::Streaming { .. } => {
                return Err(anyhow!("Unexpected streaming response for {}", lexicon))
            }
        };

        parse_moderation_json_body(&body, MODERATION_MAX_CUMULATIVE_RESPONSE_BYTES)
    }
}

fn parse_moderation_json_body(body: &Bytes, max_bytes: usize) -> Result<FetchedJson> {
    if body.len() > max_bytes {
        return Err(anyhow!("moderation response byte limit exceeded"));
    }

    Ok(FetchedJson {
        response_bytes: body.len(),
        payload: parse_json_body(body)?,
    })
}

fn parse_json_body(body: &Bytes) -> Result<Value> {
    Ok(serde_json::from_slice(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        collections::VecDeque,
        future::ready,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration as StdDuration,
    };

    fn page(items: &[&str], cursor: Option<&str>) -> Value {
        json!({ "items": items, "cursor": cursor })
    }

    fn fetched(payload: Value) -> FetchedJson {
        FetchedJson {
            response_bytes: serde_json::to_vec(&payload).expect("encode fixture").len(),
            payload,
        }
    }

    fn strings(
        payload: &Value,
        max_items: usize,
        max_retained_bytes: usize,
    ) -> Result<ExtractedPage<String>> {
        extract_required_array(
            payload,
            "items",
            max_items,
            max_retained_bytes,
            |item| {
                item.as_str()
                    .map(str::len)
                    .ok_or_else(|| anyhow!("fixture string invalid"))
            },
            |item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("fixture string invalid"))
            },
        )
    }

    async fn collect_fixture(
        pages: Vec<Value>,
        limits: PaginationLimits,
        budget: &mut AggregateWorkBudget,
        deadline: tokio::time::Instant,
        requested: &mut Vec<Option<String>>,
    ) -> Result<Vec<String>> {
        let mut pages = VecDeque::from(pages);
        collect_paginated(
            deadline,
            limits,
            budget,
            |cursor| {
                requested.push(cursor);
                ready(Ok(fetched(
                    pages.pop_front().expect("unexpected extra fetch"),
                )))
            },
            strings,
        )
        .await
    }

    #[tokio::test]
    async fn repeated_cursor_rejects_before_another_fetch() {
        let mut budget = AggregateWorkBudget::new(10);
        let mut requested = Vec::new();
        let error = collect_fixture(
            vec![page(&["one"], Some("a")), page(&["two"], Some("a"))],
            PaginationLimits::new(10, 10),
            &mut budget,
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            &mut requested,
        )
        .await
        .expect_err("repeated cursor must fail");

        assert!(error.to_string().contains("repeated or cyclic cursor"));
        assert_eq!(requested, vec![None, Some("a".to_owned())]);
    }

    #[tokio::test]
    async fn alternating_cursor_cycle_rejects_before_fourth_fetch() {
        let mut budget = AggregateWorkBudget::new(10);
        let mut requested = Vec::new();
        let error = collect_fixture(
            vec![
                page(&["one"], Some("a")),
                page(&["two"], Some("b")),
                page(&["three"], Some("a")),
            ],
            PaginationLimits::new(10, 10),
            &mut budget,
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            &mut requested,
        )
        .await
        .expect_err("cursor cycle must fail");

        assert!(error.to_string().contains("repeated or cyclic cursor"));
        assert_eq!(requested.len(), 3);
    }

    #[tokio::test]
    async fn page_limit_rejects_before_page_n_plus_one() {
        let mut budget = AggregateWorkBudget::new(10);
        let mut requested = Vec::new();
        let error = collect_fixture(
            vec![page(&["one"], Some("a")), page(&["two"], Some("b"))],
            PaginationLimits::new(2, 10),
            &mut budget,
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            &mut requested,
        )
        .await
        .expect_err("page N + 1 must be rejected");

        assert!(error.to_string().contains("page limit"));
        assert_eq!(requested.len(), 2);
    }

    #[tokio::test]
    async fn item_cap_plus_one_rejects_before_aggregate_extension() {
        let mut budget = AggregateWorkBudget::new(10);
        let materialized = Arc::new(AtomicUsize::new(0));
        let materialized_for_extract = Arc::clone(&materialized);
        let error = collect_paginated(
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            PaginationLimits::new(2, 2),
            &mut budget,
            |_| ready(Ok(fetched(page(&["one", "two", "three"], None)))),
            move |payload, max_items, max_retained_bytes| {
                extract_required_array(
                    payload,
                    "items",
                    max_items,
                    max_retained_bytes,
                    |item| {
                        item.as_str()
                            .map(str::len)
                            .ok_or_else(|| anyhow!("fixture string invalid"))
                    },
                    |item| {
                        materialized_for_extract.fetch_add(1, Ordering::SeqCst);
                        item.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| anyhow!("fixture string invalid"))
                    },
                )
            },
        )
        .await
        .expect_err("item cap plus one must fail");

        assert!(error.to_string().contains("item limit"));
        assert_eq!(budget.used(), 1, "only request work may be reserved");
        assert_eq!(
            materialized.load(Ordering::SeqCst),
            0,
            "oversized arrays must reject before materialization"
        );
    }

    #[tokio::test]
    async fn retained_cap_plus_one_rejects_before_materialization() {
        let mut budget = AggregateWorkBudget::new(10);
        let materialized = Arc::new(AtomicUsize::new(0));
        let materialized_for_extract = Arc::clone(&materialized);
        let error = collect_paginated(
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            PaginationLimits::new(2, 2).with_byte_limits(1_000, 3),
            &mut budget,
            |_| ready(Ok(fetched(page(&["four"], None)))),
            move |payload, max_items, max_retained_bytes| {
                extract_required_array(
                    payload,
                    "items",
                    max_items,
                    max_retained_bytes,
                    |item| {
                        item.as_str()
                            .map(str::len)
                            .ok_or_else(|| anyhow!("fixture string invalid"))
                    },
                    |item| {
                        materialized_for_extract.fetch_add(1, Ordering::SeqCst);
                        item.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| anyhow!("fixture string invalid"))
                    },
                )
            },
        )
        .await
        .expect_err("retained cap plus one must fail");

        assert!(error.to_string().contains("retained byte limit"));
        assert_eq!(materialized.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn both_owned_cursor_copies_are_retained_accounted() {
        let mut budget = AggregateWorkBudget::new(10);
        let mut requested = Vec::new();
        let error = collect_fixture(
            vec![page(&[], Some("a"))],
            PaginationLimits::new(2, 10).with_byte_limits(1_000, 1),
            &mut budget,
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            &mut requested,
        )
        .await
        .expect_err("both cursor copies must count against retained bytes");

        assert!(error.to_string().contains("retained byte limit"));
        assert_eq!(requested.len(), 1);
    }

    #[tokio::test]
    async fn dropped_cursor_transient_bytes_do_not_accumulate() {
        const PAGE_COUNT: usize = 50;
        const CURSOR_BYTES: usize = 8;
        let pages = (0..PAGE_COUNT)
            .map(|index| {
                let cursor = (index + 1 < PAGE_COUNT).then(|| format!("{index:08}"));
                json!({ "items": [], "cursor": cursor })
            })
            .collect();
        let mut budget = AggregateWorkBudget::new(PAGE_COUNT);
        let mut requested = Vec::new();
        let retained_limit = PAGE_COUNT * CURSOR_BYTES;

        let result = collect_fixture(
            pages,
            PaginationLimits::new(PAGE_COUNT, 0).with_byte_limits(100_000, retained_limit),
            &mut budget,
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            &mut requested,
        )
        .await
        .expect("overwritten transient cursors must release their retained-byte charge");

        assert!(result.is_empty());
        assert_eq!(requested.len(), PAGE_COUNT);
        assert_eq!(budget.used(), PAGE_COUNT);
        assert_eq!(
            budget.retained_bytes,
            (PAGE_COUNT - 1) * CURSOR_BYTES,
            "cycle-detection cursors remain persistently charged"
        );
        assert_eq!(
            budget.transient_retained_bytes, 0,
            "the final request must release its transient cursor charge"
        );
    }

    #[tokio::test]
    async fn malformed_array_entries_fail_closed_after_request_accounting() {
        let mut budget = AggregateWorkBudget::new(2);
        let error = collect_paginated(
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            PaginationLimits::new(2, 10),
            &mut budget,
            |_| ready(Ok(fetched(json!({ "items": [null, null, null] })))),
            strings,
        )
        .await
        .expect_err("malformed attacker entries must fail closed");

        assert!(error
            .to_string()
            .contains("required array items item invalid"));
        assert_eq!(budget.used(), 1);
    }

    #[tokio::test]
    async fn missing_or_wrong_type_required_array_is_rejected() {
        for payload in [json!({}), json!({ "items": {} })] {
            let mut budget = AggregateWorkBudget::new(10);
            let error = collect_paginated(
                tokio::time::Instant::now() + StdDuration::from_secs(1),
                PaginationLimits::new(2, 10),
                &mut budget,
                |_| ready(Ok(fetched(payload.clone()))),
                strings,
            )
            .await
            .expect_err("required array shape must fail closed");
            assert!(error.to_string().contains("required array"));
        }
    }

    #[tokio::test]
    async fn non_string_non_null_cursor_is_rejected() {
        let mut budget = AggregateWorkBudget::new(10);
        let error = collect_paginated(
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            PaginationLimits::new(2, 10),
            &mut budget,
            |_| ready(Ok(fetched(json!({ "items": [], "cursor": 42 })))),
            strings,
        )
        .await
        .expect_err("wrong-type cursor must fail closed");
        assert!(error.to_string().contains("cursor type"));
    }

    #[tokio::test]
    async fn oversized_cursor_rejects_before_clone_or_next_fetch() {
        let mut budget = AggregateWorkBudget::new(10);
        let mut requested = Vec::new();
        let cursor = "x".repeat(MODERATION_MAX_CURSOR_BYTES + 1);
        let error = collect_fixture(
            vec![json!({ "items": [], "cursor": cursor })],
            PaginationLimits::new(2, 10),
            &mut budget,
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            &mut requested,
        )
        .await
        .expect_err("oversized cursor must fail");
        assert!(error.to_string().contains("cursor length"));
        assert_eq!(requested.len(), 1);
    }

    #[test]
    fn oversized_raw_body_is_rejected_before_json_parse_allocation() {
        let invalid_oversized_json = Bytes::from_static(b"not-json-and-too-large");
        let error = parse_moderation_json_body(&invalid_oversized_json, 4)
            .expect_err("raw body ceiling must run before JSON parsing");
        assert!(error.to_string().contains("response byte limit"));
    }

    #[tokio::test]
    async fn cumulative_response_and_retained_byte_limits_reject_plus_one() {
        let response_pages = vec![
            page(&["aaaaaaaaaa"], Some("a")),
            page(&["bbbbbbbbbb"], None),
        ];
        let response_limit = response_pages
            .iter()
            .map(|page| serde_json::to_vec(page).expect("encode fixture").len())
            .sum::<usize>()
            - 1;
        let response_limits = PaginationLimits::new(3, 10).with_byte_limits(response_limit, 100);
        let mut response_budget = AggregateWorkBudget::new(10);
        let mut response_requests = Vec::new();
        let response_error = collect_fixture(
            response_pages,
            response_limits,
            &mut response_budget,
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            &mut response_requests,
        )
        .await
        .expect_err("cumulative response bytes must be bounded");
        assert!(response_error.to_string().contains("response byte limit"));

        let retained_limits = PaginationLimits::new(3, 10).with_byte_limits(1_000, 4);
        let mut retained_budget = AggregateWorkBudget::new(10);
        let mut retained_requests = Vec::new();
        let retained_error = collect_fixture(
            vec![page(&["aa"], Some("a")), page(&["bb"], None)],
            retained_limits,
            &mut retained_budget,
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            &mut retained_requests,
        )
        .await
        .expect_err("cumulative retained bytes must be bounded");
        assert!(retained_error.to_string().contains("retained byte limit"));
    }

    #[tokio::test]
    async fn response_and_retained_budgets_are_shared_across_collectors() {
        let first = page(&["aa"], None);
        let second = page(&["bb"], None);
        let response_limit = serde_json::to_vec(&first).expect("encode fixture").len();
        let limits = PaginationLimits::new(2, 10).with_byte_limits(response_limit, 2);
        let deadline = tokio::time::Instant::now() + StdDuration::from_secs(1);
        let mut budget = AggregateWorkBudget::new(10);

        let mut first_requests = Vec::new();
        collect_fixture(
            vec![first],
            limits,
            &mut budget,
            deadline,
            &mut first_requests,
        )
        .await
        .expect("first collector reaches exact byte ceilings");

        let mut second_requests = Vec::new();
        let error = collect_fixture(
            vec![second],
            limits,
            &mut budget,
            deadline,
            &mut second_requests,
        )
        .await
        .expect_err("second collector must share operation byte budgets");
        let message = error.to_string();
        assert!(message.contains("response byte limit") || message.contains("retained byte limit"));
    }

    #[tokio::test]
    async fn empty_pages_consume_operation_request_work_before_fetch() {
        let mut budget = AggregateWorkBudget::new(1);
        let mut requested = Vec::new();
        let error = collect_fixture(
            vec![json!({ "items": [], "cursor": "next" })],
            PaginationLimits::new(3, 10),
            &mut budget,
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            &mut requested,
        )
        .await
        .expect_err("empty pages must consume request work");
        assert!(error.to_string().contains("operation work limit"));
        assert_eq!(requested.len(), 1, "second request must not start");
    }

    #[tokio::test]
    async fn replacement_seam_preserves_cache_for_failed_snapshots() {
        async fn assert_preserved(snapshot: Result<Vec<String>>) {
            let cache = Arc::new(std::sync::Mutex::new(vec!["old-cache".to_owned()]));
            let replacement_cache = cache.clone();
            let result =
                replace_after_complete_snapshot(ready(snapshot), move |replacement| async move {
                    *replacement_cache.lock().expect("cache lock") = replacement;
                    Ok(())
                })
                .await;
            assert!(result.is_err());
            assert_eq!(*cache.lock().expect("cache lock"), ["old-cache"]);
        }

        let deadline = tokio::time::Instant::now() + StdDuration::from_secs(1);

        let mut pagination_budget = AggregateWorkBudget::new(10);
        let mut pagination_requests = Vec::new();
        let pagination_failure = collect_fixture(
            vec![page(&["one"], Some("a")), page(&["two"], Some("a"))],
            PaginationLimits::new(3, 10),
            &mut pagination_budget,
            deadline,
            &mut pagination_requests,
        )
        .await;
        assert!(pagination_failure
            .as_ref()
            .expect_err("cycle must fail")
            .to_string()
            .contains("repeated or cyclic cursor"));
        assert_preserved(pagination_failure).await;

        let mut malformed_budget = AggregateWorkBudget::new(10);
        let malformed_failure = collect_paginated(
            deadline,
            PaginationLimits::new(1, 10),
            &mut malformed_budget,
            |_| ready(Ok(fetched(json!({ "cursor": null })))),
            strings,
        )
        .await;
        assert!(malformed_failure
            .as_ref()
            .expect_err("missing array must fail")
            .to_string()
            .contains("required array"));
        assert_preserved(malformed_failure).await;

        let mut oversized_budget = AggregateWorkBudget::new(10);
        let oversized_failure = collect_paginated(
            deadline,
            PaginationLimits::new(1, 10).with_byte_limits(1, 100),
            &mut oversized_budget,
            |_| ready(Ok(fetched(json!({ "items": [], "cursor": null })))),
            strings,
        )
        .await;
        assert!(oversized_failure
            .as_ref()
            .expect_err("oversized response must fail")
            .to_string()
            .contains("response byte limit"));
        assert_preserved(oversized_failure).await;
    }

    #[tokio::test]
    async fn exact_page_item_and_work_ceilings_succeed_without_cursor() {
        let mut budget = AggregateWorkBudget::new(4);
        let mut requested = Vec::new();
        let result = collect_fixture(
            vec![page(&["one"], Some("a")), page(&["two"], None)],
            PaginationLimits::new(2, 2),
            &mut budget,
            tokio::time::Instant::now() + StdDuration::from_secs(1),
            &mut requested,
        )
        .await
        .expect("exact ceilings must succeed");

        assert_eq!(result, ["one", "two"]);
        assert_eq!(budget.used(), 4);
        assert_eq!(requested.len(), 2);
    }

    #[tokio::test]
    async fn one_cumulative_deadline_expires_during_later_page() {
        let deadline = tokio::time::Instant::now() + StdDuration::from_millis(20);
        let mut calls = 0;
        let mut budget = AggregateWorkBudget::new(10);
        let error = collect_paginated(
            deadline,
            PaginationLimits::new(3, 3),
            &mut budget,
            |_| {
                calls += 1;
                async move {
                    if calls == 2 {
                        tokio::time::sleep(StdDuration::from_millis(30)).await;
                    }
                    Ok(fetched(page(&["item"], (calls == 1).then_some("next"))))
                }
            },
            strings,
        )
        .await
        .expect_err("later page must share the original deadline");

        assert!(error.to_string().contains("deadline"));
        assert_eq!(calls, 2);
        assert_eq!(budget.retained_bytes, "item".len() + "next".len());
        assert_eq!(
            budget.transient_retained_bytes, 0,
            "timed-out fetches must release the live cursor charge"
        );
    }

    #[tokio::test]
    async fn combined_list_and_member_expansion_shares_operation_cap() {
        let deadline = tokio::time::Instant::now() + StdDuration::from_secs(1);
        let mut budget = AggregateWorkBudget::new(3);
        let mut list_requests = Vec::new();
        let lists = collect_fixture(
            vec![page(&["list-one", "list-two"], None)],
            PaginationLimits::new(2, 10),
            &mut budget,
            deadline,
            &mut list_requests,
        )
        .await
        .expect("lists fit operation cap");
        assert_eq!(lists.len(), 2);

        let mut member_requests = Vec::new();
        let error = collect_fixture(
            vec![page(&["member-one", "member-two"], None)],
            PaginationLimits::new(2, 10),
            &mut budget,
            deadline,
            &mut member_requests,
        )
        .await
        .expect_err("combined work cap plus one must fail");

        assert!(error.to_string().contains("operation work limit"));
        assert_eq!(
            budget.used(),
            3,
            "rejected request must not consume item work"
        );
    }
}
