use anyhow::{anyhow, Result};
use bytes::Bytes;
use reqwest::Method;
use serde_json::Value;
use sqlx::{Pool, Postgres, Row, Transaction};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModerationSnapshotKind {
    Actor,
    List,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotApplyOutcome {
    Applied,
    Superseded,
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

#[cfg(test)]
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

    async fn lock_moderation_did(tx: &mut Transaction<'_, Postgres>, user_did: &str) -> Result<()> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(user_did)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn bump_snapshot_generation_locked(
        tx: &mut Transaction<'_, Postgres>,
        user_did: &str,
        kind: ModerationSnapshotKind,
    ) -> Result<i64> {
        let generation = match kind {
            ModerationSnapshotKind::Actor => {
                sqlx::query_scalar::<_, i64>(
                    r#"
                    INSERT INTO moderation_snapshot_generations (
                        user_did,
                        actor_generation,
                        list_generation,
                        created_at,
                        updated_at
                    )
                    VALUES ($1, 1, 0, NOW(), NOW())
                    ON CONFLICT (user_did)
                    DO UPDATE SET
                        actor_generation = moderation_snapshot_generations.actor_generation + 1,
                        updated_at = NOW()
                    RETURNING actor_generation
                    "#,
                )
                .bind(user_did)
                .fetch_one(&mut **tx)
                .await?
            }
            ModerationSnapshotKind::List => {
                sqlx::query_scalar::<_, i64>(
                    r#"
                    INSERT INTO moderation_snapshot_generations (
                        user_did,
                        actor_generation,
                        list_generation,
                        created_at,
                        updated_at
                    )
                    VALUES ($1, 0, 1, NOW(), NOW())
                    ON CONFLICT (user_did)
                    DO UPDATE SET
                        list_generation = moderation_snapshot_generations.list_generation + 1,
                        updated_at = NOW()
                    RETURNING list_generation
                    "#,
                )
                .bind(user_did)
                .fetch_one(&mut **tx)
                .await?
            }
        };
        Ok(generation)
    }

    async fn current_snapshot_generation_locked(
        tx: &mut Transaction<'_, Postgres>,
        user_did: &str,
        kind: ModerationSnapshotKind,
    ) -> Result<Option<i64>> {
        let generation = match kind {
            ModerationSnapshotKind::Actor => sqlx::query_scalar::<_, i64>(
                "SELECT actor_generation FROM moderation_snapshot_generations WHERE user_did = $1",
            )
            .bind(user_did)
            .fetch_optional(&mut **tx)
            .await?,
            ModerationSnapshotKind::List => sqlx::query_scalar::<_, i64>(
                "SELECT list_generation FROM moderation_snapshot_generations WHERE user_did = $1",
            )
            .bind(user_did)
            .fetch_optional(&mut **tx)
            .await?,
        };
        Ok(generation)
    }

    async fn set_snapshot_freshness_locked(
        tx: &mut Transaction<'_, Postgres>,
        user_did: &str,
        kind: ModerationSnapshotKind,
        fresh: bool,
    ) -> Result<()> {
        match (kind, fresh) {
            (ModerationSnapshotKind::Actor, true) => {
                sqlx::query(
                    "UPDATE push_accounts SET last_actor_sync_at = NOW(), updated_at = NOW() WHERE account_did = $1",
                )
                .bind(user_did)
                .execute(&mut **tx)
                .await?;
            }
            (ModerationSnapshotKind::Actor, false) => {
                sqlx::query(
                    "UPDATE push_accounts SET last_actor_sync_at = NULL, updated_at = NOW() WHERE account_did = $1",
                )
                .bind(user_did)
                .execute(&mut **tx)
                .await?;
            }
            (ModerationSnapshotKind::List, true) => {
                sqlx::query(
                    "UPDATE push_accounts SET last_list_sync_at = NOW(), updated_at = NOW() WHERE account_did = $1",
                )
                .bind(user_did)
                .execute(&mut **tx)
                .await?;
            }
            (ModerationSnapshotKind::List, false) => {
                sqlx::query(
                    "UPDATE push_accounts SET last_list_sync_at = NULL, updated_at = NOW() WHERE account_did = $1",
                )
                .bind(user_did)
                .execute(&mut **tx)
                .await?;
            }
        }
        Ok(())
    }

    async fn allocate_snapshot_generation(
        &self,
        user_did: &str,
        kind: ModerationSnapshotKind,
    ) -> Result<i64> {
        let mut tx = self.db_pool.begin().await?;
        Self::lock_moderation_did(&mut tx, user_did).await?;
        let generation = Self::bump_snapshot_generation_locked(&mut tx, user_did, kind).await?;
        // A started refresh is not fresh. Clearing the timestamp before any
        // network await also makes cancellation and fetch failure fail closed.
        Self::set_snapshot_freshness_locked(&mut tx, user_did, kind, false).await?;
        tx.commit().await?;
        Ok(generation)
    }

    async fn invalidate_snapshot_freshness_if_current(
        &self,
        user_did: &str,
        kind: ModerationSnapshotKind,
        generation: i64,
    ) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        Self::lock_moderation_did(&mut tx, user_did).await?;
        if Self::current_snapshot_generation_locked(&mut tx, user_did, kind).await?
            == Some(generation)
        {
            Self::set_snapshot_freshness_locked(&mut tx, user_did, kind, false).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn fail_snapshot<T>(
        &self,
        user_did: &str,
        kind: ModerationSnapshotKind,
        generation: i64,
        error: anyhow::Error,
    ) -> Result<T> {
        self.invalidate_snapshot_freshness_if_current(user_did, kind, generation)
            .await?;
        Err(error)
    }

    async fn finish_snapshot_apply(
        &self,
        user_did: &str,
        kind: ModerationSnapshotKind,
        generation: i64,
        result: Result<SnapshotApplyOutcome>,
    ) -> Result<()> {
        match result {
            Ok(SnapshotApplyOutcome::Applied) => Ok(()),
            Ok(SnapshotApplyOutcome::Superseded) => Err(anyhow!(
                "moderation snapshot generation {generation} was superseded before apply"
            )),
            Err(error) => self.fail_snapshot(user_did, kind, generation, error).await,
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
        }

        if list_stale {
            self.sync_list_relationships(state, &session, &dpop).await?;
        }

        Ok(())
    }

    pub async fn refresh_actor_relationships_for_session(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
    ) -> Result<()> {
        self.sync_actor_relationships(state, session, dpop).await
    }

    pub async fn refresh_list_relationships_for_session(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
    ) -> Result<()> {
        self.sync_list_relationships(state, session, dpop).await
    }

    pub async fn upsert_actor_mute(&self, user_did: &str, muted_did: &str) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        Self::lock_moderation_did(&mut tx, user_did).await?;
        Self::bump_snapshot_generation_locked(&mut tx, user_did, ModerationSnapshotKind::Actor)
            .await?;
        sqlx::query(
            r#"
            INSERT INTO user_mutes (user_did, muted_did)
            VALUES ($1, $2)
            ON CONFLICT (user_did, muted_did) DO NOTHING
            "#,
        )
        .bind(user_did)
        .bind(muted_did)
        .execute(&mut *tx)
        .await?;
        Self::set_snapshot_freshness_locked(
            &mut tx,
            user_did,
            ModerationSnapshotKind::Actor,
            false,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn remove_actor_mute(&self, user_did: &str, muted_did: &str) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        Self::lock_moderation_did(&mut tx, user_did).await?;
        Self::bump_snapshot_generation_locked(&mut tx, user_did, ModerationSnapshotKind::Actor)
            .await?;
        sqlx::query("DELETE FROM user_mutes WHERE user_did = $1 AND muted_did = $2")
            .bind(user_did)
            .bind(muted_did)
            .execute(&mut *tx)
            .await?;
        Self::set_snapshot_freshness_locked(
            &mut tx,
            user_did,
            ModerationSnapshotKind::Actor,
            false,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn upsert_actor_block(&self, user_did: &str, blocked_did: &str) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        Self::lock_moderation_did(&mut tx, user_did).await?;
        Self::bump_snapshot_generation_locked(&mut tx, user_did, ModerationSnapshotKind::Actor)
            .await?;
        sqlx::query(
            r#"
            INSERT INTO user_blocks (user_did, blocked_did)
            VALUES ($1, $2)
            ON CONFLICT (user_did, blocked_did) DO NOTHING
            "#,
        )
        .bind(user_did)
        .bind(blocked_did)
        .execute(&mut *tx)
        .await?;
        Self::set_snapshot_freshness_locked(
            &mut tx,
            user_did,
            ModerationSnapshotKind::Actor,
            false,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn remove_actor_block(&self, user_did: &str, blocked_did: &str) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        Self::lock_moderation_did(&mut tx, user_did).await?;
        Self::bump_snapshot_generation_locked(&mut tx, user_did, ModerationSnapshotKind::Actor)
            .await?;
        sqlx::query("DELETE FROM user_blocks WHERE user_did = $1 AND blocked_did = $2")
            .bind(user_did)
            .bind(blocked_did)
            .execute(&mut *tx)
            .await?;
        Self::set_snapshot_freshness_locked(
            &mut tx,
            user_did,
            ModerationSnapshotKind::Actor,
            false,
        )
        .await?;
        tx.commit().await?;
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
        let generation = self
            .allocate_snapshot_generation(&session.did, ModerationSnapshotKind::List)
            .await?;
        let snapshot = async {
            let mut sync = ModerationSyncContext::new();
            let list_name = self
                .fetch_list_name(state, session, dpop, list_uri, &mut sync)
                .await?;
            let members = self
                .fetch_list_members(state, session, dpop, list_uri, &mut sync)
                .await?;
            Ok((list_name, members))
        }
        .await;
        let (list_name, members) = match snapshot {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return self
                    .fail_snapshot(
                        &session.did,
                        ModerationSnapshotKind::List,
                        generation,
                        error,
                    )
                    .await;
            }
        };
        let result = self
            .replace_list_snapshot_if_current(
                &session.did,
                generation,
                list_uri,
                purpose,
                list_name,
                members,
            )
            .await;
        self.finish_snapshot_apply(
            &session.did,
            ModerationSnapshotKind::List,
            generation,
            result,
        )
        .await
    }

    async fn replace_list_snapshot_if_current(
        &self,
        user_did: &str,
        generation: i64,
        list_uri: &str,
        purpose: &str,
        list_name: Option<String>,
        members: Vec<String>,
    ) -> Result<SnapshotApplyOutcome> {
        let mut tx = self.db_pool.begin().await?;
        Self::lock_moderation_did(&mut tx, user_did).await?;
        if Self::current_snapshot_generation_locked(&mut tx, user_did, ModerationSnapshotKind::List)
            .await?
            != Some(generation)
        {
            tx.rollback().await?;
            return Ok(SnapshotApplyOutcome::Superseded);
        }
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
        .bind(user_did)
        .bind(list_uri)
        .bind(purpose)
        .bind(list_name)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "DELETE FROM moderation_list_members_by_user WHERE user_did = $1 AND list_uri = $2",
        )
        .bind(user_did)
        .bind(list_uri)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO moderation_list_members_by_user (user_did, list_uri, subject_did)
            SELECT $1, $2, subject_did
            FROM UNNEST($3::TEXT[]) AS input(subject_did)
            ON CONFLICT (user_did, list_uri, subject_did) DO NOTHING
            "#,
        )
        .bind(user_did)
        .bind(list_uri)
        .bind(&members)
        .execute(&mut *tx)
        .await?;

        // A direct list mutation refreshes only one list, so require a full
        // reconciliation before the next moderation decision.
        Self::set_snapshot_freshness_locked(&mut tx, user_did, ModerationSnapshotKind::List, false)
            .await?;

        tx.commit().await?;
        Ok(SnapshotApplyOutcome::Applied)
    }

    async fn replace_all_list_snapshots_if_current(
        &self,
        user_did: &str,
        generation: i64,
        snapshots: Vec<(ListSubscription, Vec<String>)>,
    ) -> Result<SnapshotApplyOutcome> {
        let mut tx = self.db_pool.begin().await?;
        Self::lock_moderation_did(&mut tx, user_did).await?;
        if Self::current_snapshot_generation_locked(&mut tx, user_did, ModerationSnapshotKind::List)
            .await?
            != Some(generation)
        {
            tx.rollback().await?;
            return Ok(SnapshotApplyOutcome::Superseded);
        }
        sqlx::query("DELETE FROM moderation_list_members_by_user WHERE user_did = $1")
            .bind(user_did)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM moderation_list_subscriptions WHERE user_did = $1")
            .bind(user_did)
            .execute(&mut *tx)
            .await?;

        let mut list_uris = Vec::with_capacity(snapshots.len());
        let mut list_purposes = Vec::with_capacity(snapshots.len());
        let mut list_names = Vec::with_capacity(snapshots.len());
        let mut list_name_present = Vec::with_capacity(snapshots.len());
        let mut member_list_indexes = Vec::new();
        let mut member_dids = Vec::new();
        for (index, (list, members)) in snapshots.into_iter().enumerate() {
            list_uris.push(list.uri);
            list_purposes.push(list.purpose);
            list_name_present.push(list.name.is_some());
            list_names.push(list.name.unwrap_or_default());
            let list_index = i64::try_from(index)? + 1;
            for subject_did in members {
                member_list_indexes.push(list_index);
                member_dids.push(subject_did);
            }
        }

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
            SELECT
                $1,
                input.list_uri,
                input.list_purpose,
                CASE WHEN input.list_name_present THEN input.list_name ELSE NULL END,
                NOW(),
                NOW(),
                NOW()
            FROM UNNEST(
                $2::TEXT[],
                $3::TEXT[],
                $4::TEXT[],
                $5::BOOLEAN[]
            ) AS input(list_uri, list_purpose, list_name, list_name_present)
            "#,
        )
        .bind(user_did)
        .bind(&list_uris)
        .bind(&list_purposes)
        .bind(&list_names)
        .bind(&list_name_present)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            WITH list_input AS (
                SELECT list_uri, ordinal::BIGINT AS list_index
                FROM UNNEST($2::TEXT[]) WITH ORDINALITY AS lists(list_uri, ordinal)
            ),
            member_input AS (
                SELECT list_index, subject_did
                FROM UNNEST($3::BIGINT[], $4::TEXT[]) AS members(list_index, subject_did)
            )
            INSERT INTO moderation_list_members_by_user (user_did, list_uri, subject_did)
            SELECT $1, lists.list_uri, members.subject_did
            FROM member_input AS members
            INNER JOIN list_input AS lists USING (list_index)
            ON CONFLICT (user_did, list_uri, subject_did) DO NOTHING
            "#,
        )
        .bind(user_did)
        .bind(&list_uris)
        .bind(&member_list_indexes)
        .bind(&member_dids)
        .execute(&mut *tx)
        .await?;

        Self::set_snapshot_freshness_locked(&mut tx, user_did, ModerationSnapshotKind::List, true)
            .await?;

        tx.commit().await?;
        Ok(SnapshotApplyOutcome::Applied)
    }

    pub async fn remove_list_subscription(&self, user_did: &str, list_uri: &str) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        Self::lock_moderation_did(&mut tx, user_did).await?;
        Self::bump_snapshot_generation_locked(&mut tx, user_did, ModerationSnapshotKind::List)
            .await?;
        sqlx::query(
            "DELETE FROM moderation_list_subscriptions WHERE user_did = $1 AND list_uri = $2",
        )
        .bind(user_did)
        .bind(list_uri)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "DELETE FROM moderation_list_members_by_user WHERE user_did = $1 AND list_uri = $2",
        )
        .bind(user_did)
        .bind(list_uri)
        .execute(&mut *tx)
        .await?;
        Self::set_snapshot_freshness_locked(&mut tx, user_did, ModerationSnapshotKind::List, false)
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
                FROM moderation_list_members_by_user
                WHERE user_did = $1
                  AND subject_did = $2
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
        let generation = self
            .allocate_snapshot_generation(&session.did, ModerationSnapshotKind::Actor)
            .await?;
        let snapshot = async {
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
        }
        .await;
        let (muted_dids, blocked_dids) = match snapshot {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return self
                    .fail_snapshot(
                        &session.did,
                        ModerationSnapshotKind::Actor,
                        generation,
                        error,
                    )
                    .await;
            }
        };
        let result = self
            .replace_actor_snapshot_if_current(&session.did, generation, muted_dids, blocked_dids)
            .await;
        self.finish_snapshot_apply(
            &session.did,
            ModerationSnapshotKind::Actor,
            generation,
            result,
        )
        .await
    }

    async fn replace_actor_snapshot_if_current(
        &self,
        user_did: &str,
        generation: i64,
        muted_dids: Vec<String>,
        blocked_dids: Vec<String>,
    ) -> Result<SnapshotApplyOutcome> {
        let mut tx = self.db_pool.begin().await?;
        Self::lock_moderation_did(&mut tx, user_did).await?;
        if Self::current_snapshot_generation_locked(
            &mut tx,
            user_did,
            ModerationSnapshotKind::Actor,
        )
        .await?
            != Some(generation)
        {
            tx.rollback().await?;
            return Ok(SnapshotApplyOutcome::Superseded);
        }

        sqlx::query("DELETE FROM user_mutes WHERE user_did = $1")
            .bind(user_did)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM user_blocks WHERE user_did = $1")
            .bind(user_did)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            r#"
            INSERT INTO user_mutes (user_did, muted_did)
            SELECT $1, muted_did
            FROM UNNEST($2::TEXT[]) AS input(muted_did)
            ON CONFLICT (user_did, muted_did) DO NOTHING
            "#,
        )
        .bind(user_did)
        .bind(&muted_dids)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO user_blocks (user_did, blocked_did)
            SELECT $1, blocked_did
            FROM UNNEST($2::TEXT[]) AS input(blocked_did)
            ON CONFLICT (user_did, blocked_did) DO NOTHING
            "#,
        )
        .bind(user_did)
        .bind(&blocked_dids)
        .execute(&mut *tx)
        .await?;

        Self::set_snapshot_freshness_locked(&mut tx, user_did, ModerationSnapshotKind::Actor, true)
            .await?;
        tx.commit().await?;
        Ok(SnapshotApplyOutcome::Applied)
    }

    async fn sync_list_relationships(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
    ) -> Result<()> {
        let generation = self
            .allocate_snapshot_generation(&session.did, ModerationSnapshotKind::List)
            .await?;
        let snapshot = async {
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
        }
        .await;
        let member_map = match snapshot {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return self
                    .fail_snapshot(
                        &session.did,
                        ModerationSnapshotKind::List,
                        generation,
                        error,
                    )
                    .await;
            }
        };
        let result = self
            .replace_all_list_snapshots_if_current(&session.did, generation, member_map)
            .await;
        self.finish_snapshot_apply(
            &session.did,
            ModerationSnapshotKind::List,
            generation,
            result,
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
    use sqlx::{postgres::PgPoolOptions, Connection, PgConnection, PgPool};
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

    async fn live_pool() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored Postgres suite");
        PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .expect("connect test Postgres")
    }

    async fn cleanup_tenant_fixture(pool: &PgPool, users: &[&str], lists: &[&str]) {
        sqlx::query("DELETE FROM moderation_list_members_by_user WHERE user_did = ANY($1)")
            .bind(users)
            .execute(pool)
            .await
            .expect("clean tenant members");
        sqlx::query("DELETE FROM moderation_list_subscriptions WHERE user_did = ANY($1)")
            .bind(users)
            .execute(pool)
            .await
            .expect("clean tenant subscriptions");
        sqlx::query("DELETE FROM moderation_list_members WHERE list_uri = ANY($1)")
            .bind(lists)
            .execute(pool)
            .await
            .expect("clean legacy members");
        sqlx::query("DELETE FROM user_mutes WHERE user_did = ANY($1)")
            .bind(users)
            .execute(pool)
            .await
            .expect("clean tenant mutes");
        sqlx::query("DELETE FROM user_blocks WHERE user_did = ANY($1)")
            .bind(users)
            .execute(pool)
            .await
            .expect("clean tenant blocks");
        sqlx::query("DELETE FROM moderation_snapshot_generations WHERE user_did = ANY($1)")
            .bind(users)
            .execute(pool)
            .await
            .expect("clean tenant generations");
        sqlx::query("DELETE FROM push_accounts WHERE account_did = ANY($1)")
            .bind(users)
            .execute(pool)
            .await
            .expect("clean tenant push accounts");
    }

    async fn tenant_members(pool: &PgPool, user_did: &str) -> Vec<(String, String)> {
        sqlx::query_as::<_, (String, String)>(
            r#"
            SELECT list_uri, subject_did
            FROM moderation_list_members_by_user
            WHERE user_did = $1
            ORDER BY list_uri, subject_did
            "#,
        )
        .bind(user_did)
        .fetch_all(pool)
        .await
        .expect("load tenant members")
    }

    async fn insert_push_account_fixture(pool: &PgPool, user_did: &str) {
        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                pds_url,
                last_actor_sync_at,
                last_list_sync_at
            )
            VALUES ($1, 'fixture-session', 'https://fixture.invalid', NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE SET
                session_id = EXCLUDED.session_id,
                pds_url = EXCLUDED.pds_url,
                last_actor_sync_at = NOW(),
                last_list_sync_at = NOW(),
                auth_revoked_at = NULL,
                updated_at = NOW()
            "#,
        )
        .bind(user_did)
        .execute(pool)
        .await
        .expect("insert push account fixture");
    }

    async fn apply_list_snapshot_fixture(
        cache: &ModerationCache,
        user_did: &str,
        list_uri: &str,
        purpose: &str,
        list_name: Option<String>,
        members: Vec<String>,
    ) {
        let generation = cache
            .allocate_snapshot_generation(user_did, ModerationSnapshotKind::List)
            .await
            .expect("allocate list fixture generation");
        let outcome = cache
            .replace_list_snapshot_if_current(
                user_did, generation, list_uri, purpose, list_name, members,
            )
            .await
            .expect("apply list fixture snapshot");
        assert_eq!(outcome, SnapshotApplyOutcome::Applied);
    }

    async fn apply_full_list_snapshot_fixture(
        cache: &ModerationCache,
        user_did: &str,
        snapshots: Vec<(ListSubscription, Vec<String>)>,
    ) -> Result<SnapshotApplyOutcome> {
        let generation = cache
            .allocate_snapshot_generation(user_did, ModerationSnapshotKind::List)
            .await?;
        cache
            .replace_all_list_snapshots_if_current(user_did, generation, snapshots)
            .await
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_tenant_direct_replacement_and_removal_are_did_scoped() {
        let pool = live_pool().await;
        let cache = ModerationCache::new(pool.clone(), 60);
        let user_a = "did:plc:moderation-tenant-a";
        let user_b = "did:plc:moderation-tenant-b";
        let list = "at://did:plc:list-owner/app.bsky.graph.list/shared";
        cleanup_tenant_fixture(&pool, &[user_a, user_b], &[list]).await;

        apply_list_snapshot_fixture(
            &cache,
            user_a,
            list,
            "modlist",
            Some("shared".to_owned()),
            vec!["did:plc:member-a".to_owned()],
        )
        .await;
        apply_list_snapshot_fixture(
            &cache,
            user_b,
            list,
            "modlist",
            Some("shared".to_owned()),
            vec!["did:plc:member-b".to_owned()],
        )
        .await;

        assert!(cache
            .is_actor_list_filtered(user_a, "did:plc:member-a")
            .await
            .expect("filter DID A member"));
        assert!(!cache
            .is_actor_list_filtered(user_a, "did:plc:member-b")
            .await
            .expect("exclude DID B member from DID A"));
        assert!(cache
            .is_actor_list_filtered(user_b, "did:plc:member-b")
            .await
            .expect("filter DID B member"));

        cache
            .remove_list_subscription(user_b, list)
            .await
            .expect("remove DID B subscription");
        assert!(cache
            .is_actor_list_filtered(user_a, "did:plc:member-a")
            .await
            .expect("DID A survives DID B removal"));
        assert!(!cache
            .is_actor_list_filtered(user_b, "did:plc:member-b")
            .await
            .expect("DID B rows removed"));

        cleanup_tenant_fixture(&pool, &[user_a, user_b], &[list]).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_tenant_full_refresh_and_failures_preserve_isolation() {
        let pool = live_pool().await;
        let cache = ModerationCache::new(pool.clone(), 60);
        let user_a = "did:plc:moderation-refresh-a";
        let user_b = "did:plc:moderation-refresh-b";
        let shared_list = "at://did:plc:list-owner/app.bsky.graph.list/refresh-shared";
        let omitted_list = "at://did:plc:list-owner/app.bsky.graph.list/refresh-omitted";
        cleanup_tenant_fixture(&pool, &[user_a, user_b], &[shared_list, omitted_list]).await;

        apply_list_snapshot_fixture(
            &cache,
            user_a,
            shared_list,
            "modlist",
            None,
            vec!["did:plc:refresh-a".to_owned()],
        )
        .await;
        apply_list_snapshot_fixture(
            &cache,
            user_b,
            shared_list,
            "modlist",
            None,
            vec!["did:plc:refresh-b-old".to_owned()],
        )
        .await;
        apply_list_snapshot_fixture(
            &cache,
            user_b,
            omitted_list,
            "curatelist",
            None,
            vec!["did:plc:refresh-b-omitted".to_owned()],
        )
        .await;

        apply_full_list_snapshot_fixture(
            &cache,
            user_b,
            vec![(
                ListSubscription {
                    uri: shared_list.to_owned(),
                    purpose: "modlist".to_owned(),
                    name: Some("refreshed".to_owned()),
                },
                vec!["did:plc:refresh-b-new".to_owned()],
            )],
        )
        .await
        .expect("replace only DID B full snapshot");

        assert_eq!(
            tenant_members(&pool, user_a).await,
            vec![(shared_list.to_owned(), "did:plc:refresh-a".to_owned())]
        );
        assert_eq!(
            tenant_members(&pool, user_b).await,
            vec![(shared_list.to_owned(), "did:plc:refresh-b-new".to_owned())]
        );

        sqlx::query(
            "ALTER TABLE moderation_list_members_by_user ADD CONSTRAINT moderation_test_reject_boom CHECK (subject_did <> 'did:plc:boom')",
        )
        .execute(&pool)
        .await
        .expect("install forced transaction failure");
        let transaction_error = apply_full_list_snapshot_fixture(
            &cache,
            user_b,
            vec![(
                ListSubscription {
                    uri: shared_list.to_owned(),
                    purpose: "modlist".to_owned(),
                    name: None,
                },
                vec!["did:plc:boom".to_owned()],
            )],
        )
        .await
        .expect_err("forced insert failure must roll back replacement");
        assert!(transaction_error
            .to_string()
            .contains("moderation_test_reject_boom"));
        sqlx::query(
            "ALTER TABLE moderation_list_members_by_user DROP CONSTRAINT moderation_test_reject_boom",
        )
        .execute(&pool)
        .await
        .expect("remove forced transaction failure");

        let fetch_error = replace_after_complete_snapshot(
            async {
                Err::<Vec<(ListSubscription, Vec<String>)>, _>(anyhow!("forced fetch failure"))
            },
            |_snapshots| async {
                Err::<(), _>(anyhow!("replacement must not run after fetch failure"))
            },
        )
        .await
        .expect_err("fetch failure must skip replacement transaction");
        assert!(fetch_error.to_string().contains("forced fetch failure"));

        assert_eq!(
            tenant_members(&pool, user_a).await,
            vec![(shared_list.to_owned(), "did:plc:refresh-a".to_owned())]
        );
        assert_eq!(
            tenant_members(&pool, user_b).await,
            vec![(shared_list.to_owned(), "did:plc:refresh-b-new".to_owned())]
        );

        cleanup_tenant_fixture(&pool, &[user_a, user_b], &[shared_list, omitted_list]).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_actor_generations_reject_older_snapshot_and_isolate_dids() {
        let pool = live_pool().await;
        let cache = ModerationCache::new(pool.clone(), 60);
        let user_a = "did:plc:actor-generation-a";
        let user_b = "did:plc:actor-generation-b";
        cleanup_tenant_fixture(&pool, &[user_a, user_b], &[]).await;
        insert_push_account_fixture(&pool, user_a).await;
        insert_push_account_fixture(&pool, user_b).await;

        let older_a = cache
            .allocate_snapshot_generation(user_a, ModerationSnapshotKind::Actor)
            .await
            .expect("allocate older DID A actor snapshot");
        let current_b = cache
            .allocate_snapshot_generation(user_b, ModerationSnapshotKind::Actor)
            .await
            .expect("allocate DID B actor snapshot");
        let current_a = cache
            .allocate_snapshot_generation(user_a, ModerationSnapshotKind::Actor)
            .await
            .expect("allocate current DID A actor snapshot");

        assert_eq!(
            cache
                .replace_actor_snapshot_if_current(
                    user_a,
                    current_a,
                    vec!["did:plc:actor-current-a".to_owned()],
                    vec![],
                )
                .await
                .expect("apply current DID A actor snapshot"),
            SnapshotApplyOutcome::Applied
        );
        assert_eq!(
            cache
                .replace_actor_snapshot_if_current(
                    user_b,
                    current_b,
                    vec![],
                    vec!["did:plc:actor-current-b".to_owned()],
                )
                .await
                .expect("apply DID B actor snapshot"),
            SnapshotApplyOutcome::Applied
        );

        sqlx::query(
            "UPDATE push_accounts SET last_actor_sync_at = TIMESTAMPTZ '2000-01-01 00:00:00+00' WHERE account_did = $1",
        )
        .bind(user_a)
        .execute(&pool)
        .await
        .expect("install deterministic stale actor timestamp");

        assert_eq!(
            cache
                .replace_actor_snapshot_if_current(
                    user_a,
                    older_a,
                    vec!["did:plc:actor-stale-a".to_owned()],
                    vec![],
                )
                .await
                .expect("reject older DID A actor snapshot"),
            SnapshotApplyOutcome::Superseded
        );

        let actor_rows = sqlx::query_as::<_, (String, String)>(
            r#"
            SELECT 'mute', muted_did FROM user_mutes WHERE user_did = $1
            UNION ALL
            SELECT 'block', blocked_did FROM user_blocks WHERE user_did = $1
            ORDER BY 1, 2
            "#,
        )
        .bind(user_a)
        .fetch_all(&pool)
        .await
        .expect("load DID A actor state");
        assert_eq!(
            actor_rows,
            vec![("mute".to_owned(), "did:plc:actor-current-a".to_owned())]
        );
        assert!(cache
            .is_actor_muted_or_blocked(user_b, "did:plc:actor-current-b")
            .await
            .expect("DID B actor state survives DID A stale apply"));
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT last_actor_sync_at = TIMESTAMPTZ '2000-01-01 00:00:00+00' FROM push_accounts WHERE account_did = $1",
        )
        .bind(user_a)
        .fetch_one(&pool)
        .await
        .expect("check stale actor snapshot did not mark freshness"));

        cleanup_tenant_fixture(&pool, &[user_a, user_b], &[]).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_list_generations_reject_older_snapshot_and_isolate_dids() {
        let pool = live_pool().await;
        let cache = ModerationCache::new(pool.clone(), 60);
        let user_a = "did:plc:list-generation-a";
        let user_b = "did:plc:list-generation-b";
        let list_a = "at://did:plc:list-owner/app.bsky.graph.list/generation-a";
        let list_b = "at://did:plc:list-owner/app.bsky.graph.list/generation-b";
        cleanup_tenant_fixture(&pool, &[user_a, user_b], &[list_a, list_b]).await;
        insert_push_account_fixture(&pool, user_a).await;
        insert_push_account_fixture(&pool, user_b).await;

        let older_a = cache
            .allocate_snapshot_generation(user_a, ModerationSnapshotKind::List)
            .await
            .expect("allocate older DID A list snapshot");
        let current_b = cache
            .allocate_snapshot_generation(user_b, ModerationSnapshotKind::List)
            .await
            .expect("allocate DID B list snapshot");
        let current_a = cache
            .allocate_snapshot_generation(user_a, ModerationSnapshotKind::List)
            .await
            .expect("allocate current DID A list snapshot");

        assert_eq!(
            cache
                .replace_all_list_snapshots_if_current(
                    user_a,
                    current_a,
                    vec![(
                        ListSubscription {
                            uri: list_a.to_owned(),
                            purpose: "modlist".to_owned(),
                            name: Some("current-a".to_owned()),
                        },
                        vec!["did:plc:list-member-current-a".to_owned()],
                    )],
                )
                .await
                .expect("apply current DID A list snapshot"),
            SnapshotApplyOutcome::Applied
        );
        assert_eq!(
            cache
                .replace_all_list_snapshots_if_current(
                    user_b,
                    current_b,
                    vec![(
                        ListSubscription {
                            uri: list_b.to_owned(),
                            purpose: "curatelist".to_owned(),
                            name: None,
                        },
                        vec!["did:plc:list-member-current-b".to_owned()],
                    )],
                )
                .await
                .expect("apply DID B list snapshot"),
            SnapshotApplyOutcome::Applied
        );

        sqlx::query(
            "UPDATE push_accounts SET last_list_sync_at = TIMESTAMPTZ '2000-01-01 00:00:00+00' WHERE account_did = $1",
        )
        .bind(user_a)
        .execute(&pool)
        .await
        .expect("install deterministic stale list timestamp");

        assert_eq!(
            cache
                .replace_all_list_snapshots_if_current(
                    user_a,
                    older_a,
                    vec![(
                        ListSubscription {
                            uri: list_a.to_owned(),
                            purpose: "modlist".to_owned(),
                            name: Some("stale-a".to_owned()),
                        },
                        vec!["did:plc:list-member-stale-a".to_owned()],
                    )],
                )
                .await
                .expect("reject older DID A list snapshot"),
            SnapshotApplyOutcome::Superseded
        );

        assert_eq!(
            tenant_members(&pool, user_a).await,
            vec![(
                list_a.to_owned(),
                "did:plc:list-member-current-a".to_owned()
            )]
        );
        assert_eq!(
            tenant_members(&pool, user_b).await,
            vec![(
                list_b.to_owned(),
                "did:plc:list-member-current-b".to_owned()
            )]
        );
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT last_list_sync_at = TIMESTAMPTZ '2000-01-01 00:00:00+00' FROM push_accounts WHERE account_did = $1",
        )
        .bind(user_a)
        .fetch_one(&pool)
        .await
        .expect("check stale list snapshot did not mark freshness"));

        cleanup_tenant_fixture(&pool, &[user_a, user_b], &[list_a, list_b]).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with migration privileges"]
    async fn live_postgres_migration_backfills_subscribers_without_orphans() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored Postgres suite");
        let mut connection = PgConnection::connect(&database_url)
            .await
            .expect("connect test Postgres");
        let schema = format!("moderation_tenant_{}", uuid::Uuid::new_v4().simple());

        sqlx::raw_sql(&format!(
            r#"
            CREATE SCHEMA {schema};
            SET search_path TO {schema}, public;
            CREATE TABLE moderation_list_subscriptions (
                user_did TEXT NOT NULL,
                list_uri TEXT NOT NULL,
                UNIQUE (user_did, list_uri)
            );
            CREATE TABLE moderation_list_members (
                list_uri TEXT NOT NULL,
                subject_did TEXT NOT NULL,
                UNIQUE (list_uri, subject_did)
            );
            INSERT INTO moderation_list_subscriptions (user_did, list_uri) VALUES
                ('did:plc:migration-a', 'at://list/shared'),
                ('did:plc:migration-b', 'at://list/shared');
            INSERT INTO moderation_list_members (list_uri, subject_did) VALUES
                ('at://list/shared', 'did:plc:shared-member'),
                ('at://list/orphan', 'did:plc:orphan-member');
            "#
        ))
        .execute(&mut connection)
        .await
        .expect("seed isolated legacy schema");

        sqlx::raw_sql(include_str!(
            "../../../migrations/20260715100000_scope_moderation_list_members_by_did.up.sql"
        ))
        .execute(&mut connection)
        .await
        .expect("apply exact tenant-isolation migration");

        let backfilled = sqlx::query_as::<_, (String, String, String)>(
            r#"
            SELECT user_did, list_uri, subject_did
            FROM moderation_list_members_by_user
            ORDER BY user_did, list_uri, subject_did
            "#,
        )
        .fetch_all(&mut connection)
        .await
        .expect("load migration backfill");
        assert_eq!(
            backfilled,
            vec![
                (
                    "did:plc:migration-a".to_owned(),
                    "at://list/shared".to_owned(),
                    "did:plc:shared-member".to_owned(),
                ),
                (
                    "did:plc:migration-b".to_owned(),
                    "at://list/shared".to_owned(),
                    "did:plc:shared-member".to_owned(),
                ),
            ]
        );

        sqlx::query(
            "DELETE FROM moderation_list_members_by_user WHERE user_did = 'did:plc:migration-b'",
        )
        .execute(&mut connection)
        .await
        .expect("diverge DID B snapshot");
        let remaining = sqlx::query_scalar::<_, String>(
            "SELECT user_did FROM moderation_list_members_by_user ORDER BY user_did",
        )
        .fetch_all(&mut connection)
        .await
        .expect("load independently mutable snapshots");
        assert_eq!(remaining, vec!["did:plc:migration-a"]);

        sqlx::raw_sql(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE;"
        ))
        .execute(&mut connection)
        .await
        .expect("clean isolated migration schema");
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
