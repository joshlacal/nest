use anyhow::{anyhow, Result};
use bytes::Bytes;
use reqwest::Method;
use serde_json::Value;
use sqlx::{Pool, Postgres, Row};
use std::sync::Arc;
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
            state, user_did, &session_id, &pds_url,
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
            self.sync_actor_relationships(state, &session, &dpop).await?;
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
        let list_name = self
            .fetch_list_name(state, session, dpop, list_uri)
            .await
            .ok()
            .flatten();
        let members = self.fetch_list_members(state, session, dpop, list_uri).await?;

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
        let muted_dids = self
            .fetch_paginated_profile_dids(state, session, dpop, "app.bsky.graph.getMutes", "mutes")
            .await?;
        let blocked_dids = self
            .fetch_paginated_profile_dids(state, session, dpop, "app.bsky.graph.getBlocks", "blocks")
            .await?;

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
    }

    async fn sync_list_relationships(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
    ) -> Result<()> {
        let mut lists = self
            .fetch_paginated_lists(
                state,
                session,
                dpop,
                "app.bsky.graph.getListMutes",
                "curatelist",
            )
            .await?;
        lists.extend(
            self.fetch_paginated_lists(
                state,
                session,
                dpop,
                "app.bsky.graph.getListBlocks",
                "modlist",
            )
            .await?,
        );

        let mut member_map = Vec::with_capacity(lists.len());
        for list in &lists {
            let members = self.fetch_list_members(state, session, dpop, &list.uri).await?;
            member_map.push((list.clone(), members));
        }

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
    }

    async fn fetch_paginated_profile_dids(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        lexicon: &str,
        array_key: &str,
    ) -> Result<Vec<String>> {
        let mut cursor = None::<String>;
        let mut dids = Vec::new();

        loop {
            let query = match cursor.as_deref() {
                Some(cursor) => format!("limit=100&cursor={}", urlencoding::encode(cursor)),
                None => "limit=100".to_string(),
            };
            let payload = self.fetch_xrpc_json(state, session, dpop, lexicon, Some(&query)).await?;

            if let Some(items) = payload.get(array_key).and_then(|value| value.as_array()) {
                dids.extend(items.iter().filter_map(|item| {
                    item.get("did")
                        .and_then(|value| value.as_str())
                        .map(str::to_owned)
                }));
            }

            cursor = payload
                .get("cursor")
                .and_then(|value| value.as_str())
                .map(str::to_owned);
            if cursor.is_none() {
                break;
            }
        }

        Ok(dids)
    }

    async fn fetch_paginated_lists(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        lexicon: &str,
        purpose: &str,
    ) -> Result<Vec<ListSubscription>> {
        let mut cursor = None::<String>;
        let mut lists = Vec::new();

        loop {
            let query = match cursor.as_deref() {
                Some(cursor) => format!("limit=100&cursor={}", urlencoding::encode(cursor)),
                None => "limit=100".to_string(),
            };
            let payload = self.fetch_xrpc_json(state, session, dpop, lexicon, Some(&query)).await?;

            if let Some(items) = payload.get("lists").and_then(|value| value.as_array()) {
                lists.extend(items.iter().filter_map(|item| {
                    item.get("uri")
                        .and_then(|value| value.as_str())
                        .map(|uri| ListSubscription {
                            uri: uri.to_string(),
                            purpose: purpose.to_string(),
                            name: item
                                .get("name")
                                .and_then(|value| value.as_str())
                                .map(str::to_owned),
                        })
                }));
            }

            cursor = payload
                .get("cursor")
                .and_then(|value| value.as_str())
                .map(str::to_owned);
            if cursor.is_none() {
                break;
            }
        }

        Ok(lists)
    }

    async fn fetch_list_name(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        list_uri: &str,
    ) -> Result<Option<String>> {
        let query = format!("list={}", urlencoding::encode(list_uri));
        let payload = self
            .fetch_xrpc_json(state, session, dpop, "app.bsky.graph.getList", Some(&query))
            .await?;

        Ok(payload
            .get("list")
            .and_then(|value| value.get("name"))
            .and_then(|value| value.as_str())
            .map(str::to_owned))
    }

    async fn fetch_list_members(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        list_uri: &str,
    ) -> Result<Vec<String>> {
        let mut cursor = None::<String>;
        let mut members = Vec::new();

        loop {
            let mut query = format!("list={}&limit=100", urlencoding::encode(list_uri));
            if let Some(cursor_value) = cursor.as_deref() {
                query.push_str("&cursor=");
                query.push_str(&urlencoding::encode(cursor_value));
            }

            let payload = self
                .fetch_xrpc_json(state, session, dpop, "app.bsky.graph.getList", Some(&query))
                .await?;

            if let Some(items) = payload.get("items").and_then(|value| value.as_array()) {
                members.extend(items.iter().filter_map(|item| {
                    item.get("subject")
                        .and_then(|value| value.get("did"))
                        .and_then(|value| value.as_str())
                        .map(str::to_owned)
                }));
            }

            cursor = payload
                .get("cursor")
                .and_then(|value| value.as_str())
                .map(str::to_owned);
            if cursor.is_none() {
                break;
            }
        }

        Ok(members)
    }

    async fn fetch_xrpc_json(
        &self,
        state: &Arc<AppState>,
        session: &CatbirdSession,
        dpop: &JacquardDpopData,
        lexicon: &str,
        query: Option<&str>,
    ) -> Result<Value> {
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

        parse_json_body(&body)
    }
}

fn parse_json_body(body: &Bytes) -> Result<Value> {
    Ok(serde_json::from_slice(body)?)
}
