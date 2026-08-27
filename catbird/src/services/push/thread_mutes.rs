//! Thread mutes — the one piece of push moderation state Nest still stores.
//!
//! Everything else (actor mutes, blocks, and moderation-list membership) is
//! answered per actor by the appview via `ActorModerationResolver`, because
//! `app.bsky.actor.defs#viewerState` already reports it. Nest previously
//! mirrored all of it locally, which meant paging every member of every
//! subscribed list — 385,502 rows for ~60 subscriptions — inline in the push
//! decision path. A subscribed list too large to page inside the decision
//! budget wedged the sequential worker and stopped all push delivery. See
//! ADR-022.
//!
//! Thread mutes stay local because there is no equivalent per-actor question to
//! ask: the state is keyed by thread, `app.bsky.feed.defs#viewerState.threadMuted`
//! would need a separate post fetch, and the table has no growth path — it holds
//! one small row per thread a user explicitly muted.

use anyhow::Result;
use sqlx::{Pool, Postgres, Row};

#[derive(Clone)]
pub struct ThreadMuteStore {
    db_pool: Pool<Postgres>,
}

impl ThreadMuteStore {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self { db_pool }
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
}
