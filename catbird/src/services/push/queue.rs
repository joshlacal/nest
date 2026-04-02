use anyhow::Result;
use serde_json::Value;
use sqlx::{Pool, Postgres};

use super::types::QueueRow;

#[derive(Clone)]
pub struct PushQueue {
    db_pool: Pool<Postgres>,
}

impl PushQueue {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self { db_pool }
    }

    pub async fn claim_ready(&self, batch_size: i64) -> Result<Vec<QueueRow>> {
        let rows = sqlx::query_as::<_, QueueRow>(
            r#"
            WITH claimed AS (
                SELECT peq.id
                FROM push_event_queue peq
                LEFT JOIN push_accounts pa ON pa.account_did = peq.recipient_did
                WHERE peq.available_at <= NOW()
                  AND (peq.leased_until IS NULL OR peq.leased_until < NOW())
                  AND (pa.auth_revoked_at IS NULL)
                ORDER BY peq.created_at ASC
                LIMIT $1
                FOR UPDATE OF peq SKIP LOCKED
            )
            UPDATE push_event_queue q
            SET leased_until = NOW() + INTERVAL '30 seconds',
                attempts = q.attempts + 1,
                updated_at = NOW()
            FROM claimed
            WHERE q.id = claimed.id
            RETURNING
                q.id,
                q.recipient_did,
                q.actor_did,
                q.notification_type,
                q.event_cid,
                q.event_path,
                q.subject_uri,
                q.thread_root_uri,
                q.event_record_json,
                q.event_timestamp,
                q.attempts
            "#,
        )
        .bind(batch_size)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows)
    }

    /// Delete all queued events for accounts whose auth has been revoked.
    /// Returns the number of rows deleted.
    pub async fn purge_revoked_accounts(&self) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM push_event_queue
            WHERE recipient_did IN (
                SELECT account_did FROM push_accounts
                WHERE auth_revoked_at IS NOT NULL
            )
            "#,
        )
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn delete(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM push_event_queue WHERE id = $1")
            .bind(id)
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }

    pub async fn retry_later(&self, id: i64, attempts: i32, error: &str) -> Result<()> {
        let backoff_seconds = i64::from((attempts.max(1) * 5).min(300));
        sqlx::query(
            r#"
            UPDATE push_event_queue
            SET leased_until = NULL,
                available_at = NOW() + make_interval(secs => $2),
                last_error = $3,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(backoff_seconds)
        .bind(error)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn delete_by_dedupe_key(&self, dedupe_key: &str) -> Result<()> {
        sqlx::query("DELETE FROM push_event_queue WHERE dedupe_key = $1")
            .bind(dedupe_key)
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }

    pub async fn push_snapshot(&self, id: i64) -> Result<Option<Value>> {
        let row = sqlx::query_scalar::<_, Value>(
            "SELECT event_record_json FROM push_event_queue WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row)
    }
}
