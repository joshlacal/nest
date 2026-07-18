use anyhow::Result;
use serde_json::Value;
use sqlx::{types::Uuid, Pool, Postgres};

use super::{apns::APNS_DELIVERY_LEASE_SECS, types::QueueRow};

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
            SET leased_until = NOW() + make_interval(secs => $2::double precision),
                lease_owner = gen_random_uuid(),
                attempts = q.attempts + 1,
                updated_at = NOW()
            FROM claimed
            WHERE q.id = claimed.id
            RETURNING
                q.id,
                q.lease_owner,
                q.recipient_did,
                q.actor_did,
                q.notification_type,
                q.event_cid,
                q.event_path,
                q.subject_uri,
                q.thread_root_uri,
                q.event_record_json,
                q.event_timestamp,
                q.created_at,
                q.attempts
            "#,
        )
        .bind(batch_size)
        .bind(APNS_DELIVERY_LEASE_SECS as f64)
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

    /// Delete a claimed row only while the caller still owns its current lease.
    /// Returns false when ownership transferred or the row no longer exists.
    pub async fn delete(&self, id: i64, lease_owner: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM push_event_queue WHERE id = $1 AND lease_owner = $2")
            .bind(id)
            .bind(lease_owner)
            .execute(&self.db_pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Release a claimed row for retry only while the caller owns the lease.
    /// Returns false instead of modifying a newer claimant's state.
    pub async fn retry_later(
        &self,
        id: i64,
        lease_owner: Uuid,
        attempts: i32,
        error: &str,
    ) -> Result<bool> {
        let backoff_seconds = i64::from((attempts.max(1) * 5).min(300));
        let result = sqlx::query(
            r#"
            UPDATE push_event_queue
            SET leased_until = NULL,
                lease_owner = NULL,
                available_at = NOW() + make_interval(secs => $2),
                last_error = $3,
                updated_at = NOW()
            WHERE id = $1
              AND lease_owner = $4
            "#,
        )
        .bind(id)
        .bind(backoff_seconds)
        .bind(error)
        .bind(lease_owner)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Extend a lease immediately before an external side effect. The row lock
    /// taken by this UPDATE makes renewal race atomically with another claim:
    /// exactly one owner can succeed.
    pub async fn renew(&self, id: i64, lease_owner: Uuid) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE push_event_queue
            SET leased_until = NOW() + make_interval(secs => $3::double precision),
                updated_at = NOW()
            WHERE id = $1
              AND lease_owner = $2
              AND NOT EXISTS (
                  SELECT 1
                  FROM push_accounts pa
                  WHERE pa.account_did = push_event_queue.recipient_did
                    AND pa.auth_revoked_at IS NOT NULL
              )
            "#,
        )
        .bind(id)
        .bind(lease_owner)
        .bind(APNS_DELIVERY_LEASE_SECS as f64)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    /// Atomically claim a never-leased queued event for an active account.
    ///
    /// Once the durable worker has attempted a row, only its fenced lease
    /// protocol may own it; the Redis path must not take over an expired lease.
    pub async fn claim_by_dedupe_key(&self, dedupe_key: &str) -> Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM push_event_queue peq
            USING push_accounts pa
            WHERE peq.dedupe_key = $1
              AND peq.attempts = 0
              AND peq.leased_until IS NULL
              AND peq.lease_owner IS NULL
              AND pa.account_did = peq.recipient_did
              AND pa.auth_revoked_at IS NULL
            "#,
        )
        .bind(dedupe_key)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected() > 0)
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

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.db_pool
    }
}

#[cfg(test)]
mod tests {
    use sqlx::{postgres::PgPoolOptions, PgPool};

    use super::*;

    async fn live_pool() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored Postgres suite");
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("connect test Postgres")
    }

    async fn insert_account_and_event(pool: &PgPool, did: &str, dedupe_key: &str) -> i64 {
        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did, session_id, pds_url, auth_revoked_at
            )
            VALUES ($1, $2, 'https://pds.test', NULL)
            ON CONFLICT (account_did) DO UPDATE
            SET auth_revoked_at = NULL,
                updated_at = NOW()
            "#,
        )
        .bind(did)
        .bind(Uuid::new_v4().to_string())
        .execute(pool)
        .await
        .expect("insert push account");

        sqlx::query_scalar::<_, i64>(
            r#"
            INSERT INTO push_event_queue (
                recipient_did, actor_did, notification_type,
                event_cid, event_path, event_record_json,
                event_timestamp, dedupe_key, available_at
            )
            VALUES ($1, 'did:plc:sender', 'chat_message',
                    $2, 'chat.bsky.convo.getLog', '{}'::jsonb,
                    1, $2, NOW())
            RETURNING id
            "#,
        )
        .bind(did)
        .bind(dedupe_key)
        .fetch_one(pool)
        .await
        .expect("insert push event")
    }

    async fn cleanup(pool: &PgPool, dids: &[&str]) {
        for did in dids {
            sqlx::query("DELETE FROM push_event_queue WHERE recipient_did = $1")
                .bind(*did)
                .execute(pool)
                .await
                .expect("clean push events");
            sqlx::query("DELETE FROM push_accounts WHERE account_did = $1")
                .bind(*did)
                .execute(pool)
                .await
                .expect("clean push accounts");
        }
    }

    async fn remaining_lease_seconds(pool: &PgPool, id: i64) -> f64 {
        sqlx::query_scalar::<_, f64>(
            "SELECT EXTRACT(EPOCH FROM (leased_until - NOW()))::double precision FROM push_event_queue WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read remaining queue lease")
    }

    fn assert_full_delivery_lease(remaining_seconds: f64) {
        let configured = APNS_DELIVERY_LEASE_SECS as f64;
        assert!(
            remaining_seconds > configured - 5.0,
            "expected nearly the full {configured}s delivery lease, got {remaining_seconds}s"
        );
        assert!(
            remaining_seconds <= configured + 1.0,
            "lease exceeded the configured delivery budget: {remaining_seconds}s"
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn claim_and_renew_use_bounded_apns_delivery_lease() {
        let pool = live_pool().await;
        let queue = PushQueue::new(pool.clone());
        let did = format!("did:plc:lease-duration-{}", Uuid::new_v4());
        let dedupe = format!("lease-duration-{}", Uuid::new_v4());
        let id = insert_account_and_event(&pool, &did, &dedupe).await;

        let row = queue
            .claim_ready(256)
            .await
            .expect("claim delivery row")
            .into_iter()
            .find(|row| row.id == id)
            .expect("fixture was claimed");
        assert_full_delivery_lease(remaining_lease_seconds(&pool, id).await);

        assert!(queue.renew(id, row.lease_owner).await.unwrap());
        assert_full_delivery_lease(remaining_lease_seconds(&pool, id).await);

        assert!(queue.delete(id, row.lease_owner).await.unwrap());
        cleanup(&pool, &[&did]).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn stale_owner_cannot_renew_retry_or_delete_new_claim() {
        let pool = live_pool().await;
        let queue = PushQueue::new(pool.clone());
        let did = format!("did:plc:lease-fence-{}", Uuid::new_v4());
        let dedupe = format!("lease-fence-{}", Uuid::new_v4());
        let id = insert_account_and_event(&pool, &did, &dedupe).await;

        let first = queue
            .claim_ready(256)
            .await
            .expect("first claim")
            .into_iter()
            .find(|row| row.id == id)
            .expect("fixture was claimed");
        assert!(!first.lease_owner.is_nil());

        sqlx::query(
            "UPDATE push_event_queue SET leased_until = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(id)
        .execute(&pool)
        .await
        .expect("expire first lease");

        let second = queue
            .claim_ready(256)
            .await
            .expect("second claim")
            .into_iter()
            .find(|row| row.id == id)
            .expect("expired fixture was reclaimed");
        assert_ne!(first.lease_owner, second.lease_owner);

        assert!(!queue.renew(id, first.lease_owner).await.unwrap());
        assert!(!queue
            .retry_later(id, first.lease_owner, first.attempts, "stale")
            .await
            .unwrap());
        assert!(!queue.delete(id, first.lease_owner).await.unwrap());

        assert!(queue.renew(id, second.lease_owner).await.unwrap());
        assert!(queue.delete(id, second.lease_owner).await.unwrap());
        cleanup(&pool, &[&did]).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn fast_path_rejects_revoked_and_previously_leased_rows() {
        let pool = live_pool().await;
        let queue = PushQueue::new(pool.clone());
        let revoked_did = format!("did:plc:fast-revoked-{}", Uuid::new_v4());
        let leased_did = format!("did:plc:fast-leased-{}", Uuid::new_v4());
        let active_did = format!("did:plc:fast-active-{}", Uuid::new_v4());
        let revoked_key = format!("fast-revoked-{}", Uuid::new_v4());
        let leased_key = format!("fast-leased-{}", Uuid::new_v4());
        let active_key = format!("fast-active-{}", Uuid::new_v4());

        insert_account_and_event(&pool, &revoked_did, &revoked_key).await;
        sqlx::query("UPDATE push_accounts SET auth_revoked_at = NOW() WHERE account_did = $1")
            .bind(&revoked_did)
            .execute(&pool)
            .await
            .expect("revoke account");
        assert!(!queue.claim_by_dedupe_key(&revoked_key).await.unwrap());

        let leased_id = insert_account_and_event(&pool, &leased_did, &leased_key).await;
        let leased = queue
            .claim_ready(256)
            .await
            .expect("durable claim")
            .into_iter()
            .find(|row| row.id == leased_id)
            .expect("leased fixture was claimed");
        sqlx::query(
            "UPDATE push_event_queue SET leased_until = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(leased_id)
        .execute(&pool)
        .await
        .expect("expire durable lease");
        assert!(!queue.claim_by_dedupe_key(&leased_key).await.unwrap());

        insert_account_and_event(&pool, &active_did, &active_key).await;
        assert!(queue.claim_by_dedupe_key(&active_key).await.unwrap());

        assert!(queue.delete(leased_id, leased.lease_owner).await.unwrap());
        cleanup(&pool, &[&revoked_did, &leased_did, &active_did]).await;
    }
}
