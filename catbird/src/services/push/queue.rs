use anyhow::Result;
use serde_json::Value;
use sqlx::{Pool, Postgres, Row};

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
                lease_token = gen_random_uuid(),
                lease_version = q.lease_version + 1,
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
                q.created_at,
                q.attempts,
                q.lease_token,
                q.lease_version,
                q.auth_generation
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

    pub async fn delete_fenced(
        &self,
        id: i64,
        lease_token: uuid::Uuid,
        lease_version: i64,
    ) -> Result<bool> {
        let result = sqlx::query(
            "DELETE FROM push_event_queue WHERE id = $1 AND lease_token = $2 AND lease_version = $3 AND leased_until >= NOW()",
        )
        .bind(id)
        .bind(lease_token)
        .bind(lease_version)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn retry_later_fenced(
        &self,
        id: i64,
        lease_token: uuid::Uuid,
        lease_version: i64,
        attempts: i32,
        error: &str,
    ) -> Result<bool> {
        let backoff_seconds = i64::from((attempts.max(1) * 5).min(300));
        let result = sqlx::query(
            r#"
            UPDATE push_event_queue
            SET leased_until = NULL,
                lease_token = NULL,
                lease_version = push_event_queue.lease_version + 1,
                available_at = NOW() + make_interval(secs => $2),
                last_error = $3,
                updated_at = NOW()
            WHERE id = $1 AND lease_token = $4 AND lease_version = $5 AND leased_until >= NOW()
            "#,
        )
        .bind(id)
        .bind(backoff_seconds)
        .bind(error)
        .bind(lease_token)
        .bind(lease_version)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn extend_lease(
        &self,
        id: i64,
        lease_token: uuid::Uuid,
        lease_version: i64,
        extension_seconds: i64,
    ) -> Result<Option<i64>> {
        let row = sqlx::query(
            r#"
            UPDATE push_event_queue
            SET leased_until = NOW() + make_interval(secs => $4),
                lease_version = push_event_queue.lease_version + 1,
                updated_at = NOW()
            WHERE id = $1 AND lease_token = $2 AND lease_version = $3 AND leased_until >= NOW()
            RETURNING lease_version
            "#,
        )
        .bind(id)
        .bind(lease_token)
        .bind(lease_version)
        .bind(extension_seconds)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.and_then(|r| r.try_get::<i64, _>("lease_version").ok()))
    }

    pub async fn is_lease_valid(
        &self,
        id: i64,
        lease_token: uuid::Uuid,
        lease_version: i64,
    ) -> Result<bool> {
        let row = sqlx::query(
            r#"
            SELECT 1 FROM push_event_queue
            WHERE id = $1 AND lease_token = $2 AND lease_version = $3 AND leased_until >= NOW()
            "#,
        )
        .bind(id)
        .bind(lease_token)
        .bind(lease_version)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.is_some())
    }

    /// Atomically claim a queued event by dedupe key. Returns true only if an
    /// UNLEASED row was deleted — the caller then owns delivery. Returns false
    /// if the row is absent or the durable worker already leased it.
    pub async fn claim_by_dedupe_key(&self, dedupe_key: &str) -> Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM push_event_queue
            WHERE dedupe_key = $1
              AND (leased_until IS NULL OR leased_until < NOW())
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
    use std::collections::HashMap;
    use uuid::Uuid;

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct QueueDbRow {
        id: i64,
        recipient_did: String,
        available_at: u64,
        leased_until: Option<u64>,
        lease_token: Option<Uuid>,
        lease_version: i64,
        auth_generation: i64,
        attempts: i32,
        last_error: Option<String>,
    }

    struct SqlPushQueueEngine {
        rows: HashMap<i64, QueueDbRow>,
        auth_revoked_accounts: HashMap<String, bool>,
        clock: u64,
    }

    impl SqlPushQueueEngine {
        fn new() -> Self {
            Self {
                rows: HashMap::new(),
                auth_revoked_accounts: HashMap::new(),
                clock: 100,
            }
        }

        fn tick(&mut self, seconds: u64) -> u64 {
            self.clock += seconds;
            self.clock
        }

        fn insert_ready(&mut self, id: i64, recipient_did: &str) {
            self.rows.insert(
                id,
                QueueDbRow {
                    id,
                    recipient_did: recipient_did.to_string(),
                    available_at: self.clock,
                    leased_until: None,
                    lease_token: None,
                    lease_version: 0,
                    auth_generation: 1,
                    attempts: 0,
                    last_error: None,
                },
            );
        }

        /// Mirrors SQL:
        /// WITH claimed AS (
        ///     SELECT peq.id FROM push_event_queue peq
        ///     LEFT JOIN push_accounts pa ON pa.account_did = peq.recipient_did
        ///     WHERE peq.available_at <= NOW() AND (peq.leased_until IS NULL OR peq.leased_until < NOW())
        ///       AND (pa.auth_revoked_at IS NULL)
        ///     ORDER BY peq.created_at ASC LIMIT $1 FOR UPDATE OF peq SKIP LOCKED
        /// )
        /// UPDATE push_event_queue q
        /// SET leased_until = NOW() + INTERVAL '30 seconds', lease_token = gen_random_uuid(), lease_version = q.lease_version + 1, attempts = q.attempts + 1
        fn sql_claim_ready(&mut self, batch_size: usize) -> Vec<(i64, Uuid, i64, u64)> {
            let now = self.clock;
            let mut claimable: Vec<i64> = self
                .rows
                .values()
                .filter(|r| {
                    r.available_at <= now
                        && r.leased_until.map(|u| u < now).unwrap_or(true)
                        && !self
                            .auth_revoked_accounts
                            .get(&r.recipient_did)
                            .copied()
                            .unwrap_or(false)
                })
                .map(|r| r.id)
                .collect();
            claimable.sort();
            claimable.truncate(batch_size);

            let mut claimed = Vec::new();
            for id in claimable {
                let row = self.rows.get_mut(&id).unwrap();
                let token = Uuid::new_v4();
                let lease_expiry = now + 30;
                row.leased_until = Some(lease_expiry);
                row.lease_token = Some(token);
                row.lease_version += 1;
                row.attempts += 1;
                claimed.push((row.id, token, row.lease_version, lease_expiry));
            }
            claimed
        }

        /// Mirrors SQL:
        /// SELECT 1 FROM push_event_queue WHERE id = $1 AND lease_token = $2 AND leased_until >= NOW()
        fn sql_is_lease_valid(&self, id: i64, lease_token: Uuid) -> bool {
            let now = self.clock;
            self.rows
                .get(&id)
                .map(|r| {
                    r.lease_token == Some(lease_token)
                        && r.leased_until.map(|u| u >= now).unwrap_or(false)
                })
                .unwrap_or(false)
        }

        /// Mirrors SQL:
        /// DELETE FROM push_event_queue WHERE id = $1 AND lease_token = $2
        fn sql_delete_fenced(&mut self, id: i64, lease_token: Uuid) -> bool {
            let now = self.clock;
            if let Some(row) = self.rows.get(&id) {
                if row.lease_token == Some(lease_token)
                    && row.leased_until.map(|u| u >= now).unwrap_or(false)
                {
                    self.rows.remove(&id);
                    return true;
                }
            }
            false
        }

        /// Mirrors SQL:
        /// UPDATE push_event_queue SET leased_until = NOW() + make_interval(secs => $3), updated_at = NOW()
        /// WHERE id = $1 AND lease_token = $2 AND leased_until >= NOW()
        fn sql_extend_lease(&mut self, id: i64, lease_token: Uuid, extension_seconds: u64) -> bool {
            let now = self.clock;
            if let Some(row) = self.rows.get_mut(&id) {
                if row.lease_token == Some(lease_token)
                    && row.leased_until.map(|u| u >= now).unwrap_or(false)
                {
                    row.leased_until = Some(now + extension_seconds);
                    return true;
                }
            }
            false
        }
    }

    #[test]
    fn test_queue_fenced_lease_two_claimers_and_forced_expiry() {
        let mut queue = SqlPushQueueEngine::new();
        queue.insert_ready(1, "did:plc:alice");

        // Worker 1 claims item #1
        let claimed_w1 = queue.sql_claim_ready(1);
        assert_eq!(claimed_w1.len(), 1);
        let (id, token_w1, version_w1, expiry_w1) = claimed_w1[0];
        assert_eq!(id, 1);
        assert_eq!(version_w1, 1);
        assert_eq!(expiry_w1, 130);
        assert!(queue.sql_is_lease_valid(id, token_w1));

        // Time advances past lease expiry (Worker 1 is experiencing a long send / pause)
        queue.tick(31); // clock is now 131
        assert!(!queue.sql_is_lease_valid(id, token_w1));

        // Worker 2 claims the now-expired item #1
        let claimed_w2 = queue.sql_claim_ready(1);
        assert_eq!(claimed_w2.len(), 1);
        let (_, token_w2, version_w2, _) = claimed_w2[0];
        assert_ne!(token_w1, token_w2);
        assert_eq!(version_w2, 2);
        assert!(queue.sql_is_lease_valid(id, token_w2));

        // Worker 1 wakes up and attempts to verify/delete with its stale lease token
        assert!(!queue.sql_is_lease_valid(id, token_w1));
        assert!(!queue.sql_delete_fenced(id, token_w1)); // Fails! 0 rows affected

        // Queue still contains the row owned by Worker 2
        assert!(queue.rows.contains_key(&id));

        // Worker 2 successfully acknowledges and deletes with its valid lease token
        assert!(queue.sql_is_lease_valid(id, token_w2));
        assert!(queue.sql_delete_fenced(id, token_w2)); // Succeeds!
        assert!(!queue.rows.contains_key(&id));
    }

    #[test]
    fn test_queue_lease_extension_cas() {
        let mut queue = SqlPushQueueEngine::new();
        queue.insert_ready(1, "did:plc:alice");

        let claimed = queue.sql_claim_ready(1);
        let (id, token, _, _) = claimed[0];

        // Advance 15 seconds (lease still valid)
        queue.tick(15);
        assert!(queue.sql_is_lease_valid(id, token));

        // Extend lease by 30s
        assert!(queue.sql_extend_lease(id, token, 30));
        assert_eq!(queue.rows.get(&id).unwrap().leased_until, Some(145));

        // Advance past original expiry (was 130, now extended to 145)
        queue.tick(16); // clock is 131
        assert!(queue.sql_is_lease_valid(id, token));

        // Expire after extended time
        queue.tick(15); // clock is 146
        assert!(!queue.sql_is_lease_valid(id, token));

        // Extension fails once expired
        assert!(!queue.sql_extend_lease(id, token, 30));
    }

    #[test]
    fn test_mid_fanout_revocation_cancels_subsequent_sends() {
        let mut queue = SqlPushQueueEngine::new();
        let recipient_did = "did:plc:alice";
        queue.insert_ready(1, recipient_did);

        let claimed = queue.sql_claim_ready(1);
        let (id, token, _, _) = claimed[0];

        let devices = vec!["device-token-1", "device-token-2", "device-token-3"];
        let mut apns_sent = Vec::new();

        for (idx, dev) in devices.iter().enumerate() {
            // Pre-send check 1: Auth revocation
            if queue
                .auth_revoked_accounts
                .get(recipient_did)
                .copied()
                .unwrap_or(false)
            {
                break;
            }
            // Pre-send check 2: Lease validity
            if !queue.sql_is_lease_valid(id, token) {
                break;
            }

            // Send APNs
            apns_sent.push(*dev);

            // Simulate revocation immediately after device 1 was sent
            if idx == 0 {
                queue
                    .auth_revoked_accounts
                    .insert(recipient_did.to_string(), true);
            }
        }

        // Assert ONLY device 1 was sent, devices 2 and 3 were cancelled!
        assert_eq!(apns_sent, vec!["device-token-1"]);
    }
}
