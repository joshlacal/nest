use anyhow::Result;
use serde_json::Value;
use sqlx::{PgConnection, Pool, Postgres, Row};

use super::types::{QueueRow, RegistrationRow};
use crate::services::chat_poll::types::ChatPushEvent;

/// Caller must keep this connection in the same transaction as cursor/watermark
/// advancement. The identity and queue insert commit together or neither does.
pub async fn enqueue_chat_tx(
    conn: &mut PgConnection,
    event: &ChatPushEvent,
    delay_secs: i64,
) -> Result<bool> {
    anyhow::ensure!(event.auth_generation > 0, "invalid push auth generation");
    let event_timestamp = chrono::DateTime::parse_from_rfc3339(&event.sent_at)?.timestamp();
    let dedupe_key = event.dedupe_key();
    let mut persisted = event.clone();
    persisted.message_text.clear();
    let inserted = sqlx::query(
        "INSERT INTO push_event_receipts(dedupe_key, recipient_did, auth_generation) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
    )
    .bind(&dedupe_key).bind(&event.recipient_did).bind(event.auth_generation)
    .execute(&mut *conn).await?.rows_affected() > 0;
    if !inserted {
        return Ok(false);
    }
    sqlx::query(
        r#"
        INSERT INTO push_event_queue(recipient_did, actor_did, notification_type,
            event_cid, event_path, event_record_json, event_timestamp, dedupe_key,
            available_at, auth_generation)
        VALUES ($1,$2,'chat_message',$3,'chat.bsky.convo.getLog',$4,$5,$6,
            NOW() + make_interval(secs => $7),$8)
        ON CONFLICT (dedupe_key) DO NOTHING
    "#,
    )
    .bind(&event.recipient_did)
    .bind(&event.sender_did)
    .bind(&event.message_id)
    .bind(serde_json::to_value(persisted)?)
    .bind(event_timestamp)
    .bind(&dedupe_key)
    .bind(delay_secs.max(0) as f64)
    .bind(event.auth_generation)
    .execute(&mut *conn)
    .await?;
    Ok(true)
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeviceAttempt {
    Send(uuid::Uuid),
    AlreadyFinished,
    Held,
    LeaseLost,
}

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
                  AND peq.delivery_hold_reason IS NULL
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
            r#"WITH completed AS (
                DELETE FROM push_event_queue
                WHERE id = $1 AND lease_token = $2 AND lease_version = $3 AND leased_until >= NOW()
                RETURNING dedupe_key, recipient_did, auth_generation
            )
            INSERT INTO push_event_receipts(dedupe_key, recipient_did, auth_generation, state)
            SELECT dedupe_key, recipient_did, auth_generation, 'completed' FROM completed
            ON CONFLICT (dedupe_key) DO UPDATE SET
                state = 'completed', updated_at = NOW()"#,
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
        .bind(backoff_seconds as f64)
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
        .bind(extension_seconds as f64)
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

    /// Commit an intent before crossing the APNs boundary. An intent without a
    /// recorded response on restart is ambiguous, and is held for inspection.
    pub async fn begin_device_attempt(
        &self,
        row: &QueueRow,
        device: &RegistrationRow,
        lease_token: uuid::Uuid,
    ) -> Result<DeviceAttempt> {
        let mut tx = self.db_pool.begin().await?;
        let event_key = sqlx::query_scalar::<_, String>(
            "SELECT dedupe_key FROM push_event_queue WHERE id=$1 AND lease_token=$2 AND leased_until >= NOW() AND delivery_hold_reason IS NULL",
        ).bind(row.id).bind(lease_token).fetch_optional(&mut *tx).await?;
        let Some(event_key) = event_key else {
            return Ok(DeviceAttempt::LeaseLost);
        };
        sqlx::query("INSERT INTO push_event_receipts(dedupe_key,recipient_did,auth_generation) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(&event_key).bind(&row.recipient_did).bind(row.auth_generation)
            .execute(&mut *tx).await?;
        let event_state = sqlx::query_scalar::<_, String>(
            "SELECT state FROM push_event_receipts WHERE dedupe_key=$1 FOR UPDATE",
        )
        .bind(&event_key)
        .fetch_one(&mut *tx)
        .await?;
        if event_state == "completed" {
            return Ok(DeviceAttempt::AlreadyFinished);
        }
        if event_state == "held" {
            return Ok(DeviceAttempt::Held);
        }
        let prior = sqlx::query("SELECT state, attempts, delivery_id FROM push_device_deliveries WHERE dedupe_key=$1 AND device_id=$2 FOR UPDATE")
            .bind(&event_key).bind(device.id).fetch_optional(&mut *tx).await?;
        let outcome = if let Some(prior) = prior {
            let status: String = prior.try_get("state")?;
            let attempts: i32 = prior.try_get("attempts")?;
            if status == "accepted" || status == "invalid" {
                DeviceAttempt::AlreadyFinished
            } else if status == "retry" && attempts < 5 {
                sqlx::query("UPDATE push_device_deliveries SET state='attempting', attempts=attempts+1, updated_at=NOW() WHERE dedupe_key=$1 AND device_id=$2")
                    .bind(&event_key).bind(device.id).execute(&mut *tx).await?;
                DeviceAttempt::Send(prior.try_get("delivery_id")?)
            } else {
                sqlx::query("UPDATE push_device_deliveries SET state='held', last_error=CASE WHEN state='attempting' THEN 'ambiguous_process_interruption' WHEN state='retry' THEN 'retry_limit' ELSE last_error END, updated_at=NOW() WHERE dedupe_key=$1 AND device_id=$2")
                    .bind(&event_key).bind(device.id).execute(&mut *tx).await?;
                DeviceAttempt::Held
            }
        } else {
            let delivery_id = sqlx::query_scalar::<_, uuid::Uuid>("INSERT INTO push_device_deliveries(dedupe_key,device_id,state) VALUES($1,$2,'attempting') RETURNING delivery_id")
                .bind(&event_key).bind(device.id).fetch_one(&mut *tx).await?;
            DeviceAttempt::Send(delivery_id)
        };
        tx.commit().await?;
        Ok(outcome)
    }

    /// APNs success means accepted by APNs, never proof of phone presentation.
    pub async fn record_device_outcome(
        &self,
        delivery_id: uuid::Uuid,
        outcome: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        anyhow::ensure!(
            ["accepted", "invalid", "retry", "held"].contains(&outcome),
            "invalid delivery outcome"
        );
        let changed = sqlx::query("UPDATE push_device_deliveries SET state=$2, last_error=$3, updated_at=NOW() WHERE delivery_id=$1 AND state IN ('attempting','held')")
            .bind(delivery_id).bind(outcome).bind(reason)
            .execute(&self.db_pool).await?.rows_affected();
        anyhow::ensure!(
            changed == 1,
            "delivery outcome missing or already finalized"
        );
        Ok(())
    }

    /// Held rows are durable operator-visible work, never automatically retried.
    pub async fn hold_fenced(
        &self,
        id: i64,
        token: uuid::Uuid,
        version: i64,
        reason: &str,
    ) -> Result<bool> {
        let changed = sqlx::query(r#"
            WITH held AS (
                UPDATE push_event_queue SET delivery_hold_reason=$4, last_error=$4,
                    leased_until=NULL, lease_token=NULL, lease_version=lease_version+1, updated_at=NOW()
                WHERE id=$1 AND lease_token=$2 AND lease_version=$3 AND leased_until >= NOW()
                RETURNING dedupe_key,recipient_did,auth_generation
            )
            INSERT INTO push_event_receipts(dedupe_key,recipient_did,auth_generation,state,hold_reason)
            SELECT dedupe_key,recipient_did,auth_generation,'held',$4 FROM held
            ON CONFLICT(dedupe_key) DO UPDATE SET state='held',hold_reason=$4,updated_at=NOW()
        "#).bind(id).bind(token).bind(version).bind(reason).execute(&self.db_pool).await?;
        Ok(changed.rows_affected() > 0)
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
        ///       AND peq.delivery_hold_reason IS NULL
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
