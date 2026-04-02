use anyhow::Result;
use sqlx::{Pool, Postgres};

use super::types::{tier_interval_secs, ChatPollRow, TIER_HOT, TIER_WARM};

#[derive(Clone)]
pub struct ChatPollScheduler {
    db_pool: Pool<Postgres>,
}

impl ChatPollScheduler {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self { db_pool }
    }

    // MARK: - Work Claiming

    /// Claim a batch of accounts whose `next_poll_at` is due.
    ///
    /// Uses `FOR UPDATE SKIP LOCKED` so that multiple worker tasks can claim
    /// non-overlapping sets concurrently without contention.
    pub async fn claim_due_accounts(&self, batch_size: i64) -> Result<Vec<ChatPollRow>> {
        let rows = sqlx::query_as::<_, ChatPollRow>(
            r#"
            WITH claimed AS (
                SELECT account_did
                FROM chat_poll_state
                WHERE next_poll_at <= NOW()
                ORDER BY next_poll_at ASC
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE chat_poll_state s
            SET next_poll_at = NOW() + INTERVAL '60 seconds',
                last_poll_at = NOW()
            FROM claimed
            WHERE s.account_did = claimed.account_did
            RETURNING
                s.account_did,
                s.chat_cursor,
                s.next_poll_at,
                s.last_poll_at,
                s.poll_tier,
                s.foreground_lease_until,
                s.pds_host,
                s.last_429_at,
                s.last_retry_after_secs,
                s.last_notified_message_id
            "#,
        )
        .bind(batch_size)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows)
    }

    // MARK: - Post-Poll Updates

    /// Update state after a successful poll.
    ///
    /// Tier transitions:
    /// - `had_incoming_message` → promote to TIER_HOT
    /// - no incoming → demote one step (HOT→WARM, WARM stays WARM, COLD stays COLD)
    pub async fn update_after_poll(
        &self,
        did: &str,
        cursor: &str,
        had_incoming_message: bool,
        current_tier: i16,
    ) -> Result<()> {
        let new_tier = if had_incoming_message {
            TIER_HOT
        } else {
            match current_tier {
                TIER_HOT => TIER_WARM,
                _ => current_tier, // WARM stays WARM, COLD stays COLD
            }
        };
        let interval_secs = tier_interval_secs(new_tier);

        sqlx::query(
            r#"
            UPDATE chat_poll_state
            SET chat_cursor = $2,
                poll_tier = $3,
                next_poll_at = NOW() + make_interval(secs => $4),
                last_poll_at = NOW()
            WHERE account_did = $1
            "#,
        )
        .bind(did)
        .bind(cursor)
        .bind(new_tier)
        .bind(interval_secs)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    /// Push `next_poll_at` forward by `delay_secs` from now.
    pub async fn reschedule(&self, did: &str, delay_secs: i64) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE chat_poll_state
            SET next_poll_at = NOW() + make_interval(secs => $2)
            WHERE account_did = $1
            "#,
        )
        .bind(did)
        .bind(delay_secs)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    // MARK: - PDS Back-off

    /// Reschedule all accounts on the given PDS host after a 429 response.
    ///
    /// `retry_after_secs` is taken from the `Retry-After` header when present;
    /// a minimum of 60 seconds is enforced.
    pub async fn backoff_pds_host(&self, host: &str, retry_after_secs: i64) -> Result<u64> {
        let effective_secs = retry_after_secs.max(60);

        let result = sqlx::query(
            r#"
            UPDATE chat_poll_state
            SET next_poll_at = NOW() + make_interval(secs => $2),
                last_429_at = NOW(),
                last_retry_after_secs = $3
            WHERE pds_host = $1
            "#,
        )
        .bind(host)
        .bind(effective_secs)
        .bind(retry_after_secs as i32)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }

    // MARK: - Foreground Lease

    /// Extend (or create) the foreground lease for a DID.
    ///
    /// While the lease is active the poller should run at TIER_HOT frequency
    /// because the user has the app in the foreground.
    pub async fn update_foreground_lease(&self, did: &str, secs: i64) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE chat_poll_state
            SET foreground_lease_until = NOW() + make_interval(secs => $2),
                poll_tier = $3,
                next_poll_at = LEAST(next_poll_at, NOW() + make_interval(secs => $4))
            WHERE account_did = $1
            "#,
        )
        .bind(did)
        .bind(secs)
        .bind(TIER_HOT)
        .bind(tier_interval_secs(TIER_HOT))
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    // MARK: - Enrollment

    /// Enroll an account for chat polling (UPSERT).
    ///
    /// If the account is already enrolled the PDS host is updated but existing
    /// cursor / tier data is preserved.
    pub async fn enroll_account(&self, did: &str, pds_host: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO chat_poll_state (account_did, pds_host, poll_tier, next_poll_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (account_did)
            DO UPDATE SET pds_host = EXCLUDED.pds_host
            "#,
        )
        .bind(did)
        .bind(pds_host)
        .bind(TIER_WARM)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    /// Remove an account from chat polling.
    pub async fn unenroll_account(&self, did: &str) -> Result<()> {
        sqlx::query("DELETE FROM chat_poll_state WHERE account_did = $1")
            .bind(did)
            .execute(&self.db_pool)
            .await?;

        Ok(())
    }

    // MARK: - Mute Management

    /// Returns `true` if the conversation is muted for the given DID.
    pub async fn is_convo_muted(&self, did: &str, convo_id: &str) -> Result<bool> {
        let muted = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM chat_muted_convos
                WHERE account_did = $1 AND convo_id = $2
            )
            "#,
        )
        .bind(did)
        .bind(convo_id)
        .fetch_one(&self.db_pool)
        .await?;

        Ok(muted)
    }

    /// Insert or remove a single muted conversation entry.
    pub async fn set_convo_muted(&self, did: &str, convo_id: &str, muted: bool) -> Result<()> {
        if muted {
            sqlx::query(
                r#"
                INSERT INTO chat_muted_convos (account_did, convo_id)
                VALUES ($1, $2)
                ON CONFLICT (account_did, convo_id) DO NOTHING
                "#,
            )
            .bind(did)
            .bind(convo_id)
            .execute(&self.db_pool)
            .await?;
        } else {
            sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1 AND convo_id = $2")
                .bind(did)
                .bind(convo_id)
                .execute(&self.db_pool)
                .await?;
        }

        Ok(())
    }

    /// Bulk-replace the full set of muted conversations for a DID.
    ///
    /// Runs inside a transaction: deletes all existing mute rows for the DID,
    /// then inserts the new set.
    pub async fn sync_muted_convos(&self, did: &str, convo_ids: &[String]) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;

        sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1")
            .bind(did)
            .execute(&mut *tx)
            .await?;

        for convo_id in convo_ids {
            sqlx::query("INSERT INTO chat_muted_convos (account_did, convo_id) VALUES ($1, $2)")
                .bind(did)
                .bind(convo_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        Ok(())
    }
}
