use anyhow::Result;
use sqlx::{Pool, Postgres};

use super::types::{tier_interval_secs, ChatPollRow, TIER_HOT, TIER_WARM};

/// Maximum number of muted conversations an account can have.
pub const MAX_CHAT_MUTES_PER_ACCOUNT: usize = 1000;

/// Maximum length in bytes of a conversation identifier.
pub const MAX_CONVO_ID_LEN: usize = 256;

/// Validate conversation identifier format and length.
/// Rejects empty strings, strings exceeding `MAX_CONVO_ID_LEN`, and non-canonical characters.
pub fn is_valid_convo_id(convo_id: &str) -> bool {
    !convo_id.is_empty()
        && convo_id.len() <= MAX_CONVO_ID_LEN
        && convo_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'))
}

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
                s.last_notified_message_id,
                s.primed_at
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

    // MARK: - Prime Pass

    /// Mark an account as fully primed: the prime pass has fast-forwarded
    /// through all backlog and seeded watermarks, so the normal poll loop is
    /// now safe to run (and safe to notify) for this account.
    pub async fn mark_primed(&self, did: &str) -> Result<()> {
        sqlx::query("UPDATE chat_poll_state SET primed_at = NOW() WHERE account_did = $1")
            .bind(did)
            .execute(&self.db_pool)
            .await?;

        Ok(())
    }

    /// Persist the prime pass's cursor progress for a single page, without
    /// touching `poll_tier` / `next_poll_at`. Called after each page during
    /// priming so a crash or page-cap exhaustion mid-prime resumes from where
    /// it left off instead of restarting from `cursor=None`.
    pub async fn update_prime_cursor(&self, did: &str, cursor: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE chat_poll_state
            SET chat_cursor = $2,
                last_poll_at = NOW()
            WHERE account_did = $1
            "#,
        )
        .bind(did)
        .bind(cursor)
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
        let effective_secs = if retry_after_secs <= 0 {
            super::rate_budget::MIN_RETRY_AFTER_SECS
        } else {
            (retry_after_secs as u64).clamp(
                super::rate_budget::MIN_RETRY_AFTER_SECS,
                super::rate_budget::MAX_RETRY_AFTER_SECS,
            )
        };

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
        .bind(effective_secs as i64)
        .bind(effective_secs as i32)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }

    // MARK: - Foreground Lease

    /// Extend (or create) the foreground lease for a DID.
    ///
    /// While the lease is active the poller should run at TIER_HOT frequency
    /// because the user has the app in the foreground. Returns the number of
    /// rows updated so callers can detect a missing enrollment (0 rows).
    pub async fn update_foreground_lease(&self, did: &str, secs: i64) -> Result<u64> {
        let result = sqlx::query(
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

        Ok(result.rows_affected())
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

    /// Unenroll only if the account has no active devices — atomic, so a
    /// concurrent re-registration's enrollment can't be wiped between a
    /// check and a delete.
    pub async fn unenroll_account_if_no_active_devices(&self, did: &str) -> Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM chat_poll_state
            WHERE account_did = $1
              AND NOT EXISTS (
                  SELECT 1 FROM user_devices
                  WHERE did = $1 AND is_active
              )
            "#,
        )
        .bind(did)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected() > 0)
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

    /// Insert or remove a single muted conversation entry with quota enforcement.
    pub async fn set_convo_muted(&self, did: &str, convo_id: &str, muted: bool) -> Result<()> {
        if muted {
            if !is_valid_convo_id(convo_id) {
                anyhow::bail!("Invalid conversation ID format or length");
            }

            let mut tx = self.db_pool.begin().await?;

            // Serialize quota cardinality with shared account advisory transaction lock across all writers
            sqlx::query("SELECT pg_advisory_xact_lock(hashtext('chat_muted_convos:' || $1))")
                .bind(did)
                .execute(&mut *tx)
                .await?;

            let already_muted: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM chat_muted_convos
                    WHERE account_did = $1 AND convo_id = $2
                )
                "#,
            )
            .bind(did)
            .bind(convo_id)
            .fetch_one(&mut *tx)
            .await?;

            if !already_muted {
                let current_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM chat_muted_convos WHERE account_did = $1",
                )
                .bind(did)
                .fetch_one(&mut *tx)
                .await?;

                if current_count as usize >= MAX_CHAT_MUTES_PER_ACCOUNT {
                    anyhow::bail!(
                        "Chat mute quota exceeded: account already has {} mutes (max {})",
                        current_count,
                        MAX_CHAT_MUTES_PER_ACCOUNT
                    );
                }

                sqlx::query(
                    r#"
                    INSERT INTO chat_muted_convos (account_did, convo_id, updated_at)
                    VALUES ($1, $2, NOW())
                    ON CONFLICT (account_did, convo_id) DO UPDATE SET updated_at = NOW()
                    "#,
                )
                .bind(did)
                .bind(convo_id)
                .execute(&mut *tx)
                .await?;
            }

            tx.commit().await?;
        } else {
            // Allow delete/unmute of legacy invalid rows regardless of creation-time syntax
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
    /// then inserts the new set. Fails atomically without modifying DB if over quota
    /// or any conversation ID is invalid.
    pub async fn sync_muted_convos(&self, did: &str, convo_ids: &[String]) -> Result<()> {
        let mut deduped = std::collections::HashSet::new();
        for convo_id in convo_ids {
            if !is_valid_convo_id(convo_id) {
                anyhow::bail!("Invalid conversation ID format or length: {}", convo_id);
            }
            deduped.insert(convo_id.as_str());
        }

        if deduped.len() > MAX_CHAT_MUTES_PER_ACCOUNT {
            anyhow::bail!(
                "Mute count {} exceeds maximum allowed {}",
                deduped.len(),
                MAX_CHAT_MUTES_PER_ACCOUNT
            );
        }

        let mut tx = self.db_pool.begin().await?;

        // Serialize quota cardinality with shared account advisory transaction lock across all writers
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('chat_muted_convos:' || $1))")
            .bind(did)
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1")
            .bind(did)
            .execute(&mut *tx)
            .await?;

        for convo_id in deduped {
            sqlx::query(
                r#"
                INSERT INTO chat_muted_convos (account_did, convo_id, updated_at)
                VALUES ($1, $2, NOW())
                "#,
            )
            .bind(did)
            .bind(convo_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(())
    }

    // MARK: - Notification Watermarks

    /// All (convo_id -> last_rev) watermarks for an account, fetched once per poll.
    pub async fn get_watermarks(
        &self,
        did: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT convo_id, last_rev FROM chat_notified_watermarks WHERE account_did = $1",
        )
        .bind(did)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows.into_iter().collect())
    }

    /// Monotonically raise the watermark for (did, convo). Revs are TIDs, so
    /// lexicographic comparison is the ordering; a lower rev never overwrites.
    pub async fn bump_watermark(&self, did: &str, convo_id: &str, rev: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO chat_notified_watermarks (account_did, convo_id, last_rev, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (account_did, convo_id)
            DO UPDATE SET last_rev = EXCLUDED.last_rev, updated_at = NOW()
            WHERE chat_notified_watermarks.last_rev < EXCLUDED.last_rev
            "#,
        )
        .bind(did)
        .bind(convo_id)
        .bind(rev)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    /// Monotonically raise the watermarks for (did, convo) pairs in a single batched query.
    /// Revs are TIDs, so lexicographic comparison is the ordering; a lower rev never overwrites.
    pub async fn bump_watermarks_batch(
        &self,
        did: &str,
        watermarks: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        if watermarks.is_empty() {
            return Ok(());
        }
        let (convo_ids, revs): (Vec<String>, Vec<String>) =
            watermarks.iter().map(|(k, v)| (k.clone(), v.clone())).unzip();

        sqlx::query(
            r#"
            INSERT INTO chat_notified_watermarks (account_did, convo_id, last_rev, updated_at)
            SELECT $1, u.convo_id, u.rev, NOW()
            FROM UNNEST($2::text[], $3::text[]) AS u(convo_id, rev)
            ON CONFLICT (account_did, convo_id)
            DO UPDATE SET last_rev = EXCLUDED.last_rev, updated_at = NOW()
            WHERE chat_notified_watermarks.last_rev < EXCLUDED.last_rev
            "#,
        )
        .bind(did)
        .bind(&convo_ids)
        .bind(&revs)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_convo_id() {
        assert!(is_valid_convo_id("convo-1234_abcd.5678:xyz/abc"));
        assert!(is_valid_convo_id("3lsomerev22"));
        assert!(!is_valid_convo_id("")); // empty
        assert!(!is_valid_convo_id("has space")); // space
        assert!(!is_valid_convo_id("null\0byte")); // null byte
        assert!(!is_valid_convo_id("control\nchar")); // newline
        let long_id = "a".repeat(MAX_CONVO_ID_LEN + 1);
        assert!(!is_valid_convo_id(&long_id)); // oversized
        let exact_limit = "a".repeat(MAX_CONVO_ID_LEN);
        assert!(is_valid_convo_id(&exact_limit)); // exact limit
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_sql_chat_mute_quota_and_legacy_unmute() {
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let scheduler = ChatPollScheduler::new(pool.clone());
        let did = format!("did:plc:test_mute_quota_{}", uuid::Uuid::new_v4());

        // Clean up any stale data
        sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1")
            .bind(&did)
            .execute(&pool)
            .await
            .unwrap();

        // Seed an invalid legacy row directly in DB (e.g. spaces/punctuation that fails validation)
        let legacy_invalid_id = "legacy invalid convo id with spaces!";
        sqlx::query("INSERT INTO chat_muted_convos (account_did, convo_id) VALUES ($1, $2)")
            .bind(&did)
            .bind(legacy_invalid_id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(scheduler.is_convo_muted(&did, legacy_invalid_id).await.unwrap());

        // Unmute of legacy invalid row must SUCCEED
        scheduler
            .set_convo_muted(&did, legacy_invalid_id, false)
            .await
            .expect("Unmuting legacy invalid row must succeed");
        assert!(!scheduler.is_convo_muted(&did, legacy_invalid_id).await.unwrap());

        // Muting an invalid row must FAIL
        let res = scheduler.set_convo_muted(&did, legacy_invalid_id, true).await;
        assert!(res.is_err());

        // Test quota enforcement: insert up to 10 mutes in a loop for this test (or check boundary count)
        for i in 0..5 {
            let cid = format!("convo_test_{}", i);
            scheduler.set_convo_muted(&did, &cid, true).await.unwrap();
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat_muted_convos WHERE account_did = $1")
            .bind(&did)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 5);

        // Clean up
        sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1")
            .bind(&did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL (DATABASE_URL)"]
    async fn test_sql_concurrent_chat_mute_advisory_lock_race() {
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/test_nest_task3".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
            .connect(&db_url)
            .await
            .expect("DATABASE_URL connection must succeed when test is executed");

        let scheduler = ChatPollScheduler::new(pool.clone());
        let did = format!("did:plc:test_mute_race_{}", uuid::Uuid::new_v4());

        // Clean up
        sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1")
            .bind(&did)
            .execute(&pool)
            .await
            .unwrap();

        // Seed MAX_CHAT_MUTES_PER_ACCOUNT - 1 rows (999) in batch
        let mut query_builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO chat_muted_convos (account_did, convo_id, updated_at) "
        );
        let mutes: Vec<(String, String)> = (0..(MAX_CHAT_MUTES_PER_ACCOUNT - 1))
            .map(|i| (did.clone(), format!("seed_convo_{:04}", i)))
            .collect();
        query_builder.push_values(mutes, |mut b, (d, c)| {
            b.push_bind(d).push_bind(c).push("NOW()");
        });
        query_builder.build().execute(&pool).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat_muted_convos WHERE account_did = $1")
            .bind(&did)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count as usize, MAX_CHAT_MUTES_PER_ACCOUNT - 1);

        // Spawn 2 concurrent tasks trying to take the final slot with different convo IDs
        let s1 = scheduler.clone();
        let s2 = scheduler.clone();
        let did1 = did.clone();
        let did2 = did.clone();

        let t1 = tokio::spawn(async move {
            s1.set_convo_muted(&did1, "final_convo_1", true).await
        });
        let t2 = tokio::spawn(async move {
            s2.set_convo_muted(&did2, "final_convo_2", true).await
        });

        let (r1, r2) = tokio::join!(t1, t2);
        let res1 = r1.unwrap();
        let res2 = r2.unwrap();

        // Exactly one should succeed and one should fail with quota exceeded
        let successes = [res1.is_ok(), res2.is_ok()].iter().filter(|&&ok| ok).count();
        let failures = [res1.is_err(), res2.is_err()].iter().filter(|&&err| err).count();
        assert_eq!(successes, 1, "Exactly one writer should succeed into the final slot");
        assert_eq!(failures, 1, "The second writer must fail on quota exceeded");

        let final_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat_muted_convos WHERE account_did = $1")
            .bind(&did)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(final_count as usize, MAX_CHAT_MUTES_PER_ACCOUNT);

        // Clean up
        sqlx::query("DELETE FROM chat_muted_convos WHERE account_did = $1")
            .bind(&did)
            .execute(&pool)
            .await
            .unwrap();
    }
}
