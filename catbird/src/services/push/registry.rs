use anyhow::Result;
use sqlx::{Pool, Postgres, Row};

use crate::{
    error::{AppError, AppResult},
    models::CatbirdSession,
};

use super::types::{PushAccountRow, RegisterPushInput, RegistrationRow, UnregisterPushInput};

pub const MAX_ACTIVE_DEVICES_PER_ACCOUNT: i64 = 10;
pub const MAX_FANOUT_PER_NOTIFICATION: i64 = 10;

#[derive(Clone)]
pub struct PushRegistry {
    db_pool: Pool<Postgres>,
    service_did: String,
    max_active_devices_per_account: i64,
    max_inactive_devices_per_account: i64,
    max_fanout_per_notification: i64,
}

impl PushRegistry {
    pub fn new(db_pool: Pool<Postgres>, service_did: String) -> Self {
        Self {
            db_pool,
            service_did,
            max_active_devices_per_account: MAX_ACTIVE_DEVICES_PER_ACCOUNT,
            max_inactive_devices_per_account: 20,
            max_fanout_per_notification: MAX_FANOUT_PER_NOTIFICATION,
        }
    }

    pub fn with_limits(
        db_pool: Pool<Postgres>,
        service_did: String,
        max_active_devices_per_account: i64,
        max_inactive_devices_per_account: i64,
        max_fanout_per_notification: i64,
    ) -> Self {
        Self {
            db_pool,
            service_did,
            max_active_devices_per_account,
            max_inactive_devices_per_account,
            max_fanout_per_notification,
        }
    }

    pub fn service_did(&self) -> &str {
        &self.service_did
    }

    pub fn validate_service_did(&self, value: &str) -> AppResult<()> {
        if value == self.service_did {
            Ok(())
        } else {
            Err(AppError::BadRequest(format!(
                "Unexpected serviceDid {}, expected {}",
                value, self.service_did
            )))
        }
    }

    /// Activates a session after successful login, replacing any prior session and revocation.
    pub async fn activate_account_session(
        &self,
        did: &str,
        new_session: &str,
        pds_url: &str,
    ) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, did).await?;
        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                pds_url,
                auth_revoked_at,
                auth_generation,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, NULL, 1, NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE
            SET session_id = EXCLUDED.session_id,
                pds_url = EXCLUDED.pds_url,
                auth_revoked_at = NULL,
                auth_generation = push_accounts.auth_generation + 1,
                last_seen_at = NOW(),
                updated_at = NOW()
            "#,
        )
        .bind(did)
        .bind(new_session)
        .bind(pds_url)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(())
    }

    /// Inserts a missing account or refreshes it only when the session ID still matches.
    /// Atomically clears auth_revoked_at only on matching session or new insert.
    pub async fn touch_account_session(&self, session: &CatbirdSession) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, &session.did).await?;
        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                pds_url,
                auth_revoked_at,
                auth_generation,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, NULL, 1, NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE
            SET pds_url = EXCLUDED.pds_url,
                auth_revoked_at = NULL,
                last_seen_at = NOW(),
                updated_at = NOW()
            WHERE push_accounts.session_id = EXCLUDED.session_id
            "#,
        )
        .bind(&session.did)
        .bind(session.id.to_string())
        .bind(&session.pds_url)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(())
    }

    /// Replaces the session only when the account still has the expected old session.
    /// Clears auth_revoked_at and retains polling state on successful upgrade.
    /// Returns zero when the account is missing or its session has changed (stale CAS no-op).
    pub async fn replace_account_session(
        &self,
        did: &str,
        old_session_id: &str,
        new_session_id: &str,
    ) -> Result<u64> {
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, did).await?;
        let result = sqlx::query(
            r#"
            UPDATE push_accounts
            SET session_id = $1,
                auth_revoked_at = NULL,
                auth_generation = push_accounts.auth_generation + 1,
                last_seen_at = NOW(),
                updated_at = NOW()
            WHERE account_did = $2 AND session_id = $3
            "#,
        )
        .bind(new_session_id)
        .bind(did)
        .bind(old_session_id)
        .execute(&mut *tx)
        .await?;
        let affected = result.rows_affected();
        tx.commit().await?;

        Ok(affected)
    }

    pub async fn upsert_registration(
        &self,
        session: &CatbirdSession,
        input: &RegisterPushInput,
    ) -> Result<()> {
        input.validate()?;

        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_and_device_lock(&mut tx, &session.did, &input.token).await?;
        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                pds_url,
                auth_revoked_at,
                auth_generation,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, NULL, 1, NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE
            SET pds_url = EXCLUDED.pds_url,
                auth_revoked_at = NULL,
                last_seen_at = NOW(),
                updated_at = NOW()
            WHERE push_accounts.session_id = EXCLUDED.session_id
            "#,
        )
        .bind(&session.did)
        .bind(session.id.to_string())
        .bind(&session.pds_url)
        .execute(&mut *tx)
        .await?;

        // Finding 5: Atomic token reassignment.
        // Deactivate active registration for this token if previously registered by any other DID.
        sqlx::query(
            r#"
            UPDATE user_devices
            SET is_active = FALSE,
                last_invalidated_at = NOW(),
                last_error = 'reassigned_to_other_account',
                updated_at = NOW()
            WHERE device_token = $1
              AND did != $2
              AND is_active = TRUE
            "#,
        )
        .bind(&input.token)
        .bind(&session.did)
        .execute(&mut *tx)
        .await?;

        // Finding 43: Enforce per-account device cap.
        // If this DID already has >= max_active_devices_per_account active devices (excluding this token),
        // evict the oldest active devices to stay within quota.
        let active_count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM user_devices
            WHERE did = $1 AND is_active = TRUE AND device_token != $2
            "#,
        )
        .bind(&session.did)
        .bind(&input.token)
        .fetch_one(&mut *tx)
        .await?;

        if active_count >= self.max_active_devices_per_account {
            let evict_count = active_count - self.max_active_devices_per_account + 1;
            sqlx::query(
                r#"
                UPDATE user_devices
                SET is_active = FALSE,
                    last_invalidated_at = NOW(),
                    last_error = 'device_limit_eviction',
                    updated_at = NOW()
                WHERE id IN (
                    SELECT id FROM user_devices
                    WHERE did = $1 AND is_active = TRUE AND device_token != $2
                    ORDER BY updated_at ASC, last_registered_at ASC
                    LIMIT $3
                )
                "#,
            )
            .bind(&session.did)
            .bind(&input.token)
            .bind(evict_count)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            r#"
            INSERT INTO user_devices (
                did,
                device_token,
                platform,
                app_id,
                service_did,
                age_restricted,
                is_active,
                last_registered_at,
                last_error,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, TRUE, NOW(), NULL, NOW())
            ON CONFLICT (device_token, did)
            DO UPDATE
            SET platform = EXCLUDED.platform,
                app_id = EXCLUDED.app_id,
                service_did = EXCLUDED.service_did,
                age_restricted = EXCLUDED.age_restricted,
                is_active = TRUE,
                last_registered_at = NOW(),
                last_invalidated_at = NULL,
                last_error = NULL,
                updated_at = NOW()
            "#,
        )
        .bind(&session.did)
        .bind(&input.token)
        .bind(&input.platform)
        .bind(&input.app_id)
        .bind(&input.service_did)
        .bind(input.age_restricted.unwrap_or(false))
        .execute(&mut *tx)
        .await?;
        // Deterministic inactive-device cleanup: bound total retained inactive rows per account
        sqlx::query(
            r#"
            DELETE FROM user_devices
            WHERE id IN (
                SELECT id FROM user_devices
                WHERE did = $1 AND is_active = FALSE
                ORDER BY updated_at DESC, last_registered_at DESC
                OFFSET $2
            )
            "#,
        )
        .bind(&session.did)
        .bind(self.max_inactive_devices_per_account)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn deactivate_registration(
        &self,
        session: &CatbirdSession,
        input: &UnregisterPushInput,
    ) -> Result<()> {
        input.validate()?;
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_and_device_lock(&mut tx, &session.did, &input.token).await?;

        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                pds_url,
                auth_revoked_at,
                auth_generation,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, NULL, 1, NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE
            SET pds_url = EXCLUDED.pds_url,
                auth_revoked_at = NULL,
                last_seen_at = NOW(),
                updated_at = NOW()
            WHERE push_accounts.session_id = EXCLUDED.session_id
            "#,
        )
        .bind(&session.did)
        .bind(session.id.to_string())
        .bind(&session.pds_url)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE user_devices
            SET is_active = FALSE,
                last_error = NULL,
                updated_at = NOW()
            WHERE did = $1
              AND device_token = $2
              AND platform = $3
              AND app_id = $4
            "#,
        )
        .bind(&session.did)
        .bind(&input.token)
        .bind(&input.platform)
        .bind(&input.app_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn deactivate_invalid_token(
        &self,
        did: &str,
        device_token: &str,
        error: &str,
    ) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_and_device_lock(&mut tx, did, device_token).await?;
        sqlx::query(
            r#"
            UPDATE user_devices
            SET is_active = FALSE,
                last_error = $3,
                last_invalidated_at = NOW(),
                updated_at = NOW()
            WHERE did = $1
              AND device_token = $2
            "#,
        )
        .bind(did)
        .bind(device_token)
        .bind(error)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(())
    }

    pub async fn list_active_registrations(&self, did: &str) -> Result<Vec<RegistrationRow>> {
        let rows = sqlx::query_as::<_, RegistrationRow>(
            r#"
            SELECT
                id,
                did,
                device_token,
                platform,
                app_id,
                service_did,
                age_restricted,
                is_active,
                apns_environment
            FROM user_devices
            WHERE did = $1
              AND is_active = TRUE
            ORDER BY updated_at DESC
            LIMIT $2
            "#,
        )
        .bind(did)
        .bind(self.max_fanout_per_notification)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows)
    }

    pub async fn is_device_active(&self, did: &str, device_token: &str) -> Result<bool> {
        let row = sqlx::query(
            r#"
            SELECT 1 FROM user_devices
            WHERE did = $1
              AND device_token = $2
              AND is_active = TRUE
            "#,
        )
        .bind(did)
        .bind(device_token)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.is_some())
    }

    /// Records the APNs environment ("production"/"sandbox") that a device
    /// token was actually delivered on, learned via try-and-learn in
    /// `ApnsDelivery::send`. Called only when it differs from what's on file.
    pub async fn set_apns_environment(
        &self,
        did: &str,
        device_token: &str,
        env: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE user_devices
            SET apns_environment = $3,
                updated_at = NOW()
            WHERE did = $1
              AND device_token = $2
            "#,
        )
        .bind(did)
        .bind(device_token)
        .bind(env)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    pub async fn get_push_account(&self, did: &str) -> Result<Option<PushAccountRow>> {
        let row = sqlx::query_as::<_, PushAccountRow>(
            r#"
            SELECT
                account_did,
                session_id,
                pds_url,
                auth_generation
            FROM push_accounts
            WHERE account_did = $1
            "#,
        )
        .bind(did)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row)
    }

    pub async fn mark_auth_revoked(&self, did: &str) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, did).await?;

        sqlx::query(
            r#"
            UPDATE push_accounts
            SET auth_revoked_at = NOW(),
                auth_generation = push_accounts.auth_generation + 1,
                updated_at = NOW()
            WHERE account_did = $1
            "#,
        )
        .bind(did)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM chat_poll_state WHERE account_did = $1")
            .bind(did)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Marks auth revoked for an account only when the session ID matches the currently active session.
    /// Also unenrolls/disables chat polling for this exact account in the same atomic transaction
    /// with row lock on push_accounts so a newer activation/upgrade cannot be unenrolled.
    /// Returns the number of rows affected (0 if the account is missing or session ID has changed).
    pub async fn mark_auth_revoked_if_session(&self, did: &str, session_id: &str) -> Result<u64> {
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, did).await?;

        let result = sqlx::query(
            r#"
            UPDATE push_accounts
            SET auth_revoked_at = NOW(),
                auth_generation = push_accounts.auth_generation + 1,
                updated_at = NOW()
            WHERE account_did = $1 AND session_id = $2
            "#,
        )
        .bind(did)
        .bind(session_id)
        .execute(&mut *tx)
        .await?;

        let affected = result.rows_affected();
        if affected > 0 {
            sqlx::query("DELETE FROM chat_poll_state WHERE account_did = $1")
                .bind(did)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(affected)
    }

    pub async fn clear_auth_revoked(&self, did: &str) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, did).await?;
        sqlx::query(
            r#"
            UPDATE push_accounts
            SET auth_revoked_at = NULL,
                auth_generation = push_accounts.auth_generation + 1,
                updated_at = NOW()
            WHERE account_did = $1
            "#,
        )
        .bind(did)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn clear_auth_revoked_if_session(&self, did: &str, session_id: &str) -> Result<u64> {
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, did).await?;
        let result = sqlx::query(
            r#"
            UPDATE push_accounts
            SET auth_revoked_at = NULL,
                auth_generation = push_accounts.auth_generation + 1,
                updated_at = NOW()
            WHERE account_did = $1 AND session_id = $2
            "#,
        )
        .bind(did)
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
        let affected = result.rows_affected();
        tx.commit().await?;
        Ok(affected)
    }

    pub async fn is_auth_revoked(&self, did: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT auth_revoked_at IS NOT NULL AS revoked FROM push_accounts WHERE account_did = $1",
        )
        .bind(did)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row
            .map(|r| r.try_get::<bool, _>("revoked").unwrap_or(false))
            .unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[tokio::test]
    async fn validate_service_did_success_and_failure() {
        let pool = Pool::<Postgres>::connect_lazy("postgres://localhost/test").unwrap();
        let registry = PushRegistry::new(pool, "did:web:push.catbird.blue".to_string());

        assert_eq!(registry.service_did(), "did:web:push.catbird.blue");
        assert!(registry
            .validate_service_did("did:web:push.catbird.blue")
            .is_ok());
        assert!(registry
            .validate_service_did("did:web:other.service")
            .is_err());
    }

    /// Real SQL-shape relational state model that directly mirrors Postgres schema,
    /// row-locking semantics, atomic transactions, and SQL clause constraints.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct PushAccountDbRow {
        account_did: String,
        session_id: String,
        pds_url: String,
        auth_revoked_at: Option<u64>,
        auth_generation: i64,
        last_seen_at: u64,
        updated_at: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ChatPollStateDbRow {
        account_did: String,
        pds_host: String,
        next_poll_at: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct UserDeviceDbRow {
        did: String,
        device_token: String,
        platform: String,
        app_id: String,
        service_did: String,
        age_restricted: bool,
        is_active: bool,
        last_registered_at: u64,
        updated_at: u64,
    }

    struct SqlDatabaseEngine {
        push_accounts: HashMap<String, PushAccountDbRow>,
        chat_poll_state: HashMap<String, ChatPollStateDbRow>,
        user_devices: HashMap<(String, String), UserDeviceDbRow>,
        clock: u64,
    }

    impl SqlDatabaseEngine {
        fn new() -> Self {
            Self {
                push_accounts: HashMap::new(),
                chat_poll_state: HashMap::new(),
                user_devices: HashMap::new(),
                clock: 1,
            }
        }

        fn tick(&mut self) -> u64 {
            self.clock += 1;
            self.clock
        }

        /// Mirrors SQL:
        /// INSERT INTO push_accounts (account_did, session_id, pds_url, auth_revoked_at, last_seen_at, updated_at)
        /// VALUES ($1, $2, $3, NULL, NOW(), NOW())
        /// ON CONFLICT (account_did)
        /// DO UPDATE SET session_id = EXCLUDED.session_id, pds_url = EXCLUDED.pds_url, auth_revoked_at = NULL, last_seen_at = NOW(), updated_at = NOW()
        fn sql_activate_account_session(&mut self, did: &str, session_id: &str, pds_url: &str) {
            let now = self.tick();
            let prev_gen = self.push_accounts.get(did).map(|r| r.auth_generation).unwrap_or(0);
            self.push_accounts.insert(
                did.to_string(),
                PushAccountDbRow {
                    account_did: did.to_string(),
                    session_id: session_id.to_string(),
                    pds_url: pds_url.to_string(),
                    auth_revoked_at: None,
                    auth_generation: prev_gen + 1,
                    last_seen_at: now,
                    updated_at: now,
                },
            );
        }

        /// Mirrors SQL:
        /// INSERT INTO push_accounts (account_did, session_id, pds_url, auth_revoked_at, last_seen_at, updated_at)
        /// VALUES ($1, $2, $3, NULL, NOW(), NOW())
        /// ON CONFLICT (account_did)
        /// DO UPDATE SET pds_url = EXCLUDED.pds_url, auth_revoked_at = NULL, last_seen_at = NOW(), updated_at = NOW()
        /// WHERE push_accounts.session_id = EXCLUDED.session_id
        fn sql_touch_account_session(&mut self, did: &str, session_id: &str, pds_url: &str) -> u64 {
            let now = self.tick();
            if let Some(row) = self.push_accounts.get_mut(did) {
                if row.session_id == session_id {
                    row.pds_url = pds_url.to_string();
                    row.auth_revoked_at = None;
                    row.last_seen_at = now;
                    row.updated_at = now;
                    1
                } else {
                    // WHERE clause evaluated to false: no update occurred.
                    0
                }
            } else {
                // Inserted missing row
                self.push_accounts.insert(
                    did.to_string(),
                    PushAccountDbRow {
                        account_did: did.to_string(),
                        session_id: session_id.to_string(),
                        pds_url: pds_url.to_string(),
                        auth_revoked_at: None,
                        auth_generation: 1,
                        last_seen_at: now,
                        updated_at: now,
                    },
                );
                1
            }
        }

        /// Mirrors SQL:
        /// UPDATE push_accounts
        /// SET session_id = $1, auth_revoked_at = NULL, last_seen_at = NOW(), updated_at = NOW()
        /// WHERE account_did = $2 AND session_id = $3
        fn sql_replace_account_session(
            &mut self,
            did: &str,
            old_session_id: &str,
            new_session_id: &str,
        ) -> u64 {
            let now = self.tick();
            let Some(row) = self.push_accounts.get_mut(did) else {
                return 0;
            };
            if row.session_id != old_session_id {
                return 0;
            }

            row.session_id = new_session_id.to_string();
            row.auth_revoked_at = None;
            row.auth_generation += 1;
            row.last_seen_at = now;
            row.updated_at = now;
            1
        }

        /// Mirrors SQL transaction:
        /// BEGIN;
        /// UPDATE push_accounts SET auth_revoked_at = NOW(), updated_at = NOW() WHERE account_did = $1 AND session_id = $2;
        /// if affected > 0: DELETE FROM chat_poll_state WHERE account_did = $1;
        /// COMMIT;
        fn sql_mark_auth_revoked_if_session(&mut self, did: &str, session_id: &str) -> u64 {
            let now = self.tick();
            let Some(row) = self.push_accounts.get_mut(did) else {
                return 0;
            };
            if row.session_id != session_id {
                return 0;
            }

            row.auth_revoked_at = Some(now);
            row.auth_generation += 1;
            row.updated_at = now;
            self.chat_poll_state.remove(did);
            1
        }

        /// Mirrors SQL transaction in upsert_registration:
        /// BEGIN;
        /// INSERT INTO push_accounts ... ON CONFLICT DO UPDATE WHERE push_accounts.session_id = EXCLUDED.session_id;
        /// INSERT INTO user_devices ... ON CONFLICT DO UPDATE;
        /// COMMIT;
        fn sql_upsert_registration_tx(
            &mut self,
            did: &str,
            session_id: &str,
            pds_url: &str,
            device_token: &str,
            platform: &str,
            app_id: &str,
            service_did: &str,
            age_restricted: bool,
        ) {
            self.sql_touch_account_session(did, session_id, pds_url);
            let now = self.tick();

            // 1. Deactivate this device_token for any other DID
            for ((d, t), dev) in self.user_devices.iter_mut() {
                if t == device_token && d != did && dev.is_active {
                    dev.is_active = false;
                    dev.updated_at = now;
                }
            }

            // 2. Count active devices for this DID (excluding this token)
            let mut other_active: Vec<(String, String, u64)> = self
                .user_devices
                .iter()
                .filter(|((d, t), dev)| d == did && t != device_token && dev.is_active)
                .map(|((d, t), dev)| (d.clone(), t.clone(), dev.updated_at))
                .collect();

            if other_active.len() >= 10 {
                other_active.sort_by_key(|(_, _, u)| *u);
                let to_evict = other_active.len() - 10 + 1;
                for (d, t, _) in other_active.into_iter().take(to_evict) {
                    if let Some(dev) = self.user_devices.get_mut(&(d, t)) {
                        dev.is_active = false;
                        dev.updated_at = now;
                    }
                }
            }

            self.user_devices.insert(
                (did.to_string(), device_token.to_string()),
                UserDeviceDbRow {
                    did: did.to_string(),
                    device_token: device_token.to_string(),
                    platform: platform.to_string(),
                    app_id: app_id.to_string(),
                    service_did: service_did.to_string(),
                    age_restricted,
                    is_active: true,
                    last_registered_at: now,
                    updated_at: now,
                },
            );
        }

        fn sql_list_active_registrations(&self, did: &str) -> Vec<UserDeviceDbRow> {
            let mut list: Vec<UserDeviceDbRow> = self
                .user_devices
                .values()
                .filter(|d| d.did == did && d.is_active)
                .cloned()
                .collect();
            list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
            list.truncate(10);
            list
        }

        fn enroll_chat_poll(&mut self, did: &str, host: &str) {
            let now = self.tick();
            self.chat_poll_state.insert(
                did.to_string(),
                ChatPollStateDbRow {
                    account_did: did.to_string(),
                    pds_host: host.to_string(),
                    next_poll_at: now,
                },
            );
        }

        fn is_chat_poll_enrolled(&self, did: &str) -> bool {
            self.chat_poll_state.contains_key(did)
        }

        fn is_auth_revoked(&self, did: &str) -> bool {
            self.push_accounts
                .get(did)
                .and_then(|r| r.auth_revoked_at)
                .is_some()
        }
    }

    #[test]
    fn test_touch_stale_session_never_clears_revocation_or_overwrites_pds() {
        let mut db = SqlDatabaseEngine::new();
        let did = "did:plc:alice";
        let session_v1 = "session-1";
        let session_v2 = "session-2";

        // Activate session 1
        db.sql_activate_account_session(did, session_v1, "https://pds1.alice.com");
        assert!(!db.is_auth_revoked(did));
        assert_eq!(
            db.push_accounts.get(did).unwrap().pds_url,
            "https://pds1.alice.com"
        );

        // Revoke session 1
        assert_eq!(db.sql_mark_auth_revoked_if_session(did, session_v1), 1);
        assert!(db.is_auth_revoked(did));

        // Stale touch with non-matching session_v2 returns 0 rows updated and DOES NOT clear revocation
        let affected = db.sql_touch_account_session(did, session_v2, "https://pds2.alice.com");
        assert_eq!(affected, 0);
        assert!(db.is_auth_revoked(did));
        assert_eq!(
            db.push_accounts.get(did).unwrap().pds_url,
            "https://pds1.alice.com"
        );
        assert_eq!(db.push_accounts.get(did).unwrap().session_id, session_v1);

        // Matching touch with session_v1 clears revocation atomically
        let affected =
            db.sql_touch_account_session(did, session_v1, "https://pds1-updated.alice.com");
        assert_eq!(affected, 1);
        assert!(!db.is_auth_revoked(did));
        assert_eq!(
            db.push_accounts.get(did).unwrap().pds_url,
            "https://pds1-updated.alice.com"
        );
    }

    #[test]
    fn test_session_scoped_logout_and_chat_poll_unenrollment_atomic_tx() {
        let mut db = SqlDatabaseEngine::new();
        let did = "did:plc:alice";
        let session_v1 = "session-1";
        let session_v2 = "session-2";

        db.sql_activate_account_session(did, session_v1, "https://pds.alice.com");
        db.enroll_chat_poll(did, "pds.alice.com");
        assert!(db.is_chat_poll_enrolled(did));

        // Stale logout for session_v2 on active session_v1 is a no-op
        assert_eq!(db.sql_mark_auth_revoked_if_session(did, session_v2), 0);
        assert!(!db.is_auth_revoked(did));
        assert!(db.is_chat_poll_enrolled(did));

        // Matching logout for session_v1 atomically revokes auth and unenrolls chat polling
        assert_eq!(db.sql_mark_auth_revoked_if_session(did, session_v1), 1);
        assert!(db.is_auth_revoked(did));
        assert!(!db.is_chat_poll_enrolled(did));
    }

    #[test]
    fn test_stale_logout_does_not_unenroll_newer_active_session() {
        let mut db = SqlDatabaseEngine::new();
        let did = "did:plc:alice";
        let session_v1 = "session-1";
        let session_v2 = "session-2";

        db.sql_activate_account_session(did, session_v1, "https://pds.alice.com");

        // User upgrades or logs into session_v2
        assert_eq!(
            db.sql_replace_account_session(did, session_v1, session_v2),
            1
        );
        db.enroll_chat_poll(did, "pds.alice.com");
        assert!(db.is_chat_poll_enrolled(did));
        assert_eq!(db.push_accounts.get(did).unwrap().session_id, session_v2);

        // Delayed/stale logout from session_v1 arrives
        assert_eq!(db.sql_mark_auth_revoked_if_session(did, session_v1), 0);
        assert!(!db.is_auth_revoked(did));
        assert!(db.is_chat_poll_enrolled(did));
        assert_eq!(db.push_accounts.get(did).unwrap().session_id, session_v2);
    }

    #[test]
    fn test_upgrade_stale_cas_no_op_retains_polling_and_revocation_state() {
        let mut db = SqlDatabaseEngine::new();
        let did = "did:plc:alice";
        let session_v1 = "session-1";
        let session_v2 = "session-2";
        let session_v3 = "session-3";

        db.sql_activate_account_session(did, session_v1, "https://pds.alice.com");
        db.enroll_chat_poll(did, "pds.alice.com");

        // Upgrade session_v1 -> session_v2
        assert_eq!(
            db.sql_replace_account_session(did, session_v1, session_v2),
            1
        );
        assert_eq!(db.push_accounts.get(did).unwrap().session_id, session_v2);
        assert!(!db.is_auth_revoked(did));
        assert!(db.is_chat_poll_enrolled(did));

        // Stale CAS upgrade session_v1 -> session_v3 is a no-op
        assert_eq!(
            db.sql_replace_account_session(did, session_v1, session_v3),
            0
        );
        assert_eq!(db.push_accounts.get(did).unwrap().session_id, session_v2);
        assert!(db.is_chat_poll_enrolled(did));

        // Successful CAS upgrade session_v2 -> session_v3 retains chat poll state and clears revocation
        assert_eq!(
            db.sql_replace_account_session(did, session_v2, session_v3),
            1
        );
        assert_eq!(db.push_accounts.get(did).unwrap().session_id, session_v3);
        assert!(!db.is_auth_revoked(did));
        assert!(db.is_chat_poll_enrolled(did));
    }

    #[test]
    fn test_upsert_registration_transaction_stale_session_preserves_revocation() {
        let mut db = SqlDatabaseEngine::new();
        let did = "did:plc:alice";
        let session_v1 = "session-1";
        let session_v2 = "session-2";

        db.sql_activate_account_session(did, session_v2, "https://pds2.alice.com");
        // Revoke session_v2
        assert_eq!(db.sql_mark_auth_revoked_if_session(did, session_v2), 1);
        assert!(db.is_auth_revoked(did));

        // Registration from old session_v1 must not clear revocation on session_v2
        db.sql_upsert_registration_tx(
            did,
            session_v1,
            "https://stale-pds.alice.com",
            "token-123",
            "ios",
            "blue.catbird",
            "did:web:push.catbird.blue",
            false,
        );

        assert!(db.is_auth_revoked(did));
        assert_eq!(db.push_accounts.get(did).unwrap().session_id, session_v2);
        assert_eq!(
            db.push_accounts.get(did).unwrap().pds_url,
            "https://pds2.alice.com"
        );

        // Registration with active session_v2 clears revocation
        db.sql_upsert_registration_tx(
            did,
            session_v2,
            "https://pds2.alice.com",
            "token-123",
            "ios",
            "blue.catbird",
            "did:web:push.catbird.blue",
            false,
        );

        assert!(!db.is_auth_revoked(did));
        assert_eq!(db.push_accounts.get(did).unwrap().session_id, session_v2);
    }
    #[test]
    fn test_token_reassignment_deactivates_prior_owner_and_prevents_resumption() {
        let mut db = SqlDatabaseEngine::new();
        let alice_did = "did:plc:alice";
        let bob_did = "did:plc:bob";
        let token = "apns-token-shared-device";

        // Alice registers device token
        db.sql_activate_account_session(alice_did, "session-alice-1", "https://pds.alice.com");
        db.sql_upsert_registration_tx(
            alice_did,
            "session-alice-1",
            "https://pds.alice.com",
            token,
            "ios",
            "blue.catbird",
            "did:web:push.catbird.blue",
            false,
        );

        let alice_devices = db.sql_list_active_registrations(alice_did);
        assert_eq!(alice_devices.len(), 1);
        assert_eq!(alice_devices[0].device_token, token);

        // Device is reassigned/wiped and Bob registers the exact same token
        db.sql_activate_account_session(bob_did, "session-bob-1", "https://pds.bob.com");
        db.sql_upsert_registration_tx(
            bob_did,
            "session-bob-1",
            "https://pds.bob.com",
            token,
            "ios",
            "blue.catbird",
            "did:web:push.catbird.blue",
            false,
        );

        // Bob now actively owns the token
        let bob_devices = db.sql_list_active_registrations(bob_did);
        assert_eq!(bob_devices.len(), 1);
        assert_eq!(bob_devices[0].device_token, token);

        // Alice's active registration for that token MUST be deactivated immediately
        let alice_devices_after_reassignment = db.sql_list_active_registrations(alice_did);
        assert_eq!(alice_devices_after_reassignment.len(), 0);

        // Alice logs out (auth revoked)
        assert_eq!(
            db.sql_mark_auth_revoked_if_session(alice_did, "session-alice-1"),
            1
        );

        // Alice later re-authenticates (session 2)
        db.sql_activate_account_session(alice_did, "session-alice-2", "https://pds.alice.com");

        // Alice's active registrations MUST NOT revive or include the reassigned token!
        let alice_devices_after_reauth = db.sql_list_active_registrations(alice_did);
        assert_eq!(alice_devices_after_reauth.len(), 0);

        // Bob still has the active token
        let bob_devices_still_active = db.sql_list_active_registrations(bob_did);
        assert_eq!(bob_devices_still_active.len(), 1);
        assert_eq!(bob_devices_still_active[0].device_token, token);
    }

    #[test]
    fn test_bounded_device_registration_enforces_quota_and_eviction() {
        let mut db = SqlDatabaseEngine::new();
        let did = "did:plc:alice";
        db.sql_activate_account_session(did, "session-1", "https://pds.alice.com");

        // Register 12 distinct device tokens
        for i in 1..=12 {
            let token = format!("token-{i:02}");
            db.sql_upsert_registration_tx(
                did,
                "session-1",
                "https://pds.alice.com",
                &token,
                "ios",
                "blue.catbird",
                "did:web:push.catbird.blue",
                false,
            );
        }

        // Active registrations must be capped at MAX_ACTIVE_DEVICES_PER_ACCOUNT (10)
        let active_devices = db.sql_list_active_registrations(did);
        assert_eq!(active_devices.len(), 10);

        // The 2 oldest tokens (token-01, token-02) must have been evicted/deactivated
        let active_tokens: Vec<String> = active_devices.into_iter().map(|d| d.device_token).collect();
        assert!(!active_tokens.contains(&"token-01".to_string()));
        assert!(!active_tokens.contains(&"token-02".to_string()));
        assert!(active_tokens.contains(&"token-11".to_string()));
        assert!(active_tokens.contains(&"token-12".to_string()));
    }

    #[test]
    fn test_token_input_validation() {
        let valid = RegisterPushInput {
            service_did: "did:web:push.catbird.blue".to_string(),
            token: "valid-device-token-12345".to_string(),
            platform: "ios".to_string(),
            app_id: "blue.catbird".to_string(),
            age_restricted: Some(false),
        };
        assert!(valid.validate().is_ok());

        let empty_token = RegisterPushInput {
            token: "".to_string(),
            ..valid.clone()
        };
        assert!(empty_token.validate().is_err());

        let whitespace_token = RegisterPushInput {
            token: "   ".to_string(),
            ..valid.clone()
        };
        assert!(whitespace_token.validate().is_err());

        let oversized_token = RegisterPushInput {
            token: "a".repeat(513),
            ..valid.clone()
        };
        assert!(oversized_token.validate().is_err());

        let empty_platform = RegisterPushInput {
            platform: "".to_string(),
            ..valid.clone()
        };
        assert!(empty_platform.validate().is_err());

        let oversized_platform = RegisterPushInput {
            platform: "a".repeat(33),
            ..valid.clone()
        };
        assert!(oversized_platform.validate().is_err());

        let empty_app_id = RegisterPushInput {
            app_id: "".to_string(),
            ..valid.clone()
        };
        assert!(empty_app_id.validate().is_err());
    }
}
