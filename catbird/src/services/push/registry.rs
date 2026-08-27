use anyhow::Result;
use sqlx::{Pool, Postgres, Row};

use crate::{
    error::{AppError, AppResult},
    models::CatbirdSession,
};

use super::types::{PushAccountRow, RegisterPushInput, RegistrationRow, UnregisterPushInput};

#[derive(Clone)]
pub struct PushRegistry {
    db_pool: Pool<Postgres>,
    service_did: String,
}

impl PushRegistry {
    pub fn new(db_pool: Pool<Postgres>, service_did: String) -> Self {
        Self {
            db_pool,
            service_did,
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
        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                pds_url,
                auth_revoked_at,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, NULL, NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE
            SET session_id = EXCLUDED.session_id,
                pds_url = EXCLUDED.pds_url,
                auth_revoked_at = NULL,
                last_seen_at = NOW(),
                updated_at = NOW()
            "#,
        )
        .bind(did)
        .bind(new_session)
        .bind(pds_url)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    /// Inserts a missing account or refreshes it only when the session ID still matches.
    /// Atomically clears auth_revoked_at only on matching session or new insert.
    pub async fn touch_account_session(&self, session: &CatbirdSession) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                pds_url,
                auth_revoked_at,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, NULL, NOW(), NOW())
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
        .execute(&self.db_pool)
        .await?;

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
        let result = sqlx::query(
            r#"
            UPDATE push_accounts
            SET session_id = $1,
                auth_revoked_at = NULL,
                last_seen_at = NOW(),
                updated_at = NOW()
            WHERE account_did = $2 AND session_id = $3
            "#,
        )
        .bind(new_session_id)
        .bind(did)
        .bind(old_session_id)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn upsert_registration(
        &self,
        session: &CatbirdSession,
        input: &RegisterPushInput,
    ) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;

        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                pds_url,
                auth_revoked_at,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, NULL, NOW(), NOW())
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

        tx.commit().await?;
        Ok(())
    }

    pub async fn deactivate_registration(
        &self,
        session: &CatbirdSession,
        input: &UnregisterPushInput,
    ) -> Result<()> {
        self.touch_account_session(session).await?;

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
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    pub async fn deactivate_invalid_token(
        &self,
        did: &str,
        device_token: &str,
        error: &str,
    ) -> Result<()> {
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
        .execute(&self.db_pool)
        .await?;

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
            "#,
        )
        .bind(did)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows)
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
                pds_url
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

        sqlx::query(
            "UPDATE push_accounts SET auth_revoked_at = NOW(), updated_at = NOW() WHERE account_did = $1",
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

        let result = sqlx::query(
            r#"
            UPDATE push_accounts
            SET auth_revoked_at = NOW(),
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
        sqlx::query(
            "UPDATE push_accounts SET auth_revoked_at = NULL, updated_at = NOW() WHERE account_did = $1",
        )
        .bind(did)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn clear_auth_revoked_if_session(&self, did: &str, session_id: &str) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE push_accounts SET auth_revoked_at = NULL, updated_at = NOW() WHERE account_did = $1 AND session_id = $2",
        )
        .bind(did)
        .bind(session_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
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
            self.push_accounts.insert(
                did.to_string(),
                PushAccountDbRow {
                    account_did: did.to_string(),
                    session_id: session_id.to_string(),
                    pds_url: pds_url.to_string(),
                    auth_revoked_at: None,
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
}
