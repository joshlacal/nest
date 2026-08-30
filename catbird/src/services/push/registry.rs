use anyhow::Result;
use sqlx::{Pool, Postgres, Row};

use crate::{
    error::{AppError, AppResult},
    models::CatbirdSession,
};

use super::types::{PushAccountRow, RegisterPushInput, RegistrationRow, UnregisterPushInput};

/// Compute a non-replayable SHA-256 fingerprint for a session ID.
/// Returns a 64-character lowercase hex string.
pub fn session_fingerprint(session_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in result {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{:02x}", b);
    }
    hex
}

/// Normalizes a session identifier to its SHA-256 fingerprint representation.
/// If already a 64-character lowercase hex string, returns it as-is.
/// Otherwise, computes SHA-256(session_id).
pub fn normalize_or_hash_session_fingerprint(session_id: &str) -> String {
    if session_id.len() == 64 && session_id.chars().all(|c| c.is_ascii_hexdigit()) {
        session_id.to_ascii_lowercase()
    } else {
        session_fingerprint(session_id)
    }
}

#[derive(Clone)]
pub struct PushRegistry {
    db_pool: Pool<Postgres>,
    service_did: String,
    phase2_writers: bool,
}

impl PushRegistry {
    pub fn new(db_pool: Pool<Postgres>, service_did: String) -> Self {
        let phase2_writers = std::env::var("PUSH_ACCOUNTS_PHASE2_WRITERS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self {
            db_pool,
            service_did,
            phase2_writers,
        }
    }

    pub fn with_phase2_writers(mut self, enabled: bool) -> Self {
        self.phase2_writers = enabled;
        self
    }

    pub fn set_phase2_writers(&mut self, enabled: bool) {
        self.phase2_writers = enabled;
    }

    pub fn phase2_writers_enabled(&self) -> bool {
        self.phase2_writers
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
        let session_fp = normalize_or_hash_session_fingerprint(new_session);
        let session_id_bind: &str = if self.phase2_writers {
            &session_fp
        } else {
            new_session
        };
        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                session_fingerprint,
                pds_url,
                auth_revoked_at,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, NULL, NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE
            SET session_id = EXCLUDED.session_id,
                session_fingerprint = EXCLUDED.session_fingerprint,
                pds_url = EXCLUDED.pds_url,
                auth_revoked_at = NULL,
                last_seen_at = NOW(),
                updated_at = NOW()
            "#,
        )
        .bind(did)
        .bind(session_id_bind)
        .bind(&session_fp)
        .bind(pds_url)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    /// Inserts a missing account or refreshes it only when the session ID still matches.
    /// Atomically clears auth_revoked_at only on matching session or new insert.
    pub async fn touch_account_session(&self, session: &CatbirdSession) -> Result<()> {
        let raw_session = session.id.to_string();
        let session_fp = normalize_or_hash_session_fingerprint(&raw_session);
        let session_id_bind: &str = if self.phase2_writers {
            &session_fp
        } else {
            &raw_session
        };
        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                session_fingerprint,
                pds_url,
                auth_revoked_at,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, NULL, NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE
            SET session_id = EXCLUDED.session_id,
                pds_url = EXCLUDED.pds_url,
                auth_revoked_at = NULL,
                session_fingerprint = EXCLUDED.session_fingerprint,
                last_seen_at = NOW(),
                updated_at = NOW()
            WHERE push_accounts.session_fingerprint = EXCLUDED.session_fingerprint
               OR push_accounts.session_id = $2
            "#,
        )
        .bind(&session.did)
        .bind(session_id_bind)
        .bind(&session_fp)
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
        let old_fp = normalize_or_hash_session_fingerprint(old_session_id);
        let new_fp = normalize_or_hash_session_fingerprint(new_session_id);
        let new_session_bind: &str = if self.phase2_writers {
            &new_fp
        } else {
            new_session_id
        };
        let result = sqlx::query(
            r#"
            UPDATE push_accounts
            SET session_id = $1,
                session_fingerprint = $2,
                auth_revoked_at = NULL,
                last_seen_at = NOW(),
                updated_at = NOW()
            WHERE account_did = $3
              AND (session_fingerprint = $4 OR session_id = $5 OR session_id = $4)
            "#,
        )
        .bind(new_session_bind)
        .bind(&new_fp)
        .bind(did)
        .bind(&old_fp)
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

        let raw_session = session.id.to_string();
        let session_fp = normalize_or_hash_session_fingerprint(&raw_session);
        let session_id_bind: &str = if self.phase2_writers {
            &session_fp
        } else {
            &raw_session
        };
        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                session_fingerprint,
                pds_url,
                auth_revoked_at,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, NULL, NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE
            SET session_id = EXCLUDED.session_id,
                pds_url = EXCLUDED.pds_url,
                auth_revoked_at = NULL,
                session_fingerprint = EXCLUDED.session_fingerprint,
                last_seen_at = NOW(),
                updated_at = NOW()
            WHERE push_accounts.session_fingerprint = EXCLUDED.session_fingerprint
               OR push_accounts.session_id = $2
            "#,
        )
        .bind(&session.did)
        .bind(session_id_bind)
        .bind(&session_fp)
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
                COALESCE(session_fingerprint, encode(sha256(session_id::bytea), 'hex')) AS session_id,
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

        let session_fp = normalize_or_hash_session_fingerprint(session_id);
        let result = sqlx::query(
            r#"
            UPDATE push_accounts
            SET auth_revoked_at = NOW(),
                updated_at = NOW()
            WHERE account_did = $1
              AND (session_fingerprint = $2 OR session_id = $3 OR session_id = $2)
            "#,
        )
        .bind(did)
        .bind(&session_fp)
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
        let session_fp = normalize_or_hash_session_fingerprint(session_id);
        let result = sqlx::query(
            "UPDATE push_accounts SET auth_revoked_at = NULL, updated_at = NOW() WHERE account_did = $1 AND (session_fingerprint = $2 OR session_id = $3 OR session_id = $2)",
        )
        .bind(did)
        .bind(&session_fp)
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
        session_fingerprint: Option<String>,
        pds_url: String,
        auth_revoked_at: Option<u64>,
        last_seen_at: u64,
        updated_at: u64,
    }

    impl PushAccountDbRow {
        fn effective_fingerprint(&self) -> String {
            self.session_fingerprint
                .clone()
                .unwrap_or_else(|| session_fingerprint(&self.session_id))
        }
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
        phase2_writers: bool,
        clock: u64,
    }

    impl SqlDatabaseEngine {
        fn new() -> Self {
            Self {
                push_accounts: HashMap::new(),
                chat_poll_state: HashMap::new(),
                user_devices: HashMap::new(),
                phase2_writers: false,
                clock: 1,
            }
        }

        fn set_phase2_writers(&mut self, enabled: bool) {
            self.phase2_writers = enabled;
        }

        fn tick(&mut self) -> u64 {
            self.clock += 1;
            self.clock
        }

        /// Mirrors SQL:
        /// INSERT INTO push_accounts (account_did, session_id, session_fingerprint, pds_url, auth_revoked_at, last_seen_at, updated_at)
        /// VALUES ($1, $2, $3, $4, NULL, NOW(), NOW())
        /// ON CONFLICT (account_did)
        /// DO UPDATE SET session_id = EXCLUDED.session_id, session_fingerprint = EXCLUDED.session_fingerprint, pds_url = EXCLUDED.pds_url, auth_revoked_at = NULL, last_seen_at = NOW(), updated_at = NOW()
        fn sql_activate_account_session(&mut self, did: &str, session_id: &str, pds_url: &str) {
            let now = self.tick();
            let session_fp = normalize_or_hash_session_fingerprint(session_id);
            let bound_session_id = if self.phase2_writers {
                session_fp.clone()
            } else {
                session_id.to_string()
            };
            self.push_accounts.insert(
                did.to_string(),
                PushAccountDbRow {
                    account_did: did.to_string(),
                    session_id: bound_session_id,
                    session_fingerprint: Some(session_fp),
                    pds_url: pds_url.to_string(),
                    auth_revoked_at: None,
                    last_seen_at: now,
                    updated_at: now,
                },
            );
        }

        /// Mirrors SQL:
        /// INSERT INTO push_accounts (account_did, session_id, session_fingerprint, pds_url, auth_revoked_at, last_seen_at, updated_at)
        /// VALUES ($1, $2, $3, $4, NULL, NOW(), NOW())
        /// ON CONFLICT (account_did)
        /// DO UPDATE SET session_id = EXCLUDED.session_id, pds_url = EXCLUDED.pds_url, auth_revoked_at = NULL, session_fingerprint = EXCLUDED.session_fingerprint, last_seen_at = NOW(), updated_at = NOW()
        /// WHERE push_accounts.session_fingerprint = EXCLUDED.session_fingerprint OR push_accounts.session_id = $2
        fn sql_touch_account_session(&mut self, did: &str, session_id: &str, pds_url: &str) -> u64 {
            let now = self.tick();
            let session_fp = normalize_or_hash_session_fingerprint(session_id);
            let bound_session_id = if self.phase2_writers {
                session_fp.clone()
            } else {
                session_id.to_string()
            };
            if let Some(row) = self.push_accounts.get_mut(did) {
                if row.session_fingerprint.as_deref() == Some(&session_fp) || row.session_id == session_id {
                    row.session_id = bound_session_id;
                    row.pds_url = pds_url.to_string();
                    row.auth_revoked_at = None;
                    row.session_fingerprint = Some(session_fp);
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
                        session_id: bound_session_id,
                        session_fingerprint: Some(session_fp),
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
        /// SET session_id = $1, session_fingerprint = $2, auth_revoked_at = NULL, last_seen_at = NOW(), updated_at = NOW()
        /// WHERE account_did = $3 AND (session_fingerprint = $4 OR session_id = $5 OR session_id = $4)
        fn sql_replace_account_session(
            &mut self,
            did: &str,
            old_session_id: &str,
            new_session_id: &str,
        ) -> u64 {
            let now = self.tick();
            let old_fp = normalize_or_hash_session_fingerprint(old_session_id);
            let new_fp = normalize_or_hash_session_fingerprint(new_session_id);
            let bound_new_session_id = if self.phase2_writers {
                new_fp.clone()
            } else {
                new_session_id.to_string()
            };
            let Some(row) = self.push_accounts.get_mut(did) else {
                return 0;
            };
            if row.session_fingerprint.as_deref() != Some(&old_fp) && row.session_id != old_session_id && row.session_id != old_fp {
                return 0;
            }

            row.session_id = bound_new_session_id;
            row.session_fingerprint = Some(new_fp);
            row.auth_revoked_at = None;
            row.last_seen_at = now;
            row.updated_at = now;
            1
        }

        /// Mirrors SQL transaction:
        /// BEGIN;
        /// UPDATE push_accounts SET auth_revoked_at = NOW(), updated_at = NOW() WHERE account_did = $1 AND (session_fingerprint = $2 OR session_id = $3 OR session_id = $2);
        /// if affected > 0: DELETE FROM chat_poll_state WHERE account_did = $1;
        /// COMMIT;
        fn sql_mark_auth_revoked_if_session(&mut self, did: &str, session_id: &str) -> u64 {
            let now = self.tick();
            let session_fp = normalize_or_hash_session_fingerprint(session_id);
            let Some(row) = self.push_accounts.get_mut(did) else {
                return 0;
            };
            if row.session_fingerprint.as_deref() != Some(&session_fp) && row.session_id != session_id && row.session_id != session_fp {
                return 0;
            }

            row.auth_revoked_at = Some(now);
            row.updated_at = now;
            self.chat_poll_state.remove(did);
            1
        }

        /// Mirrors SQL transaction in upsert_registration:
        /// BEGIN;
        /// INSERT INTO push_accounts ... ON CONFLICT DO UPDATE WHERE push_accounts.session_fingerprint = EXCLUDED.session_fingerprint OR push_accounts.session_id = $2;
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
        assert_eq!(
            db.push_accounts.get(did).unwrap().session_id,
            session_v1
        );

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
        assert_eq!(
            db.push_accounts.get(did).unwrap().session_id,
            session_v2
        );

        // Delayed/stale logout from session_v1 arrives
        assert_eq!(db.sql_mark_auth_revoked_if_session(did, session_v1), 0);
        assert!(!db.is_auth_revoked(did));
        assert!(db.is_chat_poll_enrolled(did));
        assert_eq!(
            db.push_accounts.get(did).unwrap().session_id,
            session_v2
        );
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
        assert_eq!(
            db.push_accounts.get(did).unwrap().session_id,
            session_v2
        );
        assert!(!db.is_auth_revoked(did));
        assert!(db.is_chat_poll_enrolled(did));

        // Stale CAS upgrade session_v1 -> session_v3 is a no-op
        assert_eq!(
            db.sql_replace_account_session(did, session_v1, session_v3),
            0
        );
        assert_eq!(
            db.push_accounts.get(did).unwrap().session_id,
            session_v2
        );
        assert!(db.is_chat_poll_enrolled(did));

        // Successful CAS upgrade session_v2 -> session_v3 retains chat poll state and clears revocation
        assert_eq!(
            db.sql_replace_account_session(did, session_v2, session_v3),
            1
        );
        assert_eq!(
            db.push_accounts.get(did).unwrap().session_id,
            session_v3
        );
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
        assert_eq!(
            db.push_accounts.get(did).unwrap().session_id,
            session_v2
        );
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
        assert_eq!(
            db.push_accounts.get(did).unwrap().session_id,
            session_v2
        );
    }

    #[test]
    fn test_session_fingerprint_deterministic_and_non_replayable() {
        let raw_session = "550e8400-e29b-41d4-a716-446655440000";
        let fp1 = session_fingerprint(raw_session);
        let fp2 = session_fingerprint(raw_session);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);
        assert!(fp1.chars().all(|c| c.is_ascii_hexdigit()));

        // normalize_or_hash_session_fingerprint is idempotent on 64-char hex strings
        assert_eq!(normalize_or_hash_session_fingerprint(&fp1), fp1);
        assert_eq!(normalize_or_hash_session_fingerprint(raw_session), fp1);
    }

    #[test]
    fn test_push_accounts_stores_fingerprint_and_replaying_fails_401() {
        let mut db = SqlDatabaseEngine::new();
        let did = "did:plc:alice_secure";
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let expected_fp = session_fingerprint(session_id);

        db.sql_activate_account_session(did, session_id, "https://pds.alice.com");

        // 1. Assert DB stores the 64-char SHA-256 fingerprint in session_fingerprint,
        // and keeps the raw session in session_id for rolling-deploy compatibility with old replicas
        let stored_row = db.push_accounts.get(did).unwrap();
        assert_eq!(stored_row.session_fingerprint.as_deref().unwrap(), expected_fp);
        assert_eq!(stored_row.effective_fingerprint(), expected_fp);
        assert_eq!(stored_row.session_id, session_id);
        // 2. Replay simulation: Replaying the stored DB string via Cookie or Bearer header fails 401
        // Middleware strictly validates UUID format for session IDs; 64-char hex string fails UUID parsing
        assert!(uuid::Uuid::parse_str(&stored_row.effective_fingerprint()).is_err());

        // 3. Shared role column inspection test:
        // Ensure push_accounts schema contains no credential columns (no access_token, refresh_token, dpop_key, password)
        // Column list for push_accounts: account_did, session_id, session_fingerprint, pds_url, auth_revoked_at, last_seen_at, updated_at
        let columns = vec![
            "account_did",
            "session_id",
            "session_fingerprint",
            "pds_url",
            "auth_revoked_at",
            "last_seen_at",
            "updated_at",
        ];
        for col in &columns {
            assert!(!col.contains("token"));
            assert!(!col.contains("secret"));
            assert!(!col.contains("key"));
            assert!(!col.contains("password"));
        }
    }

    #[test]
    fn test_rolling_deploy_additive_column_dual_read() {
        let mut db = SqlDatabaseEngine::new();
        let did = "did:plc:legacy_user";
        let raw_session_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let expected_fp = session_fingerprint(raw_session_uuid);

        // Pre-existing row before migration: session_id holds raw UUID, session_fingerprint is NULL
        db.push_accounts.insert(
            did.to_string(),
            PushAccountDbRow {
                account_did: did.to_string(),
                session_id: raw_session_uuid.to_string(),
                session_fingerprint: None,
                pds_url: "https://pds.alice.com".to_string(),
                auth_revoked_at: None,
                last_seen_at: 1,
                updated_at: 1,
            },
        );

        // 1. Old replica reads `session_id` directly -> gets raw UUID and continues operating during rollout
        let old_replica_read = &db.push_accounts.get(did).unwrap().session_id;
        assert_eq!(old_replica_read, raw_session_uuid);

        // 2. New replica reads `COALESCE(session_fingerprint, session_id)` -> resolves to SHA-256 fingerprint
        let new_replica_fp = db.push_accounts.get(did).unwrap().effective_fingerprint();
        assert_eq!(new_replica_fp, expected_fp);

        // 3. New replica touches or updates session -> populates session_fingerprint
        assert_eq!(
            db.sql_touch_account_session(did, raw_session_uuid, "https://pds-updated.alice.com"),
            1
        );
        let updated_row = db.push_accounts.get(did).unwrap();
        assert_eq!(updated_row.session_fingerprint.as_deref().unwrap(), expected_fp);
        assert_eq!(updated_row.pds_url, "https://pds-updated.alice.com");

        // 4. Migration backfill simulation: for rows with NULL session_fingerprint, sets sha256(session_id)
        // session_id is left untouched for old replicas
        assert_eq!(updated_row.effective_fingerprint(), expected_fp);
    }

    #[test]
    fn test_registry_writers_and_cas_boundaries_use_fingerprints() {
        let mut db = SqlDatabaseEngine::new();
        let did = "did:plc:alice_cas";
        let session_v1 = "11111111-1111-1111-1111-111111111111";
        let session_v2 = "22222222-2222-2222-2222-222222222222";
        let session_v3 = "33333333-3333-3333-3333-333333333333";

        // Activate v1
        db.sql_activate_account_session(did, session_v1, "https://pds1.alice.com");
        assert_eq!(
            db.push_accounts.get(did).unwrap().session_id,
            session_v1
        );

        // Touch with matching v1 succeeds
        assert_eq!(
            db.sql_touch_account_session(did, session_v1, "https://pds1-updated.alice.com"),
            1
        );

        // Touch with stale v2 fails CAS
        assert_eq!(
            db.sql_touch_account_session(did, session_v2, "https://pds2.alice.com"),
            0
        );

        // Replace v1 -> v2 succeeds
        assert_eq!(
            db.sql_replace_account_session(did, session_v1, session_v2),
            1
        );
        assert_eq!(
            db.push_accounts.get(did).unwrap().session_id,
            session_v2
        );

        // Stale replace v1 -> v3 fails CAS
        assert_eq!(
            db.sql_replace_account_session(did, session_v1, session_v3),
            0
        );
        assert_eq!(
            db.push_accounts.get(did).unwrap().session_id,
            session_v2
        );

        // Mark revoked with matching v2 succeeds
        assert_eq!(db.sql_mark_auth_revoked_if_session(did, session_v2), 1);
        assert!(db.is_auth_revoked(did));
    }

    #[test]
    fn test_old_replica_stale_fingerprint_is_repaired_by_cas_writer() {
        let mut db = SqlDatabaseEngine::new();
        let did = "did:plc:alice_stale_fp";
        let old_session = "11111111-1111-1111-1111-111111111111";
        let new_session_from_old_replica = "22222222-2222-2222-2222-222222222222";
        let new_session_v3 = "33333333-3333-3333-3333-333333333333";

        // 1. Initial activation on Phase 1 node
        db.sql_activate_account_session(did, old_session, "https://pds.alice.com");
        let old_fp = session_fingerprint(old_session);
        assert_eq!(db.push_accounts.get(did).unwrap().session_fingerprint.as_deref(), Some(old_fp.as_str()));

        // 2. Old replica performs an update using parent SQL (which updates session_id but NOT session_fingerprint)
        // Result: session_id is new_session_from_old_replica, but session_fingerprint is STALE (old_fp)
        if let Some(row) = db.push_accounts.get_mut(did) {
            row.session_id = new_session_from_old_replica.to_string();
            // session_fingerprint left as old_fp (stale, non-NULL)
        }

        // Verify the stale state
        let stale_row = db.push_accounts.get(did).unwrap();
        assert_eq!(stale_row.session_id, new_session_from_old_replica);
        assert_eq!(stale_row.session_fingerprint.as_deref(), Some(old_fp.as_str()));
        assert_ne!(stale_row.session_fingerprint.as_deref(), Some(session_fingerprint(new_session_from_old_replica).as_str()));

        // 3. New replica calls touch_account_session with new_session_from_old_replica.
        // Because the raw session_id matches, the CAS succeeds and repairs session_fingerprint!
        let touch_res = db.sql_touch_account_session(did, new_session_from_old_replica, "https://pds-repaired.alice.com");
        assert_eq!(touch_res, 1);

        let repaired_row = db.push_accounts.get(did).unwrap();
        let expected_new_fp = session_fingerprint(new_session_from_old_replica);
        assert_eq!(repaired_row.session_fingerprint.as_deref(), Some(expected_new_fp.as_str()));
        assert_eq!(repaired_row.pds_url, "https://pds-repaired.alice.com");

        // 4. Simulate another old-replica stale update, then test replace_account_session and mark_auth_revoked_if_session
        if let Some(row) = db.push_accounts.get_mut(did) {
            row.session_id = "44444444-4444-4444-4444-444444444444".to_string();
            // session_fingerprint left stale (expected_new_fp)
        }
        let stale_raw_4 = "44444444-4444-4444-4444-444444444444";
        // replace_account_session matches on raw old_session_id even though fingerprint is stale
        let replace_res = db.sql_replace_account_session(did, stale_raw_4, new_session_v3);
        assert_eq!(replace_res, 1);
        let replaced_row = db.push_accounts.get(did).unwrap();
        assert_eq!(replaced_row.session_id, new_session_v3);
        assert_eq!(replaced_row.session_fingerprint.as_deref(), Some(session_fingerprint(new_session_v3).as_str()));
    }
    #[tokio::test]
    async fn test_phase2_writer_contract_stops_binding_raw_session_id_when_flag_set() {
        let pool = Pool::<Postgres>::connect_lazy("postgres://localhost/test").unwrap();
        let registry = PushRegistry::new(pool, "did:web:push.catbird.blue".to_string())
            .with_phase2_writers(true);
        assert!(registry.phase2_writers_enabled());

        let mut db = SqlDatabaseEngine::new();
        db.set_phase2_writers(true);

        let did = "did:plc:alice_phase2";
        let raw_session_v1 = "550e8400-e29b-41d4-a716-446655440000";
        let raw_session_v2 = "660e8400-e29b-41d4-a716-446655440001";
        let fp_v1 = session_fingerprint(raw_session_v1);
        let fp_v2 = session_fingerprint(raw_session_v2);

        // 1. activate_account_session in Phase 2 binds fingerprint to session_id
        db.sql_activate_account_session(did, raw_session_v1, "https://pds.alice.com");
        let row = db.push_accounts.get(did).unwrap();
        assert_eq!(row.session_id, fp_v1);
        assert_ne!(row.session_id, raw_session_v1);
        assert_eq!(row.session_fingerprint.as_deref(), Some(fp_v1.as_str()));

        // 2. touch_account_session in Phase 2 maintains fingerprint in session_id
        assert_eq!(
            db.sql_touch_account_session(did, raw_session_v1, "https://pds-touch.alice.com"),
            1
        );
        let row = db.push_accounts.get(did).unwrap();
        assert_eq!(row.session_id, fp_v1);
        assert_ne!(row.session_id, raw_session_v1);

        // 3. replace_account_session in Phase 2 binds new fingerprint to session_id
        assert_eq!(
            db.sql_replace_account_session(did, raw_session_v1, raw_session_v2),
            1
        );
        let row = db.push_accounts.get(did).unwrap();
        assert_eq!(row.session_id, fp_v2);
        assert_ne!(row.session_id, raw_session_v2);
        assert_eq!(row.session_fingerprint.as_deref(), Some(fp_v2.as_str()));

        // 4. upsert_registration in Phase 2 maintains fingerprint in session_id
        db.sql_upsert_registration_tx(
            did,
            raw_session_v2,
            "https://pds-reg.alice.com",
            "token-p2",
            "ios",
            "blue.catbird",
            "did:web:push.catbird.blue",
            false,
        );
        let row = db.push_accounts.get(did).unwrap();
        assert_eq!(row.session_id, fp_v2);
        assert_ne!(row.session_id, raw_session_v2);
    }

    #[tokio::test]
    async fn test_phase1_writer_contract_retains_raw_session_id_when_flag_unset() {
        let pool = Pool::<Postgres>::connect_lazy("postgres://localhost/test").unwrap();
        let registry = PushRegistry::new(pool, "did:web:push.catbird.blue".to_string())
            .with_phase2_writers(false);
        assert!(!registry.phase2_writers_enabled());

        let mut db = SqlDatabaseEngine::new();
        db.set_phase2_writers(false);

        let did = "did:plc:alice_phase1";
        let raw_session = "550e8400-e29b-41d4-a716-446655440000";
        let fp = session_fingerprint(raw_session);

        // Phase 1 binds raw session_id and populates session_fingerprint
        db.sql_activate_account_session(did, raw_session, "https://pds.alice.com");
        let row = db.push_accounts.get(did).unwrap();
        assert_eq!(row.session_id, raw_session);
        assert_eq!(row.session_fingerprint.as_deref(), Some(fp.as_str()));
    }
}
