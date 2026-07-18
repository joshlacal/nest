use anyhow::Result;
use sqlx::{Pool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    models::CatbirdSession,
};

use super::types::{PushAccountRow, RegisterPushInput, RegistrationRow, UnregisterPushInput};

const MAX_REGISTRATION_SLOTS_PER_DID: i64 = 8;
const MAX_DEVICE_TOKEN_BYTES: usize = 512;
const MAX_PLATFORM_BYTES: usize = 16;
const MAX_APP_ID_BYTES: usize = 255;
const MAX_SERVICE_DID_BYTES: usize = 512;

async fn acquire_registration_did_lock(
    transaction: &mut Transaction<'_, Postgres>,
    did: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(did)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn acquire_registration_token_lock(
    transaction: &mut Transaction<'_, Postgres>,
    device_token: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1))")
        .bind(device_token)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn bad_request(message: impl Into<String>) -> AppError {
    AppError::BadRequest(message.into())
}

fn validate_device_token(value: &str) -> AppResult<()> {
    if value.is_empty() || value.len() > MAX_DEVICE_TOKEN_BYTES {
        return Err(bad_request(format!(
            "device token must be between 1 and {MAX_DEVICE_TOKEN_BYTES} bytes"
        )));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'~' | b'-')
    }) {
        return Err(bad_request("device token contains unsupported characters"));
    }
    Ok(())
}

fn validate_platform(value: &str) -> AppResult<()> {
    if value.len() > MAX_PLATFORM_BYTES || value != "ios" {
        return Err(bad_request("platform must be the canonical value ios"));
    }
    Ok(())
}

fn validate_app_id(value: &str) -> AppResult<()> {
    if value.is_empty() || value.len() > MAX_APP_ID_BYTES {
        return Err(bad_request(format!(
            "appId must be between 1 and {MAX_APP_ID_BYTES} bytes"
        )));
    }

    let is_valid = value.split('.').all(|segment| {
        let mut bytes = segment.bytes();
        let Some(first) = bytes.next() else {
            return false;
        };
        if !first.is_ascii_alphanumeric() {
            return false;
        }

        let mut last = first;
        for byte in bytes {
            if !(byte.is_ascii_alphanumeric() || byte == b'-') {
                return false;
            }
            last = byte;
        }
        last.is_ascii_alphanumeric()
    });

    if !is_valid {
        return Err(bad_request(
            "appId must contain dot-separated alphanumeric or hyphenated segments",
        ));
    }
    Ok(())
}

fn validate_service_did_shape(value: &str) -> AppResult<()> {
    if value.is_empty() || value.len() > MAX_SERVICE_DID_BYTES {
        return Err(bad_request(format!(
            "serviceDid must be between 1 and {MAX_SERVICE_DID_BYTES} bytes"
        )));
    }
    if !value.starts_with("did:") || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(bad_request("serviceDid must be a printable DID"));
    }
    Ok(())
}

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
        validate_service_did_shape(value)?;
        if value == self.service_did {
            Ok(())
        } else {
            Err(bad_request(
                "serviceDid does not match the configured push service",
            ))
        }
    }

    pub fn validate_register_input(&self, input: &RegisterPushInput) -> AppResult<()> {
        self.validate_service_did(&input.service_did)?;
        validate_device_token(&input.token)?;
        validate_platform(&input.platform)?;
        validate_app_id(&input.app_id)
    }

    pub fn validate_unregister_input(&self, input: &UnregisterPushInput) -> AppResult<()> {
        self.validate_service_did(&input.service_did)?;
        validate_device_token(&input.token)?;
        validate_platform(&input.platform)?;
        validate_app_id(&input.app_id)
    }

    pub async fn touch_account_session(&self, session: &CatbirdSession) -> Result<()> {
        let mut transaction = self.db_pool.begin().await?;
        acquire_registration_did_lock(&mut transaction, &session.did).await?;
        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                pds_url,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE
            SET auth_revoked_at = CASE
                    WHEN push_accounts.session_id = EXCLUDED.session_id
                    THEN push_accounts.auth_revoked_at
                    ELSE NULL
                END,
                session_id = EXCLUDED.session_id,
                pds_url = EXCLUDED.pds_url,
                last_seen_at = NOW(),
                updated_at = NOW()
            "#,
        )
        .bind(&session.did)
        .bind(session.id.to_string())
        .bind(&session.pds_url)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(())
    }

    pub async fn upsert_registration(
        &self,
        session: &CatbirdSession,
        input: &RegisterPushInput,
    ) -> Result<()> {
        self.validate_register_input(input)?;
        let mut transaction = self.db_pool.begin().await?;

        // A device token has one globally active DID owner. Acquire the token
        // lock before the per-DID slot lock in every caller that takes both so
        // cross-account registration and unregister operations cannot race.
        acquire_registration_token_lock(&mut transaction, &input.token).await?;

        // Registrations for one DID share a fixed-size slot pool. Serialize all
        // slot selection so concurrent requests cannot independently observe
        // free capacity and exceed the per-account bound.
        acquire_registration_did_lock(&mut transaction, &session.did).await?;

        let transferred = sqlx::query(
            r#"
            UPDATE user_devices
            SET is_active = FALSE,
                apns_environment = NULL,
                last_error = 'device_token_transferred',
                updated_at = clock_timestamp()
            WHERE device_token = $1
              AND did <> $2
              AND is_active = TRUE
            "#,
        )
        .bind(&input.token)
        .bind(&session.did)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            > 0;

        sqlx::query(
            r#"
            INSERT INTO push_accounts (
                account_did,
                session_id,
                pds_url,
                last_seen_at,
                updated_at
            )
            VALUES ($1, $2, $3, clock_timestamp(), clock_timestamp())
            ON CONFLICT (account_did)
            DO UPDATE
            SET auth_revoked_at = CASE
                    WHEN push_accounts.session_id = EXCLUDED.session_id
                    THEN push_accounts.auth_revoked_at
                    ELSE NULL
                END,
                session_id = EXCLUDED.session_id,
                pds_url = EXCLUDED.pds_url,
                last_seen_at = clock_timestamp(),
                updated_at = clock_timestamp()
            "#,
        )
        .bind(&session.did)
        .bind(session.id.to_string())
        .bind(&session.pds_url)
        .execute(&mut *transaction)
        .await?;

        let existing = sqlx::query_scalar::<_, Uuid>(
            r#"
            UPDATE user_devices
            SET platform = $3,
                app_id = $4,
                service_did = $5,
                age_restricted = $6,
                is_active = TRUE,
                last_registered_at = clock_timestamp(),
                last_invalidated_at = NULL,
                last_error = NULL,
                apns_environment = CASE
                    WHEN $7 THEN NULL
                    ELSE apns_environment
                END,
                updated_at = clock_timestamp()
            WHERE did = $1
              AND device_token = $2
            RETURNING id
            "#,
        )
        .bind(&session.did)
        .bind(&input.token)
        .bind(&input.platform)
        .bind(&input.app_id)
        .bind(&input.service_did)
        .bind(input.age_restricted.unwrap_or(false))
        .bind(transferred)
        .fetch_optional(&mut *transaction)
        .await?;

        if existing.is_none() {
            let reused = sqlx::query_scalar::<_, Uuid>(
                r#"
                UPDATE user_devices
                SET device_token = $2,
                    platform = $3,
                    app_id = $4,
                    service_did = $5,
                    age_restricted = $6,
                    is_active = TRUE,
                    last_registered_at = clock_timestamp(),
                    last_invalidated_at = NULL,
                    last_error = NULL,
                    apns_environment = NULL,
                    updated_at = clock_timestamp()
                WHERE id = (
                    SELECT id
                    FROM user_devices
                    WHERE did = $1
                      AND is_active = FALSE
                    ORDER BY last_registered_at ASC, id ASC
                    LIMIT 1
                )
                RETURNING id
                "#,
            )
            .bind(&session.did)
            .bind(&input.token)
            .bind(&input.platform)
            .bind(&input.app_id)
            .bind(&input.service_did)
            .bind(input.age_restricted.unwrap_or(false))
            .fetch_optional(&mut *transaction)
            .await?;

            if reused.is_none() {
                let total = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM user_devices WHERE did = $1",
                )
                .bind(&session.did)
                .fetch_one(&mut *transaction)
                .await?;

                if total < MAX_REGISTRATION_SLOTS_PER_DID {
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
                        VALUES (
                            $1, $2, $3, $4, $5, $6, TRUE,
                            clock_timestamp(), NULL, clock_timestamp()
                        )
                        "#,
                    )
                    .bind(&session.did)
                    .bind(&input.token)
                    .bind(&input.platform)
                    .bind(&input.app_id)
                    .bind(&input.service_did)
                    .bind(input.age_restricted.unwrap_or(false))
                    .execute(&mut *transaction)
                    .await?;
                } else {
                    let replaced = sqlx::query_scalar::<_, Uuid>(
                        r#"
                        UPDATE user_devices
                        SET device_token = $2,
                            platform = $3,
                            app_id = $4,
                            service_did = $5,
                            age_restricted = $6,
                            is_active = TRUE,
                            last_registered_at = clock_timestamp(),
                            last_invalidated_at = NULL,
                            last_error = NULL,
                            apns_environment = NULL,
                            updated_at = clock_timestamp()
                        WHERE id = (
                            SELECT id
                            FROM user_devices
                            WHERE did = $1
                              AND is_active = TRUE
                            ORDER BY last_registered_at ASC, id ASC
                            LIMIT 1
                        )
                        RETURNING id
                        "#,
                    )
                    .bind(&session.did)
                    .bind(&input.token)
                    .bind(&input.platform)
                    .bind(&input.app_id)
                    .bind(&input.service_did)
                    .bind(input.age_restricted.unwrap_or(false))
                    .fetch_optional(&mut *transaction)
                    .await?;

                    anyhow::ensure!(
                        replaced.is_some(),
                        "registration slot accounting found no reusable active slot"
                    );
                }
            }
        }

        transaction.commit().await?;
        Ok(())
    }

    pub async fn deactivate_registration(
        &self,
        session: &CatbirdSession,
        input: &UnregisterPushInput,
    ) -> Result<()> {
        self.validate_unregister_input(input)?;
        self.touch_account_session(session).await?;

        let mut transaction = self.db_pool.begin().await?;
        acquire_registration_token_lock(&mut transaction, &input.token).await?;
        acquire_registration_did_lock(&mut transaction, &session.did).await?;

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
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(())
    }

    pub async fn deactivate_invalid_token(
        &self,
        did: &str,
        device_token: &str,
        error: &str,
    ) -> Result<()> {
        let mut transaction = self.db_pool.begin().await?;
        acquire_registration_token_lock(&mut transaction, device_token).await?;
        acquire_registration_did_lock(&mut transaction, did).await?;

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
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
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
                pds_url,
                last_actor_sync_at,
                last_list_sync_at
            FROM push_accounts
            WHERE account_did = $1
            "#,
        )
        .bind(did)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row)
    }

    pub async fn mark_actor_sync(&self, did: &str) -> Result<()> {
        sqlx::query(
            "UPDATE push_accounts SET last_actor_sync_at = NOW(), updated_at = NOW() WHERE account_did = $1",
        )
        .bind(did)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn mark_list_sync(&self, did: &str) -> Result<()> {
        sqlx::query(
            "UPDATE push_accounts SET last_list_sync_at = NOW(), updated_at = NOW() WHERE account_did = $1",
        )
        .bind(did)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn mark_auth_revoked(&self, did: &str, session_id: &str) -> Result<()> {
        let mut transaction = self.db_pool.begin().await?;
        // Serialize the logout fence with registration updates for this DID.
        // A registration that already owns the account lock must commit first
        // so this revocation marker is the last durable state transition.
        acquire_registration_did_lock(&mut transaction, did).await?;
        sqlx::query(
            r#"
            UPDATE push_accounts
            SET auth_revoked_at = NOW(), updated_at = NOW()
            WHERE account_did = $1
              AND session_id = $2
            "#,
        )
        .bind(did)
        .bind(session_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
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
    use std::{collections::HashSet, sync::Arc, time::Duration as StdDuration};

    use chrono::{Duration, Utc};
    use sqlx::{postgres::PgPoolOptions, Connection, PgConnection, PgPool};
    use tokio::sync::Barrier;
    use tokio::time::{sleep, timeout};
    use uuid::Uuid;

    use super::*;

    const TEST_SERVICE_DID: &str = "did:web:api.catbird.blue";

    async fn live_pool() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored Postgres suite");
        PgPoolOptions::new()
            .max_connections(20)
            .connect(&database_url)
            .await
            .expect("connect test Postgres")
    }

    fn session(did: &str) -> CatbirdSession {
        let now = Utc::now();
        CatbirdSession {
            id: Uuid::new_v4(),
            did: did.to_owned(),
            handle: "registration-cap.test".to_owned(),
            pds_url: "https://registration-cap.test".to_owned(),
            access_token: "test-access-token".to_owned(),
            refresh_token: "test-refresh-token".to_owned(),
            access_token_expires_at: now + Duration::hours(1),
            created_at: now,
            last_used_at: now,
        }
    }

    fn registration(token: impl Into<String>) -> RegisterPushInput {
        RegisterPushInput {
            service_did: TEST_SERVICE_DID.to_owned(),
            token: token.into(),
            platform: "ios".to_owned(),
            app_id: "blue.catbird".to_owned(),
            age_restricted: Some(false),
        }
    }

    fn unregistration(token: impl Into<String>) -> UnregisterPushInput {
        UnregisterPushInput {
            service_did: TEST_SERVICE_DID.to_owned(),
            token: token.into(),
            platform: "ios".to_owned(),
            app_id: "blue.catbird".to_owned(),
        }
    }

    fn validation_registry() -> PushRegistry {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://validation.invalid/postgres")
            .expect("construct lazy validation pool");
        PushRegistry::new(pool, TEST_SERVICE_DID.to_owned())
    }

    #[tokio::test]
    async fn registration_fields_accept_bounded_canonical_values() {
        let registry = validation_registry();
        for token in [
            "a",
            "0123456789abcdef0123456789ABCDEF",
            "opaque-token_1.2:3~4",
        ] {
            assert!(registry
                .validate_register_input(&registration(token))
                .is_ok());
            assert!(registry
                .validate_unregister_input(&unregistration(token))
                .is_ok());
        }

        let mut max_token = registration("a".repeat(MAX_DEVICE_TOKEN_BYTES));
        max_token.app_id = "Com.Example-App1".to_owned();
        assert!(registry.validate_register_input(&max_token).is_ok());
    }

    #[tokio::test]
    async fn registration_fields_reject_oversized_or_unsafe_values() {
        let registry = validation_registry();

        let mut input = registration("");
        assert!(matches!(
            registry.validate_register_input(&input),
            Err(AppError::BadRequest(_))
        ));

        input.token = "a".repeat(MAX_DEVICE_TOKEN_BYTES + 1);
        assert!(matches!(
            registry.validate_register_input(&input),
            Err(AppError::BadRequest(_))
        ));

        for token in ["token with space", "token/control\n", "token/segment"] {
            input = registration(token);
            assert!(matches!(
                registry.validate_register_input(&input),
                Err(AppError::BadRequest(_))
            ));
        }

        for platform in ["", "iOS", "android", "ios-with-suffix"] {
            input = registration("valid-token");
            input.platform = platform.to_owned();
            assert!(matches!(
                registry.validate_register_input(&input),
                Err(AppError::BadRequest(_))
            ));
        }

        for app_id in [
            "",
            ".blue.catbird",
            "blue.catbird.",
            "blue..catbird",
            "blue_catbird",
            "blue.-catbird",
            "blue.catbird-",
        ] {
            input = registration("valid-token");
            input.app_id = app_id.to_owned();
            assert!(matches!(
                registry.validate_register_input(&input),
                Err(AppError::BadRequest(_))
            ));
        }

        input = registration("valid-token");
        input.app_id = "a".repeat(MAX_APP_ID_BYTES + 1);
        assert!(matches!(
            registry.validate_register_input(&input),
            Err(AppError::BadRequest(_))
        ));

        input = registration("valid-token");
        input.service_did = "did:web:other.example".to_owned();
        assert!(matches!(
            registry.validate_register_input(&input),
            Err(AppError::BadRequest(_))
        ));

        input.service_did = format!("did:web:{}", "a".repeat(MAX_SERVICE_DID_BYTES));
        assert!(matches!(
            registry.validate_register_input(&input),
            Err(AppError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn invalid_registration_and_unregistration_fail_before_database_checkout() {
        let registry = validation_registry();
        let session = session("did:plc:validation-before-db");

        let mut invalid_registration = registration("valid-token");
        invalid_registration.app_id = "not/a/bundle/id".to_owned();
        let register_error = registry
            .upsert_registration(&session, &invalid_registration)
            .await
            .expect_err("invalid registration must fail");
        assert!(register_error.downcast_ref::<AppError>().is_some());

        let mut invalid_unregistration = unregistration("valid-token");
        invalid_unregistration.platform = "android".to_owned();
        let unregister_error = registry
            .deactivate_registration(&session, &invalid_unregistration)
            .await
            .expect_err("invalid unregistration must fail");
        assert!(unregister_error.downcast_ref::<AppError>().is_some());
    }

    async fn rows(pool: &PgPool, did: &str) -> Vec<(Uuid, String, bool)> {
        sqlx::query_as::<_, (Uuid, String, bool)>(
            r#"
            SELECT id, device_token, is_active
            FROM user_devices
            WHERE did = $1
            ORDER BY last_registered_at ASC, id ASC
            "#,
        )
        .bind(did)
        .fetch_all(pool)
        .await
        .expect("load registration fixture")
    }

    async fn cleanup(pool: &PgPool, did: &str) {
        sqlx::query("DELETE FROM user_devices WHERE did = $1")
            .bind(did)
            .execute(pool)
            .await
            .expect("clean registration fixture");
        sqlx::query("DELETE FROM push_accounts WHERE account_did = $1")
            .bind(did)
            .execute(pool)
            .await
            .expect("clean push account fixture");
    }

    async fn register_tokens(registry: &PushRegistry, session: &CatbirdSession, count: usize) {
        for index in 0..count {
            registry
                .upsert_registration(session, &registration(format!("token-{index:03}")))
                .await
                .expect("register token");
        }
    }

    async fn make_registration_order_deterministic(pool: &PgPool, did: &str) {
        sqlx::query(
            r#"
            UPDATE user_devices
            SET last_registered_at = TIMESTAMPTZ '2026-01-01 00:00:00+00'
                + (substring(device_token from '[0-9]+')::int * INTERVAL '1 second')
            WHERE did = $1
            "#,
        )
        .bind(did)
        .execute(pool)
        .await
        .expect("make replacement order deterministic");
    }

    async fn wait_until_did_advisory_lock_is_held(pool: &PgPool, did: &str) {
        let mut connection = pool.acquire().await.expect("acquire advisory probe");
        for _ in 0..200 {
            let acquired = sqlx::query_scalar::<_, bool>(
                "SELECT pg_try_advisory_lock(hashtextextended($1, 0))",
            )
            .bind(did)
            .fetch_one(&mut *connection)
            .await
            .expect("probe DID advisory lock");
            if !acquired {
                return;
            }
            let released =
                sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
                    .bind(did)
                    .fetch_one(&mut *connection)
                    .await
                    .expect("release DID advisory probe");
            assert!(released);
            sleep(StdDuration::from_millis(2)).await;
        }
        panic!("timed out waiting for registration transaction advisory lock");
    }

    #[derive(Clone, Copy)]
    enum DeactivationKind {
        Unregister,
        ApnsInvalidation,
    }

    async fn replacement_race_with_deactivation(kind: DeactivationKind) {
        let pool = live_pool().await;
        let label = match kind {
            DeactivationKind::Unregister => "unregister",
            DeactivationKind::ApnsInvalidation => "apns-invalidation",
        };
        let did = format!("did:plc:registration-cap-{label}-race-{}", Uuid::new_v4());
        let session = session(&did);
        let registry = PushRegistry::new(pool.clone(), TEST_SERVICE_DID.to_owned());
        register_tokens(&registry, &session, 8).await;
        make_registration_order_deterministic(&pool, &did).await;

        // Hold the deterministic LRU row so token nine reaches the replacement
        // UPDATE while still owning the DID advisory transaction lock.
        let mut replacement_blocker = pool.begin().await.expect("begin replacement blocker");
        sqlx::query(
            "SELECT id FROM user_devices WHERE did = $1 AND device_token = 'token-000' FOR UPDATE",
        )
        .bind(&did)
        .fetch_one(&mut *replacement_blocker)
        .await
        .expect("lock deterministic LRU row");

        let registration_registry = registry.clone();
        let registration_session = session.clone();
        let registration_task = tokio::spawn(async move {
            registration_registry
                .upsert_registration(&registration_session, &registration("token-009"))
                .await
        });
        wait_until_did_advisory_lock_is_held(&pool, &did).await;

        let deactivation_registry = registry.clone();
        let deactivation_session = session.clone();
        let deactivation_did = did.clone();
        let mut deactivation_task = tokio::spawn(async move {
            match kind {
                DeactivationKind::Unregister => {
                    deactivation_registry
                        .deactivate_registration(
                            &deactivation_session,
                            &unregistration("token-007"),
                        )
                        .await
                }
                DeactivationKind::ApnsInvalidation => {
                    deactivation_registry
                        .deactivate_invalid_token(&deactivation_did, "token-007", "BadDeviceToken")
                        .await
                }
            }
        });

        let deactivated_before_registration =
            timeout(StdDuration::from_millis(75), &mut deactivation_task).await;
        let bypassed_did_lock = deactivated_before_registration.is_ok();
        replacement_blocker
            .commit()
            .await
            .expect("release deterministic LRU row");
        registration_task
            .await
            .expect("registration task did not panic")
            .expect("token-nine registration commits");
        match deactivated_before_registration {
            Ok(result) => result
                .expect("deactivation task did not panic")
                .expect("deactivation commits"),
            Err(_) => deactivation_task
                .await
                .expect("deactivation task did not panic")
                .expect("deactivation commits"),
        }

        let retained = rows(&pool, &did).await;
        let active = retained
            .iter()
            .filter_map(|(_, token, is_active)| is_active.then_some(token.as_str()))
            .collect::<HashSet<_>>();
        let expected_active = [
            "token-001",
            "token-002",
            "token-003",
            "token-004",
            "token-005",
            "token-006",
            "token-009",
        ]
        .into_iter()
        .collect::<HashSet<_>>();
        assert_eq!(retained.len(), 8);
        assert_eq!(active, expected_active);
        assert!(retained
            .iter()
            .any(|(_, token, is_active)| token == "token-007" && !is_active));
        assert!(!retained.iter().any(|(_, token, _)| token == "token-000"));

        cleanup(&pool, &did).await;
        assert!(
            !bypassed_did_lock,
            "{label} bypassed the registration transaction's DID advisory lock"
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_unregister_and_invalidation_share_the_registration_did_lock() {
        let pool = live_pool().await;
        let did = format!("did:plc:registration-cap-lock-{}", Uuid::new_v4());
        let session = session(&did);
        let registry = PushRegistry::new(pool.clone(), TEST_SERVICE_DID.to_owned());
        register_tokens(&registry, &session, 2).await;

        let mut lock_holder = pool.begin().await.expect("begin DID lock holder");
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&did)
            .execute(&mut *lock_holder)
            .await
            .expect("hold registration DID lock");

        let unregister_registry = registry.clone();
        let unregister_session = session.clone();
        let mut unregister_task = tokio::spawn(async move {
            unregister_registry
                .deactivate_registration(&unregister_session, &unregistration("token-000"))
                .await
        });
        let invalidation_registry = registry.clone();
        let invalidation_did = did.clone();
        let mut invalidation_task = tokio::spawn(async move {
            invalidation_registry
                .deactivate_invalid_token(&invalidation_did, "token-001", "BadDeviceToken")
                .await
        });

        let unregister_before_unlock =
            timeout(StdDuration::from_millis(75), &mut unregister_task).await;
        let invalidation_before_unlock =
            timeout(StdDuration::from_millis(75), &mut invalidation_task).await;
        let unregister_bypassed_lock = unregister_before_unlock.is_ok();
        let invalidation_bypassed_lock = invalidation_before_unlock.is_ok();
        lock_holder.commit().await.expect("release DID lock holder");

        match unregister_before_unlock {
            Ok(result) => result
                .expect("unregister task did not panic")
                .expect("unregister succeeds"),
            Err(_) => unregister_task
                .await
                .expect("unregister task did not panic")
                .expect("unregister succeeds"),
        }
        match invalidation_before_unlock {
            Ok(result) => result
                .expect("invalidation task did not panic")
                .expect("invalidation succeeds"),
            Err(_) => invalidation_task
                .await
                .expect("invalidation task did not panic")
                .expect("invalidation succeeds"),
        }

        cleanup(&pool, &did).await;
        assert!(!unregister_bypassed_lock, "unregister bypassed DID lock");
        assert!(
            !invalidation_bypassed_lock,
            "APNs invalidation bypassed DID lock"
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_logout_fence_serializes_after_inflight_registration() {
        let pool = live_pool().await;
        let did = format!("did:plc:logout-registration-race-{}", Uuid::new_v4());
        let session = session(&did);
        let registry = PushRegistry::new(pool.clone(), TEST_SERVICE_DID.to_owned());
        registry
            .upsert_registration(&session, &registration("logout-race-token"))
            .await
            .expect("seed registration");

        // Hold the device row so the real registration path owns the DID
        // advisory lock while it is still in flight.
        let mut row_blocker = pool.begin().await.expect("begin row blocker");
        sqlx::query(
            "SELECT id FROM user_devices WHERE did = $1 AND device_token = 'logout-race-token' FOR UPDATE",
        )
        .bind(&did)
        .fetch_one(&mut *row_blocker)
        .await
        .expect("lock registration row");

        let registration_registry = registry.clone();
        let registration_session = session.clone();
        let registration_task = tokio::spawn(async move {
            registration_registry
                .upsert_registration(&registration_session, &registration("logout-race-token"))
                .await
        });
        wait_until_did_advisory_lock_is_held(&pool, &did).await;

        let fence_registry = registry.clone();
        let fence_did = did.clone();
        let fence_session_id = session.id.to_string();
        let mut fence_task = tokio::spawn(async move {
            fence_registry
                .mark_auth_revoked(&fence_did, &fence_session_id)
                .await
        });
        let fenced_before_registration_commit =
            timeout(StdDuration::from_millis(75), &mut fence_task).await;
        let bypassed_did_lock = fenced_before_registration_commit.is_ok();

        row_blocker
            .commit()
            .await
            .expect("release registration row");
        registration_task
            .await
            .expect("registration task did not panic")
            .expect("registration commits");
        match fenced_before_registration_commit {
            Ok(result) => result
                .expect("logout fence task did not panic")
                .expect("logout fence commits"),
            Err(_) => fence_task
                .await
                .expect("logout fence task did not panic")
                .expect("logout fence commits"),
        }

        assert!(
            registry
                .is_auth_revoked(&did)
                .await
                .expect("read durable logout fence"),
            "the logout fence must be the final durable account transition"
        );
        cleanup(&pool, &did).await;
        assert!(
            !bypassed_did_lock,
            "logout fence bypassed an in-flight registration's DID lock"
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_same_session_cannot_clear_logout_fence() {
        let pool = live_pool().await;
        let did = format!("did:plc:logout-session-fence-{}", Uuid::new_v4());
        let revoked_session = session(&did);
        let registry = PushRegistry::new(pool.clone(), TEST_SERVICE_DID.to_owned());
        registry
            .upsert_registration(&revoked_session, &registration("logout-session-token"))
            .await
            .expect("seed revoked-session registration");
        registry
            .mark_auth_revoked(&did, &revoked_session.id.to_string())
            .await
            .expect("persist logout fence");

        // A request admitted just before logout may reach either account-touch
        // or registration afterward. Neither same-session path may resurrect
        // push delivery.
        registry
            .touch_account_session(&revoked_session)
            .await
            .expect("touch revoked session");
        registry
            .upsert_registration(&revoked_session, &registration("logout-session-token"))
            .await
            .expect("refresh revoked-session registration");
        assert!(
            registry
                .is_auth_revoked(&did)
                .await
                .expect("read same-session fence"),
            "same-session work admitted before logout cleared the push fence"
        );

        // A genuinely different authenticated session may take ownership and
        // clear the old session's fence. A late logout for the old session must
        // not revoke the replacement session.
        let replacement_session = session(&did);
        registry
            .touch_account_session(&replacement_session)
            .await
            .expect("replacement session takes account ownership");
        assert!(
            !registry
                .is_auth_revoked(&did)
                .await
                .expect("read replacement-session state"),
            "a different authenticated session did not clear the old fence"
        );
        registry
            .mark_auth_revoked(&did, &revoked_session.id.to_string())
            .await
            .expect("late old-session logout is harmless");
        assert!(
            !registry
                .is_auth_revoked(&did)
                .await
                .expect("read state after stale logout"),
            "a stale logout revoked a different live session"
        );

        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_unregister_serializes_with_token_nine_replacement() {
        replacement_race_with_deactivation(DeactivationKind::Unregister).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_apns_invalidation_serializes_with_token_nine_replacement() {
        replacement_race_with_deactivation(DeactivationKind::ApnsInvalidation).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_eight_inserts_and_refresh_stay_at_eight() {
        let pool = live_pool().await;
        let did = format!("did:plc:registration-cap-eight-{}", Uuid::new_v4());
        let session = session(&did);
        let registry = PushRegistry::new(pool.clone(), TEST_SERVICE_DID.to_owned());

        register_tokens(&registry, &session, 8).await;
        let before = rows(&pool, &did).await;
        assert_eq!(before.len(), 8);
        let refreshed_id = before
            .iter()
            .find(|(_, token, _)| token == "token-003")
            .map(|(id, _, _)| *id)
            .expect("refreshed fixture id");

        registry
            .set_apns_environment(&did, "token-003", "sandbox")
            .await
            .expect("seed exact-token APNs environment");

        registry
            .deactivate_registration(&session, &unregistration("token-003"))
            .await
            .expect("deactivate existing registration");
        registry
            .upsert_registration(&session, &registration("token-003"))
            .await
            .expect("reactivate existing registration");
        let retained = rows(&pool, &did).await;
        assert_eq!(retained.len(), 8);
        assert!(retained.iter().all(|(_, _, active)| *active));
        assert!(retained
            .iter()
            .any(|(id, token, _)| *id == refreshed_id && token == "token-003"));
        let refreshed_environment = sqlx::query_scalar::<_, Option<String>>(
            "SELECT apns_environment FROM user_devices WHERE did = $1 AND device_token = 'token-003'",
        )
        .bind(&did)
        .fetch_one(&pool)
        .await
        .expect("load refreshed APNs environment");
        assert_eq!(refreshed_environment.as_deref(), Some("sandbox"));

        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_ninth_token_replaces_deterministic_oldest() {
        let pool = live_pool().await;
        let did = format!("did:plc:registration-cap-replace-{}", Uuid::new_v4());
        let session = session(&did);
        let registry = PushRegistry::new(pool.clone(), TEST_SERVICE_DID.to_owned());
        register_tokens(&registry, &session, 8).await;

        sqlx::query(
            r#"
            UPDATE user_devices
            SET last_registered_at = TIMESTAMPTZ '2026-01-01 00:00:00+00'
                + (substring(device_token from '[0-9]+')::int * INTERVAL '1 second')
            WHERE did = $1
            "#,
        )
        .bind(&did)
        .execute(&pool)
        .await
        .expect("make replacement order deterministic");

        sqlx::query(
            "UPDATE user_devices SET apns_environment = 'sandbox' WHERE did = $1 AND device_token = 'token-000'",
        )
        .bind(&did)
        .execute(&pool)
        .await
        .expect("seed replaced slot APNs environment");

        registry
            .upsert_registration(&session, &registration("token-009"))
            .await
            .expect("register ninth token");
        let retained = rows(&pool, &did).await;
        assert_eq!(retained.len(), 8);
        assert!(!retained.iter().any(|(_, token, _)| token == "token-000"));
        assert!(retained.iter().any(|(_, token, _)| token == "token-009"));
        let replacement_environment = sqlx::query_scalar::<_, Option<String>>(
            "SELECT apns_environment FROM user_devices WHERE did = $1 AND device_token = 'token-009'",
        )
        .bind(&did)
        .fetch_one(&pool)
        .await
        .expect("load replacement APNs environment");
        assert_eq!(replacement_environment, None);

        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_inactive_slot_is_reused_before_active_replacement() {
        let pool = live_pool().await;
        let did = format!("did:plc:registration-cap-inactive-{}", Uuid::new_v4());
        let session = session(&did);
        let registry = PushRegistry::new(pool.clone(), TEST_SERVICE_DID.to_owned());
        register_tokens(&registry, &session, 8).await;
        let before = rows(&pool, &did).await;
        let inactive_id = before
            .iter()
            .find(|(_, token, _)| token == "token-002")
            .map(|(id, _, _)| *id)
            .expect("inactive fixture id");

        registry
            .deactivate_registration(&session, &unregistration("token-002"))
            .await
            .expect("deactivate registration");
        sqlx::query(
            "UPDATE user_devices SET apns_environment = 'production' WHERE did = $1 AND device_token = 'token-002'",
        )
        .bind(&did)
        .execute(&pool)
        .await
        .expect("seed inactive slot APNs environment");
        registry
            .upsert_registration(&session, &registration("replacement-token"))
            .await
            .expect("reuse inactive registration");

        let retained = rows(&pool, &did).await;
        assert_eq!(retained.len(), 8);
        assert!(retained.iter().any(|(id, token, active)| {
            *id == inactive_id && token == "replacement-token" && *active
        }));
        let replacement_environment = sqlx::query_scalar::<_, Option<String>>(
            "SELECT apns_environment FROM user_devices WHERE did = $1 AND device_token = 'replacement-token'",
        )
        .bind(&did)
        .fetch_one(&pool)
        .await
        .expect("load reused APNs environment");
        assert_eq!(replacement_environment, None);
        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_hundred_register_unregister_cycles_never_exceed_eight_total() {
        let pool = live_pool().await;
        let did = format!("did:plc:registration-cap-cycles-{}", Uuid::new_v4());
        let session = session(&did);
        let registry = PushRegistry::new(pool.clone(), TEST_SERVICE_DID.to_owned());

        for index in 0..100 {
            let token = format!("cycle-token-{index:03}");
            registry
                .upsert_registration(&session, &registration(&token))
                .await
                .expect("register cycle token");
            registry
                .deactivate_registration(&session, &unregistration(&token))
                .await
                .expect("unregister cycle token");
            assert!(rows(&pool, &did).await.len() <= 8);
        }

        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_sixteen_barrier_started_registrations_commit_with_latest_eight() {
        let pool = live_pool().await;
        let did = format!("did:plc:registration-cap-race-{}", Uuid::new_v4());
        let session = session(&did);
        let registry = PushRegistry::new(pool.clone(), TEST_SERVICE_DID.to_owned());
        let barrier = Arc::new(Barrier::new(16));
        let mut tasks = Vec::new();

        for index in 0..16 {
            let registry = registry.clone();
            let session = session.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                registry
                    .upsert_registration(
                        &session,
                        &registration(format!("concurrent-token-{index:03}")),
                    )
                    .await
            }));
        }
        for task in tasks {
            task.await
                .expect("registration task did not panic")
                .expect("concurrent registration commits");
        }

        let retained = rows(&pool, &did).await;
        assert_eq!(retained.len(), 8);
        assert!(retained.iter().all(|(_, _, active)| *active));
        assert_eq!(
            retained
                .iter()
                .map(|(_, token, _)| token)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            8
        );

        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_device_token_transfer_moves_owner_and_resets_environment() {
        let pool = live_pool().await;
        let did_a = format!("did:plc:registration-cap-a-{}", Uuid::new_v4());
        let did_b = format!("did:plc:registration-cap-b-{}", Uuid::new_v4());
        let session_a = session(&did_a);
        let session_b = session(&did_b);
        let registry = PushRegistry::new(pool.clone(), TEST_SERVICE_DID.to_owned());

        registry
            .upsert_registration(&session_a, &registration("shared-token"))
            .await
            .expect("register shared token for DID A");
        let did_a_row = rows(&pool, &did_a)
            .await
            .into_iter()
            .next()
            .expect("DID A registration");
        registry
            .set_apns_environment(&did_a, "shared-token", "sandbox")
            .await
            .expect("seed DID A learned environment");

        registry
            .upsert_registration(&session_b, &registration("shared-token"))
            .await
            .expect("transfer shared token to DID B");

        let ownership = sqlx::query_as::<_, (Uuid, String, bool, Option<String>)>(
            r#"
            SELECT id, did, is_active, apns_environment
            FROM user_devices
            WHERE device_token = 'shared-token'
            ORDER BY did ASC
            "#,
        )
        .fetch_all(&pool)
        .await
        .expect("load transferred ownership");
        assert_eq!(ownership.len(), 2);
        assert_eq!(ownership[0].0, did_a_row.0);
        assert_eq!(ownership[0].1, did_a);
        assert!(!ownership[0].2);
        assert_eq!(ownership[0].3, None);
        assert_eq!(ownership[1].1, did_b);
        assert!(ownership[1].2);
        assert_eq!(ownership[1].3, None);

        registry
            .set_apns_environment(&did_b, "shared-token", "production")
            .await
            .expect("seed DID B learned environment");
        let did_b_row_id = ownership[1].0;
        registry
            .upsert_registration(&session_b, &registration("shared-token"))
            .await
            .expect("refresh same DID owner");
        let refreshed = sqlx::query_as::<_, (Uuid, Option<String>)>(
            r#"
            SELECT id, apns_environment
            FROM user_devices
            WHERE did = $1
              AND device_token = 'shared-token'
            "#,
        )
        .bind(&did_b)
        .fetch_one(&pool)
        .await
        .expect("load refreshed DID B owner");
        assert_eq!(refreshed.0, did_b_row_id);
        assert_eq!(refreshed.1.as_deref(), Some("production"));

        cleanup(&pool, &did_a).await;
        cleanup(&pool, &did_b).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with Nest push migrations applied"]
    async fn live_postgres_concurrent_cross_did_registration_has_one_active_owner() {
        let pool = live_pool().await;
        let did_a = format!("did:plc:registration-owner-race-a-{}", Uuid::new_v4());
        let did_b = format!("did:plc:registration-owner-race-b-{}", Uuid::new_v4());
        let session_a = session(&did_a);
        let session_b = session(&did_b);
        let registry = PushRegistry::new(pool.clone(), TEST_SERVICE_DID.to_owned());
        let barrier = Arc::new(Barrier::new(2));

        let registry_a = registry.clone();
        let barrier_a = barrier.clone();
        let task_a = tokio::spawn(async move {
            barrier_a.wait().await;
            registry_a
                .upsert_registration(&session_a, &registration("concurrent-owner-token"))
                .await
        });

        let registry_b = registry.clone();
        let barrier_b = barrier.clone();
        let task_b = tokio::spawn(async move {
            barrier_b.wait().await;
            registry_b
                .upsert_registration(&session_b, &registration("concurrent-owner-token"))
                .await
        });

        task_a
            .await
            .expect("DID A task did not panic")
            .expect("DID A registration commits");
        task_b
            .await
            .expect("DID B task did not panic")
            .expect("DID B registration commits");

        let owners = sqlx::query_as::<_, (String, bool)>(
            r#"
            SELECT did, is_active
            FROM user_devices
            WHERE device_token = 'concurrent-owner-token'
            ORDER BY did ASC
            "#,
        )
        .fetch_all(&pool)
        .await
        .expect("load concurrent ownership rows");
        assert_eq!(owners.len(), 2);
        assert_eq!(owners.iter().filter(|(_, is_active)| *is_active).count(), 1);

        cleanup(&pool, &did_a).await;
        cleanup(&pool, &did_b).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with migration privileges"]
    async fn live_postgres_migration_backfill_keeps_newest_eight_slots_per_did() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored Postgres suite");
        let mut connection = PgConnection::connect(&database_url)
            .await
            .expect("connect test Postgres");
        let schema = format!("registration_cap_{}", Uuid::new_v4().simple());

        sqlx::raw_sql(&format!(
            r#"
            CREATE SCHEMA {schema};
            SET search_path TO {schema}, public;
            CREATE TABLE user_devices (
                id UUID PRIMARY KEY,
                did TEXT NOT NULL,
                device_token TEXT NOT NULL,
                is_active BOOLEAN NOT NULL,
                last_registered_at TIMESTAMPTZ NOT NULL
            );
            INSERT INTO user_devices (id, did, device_token, is_active, last_registered_at)
            SELECT
                ('00000000-0000-0000-0000-' || LPAD(value::text, 12, '0'))::uuid,
                'did:plc:migration-over-cap',
                'migration-token-' || value,
                TRUE,
                TIMESTAMPTZ '2026-01-01 00:00:00+00' + (value * INTERVAL '1 second')
            FROM generate_series(1, 12) AS value;
            "#
        ))
        .execute(&mut connection)
        .await
        .expect("seed isolated over-cap schema");

        sqlx::raw_sql(include_str!(
            "../../../migrations/20260715000000_cap_push_registration_slots.up.sql"
        ))
        .execute(&mut connection)
        .await
        .expect("apply registration-cap backfill");

        let retained = sqlx::query_scalar::<_, String>(
            "SELECT device_token FROM user_devices ORDER BY last_registered_at ASC, id ASC",
        )
        .fetch_all(&mut connection)
        .await
        .expect("load backfilled slots");
        assert_eq!(retained.len(), 8);
        assert_eq!(
            retained.first().map(String::as_str),
            Some("migration-token-5")
        );
        assert_eq!(
            retained.last().map(String::as_str),
            Some("migration-token-12")
        );

        sqlx::raw_sql(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE;"
        ))
        .execute(&mut connection)
        .await
        .expect("clean isolated migration schema");
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with migration privileges"]
    async fn live_postgres_migration_backfill_preserves_active_before_newer_inactive_slots() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored Postgres suite");
        let mut connection = PgConnection::connect(&database_url)
            .await
            .expect("connect test Postgres");
        let schema = format!("registration_cap_active_{}", Uuid::new_v4().simple());

        sqlx::raw_sql(&format!(
            r#"
            CREATE SCHEMA {schema};
            SET search_path TO {schema}, public;
            CREATE TABLE user_devices (
                id UUID PRIMARY KEY,
                did TEXT NOT NULL,
                device_token TEXT NOT NULL,
                is_active BOOLEAN NOT NULL,
                last_registered_at TIMESTAMPTZ NOT NULL
            );
            INSERT INTO user_devices (id, did, device_token, is_active, last_registered_at)
            SELECT
                ('10000000-0000-0000-0000-' || LPAD(value::text, 12, '0'))::uuid,
                'did:plc:migration-active-priority',
                'active-token-' || value,
                TRUE,
                TIMESTAMPTZ '2026-01-01 00:00:00+00' + (value * INTERVAL '1 second')
            FROM generate_series(1, 8) AS value;
            INSERT INTO user_devices (id, did, device_token, is_active, last_registered_at)
            SELECT
                ('20000000-0000-0000-0000-' || LPAD(value::text, 12, '0'))::uuid,
                'did:plc:migration-active-priority',
                'inactive-token-' || value,
                FALSE,
                TIMESTAMPTZ '2026-02-01 00:00:00+00' + (value * INTERVAL '1 second')
            FROM generate_series(1, 4) AS value;
            "#
        ))
        .execute(&mut connection)
        .await
        .expect("seed active and newer inactive over-cap schema");

        sqlx::raw_sql(include_str!(
            "../../../migrations/20260715000000_cap_push_registration_slots.up.sql"
        ))
        .execute(&mut connection)
        .await
        .expect("apply registration-cap backfill");

        let retained = sqlx::query_as::<_, (String, bool)>(
            "SELECT device_token, is_active FROM user_devices ORDER BY device_token ASC",
        )
        .fetch_all(&mut connection)
        .await
        .expect("load active-priority backfilled slots");
        assert_eq!(retained.len(), 8);
        assert!(retained.iter().all(|(_, is_active)| *is_active));
        let expected = (1..=8)
            .map(|value| format!("active-token-{value}"))
            .collect::<Vec<_>>();
        assert_eq!(
            retained
                .iter()
                .map(|(token, _)| token.clone())
                .collect::<Vec<_>>(),
            expected
        );

        sqlx::raw_sql(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE;"
        ))
        .execute(&mut connection)
        .await
        .expect("clean isolated active-priority migration schema");
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with migration privileges"]
    async fn live_postgres_registration_constraints_backfill_and_enforce_active_owner() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored Postgres suite");
        let mut connection = PgConnection::connect(&database_url)
            .await
            .expect("connect test Postgres");
        let schema = format!("registration_owner_{}", Uuid::new_v4().simple());

        sqlx::raw_sql(&format!(
            r#"
            CREATE SCHEMA {schema};
            SET search_path TO {schema}, public;
            CREATE TABLE user_devices (
                id UUID PRIMARY KEY,
                did TEXT NOT NULL,
                device_token TEXT NOT NULL,
                platform TEXT NOT NULL,
                app_id TEXT NOT NULL,
                service_did TEXT,
                is_active BOOLEAN NOT NULL,
                last_registered_at TIMESTAMPTZ NOT NULL,
                apns_environment TEXT,
                last_error TEXT,
                updated_at TIMESTAMPTZ NOT NULL
            );
            INSERT INTO user_devices (
                id, did, device_token, platform, app_id, service_did,
                is_active, last_registered_at, apns_environment, updated_at
            )
            VALUES
                (
                    '00000000-0000-0000-0000-000000000001',
                    'did:plc:owner-a',
                    'duplicate-token',
                    'ios',
                    'blue.catbird',
                    '{TEST_SERVICE_DID}',
                    TRUE,
                    TIMESTAMPTZ '2026-01-01 00:00:00+00',
                    'sandbox',
                    NOW()
                ),
                (
                    '00000000-0000-0000-0000-000000000002',
                    'did:plc:owner-b',
                    'duplicate-token',
                    'ios',
                    'blue.catbird',
                    '{TEST_SERVICE_DID}',
                    TRUE,
                    TIMESTAMPTZ '2026-02-01 00:00:00+00',
                    'sandbox',
                    NOW()
                ),
                (
                    '00000000-0000-0000-0000-000000000003',
                    'did:plc:owner-c',
                    'duplicate-token',
                    'ios',
                    'blue.catbird',
                    '{TEST_SERVICE_DID}',
                    TRUE,
                    TIMESTAMPTZ '2026-02-01 00:00:00+00',
                    'production',
                    NOW()
                ),
                (
                    '00000000-0000-0000-0000-000000000006',
                    'did:plc:invalid-legacy',
                    'duplicate-token',
                    'ios',
                    'invalid/app-id',
                    '{TEST_SERVICE_DID}',
                    TRUE,
                    TIMESTAMPTZ '2026-03-01 00:00:00+00',
                    'production',
                    NOW()
                );
            "#
        ))
        .execute(&mut connection)
        .await
        .expect("seed isolated duplicate-owner schema");

        sqlx::raw_sql(include_str!(
            "../../../migrations/20260718020000_push_registration_constraints.up.sql"
        ))
        .execute(&mut connection)
        .await
        .expect("apply registration constraints migration");

        let ownership = sqlx::query_as::<_, (Uuid, bool, Option<String>, Option<String>)>(
            r#"
            SELECT id, is_active, apns_environment, last_error
            FROM user_devices
            WHERE device_token = 'duplicate-token'
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&mut connection)
        .await
        .expect("load deduplicated owners");
        assert_eq!(ownership.len(), 4);
        assert!(!ownership[0].1);
        assert_eq!(ownership[0].2, None);
        assert_eq!(ownership[0].3.as_deref(), Some("device_token_transferred"));
        assert!(!ownership[1].1);
        assert_eq!(ownership[1].2, None);
        assert!(ownership[2].1);
        assert_eq!(ownership[2].2.as_deref(), Some("production"));
        assert!(!ownership[3].1);
        assert_eq!(ownership[3].2, None);
        assert_eq!(
            ownership[3].3.as_deref(),
            Some("invalid_registration_metadata")
        );

        let invalid_legacy = sqlx::query_as::<_, (bool, Option<String>, Option<String>)>(
            r#"
            SELECT is_active, apns_environment, last_error
            FROM user_devices
            WHERE id = '00000000-0000-0000-0000-000000000006'
            "#,
        )
        .fetch_one(&mut connection)
        .await
        .expect("load invalid legacy row");
        assert!(!invalid_legacy.0);
        assert_eq!(invalid_legacy.1, None);
        assert_eq!(
            invalid_legacy.2.as_deref(),
            Some("invalid_registration_metadata")
        );

        let duplicate_error = sqlx::query(
            r#"
            INSERT INTO user_devices (
                id, did, device_token, platform, app_id, service_did,
                is_active, last_registered_at, updated_at
            )
            VALUES (
                '00000000-0000-0000-0000-000000000004',
                'did:plc:owner-d',
                'duplicate-token',
                'ios',
                'blue.catbird',
                $1,
                TRUE,
                NOW(),
                NOW()
            )
            "#,
        )
        .bind(TEST_SERVICE_DID)
        .execute(&mut connection)
        .await
        .expect_err("partial unique index must reject a second active owner");
        assert_eq!(
            duplicate_error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23505")
        );

        let invalid_field_error = sqlx::query(
            r#"
            INSERT INTO user_devices (
                id, did, device_token, platform, app_id, service_did,
                is_active, last_registered_at, updated_at
            )
            VALUES (
                '00000000-0000-0000-0000-000000000005',
                'did:plc:owner-e',
                'new-valid-token',
                'ios',
                'invalid/app-id',
                $1,
                TRUE,
                NOW(),
                NOW()
            )
            "#,
        )
        .bind(TEST_SERVICE_DID)
        .execute(&mut connection)
        .await
        .expect_err("database check must reject unsafe appId");
        assert_eq!(
            invalid_field_error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );

        sqlx::raw_sql(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE;"
        ))
        .execute(&mut connection)
        .await
        .expect("clean isolated registration-owner schema");
    }
}
