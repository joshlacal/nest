use anyhow::Result;
use sqlx::{Pool, Postgres, Row};

use crate::{
    error::{AppError, AppResult},
    models::CatbirdSession,
};

use super::types::{PushAccountRow, RegistrationRow, RegisterPushInput, UnregisterPushInput};

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

    pub async fn touch_account_session(&self, session: &CatbirdSession) -> Result<()> {
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
            SET session_id = EXCLUDED.session_id,
                pds_url = EXCLUDED.pds_url,
                last_seen_at = NOW(),
                updated_at = NOW()
            "#,
        )
        .bind(&session.did)
        .bind(session.id.to_string())
        .bind(&session.pds_url)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    pub async fn upsert_registration(
        &self,
        session: &CatbirdSession,
        input: &RegisterPushInput,
    ) -> Result<()> {
        self.touch_account_session(session).await?;
        self.clear_auth_revoked(&session.did).await?;

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
        .execute(&self.db_pool)
        .await?;

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

    pub async fn deactivate_invalid_token(&self, did: &str, device_token: &str, error: &str) -> Result<()> {
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
                is_active
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

    pub async fn mark_auth_revoked(&self, did: &str) -> Result<()> {
        sqlx::query(
            "UPDATE push_accounts SET auth_revoked_at = NOW(), updated_at = NOW() WHERE account_did = $1",
        )
        .bind(did)
        .execute(&self.db_pool)
        .await?;
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
