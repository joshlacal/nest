use anyhow::Result;
use serde_json::Value;
use sqlx::{Pool, Postgres, Row};

use super::types::{PushPreferencesDocument, PutPreferencesInput};

#[derive(Clone)]
pub struct PushPreferences {
    db_pool: Pool<Postgres>,
}

impl PushPreferences {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self { db_pool }
    }

    pub async fn get_or_create(&self, did: &str) -> Result<PushPreferencesDocument> {
        if let Some(existing) = self.get(did).await? {
            return Ok(existing);
        }

        let prefs = PushPreferencesDocument::default();
        self.put(did, &prefs).await?;
        Ok(prefs)
    }

    pub async fn get(&self, did: &str) -> Result<Option<PushPreferencesDocument>> {
        let row = sqlx::query("SELECT preferences_json FROM push_preferences WHERE account_did = $1")
            .bind(did)
            .fetch_optional(&self.db_pool)
            .await?;

        let prefs = row
            .map(|row| row.try_get::<Value, _>("preferences_json"))
            .transpose()?
            .map(serde_json::from_value)
            .transpose()?;

        Ok(prefs)
    }

    pub async fn put(&self, did: &str, prefs: &PushPreferencesDocument) -> Result<()> {
        let payload = serde_json::to_value(prefs)?;
        sqlx::query(
            r#"
            INSERT INTO push_preferences (account_did, preferences_json, created_at, updated_at)
            VALUES ($1, $2::jsonb, NOW(), NOW())
            ON CONFLICT (account_did)
            DO UPDATE
            SET preferences_json = EXCLUDED.preferences_json,
                updated_at = NOW()
            "#,
        )
        .bind(did)
        .bind(payload)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn patch(
        &self,
        did: &str,
        input: PutPreferencesInput,
    ) -> Result<PushPreferencesDocument> {
        let current = self.get_or_create(did).await?;
        let updated = input.apply_to(current);
        self.put(did, &updated).await?;
        Ok(updated)
    }
}
