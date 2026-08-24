use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::access::extract_authority_did;
use crate::error::AppError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Projection {
    CircleUpsert {
        space: String,
        authority: String,
        name: String,
        created_at: DateTime<Utc>,
    },
    MemberAdd {
        space: String,
        member: String,
    },
    MemberRemove {
        space: String,
        member: String,
    },
    CircleDelete {
        space: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncProjectionInput {
    pub operation_id: Uuid,
    #[serde(default)]
    pub operation_key: Option<String>,
    pub actor_did: String,
    pub space_uri: String,
    pub kind: String,
    pub payload: serde_json::Value,
}

impl SyncProjectionInput {
    pub fn to_projection(&self) -> Result<Projection, AppError> {
        match self.kind.as_str() {
            "circle_upsert" | "CircleUpsert" => {
                let name = self
                    .payload
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::InvalidRequest("Missing name in CircleUpsert payload".into()))?;
                let authority = self
                    .payload
                    .get("authority")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&self.actor_did);
                let space = self
                    .payload
                    .get("space")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&self.space_uri);
                let created_at = self
                    .payload
                    .get("createdAt")
                    .or_else(|| self.payload.get("created_at"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(Utc::now);

                Ok(Projection::CircleUpsert {
                    space: space.to_string(),
                    authority: authority.to_string(),
                    name: name.to_string(),
                    created_at,
                })
            }
            "member_add" | "MemberAdd" => {
                let member = self
                    .payload
                    .get("member")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::InvalidRequest("Missing member in MemberAdd payload".into()))?;
                let space = self
                    .payload
                    .get("space")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&self.space_uri);

                Ok(Projection::MemberAdd {
                    space: space.to_string(),
                    member: member.to_string(),
                })
            }
            "member_remove" | "MemberRemove" => {
                let member = self
                    .payload
                    .get("member")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::InvalidRequest("Missing member in MemberRemove payload".into()))?;
                let space = self
                    .payload
                    .get("space")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&self.space_uri);

                Ok(Projection::MemberRemove {
                    space: space.to_string(),
                    member: member.to_string(),
                })
            }
            "circle_delete" | "CircleDelete" => {
                let space = self
                    .payload
                    .get("space")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&self.space_uri);

                Ok(Projection::CircleDelete {
                    space: space.to_string(),
                })
            }
            other => Err(AppError::InvalidRequest(format!("Unknown projection kind: {other}"))),
        }
    }
}

pub async fn apply_projection(
    pool: &PgPool,
    operation_id: Uuid,
    projection: Projection,
) -> Result<(), AppError> {
    // 1. Idempotency receipt check
    let already_consumed: Option<(Uuid,)> = sqlx::query_as(
        "SELECT operation_id FROM projection_receipts WHERE operation_id = $1",
    )
    .bind(operation_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;

    if already_consumed.is_some() {
        tracing::debug!(
            operation_id = %operation_id,
            "Projection already consumed; returning idempotent success"
        );
        return Ok(());
    }

    // 2. Execute projection within transaction
    let mut tx = pool.begin().await.map_err(AppError::Database)?;

    // Insert receipt
    sqlx::query(
        r#"
        INSERT INTO projection_receipts (operation_id, consumed_at)
        VALUES ($1, now())
        ON CONFLICT (operation_id) DO NOTHING
        "#,
    )
    .bind(operation_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    match projection {
        Projection::CircleUpsert {
            space,
            authority,
            name,
            created_at,
        } => {
            sqlx::query(
                r#"
                INSERT INTO circles (space_uri, authority_did, display_name, created_at, deleted_at)
                VALUES ($1, $2, $3, $4, NULL)
                ON CONFLICT (space_uri) DO UPDATE
                SET authority_did = EXCLUDED.authority_did,
                    display_name = EXCLUDED.display_name,
                    deleted_at = NULL
                "#,
            )
            .bind(&space)
            .bind(&authority)
            .bind(&name)
            .bind(created_at)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;
        }
        Projection::MemberAdd { space, member } => {
            // Ensure circle row exists first (to prevent foreign key failure in out-of-order deliveries)
            let authority = extract_authority_did(&space).unwrap_or_else(|_| member.clone());
            sqlx::query(
                r#"
                INSERT INTO circles (space_uri, authority_did, display_name, created_at)
                VALUES ($1, $2, 'Circle', now())
                ON CONFLICT (space_uri) DO NOTHING
                "#,
            )
            .bind(&space)
            .bind(&authority)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            sqlx::query(
                r#"
                INSERT INTO circle_members (space_uri, member_did, status, updated_at)
                VALUES ($1, $2, 'active', now())
                ON CONFLICT (space_uri, member_did) DO UPDATE
                SET status = 'active', updated_at = now()
                "#,
            )
            .bind(&space)
            .bind(&member)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;
        }
        Projection::MemberRemove { space, member } => {
            // Ensure circle row exists if needed
            let authority = extract_authority_did(&space).unwrap_or_else(|_| member.clone());
            sqlx::query(
                r#"
                INSERT INTO circles (space_uri, authority_did, display_name, created_at)
                VALUES ($1, $2, 'Circle', now())
                ON CONFLICT (space_uri) DO NOTHING
                "#,
            )
            .bind(&space)
            .bind(&authority)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            // Atomically update status = 'removed'
            sqlx::query(
                r#"
                INSERT INTO circle_members (space_uri, member_did, status, updated_at)
                VALUES ($1, $2, 'removed', now())
                ON CONFLICT (space_uri, member_did) DO UPDATE
                SET status = 'removed', updated_at = now()
                "#,
            )
            .bind(&space)
            .bind(&member)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            // Delete access lease
            sqlx::query("DELETE FROM access_leases WHERE space_uri = $1 AND member_did = $2")
                .bind(&space)
                .bind(&member)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;

            // Delete notifications directed to removed member
            sqlx::query(
                "DELETE FROM circle_notifications WHERE space_uri = $1 AND recipient_did = $2",
            )
            .bind(&space)
            .bind(&member)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            // Note: Shared content (circle_records, circle_likes) is NOT touched!
        }
        Projection::CircleDelete { space } => {
            // Cascades deletion across circle_members, access_leases, circle_records, circle_likes, etc.
            sqlx::query("DELETE FROM circles WHERE space_uri = $1")
                .bind(&space)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;
        }
    }

    tx.commit().await.map_err(AppError::Database)?;
    Ok(())
}
