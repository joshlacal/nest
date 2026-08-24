use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::access::{extract_authority_did, CredentialStore};
use crate::error::AppError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Projection {
    CircleUpsert {
        space: String,
        authority: String,
        name: String,
        created_at: DateTime<Utc>,
        generation: i64,
    },
    MemberAdd {
        space: String,
        member: String,
        generation: i64,
    },
    MemberRemove {
        space: String,
        member: String,
        generation: i64,
    },
    CircleDelete {
        space: String,
        generation: i64,
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
    #[serde(default)]
    pub generation: Option<i64>,
}

pub fn compute_payload_digest(
    operation_id: &Uuid,
    actor_did: &str,
    space_uri: &str,
    kind: &str,
    payload: &serde_json::Value,
) -> Vec<u8> {
    let payload_str = serde_json::to_string(payload).unwrap_or_default();
    let data = format!("{operation_id}:{actor_did}:{space_uri}:{kind}:{payload_str}");
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hasher.finalize().to_vec()
}

impl SyncProjectionInput {
    pub fn to_projection(&self) -> Result<Projection, AppError> {
        // Enforce top-level space URI binding
        let authority_did = extract_authority_did(&self.space_uri)?;

        if let Some(payload_space) = self.payload.get("space").and_then(|v| v.as_str()) {
            if payload_space != self.space_uri {
                return Err(AppError::InvalidRequest(
                    "Payload space does not match top-level spaceUri".into(),
                ));
            }
        }

        let generation = self
            .payload
            .get("generation")
            .and_then(|v| v.as_i64())
            .or(self.generation)
            .unwrap_or(0);

        match self.kind.as_str() {
            "circle_upsert" | "CircleUpsert" => {
                let name = self
                    .payload
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AppError::InvalidRequest("Missing name in CircleUpsert payload".into())
                    })?;

                if let Some(payload_auth) = self.payload.get("authority").and_then(|v| v.as_str()) {
                    if payload_auth != authority_did {
                        return Err(AppError::InvalidRequest(
                            "Payload authority does not match Space authority".into(),
                        ));
                    }
                }

                let created_at = self
                    .payload
                    .get("createdAt")
                    .or_else(|| self.payload.get("created_at"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(Utc::now);

                Ok(Projection::CircleUpsert {
                    space: self.space_uri.clone(),
                    authority: authority_did,
                    name: name.to_string(),
                    created_at,
                    generation,
                })
            }
            "member_add" | "MemberAdd" => {
                let member = self
                    .payload
                    .get("member")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AppError::InvalidRequest("Missing member in MemberAdd payload".into())
                    })?;

                Ok(Projection::MemberAdd {
                    space: self.space_uri.clone(),
                    member: member.to_string(),
                    generation,
                })
            }
            "member_remove" | "MemberRemove" => {
                let member = self
                    .payload
                    .get("member")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AppError::InvalidRequest("Missing member in MemberRemove payload".into())
                    })?;

                Ok(Projection::MemberRemove {
                    space: self.space_uri.clone(),
                    member: member.to_string(),
                    generation,
                })
            }
            "circle_delete" | "CircleDelete" => Ok(Projection::CircleDelete {
                space: self.space_uri.clone(),
                generation,
            }),
            other => Err(AppError::InvalidRequest(format!(
                "Unknown projection kind: {other}"
            ))),
        }
    }
}

pub async fn apply_projection(
    pool: &PgPool,
    credential_store: Option<&CredentialStore>,
    operation_id: Uuid,
    projection: Projection,
    payload_digest: &[u8],
) -> Result<(), AppError> {
    // 1. Begin transaction first for atomic receipt claim
    let mut tx = pool.begin().await.map_err(AppError::Database)?;

    // Atomic claim with payload digest
    let claim_res: Option<(Uuid,)> = sqlx::query_as(
        r#"
        INSERT INTO projection_receipts (operation_id, payload_digest, consumed_at)
        VALUES ($1, $2, now())
        ON CONFLICT (operation_id) DO NOTHING
        RETURNING operation_id
        "#,
    )
    .bind(operation_id)
    .bind(payload_digest)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    if claim_res.is_none() {
        // Receipt already exists; verify payload digest matches for idempotent retry
        let existing: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
            "SELECT payload_digest FROM projection_receipts WHERE operation_id = $1",
        )
        .bind(operation_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        if let Some((Some(existing_digest),)) = existing {
            if existing_digest != payload_digest {
                return Err(AppError::Conflict(
                    "Conflict: operation_id reused with different payload".into(),
                ));
            }
        }

        // Idempotent success without reapplying mutations
        tx.commit().await.map_err(AppError::Database)?;
        return Ok(());
    }

    // 2. Check deletion tombstones
    let target_space = match &projection {
        Projection::CircleUpsert { space, .. } => space.as_str(),
        Projection::MemberAdd { space, .. } => space.as_str(),
        Projection::MemberRemove { space, .. } => space.as_str(),
        Projection::CircleDelete { space, .. } => space.as_str(),
    };

    let tombstone: Option<(String,)> = sqlx::query_as(
        "SELECT space_uri FROM circle_tombstones WHERE space_uri = $1",
    )
    .bind(target_space)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    if tombstone.is_some() {
        match projection {
            Projection::CircleDelete { .. } => {
                // Already deleted, acknowledge
            }
            _ => {
                // Circle has been deleted; stale projection cannot resurrect it
                tx.commit().await.map_err(AppError::Database)?;
                return Ok(());
            }
        }
    }

    let is_circle_delete = matches!(&projection, Projection::CircleDelete { .. });
    let deleted_space = if is_circle_delete {
        Some(target_space.to_string())
    } else {
        None
    };

    match projection {
        Projection::CircleUpsert {
            space,
            authority,
            name,
            created_at,
            generation: _,
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
        Projection::MemberAdd {
            space,
            member,
            generation,
        } => {
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

            // Check existing member generation to prevent out-of-order deliveries from overwriting newer state
            let existing_gen: Option<(i64,)> = sqlx::query_as(
                "SELECT generation FROM circle_members WHERE space_uri = $1 AND member_did = $2 FOR UPDATE",
            )
            .bind(&space)
            .bind(&member)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            if let Some((prev_gen,)) = existing_gen {
                if prev_gen >= generation {
                    // Ignore stale/older projection
                    tx.commit().await.map_err(AppError::Database)?;
                    return Ok(());
                }
            }

            sqlx::query(
                r#"
                INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at)
                VALUES ($1, $2, 'active', $3, now())
                ON CONFLICT (space_uri, member_did) DO UPDATE
                SET status = 'active', generation = EXCLUDED.generation, updated_at = now()
                "#,
            )
            .bind(&space)
            .bind(&member)
            .bind(generation)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;
        }
        Projection::MemberRemove {
            space,
            member,
            generation,
        } => {
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

            // Check existing member generation
            let existing_gen: Option<(i64,)> = sqlx::query_as(
                "SELECT generation FROM circle_members WHERE space_uri = $1 AND member_did = $2 FOR UPDATE",
            )
            .bind(&space)
            .bind(&member)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            if let Some((prev_gen,)) = existing_gen {
                if prev_gen >= generation {
                    // Ignore stale/older projection
                    tx.commit().await.map_err(AppError::Database)?;
                    return Ok(());
                }
            }

            sqlx::query(
                r#"
                INSERT INTO circle_members (space_uri, member_did, status, generation, updated_at)
                VALUES ($1, $2, 'removed', $3, now())
                ON CONFLICT (space_uri, member_did) DO UPDATE
                SET status = 'removed', generation = EXCLUDED.generation, updated_at = now()
                "#,
            )
            .bind(&space)
            .bind(&member)
            .bind(generation)
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
        }
        Projection::CircleDelete { space, .. } => {
            // 1. Insert deletion tombstone
            sqlx::query(
                r#"
                INSERT INTO circle_tombstones (space_uri, deleted_at)
                VALUES ($1, now())
                ON CONFLICT (space_uri) DO UPDATE SET deleted_at = now()
                "#,
            )
            .bind(&space)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            // 2. Cascade delete from circles
            sqlx::query("DELETE FROM circles WHERE space_uri = $1")
                .bind(&space)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;
        }
    }

    tx.commit().await.map_err(AppError::Database)?;

    // If Circle was deleted, remove credential and ephemeral keys from in-memory CredentialStore
    if let Some(space) = deleted_space {
        if let Some(store) = credential_store {
            store.remove(&space).await;
        }
    }

    Ok(())
}
