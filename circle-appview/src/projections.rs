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
        circle_generation: i64,
        member_generation: i64,
    },
    MemberRemove {
        space: String,
        member: String,
        circle_generation: i64,
        member_generation: i64,
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
    #[serde(default)]
    pub circle_generation: Option<i64>,
    #[serde(default)]
    pub member_generation: Option<i64>,
}

pub fn compute_payload_digest(
    operation_id: &Uuid,
    operation_key: Option<&str>,
    actor_did: &str,
    space_uri: &str,
    kind: &str,
    payload: &serde_json::Value,
    generation: Option<i64>,
    circle_generation: Option<i64>,
    member_generation: Option<i64>,
) -> Vec<u8> {
    let payload_str = serde_json::to_string(payload).unwrap_or_default();
    let op_key_str = operation_key.unwrap_or_default();
    let gen_str = generation.map(|g| g.to_string()).unwrap_or_default();
    let circle_gen_str = circle_generation.map(|g| g.to_string()).unwrap_or_default();
    let member_gen_str = member_generation.map(|g| g.to_string()).unwrap_or_default();
    let data = format!(
        "{operation_id}:{op_key_str}:{actor_did}:{space_uri}:{kind}:{payload_str}:{gen_str}:{circle_gen_str}:{member_gen_str}"
    );
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hasher.finalize().to_vec()
}

fn validate_equal_generations(gens: &[(Option<i64>, &str)], context: &str) -> Result<i64, AppError> {
    let mut found: Option<i64> = None;
    for (gen, name) in gens {
        if let Some(val) = gen {
            if let Some(existing) = found {
                if existing != *val {
                    return Err(AppError::InvalidRequest(format!(
                        "Conflicting {context} values: {name} ({val}) != existing ({existing})"
                    )));
                }
            } else {
                found = Some(*val);
            }
        }
    }
    found.ok_or_else(|| AppError::InvalidRequest(format!("Missing {context}")))
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

        match self.kind.as_str() {
            "circle_upsert" | "CircleUpsert" => {
                let circle_gen = validate_equal_generations(
                    &[
                        (self.circle_generation, "top-level circle_generation"),
                        (self.generation, "top-level generation"),
                        (self.payload.get("circleGeneration").and_then(|v| v.as_i64()), "payload.circleGeneration"),
                        (self.payload.get("circle_generation").and_then(|v| v.as_i64()), "payload.circle_generation"),
                        (self.payload.get("generation").and_then(|v| v.as_i64()), "payload.generation"),
                    ],
                    "CircleUpsert",
                )?;

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
                    generation: circle_gen,
                })
            }
            "member_add" | "MemberAdd" => {
                let circle_gen = validate_equal_generations(
                    &[
                        (self.circle_generation, "top-level circle_generation"),
                        (self.payload.get("circleGeneration").and_then(|v| v.as_i64()), "payload.circleGeneration"),
                        (self.payload.get("circle_generation").and_then(|v| v.as_i64()), "payload.circle_generation"),
                    ],
                    "circleGeneration for MemberAdd",
                )?;

                let member_gen = validate_equal_generations(
                    &[
                        (self.member_generation, "top-level member_generation"),
                        (self.payload.get("memberGeneration").and_then(|v| v.as_i64()), "payload.memberGeneration"),
                        (self.payload.get("member_generation").and_then(|v| v.as_i64()), "payload.member_generation"),
                        (self.generation, "top-level generation"),
                        (self.payload.get("generation").and_then(|v| v.as_i64()), "payload.generation"),
                    ],
                    "memberGeneration for MemberAdd",
                )?;
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
                    circle_generation: circle_gen,
                    member_generation: member_gen,
                })
            }
            "member_remove" | "MemberRemove" => {
                let circle_gen = validate_equal_generations(
                    &[
                        (self.circle_generation, "top-level circle_generation"),
                        (self.payload.get("circleGeneration").and_then(|v| v.as_i64()), "payload.circleGeneration"),
                        (self.payload.get("circle_generation").and_then(|v| v.as_i64()), "payload.circle_generation"),
                    ],
                    "circleGeneration for MemberRemove",
                )?;

                let member_gen = validate_equal_generations(
                    &[
                        (self.member_generation, "top-level member_generation"),
                        (self.payload.get("memberGeneration").and_then(|v| v.as_i64()), "payload.memberGeneration"),
                        (self.payload.get("member_generation").and_then(|v| v.as_i64()), "payload.member_generation"),
                        (self.generation, "top-level generation"),
                        (self.payload.get("generation").and_then(|v| v.as_i64()), "payload.generation"),
                    ],
                    "memberGeneration for MemberRemove",
                )?;
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
                    circle_generation: circle_gen,
                    member_generation: member_gen,
                })
            }
            "circle_delete" | "CircleDelete" => {
                let circle_gen = validate_equal_generations(
                    &[
                        (self.circle_generation, "top-level circle_generation"),
                        (self.generation, "top-level generation"),
                        (self.payload.get("circleGeneration").and_then(|v| v.as_i64()), "payload.circleGeneration"),
                        (self.payload.get("circle_generation").and_then(|v| v.as_i64()), "payload.circle_generation"),
                        (self.payload.get("generation").and_then(|v| v.as_i64()), "payload.generation"),
                    ],
                    "CircleDelete",
                )?;

                Ok(Projection::CircleDelete {
                    space: self.space_uri.clone(),
                    generation: circle_gen,
                })
            }
            other => Err(AppError::InvalidRequest(format!(
                "Unknown projection kind: {other}"
            ))),
        }
    }
}

pub async fn apply_projection(
    pool: &PgPool,
    credential_store: Option<&CredentialStore>,
    space_locks: Option<&crate::access::SpaceLockManager>,
    operation_id: Uuid,
    projection: Projection,
    payload_digest: &[u8],
) -> Result<(), AppError> {
    let target_space = match &projection {
        Projection::CircleUpsert { space, .. } => space.as_str(),
        Projection::MemberAdd { space, .. } => space.as_str(),
        Projection::MemberRemove { space, .. } => space.as_str(),
        Projection::CircleDelete { space, .. } => space.as_str(),
    };

    // Acquire per-Space async lock spanning DB mutations and in-memory credential store removal
    let _space_lock = if let Some(locks) = space_locks {
        Some(locks.acquire(target_space).await)
    } else {
        None
    };
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

    // 2. Check deletion tombstones against circle epoch
    let target_circle_generation = match &projection {
        Projection::CircleUpsert { generation, .. } => *generation,
        Projection::MemberAdd { circle_generation, .. } => *circle_generation,
        Projection::MemberRemove { circle_generation, .. } => *circle_generation,
        Projection::CircleDelete { generation, .. } => *generation,
    };

    let tombstone: Option<(i64,)> = sqlx::query_as(
        "SELECT generation FROM circle_tombstones WHERE space_uri = $1 AND generation >= $2",
    )
    .bind(target_space)
    .bind(target_circle_generation)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    if tombstone.is_some() {
        match projection {
            Projection::CircleDelete { .. } => {
                // Already deleted, acknowledge
            }
            _ => {
                // Circle has been deleted at or after this generation; stale projection cannot resurrect it
                tx.commit().await.map_err(AppError::Database)?;
                return Ok(());
            }
        }
    }

    let is_purging_op = matches!(&projection, Projection::CircleDelete { .. } | Projection::MemberRemove { .. });
    let deleted_space = if is_purging_op {
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
            generation,
        } => {
            // Check if deleted tombstone exists with higher or equal generation
            let tombstone: Option<(i64,)> = sqlx::query_as(
                "SELECT generation FROM circle_tombstones WHERE space_uri = $1 AND generation >= $2",
            )
            .bind(&space)
            .bind(generation)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            if tombstone.is_some() {
                tx.commit().await.map_err(AppError::Database)?;
                return Ok(());
            }

            // Check existing circle generation
            let existing_gen: Option<(i64,)> = sqlx::query_as(
                "SELECT generation FROM circles WHERE space_uri = $1 FOR UPDATE",
            )
            .bind(&space)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            if let Some((prev_gen,)) = existing_gen {
                if prev_gen >= generation {
                    tx.commit().await.map_err(AppError::Database)?;
                    return Ok(());
                }
            }

            sqlx::query(
                r#"
                INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation, deleted_at)
                VALUES ($1, $2, $3, $4, $5, NULL)
                ON CONFLICT (space_uri) DO UPDATE
                SET authority_did = EXCLUDED.authority_did,
                    display_name = EXCLUDED.display_name,
                    generation = EXCLUDED.generation,
                    deleted_at = NULL
                WHERE circles.generation <= EXCLUDED.generation
                "#,
            )
            .bind(&space)
            .bind(&authority)
            .bind(&name)
            .bind(created_at)
            .bind(generation)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;
        }
        Projection::MemberAdd {
            space,
            member,
            circle_generation,
            member_generation,
        } => {
            // Check existing circle generation
            let existing_circle: Option<(i64,)> = sqlx::query_as(
                "SELECT generation FROM circles WHERE space_uri = $1 FOR UPDATE",
            )
            .bind(&space)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            if let Some((existing_c_gen,)) = existing_circle {
                if existing_c_gen > circle_generation {
                    // Stale member projection for older circle epoch
                    tx.commit().await.map_err(AppError::Database)?;
                    return Ok(());
                }
            } else {
                let authority = extract_authority_did(&space).unwrap_or_else(|_| member.clone());
                sqlx::query(
                    r#"
                    INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation)
                    VALUES ($1, $2, 'Circle', now(), $3)
                    ON CONFLICT (space_uri) DO NOTHING
                    "#,
                )
                .bind(&space)
                .bind(&authority)
                .bind(circle_generation)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;
            }

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
                if prev_gen >= member_generation {
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
            .bind(member_generation)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;
        }
        Projection::MemberRemove {
            space,
            member,
            circle_generation,
            member_generation,
        } => {
            // Check existing circle generation
            let existing_circle: Option<(i64,)> = sqlx::query_as(
                "SELECT generation FROM circles WHERE space_uri = $1 FOR UPDATE",
            )
            .bind(&space)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            if let Some((existing_c_gen,)) = existing_circle {
                if existing_c_gen > circle_generation {
                    // Stale member projection for older circle epoch
                    tx.commit().await.map_err(AppError::Database)?;
                    return Ok(());
                }
            } else {
                let authority = extract_authority_did(&space).unwrap_or_else(|_| member.clone());
                sqlx::query(
                    r#"
                    INSERT INTO circles (space_uri, authority_did, display_name, created_at, generation)
                    VALUES ($1, $2, 'Circle', now(), $3)
                    ON CONFLICT (space_uri) DO NOTHING
                    "#,
                )
                .bind(&space)
                .bind(&authority)
                .bind(circle_generation)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;
            }

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
                if prev_gen >= member_generation {
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
            .bind(member_generation)
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
        Projection::CircleDelete { space, generation } => {
            // Check existing circle generation
            let existing_gen: Option<(i64,)> = sqlx::query_as(
                "SELECT generation FROM circles WHERE space_uri = $1 FOR UPDATE",
            )
            .bind(&space)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            if let Some((curr_gen,)) = existing_gen {
                if curr_gen > generation {
                    // Stale delete for an older generation; a newer circle exists.
                    // Do NOT delete the newer circle or insert a tombstone that would delete it.
                    tx.commit().await.map_err(AppError::Database)?;
                    return Ok(());
                }
            }

            // Check if a higher tombstone already exists
            let higher_tombstone: Option<(i64,)> = sqlx::query_as(
                "SELECT generation FROM circle_tombstones WHERE space_uri = $1 AND generation > $2",
            )
            .bind(&space)
            .bind(generation)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            if higher_tombstone.is_some() {
                tx.commit().await.map_err(AppError::Database)?;
                return Ok(());
            }

            // 1. Insert deletion tombstone with generation
            sqlx::query(
                r#"
                INSERT INTO circle_tombstones (space_uri, generation, deleted_at)
                VALUES ($1, $2, now())
                ON CONFLICT (space_uri, generation) DO UPDATE SET deleted_at = now()
                "#,
            )
            .bind(&space)
            .bind(generation)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            // 2. Cascade delete from circles where generation <= $2
            sqlx::query("DELETE FROM circles WHERE space_uri = $1 AND generation <= $2")
                .bind(&space)
                .bind(generation)
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
