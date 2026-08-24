use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

use crate::access::{extract_authority_did, resolve_space_host_endpoint, CredentialStore, SpaceLockManager};
use crate::auth::{select_authority_verification_method, DidResolver};
use crate::commit::{verify_commit, LtHash, LTHASH_SIZE};
use crate::config::AppState;
use crate::error::AppError;
use crate::space_client::SpaceClient;
use crate::validator::{validate_record, RecordCandidate, ValidationPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    Incremental,
    FullRecovery,
}

#[derive(Debug, Clone)]
pub struct SyncResult {
    pub mode: SyncMode,
    pub commit_verified: bool,
    pub ops_applied: usize,
    pub records_accepted: usize,
    pub records_rejected: usize,
    pub latest_rev: String,
}

#[derive(Debug, Clone, Default)]
pub struct SweepSummary {
    pub spaces_checked: usize,
    pub repos_checked: usize,
    pub repos_synced: usize,
    pub repos_failed: usize,
}

pub struct SyncEngine {
    db: sqlx::PgPool,
    space_client: Arc<SpaceClient>,
    credential_store: Arc<CredentialStore>,
    did_resolver: Arc<DidResolver>,
    space_locks: Arc<SpaceLockManager>,
}

impl SyncEngine {
    pub fn new(state: &AppState) -> Self {
        Self {
            db: state.db.clone(),
            space_client: state.space_client.clone(),
            credential_store: state.credential_store.clone(),
            did_resolver: state.did_resolver.clone(),
            space_locks: state.space_locks.clone(),
        }
    }

    pub fn with_services(
        db: sqlx::PgPool,
        space_client: Arc<SpaceClient>,
        credential_store: Arc<CredentialStore>,
        did_resolver: Arc<DidResolver>,
        space_locks: Arc<SpaceLockManager>,
    ) -> Self {
        Self {
            db,
            space_client,
            credential_store,
            did_resolver,
            space_locks,
        }
    }

    pub async fn sync_repo(&self, space_uri: &str, author_did: &str) -> Result<SyncResult, AppError> {
        let _lock_guard = self.space_locks.acquire(space_uri).await;

        let cred = self
            .credential_store
            .get(space_uri)
            .await
            .ok_or_else(|| AppError::Forbidden("No active Space credential in store for Space".into()))?;

        let authority_did = extract_authority_did(space_uri)?;
        let authority_doc = self.did_resolver.resolve(&authority_did).await.map_err(AppError::Unauthorized)?;
        let (service_endpoint, _) = resolve_space_host_endpoint(&authority_doc, &authority_did)?;

        let author_doc = self.did_resolver.resolve(author_did).await.map_err(AppError::Unauthorized)?;
        let author_vm = select_authority_verification_method(&author_doc, author_did, None).map_err(AppError::Unauthorized)?;
        let author_signing_key = crate::auth::parse_verification_key(author_vm).map_err(AppError::Unauthorized)?;

        // Load active members and known post URIs to build ValidationPolicy
        let active_member_rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT m.member_did
            FROM circle_members m
            JOIN access_leases l ON l.space_uri = m.space_uri AND l.member_did = m.member_did
            WHERE m.space_uri = $1 AND m.status = 'active' AND l.expires_at > now()
            "#,
        )
        .bind(space_uri)
        .fetch_all(&self.db)
        .await?;

        let active_members_set: HashSet<String> = active_member_rows.into_iter().map(|(m,)| m).collect();

        let known_post_rows: Vec<(String,)> = sqlx::query_as(
            "SELECT uri FROM circle_records WHERE space_uri = $1 AND deleted_at IS NULL",
        )
        .bind(space_uri)
        .fetch_all(&self.db)
        .await?;

        let known_posts_set: HashSet<String> = known_post_rows.into_iter().map(|(u,)| u).collect();

        let policy = ValidationPolicy::new(&authority_did, active_members_set)
            .with_space_uri(space_uri)
            .with_known_post_uris(known_posts_set);

        // Load previous sync state
        let existing_sync: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT last_rev, last_hash FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2",
        )
        .bind(space_uri)
        .bind(author_did)
        .fetch_optional(&self.db)
        .await?;

        let (last_rev, mut lthash) = match existing_sync {
            Some((rev, hash_bytes)) if hash_bytes.len() == LTHASH_SIZE => {
                let mut arr = [0u8; LTHASH_SIZE];
                arr.copy_from_slice(&hash_bytes);
                (Some(rev), LtHash::from_bytes(arr))
            }
            _ => (None, LtHash::new()),
        };

        // Try incremental sync
        let list_ops_res = self
            .space_client
            .list_repo_ops(
                &service_endpoint,
                space_uri,
                author_did,
                last_rev.as_deref(),
                &cred.token,
                &cred.dpop_key,
            )
            .await;

        match list_ops_res {
            Ok(output) => {
                let mut ops_applied = 0;
                let mut records_accepted = 0;
                let mut records_rejected = 0;
                let mut latest_rev = last_rev.clone().unwrap_or_default();

                let mut staged_valid_records = Vec::new();
                let mut staged_rejections = Vec::new();
                let mut staged_deletes = Vec::new();

                for op in &output.ops {
                    ops_applied += 1;
                    latest_rev = op.rev.to_string();

                    let collection_str = op.collection.as_str();
                    let rkey_str = op.rkey.0.as_str();
                    let uri = format!("at://{author_did}/{collection_str}/{rkey_str}");

                    if let Some(cid) = &op.cid {
                        let cid_str = cid.as_str();
                        if let Some(prev) = &op.prev {
                            lthash.remove(collection_str, rkey_str, prev.as_str());
                        }
                        lthash.add(collection_str, rkey_str, cid_str);

                        let candidate_val = op
                            .value
                            .as_ref()
                            .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null))
                            .unwrap_or(serde_json::Value::Null);

                        let candidate = RecordCandidate {
                            uri: uri.clone(),
                            author_did: author_did.to_string(),
                            collection: collection_str.to_string(),
                            rkey: rkey_str.to_string(),
                            value: candidate_val,
                        };

                        match validate_record(&candidate, &policy) {
                            Ok(valid) => {
                                records_accepted += 1;
                                staged_valid_records.push((valid, cid_str.to_string()));
                            }
                            Err(invalid) => {
                                records_rejected += 1;
                                staged_rejections.push((uri, invalid));
                            }
                        }
                    } else {
                        // Deletion op
                        if let Some(prev) = &op.prev {
                            lthash.remove(collection_str, rkey_str, prev.as_str());
                        }
                        staged_deletes.push(uri);
                    }
                }

                // Verify commit
                let commit_to_verify = match output.commit {
                    Some(c) => Some(c),
                    None => {
                        self.space_client
                            .get_latest_commit(
                                &service_endpoint,
                                space_uri,
                                author_did,
                                &cred.token,
                                &cred.dpop_key,
                            )
                            .await
                            .ok()
                    }
                };

                let commit_verified = if let Some(commit) = &commit_to_verify {
                    latest_rev = commit.rev.to_string();
                    verify_commit(
                        space_uri,
                        author_did,
                        commit,
                        lthash.as_bytes(),
                        &author_signing_key,
                    )
                    .is_ok()
                } else {
                    ops_applied == 0
                };

                if !commit_verified {
                    // Hash mismatch or invalid commit -> Fall back to full recovery
                    return self
                        .full_recovery(
                            space_uri,
                            author_did,
                            &service_endpoint,
                            &cred.token,
                            &cred.dpop_key,
                            &author_signing_key,
                            &policy,
                        )
                        .await;
                }

                // Transactional apply
                let mut tx = self.db.begin().await?;

                for (valid, cid_str) in staged_valid_records {
                    sqlx::query(
                        r#"
                        INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, indexed_at, created_at, parent_uri, root_uri)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9, $10)
                        ON CONFLICT (uri) DO UPDATE SET
                            cid = EXCLUDED.cid,
                            record_json = EXCLUDED.record_json,
                            indexed_at = now(),
                            parent_uri = EXCLUDED.parent_uri,
                            root_uri = EXCLUDED.root_uri,
                            deleted_at = NULL
                        "#,
                    )
                    .bind(&valid.uri)
                    .bind(&cid_str)
                    .bind(space_uri)
                    .bind(&valid.author_did)
                    .bind(&valid.collection)
                    .bind(&valid.rkey)
                    .bind(&valid.record_json)
                    .bind(valid.created_at)
                    .bind(&valid.parent_uri)
                    .bind(&valid.root_uri)
                    .execute(&mut *tx)
                    .await?;

                    if let Some(post_uri) = &valid.post_uri {
                        sqlx::query(
                            r#"
                            INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at)
                            VALUES ($1, $2, $3, $4, $5)
                            ON CONFLICT (uri) DO NOTHING
                            "#,
                        )
                        .bind(&valid.uri)
                        .bind(space_uri)
                        .bind(post_uri)
                        .bind(&valid.author_did)
                        .bind(valid.created_at)
                        .execute(&mut *tx)
                        .await?;

                        // Create notification for like
                        let post_author: Option<(String,)> = sqlx::query_as(
                            "SELECT author_did FROM circle_records WHERE uri = $1",
                        )
                        .bind(post_uri)
                        .fetch_optional(&mut *tx)
                        .await?;

                        if let Some((recipient,)) = post_author {
                            if recipient != valid.author_did {
                                sqlx::query(
                                    r#"
                                    INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, is_read, created_at)
                                    VALUES ($1, $2, $3, $4, 'like', $5, false, now())
                                    "#,
                                )
                                .bind(Uuid::new_v4())
                                .bind(&recipient)
                                .bind(space_uri)
                                .bind(&valid.author_did)
                                .bind(post_uri)
                                .execute(&mut *tx)
                                .await?;
                            }
                        }
                    } else if let Some(parent_uri) = &valid.parent_uri {
                        // Create notification for reply
                        let parent_author: Option<(String,)> = sqlx::query_as(
                            "SELECT author_did FROM circle_records WHERE uri = $1",
                        )
                        .bind(parent_uri)
                        .fetch_optional(&mut *tx)
                        .await?;

                        if let Some((recipient,)) = parent_author {
                            if recipient != valid.author_did {
                                sqlx::query(
                                    r#"
                                    INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, is_read, created_at)
                                    VALUES ($1, $2, $3, $4, 'reply', $5, false, now())
                                    "#,
                                )
                                .bind(Uuid::new_v4())
                                .bind(&recipient)
                                .bind(space_uri)
                                .bind(&valid.author_did)
                                .bind(&valid.uri)
                                .execute(&mut *tx)
                                .await?;
                            }
                        }
                    }
                }

                for uri in staged_deletes {
                    sqlx::query("UPDATE circle_records SET deleted_at = now() WHERE uri = $1")
                        .bind(&uri)
                        .execute(&mut *tx)
                        .await?;
                }

                for (uri, reason) in staged_rejections {
                    let uri_hash = crate::validator::compute_uri_hash(&uri);
                    sqlx::query(
                        r#"
                        INSERT INTO circle_rejections (uri_hash, reason_code, observed_at)
                        VALUES ($1, $2, now())
                        ON CONFLICT (uri_hash) DO NOTHING
                        "#,
                    )
                    .bind(&uri_hash)
                    .bind(reason.reason_code())
                    .execute(&mut *tx)
                    .await?;
                }

                // Update sync state
                sqlx::query(
                    r#"
                    INSERT INTO circle_repo_sync_state (space_uri, author_did, last_rev, last_hash, last_synced_at)
                    VALUES ($1, $2, $3, $4, now())
                    ON CONFLICT (space_uri, author_did) DO UPDATE SET
                        last_rev = EXCLUDED.last_rev,
                        last_hash = EXCLUDED.last_hash,
                        last_synced_at = now()
                    "#,
                )
                .bind(space_uri)
                .bind(author_did)
                .bind(&latest_rev)
                .bind(lthash.as_bytes().as_slice())
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;

                Ok(SyncResult {
                    mode: SyncMode::Incremental,
                    commit_verified: true,
                    ops_applied,
                    records_accepted,
                    records_rejected,
                    latest_rev,
                })
            }
            Err(_) => {
                // Incremental fetch error (e.g. compacted oplog) -> Fall back to full recovery
                self.full_recovery(
                    space_uri,
                    author_did,
                    &service_endpoint,
                    &cred.token,
                    &cred.dpop_key,
                    &author_signing_key,
                    &policy,
                )
                .await
            }
        }
    }

    async fn full_recovery(
        &self,
        space_uri: &str,
        author_did: &str,
        service_endpoint: &str,
        space_credential: &str,
        dpop_key: &p256::ecdsa::SigningKey,
        author_signing_key: &crate::auth::ParsedVerifyingKey,
        policy: &ValidationPolicy,
    ) -> Result<SyncResult, AppError> {
        let mut lthash = LtHash::new();

        let repo_ops = self
            .space_client
            .get_repo(
                service_endpoint,
                space_uri,
                author_did,
                None,
                space_credential,
                dpop_key,
            )
            .await?;

        let latest_commit = self
            .space_client
            .get_latest_commit(
                service_endpoint,
                space_uri,
                author_did,
                space_credential,
                dpop_key,
            )
            .await?;

        let mut staged_valid_records = Vec::new();
        let mut staged_rejections = Vec::new();
        let mut ops_applied = 0;
        let mut records_accepted = 0;
        let mut records_rejected = 0;

        for op in repo_ops {
            ops_applied += 1;
            let collection_str = op.collection.as_str();
            let rkey_str = op.rkey.0.as_str();
            let uri = format!("at://{author_did}/{collection_str}/{rkey_str}");

            if let Some(cid) = &op.cid {
                let cid_str = cid.as_str();
                lthash.add(collection_str, rkey_str, cid_str);

                let candidate_val = op
                    .value
                    .as_ref()
                    .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null))
                    .unwrap_or(serde_json::Value::Null);

                let candidate = RecordCandidate {
                    uri: uri.clone(),
                    author_did: author_did.to_string(),
                    collection: collection_str.to_string(),
                    rkey: rkey_str.to_string(),
                    value: candidate_val,
                };

                match validate_record(&candidate, policy) {
                    Ok(valid) => {
                        records_accepted += 1;
                        staged_valid_records.push((valid, cid_str.to_string()));
                    }
                    Err(invalid) => {
                        records_rejected += 1;
                        staged_rejections.push((uri, invalid));
                    }
                }
            }
        }

        verify_commit(
            space_uri,
            author_did,
            &latest_commit,
            lthash.as_bytes(),
            author_signing_key,
        )
        .map_err(|e| AppError::Internal(format!("Commit verification failed during full recovery: {e}")))?;

        let latest_rev = latest_commit.rev.to_string();

        let mut tx = self.db.begin().await?;

        // Clear existing records and likes for full rebuild
        sqlx::query("DELETE FROM circle_records WHERE space_uri = $1 AND author_did = $2")
            .bind(space_uri)
            .bind(author_did)
            .execute(&mut *tx)
            .await?;

        for (valid, cid_str) in staged_valid_records {
            sqlx::query(
                r#"
                INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, indexed_at, created_at, parent_uri, root_uri)
                VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9, $10)
                ON CONFLICT (uri) DO UPDATE SET
                    cid = EXCLUDED.cid,
                    record_json = EXCLUDED.record_json,
                    indexed_at = now(),
                    parent_uri = EXCLUDED.parent_uri,
                    root_uri = EXCLUDED.root_uri,
                    deleted_at = NULL
                "#,
            )
            .bind(&valid.uri)
            .bind(&cid_str)
            .bind(space_uri)
            .bind(&valid.author_did)
            .bind(&valid.collection)
            .bind(&valid.rkey)
            .bind(&valid.record_json)
            .bind(valid.created_at)
            .bind(&valid.parent_uri)
            .bind(&valid.root_uri)
            .execute(&mut *tx)
            .await?;

            if let Some(post_uri) = &valid.post_uri {
                sqlx::query(
                    r#"
                    INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (uri) DO NOTHING
                    "#,
                )
                .bind(&valid.uri)
                .bind(space_uri)
                .bind(post_uri)
                .bind(&valid.author_did)
                .bind(valid.created_at)
                .execute(&mut *tx)
                .await?;
            }
        }

        for (uri, reason) in staged_rejections {
            let uri_hash = crate::validator::compute_uri_hash(&uri);
            sqlx::query(
                r#"
                INSERT INTO circle_rejections (uri_hash, reason_code, observed_at)
                VALUES ($1, $2, now())
                ON CONFLICT (uri_hash) DO NOTHING
                "#,
            )
            .bind(&uri_hash)
            .bind(reason.reason_code())
            .execute(&mut *tx)
            .await?;
        }

        // Upsert sync state
        sqlx::query(
            r#"
            INSERT INTO circle_repo_sync_state (space_uri, author_did, last_rev, last_hash, last_synced_at)
            VALUES ($1, $2, $3, $4, now())
            ON CONFLICT (space_uri, author_did) DO UPDATE SET
                last_rev = EXCLUDED.last_rev,
                last_hash = EXCLUDED.last_hash,
                last_synced_at = now()
            "#,
        )
        .bind(space_uri)
        .bind(author_did)
        .bind(&latest_rev)
        .bind(lthash.as_bytes().as_slice())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(SyncResult {
            mode: SyncMode::FullRecovery,
            commit_verified: true,
            ops_applied,
            records_accepted,
            records_rejected,
            latest_rev,
        })
    }
}

pub async fn sweep_once(state: &AppState) -> Result<SweepSummary, AppError> {
    let sync_engine = SyncEngine::new(state);
    let mut summary = SweepSummary::default();

    let active_spaces: Vec<(String,)> = sqlx::query_as(
        "SELECT space_uri FROM circles WHERE deleted_at IS NULL",
    )
    .fetch_all(&state.db)
    .await?;

    for (space_uri,) in active_spaces {
        summary.spaces_checked += 1;
        let cred = match state.credential_store.get(&space_uri).await {
            Some(c) => c,
            None => continue,
        };
        let authority_did = match extract_authority_did(&space_uri) {
            Ok(a) => a,
            Err(_) => continue,
        };

        let authority_doc = match state.did_resolver.resolve(&authority_did).await {
            Ok(d) => d,
            Err(_) => continue,
        };

        let (service_endpoint, _) = match resolve_space_host_endpoint(&authority_doc, &authority_did) {
            Ok(ep) => ep,
            Err(_) => continue,
        };

        let list_repos_res = state
            .space_client
            .list_repos(&service_endpoint, &space_uri, &cred.token, &cred.dpop_key)
            .await;

        let repos_output = match list_repos_res {
            Ok(out) => out,
            Err(_) => continue,
        };

        for repo in repos_output.repos {
            summary.repos_checked += 1;
            let repo_did = repo.did.as_str();

            let db_sync: Option<(String, Vec<u8>)> = sqlx::query_as(
                "SELECT last_rev, last_hash FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2",
            )
            .bind(&space_uri)
            .bind(repo_did)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

            let needs_sync = match db_sync {
                Some((last_rev, last_hash)) => {
                    last_rev != repo.rev.as_str() || last_hash.as_slice() != repo.hash.as_ref()
                }
                None => true,
            };

            if needs_sync {
                match sync_engine.sync_repo(&space_uri, repo_did).await {
                    Ok(_) => summary.repos_synced += 1,
                    Err(_) => summary.repos_failed += 1,
                }
            }
        }
    }

    Ok(summary)
}
