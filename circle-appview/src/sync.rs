use std::collections::HashSet;
use std::sync::Arc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::access::{
    extract_authority_did, resolve_pds_endpoint, resolve_space_host_endpoint, CredentialStore,
    SpaceLockManager,
};
use crate::auth::{select_verification_method, DidResolver};
use crate::commit::{compute_dagcbor_cid, decode_repo_car, verify_commit, LtHash, LTHASH_SIZE};
use crate::config::AppState;
use crate::error::AppError;
use crate::space_client::SpaceClient;
use crate::validator::{validate_record, InvalidRecord, RecordCandidate, ValidatedRecord, ValidationPolicy};
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

enum StagedMutation {
    UpsertRecord {
        valid: ValidatedRecord,
        cid: String,
    },
    DeleteRecord {
        uri: String,
    },
    Rejection {
        uri: String,
        reason: InvalidRecord,
    },
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

    pub async fn sync_repo(
        &self,
        space_uri: &str,
        author_did: &str,
    ) -> Result<SyncResult, AppError> {
        self.sync_repo_with_expected_hash(space_uri, author_did, None).await
    }

    pub async fn sync_repo_with_expected_hash(
        &self,
        space_uri: &str,
        author_did: &str,
        expected_authority_hash: Option<&[u8]>,
    ) -> Result<SyncResult, AppError> {
        let _lock_guard = self.space_locks.acquire(space_uri).await;

        let cred = self.credential_store.get(space_uri).await.ok_or_else(|| {
            AppError::Forbidden("No active Space credential in store for Space".into())
        })?;

        let authority_did = extract_authority_did(space_uri)?;
        let author_doc = self
            .did_resolver
            .resolve(author_did)
            .await
            .map_err(AppError::Unauthorized)?;
        let (repo_service_endpoint, _) = resolve_pds_endpoint(&author_doc, author_did)?;
        let author_vm = select_verification_method(&author_doc, author_did, None)
            .map_err(AppError::Unauthorized)?;
        let author_signing_key =
            crate::auth::parse_verification_key(author_vm).map_err(AppError::Unauthorized)?;

        // Load active members and post-only known post URIs to build ValidationPolicy
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

        let active_members_set: HashSet<String> =
            active_member_rows.into_iter().map(|(m,)| m).collect();

        let known_post_rows: Vec<(String,)> = sqlx::query_as(
            "SELECT uri FROM circle_records WHERE space_uri = $1 AND collection = 'app.bsky.feed.post' AND deleted_at IS NULL",
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

        // Incremental sync with pagination and direct DAG-CBOR CID verification
        let mut ops_applied = 0;
        let mut records_accepted = 0;
        let mut records_rejected = 0;
        let mut latest_rev = last_rev.clone().unwrap_or_default();

        let mut staged_mutations = Vec::new();
        let mut current_policy = policy.clone();

        let mut cursor: Option<String> = None;
        let mut terminal_commit = None;
        let mut fetch_failed = false;

        loop {
            let page_res = self
                .space_client
                .list_repo_ops(
                    &repo_service_endpoint,
                    space_uri,
                    author_did,
                    last_rev.as_deref(),
                    cursor.as_deref(),
                    &cred.token,
                    &cred.dpop_key,
                )
                .await;

            let page = match page_res {
                Ok(p) => p,
                Err(_) => {
                    fetch_failed = true;
                    break;
                }
            };

            for op in &page.ops {
                ops_applied += 1;
                latest_rev = op.rev.to_string();

                let collection_str = op.collection.as_str();
                let rkey_str = op.rkey.0.as_str();
                let uri = format!("{space_uri}/{author_did}/{collection_str}/{rkey_str}");

                if let Some(cid) = &op.cid {
                    let cid_str = cid.as_str();
                    if let Some(prev) = &op.prev {
                        lthash.remove(collection_str, rkey_str, prev.as_str());
                    }
                    lthash.add(collection_str, rkey_str, cid_str);

                    // Direct DAG-CBOR CID verification on Jacquard Data
                    if let Some(data_val) = &op.value {
                        let computed_cid = compute_dagcbor_cid(data_val);
                        match computed_cid {
                            Ok(c) if c == cid_str => {}
                            _ => {
                                fetch_failed = true;
                                break;
                            }
                        }
                    }

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

                    match validate_record(&candidate, &current_policy) {
                        Ok(valid) => {
                            records_accepted += 1;
                            if valid.collection == "app.bsky.feed.post" {
                                current_policy.known_post_uris.insert(valid.uri.clone());
                            }
                            staged_mutations.push(StagedMutation::UpsertRecord {
                                valid,
                                cid: cid_str.to_string(),
                            });
                        }
                        Err(invalid) => {
                            records_rejected += 1;
                            staged_mutations.push(StagedMutation::Rejection {
                                uri,
                                reason: invalid,
                            });
                        }
                    }
                } else {
                    // Deletion op
                    if let Some(prev) = &op.prev {
                        lthash.remove(collection_str, rkey_str, prev.as_str());
                    }
                    current_policy.known_post_uris.remove(&uri);
                    staged_mutations.push(StagedMutation::DeleteRecord { uri });
                }
            }

            if fetch_failed {
                break;
            }

            if let Some(c) = page.commit {
                terminal_commit = Some(c);
            }

            if let Some(next_cur) = page.cursor {
                if Some(&next_cur.to_string()) == cursor.as_ref() {
                    break;
                }
                cursor = Some(next_cur.to_string());
            } else {
                break;
            }
        }

        if fetch_failed {
            return self
                .full_recovery(
                    space_uri,
                    author_did,
                    &repo_service_endpoint,
                    &cred.token,
                    &cred.dpop_key,
                    &author_signing_key,
                    &policy,
                    expected_authority_hash,
                )
                .await;
        }

        let commit_to_verify = match terminal_commit {
            Some(c) => Some(c),
            None => self
                .space_client
                .get_latest_commit(
                    &repo_service_endpoint,
                    space_uri,
                    author_did,
                    &cred.token,
                    &cred.dpop_key,
                )
                .await
                .ok(),
        };

        let commit_verified = if let Some(commit) = &commit_to_verify {
            latest_rev = commit.rev.to_string();
            let verified = verify_commit(
                space_uri,
                author_did,
                commit,
                lthash.as_bytes(),
                &author_signing_key,
            )
            .is_ok();

            if verified {
                if let Some(expected_hash) = expected_authority_hash {
                    commit.hash.as_ref() == expected_hash
                } else {
                    true
                }
            } else {
                false
            }
        } else {
            false
        };

        if !commit_verified {
            return self
                .full_recovery(
                    space_uri,
                    author_did,
                    &repo_service_endpoint,
                    &cred.token,
                    &cred.dpop_key,
                    &author_signing_key,
                    &policy,
                    expected_authority_hash,
                )
                .await;
        }

        // Execute staged mutations in exact sequential order in a single transaction
        let mut tx = self.db.begin().await?;

        for mutation in staged_mutations {
            match mutation {
                StagedMutation::UpsertRecord { valid, cid } => {
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
                    .bind(&cid)
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
                            ON CONFLICT (uri) DO UPDATE SET
                                space_uri = EXCLUDED.space_uri,
                                post_uri = EXCLUDED.post_uri,
                                author_did = EXCLUDED.author_did,
                                created_at = EXCLUDED.created_at
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
                        let post_author: Option<(String,)> =
                            sqlx::query_as("SELECT author_did FROM circle_records WHERE uri = $1")
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
                        let parent_author: Option<(String,)> =
                            sqlx::query_as("SELECT author_did FROM circle_records WHERE uri = $1")
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
                StagedMutation::DeleteRecord { uri } => {
                    sqlx::query("UPDATE circle_records SET deleted_at = now() WHERE uri = $1")
                        .bind(&uri)
                        .execute(&mut *tx)
                        .await?;
                    sqlx::query("DELETE FROM circle_likes WHERE uri = $1")
                        .bind(&uri)
                        .execute(&mut *tx)
                        .await?;
                }
                StagedMutation::Rejection { uri, reason } => {
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
            }
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
    #[allow(clippy::too_many_arguments)]
    async fn full_recovery(
        &self,
        space_uri: &str,
        author_did: &str,
        service_endpoint: &str,
        space_credential: &str,
        dpop_key: &p256::ecdsa::SigningKey,
        author_signing_key: &crate::auth::ParsedVerifyingKey,
        policy: &ValidationPolicy,
        expected_authority_hash: Option<&[u8]>,
    ) -> Result<SyncResult, AppError> {
        let car_bytes = self
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

        let decoded_car = decode_repo_car(&car_bytes)
            .map_err(|e| AppError::Internal(format!("CAR decoding failed: {e}")))?;

        let mut pending_records = decoded_car.records;
        let mut staged_valid_records = Vec::new();
        let mut staged_rejections = Vec::new();
        let mut current_policy = policy.clone();
        let mut lthash = LtHash::new();
        let ops_applied = pending_records.len();
        let mut records_accepted = 0;
        let mut records_rejected = 0;

        for rec in &pending_records {
            lthash.add(&rec.collection, &rec.rkey, &rec.cid);
        }

        // Multi-pass resolution for intra-repo dependencies (posts before replies/likes)
        let mut progress = true;
        while progress && !pending_records.is_empty() {
            progress = false;
            let mut remaining = Vec::new();
            for rec in pending_records {
                let collection_str = rec.collection.as_str();
                let rkey_str = rec.rkey.as_str();
                let uri = format!("{space_uri}/{author_did}/{collection_str}/{rkey_str}");

                let candidate = RecordCandidate {
                    uri: uri.clone(),
                    author_did: author_did.to_string(),
                    collection: collection_str.to_string(),
                    rkey: rkey_str.to_string(),
                    value: rec.value.clone(),
                };

                match validate_record(&candidate, &current_policy) {
                    Ok(valid) => {
                        records_accepted += 1;
                        if valid.collection == "app.bsky.feed.post" {
                            current_policy.known_post_uris.insert(valid.uri.clone());
                        }
                        staged_valid_records.push((valid, rec.cid));
                        progress = true;
                    }
                    Err(InvalidRecord::CrossSpaceReference) => {
                        remaining.push((rec, uri, InvalidRecord::CrossSpaceReference));
                    }
                    Err(invalid) => {
                        records_rejected += 1;
                        staged_rejections.push((uri, invalid));
                    }
                }
            }
            if !progress {
                for (_rec, uri, err) in remaining {
                    records_rejected += 1;
                    staged_rejections.push((uri, err));
                }
                break;
            } else {
                pending_records = remaining.into_iter().map(|(r, _, _)| r).collect();
            }
        }

        // Verify root commit embedded in CAR against LtHash
        verify_commit(
            space_uri,
            author_did,
            &decoded_car.commit,
            lthash.as_bytes(),
            author_signing_key,
        )
        .map_err(|e| AppError::Internal(format!("Commit verification failed on CAR: {e}")))?;

        // Verify against expected authority hash if provided
        if let Some(expected_hash) = expected_authority_hash {
            if decoded_car.commit.hash.as_ref() != expected_hash {
                return Err(AppError::Internal(
                    "CAR commit hash does not match expected authority hash".into(),
                ));
            }
        }

        let latest_rev = decoded_car.commit.rev.to_string();

        let mut tx = self.db.begin().await?;

        // Upsert all valid records and track their URIs
        let mut recovered_uris: HashSet<String> = HashSet::new();

        for (valid, cid_str) in staged_valid_records {
            recovered_uris.insert(valid.uri.clone());
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
                    ON CONFLICT (uri) DO UPDATE SET
                        space_uri = EXCLUDED.space_uri,
                        post_uri = EXCLUDED.post_uri,
                        author_did = EXCLUDED.author_did,
                        created_at = EXCLUDED.created_at
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

        // Soft-delete author records that were deleted in the recovered repo
        let existing_records: Vec<(String,)> = sqlx::query_as(
            "SELECT uri FROM circle_records WHERE space_uri = $1 AND author_did = $2 AND deleted_at IS NULL",
        )
        .bind(space_uri)
        .bind(author_did)
        .fetch_all(&mut *tx)
        .await?;

        for (existing_uri,) in existing_records {
            if !recovered_uris.contains(&existing_uri) {
                sqlx::query("UPDATE circle_records SET deleted_at = now() WHERE uri = $1")
                    .bind(&existing_uri)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM circle_likes WHERE uri = $1")
                    .bind(&existing_uri)
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

    let active_spaces: Vec<(String,)> =
        sqlx::query_as("SELECT space_uri FROM circles WHERE deleted_at IS NULL")
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

        let (service_endpoint, _) =
            match resolve_space_host_endpoint(&authority_doc, &authority_did) {
                Ok(ep) => ep,
                Err(_) => continue,
            };
        let mut cursor: Option<String> = None;
        let mut seen_cursors = HashSet::new();

        loop {
            let list_repos_res = state
                .space_client
                .list_repos(
                    &service_endpoint,
                    &space_uri,
                    cursor.as_deref(),
                    &cred.token,
                    &cred.dpop_key,
                )
                .await;

            let repos_output = match list_repos_res {
                Ok(out) => out,
                Err(_) => break,
            };

            for repo in &repos_output.repos {
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
                    Some((last_rev, last_hash)) if last_hash.len() == LTHASH_SIZE => {
                        let digest: [u8; 32] = Sha256::digest(&last_hash).into();
                        last_rev != repo.rev.as_str() || &digest[..] != repo.hash.as_ref()
                    }
                    _ => true,
                };

                if needs_sync {
                    match sync_engine
                        .sync_repo_with_expected_hash(&space_uri, repo_did, Some(repo.hash.as_ref()))
                        .await
                    {
                        Ok(_) => summary.repos_synced += 1,
                        Err(_) => summary.repos_failed += 1,
                    }
                }
            }

            if let Some(next_cursor) = repos_output.cursor {
                let next_cur_str = next_cursor.to_string();
                if !seen_cursors.insert(next_cur_str.clone()) {
                    break;
                }
                cursor = Some(next_cur_str);
            } else {
                break;
            }
        }
    }

    Ok(summary)
}
