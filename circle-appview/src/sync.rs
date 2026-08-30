use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

use crate::access::{
    extract_authority_did, resolve_pds_endpoint, resolve_space_host_endpoint, CredentialStore,
    SpaceLockManager,
};
use crate::auth::{select_verification_method, DidResolver};
use crate::commit::{
    compute_dagcbor_cid, extract_and_validate_car_with_policy, parse_permissioned_car,
    verify_commit_with_policy, CommitContext, CommitContextV2, CommitVerificationPolicy, LtHash,
    LTHASH_SIZE,
};
use crate::config::AppState;
use crate::error::AppError;
use crate::space_client::SpaceClient;
use crate::validator::{
    validate_record, InvalidRecord, RecordCandidate, ValidatedRecord, ValidationPolicy,
};

pub const MAX_PAGES_PER_SWEEP: usize = 50;
pub const MAX_REPOS_PER_SWEEP: usize = 100;
pub const MAX_BYTES_PER_SWEEP: usize = 10 * 1024 * 1024;
pub const MAX_TIME_PER_SWEEP_SECS: u64 = 30;
pub const MAX_CURSOR_LEN: usize = 512;
pub const MAX_PAGES_PER_REPO_SYNC: usize = 50;
pub const MAX_OPS_PER_REPO_SYNC: usize = 5_000;
pub const MAX_BYTES_PER_REPO_SYNC: usize = 10 * 1024 * 1024;
pub const MAX_TIME_PER_REPO_SYNC_SECS: u64 = 30;

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
    pub bytes_processed: usize,
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
    oauth_service: Option<Arc<crate::oauth::OAuthService>>,
    http_client: reqwest::Client,
    push_client: Option<Arc<crate::push::CirclePushClient>>,
    commit_verification_policy: CommitVerificationPolicy,
    total_bytes_processed: Arc<std::sync::atomic::AtomicUsize>,
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
        rev: String,
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
            oauth_service: Some(state.oauth_service.clone()),
            http_client: state.http_client.clone(),
            push_client: state.push_client.clone(),
            commit_verification_policy: state.config.commit_verification_policy.clone(),
            total_bytes_processed: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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
            oauth_service: None,
            http_client: reqwest::Client::new(),
            push_client: None,
            commit_verification_policy: CommitVerificationPolicy::default(),
            total_bytes_processed: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub fn with_oauth_service(mut self, oauth_service: Arc<crate::oauth::OAuthService>) -> Self {
        self.oauth_service = Some(oauth_service);
        self
    }
    pub fn with_push_client(mut self, push_client: Arc<crate::push::CirclePushClient>) -> Self {
        self.push_client = Some(push_client);
        self
    }
    pub fn with_commit_verification_policy(mut self, policy: CommitVerificationPolicy) -> Self {
        self.commit_verification_policy = policy;
        self
    }
    pub fn total_bytes_processed(&self) -> usize {
        self.total_bytes_processed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn record_bytes_processed(&self, bytes: usize) {
        self.total_bytes_processed
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    }
    pub async fn sync_repo(
        &self,
        space_uri: &str,
        author_did: &str,
    ) -> Result<SyncResult, AppError> {
        self.sync_repo_with_expected_commit(space_uri, author_did, None, None)
            .await
    }

    pub async fn sync_repo_with_expected_hash(
        &self,
        space_uri: &str,
        author_did: &str,
        expected_authority_hash: Option<&[u8]>,
    ) -> Result<SyncResult, AppError> {
        self.sync_repo_with_expected_commit(space_uri, author_did, expected_authority_hash, None)
            .await
    }

    #[allow(clippy::type_complexity)]
    pub async fn sync_repo_with_expected_commit(
        &self,
        space_uri: &str,
        author_did: &str,
        expected_authority_hash: Option<&[u8]>,
        expected_authority_rev: Option<&str>,
    ) -> Result<SyncResult, AppError> {
        let circle_active: Option<(bool,)> = sqlx::query_as(
            "SELECT app_access_granted FROM circles WHERE space_uri = $1 AND deleted_at IS NULL",
        )
        .bind(space_uri)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::Database)?;

        if !circle_active.is_some_and(|(granted,)| granted) {
            return Err(AppError::Forbidden(
                "Space is deleted or appAccess revoked".into(),
            ));
        }

        // Finding 17 & 36: Membership and generation pre-check before lock acquisition, Space credential creation, or network calls
        let initial_membership: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT meta.generation
            FROM circle_member_cache m
            JOIN circle_member_cache_meta meta ON meta.space_uri = m.space_uri
            WHERE m.space_uri = $1 AND m.member_did = $2
            "#,
        )
        .bind(space_uri)
        .bind(author_did)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::Database)?;

        let authority_did = extract_authority_did(space_uri)?;
        let _initial_generation = match initial_membership {
            Some((gen,)) => Some(gen),
            None => {
                if author_did == authority_did {
                    None
                } else {
                    return Err(AppError::Forbidden(
                        "Author is not an active member with appAccess for this Space".into(),
                    ));
                }
            }
        };

        let _lock_guard = self.space_locks.acquire(space_uri).await;

        let cred = match self.credential_store.get(space_uri).await {
            Some(c) => c,
            None => {
                if let Some(oauth) = &self.oauth_service {
                    crate::access::ensure_space_credential_from_parts(
                        &self.db,
                        &self.space_client,
                        &self.credential_store,
                        &self.did_resolver,
                        oauth,
                        &self.http_client,
                        space_uri,
                        Some(author_did),
                    )
                    .await?
                } else {
                    return Err(AppError::Forbidden(
                        "No active Space credential in store for Space".into(),
                    ));
                }
            }
        };

        let author_doc = self
            .did_resolver
            .resolve(author_did)
            .await
            .map_err(|e| match e {
                crate::error::AuthReason::SsrfBlocked => {
                    AppError::Unauthorized(crate::error::AuthReason::SsrfBlocked)
                }
                other => AppError::Internal(format!(
                    "Failed to resolve DID document for {author_did}: {other}"
                )),
            })?;
        let (repo_service_endpoint, _) = resolve_pds_endpoint(&author_doc, author_did)?;
        let author_vm = select_verification_method(&author_doc, author_did, None)
            .map_err(AppError::Unauthorized)?;
        let author_signing_key =
            crate::auth::parse_verification_key(author_vm).map_err(AppError::Unauthorized)?;

        // Load active members and post-only known post URIs to build ValidationPolicy
        let active_member_rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT member_did
            FROM circle_member_cache
            WHERE space_uri = $1
            "#,
        )
        .bind(space_uri)
        .fetch_all(&self.db)
        .await?;

        let active_members_set: HashSet<String> =
            active_member_rows.into_iter().map(|(m,)| m).collect();

        let known_post_rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT uri, cid FROM circle_records WHERE space_uri = $1 AND collection = 'app.bsky.feed.post' AND deleted_at IS NULL",
        )
        .bind(space_uri)
        .fetch_all(&self.db)
        .await?;

        let policy = ValidationPolicy::new(&authority_did, active_members_set)
            .with_space_uri(space_uri)
            .with_known_posts(known_post_rows);

        // Load previous sync state
        let existing_sync: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT last_rev, last_hash FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2",
        )
        .bind(space_uri)
        .bind(author_did)
        .fetch_optional(&self.db)
        .await?;

        let (last_rev, mut lthash) = match &existing_sync {
            Some((rev, hash_bytes)) if hash_bytes.len() == LTHASH_SIZE => (
                Some(rev.clone()),
                LtHash::from_state(hash_bytes).unwrap_or_default(),
            ),
            _ => (None, LtHash::default()),
        };

        // Incremental sync with pagination and direct DAG-CBOR CID verification
        let mut ops_applied = 0;
        let mut records_accepted = 0;
        let mut records_rejected = 0;
        let mut latest_rev = last_rev.clone().unwrap_or_default();

        let mut staged_mutations = Vec::new();
        let mut current_policy = policy.clone();

        let mut seen_cursors: HashSet<String> = HashSet::new();
        let mut cursor: Option<String> = None;
        let mut terminal_commit = None;
        let mut fetch_failed = false;
        let mut last_applied_op: Option<(
            String,
            String,
            Option<String>,
            Option<String>,
            bytes::Bytes,
        )> = None;
        let mut page_count = 0;
        let mut total_bytes = 0;
        let start_time = std::time::Instant::now();

        let mut snapshotted_prev_rev = existing_sync
            .as_ref()
            .map(|(r, _)| r.clone())
            .unwrap_or_default();
        let mut snapshotted_prev_hash = {
            let mut prev_h = [0u8; 32];
            if let Some((_, h)) = &existing_sync {
                if h.len() == 32 {
                    prev_h.copy_from_slice(h);
                } else if h.len() == LTHASH_SIZE {
                    let digest = Sha256::digest(h);
                    prev_h.copy_from_slice(&digest);
                }
            } else {
                prev_h = lthash.digest();
            }
            prev_h
        };
        let mut last_applied_rev: Option<String> = None;
        loop {
            if page_count >= MAX_PAGES_PER_REPO_SYNC
                || ops_applied >= MAX_OPS_PER_REPO_SYNC
                || total_bytes >= MAX_BYTES_PER_REPO_SYNC
                || start_time.elapsed().as_secs() >= MAX_TIME_PER_REPO_SYNC_SECS
            {
                fetch_failed = true;
                break;
            }
            page_count += 1;

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
                if ops_applied >= MAX_OPS_PER_REPO_SYNC {
                    fetch_failed = true;
                    break;
                }
                ops_applied += 1;
                latest_rev = op.rev.to_string();

                let collection_str = op.collection.as_str();
                let rkey_str = op.rkey.0.as_str();
                let uri = format!("{space_uri}/{author_did}/{collection_str}/{rkey_str}");

                // Snapshot LtHash and rev before folding in this operation (Finding 6 / Item 4)
                snapshotted_prev_hash = lthash.digest();
                if let Some(r) = &last_applied_rev {
                    snapshotted_prev_rev = r.clone();
                }

                if let Some(cid) = &op.cid {
                    let cid_str = cid.as_str();
                    let data_val = match &op.value {
                        Some(val) => val,
                        None => {
                            // Missing operation value for CID - reject atomically without modifying LtHash or staging mutations (Finding 18 / Item 3)
                            fetch_failed = true;
                            break;
                        }
                    };

                    let computed_cid = match compute_dagcbor_cid(data_val) {
                        Ok(c) => c,
                        Err(_) => {
                            fetch_failed = true;
                            break;
                        }
                    };

                    if computed_cid != cid_str {
                        fetch_failed = true;
                        break;
                    }
                    let val_bytes = match serde_ipld_dagcbor::to_vec(data_val) {
                        Ok(b) => b,
                        Err(_) => {
                            fetch_failed = true;
                            break;
                        }
                    };
                    total_bytes += val_bytes.len();
                    self.record_bytes_processed(val_bytes.len());

                    if let Some(prev) = &op.prev {
                        lthash.remove(&format!("{collection_str}/{rkey_str}/{}", prev.as_str()));
                    }
                    lthash.add(&format!("{collection_str}/{rkey_str}/{cid_str}"));

                    last_applied_op = Some((
                        format!("{collection_str}/{rkey_str}"),
                        if op.prev.is_some() {
                            "update".to_string()
                        } else {
                            "create".to_string()
                        },
                        Some(cid_str.to_string()),
                        op.prev.as_ref().map(|p| p.to_string()),
                        bytes::Bytes::from(val_bytes),
                    ));

                    let candidate_val =
                        serde_json::to_value(data_val).unwrap_or(serde_json::Value::Null);

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
                                current_policy.add_post(valid.uri.clone(), cid_str.to_string());
                            }
                            staged_mutations.push(StagedMutation::UpsertRecord {
                                valid,
                                cid: cid_str.to_string(),
                            });
                        }
                        Err(invalid) => {
                            records_rejected += 1;
                            current_policy.remove_post(&uri);
                            staged_mutations.push(StagedMutation::Rejection {
                                uri,
                                reason: invalid,
                                rev: op.rev.to_string(),
                            });
                        }
                    }
                } else {
                    if let Some(prev) = &op.prev {
                        lthash.remove(&format!("{collection_str}/{rkey_str}/{}", prev.as_str()));
                    }
                    last_applied_op = Some((
                        format!("{collection_str}/{rkey_str}"),
                        "delete".to_string(),
                        None,
                        op.prev.as_ref().map(|p| p.to_string()),
                        bytes::Bytes::new(),
                    ));
                    current_policy.remove_post(&uri);
                    staged_mutations.push(StagedMutation::DeleteRecord { uri });
                }
                last_applied_rev = Some(op.rev.to_string());
            }

            if fetch_failed {
                break;
            }

            if let Some(c) = page.commit {
                terminal_commit = Some(c);
            }

            if let Some(next_cur) = page.cursor {
                let cur_str = next_cur.to_string();
                if cur_str.len() > MAX_CURSOR_LEN
                    || seen_cursors.len() >= MAX_PAGES_PER_REPO_SYNC
                    || !seen_cursors.insert(cur_str.clone())
                {
                    fetch_failed = true;
                    break;
                }
                cursor = Some(cur_str);
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
                    expected_authority_rev,
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
            let hash_matches = commit.hash.as_ref() == lthash.digest().as_slice();
            if !hash_matches {
                false
            } else {
                let space_uri_parsed =
                    match jacquard_common::types::aturi::AtSpaceUri::new_owned(space_uri) {
                        Ok(u) => u,
                        Err(_) => {
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
                                    expected_authority_rev,
                                )
                                .await;
                        }
                    };
                let author_did_parsed =
                    match jacquard_common::types::did::Did::new_owned(author_did) {
                        Ok(d) => d,
                        Err(_) => {
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
                                    expected_authority_rev,
                                )
                                .await;
                        }
                    };

                let context_v1 = CommitContext {
                    space: space_uri_parsed,
                    author: author_did_parsed,
                    rev: commit.rev.clone(),
                };

                let current_hash_digest: [u8; 32] = lthash.digest();

                // Construct CommitContextV2 using trusted local state (Finding 18 / Item 4)
                let (path, action, cid, prev_cid, val) =
                    if let Some((p, act, c, prev_c, v)) = last_applied_op {
                        (p, act, c, prev_c, v)
                    } else {
                        (
                            "".to_string(),
                            "".to_string(),
                            None,
                            None,
                            bytes::Bytes::new(),
                        )
                    };

                let context_v2 = CommitContextV2 {
                    space: space_uri.to_string(),
                    author: author_did.to_string(),
                    rev: commit.rev.to_string(),
                    prev_rev: snapshotted_prev_rev,
                    hash: current_hash_digest,
                    prev_hash: snapshotted_prev_hash,
                    path,
                    action,
                    cid,
                    prev_cid,
                    val,
                };

                let policy_ver_res = verify_commit_with_policy(
                    commit,
                    Some(&context_v1),
                    Some(&context_v2),
                    &author_signing_key,
                    &self.commit_verification_policy,
                );

                if policy_ver_res.is_ok() {
                    let hash_ok = match expected_authority_hash {
                        Some(expected_hash) => commit.hash.as_ref() == expected_hash,
                        None => true,
                    };
                    let rev_ok = match expected_authority_rev {
                        Some(expected_rev) => commit.rev.as_str() == expected_rev,
                        None => true,
                    };
                    hash_ok && rev_ok
                } else {
                    false
                }
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
                    expected_authority_rev,
                )
                .await;
        }

        // Execute staged mutations in exact sequential order in a single transaction
        let mut tx = self.db.begin().await?;
        let mut new_notification_recipients: HashSet<String> = HashSet::new();

        for mutation in staged_mutations {
            match mutation {
                StagedMutation::UpsertRecord { valid, cid } => {
                    let existing_rec_cid: Option<String> = sqlx::query_as::<_, (String,)>(
                        "SELECT cid FROM circle_records WHERE uri = $1 AND deleted_at IS NULL",
                    )
                    .bind(&valid.uri)
                    .fetch_optional(&mut *tx)
                    .await?
                    .map(|(c,)| c);

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
                            sqlx::query_as("SELECT author_did FROM circle_records WHERE uri = $1 AND deleted_at IS NULL")
                                .bind(post_uri)
                                .fetch_optional(&mut *tx)
                                .await?;

                        if let Some((recipient,)) = post_author {
                            let author_is_member: Option<(String,)> = sqlx::query_as(
                                "SELECT member_did FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2",
                            )
                            .bind(space_uri)
                            .bind(&valid.author_did)
                            .fetch_optional(&mut *tx)
                            .await?;

                            let recipient_is_member: Option<(String,)> = sqlx::query_as(
                                "SELECT member_did FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2",
                            )
                            .bind(space_uri)
                            .bind(&recipient)
                            .fetch_optional(&mut *tx)
                            .await?;

                            if recipient != valid.author_did
                                && author_is_member.is_some()
                                && recipient_is_member.is_some()
                            {
                                let existing_notif: Option<(Uuid, String, String, String, String, Option<String>)> = sqlx::query_as(
                                    "SELECT id, recipient_did, space_uri, actor_did, reason, subject_uri FROM circle_notifications WHERE source_uri = $1",
                                )
                                .bind(&valid.uri)
                                .fetch_optional(&mut *tx)
                                .await?;

                                let is_unchanged = if let Some(old_cid) = &existing_rec_cid {
                                    if old_cid == &cid {
                                        if let Some((_, rec, sp, act, rsn, subj)) = &existing_notif
                                        {
                                            rec == &recipient
                                                && sp == space_uri
                                                && act == &valid.author_did
                                                && rsn == "like"
                                                && subj.as_deref() == Some(post_uri)
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };

                                if !is_unchanged {
                                    sqlx::query(
                                        "DELETE FROM circle_notifications WHERE source_uri = $1",
                                    )
                                    .bind(&valid.uri)
                                    .execute(&mut *tx)
                                    .await?;

                                    sqlx::query(
                                        r#"
                                        INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
                                        VALUES ($1, $2, $3, $4, 'like', $5, $6, false, now())
                                        "#,
                                    )
                                    .bind(Uuid::new_v4())
                                    .bind(&recipient)
                                    .bind(space_uri)
                                    .bind(&valid.author_did)
                                    .bind(post_uri)
                                    .bind(&valid.uri)
                                    .execute(&mut *tx)
                                    .await?;
                                    new_notification_recipients.insert(recipient);
                                }
                            } else {
                                sqlx::query(
                                    "DELETE FROM circle_notifications WHERE source_uri = $1",
                                )
                                .bind(&valid.uri)
                                .execute(&mut *tx)
                                .await?;
                            }
                        } else {
                            sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1")
                                .bind(&valid.uri)
                                .execute(&mut *tx)
                                .await?;
                        }
                    } else if let Some(parent_uri) = &valid.parent_uri {
                        // Create notification for reply
                        let parent_author: Option<(String,)> =
                            sqlx::query_as("SELECT author_did FROM circle_records WHERE uri = $1 AND deleted_at IS NULL")
                                .bind(parent_uri)
                                .fetch_optional(&mut *tx)
                                .await?;

                        if let Some((recipient,)) = parent_author {
                            let author_is_member: Option<(String,)> = sqlx::query_as(
                                "SELECT member_did FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2",
                            )
                            .bind(space_uri)
                            .bind(&valid.author_did)
                            .fetch_optional(&mut *tx)
                            .await?;

                            let recipient_is_member: Option<(String,)> = sqlx::query_as(
                                "SELECT member_did FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2",
                            )
                            .bind(space_uri)
                            .bind(&recipient)
                            .fetch_optional(&mut *tx)
                            .await?;

                            if recipient != valid.author_did
                                && author_is_member.is_some()
                                && recipient_is_member.is_some()
                            {
                                let existing_notif: Option<(Uuid, String, String, String, String, Option<String>)> = sqlx::query_as(
                                    "SELECT id, recipient_did, space_uri, actor_did, reason, subject_uri FROM circle_notifications WHERE source_uri = $1",
                                )
                                .bind(&valid.uri)
                                .fetch_optional(&mut *tx)
                                .await?;

                                let is_unchanged = if let Some(old_cid) = &existing_rec_cid {
                                    if old_cid == &cid {
                                        if let Some((_, rec, sp, act, rsn, subj)) = &existing_notif
                                        {
                                            rec == &recipient
                                                && sp == space_uri
                                                && act == &valid.author_did
                                                && rsn == "reply"
                                                && subj.as_deref() == Some(&valid.uri)
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };

                                if !is_unchanged {
                                    sqlx::query(
                                        "DELETE FROM circle_notifications WHERE source_uri = $1",
                                    )
                                    .bind(&valid.uri)
                                    .execute(&mut *tx)
                                    .await?;

                                    sqlx::query(
                                        r#"
                                        INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
                                        VALUES ($1, $2, $3, $4, 'reply', $5, $6, false, now())
                                        "#,
                                    )
                                    .bind(Uuid::new_v4())
                                    .bind(&recipient)
                                    .bind(space_uri)
                                    .bind(&valid.author_did)
                                    .bind(&valid.uri)
                                    .bind(&valid.uri)
                                    .execute(&mut *tx)
                                    .await?;
                                    new_notification_recipients.insert(recipient);
                                }
                            } else {
                                sqlx::query(
                                    "DELETE FROM circle_notifications WHERE source_uri = $1",
                                )
                                .bind(&valid.uri)
                                .execute(&mut *tx)
                                .await?;
                            }
                        } else {
                            sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1")
                                .bind(&valid.uri)
                                .execute(&mut *tx)
                                .await?;
                        }
                    } else {
                        sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1")
                            .bind(&valid.uri)
                            .execute(&mut *tx)
                            .await?;
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
                    sqlx::query("DELETE FROM circle_likes WHERE post_uri = $1")
                        .bind(&uri)
                        .execute(&mut *tx)
                        .await?;
                    sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1 OR subject_uri = $1")
                        .bind(&uri)
                        .execute(&mut *tx)
                        .await?;
                }
                StagedMutation::Rejection { uri, reason, rev } => {
                    sqlx::query("UPDATE circle_records SET deleted_at = now() WHERE uri = $1")
                        .bind(&uri)
                        .execute(&mut *tx)
                        .await?;
                    sqlx::query("DELETE FROM circle_likes WHERE uri = $1")
                        .bind(&uri)
                        .execute(&mut *tx)
                        .await?;
                    sqlx::query("DELETE FROM circle_likes WHERE post_uri = $1")
                        .bind(&uri)
                        .execute(&mut *tx)
                        .await?;
                    sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1 OR subject_uri = $1")
                        .bind(&uri)
                        .execute(&mut *tx)
                        .await?;
                    let uri_hash = crate::validator::compute_uri_hash(&uri);
                    sqlx::query(
                        r#"
                        INSERT INTO circle_rejections (space_uri, author_did, rev, uri_hash, reason_code, observed_at)
                        VALUES ($1, $2, $3, $4, $5, now())
                        ON CONFLICT (space_uri, author_did, rev, uri_hash) DO UPDATE SET
                            reason_code = EXCLUDED.reason_code,
                            observed_at = now()
                        "#,
                    )
                    .bind(space_uri)
                    .bind(author_did)
                    .bind(&rev)
                    .bind(&uri_hash)
                    .bind(reason.reason_code())
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }
        // Atomic CAS update on circle_repo_sync_state (Finding 3)
        if let Some((prev_rev, prev_hash)) = &existing_sync {
            let prev_hash_matches = prev_hash == lthash.state().as_slice()
                || (prev_hash.len() == 32 && prev_hash == lthash.digest().as_slice());
            if latest_rev.as_str() < prev_rev.as_str()
                || (latest_rev.as_str() == prev_rev.as_str() && !prev_hash_matches)
            {
                return Err(AppError::InvalidRequest(
                    "Non-monotonic revision: revision cannot rollback or equal existing with different hash".into(),
                ));
            }
            let cas_res = sqlx::query(
                r#"
                UPDATE circle_repo_sync_state
                SET last_rev = $1, last_hash = $2, last_synced_at = now()
                WHERE space_uri = $3 AND author_did = $4 AND last_rev = $5 AND last_hash = $6
                "#,
            )
            .bind(&latest_rev)
            .bind(lthash.state().as_slice())
            .bind(space_uri)
            .bind(author_did)
            .bind(prev_rev)
            .bind(prev_hash)
            .execute(&mut *tx)
            .await?;

            if cas_res.rows_affected() == 0 {
                return Err(AppError::InvalidRequest(
                    "CAS conflict: repository head state mismatch or modified concurrently".into(),
                ));
            }
        } else {
            let cas_res = sqlx::query(
                r#"
                INSERT INTO circle_repo_sync_state (space_uri, author_did, last_rev, last_hash, last_synced_at)
                VALUES ($1, $2, $3, $4, now())
                ON CONFLICT (space_uri, author_did) DO NOTHING
                "#,
            )
            .bind(space_uri)
            .bind(author_did)
            .bind(&latest_rev)
            .bind(lthash.state().as_slice())
            .execute(&mut *tx)
            .await?;

            if cas_res.rows_affected() == 0 {
                return Err(AppError::InvalidRequest(
                    "CAS conflict: repository head initial state already inserted".into(),
                ));
            }
        }

        // Recheck membership generation/state with row lock inside projection transaction immediately before commit (Finding 17 & 36)
        let _locked_gen: Option<(i64,)> = sqlx::query_as(
            "SELECT generation FROM circle_member_cache_meta WHERE space_uri = $1 FOR UPDATE",
        )
        .bind(space_uri)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        let is_still_member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2 FOR KEY SHARE)",
        )
        .bind(space_uri)
        .bind(author_did)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        if !is_still_member && author_did != authority_did {
            return Err(AppError::Forbidden(
                "Author membership was revoked during projection transaction".into(),
            ));
        }
        tx.commit().await?;

        // Dispatch generic push notifications to distinct recipients after commit
        if let Some(push_client) = &self.push_client {
            for recipient in &new_notification_recipients {
                let is_valid_recipient: Option<(String,)> = sqlx::query_as(
                    r#"
                    SELECT m.member_did FROM circle_member_cache m
                    JOIN circles c ON c.space_uri = m.space_uri AND c.deleted_at IS NULL AND c.app_access_granted = true
                    WHERE m.space_uri = $1 AND m.member_did = $2
                    "#,
                )
                .bind(space_uri)
                .bind(recipient)
                .fetch_optional(&self.db)
                .await
                .unwrap_or(None);

                if is_valid_recipient.is_some() {
                    if let Err(_e) = push_client.deliver_circle_activity(recipient).await {
                        tracing::warn!(
                            "Failed to deliver circle activity push notification: dispatch error"
                        );
                    }
                }
            }
        }
        Ok(SyncResult {
            mode: SyncMode::Incremental,
            commit_verified: true,
            ops_applied,
            records_accepted,
            records_rejected,
            latest_rev,
            bytes_processed: total_bytes,
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
        expected_authority_rev: Option<&str>,
    ) -> Result<SyncResult, AppError> {
        let existing_sync: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT last_rev, last_hash FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2",
        )
        .bind(space_uri)
        .bind(author_did)
        .fetch_optional(&self.db)
        .await?;

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
        self.record_bytes_processed(car_bytes.len());

        let car = parse_permissioned_car(&car_bytes)
            .await
            .map_err(|e| AppError::Internal(format!("CAR decoding failed: {e}")))?;

        let (commit, records, lthash) = extract_and_validate_car_with_policy(
            &car,
            space_uri,
            author_did,
            author_signing_key,
            &self.commit_verification_policy,
        )
        .map_err(|e| AppError::InvalidRequest(format!("CAR validation failed: {e}")))?;
        let latest_rev = commit.rev.to_string();
        if let Some((prev_rev, prev_hash)) = &existing_sync {
            let prev_hash_matches = prev_hash == lthash.state().as_slice()
                || (prev_hash.len() == 32 && prev_hash == lthash.digest().as_slice());
            if latest_rev.as_str() < prev_rev.as_str()
                || (latest_rev.as_str() == prev_rev.as_str() && !prev_hash_matches)
            {
                return Err(AppError::InvalidRequest(
                    "Non-monotonic revision in full recovery: revision cannot rollback or equal existing with different hash".into(),
                ));
            }

            // Conditional anchor: when commit.prev_rev == stored last_rev, require commit.prev_hash == sha256(stored last_hash)
            if let Some(commit_prev_rev) = &commit.prev_rev {
                if commit_prev_rev.as_str() == prev_rev.as_str() {
                    let stored_digest: [u8; 32] = if prev_hash.len() == LTHASH_SIZE {
                        Sha256::digest(prev_hash).into()
                    } else if prev_hash.len() == 32 {
                        let mut d = [0u8; 32];
                        d.copy_from_slice(prev_hash);
                        d
                    } else {
                        [0u8; 32]
                    };

                    let commit_prev_hash_matches = commit
                        .prev_hash
                        .as_ref()
                        .map(|h| h.as_ref() == stored_digest.as_slice())
                        .unwrap_or(false);

                    if !commit_prev_hash_matches {
                        return Err(AppError::InvalidRequest(
                            "Fork detected in full recovery: commit claims descent from stored revision but prev_hash does not match stored state digest".into(),
                        ));
                    }
                }
            }
        }
        // Verify against expected authority hash and rev if provided
        if let Some(expected_hash) = expected_authority_hash {
            if commit.hash.as_ref() != expected_hash {
                return Err(AppError::InvalidRequest(
                    "CAR commit hash does not match expected authority hash".into(),
                ));
            }
        }
        if let Some(expected_rev) = expected_authority_rev {
            if commit.rev.as_str() != expected_rev {
                return Err(AppError::InvalidRequest(
                    "CAR commit revision does not match expected authority revision".into(),
                ));
            }
        }

        let mut pending_records = records;
        let mut staged_valid_records = Vec::new();
        let mut staged_rejections = Vec::new();
        let mut current_policy = policy.clone();

        // Exact query of other authors' active posts directly from DB (no substring matching)
        let other_authors_posts: Vec<(String, String)> = sqlx::query_as(
            "SELECT uri, cid FROM circle_records WHERE space_uri = $1 AND author_did != $2 AND collection = 'app.bsky.feed.post' AND deleted_at IS NULL",
        )
        .bind(space_uri)
        .bind(author_did)
        .fetch_all(&self.db)
        .await?;

        current_policy.known_posts.clear();
        for (u, c) in other_authors_posts {
            current_policy.known_posts.insert(u, c);
        }
        let ops_applied = pending_records.len();
        let mut records_accepted = 0;
        let mut records_rejected = 0;

        // Multi-pass resolution for intra-repo dependencies (posts before replies/likes)
        let mut progress = true;
        while progress && !pending_records.is_empty() {
            progress = false;
            let mut remaining = Vec::new();
            for (collection_str, rkey_str, cid_str, value_json) in pending_records {
                let uri = format!("{space_uri}/{author_did}/{collection_str}/{rkey_str}");

                let candidate = RecordCandidate {
                    uri: uri.clone(),
                    author_did: author_did.to_string(),
                    collection: collection_str.clone(),
                    rkey: rkey_str.clone(),
                    value: value_json.clone(),
                };

                match validate_record(&candidate, &current_policy) {
                    Ok(valid) => {
                        records_accepted += 1;
                        if valid.collection == "app.bsky.feed.post" {
                            current_policy.add_post(valid.uri.clone(), cid_str.clone());
                        }
                        staged_valid_records.push((valid, cid_str));
                        progress = true;
                    }
                    Err(InvalidRecord::CrossSpaceReference) => {
                        remaining.push((
                            (collection_str, rkey_str, cid_str, value_json),
                            uri,
                            InvalidRecord::CrossSpaceReference,
                        ));
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

        let latest_rev = commit.rev.to_string();
        let mut recovered_uris: HashSet<String> = HashSet::new();
        let mut tx = self.db.begin().await?;
        let mut new_notification_recipients: HashSet<String> = HashSet::new();
        for (valid, cid_str) in staged_valid_records {
            recovered_uris.insert(valid.uri.clone());

            let existing_rec_cid: Option<String> = sqlx::query_as::<_, (String,)>(
                "SELECT cid FROM circle_records WHERE uri = $1 AND deleted_at IS NULL",
            )
            .bind(&valid.uri)
            .fetch_optional(&mut *tx)
            .await?
            .map(|(c,)| c);

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

                let post_author: Option<(String,)> = sqlx::query_as(
                    "SELECT author_did FROM circle_records WHERE uri = $1 AND deleted_at IS NULL",
                )
                .bind(post_uri)
                .fetch_optional(&mut *tx)
                .await?;

                if let Some((recipient,)) = post_author {
                    if recipient != valid.author_did {
                        let existing_notif: Option<(Uuid, String, String, String, String, Option<String>)> = sqlx::query_as(
                            "SELECT id, recipient_did, space_uri, actor_did, reason, subject_uri FROM circle_notifications WHERE source_uri = $1",
                        )
                        .bind(&valid.uri)
                        .fetch_optional(&mut *tx)
                        .await?;

                        let is_unchanged = if let Some(old_cid) = &existing_rec_cid {
                            if old_cid == &cid_str {
                                if let Some((_, rec, sp, act, rsn, subj)) = &existing_notif {
                                    rec == &recipient
                                        && sp == space_uri
                                        && act == &valid.author_did
                                        && rsn == "like"
                                        && subj.as_deref() == Some(post_uri)
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        };

                        if !is_unchanged {
                            sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1")
                                .bind(&valid.uri)
                                .execute(&mut *tx)
                                .await?;

                            sqlx::query(
                                r#"
                                INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
                                VALUES ($1, $2, $3, $4, 'like', $5, $6, false, now())
                                "#,
                            )
                            .bind(Uuid::new_v4())
                            .bind(&recipient)
                            .bind(space_uri)
                            .bind(&valid.author_did)
                            .bind(post_uri)
                            .bind(&valid.uri)
                            .execute(&mut *tx)
                            .await?;
                            new_notification_recipients.insert(recipient);
                        }
                    } else {
                        sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1")
                            .bind(&valid.uri)
                            .execute(&mut *tx)
                            .await?;
                    }
                } else {
                    sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1")
                        .bind(&valid.uri)
                        .execute(&mut *tx)
                        .await?;
                }
            } else if let Some(parent_uri) = &valid.parent_uri {
                let parent_author: Option<(String,)> = sqlx::query_as(
                    "SELECT author_did FROM circle_records WHERE uri = $1 AND deleted_at IS NULL",
                )
                .bind(parent_uri)
                .fetch_optional(&mut *tx)
                .await?;

                if let Some((recipient,)) = parent_author {
                    if recipient != valid.author_did {
                        let existing_notif: Option<(Uuid, String, String, String, String, Option<String>)> = sqlx::query_as(
                            "SELECT id, recipient_did, space_uri, actor_did, reason, subject_uri FROM circle_notifications WHERE source_uri = $1",
                        )
                        .bind(&valid.uri)
                        .fetch_optional(&mut *tx)
                        .await?;

                        let is_unchanged = if let Some(old_cid) = &existing_rec_cid {
                            if old_cid == &cid_str {
                                if let Some((_, rec, sp, act, rsn, subj)) = &existing_notif {
                                    rec == &recipient
                                        && sp == space_uri
                                        && act == &valid.author_did
                                        && rsn == "reply"
                                        && subj.as_deref() == Some(&valid.uri)
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        };

                        if !is_unchanged {
                            sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1")
                                .bind(&valid.uri)
                                .execute(&mut *tx)
                                .await?;

                            sqlx::query(
                                r#"
                                INSERT INTO circle_notifications (id, recipient_did, space_uri, actor_did, reason, subject_uri, source_uri, is_read, created_at)
                                VALUES ($1, $2, $3, $4, 'reply', $5, $6, false, now())
                                "#,
                            )
                            .bind(Uuid::new_v4())
                            .bind(&recipient)
                            .bind(space_uri)
                            .bind(&valid.author_did)
                            .bind(&valid.uri)
                            .bind(&valid.uri)
                            .execute(&mut *tx)
                            .await?;
                            new_notification_recipients.insert(recipient);
                        }
                    } else {
                        sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1")
                            .bind(&valid.uri)
                            .execute(&mut *tx)
                            .await?;
                    }
                } else {
                    sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1")
                        .bind(&valid.uri)
                        .execute(&mut *tx)
                        .await?;
                }
            } else {
                sqlx::query("DELETE FROM circle_notifications WHERE source_uri = $1")
                    .bind(&valid.uri)
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
                sqlx::query("DELETE FROM circle_likes WHERE post_uri = $1")
                    .bind(&existing_uri)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query(
                    "DELETE FROM circle_notifications WHERE source_uri = $1 OR subject_uri = $1",
                )
                .bind(&existing_uri)
                .execute(&mut *tx)
                .await?;
            }
        }

        for (uri, reason) in staged_rejections {
            sqlx::query("UPDATE circle_records SET deleted_at = now() WHERE uri = $1")
                .bind(&uri)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM circle_likes WHERE uri = $1")
                .bind(&uri)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM circle_likes WHERE post_uri = $1")
                .bind(&uri)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "DELETE FROM circle_notifications WHERE source_uri = $1 OR subject_uri = $1",
            )
            .bind(&uri)
            .execute(&mut *tx)
            .await?;
            let uri_hash = crate::validator::compute_uri_hash(&uri);
            sqlx::query(
                r#"
                INSERT INTO circle_rejections (space_uri, author_did, rev, uri_hash, reason_code, observed_at)
                VALUES ($1, $2, $3, $4, $5, now())
                ON CONFLICT (space_uri, author_did, rev, uri_hash) DO UPDATE SET
                    reason_code = EXCLUDED.reason_code,
                    observed_at = now()
                "#,
            )
            .bind(space_uri)
            .bind(author_did)
            .bind(&latest_rev)
            .bind(&uri_hash)
            .bind(reason.reason_code())
            .execute(&mut *tx)
            .await?;
        }
        // Recheck membership generation/state with row lock inside projection transaction immediately before commit (Finding 17 & 36)
        let _locked_gen: Option<(i64,)> = sqlx::query_as(
            "SELECT generation FROM circle_member_cache_meta WHERE space_uri = $1 FOR UPDATE",
        )
        .bind(space_uri)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        let is_still_member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2 FOR KEY SHARE)",
        )
        .bind(space_uri)
        .bind(author_did)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        let authority_did = extract_authority_did(space_uri)?;
        if !is_still_member && author_did != authority_did {
            return Err(AppError::Forbidden(
                "Author membership was revoked during projection transaction".into(),
            ));
        }

        // Atomic CAS update on circle_repo_sync_state in full recovery (Finding 3 / Item 1)
        if let Some((prev_rev, prev_hash)) = &existing_sync {
            let cas_res = sqlx::query(
                r#"
                UPDATE circle_repo_sync_state
                SET last_rev = $1, last_hash = $2, last_synced_at = now()
                WHERE space_uri = $3 AND author_did = $4 AND last_rev = $5 AND last_hash = $6
                "#,
            )
            .bind(&latest_rev)
            .bind(lthash.state().as_slice())
            .bind(space_uri)
            .bind(author_did)
            .bind(prev_rev)
            .bind(prev_hash)
            .execute(&mut *tx)
            .await?;

            if cas_res.rows_affected() == 0 {
                return Err(AppError::InvalidRequest(
                    "CAS conflict in full recovery: repository head state mismatch or modified concurrently".into(),
                ));
            }
        } else {
            let cas_res = sqlx::query(
                r#"
                INSERT INTO circle_repo_sync_state (space_uri, author_did, last_rev, last_hash, last_synced_at)
                VALUES ($1, $2, $3, $4, now())
                ON CONFLICT (space_uri, author_did) DO NOTHING
                "#,
            )
            .bind(space_uri)
            .bind(author_did)
            .bind(&latest_rev)
            .bind(lthash.state().as_slice())
            .execute(&mut *tx)
            .await?;

            if cas_res.rows_affected() == 0 {
                return Err(AppError::InvalidRequest(
                    "CAS conflict in full recovery: repository head initial state already inserted"
                        .into(),
                ));
            }
        }
        tx.commit().await?;

        // Dispatch generic push notifications to distinct recipients after commit
        if let Some(push_client) = &self.push_client {
            for recipient in &new_notification_recipients {
                let is_valid_recipient: Option<(String,)> = sqlx::query_as(
                    r#"
                    SELECT m.member_did FROM circle_member_cache m
                    JOIN circles c ON c.space_uri = m.space_uri AND c.deleted_at IS NULL AND c.app_access_granted = true
                    WHERE m.space_uri = $1 AND m.member_did = $2
                    "#,
                )
                .bind(space_uri)
                .bind(recipient)
                .fetch_optional(&self.db)
                .await
                .unwrap_or(None);

                if is_valid_recipient.is_some() {
                    if let Err(_e) = push_client.deliver_circle_activity(recipient).await {
                        tracing::warn!(
                            "Failed to deliver circle activity push notification: dispatch error"
                        );
                    }
                }
            }
        }
        Ok(SyncResult {
            mode: SyncMode::FullRecovery,
            commit_verified: true,
            ops_applied,
            records_accepted,
            records_rejected,
            latest_rev,
            bytes_processed: car_bytes.len(),
        })
    }
}

pub async fn sweep_once(state: &AppState) -> Result<SweepSummary, AppError> {
    sweep_once_with_shutdown(state, None).await
}

pub async fn sweep_once_with_shutdown(
    state: &AppState,
    mut shutdown_rx: Option<&mut tokio::sync::watch::Receiver<bool>>,
) -> Result<SweepSummary, AppError> {
    let sync_engine = SyncEngine::new(state);
    let mut summary = SweepSummary::default();
    let sweep_start = std::time::Instant::now();
    let mut total_bytes_processed: usize = 0;

    // Persisted checkpoint progress for fair resume (Finding 7 / Item 5)
    let last_checkpoint: Option<(String,)> = sqlx::query_as(
        "SELECT last_space_uri FROM circle_sweep_checkpoint WHERE checkpoint_key = 'revision_sweep'",
    )
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let last_space_uri = last_checkpoint.map(|(s,)| s).unwrap_or_default();

    // Query active spaces in ordered sequence starting after checkpoint
    let mut active_spaces: Vec<(String,)> = sqlx::query_as(
        "SELECT space_uri FROM circles WHERE deleted_at IS NULL AND space_uri > $1 ORDER BY space_uri ASC",
    )
    .bind(&last_space_uri)
    .fetch_all(&state.db)
    .await?;

    // If reached end, wrap around to beginning
    if active_spaces.is_empty() {
        active_spaces = sqlx::query_as(
            "SELECT space_uri FROM circles WHERE deleted_at IS NULL ORDER BY space_uri ASC",
        )
        .fetch_all(&state.db)
        .await?;
    }

    for (space_uri,) in active_spaces {
        // Cooperative shutdown check
        if let Some(rx) = &mut shutdown_rx {
            if *rx.borrow() {
                tracing::info!("Cooperative shutdown observed during revision sweep");
                break;
            }
        }

        if sweep_start.elapsed().as_secs() >= MAX_TIME_PER_SWEEP_SECS {
            tracing::info!("Sweep time budget reached; checkpointing progress for fair resume");
            break;
        }
        if summary.repos_checked >= MAX_REPOS_PER_SWEEP {
            tracing::info!("Sweep repo budget reached; checkpointing progress for fair resume");
            break;
        }
        if total_bytes_processed >= MAX_BYTES_PER_SWEEP {
            tracing::info!("Sweep byte budget reached; checkpointing progress for fair resume");
            break;
        }

        // Persist checkpoint for fair resume
        let _ = sqlx::query(
            r#"
            INSERT INTO circle_sweep_checkpoint (checkpoint_key, last_space_uri, updated_at)
            VALUES ('revision_sweep', $1, now())
            ON CONFLICT (checkpoint_key) DO UPDATE SET last_space_uri = EXCLUDED.last_space_uri, updated_at = now()
            "#,
        )
        .bind(&space_uri)
        .execute(&state.db)
        .await;

        summary.spaces_checked += 1;
        let cred = match crate::access::ensure_space_credential(state, &space_uri, None).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, space_uri = %space_uri, "Failed to ensure space credential for sweep");
                summary.repos_failed += 1;
                continue;
            }
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
        let mut page_count = 0;

        loop {
            // Check shutdown between pages
            if let Some(rx) = &mut shutdown_rx {
                if *rx.borrow() {
                    break;
                }
            }

            if page_count >= MAX_PAGES_PER_SWEEP
                || summary.repos_checked >= MAX_REPOS_PER_SWEEP
                || sweep_start.elapsed().as_secs() >= MAX_TIME_PER_SWEEP_SECS
                || total_bytes_processed >= MAX_BYTES_PER_SWEEP
            {
                break;
            }
            page_count += 1;

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
                // Cooperative shutdown check inside repo loop
                if let Some(rx) = &mut shutdown_rx {
                    if *rx.borrow() {
                        tracing::info!(
                            "Cooperative shutdown observed during revision sweep repo loop"
                        );
                        break;
                    }
                }

                if sweep_start.elapsed().as_secs() >= MAX_TIME_PER_SWEEP_SECS {
                    tracing::info!("Sweep time budget reached in repo loop");
                    break;
                }
                if summary.repos_checked >= MAX_REPOS_PER_SWEEP {
                    tracing::info!("Sweep repo budget reached in repo loop");
                    break;
                }
                if total_bytes_processed >= MAX_BYTES_PER_SWEEP {
                    tracing::info!("Sweep byte budget reached in repo loop");
                    break;
                }

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
                        .sync_repo_with_expected_commit(
                            &space_uri,
                            repo_did,
                            Some(repo.hash.as_ref()),
                            Some(repo.rev.as_str()),
                        )
                        .await
                    {
                        Ok(_res) => {
                            summary.repos_synced += 1;
                        }
                        Err(_) => summary.repos_failed += 1,
                    }
                    total_bytes_processed = sync_engine.total_bytes_processed();
                }
            }

            if let Some(next_cursor) = repos_output.cursor {
                let next_cur_str = next_cursor.to_string();
                if next_cur_str.len() > MAX_CURSOR_LEN
                    || seen_cursors.len() >= MAX_PAGES_PER_SWEEP
                    || !seen_cursors.insert(next_cur_str.clone())
                {
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

/// Spawn and retain a production revision sweep task on a repeating interval.
/// Runs `sweep_once` on each tick, emits only content-free aggregate logs/errors,
/// and terminates gracefully when shutdown is signaled.
pub fn spawn_revision_sweep_task(
    state: AppState,
    interval_duration: std::time::Duration,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Sender<bool>,
) {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_duration);
        // First tick completes immediately
        interval.tick().await;

        loop {
            tokio::select! {
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        tracing::info!("Revision sweep background task shutting down");
                        break;
                    }
                }
                _ = interval.tick() => {
                    match sweep_once_with_shutdown(&state, Some(&mut shutdown_rx)).await {
                        Ok(summary) => {
                            tracing::info!(
                                spaces_checked = summary.spaces_checked,
                                 repos_checked = summary.repos_checked,
                                repos_synced = summary.repos_synced,
                                repos_failed = summary.repos_failed,
                                "Completed scheduled revision sweep"
                            );
                        }
                        Err(_) => {
                            tracing::warn!(error_code = "RevisionSweepFailed", "Scheduled revision sweep failed");
                        }
                    }
                }
            }
        }
    });
    (handle, shutdown_tx)
}

pub async fn notify_write_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Result<axum::response::Response, AppError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized(
            crate::error::AuthReason::MissingHeader,
        ))?;
    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .ok_or(AppError::Unauthorized(
            crate::error::AuthReason::InvalidHeader,
        ))?;
    let user = crate::auth::verify_service_jwt(
        &state,
        token,
        &state.config.service_did,
        Some("com.atproto.space.notifyWrite"),
    )
    .await?;

    let input: catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite =
        serde_json::from_slice(&body)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid notifyWrite body: {e}")))?;

    if input.hash.len() != 32 {
        return Err(AppError::InvalidRequest(
            "Hash must be exactly 32 bytes".into(),
        ));
    }
    if input.rev.as_str().is_empty() {
        return Err(AppError::InvalidRequest("Rev cannot be empty".into()));
    }

    let authority = extract_authority_did(input.space.as_str())?;
    if user.did != authority && user.did != input.repo.as_str() {
        return Err(AppError::Forbidden(
            "Caller DID does not match space authority or repo author".into(),
        ));
    }

    // Finding 17 & 36: Verify caller and repo author are active members before work
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM circle_member_cache WHERE space_uri = $1 AND member_did = $2)",
    )
    .bind(input.space.as_str())
    .bind(input.repo.as_str())
    .fetch_one(&state.db)
    .await
    .map_err(AppError::Database)?;

    if !is_member && input.repo.as_str() != authority {
        return Err(AppError::Forbidden(
            "Repo author is not an active member with appAccess for this Space".into(),
        ));
    }

    let sync_engine = SyncEngine::new(&state);
    sync_engine
        .sync_repo_with_expected_commit(
            input.space.as_str(),
            input.repo.as_str(),
            Some(input.hash.as_ref()),
            Some(input.rev.as_str()),
        )
        .await?;

    use axum::response::IntoResponse;
    Ok(axum::http::StatusCode::OK.into_response())
}

#[derive(serde::Deserialize)]
pub struct NotifySpaceDeletedPayload {
    pub space: String,
}

pub async fn notify_space_deleted_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Result<axum::response::Response, AppError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized(
            crate::error::AuthReason::MissingHeader,
        ))?;
    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .ok_or(AppError::Unauthorized(
            crate::error::AuthReason::InvalidHeader,
        ))?;
    let user = crate::auth::verify_service_jwt(
        &state,
        token,
        &state.config.service_did,
        Some("com.atproto.space.notifySpaceDeleted"),
    )
    .await?;

    let input: NotifySpaceDeletedPayload = serde_json::from_slice(&body)
        .map_err(|e| AppError::InvalidRequest(format!("Invalid notifySpaceDeleted body: {e}")))?;

    let authority = crate::access::extract_authority_did(&input.space)?;
    if user.did != authority {
        return Err(AppError::Unauthorized(crate::error::AuthReason::IdMismatch));
    }

    crate::purge::delete_space(&state.db, &state.credential_store, &input.space)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    use axum::response::IntoResponse;
    Ok(axum::http::StatusCode::OK.into_response())
}
