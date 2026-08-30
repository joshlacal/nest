use crate::access;
use crate::config::AppState;
use crate::error::AppError;
use crate::feed::{build_post_view, normalize_uri_to_standard_aturi};
use crate::hydration::ProfileHydrator;
use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
use catbird_atproto::generated::app_bsky::feed::{
    NotFoundPost, ThreadViewPost, ThreadViewPostParent, ThreadViewPostRepliesItem,
};
use catbird_atproto::generated::blue_catbird::circle::get_post_thread::GetPostThreadOutput;
use catbird_atproto::generated::blue_catbird::circle::CircleSummary;
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::aturi::AtSpaceUri;
use catbird_atproto::jacquard_common::types::string::{AtUri, Did, Tid};
use chrono::{DateTime, Utc};
use sqlx::PgPool;

const MAX_THREAD_NODES: usize = 500;

#[derive(Debug, Clone)]
struct RawThreadNode {
    uri: String,
    cid: String,
    author_did: String,
    record_json: serde_json::Value,
    indexed_at: DateTime<Utc>,
    like_count: i64,
    reply_count: i64,
    viewer_like_uri: Option<String>,
    replies: Vec<RawThreadNode>,
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub async fn get_post_thread(
    state: &AppState,
    user_did: &str,
    post_uri: &str,
    space_uri: &str,
    depth: Option<i64>,
    parent_height: Option<i64>,
) -> Result<GetPostThreadOutput, AppError> {
    let depth = depth.unwrap_or(6).clamp(0, 100) as usize;
    let parent_height = parent_height.unwrap_or(80).clamp(0, 100) as usize;

    // 1. Verify space exists and active member access
    access::check_member_access(state, space_uri, user_did).await?;

    let circle_row: Option<(String, String, String, Option<bool>)> = sqlx::query_as(
        r#"
        SELECT
            c.circle_id,
            c.display_name,
            c.authority_did,
            pref.muted
        FROM circles c
        LEFT JOIN circle_preferences pref ON pref.space_uri = c.space_uri AND pref.member_did = $2
        WHERE c.space_uri = $1 AND c.deleted_at IS NULL AND c.app_access_granted = true
        "#,
    )
    .bind(space_uri)
    .bind(user_did)
    .fetch_optional(&state.db)
    .await?;

    let (circle_id, circle_name, circle_owner, circle_muted) = match circle_row {
        None => return Err(AppError::NotFound("Space not found".into())),
        Some((c_id, name, owner, muted)) => (c_id, name, owner, muted.unwrap_or(false)),
    };

    let circle_tid = Tid::new(SmolStr::new(&circle_id))
        .map_err(|e| AppError::Internal(format!("Invalid circle TID '{circle_id}': {e}")))?;
    let circle_space_ref = AtSpaceUri::new(SmolStr::new(space_uri))
        .map_err(|e| AppError::Internal(format!("Invalid Space URI '{space_uri}': {e}")))?;
    let circle_owner_did = Did::new(SmolStr::new(&circle_owner)).map_err(|e| {
        AppError::Internal(format!("Invalid circle owner DID '{circle_owner}': {e}"))
    })?;

    let circle_summary = CircleSummary {
        circle_id: circle_tid,
        uri: circle_space_ref,
        name: SmolStr::new(&circle_name),
        owner: circle_owner_did,
        member_count: None,
        muted: Some(circle_muted),
        extra_data: None,
    };

    // 2. Fetch target post (must be in same space and authorized)
    let alt_post_uri = if post_uri.contains("/space/") {
        normalize_uri_to_standard_aturi(post_uri)
    } else if let Some(rest) = post_uri.strip_prefix("at://") {
        format!("{space_uri}/{rest}")
    } else {
        post_uri.to_string()
    };

    let root_row: Option<(
        String,           // uri
        String,           // cid
        String,           // space_uri
        String,           // author_did
        serde_json::Value,// record_json
        DateTime<Utc>,    // indexed_at
        Option<String>,   // parent_uri
        Option<String>,   // root_uri
        i64,              // like_count
        i64,              // reply_count
        Option<String>,   // viewer_like_uri
    )> = sqlx::query_as(
        r#"
        SELECT
            r.uri,
            r.cid,
            r.space_uri,
            r.author_did,
            r.record_json,
            r.indexed_at,
            r.parent_uri,
            r.root_uri,
            (SELECT count(*) FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR REGEXP_REPLACE(l.post_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(r.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') OR l.post_uri = $1 OR l.post_uri = $2) AND l.space_uri = $3) AS like_count,
            (
                SELECT count(*)
                FROM circle_records rep
                WHERE (
                    rep.parent_uri = r.uri
                    OR REGEXP_REPLACE(rep.parent_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(r.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1')
                    OR rep.parent_uri = $1
                    OR rep.parent_uri = $2
                    OR REGEXP_REPLACE(rep.parent_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE($1, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1')
                )
                  AND rep.space_uri = $3
                  AND rep.deleted_at IS NULL
                  AND (
                      rep.root_uri IS NULL
                      OR EXISTS (
                          SELECT 1 FROM circle_records root
                          WHERE (root.uri = rep.root_uri OR REGEXP_REPLACE(root.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(rep.root_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1'))
                            AND root.space_uri = $3
                            AND root.deleted_at IS NULL
                            AND root.collection = 'app.bsky.feed.post'
                      )
                  )
                  AND (
                      rep.parent_uri IS NULL
                      OR EXISTS (
                          SELECT 1 FROM circle_records p
                          WHERE (p.uri = rep.parent_uri OR REGEXP_REPLACE(p.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(rep.parent_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1'))
                            AND p.space_uri = $3
                            AND p.deleted_at IS NULL
                            AND p.collection = 'app.bsky.feed.post'
                      )
                  )
            ) AS reply_count,
            (SELECT l.uri FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR REGEXP_REPLACE(l.post_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(r.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') OR l.post_uri = $1 OR l.post_uri = $2) AND l.space_uri = $3 AND l.author_did = $4) AS viewer_like_uri
        FROM circle_records r
        JOIN circles c ON c.space_uri = r.space_uri AND c.deleted_at IS NULL
        JOIN circle_member_cache m ON m.space_uri = r.space_uri AND m.member_did = $4
        WHERE (r.uri = $1 OR r.uri = $2)
          AND r.space_uri = $3
          AND r.collection = 'app.bsky.feed.post'
          AND r.deleted_at IS NULL
        "#,
    )
    .bind(post_uri)
    .bind(&alt_post_uri)
    .bind(space_uri)
    .bind(user_did)
    .fetch_optional(&state.db)
    .await?;

    let root_data = match root_row {
        Some(row) => row,
        None => {
            let post_exists: Option<(Option<DateTime<Utc>>, Option<String>, Option<String>)> = sqlx::query_as(
                "SELECT deleted_at, parent_uri, root_uri FROM circle_records WHERE (uri = $1 OR uri = $2) AND space_uri = $3 AND collection = 'app.bsky.feed.post'",
            )
            .bind(post_uri)
            .bind(&alt_post_uri)
            .bind(space_uri)
            .fetch_optional(&state.db)
            .await?;

            if let Some((Some(_), parent_u, root_u)) = post_exists {
                let has_active_context = if let Some(ref p_u) = parent_u {
                    let parent_active: Option<(i32,)> = sqlx::query_as(
                        "SELECT 1 FROM circle_records WHERE (uri = $1 OR uri = CASE WHEN $1 LIKE '%/space/%' THEN 'at://' || SPLIT_PART($1, '/space/', 2) ELSE $1 END) AND space_uri = $2 AND deleted_at IS NULL AND collection = 'app.bsky.feed.post'",
                    )
                    .bind(p_u)
                    .bind(space_uri)
                    .fetch_optional(&state.db)
                    .await?;
                    parent_active.is_some()
                } else if let Some(ref r_u) = root_u {
                    let root_active: Option<(i32,)> = sqlx::query_as(
                        "SELECT 1 FROM circle_records WHERE (uri = $1 OR uri = CASE WHEN $1 LIKE '%/space/%' THEN 'at://' || SPLIT_PART($1, '/space/', 2) ELSE $1 END) AND space_uri = $2 AND deleted_at IS NULL AND collection = 'app.bsky.feed.post'",
                    )
                    .bind(r_u)
                    .bind(space_uri)
                    .fetch_optional(&state.db)
                    .await?;
                    root_active.is_some()
                } else {
                    false
                };

                if has_active_context {
                    return Err(AppError::NotFound("Post record was deleted".into()));
                }
            }

            return Err(AppError::NotFound(
                "Post record not found in this Space".into(),
            ));
        }
    };
    // If the requested post is a reply, verify that its root and parent posts exist and are not deleted
    if let Some(ref r_uri) = root_data.7 {
        let root_active: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM circle_records WHERE (uri = $1 OR uri = CASE WHEN $1 LIKE '%/space/%' THEN 'at://' || SPLIT_PART($1, '/space/', 2) ELSE $1 END) AND space_uri = $2 AND deleted_at IS NULL AND collection = 'app.bsky.feed.post'",
        )
        .bind(r_uri)
        .bind(space_uri)
        .fetch_optional(&state.db)
        .await?;
        if root_active.is_none() {
            return Err(AppError::NotFound(
                "Root post was deleted or does not exist".into(),
            ));
        }
    }
    if let Some(ref p_uri) = root_data.6 {
        let parent_active: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM circle_records WHERE (uri = $1 OR uri = CASE WHEN $1 LIKE '%/space/%' THEN 'at://' || SPLIT_PART($1, '/space/', 2) ELSE $1 END) AND space_uri = $2 AND deleted_at IS NULL AND collection = 'app.bsky.feed.post'",
        )
        .bind(p_uri)
        .bind(space_uri)
        .fetch_optional(&state.db)
        .await?;
        if parent_active.is_none() {
            return Err(AppError::NotFound(
                "Parent post was deleted or does not exist".into(),
            ));
        }
    }

    let mut remaining_budget: usize = MAX_THREAD_NODES.saturating_sub(1);
    let db_root_uri = root_data.0.clone();

    // 3. Walk parent_uri chain upwards up to parent_height
    let mut ancestors: Vec<(
        String,
        String,
        String,
        String,
        serde_json::Value,
        DateTime<Utc>,
        Option<String>,
        Option<String>,
        i64,
        i64,
        Option<String>,
    )> = Vec::new();

    let mut current_parent_uri = root_data.6.clone();
    let mut terminal_not_found: Option<String> = None;

    while let Some(p_uri) = current_parent_uri {
        if ancestors.len() >= parent_height || remaining_budget == 0 {
            break;
        }

        let alt_p_uri = if p_uri.contains("/space/") {
            normalize_uri_to_standard_aturi(&p_uri)
        } else if let Some(rest) = p_uri.strip_prefix("at://") {
            format!("{space_uri}/{rest}")
        } else {
            p_uri.clone()
        };

        let p_row: Option<(
            String,           // uri
            String,           // cid
            String,           // space_uri
            String,           // author_did
            serde_json::Value,// record_json
            DateTime<Utc>,    // indexed_at
            Option<String>,   // parent_uri
            Option<String>,   // root_uri
            i64,              // like_count
            i64,              // reply_count
            Option<String>,   // viewer_like_uri
        )> = sqlx::query_as(
            r#"
            SELECT
                r.uri,
                r.cid,
                r.space_uri,
                r.author_did,
                r.record_json,
                r.indexed_at,
                r.parent_uri,
                r.root_uri,
                (SELECT count(*) FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR REGEXP_REPLACE(l.post_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(r.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') OR l.post_uri = $1 OR l.post_uri = $2) AND l.space_uri = $3) AS like_count,
                (
                    SELECT count(*)
                    FROM circle_records rep
                    WHERE (
                        rep.parent_uri = r.uri
                        OR REGEXP_REPLACE(rep.parent_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(r.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1')
                        OR rep.parent_uri = $1
                        OR rep.parent_uri = $2
                        OR REGEXP_REPLACE(rep.parent_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE($1, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1')
                    )
                      AND rep.space_uri = $3
                      AND rep.deleted_at IS NULL
                      AND (
                          rep.root_uri IS NULL
                          OR EXISTS (
                              SELECT 1 FROM circle_records root
                              WHERE (root.uri = rep.root_uri OR REGEXP_REPLACE(root.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(rep.root_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1'))
                                AND root.space_uri = $3
                                AND root.deleted_at IS NULL
                                AND root.collection = 'app.bsky.feed.post'
                          )
                      )
                      AND (
                          rep.parent_uri IS NULL
                          OR EXISTS (
                              SELECT 1 FROM circle_records p
                              WHERE (p.uri = rep.parent_uri OR REGEXP_REPLACE(p.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(rep.parent_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1'))
                                AND p.space_uri = $3
                                AND p.deleted_at IS NULL
                                AND p.collection = 'app.bsky.feed.post'
                          )
                      )
                ) AS reply_count,
                (SELECT l.uri FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR REGEXP_REPLACE(l.post_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(r.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') OR l.post_uri = $1 OR l.post_uri = $2) AND l.space_uri = $3 AND l.author_did = $4) AS viewer_like_uri
            FROM circle_records r
            JOIN circles c ON c.space_uri = r.space_uri AND c.deleted_at IS NULL
            JOIN circle_member_cache m ON m.space_uri = r.space_uri AND m.member_did = $4
            WHERE (r.uri = $1 OR r.uri = $2)
              AND r.space_uri = $3
              AND r.collection = 'app.bsky.feed.post'
              AND r.deleted_at IS NULL
            "#,
        )
        .bind(&p_uri)
        .bind(&alt_p_uri)
        .bind(space_uri)
        .bind(user_did)
        .fetch_optional(&state.db)
        .await?;

        match p_row {
            Some(row) => {
                remaining_budget = remaining_budget.saturating_sub(1);
                current_parent_uri = row.6.clone();
                ancestors.push(row);
            }
            None => {
                terminal_not_found = Some(p_uri);
                break;
            }
        }
    }

    // 4. Build replies recursively downwards
    let mut remaining_budget_ref = remaining_budget;
    let raw_replies = fetch_thread_replies_set_based(
        &state.db,
        user_did,
        &db_root_uri,
        space_uri,
        depth,
        &mut remaining_budget_ref,
    )
    .await?;

    // 5. Collect all DIDs across root, ancestors, and replies for deduplicated bounded hydration
    let mut all_dids = std::collections::HashSet::new();
    all_dids.insert(root_data.3.clone());
    for anc in &ancestors {
        all_dids.insert(anc.3.clone());
    }
    fn collect_reply_dids(nodes: &[RawThreadNode], dids: &mut std::collections::HashSet<String>) {
        for node in nodes {
            dids.insert(node.author_did.clone());
            collect_reply_dids(&node.replies, dids);
        }
    }
    collect_reply_dids(&raw_replies, &mut all_dids);

    let did_slices: Vec<&str> = all_dids.iter().map(|s| s.as_str()).collect();
    let profiles = state.profile_hydrator.get_profiles(&did_slices).await;

    // 6. Build views
    let root_profile = profiles
        .get(&root_data.3)
        .cloned()
        .unwrap_or_else(|| ProfileHydrator::unavailable_profile(&root_data.3));

    let root_post_view = build_post_view(
        &root_data.0,
        &root_data.1,
        &root_data.3,
        &root_data.4,
        root_data.5,
        root_data.8,
        root_data.9,
        root_data.10.as_deref(),
        space_uri,
        root_profile,
        &state.config.circle_media_base_url,
    )?;

    // Fold ancestors from oldest to immediate parent
    let mut parent_thread: Option<ThreadViewPostParent> = match terminal_not_found {
        Some(p_uri) => {
            let std_p = normalize_uri_to_standard_aturi(&p_uri);
            Some(ThreadViewPostParent::NotFoundPost(Box::new(NotFoundPost {
                not_found: true,
                uri: AtUri::new(SmolStr::new(std_p))
                    .map_err(|e| AppError::Internal(format!("Invalid parent post URI: {e}")))?,
                extra_data: None,
            })))
        }
        None => None,
    };

    for anc in ancestors.iter().rev() {
        let anc_profile = profiles
            .get(&anc.3)
            .cloned()
            .unwrap_or_else(|| ProfileHydrator::unavailable_profile(&anc.3));

        let anc_post_view = build_post_view(
            &anc.0,
            &anc.1,
            &anc.3,
            &anc.4,
            anc.5,
            anc.8,
            anc.9,
            anc.10.as_deref(),
            space_uri,
            anc_profile,
            &state.config.circle_media_base_url,
        )?;

        let tvp = ThreadViewPost {
            post: anc_post_view,
            parent: parent_thread,
            replies: None,
            thread_context: None,
            extra_data: None,
        };

        parent_thread = Some(ThreadViewPostParent::ThreadViewPost(Box::new(tvp)));
    }

    fn assemble_replies(
        nodes: Vec<RawThreadNode>,
        profiles: &std::collections::HashMap<String, ProfileViewBasic>,
        space_uri: &str,
        media_base_url: &url::Url,
    ) -> Result<Vec<ThreadViewPostRepliesItem>, AppError> {
        let mut out = Vec::with_capacity(nodes.len());
        for node in nodes {
            let profile = profiles
                .get(&node.author_did)
                .cloned()
                .unwrap_or_else(|| ProfileHydrator::unavailable_profile(&node.author_did));

            let post_view = build_post_view(
                &node.uri,
                &node.cid,
                &node.author_did,
                &node.record_json,
                node.indexed_at,
                node.like_count,
                node.reply_count,
                node.viewer_like_uri.as_deref(),
                space_uri,
                profile,
                media_base_url,
            )?;

            let child_replies = if node.replies.is_empty() {
                None
            } else {
                Some(assemble_replies(
                    node.replies,
                    profiles,
                    space_uri,
                    media_base_url,
                )?)
            };

            let tvp = ThreadViewPost {
                post: post_view,
                parent: None,
                replies: child_replies,
                thread_context: None,
                extra_data: None,
            };

            out.push(ThreadViewPostRepliesItem::ThreadViewPost(Box::new(tvp)));
        }
        Ok(out)
    }

    let replies_views = if raw_replies.is_empty() {
        None
    } else {
        Some(assemble_replies(
            raw_replies,
            &profiles,
            space_uri,
            &state.config.circle_media_base_url,
        )?)
    };

    let main_thread_view = ThreadViewPost {
        post: root_post_view,
        parent: parent_thread,
        replies: replies_views,
        thread_context: None,
        extra_data: None,
    };

    Ok(GetPostThreadOutput {
        thread: main_thread_view,
        circle: circle_summary,
        extra_data: None,
    })
}

#[allow(clippy::type_complexity)]
async fn fetch_replies_batch(
    pool: &PgPool,
    parent_uris: &[String],
    space_uri: &str,
    user_did: &str,
    budget: usize,
) -> Result<
    Vec<(
        String,
        String,
        String,
        String,
        serde_json::Value,
        DateTime<Utc>,
        Option<String>,
        Option<String>,
        i64,
        i64,
        Option<String>,
    )>,
    AppError,
> {
    if parent_uris.is_empty() || budget == 0 {
        return Ok(Vec::new());
    }

    let mut all_match_uris = Vec::new();
    for p in parent_uris {
        all_match_uris.push(p.clone());
        if p.contains("/space/") {
            all_match_uris.push(normalize_uri_to_standard_aturi(p));
        } else if let Some(rest) = p.strip_prefix("at://") {
            all_match_uris.push(format!("{space_uri}/{rest}"));
        }
    }

    let rows = sqlx::query_as(
        r#"
        SELECT
            r.uri,
            r.cid,
            r.space_uri,
            r.author_did,
            r.record_json,
            r.indexed_at,
            r.parent_uri,
            r.root_uri,
            (SELECT count(*) FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR REGEXP_REPLACE(l.post_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(r.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1')) AND l.space_uri = r.space_uri) AS like_count,
            (
                SELECT count(*)
                FROM circle_records rep
                WHERE (
                    rep.parent_uri = r.uri
                    OR REGEXP_REPLACE(rep.parent_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(r.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1')
                )
                  AND rep.space_uri = r.space_uri
                  AND rep.deleted_at IS NULL
                  AND (
                      rep.root_uri IS NULL
                      OR EXISTS (
                          SELECT 1 FROM circle_records root
                          WHERE (root.uri = rep.root_uri OR REGEXP_REPLACE(root.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(rep.root_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1'))
                            AND root.space_uri = $2
                            AND root.deleted_at IS NULL
                            AND root.collection = 'app.bsky.feed.post'
                      )
                  )
                  AND (
                      rep.parent_uri IS NULL
                      OR EXISTS (
                          SELECT 1 FROM circle_records p
                          WHERE (p.uri = rep.parent_uri OR REGEXP_REPLACE(p.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(rep.parent_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1'))
                            AND p.space_uri = $2
                            AND p.deleted_at IS NULL
                            AND p.collection = 'app.bsky.feed.post'
                      )
                  )
            ) AS reply_count,
            (SELECT l.uri FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR REGEXP_REPLACE(l.post_uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1') = REGEXP_REPLACE(r.uri, '^.*(did:[^/]+/app\.bsky\..*)$', 'at://\1')) AND l.space_uri = r.space_uri AND l.author_did = $3) AS viewer_like_uri
        FROM circle_records r
        JOIN circles c ON c.space_uri = r.space_uri AND c.deleted_at IS NULL AND c.app_access_granted = true
        JOIN circle_member_cache m ON m.space_uri = r.space_uri AND m.member_did = $3
        JOIN circle_member_cache_meta meta ON meta.space_uri = r.space_uri AND meta.app_access_granted = true AND meta.access_epoch = c.access_epoch AND meta.last_refreshed_at > now() - INTERVAL '300 seconds'
        WHERE r.parent_uri = ANY($1)
          AND r.space_uri = $2
          AND r.collection = 'app.bsky.feed.post'
          AND r.deleted_at IS NULL
        ORDER BY r.created_at ASC, r.uri ASC
        LIMIT $4
        "#,
    )
    .bind(&all_match_uris)
    .bind(space_uri)
    .bind(user_did)
    .bind(budget as i64)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

async fn fetch_thread_replies_set_based(
    pool: &PgPool,
    user_did: &str,
    root_parent_uri: &str,
    space_uri: &str,
    max_depth: usize,
    budget: &mut usize,
) -> Result<Vec<RawThreadNode>, AppError> {
    if max_depth == 0 || *budget == 0 {
        return Ok(Vec::new());
    }

    let mut current_level_parents = vec![root_parent_uri.to_string()];
    let mut levels: Vec<Vec<(String, RawThreadNode)>> = Vec::new();

    let mut current_depth = 0;
    while current_depth < max_depth && *budget > 0 && !current_level_parents.is_empty() {
        let rows =
            fetch_replies_batch(pool, &current_level_parents, space_uri, user_did, *budget).await?;
        if rows.is_empty() {
            break;
        }

        let count = rows.len();
        *budget = budget.saturating_sub(count);

        let mut next_level_parents = Vec::new();
        let mut level_nodes = Vec::with_capacity(count);

        for row in rows {
            let parent_key = row.6.clone().unwrap_or_default();
            let uri = row.0.clone();
            next_level_parents.push(uri);
            level_nodes.push((
                parent_key,
                RawThreadNode {
                    uri: row.0,
                    cid: row.1,
                    author_did: row.3,
                    record_json: row.4,
                    indexed_at: row.5,
                    like_count: row.8,
                    reply_count: row.9,
                    viewer_like_uri: row.10,
                    replies: Vec::new(),
                },
            ));
        }

        levels.push(level_nodes);
        current_level_parents = next_level_parents;
        current_depth += 1;
    }

    if levels.is_empty() {
        return Ok(Vec::new());
    }

    // Iteratively attach children to parents from deepest level up
    for d in (1..levels.len()).rev() {
        let child_level = std::mem::take(&mut levels[d]);
        let mut children_by_parent: std::collections::HashMap<String, Vec<RawThreadNode>> =
            std::collections::HashMap::new();
        for (parent_uri, node) in child_level {
            let normalized_parent = if parent_uri.contains("/space/") {
                normalize_uri_to_standard_aturi(&parent_uri)
            } else {
                parent_uri.clone()
            };
            children_by_parent
                .entry(parent_uri.clone())
                .or_default()
                .push(node.clone());
            if normalized_parent != parent_uri {
                children_by_parent
                    .entry(normalized_parent)
                    .or_default()
                    .push(node);
            }
        }

        for (_parent_key, parent_node) in &mut levels[d - 1] {
            let p_uri = &parent_node.uri;
            let norm_p_uri = normalize_uri_to_standard_aturi(p_uri);
            let mut matched_children: Vec<RawThreadNode> = Vec::new();
            let mut seen_uris = std::collections::HashSet::new();

            let mut candidates = Vec::new();
            if let Some(c) = children_by_parent.remove(p_uri) {
                candidates.extend(c);
            }
            if let Some(c) = children_by_parent.remove(&norm_p_uri) {
                candidates.extend(c);
            }
            if let Some(rest) = p_uri.strip_prefix("at://") {
                let space_scoped = format!("{space_uri}/{rest}");
                if let Some(c) = children_by_parent.remove(&space_scoped) {
                    candidates.extend(c);
                }
            }

            for child in candidates {
                if seen_uris.insert(child.uri.clone()) {
                    matched_children.push(child);
                }
            }

            matched_children.sort_by(|a, b| {
                a.indexed_at
                    .cmp(&b.indexed_at)
                    .then_with(|| a.uri.cmp(&b.uri))
            });
            parent_node.replies.extend(matched_children);
        }
    }

    let top_level = levels.into_iter().next().unwrap_or_default();
    let result = top_level.into_iter().map(|(_, node)| node).collect();
    Ok(result)
}
