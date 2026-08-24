use crate::error::AppError;
use crate::feed::{build_post_view, normalize_uri_to_standard_aturi};
use crate::hydration::ProfileHydrator;
use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
use catbird_atproto::generated::app_bsky::feed::{
    NotFoundPost, ThreadViewPost, ThreadViewPostParent, ThreadViewPostRepliesItem,
};
use catbird_atproto::generated::blue_catbird::circle::defs::{
    AccessState, CircleSummary, SpaceRef,
};
use catbird_atproto::generated::blue_catbird::circle::get_post_thread::GetPostThreadOutput;
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::string::{AtUri, Did};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::future::Future;
use std::pin::Pin;

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
    pool: &PgPool,
    hydrator: &ProfileHydrator,
    user_did: &str,
    post_uri: &str,
    space_uri: &str,
    depth: Option<i64>,
    parent_height: Option<i64>,
    media_base_url: &str,
) -> Result<GetPostThreadOutput, AppError> {
    let depth = depth.unwrap_or(6).clamp(0, 100) as usize;
    let parent_height = parent_height.unwrap_or(80).clamp(0, 100) as usize;

    // 1. Verify space exists and active access lease & membership
    let circle_row: Option<(String, String, Option<DateTime<Utc>>, Option<bool>, Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
        r#"
        SELECT
            c.display_name,
            c.authority_did,
            c.deleted_at,
            pref.muted,
            m.status,
            a.expires_at
        FROM circles c
        LEFT JOIN circle_preferences pref ON pref.space_uri = c.space_uri AND pref.member_did = $2
        LEFT JOIN circle_members m ON m.space_uri = c.space_uri AND m.member_did = $2
        LEFT JOIN access_leases a ON a.space_uri = c.space_uri AND a.member_did = $2
        WHERE c.space_uri = $1
        "#,
    )
    .bind(space_uri)
    .bind(user_did)
    .fetch_optional(pool)
    .await?;

    let (circle_name, circle_owner, circle_muted) = match circle_row {
        None => return Err(AppError::NotFound("Space not found".into())),
        Some((_, _, Some(_), _, _, _)) => return Err(AppError::NotFound("Space deleted".into())),
        Some((name, owner, None, muted, member_status, expires_at)) => {
            let is_active = member_status.as_deref() == Some("active");
            let has_lease = expires_at.is_some_and(|exp| exp > Utc::now());
            if !is_active || !has_lease {
                return Err(AppError::AccessRemoved(
                    "No active access lease for this Circle".into(),
                ));
            }
            (name, owner, muted.unwrap_or(false))
        }
    };

    let circle_summary = CircleSummary {
        uri: SpaceRef::new(SmolStr::new(space_uri)).unwrap_or_else(|_| {
            SpaceRef::new(SmolStr::new(format!("at://{circle_owner}/space/blue.catbird.circle/unknown"))).unwrap()
        }),
        name: SmolStr::new(circle_name),
        owner: Did::new(SmolStr::new(&circle_owner)).unwrap_or_else(|_| {
            Did::new(SmolStr::new("did:plc:unknown")).unwrap()
        }),
        access_state: AccessState::Active,
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
            (SELECT count(*) FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR l.post_uri = $1 OR l.post_uri = $2) AND l.space_uri = $3) AS like_count,
            (
                SELECT count(*)
                FROM circle_records rep
                WHERE (rep.parent_uri = r.uri OR rep.parent_uri = $1 OR rep.parent_uri = $2)
                  AND rep.space_uri = $3
                  AND rep.deleted_at IS NULL
                  AND (
                      rep.root_uri IS NULL
                      OR EXISTS (
                          SELECT 1 FROM circle_records root
                          WHERE (root.uri = rep.root_uri OR root.uri = (
                              CASE
                                  WHEN rep.root_uri LIKE '%/space/%' THEN 'at://' || SPLIT_PART(rep.root_uri, '/space/', 2)
                                  ELSE rep.root_uri
                              END
                          ))
                            AND root.space_uri = $3
                            AND root.deleted_at IS NULL
                      )
                  )
            ) AS reply_count,
            (SELECT l.uri FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR l.post_uri = $1 OR l.post_uri = $2) AND l.space_uri = $3 AND l.author_did = $4) AS viewer_like_uri
        FROM circle_records r
        JOIN circles c ON c.space_uri = r.space_uri AND c.deleted_at IS NULL
        JOIN access_leases a ON a.space_uri = r.space_uri AND a.member_did = $4 AND a.expires_at > now()
        JOIN circle_members m ON m.space_uri = r.space_uri AND m.member_did = $4 AND m.status = 'active'
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
    .fetch_optional(pool)
    .await?;

    let root_data = match root_row {
        Some(r) => r,
        None => {
            // Check if post exists vs access lost
            let post_exists: Option<(Option<DateTime<Utc>>,)> = sqlx::query_as(
                "SELECT deleted_at FROM circle_records WHERE (uri = $1 OR uri = $2) AND space_uri = $3",
            )
            .bind(post_uri)
            .bind(&alt_post_uri)
            .bind(space_uri)
            .fetch_optional(pool)
            .await?;

            if post_exists.is_none() || post_exists.unwrap().0.is_some() {
                return Err(AppError::NotFound("Post not found".into()));
            } else {
                return Err(AppError::AccessRemoved(
                    "Access removed for this Circle".into(),
                ));
            }
        }
    };

    let db_root_uri = root_data.0.clone();
    let mut remaining_budget = MAX_THREAD_NODES.saturating_sub(1);

    // 3. Build parents upwards up to parent_height (same-space only, with authorization predicate)
    let mut current_parent_uri = root_data.6.clone();
    let mut ancestors = Vec::new();
    let mut terminal_not_found = None;
    let mut heights_remaining = parent_height;

    while let Some(p_uri) = current_parent_uri {
        if heights_remaining == 0 || remaining_budget == 0 {
            break;
        }
        heights_remaining -= 1;

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
                (SELECT count(*) FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR l.post_uri = $1 OR l.post_uri = $2) AND l.space_uri = $3) AS like_count,
                (
                    SELECT count(*)
                    FROM circle_records rep
                    WHERE (rep.parent_uri = r.uri OR rep.parent_uri = $1 OR rep.parent_uri = $2)
                      AND rep.space_uri = $3
                      AND rep.deleted_at IS NULL
                      AND (
                          rep.root_uri IS NULL
                          OR EXISTS (
                              SELECT 1 FROM circle_records root
                              WHERE (root.uri = rep.root_uri OR root.uri = (
                                  CASE
                                      WHEN rep.root_uri LIKE '%/space/%' THEN 'at://' || SPLIT_PART(rep.root_uri, '/space/', 2)
                                      ELSE rep.root_uri
                                  END
                              ))
                                AND root.space_uri = $3
                                AND root.deleted_at IS NULL
                          )
                      )
                ) AS reply_count,
                (SELECT l.uri FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR l.post_uri = $1 OR l.post_uri = $2) AND l.space_uri = $3 AND l.author_did = $4) AS viewer_like_uri
            FROM circle_records r
            JOIN circles c ON c.space_uri = r.space_uri AND c.deleted_at IS NULL
            JOIN access_leases a ON a.space_uri = r.space_uri AND a.member_did = $4 AND a.expires_at > now()
            JOIN circle_members m ON m.space_uri = r.space_uri AND m.member_did = $4 AND m.status = 'active'
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
        .fetch_optional(pool)
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

    // 4. Build replies recursively downwards up to depth (same-space only, with authorization predicate & budget)
    let mut remaining_budget_ref = remaining_budget;
    let raw_replies = fetch_replies_raw(pool, user_did, &db_root_uri, space_uri, depth, &mut remaining_budget_ref).await?;

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
    let profiles = hydrator.get_profiles(&did_slices).await;

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
        media_base_url,
    )?;

    // Fold ancestors from oldest to immediate parent:
    let mut parent_thread: Option<ThreadViewPostParent> = terminal_not_found.map(|p_uri| {
        let std_p = normalize_uri_to_standard_aturi(&p_uri);
        let not_found = NotFoundPost {
            not_found: true,
            uri: AtUri::new(SmolStr::new(std_p)).unwrap_or_else(|_| AtUri::new(SmolStr::new("at://did:plc:unknown/app.bsky.feed.post/unknown")).unwrap()),
            extra_data: None,
        };
        ThreadViewPostParent::NotFoundPost(Box::new(not_found))
    });

    for anc in ancestors.into_iter().rev() {
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
            media_base_url,
        )?;
        let node = ThreadViewPost {
            post: anc_post_view,
            parent: parent_thread,
            replies: None,
            thread_context: None,
            extra_data: None,
        };
        parent_thread = Some(ThreadViewPostParent::ThreadViewPost(Box::new(node)));
    }

    // Build reply tree views
    fn build_reply_views(
        raw_nodes: Vec<RawThreadNode>,
        profiles: &std::collections::HashMap<String, ProfileViewBasic>,
        space_uri: &str,
        media_base_url: &str,
    ) -> Result<Vec<ThreadViewPostRepliesItem>, AppError> {
        let mut items = Vec::with_capacity(raw_nodes.len());
        for node in raw_nodes {
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
            let child_replies = build_reply_views(node.replies, profiles, space_uri, media_base_url)?;
            let thread_node = ThreadViewPost {
                post: post_view,
                parent: None,
                replies: if child_replies.is_empty() { None } else { Some(child_replies) },
                thread_context: None,
                extra_data: None,
            };
            items.push(ThreadViewPostRepliesItem::ThreadViewPost(Box::new(thread_node)));
        }
        Ok(items)
    }

    let reply_views = build_reply_views(raw_replies, &profiles, space_uri, media_base_url)?;

    // 7. Final authorization check after profile hydration before returning
    let final_lease: Option<(i32,)> = sqlx::query_as(
        r#"
        SELECT 1
        FROM circles c
        JOIN access_leases a ON a.space_uri = c.space_uri AND a.member_did = $1 AND a.expires_at > now()
        JOIN circle_members m ON m.space_uri = c.space_uri AND m.member_did = $1 AND m.status = 'active'
        WHERE c.space_uri = $2 AND c.deleted_at IS NULL
        "#,
    )
    .bind(user_did)
    .bind(space_uri)
    .fetch_optional(pool)
    .await?;

    if final_lease.is_none() {
        return Err(AppError::AccessRemoved(
            "Access removed for this Circle".into(),
        ));
    }

    let root_thread = ThreadViewPost {
        post: root_post_view,
        parent: parent_thread,
        replies: if reply_views.is_empty() { None } else { Some(reply_views) },
        thread_context: None,
        extra_data: None,
    };

    Ok(GetPostThreadOutput {
        circle: circle_summary,
        thread: root_thread,
        extra_data: None,
    })
}

#[allow(clippy::type_complexity)]
fn fetch_replies_raw<'a>(
    pool: &'a PgPool,
    user_did: &'a str,
    parent_uri: &'a str,
    space_uri: &'a str,
    depth: usize,
    budget: &'a mut usize,
) -> Pin<Box<dyn Future<Output = Result<Vec<RawThreadNode>, AppError>> + Send + 'a>> {
    Box::pin(async move {
        if depth == 0 || *budget == 0 {
            return Ok(Vec::new());
        }

        let alt_parent_uri = if parent_uri.contains("/space/") {
            normalize_uri_to_standard_aturi(parent_uri)
        } else if let Some(rest) = parent_uri.strip_prefix("at://") {
            format!("{space_uri}/{rest}")
        } else {
            parent_uri.to_string()
        };

        let rows: Vec<(
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
                (SELECT count(*) FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR l.post_uri = $1 OR l.post_uri = $2) AND l.space_uri = $3) AS like_count,
                (
                    SELECT count(*)
                    FROM circle_records rep
                    WHERE (rep.parent_uri = r.uri OR rep.parent_uri = $1 OR rep.parent_uri = $2)
                      AND rep.space_uri = $3
                      AND rep.deleted_at IS NULL
                      AND (
                          rep.root_uri IS NULL
                          OR EXISTS (
                              SELECT 1 FROM circle_records root
                              WHERE (root.uri = rep.root_uri OR root.uri = (
                                  CASE
                                      WHEN rep.root_uri LIKE '%/space/%' THEN 'at://' || SPLIT_PART(rep.root_uri, '/space/', 2)
                                      ELSE rep.root_uri
                                  END
                              ))
                                AND root.space_uri = $3
                                AND root.deleted_at IS NULL
                          )
                      )
                ) AS reply_count,
                (SELECT l.uri FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE (l.post_uri = r.uri OR l.post_uri = $1 OR l.post_uri = $2) AND l.space_uri = $3 AND l.author_did = $4) AS viewer_like_uri
            FROM circle_records r
            JOIN circles c ON c.space_uri = r.space_uri AND c.deleted_at IS NULL
            JOIN access_leases a ON a.space_uri = r.space_uri AND a.member_did = $4 AND a.expires_at > now()
            JOIN circle_members m ON m.space_uri = r.space_uri AND m.member_did = $4 AND m.status = 'active'
            WHERE (r.parent_uri = $1 OR r.parent_uri = $2)
              AND r.space_uri = $3
              AND r.collection = 'app.bsky.feed.post'
              AND r.deleted_at IS NULL
              AND (
                  r.root_uri IS NULL
                  OR EXISTS (
                      SELECT 1 FROM circle_records root
                      WHERE (root.uri = r.root_uri OR root.uri = (
                          CASE
                              WHEN r.root_uri LIKE '%/space/%' THEN 'at://' || SPLIT_PART(r.root_uri, '/space/', 2)
                              ELSE r.root_uri
                          END
                      ))
                        AND root.space_uri = $3
                        AND root.deleted_at IS NULL
                  )
              )
            ORDER BY r.created_at ASC, r.uri ASC
            "#,
        )
        .bind(parent_uri)
        .bind(&alt_parent_uri)
        .bind(space_uri)
        .bind(user_did)
        .fetch_all(pool)
        .await?;

        let mut reply_nodes = Vec::with_capacity(rows.len());

        for row in rows {
            if *budget == 0 {
                break;
            }
            *budget -= 1;

            let child_uri = row.0.clone();
            let child_replies = if depth > 1 && *budget > 0 {
                fetch_replies_raw(pool, user_did, &child_uri, space_uri, depth - 1, budget).await?
            } else {
                Vec::new()
            };

            reply_nodes.push(RawThreadNode {
                uri: row.0,
                cid: row.1,
                author_did: row.3,
                record_json: row.4,
                indexed_at: row.5,
                like_count: row.8,
                reply_count: row.9,
                viewer_like_uri: row.10,
                replies: child_replies,
            });
        }

        Ok(reply_nodes)
    })
}
