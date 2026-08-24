use crate::error::AppError;
use crate::feed::{build_post_view, normalize_uri_to_standard_aturi};
use crate::hydration::ProfileHydrator;
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

#[allow(clippy::type_complexity)]
pub async fn get_post_thread(
    pool: &PgPool,
    hydrator: &ProfileHydrator,
    user_did: &str,
    post_uri: &str,
    space_uri: &str,
    depth: Option<i64>,
    parent_height: Option<i64>,
) -> Result<GetPostThreadOutput, AppError> {
    let depth = depth.unwrap_or(6).clamp(0, 100) as usize;
    let parent_height = parent_height.unwrap_or(80).clamp(0, 100) as usize;

    // 1. Verify space exists and active access lease
    let circle_row: Option<(String, String, Option<DateTime<Utc>>, Option<bool>)> = sqlx::query_as(
        r#"
        SELECT
            c.display_name,
            c.authority_did,
            c.deleted_at,
            pref.muted
        FROM circles c
        LEFT JOIN circle_preferences pref ON pref.space_uri = c.space_uri AND pref.member_did = $2
        WHERE c.space_uri = $1
        "#,
    )
    .bind(space_uri)
    .bind(user_did)
    .fetch_optional(pool)
    .await?;

    let (circle_name, circle_owner, circle_muted) = match circle_row {
        None => return Err(AppError::NotFound("Space not found".into())),
        Some((_, _, Some(_), _)) => return Err(AppError::NotFound("Space deleted".into())),
        Some((name, owner, None, muted)) => (name, owner, muted.unwrap_or(false)),
    };

    let has_lease: Option<(DateTime<Utc>,)> = sqlx::query_as(
        "SELECT expires_at FROM access_leases WHERE space_uri = $1 AND member_did = $2 AND expires_at > now()",
    )
    .bind(space_uri)
    .bind(user_did)
    .fetch_optional(pool)
    .await?;

    if has_lease.is_none() {
        return Err(AppError::AccessRemoved(
            "No active access lease for this Circle".into(),
        ));
    }

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

    // 2. Fetch target post (must be in same space and not deleted)
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
            (SELECT count(*) FROM circle_likes l WHERE l.post_uri = r.uri) AS like_count,
            (
                SELECT count(*)
                FROM circle_records rep
                WHERE rep.parent_uri = r.uri
                  AND rep.deleted_at IS NULL
                  AND (rep.root_uri IS NULL OR EXISTS (SELECT 1 FROM circle_records root WHERE root.uri = rep.root_uri AND root.deleted_at IS NULL))
            ) AS reply_count,
            (SELECT l.uri FROM circle_likes l WHERE l.post_uri = r.uri AND l.author_did = $4) AS viewer_like_uri
        FROM circle_records r
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
        None => return Err(AppError::NotFound("Post not found".into())),
    };

    let db_root_uri = root_data.0.clone();
    let author_profile = hydrator.get_profile(&root_data.3).await;

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
        author_profile,
    );

    // 3. Build parents upwards up to parent_height (same-space only)
    let mut current_parent_uri = root_data.6.clone();
    let mut parent_thread: Option<ThreadViewPostParent> = None;
    let mut heights_remaining = parent_height;

    while let Some(p_uri) = current_parent_uri {
        if heights_remaining == 0 {
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
                (SELECT count(*) FROM circle_likes l WHERE l.post_uri = r.uri) AS like_count,
                (
                    SELECT count(*)
                    FROM circle_records rep
                    WHERE rep.parent_uri = r.uri
                      AND rep.deleted_at IS NULL
                      AND (rep.root_uri IS NULL OR EXISTS (SELECT 1 FROM circle_records root WHERE root.uri = rep.root_uri AND root.deleted_at IS NULL))
                ) AS reply_count,
                (SELECT l.uri FROM circle_likes l WHERE l.post_uri = r.uri AND l.author_did = $4) AS viewer_like_uri
            FROM circle_records r
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
                let p_author_profile = hydrator.get_profile(&row.3).await;
                let p_post_view = build_post_view(
                    &row.0,
                    &row.1,
                    &row.3,
                    &row.4,
                    row.5,
                    row.8,
                    row.9,
                    row.10.as_deref(),
                    space_uri,
                    p_author_profile,
                );

                let next_parent_node = ThreadViewPost {
                    post: p_post_view,
                    parent: None,
                    replies: None,
                    thread_context: None,
                    extra_data: None,
                };

                if let Some(existing_p) = parent_thread {
                    let mut wrapped = next_parent_node;
                    wrapped.parent = Some(existing_p);
                    parent_thread = Some(ThreadViewPostParent::ThreadViewPost(Box::new(wrapped)));
                } else {
                    parent_thread = Some(ThreadViewPostParent::ThreadViewPost(Box::new(next_parent_node)));
                }

                current_parent_uri = row.6;
            }
            None => {
                let std_p = normalize_uri_to_standard_aturi(&p_uri);
                let not_found = NotFoundPost {
                    not_found: true,
                    uri: AtUri::new(SmolStr::new(std_p)).unwrap_or_else(|_| AtUri::new(SmolStr::new("at://did:plc:unknown/app.bsky.feed.post/unknown")).unwrap()),
                    extra_data: None,
                };
                parent_thread = Some(ThreadViewPostParent::NotFoundPost(Box::new(not_found)));
                break;
            }
        }
    }

    // 4. Build replies recursively downwards up to depth (same-space only, exclude deleted parents/roots)
    let replies = fetch_replies(pool, hydrator, user_did, &db_root_uri, space_uri, depth).await?;

    let root_thread = ThreadViewPost {
        post: root_post_view,
        parent: parent_thread,
        replies: if replies.is_empty() { None } else { Some(replies) },
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
fn fetch_replies<'a>(
    pool: &'a PgPool,
    hydrator: &'a ProfileHydrator,
    user_did: &'a str,
    parent_uri: &'a str,
    space_uri: &'a str,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Result<Vec<ThreadViewPostRepliesItem>, AppError>> + Send + 'a>> {
    Box::pin(async move {
        if depth == 0 {
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
                (SELECT count(*) FROM circle_likes l WHERE l.post_uri = r.uri) AS like_count,
                (
                    SELECT count(*)
                    FROM circle_records rep
                    WHERE rep.parent_uri = r.uri
                      AND rep.deleted_at IS NULL
                      AND (rep.root_uri IS NULL OR EXISTS (SELECT 1 FROM circle_records root WHERE root.uri = rep.root_uri AND root.deleted_at IS NULL))
                ) AS reply_count,
                (SELECT l.uri FROM circle_likes l WHERE l.post_uri = r.uri AND l.author_did = $4) AS viewer_like_uri
            FROM circle_records r
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

        let mut reply_items = Vec::with_capacity(rows.len());

        for row in rows {
            let child_uri = &row.0;
            let cid = &row.1;
            let author_did = &row.3;
            let record_json = &row.4;
            let indexed_at = row.5;
            let like_count = row.8;
            let reply_count = row.9;
            let viewer_like_uri = row.10.as_deref();

            let child_profile = hydrator.get_profile(author_did).await;
            let child_post_view = build_post_view(
                child_uri,
                cid,
                author_did,
                record_json,
                indexed_at,
                like_count,
                reply_count,
                viewer_like_uri,
                space_uri,
                child_profile,
            );

            let child_replies = fetch_replies(pool, hydrator, user_did, child_uri, space_uri, depth - 1).await?;

            let child_node = ThreadViewPost {
                post: child_post_view,
                parent: None,
                replies: if child_replies.is_empty() { None } else { Some(child_replies) },
                thread_context: None,
                extra_data: None,
            };

            reply_items.push(ThreadViewPostRepliesItem::ThreadViewPost(Box::new(child_node)));
        }

        Ok(reply_items)
    })
}
