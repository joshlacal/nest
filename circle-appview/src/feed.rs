use crate::error::AppError;
use crate::hydration::ProfileHydrator;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_atproto::generated::app_bsky::embed::images::{View as ImagesView, ViewImage};
use catbird_atproto::generated::app_bsky::feed::{
    FeedViewPost, PostView, PostViewEmbed, ViewerState,
};
use catbird_atproto::generated::blue_catbird::circle::defs::{
    AccessState, CircleSummary, FeedItem, SpaceRef,
};
use catbird_atproto::generated::blue_catbird::circle::get_feed::GetFeedOutput;
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::string::{AtUri, Cid, Datetime, Did, UriValue};
use catbird_atproto::jacquard_common::types::value::Data;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedCursor {
    pub indexed_at: DateTime<Utc>,
    pub uri: String,
}

pub fn encode_cursor(cursor: &FeedCursor) -> String {
    let json_bytes = serde_json::to_vec(cursor).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(json_bytes)
}

pub fn decode_cursor(cursor_str: &str) -> Result<FeedCursor, AppError> {
    let decoded_bytes = URL_SAFE_NO_PAD
        .decode(cursor_str)
        .map_err(|_| AppError::InvalidRequest("Invalid cursor encoding".into()))?;
    let cursor: FeedCursor = serde_json::from_slice(&decoded_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid cursor payload".into()))?;
    Ok(cursor)
}

pub fn normalize_uri_to_standard_aturi(uri: &str) -> String {
    if let Some(col_idx) = uri.rfind("/app.bsky.") {
        let prefix = &uri[..col_idx];
        if let Some(slash_idx) = prefix.rfind('/') {
            let did = &prefix[slash_idx + 1..];
            let rest = &uri[col_idx..];
            return format!("at://{did}{rest}");
        }
    }
    uri.to_string()
}

#[allow(clippy::too_many_arguments)]
pub fn build_post_view(
    uri: &str,
    cid: &str,
    author_did: &str,
    record_json: &serde_json::Value,
    indexed_at: DateTime<Utc>,
    like_count: i64,
    reply_count: i64,
    viewer_like_uri: Option<&str>,
    space_uri: &str,
    author_profile: catbird_atproto::generated::app_bsky::actor::ProfileViewBasic,
    media_base_url: &url::Url,
) -> Result<PostView, AppError> {
    let embed = if let Some(e) = record_json.get("embed") {
        let type_str = e.get("$type").and_then(|t| t.as_str());
        if type_str == Some("app.bsky.embed.images") {
            let images_val = e.get("images").and_then(|i| i.as_array())
                .ok_or_else(|| AppError::InvalidRequest("Invalid images embed".into()))?;
            let mut view_images = Vec::new();
            for img in images_val {
                let alt = img.get("alt").and_then(|a| a.as_str()).unwrap_or("").to_string();
                let blob_cid = img
                    .get("image")
                    .and_then(|i| i.get("ref"))
                    .and_then(|r| r.get("$link"))
                    .and_then(|l| l.as_str())
                    .or_else(|| {
                        img.get("image")
                            .and_then(|i| i.get("cid"))
                            .and_then(|c| c.as_str())
                    });

                let blob_cid = match blob_cid {
                    Some(cid) if !cid.is_empty() => cid,
                    _ => return Err(AppError::InvalidRequest("Missing blob CID in image embed".into())),
                };

                let mut media_url_parsed = media_base_url.join("/xrpc/blue.catbird.circle.getMedia")
                    .map_err(|e| AppError::Internal(format!("Invalid media endpoint URL: {e}")))?;
                media_url_parsed
                    .query_pairs_mut()
                    .append_pair("space", space_uri)
                    .append_pair("did", author_did)
                    .append_pair("cid", blob_cid);
                let media_url = media_url_parsed.to_string();
                let uri_val = UriValue::new(SmolStr::new(&media_url))
                    .map_err(|e| AppError::Internal(format!("Invalid media URI: {e}")))?;

                let aspect_ratio = img.get("aspectRatio").and_then(|ar| {
                    let width = ar.get("width")?.as_i64()?;
                    let height = ar.get("height")?.as_i64()?;
                    if width >= 1 && height >= 1 {
                        Some(catbird_atproto::generated::app_bsky::embed::AspectRatio {
                            width,
                            height,
                            extra_data: None,
                        })
                    } else {
                        None
                    }
                });

                view_images.push(ViewImage {
                    alt: SmolStr::new(&alt),
                    aspect_ratio,
                    fullsize: uri_val.clone(),
                    thumb: uri_val,
                    extra_data: None,
                });
            }
            Some(PostViewEmbed::ImagesView(Box::new(ImagesView {
                images: view_images,
                extra_data: None,
            })))
        } else {
            None
        }
    } else {
        None
    };

    let viewer = viewer_like_uri.map(|like_uri| {
        let std_like_uri = normalize_uri_to_standard_aturi(like_uri);
        ViewerState {
            like: AtUri::new(SmolStr::new(std_like_uri)).ok(),
            repost: None,
            bookmarked: None,
            embedding_disabled: None,
            known_likers: None,
            pinned: None,
            reply_disabled: None,
            thread_muted: None,
            extra_data: None,
        }
    });

    let record_data: Data =
        serde_json::from_value(record_json.clone()).map_err(|e| AppError::Internal(format!("Invalid record data: {e}")))?;

    let std_uri = normalize_uri_to_standard_aturi(uri);
    let aturi = AtUri::new(SmolStr::new(std_uri)).map_err(|e| AppError::Internal(format!("Invalid post URI: {e}")))?;
    let cid_val = Cid::new(cid.as_bytes()).map_err(|e| AppError::Internal(format!("Invalid post CID: {e}")))?;

    Ok(PostView {
        uri: aturi,
        cid: cid_val,
        author: author_profile,
        record: record_data,
        indexed_at: Datetime::new(indexed_at.into()),
        like_count: Some(like_count),
        reply_count: Some(reply_count),
        repost_count: None,
        quote_count: None,
        bookmark_count: None,
        embed,
        labels: None,
        threadgate: None,
        viewer,
        debug: None,
        extra_data: None,
    })
}

#[allow(clippy::type_complexity)]
pub async fn get_feed(
    pool: &PgPool,
    hydrator: &ProfileHydrator,
    user_did: &str,
    space_filter: Option<&str>,
    limit: Option<i64>,
    cursor_str: Option<&str>,
    media_base_url: &url::Url,
) -> Result<GetFeedOutput, AppError> {
    let limit = limit.unwrap_or(50).clamp(1, 100) as usize;

    let cursor = match cursor_str {
        Some(c) if !c.trim().is_empty() => Some(decode_cursor(c)?),
        _ => None,
    };

    // If a specific space is filtered, verify access lease and membership
    if let Some(space_uri) = space_filter {
        let space_info: Option<(Option<DateTime<Utc>>, Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
            r#"
            SELECT c.deleted_at, m.status, a.expires_at
            FROM circles c
            LEFT JOIN circle_members m ON m.space_uri = c.space_uri AND m.member_did = $2
            LEFT JOIN access_leases a ON a.space_uri = c.space_uri AND a.member_did = $2
            WHERE c.space_uri = $1
            "#,
        )
        .bind(space_uri)
        .bind(user_did)
        .fetch_optional(pool)
        .await?;

        match space_info {
            None => return Err(AppError::NotFound("Space not found".into())),
            Some((Some(_), _, _)) => return Err(AppError::NotFound("Space deleted".into())),
            Some((None, member_status, expires_at)) => {
                let is_active_member = member_status.as_deref() == Some("active");
                let has_valid_lease = expires_at.is_some_and(|exp| exp > Utc::now());
                if !is_active_member || !has_valid_lease {
                    return Err(AppError::AccessRemoved(
                        "No active access lease for this Circle".into(),
                    ));
                }
            }
        }
    }

    // Authorize cursor Space if cursor provided
    if let Some(ref c) = cursor {
        let alt_cursor_uri = if c.uri.contains("/space/") {
            normalize_uri_to_standard_aturi(&c.uri)
        } else if let Some(rest) = c.uri.strip_prefix("at://") {
            format!("at://{rest}")
        } else {
            c.uri.clone()
        };

        let cursor_space: Option<(String,)> = sqlx::query_as(
            "SELECT space_uri FROM circle_records WHERE uri = $1 OR uri = $2 LIMIT 1",
        )
        .bind(&c.uri)
        .bind(&alt_cursor_uri)
        .fetch_optional(pool)
        .await?;

        let cursor_space_uri = match cursor_space {
            Some((sp,)) => sp,
            None => {
                if c.uri.contains("/space/") {
                    let parts: Vec<&str> = c.uri.split("/app.bsky.feed.post/").collect();
                    if let Some(prefix) = parts.first() {
                        prefix.to_string()
                    } else {
                        return Err(AppError::InvalidRequest("Invalid cursor URI".into()));
                    }
                } else {
                    return Err(AppError::InvalidRequest("Invalid cursor URI".into()));
                }
            }
        };

        let cursor_lease: Option<(i32,)> = sqlx::query_as(
            r#"
            SELECT 1
            FROM circles c
            JOIN access_leases a ON a.space_uri = c.space_uri AND a.member_did = $1 AND a.expires_at > now()
            JOIN circle_members m ON m.space_uri = c.space_uri AND m.member_did = $1 AND m.status = 'active'
            WHERE c.space_uri = $2 AND c.deleted_at IS NULL
            "#,
        )
        .bind(user_did)
        .bind(&cursor_space_uri)
        .fetch_optional(pool)
        .await?;

        if cursor_lease.is_none() {
            return Err(AppError::AccessRemoved(
                "Access removed for cursor Space".into(),
            ));
        }
    }

    // Fetch feed posts with counts and viewer like state
    let fetch_limit = (limit + 1) as i64;
    let (cursor_indexed_at, cursor_uri) = match &cursor {
        Some(c) => (Some(c.indexed_at), Some(c.uri.as_str())),
        None => (None, None),
    };

    let rows: Vec<(
        String,           // uri
        String,           // cid
        String,           // space_uri
        String,           // author_did
        serde_json::Value,// record_json
        DateTime<Utc>,    // indexed_at
        String,           // circle_name
        String,           // circle_owner
        bool,             // circle_muted
        i64,              // like_count
        i64,              // reply_count
        Option<String>,   // viewer_like_uri
        i64,              // circle_generation
    )> = sqlx::query_as(
        r#"
        SELECT
            r.uri,
            r.cid,
            r.space_uri,
            r.author_did,
            r.record_json,
            r.indexed_at,
            c.display_name AS circle_name,
            c.authority_did AS circle_owner,
            COALESCE(pref.muted, false) AS circle_muted,
            (SELECT count(*) FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE l.post_uri = r.uri AND l.space_uri = r.space_uri) AS like_count,
            (
                SELECT count(*)
                FROM circle_records rep
                WHERE rep.parent_uri = r.uri
                  AND rep.space_uri = r.space_uri
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
                             AND root.space_uri = r.space_uri
                             AND root.deleted_at IS NULL
                             AND root.collection = 'app.bsky.feed.post'
                       )
                   )
                   AND (
                       rep.parent_uri IS NULL
                       OR EXISTS (
                           SELECT 1 FROM circle_records p
                           WHERE (p.uri = rep.parent_uri OR p.uri = (
                               CASE
                                   WHEN rep.parent_uri LIKE '%/space/%' THEN 'at://' || SPLIT_PART(rep.parent_uri, '/space/', 2)
                                   ELSE rep.parent_uri
                               END
                           ))
                             AND p.space_uri = r.space_uri
                             AND p.deleted_at IS NULL
                             AND p.collection = 'app.bsky.feed.post'
                       )
                   )
             ) AS reply_count,
            (SELECT l.uri FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL WHERE l.post_uri = r.uri AND l.space_uri = r.space_uri AND l.author_did = $1) AS viewer_like_uri,
            c.generation AS circle_generation
        FROM circle_records r
        JOIN circles c ON c.space_uri = r.space_uri AND c.deleted_at IS NULL
        JOIN access_leases a ON a.space_uri = r.space_uri AND a.member_did = $1 AND a.expires_at > now()
        JOIN circle_members m ON m.space_uri = r.space_uri AND m.member_did = $1 AND m.status = 'active'
        LEFT JOIN circle_preferences pref ON pref.space_uri = r.space_uri AND pref.member_did = $1
        WHERE r.collection = 'app.bsky.feed.post'
          AND r.deleted_at IS NULL
          AND r.parent_uri IS NULL
          AND ($2::TEXT IS NULL OR r.space_uri = $2)
          AND ($2::TEXT IS NOT NULL OR COALESCE(pref.muted, false) = false)
          AND (
              $3::TIMESTAMPTZ IS NULL
              OR (r.indexed_at, r.uri) < ($3, $4)
          )
        ORDER BY r.indexed_at DESC, r.uri DESC
        LIMIT $5
        "#,
    )
    .bind(user_did)
    .bind(space_filter)
    .bind(cursor_indexed_at)
    .bind(cursor_uri)
    .bind(fetch_limit)
    .fetch_all(pool)
    .await?;

    let has_more = rows.len() > limit;
    let page_rows = if has_more { &rows[..limit] } else { &rows[..] };

    let mut space_gens = std::collections::HashMap::new();
    for row in page_rows {
        space_gens.insert(row.2.clone(), row.12);
    }
    if let Some(filtered_space) = space_filter {
        if space_gens.is_empty() {
            let gen_row: Option<(i64,)> = sqlx::query_as("SELECT generation FROM circles WHERE space_uri = $1 AND deleted_at IS NULL")
                .bind(filtered_space)
                .fetch_optional(pool)
                .await?;
            if let Some((g,)) = gen_row {
                space_gens.insert(filtered_space.to_string(), g);
            }
        }
    }

    let author_dids: Vec<&str> = page_rows.iter().map(|r| r.3.as_str()).collect();
    let profiles_map = hydrator.get_profiles(&author_dids).await;

    // Recheck authorization and generation for all involved Spaces after profile hydration
    for (sp, gen) in &space_gens {
        let valid: Option<(i32,)> = sqlx::query_as(
            r#"
            SELECT 1
            FROM circles c
            JOIN access_leases a ON a.space_uri = c.space_uri AND a.member_did = $1 AND a.expires_at > now()
            JOIN circle_members m ON m.space_uri = c.space_uri AND m.member_did = $1 AND m.status = 'active'
            WHERE c.space_uri = $2 AND c.generation = $3 AND c.deleted_at IS NULL
            "#,
        )
        .bind(user_did)
        .bind(sp)
        .bind(gen)
        .fetch_optional(pool)
        .await?;

        if valid.is_none() {
            return Err(AppError::AccessRemoved(
                "Access removed for this Circle".into(),
            ));
        }
    }

    let mut feed_items = Vec::with_capacity(page_rows.len());

    for row in page_rows {
        let uri = &row.0;
        let cid = &row.1;
        let space_uri = &row.2;
        let author_did = &row.3;
        let record_json = &row.4;
        let indexed_at = row.5;
        let circle_name = &row.6;
        let circle_owner = &row.7;
        let circle_muted = row.8;
        let like_count = row.9;
        let reply_count = row.10;
        let viewer_like_uri = row.11.as_deref();

        let author_profile = profiles_map
            .get(author_did)
            .cloned()
            .unwrap_or_else(|| ProfileHydrator::unavailable_profile(author_did));

        let post_view = build_post_view(
            uri,
            cid,
            author_did,
            record_json,
            indexed_at,
            like_count,
            reply_count,
            viewer_like_uri,
            space_uri,
            author_profile,
            media_base_url,
        )?;

        let feed_view_post = FeedViewPost {
            post: post_view,
            reply: None,
            reason: None,
            feed_context: None,
            req_id: None,
            extra_data: None,
        };

        let circle_space_ref = SpaceRef::new(SmolStr::new(space_uri))
            .map_err(|e| AppError::Internal(format!("Invalid Space URI '{space_uri}': {e}")))?;
        let circle_owner_did = Did::new(SmolStr::new(circle_owner))
            .map_err(|e| AppError::Internal(format!("Invalid circle owner DID '{circle_owner}': {e}")))?;

        let circle_summary = CircleSummary {
            uri: circle_space_ref,
            name: SmolStr::new(circle_name),
            owner: circle_owner_did,
            access_state: AccessState::Active,
            muted: Some(circle_muted),
            extra_data: None,
        };

        feed_items.push(FeedItem {
            post: feed_view_post,
            circle: circle_summary,
            extra_data: None,
        });
    }

    let next_cursor = if has_more {
        page_rows.last().map(|last_item| {
            SmolStr::new(encode_cursor(&FeedCursor {
                indexed_at: last_item.5,
                uri: last_item.0.clone(),
            }))
        })
    } else {
        None
    };

    Ok(GetFeedOutput {
        feed: feed_items,
        cursor: next_cursor,
        extra_data: None,
    })
}
