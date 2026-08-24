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
) -> PostView {
    let embed = record_json.get("embed").and_then(|e| {
        let type_str = e.get("$type").and_then(|t| t.as_str())?;
        if type_str == "app.bsky.embed.images" {
            let images_val = e.get("images").and_then(|i| i.as_array())?;
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
                    })
                    .unwrap_or("");

                let media_url = format!(
                    "/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
                    space_uri, author_did, blob_cid
                );
                let uri_val = UriValue::new(SmolStr::new(&media_url)).unwrap_or_else(|_| {
                    UriValue::new(SmolStr::new("https://example.com/invalid")).unwrap()
                });

                view_images.push(ViewImage {
                    alt: SmolStr::new(&alt),
                    aspect_ratio: None,
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
    });

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
        serde_json::from_value(record_json.clone()).unwrap_or_else(|_| serde_json::from_str("{}").unwrap());

    let std_uri = normalize_uri_to_standard_aturi(uri);
    let aturi = AtUri::new(SmolStr::new(std_uri)).unwrap_or_else(|_| {
        AtUri::new(SmolStr::new(format!("at://{author_did}/app.bsky.feed.post/unknown"))).unwrap()
    });

    PostView {
        uri: aturi,
        cid: Cid::new(cid.as_bytes()).unwrap_or_else(|_| Cid::new(b"bafyreih327dummycid").unwrap()),
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
    }
}

#[allow(clippy::type_complexity)]
pub async fn get_feed(
    pool: &PgPool,
    hydrator: &ProfileHydrator,
    user_did: &str,
    space_filter: Option<&str>,
    limit: Option<i64>,
    cursor_str: Option<&str>,
) -> Result<GetFeedOutput, AppError> {
    let limit = limit.unwrap_or(50).clamp(1, 100) as usize;

    let cursor = match cursor_str {
        Some(c) if !c.trim().is_empty() => Some(decode_cursor(c)?),
        _ => None,
    };

    // If a specific space is filtered, verify access lease first
    if let Some(space_uri) = space_filter {
        let space_exists: Option<(Option<DateTime<Utc>>,)> = sqlx::query_as(
            "SELECT deleted_at FROM circles WHERE space_uri = $1",
        )
        .bind(space_uri)
        .fetch_optional(pool)
        .await?;

        match space_exists {
            None => return Err(AppError::NotFound("Space not found".into())),
            Some((Some(_deleted),)) => return Err(AppError::NotFound("Space deleted".into())),
            Some((None,)) => {}
        }

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
            (SELECT count(*) FROM circle_likes l WHERE l.post_uri = r.uri) AS like_count,
            (
                SELECT count(*)
                FROM circle_records rep
                WHERE rep.parent_uri = r.uri
                  AND rep.deleted_at IS NULL
                  AND (rep.root_uri IS NULL OR EXISTS (SELECT 1 FROM circle_records root WHERE root.uri = rep.root_uri AND root.deleted_at IS NULL))
            ) AS reply_count,
            (SELECT l.uri FROM circle_likes l WHERE l.post_uri = r.uri AND l.author_did = $1) AS viewer_like_uri
        FROM circle_records r
        JOIN circles c ON c.space_uri = r.space_uri AND c.deleted_at IS NULL
        JOIN access_leases a ON a.space_uri = r.space_uri AND a.member_did = $1 AND a.expires_at > now()
        LEFT JOIN circle_preferences pref ON pref.space_uri = r.space_uri AND pref.member_did = $1
        WHERE r.collection = 'app.bsky.feed.post'
          AND r.deleted_at IS NULL
          AND ($2::TEXT IS NULL OR r.space_uri = $2)
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

        let author_profile = hydrator.get_profile(author_did).await;

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
        );

        let feed_view_post = FeedViewPost {
            post: post_view,
            reply: None,
            reason: None,
            feed_context: None,
            req_id: None,
            extra_data: None,
        };

        let circle_summary = CircleSummary {
            uri: SpaceRef::new(SmolStr::new(space_uri)).unwrap_or_else(|_| {
                SpaceRef::new(SmolStr::new(format!("at://{circle_owner}/space/blue.catbird.circle/unknown"))).unwrap()
            }),
            name: SmolStr::new(circle_name),
            owner: Did::new(SmolStr::new(circle_owner)).unwrap_or_else(|_| {
                Did::new(SmolStr::new("did:plc:unknown")).unwrap()
            }),
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
