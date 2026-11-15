use crate::access;
use crate::config::AppState;
use crate::error::AppError;
use crate::hydration::ProfileHydrator;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_atproto::generated::app_bsky::actor::ProfileViewBasic;
use catbird_atproto::generated::app_bsky::embed::images::{View as ImagesView, ViewImage};
use catbird_atproto::generated::app_bsky::feed::{
    FeedViewPost, PostView, PostViewEmbed, ViewerState,
};
use catbird_atproto::generated::blue_catbird::circle::get_feed::GetFeedOutput;
use catbird_atproto::generated::blue_catbird::circle::post::Post as EncryptedPostRecord;
use catbird_atproto::generated::blue_catbird::circle::{
    CircleSummary, EncryptedPostView, FeedItem, FeedItemPost,
};
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::aturi::AtSpaceUri;
use catbird_atproto::jacquard_common::types::string::{AtUri, Cid, Datetime, Did, Tid, UriValue};
use catbird_atproto::jacquard_common::types::value::Data;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

/// Collection of encrypted Circle post envelopes.
pub const ENCRYPTED_POST_COLLECTION: &str = "blue.catbird.circle.post";

/// The Circle's current key version for a `CircleSummary`: `None` for a plaintext
/// Space or an encrypted Space without indexed key records.
pub async fn summary_key_version(
    pool: &sqlx::PgPool,
    space_uri: &str,
) -> Result<Option<i64>, AppError> {
    Ok(crate::sync::latest_key_version(pool, space_uri)
        .await?
        .map(|(version, _)| version))
}

pub fn normalize_uri_to_standard_aturi(uri: &str) -> String {
    let col_idx = uri
        .rfind("/app.bsky.")
        .or_else(|| uri.rfind(&format!("/{ENCRYPTED_POST_COLLECTION}/")));
    if let Some(col_idx) = col_idx {
        let prefix = &uri[..col_idx];
        let last_segment = prefix.rsplit('/').next().unwrap_or("");
        let did = if last_segment.starts_with("did:") {
            last_segment
        } else {
            let stripped = prefix.strip_prefix("at://").unwrap_or(prefix);
            stripped.split('/').next().unwrap_or(stripped)
        };
        let rest = &uri[col_idx..];
        return format!("at://{did}{rest}");
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
        if crate::SUPPORTS_IMAGES && type_str == Some("app.bsky.embed.images") {
            let images_val = e
                .get("images")
                .and_then(|i| i.as_array())
                .ok_or_else(|| AppError::InvalidRequest("Invalid images embed".into()))?;
            let mut view_images = Vec::new();
            for img in images_val {
                let alt = img
                    .get("alt")
                    .and_then(|a| a.as_str())
                    .unwrap_or("")
                    .to_string();
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
                    _ => {
                        return Err(AppError::InvalidRequest(
                            "Missing blob CID in image embed".into(),
                        ))
                    }
                };

                let mut media_url_parsed = media_base_url
                    .join("/xrpc/blue.catbird.circle.getMedia")
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

    let viewer = viewer_state(viewer_like_uri);

    let record_data: Data = serde_json::from_value(record_json.clone())
        .map_err(|e| AppError::Internal(format!("Invalid record data: {e}")))?;

    let (aturi, cid_val) = post_identity(uri, cid)?;

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

/// The viewer state for a post: only the viewer's own like is tracked.
fn viewer_state(viewer_like_uri: Option<&str>) -> Option<ViewerState> {
    viewer_like_uri.map(|like_uri| {
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
    })
}

/// The served URI (standard `at://did/collection/rkey` form) and CID of a post row.
fn post_identity(uri: &str, cid: &str) -> Result<(AtUri, Cid), AppError> {
    let std_uri = normalize_uri_to_standard_aturi(uri);
    let aturi = AtUri::new(SmolStr::new(std_uri))
        .map_err(|e| AppError::Internal(format!("Invalid post URI: {e}")))?;
    let cid_val = Cid::new(cid.as_bytes())
        .map_err(|e| AppError::Internal(format!("Invalid post CID: {e}")))?;
    Ok((aturi, cid_val))
}

/// View of a `blue.catbird.circle.post` envelope. The record is passed through as
/// stored (plaintext header plus ciphertext); counts and viewer state are computed
/// exactly as for `build_post_view`.
#[allow(clippy::too_many_arguments)]
pub fn build_encrypted_post_view(
    uri: &str,
    cid: &str,
    author_did: &str,
    record_json: &serde_json::Value,
    indexed_at: DateTime<Utc>,
    like_count: i64,
    reply_count: i64,
    viewer_like_uri: Option<&str>,
    author_profile: ProfileViewBasic,
) -> Result<EncryptedPostView, AppError> {
    let record: EncryptedPostRecord =
        crate::validator::from_value_borrowed(record_json).map_err(|e| {
            AppError::Internal(format!(
                "Invalid encrypted post record from {author_did}: {e}"
            ))
        })?;
    let (aturi, cid_val) = post_identity(uri, cid)?;
    Ok(EncryptedPostView {
        uri: aturi,
        cid: cid_val,
        author: author_profile,
        record,
        indexed_at: Datetime::new(indexed_at.into()),
        like_count: Some(like_count),
        reply_count: Some(reply_count),
        viewer: viewer_state(viewer_like_uri),
        extra_data: None,
    })
}

#[allow(clippy::type_complexity)]
pub async fn get_feed(
    state: &AppState,
    user_did: &str,
    space_filter: Option<&str>,
    limit: Option<i64>,
    cursor_str: Option<&str>,
    include_encrypted: bool,
) -> Result<GetFeedOutput, AppError> {
    let limit = limit.unwrap_or(50).clamp(1, 100) as usize;

    let cursor = match cursor_str {
        Some(c) if !c.trim().is_empty() => Some(decode_cursor(c)?),
        _ => None,
    };

    // If a specific space is filtered, verify access via member cache (revalidating on miss/stale)
    if let Some(space_uri) = space_filter {
        access::check_member_access(state, space_uri, user_did).await?;
    } else {
        access::revalidate_stale_member_spaces(state, user_did).await?;
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
        .fetch_optional(&state.db)
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

        access::check_member_access(state, &cursor_space_uri, user_did).await?;
    }

    let fetch_limit = (limit + 1) as i64;
    let (cursor_indexed_at, cursor_uri) = match &cursor {
        Some(c) => (Some(c.indexed_at), Some(c.uri.as_str())),
        None => (None, None),
    };

    let rows: Vec<(
        String,           // uri
        String,           // cid
        String,           // space_uri
        String,           // circle_id
        String,           // author_did
        serde_json::Value,// record_json
        DateTime<Utc>,    // indexed_at
        String,           // collection
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
            c.circle_id,
            r.author_did,
            r.record_json,
            r.indexed_at,
            r.collection,
            c.display_name AS circle_name,
            c.authority_did AS circle_owner,
            COALESCE(pref.muted, false) AS circle_muted,
            (SELECT count(*) FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL AND lr.author_did NOT IN (SELECT did FROM circle_account_status WHERE NOT active) WHERE l.post_uri = r.uri AND l.space_uri = r.space_uri) AS like_count,
            (
                SELECT count(*)
                FROM circle_records rep
                WHERE rep.parent_uri = r.uri
                  AND rep.space_uri = r.space_uri
                  AND rep.deleted_at IS NULL AND NOT rep.stale_key AND rep.author_did NOT IN (SELECT did FROM circle_account_status WHERE NOT active)
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
                             AND root.deleted_at IS NULL AND NOT root.stale_key AND root.author_did NOT IN (SELECT did FROM circle_account_status WHERE NOT active)
                             AND root.collection IN ('app.bsky.feed.post', 'blue.catbird.circle.post')
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
                             AND p.deleted_at IS NULL AND NOT p.stale_key AND p.author_did NOT IN (SELECT did FROM circle_account_status WHERE NOT active)
                             AND p.collection IN ('app.bsky.feed.post', 'blue.catbird.circle.post')
                       )
                   )
             ) AS reply_count,
            (SELECT l.uri FROM circle_likes l JOIN circle_records lr ON lr.uri = l.uri AND lr.deleted_at IS NULL AND lr.author_did NOT IN (SELECT did FROM circle_account_status WHERE NOT active) WHERE l.post_uri = r.uri AND l.space_uri = r.space_uri AND l.author_did = $1) AS viewer_like_uri
        FROM circle_records r
        JOIN circles c ON c.space_uri = r.space_uri AND c.deleted_at IS NULL AND c.authority_did NOT IN (SELECT did FROM circle_account_status WHERE NOT active) AND c.app_access_granted = true
        LEFT JOIN circle_member_cache m ON m.space_uri = r.space_uri AND m.member_did = $1 AND m.can_read = true
        LEFT JOIN circle_member_cache_meta meta ON meta.space_uri = r.space_uri
        LEFT JOIN circle_preferences pref ON pref.space_uri = r.space_uri AND pref.member_did = $1
        WHERE r.collection IN ('app.bsky.feed.post', 'blue.catbird.circle.post')
          AND r.deleted_at IS NULL AND NOT r.stale_key AND r.author_did NOT IN (SELECT did FROM circle_account_status WHERE NOT active)
          AND r.parent_uri IS NULL
          AND (
              c.authority_did = $1
              OR (
                  m.member_did IS NOT NULL
                  AND meta.app_access_granted = true
                  AND meta.access_epoch = c.access_epoch
                  AND meta.last_refreshed_at > now() - INTERVAL '30 seconds'
              )
          )
          AND ($2::TEXT IS NULL OR r.space_uri = $2)
          AND ($2::TEXT IS NOT NULL OR COALESCE(pref.muted, false) = false)
          AND ($6::BOOLEAN OR r.collection <> 'blue.catbird.circle.post')
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
    .bind(include_encrypted)
    .fetch_all(&state.db)
    .await?;

    let has_more = rows.len() > limit;
    let page_rows = if has_more { &rows[..limit] } else { &rows[..] };

    let author_dids: Vec<&str> = page_rows.iter().map(|r| r.4.as_str()).collect();
    let profiles_map = state.profile_hydrator.get_profiles(&author_dids).await;

    let mut feed_items = Vec::with_capacity(page_rows.len());
    let mut key_versions: std::collections::HashMap<&str, Option<i64>> =
        std::collections::HashMap::new();

    for row in page_rows {
        let uri = &row.0;
        let cid = &row.1;
        let space_uri = &row.2;
        let circle_id = &row.3;
        let author_did = &row.4;
        let record_json = &row.5;
        let indexed_at = row.6;
        let collection = &row.7;
        let circle_name = &row.8;
        let circle_owner = &row.9;
        let circle_muted = row.10;
        let like_count = row.11;
        let reply_count = row.12;
        let viewer_like_uri = row.13.as_deref();

        let author_profile = profiles_map
            .get(author_did)
            .cloned()
            .unwrap_or_else(|| ProfileHydrator::unavailable_profile(author_did));

        let post = if collection == ENCRYPTED_POST_COLLECTION {
            FeedItemPost::EncryptedPostView(Box::new(build_encrypted_post_view(
                uri,
                cid,
                author_did,
                record_json,
                indexed_at,
                like_count,
                reply_count,
                viewer_like_uri,
                author_profile,
            )?))
        } else {
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
                &state.config.circle_media_base_url,
            )?;
            FeedItemPost::FeedViewPost(Box::new(FeedViewPost {
                post: post_view,
                reply: None,
                reason: None,
                feed_context: None,
                req_id: None,
                op_thread_post_index: None,
                op_thread_post_count: None,
                extra_data: None,
            }))
        };

        let circle_tid = Tid::new(SmolStr::new(circle_id))
            .map_err(|e| AppError::Internal(format!("Invalid circle TID '{circle_id}': {e}")))?;
        let circle_space_ref = AtSpaceUri::new(SmolStr::new(space_uri))
            .map_err(|e| AppError::Internal(format!("Invalid Space URI '{space_uri}': {e}")))?;
        let circle_owner_did = Did::new(SmolStr::new(circle_owner)).map_err(|e| {
            AppError::Internal(format!("Invalid circle owner DID '{circle_owner}': {e}"))
        })?;
        let latest_key_version = match key_versions.get(space_uri.as_str()) {
            Some(version) => *version,
            None => {
                let version = summary_key_version(&state.db, space_uri).await?;
                key_versions.insert(space_uri.as_str(), version);
                version
            }
        };

        let circle_summary = CircleSummary {
            circle_id: circle_tid,
            uri: circle_space_ref,
            name: SmolStr::new(circle_name),
            owner: circle_owner_did,
            member_count: None,
            muted: Some(circle_muted),
            latest_key_version,
            extra_data: None,
        };

        feed_items.push(FeedItem {
            post,
            circle: circle_summary,
            extra_data: None,
        });
    }

    let next_cursor = if has_more {
        page_rows.last().map(|last_item| {
            SmolStr::new(encode_cursor(&FeedCursor {
                indexed_at: last_item.6,
                uri: last_item.0.clone(),
            }))
        })
    } else {
        None
    };

    let spaces: std::collections::HashSet<_> = feed_items
        .iter()
        .map(|item| item.circle.uri.as_str())
        .collect();
    for space in spaces {
        access::check_member_access(state, space, user_did).await?;
    }
    for item in &feed_items {
        let author_did = match &item.post {
            FeedItemPost::FeedViewPost(view) => view.post.author.did.as_str(),
            FeedItemPost::EncryptedPostView(view) => view.author.did.as_str(),
            FeedItemPost::Unknown(_) => {
                return Err(AppError::Internal("feed item without a post view".into()))
            }
        };
        crate::identity_events::require_active_account(&state.db, author_did).await?;
    }
    Ok(GetFeedOutput {
        feed: feed_items,
        cursor: next_cursor,
        extra_data: None,
    })
}
