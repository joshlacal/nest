use crate::config::AppState;
use crate::error::AppError;
use crate::hydration::ProfileHydrator;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_atproto::generated::blue_catbird::circle::{
    CircleSummary, Notification, NotificationReason,
};
use catbird_atproto::generated::blue_catbird::circle::list_notifications::ListNotificationsOutput;
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::aturi::AtSpaceUri;
use catbird_atproto::jacquard_common::types::string::{AtUri, Datetime, Did, Tid};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationCursor {
    pub created_at: DateTime<Utc>,
    pub id: Uuid,
}

pub fn encode_cursor(cursor: &NotificationCursor) -> String {
    let json_bytes = serde_json::to_vec(cursor).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(json_bytes)
}

pub fn decode_cursor(cursor_str: &str) -> Result<NotificationCursor, AppError> {
    let decoded_bytes = URL_SAFE_NO_PAD
        .decode(cursor_str)
        .map_err(|_| AppError::InvalidRequest("Invalid notification cursor encoding".into()))?;
    let cursor: NotificationCursor = serde_json::from_slice(&decoded_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid notification cursor payload".into()))?;
    Ok(cursor)
}

#[allow(clippy::type_complexity)]
pub async fn list_notifications(
    state: &AppState,
    recipient_did: &str,
    limit: Option<i64>,
    cursor_str: Option<&str>,
) -> Result<ListNotificationsOutput, AppError> {
    let limit = limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(AppError::InvalidRequest(
            "Limit must be between 1 and 100".into(),
        ));
    }

    crate::access::revalidate_stale_member_spaces(state, recipient_did).await?;
    let cursor = match cursor_str {
        Some(c) if !c.trim().is_empty() => Some(decode_cursor(c)?),
        _ => None,
    };

    let (cursor_created_at, cursor_id) = match &cursor {
        Some(c) => (Some(c.created_at), Some(c.id)),
        None => (None, None),
    };

    let fetch_limit = limit + 1;

    let rows: Vec<(
        Uuid,             // id
        String,           // space_uri
        String,           // circle_id
        String,           // actor_did
        String,           // reason
        Option<String>,   // subject_uri
        DateTime<Utc>,    // created_at
        String,           // circle_name
        String,           // circle_owner
        bool,             // circle_muted
    )> = sqlx::query_as(
        r#"
        SELECT
            n.id,
            n.space_uri,
            c.circle_id,
            n.actor_did,
            n.reason,
            n.subject_uri,
            n.created_at,
            c.display_name AS circle_name,
            c.authority_did AS circle_owner,
            COALESCE(pref.muted, false) AS circle_muted
        FROM circle_notifications n
        JOIN circles c ON c.space_uri = n.space_uri AND c.deleted_at IS NULL
        JOIN circle_member_cache m ON m.space_uri = n.space_uri AND m.member_did = $1
        JOIN circle_member_cache_meta meta ON meta.space_uri = n.space_uri AND meta.last_refreshed_at > now() - INTERVAL '300 seconds'
        LEFT JOIN circle_preferences pref ON pref.space_uri = n.space_uri AND pref.member_did = $1
        WHERE n.recipient_did = $1
          AND COALESCE(pref.muted, false) = false
          AND (
              $2::TIMESTAMPTZ IS NULL
              OR (n.created_at, n.id) < ($2, $3)
          )
        ORDER BY n.created_at DESC, n.id DESC
        LIMIT $4
        "#,
    )
    .bind(recipient_did)
    .bind(cursor_created_at)
    .bind(cursor_id)
    .bind(fetch_limit)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    let has_more = rows.len() > limit as usize;
    let result_rows = if has_more {
        &rows[..limit as usize]
    } else {
        &rows[..]
    };

    let next_cursor = if has_more {
        result_rows.last().map(|r| {
            encode_cursor(&NotificationCursor {
                created_at: r.6,
                id: r.0,
            })
        })
    } else {
        None
    };

    if result_rows.is_empty() {
        return Ok(ListNotificationsOutput {
            cursor: None,
            notifications: Vec::new(),
            extra_data: None,
        });
    }

    // Collect distinct actor DIDs for hydration
    let mut unique_dids = std::collections::HashSet::new();
    for r in result_rows {
        unique_dids.insert(r.3.as_str());
    }
    let actor_did_refs: Vec<&str> = unique_dids.into_iter().collect();
    let profiles = state.profile_hydrator.get_profiles(&actor_did_refs).await;
    let mut notifications = Vec::with_capacity(result_rows.len());

    for row in result_rows {
        let notif_id = row.0;
        let space_uri = &row.1;
        let circle_id = &row.2;
        let actor_did = &row.3;
        let reason_str = &row.4;
        let subject_uri = row.5.as_deref();
        let created_at = row.6;
        let circle_name = &row.7;
        let circle_owner = &row.8;
        let circle_muted = row.9;

        let actor_profile = profiles
            .get(actor_did)
            .cloned()
            .unwrap_or_else(|| ProfileHydrator::unavailable_profile(actor_did));

        let reason = match reason_str.as_str() {
            "reply" => NotificationReason::Reply,
            "like" => NotificationReason::Like,
            "invite" => NotificationReason::Invite,
            other => NotificationReason::Other(SmolStr::new(other)),
        };

        let circle_tid = Tid::new(SmolStr::new(circle_id))
            .map_err(|e| AppError::Internal(format!("Invalid circle TID: {e}")))?;
        let circle_space_ref = AtSpaceUri::new(SmolStr::new(space_uri))
            .map_err(|e| AppError::Internal(format!("Invalid space ref: {e}")))?;
        let circle_owner_did = Did::new(SmolStr::new(circle_owner))
            .map_err(|e| AppError::Internal(format!("Invalid owner DID: {e}")))?;

        let circle_summary = CircleSummary {
            circle_id: circle_tid,
            uri: circle_space_ref,
            name: SmolStr::new(circle_name),
            owner: circle_owner_did,
            member_count: None,
            muted: Some(circle_muted),
            extra_data: None,
        };

        let dt = Datetime::try_from(created_at.to_rfc3339())
            .map_err(|e| AppError::Internal(format!("Failed to format datetime: {e}")))?;

        let subject_at_uri = match subject_uri {
            Some(u) => {
                let normalized = crate::feed::normalize_uri_to_standard_aturi(u);
                Some(
                    AtUri::new(SmolStr::new(normalized))
                        .map_err(|e| AppError::Internal(format!("Invalid subject URI: {e}")))?,
                )
            }
            None => None,
        };

        notifications.push(Notification {
            id: SmolStr::new(notif_id.to_string()),
            actor: actor_profile,
            circle: circle_summary,
            reason,
            subject: subject_at_uri,
            indexed_at: dt,
            extra_data: None,
        });
    }

    Ok(ListNotificationsOutput {
        cursor: next_cursor.map(SmolStr::new),
        notifications,
        extra_data: None,
    })
}
