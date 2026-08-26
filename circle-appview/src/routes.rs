use axum::{
    extract::{Extension, Query, State},
    middleware,
    routing::{get, post},
    Json, Router,
};
use catbird_atproto::generated::blue_catbird::circle::{
    activate_circle::{ActivateCircle, ActivateCircleOutput},
    CircleSummary,
    get_capabilities::GetCapabilitiesOutput,
    list_circles::{ListCircles, ListCirclesOutput},
};
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::aturi::AtSpaceUri;
use catbird_atproto::jacquard_common::types::string::{Did, Tid};
use chrono::{DateTime, Utc};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::CIRCLE_PROTOCOL_REVISION;
use crate::access;
use crate::auth::{self, AuthenticatedUser};
use crate::config::AppState;
use crate::error::AppError;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

pub fn create_router(state: AppState) -> Router {
    // Unauthenticated public endpoints
    let public_routes = Router::new()
        .route("/_health", get(health_check))
        .route("/xrpc/_health", get(health_check))
        .route("/.well-known/did.json", get(did_document_handler))
        .route("/did.json", get(did_document_handler))
        .route(
            "/oauth/client-metadata.json",
            get(crate::oauth::client_metadata_handler),
        )
        .route(
            "/.well-known/oauth-client-metadata.json",
            get(crate::oauth::client_metadata_handler),
        )
        .route("/oauth/jwks.json", get(crate::oauth::jwks_handler))
        .route("/.well-known/jwks.json", get(crate::oauth::jwks_handler))
        .route("/oauth/start", get(crate::oauth::oauth_start_handler))
        .route("/oauth/callback", get(crate::oauth::oauth_callback_handler))
        .route(
            "/xrpc/blue.catbird.circle.getCapabilities",
            get(get_capabilities),
        )
        .route(
            "/xrpc/com.atproto.space.notifyWrite",
            post(crate::sync::notify_write_handler),
        )
        .route(
            "/xrpc/com.atproto.space.notifySpaceDeleted",
            post(crate::sync::notify_space_deleted_handler),
        );

    // Authenticated XRPC endpoints
    let authenticated_routes = Router::new()
        .route(
            "/xrpc/blue.catbird.circle.getFeed",
            get(crate::handlers::feed::get_feed_handler),
        )
        .route(
            "/xrpc/blue.catbird.circle.getPostThread",
            get(crate::handlers::thread::get_post_thread_handler),
        )
        .route(
            "/xrpc/blue.catbird.circle.listCircles",
            get(list_circles_handler),
        )
        .route(
            "/xrpc/blue.catbird.circle.listNotifications",
            get(crate::handlers::notifications::list_notifications_handler),
        )
        .route(
            "/xrpc/blue.catbird.circle.getMedia",
            get(crate::handlers::media::get_media_handler),
        )
        .route(
            "/xrpc/blue.catbird.circle.updatePreferences",
            post(crate::handlers::moderation::update_preferences_handler),
        )
        .route(
            "/xrpc/blue.catbird.circle.reportRecord",
            post(crate::handlers::moderation::report_record_handler),
        )
        .route(
            "/xrpc/blue.catbird.circle.activateCircle",
            post(activate_circle_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ));

    Router::new()
        .merge(public_routes)
        .merge(authenticated_routes)
        .with_state(state)
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn did_document_handler(State(state): State<AppState>) -> Json<crate::auth::DidDocument> {
    Json(state.did_document())
}

async fn get_capabilities() -> Json<GetCapabilitiesOutput> {
    Json(GetCapabilitiesOutput {
        enabled: true,
        protocol_revision: CIRCLE_PROTOCOL_REVISION.into(),
        supports_images: true,
        extra_data: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircleListCursor {
    pub created_at: DateTime<Utc>,
    pub space_uri: String,
}

pub fn encode_circle_cursor(cursor: &CircleListCursor) -> String {
    let json_bytes = serde_json::to_vec(cursor).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(json_bytes)
}

pub fn decode_circle_cursor(cursor_str: &str) -> Result<CircleListCursor, AppError> {
    let decoded_bytes = URL_SAFE_NO_PAD
        .decode(cursor_str)
        .map_err(|_| AppError::InvalidRequest("Invalid cursor encoding".into()))?;
    let cursor: CircleListCursor = serde_json::from_slice(&decoded_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid cursor payload".into()))?;
    Ok(cursor)
}

#[allow(clippy::type_complexity)]
async fn list_circles_handler(
    Extension(user): Extension<AuthenticatedUser>,
    Query(query): Query<ListCircles>,
    State(state): State<AppState>,
) -> Result<Json<ListCirclesOutput>, AppError> {
    tracing::debug!("Handling listCircles request");
    access::revalidate_stale_member_spaces(&state, &user.did).await?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(AppError::InvalidRequest(
            "Limit must be between 1 and 100".into(),
        ));
    }

    let cursor = match query.cursor.as_deref() {
        Some(c) if !c.trim().is_empty() => Some(decode_circle_cursor(c)?),
        _ => None,
    };

    let (cursor_created_at, cursor_space_uri) = match &cursor {
        Some(c) => (Some(c.created_at), Some(c.space_uri.clone())),
        None => (None, None),
    };

    let fetch_limit = limit + 1;

    let rows: Vec<(
        String,
        String,
        String,
        String,
        DateTime<Utc>,
        bool,
        Option<i32>,
    )> = sqlx::query_as(
        r#"
        SELECT
            c.space_uri,
            c.circle_id,
            c.authority_did,
            c.display_name,
            c.created_at,
            COALESCE(pref.muted, false) AS muted,
            meta.member_count
        FROM circles c
        LEFT JOIN circle_member_cache m ON m.space_uri = c.space_uri AND m.member_did = $1
        LEFT JOIN circle_member_cache_meta meta ON meta.space_uri = c.space_uri
        LEFT JOIN circle_preferences pref ON pref.space_uri = c.space_uri AND pref.member_did = $1
        WHERE c.deleted_at IS NULL
          AND (
              c.authority_did = $1
              OR (
                  m.member_did IS NOT NULL
                  AND meta.last_refreshed_at > now() - INTERVAL '300 seconds'
              )
          )
          AND (
              $2::timestamptz IS NULL
              OR c.created_at < $2
              OR (c.created_at = $2 AND c.space_uri < $3)
          )
        ORDER BY c.created_at DESC, c.space_uri DESC
        LIMIT $4
        "#,
    )
    .bind(&user.did)
    .bind(cursor_created_at)
    .bind(cursor_space_uri)
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
            encode_circle_cursor(&CircleListCursor {
                created_at: r.4,
                space_uri: r.0.clone(),
            })
        })
    } else {
        None
    };

    let mut circles = Vec::with_capacity(result_rows.len());
    for (space_uri, circle_id, authority_did, display_name, _created_at, muted, member_count) in result_rows {
        let circle_tid = Tid::new(SmolStr::new(circle_id))
            .map_err(|e| AppError::Internal(format!("Invalid circle TID: {e}")))?;
        let uri = AtSpaceUri::new(SmolStr::new(space_uri))
            .map_err(|e| AppError::Internal(format!("Invalid space ref: {e}")))?;
        let owner = Did::new(SmolStr::new(authority_did))
            .map_err(|e| AppError::Internal(format!("Invalid owner DID: {e}")))?;

        circles.push(CircleSummary {
            circle_id: circle_tid,
            member_count: member_count.map(|c| c as i64),
            muted: Some(*muted),
            name: SmolStr::new(display_name),
            owner,
            uri,
            extra_data: None,
        });
    }

    Ok(Json(ListCirclesOutput {
        circles,
        cursor: next_cursor.map(SmolStr::new),
        extra_data: None,
    }))
}

async fn activate_circle_handler(
    Extension(user): Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(input): Json<ActivateCircle>,
) -> Result<Json<ActivateCircleOutput>, AppError> {
    tracing::debug!("Handling activateCircle request");

    let summary = access::activate_circle(&state, &user.did, input.space.as_str()).await?;

    Ok(Json(ActivateCircleOutput {
        circle: summary,
        extra_data: None,
    }))
}
