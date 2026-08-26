use axum::{
    extract::{Extension, Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    routing::{get, post},
    Json, Router,
};
use catbird_atproto::generated::blue_catbird::circle::{
    activate_space::ActivateSpaceOutput,
    defs::{AccessState, CircleSummary, SpaceRef},
    get_capabilities::GetCapabilitiesOutput,
    list_circles::{ListCircles, ListCirclesOutput},
};
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::string::{Datetime, Did};
use chrono::{DateTime, Utc};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::CIRCLE_PROTOCOL_REVISION;
use crate::access;
use crate::auth::{self, AuthenticatedUser};
use crate::config::AppState;
use crate::error::{AppError, AuthReason};
use crate::projections::{self, SyncProjectionInput};

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

pub fn create_router(state: AppState) -> Router {
    // Unauthenticated public endpoints
    let public_routes = Router::new()
        .route("/_health", get(health_check))
        .route("/xrpc/_health", get(health_check))
        .route(
            "/xrpc/blue.catbird.circle.getCapabilities",
            get(get_capabilities),
        )
        .route(
            "/xrpc/com.atproto.space.notifyWrite",
            post(notify_write_handler),
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
            "/xrpc/blue.catbird.circle.activateSpace",
            post(activate_space_handler),
        )
        .route("/internal/projections", post(sync_projections_handler))
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


async fn list_circles_handler(
    Extension(user): Extension<AuthenticatedUser>,
    Query(query): Query<ListCircles>,
    State(state): State<AppState>,
) -> Result<Json<ListCirclesOutput>, AppError> {
    tracing::debug!("Handling listCircles request");

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
        DateTime<Utc>,
        bool,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        r#"
        SELECT
            c.space_uri,
            c.authority_did,
            c.display_name,
            c.created_at,
            COALESCE(pref.muted, false) AS muted,
            l.expires_at
        FROM circles c
        LEFT JOIN circle_members m ON m.space_uri = c.space_uri AND m.member_did = $1 AND m.status = 'active'
        LEFT JOIN access_leases l ON l.space_uri = c.space_uri AND l.member_did = $1
        LEFT JOIN circle_preferences pref ON pref.space_uri = c.space_uri AND pref.member_did = $1
        WHERE c.deleted_at IS NULL
          AND (c.authority_did = $1 OR m.member_did IS NOT NULL)
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
                created_at: r.3,
                space_uri: r.0.clone(),
            })
        })
    } else {
        None
    };

    let now = Utc::now();
    let mut circles = Vec::with_capacity(result_rows.len());
    for (space_uri, authority_did, display_name, _created_at, muted, expires_at) in result_rows {
        let is_owner = user.did == *authority_did;
        let members = if is_owner {
            let member_rows: Vec<(String,)> = sqlx::query_as(
                r#"
                SELECT member_did
                FROM circle_members
                WHERE space_uri = $1 AND status = 'active'
                ORDER BY member_did ASC
                "#,
            )
            .bind(space_uri)
            .fetch_all(&state.db)
            .await
            .map_err(AppError::Database)?;

            let dids = member_rows
                .into_iter()
                .filter_map(|(d,)| Did::new(SmolStr::new(d)).ok())
                .collect();
            Some(dids)
        } else {
            None
        };

        let access_state = match expires_at {
            Some(exp) if *exp > now => AccessState::Active,
            _ => AccessState::Expired,
        };

        let uri = SpaceRef::new(SmolStr::new(space_uri))
            .map_err(|e| AppError::Internal(format!("Invalid space ref: {e}")))?;
        let owner = Did::new(SmolStr::new(authority_did))
            .map_err(|e| AppError::Internal(format!("Invalid owner DID: {e}")))?;

        circles.push(CircleSummary {
            access_state,
            members,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateSpaceInput {
    pub space: String,
    pub delegation_token: String,
    pub client_attestation: String,
}

async fn activate_space_handler(
    Extension(user): Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(input): Json<ActivateSpaceInput>,
) -> Result<Json<ActivateSpaceOutput>, AppError> {
    tracing::debug!("Handling activateSpace request");

    if input.client_attestation.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "Missing or empty clientAttestation".into(),
        ));
    }

    let expires_at = access::activate_space(
        &state,
        &user.did,
        &input.space,
        &input.delegation_token,
        &input.client_attestation,
    )
    .await?;

    let dt = Datetime::try_from(expires_at.to_rfc3339())
        .map_err(|e| AppError::Internal(format!("Failed to format datetime: {e}")))?;

    Ok(Json(ActivateSpaceOutput {
        access_state: AccessState::Active,
        expires_at: Some(dt),
        extra_data: None,
    }))
}

async fn sync_projections_handler(
    headers: HeaderMap,
    Extension(user): Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(input): Json<SyncProjectionInput>,
) -> Result<StatusCode, AppError> {
    tracing::debug!(
        operation_id = %input.operation_id,
        kind = %input.kind,
        "Handling syncProjection request"
    );

    // 1. Validate service auth lxm
    if user.lxm != "blue.catbird.circle.syncProjection" {
        return Err(AppError::Unauthorized(AuthReason::LxmMismatch));
    }

    // 2. Validate authenticated actor binding
    if user.did != input.actor_did {
        return Err(AppError::Forbidden(
            "Authenticated actor does not match input actor_did".into(),
        ));
    }

    // 3. Validate actor authority binding
    let authority_did = access::extract_authority_did(&input.space_uri)?;
    match input.kind.as_str() {
        "circle_upsert" | "CircleUpsert" | "circle_delete" | "CircleDelete" | "member_add"
        | "MemberAdd" => {
            if input.actor_did != authority_did {
                return Err(AppError::Forbidden(
                    "Actor is not authorized for Circle operation: must be authority".into(),
                ));
            }
        }
        "member_remove" | "MemberRemove" => {
            let member = input
                .payload
                .get("member")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if input.actor_did != authority_did && input.actor_did != member {
                return Err(AppError::Forbidden(
                    "Actor is not authorized for member removal: must be authority or member self-removing".into(),
                ));
            }
        }
        _ => {}
    }

    // 4. Verify Nest client attestation (FAIL-CLOSED dual authentication)
    let attestation = headers
        .get("x-nest-client-attestation")
        .or_else(|| headers.get("nest-attestation"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            input
                .payload
                .get("clientAttestation")
                .or_else(|| input.payload.get("client_attestation"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .ok_or(AppError::Unauthorized(AuthReason::MissingHeader))?;

    auth::verify_nest_client_attestation(&state, &attestation, &state.config.service_did).await?;

    let payload_digest = projections::compute_payload_digest(
        &input.operation_id,
        input.operation_key.as_deref(),
        &input.actor_did,
        &input.space_uri,
        &input.kind,
        &input.payload,
        input.generation,
        input.circle_generation,
        input.member_generation,
    );

    let projection = input.to_projection()?;
    projections::apply_projection(
        &state.db,
        Some(&state.credential_store),
        Some(&state.space_locks),
        input.operation_id,
        projection,
        &payload_digest,
    )
    .await?;

    Ok(StatusCode::OK)
}

pub async fn notify_write_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite>,
) -> Result<StatusCode, AppError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized(AuthReason::MissingHeader))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .ok_or(AppError::Unauthorized(AuthReason::InvalidHeader))?;
    let user = auth::verify_service_jwt(
        &state,
        token,
        &state.config.service_did,
        Some("com.atproto.space.notifyWrite"),
    )
    .await?;

    let space_uri = input.space.to_string();
    let repo_did = input.repo.to_string();

    let authority_did = crate::access::extract_authority_did(&space_uri)?;
    if user.did != repo_did && user.did != authority_did {
        let authority_doc = state
            .did_resolver
            .resolve(&authority_did)
            .await
            .map_err(AppError::Unauthorized)?;
        let host_matches = authority_doc.service.iter().any(|svc| {
            (svc.id == "#atproto_pds"
                || svc.id == "#space_host"
                || svc.id.ends_with("#atproto_pds"))
                && svc.service_endpoint.contains(&user.did)
        });
        if !host_matches {
            return Err(AppError::Forbidden(
                "Service auth caller is not authorized for this Space or repo".into(),
            ));
        }
    }

    if input.hash.len() != 32 {
        return Err(AppError::InvalidRequest(
            "NotifyWrite requires a 32-byte commit hash".into(),
        ));
    }
    let rev_str = input.rev.as_str().trim();
    if rev_str.is_empty() {
        return Err(AppError::InvalidRequest(
            "NotifyWrite requires a non-empty commit revision".into(),
        ));
    }

    let sync_engine = crate::sync::SyncEngine::new(&state);
    sync_engine
        .sync_repo_with_expected_commit(&space_uri, &repo_did, Some(input.hash.as_ref()), Some(rev_str))
        .await?;
    Ok(StatusCode::OK)
}
