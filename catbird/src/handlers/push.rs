use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    config::AppState,
    error::{AppError, AppResult},
    models::CatbirdSession,
    services::push::{
        push_unavailable_error,
        types::{
            PutActivitySubscriptionInput, PutPreferencesInput, RegisterPushInput,
            UnregisterPushInput,
        },
    },
};

#[derive(Debug, Deserialize)]
pub struct ListActivitySubscriptionsQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

pub async fn register_push(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<RegisterPushInput>,
) -> AppResult<StatusCode> {
    input
        .validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry.validate_service_did(&input.service_did)?;
    push.registry
        .upsert_registration(&session, &input)
        .await
        .map_err(internal_error)?;
    link_device_to_session(&state, &session, &input.token).await;
    crate::handlers::chat_poll::enroll_session_for_chat_poll(&state, &session).await;
    Ok(StatusCode::OK)
}

/// Best effort reverse-index repair. SQL records the authoritative owner in the
/// registration transaction; a delayed request must still prove that ownership.
async fn link_device_to_session(state: &AppState, session: &CatbirdSession, token: &str) {
    let Some(push) = state.push.as_ref() else {
        return;
    };
    let result = match push.registry.device_row_id(&session.did, token).await {
        Ok(Some(device_id)) => {
            push.registry
                .link_device_session(&session.did, device_id, &session.id.to_string())
                .await
                .map_err(|e| e.to_string())
        }
        Ok(None) => Ok(()),
        Err(e) => Err(e.to_string()),
    };
    if let Err(e) = result {
        tracing::warn!(did = %session.did, error = %e, "Failed to link push device to session");
    }
}

pub async fn unregister_push(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<UnregisterPushInput>,
) -> AppResult<StatusCode> {
    input
        .validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry.validate_service_did(&input.service_did)?;
    push.registry
        .deactivate_registration(&session, &input)
        .await
        .map_err(internal_error)?;
    if let Some(push_db) = state.push_db.as_ref() {
        let scheduler =
            crate::services::chat_poll::scheduler::ChatPollScheduler::new(push_db.clone());
        if let Err(err) = scheduler
            .unenroll_account_if_no_active_devices(&session.did)
            .await
        {
            tracing::warn!(did = %session.did, error = %err, "Chat poll unenroll failed");
        }
    }

    Ok(StatusCode::OK)
}

pub async fn get_preferences(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry
        .touch_account_session(&session)
        .await
        .map_err(internal_error)?;
    let response = crate::services::login_apply::ensure_preferences(&state, &session).await?;
    Ok(preferences_response(response))
}

/// Catbird-specific setup UX; official Bluesky settings are never consulted.
pub async fn get_setup_status(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
) -> AppResult<Json<serde_json::Value>> {
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry
        .touch_account_session(&session)
        .await
        .map_err(internal_error)?;
    let response = crate::services::login_apply::ensure_preferences(&state, &session).await?;
    // Use the same persisted preference gate as decision and pre-send. This is
    // not an assertion about OS permission, a device token, or a particular event.
    let delivery_ready = push
        .preferences
        .get_for_delivery(&session.did)
        .await
        .map_err(internal_error)?
        .is_some();
    Ok(Json(crate::services::login_apply::setup_status_response(
        &response.body,
        delivery_ready,
    )))
}

pub async fn put_preferences_v2(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<PutPreferencesInput>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    input
        .validate()
        .map_err(|message| AppError::BadRequest(message.into()))?;
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry
        .touch_account_session(&session)
        .await
        .map_err(internal_error)?;
    let response = crate::services::login_apply::ensure_preferences(&state, &session).await?;
    if !response.ready {
        return Ok(preferences_response(response));
    }
    push.preferences
        .patch_authenticated(
            state
                .auth_store
                .as_deref()
                .ok_or_else(|| AppError::Internal("Session store unavailable".into()))?,
            &session.did,
            &session.id.to_string(),
            Some(input),
        )
        .await
        .map_err(internal_error)?;
    // Configured means independent Catbird choices were stored. It does not
    // clear the separate, server-owned automatic-delivery hold.
    let response = crate::services::login_apply::ensure_preferences(&state, &session).await?;
    Ok(preferences_response(response))
}

fn preferences_response(
    response: crate::services::login_apply::PreferencesResponse,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        if response.ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(response.body),
    )
}

pub async fn list_activity_subscriptions(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Query(query): Query<ListActivitySubscriptionsQuery>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry
        .touch_account_session(&session)
        .await
        .map_err(internal_error)?;

    let restoration = crate::services::login_apply::ensure_preferences(&state, &session).await?;
    if !restoration.ready {
        return Ok(preferences_response(restoration));
    }

    let cursor = query.cursor.as_deref();
    let limit = query.limit.unwrap_or(50) as usize;

    let (subscriptions, next_cursor) = push
        .subscriptions
        .list_paginated_profiles(
            &state.http_client,
            &session.did,
            limit,
            cursor,
            Some(state.active_stream_semaphore.clone()),
            Some(state.rate_limit.clone()),
            Some(session.id.to_string()),
        )
        .await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "cursor": next_cursor,
            "subscriptions": subscriptions,
            "restoreStatus": restoration.body.get("restoreStatus"),
        })),
    ))
}

pub async fn put_activity_subscription(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<PutActivitySubscriptionInput>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let is_delete = !input.activity_subscription.post && !input.activity_subscription.reply;
    if !is_delete && !crate::services::push::subscriptions::is_valid_subject_did(&input.subject) {
        return Err(AppError::BadRequest(
            "Invalid subject DID format or length".into(),
        ));
    }

    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry
        .touch_account_session(&session)
        .await
        .map_err(internal_error)?;

    let restoration = crate::services::login_apply::ensure_preferences(&state, &session).await?;
    if !restoration.ready {
        return Ok(preferences_response(restoration));
    }

    let subscription = push
        .subscriptions
        .put_authenticated(
            state
                .auth_store
                .as_deref()
                .ok_or_else(|| AppError::Internal("Session store unavailable".into()))?,
            &session.id.to_string(),
            &session.did,
            &input.subject,
            &input.activity_subscription,
        )
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("quota exceeded") || msg.contains("Invalid subject DID") {
                AppError::BadRequest(msg)
            } else {
                AppError::Internal(msg)
            }
        })?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "subject": input.subject,
            "activitySubscription": subscription,
            "restoreStatus": restoration.body.get("restoreStatus"),
        })),
    ))
}

fn internal_error(err: anyhow::Error) -> AppError {
    AppError::Internal(err.to_string())
}
