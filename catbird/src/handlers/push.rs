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
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry.validate_service_did(&input.service_did)?;
    push.registry
        .upsert_registration(&session, &input)
        .await
        .map_err(internal_error)?;
    crate::handlers::chat_poll::enroll_session_for_chat_poll(&state, &session).await;
    Ok(StatusCode::OK)
}

pub async fn unregister_push(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<UnregisterPushInput>,
) -> AppResult<StatusCode> {
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
) -> AppResult<Json<serde_json::Value>> {
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry
        .touch_account_session(&session)
        .await
        .map_err(internal_error)?;
    let prefs = push
        .preferences
        .get_or_create(&session.did)
        .await
        .map_err(internal_error)?;
    Ok(Json(json!({ "preferences": prefs.to_lexicon_json() })))
}

pub async fn put_preferences_v2(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<PutPreferencesInput>,
) -> AppResult<Json<serde_json::Value>> {
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry
        .touch_account_session(&session)
        .await
        .map_err(internal_error)?;
    let prefs = push
        .preferences
        .patch(&session.did, input)
        .await
        .map_err(internal_error)?;
    Ok(Json(json!({ "preferences": prefs.to_lexicon_json() })))
}

pub async fn list_activity_subscriptions(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Query(query): Query<ListActivitySubscriptionsQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry
        .touch_account_session(&session)
        .await
        .map_err(internal_error)?;

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
    Ok(Json(json!({
        "cursor": next_cursor,
        "subscriptions": subscriptions,
    })))
}

pub async fn put_activity_subscription(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<PutActivitySubscriptionInput>,
) -> AppResult<Json<serde_json::Value>> {
    let is_delete = !input.activity_subscription.post && !input.activity_subscription.reply;
    if !is_delete && !crate::services::push::subscriptions::is_valid_subject_did(&input.subject) {
        return Err(AppError::BadRequest("Invalid subject DID format or length".into()));
    }

    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry
        .touch_account_session(&session)
        .await
        .map_err(internal_error)?;

    let subscription = push
        .subscriptions
        .put(&session.did, &input.subject, &input.activity_subscription)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("quota exceeded") || msg.contains("Invalid subject DID") {
                AppError::BadRequest(msg)
            } else {
                AppError::Internal(msg)
            }
        })?;

    Ok(Json(json!({
        "subject": input.subject,
        "activitySubscription": subscription,
    })))
}

fn internal_error(err: anyhow::Error) -> AppError {
    AppError::Internal(err.to_string())
}
