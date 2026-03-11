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

    let mut subscriptions = push
        .subscriptions
        .list_profiles_json(&state.http_client, &session.did)
        .await
        .map_err(internal_error)?;

    let offset = query
        .cursor
        .as_deref()
        .and_then(|cursor| cursor.parse::<usize>().ok())
        .unwrap_or(0);
    let limit = query.limit.unwrap_or(50).max(1);
    let total = subscriptions.len();

    let next_offset = offset.saturating_add(limit);
    let slice = subscriptions
        .drain(offset.min(total)..total.min(next_offset))
        .collect::<Vec<_>>();

    let cursor = (next_offset < total).then(|| next_offset.to_string());

    Ok(Json(json!({
        "cursor": cursor,
        "subscriptions": slice,
    })))
}

pub async fn put_activity_subscription(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<PutActivitySubscriptionInput>,
) -> AppResult<Json<serde_json::Value>> {
    let push = state.push.as_ref().ok_or_else(push_unavailable_error)?;
    push.registry
        .touch_account_session(&session)
        .await
        .map_err(internal_error)?;

    let subscription = push
        .subscriptions
        .put(&session.did, &input.subject, &input.activity_subscription)
        .await
        .map_err(internal_error)?;

    Ok(Json(json!({
        "subject": input.subject,
        "activitySubscription": subscription,
    })))
}

fn internal_error(err: anyhow::Error) -> AppError {
    AppError::Internal(err.to_string())
}
