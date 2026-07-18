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
        subscriptions::{bounded_page_limit, bounded_page_offset, ActivitySubscriptionWriteError},
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
    push.registry.validate_register_input(&input)?;
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
    push.registry.validate_unregister_input(&input)?;
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

    let (offset, limit) = normalize_list_query(query);
    let page = push
        .subscriptions
        .list_profiles_page_json(&state.outbound_policy, &session.did, offset, limit)
        .await
        .map_err(internal_error)?;

    Ok(Json(json!({
        "cursor": page.cursor,
        "subscriptions": page.profiles,
    })))
}

fn normalize_list_query(query: ListActivitySubscriptionsQuery) -> (i64, usize) {
    (
        bounded_page_offset(query.cursor.as_deref()),
        bounded_page_limit(query.limit),
    )
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
        .map_err(activity_subscription_write_error)?;

    Ok(Json(json!({
        "subject": input.subject,
        "activitySubscription": subscription,
    })))
}

fn activity_subscription_write_error(err: anyhow::Error) -> AppError {
    if let Some(client_error) = err.downcast_ref::<ActivitySubscriptionWriteError>() {
        AppError::BadRequest(client_error.client_message().to_owned())
    } else {
        internal_error(err)
    }
}

fn internal_error(err: anyhow::Error) -> AppError {
    AppError::Internal(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn list_query_normalization_clamps_hostile_limits_and_cursors() {
        let normal = normalize_list_query(ListActivitySubscriptionsQuery {
            limit: Some(25),
            cursor: Some("50".to_string()),
        });
        assert_eq!(normal, (50, 25));

        let hostile = normalize_list_query(ListActivitySubscriptionsQuery {
            limit: Some(usize::MAX),
            cursor: Some("184467440737095516160".to_string()),
        });
        assert_eq!(hostile, (0, 50));
    }

    #[test]
    fn permanent_activity_subscription_write_errors_map_to_fixed_bad_requests() {
        for (error, expected_message) in [
            (
                ActivitySubscriptionWriteError::InvalidSubscriberDid,
                "Invalid authenticated subscriber DID.",
            ),
            (
                ActivitySubscriptionWriteError::InvalidSubjectDid,
                "Subject must be a canonical DID.",
            ),
            (
                ActivitySubscriptionWriteError::QuotaExceeded,
                "Activity subscription limit reached.",
            ),
        ] {
            let mapped = activity_subscription_write_error(anyhow::Error::new(error));
            assert!(matches!(
                &mapped,
                AppError::BadRequest(message) if message == expected_message
            ));
            assert_eq!(mapped.into_response().status(), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn unexpected_activity_subscription_write_errors_remain_internal() {
        let mapped = activity_subscription_write_error(anyhow::anyhow!("database unavailable"));
        assert!(matches!(
            &mapped,
            AppError::Internal(message) if message == "database unavailable"
        ));
        assert_eq!(
            mapped.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
