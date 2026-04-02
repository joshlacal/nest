use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::{
    config::AppState,
    error::{AppError, AppResult},
    models::CatbirdSession,
};

#[derive(Debug, Deserialize)]
pub struct HeartbeatInput {
    /// Optional lease duration override (not currently used; fixed at 90s)
    #[serde(default)]
    pub _lease_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatOutput {
    pub lease_expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMuteStatusInput {
    pub convo_id: String,
    pub muted: bool,
}

#[derive(Debug, Serialize)]
pub struct UpdateMuteStatusOutput {
    pub success: bool,
}

pub async fn push_heartbeat(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(_input): Json<HeartbeatInput>,
) -> AppResult<Json<HeartbeatOutput>> {
    let push_db = state
        .push_db
        .as_ref()
        .ok_or_else(|| AppError::Config("Push database not configured".into()))?;

    let scheduler =
        crate::services::chat_poll::scheduler::ChatPollScheduler::new(push_db.clone());

    let lease_secs: i64 = 90;
    scheduler
        .update_foreground_lease(&session.did, lease_secs)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(lease_secs);
    Ok(Json(HeartbeatOutput {
        lease_expires_at: expires_at.to_rfc3339(),
    }))
}

pub async fn update_mute_status(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<CatbirdSession>,
    Json(input): Json<UpdateMuteStatusInput>,
) -> AppResult<Json<UpdateMuteStatusOutput>> {
    let push_db = state
        .push_db
        .as_ref()
        .ok_or_else(|| AppError::Config("Push database not configured".into()))?;

    let scheduler =
        crate::services::chat_poll::scheduler::ChatPollScheduler::new(push_db.clone());

    scheduler
        .set_convo_muted(&session.did, &input.convo_id, input.muted)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(UpdateMuteStatusOutput { success: true }))
}
