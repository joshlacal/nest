use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    extract::{Extension, State},
    Json,
};
use catbird_atproto::generated::blue_catbird::circle::report_record::{
    ReportRecord, ReportRecordOutput,
};
use catbird_atproto::generated::blue_catbird::circle::update_preferences::{
    UpdatePreferences, UpdatePreferencesOutput,
};
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;

pub async fn update_preferences_handler(
    Extension(user): Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(input): Json<UpdatePreferences>,
) -> Result<Json<UpdatePreferencesOutput>, AppError> {
    tracing::debug!("Handling updatePreferences request");
    let muted = crate::preferences::update_preferences(
        &state.db,
        &user.did,
        input.space.as_str(),
        input.muted,
    )
    .await?;
    Ok(Json(UpdatePreferencesOutput {
        muted,
        extra_data: None,
    }))
}

pub async fn report_record_handler(
    Extension(user): Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(input): Json<ReportRecord>,
) -> Result<Json<ReportRecordOutput>, AppError> {
    tracing::debug!("Handling reportRecord request");
    let details_ref = input.details.as_ref().map(|s| s.as_str());
    let id = crate::reports::report_record(
        &state.db,
        &user.did,
        input.space.as_str(),
        input.uri.as_str(),
        input.reason,
        details_ref,
    )
    .await?;

    Ok(Json(ReportRecordOutput {
        id: SmolStr::new(id),
        extra_data: None,
    }))
}
