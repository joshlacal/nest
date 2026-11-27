use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    extract::{Extension, State},
    Json,
};
use petrel_catbird::generated::blue::catbird::circle::report_record::Input as ReportRecord;
use petrel_catbird::generated::blue::catbird::circle::report_record::Output as ReportRecordOutput;
use petrel_catbird::generated::blue::catbird::circle::update_preferences::Input as UpdatePreferences;
use petrel_catbird::generated::blue::catbird::circle::update_preferences::Output as UpdatePreferencesOutput;

pub async fn update_preferences_handler(
    Extension(user): Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(input): Json<UpdatePreferences>,
) -> Result<Json<UpdatePreferencesOutput>, AppError> {
    tracing::debug!("Handling updatePreferences request");
    let muted = crate::preferences::update_preferences(
        &state,
        &user.did,
        input.space.as_str(),
        input.muted,
    )
    .await?;
    Ok(Json(UpdatePreferencesOutput { muted }))
}

pub async fn report_record_handler(
    Extension(user): Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(input): Json<ReportRecord>,
) -> Result<Json<ReportRecordOutput>, AppError> {
    tracing::debug!("Handling reportRecord request");
    let details_ref = input.details.as_deref();
    // `disclosedPostKey` / `disclosedMedia` are deliberately ignored: the
    // operator never receives the means to decrypt Circle content.
    if input.disclosed_post_key.is_some() || input.disclosed_media.is_some() {
        tracing::info!("reportRecord: discarded disclosed decryption keys from an older client");
    }
    let id = crate::reports::report_record(
        &state,
        &user.did,
        input.space.as_str(),
        input.uri.as_str(),
        input.reason,
        details_ref,
    )
    .await?;

    Ok(Json(ReportRecordOutput { id }))
}
