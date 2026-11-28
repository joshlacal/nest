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

/// Decode a procedure body whose `space` field is a space reference, rewriting the
/// spaces-alpha form (`at://{did}/space/...`) to `at:space/...` first. Any other
/// malformed value still fails the typed decode and is answered with 400.
fn decode_space_body<T: serde::de::DeserializeOwned>(
    mut body: serde_json::Value,
) -> Result<T, AppError> {
    if let Some(serde_json::Value::String(space)) = body.get_mut("space") {
        if let std::borrow::Cow::Owned(current) = crate::space_uri::normalize_legacy(space) {
            *space = current;
        }
    }
    serde_json::from_value(body)
        .map_err(|e| AppError::InvalidRequest(format!("Invalid input: {e}")))
}

pub async fn update_preferences_handler(
    Extension(user): Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<UpdatePreferencesOutput>, AppError> {
    let input: UpdatePreferences = decode_space_body(body)?;
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
    Json(body): Json<serde_json::Value>,
) -> Result<Json<ReportRecordOutput>, AppError> {
    let input: ReportRecord = decode_space_body(body)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_and_canonical_space_bodies_decode_identically() {
        for space in [
            "at:space/did:plc:owner/blue.catbird.circle/c1",
            "at://did:plc:owner/space/blue.catbird.circle/c1",
        ] {
            let input: UpdatePreferences =
                decode_space_body(serde_json::json!({ "space": space, "muted": true })).unwrap();
            assert_eq!(
                input.space.as_str(),
                "at:space/did:plc:owner/blue.catbird.circle/c1"
            );
        }
    }

    #[test]
    fn malformed_space_bodies_are_invalid_requests() {
        for space in ["garbage", "at://did:plc:owner/space/blue.catbird.circle"] {
            assert!(matches!(
                decode_space_body::<UpdatePreferences>(
                    serde_json::json!({ "space": space, "muted": true })
                ),
                Err(AppError::InvalidRequest(_))
            ));
        }
    }
}
