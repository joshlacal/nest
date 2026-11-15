use crate::access;
use crate::config::AppState;
use crate::error::AppError;
use catbird_atproto::generated::blue_catbird::circle::report_record::ReportRecordReason;
use uuid::Uuid;

/// Length of an encrypted Circle post's per-post key (`postKey`).
pub const DISCLOSED_POST_KEY_LEN: usize = 32;

#[allow(clippy::too_many_arguments)]
pub async fn report_record(
    state: &AppState,
    reporter_did: &str,
    space_uri: &str,
    subject_uri: &str,
    reason: ReportRecordReason,
    details: Option<&str>,
    disclosed_post_key: Option<&[u8]>,
    disclosed_media: Option<&serde_json::Value>,
) -> Result<String, AppError> {
    // 1. Require verified member access in the Space
    access::check_member_access(state, space_uri, reporter_did).await?;

    // A disclosed per-post key is the 32-byte `postKey`; anything else is malformed.
    if let Some(key) = disclosed_post_key {
        if key.len() != DISCLOSED_POST_KEY_LEN {
            return Err(AppError::InvalidRequest(format!(
                "disclosedPostKey must be exactly {DISCLOSED_POST_KEY_LEN} bytes"
            )));
        }
    }

    // 2. Validate details length (max 500 chars in database constraint)
    if let Some(d) = details {
        if d.chars().count() > 500 {
            return Err(AppError::InvalidRequest(
                "Report details must not exceed 500 characters".into(),
            ));
        }
    }

    // 3. Normalize URI if needed and verify subject record exists and is in the same Space and not deleted
    let path_suffix = if let Some(stripped) = subject_uri.strip_prefix("at://") {
        if let Some(slash) = stripped.find('/') {
            &stripped[slash..]
        } else {
            ""
        }
    } else {
        ""
    };
    let space_based_uri = format!("{space_uri}{path_suffix}");
    // `at://did/collection/rkey` → the stored `<space>/did/collection/rkey` form.
    let space_scoped_uri = subject_uri
        .strip_prefix("at://")
        .map(|rest| format!("{space_uri}/{rest}"))
        .unwrap_or_else(|| subject_uri.to_string());
    let standard_aturi = crate::feed::normalize_uri_to_standard_aturi(subject_uri);

    let subject_row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT uri
        FROM circle_records
        WHERE (uri = $1 OR uri = $2 OR uri = $3 OR uri = $5)
          AND space_uri = $4
          AND deleted_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(subject_uri)
    .bind(&standard_aturi)
    .bind(&space_based_uri)
    .bind(space_uri)
    .bind(&space_scoped_uri)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::Database)?;

    let verified_subject_uri = match subject_row {
        Some((uri,)) => uri,
        None => {
            return Err(AppError::InvalidRequest(
                "Subject record must exist in the same Space".into(),
            ));
        }
    };

    let report_id = Uuid::new_v4();
    let reason_str = match &reason {
        ReportRecordReason::Spam => "spam",
        ReportRecordReason::Abuse => "abuse",
        ReportRecordReason::Other => "other",
        ReportRecordReason::UnknownValue(val) => {
            return Err(AppError::InvalidRequest(format!(
                "Unknown report reason: {val}"
            )));
        }
    };

    sqlx::query(
        r#"
        INSERT INTO circle_reports (id, reporter_did, space_uri, subject_uri, reason, details, disclosed_post_key, disclosed_media, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
        "#,
    )
    .bind(report_id)
    .bind(reporter_did)
    .bind(space_uri)
    .bind(&verified_subject_uri)
    .bind(reason_str)
    .bind(details)
    .bind(disclosed_post_key)
    .bind(disclosed_media)
    .execute(&state.db)
    .await
    .map_err(AppError::Database)?;

    Ok(report_id.to_string())
}
