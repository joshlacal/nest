use crate::access;
use crate::error::AppError;
use catbird_atproto::generated::blue_catbird::circle::defs::ReportReason;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn report_record(
    pool: &PgPool,
    reporter_did: &str,
    space_uri: &str,
    subject_uri: &str,
    reason: ReportReason,
    details: Option<&str>,
) -> Result<String, AppError> {
    // 1. Require a live lease in the Space
    access::check_active_lease(pool, space_uri, reporter_did).await?;

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
    let standard_aturi = crate::feed::normalize_uri_to_standard_aturi(subject_uri);

    let subject_row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT uri
        FROM circle_records
        WHERE (uri = $1 OR uri = $2 OR uri = $3)
          AND space_uri = $4
          AND deleted_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(subject_uri)
    .bind(&standard_aturi)
    .bind(&space_based_uri)
    .bind(space_uri)
    .fetch_optional(pool)
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
    let reason_str = match reason {
        ReportReason::Spam => "spam",
        ReportReason::Abuse => "abuse",
        ReportReason::Other => "other",
    };

    sqlx::query(
        r#"
        INSERT INTO circle_reports (id, reporter_did, space_uri, subject_uri, reason, details, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, now())
        "#,
    )
    .bind(report_id)
    .bind(reporter_did)
    .bind(space_uri)
    .bind(&verified_subject_uri)
    .bind(reason_str)
    .bind(details)
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    Ok(report_id.to_string())
}
