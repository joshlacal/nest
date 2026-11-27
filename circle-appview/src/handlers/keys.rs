use crate::access;
use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    extract::{Extension, State},
    http::header,
    response::{IntoResponse, Response},
};
use petrel_catbird::generated::blue::catbird::circle::get_keys::Parameters as GetKeys;

/// Server cap on the keys returned by one `getKeys` call (and the default `limit`).
pub const GET_KEYS_MAX_ROWS: i64 = 64;
/// Server cap on the serialized size of one `getKeys` page. A 512-recipient key record
/// is about 0.8 MB of JSON, so a full 64-row page of them would be ≈ 50 MB.
pub const GET_KEYS_MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;
/// A page scans at most this many rows per requested row, so malformed rows are skipped
/// (and counted) instead of producing an empty page the client cannot advance past.
const GET_KEYS_SCAN_FACTOR: i64 = 4;
/// Allowance for the page envelope (`{"keys":[…],"latestKeyVersion":…,"skipped":…}`).
const PAGE_ENVELOPE_BYTES: usize = 128;

/// `blue.catbird.circle.getKeys`: the Space's stored `blue.catbird.circle.key` records
/// newer than `sinceVersion` (all when absent), in ascending version order. Members
/// only; the wraps inside are the security boundary, this check is defence in depth.
///
/// Each entry is built by hand as `{"uri","cid","keyVersion","record"}` with `record`
/// serialized straight from the stored JSON, so it is byte-identical to the indexed
/// record and keeps the lexicon's `{"$bytes": ..}` recipients. The stored record is not
/// re-parsed through the generated `Key` (whose `Vec<Bytes>` would serialize as integer
/// arrays, ≈ 19 MB per 512-recipient record); a cheap structural check (an object with a
/// `recipients` array) stands in, and a row that fails it is logged (URI and version,
/// never the body) and counted in `skipped`.
///
/// Malformed rows are scanned past (up to 4 × `limit` rows per call, each counted in
/// `skipped`), so a page comes back empty only when no valid row is found in that
/// window. A run of more than 4 × `limit` consecutive malformed rows still yields an empty
/// page; that needs operator repair, and each row is logged.
///
/// Paging: at most `limit` rows (1..=64, default 64; the typed `GetKeys.limit`) and at most
/// [`GET_KEYS_MAX_PAGE_BYTES`] of entries per call, ascending from `sinceVersion`; at
/// least one row is returned when any remains. `latestKeyVersion` is always the Space's
/// newest key, so a client whose last returned `keyVersion` is below it pages by calling
/// again with `sinceVersion` set to that last version.
pub async fn get_keys_handler(
    Extension(user): Extension<AuthenticatedUser>,
    crate::xrpc_query::XrpcQuery(q): crate::xrpc_query::XrpcQuery<GetKeys>,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    tracing::debug!("Handling getKeys request");
    let space_uri = q.space.as_str();
    let limit = checked_limit(Some(q.limit))?;
    access::check_member_access(&state, space_uri, &user.did).await?;

    let rows: Vec<(i64, String, String, serde_json::Value)> = sqlx::query_as(
        r#"
        SELECT key_version, uri, cid, record_json
        FROM circle_keys
        WHERE space_uri = $1 AND ($2::BIGINT IS NULL OR key_version > $2)
        ORDER BY key_version ASC
        LIMIT $3
        "#,
    )
    .bind(space_uri)
    .bind(q.since_version)
    .bind(limit * GET_KEYS_SCAN_FACTOR)
    .fetch_all(&state.db)
    .await?;

    let mut entries: Vec<String> = Vec::with_capacity(rows.len());
    let mut page_bytes = PAGE_ENVELOPE_BYTES;
    let mut skipped: u32 = 0;
    for (key_version, uri, cid, record_json) in rows {
        if entries.len() as i64 == limit {
            break;
        }
        let is_key_shaped = record_json
            .get("recipients")
            .is_some_and(serde_json::Value::is_array);
        if !is_key_shaped {
            tracing::error!(%uri, key_version, "skipping malformed stored key record");
            skipped += 1;
            continue;
        }
        let entry = serde_json::to_string(&serde_json::json!({
            "uri": uri,
            "cid": cid,
            "keyVersion": key_version,
            "record": record_json,
        }))
        .map_err(|e| AppError::Internal(format!("Failed to encode getKeys entry: {e}")))?;
        let added = entry.len() + 1; // separating comma
        if !entries.is_empty() && page_bytes + added > GET_KEYS_MAX_PAGE_BYTES {
            break;
        }
        page_bytes += added;
        entries.push(entry);
    }
    let latest_key_version = crate::feed::summary_key_version(&state.db, space_uri)
        .await?
        .unwrap_or(0);

    let body = format!(
        r#"{{"keys":[{}],"latestKeyVersion":{latest_key_version},"skipped":{skipped}}}"#,
        entries.join(",")
    );
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

/// The optional `limit` param (1..=64, default 64). The generated query type defaults it
/// but does not enforce the lexicon bounds, so check them here.
fn checked_limit(limit: Option<i64>) -> Result<i64, AppError> {
    match limit.unwrap_or(GET_KEYS_MAX_ROWS) {
        n if (1..=GET_KEYS_MAX_ROWS).contains(&n) => Ok(n),
        _ => Err(AppError::InvalidRequest(format!(
            "limit must be an integer in 1..={GET_KEYS_MAX_ROWS}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::checked_limit;

    #[test]
    fn limit_defaults_and_bounds() {
        assert_eq!(checked_limit(None).unwrap(), 64);
        assert_eq!(checked_limit(Some(5)).unwrap(), 5);
        assert_eq!(checked_limit(Some(64)).unwrap(), 64);
        for bad in [0, 65, -1] {
            assert!(checked_limit(Some(bad)).is_err(), "{bad}");
        }
    }
}
