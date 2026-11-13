//! Nov-12 Spaces notification registration state.
//!
//! A stable, per-space opaque token is included in every `authorizeSpaceSync`
//! request. Space hosts authenticate `confirmRegistration` and
//! `notifySpaceUpdate` by echoing that token in the JSON body.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use sqlx::PgPool;

use crate::error::{AppError, AuthReason};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotifyRegistration {
    pub endpoint: String,
    pub token: String,
}

/// Load the stable token for `space`, creating it on first authorization.
/// Updating the public endpoint never rotates the token.
pub async fn get_or_create_registration(
    db: &PgPool,
    space: &str,
    endpoint: &str,
) -> Result<NotifyRegistration, AppError> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let candidate = URL_SAFE_NO_PAD.encode(bytes);

    let (endpoint, token): (String, String) = sqlx::query_as(
        r#"
        INSERT INTO circle_notify_registrations (space_uri, endpoint, token, updated_at)
        VALUES ($1, $2, $3, now())
        ON CONFLICT (space_uri) DO UPDATE
        SET endpoint = EXCLUDED.endpoint,
            updated_at = now()
        RETURNING endpoint, token
        "#,
    )
    .bind(space)
    .bind(endpoint)
    .bind(candidate)
    .fetch_one(db)
    .await?;

    Ok(NotifyRegistration { endpoint, token })
}

/// Authenticate a token without a data-dependent plaintext comparison.
pub async fn authenticate(db: &PgPool, space: &str, token: &str) -> Result<(), AppError> {
    if token.is_empty() || token.len() > 512 {
        return Err(AppError::Unauthorized(AuthReason::InvalidToken));
    }
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT token FROM circle_notify_registrations WHERE space_uri = $1",
    )
    .bind(space)
    .fetch_optional(db)
    .await?;
    // Always perform the same fixed-size MAC verification for an unknown space
    // as for a wrong token, then return the same error. Registration tokens are
    // 32 random bytes encoded as 43 base64url characters.
    const DUMMY_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let known_space = stored.is_some();
    let stored = stored.as_deref().unwrap_or(DUMMY_TOKEN);
    let mut expected = Hmac::<Sha256>::new_from_slice(stored.as_bytes())
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidToken))?;
    expected.update(space.as_bytes());
    let expected = expected.finalize().into_bytes();
    let mut supplied = Hmac::<Sha256>::new_from_slice(token.as_bytes())
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidToken))?;
    supplied.update(space.as_bytes());
    let valid = supplied.verify_slice(&expected).is_ok();
    if known_space && valid {
        Ok(())
    } else {
        Err(AppError::Unauthorized(AuthReason::InvalidToken))
    }
}


pub async fn checkpoint(db: &PgPool, space: &str, space_rev: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE circle_notify_registrations \
         SET checkpoint_rev = $2, \
             pending_rev = CASE WHEN pending_rev <= $2 THEN NULL ELSE pending_rev END, \
             updated_at = now() \
         WHERE space_uri = $1",
    )
    .bind(space)
    .bind(space_rev)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn checkpoint_rev(db: &PgPool, space: &str) -> Result<Option<String>, AppError> {
    Ok(sqlx::query_scalar(
        "SELECT checkpoint_rev FROM circle_notify_registrations WHERE space_uri = $1",
    )
    .bind(space)
    .fetch_optional(db)
    .await?
    .flatten())
}
pub async fn note_authorized_revision(
    db: &PgPool,
    space: &str,
    space_rev: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE circle_notify_registrations \
         SET pending_rev = CASE \
                 WHEN $2::text IS DISTINCT FROM checkpoint_rev THEN $2 \
                 ELSE NULL \
             END, \
             updated_at = now() \
         WHERE space_uri = $1",
    )
    .bind(space)
    .bind(space_rev)
    .execute(db)
    .await?;
    Ok(())
}
pub async fn mark_pending(db: &PgPool, space: &str, space_rev: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE circle_notify_registrations SET pending_rev = $2, updated_at = now() WHERE space_uri = $1",
    )
    .bind(space)
    .bind(space_rev)
    .execute(db)
    .await?;
    Ok(())
}


pub async fn catchup_state(
    db: &PgPool,
    space: &str,
) -> Result<(Option<String>, Option<String>), AppError> {
    Ok(sqlx::query_as(
        "SELECT checkpoint_rev, pending_rev FROM circle_notify_registrations WHERE space_uri = $1",
    )
    .bind(space)
    .fetch_optional(db)
    .await?
    .unwrap_or((None, None)))
}


pub async fn remove_registration(db: &PgPool, space: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM circle_notify_registrations WHERE space_uri = $1")
        .bind(space)
        .execute(db)
        .await?;
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmRegistrationInput {
    pub space: String,
    pub token: String,
    pub challenge: String,
}

pub async fn confirm_registration_handler(
    axum::extract::State(state): axum::extract::State<crate::config::AppState>,
    axum::Json(input): axum::Json<ConfirmRegistrationInput>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    if input.challenge.len() > 512 {
        return Err(AppError::InvalidRequest(
            "challenge exceeds 512 characters".into(),
        ));
    }
    authenticate(&state.db, &input.space, &input.token).await?;
    Ok(axum::Json(serde_json::json!({
        "challenge": input.challenge,
    })))
}
