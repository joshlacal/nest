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

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotifyRegistration {
    pub endpoint: String,
    pub token: String,
}

impl std::fmt::Debug for NotifyRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyRegistration")
            .field("endpoint", &self.endpoint)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Load the stable token for `space`, creating it on first authorization.
/// Updating the public endpoint never rotates the token.
pub async fn get_or_create_registration(
    db: &PgPool,
    encryption_key: &[u8; 32],
    space: &str,
    endpoint: &str,
) -> Result<NotifyRegistration, AppError> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let candidate = URL_SAFE_NO_PAD.encode(bytes);
    let encrypted = crate::oauth::encrypt_secret(encryption_key, space, candidate.as_bytes())?;

    let (endpoint, encrypted_token): (String, Vec<u8>) = sqlx::query_as(
        r#"
        INSERT INTO circle_space_notify_tokens (space_uri, endpoint, token, updated_at)
        VALUES ($1, $2, $3, now())
        ON CONFLICT (space_uri) DO UPDATE
        SET endpoint = EXCLUDED.endpoint,
            updated_at = now()
        RETURNING endpoint, token
        "#,
    )
    .bind(space)
    .bind(endpoint)
    .bind(encrypted)
    .fetch_one(db)
    .await?;
    let token =
        String::from_utf8(decrypt_stored_token(db, encryption_key, space, &encrypted_token).await?)
            .map_err(|_| AppError::Internal("Stored notification token is not UTF-8".into()))?;

    Ok(NotifyRegistration { endpoint, token })
}

/// Authenticate a token without a data-dependent plaintext comparison.
pub async fn authenticate(
    db: &PgPool,
    encryption_key: &[u8; 32],
    space: &str,
    token: &str,
) -> Result<(), AppError> {
    if token.is_empty() || token.len() > 512 {
        return Err(AppError::Unauthorized(AuthReason::InvalidToken));
    }
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT token FROM circle_space_notify_tokens WHERE space_uri = $1")
            .bind(space)
            .fetch_optional(db)
            .await?;
    // Always perform the same fixed-size MAC verification for an unknown space
    // as for a wrong token, then return the same error. Registration tokens are
    // 32 random bytes encoded as 43 base64url characters.
    const DUMMY_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let known_space = stored.is_some();
    let decrypted;
    let stored = match stored {
        Some(envelope) => {
            decrypted = decrypt_stored_token(db, encryption_key, space, &envelope).await?;
            std::str::from_utf8(&decrypted)
                .map_err(|_| AppError::Internal("Stored notification token is not UTF-8".into()))?
        }
        None => DUMMY_TOKEN,
    };
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

/// Map a current `at:space/{spaceDid}/{rest}` Space URI back to the alpha-era
/// `at://{spaceDid}/space/{rest}` spelling; `None` for any other shape.
// TODO: remove before beta
fn to_legacy_space_uri(space: &str) -> Option<String> {
    let rest = space.strip_prefix("at:space/")?;
    let (space_did, tail) = rest.split_once('/')?;
    if !space_did.starts_with("did:") || tail.is_empty() {
        return None;
    }
    Some(format!("at://{space_did}/space/{tail}"))
}

/// Decrypt a stored token envelope whose AES-GCM associated data is the Space URI.
///
/// Tokens written before migration `20261125000001_space_uri_at_space` were encrypted
/// against the alpha-era `at://{spaceDid}/space/...` URI; the migration rewrote the
/// `space_uri` column but cannot re-encrypt (the key lives in the app). If decryption
/// under `space` fails, retry under its legacy spelling. On that fallback the returned
/// `Some(envelope)` is the same plaintext re-encrypted under `space`, for the caller to
/// persist.
// TODO: remove the legacy fallback before beta
fn decrypt_token_envelope(
    encryption_key: &[u8; 32],
    space: &str,
    envelope: &[u8],
) -> Result<(Vec<u8>, Option<Vec<u8>>), AppError> {
    let err = match crate::oauth::decrypt_secret(encryption_key, space, envelope) {
        Ok(plaintext) => return Ok((plaintext, None)),
        Err(err) => err,
    };
    let Some(legacy) = to_legacy_space_uri(space) else {
        return Err(err);
    };
    let Ok(plaintext) = crate::oauth::decrypt_secret(encryption_key, &legacy, envelope) else {
        return Err(err);
    };
    let reencrypted = crate::oauth::encrypt_secret(encryption_key, space, &plaintext)?;
    Ok((plaintext, Some(reencrypted)))
}

/// [`decrypt_token_envelope`], persisting a legacy envelope re-encrypted under the
/// current Space URI (lazy re-encryption). The update only replaces the exact envelope
/// that was read, so a concurrent writer is never overwritten.
async fn decrypt_stored_token(
    db: &PgPool,
    encryption_key: &[u8; 32],
    space: &str,
    envelope: &[u8],
) -> Result<Vec<u8>, AppError> {
    let (plaintext, reencrypted) = decrypt_token_envelope(encryption_key, space, envelope)?;
    if let Some(reencrypted) = reencrypted {
        sqlx::query(
            "UPDATE circle_space_notify_tokens SET token = $3, updated_at = now() \
             WHERE space_uri = $1 AND token = $2",
        )
        .bind(space)
        .bind(envelope)
        .bind(reencrypted)
        .execute(db)
        .await?;
    }
    Ok(plaintext)
}

pub async fn checkpoint(db: &PgPool, space: &str, space_rev: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE circle_space_notify_tokens \
         SET checkpoint_rev = GREATEST(checkpoint_rev, $2), \
             pending_rev = CASE \
                 WHEN pending_rev <= GREATEST(checkpoint_rev, $2) THEN NULL \
                 ELSE pending_rev \
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

pub async fn checkpoint_rev(db: &PgPool, space: &str) -> Result<Option<String>, AppError> {
    Ok(sqlx::query_scalar(
        "SELECT checkpoint_rev FROM circle_space_notify_tokens WHERE space_uri = $1",
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
        "UPDATE circle_space_notify_tokens \
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
        "UPDATE circle_space_notify_tokens SET pending_rev = $2, updated_at = now() WHERE space_uri = $1",
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
        "SELECT checkpoint_rev, pending_rev FROM circle_space_notify_tokens WHERE space_uri = $1",
    )
    .bind(space)
    .fetch_optional(db)
    .await?
    .unwrap_or((None, None)))
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
    authenticate(
        &state.db,
        &state.oauth_service.session_encryption_key,
        &input.space,
        &input.token,
    )
    .await?;
    Ok(axum::Json(serde_json::json!({
        "challenge": input.challenge,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const SPACE: &str = "at:space/did:plc:owner/blue.catbird.circle/3l7c1";
    const LEGACY: &str = "at://did:plc:owner/space/blue.catbird.circle/3l7c1";

    #[test]
    fn legacy_space_uri_is_the_inverse_of_the_migration_rewrite() {
        assert_eq!(to_legacy_space_uri(SPACE).as_deref(), Some(LEGACY));
        assert_eq!(
            crate::validator::from_legacy_space_uri(LEGACY).as_deref(),
            Some(SPACE)
        );
        assert_eq!(to_legacy_space_uri(LEGACY), None);
        assert_eq!(to_legacy_space_uri("at:space/not-a-did/x"), None);
        assert_eq!(to_legacy_space_uri("at:space/did:plc:owner/"), None);
    }

    #[test]
    fn current_form_envelope_decrypts_without_reencryption() {
        let envelope = crate::oauth::encrypt_secret(&KEY, SPACE, b"token").unwrap();
        let (plaintext, reencrypted) = decrypt_token_envelope(&KEY, SPACE, &envelope).unwrap();
        assert_eq!(plaintext, b"token");
        assert!(reencrypted.is_none());
    }

    #[test]
    fn legacy_envelope_decrypts_and_is_reencrypted_under_the_new_uri() {
        let legacy = crate::oauth::encrypt_secret(&KEY, LEGACY, b"token").unwrap();
        assert!(crate::oauth::decrypt_secret(&KEY, SPACE, &legacy).is_err());

        let (plaintext, reencrypted) = decrypt_token_envelope(&KEY, SPACE, &legacy).unwrap();
        assert_eq!(plaintext, b"token");
        let reencrypted = reencrypted.expect("legacy envelope must be re-encrypted");
        assert_eq!(
            crate::oauth::decrypt_secret(&KEY, SPACE, &reencrypted).unwrap(),
            b"token"
        );
        assert!(crate::oauth::decrypt_secret(&KEY, LEGACY, &reencrypted).is_err());
    }

    #[test]
    fn envelope_for_another_space_still_fails() {
        let other = crate::oauth::encrypt_secret(
            &KEY,
            "at://did:plc:owner/space/blue.catbird.circle/other",
            b"token",
        )
        .unwrap();
        assert!(decrypt_token_envelope(&KEY, SPACE, &other).is_err());
        let wrong_key = crate::oauth::encrypt_secret(&[8u8; 32], LEGACY, b"token").unwrap();
        assert!(decrypt_token_envelope(&KEY, SPACE, &wrong_key).is_err());
    }
}
