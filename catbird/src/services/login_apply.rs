//! Catbird-local notification setup after a missing-row reset.
//!
//! Official Bluesky notification preferences are never inputs here. Login sync
//! inspection helpers remain separate; setup performs no provider reads/writes.

use std::sync::Arc;

use serde_json::{json, Value};
use sqlx::{Pool, Postgres};

use super::push::types::{
    ChatPreference, FilterablePreference, Preference, PushPreferencesDocument,
};
use super::RedisAuthStore;
use crate::config::AppState;
use crate::error::{AppError, AppResult};
use crate::models::CatbirdSession;

pub const RESTORE_METADATA_KEY: &str = "_catbirdRestore";

/// Settings are available. This does not assert automatic delivery readiness.
pub struct PreferencesResponse {
    pub ready: bool,
    pub body: Value,
}

fn unavailable() -> AppError {
    AppError::ServiceUnavailable(
        "Catbird notification settings are temporarily unavailable.".into(),
    )
}
fn stale() -> AppError {
    AppError::AtprotoResponse {
        status: axum::http::StatusCode::CONFLICT,
        error: "NotificationSessionChanged".into(),
        message: "Your session changed while setting up Catbird notifications. Please retry."
            .into(),
    }
}
fn response_for_row(payload: Value) -> AppResult<PreferencesResponse> {
    let preferences: PushPreferencesDocument = serde_json::from_value(payload.clone())?;
    let mut body = json!({"preferences": preferences.to_lexicon_json()});
    if let Some(metadata) = payload.get(RESTORE_METADATA_KEY) {
        body["restoreStatus"] = metadata.clone();
    }
    Ok(PreferencesResponse { ready: true, body })
}

/// Minimal setup contract for clients. `delivery_ready` must come from the
/// server's persisted delivery-preference gate, never request/provider metadata.
/// The gate can still suppress an individual event for moderation or freshness.
pub fn setup_status_response(preferences_response: &Value, delivery_ready: bool) -> Value {
    let (required, configured, ready, status) = if !preferences_response["preferences"].is_object()
    {
        (false, false, false, "setup_unavailable")
    } else {
        match preferences_response.get("restoreStatus") {
            None => (
                false,
                true,
                delivery_ready,
                if delivery_ready {
                    "legacy_configured"
                } else {
                    "delivery_unavailable"
                },
            ),
            Some(metadata)
                if metadata["version"] == 1
                    && metadata["source"] == "catbird_local"
                    && metadata["authGeneration"]
                        .as_i64()
                        .is_some_and(|generation| generation > 0) =>
            {
                match metadata["localConsent"].as_str() {
                    Some("Required") => (true, false, false, "choices_required"),
                    Some("Configured") => (
                        false,
                        true,
                        delivery_ready,
                        if delivery_ready {
                            "configured"
                        } else {
                            "choices_configured_delivery_pending"
                        },
                    ),
                    _ => (false, false, false, "setup_unavailable"),
                }
            }
            Some(_) => (false, false, false, "setup_unavailable"),
        }
    };
    json!({"version":1,"choicesRequired":required,"choicesConfigured":configured,"deliveryReady":ready,"status":status,
        "deliveryScope": if ready && status == "configured" { "per_event" } else if ready { "legacy" } else { "none" },
        "heldCategories":[],"heldConditions":[],"reasons":[]})
}

/// Explicit new Catbird choices, not recovered or inferred provider preferences.
fn local_off_preferences() -> PushPreferencesDocument {
    let filtered = || FilterablePreference {
        include: "all".into(),
        list: true,
        push: false,
    };
    let plain = || Preference {
        list: true,
        push: false,
    };
    PushPreferencesDocument {
        chat: ChatPreference {
            include: "all".into(),
            push: false,
        },
        follow: filtered(),
        like: filtered(),
        like_via_repost: filtered(),
        mention: filtered(),
        quote: filtered(),
        reply: filtered(),
        repost: filtered(),
        repost_via_repost: filtered(),
        starterpack_joined: plain(),
        subscribed_post: plain(),
        unverified: plain(),
        verified: plain(),
    }
}

pub async fn ensure_preferences(
    state: &Arc<AppState>,
    session: &CatbirdSession,
) -> AppResult<PreferencesResponse> {
    let pool = state.push_db.as_ref().ok_or_else(unavailable)?;
    let store = state.auth_store.as_deref().ok_or_else(unavailable)?;
    ensure_local_preferences(pool, store, session).await
}

/// The lock and original live bearer prevent pre-logout requests from recreating
/// deleted state. Existing Catbird rows are returned byte-for-byte unchanged.
/// No snapshot, PDS URL, network client, or provider preference is accepted.
pub async fn ensure_local_preferences(
    pool: &Pool<Postgres>,
    store: &RedisAuthStore,
    session: &CatbirdSession,
) -> AppResult<PreferencesResponse> {
    let mut tx = pool.begin().await?;
    super::push::lock::acquire_account_lock(&mut tx, &session.did)
        .await
        .map_err(|_| unavailable())?;
    store
        .validate_live_session_local(&session.did, &session.id.to_string())
        .await
        .map_err(|_| stale())?;
    let existing: Option<Value> =
        sqlx::query_scalar("SELECT preferences_json FROM push_preferences WHERE account_did=$1")
            .bind(&session.did)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(payload) = existing {
        tx.commit().await?;
        return response_for_row(payload);
    }
    let generation: Option<i64> = sqlx::query_scalar("SELECT auth_generation FROM push_accounts WHERE account_did=$1 AND auth_revoked_at IS NULL AND auth_generation>0")
        .bind(&session.did).fetch_optional(&mut *tx).await?;
    let generation = generation.ok_or_else(stale)?;
    let mut payload = serde_json::to_value(local_off_preferences())?;
    payload[RESTORE_METADATA_KEY] = json!({
        "version": 1, "source": "catbird_local", "localConsent": "Required",
        "authGeneration": generation, "automaticPushReady": false,
    });
    sqlx::query("INSERT INTO push_preferences(account_did,preferences_json,created_at,updated_at) VALUES($1,$2,NOW(),NOW())")
        .bind(&session.did).bind(&payload).execute(&mut *tx).await?;
    tx.commit().await?;
    response_for_row(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_status_distinguishes_required_configured_and_legacy_without_inventing_readiness() {
        let mut response = json!({"preferences":local_off_preferences().to_lexicon_json(),
            "restoreStatus":{"version":1,"source":"catbird_local","localConsent":"Required","authGeneration":7,"automaticPushReady":true}});
        assert_eq!(
            setup_status_response(&response, false),
            json!({"version":1,"choicesRequired":true,"choicesConfigured":false,"deliveryReady":false,"status":"choices_required","deliveryScope":"none","heldCategories":[],"heldConditions":[],"reasons":[]})
        );
        assert_eq!(
            setup_status_response(&response, true)["deliveryReady"],
            false
        );
        response["restoreStatus"]["localConsent"] = json!("Configured");
        assert_eq!(
            setup_status_response(&response, false),
            json!({"version":1,"choicesRequired":false,"choicesConfigured":true,"deliveryReady":false,"status":"choices_configured_delivery_pending","deliveryScope":"none","heldCategories":[],"heldConditions":[],"reasons":[]})
        );
        // The persisted server gate, not automaticPushReady in this response,
        // controls partial eligibility. Individual event proof still applies.
        assert_eq!(
            setup_status_response(&response, true)["status"],
            "configured"
        );
        let configured = setup_status_response(&response, true);
        assert_eq!(configured["deliveryScope"], "per_event");
        assert_eq!(configured["heldConditions"], json!([]));
        assert_eq!(configured["heldCategories"], json!([]));
        assert_eq!(configured["reasons"], json!([]));
        response.as_object_mut().unwrap().remove("restoreStatus");
        assert_eq!(
            setup_status_response(&response, true),
            json!({"version":1,"choicesRequired":false,"choicesConfigured":true,"deliveryReady":true,"status":"legacy_configured","deliveryScope":"legacy","heldCategories":[],"heldConditions":[],"reasons":[]})
        );
        assert_eq!(
            setup_status_response(&response, false)["status"],
            "delivery_unavailable"
        );
        response["restoreStatus"] = json!({"automaticPushReady":true});
        assert_eq!(
            setup_status_response(&response, true)["deliveryReady"],
            false
        );
        assert_eq!(
            setup_status_response(&json!({}), true)["status"],
            "setup_unavailable"
        );
    }

    #[test]
    fn category_patches_require_explicit_push_and_preserve_omitted_fields() {
        use super::super::push::types::PutPreferencesInput;
        for missing in [
            json!({"like": {}}),
            json!({"chat": {"include": "all"}}),
            json!({"verified": {"list": false}}),
        ] {
            assert!(serde_json::from_value::<PutPreferencesInput>(missing).is_err());
        }
        for empty in [
            json!({}),
            json!({"_catbirdRestore": {"localConsent": "Configured"}}),
        ] {
            assert!(serde_json::from_value::<PutPreferencesInput>(empty)
                .unwrap()
                .validate()
                .is_err());
        }
        let mut old = local_off_preferences();
        old.like.include = "follows".into();
        old.like.list = false;
        let choice: PutPreferencesInput = serde_json::from_value(
            json!({"like": {"push": true}, "_catbirdRestore": {"automaticPushReady": true}}),
        )
        .unwrap();
        choice.validate().unwrap();
        let updated = choice.apply_to(old);
        assert!(updated.like.push);
        assert_eq!(updated.like.include, "follows");
        assert!(!updated.like.list);
        assert!(!updated.chat.push);
        assert!(!updated.reply.push);
    }

    #[test]
    fn local_defaults_are_explicitly_off_for_every_known_category() {
        let preferences = local_off_preferences().to_lexicon_json();
        for (category, value) in preferences.as_object().unwrap() {
            assert_eq!(value["push"], false, "{category}");
        }
        assert_eq!(preferences["like"]["list"], true);
        assert_eq!(preferences["chat"]["include"], "all");
    }
}
