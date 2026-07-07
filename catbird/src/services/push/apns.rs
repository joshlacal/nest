use std::{collections::HashMap, path::Path, sync::Arc};

use a2::{
    Client, DefaultNotificationBuilder, Error as A2Error, ErrorReason, NotificationBuilder,
    NotificationOptions, Priority,
};
use anyhow::{Context, Result};

use crate::config::ApnsConfig;

use super::types::RegistrationRow;

#[derive(Debug, Clone)]
pub struct ApnsNotification {
    pub title: String,
    pub body: String,
    pub user_did: String,
    pub custom_data: HashMap<String, String>,
    pub mutable_content: bool,
    pub thread_id: Option<String>,
}

/// The two APNs environments. Sandbox tokens (Xcode debug builds) and
/// production tokens (TestFlight/App Store builds) are not interchangeable —
/// each device token is only valid against the endpoint matching how the app
/// was signed/installed.
const ENV_PRODUCTION: &str = "production";
const ENV_SANDBOX: &str = "sandbox";

/// Picks which APNs environment to try first for a registration.
///
/// If we've previously learned (or the client told us) which environment a
/// device token belongs to, use that. Otherwise fall back to the configured
/// default (`ApnsConfig.production`: true tries production first).
pub fn first_try_env(registration_env: Option<&str>, default_production: bool) -> &'static str {
    match registration_env {
        Some(ENV_SANDBOX) => ENV_SANDBOX,
        Some(ENV_PRODUCTION) => ENV_PRODUCTION,
        _ => {
            if default_production {
                ENV_PRODUCTION
            } else {
                ENV_SANDBOX
            }
        }
    }
}

/// The environment on the other side of the one just tried.
fn other_env(env: &str) -> &'static str {
    if env == ENV_PRODUCTION {
        ENV_SANDBOX
    } else {
        ENV_PRODUCTION
    }
}

fn is_bad_device_token(err: &A2Error) -> bool {
    matches!(
        err,
        A2Error::ResponseError(response)
            if response.error.as_ref().map(|body| body.reason == ErrorReason::BadDeviceToken).unwrap_or(false)
    )
}

#[derive(Clone)]
pub struct ApnsDelivery {
    production_client: Arc<Client>,
    sandbox_client: Arc<Client>,
    topic: String,
    default_production: bool,
}

impl ApnsDelivery {
    pub fn new(config: &ApnsConfig) -> Result<Option<Self>> {
        let (Some(key_path), Some(key_id), Some(team_id), Some(topic)) = (
            config.key_path.as_deref(),
            config.key_id.as_deref(),
            config.team_id.as_deref(),
            config.topic.as_deref(),
        ) else {
            tracing::warn!("APNs delivery is not configured; push worker will stay disabled");
            return Ok(None);
        };

        let key_path = Path::new(key_path);
        let _key = std::fs::read(key_path).context(format!(
            "Failed to read APNs key file: {}",
            key_path.display()
        ))?;

        // Both clients are built from the same key file — APNs auth tokens
        // aren't endpoint-specific, only which host we POST to.
        let production_client = Client::token(
            std::fs::File::open(key_path)?,
            key_id,
            team_id,
            a2::ClientConfig::new(a2::Endpoint::Production),
        )?;
        let sandbox_client = Client::token(
            std::fs::File::open(key_path)?,
            key_id,
            team_id,
            a2::ClientConfig::new(a2::Endpoint::Sandbox),
        )?;

        Ok(Some(Self {
            production_client: Arc::new(production_client),
            sandbox_client: Arc::new(sandbox_client),
            topic: topic.to_string(),
            default_production: config.production,
        }))
    }

    fn client_for(&self, env: &str) -> &Client {
        if env == ENV_PRODUCTION {
            &self.production_client
        } else {
            &self.sandbox_client
        }
    }

    /// Sends a notification to a device, trying the environment recorded on
    /// the registration (or the configured default if unknown) first.
    ///
    /// If APNs rejects the token with `BadDeviceToken` — which happens when a
    /// sandbox token is sent to the production endpoint or vice versa — the
    /// notification is retried once against the other environment. If that
    /// also fails with `BadDeviceToken`, the original error is returned so
    /// callers can deactivate the token as invalid.
    ///
    /// Returns the APNs environment ("production" or "sandbox") that
    /// successfully delivered the notification, so callers can persist a
    /// learned environment when it differs from what's on file.
    pub async fn send(
        &self,
        registration: &RegistrationRow,
        notification: &ApnsNotification,
    ) -> Result<&'static str> {
        let payload = self.build_payload(registration, notification)?;

        let first_env = first_try_env(
            registration.apns_environment.as_deref(),
            self.default_production,
        );

        match self.client_for(first_env).send(payload.clone()).await {
            Ok(_) => Ok(first_env),
            Err(err) if is_bad_device_token(&err) => {
                let second_env = other_env(first_env);
                tracing::info!(
                    did = %registration.did,
                    first_env,
                    second_env,
                    "APNs BadDeviceToken on first attempt; retrying on other environment"
                );
                match self.client_for(second_env).send(payload).await {
                    Ok(_) => Ok(second_env),
                    Err(second_err) => {
                        // BadDeviceToken on both endpoints means the token is
                        // genuinely invalid, not just aimed at the wrong
                        // environment. Surface the original error so
                        // `is_invalid_token` (which also checks for
                        // BadDeviceToken) can deactivate it.
                        Err(anyhow::Error::new(second_err))
                    }
                }
            }
            Err(err) => Err(anyhow::Error::new(err)),
        }
    }

    fn build_payload<'a>(
        &'a self,
        registration: &'a RegistrationRow,
        notification: &'a ApnsNotification,
    ) -> Result<a2::request::payload::Payload<'a>> {
        let mut builder = DefaultNotificationBuilder::new()
            .set_title(&notification.title)
            .set_body(&notification.body)
            .set_sound("default");

        if notification.mutable_content {
            builder = builder.set_mutable_content();
        }

        let mut payload = builder.build(
            &registration.device_token,
            NotificationOptions {
                apns_topic: Some(&self.topic),
                apns_priority: Some(Priority::High),
                apns_collapse_id: None,
                apns_expiration: None,
                apns_push_type: None,
                apns_id: None,
            },
        );

        for (key, value) in &notification.custom_data {
            payload.add_custom_data(key, value)?;
        }

        if let Some(ref thread_id) = notification.thread_id {
            payload.add_custom_data("thread-id", thread_id)?;
        }

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_try_env_prefers_known_registration_env() {
        assert_eq!(first_try_env(Some(ENV_SANDBOX), true), ENV_SANDBOX);
        assert_eq!(first_try_env(Some(ENV_PRODUCTION), false), ENV_PRODUCTION);
    }

    #[test]
    fn first_try_env_falls_back_to_configured_default_when_unknown() {
        assert_eq!(first_try_env(None, true), ENV_PRODUCTION);
        assert_eq!(first_try_env(None, false), ENV_SANDBOX);
    }

    #[test]
    fn first_try_env_falls_back_to_configured_default_on_unrecognized_value() {
        assert_eq!(first_try_env(Some("bogus"), true), ENV_PRODUCTION);
        assert_eq!(first_try_env(Some("bogus"), false), ENV_SANDBOX);
    }

    #[test]
    fn other_env_flips() {
        assert_eq!(other_env(ENV_PRODUCTION), ENV_SANDBOX);
        assert_eq!(other_env(ENV_SANDBOX), ENV_PRODUCTION);
    }

    #[test]
    fn is_bad_device_token_matches_response_error_reason() {
        let bad_token_err = A2Error::ResponseError(a2::Response {
            error: Some(a2::ErrorBody {
                reason: ErrorReason::BadDeviceToken,
                timestamp: None,
            }),
            apns_id: None,
            code: 400,
        });
        assert!(is_bad_device_token(&bad_token_err));

        let unregistered_err = A2Error::ResponseError(a2::Response {
            error: Some(a2::ErrorBody {
                reason: ErrorReason::Unregistered,
                timestamp: None,
            }),
            apns_id: None,
            code: 410,
        });
        assert!(!is_bad_device_token(&unregistered_err));
    }
}
