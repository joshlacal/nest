use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::Arc,
};

use a2::{
    request::payload::{PayloadLike, APS},
    Client, CollapseId, DefaultNotificationBuilder, Error as A2Error, ErrorReason,
    NotificationBuilder, NotificationOptions, Priority, PushType,
};
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use serde_json::Value;

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

// a2 0.10's APS model has no thread-id field. Extend it at the standard aps
// location so grouping still works when the notification extension cannot run.
#[derive(Debug, Clone, Serialize)]
struct NotificationAps<'a> {
    #[serde(flatten)]
    content: APS<'a>,
    #[serde(rename = "thread-id", skip_serializing_if = "Option::is_none")]
    thread_id: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
struct NotificationPayload<'a> {
    #[serde(skip)]
    options: NotificationOptions<'a>,
    #[serde(skip)]
    device_token: &'a str,
    aps: NotificationAps<'a>,
    #[serde(flatten)]
    data: BTreeMap<&'a str, Value>,
}

impl PayloadLike for NotificationPayload<'_> {
    fn get_device_token(&self) -> &str {
        self.device_token
    }

    fn get_options(&self) -> &NotificationOptions<'_> {
        &self.options
    }
}

fn build_payload<'a>(
    topic: &'a str,
    registration: &'a RegistrationRow,
    notification: &'a ApnsNotification,
) -> Result<NotificationPayload<'a>> {
    ensure!(
        registration.did == notification.user_did,
        "APNs notification recipient does not match device registration"
    );

    let mut builder = DefaultNotificationBuilder::new()
        .set_title(&notification.title)
        .set_body(&notification.body)
        .set_sound("default");

    if notification.mutable_content {
        builder = builder.set_mutable_content();
    }
    if notification.custom_data.get("type").map(String::as_str) == Some("chat_message") {
        builder = builder.set_category("CHAT_MESSAGE");
    }

    let delivery_id = notification
        .custom_data
        .get("pushDeliveryId")
        .map(String::as_str);
    if let Some(delivery_id) = delivery_id {
        uuid::Uuid::parse_str(delivery_id).context("Invalid APNs delivery identifier")?;
    }
    let mut payload = builder.build(
        &registration.device_token,
        NotificationOptions {
            apns_topic: Some(topic),
            apns_priority: Some(Priority::High),
            // The durable per-device UUID is reused for retries of one message.
            // It can coalesce pending copies, but is not an exactly-once guarantee.
            apns_collapse_id: delivery_id.map(CollapseId::new).transpose()?,
            apns_expiration: None,
            // Communication presentation is applied by the extension using
            // INSendMessageIntent; a visible message is still an alert push.
            apns_push_type: Some(PushType::Alert),
            apns_id: delivery_id,
        },
    );

    for (key, value) in &notification.custom_data {
        ensure!(key != "aps", "APNs custom data cannot replace aps");
        payload.add_custom_data(key, value)?;
    }
    if let Some(ref thread_id) = notification.thread_id {
        // Preserve the existing custom field for older consumers as well.
        payload.add_custom_data("thread-id", thread_id)?;
    }

    Ok(NotificationPayload {
        options: payload.options,
        device_token: payload.device_token,
        aps: NotificationAps {
            content: payload.aps,
            thread_id: notification.thread_id.as_deref(),
        },
        data: payload.data,
    })
}

#[async_trait::async_trait]
pub trait ApnsSender: Send + Sync {
    async fn send(
        &self,
        registration: &RegistrationRow,
        notification: &ApnsNotification,
    ) -> Result<&'static str>;
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
        if !config.enabled {
            tracing::warn!("APNs delivery is disabled by configuration; all Nest push delivery will stay disabled");
            return Ok(None);
        }

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
    /// also fails, its error is returned. A second `BadDeviceToken` permits
    /// token deactivation, an explicit transient rejection permits bounded
    /// retry, and a lost/failed response remains an ambiguous held delivery.
    ///
    /// Returns the APNs environment ("production" or "sandbox") that
    /// successfully delivered the notification, so callers can persist a
    /// learned environment when it differs from what's on file.
    pub async fn send(
        &self,
        registration: &RegistrationRow,
        notification: &ApnsNotification,
    ) -> Result<&'static str> {
        let payload = build_payload(&self.topic, registration, notification)?;

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
                        // environment. Preserve the SECOND error: substituting
                        // the first BadDeviceToken for a second transport error
                        // would discard an ambiguous possible acceptance.
                        Err(anyhow::Error::new(second_err))
                    }
                }
            }
            Err(err) => Err(anyhow::Error::new(err)),
        }
    }
}

#[async_trait::async_trait]
impl ApnsSender for ApnsDelivery {
    async fn send(
        &self,
        registration: &RegistrationRow,
        notification: &ApnsNotification,
    ) -> Result<&'static str> {
        self.send(registration, notification).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration() -> RegistrationRow {
        RegistrationRow {
            id: uuid::Uuid::nil(),
            did: "did:plc:recipient".to_string(),
            device_token: "test-device-token".to_string(),
            platform: "ios".to_string(),
            app_id: "blue.catbird".to_string(),
            service_did: None,
            age_restricted: false,
            is_active: true,
            apns_environment: Some(ENV_PRODUCTION.to_string()),
        }
    }

    fn chat_notification() -> ApnsNotification {
        ApnsNotification {
            title: "New Message".to_string(),
            body: "You have a new message".to_string(),
            user_did: "did:plc:recipient".to_string(),
            custom_data: HashMap::from([
                ("type".to_string(), "chat_message".to_string()),
                ("recipientDid".to_string(), "did:plc:recipient".to_string()),
                ("senderDid".to_string(), "did:plc:sender".to_string()),
                ("convoId".to_string(), "conversation-1".to_string()),
                ("messageId".to_string(), "message-1".to_string()),
                (
                    "pushDeliveryId".to_string(),
                    "ca896c16-a404-47b0-842c-90fb5aefc5ce".to_string(),
                ),
            ]),
            mutable_content: true,
            thread_id: Some("chat:account-hash:conversation-1".to_string()),
        }
    }

    #[test]
    fn chat_payload_uses_visible_alert_headers_and_standard_aps_fields() {
        let registration = registration();
        let notification = chat_notification();
        let payload = build_payload("blue.catbird", &registration, &notification).unwrap();
        let options = payload.get_options();
        assert_eq!(options.apns_push_type, Some(PushType::Alert));
        assert_eq!(options.apns_push_type.unwrap().to_string(), "alert");
        assert_eq!(options.apns_priority.as_ref().unwrap().to_string(), "10");
        assert_eq!(options.apns_topic, Some("blue.catbird"));

        let json: Value = serde_json::from_str(&payload.to_json_string().unwrap()).unwrap();
        assert_eq!(
            json["aps"],
            serde_json::json!({
                "alert": { "title": "New Message", "body": "You have a new message" },
                "sound": "default",
                "category": "CHAT_MESSAGE",
                "mutable-content": 1,
                "thread-id": "chat:account-hash:conversation-1"
            })
        );
        assert_eq!(json["type"], "chat_message");
        assert_eq!(json["recipientDid"], "did:plc:recipient");
        assert_eq!(json["senderDid"], "did:plc:sender");
        assert_eq!(json["convoId"], "conversation-1");
        assert_eq!(json["messageId"], "message-1");
        assert_eq!(json["thread-id"], json["aps"]["thread-id"]);
        assert!(json.get("messageText").is_none());
        assert!(json.get("device_token").is_none());
        assert!(json.get("options").is_none());
    }

    #[test]
    fn message_delivery_id_survives_retries_without_collapsing_the_conversation() {
        let registration = registration();
        let notification = chat_notification();
        let first = build_payload("blue.catbird", &registration, &notification).unwrap();
        let retry = build_payload("blue.catbird", &registration, &notification).unwrap();
        assert_eq!(first.options.apns_id, retry.options.apns_id);
        assert_eq!(
            first.options.apns_id,
            Some("ca896c16-a404-47b0-842c-90fb5aefc5ce")
        );
        assert_eq!(
            first.options.apns_collapse_id.as_ref().unwrap().value,
            first.options.apns_id.unwrap()
        );

        let mut next_message = notification.clone();
        next_message.custom_data.insert(
            "pushDeliveryId".to_string(),
            "16b2d004-4027-41ba-8d7b-590d619a95ba".to_string(),
        );
        next_message
            .custom_data
            .insert("messageId".to_string(), "message-2".to_string());
        let next = build_payload("blue.catbird", &registration, &next_message).unwrap();
        assert_eq!(first.aps.thread_id, next.aps.thread_id);
        assert_ne!(
            first.options.apns_collapse_id.unwrap().value,
            next.options.apns_collapse_id.unwrap().value
        );
    }

    #[test]
    fn social_alert_keeps_existing_presentation_and_no_chat_category() {
        let registration = registration();
        let notification = ApnsNotification {
            title: "New like".to_string(),
            body: "Someone liked your post".to_string(),
            user_did: registration.did.clone(),
            custom_data: HashMap::from([("reason".to_string(), "like".to_string())]),
            mutable_content: false,
            thread_id: None,
        };
        let payload = build_payload("blue.catbird", &registration, &notification).unwrap();
        assert_eq!(payload.options.apns_push_type, Some(PushType::Alert));
        assert!(payload.options.apns_id.is_none());
        assert!(payload.options.apns_collapse_id.is_none());
        let json = serde_json::to_value(payload).unwrap();
        assert_eq!(json["aps"]["alert"]["body"], "Someone liked your post");
        assert!(json["aps"].get("category").is_none());
        assert!(json["aps"].get("thread-id").is_none());
        assert_ne!(json["aps"]["mutable-content"], 1);
    }

    #[test]
    fn recipient_mismatch_is_rejected_before_sending() {
        let mut registration = registration();
        registration.did = "did:plc:different-account".to_string();
        let error = build_payload("blue.catbird", &registration, &chat_notification()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "APNs notification recipient does not match device registration"
        );
    }

    #[test]
    fn invalid_delivery_id_and_reserved_aps_are_rejected() {
        let registration = registration();
        let mut notification = chat_notification();
        notification
            .custom_data
            .insert("pushDeliveryId".to_string(), "not-a-uuid".to_string());
        assert!(build_payload("blue.catbird", &registration, &notification).is_err());
        notification.custom_data.remove("pushDeliveryId");
        notification
            .custom_data
            .insert("aps".to_string(), "override".to_string());
        assert!(build_payload("blue.catbird", &registration, &notification).is_err());
    }

    #[test]
    fn disabled_apns_skips_configured_credentials() {
        let config: ApnsConfig = serde_json::from_value(serde_json::json!({
            "enabled": false,
            "key_path": "/dev/null/nest-apns-disabled-test.p8",
            "key_id": "test-key",
            "team_id": "test-team",
            "topic": "blue.catbird"
        }))
        .unwrap();

        match ApnsDelivery::new(&config) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("disabled APNs must not create a delivery client"),
            Err(err) => panic!("disabled APNs must not read configured credentials: {err}"),
        }
    }

    #[test]
    fn enabled_apns_still_validates_configured_credentials() {
        let config: ApnsConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "key_path": "/dev/null/nest-apns-enabled-test.p8",
            "key_id": "test-key",
            "team_id": "test-team",
            "topic": "blue.catbird"
        }))
        .unwrap();

        assert!(ApnsDelivery::new(&config).is_err());
    }

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
