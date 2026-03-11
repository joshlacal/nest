use std::{collections::HashMap, path::Path, sync::Arc};

use a2::{Client, DefaultNotificationBuilder, NotificationBuilder, NotificationOptions, Priority};
use anyhow::{Context, Result};

use crate::config::ApnsConfig;

use super::types::RegistrationRow;

#[derive(Debug, Clone)]
pub struct ApnsNotification {
    pub title: String,
    pub body: String,
    pub user_did: String,
    pub custom_data: HashMap<String, String>,
}

#[derive(Clone)]
pub struct ApnsDelivery {
    client: Arc<Client>,
    topic: String,
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

        let endpoint = if config.production {
            a2::Endpoint::Production
        } else {
            a2::Endpoint::Sandbox
        };
        let client = Client::token(
            std::fs::File::open(key_path)?,
            key_id,
            team_id,
            a2::ClientConfig::new(endpoint),
        )?;

        Ok(Some(Self {
            client: Arc::new(client),
            topic: topic.to_string(),
        }))
    }

    pub async fn send(
        &self,
        registration: &RegistrationRow,
        notification: &ApnsNotification,
    ) -> Result<()> {
        let builder = DefaultNotificationBuilder::new()
            .set_title(&notification.title)
            .set_body(&notification.body)
            .set_sound("default");

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

        self.client.send(payload).await?;
        Ok(())
    }
}
