use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatPreference {
    #[serde(default = "default_include")]
    pub include: String,
    #[serde(default = "default_true")]
    pub push: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterablePreference {
    #[serde(default = "default_include")]
    pub include: String,
    #[serde(default = "default_true")]
    pub list: bool,
    #[serde(default = "default_true")]
    pub push: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preference {
    #[serde(default = "default_true")]
    pub list: bool,
    #[serde(default = "default_true")]
    pub push: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivitySubscriptionPreference {
    #[serde(default)]
    pub post: bool,
    #[serde(default)]
    pub reply: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushPreferencesDocument {
    #[serde(default)]
    pub chat: ChatPreference,
    #[serde(default)]
    pub follow: FilterablePreference,
    #[serde(default)]
    pub like: FilterablePreference,
    #[serde(default)]
    pub like_via_repost: FilterablePreference,
    #[serde(default)]
    pub mention: FilterablePreference,
    #[serde(default)]
    pub quote: FilterablePreference,
    #[serde(default)]
    pub reply: FilterablePreference,
    #[serde(default)]
    pub repost: FilterablePreference,
    #[serde(default)]
    pub repost_via_repost: FilterablePreference,
    #[serde(default)]
    pub starterpack_joined: Preference,
    #[serde(default)]
    pub subscribed_post: Preference,
    #[serde(default)]
    pub unverified: Preference,
    #[serde(default)]
    pub verified: Preference,
}

impl Default for PushPreferencesDocument {
    fn default() -> Self {
        Self {
            chat: ChatPreference::default(),
            follow: FilterablePreference::default(),
            like: FilterablePreference::default(),
            like_via_repost: FilterablePreference::default(),
            mention: FilterablePreference::default(),
            quote: FilterablePreference::default(),
            reply: FilterablePreference::default(),
            repost: FilterablePreference::default(),
            repost_via_repost: FilterablePreference::default(),
            starterpack_joined: Preference::default(),
            subscribed_post: Preference::default(),
            unverified: Preference::default(),
            verified: Preference::default(),
        }
    }
}

impl Default for ChatPreference {
    fn default() -> Self {
        Self {
            include: default_include(),
            push: true,
        }
    }
}

impl Default for FilterablePreference {
    fn default() -> Self {
        Self {
            include: default_include(),
            list: true,
            push: true,
        }
    }
}

impl Default for Preference {
    fn default() -> Self {
        Self {
            list: true,
            push: true,
        }
    }
}

impl PushPreferencesDocument {
    pub fn is_push_enabled_for(&self, notification_type: &str) -> bool {
        match notification_type {
            "mention" => self.mention.push,
            "reply" => self.reply.push,
            "like" => self.like.push,
            "follow" => self.follow.push,
            "repost" => self.repost.push,
            "quote" => self.quote.push,
            "via_like" => self.like_via_repost.push,
            "via_repost" => self.repost_via_repost.push,
            "activity_post" | "activity_reply" => self.subscribed_post.push,
            "chat_message" => self.chat.push,
            _ => true,
        }
    }

    pub fn to_lexicon_json(&self) -> Value {
        json!({
            "chat": self.chat,
            "follow": self.follow,
            "like": self.like,
            "likeViaRepost": self.like_via_repost,
            "mention": self.mention,
            "quote": self.quote,
            "reply": self.reply,
            "repost": self.repost,
            "repostViaRepost": self.repost_via_repost,
            "starterpackJoined": self.starterpack_joined,
            "subscribedPost": self.subscribed_post,
            "unverified": self.unverified,
            "verified": self.verified,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PutPreferencesInput {
    pub chat: Option<ChatPreference>,
    pub follow: Option<FilterablePreference>,
    pub like: Option<FilterablePreference>,
    #[serde(rename = "likeViaRepost")]
    pub like_via_repost: Option<FilterablePreference>,
    pub mention: Option<FilterablePreference>,
    pub quote: Option<FilterablePreference>,
    pub reply: Option<FilterablePreference>,
    pub repost: Option<FilterablePreference>,
    #[serde(rename = "repostViaRepost")]
    pub repost_via_repost: Option<FilterablePreference>,
    #[serde(rename = "starterpackJoined")]
    pub starterpack_joined: Option<Preference>,
    #[serde(rename = "subscribedPost")]
    pub subscribed_post: Option<Preference>,
    pub unverified: Option<Preference>,
    pub verified: Option<Preference>,
}

impl PutPreferencesInput {
    pub fn apply_to(self, mut prefs: PushPreferencesDocument) -> PushPreferencesDocument {
        if let Some(value) = self.chat {
            prefs.chat = value;
        }
        if let Some(value) = self.follow {
            prefs.follow = value;
        }
        if let Some(value) = self.like {
            prefs.like = value;
        }
        if let Some(value) = self.like_via_repost {
            prefs.like_via_repost = value;
        }
        if let Some(value) = self.mention {
            prefs.mention = value;
        }
        if let Some(value) = self.quote {
            prefs.quote = value;
        }
        if let Some(value) = self.reply {
            prefs.reply = value;
        }
        if let Some(value) = self.repost {
            prefs.repost = value;
        }
        if let Some(value) = self.repost_via_repost {
            prefs.repost_via_repost = value;
        }
        if let Some(value) = self.starterpack_joined {
            prefs.starterpack_joined = value;
        }
        if let Some(value) = self.subscribed_post {
            prefs.subscribed_post = value;
        }
        if let Some(value) = self.unverified {
            prefs.unverified = value;
        }
        if let Some(value) = self.verified {
            prefs.verified = value;
        }
        prefs
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterPushInput {
    #[serde(rename = "serviceDid")]
    pub service_did: String,
    pub token: String,
    pub platform: String,
    #[serde(rename = "appId")]
    pub app_id: String,
    #[serde(rename = "ageRestricted")]
    pub age_restricted: Option<bool>,
}
impl RegisterPushInput {
    pub fn validate(&self) -> anyhow::Result<()> {
        let trimmed_token = self.token.trim();
        if trimmed_token.is_empty() {
            return Err(anyhow::anyhow!("Device token cannot be empty"));
        }
        if self.token.len() > 512 {
            return Err(anyhow::anyhow!("Device token exceeds maximum length of 512"));
        }
        if self.token.chars().any(|c| c.is_control()) {
            return Err(anyhow::anyhow!("Device token contains invalid control characters"));
        }
        let trimmed_platform = self.platform.trim();
        if trimmed_platform.is_empty() {
            return Err(anyhow::anyhow!("Platform cannot be empty"));
        }
        if self.platform.len() > 32 {
            return Err(anyhow::anyhow!("Platform exceeds maximum length of 32"));
        }
        let trimmed_app_id = self.app_id.trim();
        if trimmed_app_id.is_empty() {
            return Err(anyhow::anyhow!("App ID cannot be empty"));
        }
        if self.app_id.len() > 128 {
            return Err(anyhow::anyhow!("App ID exceeds maximum length of 128"));
        }
        if self.service_did.len() > 256 {
            return Err(anyhow::anyhow!("Service DID exceeds maximum length of 256"));
        }
        Ok(())
    }
}


#[derive(Debug, Clone, Deserialize)]
pub struct UnregisterPushInput {
    #[serde(rename = "serviceDid")]
    pub service_did: String,
    pub token: String,
    pub platform: String,
    #[serde(rename = "appId")]
    pub app_id: String,
}
impl UnregisterPushInput {
    pub fn validate(&self) -> anyhow::Result<()> {
        let trimmed_token = self.token.trim();
        if trimmed_token.is_empty() || self.token.len() > 512 {
            return Err(anyhow::anyhow!("Invalid device token"));
        }
        let trimmed_platform = self.platform.trim();
        if trimmed_platform.is_empty() || self.platform.len() > 32 {
            return Err(anyhow::anyhow!("Invalid platform"));
        }
        let trimmed_app_id = self.app_id.trim();
        if trimmed_app_id.is_empty() || self.app_id.len() > 128 {
            return Err(anyhow::anyhow!("Invalid app ID"));
        }
        Ok(())
    }
}


#[derive(Debug, Clone, Deserialize)]
pub struct PutActivitySubscriptionInput {
    pub subject: String,
    #[serde(rename = "activitySubscription")]
    pub activity_subscription: ActivitySubscriptionPreference,
}

#[derive(Debug, Clone, FromRow)]
pub struct RegistrationRow {
    pub id: sqlx::types::Uuid,
    pub did: String,
    pub device_token: String,
    pub platform: String,
    pub app_id: String,
    pub service_did: Option<String>,
    pub age_restricted: bool,
    pub is_active: bool,
    /// Which APNs environment ("production"/"sandbox") this token is known to
    /// belong to. NULL until try-and-learn observes a successful delivery.
    pub apns_environment: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct QueueRow {
    pub id: i64,
    pub recipient_did: String,
    pub actor_did: String,
    pub notification_type: String,
    pub event_cid: String,
    pub event_path: String,
    pub subject_uri: Option<String>,
    pub thread_root_uri: Option<String>,
    pub event_record_json: Value,
    pub event_timestamp: i64,
    pub created_at: sqlx::types::time::OffsetDateTime,
    pub attempts: i32,
    #[sqlx(default)]
    pub lease_token: Option<uuid::Uuid>,
    #[sqlx(default)]
    pub lease_version: i64,
    #[sqlx(default)]
    pub auth_generation: i64,
}
#[derive(Debug, Clone, FromRow)]
pub struct ActivitySubscriptionRow {
    pub subject_did: String,
    pub include_posts: bool,
    pub include_replies: bool,
}

#[derive(Debug, Clone, FromRow)]
pub struct PushAccountRow {
    pub account_did: String,
    pub session_id: String,
    pub pds_url: String,
    #[sqlx(default)]
    pub auth_generation: i64,
}

fn default_include() -> String {
    "all".to_string()
}

fn default_true() -> bool {
    true
}
