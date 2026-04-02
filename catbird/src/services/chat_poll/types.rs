use serde::Deserialize;
use sqlx::FromRow;
use time::OffsetDateTime;

/// Row from chat_poll_state table
#[derive(Debug, Clone, FromRow)]
pub struct ChatPollRow {
    pub account_did: String,
    pub chat_cursor: Option<String>,
    pub next_poll_at: OffsetDateTime,
    pub last_poll_at: Option<OffsetDateTime>,
    pub poll_tier: i16,
    pub foreground_lease_until: Option<OffsetDateTime>,
    pub pds_host: String,
    pub last_429_at: Option<OffsetDateTime>,
    pub last_retry_after_secs: Option<i32>,
    pub last_notified_message_id: Option<String>,
}

/// Deserialized response from chat.bsky.convo.getLog
#[derive(Debug, Deserialize)]
pub struct GetLogResponse {
    pub cursor: String,
    pub logs: Vec<LogEntry>,
}

/// A single log entry from getLog — uses serde tagged enum
#[derive(Debug, Deserialize)]
#[serde(tag = "$type")]
pub enum LogEntry {
    #[serde(rename = "chat.bsky.convo.defs#logCreateMessage")]
    CreateMessage(LogMessageEvent),
    #[serde(rename = "chat.bsky.convo.defs#logDeleteMessage")]
    DeleteMessage(LogMessageEvent),
    #[serde(rename = "chat.bsky.convo.defs#logReadMessage")]
    ReadMessage(LogMessageEvent),
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogMessageEvent {
    pub convo_id: String,
    pub rev: String,
    pub message: LogMessage,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogMessage {
    pub id: String,
    pub sender: LogSender,
    #[serde(default)]
    pub text: Option<String>,
    pub sent_at: String,
}

#[derive(Debug, Deserialize)]
pub struct LogSender {
    pub did: String,
}

/// For mute sync — minimal convo view from listConvos
#[derive(Debug, Deserialize)]
pub struct ListConvosResponse {
    pub convos: Vec<ConvoView>,
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConvoView {
    pub id: String,
    #[serde(default)]
    pub muted: bool,
}

/// Push event passed from poller to queue + Redis
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatPushEvent {
    pub recipient_did: String,
    pub sender_did: String,
    pub convo_id: String,
    pub message_id: String,
    pub message_text: String,
    pub sent_at: String,
}

pub const TIER_HOT: i16 = 1;
pub const TIER_WARM: i16 = 2;
pub const TIER_COLD: i16 = 3;

pub fn tier_interval_secs(tier: i16) -> i64 {
    match tier {
        TIER_HOT => 30,
        TIER_WARM => 60,
        TIER_COLD => 300,
        _ => 60,
    }
}
