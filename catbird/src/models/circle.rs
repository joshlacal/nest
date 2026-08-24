//! Circle orchestration models and projection outbox types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Durable outbox record for Circle AppView projections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct CircleProjectionOperation {
    pub id: Uuid,
    pub operation_key: String,
    pub actor_did: String,
    pub session_id: String,
    pub space_uri: String,
    pub kind: CircleProjectionKind,
    pub payload: serde_json::Value,
    pub state: CircleProjectionState,
    pub attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error_code: Option<String>,
    pub execution_started_at: Option<DateTime<Utc>>,
    pub claim_token: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The kind of Circle projection operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CircleProjectionKind {
    CircleUpsert,
    MemberAdd,
    MemberRemove,
    CircleDelete,
}

impl CircleProjectionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CircleUpsert => "circle_upsert",
            Self::MemberAdd => "member_add",
            Self::MemberRemove => "member_remove",
            Self::CircleDelete => "circle_delete",
        }
    }
}

impl std::fmt::Display for CircleProjectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for CircleProjectionKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "circle_upsert" => Ok(Self::CircleUpsert),
            "member_add" => Ok(Self::MemberAdd),
            "member_remove" => Ok(Self::MemberRemove),
            "circle_delete" => Ok(Self::CircleDelete),
            _ => Err(format!("Unknown projection kind: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CircleProjectionState {
    Intent,
    Executing,
    Pending,
    Delivered,
    Failed,
}

impl CircleProjectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Executing => "executing",
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for CircleProjectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for CircleProjectionState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "intent" => Ok(Self::Intent),
            "executing" => Ok(Self::Executing),
            "pending" => Ok(Self::Pending),
            "delivered" => Ok(Self::Delivered),
            "failed" => Ok(Self::Failed),
            _ => Err(format!("Unknown projection state: {s}")),
        }
    }
}

/// Calculates the deterministic SHA-256 operation key for outbox deduplication.
/// Key is SHA-256 over `actor_did + ":" + space_uri + ":" + kind + ":" + canonical payload`.
pub fn calculate_operation_key(
    actor_did: &str,
    space_uri: &str,
    kind: CircleProjectionKind,
    payload: &serde_json::Value,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(actor_did.as_bytes());
    hasher.update(b":");
    hasher.update(space_uri.as_bytes());
    hasher.update(b":");
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b":");
    let canonical = serde_json::to_string(payload).unwrap_or_default();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Errors occurring during Circle orchestration operations.
#[derive(Debug, thiserror::Error)]
pub enum CircleError {
    #[error("Not authorized: {0}")]
    NotAuthorized(String),
    #[error("Access removed: {0}")]
    AccessRemoved(String),
    #[error("Unsupported PDS: {0}")]
    UnsupportedPds(String),
    #[error("Protocol revision mismatch: {0}")]
    ProtocolRevisionMismatch(String),
    #[error("Upstream unavailable: {0}")]
    UpstreamUnavailable(String),
    #[error("Space not found: {0}")]
    SpaceNotFound(String),
    #[error("Space already exists: {0}")]
    SpaceAlreadyExists(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("PDS error: {0}")]
    Pds(String),
    #[error("AppView error: {0}")]
    AppView(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Attestation error: {0}")]
    Attestation(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for CircleError {
    fn from(err: sqlx::Error) -> Self {
        CircleError::Database(err.to_string())
    }
}

impl From<crate::error::AppError> for CircleError {
    fn from(err: crate::error::AppError) -> Self {
        match err {
            crate::error::AppError::Unauthorized(msg) => CircleError::NotAuthorized(msg),
            crate::error::AppError::BadRequest(msg) => CircleError::InvalidRequest(msg),
            crate::error::AppError::NotFound(msg) => CircleError::SpaceNotFound(msg),
            crate::error::AppError::AtprotoResponse { status, error, message } => {
                match error.as_str() {
                    "AuthRequired" => CircleError::NotAuthorized(message),
                    "AccessRemoved" => CircleError::AccessRemoved(message),
                    "UnsupportedPDS" => CircleError::UnsupportedPds(message),
                    "ProtocolRevisionMismatch" => CircleError::ProtocolRevisionMismatch(message),
                    "UpstreamUnavailable" => CircleError::UpstreamUnavailable(message),
                    "SpaceNotFound" => CircleError::SpaceNotFound(message),
                    "SpaceAlreadyExists" => CircleError::SpaceAlreadyExists(message),
                    _ => CircleError::Internal(format!("{status} - {error}: {message}")),
                }
            }
            other => CircleError::Internal(other.to_string()),
        }
    }
}

impl From<crate::services::ClientAttestationError> for CircleError {
    fn from(err: crate::services::ClientAttestationError) -> Self {
        CircleError::Attestation(err.to_string())
    }
}

impl From<CircleError> for crate::error::AppError {
    fn from(err: CircleError) -> Self {
        use axum::http::StatusCode;
        match err {
            CircleError::NotAuthorized(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::UNAUTHORIZED,
                error: "AuthRequired".into(),
                message: msg,
            },
            CircleError::AccessRemoved(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::FORBIDDEN,
                error: "AccessRemoved".into(),
                message: msg,
            },
            CircleError::UnsupportedPds(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::BAD_REQUEST,
                error: "UnsupportedPDS".into(),
                message: msg,
            },
            CircleError::ProtocolRevisionMismatch(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::BAD_REQUEST,
                error: "ProtocolRevisionMismatch".into(),
                message: msg,
            },
            CircleError::UpstreamUnavailable(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::SERVICE_UNAVAILABLE,
                error: "UpstreamUnavailable".into(),
                message: msg,
            },
            CircleError::InvalidRequest(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::BAD_REQUEST,
                error: "InvalidRequest".into(),
                message: msg,
            },
            CircleError::SpaceNotFound(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::NOT_FOUND,
                error: "SpaceNotFound".into(),
                message: msg,
            },
            CircleError::SpaceAlreadyExists(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::BAD_REQUEST,
                error: "SpaceAlreadyExists".into(),
                message: msg,
            },
            CircleError::Pds(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::BAD_GATEWAY,
                error: "UpstreamUnavailable".into(),
                message: format!("PDS error: {msg}"),
            },
            CircleError::AppView(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::BAD_GATEWAY,
                error: "UpstreamUnavailable".into(),
                message: format!("AppView error: {msg}"),
            },
            CircleError::Database(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::SERVICE_UNAVAILABLE,
                error: "UpstreamUnavailable".into(),
                message: format!("Database temporarily unavailable: {msg}"),
            },
            CircleError::Attestation(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                error: "InternalServerError".into(),
                message: format!("Attestation error: {msg}"),
            },
            CircleError::Internal(msg) => crate::error::AppError::AtprotoResponse {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                error: "InternalServerError".into(),
                message: msg,
            },
        }
    }
}
