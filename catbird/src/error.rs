//! Error types and handling for the Catbird Gateway
//!
//! Provides a unified error type that converts to appropriate HTTP responses.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Application error type
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid session")]
    InvalidSession,

    #[error("OAuth error: {0}")]
    OAuth(String),

    #[error("Upstream error: {status} - {message}")]
    Upstream { status: u16, message: String },

    #[error("Token refresh failed: {0}")]
    TokenRefresh(String),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match &self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone()),
            AppError::SessionExpired => (
                StatusCode::UNAUTHORIZED,
                "session_expired",
                "Your session has expired. Please log in again.".to_string(),
            ),
            AppError::InvalidSession => (
                StatusCode::UNAUTHORIZED,
                "invalid_session",
                "Invalid session. Please log in again.".to_string(),
            ),
            AppError::OAuth(msg) => (StatusCode::BAD_REQUEST, "oauth_error", msg.clone()),
            AppError::Upstream { status, message } => {
                let status_code = StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY);
                (status_code, "upstream_error", message.clone())
            }
            AppError::TokenRefresh(msg) => (
                StatusCode::UNAUTHORIZED,
                "token_refresh_failed",
                msg.clone(),
            ),
            AppError::Redis(e) => {
                tracing::error!("Redis error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred".to_string(),
                )
            }
            AppError::HttpClient(e) => {
                tracing::error!("HTTP client error: {}", e);
                (
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    "Failed to communicate with upstream server".to_string(),
                )
            }
            AppError::Json(e) => {
                tracing::error!("JSON error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Failed to process response".to_string(),
                )
            }
            AppError::Config(msg) => {
                tracing::error!("Config error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Server configuration error".to_string(),
                )
            }
            AppError::Crypto(msg) => {
                tracing::error!("Crypto error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Cryptographic operation failed".to_string(),
                )
            }
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    msg.clone(),
                )
            }
        };

        let body = Json(json!({
            "error": error_type,
            "message": message,
        }));

        (status, body).into_response()
    }
}

/// Result type alias for handlers
pub type AppResult<T> = Result<T, AppError>;