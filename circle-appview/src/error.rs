use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Authentication required: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Database error")]
    Database(#[from] sqlx::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_code, client_message) = match &self {
            AppError::Unauthorized(msg) => {
                tracing::warn!("Authentication failed: {}", msg);
                (StatusCode::UNAUTHORIZED, "AuthenticationRequired", msg.clone())
            }
            AppError::Forbidden(msg) => {
                tracing::warn!("Forbidden access attempt: {}", msg);
                (StatusCode::FORBIDDEN, "Forbidden", msg.clone())
            }
            AppError::NotFound(msg) => {
                (StatusCode::NOT_FOUND, "NotFound", msg.clone())
            }
            AppError::InvalidRequest(msg) => {
                (StatusCode::BAD_REQUEST, "InvalidRequest", msg.clone())
            }
            AppError::Conflict(msg) => {
                (StatusCode::CONFLICT, "Conflict", msg.clone())
            }
            AppError::Database(err) => {
                // Redact database details from client for privacy and security
                tracing::error!("Database query error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    "A database error occurred".to_string(),
                )
            }
            AppError::Internal(err) => {
                tracing::error!("Internal server error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    "An internal server error occurred".to_string(),
                )
            }
        };

        let body = Json(ErrorBody {
            error: error_code,
            message: client_message,
        });

        (status, body).into_response()
    }
}
