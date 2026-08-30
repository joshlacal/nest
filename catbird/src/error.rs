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

    #[error("Authentication temporarily unavailable: {0}")]
    AuthTemporarilyUnavailable(String),

    #[error("Service temporarily unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("ATProto error: {error} - {message}")]
    AtprotoResponse {
        status: StatusCode,
        error: String,
        message: String,
    },

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded { retry_after: u64 },

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Response too large: {0}")]
    ResponseTooLarge(String),
}

/// Constant public error message returned for all internal 500 error variants
pub const CONSTANT_INTERNAL_ERROR_MESSAGE: &str = "An internal error occurred";
pub const CONSTANT_INTERNAL_ERROR_CODE: &str = "internal_error";
/// Sanitize an error message to prevent leaking sensitive information in internal/system logs
pub fn sanitize_error_message(msg: &str) -> String {
    let mut sanitized = msg.to_string();

    // Redact URLs with credentials: scheme://user:pass@host
    if let Ok(url_creds_re) =
        regex::Regex::new(r#"(https?|redis|postgres|postgresql)://([^:@\s]+):([^@\s]+)@"#)
    {
        sanitized = url_creds_re
            .replace_all(&sanitized, "$1://[REDACTED]:[REDACTED]@")
            .to_string();
    }

    // Redact bearer tokens / authorization headers
    if let Ok(bearer_re) =
        regex::Regex::new(r#"(?i)(bearer\s+|authorization:\s*bearer\s+)([A-Za-z0-9\-_.~+/]+=*)"#)
    {
        sanitized = bearer_re
            .replace_all(&sanitized, "$1[REDACTED_TOKEN]")
            .to_string();
    }

    // Redact refresh_token, access_token, client_secret in JSON or key-value format
    if let Ok(token_re) = regex::Regex::new(
        r#"(?i)("(?:access_token|refresh_token|token|client_secret|password|secret)"\s*:\s*)"[^"]+""#,
    ) {
        sanitized = token_re
            .replace_all(&sanitized, r#"$1"[REDACTED]""#)
            .to_string();
    }

    sanitized
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let AppError::RateLimitExceeded { retry_after } = &self {
            tracing::warn!("Rate limit exceeded, retry after {} seconds", retry_after);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, retry_after.to_string())],
                Json(json!({
                    "error": "rate_limit_exceeded",
                    "message": format!(
                        "Too many requests. Please retry after {} seconds.",
                        retry_after
                    ),
                })),
            )
                .into_response();
        }

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
                (status_code, "UpstreamUnavailable", message.clone())
            }
            AppError::TokenRefresh(msg) => (
                StatusCode::UNAUTHORIZED,
                "token_refresh_failed",
                msg.clone(),
            ),
            AppError::AuthTemporarilyUnavailable(msg) | AppError::ServiceUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "TemporarilyUnavailable",
                msg.clone(),
            ),
            AppError::AtprotoResponse {
                status,
                error,
                message,
            } => (*status, error.as_str(), message.clone()),
            AppError::Redis(e) => {
                let safe_err = sanitize_error_message(&e.to_string());
                tracing::error!(error_kind = "redis", error = %safe_err, "Internal Redis error occurred");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    CONSTANT_INTERNAL_ERROR_CODE,
                    CONSTANT_INTERNAL_ERROR_MESSAGE.to_string(),
                )
            }
            AppError::Sqlx(e) => {
                let safe_err = sanitize_error_message(&e.to_string());
                tracing::error!(error_kind = "sqlx", error = %safe_err, "Internal database error occurred");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    CONSTANT_INTERNAL_ERROR_CODE,
                    CONSTANT_INTERNAL_ERROR_MESSAGE.to_string(),
                )
            }
            AppError::HttpClient(e) => {
                let safe_err = sanitize_error_message(&e.to_string());
                tracing::error!(error_kind = "http_client", error = %safe_err, "Upstream communication error");
                (
                    StatusCode::BAD_GATEWAY,
                    "UpstreamUnavailable",
                    "Failed to communicate with upstream server".to_string(),
                )
            }
            AppError::Json(e) => {
                let safe_err = sanitize_error_message(&e.to_string());
                tracing::error!(error_kind = "json", error = %safe_err, "Internal JSON processing error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    CONSTANT_INTERNAL_ERROR_CODE,
                    CONSTANT_INTERNAL_ERROR_MESSAGE.to_string(),
                )
            }
            AppError::Config(msg) => {
                let safe_err = sanitize_error_message(msg);
                tracing::error!(error_kind = "config", error = %safe_err, "Internal server configuration error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    CONSTANT_INTERNAL_ERROR_CODE,
                    CONSTANT_INTERNAL_ERROR_MESSAGE.to_string(),
                )
            }
            AppError::RateLimitExceeded { retry_after } => {
                tracing::warn!("Rate limit exceeded, retry after {} seconds", retry_after);
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limit_exceeded",
                    format!(
                        "Too many requests. Please retry after {} seconds.",
                        retry_after
                    ),
                )
            }
            AppError::Crypto(msg) => {
                let safe_err = sanitize_error_message(msg);
                tracing::error!(error_kind = "crypto", error = %safe_err, "Internal cryptographic error occurred");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    CONSTANT_INTERNAL_ERROR_CODE,
                    CONSTANT_INTERNAL_ERROR_MESSAGE.to_string(),
                )
            }
            AppError::Internal(msg) => {
                let safe_err = sanitize_error_message(msg);
                tracing::error!(error_kind = "internal", error = %safe_err, "Internal error occurred");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    CONSTANT_INTERNAL_ERROR_CODE,
                    CONSTANT_INTERNAL_ERROR_MESSAGE.to_string(),
                )
            }
            AppError::ResponseTooLarge(msg) => {
                (StatusCode::BAD_GATEWAY, "response_too_large", msg.clone())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_internal_error_returns_generic_message() {
        let err = AppError::Internal("sensitive schema and credentials: secret_123".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["error"], CONSTANT_INTERNAL_ERROR_CODE);
        assert_eq!(json["message"], CONSTANT_INTERNAL_ERROR_MESSAGE);
        assert!(!String::from_utf8_lossy(&body_bytes).contains("secret_123"));
    }

    #[tokio::test]
    async fn test_all_500_internal_error_variants_return_identical_constant_response() {
        let errors = vec![
            AppError::Internal("secret_internal_detail".to_string()),
            AppError::Crypto("secret_crypto_key_derivation_failed".to_string()),
            AppError::Config("secret_database_url_invalid".to_string()),
            AppError::Json(serde_json::from_str::<String>("not json").unwrap_err()),
        ];

        for err in errors {
            let resp = err.into_response();
            assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

            let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
            assert_eq!(json["error"], CONSTANT_INTERNAL_ERROR_CODE);
            assert_eq!(json["message"], CONSTANT_INTERNAL_ERROR_MESSAGE);
        }
    }

    #[test]
    fn test_sanitize_error_message_redacts_credentials_and_tokens() {
        let raw_url = "Failed to connect to redis://admin:supersecretpassword@127.0.0.1:6379/0";
        let sanitized_url = sanitize_error_message(raw_url);
        assert!(!sanitized_url.contains("supersecretpassword"));
        assert!(sanitized_url.contains("[REDACTED]"));

        let raw_bearer = "Upstream error: Bearer eyJhbGciOiJFUzI1NiJ9.secret_jwt_payload_data";
        let sanitized_bearer = sanitize_error_message(raw_bearer);
        assert!(!sanitized_bearer.contains("secret_jwt_payload_data"));
        assert!(sanitized_bearer.contains("[REDACTED_TOKEN]"));

        let raw_json = r#"{"refresh_token": "secret_refresh_token_value", "data": "ok"}"#;
        let sanitized_json = sanitize_error_message(raw_json);
        assert!(!sanitized_json.contains("secret_refresh_token_value"));
        assert!(sanitized_json.contains(r#""refresh_token": "[REDACTED]""#));
    }

    #[tokio::test]
    async fn test_rate_limit_exceeded_returns_429_with_retry_after_header() {
        let err = AppError::RateLimitExceeded { retry_after: 30 };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get(axum::http::header::RETRY_AFTER).unwrap(),
            "30"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["error"], "rate_limit_exceeded");
        assert_eq!(
            json["message"],
            "Too many requests. Please retry after 30 seconds."
        );
    }

    #[tokio::test]
    async fn test_service_unavailable_returns_503() {
        let err = AppError::ServiceUnavailable("Stream concurrency limit reached".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["error"], "TemporarilyUnavailable");
        assert_eq!(json["message"], "Stream concurrency limit reached");
    }
}
