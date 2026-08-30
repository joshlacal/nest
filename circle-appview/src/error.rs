use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
/// Key for storing request ID in request extensions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthReason {
    MissingHeader,
    InvalidHeader,
    InvalidJwtFormat,
    InvalidHeaderEncoding,
    InvalidClaimsEncoding,
    InvalidHeaderJson,
    InvalidClaimsJson,
    InvalidTyp,
    UnsupportedAlg,
    InvalidKid,
    MissingKid,
    NoVerificationMethod,
    InvalidKeyType,
    InvalidCurve,
    InvalidCoordinates,
    InvalidMultikey,
    InvalidSignatureFormat,
    BadSignature,
    Expired,
    FutureIat,
    MissingIat,
    MissingExp,
    LifetimeExceeded,
    AudienceMismatch,
    LxmMismatch,
    MissingLxm,
    MissingJti,
    ReplayedJti,
    DidResolutionFailed,
    DidDocumentInvalid,
    UnsupportedDidMethod,
    ControllerMismatch,
    IdMismatch,
    SsrfBlocked,
    AlgKeyMismatch,
}

impl std::fmt::Display for AuthReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::MissingHeader => "missing_header",
            Self::InvalidHeader => "invalid_header",
            Self::InvalidJwtFormat => "invalid_jwt_format",
            Self::InvalidHeaderEncoding => "invalid_header_encoding",
            Self::InvalidClaimsEncoding => "invalid_claims_encoding",
            Self::InvalidHeaderJson => "invalid_header_json",
            Self::InvalidClaimsJson => "invalid_claims_json",
            Self::InvalidTyp => "invalid_typ",
            Self::UnsupportedAlg => "unsupported_alg",
            Self::InvalidKid => "invalid_kid",
            Self::MissingKid => "missing_kid",
            Self::NoVerificationMethod => "no_verification_method",
            Self::InvalidKeyType => "invalid_key_type",
            Self::InvalidCurve => "invalid_curve",
            Self::InvalidCoordinates => "invalid_coordinates",
            Self::InvalidMultikey => "invalid_multikey",
            Self::InvalidSignatureFormat => "invalid_signature_format",
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
            Self::FutureIat => "future_iat",
            Self::MissingIat => "missing_iat",
            Self::MissingExp => "missing_exp",
            Self::LifetimeExceeded => "lifetime_exceeded",
            Self::AudienceMismatch => "audience_mismatch",
            Self::LxmMismatch => "lxm_mismatch",
            Self::MissingLxm => "missing_lxm",
            Self::MissingJti => "missing_jti",
            Self::ReplayedJti => "replayed_jti",
            Self::DidResolutionFailed => "did_resolution_failed",
            Self::DidDocumentInvalid => "did_document_invalid",
            Self::UnsupportedDidMethod => "unsupported_did_method",
            Self::ControllerMismatch => "controller_mismatch",
            Self::IdMismatch => "id_mismatch",
            Self::SsrfBlocked => "ssrf_blocked",
            Self::AlgKeyMismatch => "alg_key_mismatch",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Authentication required: {0}")]
    Unauthorized(AuthReason),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Access removed: {0}")]
    AccessRemoved(String),
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("Database error: {0}")]
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
            AppError::Unauthorized(reason) => {
                tracing::warn!(reason = %reason, "Authentication failed");
                (
                    StatusCode::UNAUTHORIZED,
                    "AuthRequired",
                    "Authentication required".to_string(),
                )
            }
            AppError::Forbidden(msg) => {
                tracing::warn!(error_code = "Forbidden", "Forbidden access attempt");
                (StatusCode::FORBIDDEN, "Forbidden", msg.clone())
            }
            AppError::AccessRemoved(msg) => {
                tracing::warn!(error_code = "AccessRemoved", "Access removed");
                (StatusCode::FORBIDDEN, "AccessRemoved", msg.clone())
            }
            AppError::NotFound(msg) => {
                tracing::info!(error_code = "NotFound", "Resource not found");
                (StatusCode::NOT_FOUND, "NotFound", msg.clone())
            }
            AppError::InvalidRequest(msg) => {
                tracing::info!(error_code = "InvalidRequest", "Invalid request");
                (StatusCode::BAD_REQUEST, "InvalidRequest", msg.clone())
            }
            AppError::Conflict(msg) => {
                tracing::info!(error_code = "Conflict", "Resource conflict");
                (StatusCode::CONFLICT, "Conflict", msg.clone())
            }
            AppError::TooManyRequests(msg) => {
                tracing::warn!(error_code = "TooManyRequests", "Too many requests");
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "TooManyRequests",
                    msg.clone(),
                )
            }
            AppError::Database(_err) => {
                tracing::error!(
                    error_code = "DatabaseError",
                    "Database query error occurred"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    "A database error occurred".to_string(),
                )
            }
            AppError::Internal(_err) => {
                tracing::error!(
                    error_code = "InternalError",
                    "Internal server error occurred"
                );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_error_response_redacts_database_and_internal_errors() {
        let internal_err = AppError::Internal(
            "Database connection string: postgres://user:SECRET_PASS@host/db".into(),
        );
        let response = internal_err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let body_str = String::from_utf8_lossy(&bytes);
        assert!(!body_str.contains("SECRET_PASS"));
        assert!(body_str.contains("An internal server error occurred"));
    }

    #[tokio::test]
    async fn test_auth_reasons_render_uniform_unauthorized() {
        let err = AppError::Unauthorized(AuthReason::Expired);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let body_str = String::from_utf8_lossy(&bytes);
        assert!(body_str.contains("AuthRequired"));
        assert!(body_str.contains("Authentication required"));
    }
}
