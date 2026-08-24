use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
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
            AppError::Unauthorized(reason) => {
                tracing::warn!(reason = %reason, "Authentication failed");
                (
                    StatusCode::UNAUTHORIZED,
                    "AuthRequired",
                    "Authentication required".to_string(),
                )
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
