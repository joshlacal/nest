//! Axum extractor for XRPC query parameters decoded by Petrel.
//!
//! Petrel's generated `Parameters` types implement `FromQueryParams` rather than
//! serde, which is what `axum::extract::Query` needs. This adapter decodes the
//! request's query string and hands the pairs to the generated decoder, so
//! lexicon defaults (`limit`) and value formats (`space`, `uri`) are applied
//! exactly as the schema states.

use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use petrel_core::FromQueryParams;

use crate::AppError;

/// Query parameters of an XRPC query, decoded with Petrel.
#[derive(Debug, Clone)]
pub struct XrpcQuery<T>(pub T);

impl<T: FromQueryParams> XrpcQuery<T> {
    /// Decode a raw (still percent-encoded) query string.
    pub fn from_query_str(query: &str) -> Result<Self, AppError> {
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        T::from_query_params(&borrowed)
            .map(XrpcQuery)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid query parameters: {e}")))
    }
}

#[async_trait]
impl<T, S> FromRequestParts<S> for XrpcQuery<T>
where
    T: FromQueryParams,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Self::from_query_str(parts.uri.query().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use petrel_catbird::generated::blue::catbird::circle::get_feed::Parameters as GetFeed;
    use petrel_catbird::generated::blue::catbird::circle::get_post_thread::Parameters as GetPostThread;

    #[test]
    fn applies_lexicon_defaults_and_decodes_percent_encoding() {
        let XrpcQuery(q) = XrpcQuery::<GetFeed>::from_query_str(
            "space=at%3Aspace%2Fdid%3Aplc%3Aowner%2Fblue.catbird.circle%2Fc1&includeEncrypted=true",
        )
        .unwrap();
        assert_eq!(q.limit, 50);
        assert_eq!(
            q.space.as_ref().map(|s| s.as_str()),
            Some("at:space/did:plc:owner/blue.catbird.circle/c1")
        );
        assert_eq!(q.include_encrypted, Some(true));

        let XrpcQuery(q) = XrpcQuery::<GetFeed>::from_query_str("").unwrap();
        assert_eq!(q.limit, 50);
        assert!(q.space.is_none());
    }

    #[test]
    fn malformed_values_and_missing_required_params_are_invalid_requests() {
        for raw in ["limit=ten", "includeEncrypted=yes", "space=not-a-space"] {
            assert!(
                matches!(
                    XrpcQuery::<GetFeed>::from_query_str(raw),
                    Err(AppError::InvalidRequest(_))
                ),
                "{raw}"
            );
        }
        assert!(matches!(
            XrpcQuery::<GetPostThread>::from_query_str(""),
            Err(AppError::InvalidRequest(_))
        ));
    }
}
