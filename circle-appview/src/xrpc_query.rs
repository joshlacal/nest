//! Axum extractor for XRPC query parameters decoded by Petrel.
//!
//! Petrel's generated `Parameters` types implement `FromQueryParams` rather than
//! serde, which is what `axum::extract::Query` needs. This adapter decodes the
//! request's query string and hands the pairs to the generated decoder, so
//! lexicon defaults (`limit`) and value formats (`space`, `uri`) are applied
//! exactly as the schema states.
//!
//! Parameters whose lexicon type is a space reference are listed per query in
//! [`SpaceRefParams`]; their spaces-alpha form (`at://{did}/space/...`) is rewritten
//! to `at:space/...` before the typed decode, so older clients keep working while
//! malformed values are still rejected.

use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use petrel_core::FromQueryParams;

use crate::AppError;

/// The query parameters whose lexicon type is a space reference.
///
/// Implemented here for each generated `Parameters` type this service decodes, so the
/// legacy rewrite in [`XrpcQuery::from_query_str`] touches only those parameters.
pub trait SpaceRefParams {
    const SPACE_REF_PARAMS: &'static [&'static str];
}

mod space_ref_params {
    use super::SpaceRefParams;
    use petrel_catbird::generated::blue::catbird::circle::{
        get_feed, get_keys, get_post_thread, list_circles, list_notifications,
    };

    impl SpaceRefParams for get_feed::Parameters {
        const SPACE_REF_PARAMS: &'static [&'static str] = &["space"];
    }
    impl SpaceRefParams for get_post_thread::Parameters {
        const SPACE_REF_PARAMS: &'static [&'static str] = &["space"];
    }
    impl SpaceRefParams for get_keys::Parameters {
        const SPACE_REF_PARAMS: &'static [&'static str] = &["space"];
    }
    impl SpaceRefParams for list_circles::Parameters {
        const SPACE_REF_PARAMS: &'static [&'static str] = &[];
    }
    impl SpaceRefParams for list_notifications::Parameters {
        const SPACE_REF_PARAMS: &'static [&'static str] = &[];
    }
}

/// Query parameters of an XRPC query, decoded with Petrel.
#[derive(Debug, Clone)]
pub struct XrpcQuery<T>(pub T);

impl<T: FromQueryParams + SpaceRefParams> XrpcQuery<T> {
    /// Decode a raw (still percent-encoded) query string.
    pub fn from_query_str(query: &str) -> Result<Self, AppError> {
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| {
                let v = if T::SPACE_REF_PARAMS.contains(&k.as_ref()) {
                    crate::space_uri::normalize_legacy(&v).into_owned()
                } else {
                    v.into_owned()
                };
                (k.into_owned(), v)
            })
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
    T: FromQueryParams + SpaceRefParams,
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
    use petrel_catbird::generated::blue::catbird::circle::get_keys::Parameters as GetKeys;
    use petrel_catbird::generated::blue::catbird::circle::get_post_thread::Parameters as GetPostThread;

    const CANONICAL: &str = "at:space/did:plc:owner/blue.catbird.circle/c1";
    const LEGACY: &str = "at://did:plc:owner/space/blue.catbird.circle/c1";

    fn enc(v: &str) -> String {
        url::form_urlencoded::byte_serialize(v.as_bytes()).collect()
    }

    #[test]
    fn legacy_and_canonical_space_params_decode_identically() {
        let uri =
            "at:space/did:plc:owner/blue.catbird.circle/c1/did:plc:bob/app.bsky.feed.post/3k2";
        for space in [CANONICAL, LEGACY] {
            let XrpcQuery(q) =
                XrpcQuery::<GetFeed>::from_query_str(&format!("space={}", enc(space))).unwrap();
            assert_eq!(q.space.as_ref().map(|s| s.as_str()), Some(CANONICAL));

            let XrpcQuery(q) =
                XrpcQuery::<GetKeys>::from_query_str(&format!("space={}", enc(space))).unwrap();
            assert_eq!(q.space.as_str(), CANONICAL);

            let XrpcQuery(q) = XrpcQuery::<GetPostThread>::from_query_str(&format!(
                "uri={}&space={}",
                enc(uri),
                enc(space)
            ))
            .unwrap();
            assert_eq!(q.space.as_str(), CANONICAL);
        }
    }

    #[test]
    fn malformed_legacy_and_garbage_space_params_are_invalid_requests() {
        for space in [
            "at://did:plc:owner/space/blue.catbird.circle",
            "at://did:plc:owner/space/",
            "at://not-a-did/space/blue.catbird.circle/c1",
            "at://did:plc:owner/blue.catbird.circle/c1",
            "garbage",
        ] {
            assert!(
                matches!(
                    XrpcQuery::<GetFeed>::from_query_str(&format!("space={}", enc(space))),
                    Err(AppError::InvalidRequest(_))
                ),
                "{space}"
            );
        }
    }

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
