use crate::auth::AuthenticatedUser;
use crate::config::AppState;
use crate::error::AppError;
use axum::{
    async_trait,
    extract::{Extension, FromRequestParts, State},
    http::request::Parts,
    response::Response,
};
use petrel_core::{Did, SpaceRef};

/// `blue.catbird.circle.getMedia` parameters.
///
/// `space` and `did` are decoded as the lexicon types. `cid` stays the raw string:
/// [`crate::media::get_media`] checks it only after the caller's access is verified,
/// and answers every malformed, unknown or unauthorized CID with the same 404, so a
/// syntax error must not be reported earlier or differently.
#[derive(Debug, Clone)]
pub struct MediaQuery {
    pub space: SpaceRef,
    pub did: Did,
    pub cid: String,
}

impl MediaQuery {
    /// Decode a raw (still percent-encoded) query string.
    pub fn from_query_str(query: &str) -> Result<Self, AppError> {
        let mut space = None;
        let mut did = None;
        let mut cid = None;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "space" => space = Some(value.into_owned()),
                "did" => did = Some(value.into_owned()),
                "cid" => cid = Some(value.into_owned()),
                _ => {}
            }
        }
        let missing = |name: &str| AppError::InvalidRequest(format!("Missing parameter {name}"));
        let space = crate::space_uri::parse_lenient(&space.ok_or_else(|| missing("space"))?)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid space: {e}")))?;
        let did = Did::parse(did.ok_or_else(|| missing("did"))?)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid did: {e}")))?;
        let cid = cid.ok_or_else(|| missing("cid"))?;
        Ok(Self { space, did, cid })
    }
}

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for MediaQuery {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Self::from_query_str(parts.uri.query().unwrap_or_default())
    }
}

pub async fn get_media_handler(
    Extension(user): Extension<AuthenticatedUser>,
    query: MediaQuery,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    if !crate::SUPPORTS_IMAGES {
        return Err(AppError::Forbidden(
            "Circle images are not available on this protocol profile".into(),
        ));
    }
    tracing::debug!("Handling getMedia request");
    crate::media::get_media(
        &state,
        user,
        query.space.as_str(),
        query.did.as_str(),
        &query.cid,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPACE: &str = "at%3Aspace%2Fdid%3Aplc%3Aowner%2Fblue.catbird.circle%2Fc1";

    #[test]
    fn a_malformed_cid_reaches_the_uniform_404_check() {
        let q = MediaQuery::from_query_str(&format!("space={SPACE}&did=did%3Aplc%3Abob&cid=%25"))
            .unwrap();
        assert_eq!(q.cid, "%");
        assert_eq!(q.did.as_str(), "did:plc:bob");
    }

    #[test]
    fn legacy_space_form_decodes_like_the_canonical_form() {
        let legacy = "at%3A%2F%2Fdid%3Aplc%3Aowner%2Fspace%2Fblue.catbird.circle%2Fc1";
        for space in [SPACE, legacy] {
            let q = MediaQuery::from_query_str(&format!("space={space}&did=did%3Aplc%3Abob&cid=x"))
                .unwrap();
            assert_eq!(
                q.space.as_str(),
                "at:space/did:plc:owner/blue.catbird.circle/c1"
            );
        }
    }

    #[test]
    fn missing_or_malformed_space_and_did_are_invalid_requests() {
        for raw in [
            "did=did%3Aplc%3Abob&cid=x".to_string(),
            format!("space={SPACE}&cid=x"),
            format!("space={SPACE}&did=did%3Aplc%3Abob"),
            "space=nope&did=did%3Aplc%3Abob&cid=x".to_string(),
            "space=at%3A%2F%2Fdid%3Aplc%3Aowner%2Fspace%2Fx&did=did%3Aplc%3Abob&cid=x".to_string(),
            format!("space={SPACE}&did=bob&cid=x"),
        ] {
            assert!(
                matches!(
                    MediaQuery::from_query_str(&raw),
                    Err(AppError::InvalidRequest(_))
                ),
                "{raw}"
            );
        }
    }
}
