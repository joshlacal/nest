//! Space references (`at:space/{spaceDid}/{spaceType}/{skey}`), parsed with Petrel.
//!
//! `at:space/` is the canonical form. Values read back from storage or sent by a
//! peer still on the spaces alpha (`at://{spaceDid}/space/{type}/{skey}`) are
//! rewritten to it before parsing; nothing this service writes uses the old form.

use petrel_core::{AtUri, Did, Nsid, RecordKey, SpaceRef, SyntaxError};

/// Parse a space reference, rewriting the spaces alpha form to `at:space/`.
pub fn parse_lenient(raw: &str) -> Result<SpaceRef, SyntaxError> {
    match AtUri::from_legacy_space_uri(raw) {
        Some(current) => SpaceRef::parse(current),
        None => SpaceRef::parse(raw),
    }
}

/// Parse a space reference in its canonical `at:space/` form only.
pub fn parse_strict(raw: &str) -> Result<SpaceRef, SyntaxError> {
    SpaceRef::parse(raw)
}

/// The URI of a record inside `space`, or `None` when the author, collection or
/// record key is not valid syntax.
pub fn record_uri(space: &SpaceRef, author: &str, collection: &str, rkey: &str) -> Option<String> {
    let author = Did::parse(author).ok()?;
    let collection = Nsid::parse(collection).ok()?;
    let rkey = RecordKey::parse(rkey).ok()?;
    space
        .record_uri(&author, &collection, &rkey)
        .ok()
        .map(|uri| uri.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_parses_in_both_modes() {
        let raw = "at:space/did:plc:owner/blue.catbird.circle/3l7skey";
        for parsed in [parse_lenient(raw).unwrap(), parse_strict(raw).unwrap()] {
            assert_eq!(parsed.as_str(), raw);
            assert_eq!(parsed.space_did().as_str(), "did:plc:owner");
            assert_eq!(parsed.space_type().as_str(), "blue.catbird.circle");
            assert_eq!(parsed.skey().as_str(), "3l7skey");
        }
    }

    #[test]
    fn alpha_form_is_rewritten_only_by_the_lenient_parser() {
        let raw = "at://did:plc:owner/space/blue.catbird.circle/3l7skey";
        assert_eq!(
            parse_lenient(raw).unwrap().as_str(),
            "at:space/did:plc:owner/blue.catbird.circle/3l7skey"
        );
        assert!(parse_strict(raw).is_err());
    }

    #[test]
    fn record_uri_appends_author_collection_and_key() {
        let space = parse_strict("at:space/did:plc:owner/blue.catbird.circle/c1").unwrap();
        assert_eq!(
            record_uri(&space, "did:plc:bob", "app.bsky.feed.post", "3k2").as_deref(),
            Some(
                "at:space/did:plc:owner/blue.catbird.circle/c1/did:plc:bob/app.bsky.feed.post/3k2"
            )
        );
        assert_eq!(record_uri(&space, "bob", "app.bsky.feed.post", "3k2"), None);
    }

    #[test]
    fn record_uris_and_garbage_are_not_space_refs() {
        for raw in [
            "at:space/did:plc:owner/blue.catbird.circle/c1/did:plc:bob/app.bsky.feed.post/3k2",
            "at://did:plc:bob/app.bsky.feed.post/3k2",
            "at:space/not-a-did/blue.catbird.circle/c1",
            "",
        ] {
            assert!(parse_lenient(raw).is_err(), "{raw}");
        }
    }
}
