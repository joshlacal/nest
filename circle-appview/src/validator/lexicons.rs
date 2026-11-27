//! Runtime lexicon validation of indexed records, through `petrel_lexicon`.
//!
//! The catalog is Petrel's bundled core corpus (which holds `app.bsky.*`) plus the
//! Catbird overlay schemas a Circle record names. petrel-catbird does not bundle
//! its lexicon documents, so the overlay files are compiled in from the sibling
//! `PetrelCatbird/lexicons` checkout that also provides the generated types.

use std::sync::OnceLock;

use petrel_lexicon::{LexiconCatalog, LexiconSchemaOptions, LexiconValidationOptions};

use super::InvalidRecord;

const OVERLAY_LEXICONS: &[&str] = &[
    include_str!(
        "../../../../PetrelCatbird/lexicons/blue/catbird/circle/blue.catbird.circle.key.json"
    ),
    include_str!(
        "../../../../PetrelCatbird/lexicons/blue/catbird/circle/blue.catbird.circle.post.json"
    ),
    include_str!("../../../../PetrelCatbird/lexicons/blue/catbird/labyrinth/blue.catbird.labyrinth.mek.json"),
    include_str!("../../../../PetrelCatbird/lexicons/blue/catbird/labyrinth/blue.catbird.labyrinth.defs.json"),
];

fn catalog() -> Result<&'static LexiconCatalog, String> {
    static CATALOG: OnceLock<Result<LexiconCatalog, String>> = OnceLock::new();
    CATALOG
        .get_or_init(|| {
            let mut catalog = LexiconCatalog::bundled()
                .map_err(|e| e.to_string())?
                .clone();
            for raw in OVERLAY_LEXICONS {
                catalog
                    .add_json(raw.as_bytes(), LexiconSchemaOptions::lenient())
                    .map_err(|e| e.to_string())?;
            }
            Ok(catalog)
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Validate a record against `{collection}#main`: every constraint the schema
/// states (lengths, graphemes, ranges, string formats, closed unions). The record
/// key's syntax is checked by the caller; the schema's key type (`tid`) is not
/// enforced, as it never was here.
pub fn validate_record(collection: &str, value: &serde_json::Value) -> Result<(), InvalidRecord> {
    let catalog = catalog()
        .map_err(|e| InvalidRecord::MalformedRecord(format!("Lexicon catalog unavailable: {e}")))?;
    let bytes = serde_json::to_vec(value)
        .map_err(|e| InvalidRecord::MalformedRecord(format!("Invalid record JSON: {e}")))?;
    let value = petrel_core::Value::from_json_data_model(&bytes)
        .map_err(|e| InvalidRecord::MalformedRecord(format!("Invalid IPLD/JSON format: {e}")))?;
    catalog
        .validate_record_value(
            collection,
            &value,
            None,
            LexiconValidationOptions::standard(),
        )
        .map_err(|e| {
            InvalidRecord::MalformedRecord(format!(
                "Lexicon validation failed for {collection}: {e}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_schemas_load_beside_the_bundled_corpus() {
        let catalog = catalog().expect("catalog builds");
        for nsid in [
            "app.bsky.feed.post",
            "app.bsky.feed.like",
            "blue.catbird.circle.key",
            "blue.catbird.circle.post",
            "blue.catbird.labyrinth.mek",
        ] {
            assert!(catalog.document(nsid).is_some(), "{nsid}");
        }
    }

    #[test]
    fn post_constraints_are_enforced() {
        let ok = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hello",
            "createdAt": "2026-08-24T12:00:00.000Z"
        });
        validate_record("app.bsky.feed.post", &ok).unwrap();

        let too_long = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "a".repeat(3001),
            "createdAt": "2026-08-24T12:00:00.000Z"
        });
        assert!(validate_record("app.bsky.feed.post", &too_long).is_err());

        let bad_date = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hello",
            "createdAt": "yesterday"
        });
        assert!(validate_record("app.bsky.feed.post", &bad_date).is_err());
    }
}
