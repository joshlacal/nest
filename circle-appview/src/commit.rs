//! LtHash and DAG-CBOR primitives used by the current STAR/MAC Spaces wire.

pub use petrel_spaces::{LtHash, SpaceError, LTHASH_BYTES};

use petrel_core::{dagcbor, Cid, Value};

/// Size of a persisted LtHash accumulator state.
pub const LTHASH_SIZE: usize = LTHASH_BYTES;

/// Format a record element for the LtHash accumulator: `{collection}/{rkey}/{cid}`.
pub fn format_lthash_element(collection: &str, rkey: &str, cid: &str) -> String {
    format!("{collection}/{rkey}/{cid}")
}

/// The LtHash record path of a record: `{collection}/{rkey}`.
pub fn record_path(collection: &str, rkey: &str) -> String {
    format!("{collection}/{rkey}")
}

/// Rebuild an accumulator from a persisted state, or `None` when the state is not
/// exactly [`LTHASH_SIZE`] bytes.
pub fn lthash_from_state(state: &[u8]) -> Option<LtHash> {
    let state: [u8; LTHASH_SIZE] = state.try_into().ok()?;
    Some(LtHash::from_state(state))
}

fn serialization(message: impl Into<String>) -> SpaceError {
    SpaceError::CborEncoding(message.into())
}

/// Compute a DAG-CBOR CIDv1 using the dag-cbor codec and SHA-256 multihash.
///
/// The value is read through the AT Protocol data model: `{"$link": …}` is a CID
/// link and `{"$bytes": …}` a byte string, whether it arrives as JSON or as a
/// decoded [`Value`]. Floats are refused.
pub fn compute_dagcbor_cid<T: serde::Serialize + ?Sized>(value: &T) -> Result<String, SpaceError> {
    let json = serde_json::to_value(value).map_err(|e| serialization(e.to_string()))?;
    let value = json_to_ipld(&json)?;
    Ok(cid_of_value(&value)?.to_string())
}

/// The DAG-CBOR CID of a data-model value.
pub fn cid_of_value(value: &Value) -> Result<Cid, SpaceError> {
    Ok(Cid::for_dag_cbor(&encode_dagcbor(value)?))
}

/// Canonical DAG-CBOR bytes of a data-model value (floats refused).
pub fn encode_dagcbor(value: &Value) -> Result<Vec<u8>, SpaceError> {
    dagcbor::try_encode(value).map_err(|e| serialization(e.to_string()))
}

/// Create raw CID bytes and its string form from DAG-CBOR block data.
pub fn create_cid_bytes_from_data(data: &[u8]) -> (Vec<u8>, String) {
    let cid = Cid::for_dag_cbor(data);
    (cid.as_bytes().to_vec(), cid.to_string())
}

fn reject_json_floats(value: &serde_json::Value) -> Result<(), SpaceError> {
    match value {
        serde_json::Value::Number(number) if !number.is_i64() && !number.is_u64() => {
            return Err(serialization(
                "Floating point numbers are forbidden in IPLD/AT Protocol",
            ));
        }
        serde_json::Value::Array(values) => {
            for value in values {
                reject_json_floats(value)?;
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                reject_json_floats(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Convert JSON to the AT Protocol data model, rejecting values it cannot encode.
pub fn json_to_ipld(value: &serde_json::Value) -> Result<Value, SpaceError> {
    reject_json_floats(value)?;
    let bytes = serde_json::to_vec(value).map_err(|e| serialization(e.to_string()))?;
    Value::from_json_data_model(&bytes)
        .map_err(|e| serialization(format!("Invalid IPLD/JSON format: {e}")))
}

/// Record fixture input for current STAR transport tests.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepoRecord {
    pub collection: String,
    pub rkey: String,
    pub cid: String,
    pub value: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_links_and_bytes_encode_as_data_model_values() {
        let cid = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
        let value = json_to_ipld(&serde_json::json!({
            "ref": {"$link": cid},
            "raw": {"$bytes": "AQID"},
        }))
        .unwrap();
        let Value::Object(map) = &value else {
            panic!("object expected");
        };
        assert!(matches!(map.get("ref"), Some(Value::Link(_))));
        assert_eq!(map.get("raw"), Some(&Value::Bytes(vec![1, 2, 3])));
        // A Value and its JSON form hash to the same CID.
        assert_eq!(
            compute_dagcbor_cid(&value).unwrap(),
            cid_of_value(&value).unwrap().to_string()
        );
    }

    #[test]
    fn floats_are_refused() {
        assert!(json_to_ipld(&serde_json::json!({"a": 1.5})).is_err());
        assert!(json_to_ipld(&serde_json::json!({"a": 1.0})).is_err());
        assert!(compute_dagcbor_cid(&serde_json::json!([0.5])).is_err());
    }

    #[test]
    fn cid_bytes_and_string_agree() {
        let block =
            encode_dagcbor(&json_to_ipld(&serde_json::json!({"text": "hi"})).unwrap()).unwrap();
        let (bytes, text) = create_cid_bytes_from_data(&block);
        assert_eq!(Cid::parse(&text).unwrap().as_bytes(), bytes.as_slice());
        assert!(text.starts_with("bafyrei"));
    }

    #[test]
    fn lthash_state_round_trips_and_rejects_wrong_length() {
        let mut hash = LtHash::default();
        hash.add_entry(&record_path("app.bsky.feed.post", "3k2"), "bafyreia");
        let restored = lthash_from_state(hash.state()).unwrap();
        assert_eq!(restored, hash);
        assert!(lthash_from_state(&[0u8; 32]).is_none());
    }
}
