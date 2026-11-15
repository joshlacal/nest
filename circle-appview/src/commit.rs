//! LtHash and DAG-CBOR primitives used by the current STAR/MAC Spaces wire.

use cid::Cid as IpldCid;
use sha2::{Digest, Sha256};

pub use jacquard_repo::permissioned::{LtHash, PermissionedError};

pub const LTHASH_SIZE: usize = 2048;

/// Format a record element for the LtHash accumulator: `{collection}/{rkey}/{cid}`.
pub fn format_lthash_element(collection: &str, rkey: &str, cid: &str) -> String {
    format!("{collection}/{rkey}/{cid}")
}

/// Compute a DAG-CBOR CIDv1 using the dag-cbor codec and SHA-256 multihash.
pub fn compute_dagcbor_cid<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<String, PermissionedError> {
    let bytes = serde_ipld_dagcbor::to_vec(value)
        .map_err(|e| PermissionedError::Serialization(e.to_string()))?;
    Ok(create_cid_bytes_from_data(&bytes).1)
}

/// Create raw CID bytes and its string form from DAG-CBOR block data.
pub fn create_cid_bytes_from_data(data: &[u8]) -> (Vec<u8>, String) {
    let hash = Sha256::digest(data);
    let multihash = multihash::Multihash::wrap(0x12, &hash).expect("SHA-256 multihash length");
    let cid = IpldCid::new_v1(0x71, multihash);
    (cid.to_bytes(), cid.to_string())
}

fn reject_json_floats(value: &serde_json::Value) -> Result<(), PermissionedError> {
    match value {
        serde_json::Value::Number(number) if !number.is_i64() && !number.is_u64() => {
            return Err(PermissionedError::Serialization(
                "Floating point numbers are forbidden in IPLD/AT Protocol".into(),
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

/// Convert JSON to IPLD data, rejecting values AT Protocol cannot encode.
pub fn json_to_ipld(
    value: &serde_json::Value,
) -> Result<jacquard_common::types::value::Data<jacquard_common::SmolStr>, PermissionedError> {
    reject_json_floats(value)?;
    let data: jacquard_common::types::value::Data<jacquard_common::SmolStr> =
        serde_json::from_value(value.clone()).map_err(|e| {
            PermissionedError::Serialization(format!("Invalid IPLD/JSON format: {e}"))
        })?;

    fn reject_ipld_floats(
        value: &jacquard_common::types::value::Data<jacquard_common::SmolStr>,
    ) -> Result<(), PermissionedError> {
        use jacquard_common::types::value::Data;
        match value {
            Data::InvalidNumber(number) => Err(PermissionedError::Serialization(format!(
                "Floating point numbers are forbidden: {number}"
            ))),
            Data::Array(values) => {
                for value in values.iter() {
                    reject_ipld_floats(value)?;
                }
                Ok(())
            }
            Data::Object(values) => {
                for value in values.values() {
                    reject_ipld_floats(value)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    reject_ipld_floats(&data)?;
    Ok(data)
}

/// Record fixture input for current STAR transport tests.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepoRecord {
    pub collection: String,
    pub rkey: String,
    pub cid: String,
    pub value: serde_json::Value,
}
