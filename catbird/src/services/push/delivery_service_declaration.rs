//! Strict reader for an account's public `blue.catbird.chat.declaration/self`
//! record, used to learn which delivery service the account declares when its
//! DID document has no `#atproto_mls` service entry.
//!
//! The rules are the ones `docs/mls-v2/CHAT_PROTOCOL.md` gives for declaration
//! reads ("Declaration reads first resolve...") and that mls-ds applies to the
//! same record:
//! - the PDS is the DID document's single `#atproto_pds` service with the exact
//!   type `AtprotoPersonalDataServer`;
//! - the read is a public `com.atproto.repo.getRecord` with no credentials;
//! - only a structured `RecordNotFound` answer proves the record is absent;
//! - a success body is decoded strictly: no duplicate keys, no unknown fields,
//!   the exact record URI, and every required field present and well formed.
//!
//! Anything else is reported as either malformed or unavailable, never as
//! "absent" and never as a usable delivery service.

use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use url::Url;

use crate::services::validate_pds_url;

pub const CHAT_DECLARATION_COLLECTION: &str = "blue.catbird.chat.declaration";
pub const CHAT_DECLARATION_RKEY: &str = "self";
const GET_RECORD_PATH: &str = "/xrpc/com.atproto.repo.getRecord";

/// Largest `getRecord` answer read for a declaration. A real record is a few
/// hundred bytes.
pub const MAX_DECLARATION_RESPONSE_BYTES: usize = 64 * 1024;

/// Why a declaration could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclarationError {
    /// The source answered, and what it said is not a valid declaration (or
    /// the DID document does not name a usable PDS). Retrying will not help.
    Malformed(String),
    /// The source could not be asked or did not give a usable answer. The
    /// caller may retry later.
    Unavailable(String),
}

impl fmt::Display for DeclarationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed chat declaration source: {why}"),
            Self::Unavailable(why) => write!(f, "chat declaration source unavailable: {why}"),
        }
    }
}

impl std::error::Error for DeclarationError {}

fn malformed(why: impl Into<String>) -> DeclarationError {
    DeclarationError::Malformed(why.into())
}

/// Parses JSON refusing duplicate object keys at any depth and trailing input.
/// `serde_json::Value` would silently keep the last duplicate.
fn strict_json(bytes: &[u8]) -> Result<Value, DeclarationError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = deserializer
        .deserialize_any(StrictJsonVisitor)
        .map_err(|e| malformed(format!("not strict JSON: {e}")))?;
    deserializer
        .end()
        .map_err(|_| malformed("trailing data after JSON value"))?;
    Ok(value)
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = input.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            values.insert(key, input.next_value_seed(StrictSeed)?);
        }
        Ok(Value::Object(values))
    }
}

struct StrictSeed;

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, DeclarationError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(format!("'{key}' must be a string")))
}

fn reject_unknown(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), DeclarationError> {
    match object.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(malformed(format!("unexpected field '{key}'"))),
        None => Ok(()),
    }
}

/// `did:plc:` with a 24-character base32 identifier, or `did:web:` naming a
/// bare public hostname (no port, no path).
pub fn is_supported_delivery_service_did(did: &str) -> bool {
    if !did.is_ascii() || !(12..=261).contains(&did.len()) {
        return false;
    }
    if let Some(id) = did.strip_prefix("did:plc:") {
        return id.len() == 24 && id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'));
    }
    did.strip_prefix("did:web:").is_some_and(is_public_hostname)
}

fn is_public_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let label_ok = |label: &&str| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            && bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
    };
    if !labels.iter().all(label_ok) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    tld.as_bytes()[0].is_ascii_lowercase()
        && !matches!(
            tld,
            "alt"
                | "arpa"
                | "example"
                | "internal"
                | "invalid"
                | "local"
                | "localhost"
                | "onion"
                | "test"
        )
}

fn is_canonical_cid(cid: &str) -> bool {
    (2..=128).contains(&cid.len())
        && cid.is_ascii()
        && jacquard_common::types::cid::Cid::str(cid)
            .to_ipld()
            .is_ok_and(|parsed| parsed.to_string() == cid)
}

/// Builds the public `getRecord` URL for `account_did`'s declaration from its
/// DID document.
///
/// The document must be for `account_did` and carry exactly one `#atproto_pds`
/// service (short or full DID-URL id) of type `AtprotoPersonalDataServer` whose
/// endpoint is a bare origin: no credentials, path, query or fragment. The
/// origin must also pass the gateway's outbound URL policy
/// ([`validate_pds_url`]: HTTPS only, no private or loopback destinations
/// outside debug builds).
pub fn declaration_record_url(
    did_doc_bytes: &[u8],
    account_did: &str,
) -> Result<Url, DeclarationError> {
    let value = strict_json(did_doc_bytes)?;
    let root = value
        .as_object()
        .ok_or_else(|| malformed("DID document is not an object"))?;
    if required_string(root, "id")? != account_did {
        return Err(malformed("DID document id does not match the account"));
    }
    let services = match root.get("service") {
        Some(Value::Array(services)) => services.as_slice(),
        None => &[],
        Some(_) => return Err(malformed("DID document 'service' is not an array")),
    };
    let full_id = format!("{account_did}#atproto_pds");
    let mut endpoint: Option<&str> = None;
    for service in services {
        let service = service
            .as_object()
            .ok_or_else(|| malformed("DID document service entry is not an object"))?;
        let id = required_string(service, "id")?;
        if id != "#atproto_pds" && id != full_id {
            continue;
        }
        if endpoint.is_some() {
            return Err(malformed("DID document has more than one #atproto_pds"));
        }
        if required_string(service, "type")? != "AtprotoPersonalDataServer" {
            return Err(malformed("#atproto_pds has the wrong service type"));
        }
        endpoint = Some(required_string(service, "serviceEndpoint")?);
    }
    let endpoint = endpoint.ok_or_else(|| malformed("DID document has no #atproto_pds"))?;

    let origin =
        Url::parse(endpoint).map_err(|_| malformed("#atproto_pds endpoint is not a URL"))?;
    if !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.path() != "/"
        || origin.host_str().is_none()
    {
        return Err(malformed("#atproto_pds endpoint is not a bare origin"));
    }
    validate_pds_url(origin.as_str())
        .map_err(|_| malformed("#atproto_pds endpoint is not an allowed destination"))?;

    let mut url = origin;
    url.set_path(GET_RECORD_PATH);
    url.query_pairs_mut()
        .append_pair("repo", account_did)
        .append_pair("collection", CHAT_DECLARATION_COLLECTION)
        .append_pair("rkey", CHAT_DECLARATION_RKEY);
    Ok(url)
}

/// Decodes a `getRecord` answer for `account_did`'s declaration.
///
/// - `Ok(Some(did))`: a valid declaration naming delivery service `did`.
/// - `Ok(None)`: the PDS answered with a structured `RecordNotFound`; the
///   account has no declaration.
/// - `Err(Malformed)`: a 200 answer that is not a valid declaration for this
///   account.
/// - `Err(Unavailable)`: any other status, or a 400/404 that is not exactly
///   `RecordNotFound` (an HTML error page, an unknown repo, a rate limit).
pub fn parse_declaration_response(
    account_did: &str,
    status: u16,
    body: &[u8],
) -> Result<Option<String>, DeclarationError> {
    if status != 200 {
        return record_not_found(status, body).map(|()| None);
    }
    let value = strict_json(body)?;
    let root = value
        .as_object()
        .ok_or_else(|| malformed("getRecord answer is not an object"))?;
    reject_unknown(root, &["uri", "cid", "value"])?;
    let expected_uri =
        format!("at://{account_did}/{CHAT_DECLARATION_COLLECTION}/{CHAT_DECLARATION_RKEY}");
    if required_string(root, "uri")? != expected_uri {
        return Err(malformed("getRecord answered for a different record"));
    }
    if let Some(cid) = root.get("cid") {
        if !cid.as_str().is_some_and(is_canonical_cid) {
            return Err(malformed("'cid' is not a valid CID"));
        }
    }
    let record = root
        .get("value")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("'value' must be an object"))?;
    reject_unknown(
        record,
        &[
            "$type",
            "allowIncoming",
            "deliveryService",
            "protocolVersion",
            "createdAt",
        ],
    )?;
    if required_string(record, "$type")? != CHAT_DECLARATION_COLLECTION {
        return Err(malformed("record has the wrong $type"));
    }
    if !matches!(
        required_string(record, "allowIncoming")?,
        "all" | "none" | "following"
    ) {
        return Err(malformed("'allowIncoming' is not a known policy"));
    }
    if !matches!(required_string(record, "protocolVersion")?, "1" | "2") {
        return Err(malformed("'protocolVersion' is not supported"));
    }
    if chrono::DateTime::parse_from_rfc3339(required_string(record, "createdAt")?).is_err() {
        return Err(malformed("'createdAt' is not an RFC 3339 timestamp"));
    }
    let delivery_service = required_string(record, "deliveryService")?;
    if !is_supported_delivery_service_did(delivery_service) {
        return Err(malformed("'deliveryService' is not a supported DID"));
    }
    Ok(Some(delivery_service.to_owned()))
}

/// A non-200 answer means "no record" only when it is exactly the PDS's typed
/// `RecordNotFound`. Every other non-200 answer is a source that could not
/// answer.
fn record_not_found(status: u16, body: &[u8]) -> Result<(), DeclarationError> {
    let unavailable = || DeclarationError::Unavailable(format!("getRecord answered HTTP {status}"));
    if status != 400 && status != 404 {
        return Err(unavailable());
    }
    let value = strict_json(body).map_err(|_| unavailable())?;
    let root = value.as_object().ok_or_else(unavailable)?;
    let only_known_fields = root.keys().all(|key| key == "error" || key == "message");
    let message_ok = root.get("message").is_none_or(Value::is_string);
    let is_record_not_found = root.get("error").and_then(Value::as_str) == Some("RecordNotFound");
    if only_known_fields && message_ok && is_record_not_found {
        Ok(())
    } else {
        Err(unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ACCOUNT: &str = "did:plc:simjzkp2kphgi6zutwqxhyzm";
    const CID: &str = "bafyreieuuyuwepk4j7aqlkkxmzfw3g7fomuet72brmcewpnzh4o6dz2coq";

    fn record() -> Value {
        json!({
            "$type": "blue.catbird.chat.declaration",
            "createdAt": "2026-09-03T08:40:20.910Z",
            "allowIncoming": "all",
            "deliveryService": "did:web:chat.catbird.blue",
            "protocolVersion": "2",
        })
    }

    fn answer(value: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "uri": format!("at://{ACCOUNT}/blue.catbird.chat.declaration/self"),
            "cid": CID,
            "value": value,
        }))
        .unwrap()
    }

    fn parse(status: u16, body: &[u8]) -> Result<Option<String>, DeclarationError> {
        parse_declaration_response(ACCOUNT, status, body)
    }

    fn assert_malformed(body: &[u8]) {
        assert!(
            matches!(parse(200, body), Err(DeclarationError::Malformed(_))),
            "expected Malformed for {}",
            String::from_utf8_lossy(body)
        );
    }

    #[test]
    fn a_production_shaped_declaration_yields_its_delivery_service() {
        // Byte-for-byte the shape the two affected production accounts serve
        // (protocol versions "1" and "2", `cid` before or after `uri`).
        let v1 = format!(
            r#"{{"uri":"at://{ACCOUNT}/blue.catbird.chat.declaration/self","cid":"{CID}","value":{{"$type":"blue.catbird.chat.declaration","createdAt":"2026-09-03T08:40:20.910Z","allowIncoming":"all","deliveryService":"did:web:chat.catbird.blue","protocolVersion":"1"}}}}"#
        );
        assert_eq!(
            parse(200, v1.as_bytes()),
            Ok(Some("did:web:chat.catbird.blue".to_string()))
        );
        assert_eq!(
            parse(200, &answer(record())),
            Ok(Some("did:web:chat.catbird.blue".to_string()))
        );
    }

    #[test]
    fn cid_is_optional_but_must_be_valid_when_present() {
        let uri = format!("at://{ACCOUNT}/blue.catbird.chat.declaration/self");
        let without = serde_json::to_vec(&json!({ "uri": uri, "value": record() })).unwrap();
        assert!(parse(200, &without).unwrap().is_some());
        for bad in [json!("not-a-cid"), json!(null), json!(7)] {
            let body =
                serde_json::to_vec(&json!({ "uri": uri, "cid": bad, "value": record() })).unwrap();
            assert_malformed(&body);
        }
    }

    #[test]
    fn only_a_structured_record_not_found_proves_absence() {
        let not_found = br#"{"error":"RecordNotFound","message":"Could not locate record"}"#;
        assert_eq!(parse(400, not_found), Ok(None));
        assert_eq!(parse(404, br#"{"error":"RecordNotFound"}"#), Ok(None));

        let unavailable: &[(u16, &[u8])] = &[
            // The answer a PDS gives for a repo it does not host.
            (
                400,
                br#"{"error":"InvalidRequest","message":"Could not find repo"}"#,
            ),
            (404, b"<html>not found</html>"),
            (404, b""),
            (400, br#"{"error":"RecordNotFound","extra":true}"#),
            (400, br#"{"error":"RecordNotFound","message":7}"#),
            (400, br#"["RecordNotFound"]"#),
            // RecordNotFound under any other status is not trusted either.
            (500, br#"{"error":"RecordNotFound"}"#),
            (401, br#"{"error":"AuthRequired"}"#),
            (429, br#"{"error":"RateLimitExceeded"}"#),
            (302, b""),
            (503, b"upstream down"),
        ];
        for (status, body) in unavailable {
            assert!(
                matches!(parse(*status, body), Err(DeclarationError::Unavailable(_))),
                "HTTP {status} {} must be unavailable",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn a_success_for_another_record_is_refused() {
        for uri in [
            "at://did:plc:6u6rzv6fk3ga37kgs3tybgdk/blue.catbird.chat.declaration/self",
            "at://did:plc:simjzkp2kphgi6zutwqxhyzm/chat.bsky.actor.declaration/self",
            "at://did:plc:simjzkp2kphgi6zutwqxhyzm/blue.catbird.chat.declaration/other",
            "at://handle.example.com/blue.catbird.chat.declaration/self",
        ] {
            let body = serde_json::to_vec(&json!({ "uri": uri, "value": record() })).unwrap();
            assert_malformed(&body);
        }
        let mut wrong_type = record();
        wrong_type["$type"] = json!("chat.bsky.actor.declaration");
        assert_malformed(&answer(wrong_type));
    }

    #[test]
    fn every_required_field_must_be_present_and_well_formed() {
        for field in [
            "$type",
            "allowIncoming",
            "deliveryService",
            "protocolVersion",
            "createdAt",
        ] {
            let mut missing = record();
            missing.as_object_mut().unwrap().remove(field);
            assert_malformed(&answer(missing));

            let mut null = record();
            null[field] = Value::Null;
            assert_malformed(&answer(null));
        }
        for (field, bad) in [
            ("allowIncoming", json!("friends")),
            ("allowIncoming", json!(true)),
            ("protocolVersion", json!("3")),
            ("protocolVersion", json!(2)),
            ("createdAt", json!("yesterday")),
            ("deliveryService", json!("https://chat.catbird.blue")),
            (
                "deliveryService",
                json!("did:web:chat.catbird.blue#atproto_mls"),
            ),
            ("deliveryService", json!("did:web:localhost")),
            ("deliveryService", json!("did:web:chat.catbird.blue%3A8443")),
            ("deliveryService", json!("did:web:10.0.0.1")),
            ("deliveryService", json!("did:key:z6Mkexample")),
            ("deliveryService", json!("did:plc:TOOSHORT")),
            ("deliveryService", json!(["did:web:chat.catbird.blue"])),
        ] {
            let mut value = record();
            value[field] = bad;
            assert_malformed(&answer(value));
        }
    }

    #[test]
    fn unknown_fields_duplicate_keys_and_trailing_data_are_refused() {
        let mut extra = record();
        extra["groupInvites"] = json!("all");
        assert_malformed(&answer(extra));

        let uri = format!("at://{ACCOUNT}/blue.catbird.chat.declaration/self");
        let extra_top =
            serde_json::to_vec(&json!({ "uri": uri, "value": record(), "takedown": false }))
                .unwrap();
        assert_malformed(&extra_top);

        // Two `deliveryService` keys: a lenient parser keeps the last one.
        let duplicate = format!(
            r#"{{"uri":"{uri}","value":{{"$type":"blue.catbird.chat.declaration","createdAt":"2026-09-03T08:40:20.910Z","allowIncoming":"all","deliveryService":"did:web:chat.catbird.blue","deliveryService":"did:web:evil-ds.example.com","protocolVersion":"2"}}}}"#
        );
        assert_malformed(duplicate.as_bytes());

        let mut trailing = answer(record());
        trailing.extend_from_slice(b" {}");
        assert_malformed(&trailing);

        assert_malformed(b"[]");
        assert_malformed(b"");
        assert_malformed(br#"{"uri":"x","value":"not an object"}"#);
    }

    fn did_doc(services: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({ "id": ACCOUNT, "service": services })).unwrap()
    }

    fn pds(endpoint: &str) -> Value {
        json!({
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": endpoint,
        })
    }

    #[test]
    fn the_record_url_is_the_public_get_record_on_the_declared_pds() {
        let url = declaration_record_url(
            &did_doc(json!([pds("https://spaces-alpha.host.bsky.network")])),
            ACCOUNT,
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://spaces-alpha.host.bsky.network/xrpc/com.atproto.repo.getRecord\
             ?repo=did%3Aplc%3Asimjzkp2kphgi6zutwqxhyzm\
             &collection=blue.catbird.chat.declaration&rkey=self"
        );

        let full_id = json!([{
            "id": format!("{ACCOUNT}#atproto_pds"),
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": "https://swan.place/",
        }]);
        let url = declaration_record_url(&did_doc(full_id), ACCOUNT).unwrap();
        assert_eq!(url.host_str(), Some("swan.place"));
        assert_eq!(url.path(), "/xrpc/com.atproto.repo.getRecord");
    }

    #[test]
    fn a_did_document_without_one_usable_pds_is_refused() {
        let wrong_type = json!([{
            "id": "#atproto_pds",
            "type": "AtprotoLabeler",
            "serviceEndpoint": "https://swan.place",
        }]);
        let cases = [
            did_doc(json!([])),
            serde_json::to_vec(&json!({ "id": ACCOUNT })).unwrap(),
            did_doc(wrong_type),
            did_doc(json!([
                pds("https://a.example.com"),
                pds("https://b.example.com")
            ])),
            did_doc(json!([pds("https://user:pw@swan.place")])),
            did_doc(json!([pds("https://swan.place/xrpc")])),
            did_doc(json!([pds("https://swan.place?x=1")])),
            did_doc(json!([pds("https://swan.place#frag")])),
            did_doc(json!([pds("ftp://swan.place")])),
            did_doc(json!([pds("http://swan.place")])),
            did_doc(json!([pds("https://10.0.0.5")])),
            did_doc(json!([pds("https://169.254.169.254")])),
            did_doc(json!([pds("not a url")])),
            serde_json::to_vec(&json!({
                "id": "did:plc:6u6rzv6fk3ga37kgs3tybgdk",
                "service": [pds("https://swan.place")],
            }))
            .unwrap(),
            b"not json".to_vec(),
        ];
        for doc in cases {
            assert!(
                matches!(
                    declaration_record_url(&doc, ACCOUNT),
                    Err(DeclarationError::Malformed(_))
                ),
                "expected Malformed for {}",
                String::from_utf8_lossy(&doc)
            );
        }
    }
}
