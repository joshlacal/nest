//! Validation of encrypted-Circle records: `blue.catbird.circle.key` (owner-authored content
//! keys with padded recipient lists) and `blue.catbird.circle.post` (ciphertext envelopes).
//! Dispatched from [`super::validate_record`].
use super::{
    created_at_utc, decode_strict, lexicons, resolve_reply, InvalidRecord, RecordCandidate,
    ValidatedRecord, ValidationPolicy,
};

/// Recipient-list sizes a `blue.catbird.circle.key` record may carry (padding buckets).
const KEY_RECIPIENT_BUCKETS: [usize; 7] = [8, 16, 32, 64, 128, 256, 512];
/// Length of a Hawk wrap of a 32-byte content key, derived from
/// `labyrinth/src/hpke/hawk.rs`: `HEADER_LEN` (1 version byte + 32 X25519 share + 1088
/// ML-KEM-768 ciphertext) + 32 payload bytes + `TAG_LEN` 16 (AES-256-GCM, zero nonce
/// that is not transmitted).
const HAWK_WRAP_32_LEN: usize = 1 + 32 + 1088 + 32 + 16;
/// Unpadded base64 length of a [`HAWK_WRAP_32_LEN`]-byte wrap.
const HAWK_WRAP_32_B64_LEN: usize = (HAWK_WRAP_32_LEN * 4).div_ceil(3);
const POST_CIPHERTEXT_MAX: usize = 65_536;
const ATTACHMENT_MIME: &str = "application/octet-stream";
const REPLY_FIELDS: [&str; 3] = ["$type", "parent", "root"];
/// The only `$type` a reply object may carry (Petrel's `ReplyRef.encode` always writes it).
const REPLY_TYPE: &str = "app.bsky.feed.post#replyRef";
const STRONG_REF_FIELDS: [&str; 3] = ["$type", "uri", "cid"];
const BLOB_FIELDS: [&str; 4] = ["$type", "ref", "mimeType", "size"];
const POST_SIG_LEN: usize = 64;
const POST_EPOCH_HEAD_LEN: usize = 32;
const POST_ATTACHMENTS_MAX: usize = 4;
/// Top-level keys an envelope may carry; anything else could smuggle plaintext content.
const ENVELOPE_FIELDS: [&str; 9] = [
    "$type",
    "circleId",
    "keyVersion",
    "createdAt",
    "reply",
    "ciphertext",
    "sig",
    "authorEpochHead",
    "attachments",
];
const SENDER_TYPE: &str = "blue.catbird.labyrinth.mek#labyrinthSender";

/// Bound the work before decoding anything: `recipients` must be a bucket-sized list of
/// `{"$bytes": <base64>}` entries, each the length of one Hawk wrap.
pub(super) fn precheck_recipients(value: &serde_json::Value) -> Result<(), InvalidRecord> {
    use base64::Engine;
    let malformed = |m: &str| InvalidRecord::MalformedRecord(format!("circle.key recipients: {m}"));
    if let Some(items) = value.get("recipients").and_then(|r| r.as_array()) {
        if !KEY_RECIPIENT_BUCKETS.contains(&items.len()) {
            return Err(InvalidRecord::RecipientCountNotBucket(items.len()));
        }
        for item in items {
            let encoded = item
                .get("$bytes")
                .and_then(|b| b.as_str())
                .ok_or_else(|| malformed("entry is not a $bytes object"))?;
            let unpadded = encoded.trim_end_matches('=').len();
            if unpadded != HAWK_WRAP_32_B64_LEN {
                return Err(InvalidRecord::BadByteLength {
                    field: "recipients",
                    got: unpadded * 3 / 4,
                });
            }
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(encoded.trim_end_matches('='))
                .map_err(|_| malformed("invalid base64"))?;
        }
    }
    Ok(())
}

fn malformed(m: impl Into<String>) -> InvalidRecord {
    InvalidRecord::MalformedRecord(m.into())
}

/// `value` is an object whose keys are all in `allowed`.
fn only_fields(
    value: &serde_json::Value,
    allowed: &[&str],
    what: &str,
) -> Result<(), InvalidRecord> {
    let obj = value
        .as_object()
        .ok_or_else(|| malformed(format!("{what} must be an object")))?;
    match obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(extra) => Err(malformed(format!("{what} carries unknown field {extra}"))),
        None => Ok(()),
    }
}

/// The record's `circleId` must be the Space's Circle when the policy knows it.
fn check_circle_id(
    candidate: &RecordCandidate,
    policy: &ValidationPolicy,
) -> Result<(), InvalidRecord> {
    match &policy.circle_id {
        Some(expected)
            if candidate.value.get("circleId").and_then(|c| c.as_str()) != Some(expected) =>
        {
            Err(InvalidRecord::CircleIdMismatch)
        }
        _ => Ok(()),
    }
}

/// Nested envelope objects are closed: `reply` holds only `parent`/`root` strong refs (and
/// optionally `$type` = `app.bsky.feed.post#replyRef`), and
/// each attachment is a bare blob of opaque bytes, so none can smuggle plaintext.
fn check_envelope_nested(value: &serde_json::Value) -> Result<(), InvalidRecord> {
    if let Some(reply) = value.get("reply") {
        only_fields(reply, &REPLY_FIELDS, "reply")?;
        if let Some(t) = reply.get("$type") {
            if t.as_str() != Some(REPLY_TYPE) {
                return Err(malformed(format!("reply $type must be {REPLY_TYPE}")));
            }
        }
        for which in ["parent", "root"] {
            if let Some(r) = reply.get(which) {
                only_fields(r, &STRONG_REF_FIELDS, "reply ref")?;
            }
        }
    }
    if let Some(items) = value.get("attachments").and_then(|a| a.as_array()) {
        for att in items {
            only_fields(att, &BLOB_FIELDS, "attachment")?;
            if let Some(r) = att.get("ref") {
                only_fields(r, &["$link"], "attachment ref")?;
            }
            if att.get("mimeType").and_then(|m| m.as_str()) != Some(ATTACHMENT_MIME) {
                return Err(malformed(format!(
                    "attachment mimeType must be {ATTACHMENT_MIME}"
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_key_record(
    candidate: &RecordCandidate,
    policy: &ValidationPolicy,
    norm_value: serde_json::Value,
) -> Result<ValidatedRecord, InvalidRecord> {
    use petrel_catbird::generated::blue::catbird::circle::key::Key;

    if !policy.is_encrypted_space() {
        return Err(InvalidRecord::EncryptedInPlaintextSpace);
    }
    if !policy.is_owner(&candidate.author_did) {
        return Err(InvalidRecord::KeyRecordAuthor);
    }
    // The on-wire sender object must carry its union tag; a record without it is not conformant.
    let sender_type = candidate
        .value
        .get("sender")
        .and_then(|s| s.get("$type"))
        .and_then(|t| t.as_str());
    if sender_type != Some(SENDER_TYPE) {
        return Err(InvalidRecord::MalformedRecord(
            "circle.key sender must carry $type labyrinthSender".into(),
        ));
    }
    let sender_did = candidate
        .value
        .get("sender")
        .and_then(|s| s.get("did"))
        .and_then(|d| d.as_str());
    if sender_did != Some(candidate.author_did.as_str()) {
        return Err(InvalidRecord::SenderNotAuthor);
    }
    check_circle_id(candidate, policy)?;
    precheck_recipients(&norm_value)?;
    let key: Key = decode_strict(&norm_value).map_err(|e| {
        InvalidRecord::MalformedRecord(format!("Invalid blue.catbird.circle.key schema: {e}"))
    })?;

    let count = key.recipients.len();
    if !KEY_RECIPIENT_BUCKETS.contains(&count) {
        return Err(InvalidRecord::RecipientCountNotBucket(count));
    }
    lexicons::validate_record(&candidate.collection, &norm_value)?;
    if let Some(bad) = key
        .recipients
        .iter()
        .find(|r| r.0.len() != HAWK_WRAP_32_LEN)
    {
        return Err(InvalidRecord::BadByteLength {
            field: "recipients",
            got: bad.0.len(),
        });
    }

    // D8 rule 2: a new key is latest+1; anything at or below latest is a rewrite.
    let latest = policy.latest_key_version.unwrap_or(0);
    if key.key_version > latest + 1 {
        return Err(InvalidRecord::KeyVersionNotMonotone {
            got: key.key_version,
            latest,
        });
    }

    Ok(ValidatedRecord {
        uri: candidate.uri.clone(),
        author_did: candidate.author_did.clone(),
        collection: candidate.collection.clone(),
        rkey: candidate.rkey.clone(),
        record_json: candidate.value.clone(),
        created_at: created_at_utc(&key.created_at)?,
        parent_uri: None,
        root_uri: None,
        post_uri: None,
        key_version: Some(key.key_version),
    })
}

pub(super) fn validate_envelope_post(
    candidate: &RecordCandidate,
    policy: &ValidationPolicy,
    norm_value: serde_json::Value,
) -> Result<ValidatedRecord, InvalidRecord> {
    use petrel_catbird::generated::blue::catbird::circle::post::Post as EnvelopePost;

    if !policy.is_encrypted_space() {
        return Err(InvalidRecord::EncryptedInPlaintextSpace);
    }
    let post: EnvelopePost = decode_strict(&norm_value).map_err(|e| {
        InvalidRecord::MalformedRecord(format!("Invalid blue.catbird.circle.post schema: {e}"))
    })?;
    if let Some(extra) = candidate
        .value
        .as_object()
        .and_then(|o| o.keys().find(|k| !ENVELOPE_FIELDS.contains(&k.as_str())))
    {
        return Err(InvalidRecord::UnknownEnvelopeField(extra.clone()));
    }
    check_envelope_nested(&candidate.value)?;
    check_circle_id(candidate, policy)?;
    // Exact byte lengths first, so an over-long field is reported as such.
    let ct_len = post.ciphertext.0.len();
    if ct_len == 0 || ct_len > POST_CIPHERTEXT_MAX {
        return Err(InvalidRecord::BadByteLength {
            field: "ciphertext",
            got: ct_len,
        });
    }
    if post.sig.0.len() != POST_SIG_LEN {
        return Err(InvalidRecord::BadByteLength {
            field: "sig",
            got: post.sig.0.len(),
        });
    }
    if post.author_epoch_head.0.len() != POST_EPOCH_HEAD_LEN {
        return Err(InvalidRecord::BadByteLength {
            field: "authorEpochHead",
            got: post.author_epoch_head.0.len(),
        });
    }
    if let Some(att) = &post.attachments {
        if att.len() > POST_ATTACHMENTS_MAX {
            return Err(InvalidRecord::BadByteLength {
                field: "attachments",
                got: att.len(),
            });
        }
    }
    lexicons::validate_record(&candidate.collection, &norm_value)?;

    if !policy.has_membership(&candidate.author_did) {
        return Err(InvalidRecord::NotMember);
    }
    match policy.latest_key_version {
        Some(latest) if post.key_version <= latest => {}
        latest => {
            return Err(InvalidRecord::KeyVersionAheadOfKeys {
                got: post.key_version,
                latest,
            });
        }
    }

    let (parent_uri, root_uri) = match &post.reply {
        Some(reply) => {
            let (p, r) = resolve_reply(candidate, policy, reply)?;
            (Some(p), Some(r))
        }
        None => {
            // Same rule as plaintext posts: top-level posts come from the Space owner.
            if !policy.is_owner(&candidate.author_did) {
                return Err(InvalidRecord::TopLevelAuthor);
            }
            (None, None)
        }
    };

    Ok(ValidatedRecord {
        uri: candidate.uri.clone(),
        author_did: candidate.author_did.clone(),
        collection: candidate.collection.clone(),
        rkey: candidate.rkey.clone(),
        record_json: candidate.value.clone(),
        created_at: created_at_utc(&post.created_at)?,
        parent_uri,
        root_uri,
        post_uri: None,
        key_version: Some(post.key_version),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::{validate_record, RecordCandidate, ValidationPolicy};
    use base64::Engine;
    use serde_json::{json, Value};

    const OWNER: &str = "did:plc:owner";
    const MEMBER: &str = "did:plc:member";
    const SPACE: &str = "ats://did:plc:owner/blue.catbird.circle.encrypted/3kaaaaaaaaaa2";
    const ENC: &str = "blue.catbird.circle.encrypted";
    const KEY: &str = "blue.catbird.circle.key";
    const POST: &str = "blue.catbird.circle.post";
    const TID: &str = "3jzfcijpj2z2a";
    const NOW: &str = "2026-11-07T00:00:00.000Z";
    /// Hawk wrap of a 32-byte plaintext: 1 + 32 + 1088 header, 32 body, 16 tag.
    const WRAP_LEN: usize = 1 + 32 + 1088 + 32 + 16;

    fn b64(n: usize) -> Value {
        let bytes = vec![7u8; n];
        json!({"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)})
    }

    fn enc_policy(latest: Option<i64>) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(OWNER, [MEMBER]).with_space_uri(SPACE);
        p.space_type = ENC.to_string();
        p.latest_key_version = latest;
        p
    }

    fn candidate(author: &str, collection: &str, value: Value) -> RecordCandidate {
        RecordCandidate {
            uri: format!("{SPACE}/{author}/{collection}/3kbbbbbbbbbb2"),
            author_did: author.to_string(),
            collection: collection.to_string(),
            rkey: "3kbbbbbbbbbb2".to_string(),
            value,
        }
    }

    fn sender(with_type: bool) -> Value {
        let mut s = json!({
            "did": OWNER,
            "senderEpoch": {
                "attestation": {"sig": b64(64), "transportPubkey": b64(32)},
                "authPubkey": b64(32),
                "encryptionPubkey": b64(1216),
                "epochHead": b64(32),
                "epochNumber": 0,
                "membersHash": b64(32),
                "selfSig": b64(64),
                "signingPubkey": b64(32),
            },
            "senderEpochHead": b64(32),
        });
        if with_type {
            s["$type"] = json!("blue.catbird.labyrinth.mek#labyrinthSender");
        }
        s
    }

    fn key_json(kv: i64, recipients: Vec<usize>, with_type: bool) -> Value {
        let recips: Vec<Value> = recipients.into_iter().map(b64).collect();
        json!({
            "$type": KEY,
            "circleId": TID,
            "createdAt": NOW,
            "keyVersion": kv,
            "reason": "created",
            "recipients": recips,
            "sender": sender(with_type),
        })
    }

    fn key_with(kv: i64, n: usize) -> Value {
        key_json(kv, vec![WRAP_LEN; n], true)
    }

    fn post_json(kv: i64) -> Value {
        json!({
            "$type": POST,
            "circleId": TID,
            "createdAt": NOW,
            "keyVersion": kv,
            "ciphertext": b64(100),
            "sig": b64(64),
            "authorEpochHead": b64(32),
        })
    }

    fn parent_uri() -> String {
        format!("at://{OWNER}/{POST}/3kcccccccccc2")
    }

    fn reply_post(kv: i64, cid: &str) -> Value {
        let mut v = post_json(kv);
        let r = json!({"uri": parent_uri(), "cid": cid});
        v["reply"] = json!({"parent": r, "root": r});
        v
    }

    const CID: &str = "bafyreibwlkyyazofc4z5vkwlz7vxx3n6pwmv3sbq4yqm4nbf6x7kk3ef4a";
    /// Blob refs are raw-codec CIDs (the only form a PDS issues; Petrel rejects others).
    const BLOB_CID: &str = "bafkreihuhrvkw25tq7bote4itvajpmwnz6zeswnrntz6gb4fa4x4mtntvm";

    #[test]
    fn encrypted_space_rejects_plaintext_post() {
        let v = json!({"$type": "app.bsky.feed.post", "text": "hi", "createdAt": NOW});
        let err = validate_record(
            &candidate(OWNER, "app.bsky.feed.post", v),
            &enc_policy(Some(1)),
        );
        assert_eq!(err.unwrap_err(), InvalidRecord::PlaintextInEncryptedSpace);
    }

    #[test]
    fn plaintext_space_rejects_envelope() {
        let p = ValidationPolicy::new(OWNER, [MEMBER]).with_space_uri(SPACE);
        let e = validate_record(&candidate(OWNER, POST, post_json(1)), &p).unwrap_err();
        assert_eq!(e, InvalidRecord::EncryptedInPlaintextSpace);
        let e = validate_record(&candidate(OWNER, KEY, key_with(1, 8)), &p).unwrap_err();
        assert_eq!(e, InvalidRecord::EncryptedInPlaintextSpace);
    }

    #[test]
    fn key_record_must_be_owner() {
        let p = enc_policy(None);
        let ok = validate_record(&candidate(OWNER, KEY, key_with(1, 8)), &p).unwrap();
        assert_eq!(ok.key_version, Some(1));
        let e = validate_record(&candidate(MEMBER, KEY, key_with(1, 8)), &p).unwrap_err();
        assert_eq!(e, InvalidRecord::KeyRecordAuthor);
    }

    #[test]
    fn key_record_sender_without_type_is_rejected() {
        let v = key_json(1, vec![WRAP_LEN; 8], false);
        let e = validate_record(&candidate(OWNER, KEY, v), &enc_policy(None)).unwrap_err();
        assert!(matches!(e, InvalidRecord::MalformedRecord(_)), "{e:?}");
    }

    #[test]
    fn key_record_bucket_sizes() {
        let p = enc_policy(None);
        for n in [8usize, 16, 32, 64, 128, 256, 512] {
            validate_record(&candidate(OWNER, KEY, key_with(1, n)), &p)
                .unwrap_or_else(|e| panic!("{n}: {e:?}"));
        }
        let e = validate_record(&candidate(OWNER, KEY, key_with(1, 9)), &p).unwrap_err();
        assert_eq!(e, InvalidRecord::RecipientCountNotBucket(9));
    }

    #[test]
    fn key_record_recipient_lengths_enforced() {
        let p = enc_policy(None);
        let mut lens = vec![WRAP_LEN; 8];
        lens[3] = WRAP_LEN + 1;
        let e = validate_record(&candidate(OWNER, KEY, key_json(1, lens, true)), &p).unwrap_err();
        assert_eq!(
            e,
            InvalidRecord::BadByteLength {
                field: "recipients",
                got: WRAP_LEN + 1
            }
        );
        let e = validate_record(&candidate(OWNER, KEY, key_json(1, vec![100; 8], true)), &p)
            .unwrap_err();
        assert_eq!(
            e,
            InvalidRecord::BadByteLength {
                field: "recipients",
                got: 100
            }
        );
    }

    #[test]
    fn key_version_monotone() {
        let p = enc_policy(Some(2));
        assert!(validate_record(&candidate(OWNER, KEY, key_with(3, 8)), &p).is_ok());
        assert!(validate_record(&candidate(OWNER, KEY, key_with(2, 8)), &p).is_ok());
        let e = validate_record(&candidate(OWNER, KEY, key_with(5, 8)), &p).unwrap_err();
        assert_eq!(
            e,
            InvalidRecord::KeyVersionNotMonotone { got: 5, latest: 2 }
        );
    }

    #[test]
    fn envelope_reply_threads_like_plaintext() {
        // Known posts are keyed by the space form; the client sends the standard form.
        let space_form = crate::validator::to_space_form(&parent_uri(), SPACE);
        assert_eq!(space_form, format!("{SPACE}/{OWNER}/{POST}/3kcccccccccc2"));
        let mut p = enc_policy(Some(1));
        p.add_post(space_form.clone(), CID);
        let v = validate_record(&candidate(MEMBER, POST, reply_post(1, CID)), &p).unwrap();
        assert_eq!(v.parent_uri.as_deref(), Some(space_form.as_str()));
        assert_eq!(v.root_uri.as_deref(), Some(space_form.as_str()));
        assert_eq!(v.key_version, Some(1));
        let unknown = enc_policy(Some(1));
        let e =
            validate_record(&candidate(MEMBER, POST, reply_post(1, CID)), &unknown).unwrap_err();
        assert_eq!(e, InvalidRecord::CrossSpaceReference);
    }

    #[test]
    fn envelope_top_level_post_and_membership() {
        let p = enc_policy(Some(1));
        let ok = validate_record(&candidate(OWNER, POST, post_json(1)), &p).unwrap();
        assert_eq!(ok.parent_uri, None);
        let e = validate_record(&candidate(MEMBER, POST, post_json(1)), &p).unwrap_err();
        assert_eq!(e, InvalidRecord::TopLevelAuthor);
        let e = validate_record(&candidate("did:plc:stranger", POST, reply_post(1, CID)), &p)
            .unwrap_err();
        assert_eq!(e, InvalidRecord::NotMember);
    }

    #[test]
    fn envelope_ahead_of_keys_rejected() {
        let e = validate_record(&candidate(OWNER, POST, post_json(3)), &enc_policy(Some(2)))
            .unwrap_err();
        assert_eq!(
            e,
            InvalidRecord::KeyVersionAheadOfKeys {
                got: 3,
                latest: Some(2)
            }
        );
        let e =
            validate_record(&candidate(OWNER, POST, post_json(1)), &enc_policy(None)).unwrap_err();
        assert_eq!(
            e,
            InvalidRecord::KeyVersionAheadOfKeys {
                got: 1,
                latest: None
            }
        );
        assert!(
            validate_record(&candidate(OWNER, POST, post_json(2)), &enc_policy(Some(2))).is_ok()
        );
    }

    #[test]
    fn envelope_byte_lengths_enforced() {
        let p = enc_policy(Some(1));
        let check = |field: &'static str, n: usize, got: usize| {
            let mut v = post_json(1);
            v[match field {
                "ciphertext" => "ciphertext",
                "sig" => "sig",
                _ => "authorEpochHead",
            }] = b64(n);
            let e = validate_record(&candidate(OWNER, POST, v), &p).unwrap_err();
            assert_eq!(e, InvalidRecord::BadByteLength { field, got });
        };
        check("ciphertext", 0, 0);
        check("ciphertext", 65537, 65537);
        check("sig", 63, 63);
        check("sig", 65, 65);
        check("authorEpochHead", 31, 31);
        let mut v = post_json(1);
        v["ciphertext"] = b64(65536);
        assert!(validate_record(&candidate(OWNER, POST, v), &p).is_ok());
    }

    #[test]
    fn envelope_with_unknown_top_level_field_rejected() {
        let mut v = post_json(1);
        v["text"] = json!("plaintext smuggled next to the ciphertext");
        let e = validate_record(&candidate(OWNER, POST, v), &enc_policy(Some(1))).unwrap_err();
        assert_eq!(e, InvalidRecord::UnknownEnvelopeField("text".into()));
        assert_eq!(e.reason_code(), "unknown_envelope_field");
    }

    fn with_circle(mut p: ValidationPolicy) -> ValidationPolicy {
        p.circle_id = Some(TID.to_string());
        p
    }

    fn attachment(mime: &str) -> Value {
        json!({
            "$type": "blob",
            "ref": {"$link": BLOB_CID},
            "mimeType": mime,
            "size": 10,
        })
    }

    #[test]
    fn envelope_attachment_mime_must_be_octet_stream() {
        let p = enc_policy(Some(1));
        let mut v = post_json(1);
        v["attachments"] = json!([attachment("application/octet-stream")]);
        validate_record(&candidate(OWNER, POST, v.clone()), &p).unwrap();
        v["attachments"] = json!([attachment("image/png")]);
        let e = validate_record(&candidate(OWNER, POST, v), &p).unwrap_err();
        assert!(matches!(e, InvalidRecord::MalformedRecord(_)), "{e:?}");
    }

    #[test]
    fn envelope_attachment_unknown_fields_rejected() {
        let p = enc_policy(Some(1));
        let mut att = attachment("application/octet-stream");
        att["alt"] = json!("a plaintext caption");
        let mut v = post_json(1);
        v["attachments"] = json!([att]);
        let e = validate_record(&candidate(OWNER, POST, v), &p).unwrap_err();
        assert!(matches!(e, InvalidRecord::MalformedRecord(_)), "{e:?}");
        let mut att = attachment("application/octet-stream");
        att["ref"]["extra"] = json!("x");
        let mut v = post_json(1);
        v["attachments"] = json!([att]);
        let e = validate_record(&candidate(OWNER, POST, v), &p).unwrap_err();
        assert!(matches!(e, InvalidRecord::MalformedRecord(_)), "{e:?}");
    }

    #[test]
    fn envelope_reply_unknown_fields_rejected() {
        let mut p = enc_policy(Some(1));
        p.add_post(crate::validator::to_space_form(&parent_uri(), SPACE), CID);
        let mut v = reply_post(1, CID);
        v["reply"]["text"] = json!("smuggled");
        let e = validate_record(&candidate(MEMBER, POST, v), &p).unwrap_err();
        assert!(matches!(e, InvalidRecord::MalformedRecord(_)), "{e:?}");
        let mut v = reply_post(1, CID);
        v["reply"]["parent"]["text"] = json!("smuggled");
        let e = validate_record(&candidate(MEMBER, POST, v), &p).unwrap_err();
        assert!(matches!(e, InvalidRecord::MalformedRecord(_)), "{e:?}");
    }

    #[test]
    fn key_sender_did_must_be_author() {
        let mut v = key_with(1, 8);
        v["sender"]["did"] = json!(MEMBER);
        let e = validate_record(&candidate(OWNER, KEY, v), &enc_policy(None)).unwrap_err();
        assert_eq!(e, InvalidRecord::SenderNotAuthor);
    }

    #[test]
    fn circle_id_must_match_the_space() {
        let p = with_circle(enc_policy(Some(1)));
        assert!(validate_record(&candidate(OWNER, POST, post_json(1)), &p).is_ok());
        assert!(validate_record(&candidate(OWNER, KEY, key_with(1, 8)), &p).is_ok());
        let mut post = post_json(1);
        post["circleId"] = json!("3kzzzzzzzzzz2");
        let e = validate_record(&candidate(OWNER, POST, post), &p).unwrap_err();
        assert_eq!(e, InvalidRecord::CircleIdMismatch);
        let mut key = key_with(1, 8);
        key["circleId"] = json!("3kzzzzzzzzzz2");
        let e = validate_record(&candidate(OWNER, KEY, key), &p).unwrap_err();
        assert_eq!(e, InvalidRecord::CircleIdMismatch);
    }

    #[test]
    fn recipient_count_and_lengths_checked_before_decoding() {
        // Not valid base64, but the count is wrong: rejected on count, not decoding.
        let mut v = key_with(1, 8);
        v["recipients"] = json!(vec![json!({"$bytes": "!!!!"}); 9]);
        let e = validate_record(&candidate(OWNER, KEY, v), &enc_policy(None)).unwrap_err();
        assert_eq!(e, InvalidRecord::RecipientCountNotBucket(9));
        // Right count, an over-long (undecodable) string: rejected on length.
        let mut v = key_with(1, 8);
        v["recipients"][0] = json!({"$bytes": "!".repeat(4000)});
        let e = validate_record(&candidate(OWNER, KEY, v), &enc_policy(None)).unwrap_err();
        assert!(
            matches!(
                e,
                InvalidRecord::BadByteLength {
                    field: "recipients",
                    ..
                }
            ),
            "{e:?}"
        );
    }

    #[test]
    fn envelope_reply_type_tag_is_pinned() {
        let mut p = enc_policy(Some(1));
        p.add_post(crate::validator::to_space_form(&parent_uri(), SPACE), CID);
        let untyped = reply_post(1, CID);
        assert!(validate_record(&candidate(MEMBER, POST, untyped), &p).is_ok());
        // Petrel's ReplyRef.encode always tags the reply object.
        let mut typed = reply_post(1, CID);
        typed["reply"]["$type"] = json!("app.bsky.feed.post#replyRef");
        validate_record(&candidate(MEMBER, POST, typed), &p).expect("typed reply is valid");
        let mut wrong = reply_post(1, CID);
        wrong["reply"]["$type"] = json!("blue.catbird.circle.post#replyRef");
        let e = validate_record(&candidate(MEMBER, POST, wrong), &p).unwrap_err();
        assert!(matches!(e, InvalidRecord::MalformedRecord(_)), "{e:?}");
    }
}
