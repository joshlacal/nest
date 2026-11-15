use catbird_atproto::generated::app_bsky::feed::like::Like;
use catbird_atproto::generated::app_bsky::feed::post::{Post, PostEmbed};
use catbird_atproto::jacquard_lexicon::schema::LexiconSchema;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub const PLAINTEXT_SPACE_TYPE: &str = "blue.catbird.circle";
pub const ENCRYPTED_SPACE_TYPE: &str = "blue.catbird.circle.encrypted";

mod encrypted;
use encrypted::{validate_envelope_post, validate_key_record};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum InvalidRecord {
    #[error("Only the space authority can author top-level posts")]
    TopLevelAuthor,
    #[error("Author is not a current member of the Space")]
    NotMember,
    #[error("Cross-space reference is not allowed")]
    CrossSpaceReference,
    #[error("Unsupported embed type")]
    UnsupportedEmbed,
    #[error("Unsupported collection: {0}")]
    UnsupportedCollection(String),
    #[error("Malformed record: {0}")]
    MalformedRecord(String),
    #[error("Missing parent record")]
    MissingParentRecord,
    #[error("Plaintext records are not allowed in an encrypted Circle space")]
    PlaintextInEncryptedSpace,
    #[error("Encrypted records are not allowed in a plaintext Circle space")]
    EncryptedInPlaintextSpace,
    #[error("Key records must be authored by the Space owner")]
    KeyRecordAuthor,
    #[error("Key version {got} is not monotone (latest is {latest})")]
    KeyVersionNotMonotone { got: i64, latest: i64 },
    #[error("Key record recipient count {0} is not an allowed bucket size")]
    RecipientCountNotBucket(usize),
    #[error("Post key version {got} is ahead of the latest key record ({latest:?})")]
    KeyVersionAheadOfKeys { got: i64, latest: Option<i64> },
    #[error("Field {field} has invalid byte length {got}")]
    BadByteLength { field: &'static str, got: usize },
    #[error("Envelope carries unknown top-level field {0}")]
    UnknownEnvelopeField(String),
}

impl InvalidRecord {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::TopLevelAuthor => "top_level_author",
            Self::NotMember => "not_member",
            Self::CrossSpaceReference => "cross_space_reference",
            Self::UnsupportedEmbed => "unsupported_embed",
            Self::UnsupportedCollection(_) => "unsupported_collection",
            Self::MalformedRecord(_) => "malformed_record",
            Self::MissingParentRecord => "missing_parent_record",
            Self::PlaintextInEncryptedSpace => "plaintext_in_encrypted_space",
            Self::EncryptedInPlaintextSpace => "encrypted_in_plaintext_space",
            Self::KeyRecordAuthor => "key_record_author",
            Self::KeyVersionNotMonotone { .. } => "key_version_not_monotone",
            Self::RecipientCountNotBucket(_) => "recipient_count_not_bucket",
            Self::KeyVersionAheadOfKeys { .. } => "key_version_ahead_of_keys",
            Self::BadByteLength { .. } => "bad_byte_length",
            Self::UnknownEnvelopeField(_) => "unknown_envelope_field",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidationPolicy {
    pub space_uri: String,
    pub owner_did: String,
    pub active_members: HashSet<String>,
    pub known_posts: HashMap<String, String>,
    /// Space type NSID: `blue.catbird.circle` (plaintext) or
    /// `blue.catbird.circle.encrypted` (encrypted records only).
    pub space_type: String,
    /// Highest `blue.catbird.circle.key` version stored for this Space, if any.
    pub latest_key_version: Option<i64>,
}

impl ValidationPolicy {
    pub fn new(
        owner_did: impl Into<String>,
        active_members: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let owner = owner_did.into();
        let mut members = HashSet::new();
        members.insert(owner.clone());
        for m in active_members {
            members.insert(m.into());
        }
        Self {
            space_uri: String::new(),
            owner_did: owner,
            active_members: members,
            known_posts: HashMap::new(),
            space_type: PLAINTEXT_SPACE_TYPE.to_string(),
            latest_key_version: None,
        }
    }

    pub fn with_space_type(mut self, space_type: impl Into<String>) -> Self {
        self.space_type = space_type.into();
        self
    }

    pub fn with_latest_key_version(mut self, latest: Option<i64>) -> Self {
        self.latest_key_version = latest;
        self
    }

    pub fn is_encrypted_space(&self) -> bool {
        self.space_type == ENCRYPTED_SPACE_TYPE
    }

    pub fn with_known_posts(
        mut self,
        posts: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (u, c) in posts {
            self.known_posts.insert(u.into(), c.into());
        }
        self
    }

    pub fn known_post_uris(&self) -> HashSet<String> {
        self.known_posts.keys().cloned().collect()
    }

    pub fn add_post(&mut self, uri: impl Into<String>, cid: impl Into<String>) {
        self.known_posts.insert(uri.into(), cid.into());
    }

    pub fn remove_post(&mut self, uri: &str) {
        self.known_posts.remove(uri);
    }

    pub fn with_space_uri(mut self, uri: impl Into<String>) -> Self {
        self.space_uri = uri.into();
        self
    }

    pub fn has_membership(&self, did: &str) -> bool {
        self.active_members.contains(did)
    }

    pub fn has_lease(&self, did: &str) -> bool {
        self.has_membership(did)
    }

    pub fn is_owner(&self, did: &str) -> bool {
        self.owner_did == did
    }
}

pub fn policy(
    owner_did: impl Into<String>,
    active_members: impl IntoIterator<Item = impl Into<String>>,
) -> ValidationPolicy {
    ValidationPolicy::new(owner_did, active_members)
}

pub fn active_members<'a>(members: &'a [&'a str]) -> impl IntoIterator<Item = String> + 'a {
    members.iter().map(|s| s.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordCandidate {
    pub uri: String,
    pub author_did: String,
    pub collection: String,
    pub rkey: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedRecord {
    pub uri: String,
    pub author_did: String,
    pub collection: String,
    pub rkey: String,
    pub record_json: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub parent_uri: Option<String>,
    pub root_uri: Option<String>,
    pub post_uri: Option<String>,
    /// Content-key version for encrypted records (`circle.key` / `circle.post`).
    pub key_version: Option<i64>,
}

fn normalize_uri_to_standard_aturi(uri: &str) -> String {
    if let Some(col_idx) = uri.rfind("/app.bsky.") {
        let prefix = &uri[..col_idx];
        if let Some(slash_idx) = prefix.rfind('/') {
            let did = &prefix[slash_idx + 1..];
            let rest = &uri[col_idx..];
            return format!("at://{did}{rest}");
        }
    }
    uri.to_string()
}

fn normalize_for_lexicon_deser(val: &serde_json::Value) -> serde_json::Value {
    let mut normalized = val.clone();
    if let Some(obj) = normalized.as_object_mut() {
        if let Some(reply) = obj.get_mut("reply").and_then(|r| r.as_object_mut()) {
            if let Some(parent) = reply.get_mut("parent").and_then(|p| p.as_object_mut()) {
                if let Some(serde_json::Value::String(uri)) = parent.get_mut("uri") {
                    *uri = normalize_uri_to_standard_aturi(uri);
                }
            }
            if let Some(root) = reply.get_mut("root").and_then(|r| r.as_object_mut()) {
                if let Some(serde_json::Value::String(uri)) = root.get_mut("uri") {
                    *uri = normalize_uri_to_standard_aturi(uri);
                }
            }
        }
        if let Some(subject) = obj.get_mut("subject").and_then(|s| s.as_object_mut()) {
            if let Some(serde_json::Value::String(uri)) = subject.get_mut("uri") {
                *uri = normalize_uri_to_standard_aturi(uri);
            }
        }
        if let Some(embed) = obj.get_mut("embed").and_then(|e| e.as_object_mut()) {
            if let Some(record) = embed.get_mut("record").and_then(|r| r.as_object_mut()) {
                if let Some(serde_json::Value::String(uri)) = record.get_mut("uri") {
                    *uri = normalize_uri_to_standard_aturi(uri);
                }
            }
        }
    }
    normalized
}

/// Map a standard-form `at://<did>/<collection>/<rkey>` reference (the form the AppView
/// serves and clients send back) to the stored space form
/// `<space_uri>/<did>/<collection>/<rkey>`. A URI already in this Space's form, or any
/// other shape (another Space's record, a malformed ref), is returned unchanged, so the
/// mapping is idempotent and never makes a foreign reference resolve.
pub fn to_space_form(uri: &str, space_uri: &str) -> String {
    if space_uri.is_empty() {
        return uri.to_string();
    }
    if uri
        .strip_prefix(space_uri)
        .is_some_and(|rest| rest.starts_with('/'))
    {
        return uri.to_string();
    }
    match uri.strip_prefix("at://") {
        Some(rest) if rest.split('/').count() == 3 && rest.starts_with("did:") => {
            format!("{space_uri}/{rest}")
        }
        _ => uri.to_string(),
    }
}

/// Look up a same-space reference: the space form first, then the URI as submitted.
fn known_cid<'a>(policy: &'a ValidationPolicy, space_form: &str, raw: &str) -> Option<&'a String> {
    policy
        .known_posts
        .get(space_form)
        .or_else(|| policy.known_posts.get(raw))
}

/// Resolve a reply block against the Space's known posts. Parent and root must be known
/// same-space posts with matching CIDs. Refs are mapped to the space form before lookup
/// (clients send the served standard form); returns the space-form parent and root URIs.
fn resolve_reply(
    candidate: &RecordCandidate,
    policy: &ValidationPolicy,
    reply: &catbird_atproto::generated::app_bsky::feed::post::ReplyRef,
) -> Result<(String, String), InvalidRecord> {
    let raw_uri = |which: &str, fallback: &str| {
        candidate
            .value
            .get("reply")
            .and_then(|r| r.get(which))
            .and_then(|p| p.get("uri"))
            .and_then(|u| u.as_str())
            .unwrap_or(fallback)
            .to_string()
    };
    let raw_parent_uri = raw_uri("parent", reply.parent.uri.as_ref());
    let raw_root_uri = raw_uri("root", reply.root.uri.as_ref());
    let parent_uri = to_space_form(&raw_parent_uri, &policy.space_uri);
    let root_uri = to_space_form(&raw_root_uri, &policy.space_uri);

    match (
        known_cid(policy, &parent_uri, &raw_parent_uri),
        known_cid(policy, &root_uri, &raw_root_uri),
    ) {
        (Some(expected_parent_cid), Some(expected_root_cid))
            if expected_parent_cid == reply.parent.cid.as_ref()
                && expected_root_cid == reply.root.cid.as_ref() =>
        {
            Ok((parent_uri, root_uri))
        }
        _ => Err(InvalidRecord::CrossSpaceReference),
    }
}

/// `Tid` (and other borrowed-string lexicon types) refuse `serde_json::from_value`, so
/// round-trip through text for the encrypted-record types.
pub(crate) fn from_value_borrowed<T: for<'de> Deserialize<'de>>(
    value: &serde_json::Value,
) -> Result<T, serde_json::Error> {
    let text = serde_json::to_string(value)?;
    serde_json::from_str(&text)
}

pub fn validate_record(
    candidate: &RecordCandidate,
    policy: &ValidationPolicy,
) -> Result<ValidatedRecord, InvalidRecord> {
    // Canonical RecordKey validation (Finding 28)
    if candidate
        .rkey
        .parse::<catbird_atproto::jacquard_common::types::string::Rkey>()
        .is_err()
    {
        return Err(InvalidRecord::MalformedRecord(format!(
            "Invalid RecordKey format '{}'",
            candidate.rkey
        )));
    }

    // 1. Reject any floats or malformed JSON via IPLD converter
    crate::commit::json_to_ipld(&candidate.value)
        .map_err(|e| InvalidRecord::MalformedRecord(format!("Invalid IPLD/JSON format: {e}")))?;

    // 2. Require explicit $type matching collection
    let type_val = candidate
        .value
        .get("$type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| InvalidRecord::MalformedRecord("Missing $type field in record".into()))?;
    if type_val != candidate.collection {
        return Err(InvalidRecord::MalformedRecord(format!(
            "Record $type '{type_val}' does not match collection '{}'",
            candidate.collection
        )));
    }

    let norm_value = normalize_for_lexicon_deser(&candidate.value);

    match candidate.collection.as_str() {
        "blue.catbird.circle.key" => validate_key_record(candidate, policy, norm_value),
        "blue.catbird.circle.post" => validate_envelope_post(candidate, policy, norm_value),
        "app.bsky.feed.post" => {
            if policy.is_encrypted_space() {
                return Err(InvalidRecord::PlaintextInEncryptedSpace);
            }
            // Deserialize into generated Post type (strictly validates schema, tags, and field types)
            let post: Post = serde_json::from_value(norm_value).map_err(|e| {
                InvalidRecord::MalformedRecord(format!("Invalid app.bsky.feed.post schema: {e}"))
            })?;

            // Run generated Lexicon constraint validation
            post.validate().map_err(|e| {
                InvalidRecord::MalformedRecord(format!("Lexicon validation failed for post: {e}"))
            })?;
            if let Some(labels) = &post.labels {
                labels.validate().map_err(|e| {
                    InvalidRecord::MalformedRecord(format!(
                        "Lexicon validation failed for labels: {e}"
                    ))
                })?;
                for label in &labels.values {
                    label.validate().map_err(|e| {
                        InvalidRecord::MalformedRecord(format!(
                            "Lexicon validation failed for label: {e}"
                        ))
                    })?;
                    if label.val.is_empty() || label.val.len() > 128 {
                        return Err(InvalidRecord::MalformedRecord(
                            "SelfLabel val must be 1..128 characters".into(),
                        ));
                    }
                }
            }

            if let Some(entities) = &post.entities {
                for entity in entities {
                    entity.validate().map_err(|e| {
                        InvalidRecord::MalformedRecord(format!(
                            "Lexicon validation failed for entity: {e}"
                        ))
                    })?;
                    entity.index.validate().map_err(|e| {
                        InvalidRecord::MalformedRecord(format!(
                            "Lexicon validation failed for entity index: {e}"
                        ))
                    })?;
                    if entity.index.start < 0 || entity.index.end < entity.index.start {
                        return Err(InvalidRecord::MalformedRecord(
                            "Invalid entity text slice index range".into(),
                        ));
                    }
                }
            }

            if let Some(facets) = &post.facets {
                for facet in facets {
                    facet.validate().map_err(|e| {
                        InvalidRecord::MalformedRecord(format!(
                            "Lexicon validation failed for facet: {e}"
                        ))
                    })?;
                    facet.index.validate().map_err(|e| {
                        InvalidRecord::MalformedRecord(format!(
                            "Lexicon validation failed for facet index: {e}"
                        ))
                    })?;
                    if facet.index.byte_start < 0 || facet.index.byte_end < facet.index.byte_start {
                        return Err(InvalidRecord::MalformedRecord(
                            "Invalid facet byte slice index range".into(),
                        ));
                    }
                    for feature in &facet.features {
                        match feature {
                            catbird_atproto::generated::app_bsky::richtext::facet::FacetFeaturesItem::Mention(m) => {
                                m.validate().map_err(|e| InvalidRecord::MalformedRecord(format!("Lexicon validation failed for mention: {e}")))?;
                                if let Err(e) = catbird_atproto::jacquard_common::types::did::validate_did(m.did.as_ref()) {
                                    return Err(InvalidRecord::MalformedRecord(format!("Invalid mention DID: {e}")));
                                }
                            }
                            catbird_atproto::generated::app_bsky::richtext::facet::FacetFeaturesItem::Link(l) => {
                                l.validate().map_err(|e| InvalidRecord::MalformedRecord(format!("Lexicon validation failed for link: {e}")))?;
                                if url::Url::parse(l.uri.as_ref()).is_err() {
                                    return Err(InvalidRecord::MalformedRecord(format!("Invalid link URI: {}", l.uri.as_ref())));
                                }
                            }
                            catbird_atproto::generated::app_bsky::richtext::facet::FacetFeaturesItem::Tag(t) => {
                                t.validate().map_err(|e| InvalidRecord::MalformedRecord(format!("Lexicon validation failed for tag: {e}")))?;
                                let tag_str = t.tag.as_str();
                                if tag_str.is_empty() || tag_str.len() > 640 || catbird_atproto::jacquard_common::deps::codegen::unicode_segmentation::UnicodeSegmentation::graphemes(tag_str, true).count() > 64 {
                                    return Err(InvalidRecord::MalformedRecord(format!("Invalid tag length/graphemes: {tag_str}")));
                                }
                            }
                            _ => {
                                return Err(InvalidRecord::MalformedRecord("Unrecognized or malformed facet feature".into()));
                            }
                        }
                    }
                }
            }

            if let Some(tags) = &post.tags {
                for tag in tags {
                    let tag_str = tag.as_str();
                    if tag_str.is_empty() || tag_str.len() > 640 || catbird_atproto::jacquard_common::deps::codegen::unicode_segmentation::UnicodeSegmentation::graphemes(tag_str, true).count() > 64 {
                        return Err(InvalidRecord::MalformedRecord(format!("Invalid tag item length/graphemes: {tag_str}")));
                    }
                }
            }

            // Reject quote embeds and only accept image embeds
            if let Some(embed) = &post.embed {
                match embed {
                    PostEmbed::Images(images) => {
                        images.validate().map_err(|e| {
                            InvalidRecord::MalformedRecord(format!(
                                "Lexicon validation failed for embed images: {e}"
                            ))
                        })?;
                        for img in &images.images {
                            img.validate().map_err(|e| {
                                InvalidRecord::MalformedRecord(format!(
                                    "Lexicon validation failed for embed image: {e}"
                                ))
                            })?;
                            if let Some(ar) = &img.aspect_ratio {
                                ar.validate().map_err(|e| {
                                    InvalidRecord::MalformedRecord(format!(
                                        "Lexicon validation failed for aspect ratio: {e}"
                                    ))
                                })?;
                            }
                        }
                    }
                    _ => return Err(InvalidRecord::UnsupportedEmbed),
                }
            }
            let created_at = post.created_at.as_ref().with_timezone(&Utc);

            if let Some(reply) = &post.reply {
                // Reply: author must be on the member list at index time
                if !policy.has_membership(&candidate.author_did) {
                    return Err(InvalidRecord::NotMember);
                }

                let (raw_parent_uri, raw_root_uri) = resolve_reply(candidate, policy, reply)?;
                Ok(ValidatedRecord {
                    uri: candidate.uri.clone(),
                    author_did: candidate.author_did.clone(),
                    collection: candidate.collection.clone(),
                    rkey: candidate.rkey.clone(),
                    record_json: candidate.value.clone(),
                    created_at,
                    parent_uri: Some(raw_parent_uri),
                    root_uri: Some(raw_root_uri),
                    post_uri: None,
                    key_version: None,
                })
            } else {
                // Top-level post: must be authored by Space owner / authority
                if !policy.is_owner(&candidate.author_did) {
                    return Err(InvalidRecord::TopLevelAuthor);
                }

                // Owner must also hold membership
                if !policy.has_membership(&candidate.author_did) {
                    return Err(InvalidRecord::NotMember);
                }

                Ok(ValidatedRecord {
                    uri: candidate.uri.clone(),
                    author_did: candidate.author_did.clone(),
                    collection: candidate.collection.clone(),
                    rkey: candidate.rkey.clone(),
                    record_json: candidate.value.clone(),
                    created_at,
                    parent_uri: None,
                    root_uri: None,
                    post_uri: None,
                    key_version: None,
                })
            }
        }
        "app.bsky.feed.like" => {
            // Deserialize into generated Like type
            let like: Like = serde_json::from_value(norm_value).map_err(|e| {
                InvalidRecord::MalformedRecord(format!("Invalid app.bsky.feed.like schema: {e}"))
            })?;

            // Run generated Lexicon constraint validation
            like.validate().map_err(|e| {
                InvalidRecord::MalformedRecord(format!("Lexicon validation failed for like: {e}"))
            })?;

            if !policy.has_membership(&candidate.author_did) {
                return Err(InvalidRecord::NotMember);
            }
            let created_at = like.created_at.as_ref().with_timezone(&Utc);

            let raw_subject_uri = candidate
                .value
                .get("subject")
                .and_then(|s| s.get("uri"))
                .and_then(|u| u.as_str())
                .unwrap_or(like.subject.uri.as_ref());
            let subject_uri = to_space_form(raw_subject_uri, &policy.space_uri);
            let subject_cid = like.subject.cid.as_ref();

            match known_cid(policy, &subject_uri, raw_subject_uri) {
                Some(expected_cid) => {
                    if expected_cid != subject_cid {
                        return Err(InvalidRecord::CrossSpaceReference);
                    }
                }
                None => {
                    return Err(InvalidRecord::CrossSpaceReference);
                }
            }
            Ok(ValidatedRecord {
                uri: candidate.uri.clone(),
                author_did: candidate.author_did.clone(),
                collection: candidate.collection.clone(),
                rkey: candidate.rkey.clone(),
                record_json: candidate.value.clone(),
                created_at,
                parent_uri: None,
                root_uri: None,
                post_uri: Some(subject_uri),
                key_version: None,
            })
        }
        other => Err(InvalidRecord::UnsupportedCollection(other.to_string())),
    }
}

pub fn validate(
    candidate: RecordCandidate,
    policy: &ValidationPolicy,
) -> Result<ValidatedRecord, InvalidRecord> {
    validate_record(&candidate, policy)
}

pub fn compute_uri_hash(uri: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(uri.as_bytes());
    hasher.finalize().to_vec()
}

pub async fn persist_rejection(
    pool: &sqlx::PgPool,
    space_uri: &str,
    author_did: &str,
    rev: &str,
    uri: &str,
    reason: &InvalidRecord,
) -> Result<(), sqlx::Error> {
    let uri_hash = compute_uri_hash(uri);
    sqlx::query(
        r#"
        INSERT INTO circle_rejections (space_uri, author_did, rev, uri_hash, reason_code, observed_at)
        VALUES ($1, $2, $3, $4, $5, now())
        ON CONFLICT (space_uri, author_did, rev, uri_hash) DO UPDATE SET
            reason_code = EXCLUDED.reason_code,
            observed_at = now()
        "#,
    )
    .bind(space_uri)
    .bind(author_did)
    .bind(rev)
    .bind(&uri_hash)
    .bind(reason.reason_code())
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn prune_rejections(pool: &sqlx::PgPool, max_age_days: i32) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM circle_rejections WHERE observed_at < now() - make_interval(days => $1)",
    )
    .bind(max_age_days)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

#[cfg(test)]
mod space_form_tests {
    use super::to_space_form;

    const SPACE: &str = "at://did:plc:owner/space/blue.catbird.circle.encrypted/c1";

    #[test]
    fn standard_form_maps_into_the_space() {
        assert_eq!(
            to_space_form("at://did:plc:bob/blue.catbird.circle.post/3k2", SPACE),
            format!("{SPACE}/did:plc:bob/blue.catbird.circle.post/3k2")
        );
    }

    #[test]
    fn mapping_is_idempotent() {
        let once = to_space_form("at://did:plc:bob/app.bsky.feed.post/3k2", SPACE);
        assert_eq!(to_space_form(&once, SPACE), once);
    }

    #[test]
    fn foreign_space_refs_and_malformed_refs_are_unchanged() {
        let other =
            "at://did:plc:eve/space/blue.catbird.circle/c9/did:plc:bob/app.bsky.feed.post/3k2";
        assert_eq!(to_space_form(other, SPACE), other);
        assert_eq!(to_space_form("at://did:plc:bob", SPACE), "at://did:plc:bob");
        assert_eq!(
            to_space_form("at://did:plc:bob/app.bsky.feed.post/3k2", ""),
            "at://did:plc:bob/app.bsky.feed.post/3k2"
        );
    }
}
