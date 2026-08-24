use catbird_atproto::generated::app_bsky::feed::like::Like;
use catbird_atproto::generated::app_bsky::feed::post::{Post, PostEmbed};
use catbird_atproto::jacquard_lexicon::schema::LexiconSchema;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum InvalidRecord {
    #[error("Only the space authority can author top-level posts")]
    TopLevelAuthor,
    #[error("Author does not hold an active member access lease")]
    NoAccessLease,
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
}

impl InvalidRecord {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::TopLevelAuthor => "top_level_author",
            Self::NoAccessLease => "no_access_lease",
            Self::CrossSpaceReference => "cross_space_reference",
            Self::UnsupportedEmbed => "unsupported_embed",
            Self::UnsupportedCollection(_) => "unsupported_collection",
            Self::MalformedRecord(_) => "malformed_record",
            Self::MissingParentRecord => "missing_parent_record",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidationPolicy {
    pub space_uri: String,
    pub owner_did: String,
    pub active_members: HashSet<String>,
    pub known_posts: HashMap<String, String>,
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
        }
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

    pub fn has_lease(&self, did: &str) -> bool {
        self.active_members.contains(did)
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

pub fn validate_record(
    candidate: &RecordCandidate,
    policy: &ValidationPolicy,
) -> Result<ValidatedRecord, InvalidRecord> {
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
        "app.bsky.feed.post" => {
            // Deserialize into generated Post type (strictly validates schema, tags, and field types)
            let post: Post = serde_json::from_value(norm_value)
                .map_err(|e| InvalidRecord::MalformedRecord(format!("Invalid app.bsky.feed.post schema: {e}")))?;

            // Run generated Lexicon constraint validation
            post.validate()
                .map_err(|e| InvalidRecord::MalformedRecord(format!("Lexicon validation failed for post: {e}")))?;

            if let Some(facets) = &post.facets {
                for facet in facets {
                    facet.validate()
                        .map_err(|e| InvalidRecord::MalformedRecord(format!("Lexicon validation failed for facet: {e}")))?;
                    facet.index.validate()
                        .map_err(|e| InvalidRecord::MalformedRecord(format!("Lexicon validation failed for facet index: {e}")))?;
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
                            }
                            _ => {
                                return Err(InvalidRecord::MalformedRecord("Unrecognized or malformed facet feature".into()));
                            }
                        }
                    }
                }
            }

            if let Some(embed) = &post.embed {
                match embed {
                    PostEmbed::Images(images) => {
                        images.validate()
                            .map_err(|e| InvalidRecord::MalformedRecord(format!("Lexicon validation failed for embed images: {e}")))?;
                        for img in &images.images {
                            img.validate()
                                .map_err(|e| InvalidRecord::MalformedRecord(format!("Lexicon validation failed for embed image: {e}")))?;
                        }
                    }
                    _ => return Err(InvalidRecord::UnsupportedEmbed),
                }
            }

            let created_at = post.created_at.as_ref().with_timezone(&Utc);

            if let Some(reply) = &post.reply {
                // Must have active member access lease
                if !policy.has_lease(&candidate.author_did) {
                    return Err(InvalidRecord::NoAccessLease);
                }

                let raw_parent_uri = candidate.value.get("reply").and_then(|r| r.get("parent")).and_then(|p| p.get("uri")).and_then(|u| u.as_str()).unwrap_or(reply.parent.uri.as_ref());
                let raw_root_uri = candidate.value.get("reply").and_then(|r| r.get("root")).and_then(|p| p.get("uri")).and_then(|u| u.as_str()).unwrap_or(reply.root.uri.as_ref());

                let parent_uri = reply.parent.uri.as_ref();
                let parent_cid = reply.parent.cid.as_ref();
                let root_uri = reply.root.uri.as_ref();
                let root_cid = reply.root.cid.as_ref();

                // Parent and root must be known same-space post URIs with matching CIDs
                let known_parent_cid = policy.known_posts.get(raw_parent_uri).or_else(|| policy.known_posts.get(parent_uri));
                let known_root_cid = policy.known_posts.get(raw_root_uri).or_else(|| policy.known_posts.get(root_uri));
                match (known_parent_cid, known_root_cid) {
                    (Some(expected_parent_cid), Some(expected_root_cid)) => {
                        if expected_parent_cid != parent_cid || expected_root_cid != root_cid {
                            return Err(InvalidRecord::CrossSpaceReference);
                        }
                    }
                    _ => {
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
                    parent_uri: Some(raw_parent_uri.to_string()),
                    root_uri: Some(raw_root_uri.to_string()),
                    post_uri: None,
                })
            } else {
                // Top-level post: must be authored by Space owner
                if !policy.is_owner(&candidate.author_did) {
                    return Err(InvalidRecord::TopLevelAuthor);
                }

                // Owner must also hold an active lease / membership
                if !policy.has_lease(&candidate.author_did) {
                    return Err(InvalidRecord::NoAccessLease);
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
                })
            }
        }
        "app.bsky.feed.like" => {
            // Deserialize into generated Like type
            let like: Like = serde_json::from_value(norm_value)
                .map_err(|e| InvalidRecord::MalformedRecord(format!("Invalid app.bsky.feed.like schema: {e}")))?;

            // Run generated Lexicon constraint validation
            like.validate()
                .map_err(|e| InvalidRecord::MalformedRecord(format!("Lexicon validation failed for like: {e}")))?;

            if !policy.has_lease(&candidate.author_did) {
                return Err(InvalidRecord::NoAccessLease);
            }
            let created_at = like.created_at.as_ref().with_timezone(&Utc);

            let raw_subject_uri = candidate.value.get("subject").and_then(|s| s.get("uri")).and_then(|u| u.as_str()).unwrap_or(like.subject.uri.as_ref());
            let subject_uri = like.subject.uri.as_ref();
            let subject_cid = like.subject.cid.as_ref();

            match policy.known_posts.get(raw_subject_uri).or_else(|| policy.known_posts.get(subject_uri)) {
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
                post_uri: Some(raw_subject_uri.to_string()),
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
    uri: &str,
    reason: &InvalidRecord,
) -> Result<(), sqlx::Error> {
    let uri_hash = compute_uri_hash(uri);
    sqlx::query(
        r#"
        INSERT INTO circle_rejections (uri_hash, reason_code, observed_at)
        VALUES ($1, $2, now())
        ON CONFLICT (uri_hash) DO NOTHING
        "#,
    )
    .bind(&uri_hash)
    .bind(reason.reason_code())
    .execute(pool)
    .await?;

    Ok(())
}
