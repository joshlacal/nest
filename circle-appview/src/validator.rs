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

pub fn validate_record(
    candidate: &RecordCandidate,
    policy: &ValidationPolicy,
) -> Result<ValidatedRecord, InvalidRecord> {
    let created_at_str = candidate
        .value
        .get("createdAt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| InvalidRecord::MalformedRecord("Missing createdAt".into()))?;

    let created_at = DateTime::parse_from_rfc3339(created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| InvalidRecord::MalformedRecord(format!("Invalid createdAt format: {e}")))?;

    match candidate.collection.as_str() {
        "app.bsky.feed.post" => {
            // Check unsupported embeds (record quote, recordWithMedia)
            if let Some(embed) = candidate.value.get("embed") {
                let embed_type = embed
                    .get("$type")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if embed_type == "app.bsky.embed.record"
                    || embed_type == "app.bsky.embed.recordWithMedia"
                {
                    return Err(InvalidRecord::UnsupportedEmbed);
                }
            }

            // Check reply structure
            if let Some(reply) = candidate.value.get("reply") {
                // Must have active member access lease
                if !policy.has_lease(&candidate.author_did) {
                    return Err(InvalidRecord::NoAccessLease);
                }

                let parent_obj = reply
                    .get("parent")
                    .and_then(|p| p.as_object())
                    .ok_or_else(|| {
                        InvalidRecord::MalformedRecord("Missing parent object in reply".into())
                    })?;
                let parent_uri = parent_obj
                    .get("uri")
                    .and_then(|u| u.as_str())
                    .ok_or_else(|| {
                        InvalidRecord::MalformedRecord("Missing parent.uri in reply".into())
                    })?;
                let parent_cid = parent_obj
                    .get("cid")
                    .and_then(|c| c.as_str())
                    .ok_or_else(|| {
                        InvalidRecord::MalformedRecord("Missing parent.cid in reply".into())
                    })?;

                let root_obj = reply
                    .get("root")
                    .and_then(|r| r.as_object())
                    .ok_or_else(|| {
                        InvalidRecord::MalformedRecord("Missing root object in reply".into())
                    })?;
                let root_uri = root_obj
                    .get("uri")
                    .and_then(|u| u.as_str())
                    .ok_or_else(|| {
                        InvalidRecord::MalformedRecord("Missing root.uri in reply".into())
                    })?;
                let root_cid = root_obj
                    .get("cid")
                    .and_then(|c| c.as_str())
                    .ok_or_else(|| {
                        InvalidRecord::MalformedRecord("Missing root.cid in reply".into())
                    })?;

                // Parent and root must be known same-space post URIs with matching CIDs
                let known_parent_cid = policy.known_posts.get(parent_uri);
                let known_root_cid = policy.known_posts.get(root_uri);
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
                    parent_uri: Some(parent_uri.to_string()),
                    root_uri: Some(root_uri.to_string()),
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
            if !policy.has_lease(&candidate.author_did) {
                return Err(InvalidRecord::NoAccessLease);
            }

            let subject_obj = candidate
                .value
                .get("subject")
                .and_then(|s| s.as_object())
                .ok_or_else(|| {
                    InvalidRecord::MalformedRecord("Missing subject object in like".into())
                })?;
            let subject_uri = subject_obj
                .get("uri")
                .and_then(|u| u.as_str())
                .ok_or_else(|| {
                    InvalidRecord::MalformedRecord("Missing subject.uri in like".into())
                })?;
            let subject_cid = subject_obj
                .get("cid")
                .and_then(|c| c.as_str())
                .ok_or_else(|| {
                    InvalidRecord::MalformedRecord("Missing subject.cid in like".into())
                })?;

            match policy.known_posts.get(subject_uri) {
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
                post_uri: Some(subject_uri.to_string()),
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
