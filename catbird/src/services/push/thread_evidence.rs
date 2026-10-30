//! Recipient-bound, short-lived proof of one relevant post's thread mute.
//! No provider preferences, enumeration, persistent post body, or write is used.
//! Missing/unsupported/failed evidence returns Err for transient worker retry.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, ensure, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;

use super::types::QueueRow;
use crate::config::AppState;
use crate::services::{AtProtoClient, ProxyResponse};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const EVIDENCE_TTL: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const POST: &str = "app.bsky.feed.post";

/// Immutable in-memory evidence. Call `matches` again under the final account
/// lock against the current SQL row and account generations before using it.
#[derive(Clone)]
pub struct ThreadEvidence {
    recipient_did: String,
    actor_did: String,
    queue_id: i64,
    event_cid: String,
    event_path: String,
    notification_type: String,
    event_timestamp: i64,
    queued_root: Option<String>,
    auth_generation: i64,
    moderation_generation: i64,
    relevant_uri: String,
    root_uri: String,
    muted: bool,
    observed_at: Instant,
}

impl fmt::Debug for ThreadEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreadEvidence")
            .field("queue_id", &self.queue_id)
            .field("muted", &self.muted)
            .finish_non_exhaustive()
    }
}

impl ThreadEvidence {
    pub fn is_muted(&self) -> bool {
        self.muted
    }
    pub fn root_uri(&self) -> &str {
        &self.root_uri
    }
    pub fn relevant_uri(&self) -> &str {
        &self.relevant_uri
    }
    pub fn matches(
        &self,
        row: &QueueRow,
        current_auth_generation: i64,
        current_moderation_generation: i64,
    ) -> bool {
        current_auth_generation > 0
            && self.auth_generation == current_auth_generation
            && row.auth_generation == current_auth_generation
            && self.moderation_generation == current_moderation_generation
            && self.recipient_did == row.recipient_did
            && self.actor_did == row.actor_did
            && self.queue_id == row.id
            && self.event_cid == row.event_cid
            && self.event_path == row.event_path
            && self.notification_type == row.notification_type
            && self.event_timestamp == row.event_timestamp
            && self.queued_root == row.thread_root_uri
            && relevant_post_uri(row).is_ok_and(|uri| uri == self.relevant_uri)
            && Instant::now()
                .checked_duration_since(self.observed_at)
                .is_some_and(|age| age <= EVIDENCE_TTL)
    }
}

/// Source contract: the verified firehose queue builder uses original subject
/// for like/repost/via, and the event's own post for mention/reply/quote/activity.
/// Quote proof must instead inspect its quoted target's thread, derived here.
pub fn relevant_post_uri(row: &QueueRow) -> Result<String> {
    ensure!(
        row.id > 0 && !row.event_cid.is_empty(),
        "thread_evidence_event_identity"
    );
    ensure!(row.auth_generation > 0, "thread_evidence_auth_generation");
    let record = row
        .event_record_json
        .as_object()
        .ok_or_else(|| anyhow!("thread_evidence_record"))?;
    let (collection, key) = row
        .event_path
        .split_once('/')
        .ok_or_else(|| anyhow!("thread_evidence_event_path"))?;
    ensure!(valid_key(key), "thread_evidence_event_path");
    let expected_collection = match row.notification_type.as_str() {
        "like" | "via_like" => "app.bsky.feed.like",
        "repost" | "via_repost" => "app.bsky.feed.repost",
        "mention" | "reply" | "quote" | "activity_post" | "activity_reply" => POST,
        _ => return Err(anyhow!("thread_evidence_category")),
    };
    ensure!(
        collection == expected_collection
            && record.get("$type").and_then(Value::as_str) == Some(expected_collection),
        "thread_evidence_record_type"
    );
    if collection != POST {
        let uri = record
            .get("subject")
            .and_then(|value| value.get("uri"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("thread_evidence_subject"))?;
        validate_post_uri(uri)?;
        ensure!(
            row.subject_uri.as_deref() == Some(uri),
            "thread_evidence_subject_mismatch"
        );
        return Ok(uri.to_owned());
    }
    let own_uri = format!("at://{}/{}", row.actor_did, row.event_path);
    validate_post_uri(&own_uri)?;
    ensure!(
        row.subject_uri.as_deref() == Some(own_uri.as_str()),
        "thread_evidence_event_subject_mismatch"
    );
    if row.notification_type != "quote" {
        return Ok(own_uri);
    }
    let embed = record
        .get("embed")
        .ok_or_else(|| anyhow!("thread_evidence_quote_embed"))?;
    let quoted = match embed.get("$type").and_then(Value::as_str) {
        Some("app.bsky.embed.record") => embed.get("record"),
        Some("app.bsky.embed.recordWithMedia") => embed
            .get("record")
            .filter(|record| {
                record.get("$type").and_then(Value::as_str) == Some("app.bsky.embed.record")
            })
            .and_then(|record| record.get("record")),
        _ => None,
    }
    .and_then(|record| record.get("uri"))
    .and_then(Value::as_str)
    .ok_or_else(|| anyhow!("thread_evidence_quote_subject"))?;
    validate_post_uri(quoted)?;
    Ok(quoted.to_owned())
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 512
        && key != "."
        && key != ".."
        && key
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || b"._~:-".contains(&value))
}

fn validate_post_uri(uri: &str) -> Result<()> {
    ensure!(uri.len() <= 2048, "thread_evidence_post_uri");
    let mut parts = uri
        .strip_prefix("at://")
        .ok_or_else(|| anyhow!("thread_evidence_post_uri"))?
        .split('/');
    let did = parts
        .next()
        .ok_or_else(|| anyhow!("thread_evidence_post_uri"))?;
    jacquard_common::types::did::Did::new(did).map_err(|_| anyhow!("thread_evidence_post_uri"))?;
    ensure!(
        parts.next() == Some(POST),
        "thread_evidence_post_collection"
    );
    ensure!(
        parts.next().is_some_and(valid_key) && parts.next().is_none(),
        "thread_evidence_post_key"
    );
    Ok(())
}

struct PostProof {
    root_uri: String,
    muted: bool,
}

fn parse_post_proof(body: &[u8], requested: &str) -> Result<PostProof> {
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "thread_evidence_byte_limit"
    );
    let value: Value = serde_json::from_slice(body).map_err(|_| anyhow!("thread_evidence_json"))?;
    let posts = value
        .get("posts")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("thread_evidence_posts"))?;
    // One requested URI must produce exactly one matching post. An omitted post
    // may be missing/blocked; a duplicate or unrelated view is not proof.
    ensure!(
        posts.len() == 1,
        "thread_evidence_missing_or_duplicate_post"
    );
    let post = &posts[0];
    ensure!(
        post.get("uri").and_then(Value::as_str) == Some(requested),
        "thread_evidence_post_mismatch"
    );
    let viewer = post
        .get("viewer")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("thread_evidence_viewer"))?;
    let muted = viewer
        .get("threadMuted")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("thread_evidence_unknown_mute"))?;
    let record = post
        .get("record")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("thread_evidence_post_record"))?;
    ensure!(
        record.get("$type").and_then(Value::as_str) == Some(POST),
        "thread_evidence_post_record_type"
    );
    let root = match record.get("reply") {
        None => requested,
        Some(reply) => reply
            .get("root")
            .and_then(|root| root.get("uri"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("thread_evidence_reply_root"))?,
    };
    validate_post_uri(root)?;
    Ok(PostProof {
        root_uri: root.to_owned(),
        muted,
    })
}

/// Resolve through the existing session/PDS client. All errors are unknown proof
/// and must retry transiently rather than permanently disabling this category.
pub async fn resolve(state: &Arc<AppState>, row: &QueueRow) -> Result<ThreadEvidence> {
    tokio::time::timeout(REQUEST_TIMEOUT, resolve_inner(state, row))
        .await
        .map_err(|_| anyhow!("thread_evidence_timeout"))?
}

async fn resolve_inner(state: &Arc<AppState>, row: &QueueRow) -> Result<ThreadEvidence> {
    let relevant_uri = relevant_post_uri(row)?;
    let pool = state
        .push_db
        .as_ref()
        .ok_or_else(|| anyhow!("thread_evidence_store"))?;
    let account: Option<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT COALESCE(session_fingerprint,encode(sha256(session_id::bytea),'hex')),pds_url,auth_generation,moderation_generation FROM push_accounts WHERE account_did=$1 AND auth_revoked_at IS NULL",
    ).bind(&row.recipient_did).fetch_optional(pool).await.map_err(|_| anyhow!("thread_evidence_account_read"))?;
    let (session_fingerprint, pds_url, auth_generation, moderation_generation) =
        account.ok_or_else(|| anyhow!("thread_evidence_account_unavailable"))?;
    ensure!(
        auth_generation > 0 && auth_generation == row.auth_generation,
        "thread_evidence_stale_generation"
    );
    let (session, dpop) = super::resolve_background_session(
        state,
        &row.recipient_did,
        &session_fingerprint,
        &pds_url,
    )
    .await
    .map_err(|_| anyhow!("thread_evidence_session_unavailable"))?;
    ensure!(
        session.did == row.recipient_did,
        "thread_evidence_recipient_mismatch"
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        "atproto-proxy",
        HeaderValue::from_static("did:web:api.bsky.app#bsky_appview"),
    );
    let query = format!("uris={}", urlencoding::encode(&relevant_uri));
    let observed_at = Instant::now();
    let response = AtProtoClient::new(state.clone())
        .proxy_request_with_limit(
            &session,
            reqwest::Method::GET,
            "/xrpc/app.bsky.feed.getPosts",
            Some(&query),
            None,
            None,
            Some(&headers),
            "push-thread-evidence",
            Some(&dpop),
            MAX_RESPONSE_BYTES,
        )
        .await
        .map_err(|_| anyhow!("thread_evidence_upstream_unavailable"))?;
    let proof = match response {
        ProxyResponse::Buffered {
            status: 200, body, ..
        } => parse_post_proof(&body, &relevant_uri)?,
        _ => return Err(anyhow!("thread_evidence_upstream_response")),
    };
    let store = state
        .auth_store
        .as_deref()
        .ok_or_else(|| anyhow!("thread_evidence_store"))?;
    store
        .validate_live_session_local(&row.recipient_did, &session.id.to_string())
        .await
        .map_err(|_| anyhow!("thread_evidence_session_changed"))?;
    let current: Option<(i64, i64)> = sqlx::query_as("SELECT auth_generation,moderation_generation FROM push_accounts WHERE account_did=$1 AND auth_revoked_at IS NULL")
        .bind(&row.recipient_did).fetch_optional(pool).await.map_err(|_| anyhow!("thread_evidence_account_read"))?;
    ensure!(
        current == Some((auth_generation, moderation_generation)),
        "thread_evidence_generation_changed"
    );
    Ok(ThreadEvidence {
        recipient_did: row.recipient_did.clone(),
        actor_did: row.actor_did.clone(),
        queue_id: row.id,
        event_cid: row.event_cid.clone(),
        event_path: row.event_path.clone(),
        notification_type: row.notification_type.clone(),
        event_timestamp: row.event_timestamp,
        queued_root: row.thread_root_uri.clone(),
        auth_generation,
        moderation_generation,
        relevant_uri,
        root_uri: proof.root_uri,
        muted: proof.muted,
        observed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SUBJECT: &str = "at://did:plc:subject/app.bsky.feed.post/subject";
    const ROOT: &str = "at://did:plc:root/app.bsky.feed.post/root";

    fn row(kind: &str) -> QueueRow {
        let collection = match kind {
            "like" | "via_like" => "app.bsky.feed.like",
            "repost" | "via_repost" => "app.bsky.feed.repost",
            _ => POST,
        };
        let event_path = format!("{collection}/event");
        let own = format!("at://did:plc:actor/{event_path}");
        QueueRow {
            id: 1,
            recipient_did: "did:plc:recipient".into(),
            actor_did: "did:plc:actor".into(),
            notification_type: kind.into(),
            event_cid: "synthetic-cid".into(),
            event_path,
            subject_uri: Some(if collection == POST {
                own
            } else {
                SUBJECT.into()
            }),
            thread_root_uri: None,
            event_record_json: json!({"$type":collection,"subject":{"uri":SUBJECT},"text":"synthetic"}),
            event_timestamp: 100,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            attempts: 0,
            lease_token: None,
            lease_version: 0,
            auth_generation: 7,
        }
    }
    fn post(muted: Value, reply: bool) -> Value {
        let mut record = json!({"$type":POST,"text":"synthetic"});
        if reply {
            record["reply"] = json!({"root":{"uri":ROOT},"parent":{"uri":ROOT}});
        }
        json!({"posts":[{"uri":SUBJECT,"record":record,"viewer":{"threadMuted":muted}}]})
    }
    fn parse(value: Value) -> Result<PostProof> {
        parse_post_proof(value.to_string().as_bytes(), SUBJECT)
    }

    #[test]
    fn original_subject_is_used_for_like_repost_and_via_events() {
        for kind in ["like", "repost", "via_like", "via_repost"] {
            assert_eq!(relevant_post_uri(&row(kind)).unwrap(), SUBJECT);
        }
        let mut bad = row("like");
        bad.subject_uri = Some(ROOT.into());
        assert!(relevant_post_uri(&bad).is_err());
        bad = row("like");
        bad.event_record_json["subject"]["uri"] = json!("at://did:plc:x/app.bsky.feed.like/record");
        assert!(relevant_post_uri(&bad).is_err());
    }
    #[test]
    fn own_post_is_used_for_mention_reply_and_activity() {
        for kind in ["mention", "reply", "activity_post", "activity_reply"] {
            assert_eq!(
                relevant_post_uri(&row(kind)).unwrap(),
                "at://did:plc:actor/app.bsky.feed.post/event"
            );
        }
        assert!(relevant_post_uri(&row("follow")).is_err());
        let mut bad = row("reply");
        bad.event_record_json["$type"] = json!("app.bsky.feed.like");
        assert!(relevant_post_uri(&bad).is_err());
    }
    #[test]
    fn quotes_use_quoted_target_even_when_quoting_thread_differs() {
        let mut event = row("quote");
        event.thread_root_uri = Some(ROOT.into());
        event.event_record_json["embed"] =
            json!({"$type":"app.bsky.embed.record","record":{"uri":SUBJECT}});
        assert_eq!(relevant_post_uri(&event).unwrap(), SUBJECT);
        event.event_record_json["embed"] = json!({"$type":"app.bsky.embed.recordWithMedia","record":{"$type":"app.bsky.embed.record","record":{"uri":SUBJECT}},"media":{}});
        assert_eq!(relevant_post_uri(&event).unwrap(), SUBJECT);
        event.event_record_json["embed"]["record"]["$type"] = json!("unknown");
        assert!(relevant_post_uri(&event).is_err());
    }
    #[test]
    fn explicit_boolean_and_canonical_root_are_required() {
        assert!(!parse(post(json!(false), false)).unwrap().muted);
        assert_eq!(parse(post(json!(false), false)).unwrap().root_uri, SUBJECT);
        assert!(parse(post(json!(true), true)).unwrap().muted);
        assert_eq!(parse(post(json!(true), true)).unwrap().root_uri, ROOT);
        for invalid in [Value::Null, json!("false"), json!(0)] {
            assert!(parse(post(invalid, false)).is_err());
        }
        let mut missing = post(json!(false), false);
        missing["posts"][0]["viewer"] = json!({});
        assert!(parse(missing).is_err());
        let mut incomplete = post(json!(false), false);
        incomplete["posts"][0]["record"]["reply"] = json!({});
        assert!(parse(incomplete).is_err());
    }
    #[test]
    fn omitted_duplicate_wrong_post_and_oversized_response_are_unknown() {
        assert!(parse(json!({"posts":[]})).is_err());
        let mut wrong = post(json!(false), false);
        wrong["posts"][0]["uri"] = json!(ROOT);
        assert!(parse(wrong).is_err());
        let value = post(json!(false), false);
        assert!(parse(json!({"posts":[value["posts"][0],value["posts"][0]]})).is_err());
        let mut missing = post(json!(false), false);
        missing["posts"][0]
            .as_object_mut()
            .unwrap()
            .remove("viewer");
        assert!(parse(missing).is_err());
        assert!(parse_post_proof(&vec![b' '; MAX_RESPONSE_BYTES + 1], SUBJECT).is_err());
        for uri in [
            "https://example.test/post",
            "at://example.test/app.bsky.feed.post/a",
            "at://did:plc:x/app.bsky.feed.like/a",
            "at://did:plc:x/app.bsky.feed.post/../x",
            "at://did:plc:x/app.bsky.feed.post/a?b",
        ] {
            assert!(validate_post_uri(uri).is_err());
        }
    }
    #[test]
    fn final_proof_is_bound_to_event_recipient_generations_and_freshness() {
        let event = row("like");
        let mut proof = ThreadEvidence {
            recipient_did: event.recipient_did.clone(),
            actor_did: event.actor_did.clone(),
            queue_id: event.id,
            event_cid: event.event_cid.clone(),
            event_path: event.event_path.clone(),
            notification_type: event.notification_type.clone(),
            event_timestamp: event.event_timestamp,
            queued_root: event.thread_root_uri.clone(),
            auth_generation: 7,
            moderation_generation: 3,
            relevant_uri: SUBJECT.into(),
            root_uri: ROOT.into(),
            muted: false,
            observed_at: Instant::now(),
        };
        assert!(proof.matches(&event, 7, 3));
        assert!(!proof.matches(&event, 8, 3));
        assert!(!proof.matches(&event, 7, 4));
        let mut changed = event.clone();
        changed.recipient_did = "did:plc:other".into();
        assert!(!proof.matches(&changed, 7, 3));
        changed = event.clone();
        changed.event_cid = "other-cid".into();
        assert!(!proof.matches(&changed, 7, 3));
        changed = event.clone();
        changed.event_timestamp += 1;
        assert!(!proof.matches(&changed, 7, 3));
        changed = event.clone();
        changed.id += 1;
        assert!(!proof.matches(&changed, 7, 3));
        proof.observed_at = Instant::now() - Duration::from_secs(31);
        assert!(!proof.matches(&event, 7, 3));
        assert_eq!(proof.root_uri(), ROOT);
        assert_eq!(proof.relevant_uri(), SUBJECT);
        assert!(!proof.is_muted());
    }
}
