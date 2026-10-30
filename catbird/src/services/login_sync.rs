//! Bounded, read-only provider snapshots for the existing login flow.
//!
//! Calls AtProtoClient directly, avoiding Nest's intercepted notification routes.
//! Never writes provider or local state. Caller must recheck authorization and
//! account generation under its lifecycle guard before applying any response.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{json, Value};

use super::atproto_client::{AtProtoClient, ProxyResponse};
use crate::middleware::JacquardDpopData;
use crate::models::CatbirdSession;

const MAX_DURATION: Duration = Duration::from_secs(30);
const MAX_BYTES: usize = 5 * 1024 * 1024;
const MAX_PAGES: usize = 20;
const MAX_ENTRIES: usize = 1_000;
const MAX_CURSOR_BYTES: usize = 512;
const APPVIEW: &str = "did:web:api.bsky.app#bsky_appview";
const CHAT: &str = "did:web:api.bsky.chat#bsky_chat";

#[derive(Clone, Copy)]
enum Source {
    Actor,
    Notification,
    Chat,
    Activity,
    Conversations,
}

impl Source {
    fn path(self) -> &'static str {
        match self {
            Self::Actor => "/xrpc/app.bsky.actor.getPreferences",
            Self::Notification => "/xrpc/app.bsky.notification.getPreferences",
            Self::Chat => "/xrpc/chat.bsky.notification.getPreferences",
            Self::Activity => "/xrpc/app.bsky.notification.listActivitySubscriptions",
            Self::Conversations => "/xrpc/chat.bsky.convo.listConvos",
        }
    }

    fn proxy(self) -> Option<&'static str> {
        match self {
            Self::Actor => None,
            Self::Notification | Self::Activity => Some(APPVIEW),
            Self::Chat | Self::Conversations => Some(CHAT),
        }
    }

    fn array_key(self) -> &'static str {
        match self {
            Self::Activity => "subscriptions",
            Self::Conversations => "convos",
            _ => "preferences",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Failure {
    status: &'static str,
    code: &'static str,
}

impl Failure {
    fn failed(code: &'static str) -> Self {
        Self {
            status: "Failed",
            code,
        }
    }

    fn partial(code: &'static str) -> Self {
        Self {
            status: "Partial",
            code,
        }
    }

    fn value(&self) -> Value {
        // Never return provider error messages, credentials, or response headers.
        json!({"status": self.status, "errorCode": self.code})
    }
}

struct Budget {
    started: Instant,
    bytes: usize,
}

impl Budget {
    fn remaining(&self) -> Result<(Duration, usize), Failure> {
        let time = MAX_DURATION
            .checked_sub(self.started.elapsed())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| Failure::partial("duration_budget_exhausted"))?;
        let bytes = MAX_BYTES.saturating_sub(self.bytes);
        if bytes == 0 {
            return Err(Failure::partial("byte_budget_exhausted"));
        }
        Ok((time, bytes))
    }
}

/// Return the `snapshots` member required by `assess_login_restore`.
///
/// Login can continue independently of source failures. This function does not
/// authorize delivery, attest consent, set a replay fence, or persist anything.
/// Scope-denied responses remain Failed; optional/missing fields are not defaults.
pub async fn fetch_login_snapshots(
    client: &AtProtoClient,
    session: &CatbirdSession,
    dpop: Option<&JacquardDpopData>,
    request_id: &str,
) -> Value {
    let mut budget = Budget {
        started: Instant::now(),
        bytes: 0,
    };
    let actor = fetch_single(
        client,
        session,
        dpop,
        request_id,
        Source::Actor,
        &mut budget,
    )
    .await;
    let notification = fetch_single(
        client,
        session,
        dpop,
        request_id,
        Source::Notification,
        &mut budget,
    )
    .await;
    let chat = fetch_single(client, session, dpop, request_id, Source::Chat, &mut budget).await;
    let activity = fetch_pages(
        client,
        session,
        dpop,
        request_id,
        Source::Activity,
        &mut budget,
    )
    .await;
    let conversations = fetch_pages(
        client,
        session,
        dpop,
        request_id,
        Source::Conversations,
        &mut budget,
    )
    .await;
    json!({
        "actorPreferences": actor,
        "notificationPreferences": notification,
        "chatPreferences": chat,
        "activitySubscriptions": activity,
        "conversationMutes": conversations,
        "threadMutes": {"status": "Unsupported", "reason": "no_public_enumeration"}
    })
}

async fn fetch_body(
    client: &AtProtoClient,
    session: &CatbirdSession,
    dpop: Option<&JacquardDpopData>,
    request_id: &str,
    source: Source,
    query: Option<&str>,
    budget: &mut Budget,
) -> Result<Value, Failure> {
    let (remaining_time, remaining_bytes) = budget.remaining()?;
    let mut headers = HeaderMap::new();
    if let Some(proxy) = source.proxy() {
        headers.insert("atproto-proxy", HeaderValue::from_static(proxy));
    }
    let result = tokio::time::timeout(
        remaining_time,
        client.proxy_request_with_limit(
            session,
            reqwest::Method::GET,
            source.path(),
            query,
            None,
            None,
            Some(&headers),
            request_id,
            dpop,
            remaining_bytes,
        ),
    )
    .await
    .map_err(|_| Failure::partial("duration_budget_exhausted"))?;
    let response = match result {
        Ok(response) => response,
        Err(_) => {
            // An error may have consumed response bytes that the client cannot
            // report. Spend the remaining allowance rather than retrying other
            // sources with an unproven aggregate byte budget.
            budget.bytes = MAX_BYTES;
            return Err(Failure::failed("upstream_request_failed"));
        }
    };
    budget.bytes = budget.bytes.saturating_add(response.bytes_transferred());
    if budget.bytes > MAX_BYTES {
        return Err(Failure::partial("byte_budget_exhausted"));
    }
    if budget.started.elapsed() >= MAX_DURATION {
        return Err(Failure::partial("duration_budget_exhausted"));
    }
    match response {
        ProxyResponse::Buffered { status, body, .. } => parse_response(status, &body),
        // Drop the response rather than collecting an unbounded stream or using
        // a partial prefix. JSON endpoints should return buffered responses.
        ProxyResponse::Streaming { .. } => Err(Failure::failed("unexpected_streaming_response")),
    }
}

fn parse_response(status: u16, bytes: &[u8]) -> Result<Value, Failure> {
    let body = serde_json::from_slice::<Value>(bytes);
    if !(200..300).contains(&status) {
        let unsupported_method = matches!(status, 400 | 404 | 501)
            && matches!(
                body.as_ref().ok().and_then(|value| value["error"].as_str()),
                Some("MethodNotImplemented" | "MethodNotFound")
            );
        return Err(if status == 501 || unsupported_method {
            Failure {
                status: "Unsupported",
                code: "method_unsupported",
            }
        } else {
            Failure::failed("upstream_http_error")
        });
    }
    let body = body.map_err(|_| Failure::failed("invalid_json"))?;
    if !body.is_object() {
        return Err(Failure::failed("invalid_response_shape"));
    }
    Ok(body)
}

async fn fetch_single(
    client: &AtProtoClient,
    session: &CatbirdSession,
    dpop: Option<&JacquardDpopData>,
    request_id: &str,
    source: Source,
    budget: &mut Budget,
) -> Value {
    match fetch_body(client, session, dpop, request_id, source, None, budget).await {
        Ok(body) => single_snapshot(source, body),
        Err(error) => error.value(),
    }
}

fn single_snapshot(source: Source, body: Value) -> Value {
    let valid = match source {
        Source::Actor => body["preferences"].as_array().is_some_and(|items| {
            items.iter().all(|item| {
                item.is_object() && item["$type"].as_str().is_some_and(|kind| !kind.is_empty())
            })
        }),
        Source::Notification => {
            let prefs = &body["preferences"];
            let filtered = [
                "follow",
                "like",
                "likeViaRepost",
                "mention",
                "quote",
                "reply",
                "repost",
                "repostViaRepost",
            ];
            let plain = [
                "starterpackJoined",
                "subscribedPost",
                "unverified",
                "verified",
            ];
            filtered
                .iter()
                .all(|category| valid_preference(&prefs[*category], true, true))
                && plain
                    .iter()
                    .all(|category| valid_preference(&prefs[*category], true, false))
        }
        Source::Chat => ["chat", "chatRequest"]
            .iter()
            .all(|category| valid_preference(&body["preferences"][*category], false, true)),
        _ => false,
    };
    if valid {
        json!({"status": "Complete", "body": body})
    } else {
        json!({"status": "Failed", "errorCode": "required_preference_fields_unknown", "body": body})
    }
}

fn valid_preference(value: &Value, list: bool, include: bool) -> bool {
    value["push"].is_boolean()
        && (!list || value["list"].is_boolean())
        && (!include || matches!(value["include"].as_str(), Some("all" | "follows")))
}

#[derive(Default)]
struct Pages {
    pages: Vec<Value>,
    cursors: BTreeSet<String>,
    entries: usize,
    choices: BTreeMap<String, (bool, bool)>,
}

impl Pages {
    /// Preserve the raw page even when a field is unknown. An error never
    /// converts missing flags into a positive or negative setting.
    fn accept(&mut self, source: Source, body: Value) -> Result<Option<String>, Failure> {
        self.pages.push(body);
        let page = self.pages.last().expect("just pushed page");
        let items = page[source.array_key()]
            .as_array()
            .ok_or_else(|| Failure::partial("page_array_missing"))?;
        self.entries = self.entries.saturating_add(items.len());
        if self.entries > MAX_ENTRIES {
            return Err(Failure::partial("entry_budget_exhausted"));
        }
        for item in items {
            let (id, flags) = match source {
                Source::Activity => (
                    item["did"].as_str(),
                    item["viewer"]["activitySubscription"]["post"]
                        .as_bool()
                        .zip(item["viewer"]["activitySubscription"]["reply"].as_bool()),
                ),
                Source::Conversations => (
                    item["id"].as_str(),
                    item["muted"].as_bool().map(|flag| (flag, false)),
                ),
                _ => return Err(Failure::partial("invalid_page_source")),
            };
            let id = id
                .filter(|id| !id.is_empty())
                .ok_or_else(|| Failure::partial("item_identity_missing"))?;
            let flags = flags.ok_or_else(|| Failure::partial("item_flags_unknown"))?;
            if self
                .choices
                .insert(id.to_string(), flags)
                .is_some_and(|prior| prior != flags)
            {
                return Err(Failure::partial("conflicting_duplicate"));
            }
        }
        match page.get("cursor") {
            None => Ok(None),
            Some(Value::String(cursor))
                if !cursor.is_empty() && cursor.len() <= MAX_CURSOR_BYTES =>
            {
                if !self.cursors.insert(cursor.clone()) {
                    return Err(Failure::partial("cursor_cycle"));
                }
                Ok(Some(cursor.clone()))
            }
            Some(_) => Err(Failure::partial("invalid_cursor")),
        }
    }

    fn finish(self, error: Option<Failure>) -> Value {
        match error {
            None => json!({"status": "Complete", "pages": self.pages}),
            Some(error) => {
                // Keep both facts: there is an incomplete collection, and why
                // its continuation stopped (including Unsupported or Failed).
                let status = if self.pages.is_empty() {
                    error.status
                } else {
                    "Partial"
                };
                json!({"status": status, "pages": self.pages,
                    "errorCode": error.code, "continuationStatus": error.status})
            }
        }
    }
}

async fn fetch_pages(
    client: &AtProtoClient,
    session: &CatbirdSession,
    dpop: Option<&JacquardDpopData>,
    request_id: &str,
    source: Source,
    budget: &mut Budget,
) -> Value {
    let mut pages = Pages::default();
    let mut cursor: Option<String> = None;
    loop {
        if pages.pages.len() >= MAX_PAGES {
            return pages.finish(Some(Failure::partial("page_budget_exhausted")));
        }
        let query = match cursor.as_deref() {
            Some(cursor) => format!("limit=100&cursor={}", urlencoding::encode(cursor)),
            None => "limit=100".to_string(),
        };
        let body = match fetch_body(
            client,
            session,
            dpop,
            request_id,
            source,
            Some(&query),
            budget,
        )
        .await
        {
            Ok(body) => body,
            Err(error) => return pages.finish(Some(error)),
        };
        match pages.accept(source, body) {
            Ok(Some(next)) => cursor = Some(next),
            Ok(None) => return pages.finish(None),
            Err(error) => return pages.finish(Some(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(raw: &str) -> Value {
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn complete_fixture_preserves_false_and_unknown_provider_fields() {
        let input = fixture(include_str!(
            "../../tests/fixtures/login_restore/complete.json"
        ));
        let snapshots = &input["input"]["snapshots"];
        for (source, key) in [
            (Source::Actor, "actorPreferences"),
            (Source::Notification, "notificationPreferences"),
            (Source::Chat, "chatPreferences"),
        ] {
            let body = snapshots[key]["body"].clone();
            let result = single_snapshot(source, body.clone());
            assert_eq!(result["status"], "Complete");
            assert_eq!(result["body"], body);
        }
        for (source, key) in [
            (Source::Activity, "activitySubscriptions"),
            (Source::Conversations, "conversationMutes"),
        ] {
            let mut pages = Pages::default();
            let raw_pages = snapshots[key]["pages"].as_array().unwrap();
            for (index, page) in raw_pages.iter().enumerate() {
                assert_eq!(
                    pages.accept(source, page.clone()).unwrap().is_none(),
                    index + 1 == raw_pages.len()
                );
            }
            assert_eq!(pages.finish(None)["pages"], snapshots[key]["pages"]);
        }
    }

    #[test]
    fn missing_required_preference_is_failed_not_defaulted() {
        let input = fixture(include_str!(
            "../../tests/fixtures/login_restore/missing_required_push.json"
        ));
        let result = single_snapshot(
            Source::Notification,
            input["input"]["snapshots"]["notificationPreferences"]["body"].clone(),
        );
        assert_eq!(result["status"], "Failed");
        assert!(result["body"]["preferences"]["reply"].get("push").is_none());
    }

    #[test]
    fn absent_subscription_flags_preserve_unknown_and_partial_page() {
        let input = fixture(include_str!(
            "../../tests/fixtures/login_restore/omittedsubscriptionflags.json"
        ));
        let page = input["input"]["snapshots"]["activitySubscriptions"]["pages"][0].clone();
        let mut pages = Pages::default();
        let error = pages.accept(Source::Activity, page.clone()).unwrap_err();
        assert_eq!(error.code, "item_flags_unknown");
        let result = pages.finish(Some(error));
        assert_eq!(result["status"], "Partial");
        assert_eq!(result["pages"][0], page);
    }

    #[test]
    fn failed_continuation_cannot_commit_prefix() {
        let input = fixture(include_str!(
            "../../tests/fixtures/login_restore/partialpage.json"
        ));
        let mut pages = Pages::default();
        assert!(pages
            .accept(
                Source::Activity,
                input["input"]["snapshots"]["activitySubscriptions"]["pages"][0].clone()
            )
            .unwrap()
            .is_some());
        let result = pages.finish(Some(Failure::failed("upstream_http_error")));
        assert_eq!(result["status"], "Partial");
        assert_eq!(result["continuationStatus"], "Failed");
    }

    #[test]
    fn only_explicit_unsupported_method_is_unsupported() {
        for (status, body, expected) in [
            (
                404,
                br#"{"error":"MethodNotFound"}"#.as_slice(),
                "Unsupported",
            ),
            (501, b"not implemented".as_slice(), "Unsupported"),
            (401, br#"{"error":"MethodNotFound"}"#.as_slice(), "Failed"),
            (403, br#"{"error":"Forbidden"}"#.as_slice(), "Failed"),
            (404, br#"{"error":"NotFound"}"#.as_slice(), "Failed"),
            (200, b"[]".as_slice(), "Failed"),
        ] {
            assert_eq!(parse_response(status, body).unwrap_err().status, expected);
        }
    }

    #[test]
    fn invalid_cursors_and_conflicting_duplicates_do_not_complete() {
        for cursor in [
            Value::Null,
            json!(""),
            json!("x".repeat(MAX_CURSOR_BYTES + 1)),
        ] {
            let error = Pages::default()
                .accept(
                    Source::Conversations,
                    json!({"convos": [], "cursor": cursor}),
                )
                .unwrap_err();
            assert_eq!(error.code, "invalid_cursor");
        }
        let mut cycle = Pages::default();
        let page = json!({"convos": [], "cursor": "same"});
        cycle.accept(Source::Conversations, page.clone()).unwrap();
        assert_eq!(
            cycle.accept(Source::Conversations, page).unwrap_err().code,
            "cursor_cycle"
        );
        let mut duplicate = Pages::default();
        duplicate
            .accept(
                Source::Conversations,
                json!({"convos": [{"id": "a", "muted": true}], "cursor": "next"}),
            )
            .unwrap();
        assert_eq!(
            duplicate
                .accept(
                    Source::Conversations,
                    json!({"convos": [{"id": "a", "muted": false}]})
                )
                .unwrap_err()
                .code,
            "conflicting_duplicate"
        );
    }

    #[test]
    fn bounded_sources_use_provider_destinations_and_no_user_filters() {
        assert_eq!(Source::Actor.proxy(), None);
        assert_eq!(Source::Notification.proxy(), Some(APPVIEW));
        assert_eq!(Source::Activity.proxy(), Some(APPVIEW));
        assert_eq!(Source::Chat.proxy(), Some(CHAT));
        assert_eq!(Source::Conversations.proxy(), Some(CHAT));
        let exhausted = Budget {
            started: Instant::now(),
            bytes: MAX_BYTES,
        };
        assert_eq!(
            exhausted.remaining().unwrap_err().code,
            "byte_budget_exhausted"
        );
    }
}
