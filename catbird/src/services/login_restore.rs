//! Pure acceptance checks for a login-time Bluesky snapshot.
//!
//! This module performs no network, database, enrollment, or delivery writes.
//! Caller-supplied readiness capabilities must describe implemented behavior;
//! a passing synthetic fixture does not prove that a deployment has that behavior.
//! Provider bodies remain untouched, including unknown actor preferences and
//! explicit false values. The permissive defaults in PushPreferencesDocument
//! must not be used to decode an untrusted or incomplete provider response.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RestoreAssessment {
    /// All required enumerable snapshots have complete, valid values.
    /// This deliberately does not claim that thread mutes were enumerated.
    pub snapshot_complete: bool,
    /// Necessary acceptance gate only, never an instruction to send a push.
    pub push_ready: bool,
    pub blockers: Vec<String>,
    pub unsupported: Vec<String>,
    pub unknown: Vec<String>,
}

#[derive(Default)]
struct Checks {
    blockers: BTreeSet<String>,
    unsupported: BTreeSet<String>,
    unknown: BTreeSet<String>,
}

impl Checks {
    fn block(&mut self, code: impl Into<String>) {
        self.blockers.insert(code.into());
    }

    fn source_complete(&mut self, snapshots: &Value, key: &str, code: &str) -> bool {
        match snapshots[key]["status"].as_str() {
            Some("Complete") => true,
            Some(status @ ("Partial" | "Unsupported" | "Failed")) => {
                self.block(format!("{code}_{}", status.to_ascii_lowercase()));
                self.unknown.insert(key.to_string());
                if status == "Unsupported" {
                    self.unsupported.insert(key.to_string());
                }
                false
            }
            _ => {
                self.block(format!("{code}_status_invalid"));
                self.unknown.insert(key.to_string());
                false
            }
        }
    }
}

/// Assess the `input` member of a login-sync fixture or equivalent caller data.
/// Missing consent, lifecycle, permission, or capability fields fail closed.
pub fn assess_login_restore(input: &Value) -> RestoreAssessment {
    let mut checks = Checks::default();
    let snapshots = &input["snapshots"];
    let mut complete = true;

    if checks.source_complete(snapshots, "actorPreferences", "actor_preferences") {
        let valid = snapshots["actorPreferences"]["body"]["preferences"]
            .as_array()
            .is_some_and(|items| {
                items.iter().all(|item| {
                    item.is_object() && item["$type"].as_str().is_some_and(|s| !s.is_empty())
                })
            });
        if !valid {
            checks.block("actor_preferences_malformed");
            checks.unknown.insert("actorPreferences".into());
            complete = false;
        }
    } else {
        complete = false;
    }

    if checks.source_complete(
        snapshots,
        "notificationPreferences",
        "notification_preferences",
    ) {
        complete &= check_notification_preferences(input, &mut checks);
    } else {
        complete = false;
    }

    if checks.source_complete(snapshots, "chatPreferences", "chat_preferences") {
        complete &= check_chat_preferences(input, &mut checks);
    } else {
        complete = false;
    }

    for (key, code, array_key) in [
        (
            "activitySubscriptions",
            "activity_subscriptions",
            "subscriptions",
        ),
        ("conversationMutes", "conversation_mutes", "convos"),
    ] {
        if checks.source_complete(snapshots, key, code) {
            complete &= check_pages(&snapshots[key]["pages"], key, code, array_key, &mut checks);
        } else {
            complete = false;
        }
    }

    // Unsupported enumeration remains unsupported even when reset is accepted.
    // Reset of lost Catbird-local overrides cannot disable upstream suppression.
    checks.unknown.insert("threadMutes".into());
    if snapshots["threadMutes"]["status"].as_str() == Some("Unsupported") {
        checks.unsupported.insert("threadMutes".into());
    } else {
        checks.block("thread_mute_snapshot_status_invalid");
    }
    if input["threadSuppressionMode"].as_str() != Some("ProviderReadThroughReady") {
        checks.block("thread_suppression_unavailable");
    }

    if input["resetAcknowledged"].as_bool() != Some(true) {
        checks.block("reset_acknowledgment_required");
    }
    if input["restoredChoicesConfirmed"].as_bool() != Some(true) {
        checks.block("restored_choices_confirmation_required");
    }
    if input["pushPermissionGranted"].as_bool() != Some(true) {
        checks.block("os_push_permission_missing");
    }
    if input["sessionActive"].as_bool() != Some(true) {
        checks.block("session_inactive");
    }
    match (
        input["syncGeneration"].as_u64(),
        input["currentGeneration"].as_u64(),
    ) {
        (Some(a), Some(b)) if a > 0 && a == b => {}
        _ => checks.block("stale_generation"),
    }
    if !input["accountDid"]
        .as_str()
        .is_some_and(|did| did.starts_with("did:") && did.len() > 4)
    {
        checks.block("account_identity_missing");
    }
    if input["priming"]["status"].as_str() != Some("Complete") {
        checks.block("priming_incomplete");
    }
    if input["priming"]["socialFenceEstablished"].as_bool() != Some(true) {
        checks.block("social_replay_fence_missing");
    }
    if input["priming"]["historicalNotificationsEnqueued"].as_u64() != Some(0) {
        checks.block("silent_priming_not_attested");
    }

    RestoreAssessment {
        snapshot_complete: complete,
        push_ready: complete && checks.blockers.is_empty(),
        blockers: checks.blockers.into_iter().collect(),
        unsupported: checks.unsupported.into_iter().collect(),
        unknown: checks.unknown.into_iter().collect(),
    }
}

fn check_notification_preferences(input: &Value, checks: &mut Checks) -> bool {
    let prefs = &input["snapshots"]["notificationPreferences"]["body"]["preferences"];
    let mut valid = true;
    for category in [
        "follow",
        "like",
        "likeViaRepost",
        "mention",
        "quote",
        "reply",
        "repost",
        "repostViaRepost",
        "starterpackJoined",
        "subscribedPost",
        "unverified",
        "verified",
    ] {
        for field in ["list", "push"] {
            if !prefs[category][field].is_boolean() {
                checks.block("notification_preference_required_field_missing");
                checks
                    .unknown
                    .insert(format!("notificationPreferences.{category}.{field}"));
                valid = false;
            }
        }
        if matches!(
            category,
            "follow"
                | "like"
                | "likeViaRepost"
                | "mention"
                | "quote"
                | "reply"
                | "repost"
                | "repostViaRepost"
        ) {
            valid &= check_include(
                &prefs[category],
                input,
                checks,
                &format!("notificationPreferences.{category}"),
            );
        }
    }
    // app.bsky.notification preferences.chat is deprecated provider filler.
    valid
}

fn check_chat_preferences(input: &Value, checks: &mut Checks) -> bool {
    let prefs = &input["snapshots"]["chatPreferences"]["body"]["preferences"];
    let mut valid = true;
    for category in ["chat", "chatRequest"] {
        if !prefs[category]["push"].is_boolean() {
            checks.block("chat_preference_required_field_missing");
            checks
                .unknown
                .insert(format!("chatPreferences.{category}.push"));
            valid = false;
        }
        valid &= check_include(
            &prefs[category],
            input,
            checks,
            &format!("chatPreferences.{category}"),
        );
    }
    if prefs["chat"] != prefs["chatRequest"]
        && (prefs["chat"]["push"].as_bool() == Some(true)
            || prefs["chatRequest"]["push"].as_bool() == Some(true))
        && input["enforcement"]["chatRequests"].as_bool() != Some(true)
    {
        checks.block("chat_request_filter_unenforced");
    }
    valid
}

fn check_include(pref: &Value, input: &Value, checks: &mut Checks, path: &str) -> bool {
    match pref["include"].as_str() {
        Some("all") => true,
        Some("follows") => {
            if pref["push"].as_bool() == Some(true)
                && input["enforcement"]["includeFollows"].as_bool() != Some(true)
            {
                checks.block("include_follows_unenforced");
            }
            true
        }
        _ => {
            checks.block("preference_include_unknown");
            checks.unknown.insert(format!("{path}.include"));
            false
        }
    }
}

fn check_pages(pages: &Value, key: &str, code: &str, array_key: &str, checks: &mut Checks) -> bool {
    let Some(pages) = pages.as_array().filter(|pages| !pages.is_empty()) else {
        checks.block(format!("{code}_pages_missing"));
        checks.unknown.insert(key.to_string());
        return false;
    };
    let mut valid = true;
    let mut cursors = BTreeSet::new();
    let mut entries = BTreeMap::new();
    for (index, page) in pages.iter().enumerate() {
        let cursor = page.get("cursor");
        if index + 1 == pages.len() {
            if cursor.is_some() {
                checks.block(format!("{code}_unfinished_cursor"));
                valid = false;
            }
        } else if !cursor
            .and_then(Value::as_str)
            .is_some_and(|cursor| !cursor.is_empty() && cursors.insert(cursor.to_string()))
        {
            checks.block(format!("{code}_invalid_cursor_chain"));
            valid = false;
        }
        let Some(items) = page[array_key].as_array() else {
            checks.block(format!("{code}_page_malformed"));
            valid = false;
            continue;
        };
        for item in items {
            let id_key = if key == "activitySubscriptions" {
                "did"
            } else {
                "id"
            };
            let Some(id) = item[id_key].as_str().filter(|id| !id.is_empty()) else {
                checks.block(format!("{code}_item_malformed"));
                valid = false;
                continue;
            };
            let flags = if key == "activitySubscriptions" {
                match (
                    item["viewer"]["activitySubscription"]["post"].as_bool(),
                    item["viewer"]["activitySubscription"]["reply"].as_bool(),
                ) {
                    (Some(post), Some(reply)) => Some((post, reply)),
                    _ => {
                        checks.block("activity_subscription_flags_unknown");
                        checks.unknown.insert(format!("{key}.{id}"));
                        None
                    }
                }
            } else {
                match item["muted"].as_bool() {
                    Some(muted) => Some((muted, false)),
                    None => {
                        checks.block("conversation_mute_unknown");
                        checks.unknown.insert(format!("{key}.{id}"));
                        None
                    }
                }
            };
            if let Some(flags) = flags {
                if entries
                    .insert(id.to_string(), flags)
                    .is_some_and(|old| old != flags)
                {
                    checks.block(format!("{code}_conflicting_duplicate"));
                    checks.unknown.insert(format!("{key}.{id}"));
                    valid = false;
                }
            } else {
                valid = false;
            }
        }
    }
    valid
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &[&str] = &[
        include_str!("../../tests/fixtures/login_restore/complete.json"),
        include_str!("../../tests/fixtures/login_restore/partialpage.json"),
        include_str!("../../tests/fixtures/login_restore/erroredprefs.json"),
        include_str!("../../tests/fixtures/login_restore/unsupportedchat.json"),
        include_str!("../../tests/fixtures/login_restore/omittedsubscriptionflags.json"),
        include_str!("../../tests/fixtures/login_restore/freshprime.json"),
        include_str!("../../tests/fixtures/login_restore/unsupported_enforcement.json"),
        include_str!("../../tests/fixtures/login_restore/reset_not_acknowledged.json"),
        include_str!("../../tests/fixtures/login_restore/stale_generation.json"),
        include_str!("../../tests/fixtures/login_restore/invalid_complete_claim.json"),
        include_str!("../../tests/fixtures/login_restore/missing_required_push.json"),
        include_str!("../../tests/fixtures/login_restore/thread_readthrough.json"),
        include_str!("../../tests/fixtures/login_restore/explicit_reset_only.json"),
        include_str!("../../tests/fixtures/login_restore/unconfirmed_restored_choices.json"),
        include_str!("../../tests/fixtures/login_restore/os_permission_missing.json"),
    ];

    fn strings(value: &Value) -> Vec<String> {
        let mut items: Vec<_> = value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        items.sort();
        items
    }

    #[test]
    fn synthetic_restore_contracts_fail_closed() {
        for raw in FIXTURES {
            let fixture: Value = serde_json::from_str(raw).unwrap();
            let before = fixture["input"].clone();
            let result = assess_login_restore(&fixture["input"]);
            let expected = &fixture["expected"];
            let name = fixture["name"].as_str().unwrap();
            assert_eq!(
                result.snapshot_complete,
                expected["snapshotComplete"].as_bool().unwrap(),
                "{name}"
            );
            assert_eq!(
                result.push_ready,
                expected["pushReady"].as_bool().unwrap(),
                "{name}"
            );
            assert_eq!(result.blockers, strings(&expected["blockers"]), "{name}");
            assert_eq!(
                result.unsupported,
                strings(&expected["unsupported"]),
                "{name}"
            );
            assert_eq!(result.unknown, strings(&expected["unknown"]), "{name}");
            assert_eq!(
                fixture["input"], before,
                "validator mutated source values: {name}"
            );
        }
    }

    #[test]
    fn empty_input_cannot_restore_or_activate() {
        let result = assess_login_restore(&Value::Null);
        assert!(!result.snapshot_complete);
        assert!(!result.push_ready);
        assert!(result.blockers.iter().any(|x| x == "stale_generation"));
        assert!(result
            .blockers
            .iter()
            .any(|x| x == "restored_choices_confirmation_required"));
    }
}
