//! Contract and serialization tests for Catbird Circle request and response models.
//!
//! Validates that generated types match Lexicon definitions and serialize/deserialize
//! with exact camelCase fields and typed descriptors, preventing field drift.

use catbird_atproto::generated::blue_catbird::circle::activate_circle::{
    ActivateCircle, ActivateCircleOutput,
};
use catbird_atproto::generated::blue_catbird::circle::get_capabilities::GetCapabilitiesOutput;
use catbird_atproto::generated::blue_catbird::circle::get_feed::{GetFeed, GetFeedOutput};
use catbird_atproto::generated::blue_catbird::circle::get_media::GetMedia;
use catbird_atproto::generated::blue_catbird::circle::get_post_thread::GetPostThread;
use catbird_atproto::generated::blue_catbird::circle::list_circles::{
    ListCircles, ListCirclesOutput,
};
use catbird_atproto::generated::blue_catbird::circle::list_notifications::{
    ListNotifications, ListNotificationsOutput,
};
use catbird_atproto::generated::blue_catbird::circle::report_record::{
    ReportRecord, ReportRecordReason,
};
use catbird_atproto::generated::blue_catbird::circle::update_preferences::{
    UpdatePreferences, UpdatePreferencesOutput,
};
use catbird_atproto::generated::blue_catbird::circle::{CircleSummary, NotificationReason};
use catbird_atproto::jacquard_common::deps::smol_str::SmolStr;
use catbird_atproto::jacquard_common::types::aturi::AtSpaceUri;
use catbird_atproto::jacquard_common::types::string::{AtUri, Cid, Did, Tid};
use serde_json::json;

#[test]
fn test_activate_circle_contract_serialization() {
    let space_uri = AtSpaceUri::new(SmolStr::new(
        "at://did:plc:alice/space/blue.catbird.circle/3l7skey",
    ))
    .unwrap();
    let input = ActivateCircle {
        space: space_uri,
        extra_data: None,
    };

    let serialized = serde_json::to_value(&input).unwrap();
    assert_eq!(
        serialized["space"],
        "at://did:plc:alice/space/blue.catbird.circle/3l7skey"
    );

    let deserialized: ActivateCircle = serde_json::from_value(serialized).unwrap();
    assert_eq!(
        deserialized.space.as_str(),
        "at://did:plc:alice/space/blue.catbird.circle/3l7skey"
    );
}

#[test]
fn test_activate_circle_output_contract() {
    let circle_summary = CircleSummary {
        circle_id: Tid::new(SmolStr::new("3l7aaaaaaaaaa")).unwrap(),
        uri: AtSpaceUri::new(SmolStr::new(
            "at://did:plc:alice/space/blue.catbird.circle/3l7skey",
        ))
        .unwrap(),
        name: SmolStr::new("Test Circle"),
        owner: Did::new(SmolStr::new("did:plc:alice")).unwrap(),
        member_count: Some(5),
        muted: Some(false),
        extra_data: None,
    };

    let output = ActivateCircleOutput {
        circle: circle_summary,
        extra_data: None,
    };

    let serialized = serde_json::to_value(&output).unwrap();
    assert_eq!(serialized["circle"]["circleId"], "3l7aaaaaaaaaa");
    assert_eq!(serialized["circle"]["name"], "Test Circle");
    assert_eq!(serialized["circle"]["owner"], "did:plc:alice");
    assert_eq!(serialized["circle"]["memberCount"], 5);
    assert_eq!(serialized["circle"]["muted"], false);
    // Must NOT contain removed fields
    assert!(serialized["circle"].get("members").is_none());
    assert!(serialized["circle"].get("accessState").is_none());
}

#[test]
fn test_circle_summary_contract() {
    let summary = CircleSummary {
        circle_id: Tid::new(SmolStr::new("3l7aaaaaaaaaa")).unwrap(),
        uri: AtSpaceUri::new(SmolStr::new(
            "at://did:plc:alice/space/blue.catbird.circle/3l7skey",
        ))
        .unwrap(),
        name: SmolStr::new("Alice's Inner Circle"),
        owner: Did::new(SmolStr::new("did:plc:alice")).unwrap(),
        member_count: Some(42),
        muted: Some(true),
        extra_data: None,
    };

    let serialized = serde_json::to_value(&summary).unwrap();
    assert_eq!(serialized["circleId"], "3l7aaaaaaaaaa");
    assert_eq!(
        serialized["uri"],
        "at://did:plc:alice/space/blue.catbird.circle/3l7skey"
    );
    assert_eq!(serialized["name"], "Alice's Inner Circle");
    assert_eq!(serialized["owner"], "did:plc:alice");
    assert_eq!(serialized["memberCount"], 42);
    assert_eq!(serialized["muted"], true);

    let json_str = serde_json::to_string(&summary).unwrap();
    let deserialized: CircleSummary = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.circle_id.as_str(), "3l7aaaaaaaaaa");
    assert_eq!(deserialized.member_count, Some(42));
    assert_eq!(deserialized.muted, Some(true));
}

#[test]
fn test_report_record_reason_open_union() {
    let reason_spam: ReportRecordReason = serde_json::from_value(json!("spam")).unwrap();
    assert_eq!(reason_spam, ReportRecordReason::Spam);

    let reason_abuse: ReportRecordReason = serde_json::from_value(json!("abuse")).unwrap();
    assert_eq!(reason_abuse, ReportRecordReason::Abuse);

    let reason_other: ReportRecordReason = serde_json::from_value(json!("other")).unwrap();
    assert_eq!(reason_other, ReportRecordReason::Other);

    // Open union: unknown value deserializes into UnknownValue
    let reason_unknown: ReportRecordReason = serde_json::from_value(json!("harassment")).unwrap();
    match reason_unknown {
        ReportRecordReason::UnknownValue(val) => assert_eq!(val.as_str(), "harassment"),
        _ => panic!("Expected UnknownValue"),
    }
}

#[test]
fn test_notification_reason_open_union() {
    let reason_reply: NotificationReason = serde_json::from_value(json!("reply")).unwrap();
    assert_eq!(reason_reply, NotificationReason::Reply);

    let reason_like: NotificationReason = serde_json::from_value(json!("like")).unwrap();
    assert_eq!(reason_like, NotificationReason::Like);

    let reason_invite: NotificationReason = serde_json::from_value(json!("invite")).unwrap();
    assert_eq!(reason_invite, NotificationReason::Invite);

    // Open union: unknown value deserializes into Other
    let reason_custom: NotificationReason = serde_json::from_value(json!("mention")).unwrap();
    match reason_custom {
        NotificationReason::Other(val) => assert_eq!(val.as_str(), "mention"),
        _ => panic!("Expected Other"),
    }
}

#[test]
fn test_get_capabilities_output_contract() {
    let output = GetCapabilitiesOutput {
        enabled: true,
        protocol_revision: SmolStr::new("89deb9faca20e56fa2a262fe9746ed52bc1095ba"),
        supports_images: true,
        extra_data: None,
    };

    let serialized = serde_json::to_value(&output).unwrap();
    assert_eq!(serialized["enabled"], true);
    assert_eq!(
        serialized["protocolRevision"],
        "89deb9faca20e56fa2a262fe9746ed52bc1095ba"
    );
    assert_eq!(serialized["supportsImages"], true);
}

#[test]
fn test_get_feed_query_and_output_contract() {
    let space_uri = AtSpaceUri::new(SmolStr::new(
        "at://did:plc:alice/space/blue.catbird.circle/3l7skey",
    ))
    .unwrap();
    let query = GetFeed {
        cursor: Some(SmolStr::new("cursor123")),
        limit: Some(25),
        space: Some(space_uri),
    };
    let serialized = serde_json::to_value(&query).unwrap();
    assert_eq!(
        serialized["space"],
        "at://did:plc:alice/space/blue.catbird.circle/3l7skey"
    );
    assert_eq!(serialized["limit"], 25);
    assert_eq!(serialized["cursor"], "cursor123");

    let output = GetFeedOutput {
        cursor: Some(SmolStr::new("next_cursor")),
        feed: Vec::new(),
        extra_data: None,
    };
    let out_ser = serde_json::to_value(&output).unwrap();
    assert_eq!(out_ser["cursor"], "next_cursor");
    assert_eq!(out_ser["feed"], json!([]));
}

#[test]
fn test_list_circles_query_and_output_contract() {
    let query = ListCircles {
        cursor: Some(SmolStr::new("cursor_c")),
        limit: Some(10),
    };
    let serialized = serde_json::to_value(&query).unwrap();
    assert_eq!(serialized["limit"], 10);
    assert_eq!(serialized["cursor"], "cursor_c");

    let output = ListCirclesOutput {
        circles: Vec::new(),
        cursor: Some(SmolStr::new("next_cursor_c")),
        extra_data: None,
    };
    let out_ser = serde_json::to_value(&output).unwrap();
    assert_eq!(out_ser["cursor"], "next_cursor_c");
    assert_eq!(out_ser["circles"], json!([]));
}

#[test]
fn test_list_notifications_query_and_output_contract() {
    let query = ListNotifications {
        cursor: Some(SmolStr::new("cursor_n")),
        limit: Some(20),
    };
    let serialized = serde_json::to_value(&query).unwrap();
    assert_eq!(serialized["limit"], 20);
    assert_eq!(serialized["cursor"], "cursor_n");

    let output = ListNotificationsOutput {
        cursor: Some(SmolStr::new("next_cursor_n")),
        notifications: Vec::new(),
        extra_data: None,
    };
    let out_ser = serde_json::to_value(&output).unwrap();
    assert_eq!(out_ser["cursor"], "next_cursor_n");
    assert_eq!(out_ser["notifications"], json!([]));
}

#[test]
fn test_get_media_and_post_thread_contract() {
    let space_uri = AtSpaceUri::new(SmolStr::new(
        "at://did:plc:alice/space/blue.catbird.circle/3l7skey",
    ))
    .unwrap();
    let aturi = AtUri::new(SmolStr::new(
        "at://did:plc:alice/app.bsky.feed.post/3l7rkey",
    ))
    .unwrap();
    let did = Did::new(SmolStr::new("did:plc:alice")).unwrap();
    let media = GetMedia {
        cid: Cid::new(b"bafkreibblob").unwrap(),
        did,
        space: space_uri.clone(),
    };
    let media_ser = serde_json::to_value(&media).unwrap();
    assert_eq!(media_ser["cid"], "bafkreibblob");
    assert_eq!(media_ser["did"], "did:plc:alice");

    let thread_query = GetPostThread {
        depth: Some(10),
        parent_height: Some(80),
        space: space_uri,
        uri: aturi,
    };
    let thread_ser = serde_json::to_value(&thread_query).unwrap();
    assert_eq!(thread_ser["depth"], 10);
    assert_eq!(thread_ser["parentHeight"], 80);
}

#[test]
fn test_moderation_and_preferences_contract() {
    let space_uri = AtSpaceUri::new(SmolStr::new(
        "at://did:plc:alice/space/blue.catbird.circle/3l7skey",
    ))
    .unwrap();
    let aturi = AtUri::new(SmolStr::new(
        "at://did:plc:alice/app.bsky.feed.post/3l7rkey",
    ))
    .unwrap();

    let report = ReportRecord {
        details: Some(SmolStr::new("Inappropriate content")),
        reason: ReportRecordReason::Abuse,
        space: space_uri.clone(),
        uri: aturi,
        extra_data: None,
    };
    let report_ser = serde_json::to_value(&report).unwrap();
    assert_eq!(report_ser["reason"], "abuse");
    assert_eq!(report_ser["details"], "Inappropriate content");

    let pref = UpdatePreferences {
        muted: true,
        space: space_uri,
        extra_data: None,
    };
    let pref_ser = serde_json::to_value(&pref).unwrap();
    assert_eq!(pref_ser["muted"], true);

    let pref_out = UpdatePreferencesOutput::<SmolStr> {
        muted: true,
        extra_data: None,
    };
    let pref_out_ser = serde_json::to_value(&pref_out).unwrap();
    assert_eq!(pref_out_ser["muted"], true);
}
