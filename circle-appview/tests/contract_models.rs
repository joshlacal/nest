//! Contract and serialization tests for Catbird Circle request and response models.
//!
//! Validates that generated types match Lexicon definitions and serialize/deserialize
//! with exact camelCase fields and typed descriptors, preventing field drift.

use petrel_catbird::generated::blue::catbird::circle::activate_circle::Input as ActivateCircle;
use petrel_catbird::generated::blue::catbird::circle::activate_circle::Output as ActivateCircleOutput;
use petrel_catbird::generated::blue::catbird::circle::defs::CircleSummary;
use petrel_catbird::generated::blue::catbird::circle::defs::NotificationReason;
use petrel_catbird::generated::blue::catbird::circle::get_capabilities::Output as GetCapabilitiesOutput;
use petrel_catbird::generated::blue::catbird::circle::get_feed::Output as GetFeedOutput;
use petrel_catbird::generated::blue::catbird::circle::get_feed::Parameters as GetFeed;
use petrel_catbird::generated::blue::catbird::circle::get_media::Parameters as GetMedia;
use petrel_catbird::generated::blue::catbird::circle::get_post_thread::Parameters as GetPostThread;
use petrel_catbird::generated::blue::catbird::circle::list_circles::Output as ListCirclesOutput;
use petrel_catbird::generated::blue::catbird::circle::list_circles::Parameters as ListCircles;
use petrel_catbird::generated::blue::catbird::circle::list_notifications::Output as ListNotificationsOutput;
use petrel_catbird::generated::blue::catbird::circle::list_notifications::Parameters as ListNotifications;
use petrel_catbird::generated::blue::catbird::circle::report_record::Input as ReportRecord;
use petrel_catbird::generated::blue::catbird::circle::report_record::InputReason as ReportRecordReason;
use petrel_catbird::generated::blue::catbird::circle::update_preferences::Input as UpdatePreferences;
use petrel_catbird::generated::blue::catbird::circle::update_preferences::Output as UpdatePreferencesOutput;
use petrel_core::AtUri;
use petrel_core::CidString as Cid;
use petrel_core::Did;
use petrel_core::SpaceRef;
use petrel_core::Tid;
use serde_json::json;

/// A raw-codec CID (the form a blob reference carries).
const BLOB_CID: &str = "bafkreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm";

/// Query parameters as the client sends them, keyed by wire name.
fn query_map<P: petrel_core::ToQueryParams>(
    params: &P,
) -> std::collections::BTreeMap<&'static str, String> {
    let mut out = Vec::new();
    params.to_query_params(&mut out);
    out.into_iter().collect()
}

/// Encode then decode query parameters the way a client and this server do.
fn round_trip<P: petrel_core::ToQueryParams + petrel_core::FromQueryParams>(params: &P) -> P {
    let mut out = Vec::new();
    params.to_query_params(&mut out);
    let pairs: Vec<(&str, &str)> = out.iter().map(|(k, v)| (*k, v.as_str())).collect();
    P::from_query_params(&pairs).unwrap()
}

#[test]
fn test_activate_circle_contract_serialization() {
    let space_uri = SpaceRef::parse("at:space/did:plc:alice/blue.catbird.circle/3l7skey").unwrap();
    let input = ActivateCircle { space: space_uri };

    let serialized = serde_json::to_value(&input).unwrap();
    assert_eq!(
        serialized["space"],
        "at:space/did:plc:alice/blue.catbird.circle/3l7skey"
    );

    let deserialized: ActivateCircle = serde_json::from_value(serialized).unwrap();
    assert_eq!(
        deserialized.space.as_str(),
        "at:space/did:plc:alice/blue.catbird.circle/3l7skey"
    );
}

#[test]
fn test_activate_circle_output_contract() {
    let circle_summary = CircleSummary {
        circle_id: Tid::parse("3l7aaaaaaaaaa").unwrap(),
        uri: SpaceRef::parse("at:space/did:plc:alice/blue.catbird.circle/3l7skey").unwrap(),
        name: String::from("Test Circle"),
        owner: Did::parse("did:plc:alice").unwrap(),
        member_count: Some(5),
        latest_key_version: None,
        muted: Some(false),
        extra_data: None,
    };

    let output = ActivateCircleOutput {
        circle: circle_summary,
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
        circle_id: Tid::parse("3l7aaaaaaaaaa").unwrap(),
        uri: SpaceRef::parse("at:space/did:plc:alice/blue.catbird.circle/3l7skey").unwrap(),
        name: String::from("Alice's Inner Circle"),
        owner: Did::parse("did:plc:alice").unwrap(),
        member_count: Some(42),
        latest_key_version: None,
        muted: Some(true),
        extra_data: None,
    };

    let serialized = serde_json::to_value(&summary).unwrap();
    assert_eq!(serialized["circleId"], "3l7aaaaaaaaaa");
    assert_eq!(
        serialized["uri"],
        "at:space/did:plc:alice/blue.catbird.circle/3l7skey"
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
        ReportRecordReason::Unknown(val) => assert_eq!(val.as_str(), "harassment"),
        _ => panic!("Expected Unknown"),
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
        NotificationReason::Unknown(val) => assert_eq!(val.as_str(), "mention"),
        _ => panic!("Expected Other"),
    }
}

#[test]
fn test_get_capabilities_output_contract() {
    let output = GetCapabilitiesOutput {
        enabled: true,
        protocol_revision: String::from("1f510f8e36a973f6fd055da349b586918805ae66"),
        supports_images: false,
        supports_encrypted_posts: None,
    };

    let serialized = serde_json::to_value(&output).unwrap();
    assert_eq!(serialized["enabled"], true);
    assert_eq!(
        serialized["protocolRevision"],
        "1f510f8e36a973f6fd055da349b586918805ae66"
    );
    assert_eq!(serialized["supportsImages"], false);
}

#[test]
fn test_get_feed_query_and_output_contract() {
    let space_uri = SpaceRef::parse("at:space/did:plc:alice/blue.catbird.circle/3l7skey").unwrap();
    let query = GetFeed {
        cursor: Some(String::from("cursor123")),
        include_encrypted: None,
        limit: 25,
        space: Some(space_uri),
    };
    let serialized = query_map(&query);
    assert_eq!(
        serialized["space"],
        "at:space/did:plc:alice/blue.catbird.circle/3l7skey"
    );
    assert_eq!(serialized["limit"], "25");
    assert_eq!(serialized["cursor"], "cursor123");
    assert_eq!(round_trip(&query), query);

    let output = GetFeedOutput {
        cursor: Some(String::from("next_cursor")),
        feed: Vec::new(),
    };
    let out_ser = serde_json::to_value(&output).unwrap();
    assert_eq!(out_ser["cursor"], "next_cursor");
    assert_eq!(out_ser["feed"], json!([]));
}

#[test]
fn test_list_circles_query_and_output_contract() {
    let query = ListCircles {
        cursor: Some(String::from("cursor_c")),
        limit: 10,
    };
    let serialized = query_map(&query);
    assert_eq!(serialized["limit"], "10");
    assert_eq!(serialized["cursor"], "cursor_c");
    assert_eq!(round_trip(&query), query);

    let output = ListCirclesOutput {
        circles: Vec::new(),
        cursor: Some(String::from("next_cursor_c")),
    };
    let out_ser = serde_json::to_value(&output).unwrap();
    assert_eq!(out_ser["cursor"], "next_cursor_c");
    assert_eq!(out_ser["circles"], json!([]));
}

#[test]
fn test_list_notifications_query_and_output_contract() {
    let query = ListNotifications {
        cursor: Some(String::from("cursor_n")),
        limit: 20,
    };
    let serialized = query_map(&query);
    assert_eq!(serialized["limit"], "20");
    assert_eq!(serialized["cursor"], "cursor_n");
    assert_eq!(round_trip(&query), query);

    let output = ListNotificationsOutput {
        cursor: Some(String::from("next_cursor_n")),
        notifications: Vec::new(),
    };
    let out_ser = serde_json::to_value(&output).unwrap();
    assert_eq!(out_ser["cursor"], "next_cursor_n");
    assert_eq!(out_ser["notifications"], json!([]));
}

#[test]
fn test_get_media_and_post_thread_contract() {
    let space_uri = SpaceRef::parse("at:space/did:plc:alice/blue.catbird.circle/3l7skey").unwrap();
    let aturi = AtUri::parse("at://did:plc:alice/app.bsky.feed.post/3l7rkey").unwrap();
    let did = Did::parse("did:plc:alice").unwrap();
    let media = GetMedia {
        cid: Cid::parse(BLOB_CID).unwrap(),
        did,
        space: space_uri.clone(),
    };
    let media_ser = query_map(&media);
    assert_eq!(media_ser["cid"], BLOB_CID);
    assert_eq!(media_ser["did"], "did:plc:alice");
    assert_eq!(round_trip(&media), media);

    let thread_query = GetPostThread {
        depth: 10,
        include_encrypted: None,
        parent_height: 80,
        space: space_uri,
        uri: aturi,
    };
    let thread_ser = query_map(&thread_query);
    assert_eq!(thread_ser["depth"], "10");
    assert_eq!(thread_ser["parentHeight"], "80");
    assert_eq!(round_trip(&thread_query), thread_query);
}

#[test]
fn test_moderation_and_preferences_contract() {
    let space_uri = SpaceRef::parse("at:space/did:plc:alice/blue.catbird.circle/3l7skey").unwrap();
    let aturi = AtUri::parse("at://did:plc:alice/app.bsky.feed.post/3l7rkey").unwrap();

    let report = ReportRecord {
        details: Some(String::from("Inappropriate content")),
        reason: ReportRecordReason::Abuse,
        space: space_uri.clone(),
        uri: aturi,
        disclosed_media: None,
        disclosed_post_key: None,
    };
    let report_ser = serde_json::to_value(&report).unwrap();
    assert_eq!(report_ser["reason"], "abuse");
    assert_eq!(report_ser["details"], "Inappropriate content");

    let pref = UpdatePreferences {
        muted: true,
        space: space_uri,
    };
    let pref_ser = serde_json::to_value(&pref).unwrap();
    assert_eq!(pref_ser["muted"], true);

    let pref_out = UpdatePreferencesOutput { muted: true };
    let pref_out_ser = serde_json::to_value(&pref_out).unwrap();
    assert_eq!(pref_out_ser["muted"], true);
}
