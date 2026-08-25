//! Contract and serialization tests for Catbird Circle request and response models.
//!
//! Validates that generated types match Lexicon definitions and serialize/deserialize
//! with exact camelCase fields and typed descriptors, preventing field drift.

use catbird_atproto::generated::blue_catbird::circle::activate_space::{
    ActivateSpace, ActivateSpaceOutput,
};
use catbird_atproto::generated::blue_catbird::circle::create_circle::{
    CreateCircle, CreateCircleOutput,
};
use catbird_atproto::generated::blue_catbird::circle::defs::{
    AccessState, MemberAction, Operation, OperationStatus, SpaceRef,
};
use catbird_atproto::generated::blue_catbird::circle::get_feed::{GetFeed, GetFeedOutput};
use catbird_atproto::generated::blue_catbird::circle::get_media::GetMedia;
use catbird_atproto::generated::blue_catbird::circle::get_operation::{
    GetOperation, GetOperationOutput,
};
use catbird_atproto::generated::blue_catbird::circle::get_post_thread::{
    GetPostThread, GetPostThreadOutput,
};
use catbird_atproto::generated::blue_catbird::circle::list_notifications::{
    ListNotifications, ListNotificationsOutput,
};
use catbird_atproto::generated::blue_catbird::circle::update_member::{
    UpdateMember, UpdateMemberOutput,
};
use catbird_atproto::types::string::{AtUri, Cid, Did};
use serde_json::json;

#[test]
fn test_create_circle_contract_serialization() {
    let input: CreateCircle<String> = CreateCircle {
        name: "Test Circle".to_string(),
        member_dids: vec![
            Did::new("did:plc:bob".to_string()).unwrap(),
            Did::new("did:plc:carol".to_string()).unwrap(),
        ],
        extra_data: None,
    };

    let serialized = serde_json::to_value(&input).unwrap();
    assert_eq!(serialized["name"], "Test Circle");
    assert_eq!(
        serialized["memberDids"],
        json!(["did:plc:bob", "did:plc:carol"])
    );
    // Must NOT have legacy/drift names
    assert!(serialized.get("initialMembers").is_none());

    // Roundtrip
    let deserialized: CreateCircle<String> = serde_json::from_value(serialized).unwrap();
    assert_eq!(deserialized.name.as_str(), "Test Circle");
    assert_eq!(deserialized.member_dids.len(), 2);
}

#[test]
fn test_create_circle_output_contract() {
    let space_ref: SpaceRef<String> =
        SpaceRef::new("at://did:plc:alice/space/blue.catbird.circle/skey123".to_string()).unwrap();
    let op: Operation<String> = Operation {
        id: "op-uuid-456".to_string(),
        status: OperationStatus::Complete,
        space: Some(space_ref),
        error: None,
        extra_data: None,
    };
    let output: CreateCircleOutput<String> = CreateCircleOutput {
        value: op,
        extra_data: None,
    };

    let serialized = serde_json::to_value(&output).unwrap();
    assert_eq!(serialized["id"], "op-uuid-456");
    assert_eq!(serialized["status"], "complete");
    assert_eq!(
        serialized["space"],
        "at://did:plc:alice/space/blue.catbird.circle/skey123"
    );
    // Must NOT have drift names
    assert!(serialized.get("spaceUri").is_none());

    let deserialized: CreateCircleOutput<String> = serde_json::from_value(serialized).unwrap();
    assert_eq!(deserialized.value.status, OperationStatus::Complete);
    assert_eq!(
        deserialized.value.space.unwrap().as_str(),
        "at://did:plc:alice/space/blue.catbird.circle/skey123"
    );
}

#[test]
fn test_update_member_contract_serialization() {
    let space_ref: SpaceRef<String> =
        SpaceRef::new("at://did:plc:alice/space/blue.catbird.circle/skey123".to_string()).unwrap();
    let input_add: UpdateMember<String> = UpdateMember {
        action: MemberAction::Add,
        member_did: Did::new("did:plc:dave".to_string()).unwrap(),
        space: space_ref.clone(),
        extra_data: None,
    };

    let serialized_add = serde_json::to_value(&input_add).unwrap();
    assert_eq!(serialized_add["action"], "add");
    assert_eq!(serialized_add["memberDid"], "did:plc:dave");
    assert_eq!(
        serialized_add["space"],
        "at://did:plc:alice/space/blue.catbird.circle/skey123"
    );
    assert!(serialized_add.get("spaceUri").is_none());
    assert!(serialized_add.get("member").is_none());

    let input_remove: UpdateMember<String> = UpdateMember {
        action: MemberAction::Remove,
        member_did: Did::new("did:plc:bob".to_string()).unwrap(),
        space: space_ref,
        extra_data: None,
    };
    let serialized_remove = serde_json::to_value(&input_remove).unwrap();
    assert_eq!(serialized_remove["action"], "remove");
    assert_eq!(serialized_remove["memberDid"], "did:plc:bob");
}

#[test]
fn test_activate_space_contract_serialization() {
    let space_ref: SpaceRef<String> =
        SpaceRef::new("at://did:plc:alice/space/blue.catbird.circle/skey123".to_string()).unwrap();
    let input: ActivateSpace<String> = ActivateSpace {
        space: space_ref,
        extra_data: None,
    };

    let serialized = serde_json::to_value(&input).unwrap();
    assert_eq!(
        serialized["space"],
        "at://did:plc:alice/space/blue.catbird.circle/skey123"
    );

    let output: ActivateSpaceOutput<String> = ActivateSpaceOutput {
        access_state: AccessState::Active,
        expires_at: None,
        extra_data: None,
    };
    let serialized_out = serde_json::to_value(&output).unwrap();
    assert_eq!(serialized_out["accessState"], "active");
}

#[test]
fn test_get_feed_contract_parameters() {
    let space_ref: SpaceRef<String> =
        SpaceRef::new("at://did:plc:alice/space/blue.catbird.circle/skey123".to_string()).unwrap();
    let input: GetFeed<String> = GetFeed {
        space: Some(space_ref),
        cursor: Some("cur-123".to_string()),
        limit: Some(25),
    };

    let serialized = serde_json::to_value(&input).unwrap();
    assert_eq!(
        serialized["space"],
        "at://did:plc:alice/space/blue.catbird.circle/skey123"
    );
    assert_eq!(serialized["cursor"], "cur-123");
    assert_eq!(serialized["limit"], 25);
}

#[test]
fn test_get_post_thread_contract_parameters() {
    let space_ref: SpaceRef<String> =
        SpaceRef::new("at://did:plc:alice/space/blue.catbird.circle/skey123".to_string()).unwrap();
    let input: GetPostThread<String> = GetPostThread {
        space: space_ref,
        uri: AtUri::new("at://did:plc:alice/app.bsky.feed.post/3kabc".to_string())
            .unwrap(),
        depth: Some(6),
        parent_height: Some(8),
    };

    let serialized = serde_json::to_value(&input).unwrap();
    assert_eq!(
        serialized["space"],
        "at://did:plc:alice/space/blue.catbird.circle/skey123"
    );
    assert_eq!(
        serialized["uri"],
        "at://did:plc:alice/app.bsky.feed.post/3kabc"
    );
    assert_eq!(serialized["depth"], 6);
    assert_eq!(serialized["parentHeight"], 8);
}

#[test]
fn test_get_media_contract_parameters() {
    let space_ref =
        SpaceRef::new(catbird_atproto::jacquard_common::DefaultStr::from("at://did:plc:alice/space/blue.catbird.circle/skey123")).unwrap();
    let input = GetMedia {
        space: space_ref,
        did: Did::new(catbird_atproto::jacquard_common::DefaultStr::from("did:plc:alice")).unwrap(),
        cid: Cid::from(String::from("bafkreibm4k")),
    };
    let serialized = serde_json::to_value(&input).unwrap();
    assert_eq!(
        serialized["space"],
        "at://did:plc:alice/space/blue.catbird.circle/skey123"
    );
    assert_eq!(serialized["did"], "did:plc:alice");
    assert_eq!(serialized["cid"], "bafkreibm4k");
    assert!(serialized.get("authorDid").is_none());
}

#[test]
fn test_get_operation_contract() {
    let input: GetOperation<String> = GetOperation {
        id: "op-uuid-789".to_string(),
    };
    let serialized = serde_json::to_value(&input).unwrap();
    assert_eq!(serialized["id"], "op-uuid-789");

    let output: GetOperationOutput<String> = GetOperationOutput {
        value: Operation {
            id: "op-uuid-789".to_string(),
            status: OperationStatus::Pending,
            space: None,
            error: None,
            extra_data: None,
        },
        extra_data: None,
    };
    let serialized_out = serde_json::to_value(&output).unwrap();
    assert_eq!(serialized_out["id"], "op-uuid-789");
    assert_eq!(serialized_out["status"], "pending");
}
