use bytes::Bytes;

use catbird_atproto::com_atproto::space::SignedCommit;
use circle_appview::auth::ParsedVerifyingKey;
use circle_appview::commit::{
    encode_commit_context_v2, verify_commit_v2, verify_commit_with_policy, CommitContextV2,
    CommitVerificationPolicy,
};

const FIXTURE_JSON: &str = include_str!("fixtures/commit_v2_vectors.json");

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn commit_v2_literal_vectors_all_curves() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE_JSON).unwrap();
    assert_eq!(fixture["domain"], "atproto-space-v2");
    let ctx_val = &fixture["context"];

    let space_str = ctx_val["space"].as_str().unwrap().to_string();
    let author_str = ctx_val["author"].as_str().unwrap().to_string();
    let rev_str = ctx_val["rev"].as_str().unwrap().to_string();
    let prev_rev_str = ctx_val["prevRev"].as_str().unwrap().to_string();
    let hash_bytes: [u8; 32] = hex_to_bytes(ctx_val["hash"].as_str().unwrap())
        .try_into()
        .unwrap();
    let prev_hash_bytes: [u8; 32] = hex_to_bytes(ctx_val["prevHash"].as_str().unwrap())
        .try_into()
        .unwrap();
    let path_str = ctx_val["path"].as_str().unwrap().to_string();
    let action_str = ctx_val["action"].as_str().unwrap().to_string();
    let cid_str = ctx_val["cid"].as_str().map(|s| s.to_string());
    let prev_cid_str = ctx_val["prevCid"].as_str().map(|s| s.to_string());
    let val_bytes = Bytes::copy_from_slice(ctx_val["val"].as_str().unwrap().as_bytes());

    let context = CommitContextV2 {
        space: space_str.clone(),
        author: author_str.clone(),
        rev: rev_str.clone(),
        prev_rev: prev_rev_str.clone(),
        hash: hash_bytes,
        prev_hash: prev_hash_bytes,
        path: path_str.clone(),
        action: action_str.clone(),
        cid: cid_str.clone(),
        prev_cid: prev_cid_str.clone(),
        val: val_bytes.clone(),
    };

    // 1. Verify transcript matches transcript_hex
    let transcript =
        encode_commit_context_v2(&context).expect("encode_commit_context_v2 should succeed");
    let expected_transcript_hex = fixture["transcript_hex"].as_str().unwrap();
    let expected_transcript = hex_to_bytes(expected_transcript_hex);
    assert_eq!(transcript, expected_transcript, "transcript bytes mismatch");

    // 2. Verify across all 3 curves
    let curves = fixture["curves"].as_object().unwrap();

    // Ed25519
    {
        let ed_info = &curves["ed25519"];
        let pub_hex = ed_info["public_key_hex"].as_str().unwrap();
        let pub_bytes: [u8; 32] = hex_to_bytes(pub_hex).try_into().unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes).unwrap();
        let parsed_key = ParsedVerifyingKey::Ed25519(vk);

        let cbor_hex = ed_info["cbor_hex"].as_str().unwrap();
        let cbor_bytes = hex_to_bytes(cbor_hex);
        let commit: SignedCommit = serde_ipld_dagcbor::from_slice(&cbor_bytes).unwrap();

        assert_eq!(commit.ver, 2);
        assert_eq!(
            commit.space.as_ref().map(|s| s.as_str()),
            Some(space_str.as_str())
        );
        assert_eq!(
            commit.did.as_ref().map(|d| d.as_str()),
            Some(author_str.as_str())
        );
        assert_eq!(commit.rev.as_str(), rev_str.as_str());
        assert_eq!(
            commit.prev_rev.as_ref().map(|r| r.as_str()),
            Some(prev_rev_str.as_str())
        );
        assert_eq!(commit.hash.as_ref(), &hash_bytes);
        assert_eq!(
            commit.prev_hash.as_ref().map(|h| h.as_ref()),
            Some(prev_hash_bytes.as_slice())
        );
        assert_eq!(commit.path.as_deref(), Some(path_str.as_str()));
        assert_eq!(commit.action.as_deref(), Some(action_str.as_str()));
        assert_eq!(commit.cid.as_ref().map(|c| c.as_str()), cid_str.as_deref());
        assert_eq!(
            commit.prev_cid.as_ref().map(|c| c.as_str()),
            prev_cid_str.as_deref()
        );
        assert_eq!(
            commit.val.as_ref().map(|v| v.as_ref()),
            Some(val_bytes.as_ref())
        );

        verify_commit_v2(&commit, &context, &parsed_key).expect("Ed25519 v2 commit must verify");

        // Re-encode to CBOR and check exact byte match
        let re_encoded = serde_ipld_dagcbor::to_vec(&commit).unwrap();
        assert_eq!(re_encoded, cbor_bytes, "Ed25519 CBOR roundtrip mismatch");
    }

    // P-256
    {
        let p256_info = &curves["p256"];
        let pub_hex = p256_info["public_key_hex"].as_str().unwrap();
        let pub_bytes = hex_to_bytes(pub_hex);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pub_bytes).unwrap();
        let parsed_key = ParsedVerifyingKey::P256(vk);

        let cbor_hex = p256_info["cbor_hex"].as_str().unwrap();
        let cbor_bytes = hex_to_bytes(cbor_hex);
        let commit: SignedCommit = serde_ipld_dagcbor::from_slice(&cbor_bytes).unwrap();

        assert_eq!(commit.ver, 2);
        verify_commit_v2(&commit, &context, &parsed_key).expect("P-256 v2 commit must verify");

        let re_encoded = serde_ipld_dagcbor::to_vec(&commit).unwrap();
        assert_eq!(re_encoded, cbor_bytes, "P-256 CBOR roundtrip mismatch");
    }

    // secp256k1
    {
        let k256_info = &curves["secp256k1"];
        let pub_hex = k256_info["public_key_hex"].as_str().unwrap();
        let pub_bytes = hex_to_bytes(pub_hex);
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pub_bytes).unwrap();
        let parsed_key = ParsedVerifyingKey::Secp256k1(vk);

        let cbor_hex = k256_info["cbor_hex"].as_str().unwrap();
        let cbor_bytes = hex_to_bytes(cbor_hex);
        let commit: SignedCommit = serde_ipld_dagcbor::from_slice(&cbor_bytes).unwrap();

        assert_eq!(commit.ver, 2);
        verify_commit_v2(&commit, &context, &parsed_key).expect("secp256k1 v2 commit must verify");

        let re_encoded = serde_ipld_dagcbor::to_vec(&commit).unwrap();
        assert_eq!(re_encoded, cbor_bytes, "secp256k1 CBOR roundtrip mismatch");
    }
}

#[test]
fn commit_v2_omission_vectors_fail() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE_JSON).unwrap();
    let ctx_val = &fixture["context"];

    let space_str = ctx_val["space"].as_str().unwrap().to_string();
    let author_str = ctx_val["author"].as_str().unwrap().to_string();
    let rev_str = ctx_val["rev"].as_str().unwrap().to_string();
    let prev_rev_str = ctx_val["prevRev"].as_str().unwrap().to_string();
    let hash_bytes: [u8; 32] = hex_to_bytes(ctx_val["hash"].as_str().unwrap())
        .try_into()
        .unwrap();
    let prev_hash_bytes: [u8; 32] = hex_to_bytes(ctx_val["prevHash"].as_str().unwrap())
        .try_into()
        .unwrap();
    let path_str = ctx_val["path"].as_str().unwrap().to_string();
    let action_str = ctx_val["action"].as_str().unwrap().to_string();
    let cid_str = ctx_val["cid"].as_str().map(|s| s.to_string());
    let prev_cid_str = ctx_val["prevCid"].as_str().map(|s| s.to_string());
    let val_bytes = Bytes::copy_from_slice(ctx_val["val"].as_str().unwrap().as_bytes());

    let p256_info = &fixture["curves"]["p256"];
    let pub_hex = p256_info["public_key_hex"].as_str().unwrap();
    let pub_bytes = hex_to_bytes(pub_hex);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pub_bytes).unwrap();
    let parsed_key = ParsedVerifyingKey::P256(vk);

    let cbor_hex = p256_info["cbor_hex"].as_str().unwrap();
    let base_commit: SignedCommit =
        serde_ipld_dagcbor::from_slice(&hex_to_bytes(cbor_hex)).unwrap();

    let omissions = fixture["omission_vectors"].as_array().unwrap();
    for item in omissions {
        let name = item["name"].as_str().unwrap();
        let expected_err = item["expected_error"].as_str().unwrap();
        let mut test_commit = base_commit.clone();

        let mut test_ctx = CommitContextV2 {
            space: space_str.clone(),
            author: author_str.clone(),
            rev: rev_str.clone(),
            prev_rev: prev_rev_str.clone(),
            hash: hash_bytes,
            prev_hash: prev_hash_bytes,
            path: path_str.clone(),
            action: action_str.clone(),
            cid: cid_str.clone(),
            prev_cid: prev_cid_str.clone(),
            val: val_bytes.clone(),
        };

        if let Some(action) = item.get("action").and_then(|a| a.as_str()) {
            test_commit.action = Some(action.to_string().into());
            test_ctx.action = action.to_string();
            if action == "update" {
                test_commit.prev_cid = Some(
                    "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
                        .to_string()
                        .into(),
                );
                test_ctx.prev_cid =
                    Some("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454".to_string());
            } else if action == "delete" {
                test_commit.cid = None;
                test_ctx.cid = None;
                test_commit.prev_cid = Some(
                    "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
                        .to_string()
                        .into(),
                );
                test_ctx.prev_cid =
                    Some("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454".to_string());
            }
        }

        if let Some(omitted) = item.get("omitted_field").and_then(|o| o.as_str()) {
            match omitted {
                "did" => test_commit.did = None,
                "space" => test_commit.space = None,
                "prev_rev" => test_commit.prev_rev = None,
                "prev_hash" => test_commit.prev_hash = None,
                "path" => test_commit.path = None,
                "action" => test_commit.action = None,
                "cid" => test_commit.cid = None,
                "prev_cid" => test_commit.prev_cid = None,
                "val" => test_commit.val = None,
                other => panic!("Unknown omitted field {other}"),
            }
        }

        if let Some(illegal) = item.get("illegal_field").and_then(|i| i.as_str()) {
            match illegal {
                "prev_cid" => {
                    test_commit.prev_cid = Some(
                        "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
                            .to_string()
                            .into(),
                    )
                }
                "cid" => {
                    test_commit.cid = Some(
                        "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
                            .to_string()
                            .into(),
                    )
                }
                other => panic!("Unknown illegal field {other}"),
            }
        }

        let res = verify_commit_v2(&test_commit, &test_ctx, &parsed_key);
        assert!(
            res.is_err(),
            "Omission vector '{name}' must fail, but succeeded"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains(expected_err),
            "Omission vector '{name}': expected error containing '{expected_err}', got '{err_msg}'"
        );
    }
}

#[test]
fn commit_v2_policy_verification() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE_JSON).unwrap();
    let p256_info = &fixture["curves"]["p256"];
    let pub_hex = p256_info["public_key_hex"].as_str().unwrap();
    let pub_bytes = hex_to_bytes(pub_hex);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pub_bytes).unwrap();
    let parsed_key = ParsedVerifyingKey::P256(vk);

    let cbor_hex = p256_info["cbor_hex"].as_str().unwrap();
    let v2_commit: SignedCommit = serde_ipld_dagcbor::from_slice(&hex_to_bytes(cbor_hex)).unwrap();

    let ctx_val = &fixture["context"];
    let context_v2 = CommitContextV2 {
        space: ctx_val["space"].as_str().unwrap().to_string(),
        author: ctx_val["author"].as_str().unwrap().to_string(),
        rev: ctx_val["rev"].as_str().unwrap().to_string(),
        prev_rev: ctx_val["prevRev"].as_str().unwrap().to_string(),
        hash: hex_to_bytes(ctx_val["hash"].as_str().unwrap())
            .try_into()
            .unwrap(),
        prev_hash: hex_to_bytes(ctx_val["prevHash"].as_str().unwrap())
            .try_into()
            .unwrap(),
        path: ctx_val["path"].as_str().unwrap().to_string(),
        action: ctx_val["action"].as_str().unwrap().to_string(),
        cid: ctx_val["cid"].as_str().map(|s| s.to_string()),
        prev_cid: ctx_val["prevCid"].as_str().map(|s| s.to_string()),
        val: Bytes::copy_from_slice(ctx_val["val"].as_str().unwrap().as_bytes()),
    };

    // StrictV2 accepts valid v2 commit
    assert!(verify_commit_with_policy(
        &v2_commit,
        None,
        Some(&context_v2),
        &parsed_key,
        &CommitVerificationPolicy::StrictV2
    )
    .is_ok());

    // Fake v1 commit
    let v1_commit = SignedCommit {
        ver: 1,
        rev: "3jzfcijpj2m2a".to_string().into(),
        prev_rev: None,
        did: None,
        space: None,
        hash: Bytes::copy_from_slice(&[0x42; 32]),
        prev_hash: None,
        path: None,
        action: None,
        cid: None,
        prev_cid: None,
        val: None,
        sig: Bytes::copy_from_slice(&[0u8; 64]),
        ikm: Some(Bytes::copy_from_slice(&[0u8; 32])),
        mac: Some(Bytes::copy_from_slice(&[0u8; 32])),
        extra_data: None,
    };

    // StrictV2 rejects v1 commit
    let err = verify_commit_with_policy(
        &v1_commit,
        None,
        None,
        &parsed_key,
        &CommitVerificationPolicy::StrictV2,
    )
    .unwrap_err();
    assert!(err.to_string().contains("StrictV2"));

    // DualReadWithCutoff rejects when rev > cutoff
    let err = verify_commit_with_policy(
        &v1_commit,
        None,
        None,
        &parsed_key,
        &CommitVerificationPolicy::DualReadWithCutoff {
            cutoff_rev: "3jzfcijpj2m20".to_string(),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("exceeds allowed cutoff"));
}
#[test]
fn commit_v2_invalid_cid_rejected() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE_JSON).unwrap();
    let p256_info = &fixture["curves"]["p256"];
    let pub_bytes = hex_to_bytes(p256_info["public_key_hex"].as_str().unwrap());
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pub_bytes).unwrap();
    let parsed_key = ParsedVerifyingKey::P256(vk);

    let cbor_hex = p256_info["cbor_hex"].as_str().unwrap();
    let mut commit: SignedCommit = serde_ipld_dagcbor::from_slice(&hex_to_bytes(cbor_hex)).unwrap();

    let ctx_val = &fixture["context"];
    let mut context_v2 = CommitContextV2 {
        space: ctx_val["space"].as_str().unwrap().to_string(),
        author: ctx_val["author"].as_str().unwrap().to_string(),
        rev: ctx_val["rev"].as_str().unwrap().to_string(),
        prev_rev: ctx_val["prevRev"].as_str().unwrap().to_string(),
        hash: hex_to_bytes(ctx_val["hash"].as_str().unwrap())
            .try_into()
            .unwrap(),
        prev_hash: hex_to_bytes(ctx_val["prevHash"].as_str().unwrap())
            .try_into()
            .unwrap(),
        path: ctx_val["path"].as_str().unwrap().to_string(),
        action: ctx_val["action"].as_str().unwrap().to_string(),
        cid: ctx_val["cid"].as_str().map(|s| s.to_string()),
        prev_cid: ctx_val["prevCid"].as_str().map(|s| s.to_string()),
        val: Bytes::copy_from_slice(ctx_val["val"].as_str().unwrap().as_bytes()),
    };

    // Set invalid CID (non-CID string that would bypass naive Cid::from_str)
    commit.cid = Some("not-a-valid-cid-at-all".to_string().into());
    context_v2.cid = Some("not-a-valid-cid-at-all".to_string());

    let err = verify_commit_v2(&commit, &context_v2, &parsed_key).unwrap_err();
    assert!(err.to_string().contains("invalid CID"));
}

#[test]
fn commit_v2_non_monotonic_revisions_fail() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE_JSON).unwrap();
    let p256_info = &fixture["curves"]["p256"];
    let pub_bytes = hex_to_bytes(p256_info["public_key_hex"].as_str().unwrap());
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pub_bytes).unwrap();
    let parsed_key = ParsedVerifyingKey::P256(vk);

    let cbor_hex = p256_info["cbor_hex"].as_str().unwrap();
    let mut commit: SignedCommit = serde_ipld_dagcbor::from_slice(&hex_to_bytes(cbor_hex)).unwrap();

    let ctx_val = &fixture["context"];
    let context_v2 = CommitContextV2 {
        space: ctx_val["space"].as_str().unwrap().to_string(),
        author: ctx_val["author"].as_str().unwrap().to_string(),
        rev: "3jzfcijpj2m22".to_string(), // older than prevRev "3jzfcijpj2m23"
        prev_rev: "3jzfcijpj2m23".to_string(),
        hash: hex_to_bytes(ctx_val["hash"].as_str().unwrap())
            .try_into()
            .unwrap(),
        prev_hash: hex_to_bytes(ctx_val["prevHash"].as_str().unwrap())
            .try_into()
            .unwrap(),
        path: ctx_val["path"].as_str().unwrap().to_string(),
        action: ctx_val["action"].as_str().unwrap().to_string(),
        cid: ctx_val["cid"].as_str().map(|s| s.to_string()),
        prev_cid: ctx_val["prevCid"].as_str().map(|s| s.to_string()),
        val: Bytes::copy_from_slice(ctx_val["val"].as_str().unwrap().as_bytes()),
    };
    commit.rev = "3jzfcijpj2m22".to_string().into();
    commit.prev_rev = Some("3jzfcijpj2m23".to_string().into());

    let err = verify_commit_v2(&commit, &context_v2, &parsed_key).unwrap_err();
    assert!(err.to_string().contains("non-monotonic revision"));
}

#[test]
fn commit_v2_finding_6_mac_recomputation_attack_fails() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE_JSON).unwrap();
    let p256_info = &fixture["curves"]["p256"];
    let pub_bytes = hex_to_bytes(p256_info["public_key_hex"].as_str().unwrap());
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pub_bytes).unwrap();
    let parsed_key = ParsedVerifyingKey::P256(vk);

    let cbor_hex = p256_info["cbor_hex"].as_str().unwrap();
    let mut commit: SignedCommit = serde_ipld_dagcbor::from_slice(&hex_to_bytes(cbor_hex)).unwrap();

    let ctx_val = &fixture["context"];
    let context_v2 = CommitContextV2 {
        space: ctx_val["space"].as_str().unwrap().to_string(),
        author: ctx_val["author"].as_str().unwrap().to_string(),
        rev: ctx_val["rev"].as_str().unwrap().to_string(),
        prev_rev: ctx_val["prevRev"].as_str().unwrap().to_string(),
        hash: [0x99; 32], // Attacker substitutes new hash
        prev_hash: hex_to_bytes(ctx_val["prevHash"].as_str().unwrap())
            .try_into()
            .unwrap(),
        path: ctx_val["path"].as_str().unwrap().to_string(),
        action: ctx_val["action"].as_str().unwrap().to_string(),
        cid: ctx_val["cid"].as_str().map(|s| s.to_string()),
        prev_cid: ctx_val["prevCid"].as_str().map(|s| s.to_string()),
        val: Bytes::copy_from_slice(ctx_val["val"].as_str().unwrap().as_bytes()),
    };
    commit.hash = Bytes::copy_from_slice(&[0x99; 32]);

    // Under v2, the hash is directly bound into the signature transcript.
    // Even if an attacker provides IKM and recomputes HMAC, the v2 signature check fails!
    let err = verify_commit_v2(&commit, &context_v2, &parsed_key).unwrap_err();
    assert!(err.to_string().contains("signature mismatch"));
}

#[test]
fn car_length_checked_decoding_and_limits() {
    use circle_appview::commit::{decode_repo_car, decode_varint, MAX_CAR_BYTES};

    // 1. Truncated CAR header returns error, never panics
    let truncated = [0x0a, 0x01, 0x02];
    assert!(decode_repo_car(&truncated).is_err());

    // 2. Malformed varint (too many bytes with continuation bit)
    let malformed_varint = [0x80; 12];
    assert!(decode_varint(&malformed_varint).is_err());

    // 3. Exceeds MAX_CAR_BYTES
    let huge_dummy = vec![0u8; MAX_CAR_BYTES + 1];
    assert!(decode_repo_car(&huge_dummy).is_err());
}

#[test]
fn car_adversarial_ordering_linear_indexing() {
    use circle_appview::commit::{
        compute_dagcbor_cid, decode_repo_car, extract_and_validate_car, mint_repo_car,
        mint_signed_commit_v2_p256, parse_permissioned_car, LtHash, RepoRecord,
    };
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    let signing_key = SigningKey::random(&mut OsRng);
    let vk = signing_key.verifying_key();
    let parsed_key = ParsedVerifyingKey::P256(*vk);

    let space_uri = "at://did:plc:space1/space/blue.catbird.circle/demo";
    let author_did = "did:plc:author1";

    let val1 = serde_json::json!({"$type": "app.bsky.feed.post", "text": "one"});
    let val2 = serde_json::json!({"$type": "app.bsky.feed.post", "text": "two"});
    let cid1 = compute_dagcbor_cid(&val1).unwrap();
    let cid2 = compute_dagcbor_cid(&val2).unwrap();

    let mut lthash = LtHash::default();
    lthash.add(&format!("app.bsky.feed.post/rkey1/{cid1}"));
    lthash.add(&format!("app.bsky.feed.post/rkey2/{cid2}"));

    let val_bytes = Bytes::from(serde_ipld_dagcbor::to_vec(&val2).unwrap());

    let ctx = CommitContextV2 {
        space: space_uri.to_string(),
        author: author_did.to_string(),
        rev: "3jzfcijpj2m2b".to_string(),
        prev_rev: "3jzfcijpj2m2a".to_string(),
        hash: lthash.digest(),
        prev_hash: [0x41; 32],
        path: "app.bsky.feed.post/rkey2".to_string(),
        action: "create".to_string(),
        cid: Some(cid2.clone()),
        prev_cid: None,
        val: val_bytes,
    };

    let commit = mint_signed_commit_v2_p256(&ctx, &signing_key).unwrap();
    let rec1 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "rkey1".to_string(),
        cid: cid1.clone(),
        value: val1,
    };
    let rec2 = RepoRecord {
        collection: "app.bsky.feed.post".to_string(),
        rkey: "rkey2".to_string(),
        cid: cid2.clone(),
        value: val2,
    };

    let car_bytes = mint_repo_car(&commit, &[rec1, rec2]).unwrap();
    let decoded = decode_repo_car(&car_bytes).unwrap();
    assert_eq!(decoded.records.len(), 2);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let parsed_car = rt.block_on(parse_permissioned_car(&car_bytes)).unwrap();
    let (verified_commit, records, verified_lthash) =
        extract_and_validate_car(&parsed_car, space_uri, author_did, &parsed_key).unwrap();
    assert_eq!(verified_commit.ver, 2);
    assert_eq!(records.len(), 2);
    assert_eq!(verified_lthash.digest(), lthash.digest());
}
