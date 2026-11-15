//! Cross-language conformance test verifying `circle-appview` against `AtprotoSpacesVectorsV2`.
use atproto_spaces::vectors::generate_v2_vectors;
use bytes::Bytes;
use catbird_atproto::jacquard_common::types::string::Tid;
use circle_appview::{
    commit::LtHash,
    space_mac::{derive_secret, verify_commit, verify_record, Commit, MacProfile, MacRequest},
    space_signature::p256_did_key,
    space_star::{parse_repo_star, read_commit},
};
use p256::{ecdsa::SigningKey, SecretKey};

fn decode_hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn circle_appview_conforms_to_atproto_spaces_v2_vectors() {
    let vectors = generate_v2_vectors().expect("deterministic v2 vectors");
    assert_eq!(vectors.version, 2);

    // 1. LtHash
    let mut lt = LtHash::default();
    assert_eq!(
        lt.digest().as_slice(),
        decode_hex(&vectors.lthash.empty_commitment_hex).as_slice()
    );
    lt.add(&vectors.lthash.record_a.element_key);
    assert_eq!(
        lt.digest().as_slice(),
        decode_hex(&vectors.lthash.only_a_commitment_hex).as_slice()
    );
    lt.add(&vectors.lthash.record_b.element_key);
    assert_eq!(
        lt.digest().as_slice(),
        decode_hex(&vectors.lthash.combined_ab_commitment_hex).as_slice()
    );
    lt.remove(&vectors.lthash.record_a.element_key);
    assert_eq!(
        lt.digest().as_slice(),
        decode_hex(&vectors.lthash.after_remove_a_commitment_hex).as_slice()
    );

    // 2. DHKEM(P-256) HPKE RFC 9180 secret export
    let author_sk =
        SecretKey::from_slice(&decode_hex(&vectors.kem_p256.author_secret_hex)).unwrap();
    let eph_sk =
        SecretKey::from_slice(&decode_hex(&vectors.kem_p256.ephemeral_secret_hex)).unwrap();
    let shared = derive_secret(
        &author_sk,
        &eph_sk.public_key(),
        &eph_sk.public_key(),
        &author_sk.public_key(),
    )
    .unwrap();
    assert_eq!(
        shared.as_slice(),
        decode_hex(&vectors.kem_p256.shared_secret_hex).as_slice()
    );

    // 3. Commit MAC (RFC 9421 Signature-Input + Signature over Atproto-Space-Commit)
    let commit_secret: [u8; 32] = decode_hex(&vectors.commit_mac.shared_secret_hex)
        .try_into()
        .unwrap();
    let commit_data: [u8; 32] = decode_hex(&vectors.commit_mac.data_hex).try_into().unwrap();
    let commit = Commit {
        space: catbird_atproto::jacquard_common::types::aturi::AtSpaceUri::new_owned(
            &vectors.commit_mac.space,
        )
        .unwrap(),
        repo: vectors.commit_mac.repo.clone().into(),
        rev: Tid::new(&vectors.commit_mac.rev).unwrap(),
        data: Bytes::copy_from_slice(&commit_data),
        ver: 1,
        extra_data: None,
    };
    let commit_req = MacRequest {
        key_share: vectors.kem_p256.key_share_did_key.clone(),
        shared_secret: commit_secret,
        profile: MacProfile::Commit,
    };
    let mut commit_headers = reqwest::header::HeaderMap::new();
    commit_headers.insert(
        "atproto-space-commit",
        vectors.commit_mac.covered_header.parse().unwrap(),
    );
    commit_headers.insert(
        "signature-input",
        vectors.commit_mac.signature_input.parse().unwrap(),
    );
    commit_headers.insert("signature", vectors.commit_mac.signature.parse().unwrap());
    verify_commit(
        &commit,
        &vectors.commit_mac.space,
        &vectors.commit_mac.repo,
        &commit_req,
        &commit_headers,
    )
    .expect("commit MAC verifies");

    // 4. Record MAC (RFC 9421 Signature-Input + Signature over Atproto-Space-Record)
    let record_secret: [u8; 32] = decode_hex(&vectors.record_mac.shared_secret_hex)
        .try_into()
        .unwrap();
    let record_bytes = decode_hex(&vectors.lthash.record_b.dagcbor_hex);
    let cid: cid::Cid = vectors.record_mac.cid.parse().unwrap();
    let record_req = MacRequest {
        key_share: vectors.kem_p256.key_share_did_key.clone(),
        shared_secret: record_secret,
        profile: MacProfile::Record,
    };
    let mut record_headers = reqwest::header::HeaderMap::new();
    record_headers.insert(
        "atproto-space-record",
        vectors.record_mac.covered_header.parse().unwrap(),
    );
    record_headers.insert(
        "signature-input",
        vectors.record_mac.signature_input.parse().unwrap(),
    );
    record_headers.insert("signature", vectors.record_mac.signature.parse().unwrap());
    verify_record(
        &vectors.record_mac.record_uri,
        &vectors.record_mac.record_uri,
        &cid,
        &record_bytes,
        &record_req,
        &record_headers,
    )
    .expect("record MAC verifies");
    assert!(
        verify_record(
            &vectors.record_mac.record_uri,
            &vectors.record_mac.record_uri,
            &cid,
            &decode_hex(&vectors.lthash.record_a.dagcbor_hex),
            &record_req,
            &record_headers,
        )
        .is_err(),
        "body/CID mismatch must fail record MAC verification"
    );

    // 5. P-256 did:key + RFC 9421 verification (low-S & high-S)
    let cnf_sk =
        SigningKey::from_slice(&decode_hex(&vectors.rfc9421_low_s.cnf_secret_hex)).unwrap();
    assert_eq!(
        p256_did_key(cnf_sk.verifying_key()),
        vectors.rfc9421_low_s.cnf_did_key
    );
    for vec9421 in [&vectors.rfc9421_low_s, &vectors.rfc9421_high_s] {
        let mut hm = axum::http::HeaderMap::new();
        hm.insert("authorization", vec9421.authorization.parse().unwrap());
        hm.insert(
            "atproto-space-audience",
            vec9421.atproto_space_audience.parse().unwrap(),
        );
        hm.insert("signature-input", vec9421.signature_input.parse().unwrap());
        hm.insert("signature", vec9421.signature.parse().unwrap());
        atproto_spaces::http_signature::verify_credential_request(
            &hm,
            &vec9421.cnf_did_key,
            vec9421.created + 1,
        )
        .expect("RFC 9421 low-S and high-S signatures verify");
    }

    // 6. STAR v0.2 empty + populated archives
    let empty_bytes = decode_hex(&vectors.star_repo.empty_swan_archive_hex);
    let empty_snap = parse_repo_star(
        &empty_bytes,
        &vectors.star_repo.empty_swan_space,
        &vectors.star_repo.empty_swan_repo,
    )
    .expect("empty Swan STAR archive parses");
    assert!(empty_snap.records.is_empty());

    let pop_bytes = decode_hex(&vectors.star_repo.populated_archive_hex);
    let head = read_commit(
        &pop_bytes,
        &vectors.star_repo.populated_space,
        &vectors.star_repo.populated_repo,
    )
    .expect("STAR metadata header parses");
    assert_eq!(head.rev.as_str(), vectors.star_repo.populated_rev);

    let pop_snap = parse_repo_star(
        &pop_bytes,
        &vectors.star_repo.populated_space,
        &vectors.star_repo.populated_repo,
    )
    .expect("populated STAR archive parses");
    assert_eq!(pop_snap.records.len(), 2);
    assert_eq!(
        pop_snap.lthash.digest().as_slice(),
        decode_hex(&vectors.star_repo.populated_data_hex).as_slice()
    );
}
