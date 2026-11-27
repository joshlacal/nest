//! Cross-language conformance: `circle-appview` against the Spaces v1 vectors that Petrel
//! checks in under `petrel-spaces/tests/vectors/` (Nov 24 `at:space/` form). The same
//! file drives Petrel's Rust and Swift conformance suites.
use circle_appview::{
    commit::LtHash,
    space_mac::{derive_secret, verify_commit, verify_record, Commit, MacProfile, MacRequest},
    space_signature::p256_did_key,
    space_star::{parse_repo_star, read_commit},
};
use p256::{ecdsa::SigningKey, SecretKey};
use petrel_core::Tid;
use serde_json::Value;

const VECTORS: &str = include_str!(concat!(
    "../../../Petrel/rust/petrel-spaces/tests/vectors/",
    "atproto",
    "_spaces_v1.json"
));

fn decode_hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn text<'a>(v: &'a Value, path: &str) -> &'a str {
    path.split('.')
        .fold(v, |node, key| &node[key])
        .as_str()
        .unwrap_or_else(|| panic!("vector field {path} is not a string"))
}

fn hex(v: &Value, path: &str) -> Vec<u8> {
    decode_hex(text(v, path))
}

#[test]
fn circle_appview_conforms_to_spaces_v1_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vector file parses");
    assert_eq!(vectors["version"], 1);

    // 1. LtHash
    let mut lt = LtHash::default();
    assert_eq!(
        lt.digest().as_slice(),
        hex(&vectors, "lthash.empty_commitment_hex").as_slice()
    );
    lt.add_entry(
        text(&vectors, "lthash.record_a.path"),
        text(&vectors, "lthash.record_a.cid"),
    );
    assert_eq!(
        lt.digest().as_slice(),
        hex(&vectors, "lthash.only_a_commitment_hex").as_slice()
    );
    lt.add_entry(
        text(&vectors, "lthash.record_b.path"),
        text(&vectors, "lthash.record_b.cid"),
    );
    assert_eq!(
        lt.digest().as_slice(),
        hex(&vectors, "lthash.combined_ab_commitment_hex").as_slice()
    );
    lt.remove_entry(
        text(&vectors, "lthash.record_a.path"),
        text(&vectors, "lthash.record_a.cid"),
    );
    assert_eq!(
        lt.digest().as_slice(),
        hex(&vectors, "lthash.after_remove_a_commitment_hex").as_slice()
    );
    // The element key the accumulator commits to is `{path}/{cid}`.
    assert_eq!(
        circle_appview::commit::format_lthash_element(
            text(&vectors, "lthash.record_a.collection"),
            text(&vectors, "lthash.record_a.rkey"),
            text(&vectors, "lthash.record_a.cid"),
        ),
        text(&vectors, "lthash.record_a.element_key")
    );

    // 2. DHKEM(P-256) HPKE RFC 9180 secret export
    let author_sk = SecretKey::from_slice(&hex(&vectors, "kem_p256.author_secret_hex")).unwrap();
    let eph_sk = SecretKey::from_slice(&hex(&vectors, "kem_p256.ephemeral_secret_hex")).unwrap();
    let shared = derive_secret(
        &author_sk,
        &eph_sk.public_key(),
        &eph_sk.public_key(),
        &author_sk.public_key(),
    )
    .unwrap();
    assert_eq!(
        shared.as_slice(),
        hex(&vectors, "kem_p256.shared_secret_hex").as_slice()
    );

    // 3. Commit MAC (RFC 9421 Signature-Input + Signature over Atproto-Space-Commit)
    let commit_secret: [u8; 32] = hex(&vectors, "commit_mac.shared_secret_hex")
        .try_into()
        .unwrap();
    let commit = Commit {
        space: petrel_core::SpaceRef::parse(text(&vectors, "commit_mac.space")).unwrap(),
        repo: petrel_core::Did::parse(text(&vectors, "commit_mac.repo")).unwrap(),
        rev: Tid::parse(text(&vectors, "commit_mac.rev")).unwrap(),
        data: petrel_core::Bytes(hex(&vectors, "commit_mac.data_hex")),
        ver: 1,
        extra_data: None,
    };
    let commit_req = MacRequest {
        key_share: text(&vectors, "kem_p256.key_share_did_key").to_owned(),
        shared_secret: commit_secret,
        profile: MacProfile::Commit,
    };
    let mut commit_headers = reqwest::header::HeaderMap::new();
    commit_headers.insert(
        "atproto-space-commit",
        text(&vectors, "commit_mac.covered_header").parse().unwrap(),
    );
    commit_headers.insert(
        "signature-input",
        text(&vectors, "commit_mac.signature_input")
            .parse()
            .unwrap(),
    );
    commit_headers.insert(
        "signature",
        text(&vectors, "commit_mac.signature").parse().unwrap(),
    );
    verify_commit(
        &commit,
        text(&vectors, "commit_mac.space"),
        text(&vectors, "commit_mac.repo"),
        &commit_req,
        &commit_headers,
    )
    .expect("commit MAC verifies");

    // 4. Record MAC (RFC 9421 Signature-Input + Signature over Atproto-Space-Record)
    let record_secret: [u8; 32] = hex(&vectors, "record_mac.shared_secret_hex")
        .try_into()
        .unwrap();
    let record_bytes = hex(&vectors, "lthash.record_b.dagcbor_hex");
    let cid = petrel_core::Cid::parse(text(&vectors, "record_mac.cid")).unwrap();
    let record_uri = text(&vectors, "record_mac.record_uri");
    let record_req = MacRequest {
        key_share: text(&vectors, "kem_p256.key_share_did_key").to_owned(),
        shared_secret: record_secret,
        profile: MacProfile::Record,
    };
    let mut record_headers = reqwest::header::HeaderMap::new();
    record_headers.insert(
        "atproto-space-record",
        text(&vectors, "record_mac.covered_header").parse().unwrap(),
    );
    record_headers.insert(
        "signature-input",
        text(&vectors, "record_mac.signature_input")
            .parse()
            .unwrap(),
    );
    record_headers.insert(
        "signature",
        text(&vectors, "record_mac.signature").parse().unwrap(),
    );
    verify_record(
        record_uri,
        record_uri,
        &cid,
        &record_bytes,
        &record_req,
        &record_headers,
    )
    .expect("record MAC verifies");
    assert!(
        verify_record(
            record_uri,
            record_uri,
            &cid,
            &hex(&vectors, "lthash.record_a.dagcbor_hex"),
            &record_req,
            &record_headers,
        )
        .is_err(),
        "body/CID mismatch must fail record MAC verification"
    );

    // 5. P-256 did:key + RFC 9421 verification (low-S & high-S)
    let cnf_sk = SigningKey::from_slice(&hex(&vectors, "rfc9421_low_s.cnf_secret_hex")).unwrap();
    assert_eq!(
        p256_did_key(cnf_sk.verifying_key()),
        text(&vectors, "rfc9421_low_s.cnf_did_key")
    );
    for name in ["rfc9421_low_s", "rfc9421_high_s"] {
        let v = &vectors[name];
        let created = v["created"].as_i64().unwrap();
        petrel_spaces::verify_http_signature_against_key(
            text(v, "authorization"),
            text(v, "atproto_space_audience"),
            text(v, "signature_input"),
            text(v, "signature"),
            text(v, "audience_did"),
            text(v, "cnf_did_key"),
            created + 1,
            300,
            60,
            512,
        )
        .unwrap_or_else(|e| panic!("RFC 9421 {name} signature verifies: {e}"));
    }

    // 6. STAR v0.2 empty + populated archives
    let empty_snap = parse_repo_star(
        &hex(&vectors, "star_repo.empty_swan_archive_hex"),
        text(&vectors, "star_repo.empty_swan_space"),
        text(&vectors, "star_repo.empty_swan_repo"),
    )
    .expect("empty Swan STAR archive parses");
    assert!(empty_snap.records.is_empty());

    let pop_bytes = hex(&vectors, "star_repo.populated_archive_hex");
    let head = read_commit(
        &pop_bytes,
        text(&vectors, "star_repo.populated_space"),
        text(&vectors, "star_repo.populated_repo"),
    )
    .expect("STAR metadata header parses");
    assert_eq!(head.rev.as_str(), text(&vectors, "star_repo.populated_rev"));

    let pop_snap = parse_repo_star(
        &pop_bytes,
        text(&vectors, "star_repo.populated_space"),
        text(&vectors, "star_repo.populated_repo"),
    )
    .expect("populated STAR archive parses");
    assert_eq!(pop_snap.records.len(), 2);
    assert_eq!(
        pop_snap.lthash.digest().as_slice(),
        hex(&vectors, "star_repo.populated_data_hex").as_slice()
    );
}
