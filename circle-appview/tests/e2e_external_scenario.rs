//! Integration test entrypoint for the live multi-user external scenario.
//!
//! Run with:
//! ```bash
//! cargo test --test e2e_external_scenario -- --ignored --nocapture
//! ```

use std::process::Command;

#[test]
#[ignore = "requires live external services (PDS, Nest, AppView)"]
fn live_external_scenario_execution() {
    let status = Command::new(env!("CARGO_BIN_EXE_e2e_external_scenario"))
        .status()
        .expect("Failed to execute e2e_external_scenario binary");

    assert!(
        status.success(),
        "Live external scenario failed with exit code: {:?}",
        status.code()
    );
}

#[test]
fn test_e2e_scenario_rejects_non_loopback_http() {
    let output = Command::new(env!("CARGO_BIN_EXE_e2e_external_scenario"))
        .env("NEST_URL", "http://192.168.1.1:3000")
        .env("CIRCLE_APPVIEW_URL", "http://127.0.0.1:3002")
        .env(
            "CIRCLE_APPVIEW_SERVICE_DID",
            "did:web:circles.catbird.blue#atproto_circles",
        )
        .env("PUBLIC_APPVIEW_URL", "https://public.api.bsky.app")
        .env("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
        .env("ALICE_DID", "did:plc:alice")
        .env("ALICE_SESSION_ID", "sess_alice")
        .env("ALICE_PDS_URL", "http://127.0.0.1:3001")
        .env("BOB_DID", "did:plc:bob")
        .env("BOB_SESSION_ID", "sess_bob")
        .env("BOB_PDS_URL", "http://127.0.0.1:3001")
        .env("CAROL_DID", "did:plc:carol")
        .env("CAROL_SESSION_ID", "sess_carol")
        .env("CAROL_PDS_URL", "http://127.0.0.1:3001")
        .env("DAVE_DID", "did:plc:dave")
        .env("DAVE_SESSION_ID", "sess_dave")
        .env("DAVE_PDS_URL", "http://127.0.0.1:3001")
        .env("ARTIFACTS_DIR", "/tmp")
        .output()
        .expect("Failed to execute e2e_external_scenario binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "Must exit with code 2 for invalid non-loopback HTTP config"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("non-loopback"),
        "Stderr must explain non-loopback HTTP restriction: {stderr}"
    );
}
