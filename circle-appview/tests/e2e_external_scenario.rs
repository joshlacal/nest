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
