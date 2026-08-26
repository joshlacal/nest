//! Guards the `.env.example` against silently dropping required variables.
//!
//! `Config::from_env` fails startup when any required non-push variable is
//! unset (see `src/config.rs`). If a future edit rewrites the example and
//! drops one of them, an operator copying the example would hit a confusing
//! startup failure — so this test fails when a required variable is missing
//! from the documented example.

fn example() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/.env.example"))
        .expect(".env.example must exist at crate root")
}

fn documented(var: &str) -> bool {
    example()
        .lines()
        .any(|line| line.starts_with(var) && line[var.len()..].starts_with('='))
}

/// Every variable `Config::from_env` treats as required (no default) must be
/// present as an uncommented assignment so copying `.env.example` works.
#[test]
fn env_example_documents_all_required_variables() {
    for var in [
        "CIRCLE_MEDIA_BASE_URL",
    ] {
        assert!(
            documented(var),
            "required variable {var} is missing from .env.example; Config::from_env fails without it"
        );
    }
}

/// The base/defaulted variables must also be documented so the example is a
/// faithful copy of the configuration surface.
#[test]
fn env_example_documents_base_variables() {
    for var in [
        "CIRCLE_APPVIEW_HOST",
        "CIRCLE_APPVIEW_PORT",
        "DATABASE_URL",
        "SERVICE_DID",
        "APPVIEW_BASE_URL",
        "APPVIEW_CLIENT_ID",
        "PLC_DIRECTORY_URL",
        "PUBLIC_APPVIEW_URL",
        "RUST_LOG",
    ] {
        assert!(
            documented(var),
            "base variable {var} is missing from .env.example"
        );
    }
}

/// The direct push block must remain documented alongside the base vars.
#[test]
fn env_example_documents_push_block() {
    let example = example();
    for var in [
        "PUSH_URL",
        "PUSH_AUDIENCE",
        "PUSH_KEY_ID",
        "PUSH_SIGNING_KEY_PATH",
        "PUSH_SIGNING_KEY_HEX",
    ] {
        assert!(
            example.contains(var),
            "push variable {var} is missing from .env.example push block"
        );
    }
}

/// Verify that .env.example contains no stale singular #atproto_circle references.
#[test]
fn env_example_uses_atproto_circles_plural() {
    let example = example();
    assert!(
        !example.contains("#atproto_circle\n") && !example.contains("#atproto_circle "),
        ".env.example must not contain stale singular #atproto_circle references"
    );
    assert!(
        example.contains("SERVICE_DID=did:web:circles.catbird.blue#atproto_circles"),
        ".env.example must use #atproto_circles for SERVICE_DID"
    );
}
