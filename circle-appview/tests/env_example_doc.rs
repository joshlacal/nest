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
    let var = "CIRCLE_MEDIA_BASE_URL";
    assert!(
        documented(var),
        "required variable {var} is missing from .env.example; Config::from_env fails without it"
    );
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

/// Helper to match multi-wildcard globs in a single path segment (e.g. `*export*.json`, `config/local.*`).
fn match_glob_segment(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let first = parts[0];
    let last = parts[parts.len() - 1];
    if !text.starts_with(first) || !text.ends_with(last) {
        return false;
    }
    let mut remainder = &text[first.len()..text.len() - last.len()];
    for &part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = remainder.find(part) {
            remainder = &remainder[pos + part.len()..];
        } else {
            return false;
        }
    }
    true
}

/// Deterministic Dockerignore pattern matching implementing Docker semantics:
/// - Directory-only rule enforcement (`/` suffix).
/// - Recursive propagation of ignored directory prefixes to all descendants.
/// - Single-segment wildcard and subpath pattern matching.
/// - Sequential precedence with negation rules (`!`).
fn match_dockerignore_pattern(pattern: &str, path: &str) -> bool {
    let pattern = pattern.trim().trim_start_matches('/');
    let path = path.trim().trim_start_matches('/');

    let must_be_dir = pattern.ends_with('/');
    let pattern = pattern.trim_end_matches('/');

    let pat_segs: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if pat_segs.is_empty() || path_segs.is_empty() {
        return false;
    }

    fn seg_match(pat_segs: &[&str], path_segs: &[&str], pat_idx: usize, target_idx: usize) -> bool {
        if pat_idx == pat_segs.len() && target_idx == path_segs.len() {
            return true;
        }
        if pat_idx < pat_segs.len() && pat_segs[pat_idx] == "**" {
            for next_target in target_idx..=path_segs.len() {
                if seg_match(pat_segs, path_segs, pat_idx + 1, next_target) {
                    return true;
                }
            }
            return false;
        }
        if pat_idx < pat_segs.len()
            && target_idx < path_segs.len()
            && match_glob_segment(pat_segs[pat_idx], path_segs[target_idx])
        {
            return seg_match(pat_segs, path_segs, pat_idx + 1, target_idx + 1);
        }
        false
    }

    // Single-segment pattern (e.g. "*.pem", "artifacts", "*export*.json")
    if pat_segs.len() == 1 && pat_segs[0] != "**" {
        let single_pat = pat_segs[0];
        // Match filename if not must_be_dir
        if !must_be_dir && match_glob_segment(single_pat, path_segs[path_segs.len() - 1]) {
            return true;
        }
        // Match any ancestor directory
        for ancestor_seg in &path_segs[..path_segs.len() - 1] {
            if match_glob_segment(single_pat, ancestor_seg) {
                return true;
            }
        }
        return false;
    }

    // Multi-segment pattern
    // 1. Match full path
    if !must_be_dir && seg_match(&pat_segs, &path_segs, 0, 0) {
        return true;
    }
    // 2. Match any ancestor directory (prefix of path_segs)
    for end_idx in 1..path_segs.len() {
        let ancestor_segs = &path_segs[..end_idx];
        if seg_match(&pat_segs, ancestor_segs, 0, 0) {
            return true;
        }
    }
    // 3. Match suffix if pattern was relative inside a subtree (e.g. config/local.* inside a subfolder)
    for start_idx in 1..path_segs.len() {
        let sub_segs = &path_segs[start_idx..];
        if !must_be_dir && seg_match(&pat_segs, sub_segs, 0, 0) {
            return true;
        }
        for end_idx in start_idx + 1..path_segs.len() {
            let sub_ancestor = &path_segs[start_idx..end_idx];
            if seg_match(&pat_segs, sub_ancestor, 0, 0) {
                return true;
            }
        }
    }

    false
}

fn evaluate_dockerignore(rules_content: &str, path: &str) -> bool {
    let mut ignored = false;
    for line in rules_content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (is_negation, pattern) = if let Some(p) = line.strip_prefix('!') {
            (true, p.trim())
        } else {
            (false, line)
        };
        if match_dockerignore_pattern(pattern, path) {
            ignored = !is_negation;
        }
    }
    ignored
}
/// Verify that Dockerfile.dockerignore and .dockerignore contain all required secret/key/export exclusions,
/// and evaluate actual sequential ignore precedence in parent and crate contexts.
#[test]
fn test_dockerignore_rules_exclude_sensitive_files() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dockerfile_ignore_path = format!("{manifest_dir}/Dockerfile.dockerignore");
    let dockerfile_ignore = std::fs::read_to_string(&dockerfile_ignore_path)
        .expect("Dockerfile.dockerignore must exist at crate root");

    let dot_ignore_path = format!("{manifest_dir}/.dockerignore");
    let dot_ignore =
        std::fs::read_to_string(&dot_ignore_path).expect(".dockerignore must exist at crate root");

    for pattern in [
        "*.pem",
        "*.p8",
        "*.key",
        "*.der",
        "config/local.*",
        "sessions.json",
        "*export*.json",
        "artifacts/",
        ".env*",
    ] {
        assert!(
            dockerfile_ignore.contains(pattern),
            "Dockerfile.dockerignore missing required sensitive pattern: {pattern}"
        );
        assert!(
            dot_ignore.contains(pattern),
            ".dockerignore missing required sensitive pattern: {pattern}"
        );
    }

    // Evaluate parent-context Dockerfile.dockerignore effective inclusion/exclusion
    let parent_inclusions = [
        "nest/circle-appview/src/main.rs",
        "nest/circle-appview/Cargo.toml",
        "nest/circle-appview/Cargo.lock",
        "nest/circle-appview/.env.example",
        "catbird-atproto/src/lib.rs",
    ];
    for path in parent_inclusions {
        assert!(
            !evaluate_dockerignore(&dockerfile_ignore, path),
            "Parent context Dockerfile.dockerignore should INCLUDE {path}"
        );
    }

    let parent_exclusions = [
        "nest/circle-appview/.env",
        "nest/circle-appview/.env.production",
        "nest/circle-appview/server.key",
        "nest/circle-appview/private.pem",
        "nest/circle-appview/apns.p8",
        "nest/circle-appview/cert.der",
        "nest/circle-appview/cert.pfx",
        "nest/circle-appview/cert.p12",
        "nest/circle-appview/config/local.toml",
        "nest/circle-appview/config/local.json",
        "nest/circle-appview/sessions.json",
        "nest/circle-appview/data/sessions.json",
        "nest/circle-appview/session_export.json",
        "nest/circle-appview/exports/user_export_2026.json",
        "nest/circle-appview/artifacts/run_123/capture.json",
        "nest/circle-appview/data/local.sqlite",
        "nest/circle-appview/data/db.sqlite3",
        "nest/circle-appview/data/test.db",
        "other-service/secret.pem",
        "other-service/src/main.rs",
    ];
    for path in parent_exclusions {
        assert!(
            evaluate_dockerignore(&dockerfile_ignore, path),
            "Parent context Dockerfile.dockerignore should EXCLUDE {path}"
        );
    }

    // Evaluate crate-context .dockerignore effective inclusion/exclusion
    let crate_inclusions = ["src/main.rs", "Cargo.toml", "Cargo.lock", ".env.example"];
    for path in crate_inclusions {
        assert!(
            !evaluate_dockerignore(&dot_ignore, path),
            "Crate context .dockerignore should INCLUDE {path}"
        );
    }

    let crate_exclusions = [
        ".env",
        ".env.production",
        "server.key",
        "private.pem",
        "apns.p8",
        "cert.der",
        "cert.pfx",
        "cert.p12",
        "config/local.toml",
        "sessions.json",
        "session_export.json",
        "artifacts/run.json",
        "target/debug/app",
    ];
    for path in crate_exclusions {
        assert!(
            evaluate_dockerignore(&dot_ignore, path),
            "Crate context .dockerignore should EXCLUDE {path}"
        );
    }
}

#[test]
fn test_dockerignore_matcher_descendant_negation_and_glob_semantics() {
    // 1. Single-segment multi-wildcard globbing
    assert!(match_glob_segment("*export*.json", "export.json"));
    assert!(match_glob_segment("*export*.json", "user_export_2026.json"));
    assert!(match_glob_segment("*export*.json", "my_export_data.json"));
    assert!(!match_glob_segment("*export*.json", "export.txt"));
    assert!(!match_glob_segment("*export*.json", "export_json"));
    assert!(match_glob_segment("local.*", "local.toml"));
    assert!(match_glob_segment("local.*", "local.json"));
    assert!(!match_glob_segment("local.*", "remote.toml"));

    // 2. Descendant directory prefix propagation
    let dir_rules = "artifacts/\ntarget/\n";
    assert!(evaluate_dockerignore(dir_rules, "artifacts/build.log"));
    assert!(evaluate_dockerignore(
        dir_rules,
        "artifacts/sub/nested/file.txt"
    ));
    assert!(evaluate_dockerignore(
        dir_rules,
        "target/debug/circle_appview"
    ));
    assert!(evaluate_dockerignore(
        dir_rules,
        "target/release/deps/lib.rlib"
    ));
    assert!(!evaluate_dockerignore(dir_rules, "src/artifacts.rs"));

    // 3. Recursive globbing (**)
    let recursive_rules = "**/config/local.*\n**/*.pem\n";
    assert!(evaluate_dockerignore(recursive_rules, "config/local.toml"));
    assert!(evaluate_dockerignore(
        recursive_rules,
        "nest/circle-appview/config/local.json"
    ));
    assert!(evaluate_dockerignore(
        recursive_rules,
        "a/b/c/config/local.yaml"
    ));
    assert!(!evaluate_dockerignore(
        recursive_rules,
        "nest/circle-appview/config/remote.json"
    ));
    assert!(evaluate_dockerignore(recursive_rules, "secret.pem"));
    assert!(evaluate_dockerignore(recursive_rules, "certs/server.pem"));
    assert!(evaluate_dockerignore(recursive_rules, "a/b/c/certs/ca.pem"));
    assert!(!evaluate_dockerignore(recursive_rules, "certs/server.crt"));

    // 4. Sequential negation ordering
    let seq_rules = r#"
**
!catbird-atproto/
!catbird-atproto/**
!nest/circle-appview/
!nest/circle-appview/**
**/.env*
!**/.env.example
*.pem
**/*.pem
"#;
    assert!(!evaluate_dockerignore(
        seq_rules,
        "catbird-atproto/src/lib.rs"
    ));
    assert!(!evaluate_dockerignore(
        seq_rules,
        "nest/circle-appview/Cargo.toml"
    ));
    assert!(!evaluate_dockerignore(
        seq_rules,
        "nest/circle-appview/.env.example"
    ));
    assert!(evaluate_dockerignore(seq_rules, "nest/circle-appview/.env"));
    assert!(evaluate_dockerignore(
        seq_rules,
        "nest/circle-appview/.env.local"
    ));
    assert!(evaluate_dockerignore(
        seq_rules,
        "nest/circle-appview/server.pem"
    ));
    assert!(evaluate_dockerignore(
        seq_rules,
        "other-service/src/main.rs"
    ));
}
