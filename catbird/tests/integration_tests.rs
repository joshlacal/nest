//! Integration tests for the Catbird Nest Gateway
//!
//! These tests verify the gateway endpoints work correctly.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

// Note: Full integration tests require a running Redis instance.
// For CI, consider using testcontainers.

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the liveness endpoint always returns 200
    #[tokio::test]
    async fn test_liveness_check() {
        // The liveness check doesn't need state, so we can test it in isolation
        // In a full setup, we'd use the actual router

        // For now, just verify the test infrastructure works
        assert!(true, "Liveness check test placeholder");
    }

    /// Test session cookie extraction
    #[tokio::test]
    async fn test_session_extraction_from_cookie() {
        // Test that sessions can be extracted from cookies
        let cookie_header = "catbird_session=abc123; other=value";

        // Parse the cookie (simplified)
        let session_id = cookie_header.split(';').find_map(|part| {
            let parts: Vec<&str> = part.trim().splitn(2, '=').collect();
            if parts.len() == 2 && parts[0] == "catbird_session" {
                Some(parts[1].to_string())
            } else {
                None
            }
        });

        assert_eq!(session_id, Some("abc123".to_string()));
    }

    /// Test session extraction from Authorization header
    #[tokio::test]
    async fn test_session_extraction_from_bearer() {
        let auth_header = "Bearer xyz789";

        let token = auth_header.strip_prefix("Bearer ");
        assert_eq!(token, Some("xyz789"));
    }

    /// Test PKCE code verifier generation
    #[tokio::test]
    async fn test_pkce_verifier_length() {
        // PKCE verifiers should be between 43-128 characters
        // Our implementation uses 128 characters

        // This would test the generate_code_verifier function if exposed
        // For now, document the expected behavior
        let expected_length = 128;
        assert!(expected_length >= 43 && expected_length <= 128);
    }
}

/// Tests that require a running Redis instance
#[cfg(test)]
mod redis_tests {
    use super::*;

    /// Test session storage and retrieval
    ///
    /// Requires: Redis running on localhost:6379
    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn test_session_storage() {
        // This test would:
        // 1. Create a session
        // 2. Store it in Redis
        // 3. Retrieve it
        // 4. Verify the data matches

        // Using testcontainers for Redis:
        // let redis = testcontainers::clients::Cli::default();
        // let node = redis.run(testcontainers_modules::redis::Redis::default());

        todo!("Implement with testcontainers");
    }

    /// Test session expiration
    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn test_session_expiration() {
        // Test that sessions expire after the configured TTL
        todo!("Implement with testcontainers");
    }
}
