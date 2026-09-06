use super::build_response;
use axum::{body::Bytes, http::StatusCode};
use reqwest::header::{HeaderMap, HeaderValue};

#[test]
fn rate_limit_preserves_exact_retry_after_delta_seconds() {
    let mut headers = HeaderMap::new();
    headers.insert("retry-after", HeaderValue::from_static("000120"));

    let response = build_response(429, &headers, Bytes::new());

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers().get("retry-after"),
        Some(&HeaderValue::from_static("000120"))
    );
}

#[test]
fn rate_limit_preserves_exact_retry_after_http_date() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Retry-After",
        HeaderValue::from_static("Sat, 05 Sep 2026 12:34:56 GMT"),
    );

    let response = build_response(429, &headers, Bytes::new());

    assert_eq!(
        response.headers().get("retry-after"),
        Some(&HeaderValue::from_static("Sat, 05 Sep 2026 12:34:56 GMT"))
    );
}

#[test]
fn absent_retry_after_remains_absent() {
    for status in [200, 429, 503] {
        let response = build_response(status, &HeaderMap::new(), Bytes::new());
        assert_eq!(response.status().as_u16(), status);
        assert!(!response.headers().contains_key("retry-after"));
    }
}

#[test]
fn authentication_and_cookie_headers_remain_excluded() {
    let mut headers = HeaderMap::new();
    let excluded = [
        "authorization",
        "proxy-authorization",
        "www-authenticate",
        "dpop",
        "dpop-nonce",
        "set-cookie",
        "x-internal-token",
    ];
    for name in excluded {
        headers.insert(name, HeaderValue::from_static("downstream-private-value"));
    }
    headers.insert("content-type", HeaderValue::from_static("application/json"));

    let response = build_response(429, &headers, Bytes::new());

    for name in excluded {
        assert!(!response.headers().contains_key(name), "forwarded {name}");
    }
    assert_eq!(response.headers().len(), 1);
    assert_eq!(response.headers()["content-type"], "application/json");
}

#[test]
fn existing_metadata_and_error_body_are_preserved() {
    let body = Bytes::from_static(br#"{"error":"RateLimitExceeded","message":"slow down"}"#);
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("content-type", "application/json"),
        ("cache-control", "no-store"),
        ("etag", "\"rate-limit\""),
        ("last-modified", "Sat, 05 Sep 2026 12:00:00 GMT"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers.insert(
        "content-length",
        HeaderValue::from_str(&body.len().to_string()).unwrap(),
    );

    let response = build_response(429, &headers, body.clone());

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers(), &headers);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let forwarded = runtime
        .block_on(axum::body::to_bytes(response.into_body(), body.len()))
        .unwrap();
    assert_eq!(forwarded, body);
}
