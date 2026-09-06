//! Response construction for requests routed directly to the MLS service.

use axum::{
    body::{Body, Bytes},
    http::StatusCode,
    response::Response,
};

/// Copy only response metadata approved for forwarding to the client.
pub(super) fn build_response(
    status: u16,
    response_headers: &reqwest::header::HeaderMap,
    response_body: Bytes,
) -> Response {
    let mut response =
        Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (name, value) in response_headers.iter() {
        let name_str = name.as_str();
        if matches!(
            name_str,
            "content-type"
                | "content-length"
                | "cache-control"
                | "etag"
                | "last-modified"
                | "retry-after"
        ) {
            if let Ok(v) = reqwest::header::HeaderValue::to_str(value) {
                response = response.header(name_str, v);
            }
        }
    }

    response.body(Body::from(response_body)).unwrap()
}

#[cfg(test)]
#[path = "mls_proxy_response_tests.rs"]
mod tests;
