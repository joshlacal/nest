//! Request ID Middleware
//!
//! Generates or propagates a unique request ID for every request.
//! - Checks for an existing `x-request-id` header
//! - Generates a UUID v4 if missing
//! - Stores the ID in request extensions for downstream handlers
//! - Echoes the ID back in the response `x-request-id` header

use axum::{
    body::Body,
    http::{Request, Response},
    middleware::Next,
};

/// Key for storing request ID in request extensions
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

pub async fn request_id_middleware(mut req: Request<Body>, next: Next) -> Response<Body> {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    req.extensions_mut().insert(RequestId(id.clone()));

    let mut response = next.run(req).await;

    if let Ok(header_value) = id.parse() {
        response.headers_mut().insert("x-request-id", header_value);
    }

    response
}
