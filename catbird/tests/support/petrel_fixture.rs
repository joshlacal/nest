//! Route only the fixture's HTTPS origins to this test's loopback wiremock server.
//! Petrel and Nest see the canonical issuer and PDS throughout discovery and DPoP signing.
use bytes::Bytes;
use petrel::net::{HttpTransport, SendOptions, SharedTransport, TransportError};
use std::sync::Arc;
use wiremock::MockServer;

pub const ISSUER: &str = "https://oauth.fixture.example";
pub const PLC: &str = "https://plc.fixture.example/";

struct MockTransport {
    client: reqwest::Client,
    loopback: String,
}

pub fn transport(mock: &MockServer) -> SharedTransport {
    Arc::new(MockTransport {
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        loopback: mock.uri(),
    })
}

impl HttpTransport for MockTransport {
    async fn send(
        &self,
        request: http::Request<Bytes>,
        options: &SendOptions,
    ) -> Result<http::Response<Bytes>, TransportError> {
        let (req, body) = request.into_parts();
        let target = url::Url::parse(&req.uri.to_string())
            .map_err(|e| TransportError::InvalidRequest(e.to_string()))?;
        if !matches!(
            target.origin().ascii_serialization().as_str(),
            ISSUER | "https://plc.fixture.example"
        ) {
            return Err(TransportError::PolicyViolation(
                "unexpected test authority".into(),
            ));
        }
        let local = format!(
            "{}{}",
            self.loopback,
            req.uri.path_and_query().map_or("/", |pq| pq.as_str())
        );
        let response = self
            .client
            .request(req.method, local)
            .headers(req.headers)
            .body(body)
            .send()
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        let mut out = http::Response::builder().status(response.status());
        *out.headers_mut().unwrap() = response.headers().clone();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;
        if let Some(limit) = options.max_response_bytes {
            if bytes.len() as u64 > limit {
                return Err(TransportError::ResponseTooLarge { limit });
            }
        }
        out.body(bytes)
            .map_err(|e| TransportError::Other(e.to_string()))
    }
}

pub fn dpop_key() -> jose_jwk::Key {
    let secret = p256::SecretKey::from_slice(&[3; 32]).expect("test P-256 scalar");
    jose_jwk::Key::from(&jose_jwk::crypto::Key::from(secret))
}
