//! Services module
//!
//! Business logic and external service integrations.

mod circle_capability;
pub mod client_attestation;
mod atproto_client;
pub mod chat_poll;
mod crypto;
mod dpop_nonce_cache;
mod mls_auth;
pub mod push;
pub(crate) mod redis_auth_store;
pub mod redis_crypto;
pub mod service_auth;
mod ssrf;

pub use atproto_client::{AtProtoClient, ProxyResponse};
pub use crypto::KeyStore;
pub use dpop_nonce_cache::DpopNonceCache;
pub use mls_auth::{
    calculate_ath, calculate_rfc7638_jkt, generate_dpop_proof, p256_jwk_thumbprint,
    p256_verifying_key_thumbprint, parse_p256_signing_key, public_p256_jwk_from_signing_key,
    public_p256_jwk_from_verifying_key, verify_dpop_proof, DpopProofClaims, DpopProofHeader,
    MlsAuthService, PublicP256Jwk, CHAT_ENDPOINTS,
};
pub use push::PushServices;
pub use redis_auth_store::RedisAuthStore;
pub use circle_capability::{AtProtoCircleProbe, CircleCapability, CircleCapabilityService, CircleProbe, CircleProbeResult};
pub use crate::models::require_circle_scopes;
pub use client_attestation::{ClientAttestationError, ClientAttestationProvider};
pub use service_auth::{ServiceAuthProvider, CIRCLE_APPVIEW_SERVICE_REF, MLS_APPVIEW_SERVICE_REF};

