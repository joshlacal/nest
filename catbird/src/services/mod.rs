//! Services module
//!
//! Business logic and external service integrations.

mod atproto_client;
pub mod chat_poll;
mod crypto;
mod dpop_nonce_cache;
mod mls_auth;
pub mod push;
pub(crate) mod redis_auth_store;
pub(crate) mod redis_crypto;
mod ssrf;

pub use atproto_client::{AtProtoClient, ProxyResponse};
pub use crypto::KeyStore;
pub use dpop_nonce_cache::DpopNonceCache;
pub use mls_auth::{
    calculate_ath, calculate_rfc7638_jkt, generate_dpop_proof, p256_jwk_thumbprint,
    p256_verifying_key_thumbprint, parse_p256_signing_key, public_p256_jwk_from_signing_key,
    public_p256_jwk_from_verifying_key, verify_dpop_proof, CleanChatClaims, CleanChatConfirmation,
    CleanChatEnrollmentClaims, CleanChatTokenHeader, DpopProofClaims, DpopProofHeader,
    MlsAuthService, PublicP256Jwk, CHAT_ENDPOINTS, CHAT_HTTP_ENDPOINTS,
};
pub use push::PushServices;
pub use redis_auth_store::RedisAuthStore;
