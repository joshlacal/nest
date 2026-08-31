//! Services module
//!
//! Business logic and external service integrations.

mod atproto_client;
pub mod chat_poll;
mod crypto;
mod dpop_nonce_cache;
mod mls_auth;
pub mod oauth_authorize;
pub mod oauth_upgrade;
pub mod push;
pub(crate) mod redis_auth_store;
pub use redis_auth_store::{fingerprint_id, SESSION_INDEX_TTL_SECONDS};
pub mod redis_crypto;
pub mod service_auth;
mod ssrf;

pub use atproto_client::{
    bounded_byte_stream, bounded_byte_stream_with_accounting, bounded_byte_stream_with_permit,
    filter_client_headers, AtProtoClient, ProxyResponse, MAX_RESPONSE_SIZE,
};
pub use crypto::KeyStore;
pub use dpop_nonce_cache::DpopNonceCache;
pub use mls_auth::{
    calculate_ath, calculate_rfc7638_jkt, generate_dpop_proof, p256_jwk_thumbprint,
    p256_verifying_key_thumbprint, parse_p256_signing_key, public_p256_jwk_from_signing_key,
    public_p256_jwk_from_verifying_key, verify_dpop_proof, DpopProofClaims, DpopProofHeader,
    MlsAuthService, PublicP256Jwk, CHAT_ENDPOINTS,
};
pub use oauth_upgrade::{
    is_allowed_upgrade_scope, is_valid_browser_nonce, validate_additional_scopes,
    OAuthUpgradeService, StagedCandidateSession, UpgradeCallbackResult, UpgradeError,
    UpgradeExchangeResult, UpgradeExchangeState, UpgradeFlowState, UpgradeReceipt,
    UpgradeStartResult, ALLOWED_UPGRADE_SCOPES, DEFAULT_UPGRADE_CALLBACK_URL,
    UPGRADE_CANDIDATE_TTL_SECONDS, UPGRADE_EXCHANGE_TTL_SECONDS, UPGRADE_FLOW_TTL_SECONDS,
    UPGRADE_RECEIPT_TTL_SECONDS,
};
pub use push::PushServices;
pub use redis_auth_store::{ReconciliationOutcome, RedisAuthStore};
pub use redis_crypto::{build_aad, open_v2_with_metadata, seal_v2_with_metadata, EnvelopeMetadata};
pub use service_auth::{
    ServiceAuthProvider, CIRCLE_APPVIEW_SERVICE_REF, CIRCLE_ENDPOINTS, MLS_APPVIEW_SERVICE_REF,
};
pub use ssrf::{
    build_hardened_http_client, build_hardened_raw_http_client, resolve_and_validate_public_url,
    validate_pds_url, HardenedHttpClient, HardenedHttpClientError, SafeDnsResolver,
    MAX_OAUTH_RESPONSE_SIZE,
};
