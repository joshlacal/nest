//! Services module
//!
//! Business logic and external service integrations.

mod atproto_client;
pub mod chat_poll;
mod crypto;
mod mls_auth;
mod mls_device_binding;
pub mod push;
pub(crate) mod redis_auth_store;
pub(crate) mod redis_crypto;
mod ssrf;

pub use atproto_client::{AtProtoClient, ProxyResponse};
pub use crypto::KeyStore;
pub use mls_auth::MlsAuthService;
pub(crate) use mls_auth::{session_p256_jkt, MlsProxyRequest};
pub(crate) use mls_device_binding::{
    authoritative_device_id, parse_begin_input, parse_begin_response, parse_complete_input,
    parse_complete_response, MlsDeviceBindingStore, BEGIN_BINDING_NSID, COMPLETE_BINDING_NSID,
};
pub use push::PushServices;
pub use redis_auth_store::RedisAuthStore;
