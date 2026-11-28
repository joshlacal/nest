//! Authenticated, Enumeration-Proof Push Gateway (`D2`, `I12`, Spec §6.2).
//!
//! Security invariants enforced here:
//! - **Anti-phishing (`aps` ownership):** `mls-ds` sends only structured wake metadata + optional `<= 2200` B
//!   base64 MLS `PrivateMessage` ciphertext. Any extra JSON field (`title`, `body`, `aps`, `alert`, etc.) is
//!   rejected with `400 InvalidRequest`. `nest` exclusively constructs APNs `aps = {"alert": {"body": "New message"}, "mutable-content": 1}`
//!   and FCM data-only envelopes.
//! - **Zero enumeration oracle:** Unknown, revoked, or wrong-`caller_ds_did` `push_key` deliveries return
//!   uniform `202 Accepted` (`{"accepted": true}`) using constant-time SHA-256 comparisons (`subtle::ConstantTimeEq`).
//!   `410 Gone` (`PushTokenGone`) is returned **only** when `caller_ds_did == row.allowed_mls_service_did` and
//!   APNs/FCM marked the native token `Unregistered`.
//! - **Replay & flood protection:** `mls-ds` authenticates `POST /xrpc/blue.catbird.push.deliver` with an
//!   `#atproto` DID-JWT (`ES256` or `ES256K`) bound to `(htm="POST", htu, iat, exp, jti, body_sha256)` (`+-60s`
//!   skew, single-use `(iss, jti)` replay cache). Per-`caller_ds_did` and per-`push_key` token buckets drop
//!   excess wakes before touching APNs/FCM, and unauthorized DSes never touch a victim's per-`push_key` bucket.
//! - **Who may wake a key:** each key is bound at registration to one delivery service. That is the
//!   `#atproto_mls` service in the account's DID document when it has one. Otherwise it is the
//!   `deliveryService` of the account's public `blue.catbird.chat.declaration/self` record, and only if the
//!   operator allows that service (`delivery_service_declaration.rs`, `with_declaration_fallback`). The binding
//!   is stored with the key and is not re-read on delivery.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use a2::{
    request::payload::PayloadLike, Client as ApnsClient, CollapseId, Error as A2Error, ErrorReason,
    NotificationOptions, Priority, PushType,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload as AeadPayload},
    Aes256Gcm,
};
use anyhow::{anyhow, Context, Result};
use axum::http::StatusCode;
use base64::{
    engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD as BASE64URL},
    Engine as _,
};
use chrono::Utc;
use dashmap::DashMap;
use petrel::crypto::ATProtoJWTVerificationKey as SpaceVerifyingKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;

use super::delivery_service_declaration::{
    declaration_record_url, is_supported_delivery_service_did, parse_declaration_response,
    DeclarationError, MAX_DECLARATION_RESPONSE_BYTES,
};
use super::wake_envelope;
use crate::{
    config::{ApnsConfig, PushConfig},
    error::{AppError, AppResult},
    metrics::{
        PUSH_GATEWAY_DELIVERIES_TOTAL, PUSH_GATEWAY_RATE_LIMITED_TOTAL,
        PUSH_GATEWAY_SPOOFED_CALLER_TOTAL, PUSH_GATEWAY_UNKNOWN_KEY_TOTAL,
    },
    services::validate_pds_url,
};
use petrel_catbird::generated::blue::catbird::push::{
    deliver::{Input as Deliver, WakePayloadWakeKind},
    register_key::{
        Input as RegisterKey, InputPlatform as RegisterKeyPlatform, Output as RegisterKeyOutput,
    },
};
use petrel_core::Uri;

pub fn parse_atproto_key(expected_did: &str, bytes: &[u8]) -> Result<SpaceVerifyingKey> {
    let document: petrel::identity::DidDocument = serde_json::from_slice(bytes)?;
    anyhow::ensure!(
        document.id.as_str() == expected_did,
        "unexpected DID document identity"
    );
    Ok(SpaceVerifyingKey::from_public_key(
        &document.atproto_signing_key()?,
    ))
}

/// Maximum inline MLS `PrivateMessage` ciphertext bytes allowed in a push wake (`I12`).
pub const MAX_INLINE_CIPHERTEXT_BYTES: usize = 2200;

/// Maximum compact DID-JWT size accepted on `blue.catbird.push.deliver`.
const MAX_DELIVER_JWT_BYTES: usize = 8 * 1024;

/// Allowed clock skew and max lifetime in seconds for `mls-ds` wake JWTs.
const JWT_MAX_SKEW_SECS: i64 = 60;
const JWT_MAX_LIFETIME_SECS: i64 = 60;
const JTI_CACHE_TTL_SECS: i64 = 120;

const ALLOWED_TOP_LEVEL_KEYS: &[&str] = &["pushKey", "appId", "payload"];
const ALLOWED_PAYLOAD_KEYS: &[&str] = &[
    "wakeKind",
    "conversationId",
    "generation",
    "seq",
    "epoch",
    "ciphertext",
];

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayPlatform {
    Apns,
    ApnsSandbox,
    Fcm,
    Webpush,
}

impl GatewayPlatform {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::ApnsSandbox => "apnsSandbox",
            Self::Fcm => "fcm",
            Self::Webpush => "webpush",
        }
    }

    pub fn from_db_str(s: &str) -> Result<Self> {
        match s {
            "apns" => Ok(Self::Apns),
            "apnsSandbox" => Ok(Self::ApnsSandbox),
            "fcm" => Ok(Self::Fcm),
            "webpush" => Ok(Self::Webpush),
            other => Err(anyhow!("unsupported gateway platform '{other}'")),
        }
    }

    pub fn from_lexicon(p: &RegisterKeyPlatform) -> Option<Self> {
        match p {
            RegisterKeyPlatform::Apns => Some(Self::Apns),
            RegisterKeyPlatform::ApnsSandbox => Some(Self::ApnsSandbox),
            RegisterKeyPlatform::Fcm => Some(Self::Fcm),
            RegisterKeyPlatform::Webpush => Some(Self::Webpush),
            RegisterKeyPlatform::Unknown(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DispatchedGatewayPush {
    pub platform: GatewayPlatform,
    pub app_id: String,
    pub native_token: String,
    pub collapse_id: String,
    pub apns_envelope: Value,
    pub fcm_envelope: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GatewayDeliveryOutcome {
    #[default]
    Delivered,
    TokenUnregistered,
}

#[async_trait::async_trait]
pub trait PushGatewayTransport: Send + Sync {
    async fn send(&self, push: DispatchedGatewayPush) -> Result<GatewayDeliveryOutcome>;
}

/// Which public statement named the delivery service a push key is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryServiceSource {
    /// The `#atproto_mls` service entry in the account's DID document.
    DidDocument,
    /// The account's `blue.catbird.chat.declaration/self` repo record, used
    /// only when the DID document has no `#atproto_mls` entry.
    ChatDeclaration,
}

impl DeliveryServiceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DidDocument => "did_document",
            Self::ChatDeclaration => "chat_declaration",
        }
    }
}

/// The delivery service allowed to wake an account's push keys, and where
/// that came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDeliveryService {
    pub did: String,
    pub source: DeliveryServiceSource,
}

/// Why no delivery service could be bound to a push key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserDeliveryServiceError {
    /// Neither the DID document nor a chat declaration names one.
    NotDeclared,
    /// A source names one, but the entry or record is malformed.
    Invalid(String),
    /// The chat declaration names a delivery service this gateway does not
    /// accept from a repo record.
    NotAllowed(String),
    /// The account's DID document can never be read as things stand: the
    /// directory does not have the DID, the DID is not one this gateway can
    /// look up, or the document is larger than the gateway reads. Retrying
    /// the same request cannot succeed.
    Unresolvable(String),
    /// The DID document or the PDS could not be read; retrying may succeed.
    Unavailable(String),
}

impl std::fmt::Display for UserDeliveryServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDeclared => f.write_str("no delivery service is declared"),
            Self::Invalid(why) => write!(f, "delivery service declaration is invalid: {why}"),
            Self::NotAllowed(did) => {
                write!(f, "declared delivery service '{did}' is not allowed")
            }
            Self::Unresolvable(why) => write!(f, "DID document cannot be resolved: {why}"),
            Self::Unavailable(why) => write!(f, "delivery service lookup unavailable: {why}"),
        }
    }
}

impl std::error::Error for UserDeliveryServiceError {}

#[async_trait::async_trait]
pub trait MlsDsIdentityResolver: Send + Sync {
    /// Resolve `account_did`'s DID document and extract the canonical bare DID of its
    /// `#atproto_mls` (`AtprotoMLSDeliveryService`) service entry.
    ///
    /// DID document only. `getServiceAuth` audience checks rely on this never
    /// consulting a repo record.
    async fn resolve_user_mls_service_did(&self, account_did: &str) -> Result<String>;

    /// Resolve the delivery service allowed to wake `account_did`'s push keys.
    ///
    /// The DID document's `#atproto_mls` entry decides when present. A
    /// resolver may fall back to the account's public chat declaration when
    /// that entry is absent; this default does not.
    async fn resolve_user_push_delivery_service(
        &self,
        account_did: &str,
    ) -> std::result::Result<UserDeliveryService, UserDeliveryServiceError> {
        self.resolve_user_mls_service_did(account_did)
            .await
            .map(|did| UserDeliveryService {
                did,
                source: DeliveryServiceSource::DidDocument,
            })
            .map_err(|e| UserDeliveryServiceError::Invalid(e.to_string()))
    }

    /// Resolve `caller_ds_did`'s `#atproto` P-256 (`ES256`) or secp256k1 (`ES256K`) verifying key.
    async fn resolve_ds_atproto_key(
        &self,
        caller_ds_did: &str,
        force_refresh: bool,
    ) -> Result<SpaceVerifyingKey>;
}

/// Production HTTP DID resolver with SSRF validation (`SafeDnsResolver` + `validate_pds_url`)
/// and bounded TTL key caching.
pub struct HttpMlsDsIdentityResolver {
    http_client: reqwest::Client,
    plc_directory_url: String,
    ds_key_cache: DashMap<String, (SpaceVerifyingKey, Instant)>,
    /// DID-document `#atproto_mls` answers. `getServiceAuth` reads this cache,
    /// so a declaration-sourced answer must never be stored here.
    user_mls_cache: DashMap<String, (String, Instant)>,
    /// Chat-declaration answers that passed the allowlist.
    user_declared_ds_cache: DashMap<String, (String, Instant)>,
    /// Delivery services a chat declaration may select. Empty: the
    /// declaration is never read.
    declaration_allowed_services: Vec<String>,
    cache_ttl: Duration,
}

/// Deadline for the one public `getRecord` read of a chat declaration.
const DECLARATION_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Environment override for the delivery services a chat declaration may
/// select: comma-separated DIDs. Set but empty turns the fallback off.
pub const DECLARATION_DELIVERY_SERVICES_ENV: &str = "CATBIRD_PUSH_DECLARATION_DELIVERY_SERVICES";

/// Resolves the delivery services a chat declaration may select.
///
/// `env_value` (the raw [`DECLARATION_DELIVERY_SERVICES_ENV`] value) wins when
/// set, even if it lists nothing. Otherwise the list is the gateway's own
/// delivery service, `default_service_did`. Entries are bare DIDs: a
/// `#fragment` is dropped, and anything that is not a supported DID is
/// ignored with a warning rather than widening the list.
pub fn declaration_delivery_services(
    env_value: Option<&str>,
    default_service_did: Option<&str>,
) -> Vec<String> {
    let raw: Vec<&str> = match env_value {
        Some(value) => value.split(',').collect(),
        None => default_service_did.into_iter().collect(),
    };
    let mut out: Vec<String> = Vec::new();
    for entry in raw {
        let bare = entry.trim().split('#').next().unwrap_or_default();
        if bare.is_empty() {
            continue;
        }
        if !is_supported_delivery_service_did(bare) {
            tracing::warn!(
                entry = %bare,
                "Ignoring unsupported DID in the push declaration delivery-service allowlist"
            );
            continue;
        }
        if !out.iter().any(|did| did == bare) {
            out.push(bare.to_string());
        }
    }
    out
}

impl HttpMlsDsIdentityResolver {
    pub fn new(http_client: reqwest::Client, plc_directory_url: impl Into<String>) -> Self {
        Self {
            http_client,
            plc_directory_url: plc_directory_url.into(),
            ds_key_cache: DashMap::new(),
            user_mls_cache: DashMap::new(),
            user_declared_ds_cache: DashMap::new(),
            declaration_allowed_services: Vec::new(),
            cache_ttl: Duration::from_secs(300),
        }
    }

    /// Lets push-key registration fall back to an account's public
    /// `blue.catbird.chat.declaration/self` record when its DID document has
    /// no `#atproto_mls` entry, but only for the delivery services listed
    /// here. A repo record is easier to change than a DID document, so it may
    /// only select a service the operator already trusts.
    pub fn with_declaration_fallback(mut self, allowed_services: Vec<String>) -> Self {
        self.declaration_allowed_services = allowed_services;
        self
    }

    /// Reads `account_did`'s chat declaration from the PDS its DID document
    /// names: one public GET with no credentials, through the gateway's
    /// hardened client (no redirects, no proxy, private addresses refused at
    /// DNS resolution), with a deadline and a streamed body cap.
    async fn fetch_declared_delivery_service(
        &self,
        did_doc_bytes: &[u8],
        account_did: &str,
    ) -> std::result::Result<Option<String>, DeclarationError> {
        let url = declaration_record_url(did_doc_bytes, account_did)?;
        let unavailable = |why: String| DeclarationError::Unavailable(why);
        let resp = self
            .http_client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .timeout(DECLARATION_READ_TIMEOUT)
            .send()
            .await
            .map_err(|e| unavailable(format!("getRecord request failed: {e}")))?;
        let status = resp.status().as_u16();
        // A redirect or server error is never parsed; only 200, 400 and 404
        // carry a body the declaration rules give meaning to.
        if !matches!(status, 200 | 400 | 404) {
            return Err(unavailable(format!("getRecord answered HTTP {status}")));
        }
        let body = read_capped_body(resp, MAX_DECLARATION_RESPONSE_BYTES)
            .await
            .map_err(|e| match e {
                CappedBodyError::TooLarge => {
                    unavailable("getRecord answer exceeds the size cap".to_string())
                }
                CappedBodyError::Read(e) => unavailable(format!("getRecord body read failed: {e}")),
            })?;
        parse_declaration_response(account_did, status, &body)
    }

    async fn fetch_did_document(
        &self,
        did: &str,
    ) -> std::result::Result<Vec<u8>, DidDocumentFetchError> {
        use DidDocumentFetchError::{Permanent, Transient};

        let did = did.trim();
        let url = if let Some(plc_suffix) = did.strip_prefix("did:plc:") {
            if plc_suffix.len() != 24
                || !plc_suffix
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
            {
                return Err(Permanent(anyhow!("invalid did:plc identifier '{did}'")));
            }
            format!("{}/{}", self.plc_directory_url.trim_end_matches('/'), did)
        } else if let Some(web_rest) = did.strip_prefix("did:web:") {
            let mut segments = web_rest.split(':');
            let raw_host = segments
                .next()
                .filter(|h| !h.is_empty())
                .ok_or_else(|| Permanent(anyhow!("missing host in did:web '{did}'")))?;
            let host = urlencoding::decode(raw_host)
                .map_err(|e| Permanent(anyhow!("invalid did:web host encoding: {e}")))?;
            let path_segments: Vec<&str> = segments.collect();
            if path_segments.is_empty() {
                format!("https://{host}/.well-known/did.json")
            } else {
                for seg in &path_segments {
                    if seg.is_empty() || *seg == "." || *seg == ".." || seg.contains('/') {
                        return Err(Permanent(anyhow!(
                            "invalid path segment in did:web '{did}'"
                        )));
                    }
                }
                format!("https://{host}/{}/did.json", path_segments.join("/"))
            }
        } else {
            return Err(Permanent(anyhow!("unsupported DID method '{did}'")));
        };

        if let Err(e) = validate_pds_url(&url) {
            let blocked = anyhow!("DID resolution URL blocked: {e}");
            // A did:web names its own host, so a refused host is a property of
            // the DID. The did:plc host is this gateway's own configuration.
            return Err(if did.starts_with("did:web:") {
                Permanent(blocked)
            } else {
                Transient(blocked)
            });
        }
        let resp = self
            .http_client
            .get(&url)
            .header(
                reqwest::header::ACCEPT,
                "application/did+ld+json, application/json",
            )
            .send()
            .await
            .map_err(|e| {
                Transient(anyhow::Error::new(e).context(format!("fetch DID document for {did}")))
            })?;
        let status = resp.status();
        if !status.is_success() {
            let failed = anyhow!("DID document lookup for {did} returned HTTP {status}");
            // 404: the directory or host has no such DID. 410: it is
            // tombstoned. Every other status can change while the DID stays
            // the same.
            return Err(
                if matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE) {
                    Permanent(failed)
                } else {
                    Transient(failed)
                },
            );
        }
        read_did_document_body(resp, did).await
    }
}

/// Why a DID document could not be fetched.
///
/// `registerKey` answers the two cases differently. Every other caller only
/// needs the underlying error, which [`From`] hands back unchanged.
#[derive(Debug)]
enum DidDocumentFetchError {
    /// Asking again cannot succeed: the DID is not one the gateway can look
    /// up, its host is refused, the directory does not have it, or its
    /// document is over the size cap.
    Permanent(anyhow::Error),
    /// Asking again may succeed: the request did not complete, or the
    /// directory or host answered with a failure of its own.
    Transient(anyhow::Error),
}

impl std::fmt::Display for DidDocumentFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permanent(e) | Self::Transient(e) => e.fmt(f),
        }
    }
}

impl From<DidDocumentFetchError> for anyhow::Error {
    fn from(error: DidDocumentFetchError) -> Self {
        match error {
            DidDocumentFetchError::Permanent(e) | DidDocumentFetchError::Transient(e) => e,
        }
    }
}

/// Largest DID document the gateway will read.
const MAX_DID_DOCUMENT_BYTES: usize = 256 * 1024;

/// Reads a DID document body, stopping as soon as it exceeds
/// [`MAX_DID_DOCUMENT_BYTES`].
///
/// `/xrpc/blue.catbird.push.deliver` resolves the caller's DID before any
/// signature is verified, so the host serving this body is chosen by an
/// unauthenticated caller. The body is therefore never buffered whole: a
/// declared length over the cap is refused up front, and an undeclared one is
/// cut off at the first chunk that crosses it.
async fn read_did_document_body(
    resp: reqwest::Response,
    did: &str,
) -> std::result::Result<Vec<u8>, DidDocumentFetchError> {
    match read_capped_body(resp, MAX_DID_DOCUMENT_BYTES).await {
        Ok(body) => Ok(body),
        Err(CappedBodyError::TooLarge) => Err(DidDocumentFetchError::Permanent(anyhow!(
            "DID document for {did} exceeds 256 KiB"
        ))),
        Err(CappedBodyError::Read(e)) => Err(DidDocumentFetchError::Transient(
            anyhow::Error::new(e).context(format!("read DID document for {did}")),
        )),
    }
}

enum CappedBodyError {
    TooLarge,
    Read(reqwest::Error),
}

/// Reads a response body of at most `cap` bytes without ever buffering more:
/// a declared length over the cap is refused before reading, and an
/// undeclared one is cut off at the first chunk that crosses it.
async fn read_capped_body(
    mut resp: reqwest::Response,
    cap: usize,
) -> std::result::Result<Vec<u8>, CappedBodyError> {
    let declared = resp.content_length().or_else(|| {
        resp.headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
    });
    if declared.is_some_and(|len| len > cap as u64) {
        return Err(CappedBodyError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(CappedBodyError::Read)? {
        if chunk.len() > cap - body.len() {
            return Err(CappedBodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Extract the bare MLS service DID from a user's DID document `#atproto_mls` service entry.
///
/// Supports:
/// - `serviceEndpoint` as `did:web:...` or `did:plc:...` (stripping any `#...` fragment)
/// - `serviceEndpoint` as `https://<host>[:port]` -> `did:web:<host[%3Aport]>`
pub fn extract_user_atproto_mls_service_did(
    did_doc_bytes: &[u8],
    user_did: &str,
) -> Result<String> {
    find_user_atproto_mls_service_did(did_doc_bytes, user_did)?
        .ok_or_else(|| anyhow!("DID document for {user_did} has no #atproto_mls service"))
}

/// Like [`extract_user_atproto_mls_service_did`], but tells a DID document
/// that has no `#atproto_mls` entry (`Ok(None)`) apart from one whose entry or
/// whose document is unusable (`Err`). Only the first case may fall back to
/// the account's chat declaration.
pub fn find_user_atproto_mls_service_did(
    did_doc_bytes: &[u8],
    user_did: &str,
) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct DidDoc {
        id: String,
        #[serde(default)]
        service: Vec<DidServiceEntry>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DidServiceEntry {
        id: String,
        #[serde(rename = "type")]
        service_type: String,
        service_endpoint: Value,
    }

    let doc: DidDoc =
        serde_json::from_slice(did_doc_bytes).context("parse user DID document JSON")?;
    if doc.id != user_did {
        return Err(anyhow!(
            "DID document id '{}' does not match requested '{}'",
            doc.id,
            user_did
        ));
    }

    let expected_full = format!("{user_did}#atproto_mls");
    let Some(entry) = doc
        .service
        .iter()
        .find(|s| {
            (s.id == "#atproto_mls" || s.id == expected_full)
                && (s.service_type == "AtprotoMLSDeliveryService"
                    || s.service_type == "AtprotoMlsDeliveryService")
        })
        .or_else(|| {
            doc.service
                .iter()
                .find(|s| s.id == "#atproto_mls" || s.id == expected_full)
        })
    else {
        return Ok(None);
    };

    let endpoint_str = entry
        .service_endpoint
        .as_str()
        .ok_or_else(|| anyhow!("#atproto_mls serviceEndpoint must be a string"))?
        .trim();

    if endpoint_str.starts_with("did:plc:") || endpoint_str.starts_with("did:web:") {
        let bare = endpoint_str
            .split_once('#')
            .map(|(d, _)| d)
            .unwrap_or(endpoint_str);
        return Ok(Some(bare.to_string()));
    }

    let parsed = Url::parse(endpoint_str)
        .with_context(|| format!("parse #atproto_mls serviceEndpoint '{endpoint_str}'"))?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err(anyhow!(
            "unsupported #atproto_mls serviceEndpoint scheme '{}'",
            parsed.scheme()
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("#atproto_mls serviceEndpoint missing host"))?
        .to_ascii_lowercase();
    let did_web = match parsed.port() {
        Some(port) => format!("did:web:{host}%3A{port}"),
        None => format!("did:web:{host}"),
    };
    Ok(Some(did_web))
}

#[async_trait::async_trait]
impl MlsDsIdentityResolver for HttpMlsDsIdentityResolver {
    async fn resolve_user_mls_service_did(&self, account_did: &str) -> Result<String> {
        if let Some(entry) = self.user_mls_cache.get(account_did) {
            if entry.value().1.elapsed() < self.cache_ttl {
                return Ok(entry.value().0.clone());
            }
        }
        let doc_bytes = self.fetch_did_document(account_did).await?;
        let service_did = extract_user_atproto_mls_service_did(&doc_bytes, account_did)?;
        self.user_mls_cache.insert(
            account_did.to_string(),
            (service_did.clone(), Instant::now()),
        );
        Ok(service_did)
    }

    async fn resolve_user_push_delivery_service(
        &self,
        account_did: &str,
    ) -> std::result::Result<UserDeliveryService, UserDeliveryServiceError> {
        let fresh = |cache: &DashMap<String, (String, Instant)>| {
            cache
                .get(account_did)
                .filter(|entry| entry.value().1.elapsed() < self.cache_ttl)
                .map(|entry| entry.value().0.clone())
        };
        if let Some(did) = fresh(&self.user_mls_cache) {
            return Ok(UserDeliveryService {
                did,
                source: DeliveryServiceSource::DidDocument,
            });
        }
        if let Some(did) = fresh(&self.user_declared_ds_cache) {
            return Ok(UserDeliveryService {
                did,
                source: DeliveryServiceSource::ChatDeclaration,
            });
        }

        let doc_bytes = self
            .fetch_did_document(account_did)
            .await
            .map_err(|e| match e {
                DidDocumentFetchError::Permanent(e) => {
                    UserDeliveryServiceError::Unresolvable(format!("{e:#}"))
                }
                DidDocumentFetchError::Transient(e) => {
                    UserDeliveryServiceError::Unavailable(format!("{e:#}"))
                }
            })?;

        // The DID document decides whenever it has an `#atproto_mls` entry,
        // usable or not: a repo record must never override it.
        if let Some(did) = find_user_atproto_mls_service_did(&doc_bytes, account_did)
            .map_err(|e| UserDeliveryServiceError::Invalid(format!("{e:#}")))?
        {
            self.user_mls_cache
                .insert(account_did.to_string(), (did.clone(), Instant::now()));
            return Ok(UserDeliveryService {
                did,
                source: DeliveryServiceSource::DidDocument,
            });
        }

        if self.declaration_allowed_services.is_empty() {
            return Err(UserDeliveryServiceError::NotDeclared);
        }
        let declared = self
            .fetch_declared_delivery_service(&doc_bytes, account_did)
            .await
            .map_err(|e| match e {
                DeclarationError::Malformed(why) => UserDeliveryServiceError::Invalid(why),
                DeclarationError::Unavailable(why) => UserDeliveryServiceError::Unavailable(why),
            })?
            .ok_or(UserDeliveryServiceError::NotDeclared)?;
        if !self.declaration_allowed_services.contains(&declared) {
            return Err(UserDeliveryServiceError::NotAllowed(declared));
        }
        self.user_declared_ds_cache
            .insert(account_did.to_string(), (declared.clone(), Instant::now()));
        Ok(UserDeliveryService {
            did: declared,
            source: DeliveryServiceSource::ChatDeclaration,
        })
    }

    async fn resolve_ds_atproto_key(
        &self,
        caller_ds_did: &str,
        force_refresh: bool,
    ) -> Result<SpaceVerifyingKey> {
        if !force_refresh {
            if let Some(entry) = self.ds_key_cache.get(caller_ds_did) {
                if entry.value().1.elapsed() < self.cache_ttl {
                    return Ok(entry.value().0.clone());
                }
            }
        }
        let doc_bytes = self.fetch_did_document(caller_ds_did).await?;
        let vk = parse_atproto_key(caller_ds_did, &doc_bytes)?;
        self.ds_key_cache
            .insert(caller_ds_did.to_string(), (vk.clone(), Instant::now()));
        Ok(vk)
    }
}

#[derive(Debug, Serialize)]
struct RawJsonApnsPayload<'a> {
    #[serde(skip)]
    device_token: &'a str,
    #[serde(skip)]
    options: NotificationOptions<'a>,
    json_string: String,
}

impl PayloadLike for RawJsonApnsPayload<'_> {
    fn get_device_token(&self) -> &str {
        self.device_token
    }

    fn get_options(&self) -> &NotificationOptions<'_> {
        &self.options
    }

    fn to_json_string(&self) -> Result<String, a2::Error> {
        Ok(self.json_string.clone())
    }
}

/// Live APNs HTTP/2 + FCM HTTP v1 transport used by Nest in production.
pub struct LivePushGatewayTransport {
    apns_production: Option<Arc<ApnsClient>>,
    apns_sandbox: Option<Arc<ApnsClient>>,
    http_client: reqwest::Client,
    fcm_endpoint_and_bearer: Option<(String, String)>,
}

impl LivePushGatewayTransport {
    pub fn from_config(apns: &ApnsConfig, http_client: reqwest::Client) -> Result<Self> {
        let (apns_production, apns_sandbox) = if apns.enabled {
            if let (Some(key_path), Some(key_id), Some(team_id)) = (
                apns.key_path.as_deref(),
                apns.key_id.as_deref(),
                apns.team_id.as_deref(),
            ) {
                let p = Path::new(key_path);
                let prod = ApnsClient::token(
                    std::fs::File::open(p)
                        .with_context(|| format!("open APNs key {}", p.display()))?,
                    key_id,
                    team_id,
                    a2::ClientConfig::new(a2::Endpoint::Production),
                )?;
                let sb = ApnsClient::token(
                    std::fs::File::open(p)
                        .with_context(|| format!("open APNs key {}", p.display()))?,
                    key_id,
                    team_id,
                    a2::ClientConfig::new(a2::Endpoint::Sandbox),
                )?;
                (Some(Arc::new(prod)), Some(Arc::new(sb)))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let fcm_endpoint_and_bearer = match (
            std::env::var("CATBIRD_FCM_PROJECT_ID").ok(),
            std::env::var("CATBIRD_FCM_BEARER_TOKEN").ok(),
        ) {
            (Some(project_id), Some(token))
                if !project_id.trim().is_empty() && !token.trim().is_empty() =>
            {
                Some((
                    format!(
                        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
                        project_id.trim()
                    ),
                    token.trim().to_string(),
                ))
            }
            _ => None,
        };

        Ok(Self {
            apns_production,
            apns_sandbox,
            http_client,
            fcm_endpoint_and_bearer,
        })
    }
}

#[async_trait::async_trait]
impl PushGatewayTransport for LivePushGatewayTransport {
    async fn send(&self, push: DispatchedGatewayPush) -> Result<GatewayDeliveryOutcome> {
        match push.platform {
            GatewayPlatform::Apns | GatewayPlatform::ApnsSandbox => {
                let client = match push.platform {
                    GatewayPlatform::Apns => self.apns_production.as_ref(),
                    GatewayPlatform::ApnsSandbox => self.apns_sandbox.as_ref(),
                    _ => unreachable!(),
                }
                .ok_or_else(|| anyhow!("APNs client not configured"))?;

                let collapse = CollapseId::new(&push.collapse_id)?;
                let payload = RawJsonApnsPayload {
                    device_token: &push.native_token,
                    options: NotificationOptions {
                        apns_topic: Some(&push.app_id),
                        apns_priority: Some(Priority::High),
                        apns_collapse_id: Some(collapse),
                        apns_expiration: None,
                        apns_push_type: Some(PushType::Alert),
                        apns_id: None,
                    },
                    json_string: serde_json::to_string(&push.apns_envelope)?,
                };

                match client.send(payload).await {
                    Ok(_) => Ok(GatewayDeliveryOutcome::Delivered),
                    Err(A2Error::ResponseError(resp))
                        if resp
                            .error
                            .as_ref()
                            .is_some_and(|b| b.reason == ErrorReason::Unregistered)
                            || resp.code == 410 =>
                    {
                        Ok(GatewayDeliveryOutcome::TokenUnregistered)
                    }
                    Err(err) => Err(anyhow!("APNs delivery failed: {err}")),
                }
            }
            GatewayPlatform::Fcm => {
                let Some((endpoint, bearer)) = &self.fcm_endpoint_and_bearer else {
                    return Err(anyhow!("FCM HTTP v1 transport is not configured"));
                };
                let resp = self
                    .http_client
                    .post(endpoint)
                    .bearer_auth(bearer)
                    .json(&push.fcm_envelope)
                    .send()
                    .await
                    .context("FCM HTTP v1 request failed")?;
                let status = resp.status();
                if status.is_success() {
                    return Ok(GatewayDeliveryOutcome::Delivered);
                }
                let body_text = resp.text().await.unwrap_or_default();
                if status == reqwest::StatusCode::NOT_FOUND
                    || status == reqwest::StatusCode::GONE
                    || body_text.contains("UNREGISTERED")
                {
                    return Ok(GatewayDeliveryOutcome::TokenUnregistered);
                }
                Err(anyhow!("FCM HTTP v1 returned {status}"))
            }
            GatewayPlatform::Webpush => {
                Err(anyhow!("WebPush transport not configured on this gateway"))
            }
        }
    }
}

/// Shape of the chat wake payload handed to the push provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WakeEnvelopeMode {
    /// Version 1: conversation id, generation, seq, epoch, wake kind and an
    /// unsalted hash of the account DID in clear. Retained only for explicit
    /// emergency rollback (`CATBIRD_PUSH_WAKE_ENVELOPE=clear`).
    ClearV1,
    /// Version 2 (default): one opaque constant-size blob (`wake_envelope`).
    /// The provider sees no conversation, account or size information.
    #[default]
    SealedV2,
}

impl WakeEnvelopeMode {
    /// Parse `CATBIRD_PUSH_WAKE_ENVELOPE`. Unset, empty, `"sealed"`, `"2"`, or
    /// unrecognized values default to [`Self::SealedV2`]; only explicit `"clear"`
    /// or `"1"` selects [`Self::ClearV1`].
    pub fn from_env_value(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("clear") || v == "1" => Self::ClearV1,
            _ => Self::SealedV2,
        }
    }
}

/// Decode a configured encryption key (`CATBIRD_PUSH_GATEWAY_TOKEN_KEY` or
/// `SESSION_ENCRYPTION_KEY`) into exact 32 non-zero bytes, accepting standard
/// base64, URL-safe base64 (padded or unpadded), or 64-character hex.
pub fn decode_exact_32_byte_key(raw: &str) -> Result<[u8; 32]> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("encryption key must not be empty"));
    }

    let decoded = if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = Vec::with_capacity(32);
        for chunk in trimmed.as_bytes().chunks_exact(2) {
            let s = std::str::from_utf8(chunk).map_err(|_| anyhow!("invalid hex key"))?;
            let byte = u8::from_str_radix(s, 16).map_err(|_| anyhow!("invalid hex key"))?;
            out.push(byte);
        }
        out
    } else {
        BASE64URL
            .decode(trimmed)
            .or_else(|_| BASE64_STD.decode(trimmed))
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE
                    .decode(trimmed)
                    .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
            })
            .map_err(|_| anyhow!("key must be valid base64, base64url, or 64-char hex"))?
    };

    if decoded.len() != 32 {
        return Err(anyhow!(
            "key decoded to {} bytes; expected exactly 32 bytes",
            decoded.len()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    if key == [0u8; 32] {
        return Err(anyhow!("all-zero 32-byte encryption key is forbidden"));
    }
    Ok(key)
}

/// Resolve the 256-bit AES-GCM key protecting stored native device push tokens.
///
/// - If `CATBIRD_PUSH_GATEWAY_TOKEN_KEY` is non-empty, it MUST decode to 32 non-zero bytes.
/// - Otherwise, if `SESSION_ENCRYPTION_KEY` is non-empty, it MUST decode to 32 non-zero bytes
///   and is domain-separated via SHA-256 (`catbird-push-gateway-token-key-v1:`).
/// - If neither variable is set:
///   - Release builds (`allow_debug_ephemeral == false` / `#[cfg(not(debug_assertions))]`)
///     refuse startup with `Err(...)`.
///   - Debug/test builds (`allow_debug_ephemeral == true` / `#[cfg(debug_assertions)]`)
///     generate 32 random CSPRNG bytes via `OsRng` (never a deterministic fallback).
pub fn resolve_gateway_token_encryption_key(
    gateway_token_key_env: Option<&str>,
    session_encryption_key_env: Option<&str>,
    allow_debug_ephemeral: bool,
) -> Result<[u8; 32]> {
    if let Some(raw_gw) = gateway_token_key_env
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return decode_exact_32_byte_key(raw_gw)
            .context("Invalid CATBIRD_PUSH_GATEWAY_TOKEN_KEY (must decode to 32 non-zero bytes)");
    }

    if let Some(raw_sess) = session_encryption_key_env
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let sess_bytes = decode_exact_32_byte_key(raw_sess)
            .context("Invalid SESSION_ENCRYPTION_KEY (must decode to 32 non-zero bytes)")?;
        let mut hasher = Sha256::new();
        hasher.update(b"catbird-push-gateway-token-key-v1:");
        hasher.update(sess_bytes);
        let mut derived = [0u8; 32];
        derived.copy_from_slice(&hasher.finalize());
        return Ok(derived);
    }

    if !allow_debug_ephemeral {
        return Err(anyhow!(
            "Push gateway startup refused: CATBIRD_PUSH_GATEWAY_TOKEN_KEY or SESSION_ENCRYPTION_KEY (32-byte key) must be configured in release builds"
        ));
    }

    let mut ephemeral = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ephemeral);
    Ok(ephemeral)
}

pub fn resolve_gateway_token_encryption_key_from_env() -> Result<[u8; 32]> {
    let gw_env = std::env::var("CATBIRD_PUSH_GATEWAY_TOKEN_KEY").ok();
    let sess_env = std::env::var("SESSION_ENCRYPTION_KEY").ok();
    #[cfg(not(debug_assertions))]
    let allow_debug_ephemeral = false;
    #[cfg(debug_assertions)]
    let allow_debug_ephemeral = true;

    resolve_gateway_token_encryption_key(
        gw_env.as_deref(),
        sess_env.as_deref(),
        allow_debug_ephemeral,
    )
}

#[derive(Debug, Clone)]
pub struct PushGatewayConfig {
    pub gateway_url: String,
    pub token_encryption_key: [u8; 32],
    pub wake_envelope: WakeEnvelopeMode,
    pub per_key_burst: u32,
    pub per_key_per_minute: u32,
    pub per_ds_burst: u32,
    pub per_ds_per_minute: u32,
}

impl PushGatewayConfig {
    pub fn from_push_and_server_config(push: &PushConfig, base_url: &str) -> Result<Self> {
        let token_encryption_key = resolve_gateway_token_encryption_key_from_env()?;
        let raw_wake_mode = std::env::var("CATBIRD_PUSH_WAKE_ENVELOPE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| push.wake_envelope.clone());

        let gateway_url = format!(
            "{}/xrpc/blue.catbird.push.deliver",
            base_url.trim_end_matches('/')
        );
        Ok(Self {
            gateway_url,
            token_encryption_key,
            wake_envelope: WakeEnvelopeMode::from_env_value(Some(raw_wake_mode.as_str())),
            per_key_burst: 10,
            per_key_per_minute: 30,
            per_ds_burst: 200,
            per_ds_per_minute: 600,
        })
    }
}

#[derive(Debug, Clone)]
struct TokenBucketState {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucketState {
    fn try_consume(&mut self, burst: u32, per_minute: u32, now: Instant) -> bool {
        let capacity = f64::from(burst.max(1));
        let rate_per_sec = f64::from(per_minute) / 60.0;
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate_per_sec).min(capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Deserialize)]
struct WakeJwtHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    jwk: Option<Value>,
    #[serde(default)]
    crit: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct WakeJwtClaims {
    iss: String,
    #[serde(default, alias = "method")]
    htm: Option<String>,
    htu: String,
    iat: i64,
    exp: i64,
    jti: String,
    body_sha256: String,
}

#[derive(Debug, Deserialize)]
struct RegisterServiceJwtClaims {
    iss: String,
    aud: String,
    #[serde(default)]
    lxm: Option<String>,
    #[serde(default)]
    iat: Option<i64>,
    exp: i64,
    #[serde(default)]
    jti: Option<String>,
}

/// What `registerKey` answers when no delivery service can be bound.
///
/// Permanent causes keep the `400 InvalidMlsServiceDid` clients already
/// handle, including a DID document that can never be read (not in the
/// directory, a DID the gateway cannot look up, an oversized document). A
/// source that failed in a way a retry can fix is `503`, so a directory or PDS
/// outage is not reported as the account's fault.
fn register_key_resolution_error(error: &UserDeliveryServiceError) -> AppError {
    let invalid = |why: &str| AppError::BadRequest(format!("InvalidMlsServiceDid: {why}"));
    match error {
        UserDeliveryServiceError::NotDeclared => invalid(
            "account has no #atproto_mls service in its DID document \
             and no usable blue.catbird.chat.declaration record",
        ),
        UserDeliveryServiceError::Invalid(_) => {
            invalid("account's delivery service entry or chat declaration is malformed")
        }
        UserDeliveryServiceError::NotAllowed(_) => invalid(
            "the delivery service in the account's chat declaration is not accepted by this \
             gateway; name it in the DID document #atproto_mls service instead",
        ),
        UserDeliveryServiceError::Unresolvable(_) => {
            invalid("account's DID document cannot be resolved")
        }
        UserDeliveryServiceError::Unavailable(_) => AppError::ServiceUnavailable(
            "Could not read the account's DID document or chat declaration; try again".into(),
        ),
    }
}

const REGISTER_SERVICE_JWT_MAX_LIFETIME_SECS: i64 = 300;
const MAX_JTI_CACHE_ENTRIES: usize = 65_536;

pub struct PushGatewayService {
    db_pool: PgPool,
    config: PushGatewayConfig,
    resolver: Arc<dyn MlsDsIdentityResolver>,
    transport: Arc<dyn PushGatewayTransport>,
    jti_replay_cache: DashMap<(String, String), i64>,
    per_key_buckets: DashMap<[u8; 32], TokenBucketState>,
    per_ds_buckets: DashMap<String, TokenBucketState>,
}

impl PushGatewayService {
    pub fn new(
        db_pool: PgPool,
        config: PushGatewayConfig,
        resolver: Arc<dyn MlsDsIdentityResolver>,
        transport: Arc<dyn PushGatewayTransport>,
    ) -> Self {
        Self {
            db_pool,
            config,
            resolver,
            transport,
            jti_replay_cache: DashMap::new(),
            per_key_buckets: DashMap::new(),
            per_ds_buckets: DashMap::new(),
        }
    }

    /// `own_delivery_service_did` is the delivery service this gateway routes
    /// chat to (`mls.service_did`). Unless
    /// [`DECLARATION_DELIVERY_SERVICES_ENV`] says otherwise, it is the only
    /// delivery service an account's chat declaration may bind push keys to;
    /// `None` leaves that fallback off.
    pub fn new_postgres(
        db_pool: PgPool,
        push_config: &PushConfig,
        base_url: &str,
        raw_http_client: reqwest::Client,
        own_delivery_service_did: Option<&str>,
    ) -> Result<Self> {
        let plc_url = std::env::var("PLC_DIRECTORY_URL")
            .unwrap_or_else(|_| "https://plc.directory".to_string());
        let env_services = std::env::var(DECLARATION_DELIVERY_SERVICES_ENV).ok();
        let declaration_services =
            declaration_delivery_services(env_services.as_deref(), own_delivery_service_did);
        // `PushServices::new` builds a placeholder gateway with nothing
        // configured; only a configured one is worth a startup line.
        if env_services.is_some() || own_delivery_service_did.is_some() {
            tracing::info!(
                allowed_delivery_services = ?declaration_services,
                "Push gateway chat-declaration fallback for accounts without #atproto_mls"
            );
        }
        let resolver = Arc::new(
            HttpMlsDsIdentityResolver::new(raw_http_client.clone(), plc_url)
                .with_declaration_fallback(declaration_services),
        );
        let transport = Arc::new(LivePushGatewayTransport::from_config(
            &push_config.apns,
            raw_http_client,
        )?);
        let config = PushGatewayConfig::from_push_and_server_config(push_config, base_url)?;
        Ok(Self::new(db_pool, config, resolver, transport))
    }

    pub fn resolver(&self) -> &Arc<dyn MlsDsIdentityResolver> {
        &self.resolver
    }

    fn build_token_aad(
        push_key_sha256: &[u8; 32],
        account_did: &str,
        device_id: &str,
        app_id: &str,
        platform: GatewayPlatform,
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(128);
        aad.extend_from_slice(b"catbird-push-gw-token-v1:");
        aad.extend_from_slice(push_key_sha256);
        aad.push(b'|');
        aad.extend_from_slice(account_did.as_bytes());
        aad.push(b'|');
        aad.extend_from_slice(device_id.as_bytes());
        aad.push(b'|');
        aad.extend_from_slice(app_id.as_bytes());
        aad.push(b'|');
        aad.extend_from_slice(platform.as_db_str().as_bytes());
        aad
    }

    fn encrypt_native_token(&self, aad: &[u8], native_token: &str) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.config.token_encryption_key)
            .map_err(|_| anyhow!("invalid AES-256-GCM key length"))?;
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(
                (&nonce_bytes).into(),
                AeadPayload {
                    msg: native_token.as_bytes(),
                    aad,
                },
            )
            .map_err(|_| anyhow!("failed to encrypt native push token"))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn decrypt_native_token(&self, aad: &[u8], encrypted: &[u8]) -> Result<String> {
        if encrypted.len() < 12 + 16 {
            return Err(anyhow!("encrypted native token truncated"));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.config.token_encryption_key)
            .map_err(|_| anyhow!("invalid AES-256-GCM key length"))?;
        let (nonce_slice, ct) = encrypted.split_at(12);
        let nonce_arr: [u8; 12] = nonce_slice
            .try_into()
            .map_err(|_| anyhow!("invalid AES-256-GCM nonce length"))?;
        let pt = cipher
            .decrypt((&nonce_arr).into(), AeadPayload { msg: ct, aad })
            .map_err(|_| anyhow!("failed to decrypt native push token"))?;
        String::from_utf8(pt).context("decrypted native push token is not UTF-8")
    }

    /// Issue a fresh 256-bit CSPRNG `push_key` bound to `(account_did, device_id, app_id, allowed_mls_service_did)`.
    pub async fn register_key(
        &self,
        account_did: &str,
        session_id: &str,
        req: &RegisterKey,
    ) -> AppResult<RegisterKeyOutput> {
        self.register_key_with_optional_session(account_did, Some(session_id), req)
            .await
    }

    /// Issue a fresh 256-bit CSPRNG `push_key` for either a Nest session (`session_id = Some(..)`)
    /// or an external PDS `ServiceJWT` caller (`session_id = None`, `D-09`).
    pub async fn register_key_with_optional_session(
        &self,
        account_did: &str,
        session_id: Option<&str>,
        req: &RegisterKey,
    ) -> AppResult<RegisterKeyOutput> {
        let session_fingerprint =
            session_id.map(crate::services::push::registry::normalize_or_hash_session_fingerprint);
        let app_id = req.app_id.as_str().trim();
        if app_id.is_empty() || app_id.len() > 128 || !app_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(AppError::BadRequest("InvalidRequest: invalid appId".into()));
        }
        let device_id = req.device_id.as_str().trim();
        if Uuid::parse_str(device_id).is_err() {
            return Err(AppError::BadRequest(
                "InvalidRequest: deviceId must be a canonical 36-char UUID".into(),
            ));
        }
        let native_token = req.native_token.as_str().trim();
        if native_token.len() < 8 || native_token.len() > 4096 {
            return Err(AppError::BadRequest(
                "InvalidRequest: nativeToken length out of bounds".into(),
            ));
        }
        let Some(platform) = GatewayPlatform::from_lexicon(&req.platform) else {
            return Err(AppError::BadRequest(
                "InvalidRequest: unsupported push platform".into(),
            ));
        };

        let delivery_service = self
            .resolver
            .resolve_user_push_delivery_service(account_did)
            .await
            .map_err(|e| {
                tracing::warn!(did = %account_did, error = %e, "Failed to resolve delivery service for registerKey");
                register_key_resolution_error(&e)
            })?;
        tracing::info!(
            did = %account_did,
            delivery_service = %delivery_service.did,
            source = delivery_service.source.as_str(),
            "Binding push key to delivery service"
        );
        let allowed_mls_service_did = delivery_service.did;

        let mut raw_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw_key);
        let push_key = BASE64URL.encode(raw_key);
        let push_key_sha256: [u8; 32] = Sha256::digest(push_key.as_bytes()).into();

        let aad = Self::build_token_aad(&push_key_sha256, account_did, device_id, app_id, platform);
        let encrypted_token = self
            .encrypt_native_token(&aad, native_token)
            .map_err(|e| AppError::Internal(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO push_gateway_keys (
                push_key_sha256,
                account_did,
                device_id,
                app_id,
                platform,
                encrypted_native_token,
                allowed_mls_service_did,
                auth_session_fingerprint,
                unregistered_at,
                revoked_at,
                created_at,
                updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, NOW(), NOW())
            ON CONFLICT (account_did, device_id, app_id) DO UPDATE SET
                push_key_sha256 = EXCLUDED.push_key_sha256,
                platform = EXCLUDED.platform,
                encrypted_native_token = EXCLUDED.encrypted_native_token,
                allowed_mls_service_did = EXCLUDED.allowed_mls_service_did,
                auth_session_fingerprint = EXCLUDED.auth_session_fingerprint,
                unregistered_at = NULL,
                revoked_at = NULL,
                updated_at = NOW()
            "#,
        )
        .bind(push_key_sha256.as_slice())
        .bind(account_did)
        .bind(device_id)
        .bind(app_id)
        .bind(platform.as_db_str())
        .bind(&encrypted_token)
        .bind(&allowed_mls_service_did)
        .bind(&session_fingerprint)
        .execute(&self.db_pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to persist push_gateway_keys row");
            AppError::Internal("Failed to persist push gateway registration".into())
        })?;

        let gateway_url = Uri::parse(self.config.gateway_url.clone())
            .map_err(|e| AppError::Internal(format!("Invalid configured gateway_url: {e}")))?;

        Ok(RegisterKeyOutput {
            app_id: app_id.into(),
            gateway_url,
            push_key,
        })
    }

    /// Revokes the keys one session registered for one app, when that session
    /// unregisters its push token. A revoked key answers `deliver` with the same
    /// 202 as an unknown key and never reaches a provider.
    pub async fn revoke_keys_for_session_app(
        &self,
        account_did: &str,
        session_id: &str,
        app_id: &str,
    ) -> Result<u64> {
        let session_fingerprint =
            crate::services::push::registry::normalize_or_hash_session_fingerprint(session_id);
        let res = sqlx::query(
            "UPDATE push_gateway_keys SET revoked_at = NOW(), updated_at = NOW() \
             WHERE account_did = $1 AND auth_session_fingerprint = $2 AND app_id = $3 \
               AND revoked_at IS NULL",
        )
        .bind(account_did)
        .bind(&session_fingerprint)
        .bind(app_id.trim())
        .execute(&self.db_pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Revoke all push gateway keys for an account (e.g. on sign-out / account cleanup).
    pub async fn revoke_keys_for_account(&self, account_did: &str) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE push_gateway_keys SET revoked_at = NOW(), updated_at = NOW() WHERE account_did = $1 AND revoked_at IS NULL",
        )
        .bind(account_did)
        .execute(&self.db_pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Authenticate an ATProto PDS `ServiceJWT` (`com.atproto.server.getServiceAuth`) for
    /// `POST /xrpc/blue.catbird.push.registerKey` (`D-09`).
    ///
    /// Verifies ES256 / ES256K signature against `iss`'s `#atproto` DID document key, enforces
    /// `lxm == "blue.catbird.push.registerKey"` and `aud` matching this gateway's service DID,
    /// and prevents `jti` replay within the token lifetime window.
    pub async fn authenticate_register_service_jwt(
        &self,
        auth_header: Option<&str>,
        extra_allowed_audiences: &[&str],
    ) -> AppResult<String> {
        let unauthorized = |msg: &'static str| AppError::AtprotoResponse {
            status: StatusCode::UNAUTHORIZED,
            error: "InvalidToken".to_string(),
            message: msg.to_string(),
        };

        let Some(raw_auth) = auth_header else {
            return Err(unauthorized("Missing Authorization Bearer token"));
        };
        let jwt = raw_auth
            .strip_prefix("Bearer ")
            .or_else(|| raw_auth.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= MAX_DELIVER_JWT_BYTES)
            .ok_or_else(|| unauthorized("Malformed Authorization Bearer header"))?;

        let mut parts = jwt.split('.');
        let (Some(hdr_b64), Some(claims_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(unauthorized("Malformed compact ServiceJWT"));
        };

        let hdr_bytes = BASE64URL
            .decode(hdr_b64)
            .map_err(|_| unauthorized("Invalid ServiceJWT header base64url"))?;
        let header: WakeJwtHeader = serde_json::from_slice(&hdr_bytes)
            .map_err(|_| unauthorized("Invalid ServiceJWT header JSON"))?;
        if header.jwk.is_some() || header.crit.is_some() {
            return Err(unauthorized("Unsupported ServiceJWT header extensions"));
        }
        if !matches!(header.alg.as_str(), "ES256" | "ES256K") {
            return Err(unauthorized("Unsupported ServiceJWT signing algorithm"));
        }
        if let Some(typ) = header.typ.as_deref() {
            if !matches!(typ, "JWT" | "jwt" | "at+jwt") {
                return Err(unauthorized("Invalid ServiceJWT typ"));
            }
        }

        let claims_bytes = BASE64URL
            .decode(claims_b64)
            .map_err(|_| unauthorized("Invalid ServiceJWT claims base64url"))?;
        let claims: RegisterServiceJwtClaims = serde_json::from_slice(&claims_bytes)
            .map_err(|_| unauthorized("Invalid ServiceJWT claims JSON"))?;

        let caller_did = claims.iss.trim();
        if caller_did.contains('#')
            || petrel_core::Did::parse(caller_did).is_err()
            || !(caller_did.starts_with("did:plc:") || caller_did.starts_with("did:web:"))
        {
            return Err(unauthorized("Invalid ServiceJWT issuer DID"));
        }

        if claims.lxm.as_deref() != Some("blue.catbird.push.registerKey") {
            return Err(unauthorized(
                "ServiceJWT lxm must equal blue.catbird.push.registerKey",
            ));
        }

        let aud_bare = match claims.aud.trim().split_once('#') {
            Some((did_part, "atproto_push" | "atproto_gateway")) => did_part,
            Some(_) => return Err(unauthorized("Invalid ServiceJWT audience fragment")),
            None => claims.aud.trim(),
        };
        let default_gw_did = Url::parse(&self.config.gateway_url).ok().and_then(|u| {
            u.host_str()
                .map(|h| format!("did:web:{}", h.to_ascii_lowercase()))
        });
        let aud_matches = default_gw_did.as_deref() == Some(aud_bare)
            || extra_allowed_audiences.iter().any(|allowed| {
                let allowed_bare = allowed.split_once('#').map_or(*allowed, |(d, _)| d);
                !allowed_bare.is_empty() && allowed_bare == aud_bare
            });
        if !aud_matches {
            return Err(unauthorized("ServiceJWT aud does not match gateway DID"));
        }

        let now = Utc::now().timestamp();
        if claims.exp < now - 5 || claims.exp > now + REGISTER_SERVICE_JWT_MAX_LIFETIME_SECS {
            return Err(unauthorized(
                "ServiceJWT exp expired or exceeds 300s window",
            ));
        }
        if let Some(iat) = claims.iat {
            if iat > now + JWT_MAX_SKEW_SECS
                || claims.exp < iat
                || claims.exp > iat + REGISTER_SERVICE_JWT_MAX_LIFETIME_SECS
            {
                return Err(unauthorized("ServiceJWT iat outside allowed window"));
            }
        }
        let jti = claims
            .jti
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or_else(|| unauthorized("ServiceJWT missing valid jti"))?
            .to_string();

        let sig_bytes = BASE64URL
            .decode(sig_b64)
            .map_err(|_| unauthorized("Invalid ServiceJWT signature base64url"))?;
        let signing_input = format!("{hdr_b64}.{claims_b64}");

        let vk = self
            .resolver
            .resolve_ds_atproto_key(caller_did, false)
            .await
            .map_err(|_| unauthorized("Unable to resolve caller #atproto key"))?;

        let verified = if vk
            .verify_with_options(
                &sig_bytes,
                signing_input.as_bytes(),
                &header.alg,
                petrel::crypto::ATProtoSignatureVerificationOptions::JWT,
            )
            .unwrap_or(false)
        {
            true
        } else if let Ok(refreshed_vk) =
            self.resolver.resolve_ds_atproto_key(caller_did, true).await
        {
            refreshed_vk
                .verify_with_options(
                    &sig_bytes,
                    signing_input.as_bytes(),
                    &header.alg,
                    petrel::crypto::ATProtoSignatureVerificationOptions::JWT,
                )
                .unwrap_or(false)
        } else {
            false
        };
        if !verified {
            return Err(unauthorized("ServiceJWT signature verification failed"));
        }

        if self.jti_replay_cache.len() > 4096 {
            self.jti_replay_cache.retain(|_, exp_at| *exp_at > now);
        }
        if self.jti_replay_cache.len() >= MAX_JTI_CACHE_ENTRIES {
            return Err(AppError::RateLimitExceeded { retry_after: 5 });
        }
        let replay_key = (format!("register:{caller_did}"), jti);
        let expiry_deadline = claims.exp.max(now) + JWT_MAX_SKEW_SECS;
        match self.jti_replay_cache.entry(replay_key) {
            dashmap::mapref::entry::Entry::Occupied(mut occ) => {
                if *occ.get() > now {
                    return Err(unauthorized("Replayed ServiceJWT jti"));
                }
                occ.insert(expiry_deadline);
            }
            dashmap::mapref::entry::Entry::Vacant(vac) => {
                vac.insert(expiry_deadline);
            }
        }

        Ok(caller_did.to_string())
    }

    async fn authenticate_ds_jwt(
        &self,
        auth_header: Option<&str>,
        raw_body: &[u8],
    ) -> Result<String, (StatusCode, Value)> {
        let unauthorized = |msg: &'static str| {
            (
                StatusCode::UNAUTHORIZED,
                json!({ "error": "NotAuthorized", "message": msg }),
            )
        };

        let Some(raw_auth) = auth_header else {
            return Err(unauthorized("Missing Authorization Bearer JWT"));
        };
        let jwt = raw_auth
            .strip_prefix("Bearer ")
            .or_else(|| raw_auth.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= MAX_DELIVER_JWT_BYTES)
            .ok_or_else(|| unauthorized("Malformed Authorization Bearer header"))?;

        let mut parts = jwt.split('.');
        let (Some(hdr_b64), Some(claims_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(unauthorized("Malformed compact JWT"));
        };

        let hdr_bytes = BASE64URL
            .decode(hdr_b64)
            .map_err(|_| unauthorized("Invalid JWT header base64url"))?;
        let header: WakeJwtHeader = serde_json::from_slice(&hdr_bytes)
            .map_err(|_| unauthorized("Invalid JWT header JSON"))?;
        if header.jwk.is_some() || header.crit.is_some() {
            return Err(unauthorized("Unsupported JWT header extensions"));
        }
        if !matches!(header.alg.as_str(), "ES256" | "ES256K") {
            return Err(unauthorized("Unsupported JWT signing algorithm"));
        }
        if let Some(typ) = header.typ.as_deref() {
            if !matches!(typ, "atproto-push-wake+jwt" | "JWT" | "jwt") {
                return Err(unauthorized("Invalid JWT typ"));
            }
        }

        let claims_bytes = BASE64URL
            .decode(claims_b64)
            .map_err(|_| unauthorized("Invalid JWT claims base64url"))?;
        let claims: WakeJwtClaims = serde_json::from_slice(&claims_bytes)
            .map_err(|_| unauthorized("Invalid JWT claims JSON"))?;

        let caller_ds_did = claims
            .iss
            .split_once('#')
            .map(|(d, _)| d)
            .unwrap_or(claims.iss.as_str())
            .trim();
        if !(caller_ds_did.starts_with("did:web:") || caller_ds_did.starts_with("did:plc:")) {
            return Err(unauthorized("Invalid caller mls-ds DID"));
        }

        if claims.htm.as_deref() != Some("POST") {
            return Err(unauthorized("JWT htm/method must be POST"));
        }
        let htu_url = Url::parse(&claims.htu).map_err(|_| unauthorized("Invalid JWT htu URL"))?;
        if htu_url.path() != "/xrpc/blue.catbird.push.deliver" || htu_url.query().is_some() {
            return Err(unauthorized(
                "JWT htu path must be /xrpc/blue.catbird.push.deliver",
            ));
        }
        if let Ok(expected_gw) = Url::parse(&self.config.gateway_url) {
            if htu_url.origin() != expected_gw.origin() {
                return Err(unauthorized("JWT htu origin mismatch"));
            }
        }

        let now = Utc::now().timestamp();
        if (now - claims.iat).abs() > JWT_MAX_SKEW_SECS {
            return Err(unauthorized("JWT iat outside +-60s skew window"));
        }
        if claims.exp < now - 5 || claims.exp > claims.iat + JWT_MAX_LIFETIME_SECS {
            return Err(unauthorized("JWT exp expired or exceeds 60s lifetime"));
        }
        if claims.jti.is_empty() || claims.jti.len() > 256 {
            return Err(unauthorized("Invalid JWT jti"));
        }

        // Constant-time body_sha256 check BEFORE DID key lookup or jti insertion.
        let actual_body_hex = hex_encode(&Sha256::digest(raw_body));
        let claimed_lower = claims.body_sha256.to_ascii_lowercase();
        if claimed_lower.len() != 64
            || actual_body_hex
                .as_bytes()
                .ct_eq(claimed_lower.as_bytes())
                .unwrap_u8()
                != 1
        {
            return Err(unauthorized("JWT body_sha256 mismatch"));
        }

        let sig_bytes = BASE64URL
            .decode(sig_b64)
            .map_err(|_| unauthorized("Invalid JWT signature base64url"))?;
        let signing_input = format!("{hdr_b64}.{claims_b64}");

        let vk = self
            .resolver
            .resolve_ds_atproto_key(caller_ds_did, false)
            .await
            .map_err(|_| unauthorized("Unable to resolve caller mls-ds #atproto key"))?;

        let verified = if vk
            .verify_with_options(
                &sig_bytes,
                signing_input.as_bytes(),
                &header.alg,
                petrel::crypto::ATProtoSignatureVerificationOptions::JWT,
            )
            .unwrap_or(false)
        {
            true
        } else if let Ok(refreshed_vk) = self
            .resolver
            .resolve_ds_atproto_key(caller_ds_did, true)
            .await
        {
            refreshed_vk
                .verify_with_options(
                    &sig_bytes,
                    signing_input.as_bytes(),
                    &header.alg,
                    petrel::crypto::ATProtoSignatureVerificationOptions::JWT,
                )
                .unwrap_or(false)
        } else {
            false
        };
        if !verified {
            return Err(unauthorized("JWT signature verification failed"));
        }

        // Prune expired jti entries opportunistically and atomically check/insert (iss, jti).
        if self.jti_replay_cache.len() > 4096 {
            self.jti_replay_cache.retain(|_, exp_at| *exp_at > now);
        }
        if self.jti_replay_cache.len() >= MAX_JTI_CACHE_ENTRIES {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                json!({ "error": "RateLimitExceeded", "message": "Replay cache saturated" }),
            ));
        }
        let replay_key = (caller_ds_did.to_string(), claims.jti);
        let expiry_deadline = now + JTI_CACHE_TTL_SECS;
        match self.jti_replay_cache.entry(replay_key) {
            dashmap::mapref::entry::Entry::Occupied(mut occ) => {
                if *occ.get() > now {
                    return Err(unauthorized("Replayed mls-ds JWT jti"));
                }
                occ.insert(expiry_deadline);
            }
            dashmap::mapref::entry::Entry::Vacant(vac) => {
                vac.insert(expiry_deadline);
            }
        }

        Ok(caller_ds_did.to_string())
    }

    fn parse_and_validate_deliver_body(raw_body: &[u8]) -> Result<Deliver, (StatusCode, Value)> {
        let bad_req = |msg: &'static str| {
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": "InvalidRequest", "message": msg }),
            )
        };

        let mut root: Value =
            serde_json::from_slice(raw_body).map_err(|_| bad_req("Malformed JSON body"))?;
        let Some(root_obj) = root.as_object_mut() else {
            return Err(bad_req("Top-level body must be a JSON object"));
        };
        for key in root_obj.keys() {
            if !ALLOWED_TOP_LEVEL_KEYS.contains(&key.as_str()) {
                return Err(bad_req(
                    "Unexpected top-level field in push wake (display/alert fields forbidden)",
                ));
            }
        }

        let Some(payload_val) = root_obj.get_mut("payload") else {
            return Err(bad_req("Missing payload object"));
        };
        let Some(payload_obj) = payload_val.as_object_mut() else {
            return Err(bad_req("payload must be a JSON object"));
        };
        for key in payload_obj.keys() {
            if !ALLOWED_PAYLOAD_KEYS.contains(&key.as_str()) {
                return Err(bad_req(
                    "Unexpected field in wake payload (display strings forbidden)",
                ));
            }
        }

        // Normalize plain base64 string ciphertext into ATProto {"$bytes": "..."} if needed.
        if let Some(Value::String(b64)) = payload_obj.get("ciphertext").cloned() {
            payload_obj.insert("ciphertext".to_string(), json!({ "$bytes": b64 }));
        }

        let req: Deliver = serde_json::from_value(root)
            .map_err(|_| bad_req("Invalid Deliver schema or ciphertext encoding"))?;

        if matches!(req.payload.wake_kind, WakePayloadWakeKind::Unknown(_)) {
            return Err(bad_req("Unsupported wakeKind"));
        }
        let push_key = req.push_key.as_str();
        if push_key.len() < 32
            || push_key.len() > 256
            || !push_key.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(bad_req("Invalid pushKey format"));
        }
        let app_id = req.app_id.as_str();
        if app_id.is_empty() || app_id.len() > 128 || !app_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(bad_req("Invalid appId format"));
        }
        if Uuid::parse_str(req.payload.conversation_id.as_str()).is_err() {
            return Err(bad_req("conversationId must be a 36-char UUID"));
        }
        if req.payload.generation < 0 || req.payload.seq < 1 || req.payload.epoch < 0 {
            return Err(bad_req("generation, seq, or epoch out of bounds"));
        }
        if let Some(ct) = req.payload.ciphertext.as_ref() {
            if ct.0.is_empty() || ct.0.len() > MAX_INLINE_CIPHERTEXT_BYTES {
                return Err(bad_req(
                    "Inline ciphertext exceeds I12 2200-byte limit or is empty",
                ));
            }
        }

        Ok(req)
    }

    fn consume_ds_bucket(&self, caller_ds_did: &str) -> bool {
        let now = Instant::now();
        let mut entry = self
            .per_ds_buckets
            .entry(caller_ds_did.to_string())
            .or_insert_with(|| TokenBucketState {
                tokens: f64::from(self.config.per_ds_burst),
                last_refill: now,
            });
        entry.try_consume(self.config.per_ds_burst, self.config.per_ds_per_minute, now)
    }

    fn consume_key_bucket(&self, push_key_sha256: &[u8; 32]) -> bool {
        let now = Instant::now();
        let mut entry = self
            .per_key_buckets
            .entry(*push_key_sha256)
            .or_insert_with(|| TokenBucketState {
                tokens: f64::from(self.config.per_key_burst),
                last_refill: now,
            });
        entry.try_consume(
            self.config.per_key_burst,
            self.config.per_key_per_minute,
            now,
        )
    }

    /// Authenticate, authorize, rate-limit, and dispatch a push wake (`POST /xrpc/blue.catbird.push.deliver`).
    pub async fn deliver_wake(
        &self,
        auth_header: Option<&str>,
        raw_body: &[u8],
    ) -> (StatusCode, Value) {
        let caller_ds_did = match self.authenticate_ds_jwt(auth_header, raw_body).await {
            Ok(did) => did,
            Err(resp) => return resp,
        };

        let req = match Self::parse_and_validate_deliver_body(raw_body) {
            Ok(r) => r,
            Err(resp) => return resp,
        };

        if !self.consume_ds_bucket(&caller_ds_did) {
            PUSH_GATEWAY_RATE_LIMITED_TOTAL.inc();
            return (
                StatusCode::TOO_MANY_REQUESTS,
                json!({ "error": "RateLimited", "message": "Caller mls-ds rate limit exceeded" }),
            );
        }

        let push_key_sha256: [u8; 32] = Sha256::digest(req.push_key.as_bytes()).into();
        let uniform_accepted = || (StatusCode::ACCEPTED, json!({ "accepted": true }));

        let db_row = match sqlx::query(
            r#"
            SELECT account_did, device_id, app_id, platform, encrypted_native_token,
                   allowed_mls_service_did, unregistered_at, revoked_at
            FROM push_gateway_keys
            WHERE push_key_sha256 = $1
            "#,
        )
        .bind(push_key_sha256.as_slice())
        .fetch_optional(&self.db_pool)
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "Database error querying push_gateway_keys");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({ "error": "InternalServerError", "message": "Push gateway unavailable" }),
                );
            }
        };

        let caller_did_hash = Sha256::digest(caller_ds_did.as_bytes());
        let req_app_hash = Sha256::digest(req.app_id.as_bytes());

        let Some(row) = db_row else {
            // Dummy constant-time comparisons to equalize execution path on unknown keys.
            let dummy_did_hash = Sha256::digest(b"did:web:dummy.invalid");
            let dummy_app_hash = Sha256::digest(b"invalid.app");
            let _ = caller_did_hash.ct_eq(&dummy_did_hash) & req_app_hash.ct_eq(&dummy_app_hash);
            PUSH_GATEWAY_UNKNOWN_KEY_TOTAL.inc();
            return uniform_accepted();
        };

        let account_did: String = row.get("account_did");
        let device_id: String = row.get("device_id");
        let row_app_id: String = row.get("app_id");
        let platform_str: String = row.get("platform");
        let encrypted_native_token: Vec<u8> = row.get("encrypted_native_token");
        let allowed_mls_service_did: String = row.get("allowed_mls_service_did");
        let unregistered_at: Option<chrono::DateTime<Utc>> = row.get("unregistered_at");
        let revoked_at: Option<chrono::DateTime<Utc>> = row.get("revoked_at");

        let allowed_did_hash = Sha256::digest(allowed_mls_service_did.as_bytes());
        let row_app_hash = Sha256::digest(row_app_id.as_bytes());
        let authorized = (caller_did_hash.ct_eq(&allowed_did_hash)
            & req_app_hash.ct_eq(&row_app_hash))
        .unwrap_u8()
            == 1;

        if !authorized {
            PUSH_GATEWAY_SPOOFED_CALLER_TOTAL.inc();
            tracing::warn!(
                caller_ds_did = %caller_ds_did,
                expected_mls_service_did = %allowed_mls_service_did,
                "Dropped push wake with mismatched caller_ds_did or app_id"
            );
            return uniform_accepted();
        }

        if revoked_at.is_some() {
            return uniform_accepted();
        }

        if unregistered_at.is_some() {
            return (
                StatusCode::GONE,
                json!({ "error": "PushTokenGone", "message": "Native push token is unregistered" }),
            );
        }

        // Only authorized callers for active keys reach the per-key token bucket.
        if !self.consume_key_bucket(&push_key_sha256) {
            PUSH_GATEWAY_RATE_LIMITED_TOTAL.inc();
            return (
                StatusCode::TOO_MANY_REQUESTS,
                json!({ "error": "RateLimited", "message": "Per-device push rate limit exceeded" }),
            );
        }

        let Ok(platform) = GatewayPlatform::from_db_str(&platform_str) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": "InternalServerError", "message": "Invalid stored platform" }),
            );
        };
        let aad = Self::build_token_aad(
            &push_key_sha256,
            &account_did,
            &device_id,
            &row_app_id,
            platform,
        );
        let Ok(native_token) = self.decrypt_native_token(&aad, &encrypted_native_token) else {
            tracing::error!(did = %account_did, device_id = %device_id, "Failed to decrypt stored native push token");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": "InternalServerError", "message": "Token decryption failed" }),
            );
        };

        let dispatched = match build_wake_dispatch(
            self.config.wake_envelope,
            WakeDispatchInput {
                platform,
                app_id: row_app_id,
                native_token,
                account_did: &account_did,
                push_key: req.push_key.as_str(),
                wake_kind: req.payload.wake_kind.as_str(),
                conversation_id: req.payload.conversation_id.as_str(),
                generation: req.payload.generation,
                seq: req.payload.seq,
                epoch: req.payload.epoch,
                ciphertext: req.payload.ciphertext.as_ref().map(|b| b.0.as_slice()),
                utc_day: &Utc::now().format("%Y-%m-%d").to_string(),
            },
        ) {
            Ok(dispatched) => dispatched,
            Err(error) => {
                tracing::error!(error = %error, "Failed to build chat wake envelope");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({ "error": "InternalServerError", "message": "Wake envelope construction failed" }),
                );
            }
        };

        match self.transport.send(dispatched).await {
            Ok(GatewayDeliveryOutcome::Delivered) => {
                PUSH_GATEWAY_DELIVERIES_TOTAL.inc();
                uniform_accepted()
            }
            Ok(GatewayDeliveryOutcome::TokenUnregistered) => {
                let _ = sqlx::query(
                    "UPDATE push_gateway_keys SET unregistered_at = NOW(), updated_at = NOW() WHERE push_key_sha256 = $1",
                )
                .bind(push_key_sha256.as_slice())
                .execute(&self.db_pool)
                .await;
                (
                    StatusCode::GONE,
                    json!({ "error": "PushTokenGone", "message": "Native push token is unregistered" }),
                )
            }
            Err(e) => {
                tracing::warn!(error = %e, "Transient native push transport error");
                (
                    StatusCode::BAD_GATEWAY,
                    json!({ "error": "UpstreamPushError", "message": "Native push delivery failed" }),
                )
            }
        }
    }
}

#[cfg(test)]
mod register_key_resolution_error_tests {
    use super::*;
    use axum::response::IntoResponse;

    async fn answer(error: UserDeliveryServiceError) -> (StatusCode, Value) {
        let response = register_key_resolution_error(&error).into_response();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn permanent_causes_keep_the_invalid_mls_service_did_error() {
        for error in [
            UserDeliveryServiceError::NotDeclared,
            UserDeliveryServiceError::Invalid("'value' must be an object".into()),
            UserDeliveryServiceError::NotAllowed("did:web:evil-ds.example.com".into()),
            UserDeliveryServiceError::Unresolvable(
                "DID document lookup for did:plc:gone returned HTTP 404 Not Found".into(),
            ),
        ] {
            let (status, body) = answer(error.clone()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{error:?}");
            let message = body["message"].as_str().unwrap_or_default();
            assert!(
                message.starts_with("InvalidMlsServiceDid: "),
                "{error:?} answered {body}"
            );
            assert!(
                !message.contains("evil-ds")
                    && !message.contains("must be an object")
                    && !message.contains("HTTP 404"),
                "the answer must not echo record contents or lookup details: {body}"
            );
        }
    }

    #[tokio::test]
    async fn an_unreadable_source_is_a_retryable_503() {
        let (status, body) = answer(UserDeliveryServiceError::Unavailable(
            "getRecord answered HTTP 503".into(),
        ))
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "TemporarilyUnavailable");
    }
}

#[cfg(test)]
mod did_document_body_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const CHUNK: usize = 64 * 1024;

    /// A response with no declared length that would stream `chunks` chunks,
    /// counting how many the reader actually pulled.
    fn streamed_response(chunks: usize, pulled: Arc<AtomicUsize>) -> reqwest::Response {
        let stream = futures_util::stream::iter((0..chunks).map(move |_| {
            pulled.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(bytes::Bytes::from(vec![b'a'; CHUNK]))
        }));
        reqwest::Response::from(http::Response::new(reqwest::Body::wrap_stream(stream)))
    }

    #[tokio::test]
    async fn undeclared_oversized_body_is_cut_off_at_the_cap() {
        let pulled = Arc::new(AtomicUsize::new(0));
        // 64 MiB on offer; the cap is 256 KiB.
        let resp = streamed_response(1024, pulled.clone());

        let err = read_did_document_body(resp, "did:web:evil.example")
            .await
            .expect_err("oversized DID document must be refused");

        assert!(err.to_string().contains("exceeds 256 KiB"), "{err}");
        assert!(
            pulled.load(Ordering::SeqCst) <= MAX_DID_DOCUMENT_BYTES / CHUNK + 2,
            "reader pulled {} chunks; it must stop at the cap, not drain the body",
            pulled.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn declared_oversized_body_is_refused_without_reading() {
        let pulled = Arc::new(AtomicUsize::new(0));
        let counter = pulled.clone();
        let stream = futures_util::stream::iter((0..8).map(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(bytes::Bytes::from(vec![b'a'; CHUNK]))
        }));
        let mut response = http::Response::new(reqwest::Body::wrap_stream(stream));
        response.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from(MAX_DID_DOCUMENT_BYTES as u64 + 1),
        );

        let err = read_did_document_body(reqwest::Response::from(response), "did:web:evil.example")
            .await
            .expect_err("declared oversized DID document must be refused");

        assert!(err.to_string().contains("exceeds 256 KiB"), "{err}");
        assert_eq!(pulled.load(Ordering::SeqCst), 0, "body must not be read");
    }

    #[tokio::test]
    async fn body_at_the_cap_is_returned_whole() {
        let pulled = Arc::new(AtomicUsize::new(0));
        let resp = streamed_response(MAX_DID_DOCUMENT_BYTES / CHUNK, pulled);

        let body = read_did_document_body(resp, "did:web:ok.example")
            .await
            .expect("a document exactly at the cap is allowed");

        assert_eq!(body.len(), MAX_DID_DOCUMENT_BYTES);
    }
}

/// Everything needed to build the provider-facing envelopes for one chat wake.
pub struct WakeDispatchInput<'a> {
    pub platform: GatewayPlatform,
    pub app_id: String,
    pub native_token: String,
    pub account_did: &'a str,
    pub push_key: &'a str,
    pub wake_kind: &'a str,
    pub conversation_id: &'a str,
    pub generation: i64,
    pub seq: i64,
    pub epoch: i64,
    pub ciphertext: Option<&'a [u8]>,
    /// `YYYY-MM-DD` in UTC; only the sealed form uses it (daily collapse-id rotation).
    pub utc_day: &'a str,
}

/// Build the APNs and FCM envelopes for one chat wake.
///
/// Nest alone constructs the APNs `aps` block and the FCM data-only message; the
/// delivery service supplies no display strings. In [`WakeEnvelopeMode::SealedV2`]
/// the `catbird` object is the opaque constant-size blob from [`wake_envelope`], and
/// the collapse id is derived from the push key so it rotates daily. In
/// [`WakeEnvelopeMode::ClearV1`] both are the original clear forms.
pub fn build_wake_dispatch(
    mode: WakeEnvelopeMode,
    input: WakeDispatchInput<'_>,
) -> Result<DispatchedGatewayPush> {
    let (catbird_val, collapse_id) = match mode {
        WakeEnvelopeMode::SealedV2 => {
            let keys = wake_envelope::WakeKeys::derive(input.push_key);
            let header = wake_envelope::WakeHeader {
                wake_kind: input.wake_kind.to_string(),
                conversation_id: input.conversation_id.to_string(),
                generation: input.generation,
                seq: input.seq,
                epoch: input.epoch,
                fetch_required: input.ciphertext.is_none(),
            };
            (
                wake_envelope::seal(&keys, &input.app_id, &header, input.ciphertext)?,
                keys.collapse_id(input.conversation_id, input.utc_day),
            )
        }
        WakeEnvelopeMode::ClearV1 => {
            let mut collapse_hasher = Sha256::new();
            collapse_hasher.update(input.push_key.as_bytes());
            collapse_hasher.update(input.conversation_id.as_bytes());
            let collapse_id = hex_encode(&collapse_hasher.finalize())[..32].to_string();

            let mut catbird_obj = serde_json::Map::new();
            catbird_obj.insert(
                "recipientAccountHash".to_string(),
                Value::String(hex_encode(&Sha256::digest(input.account_did.as_bytes()))),
            );
            catbird_obj.insert(
                "wakeKind".to_string(),
                Value::String(input.wake_kind.to_string()),
            );
            catbird_obj.insert(
                "conversationId".to_string(),
                Value::String(input.conversation_id.to_string()),
            );
            catbird_obj.insert("generation".to_string(), json!(input.generation));
            catbird_obj.insert("seq".to_string(), json!(input.seq));
            catbird_obj.insert("epoch".to_string(), json!(input.epoch));
            catbird_obj.insert(
                "fetchRequired".to_string(),
                Value::Bool(input.ciphertext.is_none()),
            );
            if let Some(ct) = input.ciphertext {
                catbird_obj.insert(
                    "ciphertext".to_string(),
                    Value::String(BASE64_STD.encode(ct)),
                );
            }
            (Value::Object(catbird_obj), collapse_id)
        }
    };

    let apns_envelope = json!({
        "aps": {
            "alert": { "body": "New message" },
            "mutable-content": 1
        },
        "catbird": catbird_val,
    });
    let fcm_envelope = json!({
        "message": {
            "token": input.native_token,
            "android": {
                "priority": "high",
                "collapse_key": collapse_id,
            },
            "data": {
                "catbird": serde_json::to_string(&apns_envelope["catbird"])?,
            }
        }
    });

    Ok(DispatchedGatewayPush {
        platform: input.platform,
        app_id: input.app_id,
        native_token: input.native_token,
        collapse_id,
        apns_envelope,
        fcm_envelope,
    })
}

#[cfg(test)]
mod gateway_key_resolution_tests {
    use super::*;

    #[test]
    fn release_mode_refuses_startup_when_gateway_and_session_keys_are_unset() {
        assert!(resolve_gateway_token_encryption_key(None, None, false).is_err());
        assert!(resolve_gateway_token_encryption_key(Some(""), Some("   "), false).is_err());
    }

    #[test]
    fn debug_mode_generates_fresh_csprng_key_when_unset() {
        let k1 = resolve_gateway_token_encryption_key(None, None, true)
            .expect("debug mode generates CSPRNG key");
        let k2 = resolve_gateway_token_encryption_key(None, None, true)
            .expect("debug mode generates CSPRNG key");
        assert_ne!(k1, [0u8; 32]);
        assert_ne!(k2, [0u8; 32]);
        assert_ne!(
            k1, k2,
            "ephemeral debug keys must come from OsRng, never a deterministic seed"
        );
    }

    #[test]
    fn malformed_or_short_or_zero_keys_are_always_rejected() {
        for allow_debug in [false, true] {
            assert!(
                resolve_gateway_token_encryption_key(Some("not-32-bytes"), None, allow_debug)
                    .is_err()
            );
            assert!(
                resolve_gateway_token_encryption_key(None, Some("short"), allow_debug).is_err()
            );
            let zero_b64 = BASE64_STD.encode([0u8; 32]);
            assert!(
                resolve_gateway_token_encryption_key(Some(&zero_b64), None, allow_debug).is_err()
            );
            assert!(
                resolve_gateway_token_encryption_key(None, Some(&zero_b64), allow_debug).is_err()
            );
        }
    }

    #[test]
    fn accepts_valid_32_byte_gateway_or_session_keys_with_domain_separation() {
        let raw_gw = [0x42u8; 32];
        let gw_b64 = BASE64_STD.encode(raw_gw);
        let resolved_gw = resolve_gateway_token_encryption_key(Some(&gw_b64), None, false).unwrap();
        assert_eq!(resolved_gw, raw_gw);

        let raw_sess = [0x7Au8; 32];
        let sess_hex = hex_encode(&raw_sess);
        let resolved_from_sess =
            resolve_gateway_token_encryption_key(None, Some(&sess_hex), false).unwrap();
        assert_ne!(resolved_from_sess, raw_sess);
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(b"catbird-push-gateway-token-key-v1:");
        expected_hasher.update(raw_sess);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&expected_hasher.finalize());
        assert_eq!(resolved_from_sess, expected);
    }
}

#[cfg(test)]
mod wake_dispatch_tests {
    use super::*;

    const PUSH_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const CONVO: &str = "3f0e6f0a-6f0b-4c5e-9d55-0a4e4f6c2b11";
    const DID: &str = "did:plc:alicecatbird000000000001";

    fn input<'a>(
        platform: GatewayPlatform,
        ciphertext: Option<&'a [u8]>,
        utc_day: &'a str,
    ) -> WakeDispatchInput<'a> {
        WakeDispatchInput {
            platform,
            app_id: "blue.catbird".into(),
            native_token: "native-token-0123456789".into(),
            account_did: DID,
            push_key: PUSH_KEY,
            wake_kind: "applicationMessage",
            conversation_id: CONVO,
            generation: 0,
            seq: 7,
            epoch: 3,
            ciphertext,
            utc_day,
        }
    }

    #[test]
    fn envelope_mode_defaults_to_sealed_v2_and_requires_explicit_clear_rollback() {
        assert_eq!(WakeEnvelopeMode::default(), WakeEnvelopeMode::SealedV2);
        assert_eq!(
            WakeEnvelopeMode::from_env_value(None),
            WakeEnvelopeMode::SealedV2
        );
        assert_eq!(
            WakeEnvelopeMode::from_env_value(Some("")),
            WakeEnvelopeMode::SealedV2
        );
        assert_eq!(
            WakeEnvelopeMode::from_env_value(Some(" Sealed ")),
            WakeEnvelopeMode::SealedV2
        );
        assert_eq!(
            WakeEnvelopeMode::from_env_value(Some("2")),
            WakeEnvelopeMode::SealedV2
        );
        assert_eq!(
            WakeEnvelopeMode::from_env_value(Some("unrecognized")),
            WakeEnvelopeMode::SealedV2
        );
        assert_eq!(
            WakeEnvelopeMode::from_env_value(Some("clear")),
            WakeEnvelopeMode::ClearV1
        );
        assert_eq!(
            WakeEnvelopeMode::from_env_value(Some(" CLEAR ")),
            WakeEnvelopeMode::ClearV1
        );
        assert_eq!(
            WakeEnvelopeMode::from_env_value(Some("1")),
            WakeEnvelopeMode::ClearV1
        );
    }

    #[test]
    fn clear_mode_is_byte_for_byte_the_version_one_payload() {
        let ct = [0xAB_u8; 16];
        let push = build_wake_dispatch(
            WakeEnvelopeMode::ClearV1,
            input(GatewayPlatform::Apns, Some(&ct), "2026-11-09"),
        )
        .unwrap();
        let mut hasher = Sha256::new();
        hasher.update(PUSH_KEY.as_bytes());
        hasher.update(CONVO.as_bytes());
        assert_eq!(push.collapse_id, hex_encode(&hasher.finalize())[..32]);
        assert_eq!(
            push.apns_envelope["catbird"],
            json!({
                "recipientAccountHash": hex_encode(&Sha256::digest(DID.as_bytes())),
                "wakeKind": "applicationMessage",
                "conversationId": CONVO,
                "generation": 0,
                "seq": 7,
                "epoch": 3,
                "fetchRequired": false,
                "ciphertext": BASE64_STD.encode(ct),
            })
        );
    }

    #[test]
    fn sealed_mode_shows_the_provider_nothing_and_opens_to_the_same_wake() {
        let ct = [0xAB_u8; 300];
        for platform in [GatewayPlatform::Apns, GatewayPlatform::Fcm] {
            let push = build_wake_dispatch(
                WakeEnvelopeMode::SealedV2,
                input(platform, Some(&ct), "2026-11-09"),
            )
            .unwrap();

            let visible = format!(
                "{}{}{}",
                push.apns_envelope, push.fcm_envelope, push.collapse_id
            );
            let did_hash = hex_encode(&Sha256::digest(DID.as_bytes()));
            for needle in [
                CONVO,
                DID,
                did_hash.as_str(),
                PUSH_KEY,
                "applicationMessage",
            ] {
                assert!(!visible.contains(needle), "provider can read {needle}");
            }
            assert_eq!(
                push.apns_envelope["aps"],
                json!({ "alert": { "body": "New message" }, "mutable-content": 1 })
            );

            let keys = wake_envelope::WakeKeys::derive(PUSH_KEY);
            let fcm_catbird: Value = serde_json::from_str(
                push.fcm_envelope["message"]["data"]["catbird"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(fcm_catbird, push.apns_envelope["catbird"]);
            let opened = wake_envelope::open(&keys, "blue.catbird", &fcm_catbird).unwrap();
            assert_eq!(opened.header.conversation_id, CONVO);
            assert_eq!(opened.header.wake_kind, "applicationMessage");
            assert_eq!(
                (
                    opened.header.generation,
                    opened.header.seq,
                    opened.header.epoch
                ),
                (0, 7, 3)
            );
            assert!(!opened.header.fetch_required);
            assert_eq!(opened.ciphertext.as_deref(), Some(&ct[..]));
            assert_eq!(push.collapse_id, keys.collapse_id(CONVO, "2026-11-09"));
            assert_eq!(
                push.fcm_envelope["message"]["android"]["collapse_key"],
                push.collapse_id
            );
        }
    }

    #[test]
    fn sealed_wakes_are_one_size_on_both_providers_and_within_their_limits() {
        let big = [1_u8; MAX_INLINE_CIPHERTEXT_BYTES];
        let mut apns = std::collections::BTreeSet::new();
        let mut fcm = std::collections::BTreeSet::new();
        for ciphertext in [None, Some(&big[..1]), Some(&big[..])] {
            let push = build_wake_dispatch(
                WakeEnvelopeMode::SealedV2,
                input(GatewayPlatform::Apns, ciphertext, "2026-11-09"),
            )
            .unwrap();
            apns.insert(serde_json::to_vec(&push.apns_envelope).unwrap().len());
            fcm.insert(
                serde_json::to_vec(&push.fcm_envelope["message"]["data"])
                    .unwrap()
                    .len(),
            );
        }
        assert_eq!(apns.len(), 1, "APNs sizes differ: {apns:?}");
        assert_eq!(fcm.len(), 1, "FCM sizes differ: {fcm:?}");
        assert!(*apns.first().unwrap() <= 4096, "{apns:?}");
        assert!(*fcm.first().unwrap() <= 4096, "{fcm:?}");
    }

    #[test]
    fn sealed_collapse_id_rotates_with_the_utc_day() {
        let today = build_wake_dispatch(
            WakeEnvelopeMode::SealedV2,
            input(GatewayPlatform::Apns, None, "2026-11-09"),
        )
        .unwrap();
        let again = build_wake_dispatch(
            WakeEnvelopeMode::SealedV2,
            input(GatewayPlatform::Apns, None, "2026-11-09"),
        )
        .unwrap();
        let tomorrow = build_wake_dispatch(
            WakeEnvelopeMode::SealedV2,
            input(GatewayPlatform::Apns, None, "2026-11-10"),
        )
        .unwrap();
        assert_eq!(today.collapse_id, again.collapse_id);
        assert_ne!(today.collapse_id, tomorrow.collapse_id);
        assert_ne!(
            today.apns_envelope["catbird"]["sealed"],
            again.apns_envelope["catbird"]["sealed"]
        );
    }
}
