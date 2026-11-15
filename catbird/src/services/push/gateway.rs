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
use atproto_spaces::{did_resolver::DidDocument, tokens::SpaceVerifyingKey};
use axum::http::StatusCode;
use base64::{
    engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD as BASE64URL},
    Engine as _,
};
use chrono::Utc;
use dashmap::DashMap;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;

use crate::{
    config::{ApnsConfig, PushConfig},
    error::{AppError, AppResult},
    metrics::{
        PUSH_GATEWAY_DELIVERIES_TOTAL, PUSH_GATEWAY_RATE_LIMITED_TOTAL,
        PUSH_GATEWAY_SPOOFED_CALLER_TOTAL, PUSH_GATEWAY_UNKNOWN_KEY_TOTAL,
    },
    services::validate_pds_url,
};
use catbird_atproto::generated::blue_catbird::push::{
    deliver::{Deliver, WakePayloadWakeKind},
    register_key::{RegisterKey, RegisterKeyOutput, RegisterKeyPlatform},
};
use jacquard_common::types::string::UriValue;

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

    pub fn from_lexicon<S: jacquard_common::BosStr>(p: &RegisterKeyPlatform<S>) -> Option<Self> {
        match p {
            RegisterKeyPlatform::Apns => Some(Self::Apns),
            RegisterKeyPlatform::ApnsSandbox => Some(Self::ApnsSandbox),
            RegisterKeyPlatform::Fcm => Some(Self::Fcm),
            RegisterKeyPlatform::Webpush => Some(Self::Webpush),
            RegisterKeyPlatform::Other(_) => None,
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

#[async_trait::async_trait]
pub trait MlsDsIdentityResolver: Send + Sync {
    /// Resolve `account_did`'s DID document and extract the canonical bare DID of its
    /// `#atproto_mls` (`AtprotoMLSDeliveryService`) service entry.
    async fn resolve_user_mls_service_did(&self, account_did: &str) -> Result<String>;

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
    user_mls_cache: DashMap<String, (String, Instant)>,
    cache_ttl: Duration,
}

impl HttpMlsDsIdentityResolver {
    pub fn new(http_client: reqwest::Client, plc_directory_url: impl Into<String>) -> Self {
        Self {
            http_client,
            plc_directory_url: plc_directory_url.into(),
            ds_key_cache: DashMap::new(),
            user_mls_cache: DashMap::new(),
            cache_ttl: Duration::from_secs(300),
        }
    }

    async fn fetch_did_document(&self, did: &str) -> Result<Vec<u8>> {
        let did = did.trim();
        let url = if let Some(plc_suffix) = did.strip_prefix("did:plc:") {
            if plc_suffix.len() != 24
                || !plc_suffix
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
            {
                return Err(anyhow!("invalid did:plc identifier '{did}'"));
            }
            format!("{}/{}", self.plc_directory_url.trim_end_matches('/'), did)
        } else if let Some(web_rest) = did.strip_prefix("did:web:") {
            let mut segments = web_rest.split(':');
            let raw_host = segments
                .next()
                .filter(|h| !h.is_empty())
                .ok_or_else(|| anyhow!("missing host in did:web '{did}'"))?;
            let host = urlencoding::decode(raw_host)
                .map_err(|e| anyhow!("invalid did:web host encoding: {e}"))?;
            let path_segments: Vec<&str> = segments.collect();
            if path_segments.is_empty() {
                format!("https://{host}/.well-known/did.json")
            } else {
                for seg in &path_segments {
                    if seg.is_empty() || *seg == "." || *seg == ".." || seg.contains('/') {
                        return Err(anyhow!("invalid path segment in did:web '{did}'"));
                    }
                }
                format!("https://{host}/{}/did.json", path_segments.join("/"))
            }
        } else {
            return Err(anyhow!("unsupported DID method '{did}'"));
        };

        validate_pds_url(&url).map_err(|e| anyhow!("DID resolution URL blocked: {e}"))?;
        let resp = self
            .http_client
            .get(&url)
            .header(
                reqwest::header::ACCEPT,
                "application/did+ld+json, application/json",
            )
            .send()
            .await
            .with_context(|| format!("fetch DID document for {did}"))?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "DID document lookup for {did} returned HTTP {}",
                resp.status()
            ));
        }
        read_did_document_body(resp, did).await
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
async fn read_did_document_body(mut resp: reqwest::Response, did: &str) -> Result<Vec<u8>> {
    let too_large = || anyhow!("DID document for {did} exceeds 256 KiB");
    let declared = resp.content_length().or_else(|| {
        resp.headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
    });
    if declared.is_some_and(|len| len > MAX_DID_DOCUMENT_BYTES as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("read DID document for {did}"))?
    {
        if chunk.len() > MAX_DID_DOCUMENT_BYTES - body.len() {
            return Err(too_large());
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
    let entry = doc
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
        .ok_or_else(|| anyhow!("DID document for {user_did} has no #atproto_mls service"))?;

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
        return Ok(bare.to_string());
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
    Ok(did_web)
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
        let doc = DidDocument::parse_json(caller_ds_did, &doc_bytes)
            .map_err(|e| anyhow!("parse DID document for {caller_ds_did}: {e}"))?;
        let vk = doc
            .atproto_key
            .ok_or_else(|| anyhow!("DID document for {caller_ds_did} has no #atproto key"))?;
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

#[derive(Debug, Clone)]
pub struct PushGatewayConfig {
    pub gateway_url: String,
    pub token_encryption_key: [u8; 32],
    pub per_key_burst: u32,
    pub per_key_per_minute: u32,
    pub per_ds_burst: u32,
    pub per_ds_per_minute: u32,
}

impl PushGatewayConfig {
    pub fn from_push_and_server_config(push: &PushConfig, base_url: &str) -> Self {
        let mut token_encryption_key = [0u8; 32];
        if let Ok(hex_or_b64) = std::env::var("CATBIRD_PUSH_GATEWAY_TOKEN_KEY") {
            let trimmed = hex_or_b64.trim();
            if let Ok(decoded) = BASE64URL
                .decode(trimmed)
                .or_else(|_| BASE64_STD.decode(trimmed))
            {
                if decoded.len() == 32 {
                    token_encryption_key.copy_from_slice(&decoded);
                }
            }
            if token_encryption_key == [0u8; 32] {
                let digest = Sha256::digest(trimmed.as_bytes());
                token_encryption_key.copy_from_slice(&digest);
            }
        } else if let Ok(sess_key) = std::env::var("SESSION_ENCRYPTION_KEY") {
            let mut hasher = Sha256::new();
            hasher.update(b"catbird-push-gateway-token-key-v1:");
            hasher.update(sess_key.as_bytes());
            token_encryption_key.copy_from_slice(&hasher.finalize());
        } else {
            // Ephemeral process key fallback for local dev/tests when env key is unset.
            let mut hasher = Sha256::new();
            hasher.update(b"catbird-push-gateway-default-dev-key:");
            hasher.update(push.service_did.as_deref().unwrap_or("nest").as_bytes());
            token_encryption_key.copy_from_slice(&hasher.finalize());
        }

        let gateway_url = format!(
            "{}/xrpc/blue.catbird.push.deliver",
            base_url.trim_end_matches('/')
        );
        Self {
            gateway_url,
            token_encryption_key,
            per_key_burst: 10,
            per_key_per_minute: 30,
            per_ds_burst: 200,
            per_ds_per_minute: 600,
        }
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

    pub fn new_postgres(
        db_pool: PgPool,
        push_config: &PushConfig,
        base_url: &str,
        raw_http_client: reqwest::Client,
    ) -> Result<Self> {
        let plc_url = std::env::var("PLC_DIRECTORY_URL")
            .unwrap_or_else(|_| "https://plc.directory".to_string());
        let resolver = Arc::new(HttpMlsDsIdentityResolver::new(
            raw_http_client.clone(),
            plc_url,
        ));
        let transport = Arc::new(LivePushGatewayTransport::from_config(
            &push_config.apns,
            raw_http_client,
        )?);
        let config = PushGatewayConfig::from_push_and_server_config(push_config, base_url);
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
        let session_fingerprint =
            crate::services::push::registry::normalize_or_hash_session_fingerprint(session_id);
        if req.extra_data.as_ref().is_some_and(|m| !m.is_empty()) {
            return Err(AppError::BadRequest(
                "InvalidRequest: unexpected extra fields in registerKey".into(),
            ));
        }
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

        let allowed_mls_service_did = self
            .resolver
            .resolve_user_mls_service_did(account_did)
            .await
            .map_err(|e| {
                tracing::warn!(did = %account_did, error = %e, "Failed to resolve #atproto_mls DID for registerKey");
                AppError::BadRequest("InvalidMlsServiceDid: user DID document missing valid #atproto_mls service".into())
            })?;

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

        let gateway_url = UriValue::new_owned(self.config.gateway_url.clone())
            .map_err(|e| AppError::Internal(format!("Invalid configured gateway_url: {e}")))?;

        Ok(RegisterKeyOutput {
            app_id: app_id.into(),
            gateway_url,
            push_key: push_key.into(),
            extra_data: None,
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

        let verified = if vk.verify_raw(&header.alg, signing_input.as_bytes(), &sig_bytes) {
            true
        } else if let Ok(refreshed_vk) = self
            .resolver
            .resolve_ds_atproto_key(caller_ds_did, true)
            .await
        {
            refreshed_vk.verify_raw(&header.alg, signing_input.as_bytes(), &sig_bytes)
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

        if req.extra_data.as_ref().is_some_and(|m| !m.is_empty())
            || req
                .payload
                .extra_data
                .as_ref()
                .is_some_and(|m| !m.is_empty())
        {
            return Err(bad_req("Extra fields are forbidden in Deliver"));
        }
        if matches!(req.payload.wake_kind, WakePayloadWakeKind::Other(_)) {
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
            if ct.is_empty() || ct.len() > MAX_INLINE_CIPHERTEXT_BYTES {
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

        let convo_id = req.payload.conversation_id.as_str();
        let mut collapse_hasher = Sha256::new();
        collapse_hasher.update(req.push_key.as_bytes());
        collapse_hasher.update(convo_id.as_bytes());
        let collapse_id = hex_encode(&collapse_hasher.finalize())[..32].to_string();

        let recipient_account_hash = hex_encode(&Sha256::digest(account_did.as_bytes()));
        let mut catbird_obj = serde_json::Map::new();
        catbird_obj.insert(
            "recipientAccountHash".to_string(),
            Value::String(recipient_account_hash),
        );
        catbird_obj.insert(
            "wakeKind".to_string(),
            Value::String(req.payload.wake_kind.as_str().to_string()),
        );
        catbird_obj.insert(
            "conversationId".to_string(),
            Value::String(convo_id.to_string()),
        );
        catbird_obj.insert("generation".to_string(), json!(req.payload.generation));
        catbird_obj.insert("seq".to_string(), json!(req.payload.seq));
        catbird_obj.insert("epoch".to_string(), json!(req.payload.epoch));
        catbird_obj.insert(
            "fetchRequired".to_string(),
            Value::Bool(req.payload.ciphertext.is_none()),
        );
        if let Some(ct) = req.payload.ciphertext.as_ref() {
            catbird_obj.insert(
                "ciphertext".to_string(),
                Value::String(BASE64_STD.encode(ct)),
            );
        }
        let catbird_val = Value::Object(catbird_obj);

        // Nest exclusively constructs APNs `aps` and FCM data-only envelopes (zero mls-ds display strings).
        let apns_envelope = json!({
            "aps": {
                "alert": { "body": "New message" },
                "mutable-content": 1
            },
            "catbird": catbird_val,
        });
        let fcm_envelope = json!({
            "message": {
                "token": native_token,
                "android": {
                    "priority": "high",
                    "collapse_key": collapse_id,
                },
                "data": {
                    "catbird": serde_json::to_string(&apns_envelope["catbird"]).unwrap_or_default(),
                }
            }
        });

        let dispatched = DispatchedGatewayPush {
            platform,
            app_id: row_app_id,
            native_token,
            collapse_id,
            apns_envelope,
            fcm_envelope,
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
