//! AppView confidential OAuth client identity and authorization-code flow.
//!
//! Provides:
//! - `client-metadata.json` and published JWKS
//! - AppView-signed `atproto-client-attestation+jwt`
//! - OAuth 2.0 authorization-code flow with PAR and PKCE against user PDSes
//! - User OAuth session management and token renewal

use crate::auth::is_loopback_or_localhost;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use axum::{
    extract::{Query, State},
    response::Redirect,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Signer;
use p256::EncodedPoint;
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

use crate::auth::{parse_public_key_jwk, DidResolver, JwtHeader, PublicKeyJwk};
use crate::config::AppState;
use crate::error::{AppError, AuthReason};

/// TTL for pending OAuth authorization states (10 minutes).
pub const PENDING_STATE_TTL_SECS: i64 = 600;

/// The bare `atproto` scope is MANDATORY in every atproto OAuth authorization
/// request; a PDS rejects the request with `invalid_request` / `Missing "atproto"
/// scope` without it. The permissioned-data scope alone is not sufficient, which
/// a live authorization against spaces-alpha.host.bsky.network proved.
pub const CIRCLE_SCOPE: &str = "atproto space:blue.catbird.circle?authority=*&action=read";
pub const CALLBACK_DEEP_LINK: &str = "blue.catbird://oauth/circle-appview";
pub const MAX_OAUTH_METADATA_BYTES: usize = 256 * 1024; // 256 KiB
pub const MAX_OAUTH_RESPONSE_BYTES: usize = 256 * 1024; // 256 KiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClientMetadata {
    pub client_id: String,
    pub client_name: String,
    pub client_uri: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scope: String,
    pub token_endpoint_auth_method: String,
    pub token_endpoint_auth_signing_alg: String,
    pub jwks_uri: String,
    pub dpop_bound_access_tokens: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<PublicKeyJwk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAttestationClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

#[derive(Debug, Clone)]
pub struct PendingOAuthState {
    pub state: String,
    pub code_verifier: String,
    pub user_did: String,
    pub pds_endpoint: String,
    pub token_endpoint: String,
    pub auth_server_iss: Option<String>,
    pub created_at: DateTime<Utc>,
    pub in_flight: bool,
}

#[derive(Clone)]
pub struct UserOAuthSession {
    pub user_did: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_endpoint: String,
    /// Authorization server issuer. This, NOT the token endpoint, is the
    /// `aud` of a `client_assertion`; refresh needs it as much as the initial
    /// exchange does.
    pub auth_server_iss: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub scope: String,
    pub dpop_key: p256::ecdsa::SigningKey,
}

impl std::fmt::Debug for UserOAuthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserOAuthSession")
            .field("user_did", &self.user_did)
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_endpoint", &self.token_endpoint)
            .field("auth_server_iss", &self.auth_server_iss)
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .field("dpop_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct UserLockManager {
    locks: Arc<tokio::sync::RwLock<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

impl UserLockManager {
    pub fn new() -> Self {
        Self {
            locks: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    pub async fn acquire(&self, user_did: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let mutex = {
            let mut map = self.locks.write().await;
            map.entry(user_did.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        mutex.lock_owned().await
    }
}

const ENVELOPE_VERSION_V1: u8 = 1;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const MIN_ENVELOPE_LEN: usize = 1 + NONCE_SIZE + TAG_SIZE; // 29 bytes

pub fn encrypt_secret(
    key: &[u8; 32],
    user_did: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Internal(format!("Cipher init error: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let aad = format!("v1:{user_did}");
    let payload = Payload {
        msg: plaintext,
        aad: aad.as_bytes(),
    };

    let ciphertext_and_tag = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| AppError::Internal(format!("Session secret encryption failed: {e}")))?;

    let mut envelope = Vec::with_capacity(1 + NONCE_SIZE + ciphertext_and_tag.len());
    envelope.push(ENVELOPE_VERSION_V1);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext_and_tag);

    Ok(envelope)
}

pub fn decrypt_secret(
    key: &[u8; 32],
    user_did: &str,
    envelope: &[u8],
) -> Result<Vec<u8>, AppError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(AppError::Internal(format!(
            "Encrypted secret for {user_did} is too short (got {} bytes, expected at least {MIN_ENVELOPE_LEN})",
            envelope.len()
        )));
    }

    let version = envelope[0];
    if version != ENVELOPE_VERSION_V1 {
        return Err(AppError::Internal(format!(
            "Unsupported session encryption envelope version {version} for {user_did}"
        )));
    }

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes.copy_from_slice(&envelope[1..1 + NONCE_SIZE]);
    let ciphertext_and_tag = &envelope[1 + NONCE_SIZE..];

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Internal(format!("Cipher init error: {e}")))?;
    let nonce = Nonce::from(nonce_bytes);

    let aad = format!("v1:{user_did}");
    let payload = Payload {
        msg: ciphertext_and_tag,
        aad: aad.as_bytes(),
    };

    cipher.decrypt(&nonce, payload).map_err(|e| {
        AppError::Internal(format!(
            "Session secret decryption failed for {user_did}: {e}"
        ))
    })
}

pub fn decode_dpop_key(
    user_did: &str,
    key_bytes: &[u8],
) -> Result<p256::ecdsa::SigningKey, AppError> {
    if key_bytes.len() != 32 {
        return Err(AppError::Internal(format!(
            "Invalid dpop_key length for {user_did}: expected exactly 32 bytes, got {}",
            key_bytes.len()
        )));
    }
    p256::ecdsa::SigningKey::from_slice(key_bytes).map_err(|e| {
        AppError::Internal(format!(
            "Corrupt dpop_key in oauth_sessions for {user_did}: {e}"
        ))
    })
}

pub fn redact_oauth_error_body(body: &str) -> String {
    #[derive(Deserialize)]
    struct OAuthErrorPayload {
        error: Option<String>,
        error_description: Option<String>,
    }

    if let Ok(payload) = serde_json::from_str::<OAuthErrorPayload>(body) {
        let err_code = payload.error.unwrap_or_else(|| "unknown_error".to_string());
        let safe_err: String = err_code
            .chars()
            .take(64)
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        if let Some(desc) = payload.error_description {
            let redacted_words: Vec<String> = desc
                .split_whitespace()
                .map(|word| {
                    if word.len() > 24
                        && word.chars().all(|c| {
                            c.is_ascii_alphanumeric()
                                || c == '.'
                                || c == '_'
                                || c == '-'
                                || c == '+'
                        })
                    {
                        "[REDACTED]".to_string()
                    } else {
                        word.to_string()
                    }
                })
                .collect();
            let bounded_desc: String = redacted_words.join(" ").chars().take(128).collect();
            format!("error: {safe_err}, description: {bounded_desc}")
        } else {
            format!("error: {safe_err}")
        }
    } else {
        "non-json error response".to_string()
    }
}

#[derive(Clone)]
pub struct OAuthService {
    pub client_id: String,
    pub base_url: String,
    pub key_id: String,
    pub signing_key: p256::ecdsa::SigningKey,
    pub verifying_key: p256::ecdsa::VerifyingKey,
    pub client_metadata: OAuthClientMetadata,
    pub jwks: JwksResponse,
    pub db: PgPool,
    pub session_encryption_key: [u8; 32],
    user_locks: UserLockManager,
    pub pending_states: Arc<RwLock<HashMap<String, PendingOAuthState>>>,
    pub transport: Arc<crate::space_client::DefaultSpaceHostTransport>,
}

impl OAuthService {
    pub fn new(
        db: PgPool,
        base_url: String,
        signing_key: p256::ecdsa::SigningKey,
        key_id: Option<String>,
    ) -> Self {
        let session_encryption_key = crate::config::load_session_encryption_key_or_fail();
        Self::with_encryption_key(db, base_url, signing_key, key_id, session_encryption_key)
    }

    pub fn with_transport(
        db: PgPool,
        base_url: String,
        signing_key: p256::ecdsa::SigningKey,
        key_id: Option<String>,
        transport: Arc<crate::space_client::DefaultSpaceHostTransport>,
    ) -> Self {
        let session_encryption_key = crate::config::load_session_encryption_key_or_fail();
        Self::with_encryption_key_and_transport(
            db,
            base_url,
            signing_key,
            key_id,
            session_encryption_key,
            transport,
        )
    }

    pub fn with_encryption_key(
        db: PgPool,
        base_url: String,
        signing_key: p256::ecdsa::SigningKey,
        key_id: Option<String>,
        session_encryption_key: [u8; 32],
    ) -> Self {
        Self::with_encryption_key_and_transport(
            db,
            base_url,
            signing_key,
            key_id,
            session_encryption_key,
            Arc::new(crate::space_client::DefaultSpaceHostTransport::new()),
        )
    }

    pub fn with_encryption_key_and_transport(
        db: PgPool,
        base_url: String,
        signing_key: p256::ecdsa::SigningKey,
        key_id: Option<String>,
        session_encryption_key: [u8; 32],
        transport: Arc<crate::space_client::DefaultSpaceHostTransport>,
    ) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let client_id = format!("{base_url}/oauth/client-metadata.json");
        let jwks_uri = format!("{base_url}/oauth/jwks.json");
        let redirect_uri = format!("{base_url}/oauth/callback");

        let verifying_key = *signing_key.verifying_key();
        let ep = EncodedPoint::from(&verifying_key);
        let x = URL_SAFE_NO_PAD.encode(ep.x().expect("x coordinate"));
        let y = URL_SAFE_NO_PAD.encode(ep.y().expect("y coordinate"));

        let key_id = key_id.unwrap_or_else(|| {
            let thumbprint = Sha256::digest(
                format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")
                    .as_bytes(),
            );
            URL_SAFE_NO_PAD.encode(thumbprint)
        });

        let public_jwk = PublicKeyJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x,
            y: Some(y),
            kid: Some(key_id.clone()),
        };

        let client_metadata = OAuthClientMetadata {
            client_id: client_id.clone(),
            client_name: "Catbird Circles AppView".into(),
            client_uri: base_url.clone(),
            redirect_uris: vec![redirect_uri],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            scope: CIRCLE_SCOPE.into(),
            token_endpoint_auth_method: "private_key_jwt".into(),
            token_endpoint_auth_signing_alg: "ES256".into(),
            jwks_uri,
            dpop_bound_access_tokens: true,
        };

        let jwks = JwksResponse {
            keys: vec![public_jwk],
        };

        Self {
            client_id,
            base_url,
            key_id,
            signing_key,
            verifying_key,
            client_metadata,
            jwks,
            db,
            session_encryption_key,
            user_locks: UserLockManager::new(),
            pending_states: Arc::new(RwLock::new(HashMap::new())),
            transport,
        }
    }

    /// Sign an `atproto-client-attestation+jwt` for a space host.
    pub fn sign_client_attestation(&self, space_host_service: &str) -> Result<String, AppError> {
        let now = Utc::now().timestamp();
        let exp = now + 60;
        let jti = Uuid::new_v4().to_string();

        let header = serde_json::json!({
            "typ": "atproto-client-attestation+jwt",
            "alg": "ES256",
            "kid": self.key_id
        });

        let claims = serde_json::json!({
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": space_host_service,
            "iat": now,
            "exp": exp,
            "jti": jti
        });

        self.sign_jwt(&header, &claims)
    }

    /// Create client assertion JWT for OAuth token endpoint authentication (RFC 7523).
    pub fn create_client_assertion(&self, audience: &str) -> Result<String, AppError> {
        let now = Utc::now().timestamp();
        let exp = now + 60;
        let jti = Uuid::new_v4().to_string();

        let header = serde_json::json!({
            "typ": "JWT",
            "alg": "ES256",
            "kid": self.key_id
        });

        let claims = serde_json::json!({
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": audience,
            "iat": now,
            "exp": exp,
            "jti": jti
        });

        self.sign_jwt(&header, &claims)
    }

    fn sign_jwt(
        &self,
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> Result<String, AppError> {
        let header_str = serde_json::to_string(header)
            .map_err(|e| AppError::Internal(format!("JWT header serialization: {e}")))?;
        let claims_str = serde_json::to_string(claims)
            .map_err(|e| AppError::Internal(format!("JWT claims serialization: {e}")))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_str.as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_str.as_bytes());
        let signing_input = format!("{header_b64}.{claims_b64}");

        let sig: p256::ecdsa::Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Start OAuth authorization-code flow with PAR and PKCE against a user's PDS.
    pub async fn start_flow(
        &self,
        user_did: &str,
        did_resolver: &DidResolver,
        http_client: &reqwest::Client,
    ) -> Result<String, AppError> {
        let _permit = crate::auth::public_flow_semaphore()
            .acquire_owned()
            .await
            .map_err(|_| {
                AppError::TooManyRequests("Public flow concurrency limit reached".into())
            })?;

        let pds_endpoint = did_resolver
            .resolve_pds_endpoint(user_did)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Resolving user PDS endpoint failed: {e:?}"))
            })?;

        let (auth_endpoint, token_endpoint, par_endpoint, auth_issuer) = self
            .discover_oauth_metadata(&pds_endpoint, http_client)
            .await?;

        let auth_issuer_val = auth_issuer
            .clone()
            .unwrap_or_else(|| pds_endpoint.trim_end_matches('/').to_string());
        let expected_auth_origin = url::Url::parse(&auth_issuer_val)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid auth issuer URL: {e}")))?
            .origin()
            .ascii_serialization();

        // Verify token_endpoint is origin-bound to auth_issuer
        let token_url = url::Url::parse(&token_endpoint)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid token endpoint URL: {e}")))?;
        let allow_loopback = self.transport.allows_loopback_for_test();
        let is_token_loopback = (token_url.scheme() == "http" || token_url.scheme() == "https")
            && is_loopback_or_localhost(token_url.host_str().unwrap_or(""));
        if (!allow_loopback || !is_token_loopback) && token_url.scheme() != "https"
            || token_url.origin().ascii_serialization() != expected_auth_origin
        {
            return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
        }

        let mut verifier_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut verifier_bytes);
        let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        let challenge_hash = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(challenge_hash);

        let mut state_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut state_bytes);
        let state = URL_SAFE_NO_PAD.encode(state_bytes);

        let redirect_uri = format!("{}/oauth/callback", self.base_url);

        // Try PAR first if supported
        let authorization_url = if let Some(par_url_str) = &par_endpoint {
            let par_url = url::Url::parse(par_url_str)
                .map_err(|e| AppError::InvalidRequest(format!("Invalid PAR endpoint URL: {e}")))?;
            let is_par_loopback = (par_url.scheme() == "http" || par_url.scheme() == "https")
                && is_loopback_or_localhost(par_url.host_str().unwrap_or(""));
            if (!allow_loopback || !is_par_loopback) && par_url.scheme() != "https"
                || par_url.origin().ascii_serialization() != expected_auth_origin
            {
                return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
            }
            let par_client = self.transport.build_pinned_client(&par_url).await?;

            let client_assertion = self.create_client_assertion(&auth_issuer_val)?;
            let params = [
                ("client_id", self.client_id.as_str()),
                ("response_type", "code"),
                ("redirect_uri", redirect_uri.as_str()),
                ("scope", CIRCLE_SCOPE),
                ("state", state.as_str()),
                ("code_challenge", code_challenge.as_str()),
                ("code_challenge_method", "S256"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", client_assertion.as_str()),
            ];

            let res = par_client.post(par_url_str).form(&params).send().await;
            match res {
                Ok(resp) if resp.status().is_success() => {
                    #[derive(Deserialize)]
                    struct ParResponse {
                        request_uri: String,
                    }
                    let body_bytes =
                        crate::auth::read_bounded_response_bytes(resp, MAX_OAUTH_RESPONSE_BYTES)
                            .await?;
                    let par: ParResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
                        AppError::Internal(format!("PAR response decode error: {e}"))
                    })?;
                    format!(
                        "{}?client_id={}&request_uri={}",
                        auth_endpoint,
                        url_encode(&self.client_id),
                        url_encode(&par.request_uri)
                    )
                }
                _ => {
                    // Fallback to standard authorization endpoint with query parameters
                    format!(
                        "{}?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
                        auth_endpoint,
                        url_encode(&self.client_id),
                        url_encode(&redirect_uri),
                        url_encode(CIRCLE_SCOPE),
                        url_encode(&state),
                        url_encode(&code_challenge)
                    )
                }
            }
        } else {
            format!(
                "{}?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
                auth_endpoint,
                url_encode(&self.client_id),
                url_encode(&redirect_uri),
                url_encode(CIRCLE_SCOPE),
                url_encode(&state),
                url_encode(&code_challenge)
            )
        };
        {
            let mut lock = self.pending_states.write();
            let now = Utc::now();
            lock.retain(|_, v| {
                v.created_at + chrono::Duration::seconds(PENDING_STATE_TTL_SECS) > now
            });
            lock.insert(
                state.clone(),
                PendingOAuthState {
                    state: state.clone(),
                    code_verifier,
                    user_did: user_did.to_string(),
                    pds_endpoint,
                    token_endpoint,
                    auth_server_iss: auth_issuer,
                    created_at: now,
                    in_flight: false,
                },
            );
        }

        Ok(authorization_url)
    }

    /// Handle callback from OAuth authorization server.
    pub async fn handle_callback(
        &self,
        code: &str,
        state: &str,
        _http_client: &reqwest::Client,
    ) -> Result<String, AppError> {
        // Look up pending state and mark it in-flight while the token exchange is in progress.
        // Single-use state vs transient failure recovery trade-off:
        //
        // Security requirement: OAuth 2.0 / RFC 6749 requires authorization codes and state parameters
        // to be single-use. If an attacker intercepts or replays an authorization response, replaying
        // the callback must fail.
        //
        // Availability / resilience requirement: A transient network failure during the token exchange
        // (e.g. timeout, 502/503 from PDS) must not permanently destroy the user's authorization flow
        // before the code has been consumed. Removing the pending state *before* the exchange makes
        // any transient network error permanent and unrecoverable.
        //
        // Safe design:
        // - We lock/claim the pending state (`in_flight = true`) while the token exchange request is active.
        //   This prevents concurrent double-exchange / race conditions.
        // - If the token exchange fails (transient error), the state claim is released (`in_flight = false`),
        //   leaving the state available for an immediate retry within its TTL.
        // - Once the token exchange succeeds and the session is persisted, the pending state is permanently
        //   removed from `pending_states`. Any subsequent replay of the same state/code will find no pending
        //   state and will be rejected with an authorization error.
        // - Pending states have a TTL (10 minutes) and are automatically evicted when expired to prevent
        //   memory growth from abandoned authorization flows.
        let pending = {
            let mut lock = self.pending_states.write();
            let now = Utc::now();
            lock.retain(|_, v| {
                v.created_at + chrono::Duration::seconds(PENDING_STATE_TTL_SECS) > now
            });

            let entry = lock.get_mut(state).ok_or_else(|| {
                AppError::Unauthorized(crate::error::AuthReason::InvalidClaimsJson)
            })?;

            if entry.in_flight {
                return Err(AppError::Unauthorized(
                    crate::error::AuthReason::InvalidClaimsJson,
                ));
            }

            entry.in_flight = true;
            entry.clone()
        };

        struct StateClaimGuard<'a> {
            pending_states: &'a Arc<RwLock<HashMap<String, PendingOAuthState>>>,
            state_key: String,
            succeeded: bool,
        }

        impl<'a> Drop for StateClaimGuard<'a> {
            fn drop(&mut self) {
                let mut lock = self.pending_states.write();
                if self.succeeded {
                    lock.remove(&self.state_key);
                } else if let Some(entry) = lock.get_mut(&self.state_key) {
                    entry.in_flight = false;
                }
            }
        }

        let mut claim_guard = StateClaimGuard {
            pending_states: &self.pending_states,
            state_key: state.to_string(),
            succeeded: false,
        };
        let _permit = crate::auth::public_flow_semaphore()
            .acquire_owned()
            .await
            .map_err(|_| {
                AppError::TooManyRequests("Public flow concurrency limit reached".into())
            })?;

        let dpop_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let redirect_uri = format!("{}/oauth/callback", self.base_url);
        // RFC 7523 as profiled by atproto: `aud` is the authorization server's
        // ISSUER, not its token endpoint. Sending the endpoint is rejected with
        // `invalid_client: unexpected "aud" claim value`.
        let auth_server_iss = pending.auth_server_iss.clone().ok_or_else(|| {
            AppError::Internal(
                "Authorization server issuer unknown; cannot build a client assertion".into(),
            )
        })?;
        let iss_url = url::Url::parse(&auth_server_iss).map_err(|e| {
            AppError::InvalidRequest(format!("Invalid auth server issuer URL: {e}"))
        })?;
        let expected_origin = iss_url.origin().ascii_serialization();
        let token_url = url::Url::parse(&pending.token_endpoint)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid token endpoint URL: {e}")))?;
        let allow_loopback = self.transport.allows_loopback_for_test();
        let is_token_loopback = (token_url.scheme() == "http" || token_url.scheme() == "https")
            && is_loopback_or_localhost(token_url.host_str().unwrap_or(""));
        if (!allow_loopback || !is_token_loopback) && token_url.scheme() != "https"
            || token_url.origin().ascii_serialization() != expected_origin
        {
            return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
        }
        let token_client = self.transport.build_pinned_client(&token_url).await?;

        let client_assertion = self.create_client_assertion(&auth_server_iss)?;
        let response = post_form_with_dpop(
            &token_client,
            &dpop_key,
            &pending.token_endpoint,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri.as_str()),
                ("code_verifier", pending.code_verifier.as_str()),
                ("client_id", self.client_id.as_str()),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", client_assertion.as_str()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(format!("Token exchange failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body_bytes =
                crate::auth::read_bounded_response_bytes(response, MAX_OAUTH_RESPONSE_BYTES)
                    .await
                    .unwrap_or_default();
            let body = String::from_utf8_lossy(&body_bytes);
            let redacted_desc = redact_oauth_error_body(&body);
            let upstream_host = url::Url::parse(&pending.token_endpoint)
                .ok()
                .and_then(|u| u.host_str().map(String::from))
                .unwrap_or_else(|| "unknown".into());
            tracing::warn!(
                operation = "token_exchange",
                upstream_host = %upstream_host,
                upstream_status = %status.as_u16(),
                redacted_error = %redacted_desc,
                "Token exchange failed upstream"
            );
            return Err(AppError::Internal(format!(
                "Token exchange returned {status}: {redacted_desc}"
            )));
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<i64>,
            scope: Option<String>,
            sub: Option<String>,
        }

        let body_bytes =
            crate::auth::read_bounded_response_bytes(response, MAX_OAUTH_RESPONSE_BYTES).await?;
        let token_data: TokenResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| AppError::Internal(format!("Token response parse error: {e}")))?;

        // Enforce subject binding: token response subject, if provided, must match initiating user_did
        if let Some(ref returned_sub) = token_data.sub {
            if returned_sub != &pending.user_did {
                tracing::warn!(
                    returned_sub = %returned_sub,
                    expected_did = %pending.user_did,
                    "Token response subject does not match initiating OAuth state"
                );
                return Err(AppError::Unauthorized(crate::error::AuthReason::IdMismatch));
            }
        }
        let user_did = pending.user_did;
        let expires_at = token_data
            .expires_in
            .map(|exp| Utc::now() + chrono::Duration::seconds(exp));

        let session = UserOAuthSession {
            user_did: user_did.clone(),
            access_token: token_data.access_token,
            refresh_token: token_data.refresh_token,
            token_endpoint: pending.token_endpoint,
            auth_server_iss,
            expires_at,
            scope: token_data.scope.unwrap_or_else(|| CIRCLE_SCOPE.to_string()),
            dpop_key,
        };

        self.store_session(session).await?;
        claim_guard.succeeded = true;

        Ok(CALLBACK_DEEP_LINK.to_string())
    }

    /// Retrieve a valid token and DPoP signing key for a user, refreshing if expired.
    pub async fn get_valid_token(
        &self,
        user_did: &str,
        _http_client: &reqwest::Client,
    ) -> Result<(String, p256::ecdsa::SigningKey), AppError> {
        let session = self.get_session(user_did).await?.ok_or_else(|| {
            AppError::Unauthorized(crate::error::AuthReason::NoVerificationMethod)
        })?;

        let expired = session
            .expires_at
            .is_some_and(|exp| exp <= Utc::now() + chrono::Duration::seconds(30));

        let needs_refresh = expired && session.refresh_token.is_some();

        if !needs_refresh {
            if expired && session.refresh_token.is_none() {
                return Err(AppError::Unauthorized(crate::error::AuthReason::Expired));
            }
            return Ok((session.access_token, session.dpop_key));
        }

        // Token is expired and has a refresh token: acquire per-user async mutex to serialize refresh.
        let _guard = self.user_locks.acquire(user_did).await;

        // Re-read session under lock to check if another concurrent task already completed refresh.
        let session = self.get_session(user_did).await?.ok_or_else(|| {
            AppError::Unauthorized(crate::error::AuthReason::NoVerificationMethod)
        })?;

        let expired = session
            .expires_at
            .is_some_and(|exp| exp <= Utc::now() + chrono::Duration::seconds(30));

        if !expired {
            return Ok((session.access_token, session.dpop_key));
        }

        let refresh_token = match session.refresh_token.as_ref() {
            Some(rt) => rt,
            None => {
                return Err(AppError::Unauthorized(crate::error::AuthReason::Expired));
            }
        };

        let new_dpop_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let iss_url = url::Url::parse(&session.auth_server_iss).map_err(|e| {
            AppError::InvalidRequest(format!("Invalid auth server issuer URL: {e}"))
        })?;
        let expected_origin = iss_url.origin().ascii_serialization();

        let token_url = url::Url::parse(&session.token_endpoint)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid token endpoint URL: {e}")))?;
        let allow_loopback = self.transport.allows_loopback_for_test();
        let is_token_loopback = (token_url.scheme() == "http" || token_url.scheme() == "https")
            && is_loopback_or_localhost(token_url.host_str().unwrap_or(""));
        if (!allow_loopback || !is_token_loopback) && token_url.scheme() != "https"
            || token_url.origin().ascii_serialization() != expected_origin
        {
            return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
        }
        let token_client = self.transport.build_pinned_client(&token_url).await?;

        let client_assertion = self.create_client_assertion(&session.auth_server_iss)?;
        let response = post_form_with_dpop(
            &token_client,
            &new_dpop_key,
            &session.token_endpoint,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.as_str()),
                ("client_id", self.client_id.as_str()),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", client_assertion.as_str()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(format!("Token refresh request error: {e}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let body_bytes =
                crate::auth::read_bounded_response_bytes(response, MAX_OAUTH_RESPONSE_BYTES)
                    .await
                    .unwrap_or_default();
            let body = String::from_utf8_lossy(&body_bytes);
            let redacted_desc = redact_oauth_error_body(&body);
            let upstream_host = url::Url::parse(&session.token_endpoint)
                .ok()
                .and_then(|u| u.host_str().map(String::from))
                .unwrap_or_else(|| "unknown".into());
            tracing::warn!(
                operation = "token_refresh",
                upstream_host = %upstream_host,
                upstream_status = %status.as_u16(),
                redacted_error = %redacted_desc,
                "Token refresh failed upstream"
            );
            return Err(AppError::Internal(format!(
                "Token refresh returned {status}: {redacted_desc}"
            )));
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<i64>,
            scope: Option<String>,
        }

        let body_bytes =
            crate::auth::read_bounded_response_bytes(response, MAX_OAUTH_RESPONSE_BYTES).await?;
        let token_data: TokenResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| AppError::Internal(format!("Token refresh parse error: {e}")))?;

        let expires_at = token_data
            .expires_in
            .map(|exp| Utc::now() + chrono::Duration::seconds(exp));

        let new_token = token_data.access_token.clone();
        let final_dpop_key = new_dpop_key.clone();

        let updated_session = UserOAuthSession {
            user_did: session.user_did,
            access_token: token_data.access_token,
            refresh_token: token_data.refresh_token.or(session.refresh_token),
            token_endpoint: session.token_endpoint,
            auth_server_iss: session.auth_server_iss,
            expires_at,
            scope: token_data.scope.unwrap_or(session.scope),
            dpop_key: new_dpop_key,
        };

        self.store_session(updated_session).await?;

        Ok((new_token, final_dpop_key))
    }

    /// Retrieve stored session for a user from Postgres.
    #[allow(clippy::type_complexity)]
    pub async fn get_session(&self, user_did: &str) -> Result<Option<UserOAuthSession>, AppError> {
        let row: Option<(
            String,
            Vec<u8>,
            Option<Vec<u8>>,
            String,
            String,
            Option<DateTime<Utc>>,
            String,
            Vec<u8>,
        )> = sqlx::query_as(
            r#"
            SELECT
                user_did,
                access_token,
                refresh_token,
                token_endpoint,
                auth_server_iss,
                expires_at,
                scope,
                dpop_key
            FROM oauth_sessions
            WHERE user_did = $1
            "#,
        )
        .bind(user_did)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get oauth session: {e}")))?;

        match row {
            Some((
                user_did,
                enc_access_token,
                enc_refresh_token,
                token_endpoint,
                auth_server_iss,
                expires_at,
                scope,
                enc_dpop_key,
            )) => {
                let access_token_bytes =
                    decrypt_secret(&self.session_encryption_key, &user_did, &enc_access_token)?;
                let access_token = String::from_utf8(access_token_bytes).map_err(|e| {
                    AppError::Internal(format!("Invalid UTF-8 in access_token for {user_did}: {e}"))
                })?;

                let refresh_token = match enc_refresh_token {
                    Some(enc_rt) => {
                        let rt_bytes =
                            decrypt_secret(&self.session_encryption_key, &user_did, &enc_rt)?;
                        let rt = String::from_utf8(rt_bytes).map_err(|e| {
                            AppError::Internal(format!(
                                "Invalid UTF-8 in refresh_token for {user_did}: {e}"
                            ))
                        })?;
                        Some(rt)
                    }
                    None => None,
                };

                let dpop_key_bytes =
                    decrypt_secret(&self.session_encryption_key, &user_did, &enc_dpop_key)?;
                let dpop_key = decode_dpop_key(&user_did, &dpop_key_bytes)?;

                Ok(Some(UserOAuthSession {
                    user_did,
                    access_token,
                    refresh_token,
                    token_endpoint,
                    auth_server_iss,
                    expires_at,
                    scope,
                    dpop_key,
                }))
            }
            None => Ok(None),
        }
    }

    /// Store or update a user OAuth session in Postgres.
    pub async fn store_session(&self, session: UserOAuthSession) -> Result<(), AppError> {
        let enc_access_token = encrypt_secret(
            &self.session_encryption_key,
            &session.user_did,
            session.access_token.as_bytes(),
        )?;

        let enc_refresh_token = match session.refresh_token.as_deref() {
            Some(rt) => Some(encrypt_secret(
                &self.session_encryption_key,
                &session.user_did,
                rt.as_bytes(),
            )?),
            None => None,
        };

        let raw_dpop_key = session.dpop_key.to_bytes();
        let enc_dpop_key = encrypt_secret(
            &self.session_encryption_key,
            &session.user_did,
            &raw_dpop_key,
        )?;

        sqlx::query(
            r#"
            INSERT INTO oauth_sessions (
                user_did,
                access_token,
                refresh_token,
                token_endpoint,
                auth_server_iss,
                expires_at,
                scope,
                dpop_key,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
            ON CONFLICT (user_did) DO UPDATE SET
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                token_endpoint = EXCLUDED.token_endpoint,
                auth_server_iss = EXCLUDED.auth_server_iss,
                expires_at = EXCLUDED.expires_at,
                scope = EXCLUDED.scope,
                dpop_key = EXCLUDED.dpop_key,
                updated_at = now()
            "#,
        )
        .bind(&session.user_did)
        .bind(enc_access_token)
        .bind(enc_refresh_token)
        .bind(&session.token_endpoint)
        .bind(&session.auth_server_iss)
        .bind(session.expires_at)
        .bind(&session.scope)
        .bind(enc_dpop_key)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to store oauth session: {e}")))?;

        Ok(())
    }

    /// Delete stored session for a user from Postgres.
    pub async fn remove_session(&self, user_did: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM oauth_sessions WHERE user_did = $1")
            .bind(user_did)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to remove oauth session: {e}")))?;

        Ok(())
    }

    /// All non-expired sessions from Postgres.
    #[allow(clippy::type_complexity)]
    pub async fn list_sessions(&self) -> Result<Vec<UserOAuthSession>, AppError> {
        let rows: Vec<(
            String,
            Vec<u8>,
            Option<Vec<u8>>,
            String,
            String,
            Option<DateTime<Utc>>,
            String,
            Vec<u8>,
        )> = sqlx::query_as(
            r#"
            SELECT
                user_did,
                access_token,
                refresh_token,
                token_endpoint,
                auth_server_iss,
                expires_at,
                scope,
                dpop_key
            FROM oauth_sessions
            WHERE expires_at IS NULL OR expires_at > now()
            ORDER BY user_did
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list oauth sessions: {e}")))?;

        let mut sessions = Vec::with_capacity(rows.len());
        for (
            user_did,
            enc_access_token,
            enc_refresh_token,
            token_endpoint,
            auth_server_iss,
            expires_at,
            scope,
            enc_dpop_key,
        ) in rows
        {
            let access_token_bytes =
                decrypt_secret(&self.session_encryption_key, &user_did, &enc_access_token)?;
            let access_token = String::from_utf8(access_token_bytes).map_err(|e| {
                AppError::Internal(format!("Invalid UTF-8 in access_token for {user_did}: {e}"))
            })?;

            let refresh_token = match enc_refresh_token {
                Some(enc_rt) => {
                    let rt_bytes =
                        decrypt_secret(&self.session_encryption_key, &user_did, &enc_rt)?;
                    let rt = String::from_utf8(rt_bytes).map_err(|e| {
                        AppError::Internal(format!(
                            "Invalid UTF-8 in refresh_token for {user_did}: {e}"
                        ))
                    })?;
                    Some(rt)
                }
                None => None,
            };

            let dpop_key_bytes =
                decrypt_secret(&self.session_encryption_key, &user_did, &enc_dpop_key)?;
            let dpop_key = decode_dpop_key(&user_did, &dpop_key_bytes)?;

            sessions.push(UserOAuthSession {
                user_did,
                access_token,
                refresh_token,
                token_endpoint,
                auth_server_iss,
                expires_at,
                scope,
                dpop_key,
            });
        }

        Ok(sessions)
    }

    /// Prune pending authorization states older than TTL.
    pub fn cleanup_expired_pending_states(&self) -> usize {
        let now = Utc::now();
        let mut lock = self.pending_states.write();
        let before = lock.len();
        lock.retain(|_, v| v.created_at + chrono::Duration::seconds(PENDING_STATE_TTL_SECS) > now);
        before - lock.len()
    }

    async fn discover_oauth_metadata(
        &self,
        pds_endpoint: &str,
        _http_client: &reqwest::Client,
    ) -> Result<(String, String, Option<String>, Option<String>), AppError> {
        let pds_url = url::Url::parse(pds_endpoint)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid PDS endpoint URL: {e}")))?;
        if pds_url.scheme() != "https" {
            return Err(AppError::InvalidRequest(
                "PDS endpoint must use HTTPS".into(),
            ));
        }
        let pds_origin = pds_url.origin().ascii_serialization();
        let pds_base = pds_endpoint.trim_end_matches('/');

        let well_known_auth = format!("{pds_base}/.well-known/oauth-authorization-server");
        let well_known_resource = format!("{pds_base}/.well-known/oauth-protected-resource");

        // Helper closure to validate and check origin binding for endpoints
        let validate_endpoints = |iss: &str,
                                  auth_ep: &str,
                                  tok_ep: &str,
                                  par_ep: Option<&str>,
                                  expected_origin: &str,
                                  expected_base: &str|
         -> bool {
            let Ok(iss_url) = url::Url::parse(iss) else {
                return false;
            };
            let Ok(auth_url) = url::Url::parse(auth_ep) else {
                return false;
            };
            let Ok(tok_url) = url::Url::parse(tok_ep) else {
                return false;
            };

            if iss_url.scheme() != "https"
                || auth_url.scheme() != "https"
                || tok_url.scheme() != "https"
            {
                return false;
            }
            if iss.trim_end_matches('/') != expected_base {
                return false;
            }
            if iss_url.origin().ascii_serialization() != expected_origin
                || auth_url.origin().ascii_serialization() != expected_origin
                || tok_url.origin().ascii_serialization() != expected_origin
            {
                return false;
            }

            if let Some(par) = par_ep {
                let Ok(par_url) = url::Url::parse(par) else {
                    return false;
                };
                if par_url.scheme() != "https"
                    || par_url.origin().ascii_serialization() != expected_origin
                {
                    return false;
                }
            }

            true
        };

        if let Ok(auth_url) = url::Url::parse(&well_known_auth) {
            if let Ok(client) = self.transport.build_pinned_client(&auth_url).await {
                if let Ok(resp) = client.get(auth_url.as_str()).send().await {
                    if resp.status().is_success() {
                        #[derive(Deserialize)]
                        struct AuthServerMetadata {
                            issuer: Option<String>,
                            authorization_endpoint: String,
                            token_endpoint: String,
                            pushed_authorization_request_endpoint: Option<String>,
                        }
                        if let Ok(body_bytes) =
                            crate::auth::read_bounded_response_bytes(resp, MAX_OAUTH_METADATA_BYTES)
                                .await
                        {
                            if let Ok(meta) =
                                serde_json::from_slice::<AuthServerMetadata>(&body_bytes)
                            {
                                if let Some(ref iss) = meta.issuer {
                                    if validate_endpoints(
                                        iss,
                                        &meta.authorization_endpoint,
                                        &meta.token_endpoint,
                                        meta.pushed_authorization_request_endpoint.as_deref(),
                                        &pds_origin,
                                        pds_base,
                                    ) {
                                        return Ok((
                                            meta.authorization_endpoint,
                                            meta.token_endpoint,
                                            meta.pushed_authorization_request_endpoint,
                                            meta.issuer,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Try protected resource metadata
        if let Ok(res_url) = url::Url::parse(&well_known_resource) {
            if let Ok(client) = self.transport.build_pinned_client(&res_url).await {
                if let Ok(resp) = client.get(res_url.as_str()).send().await {
                    if resp.status().is_success() {
                        #[derive(Deserialize)]
                        struct ProtectedResourceMetadata {
                            resource: Option<String>,
                            authorization_servers: Option<Vec<String>>,
                        }
                        if let Ok(res_bytes) =
                            crate::auth::read_bounded_response_bytes(resp, MAX_OAUTH_METADATA_BYTES)
                                .await
                        {
                            if let Ok(meta) =
                                serde_json::from_slice::<ProtectedResourceMetadata>(&res_bytes)
                            {
                                // Resource MUST be present, HTTPS, and match PDS origin & base
                                let resource_str = meta.resource.as_deref().ok_or_else(|| {
                                    AppError::Unauthorized(AuthReason::AudienceMismatch)
                                })?;
                                let r_url = url::Url::parse(resource_str).map_err(|_| {
                                    AppError::Unauthorized(AuthReason::AudienceMismatch)
                                })?;
                                if r_url.scheme() != "https"
                                    || r_url.origin().ascii_serialization() != pds_origin
                                    || resource_str.trim_end_matches('/') != pds_base
                                {
                                    return Err(AppError::Unauthorized(
                                        AuthReason::AudienceMismatch,
                                    ));
                                }

                                if let Some(servers) = meta.authorization_servers {
                                    for server in servers {
                                        let Ok(server_url) = url::Url::parse(&server) else {
                                            continue;
                                        };
                                        if server_url.scheme() != "https" {
                                            continue;
                                        };
                                        let server_origin =
                                            server_url.origin().ascii_serialization();
                                        let server_base = server.trim_end_matches('/');

                                        let server_meta_url_str = format!(
                                            "{server_base}/.well-known/oauth-authorization-server"
                                        );
                                        if let Ok(server_meta_url) =
                                            url::Url::parse(&server_meta_url_str)
                                        {
                                            if let Ok(s_client) = self
                                                .transport
                                                .build_pinned_client(&server_meta_url)
                                                .await
                                            {
                                                if let Ok(s_resp) = s_client
                                                    .get(server_meta_url.as_str())
                                                    .send()
                                                    .await
                                                {
                                                    if s_resp.status().is_success() {
                                                        #[derive(Deserialize)]
                                                        struct AuthServerMetadata {
                                                            issuer: Option<String>,
                                                            authorization_endpoint: String,
                                                            token_endpoint: String,
                                                            pushed_authorization_request_endpoint:
                                                                Option<String>,
                                                        }
                                                        if let Ok(s_bytes) = crate::auth::read_bounded_response_bytes(s_resp, MAX_OAUTH_METADATA_BYTES).await {
                                                            if let Ok(meta) = serde_json::from_slice::<AuthServerMetadata>(&s_bytes) {
                                                                if let Some(ref iss) = meta.issuer {
                                                                    if validate_endpoints(
                                                                        iss,
                                                                        &meta.authorization_endpoint,
                                                                        &meta.token_endpoint,
                                                                        meta.pushed_authorization_request_endpoint.as_deref(),
                                                                        &server_origin,
                                                                        server_base,
                                                                    ) {
                                                                        return Ok((
                                                                            meta.authorization_endpoint,
                                                                            meta.token_endpoint,
                                                                            meta.pushed_authorization_request_endpoint,
                                                                            meta.issuer,
                                                                        ));
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Default ATProto OAuth endpoints fallback
        Ok((
            format!("{pds_base}/oauth/authorize"),
            format!("{pds_base}/oauth/token"),
            Some(format!("{pds_base}/oauth/par")),
            Some(pds_base.to_string()),
        ))
    }
}

/// Sends a DPoP-bound form POST, satisfying an authorization server that demands
/// a DPoP nonce.
///
/// RFC 9449 §8: the server may reject a request with 400 `use_dpop_nonce` and
/// supply a `DPoP-Nonce` header, and the client MUST retry with that nonce in
/// the proof. atproto authorization servers require this, so the unnonced first
/// attempt is the expected path, not an error worth surfacing.
async fn post_form_with_dpop(
    http_client: &reqwest::Client,
    key: &p256::ecdsa::SigningKey,
    url: &str,
    params: &[(&str, &str)],
) -> Result<reqwest::Response, AppError> {
    let send = |proof: String| {
        http_client
            .post(url)
            .header("DPoP", proof)
            .form(params)
            .send()
    };

    let first = send(create_dpop_proof(key, "POST", url, None, None)?)
        .await
        .map_err(|e| AppError::Internal(format!("DPoP request failed: {e}")))?;

    if first.status() != reqwest::StatusCode::BAD_REQUEST {
        return Ok(first);
    }

    // Capture the nonce before consuming the body.
    let nonce = first
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body_bytes = crate::auth::read_bounded_response_bytes(first, MAX_OAUTH_RESPONSE_BYTES)
        .await
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&body_bytes);
    let needs_nonce = body.contains("use_dpop_nonce");
    match (needs_nonce, nonce) {
        (true, Some(nonce)) => send(create_dpop_proof(key, "POST", url, None, Some(&nonce))?)
            .await
            .map_err(|e| AppError::Internal(format!("DPoP retry failed: {e}"))),
        (true, None) => Err(AppError::Internal(
            "Server demanded a DPoP nonce but sent no DPoP-Nonce header".into(),
        )),
        // A genuine 400. Rebuild an equivalent error for the caller to report.
        (false, _) => Err(AppError::Internal(format!("400 Bad Request: {body}"))),
    }
}

pub fn create_dpop_proof(
    key: &p256::ecdsa::SigningKey,
    method: &str,
    target_url: &str,
    access_token: Option<&str>,
    nonce: Option<&str>,
) -> Result<String, AppError> {
    let now = Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();

    let verifying_key = *key.verifying_key();
    let ep = EncodedPoint::from(&verifying_key);
    let x = URL_SAFE_NO_PAD.encode(ep.x().expect("x coord"));
    let y = URL_SAFE_NO_PAD.encode(ep.y().expect("y coord"));

    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y
    });

    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk
    });

    let mut claims = serde_json::json!({
        "jti": jti,
        "htm": method,
        "htu": target_url,
        "iat": now
    });

    if let Some(token) = access_token {
        let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
        claims["ath"] = serde_json::Value::String(ath);
    }

    if let Some(nonce) = nonce {
        claims["nonce"] = serde_json::Value::String(nonce.to_owned());
    }

    let header_str = serde_json::to_string(&header)
        .map_err(|e| AppError::Internal(format!("DPoP header serialization: {e}")))?;
    let claims_str = serde_json::to_string(&claims)
        .map_err(|e| AppError::Internal(format!("DPoP claims serialization: {e}")))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_str.as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_str.as_bytes());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Sends a DPoP-bound GET with an access token, satisfying a resource server
/// that demands a DPoP nonce.
///
/// Same RFC 9449 §8 dance as [`post_form_with_dpop`], but a resource server
/// signals the requirement with 401 and `WWW-Authenticate: DPoP
/// error="use_dpop_nonce"` rather than a 400 body, so both are accepted.
pub async fn get_with_dpop(
    http_client: &reqwest::Client,
    key: &p256::ecdsa::SigningKey,
    url: &str,
    token: &str,
) -> Result<reqwest::Response, AppError> {
    let send = |proof: String| {
        http_client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {token}"))
            .header("DPoP", proof)
            .send()
    };

    let first = send(create_dpop_proof(key, "GET", url, Some(token), None)?)
        .await
        .map_err(|e| AppError::Internal(format!("DPoP request failed: {e}")))?;

    let status = first.status();
    if status != reqwest::StatusCode::UNAUTHORIZED && status != reqwest::StatusCode::BAD_REQUEST {
        return Ok(first);
    }

    let nonce = first
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let challenge = first
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();

    // Only retry when the server actually asked for a nonce; otherwise this is a
    // real auth failure and must surface, not be silently retried.
    if !challenge.contains("use_dpop_nonce") {
        let body_bytes = crate::auth::read_bounded_response_bytes(first, MAX_OAUTH_RESPONSE_BYTES)
            .await
            .unwrap_or_default();
        let body = String::from_utf8_lossy(&body_bytes);
        if !body.contains("use_dpop_nonce") {
            return Err(AppError::Internal(format!("{status}: {body}")));
        }
    }

    match nonce {
        Some(nonce) => send(create_dpop_proof(
            key,
            "GET",
            url,
            Some(token),
            Some(&nonce),
        )?)
        .await
        .map_err(|e| AppError::Internal(format!("DPoP retry failed: {e}"))),
        None => Err(AppError::Internal(
            "Server demanded a DPoP nonce but sent no DPoP-Nonce header".into(),
        )),
    }
}

// Axum Route Handlers

pub async fn client_metadata_handler(State(state): State<AppState>) -> Json<OAuthClientMetadata> {
    Json(state.oauth_service.client_metadata.clone())
}

pub async fn jwks_handler(State(state): State<AppState>) -> Json<JwksResponse> {
    Json(state.oauth_service.jwks.clone())
}

#[derive(Deserialize)]
pub struct OAuthStartQuery {
    pub did: String,
}

pub async fn oauth_start_handler(
    State(state): State<AppState>,
    Query(query): Query<OAuthStartQuery>,
) -> Result<Redirect, AppError> {
    let auth_url = state
        .oauth_service
        .start_flow(&query.did, &state.did_resolver, &state.http_client)
        .await?;
    Ok(Redirect::temporary(&auth_url))
}

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: String,
    pub state: String,
}

pub async fn oauth_callback_handler(
    State(state): State<AppState>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<Redirect, AppError> {
    let redirect_url = state
        .oauth_service
        .handle_callback(&query.code, &query.state, &state.http_client)
        .await?;
    Ok(Redirect::temporary(&redirect_url))
}

/// Verifies an `atproto-client-attestation+jwt` directly against a provided JWKS document.
pub fn verify_client_attestation_with_jwks(
    token: &str,
    expected_client_id: &str,
    expected_audience: &str,
    jwks: &JwksResponse,
) -> Result<ClientAttestationClaims, AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized(AuthReason::InvalidJwtFormat));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderEncoding))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderJson))?;

    if header.typ.as_deref() != Some("atproto-client-attestation+jwt") {
        return Err(AppError::Unauthorized(AuthReason::InvalidTyp));
    }
    if header.alg != "ES256" {
        return Err(AppError::Unauthorized(AuthReason::UnsupportedAlg));
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsEncoding))?;
    let claims: ClientAttestationClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsJson))?;

    if claims.iss != expected_client_id || claims.sub != expected_client_id {
        return Err(AppError::Unauthorized(AuthReason::IdMismatch));
    }
    if claims.aud != expected_audience {
        return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
    }
    let now = Utc::now().timestamp();
    if claims.exp <= now {
        return Err(AppError::Unauthorized(AuthReason::Expired));
    }

    let kid = header.kid.as_deref();
    let jwk = jwks
        .keys
        .iter()
        .find(|k| match (kid, k.kid.as_deref()) {
            (Some(target), Some(k_kid)) => target == k_kid,
            (None, _) => true,
            _ => false,
        })
        .ok_or(AppError::Unauthorized(AuthReason::NoVerificationMethod))?;

    let parsed_key = parse_public_key_jwk(jwk).map_err(AppError::Unauthorized)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidSignatureFormat))?;
    parsed_key
        .verify(signing_input.as_bytes(), &sig_bytes)
        .map_err(AppError::Unauthorized)?;

    Ok(claims)
}

/// Verifies an `atproto-client-attestation+jwt` following the space authority procedure:
/// 1. Parse JWT header and claims (extracting `iss` as client_id).
/// 2. Fetch `client-metadata.json` from `client_id`.
/// 3. Fetch JWKS from `client_metadata.jwks_uri`.
/// 4. Verify signature against matching `kid` in the JWKS.
pub async fn resolve_and_verify_client_attestation(
    token: &str,
    expected_client_id: &str,
    expected_audience: &str,
    _http_client: &reqwest::Client,
) -> Result<ClientAttestationClaims, AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized(AuthReason::InvalidJwtFormat));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderEncoding))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidHeaderJson))?;

    if header.typ.as_deref() != Some("atproto-client-attestation+jwt") {
        return Err(AppError::Unauthorized(AuthReason::InvalidTyp));
    }
    if header.alg != "ES256" {
        return Err(AppError::Unauthorized(AuthReason::UnsupportedAlg));
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsEncoding))?;
    let claims: ClientAttestationClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidClaimsJson))?;

    if claims.iss != expected_client_id || claims.sub != expected_client_id {
        return Err(AppError::Unauthorized(AuthReason::IdMismatch));
    }
    if claims.aud != expected_audience {
        return Err(AppError::Unauthorized(AuthReason::AudienceMismatch));
    }
    let now = Utc::now().timestamp();
    if claims.exp <= now {
        return Err(AppError::Unauthorized(AuthReason::Expired));
    }

    let client_id_url = url::Url::parse(&claims.iss)
        .map_err(|e| AppError::InvalidRequest(format!("Invalid client_id URL: {e}")))?;
    if client_id_url.scheme() != "https" {
        return Err(AppError::InvalidRequest("client_id must use HTTPS".into()));
    }

    let transport = crate::space_client::DefaultSpaceHostTransport::new();
    let meta_client = transport.build_pinned_client(&client_id_url).await?;

    // Fetch client metadata from client_id
    let meta_resp = meta_client
        .get(client_id_url.as_str())
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch client-metadata: {e}")))?;
    if !meta_resp.status().is_success() {
        return Err(AppError::Internal(format!(
            "client-metadata returned {}",
            meta_resp.status()
        )));
    }
    let meta_bytes =
        crate::auth::read_bounded_response_bytes(meta_resp, MAX_OAUTH_METADATA_BYTES).await?;
    let metadata: OAuthClientMetadata = serde_json::from_slice(&meta_bytes)
        .map_err(|e| AppError::Internal(format!("Failed to parse client-metadata: {e}")))?;

    // Fetch JWKS from metadata.jwks_uri
    let jwks_url = url::Url::parse(&metadata.jwks_uri)
        .map_err(|e| AppError::InvalidRequest(format!("Invalid jwks_uri: {e}")))?;
    if jwks_url.scheme() != "https" {
        return Err(AppError::InvalidRequest("jwks_uri must use HTTPS".into()));
    }
    let jwks_client = transport.build_pinned_client(&jwks_url).await?;

    let jwks_resp = jwks_client
        .get(jwks_url.as_str())
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch JWKS: {e}")))?;
    if !jwks_resp.status().is_success() {
        return Err(AppError::Internal(format!(
            "JWKS returned {}",
            jwks_resp.status()
        )));
    }
    let jwks_bytes =
        crate::auth::read_bounded_response_bytes(jwks_resp, crate::auth::MAX_JWKS_BYTES).await?;
    let jwks: JwksResponse = serde_json::from_slice(&jwks_bytes)
        .map_err(|e| AppError::Internal(format!("Failed to parse JWKS: {e}")))?;
    // Verify signature using matching kid
    let kid = header.kid.as_deref();
    let jwk = jwks
        .keys
        .iter()
        .find(|k| match (kid, k.kid.as_deref()) {
            (Some(target), Some(k_kid)) => target == k_kid,
            (None, _) => true,
            _ => false,
        })
        .ok_or(AppError::Unauthorized(AuthReason::NoVerificationMethod))?;

    let parsed_key = parse_public_key_jwk(jwk).map_err(AppError::Unauthorized)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AppError::Unauthorized(AuthReason::InvalidSignatureFormat))?;
    parsed_key
        .verify(signing_input.as_bytes(), &sig_bytes)
        .map_err(AppError::Unauthorized)?;

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space_client::DefaultSpaceHostTransport;
    use chrono::Duration;
    use p256::ecdsa::signature::Verifier;
    use sqlx::PgPool;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A PDS rejects an authorization request that omits the bare `atproto`
    /// scope with `invalid_request` / `Missing "atproto" scope`. Dropping it
    /// breaks every AppView authorization, and the failure only shows up
    /// against a live PDS, so pin it here.
    #[test]
    fn circle_scope_includes_mandatory_atproto_scope() {
        let scopes: Vec<&str> = CIRCLE_SCOPE.split(' ').collect();
        assert!(
            scopes.contains(&"atproto"),
            "CIRCLE_SCOPE must include the bare `atproto` scope, got {CIRCLE_SCOPE:?}"
        );
        assert!(
            scopes
                .iter()
                .any(|s| s.starts_with("space:blue.catbird.circle?")),
            "CIRCLE_SCOPE must still request the Circle permissioned-data scope, got {CIRCLE_SCOPE:?}"
        );
    }

    const TEST_ENC_KEY_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn setup_test_encryption_key() -> [u8; 32] {
        std::env::set_var("SESSION_ENCRYPTION_KEY", TEST_ENC_KEY_HEX);
        crate::config::parse_session_encryption_key(TEST_ENC_KEY_HEX).unwrap()
    }

    #[test]
    fn user_oauth_session_debug_redacts_tokens_and_key() {
        let dpop_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let session = UserOAuthSession {
            user_did: "did:plc:alice-debug-test".to_string(),
            access_token: "super-secret-access-token-12345".to_string(),
            refresh_token: Some("super-secret-refresh-token-67890".to_string()),
            token_endpoint: "https://pds.alice.example/oauth/token".to_string(),
            auth_server_iss: "https://pds.alice.example".to_string(),
            expires_at: None,
            scope: CIRCLE_SCOPE.to_string(),
            dpop_key,
        };

        let debug_output = format!("{session:?}");
        assert!(!debug_output.contains("super-secret-access-token-12345"));
        assert!(!debug_output.contains("super-secret-refresh-token-67890"));
        assert!(debug_output.contains("[REDACTED]"));
        assert!(debug_output.contains("did:plc:alice-debug-test"));
    }

    #[test]
    fn stored_key_with_31_bytes_is_rejected() {
        let short_key = vec![1u8; 31];
        let result = decode_dpop_key("did:plc:test", &short_key);
        assert!(result.is_err(), "31-byte key must be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("expected exactly 32 bytes, got 31"));

        let long_key = vec![1u8; 33];
        assert!(decode_dpop_key("did:plc:test", &long_key).is_err());
        let empty_key = vec![];
        assert!(decode_dpop_key("did:plc:test", &empty_key).is_err());
    }

    #[test]
    fn transplanted_row_fails_aead_aad_verification() {
        let key = setup_test_encryption_key();
        let secret = b"my-secret-access-token";
        let encrypted_for_alice = encrypt_secret(&key, "did:plc:alice", secret).unwrap();

        // Attempting to decrypt alice's ciphertext under bob's DID must fail because AAD binds user_did
        let decrypt_for_bob = decrypt_secret(&key, "did:plc:bob", &encrypted_for_alice);
        assert!(
            decrypt_for_bob.is_err(),
            "Transplanted row must fail AEAD AAD verification"
        );

        // Decrypting under alice's DID must succeed
        let decrypt_for_alice =
            decrypt_secret(&key, "did:plc:alice", &encrypted_for_alice).unwrap();
        assert_eq!(decrypt_for_alice, secret);
    }

    #[test]
    fn token_endpoint_error_body_is_redacted() {
        let raw_json_error = r#"{"error": "invalid_grant", "error_description": "The refresh token secret_refresh_token_value_abc1234567890xyz is invalid"}"#;
        let redacted = redact_oauth_error_body(raw_json_error);
        assert!(!redacted.contains("secret_refresh_token_value_abc1234567890xyz"));
        assert!(redacted.contains("invalid_grant"));
        assert!(redacted.contains("[REDACTED]"));

        let non_json_error = "<html><body>502 Bad Gateway with secret code=12345</body></html>";
        let redacted_non_json = redact_oauth_error_body(non_json_error);
        assert_eq!(redacted_non_json, "non-json error response");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn stored_session_round_trips_through_database_and_dpop_key_verifiably_signs(
        pool: PgPool,
    ) {
        setup_test_encryption_key();
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let service = OAuthService::new(
            pool.clone(),
            "http://127.0.0.1:3002".to_string(),
            signing_key,
            None,
        );
        let dpop_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let original_verifying_key = *dpop_key.verifying_key();

        let session = UserOAuthSession {
            user_did: "did:plc:alice-roundtrip-test".to_string(),
            access_token: "access-token-xyz-123".to_string(),
            refresh_token: Some("refresh-token-xyz-456".to_string()),
            token_endpoint: "https://pds.alice.example/oauth/token".to_string(),
            auth_server_iss: "https://pds.alice.example".to_string(),
            expires_at: Some(Utc::now() + Duration::hours(2)),
            scope: CIRCLE_SCOPE.to_string(),
            dpop_key,
        };

        // Store session
        service.store_session(session.clone()).await.unwrap();

        // Retrieve session
        let loaded = service
            .get_session(&session.user_did)
            .await
            .unwrap()
            .expect("Session must be found");

        assert_eq!(loaded.user_did, session.user_did);
        assert_eq!(loaded.access_token, session.access_token);
        assert_eq!(loaded.refresh_token, session.refresh_token);
        assert_eq!(loaded.token_endpoint, session.token_endpoint);
        assert_eq!(loaded.auth_server_iss, session.auth_server_iss);
        assert_eq!(loaded.scope, session.scope);
        assert!(loaded.expires_at.is_some());

        // Direct database verification: secrets MUST be encrypted at rest
        let (raw_access_token, raw_refresh_token, raw_dpop_key): (
            Vec<u8>,
            Option<Vec<u8>>,
            Vec<u8>,
        ) = sqlx::query_as(
            "SELECT access_token, refresh_token, dpop_key FROM oauth_sessions WHERE user_did = $1",
        )
        .bind(&session.user_did)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_ne!(
            raw_access_token,
            session.access_token.as_bytes(),
            "access_token must not be cleartext"
        );
        assert_ne!(
            raw_refresh_token.unwrap(),
            session.refresh_token.as_ref().unwrap().as_bytes(),
            "refresh_token must not be cleartext"
        );
        assert_ne!(
            raw_dpop_key,
            session.dpop_key.to_bytes().to_vec(),
            "dpop_key must not be cleartext"
        );
        assert_eq!(
            raw_access_token[0], 1,
            "access_token envelope version must be 1"
        );
        assert_eq!(raw_dpop_key[0], 1, "dpop_key envelope version must be 1");

        // Verify dpop_key signature verification
        let proof = create_dpop_proof(
            &loaded.dpop_key,
            "GET",
            "https://pds.alice.example/resource",
            Some(&loaded.access_token),
            None,
        )
        .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&sig_bytes).unwrap();
        original_verifying_key
            .verify(signing_input.as_bytes(), &sig)
            .expect("DPoP proof signed by loaded key must verify against original verifying key");

        // Simulate service restart: create fresh OAuthService with same DB pool
        let restart_signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let restarted_service = OAuthService::new(
            pool.clone(),
            "http://127.0.0.1:3002".to_string(),
            restart_signing_key,
            None,
        );

        let reloaded = restarted_service
            .get_session(&session.user_did)
            .await
            .unwrap()
            .expect("Session must survive restart");

        assert_eq!(reloaded.user_did, session.user_did);
        assert_eq!(reloaded.access_token, session.access_token);
        assert_eq!(reloaded.auth_server_iss, session.auth_server_iss);

        let post_restart_proof = create_dpop_proof(
            &reloaded.dpop_key,
            "POST",
            "https://pds.alice.example/resource",
            Some(&reloaded.access_token),
            None,
        )
        .unwrap();
        let pr_parts: Vec<&str> = post_restart_proof.split('.').collect();
        let pr_signing_input = format!("{}.{}", pr_parts[0], pr_parts[1]);
        let pr_sig_bytes = URL_SAFE_NO_PAD.decode(pr_parts[2]).unwrap();
        let pr_sig = p256::ecdsa::Signature::from_slice(&pr_sig_bytes).unwrap();
        original_verifying_key
            .verify(pr_signing_input.as_bytes(), &pr_sig)
            .expect("DPoP proof after restart must verify against original verifying key");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn list_sessions_omits_expired_sessions(pool: PgPool) {
        setup_test_encryption_key();
        let service = OAuthService::new(
            pool.clone(),
            "http://127.0.0.1:3002".to_string(),
            p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
            None,
        );
        let active_session = UserOAuthSession {
            user_did: "did:plc:user-active".to_string(),
            access_token: "active-token".to_string(),
            refresh_token: Some("active-refresh".to_string()),
            token_endpoint: "https://pds.example/oauth/token".to_string(),
            auth_server_iss: "https://pds.example".to_string(),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            scope: CIRCLE_SCOPE.to_string(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
        };

        let expired_session = UserOAuthSession {
            user_did: "did:plc:user-expired".to_string(),
            access_token: "expired-token".to_string(),
            refresh_token: Some("expired-refresh".to_string()),
            token_endpoint: "https://pds.example/oauth/token".to_string(),
            auth_server_iss: "https://pds.example".to_string(),
            expires_at: Some(Utc::now() - Duration::hours(1)),
            scope: CIRCLE_SCOPE.to_string(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
        };

        let no_expiry_session = UserOAuthSession {
            user_did: "did:plc:user-no-exp".to_string(),
            access_token: "no-exp-token".to_string(),
            refresh_token: None,
            token_endpoint: "https://pds.example/oauth/token".to_string(),
            auth_server_iss: "https://pds.example".to_string(),
            expires_at: None,
            scope: CIRCLE_SCOPE.to_string(),
            dpop_key: p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
        };

        service.store_session(active_session).await.unwrap();
        service.store_session(expired_session).await.unwrap();
        service.store_session(no_expiry_session).await.unwrap();

        let sessions = service.list_sessions().await.unwrap();
        let dids: Vec<&str> = sessions.iter().map(|s| s.user_did.as_str()).collect();

        assert!(
            dids.contains(&"did:plc:user-active"),
            "list_sessions must include active session"
        );
        assert!(
            dids.contains(&"did:plc:user-no-exp"),
            "list_sessions must include session with no expiry"
        );
        assert!(
            !dids.contains(&"did:plc:user-expired"),
            "list_sessions must omit expired session"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn failed_token_exchange_leaves_pending_state_retryable_and_success_prevents_replay(
        pool: PgPool,
    ) {
        setup_test_encryption_key();
        let mock_server = MockServer::start().await;
        let service = OAuthService::with_transport(
            pool.clone(),
            "http://127.0.0.1:3002".to_string(),
            p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
            None,
            Arc::new(DefaultSpaceHostTransport::with_loopback(true)),
        );
        let http_client = reqwest::Client::new();

        let state_str = "retryable-state-12345".to_string();
        let pending = PendingOAuthState {
            state: state_str.clone(),
            code_verifier: "code-verifier-abc".to_string(),
            user_did: "did:plc:bob-retry-test".to_string(),
            pds_endpoint: mock_server.uri(),
            token_endpoint: format!("{}/oauth/token", mock_server.uri()),
            auth_server_iss: Some(mock_server.uri()),
            created_at: Utc::now(),
            in_flight: false,
        };
        service
            .pending_states
            .write()
            .insert(state_str.clone(), pending);

        // 1. First attempt: token endpoint returns 500 error (transient failure)
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        let res1 = service
            .handle_callback("auth-code-1", &state_str, &http_client)
            .await;
        assert!(
            res1.is_err(),
            "First callback attempt must fail on 500 error"
        );

        // Pending state must STILL exist and in_flight must be reset to false (retryable)
        {
            let lock = service.pending_states.read();
            let state_entry = lock
                .get(&state_str)
                .expect("Pending state must survive transient failure");
            assert!(
                !state_entry.in_flight,
                "in_flight must be reset to false for retry"
            );
        }

        // 2. Second attempt: token endpoint returns 200 OK
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "valid-access-token",
                "refresh_token": "valid-refresh-token",
                "expires_in": 3600,
                "sub": "did:plc:bob-retry-test"
            })))
            .mount(&mock_server)
            .await;

        let res2 = service
            .handle_callback("auth-code-1", &state_str, &http_client)
            .await;
        assert!(
            res2.is_ok(),
            "Second callback attempt must succeed, got err: {:?}",
            res2.err()
        );

        // Session must now be stored in Postgres
        let session = service
            .get_session("did:plc:bob-retry-test")
            .await
            .unwrap()
            .expect("Session must be stored after success");
        assert_eq!(session.access_token, "valid-access-token");

        // Pending state must now be consumed / removed
        {
            let lock = service.pending_states.read();
            assert!(
                !lock.contains_key(&state_str),
                "Pending state must be removed after successful exchange"
            );
        }

        // 3. Third attempt (replay of same code and state) must fail
        let res3 = service
            .handle_callback("auth-code-1", &state_str, &http_client)
            .await;
        assert!(
            res3.is_err(),
            "Replay of already-consumed authorization code must fail"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn expired_pending_states_are_evicted(pool: PgPool) {
        setup_test_encryption_key();
        let service = OAuthService::new(
            pool.clone(),
            "http://127.0.0.1:3002".to_string(),
            p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
            None,
        );
        let expired_state = "expired-state".to_string();
        let fresh_state = "fresh-state".to_string();

        let expired_pending = PendingOAuthState {
            state: expired_state.clone(),
            code_verifier: "verifier-1".to_string(),
            user_did: "did:plc:expired-user".to_string(),
            pds_endpoint: "https://pds.expired.example".to_string(),
            token_endpoint: "https://pds.expired.example/oauth/token".to_string(),
            auth_server_iss: Some("https://pds.expired.example".to_string()),
            created_at: Utc::now() - Duration::seconds(PENDING_STATE_TTL_SECS + 30),
            in_flight: false,
        };

        let fresh_pending = PendingOAuthState {
            state: fresh_state.clone(),
            code_verifier: "verifier-2".to_string(),
            user_did: "did:plc:fresh-user".to_string(),
            pds_endpoint: "https://pds.fresh.example".to_string(),
            token_endpoint: "https://pds.fresh.example/oauth/token".to_string(),
            auth_server_iss: Some("https://pds.fresh.example".to_string()),
            created_at: Utc::now(),
            in_flight: false,
        };

        {
            let mut lock = service.pending_states.write();
            lock.insert(expired_state.clone(), expired_pending);
            lock.insert(fresh_state.clone(), fresh_pending);
        }

        let evicted_count = service.cleanup_expired_pending_states();
        assert_eq!(
            evicted_count, 1,
            "Exactly one expired state should be evicted"
        );

        {
            let lock = service.pending_states.read();
            assert!(
                !lock.contains_key(&expired_state),
                "Expired state must be evicted"
            );
            assert!(
                lock.contains_key(&fresh_state),
                "Fresh state must be retained"
            );
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn concurrent_refreshes_for_one_user_result_in_exactly_one_http_refresh(pool: PgPool) {
        setup_test_encryption_key();
        let mock_server = MockServer::start().await;
        let service = Arc::new(OAuthService::with_transport(
            pool.clone(),
            "http://127.0.0.1:3002".to_string(),
            p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
            None,
            Arc::new(DefaultSpaceHostTransport::with_loopback(true)),
        ));
        let http_client = reqwest::Client::new();

        let user_did = "did:plc:concurrent-refresh-user";
        let initial_dpop_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());

        // Store an expired session with a refresh token
        let expired_session = UserOAuthSession {
            user_did: user_did.to_string(),
            access_token: "old-expired-access-token".to_string(),
            refresh_token: Some("valid-single-use-refresh-token".to_string()),
            token_endpoint: format!("{}/oauth/token", mock_server.uri()),
            auth_server_iss: mock_server.uri(),
            expires_at: Some(Utc::now() - Duration::minutes(5)),
            scope: CIRCLE_SCOPE.to_string(),
            dpop_key: initial_dpop_key,
        };
        service.store_session(expired_session).await.unwrap();

        // Set up mock token endpoint with a small delay so concurrent requests overlap in flight
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(50))
                    .set_body_json(serde_json::json!({
                        "access_token": "newly-refreshed-access-token",
                        "refresh_token": "rotated-next-refresh-token",
                        "expires_in": 3600
                    })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        // Spawn two concurrent get_valid_token calls for the same user
        let s1 = service.clone();
        let s2 = service.clone();
        let c1 = http_client.clone();
        let c2 = http_client.clone();

        let task1 = tokio::spawn(async move { s1.get_valid_token(user_did, &c1).await });
        let task2 = tokio::spawn(async move { s2.get_valid_token(user_did, &c2).await });

        let (res1, res2) = tokio::join!(task1, task2);
        let (token1, key1) = res1.unwrap().expect("task 1 get_valid_token must succeed");
        let (token2, key2) = res2.unwrap().expect("task 2 get_valid_token must succeed");

        assert_eq!(token1, "newly-refreshed-access-token");
        assert_eq!(token2, "newly-refreshed-access-token");
        assert_eq!(
            key1.to_bytes(),
            key2.to_bytes(),
            "both callers should receive the newly stored key"
        );

        // Verify the mock server received EXACTLY 1 request, proving concurrent refreshes were serialized
        mock_server.verify().await;

        // Verify the database now holds the updated non-expired session
        let updated = service.get_session(user_did).await.unwrap().unwrap();
        assert_eq!(updated.access_token, "newly-refreshed-access-token");
        assert_eq!(
            updated.refresh_token.as_deref(),
            Some("rotated-next-refresh-token")
        );
        assert!(updated.expires_at.unwrap() > Utc::now());
    }
}
