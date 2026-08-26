//! AppView confidential OAuth client identity and authorization-code flow.
//!
//! Provides:
//! - `client-metadata.json` and published JWKS
//! - AppView-signed `atproto-client-attestation+jwt`
//! - OAuth 2.0 authorization-code flow with PAR and PKCE against user PDSes
//! - User OAuth session management and token renewal

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
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

use crate::auth::{parse_public_key_jwk, DidResolver, JwtHeader, PublicKeyJwk};
use crate::config::AppState;
use crate::error::{AppError, AuthReason};
/// Scope requested for the AppView's own grant.
///
/// The bare `atproto` scope is MANDATORY in every atproto OAuth authorization
/// request; a PDS rejects the request with `invalid_request` / `Missing "atproto"
/// scope` without it. The permissioned-data scope alone is not sufficient, which
/// a live authorization against spaces-alpha.host.bsky.network proved.
pub const CIRCLE_SCOPE: &str = "atproto space:blue.catbird.circle?authority=*&action=read";
pub const CALLBACK_DEEP_LINK: &str = "blue.catbird://oauth/circle-appview";

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
}

#[derive(Debug, Clone)]
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

#[derive(Clone)]
pub struct OAuthService {
    pub client_id: String,
    pub base_url: String,
    pub key_id: String,
    pub signing_key: p256::ecdsa::SigningKey,
    pub verifying_key: p256::ecdsa::VerifyingKey,
    pub client_metadata: OAuthClientMetadata,
    pub jwks: JwksResponse,
    pending_states: Arc<RwLock<HashMap<String, PendingOAuthState>>>,
    sessions: Arc<RwLock<HashMap<String, UserOAuthSession>>>,
}

impl OAuthService {
    pub fn new(base_url: String, signing_key: p256::ecdsa::SigningKey, key_id: Option<String>) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let client_id = format!("{base_url}/oauth/client-metadata.json");
        let jwks_uri = format!("{base_url}/oauth/jwks.json");
        let redirect_uri = format!("{base_url}/oauth/callback");

        let verifying_key = *signing_key.verifying_key();
        let ep = EncodedPoint::from(&verifying_key);
        let x = URL_SAFE_NO_PAD.encode(ep.x().expect("x coordinate"));
        let y = URL_SAFE_NO_PAD.encode(ep.y().expect("y coordinate"));

        let key_id = key_id.unwrap_or_else(|| {
            let thumbprint = Sha256::digest(format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}").as_bytes());
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
            pending_states: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
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

    fn sign_jwt(&self, header: &serde_json::Value, claims: &serde_json::Value) -> Result<String, AppError> {
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
        let pds_endpoint = did_resolver
            .resolve_pds_endpoint(user_did)
            .await
            .map_err(|e| AppError::Internal(format!("Resolving user PDS endpoint failed: {e:?}")))?;

        let (auth_endpoint, token_endpoint, par_endpoint, auth_issuer) = self
            .discover_oauth_metadata(&pds_endpoint, http_client)
            .await?;

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
        let authorization_url = if let Some(par_url) = par_endpoint {
            let client_assertion = self.create_client_assertion(&par_url)?;
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

            let res = http_client.post(&par_url).form(&params).send().await;
            match res {
                Ok(resp) if resp.status().is_success() => {
                    #[derive(Deserialize)]
                    struct ParResponse {
                        request_uri: String,
                    }
                    let par: ParResponse = resp
                        .json()
                        .await
                        .map_err(|e| AppError::Internal(format!("PAR response decode error: {e}")))?;
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
            lock.insert(
                state.clone(),
                PendingOAuthState {
                    state: state.clone(),
                    code_verifier,
                    user_did: user_did.to_string(),
                    pds_endpoint,
                    token_endpoint,
                    auth_server_iss: auth_issuer,
                    created_at: Utc::now(),
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
        http_client: &reqwest::Client,
    ) -> Result<String, AppError> {
        let pending = {
            let mut lock = self.pending_states.write();
            lock.remove(state)
                .ok_or_else(|| AppError::Unauthorized(crate::error::AuthReason::InvalidClaimsJson))?
        };

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
        let client_assertion = self.create_client_assertion(&auth_server_iss)?;

        let response = post_form_with_dpop(
            http_client,
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
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Token exchange returned {status}: {body}"
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

        let token_data: TokenResponse = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Token response parse error: {e}")))?;

        let user_did = token_data.sub.unwrap_or(pending.user_did);
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

        {
            let mut lock = self.sessions.write();
            lock.insert(user_did, session);
        }

        Ok(CALLBACK_DEEP_LINK.to_string())
    }

    /// Retrieve a valid token and DPoP signing key for a user, refreshing if expired.
    pub async fn get_valid_token(
        &self,
        user_did: &str,
        http_client: &reqwest::Client,
    ) -> Result<(String, p256::ecdsa::SigningKey), AppError> {
        let (
            needs_refresh,
            token_endpoint,
            auth_server_iss,
            refresh_token,
            dpop_key,
            current_token,
        ) = {
            let lock = self.sessions.read();
            let session = lock
                .get(user_did)
                .ok_or_else(|| AppError::Unauthorized(crate::error::AuthReason::NoVerificationMethod))?;

            let expired = session
                .expires_at
                .is_some_and(|exp| exp <= Utc::now() + chrono::Duration::seconds(30));
            (
                expired && session.refresh_token.is_some(),
                session.token_endpoint.clone(),
                session.auth_server_iss.clone(),
                session.refresh_token.clone(),
                session.dpop_key.clone(),
                session.access_token.clone(),
            )
        };

        if !needs_refresh {
            return Ok((current_token, dpop_key));
        }

        let refresh_token = refresh_token.unwrap();
        let new_dpop_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let client_assertion = self.create_client_assertion(&auth_server_iss)?;

        let response = post_form_with_dpop(
            http_client,
            &new_dpop_key,
            &token_endpoint,
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
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Token refresh returned {status}: {body}"
            )));
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<i64>,
            scope: Option<String>,
        }

        let token_data: TokenResponse = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Token refresh parse error: {e}")))?;

        let expires_at = token_data
            .expires_in
            .map(|exp| Utc::now() + chrono::Duration::seconds(exp));

        let new_token = token_data.access_token.clone();
        let final_dpop_key = new_dpop_key.clone();

        {
            let mut lock = self.sessions.write();
            if let Some(session) = lock.get_mut(user_did) {
                session.access_token = token_data.access_token;
                if let Some(rt) = token_data.refresh_token {
                    session.refresh_token = Some(rt);
                }
                session.expires_at = expires_at;
                session.dpop_key = new_dpop_key;
                if let Some(sc) = token_data.scope {
                    session.scope = sc;
                }
            }
        }

        Ok((new_token, final_dpop_key))
    }

    /// Retrieve stored session for a user.
    pub fn get_session(&self, user_did: &str) -> Option<UserOAuthSession> {
        let lock = self.sessions.read();
        lock.get(user_did).cloned()
    }

    /// Store or update a user OAuth session.
    pub fn store_session(&self, session: UserOAuthSession) {
        let mut lock = self.sessions.write();
        lock.insert(session.user_did.clone(), session);
    }

    /// Discard DPoP private key for a user or session.
    pub fn remove_session(&self, user_did: &str) {
        let mut lock = self.sessions.write();
        lock.remove(user_did);
    }

    async fn discover_oauth_metadata(
        &self,
        pds_endpoint: &str,
        http_client: &reqwest::Client,
    ) -> Result<(String, String, Option<String>, Option<String>), AppError> {
        let pds_base = pds_endpoint.trim_end_matches('/');
        let well_known_auth = format!("{pds_base}/.well-known/oauth-authorization-server");
        let well_known_resource = format!("{pds_base}/.well-known/oauth-protected-resource");

        let auth_res = http_client.get(&well_known_auth).send().await;
        if let Ok(resp) = auth_res {
            if resp.status().is_success() {
                #[derive(Deserialize)]
                struct AuthServerMetadata {
                    issuer: Option<String>,
                    authorization_endpoint: String,
                    token_endpoint: String,
                    pushed_authorization_request_endpoint: Option<String>,
                }
                if let Ok(meta) = resp.json::<AuthServerMetadata>().await {
                    return Ok((
                        meta.authorization_endpoint,
                        meta.token_endpoint,
                        meta.pushed_authorization_request_endpoint,
                        meta.issuer,
                    ));
                }
            }
        }

        // Try protected resource metadata
        let res_resp = http_client.get(&well_known_resource).send().await;
        if let Ok(resp) = res_resp {
            if resp.status().is_success() {
                #[derive(Deserialize)]
                struct ProtectedResourceMetadata {
                    authorization_servers: Option<Vec<String>>,
                }
                if let Ok(meta) = resp.json::<ProtectedResourceMetadata>().await {
                    if let Some(servers) = meta.authorization_servers {
                        if let Some(server) = servers.first() {
                            let server_meta_url = format!("{}/.well-known/oauth-authorization-server", server.trim_end_matches('/'));
                            if let Ok(s_resp) = http_client.get(&server_meta_url).send().await {
                                #[derive(Deserialize)]
                                struct AuthServerMetadata {
                                    issuer: Option<String>,
                                    authorization_endpoint: String,
                                    token_endpoint: String,
                                    pushed_authorization_request_endpoint: Option<String>,
                                }
                                if let Ok(meta) = s_resp.json::<AuthServerMetadata>().await {
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
    let body = first.text().await.unwrap_or_default();

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
    if status != reqwest::StatusCode::UNAUTHORIZED
        && status != reqwest::StatusCode::BAD_REQUEST
    {
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
        let body = first.text().await.unwrap_or_default();
        if !body.contains("use_dpop_nonce") {
            return Err(AppError::Internal(format!("{status}: {body}")));
        }
    }

    match nonce {
        Some(nonce) => send(create_dpop_proof(key, "GET", url, Some(token), Some(&nonce))?)
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
    http_client: &reqwest::Client,
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

    // Fetch client metadata from client_id
    let meta_resp = http_client
        .get(&claims.iss)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch client-metadata: {e}")))?;
    if !meta_resp.status().is_success() {
        return Err(AppError::Internal(format!(
            "client-metadata returned {}",
            meta_resp.status()
        )));
    }
    let metadata: OAuthClientMetadata = meta_resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse client-metadata: {e}")))?;

    // Fetch JWKS from metadata.jwks_uri
    let jwks_resp = http_client
        .get(&metadata.jwks_uri)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch JWKS: {e}")))?;
    if !jwks_resp.status().is_success() {
        return Err(AppError::Internal(format!(
            "JWKS returned {}",
            jwks_resp.status()
        )));
    }
    let jwks: JwksResponse = jwks_resp
        .json()
        .await
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
    use super::CIRCLE_SCOPE;

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
}
