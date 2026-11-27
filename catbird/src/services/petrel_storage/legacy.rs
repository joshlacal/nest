//! Nest's durable grant format, also used by revocation and cleanup jobs.
//! All persisted keys and flattened fields are part of the v2 rollback contract.
use jose_jwk::Key;
use petrel::{
    crypto::{base64url, decode_base64url, DpopSigner, SoftwareDpopSigner},
    oauth::{Account, SessionRecord},
    storage::StoreError,
};
use petrel_core::{Datetime, Did};
use petrel_oauth_scopes::ScopeSet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use std::fmt;
use url::Url;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OAuthTokenType {
    DPoP,
    Bearer,
}

impl OAuthTokenType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DPoP => "DPoP",
            Self::Bearer => "Bearer",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DpopClientData {
    pub dpop_key: Key,
    pub dpop_authserver_nonce: String,
    pub dpop_host_nonce: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DpopReqData {
    pub dpop_key: Key,
    pub dpop_authserver_nonce: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub iss: String,
    pub sub: Did,
    pub aud: String,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: String,
    pub token_type: OAuthTokenType,
    pub expires_at: Option<Datetime>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LegacySessionV2 {
    pub account_did: Did,
    pub session_id: String,
    pub host_url: Url,
    pub authserver_url: String,
    pub authserver_token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authserver_revocation_endpoint: Option<String>,
    #[serde(with = "scope_string")]
    pub scopes: ScopeSet,
    #[serde(flatten)]
    pub dpop_data: DpopClientData,
    #[serde(flatten)]
    pub token_set: TokenSet,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_scopes: Option<Vec<Value>>,
}

pub type ClientSessionData = LegacySessionV2;

impl fmt::Debug for LegacySessionV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacySessionV2")
            .field("account_did", &self.account_did)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthRequestData {
    pub state: String,
    pub authserver_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_did: Option<Did>,
    #[serde(with = "scope_string")]
    pub scopes: ScopeSet,
    pub request_uri: String,
    pub authserver_token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authserver_revocation_endpoint: Option<String>,
    pub pkce_verifier: String,
    #[serde(flatten)]
    pub dpop_data: DpopReqData,
}

impl fmt::Debug for AuthRequestData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthRequestData").finish_non_exhaustive()
    }
}

mod scope_string {
    use super::*;
    pub fn serialize<S: Serializer>(scopes: &ScopeSet, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&scopes.scope_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ScopeSet, D::Error> {
        ScopeSet::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

pub(super) fn corrupt(reason: &'static str) -> StoreError {
    StoreError::Corrupt(reason.into())
}

fn origin(url: &Url) -> Result<String, StoreError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(corrupt("session endpoint is not an origin"));
    }
    Ok(url.origin().ascii_serialization())
}

impl LegacySessionV2 {
    pub(crate) fn to_petrel(&self, now: u64) -> Result<(SessionRecord, [u8; 32]), StoreError> {
        if self.account_did != self.token_set.sub
            || self.token_set.token_type != OAuthTokenType::DPoP
            || self.token_set.access_token.is_empty()
        {
            return Err(corrupt("session token type or account binding is invalid"));
        }
        let iss = Url::parse(&self.token_set.iss).map_err(|_| corrupt("invalid session issuer"))?;
        let authserver = Url::parse(&self.authserver_url)
            .map_err(|_| corrupt("invalid session authorization server"))?;
        let issuer = origin(&iss)?;
        if issuer != origin(&authserver)? {
            return Err(corrupt("session issuer binding is invalid"));
        }
        let scopes = if self.scopes.raw_scopes().is_empty() {
            ScopeSet::parse(self.token_set.scope.as_deref().unwrap_or_default())
                .map_err(|_| corrupt("invalid session scope"))?
        } else {
            self.scopes.clone()
        };
        if !scopes.includes_atproto() {
            return Err(corrupt("session lacks atproto scope"));
        }
        let jwk = serde_json::to_value(&self.dpop_data.dpop_key)
            .map_err(|_| corrupt("invalid DPoP key"))?;
        if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
            return Err(corrupt("invalid DPoP curve"));
        }
        let scalar: [u8; 32] = decode_base64url(
            jwk["d"]
                .as_str()
                .ok_or_else(|| corrupt("missing private DPoP key"))?,
            32,
        )
        .map_err(|_| corrupt("invalid DPoP key"))?
        .try_into()
        .map_err(|_| corrupt("invalid DPoP key length"))?;
        let public = SoftwareDpopSigner::from_bytes(&scalar)
            .map_err(|_| corrupt("invalid DPoP scalar"))?
            .public_jwk();
        if jwk["x"] != public.x || jwk["y"] != public.y {
            return Err(corrupt("DPoP key coordinates do not match scalar"));
        }
        let jkt = public
            .thumbprint()
            .map_err(|_| corrupt("invalid DPoP thumbprint"))?;
        let expires_at = self
            .token_set
            .expires_at
            .as_ref()
            .and_then(|d| u64::try_from(d.unix_seconds()).ok())
            .unwrap_or_default();
        let session = serde_json::from_value(json!({
            "did": self.account_did, "access_token": self.token_set.access_token, "refresh_token": self.token_set.refresh_token,
            "created_at": now, "expires_in": expires_at.saturating_sub(now), "scope": scopes.scope_string()
        })).map_err(|_| corrupt("invalid token record"))?;
        Ok((
            SessionRecord {
                account: Account {
                    did: self.account_did.clone(),
                    handle: None,
                    pds: origin(&self.host_url)?,
                    expected_issuer: Some(issuer),
                    authorization_server: None,
                },
                session,
                dpop_key_id: format!("nest-{jkt}"),
                dpop_jkt: jkt,
            },
            scalar,
        ))
    }

    pub fn from_petrel(
        record: &SessionRecord,
        scalar: &[u8; 32],
        session_id: &str,
    ) -> Result<Self, StoreError> {
        let metadata = record
            .account
            .authorization_server
            .as_ref()
            .ok_or_else(|| corrupt("callback session lacks server metadata"))?;
        let public = SoftwareDpopSigner::from_bytes(scalar)
            .map_err(|_| corrupt("invalid DPoP scalar"))?
            .public_jwk();
        if record.account.did != record.session.did
            || public
                .thumbprint()
                .map_err(|_| corrupt("invalid DPoP key"))?
                != record.dpop_jkt
        {
            return Err(corrupt("callback account or key binding is invalid"));
        }
        let key = serde_json::from_value(
            json!({"kty":"EC","crv":"P-256","x":public.x,"y":public.y,"d":base64url(scalar)}),
        )
        .map_err(|_| corrupt("invalid DPoP key"))?;
        let scopes = ScopeSet::parse(record.session.scope())
            .map_err(|_| corrupt("invalid callback scope"))?;
        Ok(Self {
            account_did: record.account.did.clone(),
            session_id: session_id.to_owned(),
            host_url: Url::parse(&record.account.pds).map_err(|_| corrupt("invalid PDS origin"))?,
            authserver_url: metadata.issuer.clone(),
            authserver_token_endpoint: metadata
                .token_endpoint
                .clone()
                .ok_or_else(|| corrupt("missing token endpoint"))?,
            authserver_revocation_endpoint: metadata.revocation_endpoint.clone(),
            scopes,
            resolved_scopes: None,
            dpop_data: DpopClientData {
                dpop_key: key,
                dpop_authserver_nonce: String::new(),
                dpop_host_nonce: String::new(),
            },
            token_set: TokenSet {
                iss: metadata.issuer.clone(),
                sub: record.session.did.clone(),
                aud: record.account.pds.clone(),
                scope: Some(record.session.scope().into()),
                refresh_token: record.session.refresh_token().map(str::to_owned),
                access_token: record.session.access_token().into(),
                token_type: OAuthTokenType::DPoP,
                expires_at: Some(expiry(record)?),
            },
        })
    }
}

pub(super) fn expiry(record: &SessionRecord) -> Result<Datetime, StoreError> {
    let seconds =
        i64::try_from(record.session.expires_at()).map_err(|_| corrupt("expiry out of range"))?;
    Datetime::from_unix(seconds, 0).map_err(|_| corrupt("expiry out of range"))
}
