use chrono::{TimeDelta, Utc};
use http::{Method, Request, StatusCode};
use jacquard_common::{
    CowStr, IntoStatic,
    cowstr::ToCowStr,
    http_client::HttpClient,
    session::SessionStoreError,
    types::{
        did::Did,
        string::{AtStrError, Datetime},
    },
};
use jacquard_identity::resolver::IdentityError;
use serde::Serialize;
use serde_json::Value;
use smol_str::ToSmolStr;

use crate::{
    FALLBACK_ALG,
    atproto::atproto_client_metadata,
    dpop::DpopExt,
    jose::jwt::{RegisteredClaims, RegisteredClaimsAud},
    keyset::Keyset,
    resolver::OAuthResolver,
    scopes::Scope,
    session::{
        AuthRequestData, ClientData, ClientSessionData, DpopClientData, DpopDataSource, DpopReqData,
    },
    types::{
        AuthorizationCodeChallengeMethod, AuthorizationResponseType, AuthorizeOptionPrompt,
        OAuthAuthorizationServerMetadata, OAuthClientMetadata, OAuthParResponse,
        OAuthTokenResponse, ParParameters, RefreshRequestParameters, RevocationRequestParameters,
        TokenGrantType, TokenRequestParameters, TokenSet,
    },
    utils::{compare_algos, generate_dpop_key, generate_nonce, generate_pkce},
};

// https://datatracker.ietf.org/doc/html/rfc7523#section-2.2
const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

use smol_str::SmolStr;

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// OAuth request error for token operations and auth flows
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("{kind}")]
pub struct RequestError {
    #[diagnostic_source]
    kind: RequestErrorKind,
    #[source]
    source: Option<BoxError>,
    #[help]
    help: Option<SmolStr>,
    context: Option<SmolStr>,
    url: Option<SmolStr>,
    details: Option<SmolStr>,
    location: Option<SmolStr>,
}

/// Error categories for OAuth request operations
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum RequestErrorKind {
    /// No endpoint available
    #[error("no {0} endpoint available")]
    #[diagnostic(
        code(jacquard_oauth::request::no_endpoint),
        help("server does not advertise this endpoint")
    )]
    NoEndpoint(SmolStr),

    /// Token response verification failed
    #[error("token response verification failed")]
    #[diagnostic(code(jacquard_oauth::request::token_verification))]
    TokenVerification,

    /// Unsupported authentication method
    #[error("unsupported authentication method")]
    #[diagnostic(
        code(jacquard_oauth::request::unsupported_auth_method),
        help(
            "server must support `private_key_jwt` or `none`; configure client metadata accordingly"
        )
    )]
    UnsupportedAuthMethod,

    /// No refresh token available
    #[error("no refresh token available")]
    #[diagnostic(code(jacquard_oauth::request::no_refresh_token))]
    NoRefreshToken,

    /// Invalid DID
    #[error("failed to parse DID")]
    #[diagnostic(code(jacquard_oauth::request::invalid_did))]
    InvalidDid,

    /// DPoP client error
    #[error("dpop error")]
    #[diagnostic(code(jacquard_oauth::request::dpop))]
    Dpop,

    /// Session storage error
    #[error("storage error")]
    #[diagnostic(code(jacquard_oauth::request::storage))]
    Storage,

    /// Resolver error
    #[error("resolver error")]
    #[diagnostic(code(jacquard_oauth::request::resolver))]
    Resolver,

    /// HTTP build error
    #[error("http build error")]
    #[diagnostic(code(jacquard_oauth::request::http_build))]
    HttpBuild,

    /// HTTP status error
    #[error("http status: {0}")]
    #[diagnostic(
        code(jacquard_oauth::request::http_status),
        help("see server response for details")
    )]
    HttpStatus(StatusCode),

    /// HTTP status with error body
    #[error("http status: {status}, body: {body:?}")]
    #[diagnostic(
        code(jacquard_oauth::request::http_status_body),
        help("server returned error JSON; inspect fields like `error`, `error_description`")
    )]
    HttpStatusWithBody { status: StatusCode, body: Value },

    /// Identity resolution error
    #[error("identity error")]
    #[diagnostic(code(jacquard_oauth::request::identity))]
    Identity,

    /// Keyset error
    #[error("keyset error")]
    #[diagnostic(code(jacquard_oauth::request::keyset))]
    Keyset,

    /// Form serialization error
    #[error("form serialization error")]
    #[diagnostic(code(jacquard_oauth::request::serde_form))]
    SerdeHtmlForm,

    /// JSON error
    #[error("json error")]
    #[diagnostic(code(jacquard_oauth::request::serde_json))]
    SerdeJson,

    /// Atproto metadata error
    #[error("atproto error")]
    #[diagnostic(code(jacquard_oauth::request::atproto))]
    Atproto,
}

impl RequestError {
    /// Create a new error with the given kind and optional source
    pub fn new(kind: RequestErrorKind, source: Option<BoxError>) -> Self {
        Self {
            kind,
            source,
            help: None,
            context: None,
            url: None,
            details: None,
            location: None,
        }
    }

    /// Get the error kind
    pub fn kind(&self) -> &RequestErrorKind {
        &self.kind
    }

    /// Get the source error if present
    pub fn source_err(&self) -> Option<&BoxError> {
        self.source.as_ref()
    }

    /// Get the context string if present
    pub fn context(&self) -> Option<&str> {
        self.context.as_ref().map(|s| s.as_str())
    }

    /// Get the URL if present
    pub fn url(&self) -> Option<&str> {
        self.url.as_ref().map(|s| s.as_str())
    }

    /// Get the details if present
    pub fn details(&self) -> Option<&str> {
        self.details.as_ref().map(|s| s.as_str())
    }

    /// Get the location if present
    pub fn location(&self) -> Option<&str> {
        self.location.as_ref().map(|s| s.as_str())
    }

    /// Add help text to this error
    pub fn with_help(mut self, help: impl Into<SmolStr>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Add context to this error
    pub fn with_context(mut self, context: impl Into<SmolStr>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Add URL to this error
    pub fn with_url(mut self, url: impl Into<SmolStr>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Add details to this error
    pub fn with_details(mut self, details: impl Into<SmolStr>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Add location to this error
    pub fn with_location(mut self, location: impl Into<SmolStr>) -> Self {
        self.location = Some(location.into());
        self
    }

    // Constructors for each kind

    /// Create a no endpoint error
    pub fn no_endpoint(endpoint: impl Into<SmolStr>) -> Self {
        Self::new(RequestErrorKind::NoEndpoint(endpoint.into()), None)
    }

    /// Create a token verification error
    pub fn token_verification() -> Self {
        Self::new(RequestErrorKind::TokenVerification, None)
    }

    /// Create an unsupported authentication method error
    pub fn unsupported_auth_method() -> Self {
        Self::new(RequestErrorKind::UnsupportedAuthMethod, None)
    }

    /// Create a no refresh token error
    pub fn no_refresh_token() -> Self {
        Self::new(RequestErrorKind::NoRefreshToken, None)
    }

    /// Create an invalid DID error
    pub fn invalid_did(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::new(RequestErrorKind::InvalidDid, Some(Box::new(source)))
    }

    /// Create a DPoP error
    pub fn dpop(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::new(RequestErrorKind::Dpop, Some(Box::new(source)))
    }

    /// Create a storage error
    pub fn storage(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::new(RequestErrorKind::Storage, Some(Box::new(source)))
    }

    /// Create a resolver error
    pub fn resolver(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::new(RequestErrorKind::Resolver, Some(Box::new(source)))
    }

    /// Create an HTTP build error
    pub fn http_build(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::new(RequestErrorKind::HttpBuild, Some(Box::new(source)))
    }

    /// Create an HTTP status error
    pub fn http_status(status: StatusCode) -> Self {
        Self::new(RequestErrorKind::HttpStatus(status), None)
    }

    /// Create an HTTP status with body error
    pub fn http_status_with_body(status: StatusCode, body: Value) -> Self {
        Self::new(RequestErrorKind::HttpStatusWithBody { status, body }, None)
    }

    /// Create an identity error
    pub fn identity(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::new(RequestErrorKind::Identity, Some(Box::new(source)))
    }

    /// Create a keyset error
    pub fn keyset(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::new(RequestErrorKind::Keyset, Some(Box::new(source)))
    }

    /// Create an atproto metadata error
    pub fn atproto(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::new(RequestErrorKind::Atproto, Some(Box::new(source)))
    }

    /// Returns true if this error indicates permanent auth failure
    /// (token revoked, refresh_token expired, etc.)
    ///
    /// When this returns true, the session should be cleared from storage
    /// rather than retried.
    pub fn is_permanent(&self) -> bool {
        match &self.kind {
            RequestErrorKind::NoRefreshToken => true,
            RequestErrorKind::HttpStatusWithBody { body, .. } => body
                .get("error")
                .and_then(|e| e.as_str())
                .is_some_and(|e| matches!(e, "invalid_grant" | "access_denied")),
            _ => false,
        }
    }

    /// Returns true only when the authorization server explicitly reports
    /// that the submitted grant token is already unusable. This is narrower
    /// than `is_permanent`: access denial or client-authentication failures do
    /// not prove that a refresh grant has been revoked.
    pub fn proves_token_inactive(&self) -> bool {
        match &self.kind {
            RequestErrorKind::HttpStatusWithBody { status, body }
                if *status == StatusCode::BAD_REQUEST =>
            {
                body.get("error")
                    .and_then(|error| error.as_str())
                    .is_some_and(|error| matches!(error, "invalid_grant" | "invalid_token"))
            }
            _ => false,
        }
    }
}

// From impls for common error types

impl From<AtStrError> for RequestError {
    fn from(e: AtStrError) -> Self {
        let msg = smol_str::format_smolstr!("{:?}", e);
        Self::new(RequestErrorKind::InvalidDid, Some(Box::new(e)))
            .with_context(msg)
            .with_help("ensure DID is correctly formatted (e.g., did:plc:abc123)")
    }
}

impl From<crate::dpop::Error> for RequestError {
    fn from(e: crate::dpop::Error) -> Self {
        let msg = smol_str::format_smolstr!("{:?}", e);
        Self::new(RequestErrorKind::Dpop, Some(Box::new(e)))
            .with_context(msg)
            .with_help("check DPoP key configuration and nonce handling")
    }
}

impl From<SessionStoreError> for RequestError {
    fn from(e: SessionStoreError) -> Self {
        let msg = smol_str::format_smolstr!("{:?}", e);
        Self::new(RequestErrorKind::Storage, Some(Box::new(e)))
            .with_context(msg)
            .with_help("verify session store is accessible and writable")
    }
}

impl From<crate::resolver::ResolverError> for RequestError {
    fn from(e: crate::resolver::ResolverError) -> Self {
        let msg = smol_str::format_smolstr!("{:?}", e);
        Self::new(RequestErrorKind::Resolver, Some(Box::new(e)))
            .with_context(msg)
            .with_help("check identity resolution and OAuth metadata endpoints")
    }
}

impl From<http::Error> for RequestError {
    fn from(e: http::Error) -> Self {
        let msg = smol_str::format_smolstr!("{:?}", e);
        Self::new(RequestErrorKind::HttpBuild, Some(Box::new(e)))
            .with_context(msg)
            .with_help("verify request URIs and headers are valid")
    }
}

impl From<IdentityError> for RequestError {
    fn from(e: IdentityError) -> Self {
        let msg = smol_str::format_smolstr!("{:?}", e);
        Self::new(RequestErrorKind::Identity, Some(Box::new(e)))
            .with_context(msg)
            .with_help("check handle/DID is valid and identity resolver is configured")
    }
}

impl From<crate::keyset::Error> for RequestError {
    fn from(e: crate::keyset::Error) -> Self {
        let msg = smol_str::format_smolstr!("{:?}", e);
        Self::new(RequestErrorKind::Keyset, Some(Box::new(e)))
            .with_context(msg)
            .with_help("verify keyset configuration and signing algorithm support")
    }
}

impl From<serde_html_form::ser::Error> for RequestError {
    fn from(e: serde_html_form::ser::Error) -> Self {
        let msg = smol_str::format_smolstr!("{:?}", e);
        Self::new(RequestErrorKind::SerdeHtmlForm, Some(Box::new(e)))
            .with_context(msg)
            .with_help("check OAuth request parameters are serializable")
    }
}

impl From<serde_json::Error> for RequestError {
    fn from(e: serde_json::Error) -> Self {
        let msg = smol_str::format_smolstr!("{:?}", e);
        Self::new(RequestErrorKind::SerdeJson, Some(Box::new(e)))
            .with_context(msg)
            .with_help("verify OAuth response body is valid JSON")
    }
}

impl From<crate::atproto::Error> for RequestError {
    fn from(e: crate::atproto::Error) -> Self {
        let msg = smol_str::format_smolstr!("{:?}", e);
        Self::new(RequestErrorKind::Atproto, Some(Box::new(e)))
            .with_context(msg)
            .with_help("ensure client metadata matches atproto requirements")
    }
}

pub type Result<T> = core::result::Result<T, RequestError>;

#[allow(dead_code)]
pub enum OAuthRequest<'a> {
    Token(TokenRequestParameters<'a>),
    Refresh(RefreshRequestParameters<'a>),
    Revocation(RevocationRequestParameters<'a>),
    Introspection,
    PushedAuthorizationRequest(ParParameters<'a>),
}

impl OAuthRequest<'_> {
    pub fn name(&self) -> CowStr<'static> {
        CowStr::new_static(match self {
            Self::Token(_) => "token",
            Self::Refresh(_) => "refresh",
            Self::Revocation(_) => "revocation",
            Self::Introspection => "introspection",
            Self::PushedAuthorizationRequest(_) => "pushed_authorization_request",
        })
    }
    pub fn expected_status(&self) -> StatusCode {
        match self {
            Self::Token(_) | Self::Refresh(_) => StatusCode::OK,
            Self::PushedAuthorizationRequest(_) => StatusCode::CREATED,
            // Unlike https://datatracker.ietf.org/doc/html/rfc7009#section-2.2, oauth-provider seems to return `204`.
            Self::Revocation(_) => StatusCode::NO_CONTENT,
            _ => unimplemented!(),
        }
    }

    pub fn accepts_status(&self, status: StatusCode) -> bool {
        match self {
            // RFC 7009 requires 200. The deployed provider historically uses
            // 204, so accept both successful, bodyless revocation responses.
            Self::Revocation(_) => matches!(status, StatusCode::OK | StatusCode::NO_CONTENT),
            _ => status == self.expected_status(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RequestPayload<'a, T>
where
    T: Serialize,
{
    client_id: CowStr<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_assertion_type: Option<CowStr<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_assertion: Option<CowStr<'a>>,
    #[serde(flatten)]
    parameters: T,
}

#[derive(Debug, Clone)]
pub struct OAuthMetadata {
    pub server_metadata: OAuthAuthorizationServerMetadata<'static>,
    pub client_metadata: OAuthClientMetadata<'static>,
    pub keyset: Option<Keyset>,
}

impl OAuthMetadata {
    pub async fn new<'r, T: HttpClient + OAuthResolver + Send + Sync>(
        client: &T,
        ClientData { keyset, config }: &ClientData<'r>,
        session_data: &ClientSessionData<'r>,
    ) -> Result<Self> {
        Ok(OAuthMetadata {
            server_metadata: client
                .get_authorization_server_metadata(&session_data.authserver_url)
                .await?,
            client_metadata: atproto_client_metadata(config.clone(), &keyset)
                .unwrap()
                .into_static(),
            keyset: keyset.clone(),
        })
    }
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all, fields(login_hint = login_hint.as_ref().map(|h| h.as_ref()))))]
pub async fn par<'r, T: OAuthResolver + DpopExt + Send + Sync + 'static>(
    client: &T,
    login_hint: Option<CowStr<'r>>,
    prompt: Option<AuthorizeOptionPrompt>,
    metadata: &OAuthMetadata,
    state: Option<CowStr<'r>>,
) -> crate::request::Result<AuthRequestData<'r>> {
    let state = if let Some(state) = state {
        state
    } else {
        generate_nonce()
    };
    let (code_challenge, verifier) = generate_pkce();

    let Some(dpop_key) = generate_dpop_key(&metadata.server_metadata) else {
        return Err(RequestError::token_verification());
    };
    let mut dpop_data = DpopReqData {
        dpop_key,
        dpop_authserver_nonce: None,
    };
    let parameters = ParParameters {
        response_type: AuthorizationResponseType::Code,
        redirect_uri: metadata.client_metadata.redirect_uris[0].to_cowstr(),
        state: state.clone(),
        scope: metadata.client_metadata.scope.clone(),
        response_mode: None,
        code_challenge,
        code_challenge_method: AuthorizationCodeChallengeMethod::S256,
        login_hint: login_hint,
        prompt: prompt.map(CowStr::from),
    };

    if metadata
        .server_metadata
        .pushed_authorization_request_endpoint
        .is_some()
    {
        let par_response = oauth_request::<OAuthParResponse, T, DpopReqData>(
            &client,
            &mut dpop_data,
            OAuthRequest::PushedAuthorizationRequest(parameters),
            metadata,
        )
        .await?;

        let scopes = if let Some(scope) = &metadata.client_metadata.scope {
            Scope::parse_multiple_reduced(&scope)
                .expect("Failed to parse scopes")
                .into_static()
        } else {
            vec![]
        };
        let auth_req_data = AuthRequestData {
            state,
            authserver_url: metadata.server_metadata.issuer.clone(),
            account_did: None,
            scopes,
            request_uri: par_response.request_uri.to_cowstr().into_static(),
            authserver_token_endpoint: metadata.server_metadata.token_endpoint.clone(),
            authserver_revocation_endpoint: metadata.server_metadata.revocation_endpoint.clone(),
            pkce_verifier: verifier,
            dpop_data,
        };

        Ok(auth_req_data)
    } else if metadata
        .server_metadata
        .require_pushed_authorization_requests
        == Some(true)
    {
        Err(RequestError::no_endpoint("pushed_authorization_request"))
    } else {
        todo!("use of PAR is mandatory")
    }
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all, fields(did = %session_data.account_did)))]
pub async fn refresh<'r, T>(
    client: &T,
    mut session_data: ClientSessionData<'r>,
    metadata: &OAuthMetadata,
) -> Result<ClientSessionData<'r>>
where
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
{
    let Some(refresh_token) = session_data.token_set.refresh_token.as_ref() else {
        return Err(RequestError::no_refresh_token());
    };

    // /!\ IMPORTANT /!\
    //
    // The "sub" MUST be a DID, whose issuer authority is indeed the server we
    // are trying to obtain credentials from. Note that we are doing this
    // *before* we actually try to refresh the token:
    // 1) To avoid unnecessary refresh
    // 2) So that the refresh is the last async operation, ensuring as few
    //    async operations happen before the result gets a chance to be stored.
    let aud = client
        .verify_issuer(&metadata.server_metadata, &session_data.token_set.sub)
        .await?;
    let iss = metadata.server_metadata.issuer.clone();

    let response = oauth_request::<OAuthTokenResponse, T, DpopClientData>(
        client,
        &mut session_data.dpop_data,
        OAuthRequest::Refresh(RefreshRequestParameters {
            grant_type: TokenGrantType::RefreshToken,
            refresh_token: refresh_token.clone(),
            scope: None,
        }),
        metadata,
    )
    .await?;

    let (_, expires_in) =
        validate_oauth_token_response(&response, Some(&session_data.token_set.sub), false)?;

    let expires_at = {
        let now = Datetime::now();
        now.as_ref()
            .checked_add_signed(TimeDelta::seconds(expires_in))
            .map(Datetime::new)
    };

    session_data.update_with_tokens(TokenSet {
        iss,
        sub: session_data.token_set.sub.clone(),
        aud: CowStr::Owned(aud.to_smolstr()),
        scope: response.scope.map(CowStr::Owned),
        access_token: CowStr::Owned(response.access_token),
        refresh_token: response.refresh_token.map(CowStr::Owned),
        token_type: response.token_type,
        expires_at,
    });

    Ok(session_data)
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all))]
pub async fn exchange_code<'r, T, D>(
    client: &T,
    data_source: &'r mut D,
    code: &str,
    verifier: &str,
    metadata: &OAuthMetadata,
    expected_sub: Option<&Did<'_>>,
) -> Result<TokenSet<'r>>
where
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
    D: DpopDataSource,
{
    let token_response = oauth_request::<OAuthTokenResponse, T, D>(
        client,
        data_source,
        OAuthRequest::Token(TokenRequestParameters {
            grant_type: TokenGrantType::AuthorizationCode,
            code: code.into(),
            redirect_uri: CowStr::Owned(
                metadata.client_metadata.redirect_uris[0]
                    .clone()
                    .to_smolstr(),
            ),
            code_verifier: verifier.into(),
        }),
        metadata,
    )
    .await?;
    let (sub, expires_in) = validate_oauth_token_response(&token_response, expected_sub, true)?;
    let sub = sub.expect("required token subject was validated");
    let iss = metadata.server_metadata.issuer.clone();
    // /!\ IMPORTANT /!\
    //
    // The token_response MUST always be valid before the "sub" it contains
    // can be trusted (see Atproto's OAuth spec for details).
    let aud = client
        .verify_issuer(&metadata.server_metadata, &sub)
        .await?;

    let expires_at = {
        Datetime::now()
            .as_ref()
            .checked_add_signed(TimeDelta::seconds(expires_in))
            .map(Datetime::new)
    };
    Ok(TokenSet {
        iss,
        sub,
        aud: CowStr::Owned(aud.to_smolstr()),
        scope: token_response.scope.map(CowStr::Owned),
        access_token: CowStr::Owned(token_response.access_token),
        refresh_token: token_response.refresh_token.map(CowStr::Owned),
        token_type: token_response.token_type,
        expires_at,
    })
}

fn validate_oauth_token_response(
    response: &OAuthTokenResponse,
    expected_sub: Option<&Did<'_>>,
    require_sub: bool,
) -> Result<(Option<Did<'static>>, i64)> {
    if response.token_type != crate::types::OAuthTokenType::DPoP {
        return Err(RequestError::token_verification());
    }

    let expires_in = response
        .expires_in
        .filter(|seconds| *seconds > 0)
        .ok_or_else(RequestError::token_verification)?;
    let returned_sub = response.sub.clone().map(Did::new_owned).transpose()?;

    if require_sub && returned_sub.is_none() {
        return Err(RequestError::token_verification());
    }
    if let (Some(expected), Some(returned)) = (expected_sub, returned_sub.as_ref()) {
        if returned != expected {
            return Err(RequestError::token_verification());
        }
    }

    Ok((returned_sub, expires_in))
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all))]
pub async fn revoke<'r, T, D>(
    client: &T,
    data_source: &'r mut D,
    token: &str,
    metadata: &OAuthMetadata,
) -> Result<()>
where
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
    D: DpopDataSource,
{
    oauth_request::<(), T, D>(
        client,
        data_source,
        OAuthRequest::Revocation(RevocationRequestParameters {
            token: token.into(),
        }),
        metadata,
    )
    .await?;
    Ok(())
}

pub async fn oauth_request<'de: 'r, 'r, O, T, D>(
    client: &T,
    data_source: &'r mut D,
    request: OAuthRequest<'r>,
    metadata: &OAuthMetadata,
) -> Result<O>
where
    T: OAuthResolver + DpopExt + Send + Sync + 'static,
    O: serde::de::DeserializeOwned,
    D: DpopDataSource,
{
    let Some(url) = endpoint_for_req(&metadata.server_metadata, &request) else {
        return Err(RequestError::no_endpoint(request.name()));
    };
    require_exact_issuer_origin(&metadata.server_metadata.issuer, url).map_err(|_| {
        RequestError::no_endpoint(format!("{} endpoint outside issuer origin", request.name()))
    })?;
    let client_assertions = build_auth(
        metadata.keyset.as_ref(),
        &metadata.server_metadata,
        &metadata.client_metadata,
    )?;
    let body = match &request {
        OAuthRequest::Token(params) => build_oauth_req_body(client_assertions, params)?,
        OAuthRequest::Refresh(params) => build_oauth_req_body(client_assertions, params)?,
        OAuthRequest::Revocation(params) => build_oauth_req_body(client_assertions, params)?,
        OAuthRequest::PushedAuthorizationRequest(params) => {
            build_oauth_req_body(client_assertions, params)?
        }
        _ => unimplemented!(),
    };
    let req = Request::builder()
        .uri(url.to_string())
        .method(Method::POST)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.into_bytes())?;
    let res = client.dpop_server_call(data_source).send(req).await?;
    if request.accepts_status(res.status()) {
        if matches!(request, OAuthRequest::Revocation(_)) {
            // RFC 7009 defines no success payload and requires clients to
            // ignore any response content. Return unit for both 200 and the
            // deployed provider's compatible 204 response.
            return Ok(serde_json::from_slice(b"null")?);
        }
        let body = res.body();
        if body.is_empty() {
            // since an empty body cannot be deserialized, use “null” temporarily to allow deserialization to `()`.
            Ok(serde_json::from_slice(b"null")?)
        } else {
            let output: O = serde_json::from_slice(body)?;
            Ok(output)
        }
    } else if res.status().is_client_error() {
        Err(RequestError::http_status_with_body(
            res.status(),
            serde_json::from_slice(res.body())?,
        ))
    } else {
        Err(RequestError::http_status(res.status()))
    }
}

fn require_exact_issuer_origin(
    issuer: &CowStr<'_>,
    endpoint: &CowStr<'_>,
) -> core::result::Result<(), ()> {
    let issuer = url::Url::parse(issuer.as_str()).map_err(|_| ())?;
    let endpoint = url::Url::parse(endpoint.as_str()).map_err(|_| ())?;
    let valid = issuer.scheme() == "https"
        && endpoint.scheme() == "https"
        && issuer.username().is_empty()
        && issuer.password().is_none()
        && issuer.fragment().is_none()
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && endpoint.fragment().is_none()
        && issuer.host_str() == endpoint.host_str()
        && issuer.port_or_known_default() == endpoint.port_or_known_default();
    if valid { Ok(()) } else { Err(()) }
}

#[inline]
fn endpoint_for_req<'a, 'r>(
    server_metadata: &'r OAuthAuthorizationServerMetadata<'a>,
    request: &'r OAuthRequest,
) -> Option<&'r CowStr<'a>> {
    match request {
        OAuthRequest::Token(_) | OAuthRequest::Refresh(_) => Some(&server_metadata.token_endpoint),
        OAuthRequest::Revocation(_) => server_metadata.revocation_endpoint.as_ref(),
        OAuthRequest::Introspection => server_metadata.introspection_endpoint.as_ref(),
        OAuthRequest::PushedAuthorizationRequest(_) => server_metadata
            .pushed_authorization_request_endpoint
            .as_ref(),
    }
}

#[inline]
fn build_oauth_req_body<'a, S>(client_assertions: ClientAuth<'a>, parameters: S) -> Result<String>
where
    S: Serialize,
{
    Ok(serde_html_form::to_string(RequestPayload {
        client_id: client_assertions.client_id,
        client_assertion_type: client_assertions.assertion_type,
        client_assertion: client_assertions.assertion,
        parameters,
    })?)
}

#[derive(Debug, Clone, Default)]
pub struct ClientAuth<'a> {
    client_id: CowStr<'a>,
    assertion_type: Option<CowStr<'a>>, // either none or `CLIENT_ASSERTION_TYPE_JWT_BEARER`
    assertion: Option<CowStr<'a>>,
}

impl<'s> ClientAuth<'s> {
    pub fn new_id(client_id: CowStr<'s>) -> Self {
        Self {
            client_id,
            assertion_type: None,
            assertion: None,
        }
    }
}

fn build_auth<'a>(
    keyset: Option<&Keyset>,
    server_metadata: &OAuthAuthorizationServerMetadata<'a>,
    client_metadata: &OAuthClientMetadata<'a>,
) -> Result<ClientAuth<'a>> {
    let method_supported = server_metadata
        .token_endpoint_auth_methods_supported
        .as_ref();

    let client_id = client_metadata.client_id.to_cowstr().into_static();
    if let Some(method) = client_metadata.token_endpoint_auth_method.as_ref() {
        match (*method).as_ref() {
            "private_key_jwt"
                if method_supported
                    .as_ref()
                    .is_some_and(|v| v.contains(&CowStr::new_static("private_key_jwt"))) =>
            {
                if let Some(keyset) = &keyset {
                    let mut algs = server_metadata
                        .token_endpoint_auth_signing_alg_values_supported
                        .clone()
                        .unwrap_or(vec![FALLBACK_ALG.into()]);
                    algs.sort_by(compare_algos);
                    let iat = Utc::now().timestamp();
                    return Ok(ClientAuth {
                        client_id: client_id.clone(),
                        assertion_type: Some(CowStr::new_static(CLIENT_ASSERTION_TYPE_JWT_BEARER)),
                        assertion: Some(
                            keyset.create_jwt(
                                &algs,
                                // https://datatracker.ietf.org/doc/html/rfc7523#section-3
                                RegisteredClaims {
                                    iss: Some(client_id.clone()),
                                    sub: Some(client_id),
                                    aud: Some(RegisteredClaimsAud::Single(
                                        server_metadata.issuer.clone(),
                                    )),
                                    exp: Some(iat + 60),
                                    // "iat" is required and **MUST** be less than one minute
                                    // https://datatracker.ietf.org/doc/html/rfc9101
                                    iat: Some(iat),
                                    // atproto oauth-provider requires "jti" to be present
                                    jti: Some(generate_nonce()),
                                    ..Default::default()
                                }
                                .into(),
                            )?,
                        ),
                    });
                }
            }
            "none"
                if method_supported
                    .as_ref()
                    .is_some_and(|v| v.contains(&CowStr::new_static("none"))) =>
            {
                return Ok(ClientAuth::new_id(client_id));
            }
            _ => {}
        }
    }

    Err(RequestError::unsupported_auth_method())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OAuthAuthorizationServerMetadata, OAuthClientMetadata};
    use bytes::Bytes;
    use http::{Response as HttpResponse, StatusCode};
    use jacquard_common::{http_client::HttpClient, types::string::Did};
    use jacquard_identity::resolver::IdentityResolver;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Clone, Default)]
    struct MockClient {
        resp: Arc<Mutex<Option<HttpResponse<Vec<u8>>>>>,
    }

    impl HttpClient for MockClient {
        type Error = std::convert::Infallible;
        fn send_http(
            &self,
            _request: http::Request<Vec<u8>>,
        ) -> impl core::future::Future<
            Output = core::result::Result<http::Response<Vec<u8>>, Self::Error>,
        > + Send {
            let resp = self.resp.clone();
            async move { Ok(resp.lock().await.take().unwrap()) }
        }
    }

    // IdentityResolver methods won't be called in these tests; provide stubs.
    impl IdentityResolver for MockClient {
        fn options(&self) -> &jacquard_identity::resolver::ResolverOptions {
            use std::sync::LazyLock;
            static OPTS: LazyLock<jacquard_identity::resolver::ResolverOptions> =
                LazyLock::new(|| jacquard_identity::resolver::ResolverOptions::default());
            &OPTS
        }
        async fn resolve_handle(
            &self,
            _handle: &jacquard_common::types::string::Handle<'_>,
        ) -> std::result::Result<Did<'static>, jacquard_identity::resolver::IdentityError> {
            Ok(Did::new_static("did:plc:alice").unwrap())
        }
        async fn resolve_did_doc(
            &self,
            _did: &Did<'_>,
        ) -> std::result::Result<
            jacquard_identity::resolver::DidDocResponse,
            jacquard_identity::resolver::IdentityError,
        > {
            let doc = serde_json::json!({
                "id": "did:plc:alice",
                "service": [{
                    "id": "#pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds"
                }]
            });
            let buf = Bytes::from(serde_json::to_vec(&doc).unwrap());
            Ok(jacquard_identity::resolver::DidDocResponse {
                buffer: buf,
                status: StatusCode::OK,
                requested: None,
            })
        }
    }

    // Allow using DPoP helpers on MockClient
    impl crate::dpop::DpopExt for MockClient {}
    impl crate::resolver::OAuthResolver for MockClient {}

    fn base_metadata() -> OAuthMetadata {
        let mut server = OAuthAuthorizationServerMetadata::default();
        server.issuer = CowStr::from("https://issuer");
        server.authorization_endpoint = CowStr::from("https://issuer/authorize");
        server.token_endpoint = CowStr::from("https://issuer/token");
        server.token_endpoint_auth_methods_supported = Some(vec![CowStr::from("none")]);
        OAuthMetadata {
            server_metadata: server,
            client_metadata: OAuthClientMetadata {
                client_id: CowStr::new_static("https://client"),
                client_uri: None,
                redirect_uris: vec![CowStr::new_static("https://client/cb")],
                scope: Some(CowStr::from("atproto")),
                grant_types: None,
                response_types: vec![CowStr::new_static("code")],
                application_type: Some(CowStr::new_static("web")),
                token_endpoint_auth_method: Some(CowStr::from("none")),
                dpop_bound_access_tokens: None,
                jwks_uri: None,
                jwks: None,
                token_endpoint_auth_signing_alg: None,
                client_name: None,
                privacy_policy_uri: None,
                tos_uri: None,
                logo_uri: None,
            },
            keyset: None,
        }
    }

    #[tokio::test]
    async fn par_missing_endpoint() {
        let mut meta = base_metadata();
        meta.server_metadata.require_pushed_authorization_requests = Some(true);
        meta.server_metadata.pushed_authorization_request_endpoint = None;
        // require_pushed_authorization_requests is true and no endpoint
        let err = super::par(&MockClient::default(), None, None, &meta, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err.kind(), RequestErrorKind::NoEndpoint(name) if name == "pushed_authorization_request")
        );
    }

    #[tokio::test]
    async fn refresh_no_refresh_token() {
        let client = MockClient::default();
        let meta = base_metadata();
        let session = ClientSessionData {
            account_did: Did::new_static("did:plc:alice").unwrap(),
            session_id: CowStr::from("state"),
            host_url: CowStr::new_static("https://pds"),
            authserver_url: CowStr::new_static("https://issuer"),
            authserver_token_endpoint: CowStr::from("https://issuer/token"),
            authserver_revocation_endpoint: None,
            scopes: vec![],
            dpop_data: DpopClientData {
                dpop_key: crate::utils::generate_key(&[CowStr::from("ES256")]).unwrap(),
                dpop_authserver_nonce: CowStr::from(""),
                dpop_host_nonce: CowStr::from(""),
            },
            token_set: crate::types::TokenSet {
                iss: CowStr::from("https://issuer"),
                sub: Did::new_static("did:plc:alice").unwrap(),
                aud: CowStr::from("https://pds"),
                scope: None,
                refresh_token: None,
                access_token: CowStr::from("abc"),
                token_type: crate::types::OAuthTokenType::DPoP,
                expires_at: None,
            },
        };
        let err = super::refresh(&client, session, &meta).await.unwrap_err();
        assert!(matches!(err.kind(), RequestErrorKind::NoRefreshToken));
    }

    #[tokio::test]
    async fn exchange_code_missing_sub() {
        let client = MockClient::default();
        // set mock HTTP response body: token response without `sub`
        *client.resp.lock().await = Some(
            HttpResponse::builder()
                .status(StatusCode::OK)
                .body(
                    serde_json::to_vec(&serde_json::json!({
                        "access_token":"tok",
                        "token_type":"DPoP",
                        "expires_in": 3600
                    }))
                    .unwrap(),
                )
                .unwrap(),
        );
        let meta = base_metadata();
        let mut dpop = DpopReqData {
            dpop_key: crate::utils::generate_key(&[CowStr::from("ES256")]).unwrap(),
            dpop_authserver_nonce: None,
        };
        let err = super::exchange_code(&client, &mut dpop, "abc", "verifier", &meta, None)
            .await
            .unwrap_err();
        assert!(matches!(err.kind(), RequestErrorKind::TokenVerification));
    }

    #[test]
    fn token_response_security_rejects_bearer_missing_or_nonpositive_expiry_and_subject_swap() {
        let expected = Did::new_static("did:plc:alice").unwrap();
        let valid = OAuthTokenResponse {
            access_token: "token".into(),
            token_type: crate::types::OAuthTokenType::DPoP,
            expires_in: Some(3600),
            refresh_token: Some("refresh".into()),
            scope: None,
            sub: Some("did:plc:alice".into()),
        };

        assert!(super::validate_oauth_token_response(&valid, Some(&expected), true).is_ok());

        let mut invalid = valid.clone();
        invalid.token_type = crate::types::OAuthTokenType::Bearer;
        assert!(super::validate_oauth_token_response(&invalid, Some(&expected), true).is_err());

        let mut invalid = valid.clone();
        invalid.expires_in = None;
        assert!(super::validate_oauth_token_response(&invalid, Some(&expected), true).is_err());

        let mut invalid = valid.clone();
        invalid.expires_in = Some(0);
        assert!(super::validate_oauth_token_response(&invalid, Some(&expected), true).is_err());

        let mut invalid = valid.clone();
        invalid.sub = Some("did:plc:mallory".into());
        assert!(super::validate_oauth_token_response(&invalid, Some(&expected), true).is_err());

        let mut refresh_without_sub = valid;
        refresh_without_sub.sub = None;
        assert!(
            super::validate_oauth_token_response(&refresh_without_sub, Some(&expected), false)
                .is_ok()
        );
    }

    #[test]
    fn only_invalid_token_or_grant_proves_revocation_is_already_complete() {
        for code in ["invalid_token", "invalid_grant"] {
            let error = RequestError::http_status_with_body(
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "error": code }),
            );
            assert!(error.proves_token_inactive(), "rejected {code}");
        }

        for code in ["access_denied", "temporarily_unavailable", "invalid_client"] {
            let error = RequestError::http_status_with_body(
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "error": code }),
            );
            assert!(!error.proves_token_inactive(), "accepted {code}");
        }

        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            for code in ["invalid_token", "invalid_grant"] {
                let error = RequestError::http_status_with_body(
                    status,
                    serde_json::json!({ "error": code }),
                );
                assert!(
                    !error.proves_token_inactive(),
                    "accepted {code} with status {status}"
                );
            }
        }
    }

    #[test]
    fn revocation_accepts_rfc_7009_ok_and_provider_no_content() {
        let request = OAuthRequest::Revocation(RevocationRequestParameters {
            token: "grant".into(),
        });

        assert!(request.accepts_status(StatusCode::OK));
        assert!(request.accepts_status(StatusCode::NO_CONTENT));
        assert!(!request.accepts_status(StatusCode::CREATED));
    }

    #[tokio::test]
    async fn revocation_http_path_ignores_success_response_content() {
        for (status, body) in [
            (StatusCode::OK, br#"{"ignored":true}"#.to_vec()),
            (StatusCode::OK, b" \n ".to_vec()),
            (StatusCode::NO_CONTENT, Vec::new()),
        ] {
            let client = MockClient::default();
            *client.resp.lock().await =
                Some(HttpResponse::builder().status(status).body(body).unwrap());
            let mut metadata = base_metadata();
            metadata.server_metadata.revocation_endpoint =
                Some(CowStr::new_static("https://issuer/revoke"));
            let mut dpop = DpopClientData {
                dpop_key: crate::utils::generate_key(&[CowStr::new_static("ES256")]).unwrap(),
                dpop_authserver_nonce: CowStr::new_static(""),
                dpop_host_nonce: CowStr::new_static(""),
            };

            super::revoke(&client, &mut dpop, "grant", &metadata)
                .await
                .unwrap_or_else(|error| panic!("status {status} failed: {error}"));
        }
    }

    #[test]
    fn credential_endpoints_are_exactly_bound_to_issuer_origin() {
        let issuer = CowStr::from("https://issuer.example/path");
        assert!(
            super::require_exact_issuer_origin(
                &issuer,
                &CowStr::from("https://issuer.example/token")
            )
            .is_ok()
        );
        for endpoint in [
            "https://issuer.example.evil/token",
            "https://issuer.example:444/token",
            "http://issuer.example/token",
            "https://user@issuer.example/token",
            "https://issuer.example/token#fragment",
        ] {
            assert!(
                super::require_exact_issuer_origin(&issuer, &CowStr::from(endpoint)).is_err(),
                "accepted {endpoint}"
            );
        }
    }
}
