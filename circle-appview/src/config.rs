use crate::access::CredentialStore;
use crate::auth::DidResolver;
use crate::space_client::SpaceClient;
use sqlx::PgPool;
use std::env;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub service_did: String,
    pub plc_directory_url: String,
    pub public_appview_url: String,
    pub circle_media_base_url: String,
    pub nest_client_id: String,
    pub nest_jwks_url: String,
    pub nest_verifying_keys: Vec<crate::auth::ParsedVerifyingKey>,
}

impl Config {
    pub fn from_env() -> Result<Self, anyhow::Error> {
        let host = env::var("CIRCLE_APPVIEW_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("CIRCLE_APPVIEW_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3002);
        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string());
        let service_did = env::var("SERVICE_DID")
            .unwrap_or_else(|_| "did:web:circles.catbird.blue#atproto_circle".to_string());
        let plc_directory_url =
            env::var("PLC_DIRECTORY_URL").unwrap_or_else(|_| "https://plc.directory".to_string());
        let public_appview_url =
            env::var("PUBLIC_APPVIEW_URL").unwrap_or_else(|_| "https://public.api.bsky.app".to_string());
        let circle_media_base_url = env::var("CIRCLE_MEDIA_BASE_URL")
            .map_err(|_| anyhow::anyhow!("CIRCLE_MEDIA_BASE_URL environment variable is required"))?;
        let nest_client_id = env::var("NEST_CLIENT_ID")
            .map_err(|_| anyhow::anyhow!("NEST_CLIENT_ID environment variable is required"))?;
        let nest_jwks_url = env::var("NEST_JWKS_URL")
            .map_err(|_| anyhow::anyhow!("NEST_JWKS_URL environment variable is required"))?;
        Ok(Self {
            host,
            port,
            database_url,
            service_did,
            plc_directory_url,
            public_appview_url,
            circle_media_base_url,
            nest_client_id,
            nest_jwks_url,
            nest_verifying_keys: Vec::new(),
        })
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub http_client: reqwest::Client,
    pub did_resolver: Arc<DidResolver>,
    pub credential_store: Arc<CredentialStore>,
    pub space_client: Arc<SpaceClient>,
    pub space_locks: Arc<crate::access::SpaceLockManager>,
    pub profile_hydrator: Arc<crate::hydration::ProfileHydrator>,
}
impl AppState {
    pub fn new(config: Config, db: PgPool) -> Self {
        let config = Arc::new(config);
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        let did_resolver = Arc::new(DidResolver::new(
            config.plc_directory_url.clone(),
            http_client.clone(),
        ));
        let credential_store = Arc::new(CredentialStore::new());
        let space_client = Arc::new(SpaceClient::new());
        let space_locks = Arc::new(crate::access::SpaceLockManager::new());
        let profile_hydrator = Arc::new(crate::hydration::ProfileHydrator::new(
            config.public_appview_url.clone(),
            http_client.clone(),
        ));

        Self {
            config,
            db,
            http_client,
            did_resolver,
            credential_store,
            space_client,
            space_locks,
            profile_hydrator,
        }
    }
    pub fn with_did_resolver(config: Config, db: PgPool, did_resolver: Arc<DidResolver>) -> Self {
        let config = Arc::new(config);
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        let credential_store = Arc::new(CredentialStore::new());
        let space_client = Arc::new(SpaceClient::new());
        let space_locks = Arc::new(crate::access::SpaceLockManager::new());
        let profile_hydrator = Arc::new(crate::hydration::ProfileHydrator::new(
            config.public_appview_url.clone(),
            http_client.clone(),
        ));

        Self {
            config,
            db,
            http_client,
            did_resolver,
            credential_store,
            space_client,
            space_locks,
            profile_hydrator,
        }
    }

    pub fn with_services(
        config: Config,
        db: PgPool,
        did_resolver: Arc<DidResolver>,
        credential_store: Arc<CredentialStore>,
        space_client: Arc<SpaceClient>,
        space_locks: Arc<crate::access::SpaceLockManager>,
    ) -> Self {
        let config = Arc::new(config);
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        let profile_hydrator = Arc::new(crate::hydration::ProfileHydrator::new(
            config.public_appview_url.clone(),
            http_client.clone(),
        ));

        Self {
            config,
            db,
            http_client,
            did_resolver,
            credential_store,
            space_client,
            space_locks,
            profile_hydrator,
        }
    }

    pub fn with_profile_hydrator(
        config: Config,
        db: PgPool,
        did_resolver: Arc<DidResolver>,
        profile_hydrator: Arc<crate::hydration::ProfileHydrator>,
    ) -> Self {
        let config = Arc::new(config);
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        let credential_store = Arc::new(CredentialStore::new());
        let space_client = Arc::new(SpaceClient::new());
        let space_locks = Arc::new(crate::access::SpaceLockManager::new());

        Self {
            config,
            db,
            http_client,
            did_resolver,
            credential_store,
            space_client,
            space_locks,
            profile_hydrator,
        }
    }
}
