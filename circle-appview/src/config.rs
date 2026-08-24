use std::env;
use std::sync::Arc;
use sqlx::PgPool;
use crate::auth::DidResolver;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub service_did: String,
    pub plc_directory_url: String,
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
        let plc_directory_url = env::var("PLC_DIRECTORY_URL")
            .unwrap_or_else(|_| "https://plc.directory".to_string());

        Ok(Self {
            host,
            port,
            database_url,
            service_did,
            plc_directory_url,
        })
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub http_client: reqwest::Client,
    pub did_resolver: Arc<DidResolver>,
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

        Self {
            config,
            db,
            http_client,
            did_resolver,
        }
    }
}
