pub mod access;
pub mod auth;
pub mod commit;
pub mod config;
pub mod db;
pub mod error;
pub mod projections;
pub mod routes;
pub mod space_client;
pub mod sync;
pub mod validator;
pub use auth::{
    authenticate, AuthenticatedUser, DidDocument, DidResolver, PublicKeyJwk, VerificationMethod,
};
pub use config::{AppState, Config};
pub use error::AppError;
pub use routes::create_router;
