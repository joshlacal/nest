pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod routes;

pub use auth::{
    authenticate, AuthenticatedUser, DidDocument, DidResolver, PublicKeyJwk, VerificationMethod,
};
pub use config::{AppState, Config};
pub use error::AppError;
pub use routes::create_router;
