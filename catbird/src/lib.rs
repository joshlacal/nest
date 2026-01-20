//! Catbird Nest Library
//!
//! This module exposes the core components of the Catbird Gateway for use in tests
//! and other contexts.

pub mod config;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod services;

pub use config::{AppConfig, AppState};
pub use error::{AppError, AppResult};
pub use models::*;