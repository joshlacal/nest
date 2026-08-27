//! Models module
//!
//! Data structures and types used throughout the application.

pub mod oauth_upgrade;
mod types;

pub use oauth_upgrade::{ALLOWLISTED_UPGRADE_SCOPES, FIXED_UPGRADE_CALLBACK_URL};
pub use types::*;
