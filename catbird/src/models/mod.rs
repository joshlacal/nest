//! Models module
//!
//! Data structures and types used throughout the application.

mod types;
mod oauth_upgrade;
pub mod circle;

pub use circle::{
    calculate_operation_key, CircleError, CircleProjectionKind, CircleProjectionOperation,
    CircleProjectionState,
};
pub use oauth_upgrade::{
    require_circle_scopes, CIRCLE_MEMBER_SCOPE, CIRCLE_OWNER_SCOPE, CIRCLE_PROTOCOL_REVISION,
};

pub use types::*;
