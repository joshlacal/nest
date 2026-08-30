//! Catbird Nest Library
//!
//! This module exposes the core components of the Catbird Gateway for use in tests
//! and other contexts.

#![allow(
    clippy::too_many_arguments,
    clippy::doc_markdown,
    clippy::needless_borrow,
    clippy::useless_conversion,
    clippy::needless_question_mark,
    clippy::useless_vec,
    clippy::derivable_impls,
    clippy::collapsible_if,
    clippy::match_like_matches_macro,
    clippy::unnecessary_sort_by,
    clippy::unnecessary_to_owned,
    clippy::io_other_error,
    clippy::needless_borrows_for_generic_args,
    clippy::useless_borrows_in_formatting,
    clippy::identity_op,
    clippy::unnecessary_cast,
    clippy::question_mark,
    clippy::doc_lazy_continuation,
    clippy::collapsible_match
)]
pub mod config;
pub mod error;
pub mod handlers;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod services;

pub use config::{AppConfig, AppState};
pub use error::{AppError, AppResult};
pub use models::*;
