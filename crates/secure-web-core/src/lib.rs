//! Shared foundation for Secure Web: configuration, contract error codes, ids, model enums and the
//! trust-state types every pipeline stage speaks.
#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod ids;
pub mod model;
pub mod network;

/// Secure Web version stamped into every document's provenance (`secureWebVersion`).
pub const SECURE_WEB_VERSION: &str = env!("CARGO_PKG_VERSION");
