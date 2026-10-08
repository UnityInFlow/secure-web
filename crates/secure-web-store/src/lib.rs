//! Corpus store, manifest v1 and (PR-09) lexical find over accepted documents.
//!
//! - [`corpus`]: [`FsCorpusStore`] / [`RunWriter`] write `<workspace>/runs/<runId>/` exactly as
//!   `docs/contracts/manifest-schema.md` says (ADR-015).
//! - [`manifest`]: the manifest v1 types, [`Manifest::load`] and
//!   [`Manifest::accepted_documents`].
#![forbid(unsafe_code)]

pub mod corpus;
pub mod error;
mod fsx;
pub mod manifest;
pub mod workspace;

pub use corpus::{
    CorpusStore, DocumentSizes, FsCorpusStore, RawContent, RunSpec, RunWriter, StoreContext,
    StoreFuture, StoreOptions, CHECKPOINT_EVERY,
};
pub use error::StoreError;
pub use manifest::{
    BlockedEntry, DocumentEntry, FailedEntry, Manifest, ManifestPolicy, RunKind, RunStats,
    RunStatus, Versions,
};
