//! Store errors. Messages carry kinds, ids and fixed strings only — never paths derived from page
//! content, never page text, never serde messages (which can quote input).

use std::io;

use secure_web_core::ids::DocumentId;

/// Errors from the corpus store and manifest loading.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A filesystem operation failed.
    #[error("filesystem error during {op}: {kind}")]
    Io {
        /// What the store was doing.
        op: &'static str,
        /// The OS error kind.
        kind: io::ErrorKind,
    },
    /// A path component the store must write through is a symbolic link.
    #[error("refusing to write through a symbolic link")]
    SymlinkRefused,
    /// A computed path is not a plain, bounded name inside the run directory.
    #[error("computed path is not a safe location inside the run directory")]
    UnsafePath,
    /// The run directory already exists; runs are never reopened or overwritten.
    #[error("run directory already exists")]
    RunExists,
    /// The workspace path cannot be used.
    #[error("workspace path is invalid: {0}")]
    Workspace(&'static str),
    /// The private-audit root is equal to, inside, or an ancestor of the agent-visible `runs/`
    /// directory (compared after resolving symbolic links).
    #[error("private-audit root must be outside the runs directory")]
    AuditInsideRuns,
    /// The document id was not issued by this run's writer, or was already recorded.
    #[error("document id {0} was not issued by this run or was already recorded")]
    UnknownDocumentId(DocumentId),
    /// Every six-digit sequence number of this run was used.
    #[error("document sequence exhausted")]
    SequenceExhausted,
    /// A `web_open` run holds exactly one entry.
    #[error("an OPEN run holds exactly one entry")]
    OpenRunFull,
    /// The document breaks a store precondition (see the message); nothing was written.
    #[error("document rejected by the store: {0}")]
    InvalidDocument(&'static str),
    /// `finish` was called with a non-terminal status.
    #[error("a run can only finish with a terminal status")]
    InvalidStatus,
    /// The writer already finished.
    #[error("run already finished")]
    Finished,
    /// Serializing a store file failed.
    #[error("serialization failed")]
    Serialize,
    /// A manifest read from disk is not a valid manifest v1.
    #[error("manifest is invalid: {0}")]
    InvalidManifest(&'static str),
    /// The blocking store task panicked or was cancelled.
    #[error("store task failed")]
    Task,
}

impl StoreError {
    /// Wrap an I/O error, keeping only its kind.
    pub(crate) fn io(op: &'static str, err: &io::Error) -> Self {
        StoreError::Io {
            op,
            kind: err.kind(),
        }
    }
}
