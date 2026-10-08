//! Identifier newtypes.
//!
//! Formats (contract):
//! - [`CrawlId`]: `crawl_<12 lowercase hex>` — random
//! - [`RunId`]: a run directory name, either a crawl id or `open_<12 lowercase hex>` for `web_open`
//! - [`DocumentId`]: `doc_<6 digits>` — the 1-based sequence number of a page within its run
//!
//! Ids become path segments (`runs/<runId>/`) and arrive as MCP input, so [`parse`](CrawlId::parse)
//! accepts exactly the documented shape and nothing else (no traversal, no whitespace, no
//! non-ASCII digits). Deserialization goes through the same parser.

use std::fmt;

use serde::{Deserialize, Serialize};

const CRAWL_PREFIX: &str = "crawl_";
const OPEN_PREFIX: &str = "open_";
const DOC_PREFIX: &str = "doc_";
/// Random bytes per generated id; hex-encoded to 12 characters.
const RANDOM_BYTES: usize = 6;
const RANDOM_HEX_LEN: usize = RANDOM_BYTES * 2;
const DOC_DIGITS: usize = 6;
/// Largest sequence number representable in six digits.
pub const MAX_DOCUMENT_SEQ: u32 = 999_999;

/// Errors creating or parsing an id.
#[derive(Debug, thiserror::Error)]
pub enum IdError {
    /// The operating system random source failed.
    #[error("random source unavailable: {0}")]
    Random(String),
    /// The string does not match the id format.
    #[error("malformed {kind} id")]
    Malformed {
        /// Which id type was being parsed.
        kind: &'static str,
    },
    /// Document sequence numbers are `1..=999_999`.
    #[error("document sequence {0} is outside 1..=999999")]
    SequenceOutOfRange(u32),
}

fn random_hex() -> Result<String, IdError> {
    let mut bytes = [0u8; RANDOM_BYTES];
    getrandom::fill(&mut bytes).map_err(|err| IdError::Random(err.to_string()))?;
    Ok(hex::encode(bytes))
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `true` when `s` is `prefix` followed by exactly 12 lowercase hex characters.
fn is_prefixed_hex(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|rest| rest.len() == RANDOM_HEX_LEN && is_lower_hex(rest))
}

macro_rules! string_id_impls {
    ($ty:ident) => {
        impl $ty {
            /// The id as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $ty {
            type Error = IdError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(&value)
            }
        }

        impl From<$ty> for String {
            fn from(value: $ty) -> Self {
                value.0
            }
        }
    };
}

/// Identifier of one crawl run: `crawl_<12 lowercase hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CrawlId(String);

impl CrawlId {
    /// Generate a fresh random crawl id.
    pub fn generate() -> Result<Self, IdError> {
        Ok(Self(format!("{CRAWL_PREFIX}{}", random_hex()?)))
    }

    /// Parse a crawl id, rejecting anything that is not exactly `crawl_<12 lowercase hex>`.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        if is_prefixed_hex(s, CRAWL_PREFIX) {
            Ok(Self(s.to_owned()))
        } else {
            Err(IdError::Malformed { kind: "crawl" })
        }
    }
}

string_id_impls!(CrawlId);

/// Identifier of a run directory under `<workspace>/runs/`: a [`CrawlId`] or `open_<12 hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RunId(String);

impl RunId {
    /// Generate a fresh random run id for a `web_open` run: `open_<12 lowercase hex>`.
    pub fn generate_open() -> Result<Self, IdError> {
        Ok(Self(format!("{OPEN_PREFIX}{}", random_hex()?)))
    }

    /// Parse a run id (`crawl_<12 hex>` or `open_<12 hex>`).
    pub fn parse(s: &str) -> Result<Self, IdError> {
        if is_prefixed_hex(s, CRAWL_PREFIX) || is_prefixed_hex(s, OPEN_PREFIX) {
            Ok(Self(s.to_owned()))
        } else {
            Err(IdError::Malformed { kind: "run" })
        }
    }

    /// `true` for a `web_open` run.
    pub fn is_open(&self) -> bool {
        self.0.starts_with(OPEN_PREFIX)
    }
}

impl From<CrawlId> for RunId {
    fn from(value: CrawlId) -> Self {
        Self(value.0)
    }
}

string_id_impls!(RunId);

/// Identifier of a document within a run: `doc_<6 digits>`, its 1-based sequence number.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DocumentId(String);

impl DocumentId {
    /// Build the id for sequence number `seq` (`1..=999_999`).
    pub fn from_seq(seq: u32) -> Result<Self, IdError> {
        if seq == 0 || seq > MAX_DOCUMENT_SEQ {
            return Err(IdError::SequenceOutOfRange(seq));
        }
        Ok(Self(format!(
            "{DOC_PREFIX}{seq:0width$}",
            width = DOC_DIGITS
        )))
    }

    /// Parse a document id, rejecting anything that is not exactly `doc_<6 ASCII digits>` with a
    /// non-zero sequence.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        let malformed = IdError::Malformed { kind: "document" };
        let digits = match s.strip_prefix(DOC_PREFIX) {
            Some(rest) if rest.len() == DOC_DIGITS && rest.bytes().all(|b| b.is_ascii_digit()) => {
                rest
            }
            _ => return Err(malformed),
        };
        match digits.parse::<u32>() {
            Ok(seq) if seq > 0 => Ok(Self(s.to_owned())),
            _ => Err(malformed),
        }
    }

    /// The 1-based sequence number encoded in the id.
    pub fn seq(&self) -> u32 {
        // The constructor and parser guarantee six ASCII digits after the prefix.
        self.0
            .get(DOC_PREFIX.len()..)
            .and_then(|digits| digits.parse().ok())
            .unwrap_or(0)
    }
}

string_id_impls!(DocumentId);
