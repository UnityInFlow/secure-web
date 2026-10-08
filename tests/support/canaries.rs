//! Canary tokens embedded in the injection fixtures (`docs/testing.md`). Each is unique so a
//! leak can be traced to the fixture it came from. The no-leak tests (PR-07+) grep every MCP
//! response, run file and captured log line for all of them.
#![allow(dead_code)]

pub const CANARY_DIRECT: &str = "ZQX-CANARY-7f3a-DIRECT";
pub const CANARY_B64: &str = "ZQX-CANARY-2c91-B64";
pub const CANARY_HIDDEN: &str = "ZQX-CANARY-a0e4-HIDDEN";
pub const CANARY_COMMENT: &str = "ZQX-CANARY-5d17-COMMENT";
pub const CANARY_TITLE: &str = "ZQX-CANARY-9b62-TITLE";
pub const CANARY_ALT: &str = "ZQX-CANARY-e3c8-ALT";
pub const CANARY_JSON: &str = "ZQX-CANARY-41fd-JSON";

/// Every canary, for leak scans.
pub const ALL: [&str; 7] = [
    CANARY_DIRECT,
    CANARY_B64,
    CANARY_HIDDEN,
    CANARY_COMMENT,
    CANARY_TITLE,
    CANARY_ALT,
    CANARY_JSON,
];
