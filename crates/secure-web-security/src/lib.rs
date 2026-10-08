//! SSRF guard, injection-scanner subprocess adapter, policy engine and the `accept()`
//! trust-state step.
//!
//! - [`ssrf`] — URL guard (PR-02, ADR-010).
//! - [`injection`] — `injection-scanner` subprocess adapter; every failure is a `ScanError`
//!   (ADR-003, ADR-008, ADR-014).
//! - [`policy`] — severity → `Safe`/`Warn`/`Block`; scan errors always block.
//! - [`decision`] — `scan_and_accept` / `accept`: `ScannedDocument` →
//!   `AcceptedDocument | BlockedDocument` (ADR-005).
#![forbid(unsafe_code)]

pub mod decision;
pub mod injection;
pub mod policy;
pub mod ssrf;
