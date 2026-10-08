# ADR-003 — Scanner failure is fail-closed

Status: Accepted (2026-09-24)

## Context
The injection scanner runs as an external process that can crash, hang, be missing, or emit invalid output. Treating any of those as "no findings" would silently disable the core control.

## Decision
Any scanner error (not found, spawn failure, timeout, crash, invalid/partial/oversized JSON) produces `Block(ScannerFailure)`. No configuration value can change this in v0.1; `security.scanner.failurePolicy` accepts only `block`.

## Consequences
+ the control cannot be bypassed by breaking the scanner.
- an outage of the scanner makes Secure Web unusable rather than unsafe; monitor `secure_web_scanner_failures_total`.
