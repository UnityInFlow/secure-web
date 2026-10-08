# PR-05 — injection-scanner adapter + policy engine, fail-closed, no-leak (SW-005, SW-006)

Read first: `docs/security-policy.md` §4–6; `docs/threat-model.md` T1/T2/T11/T12; ADR-003, ADR-005;
deep-dive §20–23, §48–49.

## Goal
`secure-web-security::injection::SubprocessScanner` (implements `SecurityScanner`) and
`secure-web-security::policy::PolicyEngine` (implements `SecurityPolicy`) plus the type-level
`accept()` step producing `AcceptedDocument | BlockedDocument`. Stub scanner binary for tests.

## Design
- Real `injection-scanner 0.1.0` output is already pinned — do not re-derive the shape from
  `--help`; use `tests/contracts/scanner_output.json` (built PR-00) and `docs/security-policy.md`
  §4 as the source of truth. The fixture-based contract test runs unconditionally (it needs no
  binary); only the live-binary test stays `#[ignore]` behind `INJECTION_SCANNER_BIN`.
- `SubprocessScanner::new(cfg)`: at construction run `<exe> --version` (timeout 2 s) and cache
  `scanner_version` (format `injection-scanner X.Y.Z`); failure → construction succeeds but every
  scan returns `ScanError::Unavailable` (fail closed) and a `warn!` is logged once.
- `scan()`: `tokio::process::Command`, `kill_on_drop(true)`, write stdin then close, read stdout with
  a 1 MB cap, `timeout(cfg.timeout)`. Parse stdout as a top-level JSON **array**; require exactly one
  element with `file == "<stdin>"`, else `ScanError::InvalidOutput`. That element deserializes into
  `ScannerOutput { file, matches: Vec<RawFinding>, suppressed: Vec<serde_json::Value>,
  low_confidence: Vec<RawFinding>, baselined: Vec<serde_json::Value>, critical_count, high_count,
  medium_count, low_count }` using a `RawFinding` serde struct with fields `pattern_id` (→
  `Finding.id`), `pattern_name` (→ `Finding.detector`), `severity`, `line`, `confidence` — and
  **no** field for `message`/`remediation`/`file`/`matched_text`/`context`, so serde drops them on
  deserialize (unknown fields ignored). `suppressed`/`baselined` are parsed but never read by
  policy; `low_confidence` feeds only a `low_confidence_count` on `SecurityFindings`, never a
  decision. Convert to `SecurityFindings { scanner_version, findings:
  Vec<Finding { id, severity, detector, line, confidence }>, low_confidence_count, max_severity,
  scan_duration }`, with `max_severity` recomputed from `matches` (not trusted from the scanner's
  `*_count` fields).
- All failure modes → `ScanError::{NotFound, Spawn, Timeout, Crashed{code}, InvalidOutput, OutputTooLarge}`.
  Exit `0`/`1` are both success codes *only* when stdout parses per the shape above; exit `1` with
  unparseable stdout is `InvalidOutput`, not treated as "findings".
- `PolicyEngine::decide(&SecurityFindings) -> PolicyOutcome::{Safe, Warn, Block(BlockReason)}` from
  config mapping; `decide_error(&ScanError) -> Block(ScannerFailure)`.
- `accept(scanned: ScannedDocument, policy: &dyn SecurityPolicy, doc_id) -> Result<AcceptedDocument, BlockedDocument>`
  in `secure-web-security::decision`. Build `AcceptedDocument.markdown` from `display` only.
  `BlockedDocument` gets ids/enums only.
- `tools/stub-scanner`: implement `STUB_SCANNER_MODE` behaviours from `docs/testing.md`.

## Tests
- `tests/contracts/scanner_output_contract.rs` (**not** `#[ignore]`): loads
  `tests/contracts/scanner_output.json` (pinned in PR-00) and, for each case, feeds the fixed
  `stdout` through the real parser and asserts the resulting `ScannerOutput`/`SecurityFindings`.
  This is the parse test that proves `matched_text` (and `context`/`message`/`remediation`/`file`)
  are dropped: assert the parsed struct has no field that could hold them, and that
  `serde_json::to_value(&findings)` never contains the fixture's `matched_text` string. Also
  asserts the `pi018-false-positive` case parses to `Block(PromptInjection)` at the policy layer
  (documented, not silently swallowed) even though it is a known false positive — see
  `docs/security-policy.md` §10.
- `tests/security/scanner_fail_closed.rs`: each stub mode (`crash`, `timeout`, `garbage`, `partial`,
  `huge`, `unexpected-exit`) and a nonexistent executable → `Block(ScannerFailure)`; timeout test
  asserts the child is killed (no zombie; check `wait` returns within 1 s after timeout).
  `unexpected-exit` (valid JSON, exit 2 — see `docs/testing.md`) is the one mode that proves the
  fail-closed rule doesn't secretly depend on stdout being unparseable.
- `tests/security/injection_direct.rs`, `injection_encoded.rs`, `injection_hidden.rs`,
  `metadata_title.rs`: stub in `canary` mode; each `/injection/*` fixture → `Block(PromptInjection)`
  with `findingIds == ["PI001"]`; `MILD` fixture → `Safe` with LOW finding recorded; a MEDIUM
  fixture (add `STUB` support) → `Warn`.
- `tests/security/no_leak_canary.rs`: serialize `BlockedDocument`, `SecuritySummary`, `PolicyOutcome`
  and a `Debug` print of each; assert no canary and no `security_text` substring. Also assert via a
  compile-time check (`static_assertions` or a unit test over `serde_json::to_value` keys) that
  `BlockedDocument` JSON has exactly the allowed keys.
- Policy unit tests: every severity × config action combination; config `failurePolicy: allow` is
  rejected at config level (already in PR-01) — add a test that `PolicyEngine::new` refuses it too.
- Real-scanner tests behind `INJECTION_SCANNER_BIN` (`#[ignore]`).

## Done when
- [ ] ScanError → Block in every branch; no path returns Safe on error
- [ ] `RawFinding` has only `pattern_id`, `pattern_name`, `severity`, `line`, `confidence` — no
      text-bearing fields (`message`/`remediation`/`file`/`matched_text`/`context`); the pinned
      fixture contract test proves `matched_text` is dropped
- [ ] stub scanner binary builds in workspace and is used by tests
- [ ] ADR-003 and ADR-005 referenced in code comments at `accept()` and `decide_error()`
- [ ] fmt/clippy/test green; coverage job enabled in CI (≥ 85 %)
