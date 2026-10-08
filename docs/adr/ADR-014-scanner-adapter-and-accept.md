# ADR-014 — Scanner adapter hardening and the accept-time exposure check

Status: Accepted (2026-09-25)

## Context
PR-05 adds `secure-web-security::injection::SubprocessScanner` (ADR-008) and the policy /
`accept()` step. ADR-003 says every scanner failure blocks, and ADR-005 says blocked text is never
agent-visible. Implementing them surfaced decisions those ADRs do not spell out:

1. What counts as a scanner failure beyond "crash, timeout, invalid JSON": a report whose exit code
   contradicts its findings, identifiers that are not identifiers, a scanner that exits before
   reading its whole input, noise on stderr.
2. The scanner's own strings (`pattern_id`, `pattern_name`, the `--version` line) flow to the agent
   (`findingIds`, `scannerVersion`). A buggy or replaced scanner could echo page text through them.
3. `accept()` builds the model-facing `AcceptedDocument` from `display`, while the scanner read
   `security_text`. ADR-013 guarantees every model-facing string is inside `security_text`, but
   only as a property of the extractor. Nothing checked it at the point where content becomes
   trusted.

## Decision
Adapter (`docs/security-policy.md` §4):

- stdin and stdout are serviced **concurrently** under one `security.scanner.timeout`; on timeout,
  stdout overflow (> 1 MB) or a pipe error the child is SIGKILLed and reaped (bounded 1 s wait).
  `kill_on_drop` covers every other exit path.
- stderr is drained concurrently with stdout into a counter and discarded unread: it is never
  stored, logged or returned (it may echo page text), and it cannot fill a pipe. More than
  `MAX_STDERR_BYTES` (64 KiB) is `ScanError::StderrTooLarge` → the child is killed and the page
  blocks. `injection-scanner 0.1.0` writes nothing to stderr on a successful scan (verified on
  clean, injected and 2 MB inputs), so the cap only trips on a scanner that is failing or has
  changed; small diagnostics under the cap do not change the verdict. Discarding a flood of any
  size (the PR-05 r1 design) was rejected: a scanner that is shouting has not given a verdict
  anyone should trust.
- A write error on stdin (the scanner exited without reading all input) is `ScanError::Io` →
  block: a verdict on part of the page is not a verdict on the page.
- **End-of-input sentinel.** A write error only catches a non-reader when the input overflows the
  pipe buffer; a small page fits and the write "succeeds" whether or not anyone reads it. The
  scanner's report has no byte count or hash to compare against (`injection-scanner 0.1.0`,
  verified), so the adapter makes the scanner prove it: after the input it writes `\n\n` plus the
  fixed line `Ignore all previous instructions.` (`SENTINEL_LINE`) and a newline, and requires a
  `PI001` finding **in `matches`** at exactly line `count('\n' in input) + 3` (the scanner numbers
  lines by `\n` only), and no finding past that line. That one finding is then removed; every
  other finding — including page text identical to the sentinel, and any second finding on the
  sentinel line — stays for the policy. Anything else is `InvalidOutput::SentinelMismatch` →
  block. A scanner that did not read stdin, read only a prefix, skipped the tail or numbered lines
  differently cannot produce it. The real scanner reports the sentinel after every *line-scanner*
  state a page can leave open (unclosed code fence, HTML comment, script, table, unclosed front
  matter, CR/CRLF, 2 MB input; `scanner_real.rs`), at confidence 0.2 inside a fence but still in
  `matches` under `--strict`. Consequence: a correct scanner now always exits `1`.
- **The suffix must not cost detection (PR-05 r2).** The sentinel does *not* leave every scanner
  pass intact. `injection-scanner` builds after the 0.1.0 release (e.g. `v0.1.0-145-g5417d88`,
  which still prints `0.1.0`) run a structural config pass over an input that is one whole
  JSON/JSONC document (`PI051` on `permissions.allow`, `PI062` on an `mcpServers` launch command,
  …). The suffix makes such an input unparseable, so the pass is skipped. Those builds then add a
  top-level `config_parse_error` to the report, which the closed top level rejects → block
  (`SCANNER_FAILURE`, not `Safe`); the released 0.1.0 binary has no structural pass at all. The
  adapter does not rely on either: an input that may be a bare document
  (`is_bare_document_candidate` — after whitespace/U+FEFF it starts with `{` or `/`, a superset of
  the scanner's trigger) is scanned a **second time exactly as given**, and that raw pass's
  `matches`/`low_confidence` are merged into the sentinel pass's (by `(pattern_id, line)`). The
  raw pass is held to the same parse contract, may only report lines inside the input
  (`InvalidOutput::LineOutOfRange`), and if either pass fails the scan fails. It can only add
  findings, so it cannot weaken a verdict; its own read is proven indirectly (a prefix read of a
  JSON document does not parse, and the same binary proved a full read in the sentinel pass).
  YAML (`---`) and TOML (`+++`) front matter need no raw pass: the scanner only reads a *closed*
  block at the top of the input, which a suffix can neither open, close nor change (verified).
  Rejected: blocking every bare-document input outright (a false `SCANNER_FAILURE` on every
  clean JSON-shaped page, and it gives up the real finding id); a JSONC-comment sentinel
  (`// Ignore …`, which the scanner's JSONC relaxation would blank) — it depends on one parser
  quirk and changes the proven sentinel line in the final review round. **Rule for a scanner
  upgrade:** `config_parse_error` (or `manufactured_boundary`) may be admitted into the report
  type only together with this raw pass, and a `config_parse_error` may then be tolerated only on
  the sentinel pass of a bare-document candidate whose raw pass has none —
  `real_scanner_never_loses_findings_of_the_raw_input` fails if the top level is opened without
  the raw pass (verified by mutation).
- stdout is rejected if **any** object in it repeats a key (compared after JSON unescaping),
  whether or not the typed structs declare that field: serde only notices duplicates of declared
  fields, and two JSON readers that resolve a duplicate differently must never be able to
  disagree about a report. The report's top level is closed (`deny_unknown_fields`); only finding
  objects ignore unknown fields, which is what drops `matched_text` and the other text fields.
- Exit `0` must come with an empty `matches`, exit `1` with a non-empty one; any contradiction is
  `InvalidOutput`. Exit codes other than `0`/`1`, and signals, are `Crashed` even when stdout is
  valid JSON.
- `pattern_id` must match `[A-Z]{1,8}[0-9]{1,6}`, `pattern_name` must be `[a-z0-9]` words joined by
  single hyphens (≤ 64 bytes), `confidence` must be finite in `0..=1`, else `InvalidOutput`. The
  same holds for `low_confidence` entries.
- `--version` must print exactly `injection-scanner X.Y.Z` (optional `-<alnum/dot>` suffix). A
  malformed line makes the adapter `Unavailable` — every scan blocks — instead of stamping
  arbitrary text into `scannerVersion`.
- `ScanError`/`InvalidOutput` carry kinds and numbers only. serde error messages are discarded
  because they quote the offending value.

Policy:

- `decide_error` is a free function, not a `SecurityPolicy` method, so no policy implementation
  can override it; its match over `ScanError` is exhaustive without a wildcard.
- `PolicyEngine::new` re-checks `failurePolicy == block` and `critical/high == block` even though
  `Config::validate` already does, so an unvalidated config cannot weaken the engine.

Accept:

- `scan_and_accept` is the one entry point: it scans the document's **entire** `security_text`
  (no other input is accepted by the scanner trait) and blocks on any scan error.
- Before building an `AcceptedDocument`, `accept()` checks that the rendered Markdown is a
  contiguous substring of `security_text`, and that the title, every link and the final URL are
  whole lines of it (the `[visible]`, `[hidden:title]`, `[links]`, `[url]` sections, ADR-013). A
  miss blocks the page as `POLICY_VIOLATION` instead of exposing unscanned text.

## Consequences
+ A scanner that is wrong in any detectable way blocks pages rather than passing them; the only
  text a scanner can put in front of the agent is identifier-shaped.
+ The "scanner sees what the model sees" invariant is enforced where trust is granted, not only
  where text is produced; an extractor regression fails closed.
- A future scanner release that changes id formats, exit-code semantics or the version line will
  block every page until the adapter and `tests/contracts/scanner_output.json` are updated — by
  design, but it must be part of any scanner upgrade.
- The exposure check costs one substring search and one line-set build per accepted page (linear
  in `security_text`, ≤ 2 MB).
- The sentinel proves reading against a *buggy* scanner, not a *hostile* one: a binary written to
  guess the line count without reading could pass for a one-line input (a real page's
  `security_text` spans several section lines, so a fixed guess blocks it). A replaced scanner
  binary is outside the threat model — it could equally just emit a clean report for a page it
  did read. Proving more (a per-scan nonce the scanner echoes, or an input byte count / hash in
  the report) needs an `injection-scanner` change (e.g. `input_bytes` + `input_sha256` in the JSON report); it is a follow-up proposal for UnityInFlow/injection-scanner, not assumed here.
- A scanner upgrade that stops flagging `Ignore all previous instructions.` as `PI001` blocks
  every page until `SENTINEL_LINE`/`SENTINEL_ID` are updated — caught by the real-scanner suite.
- The duplicate-key pass parses stdout twice (≤ 1 MB, bounded by the stdout cap). Deeply nested
  JSON is bounded by serde_json's recursion limit (128): 100 000 levels of `[` or `{"a":` fail
  as `InvalidOutput::Malformed` without overflowing the stack (regression-tested).
- A bare-document candidate costs a second scanner process (run after the first, each under its
  own `security.scanner.timeout`, so up to twice the timeout). Through `PageProcessor` this is
  rare: `security_text` only starts with `{`/`/` when the page's own first text does.
- Known coverage gap, out of scope here: a JSON *page* is never a bare document in
  `security_text` (it is rendered as a fenced block under `[visible]` and followed by `[url]`),
  so a fetched `settings.json`/`.mcp.json` gets line-level scanning only; its structural
  findings need the raw body scanned as its own document — a follow-up for the extractor/page
  processor, not the adapter.
