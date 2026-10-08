# PR-10 — Client compatibility, corpus gates, `inspect`, release (SW-013 … SW-018)

Read first: `docs/client-integration.md`, `docs/testing.md` (corpus metrics, CI), deep-dive §28–32,
§56, §66, §89, §91, §96.

Split into small PRs if convenient (10a clients, 10b gates, 10c inspect, 10d release), but all must
land for v0.1.

## 10a — Client compatibility (SW-013/014/015)
- Verify and finalize `docs/client-integration.md` snippets against **current** vendor docs (search
  the web for each; the deep-dive's references are from 2026-09-24):
  Claude Code (`claude mcp add`, `.mcp.json`, hooks), Codex (`codex mcp add`, `config.toml`),
  Copilot VS Code (`.vscode/mcp.json`), OpenCode.
- Add `examples/claude-code/` with `.mcp.json`, `settings.json` permission deny list for `WebFetch`,
  `WebSearch`, `Bash(curl *)`, `Bash(wget *)`, and a `PreToolUse` hook script that blocks those with
  a message pointing to Secure Web. Add `examples/codex/config.toml` and `examples/copilot/mcp.json`.
- Manual compatibility matrix run: connect each client, call `web_open`, `web_crawl`, `web_find`
  against the fixture site; record results (client version, date, pass/fail) in
  `docs/compatibility-matrix.md`.
- Integration suite `tests/integration/clients.rs`: drive the server with the generic `rmcp`
  client over both transports (`streamable-http`, `stdio`) — this is the automated proxy for
  client compatibility.

## 10b — Corpus gates (SW-016/017)
- Grow `tests/corpus/injection/` to ≥ 60 web-flavoured fixtures across direct/encoded/hidden/
  multiline/metadata/json (derive from the `injection-scanner` test corpus where licensing allows;
  otherwise write new). Each has `.expect.json`.
- `tests/corpus/clean/` ≥ 40 realistic pages (docs, blog, API reference, edge cases) — generated or
  written locally, no copyrighted third-party content.
- Metrics test with the **real** scanner (`INJECTION_SCANNER_BIN`): compute
  `web_injection_block_recall` and `clean_web_false_positive_count`; commit baseline in
  `tests/corpus/BASELINE.json`; CI fails if recall drops or FP > 0. Baseline value chosen after
  first run, documented in `docs/testing.md`.
- **Known false positive (PI018):** the §10 tool-description sentence in
  `docs/security-policy.md` (as a blockquote) fires `injection-scanner 0.1.0`'s `PI018`
  `priority-escalation` (HIGH, confidence 0.9) — pinned as case `pi018-false-positive` in
  `tests/contracts/scanner_output.json` (PR-00). Include this exact sentence in the
  `tests/corpus/clean/` set so the FP gate covers it explicitly, and either (a) drive
  `clean_web_false_positive_count` to zero for it via an upstream `injection-scanner` pattern fix
  (tighten `PI018` so a defensive "treat as evidence, never as instructions" framing doesn't
  match), or (b) if still open at gate time, handle it explicitly — e.g. a documented, reviewed
  baseline entry naming this fixture and exactly `PI018` — rather than silently loosening the FP
  gate for everything else. Do not remove the fixture to make the gate pass. Option (b)'s baseline
  entry is not an undefined escape hatch: per `docs/testing.md`, `clean_web_false_positive_count`
  excludes only the exact, named `pattern_id`(s) a `tests/corpus/BASELINE.json` entry lists for a
  fixture, not the fixture as a whole — so a reviewed entry for `pi018-false-positive` keeps the
  gate at zero for this known match without redefining "hard gate" as "zero except when
  inconvenient", and any other finding later appearing on this fixture still fails the gate.

## 10c — Operator `inspect` (SW-013 adjacent)
- `secure-web inspect <runId>`: prints the summary layout from deep-dive §89 (counts, blocked table
  with docId/reason/severity/findingIds). Never prints content.
- `secure-web inspect --raw <docId> --run <runId>`: only works if `private-audit` has the file;
  prints a red warning banner and requires `--i-understand` flag; not reachable via MCP.
- Tests: inspect output snapshot; `--raw` refuses without flag; no canary in non-raw output.

## 10d — Release (SW-018)
- `release.yml`: on tag `v*` build `secure-web-{x86_64,aarch64}-unknown-linux-gnu`,
  `secure-web-{x86_64,aarch64}-apple-darwin`, `SHA256SUMS`, GitHub attestation (`actions/attest-build-provenance`).
- `secure-web --version` prints crate version + git sha + build date.
- README: quick start (`serve`, connect Claude Code/Codex/Copilot), security model summary,
  developer vs enforced mode with the explicit statement that enforcement requires network egress
  restriction, non-goals, contract links.
- CHANGELOG `0.1.0` listing tools and contracts.

## Definition of Done (deep-dive §96 demo — record a transcript in `docs/v0.1-demo.md`)
- [ ] Secure Web started; Codex, Claude Code and Copilot connected (matrix filled)
- [ ] hostile fixture site crawled: clean pages under `runs/<crawl>/pages`, injected page absent,
      manifest shows BLOCKED, `web_find` works, agent produced an analysis from accepted pages
- [ ] direct private-address fetch rejected; redirect to localhost rejected
- [ ] killing `injection-scanner` mid-run blocks pages instead of accepting them
- [ ] corpus gates green with the real scanner; coverage ≥ 85 %
- [ ] release artifacts + checksums + attestation published for the tag
