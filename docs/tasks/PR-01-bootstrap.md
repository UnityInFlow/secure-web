# PR-01 — Bootstrap workspace, config, CLI skeleton, CI (SW-001)

Read first: `CLAUDE.md`, `docs/architecture.md`, `docs/contracts/config.md`, deep-dive §38–41, §65.

## Goal
A compiling Cargo workspace with all v0.1 crates (empty but wired), typed config with validation,
a clap CLI that starts and loads config, and CI enforcing fmt/clippy/test.

## Scope
In: workspace layout, `secure-web-core` (config, error codes, ids, core enums, trust-state type
stubs), CLI with `serve`/`open`/`crawl`/`find`/`inspect`/`config` subcommands (all except `config`
return `NOT_IMPLEMENTED` exit 1 for now), `config/secure-web.example.yaml`, GitHub Actions CI,
ADR-001, ADR-002, `docs/backlog.md`.
Out: any network code, scanner, HTML parsing.

## Steps
1. `cargo new secure-web`; convert to workspace with members `crates/secure-web-{core,fetch,security,extract,crawl,store,search,mcp}` and `tools/stub-scanner`. Root binary crate `secure-web`.
2. Workspace-level `[workspace.dependencies]` with pinned versions; `[workspace.lints]` with `unsafe_code = "forbid"`, `clippy::unwrap_used = "deny"`, `clippy::expect_used = "deny"` (allow in tests).
3. `secure-web-core`:
   - `ids.rs`: `CrawlId`, `RunId`, `DocumentId` newtypes; generation `crawl_<12 hex>`, `open_<12 hex>`, `doc_<6 digits>`.
   - `error.rs`: `ErrorCode` enum exactly as in `docs/contracts/mcp-contract.md`, `ErrorObject { code, message, retryable, details }`, `impl From<ErrorCode> for i32` exit codes.
   - `model.rs`: `SecurityDecision`, `Severity`, `BlockReason`, `SecuritySummary`, `Provenance`, and the four trust-state structs (fields per `docs/architecture.md`, bodies can be placeholders).
   - `config.rs`: full struct tree from `docs/contracts/config.md` with `#[serde(deny_unknown_fields)]`, humantime/bytesize parsing, layered loading (defaults ← file ← env `SECURE_WEB__…`), `validate()` implementing every rule in the contract, `policy_version()`.
4. CLI (`src/main.rs`): clap derive; global `--config`, `--workspace`, `--log-level`; `config --effective` prints YAML; `tracing_subscriber` init.
5. CI workflow: fmt, clippy, test, `cargo audit`, `cargo deny check` (config file included), release build matrix (allow failure for aarch64 until PR-10).
6. ADR-001 (Rust) and ADR-002 (MCP tools primary) — copy from `docs/adr/`.

## Tests
- `tests/core/config_validation.rs`: defaults load; example yaml loads; unknown key fails; each
  weakening rule fails (T16); env override works; `policy_version` stable across key order.
- `tests/core/ids.rs`: id formats.
- Binary: `cargo run -- --help` and `cargo run -- config --effective` succeed.

## Done when
- [x] `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --locked --workspace` green locally and in CI (local green; CI confirmed on the PR checks)
- [x] `secure-web --help` lists all subcommands; unimplemented ones exit 1 with `NOT_IMPLEMENTED`
- [x] ADR-001, ADR-002 present
- [x] `docs/backlog.md` created (seeded with the items PR-01 deferred)
