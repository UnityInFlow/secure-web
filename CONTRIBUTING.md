# Contributing to Secure Web

Secure Web is a security boundary. Most of what makes a change acceptable is about not weakening
that boundary, so read the invariants below before you open a pull request.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo run -- --help
```

All four must pass. CI runs them, plus `cargo audit`, `cargo deny check`, a coverage gate (at least
85 % of lines) and release-build checks.

Tests are deterministic and offline. **Never hit the live Internet in a test.** Use the local
fixture server and, when `injection-scanner` is not on `PATH`, the stub scanner in `tests/support/`
([`docs/testing.md`](docs/testing.md)). A test that needs the real scanner must not skip silently
when it is missing. The real-scanner suite runs with:

```bash
INJECTION_SCANNER_BIN=$(command -v injection-scanner) cargo test --test scanner_real -- --ignored
```

## Invariants

These are enforced in code, tests and review. A pull request that breaks one will not be merged,
however useful it is otherwise.

1. All model-facing Internet content passes through `PageProcessor` → injection-scanner → policy.
   There is exactly one processing path.
2. SSRF validation happens after DNS resolution and on every redirect hop.
3. Scanner errors (crash, timeout, invalid output, oversized input) fail closed.
4. Blocked payload text is never returned over MCP, written to the agent corpus or logged at the
   default level.
5. Crawl budgets are hard limits enforced in code.
6. A blocked page contributes no child links to the frontier.
7. No LLM, embeddings, vector DB, message broker or browser engine in the core.
8. Every new model-facing field (title, snippet, filename, URL text) is untrusted input and must be
   scanned or tightly normalized.
9. MCP tool names and schemas, the manifest schema, decision and reason enums, and CLI exit codes
   are contracts with contract tests. To change one, update [`docs/contracts/`](docs/contracts/) in
   the same pull request.
10. Security-affecting decisions need an ADR in [`docs/adr/`](docs/adr/).

Trust state lives in the type system (`UntrustedDocument` → `ScannedDocument` →
`AcceptedDocument` / `BlockedDocument`). Only an `AcceptedDocument` may be stored or serialized
into an MCP result. See [`docs/architecture.md`](docs/architecture.md).

## Rust conventions

- Edition 2021, `#![forbid(unsafe_code)]` in every crate.
- No `unwrap()` or `expect()` outside tests. Library crates use `thiserror`; the binary uses
  `anyhow`.
- `tracing` for logs. Never log request bodies or extracted text at `info` or above.
- Bounded concurrency only (`Semaphore` and bounded queues). Never spawn one task per discovered URL.
- Pin every new dependency to an exact version (`=x.y.z`) and keep `cargo audit` and
  `cargo deny check` clean.

## Pull requests

- Keep each one small and focused on a single change.
- Fill in the checklist in the pull request template. It mirrors the invariants above.
- If you change behavior that a contract or the security policy describes, update that document
  in the same pull request.
- A new attack case needs a test that asserts its expected decision, not only that nothing
  crashed. Fixture-server routes and corpus files are described in
  [`docs/testing.md`](docs/testing.md).

## Reporting bugs and vulnerabilities

- Ordinary bugs: open an issue.
- Vulnerabilities, such as an SSRF bypass, a leak of blocked content, a budget bypass or a
  scanner fail-open: **do not** open a public issue. Follow [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
