# Secure Web

A security gateway for agentic Internet access, written in Rust and exposed over MCP.

Secure Web sits between an AI agent (Claude Code, Codex, Copilot, OpenCode, or any other MCP host)
and untrusted web content. The agent asks Secure Web for a URL instead of fetching it directly.
Every page then passes one fixed pipeline before any of its text can reach the model:

```text
URL guard → bounded fetch → extract → injection-scanner → policy → corpus
```

> No untrusted Internet content reaches an AI agent without passing the Secure Web security pipeline.

> **Status: pre-release.** v0.1 is in progress. `web_open` and `web_crawl` work end to end.
> `web_find` and `inspect` are not implemented yet: they exit `1` with `NOT_IMPLEMENTED`.
> There are no release binaries yet, so build from source. Expect breaking changes before v0.1.

## What it enforces

- **SSRF protection after DNS resolution and on every redirect hop.** Private, loopback,
  link-local and other non-public ranges are rejected, including embedded and alternate IPv4 forms
  ([`docs/security-policy.md`](docs/security-policy.md)).
- **Hard budgets.** Bytes per page, total bytes, depth, page count, duration, redirects and
  concurrency are limits enforced in code, not hints.
- **Fail closed.** If [`injection-scanner`](https://github.com/UnityInFlow/injection-scanner)
  crashes, times out, returns invalid output or is missing, the page is blocked (`SCANNER_FAILURE`)
  rather than passed through.
- **Blocked content never leaks.** A blocked page is reported only by reason, maximum severity and
  finding ids. Its text is never returned over MCP, written to the agent corpus or logged at the
  default level. A blocked page also contributes no links to the crawl frontier.
- **One processing path.** `web_open` and the crawler share a single `PageProcessor`, so there is
  no second route around the scanner.

The core has no LLM, embeddings, vector database or browser engine. The threat model is in
[`docs/threat-model.md`](docs/threat-model.md), and the decisions behind each invariant are in
[`docs/adr/`](docs/adr/).

## Build

You need Rust 1.88 or newer, plus `injection-scanner` 0.1.0 on `PATH` (or an absolute path in the
config's `executable`). Get it from the
[injection-scanner releases](https://github.com/UnityInFlow/injection-scanner/releases).

```bash
git clone https://github.com/UnityInFlow/secure-web
cd secure-web
cargo build --release
./target/release/secure-web --help
```

## Use

```bash
secure-web open https://example.com/                 # retrieve, scan and store one page
secure-web crawl https://example.com/ --depth 2      # crawl within hard budgets; Ctrl-C keeps a partial manifest
secure-web serve                                     # MCP over streamable HTTP at http://127.0.0.1:8787/mcp
secure-web serve --stdio                             # MCP over stdio
secure-web config --effective                        # print the effective configuration
```

Runs are written under `~/.secure-web/runs/` by default (`--workspace` overrides this). Every run
has a manifest that lists each page as accepted or blocked, and why.

Exit codes are a stable contract: `0` success, `1` internal error, `2` usage/config error,
`3` security block, `4` fetch/network error, `5` scanner failure, `6` crawl limit reached,
`7` cancelled ([`docs/contracts/mcp-contract.md`](docs/contracts/mcp-contract.md)).

### Connect an agent

Claude Code:

```bash
claude mcp add --transport http secure-web http://127.0.0.1:8787/mcp
```

For other clients, and for a defense-in-depth setup that denies the agent's native web tools, see
[`docs/client-integration.md`](docs/client-integration.md).

MCP tools available now are `web_open` and `web_crawl`. `web_find` is coming in v0.1, and
`web_search` is planned for v0.2.

## Configuration

Configuration is YAML. Secure Web looks for `./secure-web.yaml`, then
`~/.secure-web/config.yaml`, then falls back to built-in defaults. Start from
[`config/secure-web.example.yaml`](config/secure-web.example.yaml). Every key and its validation
rule are in [`docs/contracts/config.md`](docs/contracts/config.md).

## Documentation

| Document | What it covers |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Crates, trust-state types, `PageProcessor`, state machines |
| [`docs/security-policy.md`](docs/security-policy.md) | SSRF ranges, limits, scanner adapter, policy, no-leak rules |
| [`docs/threat-model.md`](docs/threat-model.md) | Threats → mitigation → test |
| [`docs/contracts/`](docs/contracts/) | MCP tools, manifest schema, config: all pinned by contract tests |
| [`docs/testing.md`](docs/testing.md) | Fixture server, canaries, stub scanner, corpus |
| [`docs/adr/`](docs/adr/) | Architecture decision records |
| [`docs/tasks/`](docs/tasks/) | The build plan, one brief per milestone PR |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). To report a vulnerability, see
[`SECURITY.md`](SECURITY.md); please don't open a public issue for it.

## License

[MIT](LICENSE)
