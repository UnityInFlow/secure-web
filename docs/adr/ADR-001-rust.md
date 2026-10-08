# ADR-001 — Rust as implementation language

Status: Accepted (2026-09-24)

## Context
Secure Web is network/security infrastructure that must ship as one portable static binary, integrate tightly with the existing Rust `injection-scanner`, and use an official MCP SDK.

## Decision
Implement Secure Web in Rust (Tokio, reqwest, rmcp). One binary `secure-web` with CLI + MCP server.

## Consequences
+ memory safety, static binary, shared ecosystem with the scanner, future in-process scanner library.
- slower iteration than a scripting language; HTML extraction library choices are less mature than in JS/Python (bake-off in PR-04).
