# Security Policy

Secure Web exists to stand between an AI agent and hostile web content, so a flaw in it is a
flaw in the protection people are relying on. This document says what counts as a vulnerability
and how to report one.

## Supported versions

Secure Web is pre-release. There is no tagged release yet, and only the latest `main` is
supported. Fixes land on `main`. Once v0.1 is tagged, this section will name the supported line.

This is a single-maintainer project ([@hermanngeorge15](https://github.com/hermanngeorge15)), so
see "What to expect" below.

## Reporting a vulnerability

Report it privately, using GitHub's private vulnerability reporting on this repository:

<https://github.com/UnityInFlow/secure-web/security/advisories/new>

There is no separate email address. Please don't open a public issue: a working proof of concept
for any of the cases below is itself the exploit.

In scope, which is anything that breaks an invariant Secure Web promises:

- **SSRF.** A fetch, or a redirect hop, that reaches a private, loopback, link-local or otherwise
  non-public address. This includes DNS-rebinding and alternate address encodings.
- **Leaking blocked content.** Text from a blocked page that reaches an MCP result, the agent
  corpus, a manifest, `Debug` output or a default-level log.
- **Fail-open scanning.** Any scanner failure (crash, timeout, malformed or oversized output, a
  missing binary) that results in a page being accepted.
- **Bypassing the pipeline.** A path that delivers fetched content to the model without going
  through `PageProcessor`, the scanner and policy.
- **Budget bypass.** Exceeding a crawl or fetch limit (bytes, pages, depth, duration, redirects,
  concurrency), or a blocked page that still adds links to the frontier.
- **Local file safety.** A write outside the workspace, or path traversal through a URL-derived
  file name.
- **Resource exhaustion.** A crafted response that panics, hangs or exhausts memory despite the
  limits.

## Detection misses belong to injection-scanner

Secure Web delegates prompt-injection detection to
[`injection-scanner`](https://github.com/UnityInFlow/injection-scanner). **A payload the scanner
does not detect is not a Secure Web vulnerability.** It is a missing detection, and the
injection-scanner project tracks those in the open, as public issues, so each one can become a
regression test. See that project's
[security policy](https://github.com/UnityInFlow/injection-scanner/blob/main/SECURITY.md).

The exception is when Secure Web causes the miss: for example, if extraction hides text from the
scanner that is later shown to the model, or the text that gets scanned differs from the text
that gets stored. That is a Secure Web vulnerability, so report it here privately.

## What to expect

This is a part-time, single-maintainer project. You can expect an acknowledgement within 7 days, an
initial assessment within 14 days, and best effort after that. There is no guaranteed remediation
window, no bug bounty and no monetary reward. Credit is given in the advisory unless you decline
it.
