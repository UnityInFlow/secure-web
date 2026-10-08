# PR-03 — Bounded HTTP fetcher, redirect policy, fixture server (SW-003)

Read first: `docs/security-policy.md` §1 (redirects), §2; `docs/threat-model.md` T6/T9; `docs/testing.md`
(fixture server); deep-dive §15, §17, §83.

## Goal
`secure-web-fetch::HttpFetcher` implementing `Fetcher`: takes a `ValidatedTarget` (never a raw URL),
streams the body under hard byte limits, handles redirects manually through `UrlGuard`, classifies
content type, and returns `FetchedResponse`. Plus the in-process fixture server used by every later PR.

## Design
```rust
pub struct FetchRequest { pub target: ValidatedTarget, pub limits: FetchLimits }
pub struct FetchedResponse { pub requested_url: Url, pub final_url: Url, pub redirect_chain: Vec<Url>,
    pub status: u16, pub content_type: ContentType, pub charset: Option<String>, pub body: Vec<u8>,
    pub decompressed_bytes: u64, pub retrieved_at: DateTime<Utc>, pub retry_after: Option<Duration> }
pub enum ContentType { Html, PlainText, Markdown, Json, Unsupported(String) }
```
- `reqwest` client: `redirect(Policy::none())`, rustls, gzip/br/deflate **disabled in reqwest** — do
  decompression yourself with `async-compression` so the decompressed counter is authoritative;
  `connect_timeout`, `timeout`, `user_agent`, `resolve(host, validated_addr)` per request (build a
  per-target client or use `resolve_to_addrs`). Deny `http_only` upgrade tricks.
- Redirect loop: for hop in 0..=maxRedirects: send → if 3xx with Location: join, `guard.validate()`,
  check downgrade rule, push chain, continue; else break. Exceeding cap → `REDIRECT_BLOCKED`.
  Guard rejection on a hop → `GuardError` mapped to `REDIRECT_BLOCKED` with `BlockReason::RedirectViolation`.
- Body: `bytes_stream()`; abort when decompressed > `maxPageBytes` (or `maxJsonBytes` for JSON) →
  `CONTENT_TOO_LARGE`. Never call `.bytes()`/`.text()`.
- Content type: parse `Content-Type` header (mime crate); if missing, sniff first 512 bytes for
  `<html`/`<!doctype` else treat as plain text. `Unsupported` → `UNSUPPORTED_CONTENT_TYPE` before
  reading the body beyond the sniff window.
- Per-host semaphore + optional `minDelayPerHost`; honour `Retry-After` on 429/503 by returning
  `retryable: true` and the delay (the crawler decides).
- Non-2xx after redirects: `FETCH_FAILED { status }`, retryable for 5xx/429.

## Fixture server (`tests/support/fixture_server.rs`)
Implement all routes listed in `docs/testing.md`. Export `FixtureServer::start().await -> (base_url, handle)`.
For `/redirect/private` use the fixture's own loopback address so it is a real private target.

## Tests (`tests/security/redirect_private.rs`, `size_bomb.rs`, `tests/fetch/*.rs`)
- redirect to private/metadata/loop/chain-6 rejected; chain-5 ok; downgrade rejected by default.
- `/huge` and `/gzip-bomb` → `CONTENT_TOO_LARGE`; assert peak buffered bytes ≤ limit + one chunk.
- `/slow` → `FETCH_TIMEOUT`.
- `/mime/pdf` → `UNSUPPORTED_CONTENT_TYPE` without downloading the body.
- `/status/500` retryable, `/status/404` not.
- `Content-Length` lies (smaller than body) → still capped by stream counter.

## Done when
- [ ] fetcher API accepts only `ValidatedTarget`
- [ ] no automatic redirect following anywhere (grep for `Policy::limited`)
- [ ] fixture server serves every route in `docs/testing.md`
- [ ] fmt/clippy/test green
