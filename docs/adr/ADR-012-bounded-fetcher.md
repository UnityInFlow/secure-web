# ADR-012 — Bounded fetcher: pinned connections, raw-text redirect validation, own decompression

Status: Accepted (2026-09-25)

## Context
PR-03 builds `secure-web-fetch::HttpFetcher` (threats T5, T6, T9; `docs/security-policy.md`
§1–2). ADR-010 §7 left two obligations to the fetcher: connect only to the addresses the guard
validated, and validate every redirect `Location` from its raw text. The brief also asks for a
decompressed-byte cap that no header can bypass, and leaves several mechanics open.

## Decision
1. **HTTP client.** `reqwest =0.12.28` with `default-features = false` and `rustls-tls` only
   (rustls + ring + bundled `webpki-roots`): no system proxy support, no automatic
   decompression, no cookies, no HTTP/2, no OpenSSL or platform verifier. 0.13 was not chosen
   because its rustls default pulls `aws-lc-rs` and `rustls-platform-verifier` (the macOS
   cross-link problem recorded for prompt-vc). `webpki-roots` is CDLA-Permissive-2.0; `deny.toml`
   allows that license for that crate only.
2. **Pinned connections (rebinding).** A client is built per hop with a custom DNS resolver that
   answers only the validated host name with only `ValidatedTarget::addrs()` and fails every
   other name; IP-literal hosts never reach a resolver. `no_proxy()` is set (a proxy would pick
   the destination itself), `Policy::none()` disables redirects, `referer(false)`, no pooling.
   There is no DNS lookup between the guard's check and the connect.
3. **Redirects** are followed by the fetcher: statuses 301/302/303/307/308 only; a hop cap of
   `fetch.maxRedirects` (the hop after it is `REDIRECT_BLOCKED` and is never requested); loop
   detection on the fragment-less URL; `https → http` refused unless
   `fetch.allowRedirectDowngrade`. The next URL is `base.join(location)` (what any client would
   follow). If it keeps the current scheme/host/port, its canonical serialization is validated
   (the authority was validated from raw text on an earlier hop; DNS is resolved again). If the
   authority is new, it can only come from the `Location` text, so that raw text (or
   `scheme:` + it for a scheme-relative `//host`) goes through `parse_and_check_static`, and the
   result must equal the joined URL — any disagreement fails closed
   (`InconsistentLocation`). A `Location` that is not visible ASCII is refused. Every guard
   rejection on a hop (including DNS failure) is `REDIRECT_BLOCKED` /
   `BlockReason::RedirectViolation`.
4. **Decompression** is done by the fetcher with `flate2` (pure-Rust `miniz_oxide`) write-side
   decoders feeding a sink that refuses the write that would cross the limit. The brief suggested
   `async-compression`; the write-side decoder needs no stream adapters (`tokio-util`,
   `futures`) and makes the cap exact: decoded bytes held never exceed the limit, peak memory is
   the limit plus one network chunk. Only `gzip`/`x-gzip`/`deflate` (zlib) are accepted and
   advertised; `br`, `zstd`, unknown and **stacked** codings (`gzip, gzip`) are refused as
   `UNSUPPORTED_CONTENT_TYPE`. A corrupt or truncated compressed body is `FETCH_FAILED`.
5. **Size limits.** `maxJsonBytes` applies to `application/json`, `maxPageBytes` to everything
   else. `Content-Length` larger than the limit refuses early (identity encoding only); it is
   never used to accept or to pre-allocate. The stream counter is authoritative.
6. **Content type** is decided on headers before the body is read: `text/html` (and
   `application/xhtml+xml`), `text/plain`, `text/markdown` (and `text/x-markdown`),
   `application/json`; anything else is `UNSUPPORTED_CONTENT_TYPE` without reading the body. It
   is parsed by hand (essence + `charset`, token characters only, ≤ 64 bytes) instead of the
   `mime` crate, so header text cannot carry anything else into later stages. A missing
   `Content-Type` is sniffed from the first 512 decoded bytes (`<!doctype html` / `<html` →
   HTML; a NUL byte → unsupported binary; otherwise plain text).
7. **Time.** `fetch.requestTimeout` bounds the **whole** fetch (all hops and the body);
   `fetch.connectTimeout` bounds each connect and — via `UrlGuard::with_dns_timeout` — every
   DNS lookup the guard makes for a redirect hop (`DNS_FAILED` → `REDIRECT_BLOCKED`). The guard's
   default DNS bound is 5 s.
8. **Politeness and retries.** A per-`host:port` semaphore (`fetch.perHostConcurrency`) and an
   optional `fetch.minDelayPerHost` between request starts. Non-2xx finals are
   `FETCH_FAILED { status }`, retryable for 5xx and 429; `Retry-After` (seconds or HTTP-date,
   clamped to 1 h) is reported on 429/503 when `fetch.respectRetryAfter`. The fetcher never
   retries by itself — the crawler decides.
9. The `Fetcher` trait lives in `secure-web-fetch` (not `secure-web-core::ports` as sketched in
   `docs/architecture.md`), because `FetchRequest` carries a `ValidatedTarget` from
   `secure-web-security`, which `core` must not depend on. It returns a boxed future (no
   `async-trait` dependency), like the guard's `Resolver`.

## Consequences
+ no DNS rebinding window; no redirect or proxy path around the guard; no header can make the
  fetcher buffer more than the limit plus one chunk.
- a client (and its rustls config) is built per hop; acceptable for v0.1 volumes, tracked in
  `docs/backlog.md`.
- brotli/zstd-only servers cannot be fetched; they must fall back to gzip/identity, which every
  server does when the client does not advertise them.
- the downgrade rule is covered by unit tests on the redirect resolver; an end-to-end test needs a
  TLS fixture server (backlog).
