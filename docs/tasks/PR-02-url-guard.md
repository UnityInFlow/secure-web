# PR-02 — URL guard / SSRF protection (SW-002)

Read first: `docs/security-policy.md` §1, `docs/threat-model.md` T5/T6, deep-dive §14.

## Goal
`secure-web-security::ssrf::UrlGuard` that turns a `&str` into a `ValidatedTarget { url: Url,
addrs: Vec<IpAddr>, host: String, port: u16 }` or a typed rejection, and is the only way to obtain
a target the fetcher will connect to.

## Design
```rust
pub struct UrlGuard { cfg: NetworkConfig, resolver: Arc<dyn Resolver> }   // Resolver trait for test injection
pub enum GuardError { InvalidUrl, UnsupportedScheme(String), DnsFailed, Ssrf { addr: IpAddr, rule: &'static str }, HostDenied(String) }
impl UrlGuard {
    pub fn parse_and_check_static(&self, raw: &str) -> Result<Url, GuardError>;          // scheme, userinfo, host denylist, IP literal
    pub async fn resolve_and_check(&self, url: &Url) -> Result<ValidatedTarget, GuardError>; // DNS + ranges
    pub async fn validate(&self, raw: &str) -> Result<ValidatedTarget, GuardError>;      // both
}
```
- Reject URLs with userinfo (`user:pass@host`), empty host, port 0.
- Normalize IP literals: dotted-decimal with leading zeros (treat as octal → reject as ambiguous),
  pure decimal, hex, IPv4-mapped/compatible IPv6, NAT64 prefix → extract embedded v4.
- Range list from the policy doc as `const` tables (`ipnet` crate); unit-test each CIDR boundary
  (first, last, one-before, one-after).
- Resolver: production uses `tokio::net::lookup_host`; tests use a `HashMap<String, Vec<IpAddr>>` stub.
- If **any** resolved address is blocked → reject (mixed public/private is an attack).
- `ValidatedTarget` is `#[non_exhaustive]`-style with private constructor so no code path can build
  one without the guard.

## Tests (`tests/security/ssrf_ranges.rs`, `ssrf_hosts.rs`, `ssrf_literals.rs`)
Data-driven from `tests/corpus/network/{localhost,private-ip}/urls.txt` plus inline cases from the
acceptance checklist in `docs/testing.md`. Include: every CIDR, `localhost`/`foo.localhost`,
metadata hostnames, decimal/hex/octal literals, `[::ffff:127.0.0.1]`, `[64:ff9b::7f00:1]`, mixed
resolution, userinfo, `file:`, `data:`, `javascript:`, uppercase schemes, extra `extraBlockedCidrs`/`extraBlockedHosts`.
Positive cases: `https://example.com` resolving to `93.184.216.34`, IPv6 public, non-default port.

## Done when
- [x] all ranges in `docs/security-policy.md` §1 covered by boundary tests
- [x] `ValidatedTarget` cannot be constructed outside the module (compile-fail doc test or private ctor)
- [x] no `unwrap` in non-test code; fmt/clippy/test green
