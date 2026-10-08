# ADR-010 — URL guard: WHATWG parsing, ambiguous IPv4 literals, embedded IPv4, denylist semantics

Status: Accepted (2026-09-25)

## Context
`docs/security-policy.md` §1 lists the blocked ranges and says obfuscated IPv4 literals
(`2130706433`, `0x7f000001`, `017700000001`) must be parsed as IPs and range-checked. The PR-02
brief additionally asks for dotted-decimal with leading zeros to be treated as "ambiguous". Several
details were left open: which parser defines "the host", what happens to an obfuscated literal that
encodes a *public* address, which IPv6 forms carry an embedded IPv4, how `extraBlockedHosts` and
`extraBlockedCidrs` are matched, and how the guard is kept the only producer of a connectable
target. Each affects which destinations the fetcher can reach (invariant 2).

## Decision
1. **Parser.** URLs are parsed with the `url` crate (WHATWG). It is the same parser `reqwest` uses,
   so the host the guard checks is the host the client would connect to. WHATWG normalizes decimal,
   hex, octal, short (`127.1`), percent-encoded and full-width IPv4 spellings into an `Ipv4Addr`;
   that address is range-checked like any other.
2. **Ambiguous IPv4 literals are refused even when public.** After the range check, the host text
   *as written* in the raw input is recovered (same tab/newline/C0 stripping and `/` `\` handling as
   WHATWG). If it is not exactly the canonical dotted-decimal form of the parsed address, the URL is
   rejected as `Ssrf { rule: "ambiguous-ipv4-literal" }` (`SSRF_BLOCKED`). A private address is
   still reported under its CIDR rule, because the range check runs first. If the raw host cannot
   be located, the URL is rejected (fail closed). `093.x.x.x` is not valid octal and fails to parse
   (`INVALID_URL`).
3. **Embedded IPv4.** IPv4-mapped (`::ffff:0:0/96`), NAT64 (`64:ff9b::/96`) and deprecated
   IPv4-compatible (`::/96`) addresses are unwrapped and the embedded IPv4 is checked against the
   IPv4 rules and IPv4 `extraBlockedCidrs`. The IPv6 table (`::/128`, `::1/128`, …) is checked first
   so those addresses report their own rule. A NAT64 address embedding a public IPv4 is allowed.
4. **Every resolved address** must pass; one blocked address rejects the URL (mixed public/private
   answers are a rebinding attack). Duplicates are collapsed; an empty answer is `DNS_FAILED`.
5. **Denylist.** `localhost`, `*.localhost` and `metadata.google.internal` (and its subdomains) are
   refused by name before DNS. Host comparison is case-insensitive and ignores trailing dots.
   An `extraBlockedHosts` entry blocks that host **and all its subdomains**. Entries go through the
   same WHATWG host parser as URLs (percent-decoding, IDNA/UTS #46 to ASCII, lower case; trailing
   dots dropped), so `bücher.example`, `BÜCHER.example.` and `xn--bcher-kva.example` are one entry.
   The name denylist is only consulted for domain hosts, so an IP literal in any notation
   (`93.184.216.34`, `1572395042`, `[::1]`, `::1`) is refused at startup with an error pointing to
   `extraBlockedCidrs`; so are ports, paths, userinfo, wildcards, a leading dot and empty labels,
   which would otherwise silently block nothing. An `extraBlockedCidrs`
   entry must be `addr/prefix`; an invalid entry makes `UrlGuard::new` fail (startup error).
6. **Userinfo** (`user:pass@`, `user@`, and even an empty `@host`) and port `0` are refused with
   `INVALID_URL`. Schemes other than `http`/`https` are `UNSUPPORTED_SCHEME`.
7. **Sealed types.** `ValidatedTarget` has private fields and no public constructor, `Default` or
   `Deserialize`; a compile-fail doc test pins this. Two static checks read the **raw text** and
   cannot be recovered from a parsed `Url`, because `Url::parse` erases the evidence: a
   non-canonical IPv4 spelling (`http://1572395042/` parses to `http://93.184.216.34/`) and an
   empty userinfo (`http://@example.com/` parses to `http://example.com/`). So
   `parse_and_check_static(&str)` returns a sealed `CheckedUrl`, and `resolve_and_check` accepts
   only `&CheckedUrl`, never a bare `Url`; compile-fail doc tests pin both. `resolve_and_check`
   still re-runs the checks that survive parsing (scheme, userinfo, port, host denylist, IP ranges)
   as defence in depth. Consequence for PR-03: a redirect `Location` must be validated from its
   raw text; a relative `Location` must be resolved against the base without discarding the raw
   authority it carries (a `Url::join` result may not be fed back in as trusted).
   `ValidatedTarget` and `CheckedUrl` have hand-written `Debug` that prints only scheme, host,
   port (and resolved addresses); path, query, fragment and userinfo are never printed.
8. **Resolver injection.** DNS goes through a `Resolver` trait (production: `tokio::net::lookup_host`)
   so tests use a fixed map and never touch real DNS.
9. The `security.network.block*` booleans are not consulted by the guard: config validation already
   refuses `false`, and the guard enforces every range unconditionally.
10. **Dependencies** added to `secure-web-security`: `ipnet =2.12.2` (CIDR tables and parsing of
    `extraBlockedCidrs`; no transitive deps) and `tokio =1.53.1` (`net`, `rt`: `lookup_host`),
    both pinned; `cargo deny check` and `cargo audit` clean.

## Consequences
+ no notation trick reaches a private address, and no public address is reachable through an
  obfuscated spelling either (an obfuscated literal has no legitimate agent use).
+ the rule string in a rejection names the exact policy line that fired.
- a site that genuinely links to `http://1572395042/` cannot be fetched; the canonical spelling can.
- the guard is only half of T5: the fetcher (PR-03) must connect to `ValidatedTarget::addrs()`
  (pinned resolution) and revalidate every redirect hop.
- ranges beyond the policy (NAT64 local-use `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo
  `2001::/32`, site-local `fec0::/10`) are not blocked; tracked in `docs/backlog.md`.
  (Superseded: 6to4/Teredo are unwrapped since ADR-017; `64:ff9b:1::/48` and `fec0::/10` are
  blocked and ISATAP unwrapped since the ADR-017 PR-08 addendum.)
