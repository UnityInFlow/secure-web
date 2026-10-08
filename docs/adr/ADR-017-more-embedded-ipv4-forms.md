# ADR-017 — Unwrap IPv4-translated, 6to4 and Teredo addresses

Status: Accepted (2026-09-26)

## Context
ADR-010 unwraps the IPv4 address embedded in IPv4-mapped (`::ffff:0:0/96`), NAT64
(`64:ff9b::/96`) and IPv4-compatible (`::/96`) IPv6 addresses and applies the IPv4 rules. Three
other standard forms also carry an IPv4 address that a translator or relay on the path may
deliver to, and they passed the guard (PR-07 review, finding 3): IPv4-translated
`::ffff:0:0:0/96` (SIIT), 6to4 `2002::/16` (RFC 3056, IPv4 in bits 16..48) and Teredo `2001::/32`
(RFC 4380, server IPv4 in bits 32..64, client IPv4 in the last 32 bits, inverted). On a host with
SIIT, 6to4 or Teredo routing, `http://[2002:7f00:1::]/` could reach `127.0.0.1`.

## Decision
`ranges::embedded_v4` also unwraps these three forms. Teredo yields two addresses (server and
client); each embedded address is checked against the IPv4 rules and the operator's
`extraBlockedCidrs`, and any hit blocks with that IPv4 rule. The rest of the prefix stays allowed:
a public embedded address is a legitimate destination.

## Consequences
+ Loopback, link-local/metadata and private IPv4 destinations can no longer be reached through
  these translation forms, from a URL literal or from a DNS AAAA answer.
- Not covered (backlog): the NAT64 local-use prefix `64:ff9b:1::/48` (RFC 8215, variable
  embedding position) and ISATAP interface identifiers (`::5efe:a.b.c.d` under any prefix). Both
  need a routing setup that Secure Web does not expect on its host.

## Addendum (PR-08, 2026-09-26)
The crawler follows server-chosen links, so the forms listed as "not covered" above are closed
before it ships:

- **NAT64 local-use `64:ff9b:1::/48`** (RFC 8215) is **blocked whole** (rule `64:ff9b:1::/48`).
  Unwrapping would need the local network's prefix length (RFC 6052 embeds the IPv4 address at a
  position that depends on it, around the reserved `u` octet); the prefix is local-use by
  definition and never a public destination, so blocking it loses nothing.
- **ISATAP** interface identifiers (RFC 5214: `0000:5efe` or `0200:5efe` in bits 64..96, IPv4 in
  the last 32 bits, under any /64 prefix) are **unwrapped** and the IPv4 address is checked
  against the IPv4 rules; a public embedded address stays allowed.
- **Site-local `fec0::/10`** (deprecated by RFC 3879, still routed on some internal networks) is
  **blocked** (rule `fec0::/10`).

Tests: `tests/security/ssrf_ranges.rs` (table boundaries, ISATAP unwrap). The remaining `::/8`
space beyond `::/128`, `::1/128`, `::/96` and `::ffff:0:0/96` stays unassigned and unrouted; it
is not special-cased.
