//! Blocked destination ranges (`docs/security-policy.md` §1) and address classification.
//!
//! The rule string reported for a blocked address is the CIDR text of the matching entry, so a
//! rejection names exactly which policy line fired.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

/// Rule reported for an address blocked by `security.network.extraBlockedCidrs`.
pub const EXTRA_BLOCKED_CIDRS: &str = "extraBlockedCidrs";

/// Blocked IPv4 ranges, in match order. The `/32` broadcast entry precedes `240.0.0.0/4` so the
/// more specific rule is the one reported.
pub(crate) const BLOCKED_V4: &[(Ipv4Net, &str)] = &[
    (v4(0, 0, 0, 0, 8), "0.0.0.0/8"),
    (v4(10, 0, 0, 0, 8), "10.0.0.0/8"),
    (v4(100, 64, 0, 0, 10), "100.64.0.0/10"),
    (v4(127, 0, 0, 0, 8), "127.0.0.0/8"),
    (v4(169, 254, 0, 0, 16), "169.254.0.0/16"),
    (v4(172, 16, 0, 0, 12), "172.16.0.0/12"),
    (v4(192, 0, 0, 0, 24), "192.0.0.0/24"),
    (v4(192, 168, 0, 0, 16), "192.168.0.0/16"),
    (v4(198, 18, 0, 0, 15), "198.18.0.0/15"),
    (v4(224, 0, 0, 0, 4), "224.0.0.0/4"),
    (v4(255, 255, 255, 255, 32), "255.255.255.255/32"),
    (v4(240, 0, 0, 0, 4), "240.0.0.0/4"),
];

/// Blocked IPv6 ranges, in match order.
pub(crate) const BLOCKED_V6: &[(Ipv6Net, &str)] = &[
    (v6([0, 0, 0, 0, 0, 0, 0, 0], 128), "::/128"),
    (v6([0, 0, 0, 0, 0, 0, 0, 1], 128), "::1/128"),
    (v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7), "fc00::/7"),
    (v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10), "fe80::/10"),
    // Deprecated site-local (RFC 3879), still routed on some internal networks.
    (v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10), "fec0::/10"),
    // NAT64 local-use prefix (RFC 8215): its embedding position depends on a prefix length only
    // the local network knows, and it is never a public destination, so it is blocked whole.
    (v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48), "64:ff9b:1::/48"),
    (v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8), "ff00::/8"),
];

/// `::ffff:0:0/96` — IPv4-mapped: unwrap and apply the IPv4 rules.
const V4_MAPPED: Ipv6Net = v6([0, 0, 0, 0, 0, 0xffff, 0, 0], 96);
/// `64:ff9b::/96` — NAT64 well-known prefix: unwrap and apply the IPv4 rules.
const NAT64: Ipv6Net = v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96);
/// `::/96` — deprecated IPv4-compatible form: unwrap and apply the IPv4 rules.
const V4_COMPATIBLE: Ipv6Net = v6([0, 0, 0, 0, 0, 0, 0, 0], 96);
/// `::ffff:0:0:0/96` — IPv4-translated (SIIT, RFC 2765): unwrap the last 32 bits.
const V4_TRANSLATED: Ipv6Net = v6([0, 0, 0, 0, 0xffff, 0, 0, 0], 96);
/// `2002::/16` — 6to4 (RFC 3056): the IPv4 address is in bits 16..48.
const SIX_TO_FOUR: Ipv6Net = v6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16);
/// `2001::/32` — Teredo (RFC 4380): the server IPv4 is in bits 32..64, the client IPv4 is the
/// last 32 bits inverted.
const TEREDO: Ipv6Net = v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 32);

const fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(a, b, c, d), prefix)
}

const fn v6(segments: [u16; 8], prefix: u8) -> Ipv6Net {
    let [a, b, c, d, e, f, g, h] = segments;
    Ipv6Net::new_assert(Ipv6Addr::new(a, b, c, d, e, f, g, h), prefix)
}

/// Operator-supplied ranges from `security.network.extraBlockedCidrs`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ExtraRanges {
    pub(crate) v4: Vec<Ipv4Net>,
    pub(crate) v6: Vec<Ipv6Net>,
}

/// ISATAP interface identifier (RFC 5214 §6.1): `0000:5efe` or `0200:5efe` (the universal/local
/// bit set) in bits 64..96, followed by the IPv4 address, under any /64 prefix.
fn is_isatap(addr: Ipv6Addr) -> bool {
    let s = addr.segments();
    (s[4] == 0 || s[4] == 0x0200) && s[5] == 0x5efe
}

/// The IPv4 addresses embedded in an IPv4-mapped, NAT64, IPv4-compatible, IPv4-translated,
/// 6to4, Teredo or ISATAP IPv6 address (Teredo embeds two: server, then client). A translator,
/// relay or ISATAP router on the path may deliver to them, so each one is checked against the
/// IPv4 rules (ADR-017).
fn embedded_v4(addr: Ipv6Addr) -> [Option<Ipv4Addr>; 2] {
    let o = addr.octets();
    let last = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    if V4_MAPPED.contains(&addr)
        || NAT64.contains(&addr)
        || V4_COMPATIBLE.contains(&addr)
        || V4_TRANSLATED.contains(&addr)
        || is_isatap(addr)
    {
        return [Some(last), None];
    }
    if SIX_TO_FOUR.contains(&addr) {
        return [Some(Ipv4Addr::new(o[2], o[3], o[4], o[5])), None];
    }
    if TEREDO.contains(&addr) {
        let server = Ipv4Addr::new(o[4], o[5], o[6], o[7]);
        let client = Ipv4Addr::new(!o[12], !o[13], !o[14], !o[15]);
        return [Some(server), Some(client)];
    }
    [None, None]
}

fn classify_v4(addr: Ipv4Addr, extra: &ExtraRanges) -> Option<&'static str> {
    if let Some((_, rule)) = BLOCKED_V4.iter().find(|(net, _)| net.contains(&addr)) {
        return Some(rule);
    }
    if extra.v4.iter().any(|net| net.contains(&addr)) {
        return Some(EXTRA_BLOCKED_CIDRS);
    }
    None
}

/// The rule that blocks `addr`, or `None` when it is an allowed destination.
///
/// IPv6 order: the IPv6 table (so `::` and `::1` report their own rules), then any embedded
/// IPv4 address against the IPv4 rules, then operator extras.
pub(crate) fn classify(addr: IpAddr, extra: &ExtraRanges) -> Option<&'static str> {
    match addr {
        IpAddr::V4(v4) => classify_v4(v4, extra),
        IpAddr::V6(v6) => {
            if let Some((_, rule)) = BLOCKED_V6.iter().find(|(net, _)| net.contains(&v6)) {
                return Some(rule);
            }
            for inner in embedded_v4(v6).into_iter().flatten() {
                if let Some(rule) = classify_v4(inner, extra) {
                    return Some(rule);
                }
            }
            if extra.v6.iter().any(|net| net.contains(&v6)) {
                return Some(EXTRA_BLOCKED_CIDRS);
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_entries_are_network_addresses_matching_their_rule_text() {
        for (net, rule) in BLOCKED_V4 {
            assert_eq!(net.to_string(), *rule);
            assert_eq!(net.trunc(), *net, "{rule} has host bits set");
        }
        for (net, rule) in BLOCKED_V6 {
            assert_eq!(net.to_string(), *rule);
            assert_eq!(net.trunc(), *net, "{rule} has host bits set");
        }
    }

    #[test]
    fn embedded_v4_covers_mapped_nat64_compatible_translated_6to4_teredo_and_isatap() {
        let ip = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        let v4 = Ipv4Addr::new(127, 0, 0, 1);
        assert_eq!(embedded_v4(ip("::ffff:127.0.0.1")), [Some(v4), None]);
        assert_eq!(embedded_v4(ip("64:ff9b::7f00:1")), [Some(v4), None]);
        assert_eq!(embedded_v4(ip("::127.0.0.1")), [Some(v4), None]);
        assert_eq!(embedded_v4(ip("::ffff:0:127.0.0.1")), [Some(v4), None]);
        assert_eq!(embedded_v4(ip("2002:7f00:1::")), [Some(v4), None]);
        assert_eq!(
            embedded_v4(ip("2001:0:7f00:1:0:0:80ff:fffe")),
            [Some(v4), Some(v4)]
        );
        assert_eq!(embedded_v4(ip("2606:4700::1")), [None, None]);
        assert_eq!(embedded_v4(ip("64:ff9b::1:7f00:1")), [None, None]);
        assert_eq!(embedded_v4(ip("2001:db8::1")), [None, None]);
        assert_eq!(embedded_v4(ip("2001:db8::5efe:7f00:1")), [Some(v4), None]);
        assert_eq!(
            embedded_v4(ip("2001:db8::200:5efe:7f00:1")),
            [Some(v4), None]
        );
        assert_eq!(embedded_v4(ip("2001:db8::5efe:0:7f00:1")), [None, None]);
    }
}
