//! IPv4 subnet maths and address classification.

use std::net::Ipv4Addr;

/// What kind of address this is (the more specific kind wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrKind {
    /// 0.0.0.0/8
    ThisNetwork,
    Loopback,
    /// 10/8, 172.16/12, 192.168/16
    Private,
    /// 169.254/16
    LinkLocal,
    /// 100.64/10 carrier-grade NAT
    SharedSpace,
    /// 192.0.2/24, 198.51.100/24, 203.0.113/24
    Documentation,
    Multicast,
    /// 255.255.255.255
    Broadcast,
    /// 240/4
    Reserved,
    Public,
}

impl AddrKind {
    pub fn name(self) -> &'static str {
        match self {
            AddrKind::ThisNetwork => "this network (0.x)",
            AddrKind::Loopback => "loopback",
            AddrKind::Private => "private (RFC 1918)",
            AddrKind::LinkLocal => "link-local",
            AddrKind::SharedSpace => "shared space (CGNAT)",
            AddrKind::Documentation => "documentation range",
            AddrKind::Multicast => "multicast",
            AddrKind::Broadcast => "broadcast",
            AddrKind::Reserved => "reserved (class E)",
            AddrKind::Public => "public internet",
        }
    }

    /// Can a TCP connection be made to this kind of address at all?
    pub fn is_connectable(self) -> bool {
        !matches!(self, AddrKind::ThisNetwork | AddrKind::Multicast | AddrKind::Broadcast | AddrKind::Reserved)
    }
}

pub fn classify(ip: Ipv4Addr) -> AddrKind {
    let o = ip.octets();
    if o[0] == 0 {
        AddrKind::ThisNetwork
    } else if ip.is_loopback() {
        AddrKind::Loopback
    } else if ip.is_private() {
        AddrKind::Private
    } else if ip.is_link_local() {
        AddrKind::LinkLocal
    } else if o[0] == 100 && (64..=127).contains(&o[1]) {
        AddrKind::SharedSpace
    } else if ip.is_documentation() {
        AddrKind::Documentation
    } else if ip.is_multicast() {
        AddrKind::Multicast
    } else if ip.is_broadcast() {
        AddrKind::Broadcast
    } else if o[0] >= 240 {
        AddrKind::Reserved
    } else {
        AddrKind::Public
    }
}

/// Historical class letter of the first octet.
pub fn class_letter(ip: Ipv4Addr) -> char {
    match ip.octets()[0] {
        0..=127 => 'A',
        128..=191 => 'B',
        192..=223 => 'C',
        224..=239 => 'D',
        _ => 'E',
    }
}

/// Subnet calculation results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubnetInfo {
    pub address: Ipv4Addr,
    pub network: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub first_host: Ipv4Addr,
    pub last_host: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub wildcard: Ipv4Addr,
    pub prefix: u8,
    /// Usable host addresses: 2^(32-p) - 2, but 2 for /31 (RFC 3021) and 1 for /32.
    pub host_count: u32,
    pub class: char,
    pub kind: AddrKind,
}

/// Calculate subnet info. A prefix over 32 is clamped to 32.
pub fn subnet_calc(ip: Ipv4Addr, prefix: u8) -> SubnetInfo {
    let prefix = prefix.min(32);
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let addr = u32::from(ip);
    let network = addr & mask;
    let broadcast = network | !mask;
    let (first, last, hosts) = match prefix {
        32 => (network, network, 1),
        31 => (network, broadcast, 2),
        // At least /30 here, so the subtractions cannot underflow; /0 gives 2^32 - 2.
        _ => (network + 1, broadcast - 1, broadcast - network - 1),
    };
    SubnetInfo {
        address: ip,
        network: Ipv4Addr::from(network),
        broadcast: Ipv4Addr::from(broadcast),
        first_host: Ipv4Addr::from(first),
        last_host: Ipv4Addr::from(last),
        mask: Ipv4Addr::from(mask),
        wildcard: Ipv4Addr::from(!mask),
        prefix,
        host_count: hosts,
        class: class_letter(ip),
        kind: classify(ip),
    }
}

impl SubnetInfo {
    /// Is `ip` inside this subnet (network and broadcast addresses included)?
    pub fn contains(&self, ip: Ipv4Addr) -> bool { u32::from(ip) & u32::from(self.mask) == u32::from(self.network) }
}

/// Parse `a.b.c.d`: four decimal octets, no leading zeros, nothing else.
pub fn parse_ip(s: &str) -> Option<Ipv4Addr> {
    let s = s.trim();
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        o[i] = p.parse::<u16>().ok().filter(|&v| v <= 255)? as u8;
    }
    Some(Ipv4Addr::from(o))
}

/// Parse `a.b.c.d/n`. Without `/n` the classful prefix of the first octet is used
/// (A /8, B /16, otherwise /24); the second value tells whether that default was used.
pub fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8, bool)> {
    let s = s.trim();
    match s.split_once('/') {
        Some((a, p)) => {
            if p.is_empty() || p.len() > 2 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let prefix: u8 = p.parse().ok()?;
            (prefix <= 32).then_some((parse_ip(a)?, prefix, false))
        }
        None => {
            let ip = parse_ip(s)?;
            let prefix = match ip.octets()[0] {
                0..=127 => 8,
                128..=191 => 16,
                _ => 24,
            };
            Some((ip, prefix, true))
        }
    }
}

/// Dotted mask for a prefix, e.g. 24 -> 255.255.255.0.
pub fn mask_for(prefix: u8) -> Ipv4Addr { subnet_calc(Ipv4Addr::UNSPECIFIED, prefix).mask }
