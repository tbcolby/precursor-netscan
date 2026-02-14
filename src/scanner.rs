//! Network scanner logic — subnet calculator, port reference, scan simulator.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// An IPv4 address as 4 octets.
#[derive(Clone, Copy)]
pub struct Ipv4 {
    pub octets: [u8; 4],
}

impl Ipv4 {
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self { octets: [a, b, c, d] }
    }

    pub fn to_u32(&self) -> u32 {
        (self.octets[0] as u32) << 24
            | (self.octets[1] as u32) << 16
            | (self.octets[2] as u32) << 8
            | (self.octets[3] as u32)
    }

    pub fn from_u32(v: u32) -> Self {
        Self {
            octets: [
                ((v >> 24) & 0xFF) as u8,
                ((v >> 16) & 0xFF) as u8,
                ((v >> 8) & 0xFF) as u8,
                (v & 0xFF) as u8,
            ],
        }
    }

    pub fn display(&self) -> String {
        format!("{}.{}.{}.{}", self.octets[0], self.octets[1], self.octets[2], self.octets[3])
    }
}

/// Subnet calculation results.
pub struct SubnetInfo {
    pub network: Ipv4,
    pub broadcast: Ipv4,
    pub first_host: Ipv4,
    pub last_host: Ipv4,
    pub mask: Ipv4,
    pub prefix: u8,
    pub host_count: u32,
    pub class: char,
}

/// Calculate subnet info from IP + CIDR prefix.
pub fn subnet_calc(ip: Ipv4, prefix: u8) -> SubnetInfo {
    let prefix = if prefix > 32 { 32 } else { prefix };
    let mask_u32 = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let ip_u32 = ip.to_u32();
    let network_u32 = ip_u32 & mask_u32;
    let broadcast_u32 = network_u32 | !mask_u32;
    let host_count = if prefix >= 31 { if prefix == 32 { 1 } else { 2 } } else { broadcast_u32 - network_u32 - 1 };
    let first_host = if prefix >= 31 { network_u32 } else { network_u32 + 1 };
    let last_host = if prefix >= 31 { broadcast_u32 } else { broadcast_u32 - 1 };

    let class = match ip.octets[0] {
        0..=127 => 'A',
        128..=191 => 'B',
        192..=223 => 'C',
        224..=239 => 'D',
        _ => 'E',
    };

    SubnetInfo {
        network: Ipv4::from_u32(network_u32),
        broadcast: Ipv4::from_u32(broadcast_u32),
        first_host: Ipv4::from_u32(first_host),
        last_host: Ipv4::from_u32(last_host),
        mask: Ipv4::from_u32(mask_u32),
        prefix,
        host_count,
        class,
    }
}

/// Parse "a.b.c.d" into Ipv4. Returns None on invalid input.
pub fn parse_ip(s: &str) -> Option<Ipv4> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return None; }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        let v: u32 = part.parse().ok()?;
        if v > 255 { return None; }
        octets[i] = v as u8;
    }
    Some(Ipv4 { octets })
}

/// Parse "a.b.c.d/n" into (Ipv4, prefix).
pub fn parse_cidr(s: &str) -> Option<(Ipv4, u8)> {
    if let Some(slash) = s.find('/') {
        let ip = parse_ip(&s[..slash])?;
        let prefix: u32 = s[slash + 1..].parse().ok()?;
        if prefix > 32 { return None; }
        Some((ip, prefix as u8))
    } else {
        let ip = parse_ip(s)?;
        // Default prefix based on class
        let prefix = match ip.octets[0] {
            0..=127 => 8,
            128..=191 => 16,
            _ => 24,
        };
        Some((ip, prefix))
    }
}

/// Well-known port entry.
pub struct PortEntry {
    pub port: u16,
    pub protocol: &'static str,
    pub service: &'static str,
}

/// Common well-known ports.
pub static PORTS: &[PortEntry] = &[
    PortEntry { port: 20, protocol: "TCP", service: "FTP Data" },
    PortEntry { port: 21, protocol: "TCP", service: "FTP Control" },
    PortEntry { port: 22, protocol: "TCP", service: "SSH" },
    PortEntry { port: 23, protocol: "TCP", service: "Telnet" },
    PortEntry { port: 25, protocol: "TCP", service: "SMTP" },
    PortEntry { port: 53, protocol: "TCP/UDP", service: "DNS" },
    PortEntry { port: 67, protocol: "UDP", service: "DHCP Server" },
    PortEntry { port: 68, protocol: "UDP", service: "DHCP Client" },
    PortEntry { port: 80, protocol: "TCP", service: "HTTP" },
    PortEntry { port: 110, protocol: "TCP", service: "POP3" },
    PortEntry { port: 123, protocol: "UDP", service: "NTP" },
    PortEntry { port: 143, protocol: "TCP", service: "IMAP" },
    PortEntry { port: 161, protocol: "UDP", service: "SNMP" },
    PortEntry { port: 443, protocol: "TCP", service: "HTTPS" },
    PortEntry { port: 445, protocol: "TCP", service: "SMB" },
    PortEntry { port: 993, protocol: "TCP", service: "IMAPS" },
    PortEntry { port: 995, protocol: "TCP", service: "POP3S" },
    PortEntry { port: 3306, protocol: "TCP", service: "MySQL" },
    PortEntry { port: 3389, protocol: "TCP", service: "RDP" },
    PortEntry { port: 5432, protocol: "TCP", service: "PostgreSQL" },
    PortEntry { port: 5900, protocol: "TCP", service: "VNC" },
    PortEntry { port: 6379, protocol: "TCP", service: "Redis" },
    PortEntry { port: 8080, protocol: "TCP", service: "HTTP Proxy" },
    PortEntry { port: 8443, protocol: "TCP", service: "HTTPS Alt" },
    PortEntry { port: 27017, protocol: "TCP", service: "MongoDB" },
];

/// Simulated scan result.
pub struct ScanResult {
    pub ip: Ipv4,
    pub open_ports: Vec<u16>,
    pub hostname: String,
}

/// Generate simulated scan results for a /24 subnet.
pub fn simulate_scan(network: Ipv4) -> Vec<ScanResult> {
    let mut results = Vec::new();
    let base = network.to_u32();

    // Gateway
    results.push(ScanResult {
        ip: Ipv4::from_u32(base + 1),
        open_ports: alloc::vec![22, 53, 80, 443],
        hostname: String::from("gateway.local"),
    });
    // DNS server
    results.push(ScanResult {
        ip: Ipv4::from_u32(base + 2),
        open_ports: alloc::vec![53, 953],
        hostname: String::from("dns.local"),
    });
    // Web server
    results.push(ScanResult {
        ip: Ipv4::from_u32(base + 10),
        open_ports: alloc::vec![22, 80, 443, 8080],
        hostname: String::from("web.local"),
    });
    // Database
    results.push(ScanResult {
        ip: Ipv4::from_u32(base + 20),
        open_ports: alloc::vec![22, 3306, 5432],
        hostname: String::from("db.local"),
    });
    // Printer
    results.push(ScanResult {
        ip: Ipv4::from_u32(base + 50),
        open_ports: alloc::vec![80, 443, 631, 9100],
        hostname: String::from("printer.local"),
    });
    // NAS
    results.push(ScanResult {
        ip: Ipv4::from_u32(base + 100),
        open_ports: alloc::vec![22, 80, 139, 445, 5900],
        hostname: String::from("nas.local"),
    });

    results
}

/// Look up a port in the well-known ports table.
pub fn lookup_port(port: u16) -> Option<&'static PortEntry> {
    PORTS.iter().find(|p| p.port == port)
}
