//! Well-known port table and port-list parsing.

/// Most ports one check may contain.
pub const MAX_PORTS: usize = 16;

pub struct PortEntry {
    pub port: u16,
    pub protocol: &'static str,
    pub service: &'static str,
}

/// Common well-known ports. Every port the app names in a result is here.
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
    PortEntry { port: 139, protocol: "TCP", service: "NetBIOS" },
    PortEntry { port: 143, protocol: "TCP", service: "IMAP" },
    PortEntry { port: 161, protocol: "UDP", service: "SNMP" },
    PortEntry { port: 443, protocol: "TCP", service: "HTTPS" },
    PortEntry { port: 445, protocol: "TCP", service: "SMB" },
    PortEntry { port: 631, protocol: "TCP", service: "IPP (printing)" },
    PortEntry { port: 953, protocol: "TCP", service: "BIND control" },
    PortEntry { port: 993, protocol: "TCP", service: "IMAPS" },
    PortEntry { port: 995, protocol: "TCP", service: "POP3S" },
    PortEntry { port: 3306, protocol: "TCP", service: "MySQL" },
    PortEntry { port: 3389, protocol: "TCP", service: "RDP" },
    PortEntry { port: 5432, protocol: "TCP", service: "PostgreSQL" },
    PortEntry { port: 5900, protocol: "TCP", service: "VNC" },
    PortEntry { port: 6379, protocol: "TCP", service: "Redis" },
    PortEntry { port: 8080, protocol: "TCP", service: "HTTP Proxy" },
    PortEntry { port: 8443, protocol: "TCP", service: "HTTPS Alt" },
    PortEntry { port: 9100, protocol: "TCP", service: "JetDirect (printing)" },
    PortEntry { port: 27017, protocol: "TCP", service: "MongoDB" },
];

pub fn lookup_port(port: u16) -> Option<&'static PortEntry> { PORTS.iter().find(|p| p.port == port) }

/// Service name, or an empty string for a port not in the table.
pub fn service_name(port: u16) -> &'static str { lookup_port(port).map(|p| p.service).unwrap_or("") }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortsError {
    Empty,
    /// Not a number (including signs, spaces inside a number, hex).
    BadNumber,
    /// 0 or above 65535.
    OutOfRange,
    /// `80-22`.
    BackwardsRange,
    /// More than [`MAX_PORTS`] distinct ports.
    TooMany,
}

impl std::fmt::Display for PortsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortsError::Empty => write!(f, "Enter at least one port"),
            PortsError::BadNumber => write!(f, "Ports are numbers, like 22,80,8000-8003"),
            PortsError::OutOfRange => write!(f, "Ports are 1 to 65535"),
            PortsError::BackwardsRange => write!(f, "Range start is above its end"),
            PortsError::TooMany => write!(f, "At most {MAX_PORTS} ports per check"),
        }
    }
}

fn port_number(s: &str) -> Result<u32, PortsError> {
    if s.is_empty() || s.len() > 6 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PortsError::BadNumber);
    }
    let n: u32 = s.parse().map_err(|_| PortsError::BadNumber)?;
    if !(1..=65535).contains(&n) {
        return Err(PortsError::OutOfRange);
    }
    Ok(n)
}

/// Parse `22,80,443` / `22 80` / `8000-8003`. Duplicates are dropped, order is kept, and
/// the total is capped at [`MAX_PORTS`] (a range is expanded before the cap is applied, so
/// `1-65535` is refused rather than started).
pub fn parse_ports(s: &str) -> Result<Vec<u16>, PortsError> {
    let mut out: Vec<u16> = Vec::new();
    let mut any = false;
    for tok in s.split([',', ' ']).filter(|t| !t.is_empty()) {
        any = true;
        let (lo, hi) = match tok.split_once('-') {
            Some((a, b)) => (port_number(a)?, port_number(b)?),
            None => {
                let n = port_number(tok)?;
                (n, n)
            }
        };
        if lo > hi {
            return Err(PortsError::BackwardsRange);
        }
        if (hi - lo) as usize >= MAX_PORTS {
            return Err(PortsError::TooMany);
        }
        for p in lo..=hi {
            let p = p as u16;
            if !out.contains(&p) {
                if out.len() == MAX_PORTS {
                    return Err(PortsError::TooMany);
                }
                out.push(p);
            }
        }
    }
    if any {
        Ok(out)
    } else {
        Err(PortsError::Empty)
    }
}
