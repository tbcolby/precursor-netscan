//! Rate-limited TCP connect checks.
//!
//! What this does: for ONE host and at most [`MAX_PORTS`](crate::ports::MAX_PORTS) ports the
//! user typed, it attempts an ordinary TCP connection to each port in turn, with a timeout,
//! a pause between attempts, a cancel flag, and closes the connection as soon as it opens.
//! It sends no data. It does not sweep address ranges, ping, ARP, send raw packets or read
//! banners: Xous gives apps TCP/UDP sockets and DNS, nothing lower.

use crate::ip::{classify, parse_ip, AddrKind};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// How long one connection attempt may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Pause between two attempts, so a check is at most a few connections per second.
pub const GAP: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Ip(Ipv4Addr),
    Name(String),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Ip(ip) => write!(f, "{ip}"),
            Target::Name(n) => write!(f, "{n}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    Empty,
    /// Contains `:` (IPv6 or `host:port`).
    NotIpv4,
    /// Looks like a dotted number but is not a valid address (`999.1.1.1`, `1.2.3`, `010.1.1.1`).
    BadAddress,
    BadName,
    /// An address nothing can be connected to.
    NotConnectable(AddrKind),
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetError::Empty => write!(f, "Enter a host"),
            TargetError::NotIpv4 => write!(f, "IPv4 address or host name only (no : or port here)"),
            TargetError::BadAddress => write!(f, "Not a valid IPv4 address"),
            TargetError::BadName => write!(f, "Not a valid host name"),
            TargetError::NotConnectable(k) => write!(f, "Can't connect to a {} address", k.name()),
        }
    }
}

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Parse an IPv4 address or host name. Refuses addresses that cannot be connected to.
pub fn parse_target(s: &str) -> Result<Target, TargetError> {
    let s = s.trim().trim_end_matches('.');
    if s.is_empty() {
        return Err(TargetError::Empty);
    }
    if s.contains(':') {
        return Err(TargetError::NotIpv4);
    }
    if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let ip = parse_ip(s).ok_or(TargetError::BadAddress)?;
        let kind = classify(ip);
        return if kind.is_connectable() { Ok(Target::Ip(ip)) } else { Err(TargetError::NotConnectable(kind)) };
    }
    let labels: Vec<&str> = s.split('.').collect();
    // The last label (the TLD, or the whole name for `printer`) must contain a letter, so
    // numeric near-misses like `192.168.1.1-50` or `example.123` are not looked up as names.
    let last_has_letter = labels.last().is_some_and(|l| l.bytes().any(|b| b.is_ascii_alphabetic()));
    if s.len() > 253 || labels.iter().any(|l| !valid_label(l)) || !last_has_letter {
        return Err(TargetError::BadName);
    }
    Ok(Target::Name(s.to_ascii_lowercase()))
}

/// One check: a target and its ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub target: Target,
    pub ports: Vec<u16>,
}

impl Plan {
    /// Longest the check can take, in seconds, rounded up (name lookup not included).
    pub fn worst_case_secs(&self) -> u64 {
        let n = self.ports.len() as u64;
        let ms = n * CONNECT_TIMEOUT.as_millis() as u64 + n.saturating_sub(1) * GAP.as_millis() as u64;
        ms.div_ceil(1000)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The connection was accepted.
    Open,
    /// The host answered and refused: nothing is listening.
    Closed,
    /// No answer within the timeout: filtered, host down, or too slow.
    NoReply,
    /// The network said there is no route.
    Unreachable,
    /// Some other error.
    Error,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::Closed => "closed",
            Status::NoReply => "no reply",
            Status::Unreachable => "unreachable",
            Status::Error => "error",
        }
    }

    /// Compact code for an IPC scalar.
    pub fn code(self) -> usize {
        match self {
            Status::Open => 0,
            Status::Closed => 1,
            Status::NoReply => 2,
            Status::Unreachable => 3,
            Status::Error => 4,
        }
    }

    pub fn from_code(c: usize) -> Status {
        match c {
            0 => Status::Open,
            1 => Status::Closed,
            2 => Status::NoReply,
            3 => Status::Unreachable,
            _ => Status::Error,
        }
    }
}

/// Map a connect error to a status.
pub fn classify_error(kind: ErrorKind) -> Status {
    match kind {
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => Status::Closed,
        ErrorKind::TimedOut | ErrorKind::WouldBlock => Status::NoReply,
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable | ErrorKind::NetworkDown | ErrorKind::AddrNotAvailable => {
            Status::Unreachable
        }
        _ => Status::Error,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortResult {
    pub port: u16,
    pub status: Status,
}

/// Progress from [`run_check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The name resolved to this address (sent first, for names).
    Resolved(Ipv4Addr),
    /// The name did not resolve, or resolved to something that can't be connected to.
    ResolveFailed,
    Port(PortResult),
    /// Finished; `cancelled` if the user stopped it early.
    Done { cancelled: bool },
}

/// The network side, so the check logic can be tested without a network.
pub trait Connector {
    fn resolve(&mut self, name: &str) -> Result<Ipv4Addr, ErrorKind>;
    /// `Ok(())` if the connection was accepted (and has been closed again).
    fn connect(&mut self, ip: Ipv4Addr, port: u16, timeout: Duration) -> Result<(), ErrorKind>;
    fn pause(&mut self, d: Duration);
}

/// Run a check. `cancelled` is polled before every attempt and after every pause.
pub fn run_check(plan: &Plan, conn: &mut dyn Connector, cancelled: &dyn Fn() -> bool, on_event: &mut dyn FnMut(Event)) {
    let ip = match &plan.target {
        Target::Ip(ip) => *ip,
        Target::Name(n) => match conn.resolve(n) {
            Ok(ip) if classify(ip).is_connectable() => {
                on_event(Event::Resolved(ip));
                ip
            }
            _ => {
                on_event(Event::ResolveFailed);
                return;
            }
        },
    };
    for (i, &port) in plan.ports.iter().enumerate() {
        if i > 0 {
            conn.pause(GAP);
        }
        if cancelled() {
            on_event(Event::Done { cancelled: true });
            return;
        }
        let status = match conn.connect(ip, port, CONNECT_TIMEOUT) {
            Ok(()) => Status::Open,
            Err(kind) => classify_error(kind),
        };
        on_event(Event::Port(PortResult { port, status }));
    }
    on_event(Event::Done { cancelled: false });
}

/// Real sockets through `std::net` (the Xous network stack on the device).
pub struct StdConnector;

impl Connector for StdConnector {
    fn resolve(&mut self, name: &str) -> Result<Ipv4Addr, ErrorKind> {
        let addrs = (name, 0u16).to_socket_addrs().map_err(|e| e.kind())?;
        for a in addrs {
            if let SocketAddr::V4(v4) = a {
                return Ok(*v4.ip());
            }
        }
        Err(ErrorKind::NotFound)
    }

    fn connect(&mut self, ip: Ipv4Addr, port: u16, timeout: Duration) -> Result<(), ErrorKind> {
        match TcpStream::connect_timeout(&SocketAddr::new(ip.into(), port), timeout) {
            Ok(stream) => {
                // Close at once; nothing is sent.
                stream.shutdown(std::net::Shutdown::Both).ok();
                Ok(())
            }
            Err(e) => Err(e.kind()),
        }
    }

    fn pause(&mut self, d: Duration) { std::thread::sleep(d); }
}
