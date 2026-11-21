use crate::app::{Action, NetApp, Screen, COMMON_PORTS};
use crate::check::*;
use crate::ip::*;
use crate::ports::*;
use precursor_appkit_core::keys::Key;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, TcpListener};
use std::time::Duration;

fn ip(s: &str) -> Ipv4Addr { parse_ip(s).unwrap() }

// ------------------------------------------------------------ subnet maths

#[test]
fn parse_ip_valid_and_invalid() {
    assert_eq!(parse_ip("192.168.1.10"), Some(Ipv4Addr::new(192, 168, 1, 10)));
    assert_eq!(parse_ip(" 10.0.0.1 "), Some(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(parse_ip("0.0.0.0"), Some(Ipv4Addr::UNSPECIFIED));
    assert_eq!(parse_ip("255.255.255.255"), Some(Ipv4Addr::BROADCAST));
    for bad in ["", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.-4", "a.b.c.d", "1..2.3", "1.2.3.", "+1.2.3.4", "1.2.3.4 5", "1,2,3,4", "::1"] {
        assert_eq!(parse_ip(bad), None, "{bad}");
    }
}

#[test]
fn parse_ip_rejects_leading_zeros() {
    // Audit: `010.1.1.1` was accepted as 10.1.1.1 (some stacks read it as octal).
    assert_eq!(parse_ip("010.1.1.1"), None);
    assert_eq!(parse_ip("1.2.3.04"), None);
    assert_eq!(parse_ip("00.0.0.0"), None);
    assert_eq!(parse_ip("0.0.0.0"), Some(Ipv4Addr::UNSPECIFIED));
}

#[test]
fn parse_cidr_forms() {
    assert_eq!(parse_cidr("192.168.1.0/24"), Some((ip("192.168.1.0"), 24, false)));
    assert_eq!(parse_cidr("10.1.2.3/0"), Some((ip("10.1.2.3"), 0, false)));
    assert_eq!(parse_cidr("10.1.2.3/32"), Some((ip("10.1.2.3"), 32, false)));
    // Without a prefix: classful default, flagged.
    assert_eq!(parse_cidr("10.1.2.3"), Some((ip("10.1.2.3"), 8, true)));
    assert_eq!(parse_cidr("172.16.0.1"), Some((ip("172.16.0.1"), 16, true)));
    assert_eq!(parse_cidr("192.168.1.1"), Some((ip("192.168.1.1"), 24, true)));
    for bad in ["10.0.0.0/33", "10.0.0.0/", "10.0.0.0/-1", "10.0.0.0/+8", "10.0.0.0/x", "10.0.0.0/8/8", "/24", "10.0.0/24", "10.0.0.0/123"] {
        assert_eq!(parse_cidr(bad), None, "{bad}");
    }
}

#[test]
fn subnet_standard_prefixes() {
    let s = subnet_calc(ip("192.168.1.77"), 24);
    assert_eq!(s.network, ip("192.168.1.0"));
    assert_eq!(s.broadcast, ip("192.168.1.255"));
    assert_eq!(s.mask, ip("255.255.255.0"));
    assert_eq!(s.wildcard, ip("0.0.0.255"));
    assert_eq!(s.first_host, ip("192.168.1.1"));
    assert_eq!(s.last_host, ip("192.168.1.254"));
    assert_eq!(s.host_count, 254);
    assert_eq!(s.class, 'C');
    assert_eq!(s.kind, AddrKind::Private);

    let s = subnet_calc(ip("10.20.30.40"), 12);
    assert_eq!((s.network, s.broadcast), (ip("10.16.0.0"), ip("10.31.255.255")));
    assert_eq!(s.host_count, (1 << 20) - 2);

    let s = subnet_calc(ip("172.16.5.9"), 20);
    assert_eq!(s.network, ip("172.16.0.0"));
    assert_eq!(s.last_host, ip("172.16.15.254"));
}

#[test]
fn subnet_edge_prefixes() {
    // /0
    let s = subnet_calc(ip("8.8.8.8"), 0);
    assert_eq!((s.network, s.broadcast, s.mask), (ip("0.0.0.0"), ip("255.255.255.255"), ip("0.0.0.0")));
    assert_eq!(s.host_count, u32::MAX - 1);
    assert_eq!((s.first_host, s.last_host), (ip("0.0.0.1"), ip("255.255.255.254")));
    // /30
    let s = subnet_calc(ip("10.0.0.5"), 30);
    assert_eq!((s.network, s.broadcast), (ip("10.0.0.4"), ip("10.0.0.7")));
    assert_eq!((s.first_host, s.last_host, s.host_count), (ip("10.0.0.5"), ip("10.0.0.6"), 2));
    // /31 (RFC 3021: both addresses are hosts)
    let s = subnet_calc(ip("10.0.0.5"), 31);
    assert_eq!((s.first_host, s.last_host, s.host_count), (ip("10.0.0.4"), ip("10.0.0.5"), 2));
    // /32
    let s = subnet_calc(ip("10.0.0.5"), 32);
    assert_eq!((s.network, s.broadcast, s.first_host, s.last_host, s.host_count), (ip("10.0.0.5"), ip("10.0.0.5"), ip("10.0.0.5"), ip("10.0.0.5"), 1));
    // clamp
    assert_eq!(subnet_calc(ip("10.0.0.5"), 99).prefix, 32);
    // top of the address space (the old code overflowed on 255.255.255.255/32 with `base + 1`)
    let s = subnet_calc(ip("255.255.255.255"), 32);
    assert_eq!(s.host_count, 1);
    let s = subnet_calc(ip("255.255.255.254"), 31);
    assert_eq!(s.last_host, ip("255.255.255.255"));
    let s = subnet_calc(ip("255.255.255.255"), 30);
    assert_eq!((s.first_host, s.last_host), (ip("255.255.255.253"), ip("255.255.255.254")));
}

#[test]
fn every_prefix_is_consistent() {
    for p in 0..=32u8 {
        let s = subnet_calc(ip("203.0.113.77"), p);
        assert_eq!(u32::from(s.mask).count_ones(), p as u32);
        assert_eq!(u32::from(s.wildcard), !u32::from(s.mask));
        assert!(s.contains(ip("203.0.113.77")));
        assert!(s.contains(s.first_host) && s.contains(s.last_host));
        assert_eq!(u64::from(u32::from(s.broadcast)) - u64::from(u32::from(s.network)) + 1, 1u64 << (32 - p));
    }
}

#[test]
fn subnet_contains() {
    let s = subnet_calc(ip("192.168.1.0"), 24);
    assert!(s.contains(ip("192.168.1.200")));
    assert!(!s.contains(ip("192.168.2.1")));
    assert!(!s.contains(ip("10.0.0.5")));
}

#[test]
fn classification() {
    use AddrKind::*;
    for (a, k) in [
        ("0.1.2.3", ThisNetwork),
        ("127.0.0.1", Loopback),
        ("10.0.0.1", Private),
        ("172.16.0.1", Private),
        ("172.31.255.255", Private),
        ("172.32.0.1", Public),
        ("192.168.0.1", Private),
        ("169.254.1.1", LinkLocal),
        ("100.64.0.1", SharedSpace),
        ("100.127.255.255", SharedSpace),
        ("100.128.0.1", Public),
        ("192.0.2.5", Documentation),
        ("198.51.100.5", Documentation),
        ("203.0.113.5", Documentation),
        ("224.0.0.1", Multicast),
        ("239.255.255.255", Multicast),
        ("255.255.255.255", Broadcast),
        ("240.0.0.1", Reserved),
        ("8.8.8.8", Public),
    ] {
        assert_eq!(classify(ip(a)), k, "{a}");
    }
    // Audit: 8.8.8.8 and 127.x were just "class A" with no note.
    assert_eq!(class_letter(ip("8.8.8.8")), 'A');
    assert_eq!(class_letter(ip("192.168.1.1")), 'C');
    assert_eq!(class_letter(ip("224.0.0.1")), 'D');
    assert_eq!(class_letter(ip("250.0.0.1")), 'E');
    assert!(!Multicast.is_connectable() && !Reserved.is_connectable() && !Broadcast.is_connectable() && !ThisNetwork.is_connectable());
    assert!(Loopback.is_connectable() && Private.is_connectable() && Public.is_connectable());
}

#[test]
fn mask_for_prefix() {
    assert_eq!(mask_for(24), ip("255.255.255.0"));
    assert_eq!(mask_for(0), ip("0.0.0.0"));
    assert_eq!(mask_for(32), ip("255.255.255.255"));
    assert_eq!(mask_for(19), ip("255.255.224.0"));
}

// ------------------------------------------------------------ ports

#[test]
fn port_lists() {
    assert_eq!(parse_ports("22,80,443"), Ok(vec![22, 80, 443]));
    assert_eq!(parse_ports("22 80  443"), Ok(vec![22, 80, 443]));
    assert_eq!(parse_ports(" 80 , 22 "), Ok(vec![80, 22]));
    assert_eq!(parse_ports("8000-8003"), Ok(vec![8000, 8001, 8002, 8003]));
    assert_eq!(parse_ports("80,80,80"), Ok(vec![80]));
    assert_eq!(parse_ports("22,20-23"), Ok(vec![22, 20, 21, 23]));
    assert_eq!(parse_ports("1"), Ok(vec![1]));
    assert_eq!(parse_ports("65535"), Ok(vec![65535]));
    assert_eq!(parse_ports(""), Err(PortsError::Empty));
    assert_eq!(parse_ports(" , "), Err(PortsError::Empty));
    assert_eq!(parse_ports("0"), Err(PortsError::OutOfRange));
    assert_eq!(parse_ports("65536"), Err(PortsError::OutOfRange));
    assert_eq!(parse_ports("80-22"), Err(PortsError::BackwardsRange));
    assert_eq!(parse_ports("abc"), Err(PortsError::BadNumber));
    assert_eq!(parse_ports("+80"), Err(PortsError::BadNumber));
    assert_eq!(parse_ports("-80"), Err(PortsError::BadNumber));
    assert_eq!(parse_ports("80-"), Err(PortsError::BadNumber));
    assert_eq!(parse_ports("0x50"), Err(PortsError::BadNumber));
    assert_eq!(parse_ports("1234567"), Err(PortsError::BadNumber));
}

#[test]
fn port_count_is_capped() {
    // A check is at most MAX_PORTS connections; a wide range is refused, not started.
    assert_eq!(MAX_PORTS, 16);
    assert_eq!(parse_ports("1-16").unwrap().len(), 16);
    assert_eq!(parse_ports("1-17"), Err(PortsError::TooMany));
    assert_eq!(parse_ports("1-65535"), Err(PortsError::TooMany));
    let many = (1..=17).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    assert_eq!(parse_ports(&many), Err(PortsError::TooMany));
    // Duplicates don't count twice.
    let dup = (1..=16).chain(1..=16).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    assert_eq!(parse_ports(&dup).unwrap().len(), 16);
}

#[test]
fn port_table_is_complete_and_sorted() {
    // Audit: the (fake) results used 139, 631, 953 and 9100 which weren't in the table.
    for p in [139, 631, 953, 9100] {
        assert!(lookup_port(p).is_some(), "{p}");
    }
    assert!(PORTS.windows(2).all(|w| w[0].port < w[1].port));
    assert_eq!(service_name(22), "SSH");
    assert_eq!(service_name(12345), "");
}

// ------------------------------------------------------------ targets

#[test]
fn targets() {
    assert_eq!(parse_target("192.168.1.10"), Ok(Target::Ip(ip("192.168.1.10"))));
    assert_eq!(parse_target(" 127.0.0.1 "), Ok(Target::Ip(Ipv4Addr::LOCALHOST)));
    assert_eq!(parse_target("example.com"), Ok(Target::Name("example.com".into())));
    assert_eq!(parse_target("Example.COM."), Ok(Target::Name("example.com".into())));
    assert_eq!(parse_target("my-host"), Ok(Target::Name("my-host".into())));
    assert_eq!(parse_target("a1.b2.example.org"), Ok(Target::Name("a1.b2.example.org".into())));
    assert_eq!(parse_target(""), Err(TargetError::Empty));
    assert_eq!(parse_target("   "), Err(TargetError::Empty));
    assert_eq!(parse_target("::1"), Err(TargetError::NotIpv4));
    assert_eq!(parse_target("example.com:80"), Err(TargetError::NotIpv4));
    assert_eq!(parse_target("999.1.1.1"), Err(TargetError::BadAddress));
    assert_eq!(parse_target("1.2.3"), Err(TargetError::BadAddress));
    assert_eq!(parse_target("010.1.1.1"), Err(TargetError::BadAddress));
    assert_eq!(parse_target("2130706433"), Err(TargetError::BadAddress));
    assert_eq!(parse_target("-bad.com"), Err(TargetError::BadName));
    assert_eq!(parse_target("bad-.com"), Err(TargetError::BadName));
    assert_eq!(parse_target("a..b"), Err(TargetError::BadName));
    assert_eq!(parse_target("under_score.com"), Err(TargetError::BadName));
    assert_eq!(parse_target("exa mple.com"), Err(TargetError::BadName));
    assert_eq!(parse_target("example.123"), Err(TargetError::BadName));
    assert_eq!(parse_target("é.com"), Err(TargetError::BadName));
    assert_eq!(parse_target(&format!("{}.com", "a".repeat(64))), Err(TargetError::BadName));
    assert_eq!(parse_target(&"a.".repeat(130)), Err(TargetError::BadName));
}

#[test]
fn unconnectable_targets_are_refused() {
    assert_eq!(parse_target("0.0.0.0"), Err(TargetError::NotConnectable(AddrKind::ThisNetwork)));
    assert_eq!(parse_target("224.0.0.251"), Err(TargetError::NotConnectable(AddrKind::Multicast)));
    assert_eq!(parse_target("255.255.255.255"), Err(TargetError::NotConnectable(AddrKind::Broadcast)));
    assert_eq!(parse_target("250.1.1.1"), Err(TargetError::NotConnectable(AddrKind::Reserved)));
    // Subnet ranges are not targets at all.
    assert!(parse_target("192.168.1.0/24").is_err());
    assert!(parse_target("192.168.1.1-50").is_err());
}

// ------------------------------------------------------------ the check runner

#[derive(Default)]
struct Fake {
    calls: RefCell<Vec<String>>,
    open: Vec<u16>,
    resolve_to: Option<Ipv4Addr>,
}

impl Connector for Fake {
    fn resolve(&mut self, name: &str) -> Result<Ipv4Addr, ErrorKind> {
        self.calls.borrow_mut().push(format!("resolve {name}"));
        self.resolve_to.ok_or(ErrorKind::NotFound)
    }
    fn connect(&mut self, ip: Ipv4Addr, port: u16, timeout: Duration) -> Result<(), ErrorKind> {
        self.calls.borrow_mut().push(format!("connect {ip}:{port} {}ms", timeout.as_millis()));
        match port {
            p if self.open.contains(&p) => Ok(()),
            1 => Err(ErrorKind::TimedOut),
            2 => Err(ErrorKind::HostUnreachable),
            3 => Err(ErrorKind::PermissionDenied),
            _ => Err(ErrorKind::ConnectionRefused),
        }
    }
    fn pause(&mut self, d: Duration) { self.calls.borrow_mut().push(format!("pause {}ms", d.as_millis())); }
}

fn run(plan: &Plan, fake: &mut Fake, cancel_after: Option<usize>) -> Vec<Event> {
    let mut events = Vec::new();
    let polls = RefCell::new(0usize);
    let cancelled = || {
        let mut p = polls.borrow_mut();
        *p += 1;
        cancel_after.is_some_and(|n| *p > n)
    };
    run_check(plan, fake, &cancelled, &mut |e| events.push(e));
    events
}

#[test]
fn check_runs_ports_in_order_with_timeout_and_gaps() {
    let plan = Plan { target: Target::Ip(ip("192.168.1.10")), ports: vec![22, 80, 443] };
    let mut f = Fake { open: vec![22, 443], ..Default::default() };
    let ev = run(&plan, &mut f, None);
    assert_eq!(
        ev,
        vec![
            Event::Port(PortResult { port: 22, status: Status::Open }),
            Event::Port(PortResult { port: 80, status: Status::Closed }),
            Event::Port(PortResult { port: 443, status: Status::Open }),
            Event::Done { cancelled: false },
        ]
    );
    // Strictly one connection at a time, each with the 2 s timeout, 250 ms between them,
    // and no pause before the first or after the last.
    assert_eq!(
        *f.calls.borrow(),
        vec![
            "connect 192.168.1.10:22 2000ms",
            "pause 250ms",
            "connect 192.168.1.10:80 2000ms",
            "pause 250ms",
            "connect 192.168.1.10:443 2000ms",
        ]
    );
}

#[test]
fn check_statuses_from_errors() {
    let plan = Plan { target: Target::Ip(ip("10.0.0.2")), ports: vec![1, 2, 3, 4] };
    let ev = run(&plan, &mut Fake::default(), None);
    let st: Vec<Status> = ev
        .iter()
        .filter_map(|e| if let Event::Port(r) = e { Some(r.status) } else { None })
        .collect();
    assert_eq!(st, vec![Status::NoReply, Status::Unreachable, Status::Error, Status::Closed]);
}

#[test]
fn cancel_stops_before_the_next_connection() {
    let plan = Plan { target: Target::Ip(ip("10.0.0.2")), ports: vec![20, 21, 22, 23, 24] };
    let mut f = Fake::default();
    let ev = run(&plan, &mut f, Some(2)); // allows two attempts, cancelled on the third poll
    let attempts = f.calls.borrow().iter().filter(|c| c.starts_with("connect")).count();
    assert_eq!(attempts, 2);
    assert_eq!(ev.last(), Some(&Event::Done { cancelled: true }));
    assert_eq!(ev.iter().filter(|e| matches!(e, Event::Port(_))).count(), 2);
    // Cancelled before the first attempt: nothing is connected at all.
    let mut f = Fake::default();
    let ev = run(&plan, &mut f, Some(0));
    assert_eq!(f.calls.borrow().len(), 0);
    assert_eq!(ev, vec![Event::Done { cancelled: true }]);
}

#[test]
fn names_are_resolved_first_and_the_result_is_checked() {
    let plan = Plan { target: Target::Name("printer.local".into()), ports: vec![631] };
    let mut f = Fake { open: vec![631], resolve_to: Some(ip("192.168.1.50")), ..Default::default() };
    let ev = run(&plan, &mut f, None);
    assert_eq!(ev[0], Event::Resolved(ip("192.168.1.50")));
    assert_eq!(f.calls.borrow()[0], "resolve printer.local");
    assert_eq!(f.calls.borrow()[1], "connect 192.168.1.50:631 2000ms");
    // Lookup failure: no connection is attempted.
    let mut f = Fake::default();
    let ev = run(&plan, &mut f, None);
    assert_eq!(ev, vec![Event::ResolveFailed]);
    assert_eq!(f.calls.borrow().len(), 1);
    // A name that resolves to something unconnectable (multicast) is refused too.
    let mut f = Fake { resolve_to: Some(ip("224.0.0.1")), ..Default::default() };
    assert_eq!(run(&plan, &mut f, None), vec![Event::ResolveFailed]);
    assert_eq!(f.calls.borrow().len(), 1);
}

#[test]
fn worst_case_time() {
    let p = |n: usize| Plan { target: Target::Ip(ip("10.0.0.1")), ports: (1..=n as u16).collect() };
    assert_eq!(p(1).worst_case_secs(), 2);
    assert_eq!(p(3).worst_case_secs(), 7); // 3*2000 + 2*250 = 6500 ms
    assert_eq!(p(16).worst_case_secs(), 36); // 32000 + 3750 = 35750 ms
}

#[test]
fn error_classification() {
    assert_eq!(classify_error(ErrorKind::ConnectionRefused), Status::Closed);
    assert_eq!(classify_error(ErrorKind::TimedOut), Status::NoReply);
    assert_eq!(classify_error(ErrorKind::WouldBlock), Status::NoReply);
    assert_eq!(classify_error(ErrorKind::HostUnreachable), Status::Unreachable);
    assert_eq!(classify_error(ErrorKind::NetworkUnreachable), Status::Unreachable);
    assert_eq!(classify_error(ErrorKind::Other), Status::Error);
    for s in [Status::Open, Status::Closed, Status::NoReply, Status::Unreachable, Status::Error] {
        assert_eq!(Status::from_code(s.code()), s);
    }
}

#[test]
fn real_loopback_connect() {
    // The std connector against a listener on this machine: an open port and a refused one.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let open = listener.local_addr().unwrap().port();
    let mut c = StdConnector;
    assert_eq!(c.connect(Ipv4Addr::LOCALHOST, open, CONNECT_TIMEOUT), Ok(()));
    drop(listener);
    assert_eq!(c.connect(Ipv4Addr::LOCALHOST, open, CONNECT_TIMEOUT), Err(ErrorKind::ConnectionRefused));
    assert_eq!(c.resolve("localhost").map(|a| a.is_loopback()), Ok(true));
}

// ------------------------------------------------------------ the app

fn type_str(app: &mut NetApp, s: &str) {
    for ch in s.chars() {
        app.on_key(Key::Char(ch));
    }
}

fn to_confirm(app: &mut NetApp, host: &str, ports: &str) {
    app.on_key(Key::Enter); // Home -> host input
    type_str(app, host);
    app.on_key(Key::Enter);
    type_str(app, ports);
    app.on_key(Key::Enter);
}

#[test]
fn nothing_is_preloaded_and_nothing_starts_without_confirmation() {
    let mut app = NetApp::new();
    assert!(app.host.is_empty() && app.ports.is_empty() && app.subnet.is_empty());
    assert!(app.plan.is_none() && app.results.is_empty());
    // Walking the whole input flow never starts a check.
    app.on_key(Key::Enter);
    type_str(&mut app, "192.168.1.10");
    assert_eq!(app.on_key(Key::Enter), Action::Stay);
    type_str(&mut app, "22,80");
    assert_eq!(app.on_key(Key::Enter), Action::Stay);
    assert_eq!(app.screen, Screen::Confirm);
    assert!(app.results.is_empty(), "still nothing attempted");
    // Only Enter on the confirm screen starts.
    let a = app.on_key(Key::Enter);
    assert_eq!(a, Action::StartCheck(Plan { target: Target::Ip(ip("192.168.1.10")), ports: vec![22, 80] }));
    assert_eq!(app.screen, Screen::Running);
}

#[test]
fn confirm_back_does_not_start() {
    for k in [Key::Backspace, Key::F(4), Key::Left] {
        let mut app = NetApp::new();
        to_confirm(&mut app, "10.0.0.1", "22");
        assert_eq!(app.screen, Screen::Confirm);
        assert_eq!(app.on_key(k), Action::Stay);
        assert_eq!(app.screen, Screen::PortsInput);
    }
}

#[test]
fn confirm_text_says_what_will_happen() {
    let mut app = NetApp::new();
    to_confirm(&mut app, "192.168.1.10", "22,80");
    let t = app.confirm_lines().join("\n");
    assert!(t.contains("Connect to 192.168.1.10"));
    assert!(t.contains("private"));
    assert!(t.contains("Ports: 22, 80"));
    assert!(t.contains("2 s timeout") && t.contains("250 ms apart"));
    assert!(t.contains("Nothing is sent"));
    assert!(!t.contains("public internet"));
    let mut app = NetApp::new();
    to_confirm(&mut app, "8.8.8.8", "53");
    assert!(app.confirm_lines().join("\n").contains("public internet"));
    let mut app = NetApp::new();
    to_confirm(&mut app, "example.com", "443");
    assert!(app.confirm_lines().join("\n").contains("looked up first"));
}

#[test]
fn bad_input_shows_an_error_and_stays() {
    let mut app = NetApp::new();
    app.on_key(Key::Enter);
    type_str(&mut app, "999.1.1.1");
    app.on_key(Key::Enter);
    assert_eq!(app.screen, Screen::HostInput);
    assert_eq!(app.error.as_deref(), Some("Not a valid IPv4 address"));
    app.on_key(Key::Backspace);
    assert!(app.error.is_none());
    app.host.clear();
    type_str(&mut app, "10.0.0.1");
    app.on_key(Key::Enter);
    assert_eq!(app.screen, Screen::PortsInput);
    type_str(&mut app, "1-100");
    app.on_key(Key::Enter);
    assert_eq!(app.screen, Screen::PortsInput);
    assert_eq!(app.error.as_deref(), Some("At most 16 ports per check"));
    assert!(app.plan.is_none());
}

#[test]
fn f1_fills_common_ports_but_does_not_start() {
    let mut app = NetApp::new();
    app.on_key(Key::Enter);
    type_str(&mut app, "10.0.0.1");
    app.on_key(Key::Enter);
    app.on_key(Key::F(1));
    assert_eq!(app.ports.as_str(), COMMON_PORTS);
    assert_eq!(app.screen, Screen::PortsInput);
}

#[test]
fn running_cancel_keeps_partial_results() {
    let mut app = NetApp::new();
    to_confirm(&mut app, "10.0.0.1", "22,80,443");
    app.on_key(Key::Enter);
    app.on_event(Event::Port(PortResult { port: 22, status: Status::Open }));
    assert_eq!(app.on_key(Key::Backspace), Action::CancelCheck);
    assert_eq!(app.screen, Screen::Results);
    assert!(app.cancelled);
    assert_eq!(app.not_tried(), 2);
    // Late events from the stopped worker are ignored.
    app.on_event(Event::Port(PortResult { port: 80, status: Status::Closed }));
    app.on_event(Event::Done { cancelled: true });
    assert_eq!(app.results.len(), 1);
    assert_eq!(app.screen, Screen::Results);
}

#[test]
fn full_run_to_results_and_summary() {
    let mut app = NetApp::new();
    to_confirm(&mut app, "example.com", "22,80,443,9");
    app.on_key(Key::Enter);
    app.on_event(Event::Resolved(ip("93.184.216.34")));
    for (p, s) in [(22, Status::Closed), (80, Status::Open), (443, Status::Open), (9, Status::NoReply)] {
        app.on_event(Event::Port(PortResult { port: p, status: s }));
    }
    app.on_event(Event::Done { cancelled: false });
    assert_eq!(app.screen, Screen::Results);
    assert!(!app.cancelled);
    assert_eq!(app.resolved, Some(ip("93.184.216.34")));
    assert_eq!(app.summary(), "2 open, 1 closed, 1 no reply");
    assert_eq!(app.result_labels(), vec!["22 SSH: closed", "80 HTTP: open", "443 HTTPS: open", "9: no reply"]);
    // Checking again goes back to the confirmation, not straight to the network.
    assert_eq!(app.on_key(Key::F(1)), Action::Stay);
    assert_eq!(app.screen, Screen::Confirm);
}

#[test]
fn resolve_failure_returns_to_the_host_screen() {
    let mut app = NetApp::new();
    to_confirm(&mut app, "nope.invalid", "80");
    app.on_key(Key::Enter);
    app.on_event(Event::ResolveFailed);
    assert_eq!(app.screen, Screen::HostInput);
    assert!(app.error.as_deref().unwrap().contains("look up"));
}

#[test]
fn every_screen_can_be_left() {
    // Home leaves; every other screen goes back toward Home with Backspace or F4.
    let mut app = NetApp::new();
    assert_eq!(app.on_key(Key::F(4)), Action::Leave);
    assert_eq!(app.on_key(Key::Backspace), Action::Leave);
    for item in 0..3usize {
        let mut app = NetApp::new();
        for _ in 0..item {
            app.on_key(Key::Down);
        }
        app.on_key(Key::Enter);
        assert_ne!(app.screen, Screen::Home);
        app.on_key(Key::Backspace);
        assert_eq!(app.screen, Screen::Home);
    }
    let mut app = NetApp::new();
    to_confirm(&mut app, "10.0.0.1", "22");
    for _ in 0..3 {
        app.on_key(Key::F(4));
    }
    assert_eq!(app.screen, Screen::Home);
}

#[test]
fn subnet_screen() {
    let mut app = NetApp::new();
    app.on_key(Key::Down);
    app.on_key(Key::Enter);
    assert_eq!(app.screen, Screen::SubnetInput);
    type_str(&mut app, "10.0.0.5/30");
    app.on_key(Key::Enter);
    assert_eq!(app.screen, Screen::SubnetResult);
    let l = app.subnet_lines().join("\n");
    assert!(l.contains("Network  10.0.0.4"));
    assert!(l.contains("Broadcast 10.0.0.7"));
    assert!(l.contains("Hosts    2"));
    assert!(l.contains("Wildcard 0.0.0.3"));
    app.on_key(Key::Backspace);
    assert_eq!(app.screen, Screen::SubnetInput);
    app.subnet.clear();
    type_str(&mut app, "10.0.0.5/33");
    app.on_key(Key::Enter);
    assert_eq!(app.screen, Screen::SubnetInput);
    assert!(app.error.is_some());
    // Letters and spaces aren't typed into the field.
    app.subnet.clear();
    type_str(&mut app, "1a 2");
    assert_eq!(app.subnet.as_str(), "12");
}

#[test]
fn subnet_special_cases_are_labelled() {
    let mut app = NetApp::new();
    app.on_key(Key::Down);
    app.on_key(Key::Enter);
    type_str(&mut app, "10.0.0.1/31");
    app.on_key(Key::Enter);
    assert!(app.subnet_lines().join("\n").contains("RFC 3021"));
    app.on_key(Key::Backspace);
    app.subnet.clear();
    type_str(&mut app, "8.8.8.8");
    app.on_key(Key::Enter);
    let l = app.subnet_lines().join("\n");
    assert!(l.contains("classful default"));
    assert!(l.contains("public internet"));
    app.on_key(Key::Backspace);
    app.subnet.clear();
    type_str(&mut app, "255.255.255.255/32");
    app.on_key(Key::Enter);
    assert!(app.subnet_lines().join("\n").contains("single host"));
}

#[test]
fn port_reference_scrolls_within_bounds() {
    let mut app = NetApp::new();
    app.rows = 10;
    app.on_key(Key::Down);
    app.on_key(Key::Down);
    app.on_key(Key::Enter);
    assert_eq!(app.screen, Screen::PortRef);
    for _ in 0..500 {
        app.on_key(Key::Down);
    }
    assert_eq!(app.port_list.selected, PORTS.len() - 1);
    assert_eq!(app.port_list.top, PORTS.len() - 10);
    assert_eq!(NetApp::port_labels().len(), PORTS.len());
}

#[test]
fn host_input_is_limited_and_printable() {
    let mut app = NetApp::new();
    app.on_key(Key::Enter);
    for _ in 0..200 {
        app.on_key(Key::Char('a'));
    }
    assert_eq!(app.host.len(), crate::app::MAX_HOST);
    app.on_key(Key::F(3));
    assert!(app.host.is_empty());
    app.on_key(Key::Char('é'));
    assert!(app.host.is_empty());
}
