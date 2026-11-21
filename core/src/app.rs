//! Screen state machine. The shell maps device keys to `Key`, calls
//! [`NetApp::on_key`], starts the worker when told to, feeds back [`Event`]s,
//! and draws what the fields say. A connection is only ever attempted after the
//! user has pressed Enter on the Confirm screen.

use crate::check::{parse_target, Event, Plan, PortResult, Status, Target, CONNECT_TIMEOUT, GAP};
use crate::ip::{classify, parse_cidr, subnet_calc, AddrKind, SubnetInfo};
use crate::ports::{parse_ports, service_name, PORTS};
use precursor_appkit_core::keys::Key;
use precursor_appkit_core::layout::ListState;
use precursor_appkit_core::text::TextField;
use std::net::Ipv4Addr;

pub const HOME_ITEMS: [&str; 3] = ["Check TCP ports on a host", "Subnet calculator", "Port reference"];
/// Filled in by F1 on the ports screen.
pub const COMMON_PORTS: &str = "22,80,443";
pub const MAX_HOST: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    HostInput,
    PortsInput,
    Confirm,
    Running,
    Results,
    SubnetInput,
    SubnetResult,
    PortRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Stay,
    Leave,
    /// Start the worker for this plan (the user confirmed it).
    StartCheck(Plan),
    /// Stop the worker.
    CancelCheck,
}

pub struct NetApp {
    pub screen: Screen,
    pub home: ListState,
    pub host: TextField,
    pub ports: TextField,
    pub error: Option<String>,
    pub plan: Option<Plan>,
    pub resolved: Option<Ipv4Addr>,
    pub results: Vec<PortResult>,
    pub cancelled: bool,
    pub results_list: ListState,
    pub subnet: TextField,
    pub subnet_info: Option<(SubnetInfo, bool)>,
    pub port_list: ListState,
    /// Rows the shell can show in a list (set while drawing).
    pub rows: usize,
}

impl Default for NetApp {
    fn default() -> Self { Self::new() }
}

impl NetApp {
    pub fn new() -> Self {
        Self {
            screen: Screen::Home,
            home: ListState::default(),
            // Never preloaded with a target.
            host: TextField::with_max(MAX_HOST),
            ports: TextField::with_max(40),
            error: None,
            plan: None,
            resolved: None,
            results: Vec::new(),
            cancelled: false,
            results_list: ListState::default(),
            subnet: TextField::with_max(18),
            subnet_info: None,
            port_list: ListState::default(),
            rows: 8,
        }
    }

    pub fn on_key(&mut self, key: Key) -> Action {
        match self.screen {
            Screen::Home => self.key_home(key),
            Screen::HostInput => self.key_host(key),
            Screen::PortsInput => self.key_ports(key),
            Screen::Confirm => self.key_confirm(key),
            Screen::Running => self.key_running(key),
            Screen::Results => self.key_results(key),
            Screen::SubnetInput => self.key_subnet(key),
            Screen::SubnetResult => self.key_subnet_result(key),
            Screen::PortRef => self.key_portref(key),
        }
    }

    fn key_home(&mut self, key: Key) -> Action {
        match key {
            Key::F(4) | Key::Backspace => return Action::Leave,
            Key::Up => self.home.step(-1, HOME_ITEMS.len(), HOME_ITEMS.len()),
            Key::Down => self.home.step(1, HOME_ITEMS.len(), HOME_ITEMS.len()),
            Key::Enter | Key::Right => {
                self.error = None;
                self.screen = match self.home.selected {
                    0 => Screen::HostInput,
                    1 => Screen::SubnetInput,
                    _ => {
                        self.port_list = ListState::default();
                        Screen::PortRef
                    }
                };
            }
            _ => {}
        }
        Action::Stay
    }

    fn key_host(&mut self, key: Key) -> Action {
        match key {
            Key::F(4) => self.screen = Screen::Home,
            Key::Backspace => {
                if self.host.is_empty() {
                    self.screen = Screen::Home;
                } else {
                    self.host.backspace();
                    self.error = None;
                }
            }
            Key::Enter => match parse_target(self.host.as_str()) {
                Ok(_) => {
                    self.error = None;
                    self.screen = Screen::PortsInput;
                }
                Err(e) => self.error = Some(e.to_string()),
            },
            Key::Left => self.host.left(),
            Key::Right => self.host.right(),
            Key::F(3) => {
                self.host.clear();
                self.error = None;
            }
            Key::Char(c) if c.is_ascii_graphic() => {
                if self.host.insert(c) {
                    self.error = None;
                }
            }
            _ => {}
        }
        Action::Stay
    }

    fn key_ports(&mut self, key: Key) -> Action {
        match key {
            Key::F(4) => {
                self.error = None;
                self.screen = Screen::HostInput;
            }
            Key::Backspace => {
                if self.ports.is_empty() {
                    self.error = None;
                    self.screen = Screen::HostInput;
                } else {
                    self.ports.backspace();
                    self.error = None;
                }
            }
            Key::F(1) => {
                self.ports.set(COMMON_PORTS);
                self.error = None;
            }
            Key::F(3) => {
                self.ports.clear();
                self.error = None;
            }
            Key::Enter => {
                let target = parse_target(self.host.as_str());
                match (target, parse_ports(self.ports.as_str())) {
                    (Ok(target), Ok(ports)) => {
                        self.plan = Some(Plan { target, ports });
                        self.error = None;
                        self.screen = Screen::Confirm;
                    }
                    (Err(e), _) => self.error = Some(e.to_string()),
                    (_, Err(e)) => self.error = Some(e.to_string()),
                }
            }
            Key::Left => self.ports.left(),
            Key::Right => self.ports.right(),
            Key::Char(c) if c.is_ascii_digit() || c == ',' || c == '-' || c == ' ' => {
                if self.ports.insert(c) {
                    self.error = None;
                }
            }
            _ => {}
        }
        Action::Stay
    }

    fn key_confirm(&mut self, key: Key) -> Action {
        match key {
            Key::Enter => {
                if let Some(plan) = self.plan.clone() {
                    self.results.clear();
                    self.resolved = None;
                    self.cancelled = false;
                    self.results_list = ListState::default();
                    self.screen = Screen::Running;
                    return Action::StartCheck(plan);
                }
            }
            Key::F(4) | Key::Backspace | Key::Left => self.screen = Screen::PortsInput,
            _ => {}
        }
        Action::Stay
    }

    fn key_running(&mut self, key: Key) -> Action {
        if key.is_back() || key == Key::Char('q') {
            self.cancelled = true;
            self.screen = Screen::Results;
            return Action::CancelCheck;
        }
        Action::Stay
    }

    fn key_results(&mut self, key: Key) -> Action {
        match key {
            Key::F(4) | Key::Backspace => self.screen = Screen::Home,
            Key::Up => self.results_list.step(-1, self.results.len(), self.rows),
            Key::Down => self.results_list.step(1, self.results.len(), self.rows),
            // Checking again is a new, explicit confirmation.
            Key::F(1) | Key::Right => {
                if self.plan.is_some() {
                    self.screen = Screen::Confirm;
                }
            }
            _ => {}
        }
        Action::Stay
    }

    fn key_subnet(&mut self, key: Key) -> Action {
        match key {
            Key::F(4) => self.screen = Screen::Home,
            Key::Backspace => {
                if self.subnet.is_empty() {
                    self.screen = Screen::Home;
                } else {
                    self.subnet.backspace();
                    self.error = None;
                }
            }
            Key::Enter => match parse_cidr(self.subnet.as_str()) {
                Some((ip, prefix, defaulted)) => {
                    self.subnet_info = Some((subnet_calc(ip, prefix), defaulted));
                    self.error = None;
                    self.screen = Screen::SubnetResult;
                }
                None => self.error = Some("Use a.b.c.d or a.b.c.d/n (n = 0 to 32)".into()),
            },
            Key::Left => self.subnet.left(),
            Key::Right => self.subnet.right(),
            Key::F(3) => {
                self.subnet.clear();
                self.error = None;
            }
            Key::Char(c) if c.is_ascii_digit() || c == '.' || c == '/' => {
                if self.subnet.insert(c) {
                    self.error = None;
                }
            }
            _ => {}
        }
        Action::Stay
    }

    fn key_subnet_result(&mut self, key: Key) -> Action {
        if matches!(key, Key::F(4) | Key::Backspace | Key::Left | Key::Enter) {
            self.screen = Screen::SubnetInput;
        }
        Action::Stay
    }

    fn key_portref(&mut self, key: Key) -> Action {
        match key {
            Key::F(4) | Key::Backspace | Key::Left => self.screen = Screen::Home,
            Key::Up => self.port_list.step(-1, PORTS.len(), self.rows),
            Key::Down => self.port_list.step(1, PORTS.len(), self.rows),
            _ => {}
        }
        Action::Stay
    }

    /// Progress from the worker. Ignored unless a check is running.
    pub fn on_event(&mut self, ev: Event) {
        if self.screen != Screen::Running {
            return;
        }
        match ev {
            Event::Resolved(ip) => self.resolved = Some(ip),
            Event::ResolveFailed => {
                self.error = Some("Couldn't look up that name (is Wi-Fi connected?)".into());
                self.screen = Screen::HostInput;
            }
            Event::Port(r) => self.results.push(r),
            Event::Done { cancelled } => {
                self.cancelled = cancelled;
                self.screen = Screen::Results;
            }
        }
    }

    // ----------------------------------------------------------- text for the shell

    /// Lines for the Confirm screen: what exactly will happen.
    pub fn confirm_lines(&self) -> Vec<String> {
        let Some(plan) = &self.plan else { return Vec::new() };
        let mut out = vec![format!("Connect to {}", plan.target)];
        match &plan.target {
            Target::Ip(ip) => {
                let kind = classify(*ip);
                out.push(format!("Address type: {}", kind.name()));
                if kind == AddrKind::Public {
                    out.push("This is on the public internet. Only check hosts you own or have permission to test.".into());
                }
            }
            Target::Name(_) => out.push("The name is looked up first; its address is shown, not guessed.".into()),
        }
        let ports: Vec<String> = plan.ports.iter().map(|p| p.to_string()).collect();
        out.push(format!("Ports: {}", ports.join(", ")));
        out.push(format!(
            "One TCP connect per port, {} s timeout, {} ms apart: up to {} s. Nothing is sent; each connection is closed at once.",
            CONNECT_TIMEOUT.as_secs(),
            GAP.as_millis(),
            plan.worst_case_secs()
        ));
        out
    }

    /// Result rows: `22 SSH: open`.
    pub fn result_labels(&self) -> Vec<String> {
        self.results
            .iter()
            .map(|r| {
                let name = service_name(r.port);
                if name.is_empty() {
                    format!("{}: {}", r.port, r.status.label())
                } else {
                    format!("{} {}: {}", r.port, name, r.status.label())
                }
            })
            .collect()
    }

    /// `2 open, 1 closed, 0 no reply`.
    pub fn summary(&self) -> String {
        let n = |s: Status| self.results.iter().filter(|r| r.status == s).count();
        let other = self.results.len() - n(Status::Open) - n(Status::Closed) - n(Status::NoReply);
        let mut s = format!("{} open, {} closed, {} no reply", n(Status::Open), n(Status::Closed), n(Status::NoReply));
        if other > 0 {
            s += &format!(", {other} failed");
        }
        s
    }

    /// How many ports were planned but not tried (after a cancel).
    pub fn not_tried(&self) -> usize { self.plan.as_ref().map(|p| p.ports.len().saturating_sub(self.results.len())).unwrap_or(0) }

    /// Port-reference rows.
    pub fn port_labels() -> Vec<String> { PORTS.iter().map(|p| format!("{:<5} {:<7} {}", p.port, p.protocol, p.service)).collect() }

    /// Lines for the subnet result.
    pub fn subnet_lines(&self) -> Vec<String> {
        let Some((i, defaulted)) = &self.subnet_info else { return Vec::new() };
        let mut v = vec![
            format!("Address  {}/{}{}", i.address, i.prefix, if *defaulted { " (classful default)" } else { "" }),
            format!("Mask     {}", i.mask),
            format!("Wildcard {}", i.wildcard),
            format!("Network  {}", i.network),
            format!("Broadcast {}", i.broadcast),
            format!("Hosts    {}", i.host_count),
            format!("First    {}", i.first_host),
            format!("Last     {}", i.last_host),
            format!("Class {}  {}", i.class, i.kind.name()),
        ];
        if i.prefix == 31 {
            v.push("/31: both addresses are hosts (RFC 3021)".into());
        }
        if i.prefix == 32 {
            v.push("/32: a single host".into());
        }
        v
    }
}
