//! State machine for Network Scanner.
//! States: SubnetInput, SubnetResult, PortRef, ScanSim, HostDetail

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use crate::scanner::{self, Ipv4, SubnetInfo, ScanResult};

const KEY_UP: char = '\u{F700}';
const KEY_DOWN: char = '\u{F701}';
const KEY_LEFT: char = '\u{F702}';
const KEY_RIGHT: char = '\u{F703}';
const KEY_ENTER: char = '\u{000D}';
const KEY_BACKSPACE: char = '\u{0008}';
const KEY_MENU: char = '\u{2234}';

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppState { SubnetInput, SubnetResult, PortRef, ScanSim, HostDetail }

pub struct NetScanApp {
    pub state: AppState,
    pub needs_redraw: bool,
    pub input: String,
    pub subnet: Option<SubnetInfo>,
    pub error: Option<String>,
    pub port_scroll: usize,
    pub scan_results: Vec<ScanResult>,
    pub scan_cursor: usize,
    pub scan_scroll: usize,
}

impl NetScanApp {
    pub fn new() -> Self {
        Self {
            state: AppState::SubnetInput,
            needs_redraw: true,
            input: String::from("192.168.1.0/24"),
            subnet: None,
            error: None,
            port_scroll: 0,
            scan_results: Vec::new(),
            scan_cursor: 0,
            scan_scroll: 0,
        }
    }

    pub fn handle_key(&mut self, key: char) -> bool {
        self.needs_redraw = true;
        match self.state {
            AppState::SubnetInput => self.key_input(key),
            AppState::SubnetResult => self.key_result(key),
            AppState::PortRef => self.key_port(key),
            AppState::ScanSim => self.key_scan(key),
            AppState::HostDetail => self.key_host(key),
        }
    }

    fn key_input(&mut self, key: char) -> bool {
        match key {
            KEY_MENU => return false,
            KEY_ENTER => {
                match scanner::parse_cidr(&self.input) {
                    Some((ip, prefix)) => {
                        self.subnet = Some(scanner::subnet_calc(ip, prefix));
                        self.error = None;
                        self.state = AppState::SubnetResult;
                    }
                    None => {
                        self.error = Some(String::from("Invalid CIDR. Use: a.b.c.d/n"));
                    }
                }
            }
            KEY_BACKSPACE => { self.input.pop(); self.error = None; }
            KEY_RIGHT => { self.port_scroll = 0; self.state = AppState::PortRef; }
            c if (c >= '0' && c <= '9') || c == '.' || c == '/' => {
                if self.input.len() < 18 { self.input.push(c); }
            }
            _ => {}
        }
        true
    }

    fn key_result(&mut self, key: char) -> bool {
        match key {
            KEY_MENU | KEY_LEFT => { self.state = AppState::SubnetInput; }
            KEY_RIGHT | 's' | 'S' => {
                // Run simulated scan
                if let Some(ref subnet) = self.subnet {
                    self.scan_results = scanner::simulate_scan(subnet.network);
                    self.scan_cursor = 0;
                    self.scan_scroll = 0;
                    self.state = AppState::ScanSim;
                }
            }
            _ => {}
        }
        true
    }

    fn key_port(&mut self, key: char) -> bool {
        match key {
            KEY_MENU | KEY_LEFT => { self.state = AppState::SubnetInput; }
            KEY_UP => { if self.port_scroll > 0 { self.port_scroll -= 1; } }
            KEY_DOWN => {
                if self.port_scroll < scanner::PORTS.len().saturating_sub(1) {
                    self.port_scroll += 1;
                }
            }
            _ => {}
        }
        true
    }

    fn key_scan(&mut self, key: char) -> bool {
        match key {
            KEY_MENU | KEY_LEFT => { self.state = AppState::SubnetResult; }
            KEY_UP => {
                if self.scan_cursor > 0 {
                    self.scan_cursor -= 1;
                    if self.scan_cursor < self.scan_scroll { self.scan_scroll = self.scan_cursor; }
                }
            }
            KEY_DOWN => {
                if !self.scan_results.is_empty() && self.scan_cursor < self.scan_results.len() - 1 {
                    self.scan_cursor += 1;
                    if self.scan_cursor >= self.scan_scroll + 8 { self.scan_scroll = self.scan_cursor - 7; }
                }
            }
            KEY_ENTER | KEY_RIGHT => {
                if !self.scan_results.is_empty() { self.state = AppState::HostDetail; }
            }
            _ => {}
        }
        true
    }

    fn key_host(&mut self, key: char) -> bool {
        match key {
            KEY_MENU | KEY_LEFT | KEY_BACKSPACE => { self.state = AppState::ScanSim; }
            _ => {}
        }
        true
    }
}
