//! Keys, worker control and drawing for Net Check. Rules, parsing and the connect logic
//! are in `netscan-core`; the worker thread is in `net.rs`.

use crate::net::{Check, EV_DONE, EV_PORT, EV_RESOLVED, EV_RESOLVE_FAILED};
use gam::menu::Point;
use gam::GlyphStyle;
use netscan_core::app::{NetApp, HOME_ITEMS};
use netscan_core::check::{Event, PortResult, Status};
use netscan_core::{Action as CoreAction, Screen as View};
use precursor_appkit::screen::Screen;
use std::net::Ipv4Addr;

pub use precursor_appkit::keys::Key;

const MARGIN: isize = 8;

#[derive(PartialEq, Eq)]
pub enum Action {
    Stay,
    Leave,
}

pub struct App {
    screen: Screen,
    core: NetApp,
    check: Option<Check>,
    next_id: usize,
    self_cid: xous::CID,
    check_op: usize,
}

impl App {
    pub fn new(screen: Screen, self_cid: xous::CID, check_op: usize) -> Self {
        Self { screen, core: NetApp::new(), check: None, next_id: 1, self_cid, check_op }
    }

    pub fn screen(&self) -> &Screen { &self.screen }

    pub fn on_foreground(&mut self) {
        self.screen.refresh_size();
        self.draw();
    }

    /// Stop a running check when the app quits.
    pub fn leaving(&mut self) { self.cancel_check(); }

    fn cancel_check(&mut self) {
        if let Some(c) = self.check.take() {
            c.cancel();
        }
    }

    pub fn on_key(&mut self, key: Key) -> Action {
        match self.core.on_key(key) {
            CoreAction::Stay => Action::Stay,
            CoreAction::Leave => Action::Leave,
            CoreAction::CancelCheck => {
                self.cancel_check();
                Action::Stay
            }
            CoreAction::StartCheck(plan) => {
                // The user pressed Enter on the confirmation screen.
                self.cancel_check();
                let id = self.next_id;
                self.next_id += 1;
                self.check = Some(Check::start(id, plan, self.self_cid, self.check_op));
                Action::Stay
            }
        }
    }

    /// A worker message. Events from a cancelled or finished check (older id) are ignored.
    pub fn check_event(&mut self, id: usize, kind: usize, a: usize, b: usize) {
        if self.check.as_ref().map(|c| c.id) != Some(id) {
            return;
        }
        let ev = match kind {
            EV_RESOLVED => Event::Resolved(Ipv4Addr::from(a as u32)),
            EV_RESOLVE_FAILED => Event::ResolveFailed,
            EV_PORT => Event::Port(PortResult { port: a as u16, status: Status::from_code(b) }),
            EV_DONE => Event::Done { cancelled: a != 0 },
            _ => return,
        };
        let finished = matches!(ev, Event::Done { .. } | Event::ResolveFailed);
        self.core.on_event(ev);
        if finished {
            self.check = None;
        }
    }

    // ---------------------------------------------------------------- drawing

    fn text(&self, y: isize, style: GlyphStyle, text: &str) -> isize {
        let w = self.screen.size().x;
        y + self.screen.text_in(Point::new(MARGIN, y), Point::new(w - MARGIN, y + 300), style, text) + 2
    }

    pub fn draw(&mut self) {
        self.screen.clear();
        match self.core.screen {
            View::Home => self.draw_home(),
            View::HostInput => self.draw_input("Host", "IPv4 address or host name:", &self.core.host.display_with_cursor('|'), "⏎ next · F3 clear · ⌫ back"),
            View::PortsInput => {
                let host = self.core.host.as_str().to_string();
                self.draw_input(
                    &format!("Ports on {host}"),
                    "Ports (like 22,80,8000-8003; up to 16):",
                    &self.core.ports.display_with_cursor('|'),
                    "⏎ review · F1 22,80,443 · F3 clear · ⌫ back",
                );
            }
            View::Confirm => self.draw_confirm(),
            View::Running => self.draw_running(),
            View::Results => self.draw_results(),
            View::SubnetInput => self.draw_input(
                "Subnet calculator",
                "a.b.c.d/n (or just an address):",
                &self.core.subnet.display_with_cursor('|'),
                "⏎ calculate · F3 clear · ⌫ back",
            ),
            View::SubnetResult => self.draw_subnet(),
            View::PortRef => self.draw_ports(),
        }
        self.screen.flush();
    }

    fn draw_home(&self) {
        let top = self.screen.header("Net Check");
        let bottom = self.screen.footer("↑↓ · ⏎ open · ⌫ quit");
        let items: Vec<&str> = HOME_ITEMS.to_vec();
        self.screen.list(top, bottom - 70, &items, &self.core.home);
        self.screen.para(
            bottom - 66,
            bottom,
            GlyphStyle::Small,
            "Not a scanner: connects to one host you type, one port at a time, only after you confirm.",
        );
    }

    fn draw_input(&self, title: &str, prompt: &str, field: &str, hint: &str) {
        let top = self.screen.header(title);
        self.screen.footer(hint);
        let mut y = self.text(top + 4, GlyphStyle::Regular, prompt);
        y = self.text(y + 8, GlyphStyle::Monospace, field);
        if let Some(err) = &self.core.error {
            self.text(y + 8, GlyphStyle::Bold, err);
        }
    }

    fn draw_confirm(&self) {
        let top = self.screen.header("Confirm check");
        let bottom = self.screen.footer("⏎ START · ⌫ cancel");
        let mut y = top;
        for (i, line) in self.core.confirm_lines().iter().enumerate() {
            let style = if i == 0 { GlyphStyle::Bold } else { GlyphStyle::Regular };
            y = self.screen.para(y, bottom, style, line);
        }
    }

    fn draw_running(&self) {
        let top = self.screen.header("Checking…");
        let bottom = self.screen.footer("⌫ cancel");
        let Some(plan) = &self.core.plan else { return };
        let mut y = self.screen.para(top, bottom, GlyphStyle::Bold, &plan.target.to_string());
        if let Some(ip) = self.core.resolved {
            y = self.screen.para(y, bottom, GlyphStyle::Small, &format!("resolved to {ip}"));
        }
        y = self.screen.para(y, bottom, GlyphStyle::Small, &format!("{} of {} ports tried", self.core.results.len(), plan.ports.len()));
        for line in self.core.result_labels() {
            if y + 20 > bottom {
                break;
            }
            y = self.screen.para(y, bottom, GlyphStyle::Regular, &line);
        }
    }

    fn draw_results(&mut self) {
        let top = self.screen.header(if self.core.cancelled { "Cancelled" } else { "Results" });
        let mut bottom = self.screen.footer("↑↓ · F1 check again · ⌫ done");
        let h = self.screen.line_height(GlyphStyle::Small);
        let mut note = self.core.summary();
        if self.core.cancelled {
            note += &format!(" ({} not tried)", self.core.not_tried());
        }
        bottom -= 2 * h + 4;
        self.screen.text_in(Point::new(MARGIN, bottom + 2), Point::new(self.screen.size().x - MARGIN, bottom + 2 + h), GlyphStyle::Small, &note);
        if let Some(ip) = self.core.resolved {
            let t = self.core.plan.as_ref().map(|p| p.target.to_string()).unwrap_or_default();
            self.screen.text_in(
                Point::new(MARGIN, bottom + 2 + h),
                Point::new(self.screen.size().x - MARGIN, bottom + 2 + 2 * h),
                GlyphStyle::Small,
                &format!("{t} = {ip}"),
            );
        }
        let labels = self.core.result_labels();
        self.core.rows = self.screen.list(top, bottom, &labels, &self.core.results_list);
    }

    fn draw_subnet(&self) {
        let top = self.screen.header("Subnet");
        self.screen.footer("⌫ back");
        let mut y = top;
        for line in self.core.subnet_lines() {
            y = self.text(y, GlyphStyle::Monospace, &line);
        }
    }

    fn draw_ports(&mut self) {
        let top = self.screen.header("Ports");
        let bottom = self.screen.footer("↑↓ scroll · ⌫ back");
        let h = self.screen.line_height(GlyphStyle::Monospace) + 2;
        let rows = (((bottom - top) / h).max(1)) as usize;
        self.core.rows = rows;
        let labels = NetApp::port_labels();
        let range = self.core.port_list.visible_range(labels.len(), rows);
        let mut y = top;
        for i in range {
            let marker = if i == self.core.port_list.selected { "▸" } else { " " };
            self.screen.text_in(
                Point::new(MARGIN, y),
                Point::new(self.screen.size().x - MARGIN, y + h),
                GlyphStyle::Monospace,
                &format!("{marker}{}", labels[i]),
            );
            y += h;
        }
    }
}
