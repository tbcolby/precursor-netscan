//! The connect-check worker. It runs on its own thread so the main loop never blocks, and
//! reports each step back as a scalar message. A worker exists only for a check the user
//! confirmed; cancelling stops it before its next connection.

use netscan_core::check::{run_check, Event, Plan, StdConnector};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Message kinds in the `kind` argument of a worker message.
pub const EV_RESOLVED: usize = 0;
pub const EV_RESOLVE_FAILED: usize = 1;
pub const EV_PORT: usize = 2;
pub const EV_DONE: usize = 3;

pub struct Check {
    pub id: usize,
    cancel: Arc<AtomicBool>,
}

impl Check {
    /// Start a check. Every event is sent to `cid` as `(opcode, id, kind, a, b)`:
    /// `Resolved`: a = address as u32; `Port`: a = port, b = status code; `Done`: a = 1 if cancelled.
    pub fn start(id: usize, plan: Plan, cid: xous::CID, opcode: usize) -> Check {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        std::thread::spawn(move || {
            let mut conn = StdConnector;
            let cancelled = || flag.load(Ordering::SeqCst);
            run_check(&plan, &mut conn, &cancelled, &mut |ev| {
                let (kind, a, b) = match ev {
                    Event::Resolved(ip) => (EV_RESOLVED, u32::from(ip) as usize, 0),
                    Event::ResolveFailed => (EV_RESOLVE_FAILED, 0, 0),
                    Event::Port(r) => (EV_PORT, r.port as usize, r.status.code()),
                    Event::Done { cancelled } => (EV_DONE, cancelled as usize, 0),
                };
                xous::send_message(cid, xous::Message::new_scalar(opcode, id, kind, a, b)).ok();
            });
        });
        Check { id, cancel }
    }

    /// Stop before the next connection.
    pub fn cancel(&self) { self.cancel.store(true, Ordering::SeqCst); }
}
