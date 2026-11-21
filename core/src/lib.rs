//! Net Check core: IPv4 subnet maths, a port table, and rate-limited TCP connect
//! checks with their screen state machine. Only `std` (sockets are behind the
//! [`check::Connector`] trait so the logic is testable offline); no Xous dependencies.
//!
//! This is deliberately not a scanner. See [`check`] for exactly what it does.

pub mod app;
pub mod check;
pub mod ip;
pub mod ports;

pub use app::{Action, NetApp, Screen};

#[cfg(test)]
mod tests;
