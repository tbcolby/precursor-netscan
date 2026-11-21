#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

//! Net Check for Precursor: a subnet calculator, a port reference and rate-limited TCP
//! connect checks against one host the user types. It is not a scanner (see the README).
//! Logic is in `netscan-core`; `app.rs` maps keys and draws, `net.rs` runs the worker.
//! Nothing is stored and nothing runs in the background.

mod app;
mod net;

use num_traits::{FromPrimitive, ToPrimitive};
use precursor_appkit::{app as kit, keys};

/// xous-names server name. Any unique string; NOT the GAM app name.
const SERVER_NAME: &str = "_Net Check_";

#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub(crate) enum AppOp {
    Redraw = 0,
    Rawkeys,
    FocusChange,
    /// From the check worker: arg1 = check id, arg2 = kind, arg3/arg4 = data (see `net.rs`).
    CheckEvent,
    Quit,
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("netscan PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(SERVER_NAME, None).expect("can't register server");

    // GAM app name comes from apps/manifest.json key "netscan".
    let reg = kit::register(
        &xns,
        sid,
        gam::APP_NAME_NETSCAN,
        gam::UxType::Framebuffer,
        kit::Opcodes {
            redraw: AppOp::Redraw.to_u32().unwrap(),
            rawkeys: Some(AppOp::Rawkeys.to_u32().unwrap()),
            focus_change: Some(AppOp::FocusChange.to_u32().unwrap()),
            got_input: None,
        },
    );

    let self_cid = xous::connect(sid).unwrap();
    let mut app = app::App::new(reg.screen, self_cid, AppOp::CheckEvent.to_usize().unwrap());
    let mut foreground = true;

    loop {
        let msg = xous::receive_message(sid).unwrap();
        match FromPrimitive::from_usize(msg.body.id()) {
            Some(AppOp::Redraw) => app.draw(),
            Some(AppOp::Rawkeys) => xous::msg_scalar_unpack!(msg, k1, k2, k3, k4, {
                for key in keys::decode_rawkeys([k1, k2, k3, k4]) {
                    if app.on_key(key) == app::Action::Leave {
                        app.leaving();
                        kit::leave(app.screen());
                    }
                }
                app.draw();
            }),
            Some(AppOp::FocusChange) => xous::msg_scalar_unpack!(msg, code, _, _, _, {
                match kit::focus_state(code) {
                    gam::FocusState::Foreground => {
                        foreground = true;
                        app.on_foreground();
                    }
                    gam::FocusState::Background => foreground = false,
                }
            }),
            Some(AppOp::CheckEvent) => xous::msg_scalar_unpack!(msg, id, kind, a, b, {
                app.check_event(id, kind, a, b);
                if foreground {
                    app.draw();
                }
            }),
            Some(AppOp::Quit) => break,
            None => log::warn!("unknown opcode {:?}", msg.body.id()),
        }
    }
    app.leaving();
    kit::shutdown(&xns, sid)
}
