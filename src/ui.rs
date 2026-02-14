//! UI rendering for Network Scanner.

extern crate alloc;
use alloc::format;
use alloc::string::String;

use gam::{Gam, Point, Line, TextView, TextBounds, GlyphStyle};
use crate::app::{NetScanApp, AppState};
use crate::scanner;

const SCREEN_W: i16 = 336;
const HEADER_H: i16 = 30;
const FOOTER_Y: i16 = 490;

fn draw_header(gam: &Gam, title: &str) {
    gam.draw_rectangle(Point::new(0, 0), Point::new(SCREEN_W, HEADER_H)).ok();
    let mut tv = TextView::new(TextBounds::BoundingBox(Point::new(8, 2), Point::new(SCREEN_W - 8, HEADER_H)));
    tv.style = GlyphStyle::Bold; tv.invert = true;
    tv.text = String::from(title);
    gam.post_textview(&mut tv).ok();
}

fn draw_footer(gam: &Gam, text: &str) {
    gam.draw_line(Line::new(Point::new(0, FOOTER_Y), Point::new(SCREEN_W, FOOTER_Y))).ok();
    let mut tv = TextView::new(TextBounds::BoundingBox(Point::new(8, FOOTER_Y + 4), Point::new(SCREEN_W - 8, FOOTER_Y + 40)));
    tv.style = GlyphStyle::Small;
    tv.text = String::from(text);
    gam.post_textview(&mut tv).ok();
}

fn text_at(gam: &Gam, x: i16, y: i16, h: i16, s: &str, style: GlyphStyle) {
    let mut tv = TextView::new(TextBounds::BoundingBox(Point::new(x, y), Point::new(SCREEN_W - 8, y + h)));
    tv.style = style; tv.text = String::from(s);
    gam.post_textview(&mut tv).ok();
}

pub fn draw(gam: &Gam, app: &NetScanApp) {
    gam.clear().ok();
    match app.state {
        AppState::SubnetInput => draw_input(gam, app),
        AppState::SubnetResult => draw_result(gam, app),
        AppState::PortRef => draw_ports(gam, app),
        AppState::ScanSim => draw_scan(gam, app),
        AppState::HostDetail => draw_host(gam, app),
    }
    gam.redraw().ok();
}

fn draw_input(gam: &Gam, app: &NetScanApp) {
    draw_header(gam, "Network Scanner");

    let mut y: i16 = 50;
    text_at(gam, 12, y, 22, "Enter IP/CIDR:", GlyphStyle::Regular);
    y += 30;

    // Input field
    gam.draw_line(Line::new(Point::new(8, y + 24), Point::new(SCREEN_W - 8, y + 24))).ok();
    let display = format!("{}|", app.input);
    text_at(gam, 12, y, 22, &display, GlyphStyle::Regular);
    y += 40;

    if let Some(ref err) = app.error {
        text_at(gam, 12, y, 22, err, GlyphStyle::Small);
        y += 24;
    }

    y += 10;
    text_at(gam, 12, y, 18, "Examples:", GlyphStyle::Small);
    y += 20;
    text_at(gam, 16, y, 18, "192.168.1.0/24", GlyphStyle::Small);
    y += 18;
    text_at(gam, 16, y, 18, "10.0.0.0/8", GlyphStyle::Small);
    y += 18;
    text_at(gam, 16, y, 18, "172.16.0.0/16", GlyphStyle::Small);
    y += 30;
    text_at(gam, 12, y, 18, "Right: port reference", GlyphStyle::Small);

    draw_footer(gam, "Enter: calculate  Right: ports  Menu: quit");
}

fn draw_result(gam: &Gam, app: &NetScanApp) {
    draw_header(gam, "Subnet Calculator");

    if let Some(ref sub) = app.subnet {
        let mut y: i16 = 40;
        let lh: i16 = 26;

        text_at(gam, 12, y, 22, &format!("Input: {}", app.input), GlyphStyle::Regular);
        y += lh;
        gam.draw_line(Line::new(Point::new(8, y), Point::new(SCREEN_W - 8, y))).ok();
        y += 8;

        text_at(gam, 12, y, 22, &format!("Network:   {}", sub.network.display()), GlyphStyle::Regular);
        y += lh;
        text_at(gam, 12, y, 22, &format!("Broadcast: {}", sub.broadcast.display()), GlyphStyle::Regular);
        y += lh;
        text_at(gam, 12, y, 22, &format!("Mask:      {}", sub.mask.display()), GlyphStyle::Regular);
        y += lh;
        text_at(gam, 12, y, 22, &format!("Prefix:    /{}", sub.prefix), GlyphStyle::Regular);
        y += lh;

        gam.draw_line(Line::new(Point::new(8, y), Point::new(SCREEN_W - 8, y))).ok();
        y += 8;

        text_at(gam, 12, y, 22, &format!("First:     {}", sub.first_host.display()), GlyphStyle::Regular);
        y += lh;
        text_at(gam, 12, y, 22, &format!("Last:      {}", sub.last_host.display()), GlyphStyle::Regular);
        y += lh;
        text_at(gam, 12, y, 22, &format!("Hosts:     {}", sub.host_count), GlyphStyle::Regular);
        y += lh;
        text_at(gam, 12, y, 22, &format!("Class:     {}", sub.class), GlyphStyle::Regular);
    }

    draw_footer(gam, "Left: edit  Right/S: scan  Menu: back");
}

fn draw_ports(gam: &Gam, app: &NetScanApp) {
    draw_header(gam, "Port Reference");

    let start_y: i16 = 36;
    let line_h: i16 = 22;
    let visible = 20;
    let end = (app.port_scroll + visible).min(scanner::PORTS.len());

    // Column headers
    let mut tv = TextView::new(TextBounds::BoundingBox(Point::new(8, start_y), Point::new(SCREEN_W - 8, start_y + 20)));
    tv.style = GlyphStyle::Bold;
    tv.text = String::from("Port   Proto   Service");
    gam.post_textview(&mut tv).ok();

    gam.draw_line(Line::new(Point::new(8, start_y + 20), Point::new(SCREEN_W - 8, start_y + 20))).ok();

    for i in app.port_scroll..end {
        let row = i - app.port_scroll;
        let y = start_y + 24 + (row as i16) * line_h;
        let p = &scanner::PORTS[i];
        let line = format!("{:<6} {:<7} {}", p.port, p.protocol, p.service);
        text_at(gam, 8, y, 20, &line, GlyphStyle::Small);
    }

    if scanner::PORTS.len() > visible {
        let ind = format!("{}-{}/{}", app.port_scroll + 1, end, scanner::PORTS.len());
        text_at(gam, SCREEN_W - 80, FOOTER_Y - 16, 16, &ind, GlyphStyle::Small);
    }

    draw_footer(gam, "Up/Down: scroll  Left: back");
}

fn draw_scan(gam: &Gam, app: &NetScanApp) {
    draw_header(gam, "Scan Results (Simulated)");

    let start_y: i16 = 38;
    let line_h: i16 = 48;
    let visible = 8;

    if app.scan_results.is_empty() {
        text_at(gam, 12, start_y + 20, 22, "No results.", GlyphStyle::Regular);
    } else {
        let end = (app.scan_scroll + visible).min(app.scan_results.len());
        for vi in app.scan_scroll..end {
            let row = vi - app.scan_scroll;
            let y = start_y + (row as i16) * line_h;
            let r = &app.scan_results[vi];
            let selected = vi == app.scan_cursor;

            if selected {
                gam.draw_rectangle(Point::new(4, y - 2), Point::new(SCREEN_W - 4, y + line_h - 4)).ok();
            }

            let mut tv = TextView::new(TextBounds::BoundingBox(Point::new(12, y), Point::new(SCREEN_W - 12, y + 22)));
            tv.style = GlyphStyle::Regular;
            if selected { tv.invert = true; }
            tv.text = format!("{} ({})", r.ip.display(), r.hostname);
            gam.post_textview(&mut tv).ok();

            let ports_str: String = r.open_ports.iter().map(|p| format!("{}", p)).collect::<alloc::vec::Vec<_>>().join(", ");
            let mut tv2 = TextView::new(TextBounds::BoundingBox(Point::new(16, y + 22), Point::new(SCREEN_W - 12, y + line_h)));
            tv2.style = GlyphStyle::Small;
            if selected { tv2.invert = true; }
            tv2.text = format!("Ports: {}", ports_str);
            gam.post_textview(&mut tv2).ok();
        }
    }

    draw_footer(gam, "Up/Down: browse  Enter: detail  Left: back");
}

fn draw_host(gam: &Gam, app: &NetScanApp) {
    if app.scan_cursor >= app.scan_results.len() { return; }
    let host = &app.scan_results[app.scan_cursor];

    draw_header(gam, &host.hostname);

    let mut y: i16 = 40;
    text_at(gam, 12, y, 22, &format!("IP: {}", host.ip.display()), GlyphStyle::Regular);
    y += 26;
    text_at(gam, 12, y, 22, &format!("Hostname: {}", host.hostname), GlyphStyle::Regular);
    y += 30;

    gam.draw_line(Line::new(Point::new(8, y), Point::new(SCREEN_W - 8, y))).ok();
    y += 8;

    text_at(gam, 12, y, 22, "Open Ports:", GlyphStyle::Bold);
    y += 24;

    for &port in &host.open_ports {
        let service = scanner::lookup_port(port)
            .map(|p| format!("{:<6} {:<7} {}", p.port, p.protocol, p.service))
            .unwrap_or_else(|| format!("{:<6} ???     Unknown", port));
        text_at(gam, 16, y, 20, &service, GlyphStyle::Small);
        y += 22;
        if y > FOOTER_Y - 20 { break; }
    }

    draw_footer(gam, "Left: back to scan results");
}
