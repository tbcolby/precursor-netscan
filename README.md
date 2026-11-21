# Net Check

A subnet calculator, a port reference and a small, rate-limited TCP connect check for the [Precursor](https://precursor.dev) handheld.

**This is not a network scanner.** The app is still named `netscan` for continuity; the earlier versions "scanned" by printing six invented hosts for any subnet, which is gone. What it does now is only what the Xous network stack gives an app: ordinary TCP connections and DNS lookups. It cannot ping, ARP, send raw packets, sweep an address range or fingerprint anything, and it does none of those.

Version 0.2. Not yet run on Renode or hardware: `capture.py` is written but unrun, and there are no screenshots yet. The connect check relies on `std::net::TcpStream::connect_timeout` through the Xous network stack; it is tested here against a real loopback listener and a fake network, not on a device with Wi-Fi.

## What it does

1. **Check TCP ports on a host.** You type one host (an IPv4 address or a host name) and up to 16 ports. A confirmation screen says exactly what will happen. Only when you press Enter there does it try one TCP connection per port.
2. **Subnet calculator.** `a.b.c.d/n` gives mask, wildcard, network, broadcast, host count, first and last host, class and address type (private, loopback, link-local, CGNAT, documentation, multicast, public ...). `/0`, `/31` (RFC 3021) and `/32` are handled. Leading zeros (`010.1.1.1`) are rejected. Without `/n` the classful default is used and flagged.
3. **Port reference.** 29 common ports with protocol and service.

## The connect check, precisely

- **Never without you.** Nothing is preloaded, nothing connects while you type, and nothing runs in the background. The check starts only when you press Enter on the confirmation screen. "Check again" goes back to that screen.
- **One host.** No ranges, no `/24`, no subnets, no lists of hosts. Multicast, broadcast, `0.x` and class E addresses are refused. A name's address is shown after lookup, and a name that resolves to something unconnectable is refused.
- **At most 16 ports**, so a range like `1-65535` is refused, not started.
- **Rate-limited.** One connection at a time, 2 s timeout each, 250 ms between attempts: about four attempts a second at the very most, usually far fewer. The confirmation screen shows the worst-case time.
- **Cancellable.** Backspace or F4 stops it before its next connection (an attempt already in progress ends within its 2 s timeout). Leaving the app cancels too.
- **Nothing is sent.** Each connection is closed as soon as it opens; no banner grabbing, no probes. A public address gets a note on the confirmation screen to check only hosts you own or may test.
- **Results:** `open` (the connection was accepted), `closed` (the host answered and refused), `no reply` (nothing within 2 s: filtered, down or slow), `unreachable` (no route; is Wi-Fi connected?), `error`.

A TCP connect is visible to the host and to anything watching it, like any connection. Use it on your own network and hosts.

## Keys

The `∴` menu key belongs to the OS and is not used. Backspace or F4 goes back one screen everywhere; on the home screen it leaves the app.

| Screen | Keys |
|---|---|
| Home | Up/Down; Enter or Right open |
| Host | type; Left/Right move; Enter next; F3 clear; Backspace delete (on an empty field: back) |
| Ports | digits, `,` `-` space; F1 fills `22,80,443`; Enter review; F3 clear |
| Confirm | **Enter starts the check**; Backspace, F4 or Left cancel |
| Running | Backspace or F4 cancel |
| Results | Up/Down; F1 or Right check again (back to Confirm) |
| Subnet | digits, `.`, `/`; Enter calculate; F3 clear |
| Port reference | Up/Down scroll |

## Storage

None. Nothing is saved, so there is nothing to reload when PDDB bases change.

## Not supported

Ping (ICMP), ARP, raw sockets, UDP probes, IPv6, address-range scans, banner grabbing, OS fingerprinting. Xous exposes none of the lower-level ones to apps, and the app does not pretend otherwise.

## Layout

- `core/` (`netscan-core`): `ip.rs` (subnet maths, address kinds), `ports.rs` (table, port-list parsing), `check.rs` (targets, the rate-limited runner behind a `Connector` trait, the `std` connector), `app.rs` (screen state). No Xous dependencies; 34 host tests, including a real loopback connect.
- `src/`: Xous shell on `precursor-appkit`; `net.rs` is the worker thread.
- `manifest-fragment.json`: the `netscan` entry. `capture.py`: Renode sequence (unrun; it stops at the confirmation screen and never starts a check).

## Build

```bash
xous-dev-toolkit/bin/integrate --xous-root ~/xous-core --grade precursor-netscan
cd precursor-netscan/core && cargo test
```

## Author

Made by Tyler Colby, [Colby's Data Movers, LLC](https://colbysdatamovers.com). Licensed under the Apache License 2.0; see [LICENSE](LICENSE).
