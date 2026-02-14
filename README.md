# Network Scanner

A network scanning educational tool for the [Precursor](https://precursor.dev) handheld, with subnet calculator, port reference, and simulated scan results on the 336x536 monochrome 1-bit display.

## Features

- **Subnet calculator** — CIDR input, network/broadcast/mask/host range computation
- **Port reference** — 25 well-known ports with protocol and service names
- **Scan simulator** — Simulated network scan with 6 sample hosts and open ports
- **Host detail** — Per-host view showing IP, hostname, and port breakdown
- **IP parser** — Validates dotted-quad and CIDR notation

## Architecture

- `scanner.rs` — IPv4 handling, subnet math, port table, scan simulation
- `app.rs` — 5-state machine (SubnetInput → SubnetResult → ScanSim → HostDetail, PortRef)
- `ui.rs` — CIDR input, subnet results, port table, scan list, host detail
- `main.rs` — Standard Xous event loop

## Controls

| Key | Action |
|-----|--------|
| 0-9, ., / | Enter IP/CIDR |
| Enter | Calculate subnet |
| Right | Port reference / Scan |
| Up/Down | Scroll lists |
| Left | Back |
| Menu (∴) | Quit |

---

## Development

This app was developed using the methodology described in [xous-dev-toolkit](https://github.com/tbcolby/xous-dev-toolkit) — an LLM-assisted approach to Precursor app development on macOS ARM64.

---

## Author

Made by Tyler Colby — [Colby's Data Movers, LLC](https://colbysdatamovers.com)

Contact: [tyler@colbysdatamovers.com](mailto:tyler@colbysdatamovers.com) | [GitHub Issues](https://github.com/tbcolby/precursor-netscan/issues)

---

## License

Licensed under the Apache License, Version 2.0.

See [LICENSE](LICENSE) for the full text.
