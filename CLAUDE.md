# Network Scanner — Build Notes
## What This Is
Network scanning educational tool for Precursor.
## Key Decisions
- Subnet calculator using bitwise mask operations (no float)
- 25 well-known ports embedded as static table
- Simulated scan with 6 preset hosts (can't do real network I/O)
- 5 states: SubnetInput, SubnetResult, PortRef, ScanSim, HostDetail
