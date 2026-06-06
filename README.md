# ReconForge

**Network Discovery & Security Assessment Platform**

ReconForge is a powerful, cross-distribution Linux recon tool that performs host discovery, port scanning, service fingerprinting, DNS enumeration, and optional Metasploit integration — all from a single command.

> ⚠️ **For authorised security assessments only.** Only scan systems you own or have explicit written permission to test.

---

## Features

- **Host Discovery** — Triple-method: nmap (primary) + ARP sweep (Scapy) + parallel ICMP/TCP/UDP probe — finds all devices including those that block ping
- **Port Scanning** — Full 65,535-port scan in two phases; top-1000 ports first for speed, then full sweep; nmap service version detection on found ports
- **Service Enumeration** — Banner grabbing, HTTP headers, SSL cert inspection
- **DNS Recon** — A, AAAA, MX, NS, TXT, CNAME lookups
- **Metasploit Integration** — Fast-boot mode (skips DB init, ~15-45s vs ~2-3min); optional MSF auxiliary module runner (offline-safe)
- **Interactive TUI** — Menu-driven session for guided assessments
- **JSON Reports** — Structured output saved automatically after each scan
- **Offline Mode** — Full functionality without Metasploit installed

---

## Quick Install (One Command)

```bash
pip install git+https://github.com/humairali/ReconForge.git
```

Then run:

```bash
reconforge -t <target>
```

---

## Full Install (Recommended — Zero chmod needed)

```bash
# 1. Clone
git clone https://github.com/humairali/ReconForge.git
cd ReconForge

# 2. Run installer — no chmod needed, just:
sudo bash install.sh

# 3. Done — run it
reconforge --help
```

Or even simpler — auto-installs on first run:

```bash
bash run.sh -t <target>
```

Or with make:

```bash
make install   # install
make run       # install if needed + launch
```

---

## Usage

```
reconforge [OPTIONS]
```

### Basic Scan

```bash
# Scan a single host (auto offline/online mode)
reconforge -t 192.168.1.1

# Scan without Metasploit
reconforge -t 192.168.1.1 --no-msf

# Scan a hostname
reconforge -t example.com --no-msf

# Scan with extra ports
reconforge -t 192.168.1.1 -p 8080,8443,9000-9100 --no-msf

# Save report to custom file
reconforge -t 192.168.1.1 --no-msf -o my_report.json
```

### Metasploit Mode

```bash
# Full scan with Metasploit auxiliary modules
reconforge -t 192.168.1.1 --lhost 192.168.1.100

# Specific module categories only
reconforge -t 192.168.1.1 -c "Port Scanning" "Service Fingerprinting"

# Custom msfconsole path
reconforge -t 192.168.1.1 --msf-path /opt/metasploit-framework/bin/msfconsole
```

### Interactive TUI

```bash
reconforge --interactive
```

### Utility Commands

```bash
reconforge --check-deps          # Verify system dependencies
reconforge --list-modules        # Show all available MSF modules
reconforge --list-categories     # Show module categories
reconforge --version             # Show version
```

---

## Options Reference

| Flag | Description |
|------|-------------|
| `-t, --target` | IP, hostname, or CIDR range |
| `-i, --interactive` | Launch interactive TUI |
| `--no-msf` | Pure Python mode (no Metasploit) |
| `--msf-path PATH` | Path to msfconsole binary |
| `--lhost IP` | Local IP for MSF payloads |
| `--lport PORT` | Local port (default: 4444) |
| `-c CATS...` | Filter by module categories |
| `-p PORTS` | Extra ports (e.g. `22,80,8000-8100`) |
| `--threads N` | Scan thread count (default: 100) |
| `--timeout SECS` | TCP timeout (default: 1.5s) |
| `-o FILE` | Save report to file |
| `--no-banner` | Suppress ASCII banner |
| `--check-deps` | Check system dependencies |
| `--list-modules` | List available MSF modules |
| `--list-categories` | List module categories |

---

## System Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| OS | Ubuntu 20.04+ / Kali / Parrot / Debian 11+ | Any modern Linux distro |
| Python | 3.9+ | `python3 --version` |
| nmap | Any recent | `sudo apt install nmap` |
| Metasploit | Optional | Only needed for MSF mode |

---

## Project Structure

```
ReconForge/
│
├── reconforge/                   # Main Python package
│   ├── __init__.py               # Version, metadata
│   ├── cli.py                    # Entry point (reconforge command)
│   ├── interactive.py            # Interactive TUI session
│   │
│   ├── core/                     # Core engine modules
│   │   ├── __init__.py
│   │   ├── recon_engine.py       # Main orchestrator
│   │   ├── msf_bridge.py         # Metasploit subprocess bridge
│   │   ├── msf_module_runner.py  # Module execution logic
│   │   └── report_generator.py  # Report formatting
│   │
│   ├── modules/                  # Module definitions
│   │   ├── __init__.py
│   │   └── catalog.py            # MSF module catalog
│   │
│   ├── utils/                    # Utilities
│   │   ├── __init__.py
│   │   └── deps.py               # Dependency checker
│   │
│   └── static/                   # Web UI assets (future)
│       ├── css/style.css
│       ├── js/app.js
│       ├── js/network3d.js
│       └── index.html
│
├── tests/                        # Unit tests
├── docs/                         # Documentation
│
├── setup.py                      # Legacy pip install support
├── pyproject.toml                # Modern packaging (PEP 517/518)
├── requirements.txt              # Python dependencies
├── install.sh                    # Linux installer script
├── uninstall.sh                  # Uninstaller
├── LICENSE                       # MIT
└── README.md
```

---

## Module Categories

| Category | Description |
|---|---|
| Port Scanning | TCP, SYN, ACK, UDP scanners |
| Host Discovery | ARP, ICMP, NetBIOS discovery |
| Service Fingerprinting | FTP, SSH, HTTP, SMB, MySQL, RDP banners |
| Vulnerability Checks | MS17-010, EternalBlue, Heartbleed, etc. |
| Web Enumeration | HTTP methods, directory brute-force, Nikto |
| DNS Enumeration | Zone transfers, subdomain brute-force |
| SNMP Enumeration | Community strings, OID walking |
| SMB Enumeration | Shares, users, OS detection |

---

## Uninstall

```bash
chmod +x uninstall.sh
sudo ./uninstall.sh
```

---

## Legal

This tool is intended **only** for:
- Penetration testing of systems you own
- Authorised security assessments with written permission
- Education and research in controlled lab environments

Unauthorised scanning is illegal in most jurisdictions. The author takes no responsibility for misuse.

---

## License

MIT © Humair Ali
