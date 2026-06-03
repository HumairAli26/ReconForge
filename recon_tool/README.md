# MSF Recon Tool — Python Recon Framework powered by Metasploit

> ⚠️ **For authorised security assessments only.** Do not use against systems you do not own or have explicit permission to test.

---

## Overview

A Python-based recon tool that **wraps Metasploit Framework modules** and adds its own built-in probes, giving you:

| Feature | Without MSF | With MSF |
|---|---|---|
| Port scanning | ✅ Python (threaded TCP) | ✅ + SYN/ACK/UDP/XMAS |
| Banner grabbing | ✅ Raw socket | ✅ + service-specific |
| HTTP recon | ✅ Headers, SSL cert | ✅ + dir brute, robots.txt |
| DNS enumeration | ✅ dnspython | ✅ + subdomain brute |
| SMB enumeration | ❌ | ✅ Users, shares, MS17-010 |
| Vulnerability checks | ❌ | ✅ ShellShock, BlueKeep, Log4Shell… |
| HTML report | ✅ | ✅ |

---

## File Structure

```
recon_tool/
├── main.py               # CLI entry point
├── interactive.py        # Interactive TUI menu
├── recon_engine.py       # Core orchestration + offline probes
├── msf_bridge.py         # msfconsole subprocess bridge
├── modules_catalog.py    # All 45+ mapped Metasploit modules
├── report_generator.py   # JSON → HTML report
└── requirements.txt
```

---

## Installation

```powershell
# 1. Enter the tool directory
cd D:\Metasploit-framework\recon_tool

# 2. (Recommended) create a virtual environment
python -m venv .venv
.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

> **dnspython** is optional — DNS falls back to `socket.gethostbyname` if not installed.

---

## Usage

### CLI Mode

```powershell
# Basic scan (offline Python probes only)
python main.py -t 192.168.1.1 --no-msf

# Full scan with Metasploit (msfconsole must be running / on PATH)
python main.py -t 192.168.1.1

# Specify msfconsole path manually
python main.py -t 10.0.0.5 --msf-path "C:\metasploit-framework\bin\msfconsole.bat"

# Scan with custom ports + specific categories
python main.py -t scanme.nmap.org -p "8000-9000,27017" -c "Port Scanning" "Web Reconnaissance"

# Save report to file
python main.py -t 192.168.1.1 -o my_scan.json

# List all available modules
python main.py --list-modules

# List categories
python main.py --list-categories
```

### Interactive TUI Mode

```powershell
python interactive.py
```

Presents a menu to:
1. Run full auto recon
2. Pick categories
3. Run a single module with custom options
4. Browse the module catalog

### Generate HTML Report from JSON

```powershell
python report_generator.py recon_192.168.1.1_1234567890.json report.html
```

---

## Module Categories

| Category | Modules | Notes |
|---|---|---|
| **Port Scanning** | TCP, SYN, ACK, UDP, XMAS | MSF required for SYN/ACK/XMAS |
| **Service Fingerprinting** | SSH, FTP, HTTP, SMB, RDP, SMTP, MySQL, MSSQL, SNMP, Telnet, VNC, LDAP, POP3, IMAP | |
| **Web Reconnaissance** | Headers, dir brute, robots.txt, title, SSL, crawl, HTTP methods | |
| **Host Discovery** | ARP sweep, UDP sweep, IPv6 | Local network only for ARP |
| **SMB / Windows** | User enum, share enum, MS17-010 check + exploit, login brute | |
| **Vulnerability Checks** | SSH login, FTP anon, MySQL login, ShellShock, VNC no-auth, BlueKeep | |
| **DNS** | Full DNS enum, subdomain brute | |
| **Web App Checks** | Apache Solr, Docker registry, Hadoop, Log4Shell | |

---

## How It Works

```
main.py / interactive.py
        │
        ▼
  ReconEngine
  ├── Offline Probes (always run)
  │   ├── Threaded TCP port scan
  │   ├── Banner grabbing
  │   ├── HTTP HEAD requests
  │   ├── SSL certificate parsing
  │   └── DNS lookups
  │
  └── MSFBridge (if msfconsole available)
      ├── Launches msfconsole as subprocess
      ├── Loads modules from modules_catalog.py
      ├── Sets RHOSTS + options
      ├── Runs and captures output
      └── Returns structured results
```

---

## Adding Custom Modules

Edit `modules_catalog.py` and append to `MODULES`:

```python
{
    "key": "my_custom_check",
    "path": "auxiliary/scanner/http/my_module",   # MSF module path
    "type": "auxiliary",
    "category": "Web App Checks",
    "description": "My custom check",
    "default_opts": {"THREADS": "5"},
    "run_cmd": "run",
},
```

---

## Requirements

- Python 3.8+
- Metasploit Framework (optional — falls back to offline mode)
- `rich` — pretty terminal output
- `dnspython` — full DNS enumeration

---

## Legal Notice

This tool is provided for **educational and authorised penetration testing** purposes only.
Unauthorised use against systems is illegal. Always obtain written permission before testing.
