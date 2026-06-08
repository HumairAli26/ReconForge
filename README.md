# ⚔️ ReconForge

## Advanced Network Discovery & Security Assessment Platform

ReconForge is a comprehensive Linux-based reconnaissance and security assessment framework designed to automate network discovery, service enumeration, vulnerability identification, and infrastructure analysis from a single command-line interface.

Built with cybersecurity professionals, students, researchers, and penetration testers in mind, ReconForge combines the power of Python, Nmap, Scapy, DNS intelligence gathering, and optional Metasploit integration into a unified reconnaissance platform capable of performing both rapid assessments and in-depth network analysis.

> ⚠️ **Authorized Use Only**
>
> ReconForge is intended exclusively for educational purposes, authorized penetration testing, security research, and assessments conducted with explicit permission from the system owner. Unauthorized scanning or testing of systems may violate local laws and regulations.

---

# 🎯 Project Goals

ReconForge was developed to simplify and automate the reconnaissance phase of security assessments by providing:

✅ Host Discovery

✅ Port Scanning

✅ Service Fingerprinting

✅ DNS Intelligence Gathering

✅ Vulnerability Enumeration

✅ Automated Reporting

✅ Metasploit Integration

✅ Interactive Assessment Workflows

All within a single platform.

---

# ✨ Key Features

## 🌐 Advanced Host Discovery

ReconForge employs a multi-layered discovery strategy to maximize device detection accuracy.

### Discovery Techniques

🔹 Nmap Host Discovery

🔹 ARP Sweeping (Scapy)

🔹 Parallel ICMP Probing

🔹 TCP Reachability Checks

🔹 UDP Reachability Checks

### Benefits

* Detects devices that block ICMP ping
* Finds hidden hosts on local networks
* Improves discovery accuracy
* Faster than traditional single-method scanning

---

## 🔍 High-Speed Port Scanning

ReconForge performs intelligent two-stage port scanning.

### Phase 1

Scan the most common 1000 ports for rapid results.

### Phase 2

Expand to all 65,535 TCP ports for comprehensive analysis.

### Additional Capabilities

* Service Version Detection
* Operating System Fingerprinting
* Protocol Identification
* Open Port Classification

---

## 🖥 Service Enumeration

After identifying open ports, ReconForge automatically gathers detailed information about exposed services.

### Supported Enumeration

* HTTP Header Analysis
* Web Server Identification
* Banner Grabbing
* SSL Certificate Inspection
* Service Version Collection
* Protocol Detection

This enables quick identification of technologies and potentially outdated software.

---

## 🌍 DNS Intelligence Gathering

Perform detailed DNS reconnaissance against target domains.

### Supported Record Types

📌 A Records

📌 AAAA Records

📌 MX Records

📌 NS Records

📌 TXT Records

📌 CNAME Records

### Benefits

* Discover mail infrastructure
* Identify hosting providers
* Gather domain intelligence
* Support attack surface mapping

---

## 🚀 Metasploit Integration

ReconForge includes optional integration with the Metasploit Framework.

### Fast Boot Mode

Traditional Metasploit startup:

⏱ 2–3 Minutes

ReconForge optimized startup:

⚡ 15–45 Seconds

### Capabilities

* Auxiliary Module Execution
* Vulnerability Verification
* Service-Specific Enumeration
* Automated Module Selection

### Offline Safe

ReconForge automatically falls back to pure Python mode if Metasploit is unavailable.

---

## 🖥 Interactive Terminal Interface (TUI)

For users who prefer guided workflows, ReconForge provides an interactive text-based interface.

### Features

* Menu-driven navigation
* Guided assessments
* Interactive module selection
* Report viewing
* Session management

Ideal for beginners and classroom demonstrations.

---

## 📊 Automated JSON Reporting

Every scan automatically generates structured reports.

### Included Information

* Target Details
* Host Discovery Results
* Open Ports
* Service Information
* DNS Records
* Module Results
* Scan Metadata

Reports can be easily integrated into:

* SIEM Platforms
* Dashboards
* Security Pipelines
* Custom Analysis Tools

---

## 🔌 Fully Functional Offline Mode

ReconForge remains operational even without Metasploit.

### Available Offline Features

✅ Host Discovery

✅ Port Scanning

✅ DNS Enumeration

✅ Service Fingerprinting

✅ Reporting

This makes the tool lightweight and highly portable.

---

# 🏗 Architecture Overview

ReconForge follows a modular architecture that separates scanning, enumeration, reporting, and external integrations.

```text
ReconForge
│
├── CLI Layer
│   ├── Argument Parsing
│   └── Interactive TUI
│
├── Recon Engine
│   ├── Host Discovery
│   ├── Port Scanning
│   ├── Service Enumeration
│   ├── DNS Intelligence
│   └── Reporting
│
├── Metasploit Layer
│   ├── MSF Bridge
│   ├── Module Runner
│   └── Auxiliary Modules
│
└── Output Layer
    ├── JSON Reports
    ├── Console Output
    └── Future Web Dashboard
```

---

# ⚡ Installation

## Quick Installation

Install directly from GitHub:

```bash
pip install git+https://github.com/humairali/ReconForge.git
```

Run:

```bash
reconforge -t <target>
```

---

## Recommended Installation

Clone the repository:

```bash
git clone https://github.com/humairali/ReconForge.git
cd ReconForge
```

Run the installer:

```bash
sudo bash install.sh
```

Launch:

```bash
reconforge --help
```

---

## Auto-Install Mode

```bash
bash run.sh -t <target>
```

ReconForge automatically installs missing dependencies before execution.

---

## Makefile Installation

```bash
make install
```

Run:

```bash
make run
```

---

# 🚀 Usage Examples

## Basic Host Scan

```bash
reconforge -t 192.168.1.1
```

---

## Pure Python Mode

```bash
reconforge -t 192.168.1.1 --no-msf
```

---

## Scan a Domain

```bash
reconforge -t example.com --no-msf
```

---

## Additional Ports

```bash
reconforge -t 192.168.1.1 -p 8080,8443,9000-9100
```

---

## Save Custom Report

```bash
reconforge -t 192.168.1.1 -o report.json
```

---

## Interactive Mode

```bash
reconforge --interactive
```

---

# 🧰 Utility Commands

## Dependency Verification

```bash
reconforge --check-deps
```

---

## Available Metasploit Modules

```bash
reconforge --list-modules
```

---

## Module Categories

```bash
reconforge --list-categories
```

---

## Version Information

```bash
reconforge --version
```

---

# 📂 Project Structure

```text
ReconForge/
│
├── reconforge/
│   ├── cli.py
│   ├── interactive.py
│   │
│   ├── core/
│   │   ├── recon_engine.py
│   │   ├── msf_bridge.py
│   │   ├── msf_module_runner.py
│   │   └── report_generator.py
│   │
│   ├── modules/
│   │   └── catalog.py
│   │
│   ├── utils/
│   │   └── deps.py
│   │
│   └── static/
│       ├── css/
│       ├── js/
│       └── index.html
│
├── docs/
├── tests/
├── install.sh
├── uninstall.sh
├── requirements.txt
├── pyproject.toml
├── setup.py
└── README.md
```

---

# 🛡 Supported Security Modules

| Category                  | Capabilities                         |
| ------------------------- | ------------------------------------ |
| 🔍 Port Scanning          | TCP, SYN, ACK, UDP scans             |
| 🌐 Host Discovery         | ARP, ICMP, NetBIOS discovery         |
| 🖥 Service Fingerprinting | HTTP, FTP, SSH, SMB, RDP, MySQL      |
| 🚨 Vulnerability Checks   | Heartbleed, MS17-010, EternalBlue    |
| 🌎 Web Enumeration        | Directories, headers, methods, Nikto |
| 📡 DNS Enumeration        | Zone transfers, subdomain discovery  |
| 📶 SNMP Enumeration       | Community strings, OID walking       |
| 🗂 SMB Enumeration        | Shares, users, OS information        |

---

# 📈 Future Roadmap

ReconForge is actively designed for future expansion.

Planned features include:

### 🌐 Web Dashboard

Interactive browser-based interface.

### 🕸 Network Topology Visualization

Real-time 2D and 3D network mapping.

### 🤖 Automated Risk Scoring

CVSS-based vulnerability ranking.

### 📊 Advanced Reporting

PDF, HTML, and Executive Reports.

### ☁ Cloud Asset Discovery

AWS, Azure, and GCP reconnaissance.

### 🔄 Continuous Monitoring

Scheduled assessments and alerts.

---

# 🎓 Educational Value

ReconForge serves as an excellent learning platform for:

* Network Security
* Penetration Testing
* Ethical Hacking
* Cybersecurity Research
* Network Enumeration
* Vulnerability Assessment
* Python Security Tool Development

---

# 🗑 Uninstallation

```bash
sudo ./uninstall.sh
```

---

# ⚖ Legal Disclaimer

ReconForge is intended solely for:

* Authorized penetration testing
* Security research
* Educational environments
* Laboratory simulations
* Systems owned by the user

The developer assumes no responsibility for misuse, unauthorized access, or illegal activity conducted using this software.

Always obtain written permission before assessing any system.

---

# 📜 License

MIT License

© Humair Ali

---

# 🏆 Conclusion

ReconForge is a modern reconnaissance and security assessment framework that streamlines the information-gathering phase of penetration testing. By integrating host discovery, service enumeration, DNS intelligence, vulnerability verification, reporting, and optional Metasploit support into a single platform, ReconForge provides both beginners and security professionals with a powerful, efficient, and extensible cybersecurity toolkit.
