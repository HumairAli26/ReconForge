"""
modules_catalog.py
------------------
Maps every relevant Metasploit module to a human-readable recon action.
These paths match the modules/ directory structure exactly.
"""

from typing import Dict, List, Any


# ─────────────────────────────────────────────────────────────────────────────
# RECON MODULE CATALOG
# Each entry:
#   "key"          – Python identifier used by the tool
#   "path"         – module path inside Metasploit (use / set)
#   "type"         – auxiliary | exploit | post
#   "category"     – logical grouping for the UI
#   "description"  – one-liner
#   "default_opts" – sane defaults for recon (override at runtime)
#   "run_cmd"      – 'run' or 'exploit' (some modules need exploit)
# ─────────────────────────────────────────────────────────────────────────────

MODULES: List[Dict[str, Any]] = [

    # ── PORT SCANNING ─────────────────────────────────────────────────────────
    {
        "key": "port_scan_tcp",
        "path": "auxiliary/scanner/portscan/tcp",
        "type": "auxiliary",
        "category": "Port Scanning",
        "description": "TCP port scanner",
        "default_opts": {"THREADS": "10", "PORTS": "1-1024"},
        "run_cmd": "run",
    },
    {
        "key": "port_scan_syn",
        "path": "auxiliary/scanner/portscan/syn",
        "type": "auxiliary",
        "category": "Port Scanning",
        "description": "SYN (stealth) port scanner",
        "default_opts": {"THREADS": "10", "PORTS": "1-1024"},
        "run_cmd": "run",
    },
    {
        "key": "port_scan_ack",
        "path": "auxiliary/scanner/portscan/ack",
        "type": "auxiliary",
        "category": "Port Scanning",
        "description": "ACK port scanner (firewall detection)",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "port_scan_udp",
        "path": "auxiliary/scanner/portscan/udp",
        "type": "auxiliary",
        "category": "Port Scanning",
        "description": "UDP port scanner",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "port_scan_xmas",
        "path": "auxiliary/scanner/portscan/xmas",
        "type": "auxiliary",
        "category": "Port Scanning",
        "description": "XMAS port scanner",
        "default_opts": {"THREADS": "5"},
        "run_cmd": "run",
    },

    # ── SERVICE FINGERPRINTING ─────────────────────────────────────────────────
    {
        "key": "ssh_version",
        "path": "auxiliary/scanner/ssh/ssh_version",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "SSH version fingerprinting",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "ftp_version",
        "path": "auxiliary/scanner/ftp/ftp_version",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "FTP banner grabbing",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "http_version",
        "path": "auxiliary/scanner/http/http_version",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "HTTP version / server banner",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "smb_version",
        "path": "auxiliary/scanner/smb/smb_version",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "SMB version detection",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "rdp_enum",
        "path": "auxiliary/scanner/rdp/rdp_scanner",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "Detect open RDP (port 3389)",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "smtp_version",
        "path": "auxiliary/scanner/smtp/smtp_version",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "SMTP version / banner",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "mysql_version",
        "path": "auxiliary/scanner/mysql/mysql_version",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "MySQL version detection",
        "default_opts": {"THREADS": "5"},
        "run_cmd": "run",
    },
    {
        "key": "mssql_ping",
        "path": "auxiliary/scanner/mssql/mssql_ping",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "Find MSSQL servers via UDP ping",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "snmp_version",
        "path": "auxiliary/scanner/snmp/snmp_login",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "SNMP community string / version",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "telnet_version",
        "path": "auxiliary/scanner/telnet/telnet_version",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "Telnet banner grabbing",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "vnc_version",
        "path": "auxiliary/scanner/vnc/vnc_login",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "VNC presence and auth type",
        "default_opts": {"THREADS": "5"},
        "run_cmd": "run",
    },
    {
        "key": "ldap_version",
        "path": "auxiliary/scanner/ldap/ldap_login",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "LDAP server detection",
        "default_opts": {"THREADS": "5"},
        "run_cmd": "run",
    },
    {
        "key": "pop3_version",
        "path": "auxiliary/scanner/pop3/pop3_version",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "POP3 banner grabbing",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "imap_version",
        "path": "auxiliary/scanner/imap/imap_version",
        "type": "auxiliary",
        "category": "Service Fingerprinting",
        "description": "IMAP banner grabbing",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },

    # ── WEB RECONNAISSANCE ────────────────────────────────────────────────────
    {
        "key": "http_header",
        "path": "auxiliary/scanner/http/http_header",
        "type": "auxiliary",
        "category": "Web Reconnaissance",
        "description": "Collect HTTP response headers",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "dir_brute",
        "path": "auxiliary/scanner/http/dir_brute",
        "type": "auxiliary",
        "category": "Web Reconnaissance",
        "description": "HTTP directory brute-force",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "robots_txt",
        "path": "auxiliary/scanner/http/robots_txt",
        "type": "auxiliary",
        "category": "Web Reconnaissance",
        "description": "Fetch and parse robots.txt",
        "default_opts": {},
        "run_cmd": "run",
    },
    {
        "key": "http_title",
        "path": "auxiliary/scanner/http/title",
        "type": "auxiliary",
        "category": "Web Reconnaissance",
        "description": "Grab web page title",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "ssl_cert",
        "path": "auxiliary/scanner/ssl/openssl_heartbleed",
        "type": "auxiliary",
        "category": "Web Reconnaissance",
        "description": "SSL/TLS certificate info + Heartbleed check",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "http_options",
        "path": "auxiliary/scanner/http/options",
        "type": "auxiliary",
        "category": "Web Reconnaissance",
        "description": "Enumerate allowed HTTP methods",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "web_crawl",
        "path": "auxiliary/crawler/msfcrawler",
        "type": "auxiliary",
        "category": "Web Reconnaissance",
        "description": "Spider / crawl a web application",
        "default_opts": {"THREADS": "5"},
        "run_cmd": "run",
    },

    # ── HOST DISCOVERY ────────────────────────────────────────────────────────
    {
        "key": "arp_sweep",
        "path": "auxiliary/scanner/discovery/arp_sweep",
        "type": "auxiliary",
        "category": "Host Discovery",
        "description": "ARP host discovery on local subnet",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "udp_sweep",
        "path": "auxiliary/scanner/discovery/udp_sweep",
        "type": "auxiliary",
        "category": "Host Discovery",
        "description": "UDP host discovery sweep",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "ipv6_neighbor_router",
        "path": "auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement",
        "type": "auxiliary",
        "category": "Host Discovery",
        "description": "IPv6 host discovery via router advertisements",
        "default_opts": {},
        "run_cmd": "run",
    },

    # ── SMB / WINDOWS ─────────────────────────────────────────────────────────
    {
        "key": "smb_enumusers",
        "path": "auxiliary/scanner/smb/smb_enumusers",
        "type": "auxiliary",
        "category": "SMB / Windows",
        "description": "Enumerate SMB users",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "smb_enumshares",
        "path": "auxiliary/scanner/smb/smb_enumshares",
        "type": "auxiliary",
        "category": "SMB / Windows",
        "description": "Enumerate SMB shares",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "smb_ms17_010_check",
        "path": "auxiliary/scanner/smb/smb_ms17_010",
        "type": "auxiliary",
        "category": "SMB / Windows",
        "description": "Check for EternalBlue (MS17-010)",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "smb_ms17_010_exploit",
        "path": "exploit/windows/smb/ms17_010_eternalblue",
        "type": "exploit",
        "category": "SMB / Windows",
        "description": "EternalBlue SMB RCE (MS17-010)",
        "default_opts": {"PAYLOAD": "windows/x64/meterpreter/reverse_tcp"},
        "run_cmd": "exploit",
    },
    {
        "key": "smb_login",
        "path": "auxiliary/scanner/smb/smb_login",
        "type": "auxiliary",
        "category": "SMB / Windows",
        "description": "SMB credential brute-force",
        "default_opts": {"THREADS": "5"},
        "run_cmd": "run",
    },

    # ── VULNERABILITY CHECKS ──────────────────────────────────────────────────
    {
        "key": "ssh_login",
        "path": "auxiliary/scanner/ssh/ssh_login",
        "type": "auxiliary",
        "category": "Vulnerability Checks",
        "description": "SSH credential brute-force",
        "default_opts": {"THREADS": "5"},
        "run_cmd": "run",
    },
    {
        "key": "ftp_anonymous",
        "path": "auxiliary/scanner/ftp/anonymous",
        "type": "auxiliary",
        "category": "Vulnerability Checks",
        "description": "Check for anonymous FTP login",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "mysql_login",
        "path": "auxiliary/scanner/mysql/mysql_login",
        "type": "auxiliary",
        "category": "Vulnerability Checks",
        "description": "MySQL credential brute-force",
        "default_opts": {"THREADS": "5", "BLANK_PASSWORDS": "true"},
        "run_cmd": "run",
    },
    {
        "key": "http_shellshock",
        "path": "auxiliary/scanner/http/apache_mod_cgi_bash_env",
        "type": "auxiliary",
        "category": "Vulnerability Checks",
        "description": "ShellShock (CVE-2014-6271) check",
        "default_opts": {},
        "run_cmd": "run",
    },
    {
        "key": "vnc_none_auth",
        "path": "auxiliary/scanner/vnc/vnc_none_auth",
        "type": "auxiliary",
        "category": "Vulnerability Checks",
        "description": "Detect VNC servers with no authentication",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },
    {
        "key": "smb_bluekeep_check",
        "path": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
        "type": "auxiliary",
        "category": "Vulnerability Checks",
        "description": "BlueKeep (CVE-2019-0708) RDP check",
        "default_opts": {"THREADS": "10"},
        "run_cmd": "run",
    },

    # ── DNS ───────────────────────────────────────────────────────────────────
    {
        "key": "dns_enum",
        "path": "auxiliary/gather/dns_enum",
        "type": "auxiliary",
        "category": "DNS",
        "description": "DNS enumeration (A, MX, NS, SOA…)",
        "default_opts": {},
        "run_cmd": "run",
    },
    {
        "key": "dns_bruteforce",
        "path": "auxiliary/gather/dns_bruteforce",
        "type": "auxiliary",
        "category": "DNS",
        "description": "DNS subdomain brute-force",
        "default_opts": {},
        "run_cmd": "run",
    },

    # ── CLOUD / WEB APP EXPLOITS (for confirmation/check only) ────────────────
    {
        "key": "apache_solr_info",
        "path": "auxiliary/scanner/http/apache_solr_information_disclosure",
        "type": "auxiliary",
        "category": "Web App Checks",
        "description": "Apache Solr unauthenticated info disclosure",
        "default_opts": {"THREADS": "5"},
        "run_cmd": "run",
    },
    {
        "key": "docker_tcp",
        "path": "auxiliary/scanner/http/docker_registry_enum",
        "type": "auxiliary",
        "category": "Web App Checks",
        "description": "Enumerate exposed Docker registry",
        "default_opts": {"THREADS": "5"},
        "run_cmd": "run",
    },
    {
        "key": "hadoop_info",
        "path": "exploit/linux/http/hadoop_unauth_exec",
        "type": "exploit",
        "category": "Web App Checks",
        "description": "Unauthenticated Hadoop YARN RCE (check mode)",
        "default_opts": {},
        "run_cmd": "check",
    },
    {
        "key": "log4shell_check",
        "path": "auxiliary/scanner/http/log4shell_scanner",
        "type": "auxiliary",
        "category": "Web App Checks",
        "description": "Log4Shell (CVE-2021-44228) scanner",
        "default_opts": {"THREADS": "5"},
        "run_cmd": "run",
    },
]

# ── convenience look-ups ───────────────────────────────────────────────────────

def get_module(key: str) -> Dict:
    for m in MODULES:
        if m["key"] == key:
            return m
    raise KeyError(f"No module with key '{key}'")

def list_categories() -> List[str]:
    seen = []
    for m in MODULES:
        if m["category"] not in seen:
            seen.append(m["category"])
    return seen

def modules_for_category(category: str) -> List[Dict]:
    return [m for m in MODULES if m["category"] == category]
