"""
core/vuln_engine.py
-------------------
Matches ports and banners to common vulnerabilities/CVEs for standard
services found in vulnerable environments like Metasploitable.
"""

from typing import List, Dict

# Local DB matching known service signatures to vulnerability records
VULN_SIGNATURES = [
    {
        "port": 21,
        "banner_contains": "vsftpd 2.3.4",
        "cve": "CVE-2011-2523",
        "name": "vsftpd 2.3.4 Backdoor Double Free / Execution",
        "description": "The vsftpd 2.3.4 download archive contained a backdoor that opens a shell on port 6200 when a username containing ':)' is supplied.",
        "severity": "Critical",
        "cvss": 10.0,
        "remediation": "Update vsftpd to a secure version, or replace with standard FTP/SFTP server implementation."
    },
    {
        "port": 22,
        "banner_contains": "SSH-2.0-OpenSSH_4.7p1",
        "cve": "CVE-2008-0166",
        "name": "Debian OpenSSL Predictable PRNG (Weak Keys)",
        "description": "A vulnerability in the OpenSSL package on Debian/Ubuntu systems allowed generating predictable SSH keys, leading to potential authentication bypass.",
        "severity": "High",
        "cvss": 7.8,
        "remediation": "Regenerate all SSH keys on the host, upgrade openssl, and reject weak ssh keys."
    },
    {
        "port": 445,
        "service": "SMB",
        "name": "SMB EternalBlue Check (MS17-010)",
        "cve": "CVE-2017-0144",
        "description": "Remote code execution vulnerability in Microsoft Server Message Block 1.0 (SMBv1) protocol.",
        "severity": "Critical",
        "cvss": 10.0,
        "remediation": "Disable SMBv1 protocol entirely and apply MS17-010 security update."
    },
    {
        "port": 3306,
        "service": "MySQL",
        "name": "MySQL Default/Weak Credentials",
        "cve": "Weak Config",
        "description": "MySQL database server exposes administration access without credentials or uses simple defaults (e.g. root:root).",
        "severity": "High",
        "cvss": 8.5,
        "remediation": "Configure strong administrative passwords and restrict MySQL access to localhost."
    },
    {
        "port": 80,
        "banner_contains": "Apache/2.2.8",
        "cve": "CVE-2012-1823",
        "name": "PHP-CGI Query String Parameter Vulnerability",
        "description": "PHP-CGI allows remote attackers to execute arbitrary code or view source code via direct query string parameters.",
        "severity": "High",
        "cvss": 7.5,
        "remediation": "Upgrade PHP interpreter or switch from CGI to FastCGI/PHP-FPM."
    },
    {
        "port": 8180,
        "banner_contains": "Apache-Coyote",
        "cve": "CVE-2010-1157",
        "name": "Apache Tomcat Default Manager Credentials",
        "cve": "Weak Config",
        "description": "Tomcat administration manager page uses default administrator credentials, enabling arbitrary WAR file uploads (Remote Code Execution).",
        "severity": "Critical",
        "cvss": 10.0,
        "remediation": "Remove default manager roles/credentials and restrict manager access behind a reverse proxy or local subnet."
    }
]

class VulnEngine:
    @staticmethod
    def analyze_device(ip: str, open_ports: Dict[int, Dict]) -> List[Dict]:
        """
        Analyzes open ports and banners to return a list of vulnerabilities.
        """
        vulns = []
        for port, info in open_ports.items():
            banner = info.get("banner", "").lower()
            service = info.get("service", "").upper()

            # 1. Match against known signatures
            for sig in VULN_SIGNATURES:
                match = False
                if sig.get("port") == port:
                    if "banner_contains" in sig:
                        if sig["banner_contains"].lower() in banner:
                            match = True
                    elif "service" in sig:
                        if sig["service"].upper() == service:
                            match = True
                    else:
                        match = True

                if match:
                    vulns.append({
                        "port": port,
                        "service": info.get("service", "unknown"),
                        "cve": sig["cve"],
                        "name": sig["name"],
                        "description": sig["description"],
                        "severity": sig["severity"],
                        "cvss": sig["cvss"],
                        "remediation": sig["remediation"]
                    })

            # 2. General fallback severity hints if no signatures match
            if port in [21, 23] and not any(v["port"] == port for v in vulns):
                vulns.append({
                    "port": port,
                    "service": info.get("service", "unknown"),
                    "cve": "Insecure Protocol",
                    "name": f"Cleartext Service Enabled ({info.get('service')})",
                    "description": f"The service on port {port} transmits credentials and data in cleartext, exposing users to eavesdropping.",
                    "severity": "Medium",
                    "cvss": 5.0,
                    "remediation": f"Disable {info.get('service')} and transition to encrypted alternatives like SSH or SFTP."
                })

        return vulns
