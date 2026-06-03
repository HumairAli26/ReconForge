"""
recon_engine.py
---------------
High-level orchestrator.  Accepts a target, selects modules, calls MSFBridge,
and collects structured results without needing msfconsole to be running.

If Metasploit is not installed / reachable, the engine runs in OFFLINE mode
and performs built-in Python recon (port scan, banner grab, DNS, HTTP headers).
"""

import socket
import ssl
import http.client
import concurrent.futures
import json
import ipaddress
import subprocess
import time
from datetime import datetime, timezone
UTC = timezone.utc
from typing import Dict, List, Optional, Any

from modules_catalog import MODULES, get_module, list_categories, modules_for_category

# optional rich
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    class Console:
        def print(self, *a, **kw): print(*a)
    console = Console()


# ═══════════════════════════════════════════════════════════════════════════════
# OFFLINE RECON PRIMITIVES
# ═══════════════════════════════════════════════════════════════════════════════

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    1433: "MSSQL", 1521: "Oracle", 389: "LDAP", 636: "LDAPS",
    111: "RPC", 2049: "NFS", 161: "SNMP", 162: "SNMP-Trap",
    512: "rexec", 513: "rlogin", 514: "rsh", 873: "rsync",
}


def _tcp_connect(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(1024).decode(errors="replace").strip()
            return banner[:200]
    except Exception:
        return ""


def _http_banner(host: str, port: int, https: bool = False, timeout: float = 4.0) -> Dict:
    try:
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("HEAD", "/")
        r = conn.getresponse()
        headers = dict(r.getheaders())
        return {
            "status": r.status,
            "server": headers.get("Server", ""),
            "headers": headers,
        }
    except Exception as e:
        return {"error": str(e)}


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _ssl_cert_info(host: str, port: int = 443) -> Dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "notBefore": cert.get("notBefore", ""),
                    "notAfter": cert.get("notAfter", ""),
                    "san": [v for _, v in cert.get("subjectAltName", [])],
                }
    except Exception as e:
        return {"error": str(e)}


def _dns_lookup(domain: str) -> Dict:
    results = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    for rt in record_types:
        try:
            import dns.resolver  # dnspython
            answers = dns.resolver.resolve(domain, rt)
            results[rt] = [str(r) for r in answers]
        except Exception:
            # fallback for A record
            if rt == "A":
                try:
                    results["A"] = [socket.gethostbyname(domain)]
                except Exception:
                    results["A"] = []
    return results


def port_scan_offline(host: str, ports: List[int] = None, threads: int = 100) -> Dict[int, Dict]:
    """Fast threaded TCP port scanner."""
    ports = ports or list(COMMON_PORTS.keys())
    open_ports: Dict[int, Dict] = {}

    def check(p):
        if _tcp_connect(host, p):
            service = COMMON_PORTS.get(p, "unknown")
            banner = _grab_banner(host, p)
            extra = {}
            if p in (80, 8080):
                extra = _http_banner(host, p, https=False)
            elif p in (443, 8443):
                extra = _http_banner(host, p, https=True)
                extra["ssl_cert"] = _ssl_cert_info(host, p)
            open_ports[p] = {"service": service, "banner": banner, **extra}

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(check, ports))

    return dict(sorted(open_ports.items()))


# ═══════════════════════════════════════════════════════════════════════════════
# RECON ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class ReconEngine:
    """
    Orchestrates recon against one or more targets.
    Tries MSFBridge first; falls back to offline Python probes.
    """

    def __init__(self, use_msf: bool = True, msf_path: str = None):
        self.use_msf = use_msf
        self.msf_path = msf_path
        self._bridge = None
        self._msf_online = False

    # ── setup ──────────────────────────────────────────────────────────────────
    def connect_msf(self) -> bool:
        if not self.use_msf:
            return False
        try:
            from msf_bridge import MSFBridge
            self._bridge = MSFBridge(self.msf_path)
            self._msf_online = self._bridge.start()
        except Exception as e:
            console.print(f"[yellow]MSF bridge error: {e}[/yellow]")
            self._msf_online = False
        return self._msf_online

    def disconnect_msf(self):
        if self._bridge:
            self._bridge.stop()

    # ── target validation ──────────────────────────────────────────────────────
    @staticmethod
    def resolve_target(target: str) -> str:
        """Return IP for hostname; pass through IPs unchanged."""
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            return socket.gethostbyname(target)

    # ── full recon ─────────────────────────────────────────────────────────────
    def recon(
        self,
        target: str,
        categories: List[str] = None,
        custom_ports: List[int] = None,
        threads: int = 50,
        lhost: str = None,
        lport: int = 4444,
    ) -> Dict[str, Any]:
        """
        Main entry point.  Returns a structured report dict.

        Parameters
        ----------
        target     : hostname or IP (CIDR also accepted for port scan)
        categories : subset of CATALOG categories; None = all
        custom_ports : extra ports to probe
        threads    : concurrency for offline scanner
        lhost      : local IP for payload options (MSF mode)
        lport      : local port for payload
        """
        report: Dict[str, Any] = {
            "target": target,
            "timestamp": datetime.now(UTC).isoformat(),
            "msf_used": self._msf_online,
            "sections": {},
        }

        ip = target
        try:
            ip = self.resolve_target(target)
            report["resolved_ip"] = ip
        except Exception:
            report["resolved_ip"] = None

        # ── DNS ───────────────────────────────────────────────────────────────
        if not target.replace(".", "").isdigit():
            console.print("[cyan][*][/cyan] Running DNS lookups…")
            report["sections"]["dns"] = _dns_lookup(target)

        # ── Reverse DNS ───────────────────────────────────────────────────────
        if ip:
            rdns = _reverse_dns(ip)
            if rdns:
                report["sections"]["reverse_dns"] = rdns

        # ── Port Scan ─────────────────────────────────────────────────────────
        ports = list(COMMON_PORTS.keys())
        if custom_ports:
            ports = sorted(set(ports + custom_ports))

        console.print(f"[cyan][*][/cyan] Port scanning {target} ({len(ports)} ports)…")
        open_ports = port_scan_offline(target, ports, threads=threads)
        report["sections"]["open_ports"] = open_ports

        if not open_ports:
            console.print("[yellow][-][/yellow] No open ports found — target may be firewalled.")
            return report

        # ── Service-specific probes ────────────────────────────────────────────
        console.print("[cyan][*][/cyan] Running service probes…")
        service_results: Dict[str, Any] = {}

        for port, info in open_ports.items():
            svc = info.get("service", "")

            if svc == "HTTP" or port in (80, 8080):
                service_results.setdefault("http", []).append({
                    "port": port, **_http_banner(target, port, https=False)
                })
            elif svc == "HTTPS" or port in (443, 8443):
                service_results.setdefault("https", []).append({
                    "port": port,
                    **_http_banner(target, port, https=True),
                    "ssl_cert": _ssl_cert_info(target, port),
                })
            elif svc == "SSH":
                service_results.setdefault("ssh", []).append({
                    "port": port, "banner": info.get("banner", "")
                })
            elif svc == "FTP":
                service_results.setdefault("ftp", []).append({
                    "port": port, "banner": info.get("banner", "")
                })
            elif svc == "SMB":
                service_results.setdefault("smb", []).append({"port": port})

        report["sections"]["services"] = service_results

        # ── MSF Modules (if online) ────────────────────────────────────────────
        if self._msf_online and self._bridge:
            console.print("[cyan][*][/cyan] Running Metasploit auxiliary modules…")
            msf_results = self._run_msf_recon(
                target=target,
                ip=ip,
                open_ports=open_ports,
                categories=categories,
                lhost=lhost,
                lport=lport,
            )
            report["sections"]["msf"] = msf_results

        return report

    # ── MSF module runner ──────────────────────────────────────────────────────
    def _run_msf_recon(
        self,
        target: str,
        ip: str,
        open_ports: Dict,
        categories: List[str],
        lhost: str,
        lport: int,
    ) -> Dict[str, Any]:
        port_nums = set(open_ports.keys())
        results: Dict[str, Any] = {}

        # Filter modules to only those whose service port is actually open
        PORT_MAP = {
            "FTP": {21}, "SSH": {22}, "SMTP": {25}, "HTTP": {80, 8080},
            "HTTPS": {443, 8443}, "SMB": {445}, "MySQL": {3306}, "RDP": {3389},
            "VNC": {5900}, "LDAP": {389, 636}, "Telnet": {23}, "SNMP": {161},
            "POP3": {110}, "IMAP": {143}, "MSSQL": {1433},
        }

        for mod in MODULES:
            cat = mod["category"]
            if categories and cat not in categories:
                continue

            # Check if relevant port open (skip service-specific if port closed)
            service_name = COMMON_PORTS.get(list(port_nums)[0], "") if port_nums else ""
            if cat in ("Service Fingerprinting", "Vulnerability Checks"):
                svc_ports = PORT_MAP.get(service_name, set())
                # only skip if we can determine no relevant port is open
                needed = {p for svc, pts in PORT_MAP.items() for p in pts if svc in mod["path"].upper()}
                if needed and not (needed & port_nums):
                    continue

            opts = {**mod["default_opts"], "RHOSTS": ip}
            if lhost:
                opts["LHOST"] = lhost
                opts["LPORT"] = str(lport)

            console.print(f"  [dim]-> {mod['path']}[/dim]")
            result = self._bridge.run_module(
                module_path=mod["path"],
                options=opts,
                run_cmd=mod["run_cmd"],
                timeout=60,
            )
            results[mod["key"]] = {
                "module": mod["path"],
                "description": mod["description"],
                "success": result["success"],
                "output": [l for l in result["output"] if l.strip()],
            }

        return results

    # ── report helpers ─────────────────────────────────────────────────────────
    @staticmethod
    def save_report(report: Dict, path: str = "recon_report.json"):
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"[green][+][/green] Report saved -> {path}")

    @staticmethod
    def print_summary(report: Dict):
        target = report.get("target", "?")
        ip = report.get("resolved_ip", target)
        ts = report.get("timestamp", "")
        sections = report.get("sections", {})

        if _RICH:
            console.print(f"\n[bold cyan]━━━ RECON REPORT ━━━[/bold cyan]")
            console.print(f"[bold]Target:[/bold] {target}  [dim]({ip})[/dim]")
            console.print(f"[bold]Time:[/bold]   {ts}")

            # Open ports table
            ports = sections.get("open_ports", {})
            if ports:
                t = Table(title="Open Ports", show_lines=True)
                t.add_column("Port", style="cyan")
                t.add_column("Service", style="green")
                t.add_column("Banner / Info", style="white", no_wrap=False)
                for port, info in ports.items():
                    banner = info.get("banner") or info.get("server") or ""
                    t.add_row(str(port), info.get("service", ""), banner[:80])
                console.print(t)

            # DNS
            dns = sections.get("dns", {})
            if dns:
                console.print("\n[bold]DNS Records:[/bold]")
                for rtype, vals in dns.items():
                    console.print(f"  [cyan]{rtype:6}[/cyan] {', '.join(vals)}")

            # SSL cert
            services = sections.get("services", {})
            for entry in services.get("https", []):
                cert = entry.get("ssl_cert", {})
                if cert and "error" not in cert:
                    console.print(f"\n[bold]SSL Certificate (port {entry['port']}):[/bold]")
                    subj = cert.get("subject", {})
                    console.print(f"  CN: {subj.get('commonName', '?')}")
                    console.print(f"  Expires: {cert.get('notAfter', '?')}")
                    san = cert.get("san", [])
                    if san:
                        console.print(f"  SAN: {', '.join(san[:5])}")

            # MSF results
            msf = sections.get("msf", {})
            if msf:
                console.print(f"\n[bold]Metasploit Module Results ({len(msf)}):[/bold]")
                for key, res in msf.items():
                    status = "[green]✓[/green]" if res["success"] else "[dim]·[/dim]"
                    console.print(f"  {status} {res['description']}")
        else:
            print(f"\n=== RECON REPORT ===")
            print(f"Target: {target} ({ip})")
            print(f"Time: {ts}")
            ports = sections.get("open_ports", {})
            print(f"\nOpen Ports ({len(ports)}):")
            for p, info in ports.items():
                print(f"  {p:5} {info.get('service',''):<12} {info.get('banner','')[:60]}")
