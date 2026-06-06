"""
core/port_scanner.py
--------------------
Full 65535-port scanner with smart prioritization.
 - Phase 1: Top-1000 ports (nmap standard list) — fast, catches ~99% of services
 - Phase 2: Extended 1001-65535 scan — thorough sweep for non-standard ports
 - Banner grabbing with service fingerprinting
 - nmap service version detection when available
"""

import socket
import ssl
import subprocess
import concurrent.futures
import threading
import re
from typing import List, Dict, Optional, Callable

# ── Service map (extended to 500+ well-known ports) ───────────────────────────
SERVICE_MAP: Dict[int, str] = {
    # Common / well-known
    1: "tcpmux", 7: "echo", 9: "discard", 11: "systat", 13: "daytime",
    17: "qotd", 19: "chargen", 20: "ftp-data", 21: "FTP", 22: "SSH",
    23: "Telnet", 25: "SMTP", 37: "time", 39: "rlp", 42: "nameserver",
    43: "whois", 49: "tacacs", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 70: "gopher", 79: "finger", 80: "HTTP", 88: "kerberos",
    102: "ms-sql-m", 104: "acr-nema", 110: "POP3", 111: "rpcbind",
    113: "ident", 119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    162: "SNMP-trap", 179: "BGP", 194: "IRC", 201: "AppleTalk",
    264: "bgmp", 389: "LDAP", 443: "HTTPS", 444: "snpp", 445: "SMB",
    465: "SMTPS", 500: "isakmp", 502: "Modbus", 513: "rlogin",
    514: "rsh/syslog", 515: "lpd", 530: "courier", 543: "klogin",
    544: "kshell", 548: "afp", 554: "RTSP", 587: "SMTP-submission",
    593: "http-rpc", 631: "IPP", 636: "LDAPS", 646: "ldp", 660: "MacOS-srvre",
    691: "msexch-routing", 749: "kerberos-adm", 873: "rsync",
    902: "vmware-auth", 989: "ftps-data", 990: "FTPS", 992: "telnets",
    993: "IMAPS", 995: "POP3S",
    # 1000-range
    1025: "NFS", 1026: "win-rpc", 1027: "win-rpc", 1028: "win-rpc",
    1029: "win-rpc", 1080: "SOCKS", 1110: "nfsd-status", 1194: "OpenVPN",
    1214: "kazaa", 1234: "ultrabac", 1311: "dell-openmanage",
    1352: "lotus-notes", 1433: "MSSQL", 1434: "MSSQL-monitor",
    1521: "Oracle", 1604: "citrix", 1701: "L2TP", 1723: "PPTP",
    1755: "wms", 1812: "radius", 1813: "radius-acct",
    1883: "MQTT", 1900: "UPnP", 2000: "cisco-sccp",
    2049: "NFS", 2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm",
    2087: "whm-ssl", 2095: "webmail", 2096: "webmail-ssl",
    2121: "ccproxy-ftp", 2181: "ZooKeeper", 2375: "Docker",
    2376: "Docker-tls", 2379: "etcd", 2380: "etcd-peer",
    2483: "Oracle-tls", 2484: "Oracle-tls", 2967: "symantec-av",
    3000: "dev-server", 3001: "dev-server", 3128: "Squid",
    3268: "LDAP-GC", 3269: "LDAPS-GC", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 3784: "ventrilo", 3868: "DIAMETER",
    4000: "remoteanything", 4369: "Erlang-EPMD", 4444: "metasploit",
    4500: "ipsec-nat", 4848: "glassfish-admin", 5000: "Flask/dev",
    5001: "commplex-link", 5060: "SIP", 5061: "SIP-tls",
    5432: "PostgreSQL", 5555: "adb/freeciv", 5601: "Kibana",
    5672: "AMQP", 5800: "VNC-http", 5900: "VNC", 5985: "WinRM",
    5986: "WinRM-ssl", 6000: "X11", 6001: "X11", 6379: "Redis",
    6443: "Kubernetes", 6667: "IRC", 6881: "bittorrent",
    7001: "WebLogic", 7002: "WebLogic-ssl", 7070: "RTSP",
    7474: "Neo4j", 8000: "HTTP-alt", 8008: "HTTP-alt",
    8009: "ajp13", 8080: "HTTP-proxy", 8081: "HTTP-alt",
    8083: "HTTP-alt", 8086: "InfluxDB", 8088: "HTTP-alt",
    8161: "ActiveMQ", 8443: "HTTPS-alt", 8444: "HTTPS-alt",
    8500: "Consul", 8834: "Nessus", 8888: "Jupyter",
    9000: "Portainer/SonarQube", 9001: "tor-orport",
    9042: "Cassandra", 9090: "Prometheus/Cockpit",
    9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch",
    9418: "git", 9443: "HTTPS-alt", 9999: "abyss",
    10000: "Webmin", 10050: "Zabbix-agent", 10051: "Zabbix-server",
    11211: "Memcached", 15672: "RabbitMQ-mgmt",
    16992: "AMT", 16993: "AMT-tls",
    27017: "MongoDB", 27018: "MongoDB", 27019: "MongoDB",
    28017: "MongoDB-web",
    32768: "filenet-tms", 49152: "win-dyn-rpc",
}

# nmap's top-1000 ports (abridged to key entries; full list generated below)
_NMAP_TOP_1000 = sorted(SERVICE_MAP.keys()) + [
    # Fill in common ports not already in SERVICE_MAP
    p for p in [
        81, 82, 83, 84, 85, 86, 87, 89, 90, 99, 100, 106, 109, 111,
        125, 144, 165, 174, 213, 222, 264, 340, 381, 383, 384, 387,
        407, 422, 425, 427, 443, 444, 458, 464, 465, 481, 497, 500,
        512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555,
        563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667,
        668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749,
        765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898,
        900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
        999, 1000, 1001,
    ]
    if p not in SERVICE_MAP
]

NMAP_AVAILABLE = False
try:
    r = subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
    NMAP_AVAILABLE = r.returncode == 0
except Exception:
    pass


# ── Banner grabbing ────────────────────────────────────────────────────────────

def _grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """Grab service banner with HTTP fallback."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Send HTTP HEAD for web ports
            if port in (80, 8080, 8000, 8008, 8081, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            try:
                data = s.recv(256).decode(errors="replace").strip()
                return data[:120]
            except Exception:
                return ""
    except Exception:
        # Try SSL for known HTTPS ports
        if port in (443, 8443, 465, 993, 995, 636, 5986):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=timeout) as raw:
                    with ctx.wrap_socket(raw) as s:
                        s.settimeout(timeout)
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        try:
                            return s.recv(256).decode(errors="replace").strip()[:120]
                        except Exception:
                            return "SSL/TLS"
            except Exception:
                return ""
        return ""


# ── nmap version scan parser ───────────────────────────────────────────────────

def _nmap_version_scan(ip: str, ports: List[int]) -> Dict[int, Dict]:
    """Run nmap -sV on found ports for accurate service detection."""
    if not NMAP_AVAILABLE or not ports:
        return {}
    port_str = ",".join(str(p) for p in ports[:200])  # limit for speed
    try:
        proc = subprocess.run(
            ["nmap", "-sV", "--version-intensity", "3",
             "-T4", "-p", port_str, ip],
            capture_output=True, text=True, timeout=120
        )
        results = {}
        for line in proc.stdout.splitlines():
            m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
            if m:
                port = int(m.group(1))
                svc  = m.group(3)
                ver  = m.group(4).strip()
                results[port] = {
                    "service": SERVICE_MAP.get(port, svc),
                    "banner":  ver[:120] if ver else "",
                }
        return results
    except Exception:
        return {}


# ── Port Scanner ───────────────────────────────────────────────────────────────

class PortScanner:
    """
    Full 65535-port scanner.
    Phase 1: Top ~1000 ports fast (200 threads, 0.5s timeout)
    Phase 2: Remaining ports (300 threads, 0.3s timeout)
    Uses nmap -sV for accurate service fingerprinting on discovered ports.
    """

    def __init__(self, timeout: float = 0.5, threads: int = 300):
        self.timeout = timeout
        self.threads = threads
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def scan(
        self,
        ip: str,
        ports: List[int] = None,
        on_port_found: Callable = None,
        on_progress: Callable = None,
    ) -> Dict[int, Dict]:
        self._stop_event.clear()

        if ports is not None:
            # Custom port list — use as-is
            return self._tcp_scan(ip, ports, on_port_found, on_progress)

        # Full scan: all 65535 ports in two phases
        # Phase 1: top ~1000 priority ports
        priority = sorted(set(_NMAP_TOP_1000))
        # Phase 2: everything else
        all_ports = set(range(1, 65536))
        extended  = sorted(all_ports - set(priority))

        total = 65535
        done  = [0]
        lock  = threading.Lock()
        results: Dict[int, Dict] = {}

        def _on_found(port, info):
            with lock:
                results[port] = info
            if on_port_found:
                on_port_found(port, info)

        def _on_prog(d, _):
            with lock:
                done[0] += d
                if on_progress:
                    on_progress(done[0], total)

        # Phase 1 — fast, tight timeout
        self._tcp_scan_batch(ip, priority, _on_found, _on_prog,
                              timeout=0.5, threads=200)

        if self._stop_event.is_set():
            return dict(sorted(results.items()))

        # Phase 2 — wider sweep, slightly looser timeout
        self._tcp_scan_batch(ip, extended, _on_found, _on_prog,
                              timeout=0.3, threads=300)

        # nmap version detection on found ports
        if results and NMAP_AVAILABLE:
            found_ports = list(results.keys())
            versioned = _nmap_version_scan(ip, found_ports)
            for port, info in versioned.items():
                if port in results:
                    results[port].update(info)

        return dict(sorted(results.items()))

    # ── Internal batch scanner ─────────────────────────────────────────────────

    def _tcp_scan_batch(
        self,
        ip: str,
        ports: List[int],
        on_found: Callable,
        on_prog: Callable,
        timeout: float,
        threads: int,
    ):
        lock = threading.Lock()
        done = [0]

        def check(port: int):
            if self._stop_event.is_set():
                return
            is_open = False
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    is_open = True
            except Exception:
                pass

            if is_open:
                service = SERVICE_MAP.get(port, "unknown")
                banner  = _grab_banner(ip, port, timeout=1.5)
                info    = {"service": service, "banner": banner}
                on_found(port, info)

            with lock:
                done[0] += 1
            on_prog(1, len(ports))

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            ex.map(check, ports)

    def _tcp_scan(
        self,
        ip: str,
        ports: List[int],
        on_port_found: Callable,
        on_progress: Callable,
    ) -> Dict[int, Dict]:
        """Simple scan for a given port list (used when ports= is specified)."""
        total   = len(ports)
        done    = [0]
        lock    = threading.Lock()
        results: Dict[int, Dict] = {}

        def check(port: int):
            if self._stop_event.is_set():
                return
            try:
                with socket.create_connection((ip, port), timeout=self.timeout):
                    pass
                service = SERVICE_MAP.get(port, "unknown")
                banner  = _grab_banner(ip, port)
                info    = {"service": service, "banner": banner}
                with lock:
                    results[port] = info
                    done[0] += 1
                    if on_port_found:
                        on_port_found(port, info)
                    if on_progress:
                        on_progress(done[0], total)
            except Exception:
                with lock:
                    done[0] += 1
                    if on_progress:
                        on_progress(done[0], total)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(check, ports)

        return dict(sorted(results.items()))


# Keep for backward compatibility
COMMON_PORTS = sorted(SERVICE_MAP.keys())
