"""
core/network_scanner.py
-----------------------
Enhanced network scanner: nmap (primary) + ARP (Scapy) + ICMP/TCP parallel
fallback. Detects ALL hosts on the subnet including those that block ARP/ICMP.
"""

import socket
import subprocess
import ipaddress
import threading
import sys
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional

# ── Optional imports ───────────────────────────────────────────────────────────
SCAPY_AVAILABLE = False
if sys.platform != "win32":
    try:
        from scapy.all import ARP, Ether, srp, conf, ICMP, IP, sr1
        conf.verb = 0
        SCAPY_AVAILABLE = True
    except Exception:
        SCAPY_AVAILABLE = False

NMAP_AVAILABLE = False
try:
    result = subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
    NMAP_AVAILABLE = result.returncode == 0
except Exception:
    NMAP_AVAILABLE = False

try:
    from mac_vendor_lookup import MacLookup
    _mac_lookup = MacLookup()
    MAC_LOOKUP_AVAILABLE = True
except Exception:
    MAC_LOOKUP_AVAILABLE = False
    _mac_lookup = None

try:
    from reconforge.core.device_info import collect_device_info, get_device_type
except ImportError:
    try:
        from device_info import collect_device_info, get_device_type
    except ImportError:
        def collect_device_info(d): return d
        def get_device_type(v, h): return "Unknown"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_vendor(mac: str) -> str:
    if MAC_LOOKUP_AVAILABLE and _mac_lookup and mac not in ("00:00:00:00:00:00", ""):
        try:
            return _mac_lookup.lookup(mac)
        except Exception:
            pass
    return "Unknown"


def _get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def _ping_host(ip: str, timeout: float = 0.8) -> bool:
    """Cross-platform ICMP ping with short timeout."""
    flag = "-n" if sys.platform == "win32" else "-c"
    try:
        result = subprocess.run(
            ["ping", flag, "1", "-w", "500", ip] if sys.platform == "win32"
            else ["ping", flag, "1", "-W", "1", ip],
            capture_output=True, timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        return False


def _probe_tcp(ip: str, timeout: float = 0.3) -> bool:
    """
    Aggressively probe common ports to detect hosts that block ICMP.
    Checks 20 ports in parallel to maximise hit rate.
    """
    ports = [
        22, 23, 25, 53, 80, 110, 135, 139,
        143, 443, 445, 3306, 3389, 5900, 8080,
        8443, 8888, 9090, 1080, 5432
    ]

    found = threading.Event()

    def _check(port):
        if found.is_set():
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    found.set()
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(_check, ports))

    return found.is_set()


def _probe_udp(ip: str, timeout: float = 0.3) -> bool:
    """UDP probe on DNS port — catches hosts that only expose UDP services."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00" * 12, (ip, 53))
            s.recv(64)
            return True
    except socket.timeout:
        # No response — host might still be up (ICMP unreachable not received)
        return False
    except Exception:
        return False


def _scapy_icmp_ping(ip: str, timeout: float = 1.0) -> bool:
    """Scapy ICMP probe — works even on hosts that block subprocess ping."""
    if not SCAPY_AVAILABLE:
        return False
    try:
        pkt = IP(dst=ip) / ICMP()
        resp = sr1(pkt, timeout=timeout, verbose=False)
        return resp is not None
    except Exception:
        return False


def _auto_detect_network() -> str:
    """Detect local /24 subnet."""
    if SCAPY_AVAILABLE:
        try:
            local_ip = conf.route.route("0.0.0.0")[1]
            net = ipaddress.IPv4Network(local_ip + "/24", strict=False)
            return str(net)
        except Exception:
            pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.IPv4Network(local_ip + "/24", strict=False)
        return str(net)
    except Exception:
        return "192.168.1.0/24"


# ── Nmap parser ────────────────────────────────────────────────────────────────

def _parse_nmap_hosts(output: str) -> List[Dict]:
    """Parse nmap -sn output into list of {ip, mac, vendor} dicts."""
    results = []
    current: Dict = {}

    for line in output.splitlines():
        # New host block
        m = re.search(r"Nmap scan report for (.+)", line)
        if m:
            if current.get("ip"):
                results.append(current)
            host_str = m.group(1).strip()
            # Extract IP from "hostname (IP)" or just IP
            ip_m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", host_str)
            ip = ip_m.group(1) if ip_m else host_str
            hostname = host_str.split("(")[0].strip() if ip_m else "Unknown"
            current = {"ip": ip, "mac": "00:00:00:00:00:00", "vendor": "Unknown", "hostname": hostname}
            continue

        # MAC address line
        mac_m = re.search(r"MAC Address: ([0-9A-F:]{17}) \(([^)]+)\)", line)
        if mac_m and current:
            current["mac"] = mac_m.group(1).lower().replace("-", ":")
            current["vendor"] = mac_m.group(2)

    if current.get("ip"):
        results.append(current)

    return results


# ── Main Scanner ───────────────────────────────────────────────────────────────

class NetworkScanner:
    """
    Discovers live hosts using:
      1. nmap -sn -PE -PA21,22,23,25,80,443,445,3389 --min-hostgroup 256 (best)
      2. ARP sweep via Scapy (fast on LAN, requires root)
      3. Parallel ICMP + TCP + UDP probe (universal fallback)

    All methods run and results are merged (deduplicated by IP).
    """

    def __init__(self):
        self._results: List[Dict] = []
        self._lock = threading.Lock()
        self._running = False

    def auto_detect_network(self) -> str:
        return _auto_detect_network()

    def scan(self, network: str, on_device=None, on_progress=None) -> List[Dict]:
        self._results = []
        self._running = True
        seen_ips: Dict[str, Dict] = {}

        def add(dev):
            ip = dev["ip"]
            with self._lock:
                if ip not in seen_ips:
                    seen_ips[ip] = dev
                    self._results.append(dev)
                    if on_device:
                        on_device(dev)

        # ── Method 1: nmap (most powerful) ─────────────────────────────────
        if NMAP_AVAILABLE:
            try:
                nmap_devs = self._nmap_scan(network)
                for d in nmap_devs:
                    add(d)
            except Exception:
                pass

        # ── Method 2: ARP sweep (catches anything nmap missed on same LAN) ─
        if SCAPY_AVAILABLE:
            try:
                arp_devs = self._arp_scan(network)
                for d in arp_devs:
                    if d["ip"] not in seen_ips:
                        add(d)
            except Exception:
                pass

        # ── Method 3: Parallel probe fallback ──────────────────────────────
        # Always run if nmap didn't find anything, or as supplemental check
        if not seen_ips or not NMAP_AVAILABLE:
            probe_devs = self._parallel_probe_scan(network, seen_ips, on_progress)
            for d in probe_devs:
                add(d)
        elif on_progress:
            hosts = list(ipaddress.IPv4Network(network, strict=False).hosts())
            on_progress(len(hosts), len(hosts))

        self._running = False
        return self._results

    def stop(self):
        self._running = False

    # ── nmap scan ─────────────────────────────────────────────────────────────

    def _nmap_scan(self, network: str) -> List[Dict]:
        """
        nmap host discovery — uses multiple probe types to find all hosts.
        -sn: ping scan (no port scan)
        -PE: ICMP echo
        -PS: TCP SYN to common ports
        -PA: TCP ACK to common ports
        -PU: UDP probe
        --min-hostgroup 256: scan whole subnet in one batch
        """
        cmd = [
            "nmap", "-sn",
            "-PE", "-PS22,80,443,445,3389,8080",
            "-PA80,443",
            "-PU53,161",
            "--min-hostgroup", "256",
            "--min-parallelism", "100",
            "-T4",
            network
        ]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            hosts = _parse_nmap_hosts(proc.stdout)
            result = []
            for h in hosts:
                # Resolve hostname if nmap didn't get it
                hostname = h.get("hostname", "Unknown")
                if not hostname or hostname == "Unknown":
                    hostname = _get_hostname(h["ip"])
                vendor = h.get("vendor", "Unknown")
                if vendor == "Unknown":
                    vendor = _get_vendor(h["mac"])
                dev = self._build_device(h["ip"], h["mac"], hostname, vendor)
                result.append(dev)
            return result
        except subprocess.TimeoutExpired:
            return []
        except Exception:
            return []

    # ── ARP scan ──────────────────────────────────────────────────────────────

    def _arp_scan(self, network: str) -> List[Dict]:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(ether / arp, timeout=3, verbose=False)

        results = []
        for _, received in answered:
            if not self._running:
                break
            ip  = received.psrc
            mac = received.hwsrc
            vendor = _get_vendor(mac)
            hostname = _get_hostname(ip)
            dev = self._build_device(ip, mac, hostname, vendor)
            results.append(dev)
        return results

    # ── Parallel probe scan ───────────────────────────────────────────────────

    def _parallel_probe_scan(
        self, network: str, skip_ips: Dict, on_progress=None
    ) -> List[Dict]:
        hosts = [
            str(h) for h in ipaddress.IPv4Network(network, strict=False).hosts()
            if str(h) not in skip_ips
        ]
        total = len(hosts) + len(skip_ips)
        done = [len(skip_ips)]
        lock = threading.Lock()
        results = []

        def probe(ip: str):
            if not self._running:
                return None
            alive = (
                _scapy_icmp_ping(ip, timeout=0.5)
                or _ping_host(ip, timeout=0.5)
                or _probe_tcp(ip, timeout=0.25)
            )
            with lock:
                done[0] += 1
                if on_progress:
                    on_progress(done[0], total)
            if alive:
                dev = self._build_device(ip, "00:00:00:00:00:00",
                                         _get_hostname(ip), "Unknown")
                results.append(dev)
            return None

        with ThreadPoolExecutor(max_workers=150) as ex:
            list(ex.map(probe, hosts))

        return results

    # ── Device builder ────────────────────────────────────────────────────────

    @staticmethod
    def _build_device(ip: str, mac: str, hostname: str = None,
                       vendor: str = None) -> Dict:
        if hostname is None:
            hostname = _get_hostname(ip)
        if vendor is None:
            vendor = _get_vendor(mac)
        dev_type = get_device_type(vendor, hostname)
        return {
            "ip":          ip,
            "mac":         mac,
            "hostname":    hostname,
            "vendor":      vendor,
            "device_type": dev_type,
            "open_ports":  [],
            "services":    {},
            "vulns":       [],
            "risk":        "Unknown",
            "exploited":   False,
            "first_seen":  datetime.now().isoformat(),
        }
