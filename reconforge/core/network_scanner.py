"""
core/network_scanner.py
-----------------------
Enhanced network scanner: ARP (Scapy) + ICMP ping fallback for VMs.
Works on Windows (needs Npcap) and Linux/Kali natively.
"""

import socket
import subprocess
import ipaddress
import threading
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional

# Scapy import with graceful fallback, disabled on Windows by default to prevent hangs
SCAPY_AVAILABLE = False
if sys.platform != "win32":
    try:
        from scapy.all import ARP, Ether, srp, conf, ICMP, IP, sr1
        conf.verb = 0
        SCAPY_AVAILABLE = True
    except Exception:
        SCAPY_AVAILABLE = False

# MAC vendor lookup
try:
    from mac_vendor_lookup import MacLookup
    _mac_lookup = MacLookup()
    MAC_LOOKUP_AVAILABLE = True
except Exception:
    MAC_LOOKUP_AVAILABLE = False
    _mac_lookup = None

# Import existing device_info if available

try:
    from reconforge.core.device_info import collect_device_info, get_device_type
except ImportError:
    try:
        from device_info import collect_device_info, get_device_type
    except ImportError:
        def collect_device_info(d): return d
        def get_device_type(v, h): return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────

def _get_vendor(mac: str) -> str:
    if MAC_LOOKUP_AVAILABLE and _mac_lookup:
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


def _ping_host(ip: str, timeout: float = 0.5) -> bool:
    """Cross-platform ICMP ping."""
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


def _probe_tcp(ip: str, timeout: float = 0.15) -> bool:
    """Fast check for standard open ports to detect hosts behind firewalls."""
    ports = [22, 80, 135, 443, 445, 3389, 8080]
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            pass
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
    # Fallback: socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.IPv4Network(local_ip + "/24", strict=False)
        return str(net)
    except Exception:
        return "192.168.1.0/24"


# ─────────────────────────────────────────────────────────────────────────────

class NetworkScanner:
    """
    Discovers all live hosts on a subnet using:
    1. ARP sweep (Scapy, requires root/Npcap) — fast & reliable on LAN
    2. Ping sweep fallback — works without Scapy
    """

    def __init__(self):
        self._results: List[Dict] = []
        self._lock = threading.Lock()
        self._progress = 0
        self._total = 0
        self._running = False

    # ── Public API ────────────────────────────────────────────────────────────

    def auto_detect_network(self) -> str:
        return _auto_detect_network()

    def scan(self, network: str, on_device=None, on_progress=None) -> List[Dict]:
        """
        Scan the network. Returns list of device dicts.
        on_device(device_dict)     — called each time a host is found
        on_progress(done, total)   — called for progress updates
        """
        self._results = []
        self._running = True

        if SCAPY_AVAILABLE:
            devices = self._arp_scan(network, on_device, on_progress)
        else:
            devices = self._ping_scan(network, on_device, on_progress)

        self._running = False
        return devices

    def stop(self):
        self._running = False

    # ── ARP Scan (Scapy) ──────────────────────────────────────────────────────

    def _arp_scan(self, network: str, on_device=None, on_progress=None) -> List[Dict]:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(ether / arp, timeout=3, verbose=False)

        total = len(answered)
        results = []
        for i, (sent, received) in enumerate(answered):
            if not self._running:
                break
            ip  = received.psrc
            mac = received.hwsrc
            dev = self._build_device(ip, mac)
            results.append(dev)
            if on_device:
                on_device(dev)
            if on_progress:
                on_progress(i + 1, total)

        return results

    # ── Ping Scan (fallback) ──────────────────────────────────────────────────

    def _ping_scan(self, network: str, on_device=None, on_progress=None) -> List[Dict]:
        hosts = list(ipaddress.IPv4Network(network, strict=False).hosts())
        total = len(hosts)
        self._total = total
        results = []
        done = [0]
        lock = threading.Lock()

        def probe(ip_obj):
            if not self._running:
                return None
            ip = str(ip_obj)
            alive = _ping_host(ip) or _probe_tcp(ip)
            with lock:
                done[0] += 1
                if on_progress:
                    on_progress(done[0], total)
            if alive:
                dev = self._build_device(ip, "00:00:00:00:00:00")
                with lock:
                    results.append(dev)
                if on_device:
                    on_device(dev)
            return None

        with ThreadPoolExecutor(max_workers=100) as ex:
            list(ex.map(probe, hosts))

        return results

    # ── Device builder ────────────────────────────────────────────────────────

    @staticmethod
    def _build_device(ip: str, mac: str) -> Dict:
        hostname = _get_hostname(ip)
        vendor   = _get_vendor(mac)
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
