"""
core/port_scanner.py
--------------------
Threaded port scanner with banner grabbing.
"""

import socket
import ssl
import concurrent.futures
import threading
from typing import List, Dict, Optional, Callable

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    8080: "HTTP-Alt"
}

COMMON_PORTS = sorted(SERVICE_MAP.keys())

def _grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(128).decode(errors="replace").strip()[:100]
            except Exception:
                return ""
    except Exception:
        return ""

class PortScanner:
    def __init__(self, timeout: float = 1.0, threads: int = 100):
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
        if ports is None:
            ports = COMMON_PORTS

        total = len(ports)
        done = [0]
        lock = threading.Lock()
        results: Dict[int, Dict] = {}

        def check(port: int):
            if self._stop_event.is_set():
                return
            try:
                with socket.create_connection((ip, port), timeout=self.timeout):
                    pass
                service = SERVICE_MAP.get(port, "unknown")
                info = {"service": service, "banner": ""}
                banner = _grab_banner(ip, port, timeout=1.0)
                if banner:
                    info["banner"] = banner

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
