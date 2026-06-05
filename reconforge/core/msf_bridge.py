"""
msf_bridge.py
-------------
Communicates with a running Metasploit instance via msfconsole subprocess.
Provides a clean Python API to run modules, set options, and collect results.
"""

import subprocess
import shutil
import threading
import queue
import time
import os
import sys
from typing import Optional, List, Dict

# ── colour helpers ─────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    console = Console()
    def info(msg):  console.print(f"[cyan][*][/cyan] {msg}")
    def ok(msg):    console.print(f"[green][+][/green] {msg}")
    def warn(msg):  console.print(f"[yellow][-][/yellow] {msg}")
    def err(msg):   console.print(f"[red][!][/red] {msg}")
except ImportError:
    def info(msg):  print(f"[*] {msg}")
    def ok(msg):    print(f"[+] {msg}")
    def warn(msg):  print(f"[-] {msg}")
    def err(msg):   print(f"[!] {msg}")


# ── locate msfconsole ──────────────────────────────────────────────────────────
def _find_msfconsole() -> Optional[str]:
    """
    Locate msfconsole on Windows/Linux/macOS.
    """

    path = shutil.which("msfconsole")
    if path:
        return path

    candidates = [
        r"C:\metasploit-framework\bin\msfconsole.bat",
        r"C:\metasploit-framework\bin\msfconsole",
        r"C:\Program Files\Metasploit\bin\msfconsole",
        "/usr/bin/msfconsole",
        "/usr/local/bin/msfconsole",
        "/opt/metasploit-framework/bin/msfconsole",
        os.path.expanduser("~/metasploit-framework/msfconsole"),
    ]

    for c in candidates:
        if os.path.isfile(c):
            return c

    return None


# ── MSF Session ───────────────────────────────────────────────────────────────
class MSFBridge:
    """
    Wraps msfconsole in a subprocess and exposes a simple run_module() API.

    Usage:
        bridge = MSFBridge()
        bridge.start()
        output = bridge.run_module(
            module_path="auxiliary/scanner/portscan/tcp",
            options={"RHOSTS": "192.168.1.1", "PORTS": "22,80,443"}
        )
        bridge.stop()
    """

    PROMPT = ["msf6 >", "msf >", "msf5 >"]
    TIMEOUT = 120  # seconds per command

    def __init__(self, msf_path: Optional[str] = None):
        self.msf_path = msf_path or _find_msfconsole()
        self._proc: Optional[subprocess.Popen] = None
        self._out_q: queue.Queue = queue.Queue()
        self._reader: Optional[threading.Thread] = None
        self._ready = False

    # ── lifecycle ──────────────────────────────────────────────────────────────
    def is_installed(self):
        return self.msf_path is not None
    
    def is_running(self) -> bool:
        return (
            self._proc is not None
            and self._proc.poll() is None
            and self._ready
        )
    def start(self) -> bool:
        if not self.msf_path:
            err("msfconsole not found. Install Metasploit or add it to PATH.")
            return False

        info(f"Starting msfconsole from: {self.msf_path}")

        try:
            self._proc = subprocess.Popen(
                [self.msf_path, "--quiet", "--no-readline"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            err(f"Failed to start Metasploit: {e}")
            return False

        self._reader = threading.Thread(
            target=self._read_output,
            daemon=True
        )
        self._reader.start()

        ok("Waiting for msfconsole to initialise...")

        self._ready = self._wait_for_prompt(timeout=180)

        if self._ready:
            ok("msfconsole ready.")
        else:
            err("msfconsole did not start in time.")

        return self._ready

    def stop(self):
        if self._proc:
            try:
                self._send("exit -y")
                self._proc.wait(timeout=10)
            except Exception:
                self._proc.kill()
        self._ready = False

    # ── internal I/O ──────────────────────────────────────────────────────────
    def _read_output(self):
        for line in self._proc.stdout:
            self._out_q.put(line)

    def _send(self, cmd: str):
        if self._proc and self._proc.stdin:
            self._proc.stdin.write(cmd + "\n")
            self._proc.stdin.flush()

    def _drain(self, timeout: float = 5.0) -> List[str]:
        lines = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self._out_q.get(timeout=0.2)
                lines.append(line.rstrip())
            except queue.Empty:
                break
        return lines

    def _wait_for_prompt(self, timeout: float = 180) -> bool:
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                line = self._out_q.get(timeout=1)

                line = line.strip()

                if (
                    "msf6 >" in line
                    or "msf5 >" in line
                    or line.endswith(">")
                ):
                    return True

            except queue.Empty:
                continue

        return False

    def _collect_until_prompt(self, timeout: float = None) -> List[str]:
        timeout = timeout or self.TIMEOUT

        lines = []
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                line = self._out_q.get(timeout=1)

                lines.append(line.rstrip())

                stripped = line.strip()

                if (
                    "msf6 >" in stripped
                    or "msf5 >" in stripped
                    or stripped.endswith(">")
                ):
                    break

            except queue.Empty:
                continue

        return lines

    # ── public API ────────────────────────────────────────────────────────────
    def run_module(
        self,
        module_path: str,
        options: Dict[str, str],
        run_cmd: str = "run",
        timeout: float = None,
    ) -> Dict:
        """
        Load a module, set options, and execute it.
        Returns {'module': ..., 'options': ..., 'output': [...], 'success': bool}
        """
        if not self._ready:
            return {"success": False, "output": ["MSF not ready"], "module": module_path}

        self._drain(2)  # clear any stale output

        cmds = [f"use {module_path}"]
        for k, v in options.items():
            cmds.append(f"set {k} {v}")
        cmds.append(run_cmd)

        for cmd in cmds:
            self._send(cmd)

        output = self._collect_until_prompt(timeout)
        success = any(
            kw in ln.lower()
            for ln in output
            for kw in ("completed", "success", "found", "[+]", "result")
        )
        return {
            "module": module_path,
            "options": options,
            "output": output,
            "success": success,
        }

    def raw_command(self, cmd: str, timeout: float = 30) -> List[str]:
        """Send any raw msfconsole command and return output lines."""
        if not self._ready:
            return []
        self._drain(1)
        self._send(cmd)
        return self._collect_until_prompt(timeout)

    def search_modules(self, keyword: str) -> List[Dict]:
        """Search Metasploit module DB and parse results."""
        raw = self.raw_command(f"search {keyword}", timeout=30)
        results = []
        for line in raw:
            parts = line.split()
            if len(parts) >= 3 and "/" in parts[0]:
                results.append({
                    "name": parts[0],
                    "rank": parts[1] if len(parts) > 1 else "",
                    "description": " ".join(parts[2:]) if len(parts) > 2 else "",
                })
        return results
