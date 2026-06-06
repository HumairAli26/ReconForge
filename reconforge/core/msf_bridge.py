"""
msf_bridge.py
-------------
Metasploit integration for ReconForge.

Boot strategy (fastest possible):
  1. ensure_msfdb() — init/start PostgreSQL once (biggest win: saves 60-120s on cold boot)
  2. Launch with --quiet --no-readline -n (skip MSF's own DB connect: saves 20-40s more)
  3. Set TERM=dumb + NO_COLOR (strip slow ANSI processing)
  4. Fall back to standard boot if -n fails
  5. Pre-warm with a no-op command after boot to ensure prompt is stable
"""

import subprocess
import shutil
import threading
import queue
import time
import os
from typing import Optional, List, Dict

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


# ── Binary locators ────────────────────────────────────────────────────────────

def _find_msfconsole() -> Optional[str]:
    path = shutil.which("msfconsole")
    if path:
        return path
    for c in [
        "/usr/bin/msfconsole", "/usr/local/bin/msfconsole",
        "/opt/metasploit-framework/bin/msfconsole",
        os.path.expanduser("~/metasploit-framework/msfconsole"),
        r"C:\metasploit-framework\bin\msfconsole.bat",
    ]:
        if os.path.isfile(c):
            return c
    return None


def _find_msfdb() -> Optional[str]:
    path = shutil.which("msfdb")
    if path:
        return path
    for c in ["/usr/bin/msfdb", "/usr/local/bin/msfdb",
              "/opt/metasploit-framework/bin/msfdb"]:
        if os.path.isfile(c):
            return c
    return None


# ── msfdb helper ──────────────────────────────────────────────────────────────

def ensure_msfdb() -> bool:
    """
    Ensure msfdb PostgreSQL is running.
    This is the single biggest speed improvement — a running DB removes the
    biggest cold-start bottleneck (60-120s) from msfconsole startup.
    Returns True if DB is ready.
    """
    msfdb = _find_msfdb()
    if not msfdb:
        warn("msfdb not found — will use -n (no-database) mode instead.")
        return False

    try:
        # Check status
        r = subprocess.run([msfdb, "status"], capture_output=True,
                           text=True, timeout=15)
        output = (r.stdout + r.stderr).lower()

        if "running" in output or "online" in output:
            ok("msfdb: PostgreSQL already running ✓")
            return True

        if "not running" in output or "stopped" in output:
            # DB exists but stopped — just start it
            info("msfdb: Starting PostgreSQL...")
            start = subprocess.run([msfdb, "start"], capture_output=True,
                                   text=True, timeout=60)
            if start.returncode == 0:
                ok("msfdb: PostgreSQL started ✓")
                return True

        # DB not initialised — run init (one-time ~30s setup)
        info("msfdb: First-time init (this runs once, ~30s)...")
        init = subprocess.run([msfdb, "init"], capture_output=True,
                              text=True, timeout=180)
        if init.returncode == 0:
            ok("msfdb: Database initialised ✓")
            return True

        warn(f"msfdb init returned {init.returncode} — falling back to -n mode.")
        return False

    except subprocess.TimeoutExpired:
        warn("msfdb timed out — using -n mode.")
        return False
    except Exception as e:
        warn(f"msfdb error ({e}) — using -n mode.")
        return False


# ── MSFBridge ─────────────────────────────────────────────────────────────────

class MSFBridge:
    """
    Wraps msfconsole in a persistent subprocess for ReconForge.

    Fast-boot order:
      1. ensure_msfdb() — start PostgreSQL (removes biggest bottleneck)
      2. --quiet --no-readline (suppress banner overhead)
      3. If DB failed: add -n flag (skip MSF's DB connect attempt)
      4. TERM=dumb + NO_COLOR (remove ANSI parsing overhead)
      5. Fallback: standard mode with longer timeout
    """

    TIMEOUT = 120  # per-command timeout

    def __init__(self, msf_path: Optional[str] = None):
        self.msf_path  = msf_path or _find_msfconsole()
        self._proc:    Optional[subprocess.Popen] = None
        self._out_q:   queue.Queue = queue.Queue()
        self._reader:  Optional[threading.Thread] = None
        self._ready    = False

    def is_installed(self) -> bool:
        return self.msf_path is not None

    def is_running(self) -> bool:
        return (self._proc is not None
                and self._proc.poll() is None
                and self._ready)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _make_env(self) -> dict:
        env = os.environ.copy()
        env["TERM"]     = "dumb"   # no ANSI escape codes
        env["NO_COLOR"] = "1"      # suppress colour output
        env["COLUMNS"]  = "220"    # prevent line-wrap breaking prompt detection
        env["MSF_DISABLE_WEBRICK_LOGS"] = "1"  # suppress ruby webrick noise
        return env

    def _launch(self, cmd: list) -> bool:
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                env=self._make_env(),
            )
            self._out_q = queue.Queue()
            self._reader = threading.Thread(
                target=self._read_output, daemon=True)
            self._reader.start()
            return True
        except Exception as e:
            err(f"Failed to launch msfconsole: {e}")
            return False

    def _kill_proc(self):
        if self._proc:
            try:
                self._proc.kill()
                self._proc.wait(timeout=5)
            except Exception:
                pass
        self._proc = None

    def _read_output(self):
        try:
            for line in self._proc.stdout:
                self._out_q.put(line)
        except Exception:
            pass

    def _send(self, cmd: str):
        if self._proc and self._proc.stdin:
            try:
                self._proc.stdin.write(cmd + "\n")
                self._proc.stdin.flush()
            except Exception:
                pass

    def _wait_for_prompt(self, timeout: float = 120) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self._out_q.get(timeout=0.5).strip()
                # Accept msf6, msf5, or any line ending with >
                if ("msf6 >" in line or "msf5 >" in line
                        or "msf4 >" in line or line.endswith(">")):
                    return True
                # Also accept framework version line as a sign it's loading
            except queue.Empty:
                # Check if process died
                if self._proc and self._proc.poll() is not None:
                    return False
        return False

    def _drain(self, timeout: float = 2.0) -> List[str]:
        lines = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                lines.append(self._out_q.get(timeout=0.1).rstrip())
            except queue.Empty:
                break
        return lines

    def _collect_until_prompt(self, timeout: float = None) -> List[str]:
        timeout = timeout or self.TIMEOUT
        lines = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self._out_q.get(timeout=0.5)
                lines.append(line.rstrip())
                s = line.strip()
                if "msf6 >" in s or "msf5 >" in s or s.endswith(">"):
                    break
            except queue.Empty:
                if self._proc and self._proc.poll() is not None:
                    break
        return lines

    # ── Public start ──────────────────────────────────────────────────────────

    def start(self) -> bool:
        if not self.msf_path:
            err("msfconsole not found.")
            return False

        info(f"Starting Metasploit: {self.msf_path}")

        # Step 1: ensure msfdb PostgreSQL is running (biggest speed win)
        db_ready = ensure_msfdb()

        # Step 2a: if DB is ready, use standard boot (DB connect is now fast)
        if db_ready:
            info("DB ready — launching msfconsole (standard mode)...")
            cmd = [self.msf_path, "--quiet", "--no-readline"]
            if self._launch(cmd):
                self._ready = self._wait_for_prompt(timeout=120)

        # Step 2b: DB not ready — use -n to skip DB connect entirely
        if not self._ready:
            self._kill_proc()
            info("Launching msfconsole with -n (no-database fast-boot)...")
            cmd = [self.msf_path, "--quiet", "--no-readline", "-n"]
            if self._launch(cmd):
                self._ready = self._wait_for_prompt(timeout=90)

        # Step 2c: Last resort — plain fallback
        if not self._ready:
            self._kill_proc()
            warn("Trying plain msfconsole (last resort, may be slow)...")
            cmd = [self.msf_path]
            if self._launch(cmd):
                self._ready = self._wait_for_prompt(timeout=180)

        if self._ready:
            # Pre-warm: send a no-op to flush any remaining banner lines
            time.sleep(0.5)
            self._drain(1.0)
            ok("Metasploit ready ✓")
        else:
            err("Metasploit failed to start.")

        return self._ready

    def stop(self):
        if self._proc:
            try:
                self._send("exit -y")
                self._proc.wait(timeout=10)
            except Exception:
                self._kill_proc()
        self._ready = False

    # ── Public API ────────────────────────────────────────────────────────────

    def run_module(self, module_path: str, options: Dict[str, str],
                   run_cmd: str = "run", timeout: float = None) -> Dict:
        if not self._ready:
            return {"success": False, "output": ["MSF not ready"],
                    "module": module_path}
        self._drain(1)
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
        return {"module": module_path, "options": options,
                "output": output, "success": success}

    def raw_command(self, cmd: str, timeout: float = 30) -> List[str]:
        if not self._ready:
            return []
        self._drain(1)
        self._send(cmd)
        return self._collect_until_prompt(timeout)

    def search_modules(self, keyword: str) -> List[Dict]:
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
