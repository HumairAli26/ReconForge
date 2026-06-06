"""
core/nuclei_bridge.py
---------------------
Nuclei integration for ReconForge.
Provides fast, template-based vulnerability scanning as an alternative to MSF.
Nuclei is instant-start (no boot delay), actively maintained, and covers
thousands of CVEs and misconfigurations out of the box.

Install nuclei:
    sudo apt install nuclei
    # or
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    # or download binary: https://github.com/projectdiscovery/nuclei/releases
"""

import subprocess
import shutil
import json
import threading
import os
from typing import Optional, List, Dict, Callable

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


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _find_nuclei() -> Optional[str]:
    path = shutil.which("nuclei")
    if path:
        return path
    candidates = [
        "/usr/bin/nuclei",
        "/usr/local/bin/nuclei",
        os.path.expanduser("~/go/bin/nuclei"),
        os.path.expanduser("~/.local/bin/nuclei"),
        "/snap/bin/nuclei",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _nuclei_version(nuclei_path: str) -> str:
    try:
        r = subprocess.run([nuclei_path, "-version"],
                           capture_output=True, text=True, timeout=10)
        for line in (r.stdout + r.stderr).splitlines():
            if "nuclei" in line.lower() and ("v" in line or "version" in line.lower()):
                return line.strip()
    except Exception:
        pass
    return "unknown"


class NucleiBridge:
    """
    Wraps the nuclei CLI for vulnerability scanning.

    Usage:
        bridge = NucleiBridge()
        if bridge.is_available():
            results = bridge.scan("192.168.1.1")
            results = bridge.scan("192.168.1.0/24", severities=["critical","high"])
    """

    def __init__(self, nuclei_path: Optional[str] = None):
        self.nuclei_path = nuclei_path or _find_nuclei()
        self._stop = threading.Event()

    def is_available(self) -> bool:
        return self.nuclei_path is not None

    def is_installed(self) -> bool:
        return self.nuclei_path is not None

    def get_version(self) -> str:
        if not self.nuclei_path:
            return "not installed"
        return _nuclei_version(self.nuclei_path)

    def update_templates(self) -> bool:
        """Update nuclei templates to latest. Returns True on success."""
        if not self.nuclei_path:
            return False
        try:
            result = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True, text=True, timeout=120
            )
            ok("Nuclei templates updated.")
            return result.returncode == 0
        except Exception as e:
            warn(f"Template update failed: {e}")
            return False

    def scan(
        self,
        target: str,
        severities: List[str] = None,
        tags: List[str] = None,
        templates: List[str] = None,
        exclude_tags: List[str] = None,
        timeout: int = 300,
        on_finding: Callable = None,
    ) -> List[Dict]:
        """
        Run nuclei scan against target.

        Args:
            target:       IP, hostname, CIDR, or URL
            severities:   e.g. ["critical","high","medium"] — default all
            tags:         e.g. ["cve","misconfig","exposed-panels"]
            templates:    specific template paths/dirs to use
            exclude_tags: tags to exclude
            timeout:      max seconds for scan
            on_finding:   callback(finding_dict) called for each result

        Returns list of finding dicts with keys:
            template_id, name, severity, host, matched, description, tags, reference
        """
        if not self.nuclei_path:
            err("nuclei not found — install it: sudo apt install nuclei")
            return []

        self._stop.clear()

        cmd = [
            self.nuclei_path,
            "-target", target,
            "-json",              # machine-readable output
            "-silent",            # no progress noise
            "-no-color",          # clean output
            "-timeout", "10",     # per-request timeout (seconds)
            "-rate-limit", "150", # requests per second
            "-bulk-size", "25",   # concurrent template execution
            "-concurrency", "25", # parallel host processing
        ]

        if severities:
            cmd += ["-severity", ",".join(s.lower() for s in severities)]
        if tags:
            cmd += ["-tags", ",".join(tags)]
        if templates:
            for t in templates:
                cmd += ["-t", t]
        if exclude_tags:
            cmd += ["-exclude-tags", ",".join(exclude_tags)]

        findings: List[Dict] = []

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            for line in proc.stdout:
                if self._stop.is_set():
                    proc.kill()
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    finding = self._parse_finding(raw)
                    findings.append(finding)
                    if on_finding:
                        on_finding(finding)
                except json.JSONDecodeError:
                    continue

            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

        except FileNotFoundError:
            err(f"nuclei binary not found at: {self.nuclei_path}")
        except Exception as e:
            err(f"Nuclei scan error: {e}")

        # Sort by severity
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "unknown"), 5))
        return findings

    def scan_ports(self, target: str, ports: List[int],
                   severities: List[str] = None) -> List[Dict]:
        """
        Scan specific ports/services on a target.
        Builds URLs from open ports and runs nuclei against them.
        """
        if not ports:
            return self.scan(target, severities=severities)

        # Build targets list from open ports
        targets = [target]  # raw IP/host always included
        for port in ports:
            if port in (80, 8080, 8000, 8008, 8888, 8081):
                targets.append(f"http://{target}:{port}")
            elif port in (443, 8443, 9443):
                targets.append(f"https://{target}:{port}")

        # Write targets to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as f:
            f.write("\n".join(targets))
            targets_file = f.name

        cmd_extra = ["-list", targets_file]
        # temporarily patch scan to use -list
        original_path = self.nuclei_path
        try:
            return self._scan_with_list(targets_file, severities)
        finally:
            try:
                os.unlink(targets_file)
            except Exception:
                pass

    def _scan_with_list(self, targets_file: str,
                         severities: List[str] = None) -> List[Dict]:
        cmd = [
            self.nuclei_path,
            "-list", targets_file,
            "-json", "-silent", "-no-color",
            "-timeout", "10",
            "-rate-limit", "100",
            "-bulk-size", "20",
            "-concurrency", "20",
        ]
        if severities:
            cmd += ["-severity", ",".join(s.lower() for s in severities)]

        findings = []
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(self._parse_finding(json.loads(line)))
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            err(f"Nuclei list scan error: {e}")

        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "unknown"), 5))
        return findings

    @staticmethod
    def _parse_finding(raw: dict) -> Dict:
        """Normalise raw nuclei JSON output into ReconForge finding format."""
        info_block = raw.get("info", {})
        return {
            "template_id":   raw.get("template-id", "unknown"),
            "name":          info_block.get("name", raw.get("template-id", "unknown")),
            "severity":      info_block.get("severity", "unknown").lower(),
            "host":          raw.get("host", ""),
            "matched":       raw.get("matched-at", raw.get("host", "")),
            "description":   info_block.get("description", ""),
            "tags":          info_block.get("tags", []),
            "reference":     info_block.get("reference", []),
            "cve":           next(
                (t for t in info_block.get("tags", []) if t.upper().startswith("CVE-")),
                ""
            ),
            "type":          raw.get("type", ""),
            "curl_command":  raw.get("curl-command", ""),
            "source":        "nuclei",
        }

    def stop(self):
        self._stop.set()


class NucleiBridgeStatus:
    """Lightweight status object for the web UI."""

    def __init__(self):
        self._bridge = NucleiBridge()

    def is_installed(self) -> bool:
        return self._bridge.is_installed()

    def is_available(self) -> bool:
        return self._bridge.is_available()

    def get_version(self) -> str:
        return self._bridge.get_version()

    def scan(self, target: str, **kwargs) -> List[Dict]:
        return self._bridge.scan(target, **kwargs)
