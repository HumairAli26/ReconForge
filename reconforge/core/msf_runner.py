"""
core/msf_runner.py
------------------
MSF bridge wrapper used by the Flask app.

The key fix: MSFRunner now starts msfconsole eagerly in a background
thread and exposes a proper ready-state so the /api/msf/available
endpoint returns the correct answer even when called immediately.
"""

import threading
import shutil

try:
    from reconforge.core.msf_bridge import MSFBridge, _find_msfconsole
except ImportError:
    from msf_bridge import MSFBridge, _find_msfconsole

try:
    from reconforge.modules.catalog import MODULES, get_module
except ImportError:
    from modules_catalog import MODULES, get_module
    def get_module(k): return None


class MSFRunner:
    """
    Wraps MSFBridge for use by the Flask REST API.

    is_installed()  → msfconsole binary exists on PATH
    is_available()  → msfconsole binary exists AND the subprocess is ready
    """

    def __init__(self, msf_path: str = None):
        self._msf_path  = msf_path or _find_msfconsole()
        self._bridge    = None
        self._lock      = threading.Lock()
        self._started   = False

        # If msfconsole exists, kick off startup in background immediately
        if self._msf_path:
            t = threading.Thread(target=self._boot, daemon=True)
            t.start()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _boot(self):
        """Blocking call — runs in a daemon thread."""
        with self._lock:
            if self._started:
                return
            self._started = True

        bridge = MSFBridge(msf_path=self._msf_path)
        success = bridge.start()          # blocks until prompt appears (~30-180s)

        with self._lock:
            if success:
                self._bridge = bridge

    # ── Public API ────────────────────────────────────────────────────────────

    def is_installed(self) -> bool:
        """True if msfconsole binary is on PATH — instant check."""
        return self._msf_path is not None

    def is_available(self) -> bool:
        """True only when the subprocess is running and ready."""
        with self._lock:
            return (
                self._bridge is not None
                and self._bridge.is_running()
            )

    def get_available_modules(self):
        return MODULES

    def run_exploit(self, module_key: str, target: str, extra_opts: dict = None) -> dict:
        if not self.is_available():
            return {
                "success": False,
                "error": (
                    "Metasploit is still starting up — please wait a moment and retry."
                    if self.is_installed()
                    else "msfconsole not found on this system."
                ),
            }

        mod = get_module(module_key)
        if not mod:
            return {"success": False, "error": f"Unknown module key: '{module_key}'"}

        opts = mod.get("default_opts", {}).copy()
        opts["RHOSTS"] = target
        if extra_opts:
            opts.update(extra_opts)

        try:
            with self._lock:
                result = self._bridge.run_module(
                    module_path=mod["path"],
                    options=opts,
                    run_cmd=mod.get("run_cmd", "run"),
                )
            return {
                "success":  result.get("success", False),
                "module":   module_key,
                "target":   target,
                "output":   "\n".join(result.get("output", [])),
                "errors":   result.get("errors", ""),
            }
        except Exception as e:
            return {"success": False, "error": f"Module execution failed: {e}"}
