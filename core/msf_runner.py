"""
core/msf_runner.py
------------------
Adapts the recon_tool MSFBridge to be runnable from the ReconForge Flask app.
Supports running custom modules and collecting structured outputs.
"""

import sys
import os

# Add recon_tool to path to import MSFBridge and catalog
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "recon_tool")))

try:
    from msf_bridge import MSFBridge
    from modules_catalog import MODULES, get_module
    MSF_SUPPORTED = True
except ImportError:
    MSF_SUPPORTED = False
    MSFBridge = None
    MODULES = []
    def get_module(key): return None

import threading

class MSFRunner:
    def __init__(self, msf_path: str = None):
        self.bridge = None
        if MSF_SUPPORTED:
            try:
                self.bridge = MSFBridge(msf_path=msf_path)
                # Spin up msfconsole in background thread
                threading.Thread(target=self.bridge.start, daemon=True).start()
            except Exception:
                pass

    def is_available(self) -> bool:
        return MSF_SUPPORTED and self.bridge is not None and self.bridge._ready

    def get_available_modules(self):
        return MODULES

    def run_exploit(self, module_key: str, target: str, extra_opts: dict = None) -> dict:
        """
        Runs a module using MSFBridge and returns the output log and status.
        """
        if not self.is_available():
            return {
                "success": False,
                "error": "Metasploit is not installed or available on this system."
            }

        mod = get_module(module_key)
        if not mod:
            return {
                "success": False,
                "error": f"Module key '{module_key}' not found in catalog."
            }

        # Setup options
        opts = mod.get("default_opts", {}).copy()
        opts["RHOSTS"] = target
        if extra_opts:
            opts.update(extra_opts)

        try:
            result = self.bridge.run_module(
                module_path=mod["path"],
                options=opts,
                run_cmd=mod.get("run_cmd", "run")
            )
            return {
                "success": True,
                "module": module_key,
                "target": target,
                "output": result.get("output", ""),
                "errors": result.get("errors", "")
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed executing exploit module: {str(e)}"
            }
