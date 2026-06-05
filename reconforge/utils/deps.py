"""
utils/deps.py
-------------
Checks that required system binaries are available before running.
"""

import shutil
import sys

REQUIRED_BINS = ["nmap"]
OPTIONAL_BINS = ["msfconsole"]


def check_dependencies(require_msf: bool = False) -> bool:
    """
    Verify system dependencies are installed.

    Parameters
    ----------
    require_msf : bool
        If True, msfconsole is treated as required, not optional.

    Returns
    -------
    bool
        True if all required (and optionally MSF) tools are found.
    """
    ok = True

    for tool in REQUIRED_BINS:
        path = shutil.which(tool)
        if path:
            print(f"  [✓] {tool} → {path}")
        else:
            print(f"  [✗] {tool} — NOT FOUND  (install: sudo apt install {tool})")
            ok = False

    msf = shutil.which("msfconsole")
    if msf:
        print(f"  [✓] msfconsole → {msf}")
    else:
        msg = "  [-] msfconsole — not found (Metasploit features disabled)"
        if require_msf:
            print(f"  [✗] msfconsole — NOT FOUND")
            ok = False
        else:
            print(msg)

    return ok


def get_msf_path() -> str | None:
    """Return the absolute path to msfconsole, or None."""
    return shutil.which("msfconsole")


def get_nmap_path() -> str | None:
    """Return the absolute path to nmap, or None."""
    return shutil.which("nmap")
