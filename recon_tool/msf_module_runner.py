"""
msf_module_runner.py
--------------------
Stand-alone helper: given a module key from the catalog,
builds and prints the exact msfconsole commands needed to run it.
Useful when you want to copy-paste into a running msfconsole session
instead of using the automated bridge.

Usage:
    python msf_module_runner.py ssh_version 192.168.1.1
    python msf_module_runner.py smb_ms17_010_check 10.0.0.0/24 --threads 20
    python msf_module_runner.py --list
"""

import sys
import os
import argparse
sys.path.insert(0, os.path.dirname(__file__))

from modules_catalog import MODULES, get_module, list_categories, modules_for_category

try:
    from rich.console import Console
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.panel import Panel
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    class _C:
        def print(self, *a, **kw): print(*a)
    console = _C()


def build_rc_script(module_key: str, rhosts: str, extra_opts: dict = None, lhost: str = None, lport: int = 4444) -> str:
    """Return a .rc script string for the given module."""
    try:
        mod = get_module(module_key)
    except KeyError:
        return f"# ERROR: unknown module key '{module_key}'"

    lines = [
        f"# MSF Recon — {mod['description']}",
        f"use {mod['path']}",
        f"set RHOSTS {rhosts}",
    ]

    opts = {**mod["default_opts"]}
    if extra_opts:
        opts.update(extra_opts)
    for k, v in opts.items():
        lines.append(f"set {k} {v}")

    if lhost and mod["type"] == "exploit":
        lines.append(f"set LHOST {lhost}")
        lines.append(f"set LPORT {lport}")

    lines.append(mod["run_cmd"])
    return "\n".join(lines)


def print_script(script: str, title: str = "msfconsole commands"):
    if _RICH:
        console.print(Panel(
            Syntax(script, "ruby", theme="monokai", line_numbers=True),
            title=f"[bold cyan]{title}[/bold cyan]",
            border_style="cyan",
        ))
    else:
        print(f"\n--- {title} ---")
        print(script)
        print("---\n")


def list_all():
    if _RICH:
        for cat in list_categories():
            mods = modules_for_category(cat)
            t = Table(title=cat, header_style="bold yellow", show_lines=False)
            t.add_column("Key", style="cyan", no_wrap=True)
            t.add_column("MSF Path", style="dim")
            t.add_column("Description", style="white")
            t.add_column("Type", style="magenta")
            for m in mods:
                t.add_row(m["key"], m["path"], m["description"], m["type"])
            console.print(t)
            console.print()
    else:
        for cat in list_categories():
            print(f"\n=== {cat} ===")
            for m in modules_for_category(cat):
                print(f"  {m['key']:<35} {m['description']}")


def main():
    p = argparse.ArgumentParser(
        prog="msf_module_runner",
        description="Print msfconsole commands for a catalog module",
    )
    p.add_argument("module_key", nargs="?", help="Module key (see --list)")
    p.add_argument("rhosts", nargs="?", default="<TARGET>", help="Target IP/CIDR")
    p.add_argument("--list", action="store_true", help="List all modules")
    p.add_argument("--lhost", help="LHOST for exploit modules")
    p.add_argument("--lport", type=int, default=4444, help="LPORT")
    p.add_argument("--threads", help="Override THREADS option")
    p.add_argument("--save", metavar="FILE", help="Save .rc script to file")
    args = p.parse_args()

    if args.list:
        list_all()
        return

    if not args.module_key:
        p.print_help()
        return

    extra = {}
    if args.threads:
        extra["THREADS"] = args.threads

    script = build_rc_script(
        module_key=args.module_key,
        rhosts=args.rhosts,
        extra_opts=extra or None,
        lhost=args.lhost,
        lport=args.lport,
    )

    print_script(script, title=f"{args.module_key} -> {args.rhosts}")

    if args.save:
        with open(args.save, "w") as f:
            f.write(script + "\n")
        console.print(f"[green][+][/green] Saved to {args.save}")
        console.print(f"[dim]Run with: msfconsole -r {args.save}[/dim]")


if __name__ == "__main__":
    main()
