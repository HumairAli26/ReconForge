"""
main.py
-------
Entry-point CLI for the Metasploit-backed Python Recon Tool.

Usage examples:
  python main.py -t 192.168.1.1
  python main.py -t scanme.nmap.org --no-msf
  python main.py -t 10.0.0.0/24 -c "Port Scanning" "Host Discovery"
  python main.py -t 192.168.1.5 --msf-path /usr/bin/msfconsole --lhost 192.168.1.100
  python main.py -t example.com --list-modules
"""

import argparse
import sys
import os
import json

# ── make sure we can import sibling modules ────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from modules_catalog import MODULES, list_categories, modules_for_category

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    class _FakeConsole:
        def print(self, *a, **kw): print(*a)
        def rule(self, *a, **kw): print("=" * 60)
    console = _FakeConsole()


# ═══════════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
  ███╗   ███╗███████╗███████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ████╗ ████║██╔════╝██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██╔████╔██║███████╗█████╗      ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║╚██╔╝██║╚════██║██╔══╝      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║ ╚═╝ ██║███████║██║         ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝     ╚═╝╚══════╝╚═╝         ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                        Python Recon Tool  |  Powered by Metasploit
"""


def print_banner():
    if _RICH:
        console.print(Panel(
            Text(BANNER, style="bold cyan"),
            border_style="cyan",
            subtitle="[dim]For authorised security assessments only[/dim]",
        ))
    else:
        print(BANNER)
        print("  For authorised security assessments only.\n")


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def list_modules_table():
    if _RICH:
        t = Table(title="Available Recon Modules", show_lines=True, header_style="bold magenta")
        t.add_column("Key", style="cyan", no_wrap=True)
        t.add_column("Category", style="yellow")
        t.add_column("MSF Path", style="dim")
        t.add_column("Description", style="white")
        for m in MODULES:
            t.add_row(m["key"], m["category"], m["path"], m["description"])
        console.print(t)
    else:
        print(f"{'KEY':<35} {'CATEGORY':<25} {'DESCRIPTION'}")
        print("-" * 90)
        for m in MODULES:
            print(f"{m['key']:<35} {m['category']:<25} {m['description']}")


def list_categories_table():
    cats = list_categories()
    if _RICH:
        t = Table(title="Module Categories", header_style="bold yellow")
        t.add_column("Category", style="cyan")
        t.add_column("Modules", justify="right", style="green")
        for c in cats:
            cnt = len(modules_for_category(c))
            t.add_row(c, str(cnt))
        console.print(t)
    else:
        for c in cats:
            print(f"  {c}  ({len(modules_for_category(c))} modules)")


def parse_custom_ports(raw: str):
    """Parse '22,80,443,8000-8100' → sorted list of ints."""
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# ═══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="msf-recon",
        description="Metasploit-backed Python Recon Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Target
    p.add_argument("-t", "--target", metavar="TARGET",
                   help="IP, hostname or CIDR range to scan")

    # MSF options
    msf = p.add_argument_group("Metasploit Options")
    msf.add_argument("--no-msf", action="store_true",
                     help="Skip Metasploit; use built-in Python probes only")
    msf.add_argument("--msf-path", metavar="PATH",
                     help="Full path to msfconsole binary")
    msf.add_argument("--lhost", metavar="IP",
                     help="Local IP for reverse payloads (MSF mode)")
    msf.add_argument("--lport", metavar="PORT", type=int, default=4444,
                     help="Local port for reverse payloads (default: 4444)")

    # Scan options
    scan = p.add_argument_group("Scan Options")
    scan.add_argument("-c", "--categories", nargs="+", metavar="CAT",
                      help="Restrict to specific module categories (space-separated)")
    scan.add_argument("-p", "--ports", metavar="PORTS",
                      help="Extra ports to scan, e.g. '22,80,8000-9000'")
    scan.add_argument("--threads", type=int, default=100, metavar="N",
                      help="Concurrent threads for port scan (default: 100)")
    scan.add_argument("--timeout", type=float, default=1.5,
                      help="TCP connect timeout in seconds (default: 1.5)")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output", metavar="FILE",
                     help="Save JSON report to this file")
    out.add_argument("--no-banner", action="store_true",
                     help="Suppress ASCII banner")

    # Info
    info = p.add_argument_group("Information")
    info.add_argument("--list-modules", action="store_true",
                      help="List all available recon modules and exit")
    info.add_argument("--list-categories", action="store_true",
                      help="List module categories and exit")

    return p


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    # Info-only actions
    if args.list_modules:
        list_modules_table()
        return

    if args.list_categories:
        list_categories_table()
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    # ── import engine ─────────────────────────────────────────────────────────
    try:
        from recon_engine import ReconEngine
    except ImportError as e:
        console.print(f"[red][!][/red] Cannot import recon_engine: {e}")
        sys.exit(1)

    engine = ReconEngine(
        use_msf=not args.no_msf,
        msf_path=args.msf_path,
    )

    # ── connect MSF if requested ──────────────────────────────────────────────
    if not args.no_msf:
        if _RICH:
            console.rule("[cyan]Connecting to Metasploit[/cyan]")
        ok = engine.connect_msf()
        if not ok:
            console.print("[yellow][-][/yellow] Running in offline mode (pure Python probes).")

    # ── parse extra ports ─────────────────────────────────────────────────────
    extra_ports = []
    if args.ports:
        try:
            extra_ports = parse_custom_ports(args.ports)
        except ValueError as e:
            console.print(f"[red][!][/red] Invalid port spec: {e}")
            sys.exit(1)

    # ── run recon ─────────────────────────────────────────────────────────────
    if _RICH:
        console.rule(f"[bold cyan]Scanning: {args.target}[/bold cyan]")

    try:
        report = engine.recon(
            target=args.target,
            categories=args.categories,
            custom_ports=extra_ports,
            threads=args.threads,
            lhost=args.lhost,
            lport=args.lport,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow][!][/yellow] Aborted by user.")
        engine.disconnect_msf()
        sys.exit(0)
    except Exception as e:
        console.print(f"[red][!][/red] Recon failed: {e}")
        engine.disconnect_msf()
        sys.exit(1)

    # ── print & save ──────────────────────────────────────────────────────────
    from recon_engine import ReconEngine as RE
    RE.print_summary(report)

    output_file = args.output or f"recon_{args.target.replace('/', '_')}_{int(__import__('time').time())}.json"
    RE.save_report(report, output_file)

    engine.disconnect_msf()

    if _RICH:
        console.rule("[bold green]Done[/bold green]")


if __name__ == "__main__":
    main()
