"""
reconforge/cli.py
-----------------
Primary CLI entry point — registered as the `reconforge` console script.

Usage:
  reconforge --sweep                          # auto-detect subnet and sweep it
  reconforge --sweep -t 10.0.0.0/24          # sweep a specific subnet
  reconforge --sweep -t 10.0.0.0/24 --ports  # sweep + port scan every host
  reconforge --sweep -t 10.0.0.0/24 --ports -o report.html
  reconforge -t 192.168.1.1 --no-msf         # deep-scan a single host
  reconforge --web                            # launch 3D web dashboard
  reconforge --interactive                    # TUI menu
  reconforge --check-deps
  reconforge --list-modules
"""

import argparse
import sys
import os
import time

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    class _FakeConsole:
        def print(self, *a, **kw): print(*a)
        def rule(self, *a, **kw): print("=" * 60)
    console = _FakeConsole()

from reconforge import __version__
from reconforge.modules.catalog import MODULES, list_categories, modules_for_category
from reconforge.utils.deps import check_dependencies


# ═══════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════

BANNER = r"""
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
            Network Discovery & Security Assessment Platform  v{version}
"""


def print_banner():
    banner = BANNER.format(version=__version__)
    if _RICH:
        console.print(Panel(
            Text(banner, style="bold cyan"),
            border_style="cyan",
            subtitle="[dim]For authorised security assessments only[/dim]",
        ))
    else:
        print(banner)
        print("  For authorised security assessments only.\n")


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def list_modules_table():
    if _RICH:
        t = Table(title="Available Recon Modules", show_lines=True, header_style="bold magenta")
        t.add_column("Key",      style="cyan",   no_wrap=True)
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
        t.add_column("Modules",  justify="right", style="green")
        for c in cats:
            t.add_row(c, str(len(modules_for_category(c))))
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


# ═══════════════════════════════════════════════════════════════
# SUBNET SWEEP MODE  (--sweep)
# ═══════════════════════════════════════════════════════════════

def run_sweep(target: str | None, do_ports: bool, output: str | None):
    """
    Discover all live hosts on a subnet, optionally port-scan each one,
    run the vuln engine, and save an HTML report.
    """
    from reconforge.core.network_scanner import NetworkScanner
    from reconforge.core.port_scanner import PortScanner
    from reconforge.core.vuln_engine import VulnEngine
    from reconforge.core.report_builder import ReportBuilder
    from datetime import datetime

    scanner_net  = NetworkScanner()
    scanner_port = PortScanner()
    vuln_engine  = VulnEngine()

    # Auto-detect subnet if none provided
    if not target:
        target = scanner_net.auto_detect_network()
        console.print(f"[cyan][*][/cyan] Auto-detected network: [bold]{target}[/bold]" if _RICH
                      else f"[*] Auto-detected network: {target}")

    state = {
        "network":   target,
        "devices":   [],
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # ── Phase 1: Host Discovery ──────────────────────────────────────────────
    if _RICH:
        console.rule(f"[bold cyan]Phase 1 — Host Discovery  ({target})[/bold cyan]")
    else:
        print(f"\n{'='*60}\n  Phase 1 — Host Discovery  ({target})\n{'='*60}")

    devices = []

    if _RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}[/cyan]"),
            BarColumn(),
            TextColumn("[green]{task.completed}/{task.total}[/green]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Sweeping subnet...", total=254)

            def on_progress(done, total):
                progress.update(task, completed=done, total=total)

            def on_device(dev):
                devices.append(dev)
                progress.print(
                    f"  [green][+][/green] Found: [bold]{dev['ip']:<16}[/bold] "
                    f"[dim]{dev.get('hostname','Unknown'):<28}[/dim] "
                    f"[yellow]{dev.get('vendor','Unknown')}[/yellow]"
                )

            scanner_net.scan(target, on_device=on_device, on_progress=on_progress)
    else:
        print(f"[*] Sweeping {target} ...")

        def on_device(dev):
            devices.append(dev)
            print(f"  [+] {dev['ip']:<16}  {dev.get('hostname','Unknown'):<28}  {dev.get('vendor','Unknown')}")

        scanner_net.scan(target, on_device=on_device)

    state["devices"] = devices

    if not devices:
        console.print("\n[yellow][-][/yellow] No live hosts found. Check the subnet or try with sudo (ARP requires root)." if _RICH
                      else "\n[-] No live hosts found. Try running with sudo.")
        return

    # ── Summary table ────────────────────────────────────────────────────────
    if _RICH:
        t = Table(title=f"Live Hosts ({len(devices)} found)", show_lines=True, header_style="bold cyan")
        t.add_column("IP Address",   style="bold white")
        t.add_column("MAC Address",  style="dim")
        t.add_column("Hostname",     style="green")
        t.add_column("Vendor",       style="yellow")
        t.add_column("Device Type",  style="cyan")
        for d in devices:
            t.add_row(d["ip"], d["mac"], d.get("hostname","Unknown"),
                      d.get("vendor","Unknown"), d.get("device_type","Unknown"))
        console.print(t)
    else:
        print(f"\n{'IP ADDRESS':<16} {'MAC ADDRESS':<20} {'HOSTNAME':<28} {'VENDOR':<22} {'TYPE'}")
        print("-" * 100)
        for d in devices:
            print(f"{d['ip']:<16} {d['mac']:<20} {d.get('hostname','Unknown'):<28} "
                  f"{d.get('vendor','Unknown'):<22} {d.get('device_type','Unknown')}")
        print(f"\n  Total: {len(devices)} host(s)")

    # ── Phase 2: Port Scan (optional) ────────────────────────────────────────
    if do_ports:
        if _RICH:
            console.rule("[bold cyan]Phase 2 — Port & Vulnerability Scan[/bold cyan]")
        else:
            print(f"\n{'='*60}\n  Phase 2 — Port & Vulnerability Scan\n{'='*60}")

        for idx, dev in enumerate(devices, 1):
            ip = dev["ip"]
            label = f"[{idx}/{len(devices)}] {ip}"

            if _RICH:
                console.print(f"\n[cyan][*][/cyan] Scanning {label} ...")
            else:
                print(f"\n[*] Scanning {label} ...")

            ports_info = scanner_port.scan(ip)
            dev["open_ports"] = list(ports_info.keys())
            dev["services"]   = ports_info

            # Vuln analysis
            vulns = vuln_engine.analyze_device(ip, ports_info)
            dev["vulns"] = vulns
            dev["risk"]  = "Exploited" if dev.get("exploited") else (
                           "Vulnerable" if vulns else ("Open" if ports_info else "Clean"))

            if _RICH:
                if ports_info:
                    pt = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
                    pt.add_column("Port",    style="cyan",  width=8)
                    pt.add_column("Service", style="green", width=14)
                    pt.add_column("Banner",  style="dim")
                    for port, info in ports_info.items():
                        pt.add_row(str(port), info.get("service","?"),
                                   (info.get("banner","") or "")[:70])
                    console.print(pt)
                else:
                    console.print("    [dim]No open ports found.[/dim]")

                if vulns:
                    for v in vulns:
                        sev_colour = {"Critical":"red","High":"orange3",
                                      "Medium":"yellow","Low":"dim"}.get(v["severity"],"white")
                        console.print(
                            f"  [bold red][!][/bold red] [{sev_colour}]{v['severity'].upper()}[/{sev_colour}] "
                            f"{v['name']}  [dim]({v['cve']})[/dim]"
                        )
            else:
                ports_str = ", ".join(str(p) for p in dev["open_ports"]) or "None"
                print(f"    Open ports: {ports_str}")
                for v in vulns:
                    print(f"    [!] {v['severity'].upper()} — {v['name']} ({v['cve']})")

        # ── Vuln summary ─────────────────────────────────────────────────────
        total_vulns = sum(len(d.get("vulns", [])) for d in devices)
        critical    = sum(1 for d in devices for v in d.get("vulns",[]) if v["severity"]=="Critical")
        high        = sum(1 for d in devices for v in d.get("vulns",[]) if v["severity"]=="High")

        if _RICH:
            console.rule("[bold cyan]Vulnerability Summary[/bold cyan]")
            vs = Table(show_header=False, box=None, padding=(0, 4))
            vs.add_column(style="dim");  vs.add_column(style="bold white")
            vs.add_row("Total vulnerabilities found:", str(total_vulns))
            vs.add_row("Critical:",  f"[red]{critical}[/red]")
            vs.add_row("High:",      f"[orange3]{high}[/orange3]")
            vs.add_row("Hosts vulnerable:", str(sum(1 for d in devices if d.get("vulns"))))
            console.print(vs)
        else:
            print(f"\n  Vulnerabilities found : {total_vulns}")
            print(f"  Critical              : {critical}")
            print(f"  High                  : {high}")

    # ── Phase 3: Save HTML Report ─────────────────────────────────────────────
    report_path = output or f"ReconForge_Report_{target.replace('/', '_')}_{int(time.time())}.html"
    html = ReportBuilder.generate_html_report(state)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    if _RICH:
        console.rule("[bold green]Done[/bold green]")
        console.print(f"[green][+][/green] HTML report saved → [bold]{report_path}[/bold]")
    else:
        print(f"\n[+] HTML report saved → {report_path}")


# ═══════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconforge",
        description="ReconForge — Network Discovery & Security Assessment Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version", version=f"ReconForge {__version__}")

    # Target
    p.add_argument("-t", "--target", metavar="TARGET",
                   help="IP, hostname, CIDR range, or subnet (e.g. 192.168.1.0/24)")

    # ── Modes ─────────────────────────────────────────────────────────────────
    modes = p.add_argument_group("Modes (pick one)")
    modes.add_argument("--sweep", action="store_true",
                       help="Subnet sweep: discover all live hosts, optional port scan & HTML report")
    modes.add_argument("-i", "--interactive", action="store_true",
                       help="Launch interactive TUI session")
    modes.add_argument("--web", action="store_true",
                       help="Launch the 3D web dashboard (requires flask, flask-cors)")

    # ── Sweep options ─────────────────────────────────────────────────────────
    sweep = p.add_argument_group("Sweep Options  (used with --sweep)")
    sweep.add_argument("--ports", action="store_true",
                       help="Port-scan every discovered host and run vuln analysis")
    sweep.add_argument("-o", "--output", metavar="FILE",
                       help="Save HTML report to this file (default: auto-named)")

    # ── Web options ───────────────────────────────────────────────────────────
    web = p.add_argument_group("Web Dashboard Options  (used with --web)")
    web.add_argument("--web-host", metavar="HOST", default="127.0.0.1",
                     help="Bind address (default: 127.0.0.1)")
    web.add_argument("--web-port", metavar="PORT", type=int, default=5000,
                     help="Port (default: 5000)")

    # ── Deep-scan / MSF options ───────────────────────────────────────────────
    msf = p.add_argument_group("Deep-Scan / Metasploit Options  (single-target scan)")
    msf.add_argument("--no-msf", action="store_true",
                     help="Skip Metasploit; use built-in Python probes only")
    msf.add_argument("--msf-path", metavar="PATH",
                     help="Full path to msfconsole binary")
    msf.add_argument("--lhost", metavar="IP",
                     help="Local IP for reverse payloads")
    msf.add_argument("--lport", metavar="PORT", type=int, default=4444,
                     help="Local port for reverse payloads (default: 4444)")
    msf.add_argument("-c", "--categories", nargs="+", metavar="CAT",
                     help="Restrict to specific MSF module categories")
    msf.add_argument("-p", "--extra-ports", metavar="PORTS",
                     help="Extra ports to scan (e.g. '22,80,8000-9000')")
    msf.add_argument("--threads", type=int, default=100, metavar="N",
                     help="Concurrent threads (default: 100)")
    msf.add_argument("--timeout", type=float, default=1.5,
                     help="TCP connect timeout in seconds (default: 1.5)")

    # ── Nuclei options ────────────────────────────────────────────────────────
    nuc = p.add_argument_group("Nuclei Options  (fast template-based vuln scanning)")
    nuc.add_argument("--nuclei", action="store_true",
                     help="Run nuclei scan against target (instant start, no boot delay)")
    nuc.add_argument("--nuclei-severity", metavar="LEVEL",
                     default="critical,high,medium",
                     help="Severity filter: critical,high,medium,low,info (default: critical,high,medium)")
    nuc.add_argument("--nuclei-tags", metavar="TAGS",
                     help="Nuclei template tags to include (e.g. 'cve,misconfig,exposed-panels')")
    nuc.add_argument("--nuclei-update", action="store_true",
                     help="Update nuclei templates before scanning")
    nuc.add_argument("--nuclei-path", metavar="PATH",
                     help="Full path to nuclei binary")

    # ── Output / info ─────────────────────────────────────────────────────────
    info = p.add_argument_group("Information & Utilities")
    info.add_argument("--no-banner",       action="store_true", help="Suppress ASCII banner")
    info.add_argument("--list-modules",    action="store_true", help="List all MSF modules and exit")
    info.add_argument("--list-categories", action="store_true", help="List module categories and exit")
    info.add_argument("--check-deps",      action="store_true", help="Check system dependencies and exit")
    info.add_argument("--nuclei-status",   action="store_true", help="Check nuclei installation and exit")

    return p


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Banner (suppress for util-only commands)
    quiet = args.check_deps or args.list_modules or args.list_categories
    if not args.no_banner and not quiet:
        print_banner()

    # ── Utilities ────────────────────────────────────────────────────────────
    if args.check_deps:
        console.print("\n[bold cyan]Checking system dependencies...[/bold cyan]\n" if _RICH
                      else "\nChecking system dependencies...\n")
        sys.exit(0 if check_dependencies() else 1)

    if args.list_modules:
        list_modules_table()
        return

    if args.list_categories:
        list_categories_table()
        return

    if args.nuclei_status:
        from reconforge.core.nuclei_bridge import NucleiBridge
        nb = NucleiBridge(nuclei_path=getattr(args, "nuclei_path", None))
        if nb.is_available():
            console.print(f"[green][+][/green] nuclei installed: {nb.get_version()}" if _RICH
                          else f"[+] nuclei installed: {nb.get_version()}")
            console.print(f"[green][+][/green] Path: {nb.nuclei_path}" if _RICH
                          else f"[+] Path: {nb.nuclei_path}")
        else:
            console.print("[red][!][/red] nuclei not found." if _RICH
                          else "[!] nuclei not found.")
            console.print("    Install: sudo apt install nuclei" if _RICH
                          else "    Install: sudo apt install nuclei")
            console.print("    Or:      go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" if _RICH
                          else "    Or:      go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return

    # ── Nuclei standalone scan ────────────────────────────────────────────────
    if args.nuclei:
        if not args.target:
            console.print("[red][!][/red] --nuclei requires -t <target>" if _RICH
                          else "[!] --nuclei requires -t <target>")
            sys.exit(1)

        from reconforge.core.nuclei_bridge import NucleiBridge
        nb = NucleiBridge(nuclei_path=getattr(args, "nuclei_path", None))

        if not nb.is_available():
            console.print("[red][!][/red] nuclei not installed." if _RICH
                          else "[!] nuclei not installed.")
            console.print("    Install: sudo apt install nuclei" if _RICH
                          else "    Install: sudo apt install nuclei")
            sys.exit(1)

        if args.nuclei_update:
            console.print("[cyan][*][/cyan] Updating nuclei templates..." if _RICH
                          else "[*] Updating nuclei templates...")
            nb.update_templates()

        severities = [s.strip() for s in args.nuclei_severity.split(",")]
        tags = [t.strip() for t in args.nuclei_tags.split(",")] if args.nuclei_tags else None

        if _RICH:
            console.rule(f"[bold cyan]Nuclei Scan: {args.target}[/bold cyan]")
            console.print(f"[cyan][*][/cyan] Severities : [yellow]{', '.join(severities)}[/yellow]")
            if tags:
                console.print(f"[cyan][*][/cyan] Tags       : [yellow]{', '.join(tags)}[/yellow]")
            console.print(f"[cyan][*][/cyan] Engine     : [green]nuclei {nb.get_version()}[/green]\n")
        else:
            print(f"\n[*] Nuclei Scan: {args.target}")
            print(f"[*] Severities: {', '.join(severities)}")

        finding_count = [0]

        def on_finding(f):
            finding_count[0] += 1
            sev = f.get("severity", "info").upper()
            colours = {"CRITICAL": "red", "HIGH": "orange3",
                       "MEDIUM": "yellow", "LOW": "dim", "INFO": "blue"}
            col = colours.get(sev, "white")
            if _RICH:
                console.print(
                    f"  [bold {col}][{sev}][/bold {col}] "
                    f"[white]{f.get('name','?')}[/white]  "
                    f"[dim]{f.get('matched', f.get('host',''))}[/dim]"
                )
            else:
                print(f"  [{sev}] {f.get('name','?')}  {f.get('matched','')}")

        try:
            findings = nb.scan(
                args.target,
                severities=severities,
                tags=tags,
                on_finding=on_finding,
            )
        except KeyboardInterrupt:
            console.print("\n[yellow][!][/yellow] Aborted." if _RICH else "\n[!] Aborted.")
            sys.exit(0)

        # Summary
        if _RICH:
            console.rule("[bold cyan]Nuclei Scan Summary[/bold cyan]")
            from rich.table import Table as RTable
            st = RTable(show_header=False, box=None, padding=(0, 4))
            st.add_column(style="dim")
            st.add_column(style="bold white")
            st.add_row("Target:",   args.target)
            st.add_row("Total findings:", str(len(findings)))
            for sev in ("critical", "high", "medium", "low", "info"):
                count = sum(1 for f in findings if f.get("severity") == sev)
                if count:
                    col = {"critical":"red","high":"orange3","medium":"yellow",
                           "low":"dim","info":"blue"}.get(sev, "white")
                    st.add_row(f"{sev.capitalize()}:", f"[{col}]{count}[/{col}]")
            console.print(st)
        else:
            print(f"\n[*] Total findings: {len(findings)}")

        # Save JSON report
        if findings:
            import json as _json
            out = args.output or f"nuclei_{args.target.replace('/', '_')}_{int(time.time())}.json"
            with open(out, "w") as f:
                _json.dump({"target": args.target, "findings": findings}, f, indent=2)
            console.print(f"[green][+][/green] Report saved → [bold]{out}[/bold]" if _RICH
                          else f"[+] Report saved → {out}")

        if _RICH:
            console.rule("[bold green]Done[/bold green]")
        return

    # ── Interactive TUI ──────────────────────────────────────────────────────
    if args.interactive:
        from reconforge.interactive import interactive_session
        interactive_session()
        return

    # ── Web Dashboard ────────────────────────────────────────────────────────
    if args.web:
        import webbrowser, threading
        url = f"http://{args.web_host}:{args.web_port}/"
        def _open():
            time.sleep(1.5)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()
        from reconforge.app import run_web
        run_web(host=args.web_host, port=args.web_port)
        return

    # ── Subnet Sweep Mode ────────────────────────────────────────────────────
    if args.sweep:
        try:
            run_sweep(
                target   = args.target,
                do_ports = args.ports,
                output   = args.output,
            )
        except KeyboardInterrupt:
            console.print("\n[yellow][!][/yellow] Aborted." if _RICH else "\n[!] Aborted.")
            sys.exit(0)
        return

    # ── Deep Single-Target Scan ──────────────────────────────────────────────
    if not args.target:
        parser.print_help()
        sys.exit(1)

    try:
        from reconforge.core.recon_engine import ReconEngine
    except ImportError as e:
        console.print(f"[red][!][/red] Cannot import ReconEngine: {e}" if _RICH
                      else f"[!] Cannot import ReconEngine: {e}")
        sys.exit(1)

    engine = ReconEngine(use_msf=not args.no_msf, msf_path=args.msf_path)

    if not args.no_msf:
        if _RICH:
            console.rule("[cyan]Connecting to Metasploit[/cyan]")
        if not engine.connect_msf():
            console.print("[yellow][-][/yellow] Running in offline mode." if _RICH
                          else "[-] Running in offline mode.")

    extra_ports = []
    if args.extra_ports:
        try:
            extra_ports = parse_custom_ports(args.extra_ports)
        except ValueError as e:
            console.print(f"[red][!][/red] Invalid port spec: {e}" if _RICH
                          else f"[!] Invalid port spec: {e}")
            sys.exit(1)

    if _RICH:
        console.rule(f"[bold cyan]Deep Scan: {args.target}[/bold cyan]")

    try:
        report = engine.recon(
            target       = args.target,
            categories   = args.categories,
            custom_ports = extra_ports,
            threads      = args.threads,
            lhost        = args.lhost,
            lport        = args.lport,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow][!][/yellow] Aborted." if _RICH else "\n[!] Aborted.")
        engine.disconnect_msf()
        sys.exit(0)
    except Exception as e:
        console.print(f"[red][!][/red] Recon failed: {e}" if _RICH else f"[!] Recon failed: {e}")
        engine.disconnect_msf()
        sys.exit(1)

    from reconforge.core.recon_engine import ReconEngine as RE
    RE.print_summary(report)

    output_file = args.output or f"recon_{args.target.replace('/', '_')}_{int(time.time())}.json"
    RE.save_report(report, output_file)
    engine.disconnect_msf()

    if _RICH:
        console.rule("[bold green]Done[/bold green]")


if __name__ == "__main__":
    main()
