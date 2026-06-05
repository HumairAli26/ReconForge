"""
interactive.py
--------------
Interactive TUI session — lets you select modules from a menu,
set options, run them live, and review results — all without
knowing msfconsole commands.
"""

import sys
import os
try:
    from reconforge.modules.catalog import MODULES, list_categories, modules_for_category
    from reconforge.core.recon_engine import ReconEngine
    from reconforge.core.msf_bridge import MSFBridge
except ImportError:
    from modules_catalog import MODULES, list_categories, modules_for_category

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.columns import Columns
    _RICH = True
except ImportError:
    _RICH = False

console = Console() if _RICH else None


def _print(msg, style=""):
    if _RICH:
        console.print(msg, style=style)
    else:
        print(msg)


def _input(prompt):
    if _RICH:
        return Prompt.ask(prompt)
    return input(f"{prompt}: ")


def _confirm(prompt):
    if _RICH:
        return Confirm.ask(prompt)
    return input(f"{prompt} [y/N]: ").lower().startswith("y")


# ─────────────────────────────────────────────────────────────────────────────
# MENU HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def show_main_menu():
    if _RICH:
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(style="bold cyan")
        t.add_column(style="white")
        t.add_row("[1]", "Full Auto Recon  (all modules)")
        t.add_row("[2]", "Select Categories")
        t.add_row("[3]", "Select Single Module")
        t.add_row("[4]", "List All Modules")
        t.add_row("[5]", "Settings")
        t.add_row("[0]", "Exit")
        console.print(Panel(t, title="[bold]MSF Recon Tool[/bold]", border_style="cyan"))
    else:
        print("\n=== MSF Recon Tool ===")
        print(" 1. Full Auto Recon")
        print(" 2. Select Categories")
        print(" 3. Select Single Module")
        print(" 4. List All Modules")
        print(" 5. Settings")
        print(" 0. Exit")


def show_categories_menu():
    cats = list_categories()
    if _RICH:
        t = Table(show_header=True, header_style="bold yellow")
        t.add_column("#", style="cyan", justify="right")
        t.add_column("Category", style="white")
        t.add_column("Modules", justify="right", style="green")
        for i, c in enumerate(cats, 1):
            t.add_row(str(i), c, str(len(modules_for_category(c))))
        console.print(t)
    else:
        for i, c in enumerate(cats, 1):
            print(f"  [{i}] {c} ({len(modules_for_category(c))} modules)")
    return cats


def show_modules_menu(modules):
    if _RICH:
        t = Table(show_header=True, header_style="bold magenta", show_lines=True)
        t.add_column("#", justify="right", style="cyan")
        t.add_column("Key", style="dim")
        t.add_column("Description", style="white")
        t.add_column("Type", style="yellow")
        for i, m in enumerate(modules, 1):
            t.add_row(str(i), m["key"], m["description"], m["type"])
        console.print(t)
    else:
        for i, m in enumerate(modules, 1):
            print(f"  [{i:2}] {m['description']}")


def get_target_and_options():
    target = _input("[bold cyan]Enter target[/bold cyan] (IP/hostname/CIDR)")
    if not target:
        return None, {}

    opts: dict = {}
    use_msf = _confirm("Use Metasploit (requires msfconsole)?")
    if use_msf:
        lhost = _input("LHOST (your IP, press Enter to skip)")
        if lhost:
            opts["lhost"] = lhost
            opts["lport"] = int(_input("LPORT") or "4444")

    ports_raw = _input("Extra ports to scan (e.g. 8000-9000, blank = defaults)")
    if ports_raw.strip():
        from main import parse_custom_ports
        opts["custom_ports"] = parse_custom_ports(ports_raw)

    threads = _input("Threads (default 100)")
    opts["threads"] = int(threads) if threads.strip().isdigit() else 100
    opts["use_msf"] = use_msf
    return target, opts


def run_recon(target, categories, options):
    from recon_engine import ReconEngine
    engine = ReconEngine(use_msf=options.get("use_msf", False))

    if options.get("use_msf"):
        ok = engine.connect_msf()
        if not ok:
            _print("[yellow][-] MSF offline — running Python-only probes.[/yellow]")

    report = engine.recon(
        target=target,
        categories=categories or None,
        custom_ports=options.get("custom_ports"),
        threads=options.get("threads", 100),
        lhost=options.get("lhost"),
        lport=options.get("lport", 4444),
    )

    ReconEngine.print_summary(report)

    save = _confirm("Save JSON report?")
    if save:
        path = _input("Filename (blank = auto)")
        if not path:
            import time
            path = f"recon_{target.replace('/', '_')}_{int(time.time())}.json"
        ReconEngine.save_report(report, path)

    engine.disconnect_msf()
    return report


# ─────────────────────────────────────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if _RICH:
        console.print(Panel(
            "[bold cyan]MSF Recon Tool[/bold cyan]  [dim]— Interactive Mode[/dim]",
            border_style="cyan"
        ))
    else:
        print("=== MSF Recon Tool — Interactive Mode ===")

    while True:
        show_main_menu()
        choice = _input("Select option").strip()

        if choice == "0":
            _print("Goodbye!", style="green")
            break

        elif choice == "1":
            target, opts = get_target_and_options()
            if target:
                run_recon(target, None, opts)

        elif choice == "2":
            cats = show_categories_menu()
            sel = _input("Select categories (comma-separated numbers)").strip()
            selected = []
            for part in sel.split(","):
                part = part.strip()
                if part.isdigit():
                    idx = int(part) - 1
                    if 0 <= idx < len(cats):
                        selected.append(cats[idx])
            if not selected:
                _print("No categories selected.", style="yellow")
                continue
            target, opts = get_target_and_options()
            if target:
                run_recon(target, selected, opts)

        elif choice == "3":
            all_mods = MODULES
            show_modules_menu(all_mods)
            sel = _input("Select module number").strip()
            if sel.isdigit():
                idx = int(sel) - 1
                if 0 <= idx < len(all_mods):
                    mod = all_mods[idx]
                    target, opts = get_target_and_options()
                    if target:
                        # Override options interactively
                        _print(f"\n[cyan]Default options for {mod['key']}:[/cyan]")
                        merged_opts = {**mod["default_opts"]}
                        for k, v in merged_opts.items():
                            new_val = _input(f"  {k} (default: {v})")
                            if new_val.strip():
                                merged_opts[k] = new_val

                        if opts.get("use_msf"):
                            from recon_engine import ReconEngine
                            engine = ReconEngine(use_msf=True)
                            if engine.connect_msf():
                                merged_opts["RHOSTS"] = target
                                result = engine._bridge.run_module(
                                    mod["path"], merged_opts,
                                    run_cmd=mod["run_cmd"], timeout=90
                                )
                                _print(f"\n[green]Output:[/green]")
                                for line in result["output"]:
                                    if line.strip():
                                        _print(f"  {line}")
                                engine.disconnect_msf()
                            else:
                                _print("[yellow]MSF not available.[/yellow]")
                        else:
                            _print("[yellow]MSF mode required for single module run.[/yellow]")

        elif choice == "4":
            from reconforge.cli import list_modules_table
            list_modules_table()

        elif choice == "5":
            _print("[dim]Settings — future feature.[/dim]")

        else:
            _print("Unknown option.", style="yellow")


if __name__ == "__main__":
    main()


# Alias for CLI entry point
def interactive_session():
    """Public entry point called from cli.py."""
    main()
