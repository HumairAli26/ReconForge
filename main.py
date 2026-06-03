#!/usr/bin/env python
"""
ReconForge — CLI Entry Point and Web GUI Launcher
-------------------------------------------------
White-hat network verification and penetration testing suite.
"""

import argparse
import sys
import os
import webbrowser
import threading
import time

# Ensure imports from current directory work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, state, scanner_net, scanner_port, vuln_engine, ReportBuilder

def start_web_gui(host="127.0.0.1", port=5000):
    url = f"http://{host}:{port}/"
    print(f"[*] Starting ReconForge Platform Web GUI at: {url}")
    
    # Auto-open browser in a separate thread
    def open_browser():
        time.sleep(1.5)
        print(f"[*] Launching web browser to {url}...")
        webbrowser.open(url)
        
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host=host, port=port, debug=False)

def run_cli_mode(network, port_scan, html_report_path):
    print("=" * 60)
    print("           ReconForge Security Assessment Console")
    print("=" * 60)
    
    # Subnet discovery
    print(f"[*] Starting network discovery sweep on: {network}...")
    devices = scanner_net.scan(network)
    state["network"] = network
    state["devices"] = devices
    print(f"[+] Found {len(devices)} active host(s) on the subnet.")
    
    # Table headers
    print(f"\n{'IP ADDRESS':<16} {'MAC ADDRESS':<20} {'HOSTNAME':<25} {'VENDOR':<20}")
    print("-" * 85)
    for dev in devices:
        print(f"{dev['ip']:<16} {dev['mac']:<20} {dev.get('hostname', 'Unknown'):<25} {dev.get('vendor', 'Unknown'):<20}")
        
    if port_scan:
        print("\n[*] Commencing threaded port/service scan on all discovered hosts...")
        for dev in devices:
            ip = dev["ip"]
            print(f"[*] Scanning {ip}...")
            ports_info = scanner_port.scan(ip)
            dev["open_ports"] = list(ports_info.keys())
            dev["services"] = ports_info
            
            # Vulns engine mapping
            vulns = vuln_engine.analyze_device(ip, ports_info)
            dev["vulns"] = vulns
            
            ports_str = ", ".join(str(p) for p in dev["open_ports"]) or "None"
            print(f"    [+] Open ports: {ports_str}")
            if len(vulns) > 0:
                print(f"    [!] Detected {len(vulns)} potential vulnerabilities.")
                for v in vulns:
                    print(f"        - {v['name']} ({v['severity']})")
                    
    # Generate HTML report if requested
    if html_report_path:
        html_report = ReportBuilder.generate_html_report(state)
        with open(html_report_path, "w", encoding="utf-8") as f:
            f.write(html_report)
        print(f"\n[+] Vulnerability Assessment Report saved to: {html_report_path}")

def main():
    parser = argparse.ArgumentParser(description="ReconForge Network Verification and Pentest Dashboard Launcher")
    parser.add_argument("--cli", action="store_true", help="Run in command line mode without starting the web UI")
    parser.add_argument("-t", "--target", default=None, help="Target subnet network (e.g. 192.168.1.0/24)")
    parser.add_argument("--ports", action="store_true", help="Perform service and port scan on CLI targets")
    parser.add_argument("-o", "--output", default="ReconForge_Report.html", help="HTML report output path (CLI mode only)")
    parser.add_argument("--port", type=int, default=5000, help="Web Server Port (Default: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Web Server Bind Address")
    
    args = parser.parse_args()
    
    if args.cli:
        target = args.target or scanner_net.auto_detect_network()
        run_cli_mode(target, args.ports, args.output)
    else:
        # Default behavior: run GUI
        start_web_gui(host=args.host, port=args.port)

if __name__ == "__main__":
    main()
