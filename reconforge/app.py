"""
reconforge/app.py — Flask REST API + Web Dashboard backend

Fixes in this version:
  - All scans run in background threads (never block the API)
  - Flask runs threaded=True so MSF boot, scans, and API calls all work simultaneously
  - Ctrl+C in terminal shuts down Flask cleanly
  - Closing the browser tab (beforeunload ping) also shuts down the server
  - MSF initialises in background — web UI and scans work immediately, MSF readies itself
  - Proper scan status endpoint so frontend can poll progress
"""

import os
import signal
import sys
import threading
import time
from datetime import datetime

try:
    from flask import Flask, jsonify, request, send_from_directory, send_file
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

from reconforge.core.network_scanner import NetworkScanner
from reconforge.core.port_scanner    import PortScanner
from reconforge.core.msf_runner      import MSFRunner
from reconforge.core.nuclei_bridge   import NucleiBridge
from reconforge.core.vuln_engine     import VulnEngine
from reconforge.core.report_builder  import ReportBuilder

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

if FLASK_AVAILABLE:
    app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
    CORS(app)
else:
    app = None

# ── Global state ──────────────────────────────────────────────────────────────
state = {
    "network":       "192.168.1.0/24",
    "devices":       [],
    "scan_time":     None,
    "active_engine": "msf",
}

# Scan progress tracking
scan_status = {
    "network_scanning": False,
    "network_progress": 0,
    "network_total":    0,
    "port_scanning":    {},   # ip -> bool
}

# Tool instances — MSF boots in background, everything else is instant
scanner_net  = NetworkScanner()
scanner_port = PortScanner()
msf_runner   = MSFRunner()     # starts msfconsole in daemon thread immediately
nuclei       = NucleiBridge()  # instant — no boot needed
vuln_engine  = VulnEngine()

# ── Shutdown helper ───────────────────────────────────────────────────────────
_shutdown_lock = threading.Lock()
_shutting_down = False

def _shutdown(reason="signal"):
    global _shutting_down
    with _shutdown_lock:
        if _shutting_down:
            return
        _shutting_down = True
    print(f"\n[*] ReconForge shutting down ({reason})...")
    # Stop MSF cleanly
    try:
        if msf_runner._bridge:
            msf_runner._bridge.stop()
    except Exception:
        pass
    # Kill this process
    os.kill(os.getpid(), signal.SIGTERM)

# Handle Ctrl+C and SIGTERM in terminal
def _handle_signal(sig, frame):
    _shutdown("Ctrl+C")

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


if FLASK_AVAILABLE:

    @app.route("/")
    def serve_index():
        return send_from_directory(app.static_folder, "index.html")

    # ── Shutdown endpoint (called when browser tab closes) ────────────────────

    @app.route("/api/shutdown", methods=["POST"])
    def shutdown():
        """Called by frontend beforeunload event to shut down server."""
        t = threading.Thread(target=lambda: (_shutdown("browser closed")), daemon=True)
        t.start()
        return jsonify({"ok": True})

    # ── Heartbeat (frontend pings this; if it stops → server is dead) ─────────

    @app.route("/api/ping")
    def ping():
        return jsonify({"ok": True, "time": time.time()})

    # ── Network detect ────────────────────────────────────────────────────────

    @app.route("/api/network/detect")
    def detect_network():
        net = scanner_net.auto_detect_network()
        state["network"] = net
        return jsonify({"network": net})

    # ── Network scan — runs in background thread, returns immediately ─────────

    @app.route("/api/scan/network", methods=["POST"])
    def scan_network():
        if scan_status["network_scanning"]:
            return jsonify({"success": False, "error": "Scan already running"}), 409

        data    = request.json or {}
        network = data.get("network") or state["network"]
        state["network"]   = network
        state["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state["devices"]   = []

        scan_status["network_scanning"] = True
        scan_status["network_progress"] = 0
        scan_status["network_total"]    = 0

        def _run():
            devices = []
            try:
                def on_device(dev):
                    devices.append(dev)
                    state["devices"].append(dev)

                def on_progress(done, total):
                    scan_status["network_progress"] = done
                    scan_status["network_total"]    = total

                scanner_net.scan(network, on_device=on_device, on_progress=on_progress)
            finally:
                scan_status["network_scanning"] = False

        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"success": True, "status": "scanning", "network": network})

    # ── Network scan progress ─────────────────────────────────────────────────

    @app.route("/api/scan/network/status")
    def scan_network_status():
        return jsonify({
            "scanning": scan_status["network_scanning"],
            "progress": scan_status["network_progress"],
            "total":    scan_status["network_total"],
            "devices":  state["devices"],
            "count":    len(state["devices"]),
        })

    # ── Port scan — runs in background thread ─────────────────────────────────

    @app.route("/api/scan/ports", methods=["POST"])
    def scan_ports():
        ip = (request.json or {}).get("ip")
        if not ip:
            return jsonify({"success": False, "error": "IP required"}), 400

        if scan_status["port_scanning"].get(ip):
            return jsonify({"success": False, "error": f"Port scan already running for {ip}"}), 409

        scan_status["port_scanning"][ip] = True

        def _run():
            try:
                ports_info = scanner_port.scan(ip)
                device = next((d for d in state["devices"] if d["ip"] == ip), None)
                if not device:
                    device = {
                        "ip": ip, "mac": "00:00:00:00:00:00",
                        "hostname": "Adhoc Target", "vendor": "Unknown",
                        "device_type": "Computer",
                        "first_seen": datetime.now().isoformat(),
                        "open_ports": [], "services": {}, "vulns": [],
                        "risk": "Unknown", "exploited": False,
                    }
                    state["devices"].append(device)

                device["open_ports"] = list(ports_info.keys())
                device["services"]   = ports_info
                vulns = vuln_engine.analyze_device(ip, ports_info)
                device["vulns"] = vulns
                device["risk"]  = "Vulnerable" if vulns else ("Open" if ports_info else "Clean")
            finally:
                scan_status["port_scanning"][ip] = False

        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"success": True, "status": "scanning", "ip": ip})

    # ── Port scan status ──────────────────────────────────────────────────────

    @app.route("/api/scan/ports/status")
    def scan_ports_status():
        ip = request.args.get("ip")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        scanning = scan_status["port_scanning"].get(ip, False)
        device   = next((d for d in state["devices"] if d["ip"] == ip), None)
        return jsonify({
            "scanning": scanning,
            "done":     not scanning,
            "device":   device,
        })

    # ── Engine selector ───────────────────────────────────────────────────────

    @app.route("/api/engine/select", methods=["POST"])
    def select_engine():
        engine = (request.json or {}).get("engine", "msf").lower()
        if engine not in ("msf", "nuclei"):
            return jsonify({"success": False, "error": "engine must be 'msf' or 'nuclei'"}), 400
        state["active_engine"] = engine
        return jsonify({"success": True, "active_engine": engine})

    @app.route("/api/engine/status")
    def engine_status():
        return jsonify({
            "active_engine": state["active_engine"],
            "msf": {
                "installed": msf_runner.is_installed(),
                "available": msf_runner.is_available(),
            },
            "nuclei": {
                "installed": nuclei.is_installed(),
                "available": nuclei.is_available(),
                "version":   nuclei.get_version() if nuclei.is_available() else "not installed",
            },
        })

    # ── MSF endpoints ─────────────────────────────────────────────────────────

    @app.route("/api/msf/status")
    def msf_status():
        return jsonify({
            "installed": msf_runner.is_installed(),
            "available": msf_runner.is_available(),
        })

    @app.route("/api/msf/available")
    def msf_available():
        return jsonify({"available": msf_runner.is_available()})

    @app.route("/api/msf/modules")
    def get_msf_modules():
        return jsonify({"modules": msf_runner.get_available_modules()})

    @app.route("/api/msf/exploit", methods=["POST"])
    def run_exploit():
        data       = request.json or {}
        module_key = data.get("module")
        ip         = data.get("ip")
        if not module_key or not ip:
            return jsonify({"success": False, "error": "module and ip required"}), 400
        res = msf_runner.run_exploit(module_key, ip, data.get("options", {}))
        if res.get("success"):
            for d in state["devices"]:
                if d["ip"] == ip:
                    d["exploited"] = True
                    d["risk"]      = "Exploited"
        return jsonify(res)

    # ── Nuclei endpoints ──────────────────────────────────────────────────────

    @app.route("/api/nuclei/status")
    def nuclei_status_ep():
        return jsonify({
            "installed": nuclei.is_installed(),
            "available": nuclei.is_available(),
            "version":   nuclei.get_version() if nuclei.is_available() else "not installed",
        })

    @app.route("/api/nuclei/scan", methods=["POST"])
    def nuclei_scan():
        data       = request.json or {}
        ip         = data.get("ip")
        severities = data.get("severities")
        if not ip:
            return jsonify({"success": False, "error": "ip required"}), 400
        if not nuclei.is_available():
            return jsonify({"success": False,
                            "error": "nuclei not installed. Run: sudo apt install nuclei"}), 503

        device     = next((d for d in state["devices"] if d["ip"] == ip), None)
        open_ports = device.get("open_ports", []) if device else []
        findings   = nuclei.scan_ports(ip, open_ports, severities=severities)

        if device:
            device["nuclei_findings"] = findings
            device["risk"] = (
                "Critical"   if any(f["severity"] == "critical" for f in findings) else
                "Vulnerable" if findings else device.get("risk", "Clean")
            )
        return jsonify({"success": True, "ip": ip,
                        "findings": findings, "count": len(findings)})

    @app.route("/api/nuclei/update", methods=["POST"])
    def nuclei_update():
        if not nuclei.is_available():
            return jsonify({"success": False, "error": "nuclei not installed"}), 503
        success = nuclei.update_templates()
        return jsonify({"success": success})

    # ── Unified vuln scan (active engine) ─────────────────────────────────────

    @app.route("/api/scan/vuln", methods=["POST"])
    def scan_vuln():
        data   = request.json or {}
        ip     = data.get("ip")
        engine = state["active_engine"]
        if not ip:
            return jsonify({"success": False, "error": "ip required"}), 400

        if engine == "nuclei":
            if not nuclei.is_available():
                return jsonify({"success": False,
                                "error": "Nuclei not installed. Run: sudo apt install nuclei"}), 503
            device     = next((d for d in state["devices"] if d["ip"] == ip), None)
            open_ports = device.get("open_ports", []) if device else []
            findings   = nuclei.scan_ports(ip, open_ports, severities=data.get("severities"))
            if device:
                device["nuclei_findings"] = findings
            return jsonify({"success": True, "engine": "nuclei",
                            "ip": ip, "findings": findings, "count": len(findings)})
        else:
            module_key = data.get("module")
            if not module_key:
                return jsonify({"success": False, "error": "module required for MSF"}), 400
            res = msf_runner.run_exploit(module_key, ip, data.get("options", {}))
            if res.get("success"):
                for d in state["devices"]:
                    if d["ip"] == ip:
                        d["exploited"] = True
                        d["risk"] = "Exploited"
            res["engine"] = "msf"
            return jsonify(res)

    # ── Report ────────────────────────────────────────────────────────────────

    @app.route("/api/report/generate")
    def get_report():
        html = ReportBuilder.generate_html_report(state)
        path = "/tmp/ReconForge_Report.html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return send_file(path, as_attachment=True,
                         download_name="ReconForge_Assessment_Report.html")


def run_web(host="127.0.0.1", port=5000, debug=False):
    if not FLASK_AVAILABLE:
        print("[!] Flask not installed. Run: pip install flask flask-cors")
        return
    print(f"[*] ReconForge Web GUI → http://{host}:{port}/")
    print(f"[*] Press Ctrl+C to stop.")
    try:
        app.run(
            host=host,
            port=port,
            debug=False,          # never use debug=True — it spawns a reloader that breaks signals
            use_reloader=False,   # reloader forks the process and breaks Ctrl+C
            threaded=True,        # CRITICAL: allows concurrent requests (scans + API at same time)
        )
    except (KeyboardInterrupt, SystemExit):
        _shutdown("Ctrl+C")


if __name__ == "__main__":
    run_web()
