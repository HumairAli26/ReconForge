"""
reconforge/app.py  —  Flask REST API + Web Dashboard backend
Supports MSF and Nuclei as selectable scan engines.
"""

import os
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

state = {
    "network":      "192.168.1.0/24",
    "devices":      [],
    "scan_time":    None,
    "active_engine": "msf",   # "msf" or "nuclei"
}

scanner_net  = NetworkScanner()
scanner_port = PortScanner()
msf_runner   = MSFRunner()        # boots msfconsole in background
nuclei       = NucleiBridge()     # instant — no boot needed
vuln_engine  = VulnEngine()


if FLASK_AVAILABLE:

    @app.route("/")
    def serve_index():
        return send_from_directory(app.static_folder, "index.html")

    # ── Network ───────────────────────────────────────────────────────────────

    @app.route("/api/network/detect")
    def detect_network():
        net = scanner_net.auto_detect_network()
        state["network"] = net
        return jsonify({"network": net})

    @app.route("/api/scan/network", methods=["POST"])
    def scan_network():
        data    = request.json or {}
        network = data.get("network") or state["network"]
        state["network"]   = network
        state["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        devices = scanner_net.scan(network)
        state["devices"] = devices
        return jsonify({"success": True, "devices": devices})

    @app.route("/api/scan/ports", methods=["POST"])
    def scan_ports():
        ip = (request.json or {}).get("ip")
        if not ip:
            return jsonify({"success": False, "error": "IP required"}), 400
        ports_info = scanner_port.scan(ip)
        device = next((d for d in state["devices"] if d["ip"] == ip), {
            "ip": ip, "mac": "00:00:00:00:00:00",
            "hostname": "Adhoc Target", "vendor": "Unknown",
            "device_type": "Computer",
            "first_seen": datetime.now().isoformat(),
        })
        device["open_ports"] = list(ports_info.keys())
        device["services"]   = ports_info
        vulns = vuln_engine.analyze_device(ip, ports_info)
        device["vulns"] = vulns
        device["risk"]  = "Vulnerable" if vulns else "Clean"
        if device not in state["devices"]:
            state["devices"].append(device)
        return jsonify({"success": True, "device": device})

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
    def nuclei_status():
        return jsonify({
            "installed": nuclei.is_installed(),
            "available": nuclei.is_available(),
            "version":   nuclei.get_version() if nuclei.is_available() else "not installed",
        })

    @app.route("/api/nuclei/scan", methods=["POST"])
    def nuclei_scan():
        data       = request.json or {}
        ip         = data.get("ip")
        severities = data.get("severities")   # e.g. ["critical","high","medium"]
        tags       = data.get("tags")         # e.g. ["cve","misconfig"]

        if not ip:
            return jsonify({"success": False, "error": "ip required"}), 400
        if not nuclei.is_available():
            return jsonify({
                "success": False,
                "error": "nuclei not installed. Run: sudo apt install nuclei"
            }), 503

        # Get open ports from state for smarter scanning
        device = next((d for d in state["devices"] if d["ip"] == ip), None)
        open_ports = device.get("open_ports", []) if device else []

        findings = nuclei.scan_ports(ip, open_ports, severities=severities)

        # Update device state with findings
        if device:
            device["nuclei_findings"] = findings
            device["risk"] = (
                "Critical" if any(f["severity"] == "critical" for f in findings) else
                "Vulnerable" if findings else
                device.get("risk", "Clean")
            )

        return jsonify({
            "success":  True,
            "ip":       ip,
            "findings": findings,
            "count":    len(findings),
        })

    @app.route("/api/nuclei/update", methods=["POST"])
    def nuclei_update():
        if not nuclei.is_available():
            return jsonify({"success": False, "error": "nuclei not installed"}), 503
        success = nuclei.update_templates()
        return jsonify({"success": success})

    # ── Unified scan endpoint (uses active engine) ────────────────────────────

    @app.route("/api/scan/vuln", methods=["POST"])
    def scan_vuln():
        """
        Run vulnerability scan using the currently selected engine (MSF or Nuclei).
        POST body: { "ip": "...", "module": "...(msf only)", "options": {...} }
        """
        data   = request.json or {}
        ip     = data.get("ip")
        engine = state["active_engine"]

        if not ip:
            return jsonify({"success": False, "error": "ip required"}), 400

        if engine == "nuclei":
            if not nuclei.is_available():
                return jsonify({
                    "success": False,
                    "error": "Nuclei not installed. Run: sudo apt install nuclei"
                }), 503
            device = next((d for d in state["devices"] if d["ip"] == ip), None)
            open_ports = device.get("open_ports", []) if device else []
            findings = nuclei.scan_ports(ip, open_ports,
                                          severities=data.get("severities"))
            if device:
                device["nuclei_findings"] = findings
            return jsonify({"success": True, "engine": "nuclei",
                            "ip": ip, "findings": findings, "count": len(findings)})

        else:  # msf
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
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_web()
