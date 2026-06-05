"""
reconforge/app.py  —  Flask REST API + Web Dashboard backend
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
from reconforge.core.vuln_engine     import VulnEngine
from reconforge.core.report_builder  import ReportBuilder

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

if FLASK_AVAILABLE:
    app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
    CORS(app)
else:
    app = None

state = {"network": "192.168.1.0/24", "devices": [], "scan_time": None}

scanner_net  = NetworkScanner()
scanner_port = PortScanner()
msf_runner   = MSFRunner()   # starts msfconsole in background immediately
vuln_engine  = VulnEngine()


if FLASK_AVAILABLE:

    @app.route("/")
    def serve_index():
        return send_from_directory(app.static_folder, "index.html")

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

    # ── MSF endpoints ─────────────────────────────────────────────────────────

    @app.route("/api/msf/status")
    def msf_status():
        """
        Returns both installed (binary found) and ready (subprocess up).
        The frontend polls this so the badge updates automatically.
        """
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

    @app.route("/api/report/generate")
    def get_report():
        html  = ReportBuilder.generate_html_report(state)
        path  = "/tmp/ReconForge_Report.html"
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
