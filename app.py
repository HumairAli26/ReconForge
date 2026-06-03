"""
app.py
------
Flask REST API for ReconForge dashboard. Serves 3D interactive frontend
and coordinates scanning, profiling, Metasploit integration, and reporting.
"""

import os
from flask import Flask, jsonify, request, send_from_directory, send_file
from flask_cors import CORS
from datetime import datetime

from core.network_scanner import NetworkScanner
from core.port_scanner import PortScanner
from core.msf_runner import MSFRunner
from core.vuln_engine import VulnEngine
from core.report_builder import ReportBuilder

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

# Global in-memory state
state = {
    "network": "192.168.1.0/24",
    "devices": [],
    "scan_time": None,
    "latest_exploit_log": ""
}

# Initialize engines
scanner_net = NetworkScanner()
scanner_port = PortScanner()
msf_runner = MSFRunner()
vuln_engine = VulnEngine()

@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/api/network/detect", methods=["GET"])
def detect_network():
    net = scanner_net.auto_detect_network()
    state["network"] = net
    return jsonify({"network": net})

@app.route("/api/scan/network", methods=["POST"])
def scan_network():
    data = request.json or {}
    network = data.get("network") or state["network"] or "192.168.1.0/24"
    state["network"] = network
    state["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Run network scan
    devices = scanner_net.scan(network)
    state["devices"] = devices
    return jsonify({"success": True, "devices": devices})

@app.route("/api/scan/ports", methods=["POST"])
def scan_ports():
    data = request.json or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"success": False, "error": "IP address target required"}), 400

    # Port scan
    ports_info = scanner_port.scan(ip)
    
    # Find device in state to update it
    device = None
    for d in state["devices"]:
        if d["ip"] == ip:
            device = d
            break
            
    if not device:
        # Create adhoc device if not scanned before
        device = {
            "ip": ip,
            "mac": "00:00:00:00:00:00",
            "hostname": "Adhoc Target",
            "vendor": "Unknown",
            "device_type": "Computer",
            "first_seen": datetime.now().isoformat()
        }
        state["devices"].append(device)

    device["open_ports"] = list(ports_info.keys())
    device["services"] = ports_info
    
    # Run vulnerability analysis offline mapping
    vulns = vuln_engine.analyze_device(ip, ports_info)
    device["vulns"] = vulns
    
    # Deduce device status / severity
    if len(vulns) > 0:
        device["risk"] = "Vulnerable"
    else:
        device["risk"] = "Clean"
        
    return jsonify({"success": True, "device": device})

@app.route("/api/msf/available", methods=["GET"])
def msf_available():
    return jsonify({
        "available": msf_runner.is_available()
    })

@app.route("/api/msf/modules", methods=["GET"])
def get_msf_modules():
    mods = msf_runner.get_available_modules()
    return jsonify({"modules": mods})

@app.route("/api/msf/exploit", methods=["POST"])
def run_exploit():
    data = request.json or {}
    module_key = data.get("module")
    ip = data.get("ip")
    extra_opts = data.get("options", {})

    if not module_key or not ip:
        return jsonify({"success": False, "error": "Module key and Target IP required"}), 400

    res = msf_runner.run_exploit(module_key, ip, extra_opts)
    if res.get("success"):
        # Update device in state as exploited if attack succeeded
        for d in state["devices"]:
            if d["ip"] == ip:
                d["exploited"] = True
                d["risk"] = "Exploited"
                break
        state["latest_exploit_log"] = res.get("output", "")
    
    return jsonify(res)

@app.route("/api/report/generate", methods=["GET", "POST"])
def get_report():
    html_report = ReportBuilder.generate_html_report(state)
    report_path = os.path.join(os.path.dirname(__file__), "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_report)
    return send_file(report_path, as_attachment=True, download_name="ReconForge_Assessment_Report.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
