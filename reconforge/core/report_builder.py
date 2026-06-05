"""
core/report_builder.py
----------------------
Builds a professional HTML Vulnerability Assessment Report with
executive summary, risk scoring, visual indicators, and remediation steps.
"""

import json
from datetime import datetime

class ReportBuilder:
    @staticmethod
    def generate_html_report(scan_results: dict) -> str:
        """
        Generates a clean, dark-mode styled HTML Vulnerability Assessment Report.
        """
        target_network = scan_results.get("network", "Local Network")
        scan_time = scan_results.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        devices = scan_results.get("devices", [])

        # Calculate metrics
        total_devices = len(devices)
        vuln_count = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        exploited_count = 0

        for d in devices:
            if d.get("exploited", False):
                exploited_count += 1
            for v in d.get("vulns", []):
                vuln_count += 1
                sev = v.get("severity", "Low").lower()
                if sev == "critical":
                    critical_count += 1
                elif sev == "high":
                    high_count += 1
                elif sev == "medium":
                    medium_count += 1
                else:
                    low_count += 1

        # Security Risk Score (out of 100)
        risk_score = 0
        if total_devices > 0:
            deductions = (critical_count * 25) + (high_count * 15) + (medium_count * 5) + (low_count * 1)
            risk_score = max(0, min(100, deductions))

        risk_level = "Secure"
        risk_color = "#10B981"
        if risk_score > 75:
            risk_level = "Critical Threat"
            risk_color = "#EF4444"
        elif risk_score > 40:
            risk_level = "High Risk"
            risk_color = "#F59E0B"
        elif risk_score > 10:
            risk_level = "Medium Risk"
            risk_color = "#3B82F6"

        device_rows = ""
        for d in devices:
            status_badge = '<span class="badge badge-success">Clean</span>'
            if d.get("exploited", False):
                status_badge = '<span class="badge badge-danger">EXPLOITED</span>'
            elif len(d.get("vulns", [])) > 0:
                status_badge = '<span class="badge badge-warning">Vulnerable</span>'

            ports_str = ", ".join(str(p) for p in d.get("open_ports", [])) or "None"

            device_rows += f"""
            <tr class="device-row">
                <td>
                    <div style="font-weight: 700; color: #fff;">{d['ip']}</div>
                    <div style="font-size: 0.8rem; color: #8892b0;">{d.get('hostname', 'Unknown')}</div>
                </td>
                <td style="color: #ccd6f6; font-size: 0.9rem;">{d['mac']}</td>
                <td style="color: #ccd6f6; font-size: 0.9rem;">{d.get('vendor', 'Unknown')}</td>
                <td style="color: #ccd6f6; font-size: 0.9rem;">{d.get('device_type', 'Unknown')}</td>
                <td style="color: #64ffda; font-weight: 500;">{ports_str}</td>
                <td>{status_badge}</td>
            </tr>
            """

        vuln_details = ""
        if vuln_count == 0:
            vuln_details = '<div class="no-findings">No security vulnerabilities were identified on the network.</div>'
        else:
            for d in devices:
                if len(d.get("vulns", [])) == 0:
                    continue
                vuln_details += f"""
                <div class="vuln-card">
                    <div class="vuln-card-header">
                        <div>
                            <span class="vuln-ip">{d['ip']}</span>
                            <span style="color: #8892b0; margin-left: 10px;">({d.get('hostname', 'Unknown')})</span>
                        </div>
                        <span class="badge badge-danger">Vulnerabilities Detected</span>
                    </div>
                """
                for v in d.get("vulns", []):
                    sev_class = f"badge-{v.get('severity', 'Low').lower()}"
                    vuln_details += f"""
                    <div class="vuln-item">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <h4 style="margin: 0; color: #fff; font-size: 1.1rem;">{v['name']}</h4>
                            <span class="badge {sev_class}">{v['severity'].upper()} (CVSS: {v.get('cvss', 'N/A')})</span>
                        </div>
                        <div style="font-size: 0.9rem; color: #64ffda; margin-bottom: 6px;">Port: {v['port']} | CVE: {v['cve']}</div>
                        <p style="margin: 0 0 10px 0; color: #a8b2d1; font-size: 0.95rem; line-height: 1.5;">{v['description']}</p>
                        <div class="remediation-block">
                            <strong>Remediation:</strong> {v['remediation']}
                        </div>
                    </div>
                    """
                vuln_details += "</div>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Assessment Report - {target_network}</title>
    <style>
        :root {{
            --bg-dark: #0a192f;
            --bg-card: #112240;
            --text-main: #a8b2d1;
            --text-header: #ccd6f6;
            --teal: #64ffda;
        }}
        body {{
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 2px solid #233554;
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }}
        h1 {{
            color: #fff;
            margin: 0 0 10px 0;
            font-size: 2.2rem;
        }}
        h2 {{
            color: #fff;
            border-bottom: 1px solid #233554;
            padding-bottom: 8px;
            margin-top: 40px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1-fraction));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: var(--bg-card);
            border: 1px solid #233554;
            border-radius: 6px;
            padding: 20px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 2rem;
            font-weight: bold;
            color: #fff;
            margin-top: 5px;
        }}
        .metric-title {{
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #8892b0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 6px;
            overflow: hidden;
        }}
        th, td {{
            padding: 14px 18px;
            text-align: left;
        }}
        th {{
            background-color: #233554;
            color: #fff;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        tr {{
            border-bottom: 1px solid #233554;
        }}
        tr:last-child {{
            border-bottom: none;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            font-size: 0.75rem;
            font-weight: bold;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-success {{ background-color: #10B981; color: #fff; }}
        .badge-warning {{ background-color: #F59E0B; color: #fff; }}
        .badge-danger {{ background-color: #EF4444; color: #fff; }}
        .badge-critical {{ background-color: #EF4444; color: #fff; }}
        .badge-high {{ background-color: #F59E0B; color: #fff; }}
        .badge-medium {{ background-color: #3B82F6; color: #fff; }}
        .badge-low {{ background-color: #6B7280; color: #fff; }}

        .vuln-card {{
            background: var(--bg-card);
            border: 1px solid #233554;
            border-radius: 6px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .vuln-card-header {{
            background-color: #1b2f4a;
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #233554;
        }}
        .vuln-ip {{
            font-weight: bold;
            color: #fff;
            font-size: 1.1rem;
        }}
        .vuln-item {{
            padding: 20px;
            border-bottom: 1px solid #233554;
        }}
        .vuln-item:last-child {{
            border-bottom: none;
        }}
        .remediation-block {{
            background-color: rgba(100, 255, 218, 0.08);
            border-left: 3px solid var(--teal);
            padding: 10px 15px;
            border-radius: 0 4px 4px 0;
            font-size: 0.9rem;
            color: var(--teal);
        }}
        .no-findings {{
            text-align: center;
            padding: 40px;
            background: var(--bg-card);
            border: 1px dashed #233554;
            border-radius: 6px;
            color: #8892b0;
        }}
        .footer {{
            margin-top: 60px;
            padding-top: 20px;
            border-top: 1px solid #233554;
            text-align: center;
            font-size: 0.8rem;
            color: #8892b0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Vulnerability Assessment Report</h1>
                <div style="color: var(--teal); font-size: 1.1rem;">ReconForge Assessment Platform</div>
            </div>
            <div style="text-align: right; font-size: 0.9rem; color: #8892b0;">
                <div>Target Net: <strong>{target_network}</strong></div>
                <div>Generated: <strong>{scan_time}</strong></div>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">Risk Index Score</div>
                <div class="metric-value" style="color: {risk_color}">{risk_score} / 100</div>
                <div style="font-size: 0.8rem; margin-top: 5px; color: {risk_color}">{risk_level}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Live Host Count</div>
                <div class="metric-value">{total_devices}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Identified Vulnerabilities</div>
                <div class="metric-value" style="color: #EF4444;">{vuln_count}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Exploited Systems</div>
                <div class="metric-value" style="color: #EF4444;">{exploited_count}</div>
            </div>
        </div>

        <h2>Discovered Network Devices</h2>
        <div style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>IP / Hostname</th>
                        <th>MAC Address</th>
                        <th>Vendor</th>
                        <th>Device Type</th>
                        <th>Open Ports</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {device_rows}
                </tbody>
            </table>
        </div>

        <h2>Vulnerability Details & Remediation Guidance</h2>
        {vuln_details}

        <div class="footer">
            Confidential Assessment Report. Generated by ReconForge for network verification purposes.
        </div>
    </div>
</body>
</html>
"""
        return html_content
