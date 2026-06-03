"""
report_generator.py
-------------------
Converts the JSON recon report into a styled HTML file.
No external dependencies — pure stdlib template.
"""

import json
import os
from datetime import datetime, timezone
UTC = timezone.utc
from typing import Dict, Any


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Recon Report — {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

  :root {{
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #30363d;
    --accent:   #58a6ff;
    --green:    #3fb950;
    --yellow:   #d29922;
    --red:      #f85149;
    --text:     #c9d1d9;
    --muted:    #8b949e;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Inter', sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
  }}

  header {{
    background: linear-gradient(135deg, #0d1117 0%, #1a2332 50%, #0d1117 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2rem 2.5rem;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
  }}
  header::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 3px;
    background: linear-gradient(90deg, var(--accent), #a371f7, var(--green));
  }}
  header h1 {{
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--accent);
    margin-bottom: 0.5rem;
  }}
  header .meta {{ color: var(--muted); font-size: 0.9rem; }}
  header .meta span {{ margin-right: 1.5rem; }}
  header .badge {{
    display: inline-block;
    padding: 0.2rem 0.7rem;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
    margin-left: 0.5rem;
  }}
  .badge-msf  {{ background: #1f3a5f; color: var(--accent); border: 1px solid var(--accent); }}
  .badge-offline {{ background: #2a2010; color: var(--yellow); border: 1px solid var(--yellow); }}

  section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 1.5rem;
    overflow: hidden;
  }}
  .section-header {{
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 0.75rem;
    background: rgba(88,166,255,0.04);
  }}
  .section-header h2 {{
    font-size: 1rem;
    font-weight: 600;
    color: var(--accent);
  }}
  .section-header .icon {{ font-size: 1.2rem; }}
  .section-body {{ padding: 1.5rem; }}

  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }}
  th {{
    text-align: left;
    padding: 0.6rem 1rem;
    border-bottom: 2px solid var(--border);
    color: var(--muted);
    font-weight: 600;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  td {{
    padding: 0.6rem 1rem;
    border-bottom: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}

  .port {{ color: var(--accent); font-weight: 600; }}
  .service {{ color: var(--green); }}
  .banner {{ color: var(--muted); word-break: break-all; }}

  .dns-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 1rem;
  }}
  .dns-card {{
    background: rgba(88,166,255,0.05);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
  }}
  .dns-card h3 {{
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--accent);
    margin-bottom: 0.5rem;
  }}
  .dns-value {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: var(--text);
    margin-bottom: 0.2rem;
  }}

  .tag {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
  }}
  .tag-ok  {{ background: #1a3a1a; color: var(--green); }}
  .tag-err {{ background: #3a1a1a; color: var(--red); }}
  .tag-warn {{ background: #3a2a0a; color: var(--yellow); }}

  .ssl-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.75rem;
  }}
  .ssl-field {{ margin-bottom: 0.25rem; }}
  .ssl-label {{ color: var(--muted); font-size: 0.75rem; }}
  .ssl-value {{ font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; }}

  .msf-item {{
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 1rem;
    overflow: hidden;
  }}
  .msf-header {{
    padding: 0.75rem 1rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    cursor: pointer;
    background: rgba(255,255,255,0.02);
  }}
  .msf-header:hover {{ background: rgba(255,255,255,0.04); }}
  .msf-desc {{ flex: 1; font-size: 0.9rem; }}
  .msf-path {{ font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--muted); }}
  .msf-output {{
    display: none;
    padding: 1rem;
    border-top: 1px solid var(--border);
    background: #0a0d11;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }}
  .msf-output.open {{ display: block; }}

  .stat-row {{
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    margin-bottom: 1.5rem;
  }}
  .stat-card {{
    flex: 1;
    min-width: 120px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.5rem;
    text-align: center;
  }}
  .stat-card .num {{
    font-size: 2.2rem;
    font-weight: 700;
    color: var(--accent);
    display: block;
  }}
  .stat-card .label {{
    font-size: 0.75rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}

  footer {{
    text-align: center;
    color: var(--muted);
    font-size: 0.8rem;
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
  }}
</style>
</head>
<body>

<header>
  <h1>🔍 Recon Report — {target}</h1>
  <div class="meta">
    <span>🌐 <strong>{target}</strong>{ip_part}</span>
    <span>🕐 {timestamp}</span>
    <span>{msf_badge}</span>
  </div>
</header>

<!-- Stats -->
<div class="stat-row">
{stat_cards}
</div>

{sections_html}

<footer>
  Generated by MSF Recon Tool &nbsp;|&nbsp; For authorised security testing only
</footer>

<script>
  document.querySelectorAll('.msf-header').forEach(h => {{
    h.addEventListener('click', () => {{
      h.nextElementSibling.classList.toggle('open');
    }});
  }});
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Section renderers
# ─────────────────────────────────────────────────────────────────────────────

def _ports_section(ports: dict) -> str:
    if not ports:
        return ""
    rows = ""
    for port, info in ports.items():
        service = info.get("service", "unknown")
        banner = (info.get("banner") or info.get("server") or "")[:120]
        rows += f"""
        <tr>
          <td class="port">{port}</td>
          <td class="service">{service}</td>
          <td class="banner">{_esc(banner)}</td>
        </tr>"""
    return f"""
<section>
  <div class="section-header"><span class="icon">🔌</span><h2>Open Ports ({len(ports)})</h2></div>
  <div class="section-body" style="padding:0">
    <table>
      <tr><th>Port</th><th>Service</th><th>Banner / Info</th></tr>
      {rows}
    </table>
  </div>
</section>"""


def _dns_section(dns: dict) -> str:
    if not dns:
        return ""
    cards = ""
    for rtype, values in dns.items():
        vals = "".join(f'<div class="dns-value">{_esc(v)}</div>' for v in values)
        cards += f'<div class="dns-card"><h3>{rtype}</h3>{vals}</div>'
    return f"""
<section>
  <div class="section-header"><span class="icon">📡</span><h2>DNS Records</h2></div>
  <div class="section-body">
    <div class="dns-grid">{cards}</div>
  </div>
</section>"""


def _ssl_section(services: dict) -> str:
    https_list = services.get("https", [])
    if not https_list:
        return ""
    out = ""
    for entry in https_list:
        cert = entry.get("ssl_cert", {})
        if not cert or "error" in cert:
            continue
        subj = cert.get("subject", {})
        issuer = cert.get("issuer", {})
        san = ", ".join(cert.get("san", [])[:8])
        out += f"""
    <div style="margin-bottom:1rem; padding:1rem; border:1px solid var(--border); border-radius:8px;">
      <div class="ssl-grid">
        <div>
          <div class="ssl-field"><span class="ssl-label">Common Name</span><div class="ssl-value">{_esc(subj.get('commonName','—'))}</div></div>
          <div class="ssl-field"><span class="ssl-label">Issuer</span><div class="ssl-value">{_esc(issuer.get('organizationName','—'))}</div></div>
          <div class="ssl-field"><span class="ssl-label">Valid Until</span><div class="ssl-value">{_esc(cert.get('notAfter','—'))}</div></div>
        </div>
        <div>
          <div class="ssl-field"><span class="ssl-label">SAN</span><div class="ssl-value">{_esc(san) or '—'}</div></div>
          <div class="ssl-field"><span class="ssl-label">Port</span><div class="ssl-value">{entry.get('port','443')}</div></div>
        </div>
      </div>
    </div>"""
    if not out:
        return ""
    return f"""
<section>
  <div class="section-header"><span class="icon">🔒</span><h2>SSL/TLS Certificates</h2></div>
  <div class="section-body">{out}</div>
</section>"""


def _http_section(services: dict) -> str:
    items = services.get("http", []) + services.get("https", [])
    if not items:
        return ""
    rows = ""
    for entry in items:
        port = entry.get("port", "")
        status = entry.get("status", "")
        server = entry.get("server", "")
        headers = entry.get("headers", {})
        powered = headers.get("X-Powered-By", "")
        rows += f"""
        <tr>
          <td class="port">{port}</td>
          <td><span class="tag {'tag-ok' if str(status).startswith('2') else 'tag-warn'}">{status}</span></td>
          <td class="service">{_esc(server)}</td>
          <td class="banner">{_esc(powered)}</td>
        </tr>"""
    return f"""
<section>
  <div class="section-header"><span class="icon">🌐</span><h2>HTTP/S Services</h2></div>
  <div class="section-body" style="padding:0">
    <table>
      <tr><th>Port</th><th>Status</th><th>Server</th><th>X-Powered-By</th></tr>
      {rows}
    </table>
  </div>
</section>"""


def _msf_section(msf: dict) -> str:
    if not msf:
        return ""
    items = ""
    for key, res in msf.items():
        ok = res.get("success", False)
        tag = '<span class="tag tag-ok">✓ Hit</span>' if ok else '<span class="tag tag-err">· Miss</span>'
        output_lines = _esc("\n".join(res.get("output", [])))
        items += f"""
  <div class="msf-item">
    <div class="msf-header">
      {tag}
      <div>
        <div class="msf-desc">{_esc(res.get('description',''))}</div>
        <div class="msf-path">{_esc(res.get('module',''))}</div>
      </div>
    </div>
    <pre class="msf-output">{output_lines}</pre>
  </div>"""
    return f"""
<section>
  <div class="section-header"><span class="icon">⚙️</span><h2>Metasploit Module Results ({len(msf)})</h2></div>
  <div class="section-body">{items}</div>
</section>"""


def _esc(s: str) -> str:
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def generate_html(report: Dict[str, Any], out_path: str = None) -> str:
    target = report.get("target", "unknown")
    ip = report.get("resolved_ip")
    ts = report.get("timestamp", datetime.now(UTC).isoformat())
    msf_used = report.get("msf_used", False)
    sections = report.get("sections", {})

    ip_part = f" <span style='color:var(--muted)'>({ip})</span>" if ip and ip != target else ""
    msf_badge = (
        '<span class="badge badge-msf">Metasploit</span>'
        if msf_used else
        '<span class="badge badge-offline">Offline Mode</span>'
    )

    ports = sections.get("open_ports", {})
    dns   = sections.get("dns", {})
    svcs  = sections.get("services", {})
    msf   = sections.get("msf", {})

    # Stats
    n_ports = len(ports)
    n_msf   = len(msf)
    n_hits  = sum(1 for v in msf.values() if v.get("success"))
    n_dns   = sum(len(v) for v in dns.values())

    stat_cards = "".join([
        f'<div class="stat-card"><span class="num">{n_ports}</span><span class="label">Open Ports</span></div>',
        f'<div class="stat-card"><span class="num">{n_dns}</span><span class="label">DNS Records</span></div>',
        f'<div class="stat-card"><span class="num">{n_msf}</span><span class="label">MSF Modules Run</span></div>',
        f'<div class="stat-card"><span class="num" style="color:var(--green)">{n_hits}</span><span class="label">Module Hits</span></div>',
    ])

    sections_html = (
        _dns_section(dns) +
        _ports_section(ports) +
        _http_section(svcs) +
        _ssl_section(svcs) +
        _msf_section(msf)
    )

    html = HTML_TEMPLATE.format(
        target=_esc(target),
        ip_part=ip_part,
        timestamp=_esc(ts),
        msf_badge=msf_badge,
        stat_cards=stat_cards,
        sections_html=sections_html,
    )

    if out_path is None:
        out_path = f"recon_{target.replace('/', '_')}.html"

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    return out_path


# ─────────────────────────────────────────────────────────────────────────────
# CLI convenience
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python report_generator.py recon_report.json [output.html]")
        sys.exit(1)

    json_path = sys.argv[1]
    html_path = sys.argv[2] if len(sys.argv) > 2 else None

    with open(json_path) as f:
        report_data = json.load(f)

    out = generate_html(report_data, html_path)
    print(f"[+] HTML report saved -> {out}")
