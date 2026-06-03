"""
test_offline.py
---------------
Self-test that runs WITHOUT Metasploit installed.
Tests the offline probes against scanme.nmap.org (Nmap's public test server).
Safe to run — it only does read-only TCP probes.

Run:
    python test_offline.py
"""

import sys
import os
import json
import unittest
import socket

sys.path.insert(0, os.path.dirname(__file__))

# ─────────────────────────────────────────────────────────────────────────────
# Unit-level tests for helper functions
# ─────────────────────────────────────────────────────────────────────────────

class TestOfflineHelpers(unittest.TestCase):

    def test_modules_catalog_loads(self):
        from modules_catalog import MODULES, list_categories, modules_for_category
        self.assertGreater(len(MODULES), 10, "Should have many modules")
        cats = list_categories()
        self.assertIn("Port Scanning", cats)
        self.assertIn("Web Reconnaissance", cats)
        self.assertIn("SMB / Windows", cats)

    def test_get_module(self):
        from modules_catalog import get_module
        m = get_module("ssh_version")
        self.assertEqual(m["path"], "auxiliary/scanner/ssh/ssh_version")
        self.assertEqual(m["type"], "auxiliary")

    def test_get_module_missing(self):
        from modules_catalog import get_module
        with self.assertRaises(KeyError):
            get_module("does_not_exist_xyz")

    def test_report_generator_html(self):
        from report_generator import generate_html
        dummy_report = {
            "target": "127.0.0.1",
            "timestamp": "2026-01-01T00:00:00Z",
            "msf_used": False,
            "resolved_ip": "127.0.0.1",
            "sections": {
                "open_ports": {
                    80: {"service": "HTTP", "banner": "Apache"},
                    22: {"service": "SSH",  "banner": "OpenSSH_8.9"},
                },
                "dns": {"A": ["127.0.0.1"]},
                "services": {
                    "http": [{"port": 80, "status": 200, "server": "Apache", "headers": {}}]
                },
                "msf": {},
            },
        }
        out_path = "test_report_output.html"
        result = generate_html(dummy_report, out_path)
        self.assertTrue(os.path.isfile(result))
        with open(result, encoding="utf-8") as f:
            html = f.read()
        self.assertIn("127.0.0.1", html)
        self.assertIn("Open Ports", html)
        self.assertIn("Apache", html)
        os.remove(result)

    def test_resolve_target_ip_passthrough(self):
        from recon_engine import ReconEngine
        ip = ReconEngine.resolve_target("192.168.1.1")
        self.assertEqual(ip, "192.168.1.1")

    def test_resolve_target_localhost(self):
        from recon_engine import ReconEngine
        ip = ReconEngine.resolve_target("localhost")
        self.assertIn(ip, ("127.0.0.1", "::1"))

    def test_port_scan_localhost(self):
        """Scan localhost — at least one port should be open on any dev machine."""
        from recon_engine import port_scan_offline
        # Only scan a small set so the test is quick
        result = port_scan_offline("127.0.0.1", ports=[80, 443, 8080, 3000, 5000, 22], threads=10)
        # We just check the return type; localhost may have nothing open
        self.assertIsInstance(result, dict)


# ─────────────────────────────────────────────────────────────────────────────
# Live probe test (skipped if no network)
# ─────────────────────────────────────────────────────────────────────────────

def _has_network() -> bool:
    try:
        socket.create_connection(("scanme.nmap.org", 80), timeout=3)
        return True
    except Exception:
        return False


class TestLiveProbe(unittest.TestCase):

    @unittest.skipUnless(_has_network(), "No network access")
    def test_scanme_http(self):
        """scanme.nmap.org should have port 80 open."""
        from recon_engine import port_scan_offline
        result = port_scan_offline("scanme.nmap.org", ports=[80, 22], threads=5)
        self.assertIn(80, result, "Port 80 should be open on scanme.nmap.org")

    @unittest.skipUnless(_has_network(), "No network access")
    def test_full_offline_recon(self):
        """Run full offline recon and check report structure."""
        from recon_engine import ReconEngine
        engine = ReconEngine(use_msf=False)
        report = engine.recon(
            target="scanme.nmap.org",
            categories=None,
            custom_ports=None,
            threads=50,
        )
        self.assertIn("sections", report)
        self.assertIn("open_ports", report["sections"])
        ports = report["sections"]["open_ports"]
        self.assertGreater(len(ports), 0, "Should find at least one open port")
        print(f"\n  [OK] Found {len(ports)} open ports on scanme.nmap.org: {list(ports.keys())}")

        # Save and check JSON
        path = "test_live_report.json"
        ReconEngine.save_report(report, path)
        self.assertTrue(os.path.isfile(path))
        with open(path) as f:
            loaded = json.load(f)
        self.assertEqual(loaded["target"], "scanme.nmap.org")
        os.remove(path)


# ─────────────────────────────────────────────────────────────────────────────
# Quick demo (non-unittest)
# ─────────────────────────────────────────────────────────────────────────────

def demo_list_modules():
    from modules_catalog import MODULES, list_categories, modules_for_category
    print(f"\n{'='*60}")
    print(f"  Total modules in catalog : {len(MODULES)}")
    print(f"  Categories               : {len(list_categories())}")
    for cat in list_categories():
        mods = modules_for_category(cat)
        print(f"    {cat:<30} {len(mods):>3} modules")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    demo_list_modules()
    print("Running tests…\n")
    unittest.main(verbosity=2)
