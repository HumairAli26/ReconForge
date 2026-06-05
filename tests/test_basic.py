"""
tests/test_basic.py
-------------------
Basic smoke tests for ReconForge.
Run with: pytest tests/
"""

import sys
import os

# Ensure the package root is on the path during testing
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def test_import_package():
    import reconforge
    assert reconforge.__version__ == "1.0.0"


def test_import_cli():
    from reconforge.cli import build_parser
    parser = build_parser()
    assert parser is not None


def test_import_modules():
    from reconforge.modules.catalog import MODULES, list_categories
    assert len(MODULES) > 0
    cats = list_categories()
    assert len(cats) > 0


def test_import_deps():
    from reconforge.utils.deps import check_dependencies, get_nmap_path
    # Just confirm functions are callable
    assert callable(check_dependencies)
    assert callable(get_nmap_path)


def test_import_recon_engine():
    from reconforge.core.recon_engine import ReconEngine
    engine = ReconEngine(use_msf=False)
    assert engine is not None


def test_parse_ports():
    from reconforge.cli import parse_custom_ports
    ports = parse_custom_ports("22,80,443,8000-8002")
    assert 22 in ports
    assert 80 in ports
    assert 443 in ports
    assert 8000 in ports
    assert 8001 in ports
    assert 8002 in ports
