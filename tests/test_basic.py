"""
tests/test_basic.py
-------------------
Basic smoke tests for ReconForge.
Run with:
    pytest tests/
"""

import os
import sys
from packaging.version import Version

# Ensure the package root is on the path during testing
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def test_import_package():
    """Verify package imports and exposes a valid version."""
    import reconforge

    assert hasattr(reconforge, "__version__")
    Version(reconforge.__version__)


def test_import_cli():
    """Verify CLI parser can be built."""
    from reconforge.cli import build_parser

    parser = build_parser()
    assert parser is not None


def test_import_modules():
    """Verify module catalogue loads."""
    from reconforge.modules.catalog import MODULES, list_categories

    assert len(MODULES) > 0

    categories = list_categories()
    assert len(categories) > 0


def test_import_deps():
    """Verify dependency helper functions exist."""
    from reconforge.utils.deps import (
        check_dependencies,
        get_nmap_path,
    )

    assert callable(check_dependencies)
    assert callable(get_nmap_path)


def test_import_recon_engine():
    """Verify ReconEngine initializes."""
    from reconforge.core.recon_engine import ReconEngine

    engine = ReconEngine(use_msf=False)
    assert engine is not None


def test_parse_ports():
    """Verify custom port parsing works."""
    from reconforge.cli import parse_custom_ports

    ports = parse_custom_ports("22,80,443,8000-8002")

    assert 22 in ports
    assert 80 in ports
    assert 443 in ports
    assert 8000 in ports
    assert 8001 in ports
    assert 8002 in ports
