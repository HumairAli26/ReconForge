"""
__init__.py
-----------
Makes recon_tool importable as a Python package.
"""

from .recon_engine import ReconEngine
from .modules_catalog import MODULES, get_module, list_categories, modules_for_category
from .report_generator import generate_html

__all__ = [
    "ReconEngine",
    "MODULES",
    "get_module",
    "list_categories",
    "modules_for_category",
    "generate_html",
]

__version__ = "1.0.0"
__author__  = "MSF Recon Tool"
