"""
setup.py — ReconForge installation script.

Install from PyPI (future):
    pip install reconforge

Install from GitHub:
    pip install git+https://github.com/HumairAli26/ReconForge.git

Install locally (development):
    pip install -e .
"""

from setuptools import setup, find_packages
from pathlib import Path

HERE = Path(__file__).parent
LONG_DESC = (HERE / "README.md").read_text(encoding="utf-8")

setup(
    name="reconforge",
    version="3.4.0",
    author="Humair Ali",
    description="Network Discovery and Security Assessment Platform",
    long_description=LONG_DESC,
    long_description_content_type="text/markdown",
    url="https://github.com/humairali/ReconForge",
    license="MIT",
    packages=find_packages(exclude=["tests*", "docs*"]),
    package_data={
        "reconforge": [
            "static/css/*.css",
            "static/js/*.js",
            "static/*.html",
        ],
    },
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
        "python-nmap>=0.7.1",
        "rich>=13.7.0",
        "dnspython>=2.6.1",
        "paramiko>=3.4.0",
        "scapy>=2.5.0",
        "mac-vendor-lookup>=0.1.12",
        "flask>=3.0.0",
        "flask-cors>=4.0.0",
    ],
    extras_require={
        "msf": ["pymsfrpc>=0.1.3"],
        "dev": ["pytest>=7.0", "pytest-cov", "black", "isort", "mypy"],
    },
    entry_points={
        "console_scripts": [
            "reconforge=reconforge.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    keywords="security recon nmap metasploit network scanning",
)
