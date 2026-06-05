#!/usr/bin/env bash
# ReconForge Uninstaller

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[-]${RESET} $*"; }

echo ""
echo "Uninstalling ReconForge..."
echo ""

# Remove wrapper
if [[ -f /usr/local/bin/reconforge ]]; then
    rm -f /usr/local/bin/reconforge
    ok "Removed /usr/local/bin/reconforge"
fi

# Remove virtual environment
VENV_DIR="$HOME/.reconforge-venv"
if [[ -d "$VENV_DIR" ]]; then
    rm -rf "$VENV_DIR"
    ok "Removed virtual environment: $VENV_DIR"
fi

# Pip uninstall (if installed globally)
pip uninstall -y reconforge 2>/dev/null && ok "Removed pip package: reconforge" || true

ok "ReconForge has been removed."
