#!/usr/bin/env bash
# Quick-start: install if needed, then launch ReconForge
# Usage: bash run.sh [reconforge args...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$HOME/.reconforge-venv"

# Auto-install if venv doesn't exist
if [[ ! -d "$VENV_DIR" ]] || ! "$VENV_DIR/bin/python" -c "import reconforge" 2>/dev/null; then
    echo "[*] ReconForge not installed. Running installer..."
    bash "$SCRIPT_DIR/install.sh"
fi

source "$VENV_DIR/bin/activate"
exec reconforge "$@"
