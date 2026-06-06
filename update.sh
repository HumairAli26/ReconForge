#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ReconForge — Update Script
# Run from inside the ReconForge directory:  bash update.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[-]${RESET} $*"; }
err()   { echo -e "${RED}[!]${RESET} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$HOME/.reconforge-venv"

echo ""
echo -e "${BOLD}${CYAN}ReconForge — Update${RESET}"
echo ""

# ── Git pull ─────────────────────────────────────────────────────────────────
if [ -d "$SCRIPT_DIR/.git" ]; then
    info "Pulling latest changes from git..."
    cd "$SCRIPT_DIR"
    git pull
    ok "Git pull complete."
else
    warn "No .git directory — skipping git pull (manual update)."
fi

# ── Activate venv ─────────────────────────────────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
    warn "Virtual environment not found. Running full installer..."
    bash "$SCRIPT_DIR/install.sh"
    exit 0
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

# ── Reinstall package ─────────────────────────────────────────────────────────
info "Reinstalling ReconForge package..."
pip install --quiet --upgrade pip
pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
pip install --quiet --force-reinstall -e "$SCRIPT_DIR"
ok "ReconForge reinstalled."

# ── Show new version ──────────────────────────────────────────────────────────
NEW_VER=$(python3 -c "import reconforge; print(reconforge.__version__)" 2>/dev/null || echo "unknown")
ok "Version: $NEW_VER"

echo ""
ok "Update complete. Run: reconforge --version"
