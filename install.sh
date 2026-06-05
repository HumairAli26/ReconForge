#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ReconForge — Linux Installer
# Tested on: Ubuntu 20.04/22.04/24.04, Kali Linux, Parrot OS, Debian 11/12
# Usage:  chmod +x install.sh && ./install.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     RESET='\033[0m'

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[-]${RESET} $*"; }
err()   { echo -e "${RED}[!]${RESET} $*"; }
banner(){ echo -e "${BOLD}${CYAN}$*${RESET}"; }

# ── Root check ─────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root — some apt steps may fail."
    warn "Re-run with: sudo ./install.sh"
fi

# ── Banner ─────────────────────────────────────────────────────────────────
echo ""
banner "╔══════════════════════════════════════════════╗"
banner "║          ReconForge  Installer               ║"
banner "╚══════════════════════════════════════════════╝"
echo ""

# ── Detect distro ──────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt-get"
elif command -v apt &>/dev/null; then
    PKG_MGR="apt"
else
    warn "apt not found — skipping system package installation."
    PKG_MGR=""
fi

# ── System packages ────────────────────────────────────────────────────────
if [[ -n "$PKG_MGR" ]]; then
    info "Updating package lists..."
    $PKG_MGR update -qq

    info "Installing system dependencies..."
    $PKG_MGR install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        git \
        nmap \
        net-tools \
        dnsutils \
        curl \
        build-essential \
        libssl-dev \
        libffi-dev \
        libpcap-dev

    ok "System packages installed."
fi

# ── Python version check ───────────────────────────────────────────────────
PYTHON=$(command -v python3 || true)
if [[ -z "$PYTHON" ]]; then
    err "python3 not found. Please install Python 3.9+."
    exit 1
fi

PY_VER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJ=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MIN=$($PYTHON -c "import sys; print(sys.version_info.minor)")

if [[ $PY_MAJ -lt 3 ]] || [[ $PY_MAJ -eq 3 && $PY_MIN -lt 9 ]]; then
    err "Python 3.9+ required. Found: $PY_VER"
    exit 1
fi
ok "Python $PY_VER detected."

# ── Virtual environment (recommended) ─────────────────────────────────────
VENV_DIR="$HOME/.reconforge-venv"
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment at $VENV_DIR ..."
    $PYTHON -m venv "$VENV_DIR"
fi
ok "Virtual environment ready."

# Activate
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

# Upgrade pip inside venv
info "Upgrading pip..."
pip install --quiet --upgrade pip

# ── Install Python dependencies ────────────────────────────────────────────
info "Installing Python dependencies..."
pip install --quiet -r requirements.txt
ok "Python dependencies installed."

# ── Install ReconForge ─────────────────────────────────────────────────────
info "Installing ReconForge..."
pip install --quiet -e .
ok "ReconForge installed."

# ── Wrapper script so `reconforge` works outside the venv ─────────────────
WRAPPER="/usr/local/bin/reconforge"
if [[ $EUID -eq 0 ]]; then
    cat > "$WRAPPER" << SCRIPT
#!/usr/bin/env bash
source "$VENV_DIR/bin/activate"
exec reconforge "\$@"
SCRIPT
    chmod +x "$WRAPPER"
    ok "Global command registered: $WRAPPER"
else
    warn "Not root — skipping global /usr/local/bin/reconforge wrapper."
    warn "Activate venv manually: source $VENV_DIR/bin/activate"
fi

# ── Verify nmap ────────────────────────────────────────────────────────────
if command -v nmap &>/dev/null; then
    ok "nmap is available: $(nmap --version | head -1)"
else
    warn "nmap not found — host discovery features may not work."
fi

# ── Metasploit hint ───────────────────────────────────────────────────────
if command -v msfconsole &>/dev/null; then
    ok "msfconsole detected — Metasploit integration enabled."
else
    warn "msfconsole not found — Metasploit features disabled (use --no-msf flag)."
    warn "Install Metasploit: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
fi

# ── Done ───────────────────────────────────────────────────────────────────
echo ""
banner "╔══════════════════════════════════════════════╗"
banner "║        Installation Complete!                ║"
banner "╚══════════════════════════════════════════════╝"
echo ""
ok  "Run:        reconforge --help"
ok  "Scan:       reconforge -t <target>"
ok  "No MSF:     reconforge -t <target> --no-msf"
ok  "Check deps: reconforge --check-deps"
echo ""
