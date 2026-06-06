#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ReconForge — Zero-friction Linux/macOS Installer
# After git clone, just run:  bash install.sh   (no chmod needed)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     RESET='\033[0m'

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[-]${RESET} $*"; }
err()   { echo -e "${RED}[!]${RESET} $*"; }
banner(){ echo -e "${BOLD}${CYAN}$*${RESET}"; }

# Auto-make all scripts executable (so users never need chmod)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/uninstall.sh" 2>/dev/null || true

echo ""
banner "╔══════════════════════════════════════════════╗"
banner "║          ReconForge  Installer               ║"
banner "╚══════════════════════════════════════════════╝"
echo ""

# ── Root check ─────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root — system package install may fail."
    warn "Re-run with: sudo bash install.sh"
fi

# ── Detect distro / package manager ───────────────────────────────────────
if command -v apt-get &>/dev/null; then PKG_MGR="apt-get"
elif command -v apt &>/dev/null;     then PKG_MGR="apt"
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
        python3 python3-pip python3-venv python3-dev \
        git nmap net-tools dnsutils curl \
        build-essential libssl-dev libffi-dev libpcap-dev
    ok "System packages installed."
fi

# ── Python version check ────────────────────────────────────────────────────
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

# ── Virtual environment ─────────────────────────────────────────────────────
VENV_DIR="$HOME/.reconforge-venv"
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment at $VENV_DIR ..."
    $PYTHON -m venv "$VENV_DIR"
fi
ok "Virtual environment ready."

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

info "Upgrading pip..."
pip install --quiet --upgrade pip

# ── Python dependencies ─────────────────────────────────────────────────────
info "Installing Python dependencies..."
pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
ok "Python dependencies installed."

# ── Install ReconForge ──────────────────────────────────────────────────────
info "Installing ReconForge..."
pip install --quiet -e "$SCRIPT_DIR"
ok "ReconForge installed."

# ── Global wrapper ──────────────────────────────────────────────────────────
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
    warn "Skipping /usr/local/bin wrapper (not root)."
    warn "To run: source $VENV_DIR/bin/activate && reconforge --help"
fi

# ── Tool checks ─────────────────────────────────────────────────────────────
if command -v nmap &>/dev/null; then
    ok "nmap available — enhanced host/port discovery enabled."
else
    warn "nmap not found — install it for best scan coverage: sudo apt install nmap"
fi

if command -v msfconsole &>/dev/null; then
    ok "msfconsole detected — Metasploit integration enabled (fast-boot mode)."
    # Run msfdb init once to pre-warm the database (biggest speed win)
    if command -v msfdb &>/dev/null; then
        info "Running msfdb init to pre-warm PostgreSQL (speeds up future boots)..."
        sudo msfdb init 2>/dev/null && ok "msfdb: Database ready." || warn "msfdb init failed — will use -n mode."
    fi
else
    warn "msfconsole not found — Metasploit features disabled."
    warn "Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
fi

# ── Nuclei check ────────────────────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
    ok "nuclei detected — fast vulnerability scanning enabled ($(nuclei -version 2>&1 | head -1))."
    info "Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null && ok "nuclei templates updated." || warn "Template update failed (run manually: nuclei -update-templates)"
else
    warn "nuclei not found — install for fast vuln scanning (optional but recommended)."
    warn "Install: sudo apt install nuclei"
    warn "Or:      go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
fi

echo ""
banner "╔══════════════════════════════════════════════╗"
banner "║        Installation Complete!                ║"
banner "╚══════════════════════════════════════════════╝"
echo ""
ok  "Run:            reconforge --help"
ok  "Scan:           reconforge -t <target>"
ok  "No MSF:         reconforge -t <target> --no-msf"
ok  "Full port scan: reconforge -t <target> --full-ports"
ok  "Check deps:     reconforge --check-deps"
echo ""
