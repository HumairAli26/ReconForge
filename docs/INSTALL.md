# Installation Guide

## One-Command Install (pip)

```bash
pip install git+https://github.com/humairali/ReconForge.git
reconforge --help
```

## Full Install (Recommended)

### Step 1 — Clone the repository

```bash
git clone https://github.com/humairali/ReconForge.git
cd ReconForge
```

### Step 2 — Run the installer

```bash
chmod +x install.sh
sudo ./install.sh
```

The installer:
- Updates your apt package lists
- Installs `python3`, `python3-pip`, `python3-venv`, `git`, `nmap`, `net-tools`, `dnsutils`
- Creates a virtual environment at `~/.reconforge-venv`
- Installs all Python dependencies
- Installs ReconForge
- Creates a global `/usr/local/bin/reconforge` wrapper

### Step 3 — Verify

```bash
reconforge --check-deps
```

---

## Manual Install (Without the Script)

```bash
# System deps
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git nmap net-tools dnsutils

# Virtual environment (strongly recommended)
python3 -m venv ~/.reconforge-venv
source ~/.reconforge-venv/bin/activate

# Python deps + package
pip install -r requirements.txt
pip install .

# Run
reconforge --help
```

---

## Kali Linux Notes

Kali already ships with `nmap` and Metasploit.  
The installer works on Kali without modification.  
Skip the apt install block if packages are already present.

---

## Metasploit (Optional)

ReconForge works fully without Metasploit (`--no-msf` flag).

To enable Metasploit integration:

```bash
# Official installer
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
sudo ./msfinstall
```

Then run `msfconsole` once to initialise the database before using ReconForge in MSF mode.

---

## Uninstall

```bash
chmod +x uninstall.sh
sudo ./uninstall.sh
```
