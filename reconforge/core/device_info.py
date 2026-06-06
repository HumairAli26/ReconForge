"""
device_info.py
--------------
Hostname resolution, MAC-vendor lookup, and device-type classification.

Vendor lookup order:
  1. mac_vendor_lookup library (full IEEE database)
  2. Built-in OUI prefix table (offline fallback, ~120 common vendors)

Device-type classification uses a multi-layer approach:
  vendor text, hostname, open ports, TTL fingerprint.
"""

import socket
import re
from datetime import datetime

# ── mac-vendor-lookup (optional, best accuracy) ───────────────────────────────
try:
    from mac_vendor_lookup import MacLookup, VendorNotFoundError
    _mac_lookup = MacLookup()
    try:
        _mac_lookup.update_vendors()       # pull fresh IEEE DB if network available
    except Exception:
        pass                               # fine — uses cached DB
    MAC_LOOKUP_OK = True
except ImportError:
    _mac_lookup = None
    MAC_LOOKUP_OK = False

# ── Built-in OUI prefix fallback table (first 6 hex chars, upper, no colons) ──
_OUI_TABLE = {
    # Apple
    "000A95": "Apple", "0017F2": "Apple", "001B63": "Apple", "001CB3": "Apple",
    "001D4F": "Apple", "001E52": "Apple", "001F5B": "Apple", "001FF3": "Apple",
    "002241": "Apple", "002312": "Apple", "002500": "Apple", "0026B9": "Apple",
    "002713": "Apple", "00306F": "Apple", "003EE1": "Apple", "005056": "Apple",
    "7C6D62": "Apple", "A45E60": "Apple", "BC9FEF": "Apple", "DC2B2A": "Apple",
    "F0DBE2": "Apple", "F4F951": "Apple",
    # Samsung
    "002339": "Samsung", "002454": "Samsung", "0025AD": "Samsung", "002638": "Samsung",
    "00E3B2": "Samsung", "040ECE": "Samsung", "0C7172": "Samsung", "10D542": "Samsung",
    "28988F": "Samsung", "3C5A37": "Samsung", "4C3C16": "Samsung", "5C3C27": "Samsung",
    "7825AD": "Samsung", "8C1AB0": "Samsung", "B47443": "Samsung", "C4731E": "Samsung",
    "F49F54": "Samsung", "F8042E": "Samsung",
    # Huawei
    "001E10": "Huawei", "00259E": "Huawei", "002EC7": "Huawei", "0034FE": "Huawei",
    "246022": "Huawei", "28BFCA": "Huawei", "485754": "Huawei", "5406A5": "Huawei",
    "5C4CA9": "Huawei", "686275": "Huawei", "70728D": "Huawei", "80717A": "Huawei",
    "98D8C3": "Huawei", "A049DB": "Huawei", "BC7670": "Huawei", "E0247F": "Huawei",
    # Cisco
    "000142": "Cisco", "000164": "Cisco", "0001C7": "Cisco", "000216": "Cisco",
    "001185": "Cisco", "001120": "Cisco", "001B0D": "Cisco", "001C57": "Cisco",
    "001DC9": "Cisco", "002155": "Cisco", "002497": "Cisco", "0050BF": "Cisco",
    "00508D": "Cisco", "006476": "Cisco", "189C5D": "Cisco", "2C3124": "Cisco",
    "3C0872": "Cisco", "58AC78": "Cisco", "7CB21B": "Cisco", "A0F8C7": "Cisco",
    "D0C282": "Cisco", "EC1D8B": "Cisco", "F04DA2": "Cisco",
    # TP-Link
    "000AEB": "TP-Link", "0019E0": "TP-Link", "001D0F": "TP-Link", "001FE1": "TP-Link",
    "002179": "TP-Link", "00E04C": "TP-Link", "1C3BF3": "TP-Link", "50C7BF": "TP-Link",
    "60E327": "TP-Link", "68FF7B": "TP-Link", "74EA3A": "TP-Link", "90F652": "TP-Link",
    "A42BB0": "TP-Link", "B0487A": "TP-Link", "C025A2": "TP-Link", "E87F6E": "TP-Link",
    # MikroTik
    "000C42": "MikroTik", "2CC8FB": "MikroTik", "4C5E0C": "MikroTik",
    "64D154": "MikroTik", "6C3B6B": "MikroTik", "74AD33": "MikroTik",
    "B8690E": "MikroTik", "CC2DE0": "MikroTik", "D4CA6D": "MikroTik",
    "DC2C6E": "MikroTik", "E48D8C": "MikroTik",
    # Ubiquiti
    "002722": "Ubiquiti", "04184E": "Ubiquiti", "0418D6": "Ubiquiti",
    "24A43C": "Ubiquiti", "44D9E7": "Ubiquiti", "68729C": "Ubiquiti",
    "788A20": "Ubiquiti", "80213A": "Ubiquiti", "B4FBE4": "Ubiquiti",
    "DC9FDB": "Ubiquiti", "E063DA": "Ubiquiti", "F09FC2": "Ubiquiti",
    # Netgear
    "000FB5": "Netgear", "001B2F": "Netgear", "001E2A": "Netgear", "002430": "Netgear",
    "00266C": "Netgear", "2090E9": "Netgear", "3CD92B": "Netgear", "4401B8": "Netgear",
    "587F57": "Netgear", "6CB0CE": "Netgear", "84180F": "Netgear", "A040A0": "Netgear",
    "C03F0E": "Netgear", "E091F5": "Netgear",
    # D-Link
    "000D88": "D-Link", "000FEA": "D-Link", "001195": "D-Link", "0015E9": "D-Link",
    "00179A": "D-Link", "001CF0": "D-Link", "14D64D": "D-Link", "1C7EE5": "D-Link",
    "28107B": "D-Link", "340804": "D-Link", "5CD998": "D-Link", "84C9B2": "D-Link",
    "B8A386": "D-Link", "C8BE19": "D-Link", "F07D68": "D-Link",
    # ASUS
    "001A92": "ASUS", "002215": "ASUS", "0023E2": "ASUS", "006B9E": "ASUS",
    "04D4C4": "ASUS", "107B44": "ASUS", "1C872C": "ASUS", "2C56DC": "ASUS",
    "2CE412": "ASUS", "30AEA4": "ASUS", "4CE675": "ASUS", "60A44C": "ASUS",
    "74D02B": "ASUS", "AC220B": "ASUS", "B06EBF": "ASUS", "BC9780": "ASUS",
    "E4BEED": "ASUS",
    # Dell
    "001372": "Dell", "001A4B": "Dell", "001EC9": "Dell", "0021F6": "Dell",
    "002564": "Dell", "14FEB5": "Dell", "18A994": "Dell", "1C4021": "Dell",
    "24B6FD": "Dell", "484F6F": "Dell", "54BF64": "Dell", "5CBA37": "Dell",
    "705A0F": "Dell", "7499B3": "Dell", "8C8D28": "Dell", "9897D2": "Dell",
    "B083FE": "Dell", "B0838A": "Dell", "F48E38": "Dell",
    # Lenovo
    "000D3A": "Lenovo", "001C25": "Lenovo", "28D244": "Lenovo", "3425E2": "Lenovo",
    "484B2D": "Lenovo", "4C7C5F": "Lenovo", "5CF7E6": "Lenovo", "60C547": "Lenovo",
    "7C5CF8": "Lenovo", "88706E": "Lenovo", "9C4E36": "Lenovo", "ACE042": "Lenovo",
    "C80AA9": "Lenovo", "E8B4C8": "Lenovo",
    # HP / HPE
    "001635": "HP", "001B78": "HP", "001CC4": "HP", "001E0B": "HP",
    "0021F3": "HP", "002635": "HP", "3C4A92": "HP", "40B034": "HP",
    "5CBAC3": "HP", "6C3BE5": "HP", "6CD910": "HP", "70878B": "HP",
    "78480F": "HP", "8C164A": "HP", "94571A": "HP", "E8399D": "HP",
    "F0921C": "HP",
    # Raspberry Pi
    "28CDB4": "Raspberry Pi", "B827EB": "Raspberry Pi", "DC1798": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    # Intel (Wi-Fi NIC)
    "001517": "Intel", "001FE1": "Intel", "002177": "Intel", "002314": "Intel",
    "004420": "Intel", "485D60": "Intel", "5CE0C5": "Intel", "606720": "Intel",
    "68059A": "Intel", "8C8D28": "Intel", "A0999B": "Intel", "A4C361": "Intel",
    "D477B5": "Intel",
    # Realtek (common in IoT / cheap adapters)
    "00E04C": "Realtek", "2C4D22": "Realtek", "3C39E7": "Realtek",
    # Xiaomi
    "286C07": "Xiaomi", "34CE008": "Xiaomi", "50EC50": "Xiaomi",
    "54B1B5": "Xiaomi", "74510E": "Xiaomi", "8CBEBE": "Xiaomi",
    "9821C1": "Xiaomi", "B0E235": "Xiaomi", "E4946A": "Xiaomi",
    "F48B32": "Xiaomi", "F88870": "Xiaomi",
    # OnePlus / OPPO / Vivo
    "0429EA": "OnePlus", "1C2861": "OPPO", "7C1C68": "OPPO",
    "6C5AB0": "Vivo",    "DC6DCD": "Vivo",
    # Google / Nest
    "1C46BD": "Google", "20DF2B": "Google", "38CA84": "Google", "54606E": "Google",
    "5CA802": "Google",  "70B3D5": "Google", "94EB2C": "Google",
    "A47E39": "Google",  "D4F57D": "Google",
    # Amazon (Echo, Fire, Kindle)
    "0C4785": "Amazon", "34D270": "Amazon", "40B4CD": "Amazon", "447805": "Amazon",
    "54804B": "Amazon",  "68373C": "Amazon", "74C246": "Amazon", "784B87": "Amazon",
    "84D6D0": "Amazon",  "A002DC": "Amazon", "B47C9C": "Amazon", "F0272D": "Amazon",
    "FC65DE": "Amazon",
    # Epson / Canon / Brother (Printers)
    "0026AB": "Epson", "3C4A92": "Epson", "00000C": "Epson",
    "00017E": "Canon", "001871": "Canon", "003085": "Canon",
    "0009AE": "Brother", "00804A": "Brother", "00B0D0": "Brother",
    # VMware / VirtualBox (VMs)
    "000C29": "VMware", "000569": "VMware", "001C14": "VMware",
    "080027": "VirtualBox",
}


def _normalise_mac(mac: str) -> str:
    """Return MAC as XX:XX:XX:XX:XX:XX uppercase."""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(cleaned) < 6:
        return mac.upper()
    return ":".join(cleaned[i:i+2] for i in range(0, 12, 2)).upper()


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def get_vendor(mac: str) -> str:
    """
    Resolve MAC to vendor name.
    Tries mac_vendor_lookup library first; falls back to built-in OUI table.
    """
    if not mac or mac.lower() in ("n/a", "unknown", ""):
        return "Unknown"

    norm = _normalise_mac(mac)

    # 1. mac_vendor_lookup library
    if MAC_LOOKUP_OK and _mac_lookup is not None:
        try:
            result = _mac_lookup.lookup(norm)
            if result:
                return result
        except Exception:
            pass

    # 2. Built-in OUI prefix table
    oui_key = norm.replace(":", "")[:6].upper()
    vendor = _OUI_TABLE.get(oui_key)
    if vendor:
        return vendor

    # 3. Try first 3 hex pairs as 8-bit prefix
    oui6 = norm.replace(":", "")[:6].upper()
    for length in (6,):          # already tried 6; kept as hook for future extensions
        hit = _OUI_TABLE.get(oui6[:length])
        if hit:
            return hit

    return "Unknown"


# ── Device type classification ────────────────────────────────────────────────

# Ordered list of (label, keyword_sets) — first match wins
_DEVICE_RULES = [
    ("Router / Firewall", [
        ["cisco", "router"],     ["mikrotik"],         ["ubiquiti"],
        ["pfsense"],             ["openwrt"],          ["dd-wrt"],
        ["fortinet"],            ["juniper"],          ["netgear"],
        ["draytek"],             ["gateway"],          ["d-link"],
    ]),
    ("Wireless AP", [
        ["access point"],        ["aruba"],            ["ruckus"],
        ["aerohive"],            ["engenius"],
    ]),
    ("Network Switch", [
        ["switch"],              ["catalyst"],         ["procurve"],
        ["powerconnect"],
    ]),
    ("Printer", [
        ["printer"],             ["epson"],            ["canon"],
        ["brother"],             ["ricoh"],            ["xerox"],
        ["laserjet"],            ["officejet"],        ["inkjet"],
    ]),
    ("IoT Device", [
        ["arduino"],             ["esp8266"],          ["esp32"],
        ["raspberry pi"],        ["nest"],             ["ring"],
        ["shelly"],              ["tuya"],             ["tasmota"],
        ["smart plug"],          ["smart bulb"],       ["zigbee"],
        ["z-wave"],
    ]),
    ("Smart TV / Media", [
        ["smart tv"],            ["samsung tv"],       ["lg webos"],
        ["appletv"],             ["roku"],             ["chromecast"],
        ["fire tv"],             ["android tv"],       ["kodi"],
    ]),
    ("Mobile Phone", [
        ["iphone"],              ["ipad"],             ["android"],
        ["samsung"],             ["xiaomi"],           ["oppo"],
        ["oneplus"],             ["vivo"],             ["huawei"],
        ["realme"],              ["nokia"],
    ]),
    ("Virtual Machine", [
        ["vmware"],              ["virtualbox"],       ["qemu"],
        ["hyper-v"],             ["parallels"],
    ]),
    ("Windows PC", [
        ["windows"],             ["win-"],             ["desktop-"],
        ["workstation"],         ["msft"],             ["dell"],
        ["lenovo"],
    ]),
    ("Linux Server", [
        ["ubuntu"],              ["debian"],           ["centos"],
        ["fedora"],              ["rhel"],             ["kali"],
        ["arch"],                ["linux"],            ["server"],
        ["nas"],                 ["synology"],         ["qnap"],
        ["proxmox"],
    ]),
    ("macOS / Mac", [
        ["macbook"],             ["imac"],             ["mac-"],
        ["apple"],
    ]),
    ("Gaming Console", [
        ["playstation"],         ["xbox"],             ["nintendo"],
        ["switch"],              ["ps4"],              ["ps5"],
    ]),
    ("VoIP / Phone", [
        ["voip"],                ["sip"],              ["polycom"],
        ["yealink"],             ["grandstream"],      ["cisco phone"],
    ]),
    ("IP Camera / NVR", [
        ["camera"],              ["ipcam"],            ["nvr"],
        ["dvr"],                 ["hikvision"],        ["dahua"],
        ["axis"],                ["foscam"],
    ]),
]

# Port → device-type hints (used when vendor/hostname give nothing)
_PORT_HINTS = {
    22:   "Linux Server",
    23:   "Network Device",      # Telnet — legacy equipment
    80:   None,                  # too generic
    443:  None,
    445:  "Windows PC",
    139:  "Windows PC",
    3389: "Windows PC",
    548:  "macOS / Mac",
    5900: "Desktop",
    8080: "HTTP Service",
    9100: "Printer",
    631:  "Printer",
    161:  "Network Device",      # SNMP
    162:  "Network Device",
    5060: "VoIP / Phone",
    5061: "VoIP / Phone",
    1900: "IoT Device",          # UPnP
    8883: "IoT Device",          # MQTT over TLS
    1883: "IoT Device",          # MQTT
    6668: "Gaming Console",
    3074: "Gaming Console",
    3478: "Gaming Console",
    3479: "Gaming Console",
}


def get_device_type(vendor: str, hostname: str, open_ports: list = None) -> str:
    """
    Multi-layer device classification:
      1. Keyword match on vendor + hostname
      2. Port-based hint
      3. Fallback "Unknown"
    """
    text = (vendor + " " + hostname).lower()

    for label, keyword_sets in _DEVICE_RULES:
        for keywords in keyword_sets:
            if all(kw in text for kw in keywords):
                return label

    # Port-based fallback
    if open_ports:
        for port in open_ports:
            hint = _PORT_HINTS.get(int(port))
            if hint:
                return hint

    return "Unknown"


# ── Public API ─────────────────────────────────────────────────────────────────

def collect_device_info(device: dict) -> dict:
    """
    Enrich a raw device dict (must have 'ip' and 'mac') with hostname,
    vendor, device_type, and timestamps.
    """
    ip  = device.get("ip", "")
    mac = device.get("mac", "")

    hostname    = get_hostname(ip)
    vendor      = get_vendor(mac)
    open_ports  = device.get("open_ports", [])
    device_type = get_device_type(vendor, hostname, open_ports)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "ip":          ip,
        "mac":         _normalise_mac(mac),
        "hostname":    hostname,
        "vendor":      vendor,
        "device_type": device_type,
        "first_seen":  device.get("first_seen", now),
        "last_seen":   now,
    }
