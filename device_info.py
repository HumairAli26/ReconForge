import socket
from datetime import datetime
from mac_vendor_lookup import MacLookup

# Initialize vendor lookup database
lookup = MacLookup()


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


def get_vendor(mac):
    try:
        return lookup.lookup(mac)
    except:
        return "Unknown"


def get_device_type(vendor, hostname):
    text = (vendor + " " + hostname).lower()

    if any(word in text for word in ["iphone", "samsung", "xiaomi", "oppo", "vivo"]):
        return "Mobile Phone"

    if any(word in text for word in ["printer", "hp print", "canon"]):
        return "Printer"

    if any(word in text for word in ["cisco", "router", "gateway", "mikrotik", "tp-link"]):
        return "Network Device"

    if any(word in text for word in ["dell", "lenovo", "asus", "acer", "desktop", "laptop"]):
        return "Computer"

    return "Unknown"


def collect_device_info(device):
    """
    device must contain:
    {
        'ip': ...,
        'mac': ...
    }
    """

    hostname = get_hostname(device["ip"])
    vendor = get_vendor(device["mac"])

    info = {
        "ip": device["ip"],
        "mac": device["mac"],
        "hostname": hostname,
        "vendor": vendor,
        "device_type": get_device_type(vendor, hostname),
        "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    return info