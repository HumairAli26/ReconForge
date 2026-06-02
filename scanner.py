import ipaddress
from scapy.all import ARP, Ether, srp, conf
from mac_vendor_lookup import MacLookup
import socket
from device_info import collect_device_info

lookup = MacLookup()
try:
    lookup.update_vendors()
except:
    pass

def get_network():
    local_ip = conf.route.route("0.0.0.0")[1]
    network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
    return str(network)

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


def arp_scan(network):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    answered = srp(
        packet,
        timeout=2,
        verbose=False
    )[0]

    devices = []

    for sent, received in answered:

        ip = received.psrc
        mac = received.hwsrc

        basic_device = {
        "ip": ip,
        "mac": mac
        }

        devices.append(
            collect_device_info(basic_device)
        )
        return devices


def print_results(devices):

    print("\n" + "=" * 50)
    print("ReconForge")
    print("=" * 50)

    print(
        "{:<16} {:<20} {:<30} {:<30}".format(
            "IP ADDRESS",
            "MAC ADDRESS",
            "HOSTNAME",
            "VENDOR"
        )
    )

    print("-" * 110)

    for device in devices:

        print(
            "{:<16} {:<20} {:<30} {:<30}".format(
                device["ip"],
                device["mac"],
                device["hostname"],
                device["vendor"]
            )
        )

    print("\nDevices Found:", len(devices))


def main():
    network=get_network()
    print("Starting ARP scan...")
    print("Target Network:", network)

    devices = arp_scan(network)

    print_results(devices)


if __name__ == "__main__":
    main()