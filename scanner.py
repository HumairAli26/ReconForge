from scapy.all import ARP, Ether, srp
from scapy.config import conf
import socket

NETWORK = "192.168.1.0/24"


def get_vendor(mac):
    try:
        vendor = conf.manufdb._get_manuf(mac)
        if vendor:
            return vendor
        return "Unknown"
    except:
        return "Unknown"


def scan(network):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(
        packet,
        timeout=2,
        verbose=False
    )[0]

    devices = []

    for sent, received in result:

        ip = received.psrc
        mac = received.hwsrc

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

        vendor = get_vendor(mac)

        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor
        })

    return devices


def main():
    print("=" * 30)
    print("ReconForge")
    print("=" * 30)

    devices = scan(NETWORK)

    print(f"\nFound {len(devices)} device(s)\n")

    print(
        "{:<16} {:<20} {:<25} {:<20}".format(
            "IP ADDRESS",
            "MAC ADDRESS",
            "HOSTNAME",
            "VENDOR"
        )
    )

    print("-" * 95)

    for device in devices:
        print(
            "{:<16} {:<20} {:<25} {:<20}".format(
                device["ip"],
                device["mac"],
                device["hostname"],
                device["vendor"]
            )
        )


if __name__ == "__main__":
    main()