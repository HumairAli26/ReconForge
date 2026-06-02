import socket

COMMON_PORTS = [
    21, 22, 23, 25,
    53, 80, 110, 135,
    139, 143, 443, 445,
    3306, 3389, 5432, 8080
]


def quick_scan(ip, timeout=0.2):
    open_ports = []

    for port in COMMON_PORTS:

        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(timeout)

            result = sock.connect_ex(
                (ip, port)
            )

            if result == 0:
                open_ports.append(port)

            sock.close()

        except:
            pass

    return open_ports


def full_scan(
    ip,
    start_port=1,
    end_port=65535,
    timeout=0.1
):
    open_ports = []

    for port in range(
        start_port,
        end_port + 1
    ):

        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(timeout)

            result = sock.connect_ex(
                (ip, port)
            )

            if result == 0:
                open_ports.append(port)

            sock.close()

        except:
            pass

    return open_ports