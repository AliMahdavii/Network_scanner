import socket
import ipaddress


class NetworkInfo:
    def __init__(self):
        self.local_ip = self.get_local_ip()

        self.network = ipaddress.ip_network(
            self.local_ip + "/24",
            strict=False
        )

        self.netmask = self.network.netmask

    def get_local_ip(self):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        try:
            sock.connect(("8.8.8.8", 80))

            return sock.getsockname()[0]

        finally:
            sock.close()
