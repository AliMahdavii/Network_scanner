import socket
import ipaddress
import subprocess

from concurrent.futures import ThreadPoolExecutor


class NetworkInfo:
    def __init__(self):
        self.local_ip = self.get_local_ip()

        self.network = ipaddress.ip_network(
            self.local_ip + "/24",
            strict=False
        )

        self.netmask = self.network.broadcast_address

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


class HostScanner:

    def __init__(self):

        self.online_hosts = []

    def ping(self, ip):
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", str(ip)],
            stdout=subprocess.DEVNULL
        )

        return result.returncode == 0

    def get_hostname(self, ip):
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except socket.herror:
            return "Unknown"

    def get_arp_table(self):
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True
        )

        lines = result.stdout.splitlines()

        arp_table = {}

        for line in lines:

            line = line.strip()
            parts = line.split()

            if len(parts) >= 3 and parts[2] in ["dynamic", "static"]:

                ip = parts[0]
                mac = parts[1]

                arp_table[ip] = mac

        return arp_table

    def scan_host(self, ip):

        if self.ping(ip):

            hostname = self.get_hostname(ip)

            self.online_hosts.append({
                "ip": str(ip),
                "hostname": hostname
            })


class PortScanner:

    def validate_port(self, port):

        if 0 <= port <= 65535:
            return True

        print("\nPort must be between 0 and 65535!\n")
        return False

    def get_port_range(self):

        while True:
            try:
                start_port = int(input("Start port: "))

                if not self.validate_port(start_port):
                    continue

                break

            except ValueError:
                print("\nPlease enter a valid number!\n")

        while True:
            try:
                end_port = int(input("End port: "))

                if not self.validate_port(end_port):
                    continue

                break

            except ValueError:
                print("\nPlease enter a valid number!\n")

        return range(start_port, end_port + 1)

    def scan_port(self, ip, port):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(1)

        result = sock.connect_ex((str(ip), port))

        sock.close()

        return result == 0

    def scan_port_thread(self, ip, port):

        if self.scan_port(ip, port):
            return port

        return None

    def scan_ports(self, ip, ports):

        open_ports = []

        with ThreadPoolExecutor(max_workers=20) as executor:

            results = executor.map(
                lambda port: self.scan_port_thread(ip, port),
                ports
            )

            for port in results:

                if port is not None:
                    open_ports.append(port)

        return open_ports
