import subprocess
import socket

from models import Host


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

            self.online_hosts.append(
                Host(
                    str(ip),
                    hostname
                )
            )
