import socket
import ipaddress
import subprocess

from concurrent.futures import ThreadPoolExecutor


def ping(ip):
    result = subprocess.run(
        ["ping", "-n", "1", "-w", "1000", str(ip)],
        stdout=subprocess.DEVNULL
    )

    return result.returncode == 0


def get_arp_table():
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


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except socket.herror:
        return "Unknown"


def scan_host(ip):

    if ping(ip):

        hostname = get_hostname(ip)

        mac = arp_table.get(str(ip), "Unknown")

        print(
            ip,
            "ONLINE",
            "|  Hostname: ",
            hostname,
            "|  MAC: ",
            mac
        )

# Find local IP


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.connect(("8.8.8.8", 80))

local_ip = sock.getsockname()[0]

sock.close()

# Find network

network = ipaddress.ip_network(local_ip + "/24", strict=False)

print("Local IP: ", local_ip)
print("Network: ", network)
print("Netmask: ", network.netmask)
print("Broadcast: ", network.broadcast_address)

print("\nScanning...\n")

# Scan hosts

arp_table = get_arp_table()

with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(scan_host, network.hosts())
