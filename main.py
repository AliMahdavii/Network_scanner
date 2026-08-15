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


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except socket.herror:
        return "Unknown"


def scan_host(ip):
    hostname = get_hostname(ip)

    if ping(ip):
        print(
            ip,
            "ONLINE",
            "|  Hostname: ",
            hostname
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

with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(scan_host, network.hosts())
