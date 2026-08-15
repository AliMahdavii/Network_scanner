import socket
import ipaddress
import subprocess

from concurrent.futures import ThreadPoolExecutor

# Network

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.connect(("8.8.8.8", 80))

local_ip = sock.getsockname()[0]

sock.close()


network = ipaddress.ip_network(local_ip + "/24", strict=False)

# Ping


def ping(ip):
    result = subprocess.run(
        ["ping", "-n", "1", "-w", "1000", str(ip)],
        stdout=subprocess.DEVNULL
    )

    return result.returncode == 0


# Hostname
def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except socket.herror:
        return "Unknown"


# ARP Table
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


# Host scanner

online_hosts = []


def scan_host(ip):

    if ping(ip):

        hostname = get_hostname(ip)

        online_hosts.append({
            "ip": str(ip),
            "hostname": hostname
        })

# Scan network


print("=" * 65)
print("                            NETWORK SCANNER")
print("=" * 65)

print()

print("Local IP: ", local_ip)
print("Network: ", network)
print("Netmask: ", network.netmask)
print("Broadcast: ", network.broadcast_address)

print("\nScanning...\n")

with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(scan_host, network.hosts())

# Get mac addresses

arp_table = get_arp_table()

for host in online_hosts:

    ip = host["ip"]

    host["mac"] = arp_table.get(
        ip,
        "Unknown"
    )

# Display results

print("IP ADDRESS".ljust(18), end="")
print("HOSTNAME".ljust(21), end="")
print("MAC ADDRESS")

print("-" * 65)


for host in online_hosts:

    print(
        host["ip"].ljust(18),
        host["hostname"].ljust(21),
        host["mac"]
    )

print()
print("-" * 65)

print(
    len(online_hosts),
    " hosts found"
)

print("=" * 65)
